//! The gateway: an MCP server to the agent, routing to upstream MCP servers
//! through the decision pipeline.
//!
//! [`Gateway::handle`] takes one JSON-RPC message from the agent and returns
//! the response, if any. Transport (stdio, HTTP) lives in the `airlock`
//! binary; upstream connections are behind the [`Upstreams`] trait so the
//! pipeline can be tested without processes.
//!
//! The MCP connection offers exactly three methods: `initialize`, `ping`,
//! `tools/list` and `tools/call` (plus notifications, which are ignored).
//! Nothing on it can approve, reject, unfreeze or change policy.

use std::path::PathBuf;

use serde_json::{json, Value};

use crate::approvals::{args_hash, ApprovalStore, Pending, Status};
use crate::audit::{AuditLog, Record};
use crate::budget::{BudgetCheck, Budgets};
use crate::freeze;
use crate::limits::{check_deny_patterns, check_limit};
use crate::policy::{Class, Policy, Provenance};
use crate::taint::TaintStore;
use crate::util::{now_unix, redact, rfc3339};
use crate::Error;

pub const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

/// Connections to upstream MCP servers.
pub trait Upstreams {
    /// Tool definitions offered by `upstream` (each an object with `name`).
    fn list_tools(&mut self, upstream: &str) -> Result<Vec<Value>, String>;
    /// Call `tool` on `upstream`; returns the MCP `CallToolResult`.
    fn call_tool(&mut self, upstream: &str, tool: &str, args: &Value) -> Result<Value, String>;
}

/// Where alerts go (a file, a webhook, a pager).
pub trait Notifier {
    fn alert(&self, alert: &Value);
}

/// Writes alerts as JSON Lines to `<state_dir>/alerts.jsonl`.
pub struct FileNotifier {
    pub path: PathBuf,
}

impl Notifier for FileNotifier {
    fn alert(&self, alert: &Value) {
        use std::io::Write;
        let line = format!("{}\n", alert);
        let res = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .and_then(|mut f| f.write_all(line.as_bytes()));
        if let Err(e) = res {
            eprintln!(
                "airlock: could not write alert to {}: {e}",
                self.path.display()
            );
        }
    }
}

/// What the pipeline decided about one call.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Forward it. `approval` is set when a person approved it.
    Allow {
        approval: Option<Pending>,
        fail_open: Option<String>,
    },
    /// Refuse it.
    Deny { reason: String },
    /// Return a dry run and wait for a person.
    Hold { pending: Pending, fresh: bool },
}

/// The pipeline's output for one call.
#[derive(Debug, Clone)]
pub struct Evaluation {
    pub class: Option<Class>,
    pub verdict: Verdict,
    pub tainted: Vec<String>,
    pub tripped: bool,
}

pub struct Gateway<U: Upstreams> {
    policy: Policy,
    task: String,
    session: String,
    upstreams: U,
    taint: TaintStore,
    budgets: Budgets,
    audit: AuditLog,
    approvals: ApprovalStore,
    state_dir: PathBuf,
    notifier: Box<dyn Notifier>,
    clock: Box<dyn Fn() -> i64>,
}

impl<U: Upstreams> Gateway<U> {
    /// Build a gateway for one task. The task comes from the operator (the
    /// command line), never from the agent.
    pub fn new(
        policy: Policy,
        task: &str,
        session: &str,
        upstreams: U,
        notifier: Box<dyn Notifier>,
    ) -> Result<Self, Error> {
        if !policy.grants.contains_key(task) {
            return Err(Error::Policy(format!("no grant for task {task:?}")));
        }
        let state_dir = policy.state_dir();
        std::fs::create_dir_all(&state_dir)?;
        let audit = AuditLog::open(&policy.audit_path())?;
        let gw = Gateway {
            taint: TaintStore::new(policy.gateway.min_taint_len),
            approvals: ApprovalStore::new(&state_dir),
            task: task.to_string(),
            session: session.to_string(),
            budgets: Budgets::new(),
            policy,
            upstreams,
            audit,
            state_dir,
            notifier,
            clock: Box::new(now_unix),
        };
        gw.audit.append(Record {
            session: gw.session.clone(),
            task: gw.task.clone(),
            event: "session_start".into(),
            decision: "info".into(),
            reason: "gateway session started".into(),
            ..Default::default()
        })?;
        Ok(gw)
    }

    /// Replace the clock (tests).
    pub fn with_clock(mut self, clock: impl Fn() -> i64 + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn upstreams_mut(&mut self) -> &mut U {
        &mut self.upstreams
    }

    pub fn approvals(&self) -> &ApprovalStore {
        &self.approvals
    }

    // ------------------------------------------------------------------
    // JSON-RPC handling
    // ------------------------------------------------------------------

    /// Handle one JSON-RPC message from the agent.
    pub fn handle(&mut self, msg: &Value) -> Option<Value> {
        let Some(obj) = msg.as_object() else {
            return Some(rpc_error(
                &Value::Null,
                -32600,
                "expected a JSON-RPC object (batches are not supported)",
            ));
        };
        let id = obj.get("id").cloned();
        let Some(method) = obj.get("method").and_then(Value::as_str) else {
            // A response to a server-initiated request; we never send any.
            return None;
        };
        let id = id?; // notifications get no response
        let params = obj.get("params").cloned().unwrap_or(Value::Null);
        let result = match method {
            "initialize" => Ok(self.initialize(&params)),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(self.tools_list()),
            "tools/call" => self.tools_call(&params),
            _ => Err((
                -32601,
                format!("method {method:?} is not available through airlock"),
            )),
        };
        Some(match result {
            Ok(r) => json!({"jsonrpc": "2.0", "id": id, "result": r}),
            Err((code, m)) => rpc_error(&id, code, &m),
        })
    }

    fn initialize(&self, params: &Value) -> Value {
        let requested = params
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or("");
        let version = if PROTOCOL_VERSIONS.contains(&requested) {
            requested
        } else {
            PROTOCOL_VERSIONS[0]
        };
        json!({
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "airlock", "version": env!("CARGO_PKG_VERSION")},
            "instructions": format!(
                "Tool calls pass through the airlock gateway for task {:?}. Destructive and external actions return a dry run and wait for a person's approval; repeat the identical call after approval.",
                self.task
            ),
        })
    }

    fn tools_list(&mut self) -> Value {
        let grant = &self.policy.grants[&self.task];
        let mut by_upstream: std::collections::BTreeMap<String, Vec<String>> = Default::default();
        for name in &grant.tools {
            let t = &self.policy.tools[name];
            by_upstream
                .entry(t.upstream.clone())
                .or_default()
                .push(name.clone());
        }
        let mut tools = Vec::new();
        for (upstream, granted) in by_upstream {
            let defs = match self.upstreams.list_tools(&upstream) {
                Ok(d) => d,
                Err(e) => {
                    eprintln!("airlock: could not list tools from upstream {upstream:?}: {e}");
                    continue;
                }
            };
            for def in defs {
                let Some(local) = def.get("name").and_then(Value::as_str) else {
                    continue;
                };
                let full = format!("{upstream}.{local}");
                if !granted.contains(&full) {
                    continue;
                }
                let class = self.policy.tools[&full].class;
                let mut def = def.clone();
                let desc = def
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                def["name"] = json!(full);
                def["description"] = json!(format!("[airlock class: {class}] {desc}")
                    .trim_end()
                    .to_string());
                tools.push(def);
            }
        }
        json!({"tools": tools})
    }

    fn tools_call(&mut self, params: &Value) -> Result<Value, (i64, String)> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or((-32602, "tools/call needs a string `name`".to_string()))?
            .to_string();
        let args = match params.get("arguments") {
            None | Some(Value::Null) => json!({}),
            Some(v @ Value::Object(_)) => v.clone(),
            Some(_) => return Err((-32602, "`arguments` must be an object".into())),
        };
        Ok(self.call(&name, &args))
    }

    /// Run one tool call through the pipeline and, if allowed, upstream.
    pub fn call(&mut self, name: &str, args: &Value) -> Value {
        let now = (self.clock)();
        let eval = self.evaluate(name, args, now);
        let redacted = redact(args, &self.policy.audit.redact);
        let class_str = eval.class.map(|c| c.as_str().to_string());
        let base = Record {
            session: self.session.clone(),
            task: self.task.clone(),
            event: "call".into(),
            tool: Some(name.to_string()),
            args: redacted,
            class: class_str.clone(),
            tainted_args: eval.tainted.clone(),
            ..Default::default()
        };

        match eval.verdict {
            Verdict::Deny { reason } => {
                self.log(Record {
                    decision: "denied".into(),
                    reason: reason.clone(),
                    ..base
                });
                if eval.tripped || eval.class.is_some_and(Class::is_high_risk) {
                    self.alert(
                        if eval.tripped {
                            "circuit_breaker_tripped"
                        } else {
                            "blocked"
                        },
                        name,
                        &reason,
                        None,
                    );
                }
                tool_error(&format!("airlock denied this call: {reason}"))
            }
            Verdict::Hold { pending, fresh } => {
                let reason = format!("held for approval: {}", pending.reasons.join("; "));
                self.log(Record {
                    decision: "held".into(),
                    reason: reason.clone(),
                    approval_id: Some(pending.id.clone()),
                    ..base
                });
                if fresh {
                    self.alert("approval_needed", name, &reason, Some(&pending.id));
                }
                tool_error(&pending.dry_run)
            }
            Verdict::Allow {
                approval,
                fail_open,
            } => {
                let tool = self.policy.tools[name].clone();
                let provenance = self
                    .policy
                    .upstream(&tool.upstream)
                    .map(|u| u.provenance)
                    .unwrap_or(Provenance::Untrusted);
                let (decision, reason) = match (&approval, &fail_open) {
                    (_, Some(w)) => (
                        "allowed_fail_open",
                        format!("read allowed despite evaluation error (fail open): {w}"),
                    ),
                    (Some(p), None) => {
                        ("allowed", format!("approved by {}", p.approvers.join(", ")))
                    }
                    (None, None) => ("allowed", "within grant".to_string()),
                };
                let logged = self.audit.append(Record {
                    decision: decision.into(),
                    reason,
                    result_provenance: Some(provenance.as_str().into()),
                    approval_id: approval.as_ref().map(|p| p.id.clone()),
                    approvers: approval
                        .as_ref()
                        .map(|p| p.approvers.clone())
                        .unwrap_or_default(),
                    ..base.clone()
                });
                if let Err(e) = logged {
                    if tool.class == Class::Read {
                        eprintln!(
                            "airlock: WARNING audit write failed, read allowed (fail open): {e}"
                        );
                    } else {
                        return tool_error(&format!(
                            "airlock denied this call: audit log unavailable, writes fail closed ({e})"
                        ));
                    }
                }
                match self
                    .upstreams
                    .call_tool(&tool.upstream, &tool.upstream_tool, args)
                {
                    Ok(mut result) => {
                        if provenance == Provenance::Untrusted {
                            self.taint.record(&result);
                        }
                        label(&mut result, provenance);
                        result
                    }
                    Err(e) => {
                        self.log(Record {
                            event: "upstream_error".into(),
                            decision: "info".into(),
                            reason: e.clone(),
                            ..base
                        });
                        tool_error(&format!("upstream {} failed: {e}", tool.upstream))
                    }
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // The decision pipeline
    // ------------------------------------------------------------------

    /// Decide about one call. Pure policy: nothing the agent says about
    /// itself is an input.
    pub fn evaluate(&mut self, name: &str, args: &Value, now: i64) -> Evaluation {
        let deny = |class, reason: String, tainted: Vec<String>| Evaluation {
            class,
            verdict: Verdict::Deny { reason },
            tainted,
            tripped: false,
        };

        // 0. The tool must be defined; its class comes from policy.
        let Some(tool) = self.policy.tools.get(name).cloned() else {
            return deny(
                None,
                format!("tool {name:?} is not defined in policy"),
                vec![],
            );
        };
        let class = Some(tool.class);
        let mut fail_open = None;

        // Kill switch.
        match freeze::is_frozen(&self.state_dir) {
            Ok(true) if tool.class != Class::Read => {
                return deny(
                    class,
                    "all agent writes are frozen (kill switch); only reads are allowed".into(),
                    vec![],
                );
            }
            Ok(_) => {}
            Err(e) if tool.class == Class::Read => fail_open = Some(e.to_string()),
            Err(e) => {
                return deny(
                    class,
                    format!("cannot determine freeze state, writes fail closed: {e}"),
                    vec![],
                )
            }
        }

        // 1. Grant: tool granted and grant unexpired.
        let grant = &self.policy.grants[&self.task];
        if !grant.tools.contains(name) {
            return deny(
                class,
                format!("tool {name} is not in the grant for task {:?}", self.task),
                vec![],
            );
        }
        if now >= grant.expires.unix_timestamp() {
            return deny(
                class,
                format!(
                    "grant for task {:?} expired at {}",
                    self.task,
                    rfc3339(grant.expires.unix_timestamp())
                ),
                vec![],
            );
        }

        // 2. Deny patterns (absolute) and argument limits.
        if let Err(r) = check_deny_patterns(&tool, args) {
            return deny(class, r, vec![]);
        }
        if let Some(limits) = grant.limits.get(name) {
            for l in limits {
                if let Err(r) = check_limit(l, args) {
                    return deny(class, format!("limit violated: {r}"), vec![]);
                }
            }
        }

        // 3. Provenance.
        let tainted = self.taint.tainted_paths(args);

        // A budget unit is charged once per logical action. For reads and
        // reversible writes that is each call. For destructive/external calls
        // it is the *fresh* attempt that opens an approval; a repeated hold or
        // the approved retry of that same call is not charged again, so one
        // action never counts twice.
        let per_hour = grant.budgets.get(name).copied();

        if !tool.class.is_high_risk() {
            if let Some(per_hour) = per_hour {
                match self.budgets.consume(name, per_hour, now) {
                    BudgetCheck::Ok => {}
                    BudgetCheck::JustTripped(r) => {
                        return Evaluation {
                            class,
                            verdict: Verdict::Deny { reason: r },
                            tainted,
                            tripped: true,
                        };
                    }
                    BudgetCheck::Tripped(r) => return deny(class, r, tainted),
                }
            }
            return Evaluation {
                class,
                verdict: Verdict::Allow {
                    approval: None,
                    fail_open,
                },
                tainted,
                tripped: false,
            };
        }

        // 4. Destructive and external calls always need a person. An already
        // open approval for this exact call is resolved first, without
        // charging budget again.
        let hash = args_hash(name, args);
        let existing = match self
            .approvals
            .find_for_call(&self.session, name, &hash, now)
        {
            Ok(e) => e,
            Err(e) => {
                return deny(
                    class,
                    format!("approval store unavailable, fails closed: {e}"),
                    tainted,
                )
            }
        };
        if let Some(p) = existing {
            return match p.status(now) {
                Status::Approved => match self.approvals.consume(&p.id, now) {
                    Ok(p) => Evaluation {
                        class,
                        verdict: Verdict::Allow {
                            approval: Some(p),
                            fail_open: None,
                        },
                        tainted,
                        tripped: false,
                    },
                    Err(e) => deny(
                        class,
                        format!("could not use approval {}: {e}", p.id),
                        tainted,
                    ),
                },
                Status::Rejected => deny(
                    class,
                    format!(
                        "a person rejected this call ({}, by {})",
                        p.id,
                        p.rejected_by.unwrap_or_default()
                    ),
                    tainted,
                ),
                _ => Evaluation {
                    class,
                    verdict: Verdict::Hold {
                        pending: p,
                        fresh: false,
                    },
                    tainted,
                    tripped: false,
                },
            };
        }

        // 5. A fresh high-risk attempt: charge budget now, then open a hold.
        if let Some(per_hour) = per_hour {
            match self.budgets.consume(name, per_hour, now) {
                BudgetCheck::Ok => {}
                BudgetCheck::JustTripped(r) => {
                    return Evaluation {
                        class,
                        verdict: Verdict::Deny { reason: r },
                        tainted,
                        tripped: true,
                    };
                }
                BudgetCheck::Tripped(r) => return deny(class, r, tainted),
            }
        }

        let mut reasons = vec![format!(
            "{} calls always need a person's approval",
            tool.class
        )];
        if !tainted.is_empty() {
            reasons.push(format!(
                "argument(s) {} derived from untrusted content seen earlier in this session",
                tainted.join(", ")
            ));
        }
        let required = if tool.two_person { 2 } else { 1 };
        let redacted = redact(args, &self.policy.audit.redact);
        let created = self.approvals.create(
            &self.session,
            &self.task,
            name,
            tool.class.as_str(),
            &hash,
            redacted.clone(),
            |id, expires| {
                dry_run_text(
                    name,
                    &tool.upstream,
                    tool.class,
                    &redacted,
                    &reasons,
                    id,
                    required,
                    expires,
                )
            },
            reasons.clone(),
            required,
            self.policy.gateway.approval_ttl_secs,
        );
        match created {
            Ok(p) => Evaluation {
                class,
                verdict: Verdict::Hold {
                    pending: p,
                    fresh: true,
                },
                tainted,
                tripped: false,
            },
            Err(e) => deny(
                class,
                format!("approval store unavailable, fails closed: {e}"),
                tainted,
            ),
        }
    }

    fn log(&self, rec: Record) {
        if let Err(e) = self.audit.append(rec) {
            eprintln!("airlock: WARNING audit write failed: {e}");
        }
    }

    fn alert(&self, kind: &str, tool: &str, reason: &str, approval_id: Option<&str>) {
        self.notifier.alert(&json!({
            "ts": rfc3339((self.clock)()),
            "kind": kind,
            "session": self.session,
            "task": self.task,
            "tool": tool,
            "reason": reason,
            "approval_id": approval_id,
        }));
    }
}

#[allow(clippy::too_many_arguments)]
fn dry_run_text(
    tool: &str,
    upstream: &str,
    class: Class,
    args: &Value,
    reasons: &[String],
    id: &str,
    required: usize,
    expires: i64,
) -> String {
    let pretty = serde_json::to_string_pretty(args).unwrap_or_default();
    let mut s = format!(
        "DRY RUN: nothing was executed.\nWould call {tool} (class: {class}) on upstream {upstream:?} with arguments:\n{pretty}\nHeld because:\n"
    );
    for r in reasons {
        s.push_str(&format!("- {r}\n"));
    }
    s.push_str(&format!(
        "Approval {id} needs {required} approver(s) and expires at {}. A person must decide outside this connection; this connection cannot approve it. If it is approved, repeat the identical call.",
        rfc3339(expires)
    ));
    s
}

fn rpc_error(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn tool_error(text: &str) -> Value {
    json!({"content": [{"type": "text", "text": text}], "isError": true})
}

fn label(result: &mut Value, provenance: Provenance) {
    if let Some(obj) = result.as_object_mut() {
        let meta = obj.entry("_meta").or_insert_with(|| json!({}));
        if let Some(m) = meta.as_object_mut() {
            m.insert("airlock/provenance".into(), json!(provenance.as_str()));
        }
    }
}
