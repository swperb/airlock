//! The `airlock` command-line interface.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use airlock_core::approvals::{ApprovalStore, Pending, Status};
use airlock_core::audit::{self, Verification};
use airlock_core::signing::{self, PolicySignature, PrivateKey, Serial, TrustedKeys};
use airlock_core::util::now_unix;
use airlock_core::{freeze, Policy};
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "airlock",
    version,
    about = "An MCP gateway that deterministically limits what AI agents can do"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the gateway for one task, proxying MCP stdio.
    Run(RunArgs),
    /// Serve the gateway for one task over MCP streamable HTTP.
    Serve(ServeArgs),
    /// Generate an Ed25519 key pair for signing policies.
    Keygen {
        /// Path prefix: writes <OUT>.key (private, mode 0600) and <OUT>.pub.
        #[arg(long)]
        out: PathBuf,
        /// Comment stored with the public key, e.g. who holds it.
        #[arg(long, default_value = "")]
        comment: String,
    },
    /// Check, sign or verify a policy file.
    Policy {
        #[command(subcommand)]
        what: PolicyCmd,
    },
    /// Approve a pending request (out-of-band; the agent cannot do this).
    Approve(DecideArgs),
    /// Reject a pending request.
    Reject(DecideArgs),
    /// List pending approvals.
    Pending(StateArgs),
    /// Freeze all agent writes (kill switch).
    Freeze(FreezeArgs),
    /// Lift the freeze.
    Unfreeze(StateArgs),
    /// Audit log commands.
    Audit {
        #[command(subcommand)]
        what: AuditCmd,
    },
    /// Show or reset budgets and circuit breakers.
    Budget {
        #[command(subcommand)]
        what: BudgetCmd,
    },
}

#[derive(Subcommand)]
enum BudgetCmd {
    /// Show each task's budget use in the last hour and any open breakers.
    Status(StateArgs),
    /// Close a tripped circuit breaker and clear its window (out-of-band;
    /// the agent cannot do this). Recorded in the audit log.
    Reset {
        /// Task whose budget to reset.
        #[arg(long)]
        task: String,
        /// Only this tool (e.g. mail.send); default is every tool of the task.
        #[arg(long)]
        tool: Option<String>,
        /// Name of the person resetting it.
        #[arg(long)]
        by: String,
        #[command(flatten)]
        state: StateArgs,
    },
}

/// Policy signature enforcement. When a trusted-keys file is given, the
/// policy must carry a valid signature (`<policy>.sig`) from one of its keys.
#[derive(Args, Clone)]
struct TrustArgs {
    #[arg(long, env = "AIRLOCK_TRUSTED_KEYS")]
    trusted_keys: Option<PathBuf>,
}

impl TrustArgs {
    fn load(&self) -> Result<Option<TrustedKeys>, Box<dyn std::error::Error>> {
        Ok(match &self.trusted_keys {
            Some(p) => Some(TrustedKeys::load(p)?),
            None => None,
        })
    }
}

#[derive(Args)]
struct RunArgs {
    #[arg(long)]
    policy: PathBuf,
    /// The task whose grant applies to this session.
    #[arg(long)]
    task: String,
    /// Session id (defaults to a timestamp-based id).
    #[arg(long)]
    session: Option<String>,
    #[command(flatten)]
    trust: TrustArgs,
}

#[derive(Args)]
struct ServeArgs {
    #[arg(long)]
    policy: PathBuf,
    /// The task whose grant applies to every session on this listener.
    #[arg(long)]
    task: String,
    /// Address to listen on. Non-loopback addresses require AIRLOCK_HTTP_TOKEN.
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: String,
    /// Allow browser requests from this Origin (repeatable). By default any
    /// request carrying an Origin header is refused.
    #[arg(long = "allow-origin")]
    allow_origin: Vec<String>,
    #[arg(long, default_value_t = 8)]
    workers: usize,
    #[arg(long, default_value_t = 256)]
    max_sessions: usize,
    /// End sessions idle for this many seconds.
    #[arg(long, default_value_t = 3600)]
    idle_timeout_secs: u64,
    #[command(flatten)]
    trust: TrustArgs,
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Validate the policy file and print a summary.
    Check {
        #[arg(long)]
        policy: PathBuf,
        #[command(flatten)]
        trust: TrustArgs,
    },
    /// Sign a policy, writing <POLICY>.sig.
    Sign {
        #[arg(long)]
        policy: PathBuf,
        /// Private key file from `airlock keygen`.
        #[arg(long)]
        key: PathBuf,
        /// Serial number; defaults to one more than the existing signature's.
        /// Gateways refuse a serial lower than one they have accepted.
        #[arg(long)]
        serial: Option<u64>,
    },
    /// Verify a policy's signature against trusted keys.
    Verify {
        #[arg(long)]
        policy: PathBuf,
        #[arg(long, env = "AIRLOCK_TRUSTED_KEYS")]
        trusted_keys: PathBuf,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Verify the hash chain.
    Verify(StateArgs),
    /// Print the most recent entries.
    Tail {
        #[command(flatten)]
        state: StateArgs,
        #[arg(long, default_value_t = 20)]
        n: usize,
    },
}

/// Ways to locate the state directory and audit log: either from a policy
/// file, or by giving the paths directly (so an operator on another machine
/// can act without the policy).
#[derive(Args, Clone)]
struct StateArgs {
    #[arg(long)]
    policy: Option<PathBuf>,
    #[arg(long)]
    state_dir: Option<PathBuf>,
    #[arg(long)]
    audit: Option<PathBuf>,
}

#[derive(Args)]
struct DecideArgs {
    id: String,
    /// Name of the person approving or rejecting (recorded in the audit log).
    #[arg(long)]
    by: String,
    #[command(flatten)]
    state: StateArgs,
}

#[derive(Args)]
struct FreezeArgs {
    #[arg(long, default_value = "operator")]
    by: String,
    #[command(flatten)]
    state: StateArgs,
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("airlock: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match cli.cmd {
        Cmd::Run(a) => cmd_run(a),
        Cmd::Serve(a) => cmd_serve(a),
        Cmd::Keygen { out, comment } => cmd_keygen(&out, &comment),
        Cmd::Policy { what } => match what {
            PolicyCmd::Check { policy, trust } => cmd_policy_check(&policy, &trust),
            PolicyCmd::Sign {
                policy,
                key,
                serial,
            } => cmd_policy_sign(&policy, &key, serial),
            PolicyCmd::Verify {
                policy,
                trusted_keys,
            } => cmd_policy_verify(&policy, &trusted_keys),
        },
        Cmd::Approve(a) => cmd_decide(a, true),
        Cmd::Reject(a) => cmd_decide(a, false),
        Cmd::Pending(s) => cmd_pending(&s),
        Cmd::Freeze(a) => cmd_freeze(a),
        Cmd::Unfreeze(s) => cmd_unfreeze(&s),
        Cmd::Audit { what } => cmd_audit(what),
        Cmd::Budget { what } => cmd_budget(what),
    }
}

impl StateArgs {
    fn state_dir(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        if let Some(d) = &self.state_dir {
            return Ok(d.clone());
        }
        if let Some(p) = &self.policy {
            return Ok(Policy::load(p)?.state_dir());
        }
        Err("need --state-dir or --policy".into())
    }

    fn audit_path(&self) -> Result<PathBuf, Box<dyn std::error::Error>> {
        if let Some(a) = &self.audit {
            return Ok(a.clone());
        }
        if let Some(p) = &self.policy {
            return Ok(Policy::load(p)?.audit_path());
        }
        Ok(self.state_dir()?.join("audit.jsonl"))
    }
}

fn cmd_run(a: RunArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let trusted = a.trust.load()?;
    airlock::run_gateway(&a.policy, &a.task, a.session, trusted.as_ref())?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_serve(a: ServeArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let mut cfg = airlock::http::HttpConfig::new(&a.listen);
    // The token comes from the environment, never the command line, so it
    // does not show up in process listings or shell history.
    cfg.token = std::env::var("AIRLOCK_HTTP_TOKEN")
        .ok()
        .filter(|t| !t.is_empty());
    cfg.allowed_origins = a.allow_origin;
    cfg.workers = a.workers;
    cfg.max_sessions = a.max_sessions;
    cfg.idle_timeout = std::time::Duration::from_secs(a.idle_timeout_secs.max(1));
    let auth = if cfg.token.is_some() {
        "bearer token required"
    } else {
        "no token (loopback only)"
    };
    let trusted = a.trust.load()?;
    let server = airlock::serve_http(&a.policy, &a.task, cfg, trusted.as_ref())?;
    eprintln!(
        "airlock: serving task {:?} on {} ({auth})",
        a.task,
        server.url()
    );
    server.join();
    Ok(ExitCode::SUCCESS)
}

fn cmd_policy_check(
    path: &Path,
    trust: &TrustArgs,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let trusted = trust.load()?;
    let loaded = signing::load_policy(path, trusted.as_ref(), Serial::CheckOnly)?;
    let p = loaded.policy;
    println!(
        "policy OK: {} upstream(s), {} tool(s), {} grant(s)",
        p.upstreams.len(),
        p.tools.len(),
        p.grants.len()
    );
    for (task, g) in &p.grants {
        println!(
            "  grant {task:?}: {} tool(s), expires {}",
            g.tools.len(),
            g.expires
        );
    }
    println!("  state dir: {}", p.state_dir().display());
    println!("  audit log: {}", p.audit_path().display());
    println!("  sha256:    {}", loaded.sha256);
    match loaded.verified {
        Some(v) => println!(
            "  signature: valid, key {} ({}), serial {}",
            v.key_id, v.key_comment, v.serial
        ),
        None => println!("  signature: not checked (no trusted keys given)"),
    }
    Ok(ExitCode::SUCCESS)
}

fn write_new_file(path: &Path, contents: &str, private: bool) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut f = opts.open(path)?;
    f.write_all(contents.as_bytes())?;
    f.sync_all()
}

fn with_suffix(prefix: &Path, suffix: &str) -> PathBuf {
    let mut s = prefix.as_os_str().to_owned();
    s.push(suffix);
    PathBuf::from(s)
}

fn cmd_keygen(out: &Path, comment: &str) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let (key_path, pub_path) = (with_suffix(out, ".key"), with_suffix(out, ".pub"));
    for p in [&key_path, &pub_path] {
        if p.exists() {
            return Err(format!(
                "{} already exists; refusing to overwrite a key",
                p.display()
            )
            .into());
        }
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| format!("no system randomness: {e}"))?;
    let key = PrivateKey::from_seed(seed);
    seed.fill(0);
    write_new_file(&key_path, &key.to_file_text(), true)?;
    write_new_file(
        &pub_path,
        &signing::public_key_line(&key.public(), comment),
        false,
    )?;
    println!(
        "private key: {}  (keep it offline; anyone holding it can sign policies)",
        key_path.display()
    );
    println!(
        "public key:  {}  (key id {})",
        pub_path.display(),
        signing::key_id(&key.public())
    );
    println!("Give gateways the public key with --trusted-keys or AIRLOCK_TRUSTED_KEYS.");
    Ok(ExitCode::SUCCESS)
}

fn cmd_policy_sign(
    policy: &Path,
    key: &Path,
    serial: Option<u64>,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(policy).map_err(|e| format!("reading {}: {e}", policy.display()))?;
    // Never sign a policy the gateway would reject.
    let text = String::from_utf8(bytes.clone()).map_err(|_| "policy file is not UTF-8")?;
    let base = policy.parent().map(Path::to_path_buf).unwrap_or_default();
    Policy::parse(&text, base)?;
    let sig_path = signing::signature_path(policy);
    let previous = match std::fs::read_to_string(&sig_path) {
        Ok(t) => Some(PolicySignature::parse(&t)?.serial),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let serial = match (serial, previous) {
        (Some(s), Some(prev)) if s <= prev => {
            return Err(format!(
                "serial {s} is not higher than the existing signature's serial {prev}"
            )
            .into())
        }
        (Some(s), _) => s,
        (None, Some(prev)) => prev.checked_add(1).ok_or("serial overflow")?,
        (None, None) => 1,
    };
    let key = PrivateKey::load(key)?;
    let sig = signing::sign(&bytes, serial, &key);
    let tmp = with_suffix(&sig_path, ".tmp");
    std::fs::write(&tmp, sig.to_file_text())?;
    std::fs::rename(&tmp, &sig_path)?;
    println!(
        "signed {} with key {} at serial {serial}: {}",
        policy.display(),
        sig.key_id,
        sig_path.display()
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_policy_verify(
    policy: &Path,
    trusted_keys: &Path,
) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let trusted = TrustedKeys::load(trusted_keys)?;
    let loaded = signing::load_policy(policy, Some(&trusted), Serial::CheckOnly)?;
    let v = loaded
        .verified
        .expect("verified when trusted keys are given");
    println!(
        "signature OK: {} is signed by key {} ({}) at serial {}",
        policy.display(),
        v.key_id,
        v.key_comment,
        v.serial
    );
    println!("sha256: {}", loaded.sha256);
    Ok(ExitCode::SUCCESS)
}

fn cmd_decide(a: DecideArgs, approve: bool) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let store = ApprovalStore::new(&a.state.state_dir()?);
    let audit = audit::AuditLog::open(&a.state.audit_path()?)?;
    let now = now_unix();
    let p = if approve {
        store.approve(&a.id, &a.by, now)?
    } else {
        store.reject(&a.id, &a.by, now)?
    };
    audit.append(audit::Record {
        session: p.session.clone(),
        task: p.task.clone(),
        event: if approve { "approve" } else { "reject" }.into(),
        tool: Some(p.tool.clone()),
        args: p.args.clone(),
        class: Some(p.class.clone()),
        decision: if approve { "approved" } else { "rejected" }.into(),
        reason: format!(
            "{} by {}",
            if approve { "approved" } else { "rejected" },
            a.by
        ),
        approval_id: Some(p.id.clone()),
        approvers: p.approvers.clone(),
        ..Default::default()
    })?;
    match p.status(now) {
        Status::Approved => println!(
            "{} approved by {} and ready; the agent may now repeat the call.",
            p.id,
            join(&p.approvers)
        ),
        Status::Waiting => println!(
            "{} now has {}/{} approvals ({}); still waiting.",
            p.id,
            p.approvers.len(),
            p.required_approvers,
            join(&p.approvers)
        ),
        Status::Rejected => println!("{} rejected by {}.", p.id, a.by),
        _ => println!("{} is now {:?}.", p.id, p.status(now)),
    }
    Ok(ExitCode::SUCCESS)
}

fn join(v: &[String]) -> String {
    if v.is_empty() {
        "none".into()
    } else {
        v.join(", ")
    }
}

fn cmd_pending(s: &StateArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let store = ApprovalStore::new(&s.state_dir()?);
    let now = now_unix();
    let mut any = false;
    for p in store.list()? {
        if matches!(p.status(now), Status::Waiting) {
            any = true;
            print_pending(&p, now);
        }
    }
    if !any {
        println!("no pending approvals.");
    }
    Ok(ExitCode::SUCCESS)
}

fn print_pending(p: &Pending, now: i64) {
    let secs = (p.expires - now).max(0);
    println!("── {} ───────────────────────────", p.id);
    println!(
        "  session {}  task {}  tool {}  class {}",
        p.session, p.task, p.tool, p.class
    );
    println!(
        "  approvers {}/{} ({})",
        p.approvers.len(),
        p.required_approvers,
        join(&p.approvers)
    );
    println!("  expires in {secs}s");
    for r in &p.reasons {
        println!("  reason: {r}");
    }
    println!("{}", indent(&p.dry_run));
    println!(
        "  approve:  airlock approve {} --by <you> --state-dir <dir>",
        p.id
    );
}

fn indent(s: &str) -> String {
    s.lines()
        .map(|l| format!("    {l}"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn cmd_freeze(a: FreezeArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let dir = a.state.state_dir()?;
    freeze::freeze(&dir, &a.by)?;
    if let Ok(audit) = audit::AuditLog::open(&a.state.audit_path()?) {
        let _ = audit.append(audit::Record {
            event: "freeze".into(),
            decision: "info".into(),
            reason: format!("all agent writes frozen by {}", a.by),
            ..Default::default()
        });
    }
    println!(
        "FROZEN: all agent writes are now refused ({}). Lift with `airlock unfreeze`.",
        freeze::freeze_path(&dir).display()
    );
    Ok(ExitCode::SUCCESS)
}

fn cmd_unfreeze(s: &StateArgs) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let dir = s.state_dir()?;
    if freeze::unfreeze(&dir)? {
        if let Ok(audit) = audit::AuditLog::open(&s.audit_path()?) {
            let _ = audit.append(audit::Record {
                event: "unfreeze".into(),
                decision: "info".into(),
                reason: "freeze lifted".into(),
                ..Default::default()
            });
        }
        println!("freeze lifted; agent writes are allowed again.");
    } else {
        println!("was not frozen.");
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_budget(what: BudgetCmd) -> Result<ExitCode, Box<dyn std::error::Error>> {
    use airlock_core::budget::{self, BudgetStore};
    match what {
        BudgetCmd::Status(state) => {
            let now = now_unix();
            let tasks = budget::list(&state.state_dir()?, now)?;
            if tasks.is_empty() {
                println!("no budget use recorded.");
            }
            for (task, tools) in tasks {
                println!("task {task:?}");
                for t in tools {
                    match t.tripped_at {
                        Some(at) => println!(
                            "  {:<28} {:>5} in the last hour  BREAKER OPEN since {}",
                            t.tool,
                            t.used_last_hour,
                            airlock_core::util::rfc3339(at)
                        ),
                        None => {
                            println!("  {:<28} {:>5} in the last hour", t.tool, t.used_last_hour)
                        }
                    }
                }
            }
            Ok(ExitCode::SUCCESS)
        }
        BudgetCmd::Reset {
            task,
            tool,
            by,
            state,
        } => {
            if by.trim().is_empty() {
                return Err("--by must name the person resetting the budget".into());
            }
            let store = BudgetStore::new(&state.state_dir()?, &task);
            let reset = store.reset(tool.as_deref())?;
            if reset.is_empty() {
                println!(
                    "nothing to reset for task {task:?}{}.",
                    tool.map(|t| format!(", tool {t}")).unwrap_or_default()
                );
                return Ok(ExitCode::SUCCESS);
            }
            audit::AuditLog::open(&state.audit_path()?)?.append(audit::Record {
                task: task.clone(),
                event: "budget_reset".into(),
                tool: tool.clone(),
                decision: "info".into(),
                reason: format!("budget and breaker reset by {by} for {}", reset.join(", ")),
                args: serde_json::json!({"tools": reset, "by": by}),
                ..Default::default()
            })?;
            println!("reset {} for task {task:?}.", reset.join(", "));
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn cmd_audit(what: AuditCmd) -> Result<ExitCode, Box<dyn std::error::Error>> {
    match what {
        AuditCmd::Verify(s) => {
            let path = s.audit_path()?;
            match audit::verify(&path)? {
                Verification::Ok { entries } => {
                    println!(
                        "audit log OK: {entries} entr{} verified, chain intact.",
                        if entries == 1 { "y" } else { "ies" }
                    );
                    Ok(ExitCode::SUCCESS)
                }
                Verification::Broken { line, reason } => {
                    println!("audit log BROKEN at line {line}: {reason}");
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        AuditCmd::Tail { state, n } => {
            let entries = audit::read_entries(&state.audit_path()?)?;
            let out = std::io::stdout();
            let mut out = out.lock();
            for e in entries.iter().rev().take(n).rev() {
                let tool = e.tool.as_deref().unwrap_or("-");
                writeln!(
                    out,
                    "#{:<4} {} {:<18} {:<10} {:<22} {}",
                    e.seq, e.ts, e.event, e.decision, tool, e.reason
                )?;
                if !e.tainted_args.is_empty() {
                    writeln!(out, "        tainted: {}", e.tainted_args.join(", "))?;
                }
            }
            Ok(ExitCode::SUCCESS)
        }
    }
}
