//! The `airlock` command-line interface.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use airlock_core::approvals::{ApprovalStore, Pending, Status};
use airlock_core::audit::{self, Verification};
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
    /// Check that a policy file is valid.
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
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Validate the policy file and print a summary.
    Check {
        #[arg(long)]
        policy: PathBuf,
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
        Cmd::Policy {
            what: PolicyCmd::Check { policy },
        } => cmd_policy_check(&policy),
        Cmd::Approve(a) => cmd_decide(a, true),
        Cmd::Reject(a) => cmd_decide(a, false),
        Cmd::Pending(s) => cmd_pending(&s),
        Cmd::Freeze(a) => cmd_freeze(a),
        Cmd::Unfreeze(s) => cmd_unfreeze(&s),
        Cmd::Audit { what } => cmd_audit(what),
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
    airlock::run_gateway(&a.policy, &a.task, a.session)?;
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
    let server = airlock::serve_http(&a.policy, &a.task, cfg)?;
    eprintln!(
        "airlock: serving task {:?} on {} ({auth})",
        a.task,
        server.url()
    );
    server.join();
    Ok(ExitCode::SUCCESS)
}

fn cmd_policy_check(path: &Path) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let p = Policy::load(path)?;
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
