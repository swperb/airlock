//! The `airlock` gateway binary's library half: MCP stdio transport and a
//! subprocess-backed [`Upstreams`] implementation.
//!
//! Only the stdio transport is implemented in this version. Streamable HTTP is
//! a documented extension point (see the README).

pub mod stdio;
pub mod upstream;

pub use airlock_core as core;

use std::path::Path;

use airlock_core::gateway::FileNotifier;
use airlock_core::{Gateway, Policy};

/// Run the gateway on this process's stdio for one task. Shared by the
/// `airlock run` command and the demo's test harness, so both exercise the
/// same code.
pub fn run_gateway(
    policy_path: &Path,
    task: &str,
    session: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = Policy::load(policy_path)?;
    let session = session.unwrap_or_else(|| format!("sess-{}", airlock_core::util::now_unix()));
    let upstreams = upstream::ProcessUpstreams::from_policy(&policy);
    let notifier = Box::new(FileNotifier {
        path: policy.state_dir().join("alerts.jsonl"),
    });
    let mut gw = Gateway::new(policy, task, &session, upstreams, notifier)?;
    eprintln!(
        "airlock: serving task {task:?} as session {:?} on stdio",
        gw.session()
    );
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    stdio::serve(&mut gw, stdin.lock(), stdout.lock())?;
    Ok(())
}
