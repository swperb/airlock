//! The `airlock` gateway binary's library half: the MCP transports facing the
//! agent (stdio and streamable HTTP) and the upstream connections (stdio and
//! streamable HTTP) behind the [`airlock_core::Upstreams`] trait.

pub mod http;
pub mod stdio;
pub mod upstream;

pub use airlock_core as core;

use std::path::Path;

use airlock_core::gateway::{FileNotifier, TaskState};
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
    let upstreams = upstream::PolicyUpstreams::from_policy(&policy);
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

/// Start the gateway as a streamable HTTP service for one task. Every MCP
/// session gets its own gateway and upstream connections; taint and budgets
/// are shared across all of them.
pub fn serve_http(
    policy_path: &Path,
    task: &str,
    cfg: http::HttpConfig,
) -> Result<http::HttpGateway, Box<dyn std::error::Error>> {
    let policy = Policy::load(policy_path)?;
    if !policy.grants.contains_key(task) {
        return Err(format!("no grant for task {task:?}").into());
    }
    let state = TaskState::shared(&policy);
    let task = task.to_string();
    let factory = move |sid: &str| {
        let upstreams = upstream::PolicyUpstreams::from_policy(&policy);
        let notifier = Box::new(FileNotifier {
            path: policy.state_dir().join("alerts.jsonl"),
        });
        Gateway::with_shared_state(
            policy.clone(),
            &task,
            sid,
            upstreams,
            notifier,
            state.clone(),
        )
        .map_err(|e| e.to_string())
    };
    Ok(http::start(cfg, Box::new(factory))?)
}
