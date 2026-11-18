//! The `airlock` gateway binary's library half: the MCP transports facing the
//! agent (stdio and streamable HTTP) and the upstream connections (stdio and
//! streamable HTTP) behind the [`airlock_core::Upstreams`] trait.

pub mod http;
pub mod stdio;
pub mod upstream;

pub use airlock_core as core;

use std::path::Path;

use airlock_core::audit::{AuditLog, Record};
use airlock_core::gateway::{FileNotifier, TaskState};
use airlock_core::signing::{self, LoadedPolicy, Serial, TrustedKeys};
use airlock_core::{Gateway, Policy};
use serde_json::json;

/// Load the policy for a starting gateway: verify its signature if trusted
/// keys are configured (recording the accepted serial), and write what was
/// loaded to the audit log, so every session can be traced to the exact
/// policy bytes it ran under.
pub fn load_for_gateway(
    policy_path: &Path,
    trusted: Option<&TrustedKeys>,
) -> Result<Policy, Box<dyn std::error::Error>> {
    let LoadedPolicy {
        policy,
        sha256,
        verified,
    } = signing::load_policy(policy_path, trusted, Serial::Record)?;
    let path = policy_path.display().to_string();
    let (reason, details) = match &verified {
        Some(v) => (
            format!(
                "policy loaded, signed by key {} at serial {}",
                v.key_id, v.serial
            ),
            json!({"path": path, "sha256": sha256, "signed": true, "key_id": v.key_id, "key_comment": v.key_comment, "serial": v.serial}),
        ),
        None => {
            eprintln!(
                "airlock: WARNING policy signatures are not checked (no trusted keys configured)"
            );
            (
                "policy loaded without signature checking (no trusted keys configured)".to_string(),
                json!({"path": path, "sha256": sha256, "signed": false}),
            )
        }
    };
    AuditLog::open(&policy.audit_path())?.append(Record {
        event: "policy_loaded".into(),
        decision: "info".into(),
        reason,
        args: details,
        ..Default::default()
    })?;
    Ok(policy)
}

/// Run the gateway on this process's stdio for one task. Shared by the
/// `airlock run` command and the demo's test harness, so both exercise the
/// same code.
pub fn run_gateway(
    policy_path: &Path,
    task: &str,
    session: Option<String>,
    trusted: Option<&TrustedKeys>,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = load_for_gateway(policy_path, trusted)?;
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
    trusted: Option<&TrustedKeys>,
) -> Result<http::HttpGateway, Box<dyn std::error::Error>> {
    let policy = load_for_gateway(policy_path, trusted)?;
    if !policy.grants.contains_key(task) {
        return Err(format!("no grant for task {task:?}").into());
    }
    let state = TaskState::shared(&policy, task);
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
