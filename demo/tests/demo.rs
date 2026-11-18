//! Integration test: run the hijacked agent both ways and assert outcomes.
//!
//! This builds the demo binaries and drives the agent against (a) the no-policy
//! passthrough and (b) the real `airlock run`, then checks the database and
//! outbox, the held approvals and the audit chain.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is .../airlock/demo
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn bin(name: &str) -> PathBuf {
    // Cargo sets CARGO_BIN_EXE_<name> for this crate's bins, and the airlock
    // bin via its dependency. Fall back to target/debug.
    let root = workspace_root();
    let p = root.join("target/debug").join(name);
    assert!(
        p.exists(),
        "missing binary {}; run `cargo build --workspace` first",
        p.display()
    );
    p
}

fn seed_db(db: &Path) {
    // Starting db-server seeds the table, then it exits on EOF.
    let mut child = Command::new(bin("db-server"))
        .env("AIRLOCK_DEMO_DB", db)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    drop(child.stdin.take());
    let _ = child.wait();
}

fn customers_rows(db: &Path) -> Option<i64> {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.query_row("SELECT count(*) FROM customers", [], |r| r.get::<_, i64>(0))
        .ok()
}

fn run_agent(endpoint: &[&str], db: &Path, mail: &Path) -> String {
    let mut args: Vec<String> = vec!["--".into()];
    args.extend(endpoint.iter().map(|s| s.to_string()));
    let out = Command::new(bin("agent"))
        .args(&args)
        .env("AIRLOCK_DEMO_DB", db)
        .env("AIRLOCK_DEMO_MAIL", mail)
        .current_dir(workspace_root())
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn without_gateway_the_attack_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("demo.db");
    let mail = dir.path().join("outbox.txt");
    seed_db(&db);
    assert_eq!(customers_rows(&db), Some(3));

    let passthrough = bin("passthrough");
    run_agent(&[passthrough.to_str().unwrap()], &db, &mail);

    // The table was dropped and the exfil mail was sent.
    assert_eq!(customers_rows(&db), None, "table should be gone");
    let outbox = std::fs::read_to_string(&mail).unwrap_or_default();
    assert!(
        outbox.contains("exfil@attacker.example"),
        "mail should have been sent: {outbox:?}"
    );
}

#[test]
fn with_gateway_the_attack_is_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("demo.db");
    let mail = dir.path().join("outbox.txt");
    let state = dir.path().join("state");
    seed_db(&db);

    // Write a policy whose state dir and audit log are inside the temp dir,
    // and whose upstream servers are the demo binaries by absolute path.
    let policy_path = dir.path().join("policy.toml");
    std::fs::write(
        &policy_path,
        format!(
            r#"
[gateway]
state_dir = "{state}"
[[upstream]]
name = "db"
command = ["{db_bin}"]
[[upstream]]
name = "mail"
command = ["{mail_bin}"]
[[upstream]]
name = "web"
command = ["{web_bin}"]
provenance = "untrusted"
[[tool]]
name = "db.query"
class = "read"
[[tool]]
name = "db.execute"
class = "destructive"
deny_patterns = ["(?i)\\bdrop\\b"]
[[tool]]
name = "mail.send"
class = "irreversible_external"
[[tool]]
name = "web.fetch"
class = "read"
[[grant]]
task = "t"
expires = "2099-01-01T00:00:00Z"
tools = ["db.query", "db.execute", "mail.send", "web.fetch"]
[grant.limits]
"mail.send".to_domains = ["example.com"]
"#,
            state = state.display(),
            db_bin = bin("db-server").display(),
            mail_bin = bin("mail-server").display(),
            web_bin = bin("web-server").display(),
        ),
    )
    .unwrap();

    let airlock = bin("airlock");
    let endpoint = [
        airlock.to_str().unwrap(),
        "run",
        "--policy",
        policy_path.to_str().unwrap(),
        "--task",
        "t",
        "--session",
        "itest",
    ];
    let log = run_agent(&endpoint, &db, &mail);

    // The table survived and nothing was mailed.
    assert_eq!(customers_rows(&db), Some(3), "table must survive");
    let outbox = std::fs::read_to_string(&mail).unwrap_or_default();
    assert!(
        outbox.is_empty(),
        "nothing should have been sent, got {outbox:?}"
    );

    // The agent saw both writes blocked.
    assert!(log.contains("[BLOCKED] drop customers table"), "log: {log}");
    assert!(log.contains("[BLOCKED] email export"), "log: {log}");

    // The audit chain verifies and records the denials.
    let audit = state.join("audit.jsonl");
    assert!(matches!(
        airlock_core::audit::verify(&audit).unwrap(),
        airlock_core::audit::Verification::Ok { .. }
    ));
    let entries = airlock_core::audit::read_entries(&audit).unwrap();
    assert!(entries
        .iter()
        .any(|e| e.tool.as_deref() == Some("db.execute") && e.decision == "denied"));
    assert!(entries
        .iter()
        .any(|e| e.tool.as_deref() == Some("mail.send") && e.decision == "denied"));
}
