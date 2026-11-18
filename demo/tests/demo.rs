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

/// Write a policy whose state dir and audit log are inside `dir`, and whose
/// upstream servers are the demo binaries by absolute path. Returns the policy
/// path and the state dir.
fn write_policy(dir: &Path) -> (PathBuf, PathBuf) {
    let state = dir.join("state");
    let policy_path = dir.join("policy.toml");
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
    (policy_path, state)
}

/// The table survived, nothing was mailed, the agent saw both writes blocked,
/// and the audit chain verifies and records the denials.
fn assert_attack_blocked(db: &Path, mail: &Path, log: &str, state: &Path) {
    assert_eq!(customers_rows(db), Some(3), "table must survive");
    let outbox = std::fs::read_to_string(mail).unwrap_or_default();
    assert!(
        outbox.is_empty(),
        "nothing should have been sent, got {outbox:?}"
    );
    assert!(log.contains("[BLOCKED] drop customers table"), "log: {log}");
    assert!(log.contains("[BLOCKED] email export"), "log: {log}");
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

#[test]
fn with_gateway_the_attack_is_blocked() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("demo.db");
    let mail = dir.path().join("outbox.txt");
    seed_db(&db);
    let (policy_path, state) = write_policy(dir.path());

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
    assert_attack_blocked(&db, &mail, &log, &state);
}

#[test]
fn with_gateway_over_http_the_attack_is_blocked() {
    use std::io::BufRead;

    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("demo.db");
    let mail = dir.path().join("outbox.txt");
    seed_db(&db);
    let (policy_path, state) = write_policy(dir.path());

    // Start `airlock serve` on a free port and read the URL it announces.
    let token = "demo-http-token-0123456789";
    let mut server = Command::new(bin("airlock"))
        .args([
            "serve",
            "--policy",
            policy_path.to_str().unwrap(),
            "--task",
            "t",
            "--listen",
            "127.0.0.1:0",
        ])
        .env("AIRLOCK_HTTP_TOKEN", token)
        .env("AIRLOCK_DEMO_DB", &db)
        .env("AIRLOCK_DEMO_MAIL", &mail)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = std::io::BufReader::new(server.stderr.take().unwrap());
    let mut url = None;
    for _ in 0..20 {
        let mut line = String::new();
        if stderr.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if let Some(rest) = line.split(" on ").nth(1) {
            url = rest.split_whitespace().next().map(str::to_string);
            break;
        }
    }
    let url = url.expect("airlock serve should announce its URL");
    // Keep draining the server's stderr so it never blocks on a full pipe.
    std::thread::spawn(move || for _ in stderr.lines() {});

    let out = Command::new(bin("agent"))
        .args(["--http", &url])
        .env("AIRLOCK_HTTP_TOKEN", token)
        .current_dir(workspace_root())
        .output()
        .unwrap();
    let log = String::from_utf8_lossy(&out.stdout).into_owned();
    let _ = server.kill();
    let _ = server.wait();
    assert_attack_blocked(&db, &mail, &log, &state);
}
