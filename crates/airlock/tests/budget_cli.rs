//! Persistent budgets through the `airlock` binary: a breaker tripped in one
//! gateway process stays open in the next, until `airlock budget reset`.

use std::io::Write;
use std::process::{Command, Output, Stdio};

const POLICY: &str = r#"
[gateway]
state_dir = "state"

[[upstream]]
name = "db"
command = ["airlock-test-no-such-upstream"]

[[tool]]
name = "db.query"
class = "read"

[[grant]]
task = "t"
expires = "2099-01-01T00:00:00Z"
tools = ["db.query"]
[grant.budget]
"db.query" = { per_hour = 1 }
"#;

fn airlock(dir: &std::path::Path, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(args)
        .current_dir(dir)
        .env_remove("AIRLOCK_TRUSTED_KEYS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(o: &Output) -> String {
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

/// One gateway process: initialize, then `n` identical queries.
fn session(dir: &std::path::Path, n: usize) -> Vec<String> {
    let mut input =
        String::from("{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"initialize\",\"params\":{}}\n");
    for i in 1..=n {
        input.push_str(&format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":{i},\"method\":\"tools/call\",\"params\":{{\"name\":\"db.query\",\"arguments\":{{\"sql\":\"SELECT 1\"}}}}}}\n"
        ));
    }
    let out = stdout(&airlock(
        dir,
        &["run", "--policy", "policy.toml", "--task", "t"],
        &input,
    ));
    out.lines()
        .skip(1)
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["result"]["content"][0]["text"]
                .as_str()
                .unwrap_or("")
                .to_string()
        })
        .collect()
}

#[test]
fn breaker_survives_restart_until_reset() {
    let d = tempfile::tempdir().unwrap();
    std::fs::write(d.path().join("policy.toml"), POLICY).unwrap();

    // First process: the first query spends the budget (the upstream does
    // not exist, so it fails after the charge); the second trips the breaker.
    let first = session(d.path(), 2);
    assert!(first[0].contains("upstream db failed"), "{first:?}");
    assert!(first[1].contains("budget exceeded"), "{first:?}");

    // Restarting the gateway does not help.
    let second = session(d.path(), 1);
    assert!(second[0].contains("circuit breaker open"), "{second:?}");

    let status = stdout(&airlock(
        d.path(),
        &["budget", "status", "--state-dir", "state"],
        "",
    ));
    assert!(
        status.contains("task \"t\"") && status.contains("BREAKER OPEN"),
        "{status}"
    );

    // Reset needs a person's name, and is recorded.
    let unnamed = airlock(
        d.path(),
        &[
            "budget",
            "reset",
            "--task",
            "t",
            "--by",
            " ",
            "--state-dir",
            "state",
        ],
        "",
    );
    assert!(!unnamed.status.success());
    let reset = stdout(&airlock(
        d.path(),
        &[
            "budget",
            "reset",
            "--task",
            "t",
            "--tool",
            "db.query",
            "--by",
            "alice",
            "--state-dir",
            "state",
        ],
        "",
    ));
    assert!(reset.contains("reset db.query"), "{reset}");

    let third = session(d.path(), 1);
    assert!(
        third[0].contains("upstream db failed"),
        "breaker should be closed: {third:?}"
    );

    let audit = std::fs::read_to_string(d.path().join("state/audit.jsonl")).unwrap();
    assert!(audit.contains("\"event\":\"budget_reset\"") && audit.contains("reset by alice"));
    let chain = stdout(&airlock(
        d.path(),
        &["audit", "verify", "--state-dir", "state"],
        "",
    ));
    assert!(chain.contains("chain intact"), "{chain}");
}
