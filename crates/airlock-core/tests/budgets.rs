//! Persistent budgets through the decision pipeline.

use airlock_core::budget::budgets_dir;
use airlock_core::gateway::{Notifier, Upstreams, Verdict};
use airlock_core::{Gateway, Policy};
use serde_json::{json, Value};

const POLICY: &str = r#"
[gateway]
state_dir = "state"

[[upstream]]
name = "db"
command = ["unused"]

[[tool]]
name = "db.query"
class = "read"
[[tool]]
name = "db.update"
class = "reversible_write"

[[grant]]
task = "t"
expires = "2099-01-01T00:00:00Z"
tools = ["db.query", "db.update"]
[grant.budget]
"db.query" = { per_hour = 2 }
"db.update" = { per_hour = 2 }
"#;

struct Mock;
impl Upstreams for Mock {
    fn list_tools(&mut self, _u: &str) -> Result<Vec<Value>, String> {
        Ok(vec![])
    }
    fn call_tool(&mut self, _u: &str, _t: &str, _a: &Value) -> Result<Value, String> {
        Ok(json!({"content": []}))
    }
}

struct Null;
impl Notifier for Null {
    fn alert(&self, _: &Value) {}
}

/// A fresh gateway process for task `t` over the same state directory.
fn gateway(dir: &std::path::Path, session: &str) -> Gateway<Mock> {
    let policy = Policy::parse(POLICY, dir.to_path_buf()).unwrap();
    Gateway::new(policy, "t", session, Mock, Box::new(Null)).unwrap()
}

fn kind(v: &Verdict) -> &'static str {
    match v {
        Verdict::Allow {
            fail_open: Some(_), ..
        } => "allow_fail_open",
        Verdict::Allow { .. } => "allow",
        Verdict::Deny { .. } => "deny",
        Verdict::Hold { .. } => "hold",
    }
}

#[test]
fn a_restart_does_not_reset_the_budget_or_close_the_breaker() {
    let d = tempfile::tempdir().unwrap();
    let q = json!({"sql": "SELECT 1"});
    {
        let mut g = gateway(d.path(), "s1");
        assert_eq!(kind(&g.evaluate("db.query", &q, 1000).verdict), "allow");
        assert_eq!(kind(&g.evaluate("db.query", &q, 1001).verdict), "allow");
    }
    // The agent gets the gateway restarted, hoping for a fresh budget.
    let mut g = gateway(d.path(), "s2");
    let e = g.evaluate("db.query", &q, 1002);
    assert_eq!(kind(&e.verdict), "deny");
    assert!(e.tripped);
    // And the breaker is still open in yet another process, hours later.
    let mut g = gateway(d.path(), "s3");
    let e = g.evaluate("db.query", &q, 1002 + 10 * 3600);
    match e.verdict {
        Verdict::Deny { reason } => assert!(reason.contains("airlock budget reset"), "{reason}"),
        v => panic!("expected deny, got {}", kind(&v)),
    }
}

#[test]
fn concurrent_gateways_share_one_budget() {
    let d = tempfile::tempdir().unwrap();
    let q = json!({"sql": "SELECT 1"});
    let mut a = gateway(d.path(), "a");
    let mut b = gateway(d.path(), "b");
    assert_eq!(kind(&a.evaluate("db.query", &q, 10).verdict), "allow");
    assert_eq!(kind(&b.evaluate("db.query", &q, 11).verdict), "allow");
    assert_eq!(kind(&a.evaluate("db.query", &q, 12).verdict), "deny");
}

#[test]
fn unreadable_budget_store_fails_open_for_reads_and_closed_for_writes() {
    let d = tempfile::tempdir().unwrap();
    let mut g = gateway(d.path(), "s");
    assert_eq!(
        kind(&g.evaluate("db.query", &json!({}), 1).verdict),
        "allow"
    );
    // Corrupt the stored budget.
    let dir = budgets_dir(&d.path().join("state"));
    for e in std::fs::read_dir(&dir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().and_then(|x| x.to_str()) == Some("json") {
            std::fs::write(&p, b"garbage").unwrap();
        }
    }
    assert_eq!(
        kind(&g.evaluate("db.query", &json!({}), 2).verdict),
        "allow_fail_open"
    );
    let e = g.evaluate("db.update", &json!({"id": 1}), 2);
    match e.verdict {
        Verdict::Deny { reason } => assert!(reason.contains("fail closed"), "{reason}"),
        v => panic!("expected deny, got {}", kind(&v)),
    }
    // The fail-open read is recorded as such in the audit log.
    let r = g.call("db.query", &json!({"sql": "SELECT 2"}));
    assert!(!r["isError"].as_bool().unwrap_or(false));
    let audit = airlock_core::audit::read_entries(&d.path().join("state/audit.jsonl")).unwrap();
    assert!(audit
        .iter()
        .any(|e| e.decision == "allowed_fail_open" && e.reason.contains("budget store")));
}
