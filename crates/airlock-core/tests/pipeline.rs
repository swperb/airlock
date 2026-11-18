//! End-to-end tests of the decision pipeline against a mock upstream.

use std::cell::RefCell;
use std::rc::Rc;

use airlock_core::approvals::{args_hash, ApprovalStore};
use airlock_core::audit::{self, Verification};
use airlock_core::gateway::{Notifier, Upstreams, Verdict};
use airlock_core::util::now_unix;
use airlock_core::{freeze, Gateway, Policy};
use serde_json::{json, Value};

const POLICY: &str = r#"
[gateway]
state_dir = "state"
min_taint_len = 8

[[upstream]]
name = "db"
command = ["x"]
[[upstream]]
name = "mail"
command = ["x"]
[[upstream]]
name = "web"
command = ["x"]
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
name = "deploy.ship"
class = "destructive"
two_person = true
[[upstream]]
name = "deploy"
command = ["x"]

[[grant]]
task = "t"
expires = "2099-01-01T00:00:00Z"
tools = ["db.query", "db.execute", "mail.send", "deploy.ship", "web.fetch"]
[grant.limits]
"mail.send".to_domains = ["example.com"]
[grant.budget]
"mail.send" = { per_hour = 2 }

[[tool]]
name = "web.fetch"
class = "read"
"#;

#[derive(Clone, Default)]
struct Calls(Rc<RefCell<Vec<(String, String)>>>);

struct Mock {
    calls: Calls,
    web_returns: String,
}

impl Upstreams for Mock {
    fn list_tools(&mut self, upstream: &str) -> Result<Vec<Value>, String> {
        Ok(vec![json!({"name": match upstream {
            "db" => "query",
            "mail" => "send",
            "web" => "fetch",
            _ => "ship",
        }})])
    }
    fn call_tool(&mut self, upstream: &str, tool: &str, _args: &Value) -> Result<Value, String> {
        self.calls
            .0
            .borrow_mut()
            .push((upstream.into(), tool.into()));
        let text = if upstream == "web" {
            self.web_returns.clone()
        } else {
            "ok".into()
        };
        Ok(json!({"content": [{"type": "text", "text": text}]}))
    }
}

struct NullNotifier;
impl Notifier for NullNotifier {
    fn alert(&self, _: &Value) {}
}

struct Fixture {
    // Held only to keep the temp dir alive for the test's lifetime.
    #[allow(dead_code)]
    dir: tempfile::TempDir,
    policy: Policy,
    calls: Calls,
}

fn fixture(web_returns: &str) -> (Gateway<Mock>, Fixture) {
    let dir = tempfile::tempdir().unwrap();
    let policy = Policy::parse(POLICY, dir.path().to_path_buf()).unwrap();
    let calls = Calls::default();
    let mock = Mock {
        calls: calls.clone(),
        web_returns: web_returns.into(),
    };
    let gw = Gateway::new(policy.clone(), "t", "s1", mock, Box::new(NullNotifier)).unwrap();
    (gw, Fixture { dir, policy, calls })
}

fn is_error(v: &Value) -> bool {
    v["isError"].as_bool().unwrap_or(false)
}

#[test]
fn reads_pass_destructive_and_external_are_controlled() {
    let (mut gw, fx) = fixture("nothing interesting");
    // Read is allowed and forwarded.
    assert!(!is_error(&gw.call("db.query", &json!({"sql": "SELECT 1"}))));
    // Deny pattern blocks DROP outright.
    let r = gw.call("db.execute", &json!({"sql": "DROP TABLE t"}));
    assert!(is_error(&r));
    assert!(r["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("deny pattern"));
    // mail.send to a disallowed domain is denied by the limit.
    assert!(is_error(&gw.call(
        "mail.send",
        &json!({"to": "x@evil.io", "subject": "s", "body": "b"})
    )));
    // Only the read reached the upstream.
    assert_eq!(
        *fx.calls.0.borrow(),
        vec![("db".to_string(), "query".to_string())]
    );
}

#[test]
fn allowed_external_call_holds_then_runs_after_approval() {
    let now = now_unix();
    let (mut gw, fx) = fixture("x");
    let gw = &mut gw;
    let args = json!({"to": "ops@example.com", "subject": "s", "body": "b"});
    // First attempt: held (irreversible_external always needs a person).
    let r = gw.call("mail.send", &args);
    assert!(is_error(&r));
    assert!(r["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("DRY RUN"));
    assert!(
        fx.calls.0.borrow().is_empty(),
        "nothing forwarded while held"
    );

    // A person approves out of band.
    let store = ApprovalStore::new(&fx.policy.state_dir());
    let pending = store
        .find_for_call("s1", "mail.send", &args_hash("mail.send", &args), now)
        .unwrap()
        .unwrap();
    store.approve(&pending.id, "alice", now).unwrap();

    // Identical call now goes through, exactly once.
    assert!(!is_error(&gw.call("mail.send", &args)));
    assert_eq!(
        *fx.calls.0.borrow(),
        vec![("mail".to_string(), "send".to_string())]
    );

    // The approval is single-use: a repeat holds again.
    assert!(is_error(&gw.call("mail.send", &args)));
}

#[test]
fn untrusted_content_forces_approval_for_external_action() {
    // The agent reads an untrusted page that contains the recipient address,
    // then tries to mail to it. Even though example.com is allowed, the taint
    // makes it need a person.
    let (mut gw, _fx) = fixture("contact us at partner@example.com for details about this");
    assert!(!is_error(
        &gw.call("web.fetch", &json!({"url": "http://x"}))
    ));
    let eval = gw.evaluate(
        "mail.send",
        &json!({"to": "partner@example.com", "subject": "s", "body": "b"}),
        now_unix(),
    );
    match eval.verdict {
        Verdict::Hold { .. } => {}
        other => panic!("expected hold, got {other:?}"),
    }
    assert_eq!(eval.tainted, vec!["/to".to_string()]);
}

#[test]
fn clean_external_arguments_still_hold_but_without_taint() {
    let (mut gw, _fx) = fixture("unrelated page text");
    gw.call("web.fetch", &json!({"url": "http://x"}));
    let eval = gw.evaluate(
        "mail.send",
        &json!({"to": "ops@example.com", "subject": "s", "body": "b"}),
        now_unix(),
    );
    assert!(eval.tainted.is_empty());
    assert!(matches!(eval.verdict, Verdict::Hold { .. }));
}

#[test]
fn two_person_tool_needs_two_distinct_approvers() {
    let now = now_unix();
    let (mut gw, fx) = fixture("x");
    let args = json!({"release": "1.2.3"});
    gw.call("deploy.ship", &args);
    let store = ApprovalStore::new(&fx.policy.state_dir());
    let p = store
        .find_for_call("s1", "deploy.ship", &args_hash("deploy.ship", &args), now)
        .unwrap()
        .unwrap();
    assert_eq!(p.required_approvers, 2);
    store.approve(&p.id, "alice", now).unwrap();
    // One approval is not enough: still held.
    assert!(is_error(&gw.call("deploy.ship", &args)));
    store.approve(&p.id, "bob", now).unwrap();
    assert!(!is_error(&gw.call("deploy.ship", &args)));
    assert_eq!(
        *fx.calls.0.borrow(),
        vec![("deploy".to_string(), "ship".to_string())]
    );
}

#[test]
fn freeze_blocks_writes_within_one_call_but_not_reads() {
    let (mut gw, fx) = fixture("x");
    freeze::freeze(&fx.policy.state_dir(), "ops").unwrap();
    // A read still passes (fail open).
    assert!(!is_error(&gw.call("db.query", &json!({"sql": "SELECT 1"}))));
    // A destructive write is refused immediately.
    let r = gw.call("db.execute", &json!({"sql": "UPDATE t SET a=1"}));
    assert!(is_error(&r));
    assert!(r["content"][0]["text"].as_str().unwrap().contains("frozen"));
    freeze::unfreeze(&fx.policy.state_dir()).unwrap();
    assert!(matches!(
        gw.evaluate(
            "db.execute",
            &json!({"sql": "UPDATE t SET a=1"}),
            now_unix()
        )
        .verdict,
        Verdict::Hold { .. }
    ));
}

#[test]
fn budget_trips_the_circuit_breaker() {
    let now = now_unix();
    let (mut gw, fx) = fixture("x");
    let store = ApprovalStore::new(&fx.policy.state_dir());
    // Budget for mail.send is 2/hour. Approve and spend both.
    for _ in 0..2 {
        let args =
            json!({"to": "ops@example.com", "subject": "s", "body": format!("{}", now_unix())});
        gw.call("mail.send", &args);
        let p = store
            .find_for_call("s1", "mail.send", &args_hash("mail.send", &args), now)
            .unwrap()
            .unwrap();
        store.approve(&p.id, "alice", now).unwrap();
        assert!(!is_error(&gw.call("mail.send", &args)));
    }
    // Third distinct call: budget exceeded, breaker trips, denied even before approval.
    let args = json!({"to": "ops@example.com", "subject": "s", "body": "third"});
    let eval = gw.evaluate("mail.send", &args, now);
    assert!(eval.tripped);
    assert!(matches!(eval.verdict, Verdict::Deny { .. }));
}

#[test]
fn expired_grant_denies_everything() {
    let dir = tempfile::tempdir().unwrap();
    let expired = POLICY.replace("2099-01-01T00:00:00Z", "2000-01-01T00:00:00Z");
    let policy = Policy::parse(&expired, dir.path().to_path_buf()).unwrap();
    let mock = Mock {
        calls: Calls::default(),
        web_returns: "x".into(),
    };
    let mut gw = Gateway::new(policy, "t", "s1", mock, Box::new(NullNotifier)).unwrap();
    let r = gw.call("db.query", &json!({"sql": "SELECT 1"}));
    assert!(is_error(&r));
    assert!(r["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("expired"));
}

#[test]
fn ungranted_or_undefined_tools_are_denied() {
    let (mut gw, _fx) = fixture("x");
    assert!(is_error(&gw.call("db.nope", &json!({}))));
    assert!(is_error(
        &gw.call("shell.exec", &json!({"cmd": "rm -rf /"}))
    ));
}

#[test]
fn audit_log_records_and_verifies() {
    let (mut gw, fx) = fixture("x");
    gw.call("db.query", &json!({"sql": "SELECT 1"}));
    gw.call("db.execute", &json!({"sql": "DROP TABLE t"}));
    let path = fx.policy.audit_path();
    assert!(matches!(
        audit::verify(&path).unwrap(),
        Verification::Ok { .. }
    ));
    let entries = audit::read_entries(&path).unwrap();
    assert!(entries
        .iter()
        .any(|e| e.decision == "denied" && e.tool.as_deref() == Some("db.execute")));
    assert!(entries.iter().any(|e| e.event == "session_start"));
}

#[test]
fn tools_list_namespaces_and_filters_by_grant() {
    let (mut gw, _fx) = fixture("x");
    let resp = gw
        .handle(&json!({"jsonrpc":"2.0","id":1,"method":"tools/list"}))
        .unwrap();
    let names: Vec<String> = resp["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"db.query".to_string()));
    assert!(names.iter().all(|n| n.contains('.')));
}
