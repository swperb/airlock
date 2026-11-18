//! Property: nothing an agent can send through the MCP connection can approve
//! its own pending action.
//!
//! The gateway's `handle` is the agent's entire attack surface. We throw
//! arbitrary JSON-RPC messages (including ones crafted to look like approvals)
//! at a gateway holding a pending destructive call, and assert that the call
//! is never forwarded: the only way it runs is a real out-of-band
//! `ApprovalStore::approve`, which the connection has no path to.

use std::cell::RefCell;
use std::rc::Rc;

use airlock_core::gateway::{Notifier, Upstreams};
use airlock_core::{Gateway, Policy};
use proptest::prelude::*;
use serde_json::{json, Value};

const POLICY: &str = r#"
[gateway]
state_dir = "state"
[[upstream]]
name = "db"
command = ["x"]
[[tool]]
name = "db.execute"
class = "destructive"
[[grant]]
task = "t"
expires = "2099-01-01T00:00:00Z"
tools = ["db.execute"]
"#;

#[derive(Clone, Default)]
struct Count(Rc<RefCell<usize>>);

struct Mock(Count);
impl Upstreams for Mock {
    fn list_tools(&mut self, _u: &str) -> Result<Vec<Value>, String> {
        Ok(vec![json!({"name": "execute"})])
    }
    fn call_tool(&mut self, _u: &str, _t: &str, _a: &Value) -> Result<Value, String> {
        *self.0 .0.borrow_mut() += 1;
        Ok(json!({"content": []}))
    }
}
struct Null;
impl Notifier for Null {
    fn alert(&self, _: &Value) {}
}

fn arb_message() -> impl Strategy<Value = Value> {
    let ids = prop_oneof![Just(json!(1)), Just(json!("x")), Just(Value::Null)];
    let methods = prop_oneof![
        Just("tools/call".to_string()),
        Just("approve".to_string()),
        Just("approvals/approve".to_string()),
        Just("initialize".to_string()),
        Just("tools/list".to_string()),
        ".*".prop_map(|s: String| s),
    ];
    let approvers = prop_oneof![Just("alice"), Just("self"), Just("agent")];
    (ids, methods, any::<bool>(), approvers).prop_map(|(id, method, approved, approver)| {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": {
                "name": "db.execute",
                "arguments": {"sql": "DELETE FROM t"},
                // Decoy fields an attacker might hope the gateway honours:
                "approved": approved,
                "approval": {"approved": true, "approvers": [approver, "bob"]},
                "approvers": [approver, "bob"],
                "two_person": false,
                "class": "read",
                "bypass": true,
            }
        })
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(600))]
    #[test]
    fn agent_cannot_approve_itself(msgs in prop::collection::vec(arb_message(), 1..40)) {
        let dir = tempfile::tempdir().unwrap();
        let policy = Policy::parse(POLICY, dir.path().to_path_buf()).unwrap();
        let count = Count::default();
        let mut gw = Gateway::new(policy, "t", "s1", Mock(count.clone()), Box::new(Null)).unwrap();
        for m in &msgs {
            let _ = gw.handle(m);
        }
        // The destructive call was never forwarded, no matter what the agent sent.
        prop_assert_eq!(*count.0.borrow(), 0);
    }
}
