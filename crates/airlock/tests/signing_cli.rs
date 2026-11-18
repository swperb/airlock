//! End-to-end tests of policy signing through the `airlock` binary.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

const POLICY: &str = r#"
[gateway]
state_dir = "state"

[[upstream]]
name = "db"
command = ["db-mcp"]

[[tool]]
name = "db.query"
class = "read"

[[grant]]
task = "t"
expires = "2099-01-01T00:00:00Z"
tools = ["db.query"]
"#;

fn airlock(args: &[&str], envs: &[(&str, &Path)], stdin: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_airlock"))
        .args(args)
        .env_remove("AIRLOCK_TRUSTED_KEYS")
        .envs(envs.iter().map(|(k, v)| (*k, *v)))
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

fn ok(out: &Output) -> String {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success(), "expected success, got: {text}");
    text
}

fn fails(out: &Output) -> String {
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!out.status.success(), "expected failure, got: {text}");
    text
}

struct Setup {
    dir: tempfile::TempDir,
}

impl Setup {
    fn new() -> Setup {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("policy.toml"), POLICY).unwrap();
        Setup { dir }
    }
    fn p(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
    fn s(&self, name: &str) -> String {
        self.p(name).display().to_string()
    }
    fn keygen(&self, name: &str) {
        ok(&airlock(
            &[
                "keygen",
                "--out",
                &self.s(name),
                "--comment",
                "ops@example.com",
            ],
            &[],
            "",
        ));
    }
    fn sign(&self, key: &str, extra: &[&str]) -> Output {
        let policy = self.s_policy();
        let mut args = vec!["policy", "sign", "--policy", policy.as_str(), "--key", key];
        args.extend_from_slice(extra);
        airlock(&args, &[], "")
    }
    fn s_policy(&self) -> String {
        self.s("policy.toml")
    }
    /// Start `airlock run`, send one initialize, and let it exit on EOF.
    fn run(&self, trusted: Option<&str>) -> Output {
        let policy = self.s_policy();
        let mut args = vec!["run", "--policy", policy.as_str(), "--task", "t"];
        if let Some(t) = trusted {
            args.extend_from_slice(&["--trusted-keys", t]);
        }
        airlock(
            &args,
            &[],
            "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n",
        )
    }
}

#[test]
fn keygen_writes_a_private_key_only_the_owner_can_read() {
    let s = Setup::new();
    s.keygen("ops");
    let key = std::fs::read_to_string(s.p("ops.key")).unwrap();
    assert!(key.starts_with("airlock-ed25519-private "));
    let public = std::fs::read_to_string(s.p("ops.pub")).unwrap();
    assert!(
        public.starts_with("airlock-ed25519-public ")
            && public.trim_end().ends_with("ops@example.com")
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(s.p("ops.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
    let again = fails(&airlock(&["keygen", "--out", &s.s("ops")], &[], ""));
    assert!(again.contains("refusing to overwrite"), "{again}");
}

#[test]
fn sign_verify_and_serials() {
    let s = Setup::new();
    s.keygen("ops");
    let key = s.s("ops.key");
    let trusted = s.s("ops.pub");

    assert!(ok(&s.sign(&key, &[])).contains("serial 1"));
    assert!(ok(&s.sign(&key, &[])).contains("serial 2"));
    let low = fails(&s.sign(&key, &["--serial", "2"]));
    assert!(low.contains("not higher"), "{low}");
    assert!(ok(&s.sign(&key, &["--serial", "10"])).contains("serial 10"));

    let verified = ok(&airlock(
        &[
            "policy",
            "verify",
            "--policy",
            &s.s_policy(),
            "--trusted-keys",
            &trusted,
        ],
        &[],
        "",
    ));
    assert!(
        verified.contains("signature OK") && verified.contains("serial 10"),
        "{verified}"
    );

    let checked = ok(&airlock(
        &[
            "policy",
            "check",
            "--policy",
            &s.s_policy(),
            "--trusted-keys",
            &trusted,
        ],
        &[],
        "",
    ));
    assert!(checked.contains("signature: valid"), "{checked}");
    // The trusted keys can also come from the environment.
    let env_checked = ok(&airlock(
        &["policy", "check", "--policy", &s.s_policy()],
        &[("AIRLOCK_TRUSTED_KEYS", &s.p("ops.pub"))],
        "",
    ));
    assert!(env_checked.contains("signature: valid"), "{env_checked}");
}

#[test]
fn signing_an_invalid_policy_is_refused() {
    let s = Setup::new();
    s.keygen("ops");
    std::fs::write(s.p("policy.toml"), "[gateway]\nmystery = 1\n").unwrap();
    fails(&s.sign(&s.s("ops.key"), &[]));
    assert!(!s.p("policy.toml.sig").exists());
}

#[test]
fn gateway_refuses_tampered_unsigned_or_untrusted_policies() {
    let s = Setup::new();
    s.keygen("ops");
    s.keygen("intruder");
    let trusted = s.s("ops.pub");

    // Unsigned, with trust configured: refused.
    let e = fails(&s.run(Some(&trusted)));
    assert!(e.contains("must be signed"), "{e}");

    // Signed by a key that is not trusted: refused.
    ok(&s.sign(&s.s("intruder.key"), &[]));
    let e = fails(&s.run(Some(&trusted)));
    assert!(e.contains("not in the trusted keys"), "{e}");

    // Signed correctly: starts and answers.
    std::fs::remove_file(s.p("policy.toml.sig")).unwrap();
    ok(&s.sign(&s.s("ops.key"), &[]));
    let started = ok(&s.run(Some(&trusted)));
    assert!(started.contains("\"serverInfo\""), "{started}");

    // Loosened after signing: refused.
    let loosened = POLICY.replace(
        "tools = [\"db.query\"]",
        "tools = [\"db.query\"]\n# widened",
    );
    std::fs::write(s.p("policy.toml"), loosened).unwrap();
    let e = fails(&s.run(Some(&trusted)));
    assert!(e.contains("does not verify"), "{e}");
}

#[test]
fn gateway_refuses_replay_of_an_older_signed_policy() {
    let s = Setup::new();
    s.keygen("ops");
    let trusted = s.s("ops.pub");
    ok(&s.sign(&s.s("ops.key"), &[]));
    let old_sig = std::fs::read_to_string(s.p("policy.toml.sig")).unwrap();
    ok(&s.sign(&s.s("ops.key"), &[]));
    ok(&s.run(Some(&trusted))); // accepts serial 2 and records it

    std::fs::write(s.p("policy.toml.sig"), old_sig).unwrap(); // replay serial 1
    let e = fails(&s.run(Some(&trusted)));
    assert!(e.contains("rollback refused"), "{e}");
}

#[test]
fn every_start_records_the_policy_it_ran_under() {
    let s = Setup::new();
    s.keygen("ops");
    ok(&s.sign(&s.s("ops.key"), &[]));
    ok(&s.run(Some(&s.s("ops.pub"))));
    let unsigned = ok(&s.run(None));
    assert!(
        unsigned.contains("signatures are not checked"),
        "{unsigned}"
    );

    let audit = std::fs::read_to_string(s.p("state/audit.jsonl")).unwrap();
    let loads: Vec<serde_json::Value> = audit
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["entry"].clone())
        .filter(|e| e["event"] == "policy_loaded")
        .collect();
    assert_eq!(loads.len(), 2);
    assert_eq!(loads[0]["args"]["signed"], true);
    assert_eq!(loads[0]["args"]["serial"], 1);
    assert_eq!(loads[1]["args"]["signed"], false);
    assert_eq!(loads[0]["args"]["sha256"], loads[1]["args"]["sha256"]);
    let chain = ok(&airlock(
        &["audit", "verify", "--state-dir", &s.s("state")],
        &[],
        "",
    ));
    assert!(chain.contains("chain intact"), "{chain}");
}
