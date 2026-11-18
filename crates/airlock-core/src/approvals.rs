//! Pending approvals.
//!
//! Approvals live as JSON files in `<state_dir>/approvals/`. The gateway only
//! ever *creates* and *consumes* them; only the out-of-band CLI
//! (`airlock approve` / `airlock reject`) can add an approver or a rejection.
//! There is no code path from the MCP connection to [`ApprovalStore::approve`].
//!
//! An approval is bound to one session, one tool and the exact canonical
//! arguments, is single-use, and expires.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::util::{now_unix, sha256_hex};
use crate::Error;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Pending {
    pub id: String,
    pub created: i64,
    pub expires: i64,
    pub session: String,
    pub task: String,
    pub tool: String,
    pub class: String,
    /// SHA-256 of the canonical arguments; the retry must match exactly.
    pub args_hash: String,
    /// Arguments after redaction, for the person deciding.
    pub args: Value,
    pub dry_run: String,
    pub reasons: Vec<String>,
    pub required_approvers: usize,
    pub approvers: Vec<String>,
    pub rejected_by: Option<String>,
    pub consumed: bool,
}

/// State of a pending approval at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Waiting,
    Approved,
    Rejected,
    Expired,
    Consumed,
}

impl Pending {
    pub fn status(&self, now: i64) -> Status {
        if self.consumed {
            Status::Consumed
        } else if self.rejected_by.is_some() {
            Status::Rejected
        } else if now >= self.expires {
            Status::Expired
        } else if self.approvers.len() >= self.required_approvers {
            Status::Approved
        } else {
            Status::Waiting
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApprovalStore {
    dir: PathBuf,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

impl ApprovalStore {
    pub fn new(state_dir: &Path) -> ApprovalStore {
        ApprovalStore {
            dir: state_dir.join("approvals"),
        }
    }

    fn ensure(&self) -> Result<(), Error> {
        std::fs::create_dir_all(&self.dir)?;
        Ok(())
    }

    fn lock(&self) -> Result<File, Error> {
        self.ensure()?;
        let f = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join(".lock"))?;
        f.lock()?;
        Ok(f)
    }

    fn path(&self, id: &str) -> Result<PathBuf, Error> {
        if !valid_id(id) {
            return Err(Error::Io(format!("invalid approval id {id:?}")));
        }
        Ok(self.dir.join(format!("{id}.json")))
    }

    fn write(&self, p: &Pending) -> Result<(), Error> {
        let path = self.path(&p.id)?;
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(p)?)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<Option<Pending>, Error> {
        let path = self.path(id)?;
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// All approval records, newest first.
    pub fn list(&self) -> Result<Vec<Pending>, Error> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let path = entry?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let bytes = std::fs::read(&path)?;
                out.push(serde_json::from_slice::<Pending>(&bytes)?);
            }
        }
        out.sort_by(|a, b| b.created.cmp(&a.created).then_with(|| a.id.cmp(&b.id)));
        Ok(out)
    }

    /// Find the live approval record for this exact call, if any.
    /// Consumed and expired records are skipped so a fresh request is made.
    pub fn find_for_call(
        &self,
        session: &str,
        tool: &str,
        args_hash: &str,
        now: i64,
    ) -> Result<Option<Pending>, Error> {
        Ok(self.list()?.into_iter().find(|p| {
            p.session == session
                && p.tool == tool
                && p.args_hash == args_hash
                && !matches!(p.status(now), Status::Consumed | Status::Expired)
        }))
    }

    /// Create a new pending approval. Called by the gateway.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &self,
        session: &str,
        task: &str,
        tool: &str,
        class: &str,
        args_hash: &str,
        args: Value,
        dry_run: impl FnOnce(&str, i64) -> String,
        reasons: Vec<String>,
        required_approvers: usize,
        ttl_secs: u64,
    ) -> Result<Pending, Error> {
        let _lock = self.lock()?;
        let now = now_unix();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seed = format!(
            "{nanos}:{}:{}:{session}:{tool}:{args_hash}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let id = format!("ap-{}", &sha256_hex(seed.as_bytes())[..12]);
        let expires = now.saturating_add(i64::try_from(ttl_secs).unwrap_or(i64::MAX));
        let dry_run = dry_run(&id, expires);
        let p = Pending {
            id,
            created: now,
            expires,
            session: session.to_string(),
            task: task.to_string(),
            tool: tool.to_string(),
            class: class.to_string(),
            args_hash: args_hash.to_string(),
            args,
            dry_run,
            reasons,
            required_approvers: required_approvers.max(1),
            approvers: Vec::new(),
            rejected_by: None,
            consumed: false,
        };
        self.write(&p)?;
        Ok(p)
    }

    /// Mark an approved record as used. Called by the gateway just before it
    /// forwards the call. Fails if the record is not approved right now.
    pub fn consume(&self, id: &str, now: i64) -> Result<Pending, Error> {
        let _lock = self.lock()?;
        let mut p = self
            .get(id)?
            .ok_or_else(|| Error::Io(format!("approval {id} vanished")))?;
        if p.status(now) != Status::Approved {
            return Err(Error::Io(format!("approval {id} is no longer approved")));
        }
        p.consumed = true;
        self.write(&p)?;
        Ok(p)
    }

    /// Add an approver. **Out-of-band only**: called from the CLI, never from
    /// the gateway's MCP handling.
    pub fn approve(&self, id: &str, approver: &str, now: i64) -> Result<Pending, Error> {
        if approver.trim().is_empty() {
            return Err(Error::Io("approver name is empty".into()));
        }
        let _lock = self.lock()?;
        let mut p = self
            .get(id)?
            .ok_or_else(|| Error::Io(format!("no approval with id {id}")))?;
        match p.status(now) {
            Status::Waiting => {}
            Status::Approved => return Err(Error::Io(format!("{id} is already approved"))),
            Status::Rejected => return Err(Error::Io(format!("{id} was rejected"))),
            Status::Expired => return Err(Error::Io(format!("{id} has expired"))),
            Status::Consumed => return Err(Error::Io(format!("{id} was already used"))),
        }
        if p.approvers.iter().any(|a| a == approver) {
            return Err(Error::Io(format!(
                "{approver} has already approved {id}; it needs {} distinct approvers",
                p.required_approvers
            )));
        }
        p.approvers.push(approver.to_string());
        self.write(&p)?;
        Ok(p)
    }

    /// Reject. **Out-of-band only.**
    pub fn reject(&self, id: &str, by: &str, now: i64) -> Result<Pending, Error> {
        let _lock = self.lock()?;
        let mut p = self
            .get(id)?
            .ok_or_else(|| Error::Io(format!("no approval with id {id}")))?;
        if matches!(p.status(now), Status::Consumed) {
            return Err(Error::Io(format!("{id} was already used")));
        }
        p.rejected_by = Some(by.to_string());
        self.write(&p)?;
        Ok(p)
    }
}

/// Hash of the canonical arguments, used to bind an approval to one exact call.
pub fn args_hash(tool: &str, args: &Value) -> String {
    sha256_hex(format!("{tool}\n{}", crate::util::canonical(args)).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make(store: &ApprovalStore, required: usize, ttl: u64) -> Pending {
        store
            .create(
                "s1",
                "t",
                "db.execute",
                "destructive",
                "h",
                json!({}),
                |_, _| "dry".into(),
                vec![],
                required,
                ttl,
            )
            .unwrap()
    }

    #[test]
    fn single_approval_flow() {
        let d = tempfile::tempdir().unwrap();
        let s = ApprovalStore::new(d.path());
        let p = make(&s, 1, 600);
        let now = now_unix();
        assert_eq!(p.status(now), Status::Waiting);
        assert!(
            s.consume(&p.id, now).is_err(),
            "cannot consume before approval"
        );
        let p = s.approve(&p.id, "alice", now).unwrap();
        assert_eq!(p.status(now), Status::Approved);
        let p = s.consume(&p.id, now).unwrap();
        assert_eq!(p.status(now), Status::Consumed);
        assert!(s.consume(&p.id, now).is_err(), "single use");
        assert!(s
            .find_for_call("s1", "db.execute", "h", now)
            .unwrap()
            .is_none());
    }

    #[test]
    fn two_person_needs_distinct_approvers() {
        let d = tempfile::tempdir().unwrap();
        let s = ApprovalStore::new(d.path());
        let p = make(&s, 2, 600);
        let now = now_unix();
        s.approve(&p.id, "alice", now).unwrap();
        assert!(s.approve(&p.id, "alice", now).is_err());
        assert_eq!(s.get(&p.id).unwrap().unwrap().status(now), Status::Waiting);
        s.approve(&p.id, "bob", now).unwrap();
        assert_eq!(s.get(&p.id).unwrap().unwrap().status(now), Status::Approved);
    }

    #[test]
    fn expiry_and_rejection() {
        let d = tempfile::tempdir().unwrap();
        let s = ApprovalStore::new(d.path());
        let p = make(&s, 1, 10);
        assert_eq!(p.status(p.created + 10), Status::Expired);
        assert!(s.approve(&p.id, "alice", p.created + 11).is_err());
        let q = make(&s, 1, 600);
        let now = now_unix();
        s.reject(&q.id, "alice", now).unwrap();
        assert!(s.approve(&q.id, "bob", now).is_err());
        assert_eq!(s.get(&q.id).unwrap().unwrap().status(now), Status::Rejected);
    }

    #[test]
    fn ids_cannot_escape_the_directory() {
        let d = tempfile::tempdir().unwrap();
        let s = ApprovalStore::new(d.path());
        assert!(s.get("../../etc/passwd").is_err());
        assert!(s.approve("../x", "a", 0).is_err());
    }

    #[test]
    fn args_hash_is_order_independent() {
        let a: Value = serde_json::from_str(r#"{"to":"x","body":"y"}"#).unwrap();
        let b: Value = serde_json::from_str(r#"{"body":"y","to":"x"}"#).unwrap();
        assert_eq!(args_hash("m.s", &a), args_hash("m.s", &b));
        assert_ne!(args_hash("m.s", &a), args_hash("m.t", &a));
    }
}
