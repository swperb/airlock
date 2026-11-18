//! Tamper-evident audit log.
//!
//! Append-only JSON Lines. Each line is `{"entry": <entry>, "hash": "<hex>"}`
//! where `hash = SHA-256(prev_hash || entry_text)` and `entry.prev_hash` is the
//! previous line's hash (64 zeros for the first). The hash covers the exact
//! bytes of the entry as written, so verification never depends on
//! re-serialising JSON. Editing, deleting or reordering any line breaks the
//! chain at that line.
//!
//! Appends take an exclusive file lock, so several gateway processes can share
//! one log without forking the chain.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::Value;

use crate::util::sha256_hex;
use crate::Error;

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One audited event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    pub seq: u64,
    pub ts: String,
    pub session: String,
    pub task: String,
    /// `call`, `freeze`, `startup`, ...
    pub event: String,
    pub tool: Option<String>,
    /// Arguments after redaction.
    pub args: Value,
    pub class: Option<String>,
    /// `allowed`, `denied`, `held`, `allowed_fail_open`, `info`.
    pub decision: String,
    pub reason: String,
    /// JSON-pointer paths of arguments derived from untrusted output.
    pub tainted_args: Vec<String>,
    /// Provenance label of the result, for forwarded calls.
    pub result_provenance: Option<String>,
    pub approval_id: Option<String>,
    pub approvers: Vec<String>,
    pub prev_hash: String,
}

/// The parts of an entry the caller supplies; `seq`, `ts` and `prev_hash`
/// are filled in at append time.
#[derive(Debug, Clone, Default)]
pub struct Record {
    pub session: String,
    pub task: String,
    pub event: String,
    pub tool: Option<String>,
    pub args: Value,
    pub class: Option<String>,
    pub decision: String,
    pub reason: String,
    pub tainted_args: Vec<String>,
    pub result_provenance: Option<String>,
    pub approval_id: Option<String>,
    pub approvers: Vec<String>,
}

#[derive(Deserialize)]
struct Line<'a> {
    #[serde(borrow)]
    entry: &'a RawValue,
    hash: String,
}

/// Writer for one audit log file.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<AuditLog, Error> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        OpenOptions::new().create(true).append(true).open(path)?;
        Ok(AuditLog {
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a record, chaining it to the current last line.
    pub fn append(&self, rec: Record) -> Result<Entry, Error> {
        let mut file = OpenOptions::new()
            .read(true)
            .append(true)
            .open(&self.path)?;
        file.lock()?;
        let result = (|| {
            let (prev_hash, last_seq) = last_link(&mut file)?;
            let entry = Entry {
                seq: last_seq.map_or(0, |s| s + 1),
                ts: crate::util::rfc3339(crate::util::now_unix()),
                session: rec.session,
                task: rec.task,
                event: rec.event,
                tool: rec.tool,
                args: rec.args,
                class: rec.class,
                decision: rec.decision,
                reason: rec.reason,
                tainted_args: rec.tainted_args,
                result_provenance: rec.result_provenance,
                approval_id: rec.approval_id,
                approvers: rec.approvers,
                prev_hash: prev_hash.clone(),
            };
            let body = serde_json::to_string(&entry)?;
            let hash = chain_hash(&prev_hash, &body);
            let line = format!("{{\"entry\":{body},\"hash\":\"{hash}\"}}\n");
            file.seek(SeekFrom::End(0))?;
            file.write_all(line.as_bytes())?;
            file.sync_data()?;
            Ok(entry)
        })();
        let _ = file.unlock();
        result
    }
}

fn chain_hash(prev: &str, body: &str) -> String {
    let mut buf = Vec::with_capacity(prev.len() + body.len());
    buf.extend_from_slice(prev.as_bytes());
    buf.extend_from_slice(body.as_bytes());
    sha256_hex(&buf)
}

/// Read the hash and sequence number of the last line.
fn last_link(file: &mut File) -> Result<(String, Option<u64>), Error> {
    let len = file.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok((GENESIS.to_string(), None));
    }
    // Read backwards in chunks until we have the whole last line.
    let mut tail: Vec<u8> = Vec::new();
    let mut pos = len;
    loop {
        let step = (64 * 1024u64).min(pos);
        pos -= step;
        file.seek(SeekFrom::Start(pos))?;
        let mut chunk = vec![0u8; step as usize];
        file.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&tail);
        tail = chunk;
        let trimmed = trim_trailing_newlines(&tail);
        if trimmed.contains(&b'\n') || pos == 0 {
            break;
        }
    }
    let trimmed = trim_trailing_newlines(&tail);
    let start = trimmed
        .iter()
        .rposition(|b| *b == b'\n')
        .map_or(0, |i| i + 1);
    let last = std::str::from_utf8(&trimmed[start..])
        .map_err(|_| Error::Io("audit log is not UTF-8; run `airlock audit verify`".into()))?;
    let line: Line<'_> = serde_json::from_str(last).map_err(|e| {
        Error::Io(format!(
            "audit log last line is unreadable ({e}); run `airlock audit verify`"
        ))
    })?;
    let entry: Entry = serde_json::from_str(line.entry.get())?;
    Ok((line.hash, Some(entry.seq)))
}

fn trim_trailing_newlines(b: &[u8]) -> &[u8] {
    let mut end = b.len();
    while end > 0 && b[end - 1] == b'\n' {
        end -= 1;
    }
    &b[..end]
}

/// Result of verifying a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verification {
    Ok {
        entries: u64,
    },
    /// `line` is 1-based.
    Broken {
        line: u64,
        reason: String,
    },
}

/// Verify the hash chain of an audit log.
pub fn verify(path: &Path) -> Result<Verification, Error> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut prev = GENESIS.to_string();
    let mut count = 0u64;
    for (i, line) in reader.lines().enumerate() {
        let expected_seq = i as u64;
        let lineno = expected_seq + 1;
        let text = match line {
            Ok(t) => t,
            Err(e) => {
                return Ok(Verification::Broken {
                    line: lineno,
                    reason: format!("unreadable: {e}"),
                })
            }
        };
        if text.is_empty() {
            return Ok(Verification::Broken {
                line: lineno,
                reason: "empty line".into(),
            });
        }
        let parsed: Line<'_> = match serde_json::from_str(&text) {
            Ok(l) => l,
            Err(e) => {
                return Ok(Verification::Broken {
                    line: lineno,
                    reason: format!("not a valid audit line: {e}"),
                })
            }
        };
        let entry: Entry = match serde_json::from_str(parsed.entry.get()) {
            Ok(e) => e,
            Err(e) => {
                return Ok(Verification::Broken {
                    line: lineno,
                    reason: format!("entry is malformed: {e}"),
                })
            }
        };
        if entry.prev_hash != prev {
            return Ok(Verification::Broken {
                line: lineno,
                reason: "prev_hash does not match the previous line (line inserted, removed or reordered)".into(),
            });
        }
        let computed = chain_hash(&prev, parsed.entry.get());
        if computed != parsed.hash {
            return Ok(Verification::Broken {
                line: lineno,
                reason: "hash mismatch (entry was edited)".into(),
            });
        }
        if entry.seq != expected_seq {
            return Ok(Verification::Broken {
                line: lineno,
                reason: format!(
                    "sequence number {} where {} was expected",
                    entry.seq, expected_seq
                ),
            });
        }
        prev = parsed.hash;
        count += 1;
    }
    Ok(Verification::Ok { entries: count })
}

/// Read every entry (without verifying). Used by `audit tail`.
pub fn read_entries(path: &Path) -> Result<Vec<Entry>, Error> {
    let file = File::open(path)?;
    let mut out = Vec::new();
    for line in BufReader::new(file).lines() {
        let text = line?;
        if text.is_empty() {
            continue;
        }
        let parsed: Line<'_> = serde_json::from_str(&text)?;
        out.push(serde_json::from_str(parsed.entry.get())?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rec(i: u32) -> Record {
        Record {
            session: "s".into(),
            task: "t".into(),
            event: "call".into(),
            tool: Some("db.query".into()),
            args: json!({"sql": format!("SELECT {i}"), "f": 0.1}),
            class: Some("read".into()),
            decision: "allowed".into(),
            reason: "ok".into(),
            ..Default::default()
        }
    }

    fn write_log(n: u32) -> (tempfile::TempDir, PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("audit.jsonl");
        let log = AuditLog::open(&p).unwrap();
        for i in 0..n {
            let e = log.append(rec(i)).unwrap();
            assert_eq!(e.seq, u64::from(i));
        }
        (d, p)
    }

    #[test]
    fn chain_verifies() {
        let (_d, p) = write_log(5);
        assert_eq!(verify(&p).unwrap(), Verification::Ok { entries: 5 });
        assert_eq!(read_entries(&p).unwrap().len(), 5);
    }

    #[test]
    fn reopening_continues_the_chain() {
        let (_d, p) = write_log(3);
        let log = AuditLog::open(&p).unwrap();
        assert_eq!(log.append(rec(9)).unwrap().seq, 3);
        assert_eq!(verify(&p).unwrap(), Verification::Ok { entries: 4 });
    }

    #[test]
    fn tampered_entry_fails_at_that_line() {
        let (_d, p) = write_log(5);
        let text = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        lines[2] = lines[2].replace("\"allowed\"", "\"denied\"");
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        match verify(&p).unwrap() {
            Verification::Broken { line, reason } => {
                assert_eq!(line, 3);
                assert!(reason.contains("hash mismatch"), "{reason}");
            }
            v => panic!("expected broken, got {v:?}"),
        }
    }

    #[test]
    fn deleted_line_fails_at_the_gap() {
        let (_d, p) = write_log(5);
        let text = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.remove(1);
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        assert!(matches!(
            verify(&p).unwrap(),
            Verification::Broken { line: 2, .. }
        ));
    }

    #[test]
    fn rehashed_edit_still_fails_downstream() {
        // An attacker who edits line 2 and recomputes its hash still breaks line 3.
        let (_d, p) = write_log(4);
        let text = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        let parsed: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        let mut entry = parsed["entry"].clone();
        entry["decision"] = json!("denied");
        let body = serde_json::to_string(&entry).unwrap();
        let hash = chain_hash(entry["prev_hash"].as_str().unwrap(), &body);
        lines[1] = format!("{{\"entry\":{body},\"hash\":\"{hash}\"}}");
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        assert!(matches!(
            verify(&p).unwrap(),
            Verification::Broken { line: 3, .. }
        ));
    }

    #[test]
    fn long_last_line_is_read_correctly() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a.jsonl");
        let log = AuditLog::open(&p).unwrap();
        let mut r = rec(0);
        r.args = json!({"blob": "x".repeat(200_000)});
        log.append(r).unwrap();
        log.append(rec(1)).unwrap();
        assert_eq!(verify(&p).unwrap(), Verification::Ok { entries: 2 });
    }
}
