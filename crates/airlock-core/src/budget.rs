//! Per-tool hourly budgets with a circuit breaker, persisted in the state
//! directory.
//!
//! Each attempt that reaches the budget step consumes one unit, whether it is
//! later forwarded, held or refused. When a tool exceeds its budget the
//! breaker trips and that tool stays refused until a person resets it with
//! `airlock budget reset`, so a runaway agent is stopped rather than
//! throttled.
//!
//! Budget state lives in `<state_dir>/budgets/`, one file per task, updated
//! under a file lock on every charge. That makes it the shared source of
//! truth: restarting the gateway does not reset a budget or close a breaker,
//! and several gateway processes serving the same task share one budget.

use std::collections::{BTreeMap, VecDeque};
use std::fs::OpenOptions;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::util::{rfc3339, sha256_hex};
use crate::Error;

const WINDOW_SECS: i64 = 3600;
const FORMAT_VERSION: u32 = 1;

/// Budget state for one task.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct Budgets {
    /// Timestamps (Unix seconds) of charges within the last hour, per tool.
    windows: BTreeMap<String, VecDeque<i64>>,
    /// Tools whose breaker is open, with the time it tripped.
    tripped: BTreeMap<String, i64>,
}

/// Outcome of a budget check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BudgetCheck {
    Ok,
    /// This attempt tripped the breaker.
    JustTripped(String),
    /// The breaker was already open.
    Tripped(String),
}

/// Usage of one tool, for `airlock budget status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolUsage {
    pub tool: String,
    pub used_last_hour: usize,
    pub tripped_at: Option<i64>,
}

impl Budgets {
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume one unit of `tool`'s budget at time `now`.
    pub fn consume(&mut self, tool: &str, per_hour: u32, now: i64) -> BudgetCheck {
        if let Some(at) = self.tripped.get(tool) {
            return BudgetCheck::Tripped(format!(
                "circuit breaker open for {tool} since {}: its budget of {per_hour}/hour was exceeded; a person must reset it with `airlock budget reset`",
                rfc3339(*at)
            ));
        }
        let w = self.windows.entry(tool.to_string()).or_default();
        while w.front().is_some_and(|t| now - *t >= WINDOW_SECS) {
            w.pop_front();
        }
        if w.len() as u64 >= u64::from(per_hour) {
            self.tripped.insert(tool.to_string(), now);
            return BudgetCheck::JustTripped(format!(
                "budget exceeded for {tool}: {per_hour}/hour; circuit breaker tripped"
            ));
        }
        w.push_back(now);
        BudgetCheck::Ok
    }

    pub fn is_tripped(&self, tool: &str) -> bool {
        self.tripped.contains_key(tool)
    }

    /// Close the breaker and clear the window for `tool`, or for every tool.
    /// Returns the tools that were reset.
    pub fn reset(&mut self, tool: Option<&str>) -> Vec<String> {
        let mut names: Vec<String> = self
            .windows
            .keys()
            .chain(self.tripped.keys())
            .cloned()
            .collect();
        names.sort();
        names.dedup();
        names.retain(|n| tool.is_none_or(|t| t == n));
        for n in &names {
            self.windows.remove(n);
            self.tripped.remove(n);
        }
        names
    }

    pub fn usage(&self, now: i64) -> Vec<ToolUsage> {
        let mut names: Vec<&String> = self.windows.keys().chain(self.tripped.keys()).collect();
        names.sort();
        names.dedup();
        names
            .into_iter()
            .map(|n| ToolUsage {
                tool: n.clone(),
                used_last_hour: self
                    .windows
                    .get(n)
                    .map_or(0, |w| w.iter().filter(|t| now - **t < WINDOW_SECS).count()),
                tripped_at: self.tripped.get(n).copied(),
            })
            .collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetFile {
    version: u32,
    task: String,
    #[serde(flatten)]
    budgets: Budgets,
}

/// The persisted budget for one task.
#[derive(Debug, Clone)]
pub struct BudgetStore {
    dir: PathBuf,
    task: String,
}

/// Directory holding budget files.
pub fn budgets_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("budgets")
}

impl BudgetStore {
    pub fn new(state_dir: &Path, task: &str) -> BudgetStore {
        BudgetStore {
            dir: budgets_dir(state_dir),
            task: task.to_string(),
        }
    }

    pub fn task(&self) -> &str {
        &self.task
    }

    /// File name from a hash of the task, so any task name is a safe path.
    fn path(&self) -> PathBuf {
        self.dir
            .join(format!("{}.json", &sha256_hex(self.task.as_bytes())[..16]))
    }

    /// Run `f` on the stored state under the directory lock, saving the
    /// result if `f` changed it.
    fn update<T>(&self, f: impl FnOnce(&mut Budgets) -> T) -> Result<T, Error> {
        std::fs::create_dir_all(&self.dir)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.dir.join(".lock"))?;
        lock.lock()?;
        let result = (|| {
            let mut budgets = self.read()?;
            let before = budgets.clone();
            let out = f(&mut budgets);
            if budgets != before {
                let file = BudgetFile {
                    version: FORMAT_VERSION,
                    task: self.task.clone(),
                    budgets,
                };
                let path = self.path();
                let tmp = path.with_extension("json.tmp");
                std::fs::write(&tmp, serde_json::to_vec(&file)?)?;
                std::fs::rename(&tmp, &path)?;
            }
            Ok(out)
        })();
        let _ = lock.unlock();
        result
    }

    /// Read the stored state. A missing file is an empty budget; an
    /// unreadable or corrupt one is an error, never a silent reset.
    pub fn read(&self) -> Result<Budgets, Error> {
        let path = self.path();
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Budgets::new()),
            Err(e) => return Err(e.into()),
        };
        let file: BudgetFile = serde_json::from_slice(&bytes).map_err(|e| {
            Error::Io(format!(
                "budget file {} is corrupt ({e}); refusing to reset it silently",
                path.display()
            ))
        })?;
        if file.version != FORMAT_VERSION || file.task != self.task {
            return Err(Error::Io(format!(
                "budget file {} does not belong to task {:?} (format {})",
                path.display(),
                self.task,
                file.version
            )));
        }
        Ok(file.budgets)
    }

    /// Charge one unit of `tool`'s budget.
    pub fn consume(&self, tool: &str, per_hour: u32, now: i64) -> Result<BudgetCheck, Error> {
        self.update(|b| b.consume(tool, per_hour, now))
    }

    /// Reset `tool` (or every tool). Out-of-band only: called from the CLI.
    pub fn reset(&self, tool: Option<&str>) -> Result<Vec<String>, Error> {
        self.update(|b| b.reset(tool))
    }
}

/// Every task with stored budget state, with its usage, for `airlock budget status`.
pub fn list(state_dir: &Path, now: i64) -> Result<Vec<(String, Vec<ToolUsage>)>, Error> {
    let dir = budgets_dir(state_dir);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let mut out = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let file: BudgetFile = serde_json::from_slice(&std::fs::read(&path)?)
            .map_err(|e| Error::Io(format!("budget file {} is corrupt: {e}", path.display())))?;
        out.push((file.task, file.budgets.usage(now)));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_budget_then_trips_and_stays_tripped() {
        let mut b = Budgets::new();
        for i in 0..3 {
            assert_eq!(b.consume("mail.send", 3, 1000 + i), BudgetCheck::Ok);
        }
        assert!(matches!(
            b.consume("mail.send", 3, 1010),
            BudgetCheck::JustTripped(_)
        ));
        assert!(b.is_tripped("mail.send"));
        // Even after the window slides, the breaker stays open.
        assert!(matches!(
            b.consume("mail.send", 3, 1000 + 10_000),
            BudgetCheck::Tripped(_)
        ));
        // Other tools are unaffected.
        assert_eq!(b.consume("db.query", 3, 1010), BudgetCheck::Ok);
    }

    #[test]
    fn window_slides() {
        let mut b = Budgets::new();
        assert_eq!(b.consume("t", 1, 0), BudgetCheck::Ok);
        assert_eq!(b.consume("t", 1, 3600), BudgetCheck::Ok);
    }

    #[test]
    fn zero_budget_trips_immediately() {
        let mut b = Budgets::new();
        assert!(matches!(b.consume("t", 0, 0), BudgetCheck::JustTripped(_)));
    }

    #[test]
    fn budgets_survive_a_restart() {
        let d = tempfile::tempdir().unwrap();
        let first = BudgetStore::new(d.path(), "triage");
        assert_eq!(first.consume("mail.send", 2, 100).unwrap(), BudgetCheck::Ok);
        assert_eq!(first.consume("mail.send", 2, 101).unwrap(), BudgetCheck::Ok);
        drop(first);
        // A new gateway process for the same task sees the spent budget.
        let second = BudgetStore::new(d.path(), "triage");
        assert!(matches!(
            second.consume("mail.send", 2, 102).unwrap(),
            BudgetCheck::JustTripped(_)
        ));
        let third = BudgetStore::new(d.path(), "triage");
        assert!(matches!(
            third.consume("mail.send", 2, 99_999).unwrap(),
            BudgetCheck::Tripped(_)
        ));
    }

    #[test]
    fn tasks_are_kept_apart() {
        let d = tempfile::tempdir().unwrap();
        let a = BudgetStore::new(d.path(), "a");
        let b = BudgetStore::new(d.path(), "b/../../etc");
        assert_eq!(a.consume("t", 1, 0).unwrap(), BudgetCheck::Ok);
        assert_eq!(b.consume("t", 1, 0).unwrap(), BudgetCheck::Ok);
        assert!(matches!(
            a.consume("t", 1, 1).unwrap(),
            BudgetCheck::JustTripped(_)
        ));
        // Every file stays inside the budgets directory.
        for e in std::fs::read_dir(budgets_dir(d.path())).unwrap() {
            assert!(e.unwrap().path().starts_with(budgets_dir(d.path())));
        }
    }

    #[test]
    fn reset_closes_the_breaker() {
        let d = tempfile::tempdir().unwrap();
        let s = BudgetStore::new(d.path(), "t");
        s.consume("x", 1, 0).unwrap();
        s.consume("x", 1, 1).unwrap();
        s.consume("y", 5, 1).unwrap();
        assert!(s.read().unwrap().is_tripped("x"));
        assert_eq!(s.reset(Some("x")).unwrap(), vec!["x".to_string()]);
        assert_eq!(s.consume("x", 1, 2).unwrap(), BudgetCheck::Ok);
        assert_eq!(
            s.reset(None).unwrap(),
            vec!["x".to_string(), "y".to_string()]
        );
        assert!(s.read().unwrap().usage(2).is_empty());
    }

    #[test]
    fn corrupt_file_is_an_error_not_a_reset() {
        let d = tempfile::tempdir().unwrap();
        let s = BudgetStore::new(d.path(), "t");
        s.consume("x", 1, 0).unwrap();
        std::fs::write(s.path(), b"{not json").unwrap();
        assert!(s.consume("x", 1, 1).is_err());
        assert!(list(d.path(), 1).is_err());
    }

    #[test]
    fn usage_and_listing() {
        let d = tempfile::tempdir().unwrap();
        let s = BudgetStore::new(d.path(), "triage");
        s.consume("db.query", 10, 1000).unwrap();
        s.consume("db.query", 10, 1001).unwrap();
        let listed = list(d.path(), 1002).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0, "triage");
        assert_eq!(listed[0].1[0].used_last_hour, 2);
        assert_eq!(
            list(d.path(), 1000 + WINDOW_SECS + 5).unwrap()[0].1[0].used_last_hour,
            0
        );
    }
}
