//! Per-tool hourly budgets with a circuit breaker.
//!
//! Each attempt that reaches the budget step consumes one unit, whether it is
//! later forwarded, held or refused. When a tool exceeds its budget the
//! breaker trips and that tool stays refused for the rest of the gateway
//! process, so a runaway agent is stopped rather than throttled.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

const WINDOW_SECS: i64 = 3600;

#[derive(Debug, Default, Clone)]
pub struct Budgets {
    windows: BTreeMap<String, VecDeque<i64>>,
    tripped: BTreeSet<String>,
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

impl Budgets {
    pub fn new() -> Self {
        Self::default()
    }

    /// Consume one unit of `tool`'s budget at time `now`.
    pub fn consume(&mut self, tool: &str, per_hour: u32, now: i64) -> BudgetCheck {
        if self.tripped.contains(tool) {
            return BudgetCheck::Tripped(format!(
                "circuit breaker open for {tool}: budget of {per_hour}/hour was exceeded earlier in this session"
            ));
        }
        let w = self.windows.entry(tool.to_string()).or_default();
        while w.front().is_some_and(|t| now - *t >= WINDOW_SECS) {
            w.pop_front();
        }
        if w.len() as u64 >= u64::from(per_hour) {
            self.tripped.insert(tool.to_string());
            return BudgetCheck::JustTripped(format!(
                "budget exceeded for {tool}: {per_hour}/hour; circuit breaker tripped"
            ));
        }
        w.push_back(now);
        BudgetCheck::Ok
    }

    pub fn is_tripped(&self, tool: &str) -> bool {
        self.tripped.contains(tool)
    }
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
}
