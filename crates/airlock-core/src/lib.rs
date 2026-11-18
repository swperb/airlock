//! airlock-core: the deterministic policy engine behind the airlock gateway.
//!
//! Nothing in this crate looks at prompt text or asks a model for an opinion.
//! Every decision comes from the policy file, the tool's class and the
//! provenance of the arguments.

pub mod approvals;
pub mod audit;
pub mod budget;
pub mod freeze;
pub mod gateway;
pub mod limits;
pub mod policy;
pub mod signing;
pub mod taint;
pub mod util;

pub use gateway::{Gateway, Notifier, Upstreams, Verdict};
pub use policy::{Class, Policy, Provenance};

use std::fmt;

/// Errors from the engine.
#[derive(Debug)]
pub enum Error {
    /// The policy file is invalid.
    Policy(String),
    /// A state file (approvals, audit, freeze) could not be read or written.
    Io(String),
    /// Something else that prevents evaluating a call.
    Internal(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Policy(m) => write!(f, "policy error: {m}"),
            Error::Io(m) => write!(f, "state error: {m}"),
            Error::Internal(m) => write!(f, "internal error: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Io(e.to_string())
    }
}
