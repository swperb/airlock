//! The kill switch.
//!
//! Freezing is a file in the state directory. The gateway checks it on every
//! call, so `touch <state_dir>/FREEZE` works even when the CLI cannot reach
//! the gateway process, and every gateway sharing the state directory sees it.

use std::path::{Path, PathBuf};

pub const FREEZE_FILE: &str = "FREEZE";

pub fn freeze_path(state_dir: &Path) -> PathBuf {
    state_dir.join(FREEZE_FILE)
}

/// Is the organisation-wide write freeze on?
///
/// Returns `Err` if the state cannot be determined; callers treat that as
/// frozen for writes (fail closed) and as not frozen for reads (fail open).
pub fn is_frozen(state_dir: &Path) -> Result<bool, crate::Error> {
    match std::fs::symlink_metadata(freeze_path(state_dir)) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(crate::Error::Io(format!("checking freeze file: {e}"))),
    }
}

pub fn freeze(state_dir: &Path, by: &str) -> Result<(), crate::Error> {
    std::fs::create_dir_all(state_dir)?;
    let note = format!(
        "frozen by {by} at {}\n",
        crate::util::rfc3339(crate::util::now_unix())
    );
    std::fs::write(freeze_path(state_dir), note)?;
    Ok(())
}

pub fn unfreeze(state_dir: &Path) -> Result<bool, crate::Error> {
    match std::fs::remove_file(freeze_path(state_dir)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeze_roundtrip() {
        let d = tempfile::tempdir().unwrap();
        assert!(!is_frozen(d.path()).unwrap());
        freeze(d.path(), "ops").unwrap();
        assert!(is_frozen(d.path()).unwrap());
        assert!(unfreeze(d.path()).unwrap());
        assert!(!is_frozen(d.path()).unwrap());
        assert!(!unfreeze(d.path()).unwrap());
    }
}
