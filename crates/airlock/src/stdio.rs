//! Newline-delimited JSON-RPC over stdio, facing the agent.

use std::io::{BufRead, Write};

use airlock_core::{Gateway, Upstreams};
use serde_json::Value;

/// Serve the gateway over the given reader/writer until EOF.
///
/// Each input line is one JSON-RPC message. Blank lines are skipped;
/// unparseable lines get a JSON-RPC parse error. Responses are written one per
/// line and flushed immediately.
pub fn serve<U: Upstreams>(
    gw: &mut Gateway<U>,
    input: impl BufRead,
    mut output: impl Write,
) -> std::io::Result<()> {
    for line in input.lines() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let response = match serde_json::from_str::<Value>(trimmed) {
            Ok(msg) => gw.handle(&msg),
            Err(e) => Some(serde_json::json!({
                "jsonrpc": "2.0",
                "id": Value::Null,
                "error": {"code": -32700, "message": format!("parse error: {e}")}
            })),
        };
        if let Some(resp) = response {
            let mut text = serde_json::to_string(&resp).unwrap_or_default();
            text.push('\n');
            output.write_all(text.as_bytes())?;
            output.flush()?;
        }
    }
    Ok(())
}
