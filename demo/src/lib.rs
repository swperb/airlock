//! Shared helpers for the demo: a minimal MCP stdio server and client.
//!
//! Everything here is a local stand-in. The "database" is a SQLite file, the
//! "mail server" appends to a file, and the "web" server returns a fixture.
//! Nothing touches the network.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

/// A tool a demo server offers.
pub struct ToolDef {
    pub name: &'static str,
    pub description: &'static str,
    pub schema: Value,
}

/// Serve MCP on stdio. `handler(tool, args)` returns the text result or an error.
pub fn serve(
    name: &str,
    tools: Vec<ToolDef>,
    mut handler: impl FnMut(&str, &Value) -> Result<String, String>,
) {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let Ok(msg) = serde_json::from_str::<Value>(line.trim()) else {
            continue;
        };
        let Some(id) = msg.get("id").cloned() else {
            continue;
        };
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        let result = match method {
            "initialize" => json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": name, "version": "0.1.0"}
            }),
            "tools/list" => json!({"tools": tools.iter().map(|t| json!({
                "name": t.name, "description": t.description, "inputSchema": t.schema
            })).collect::<Vec<_>>()}),
            "tools/call" => {
                let tool = msg["params"]["name"].as_str().unwrap_or("");
                let args = msg["params"].get("arguments").cloned().unwrap_or(json!({}));
                match handler(tool, &args) {
                    Ok(text) => json!({"content": [{"type": "text", "text": text}]}),
                    Err(e) => json!({"content": [{"type": "text", "text": e}], "isError": true}),
                }
            }
            "ping" => json!({}),
            _ => {
                let _ = writeln!(
                    out,
                    "{}",
                    json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "method not found"}})
                );
                let _ = out.flush();
                continue;
            }
        };
        let _ = writeln!(
            out,
            "{}",
            json!({"jsonrpc": "2.0", "id": id, "result": result})
        );
        let _ = out.flush();
    }
}

/// A blocking MCP client over a child process's stdio.
pub struct Client {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next: i64,
}

impl Client {
    pub fn spawn(cmd: &[String]) -> Result<Client, String> {
        let mut child = Command::new(&cmd[0])
            .args(&cmd[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawning {:?}: {e}", cmd[0]))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("no stdout")?);
        let mut c = Client {
            child,
            stdin,
            stdout,
            next: 1,
        };
        c.request("initialize", json!({"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "demo-agent", "version": "0.1.0"}}))?;
        c.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
        Ok(c)
    }

    fn send(&mut self, v: &Value) -> Result<(), String> {
        writeln!(self.stdin, "{v}").map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())
    }

    pub fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next;
        self.next += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        loop {
            let mut line = String::new();
            if self
                .stdout
                .read_line(&mut line)
                .map_err(|e| e.to_string())?
                == 0
            {
                return Err("server closed the connection".into());
            }
            let Ok(msg) = serde_json::from_str::<Value>(line.trim()) else {
                continue;
            };
            if msg.get("id").and_then(Value::as_i64) != Some(id) {
                continue;
            }
            if let Some(e) = msg.get("error") {
                return Err(e.to_string());
            }
            return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    /// Call a tool; returns (is_error, text).
    pub fn call(&mut self, tool: &str, args: Value) -> Result<(bool, String), String> {
        let r = self.request("tools/call", json!({"name": tool, "arguments": args}))?;
        let text = r["content"]
            .as_array()
            .map(|c| {
                c.iter()
                    .filter_map(|i| i["text"].as_str())
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        Ok((r["isError"].as_bool().unwrap_or(false), text))
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Read a path from an env var with a default.
pub fn env_path(var: &str, default: &str) -> String {
    std::env::var(var).unwrap_or_else(|_| default.to_string())
}
