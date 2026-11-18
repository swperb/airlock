//! A subprocess-backed [`Upstreams`] over MCP stdio.
//!
//! Each upstream is a child process speaking JSON-RPC over newline-delimited
//! stdio. The gateway is its sole client. Credentials come from the policy's
//! `env` for that upstream and are set on the child only; they are never
//! returned to the agent.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use airlock_core::gateway::PROTOCOL_VERSIONS;
use airlock_core::{Policy, Upstreams};
use serde_json::{json, Value};

/// One connected upstream MCP server.
struct Server {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
    initialized: bool,
}

impl Server {
    fn spawn(command: &[String], env: &BTreeMap<String, String>) -> Result<Server, String> {
        let mut cmd = Command::new(&command[0]);
        cmd.args(&command[1..])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| format!("spawning {:?}: {e}", command[0]))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let stdout = BufReader::new(child.stdout.take().ok_or("no stdout")?);
        Ok(Server {
            child,
            stdin,
            stdout,
            next_id: 1,
            initialized: false,
        })
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let mut line = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .map_err(|e| format!("writing to upstream: {e}"))?;
        self.stdin.flush().map_err(|e| e.to_string())?;
        // Read until a response with our id (skip notifications/logs).
        loop {
            let mut buf = String::new();
            let n = self
                .stdout
                .read_line(&mut buf)
                .map_err(|e| format!("reading from upstream: {e}"))?;
            if n == 0 {
                return Err("upstream closed the connection".into());
            }
            let trimmed = buf.trim();
            if trimmed.is_empty() {
                continue;
            }
            let msg: Value = match serde_json::from_str(trimmed) {
                Ok(v) => v,
                Err(_) => continue, // ignore non-JSON log noise
            };
            if msg.get("id").and_then(Value::as_i64) != Some(id) {
                continue;
            }
            if let Some(err) = msg.get("error") {
                return Err(format!("upstream error: {err}"));
            }
            return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
        }
    }

    fn ensure_initialized(&mut self) -> Result<(), String> {
        if self.initialized {
            return Ok(());
        }
        self.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSIONS[0],
                "capabilities": {},
                "clientInfo": {"name": "airlock-gateway", "version": env!("CARGO_PKG_VERSION")}
            }),
        )?;
        let notif = json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        let mut line = serde_json::to_string(&notif).map_err(|e| e.to_string())?;
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .map_err(|e| e.to_string())?;
        self.stdin.flush().map_err(|e| e.to_string())?;
        self.initialized = true;
        Ok(())
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Upstreams backed by child processes, spawned lazily on first use.
pub struct ProcessUpstreams {
    configs: BTreeMap<String, (Vec<String>, BTreeMap<String, String>)>,
    servers: BTreeMap<String, Server>,
}

impl ProcessUpstreams {
    pub fn from_policy(policy: &Policy) -> ProcessUpstreams {
        let configs = policy
            .upstreams
            .iter()
            .map(|u| (u.name.clone(), (u.command.clone(), u.env.clone())))
            .collect();
        ProcessUpstreams {
            configs,
            servers: BTreeMap::new(),
        }
    }

    fn server(&mut self, name: &str) -> Result<&mut Server, String> {
        if !self.servers.contains_key(name) {
            let (cmd, env) = self
                .configs
                .get(name)
                .ok_or_else(|| format!("no upstream {name:?}"))?
                .clone();
            let mut s = Server::spawn(&cmd, &env)?;
            s.ensure_initialized()?;
            self.servers.insert(name.to_string(), s);
        }
        Ok(self.servers.get_mut(name).unwrap())
    }
}

impl Upstreams for ProcessUpstreams {
    fn list_tools(&mut self, upstream: &str) -> Result<Vec<Value>, String> {
        let result = self.server(upstream)?.request("tools/list", json!({}))?;
        Ok(result
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default())
    }

    fn call_tool(&mut self, upstream: &str, tool: &str, args: &Value) -> Result<Value, String> {
        self.server(upstream)?
            .request("tools/call", json!({"name": tool, "arguments": args}))
    }
}
