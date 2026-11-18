//! Connections to upstream MCP servers, as configured in the policy.
//!
//! Two kinds:
//!
//! * **stdio**: a child process speaking newline-delimited JSON-RPC. Its
//!   credentials come from the policy's `env` for that upstream and are set on
//!   the child only.
//! * **streamable HTTP**: a remote MCP endpoint. Its bearer token is read from
//!   the environment variable named by `bearer_token_env` and sent only to that
//!   upstream.
//!
//! Neither kind ever returns credentials to the agent. Both are connected
//! lazily, honour `gateway.upstream_timeout_secs`, and are dropped and
//! reconnected after a transport failure so one hung or crashed server cannot
//! wedge the gateway.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use airlock_core::gateway::PROTOCOL_VERSIONS;
use airlock_core::policy::UpstreamConfig;
use airlock_core::{Policy, Upstreams};
use serde_json::{json, Value};

/// Largest response body accepted from an upstream.
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// A transport-level failure: the connection is dropped and rebuilt on the
/// next call. Distinct from a JSON-RPC error, which leaves it intact.
struct Broken(String);

type ConnResult<T> = Result<T, (String, bool)>;

fn ok_or_broken<T>(r: Result<T, Broken>) -> ConnResult<T> {
    r.map_err(|Broken(m)| (m, true))
}

// ---------------------------------------------------------------------------
// stdio
// ---------------------------------------------------------------------------

struct StdioConn {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    next_id: i64,
    timeout: Duration,
}

impl StdioConn {
    fn connect(
        command: &[String],
        env: &BTreeMap<String, String>,
        timeout: Duration,
    ) -> Result<StdioConn, Broken> {
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
            .map_err(|e| Broken(format!("spawning {:?}: {e}", command[0])))?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Broken("no stdin".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Broken("no stdout".into()))?;
        // A reader thread lets requests wait with a timeout.
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
        let mut conn = StdioConn {
            child,
            stdin,
            lines: rx,
            next_id: 1,
            timeout,
        };
        conn.request("initialize", initialize_params())
            .map_err(|(m, _)| Broken(format!("initialize failed: {m}")))?;
        conn.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
        Ok(conn)
    }

    fn send(&mut self, msg: &Value) -> Result<(), Broken> {
        let mut line = msg.to_string();
        line.push('\n');
        self.stdin
            .write_all(line.as_bytes())
            .and_then(|()| self.stdin.flush())
            .map_err(|e| Broken(format!("writing to upstream: {e}")))
    }

    fn request(&mut self, method: &str, params: Value) -> ConnResult<Value> {
        let id = self.next_id;
        self.next_id += 1;
        ok_or_broken(
            self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})),
        )?;
        let deadline = Instant::now() + self.timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let line = match self.lines.recv_timeout(remaining) {
                Ok(l) => l,
                Err(RecvTimeoutError::Timeout) => {
                    return Err((
                        format!("no response within {}s", self.timeout.as_secs()),
                        true,
                    ))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(("upstream closed the connection".into(), true))
                }
            };
            let Ok(msg) = serde_json::from_str::<Value>(line.trim()) else {
                continue; // log noise on stdout
            };
            if msg.get("id").and_then(Value::as_i64) != Some(id) || msg.get("method").is_some() {
                continue; // notifications, or requests from the server
            }
            return rpc_result(&msg);
        }
    }
}

impl Drop for StdioConn {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// streamable HTTP
// ---------------------------------------------------------------------------

struct HttpConn {
    agent: ureq::Agent,
    url: String,
    token: Option<String>,
    session: Option<String>,
    protocol: Option<String>,
    next_id: i64,
}

impl HttpConn {
    fn connect(url: &str, token: Option<String>, timeout: Duration) -> Result<HttpConn, Broken> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .max_redirects(0)
            .build()
            .into();
        let mut conn = HttpConn {
            agent,
            url: url.to_string(),
            token,
            session: None,
            protocol: None,
            next_id: 1,
        };
        let result = conn
            .request("initialize", initialize_params())
            .map_err(|(m, _)| Broken(format!("initialize failed: {m}")))?;
        conn.protocol = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .map(str::to_string);
        conn.post(
            &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            None,
        )
        .map_err(|(m, _)| Broken(m))?;
        Ok(conn)
    }

    fn request(&mut self, method: &str, params: Value) -> ConnResult<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        match self.post(&msg, Some(id))? {
            Some(resp) => rpc_result(&resp),
            None => Err((
                "upstream accepted the request but sent no response".into(),
                true,
            )),
        }
    }

    /// POST one message. For a request (`expect` is its id) returns the
    /// matching response; for a notification returns `None`.
    fn post(&mut self, msg: &Value, expect: Option<i64>) -> ConnResult<Option<Value>> {
        let mut req = self
            .agent
            .post(&self.url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream");
        if let Some(t) = &self.token {
            req = req.header("Authorization", &format!("Bearer {t}"));
        }
        if let Some(s) = &self.session {
            req = req.header("Mcp-Session-Id", s);
        }
        if let Some(p) = &self.protocol {
            req = req.header("MCP-Protocol-Version", p);
        }
        let mut resp = req
            .send(msg.to_string())
            .map_err(|e| (format!("HTTP request to upstream failed: {e}"), true))?;
        let status = resp.status().as_u16();
        if let Some(sid) = resp
            .headers()
            .get("mcp-session-id")
            .and_then(|v| v.to_str().ok())
        {
            self.session = Some(sid.to_string());
        }
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        match status {
            202 if expect.is_none() => return Ok(None),
            200 if expect.is_none() => return Ok(None),
            200 => {}
            404 if self.session.is_some() => {
                return Err((
                    "upstream session expired (HTTP 404); reconnecting on next call".into(),
                    true,
                ))
            }
            401 | 403 => {
                return Err((
                    format!("upstream refused the gateway's credentials (HTTP {status})"),
                    true,
                ))
            }
            _ => {
                let body = resp
                    .body_mut()
                    .with_config()
                    .limit(4096)
                    .read_to_string()
                    .unwrap_or_default();
                return Err((
                    format!("upstream returned HTTP {status}: {}", body.trim()),
                    true,
                ));
            }
        }
        let id = expect.unwrap_or_default();
        if content_type.starts_with("text/event-stream") {
            let reader = resp.body_mut().as_reader().take(MAX_RESPONSE_BYTES);
            return read_sse(BufReader::new(reader), id).map(Some);
        }
        let text = resp
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|e| (format!("reading upstream response: {e}"), true))?;
        let v: Value = serde_json::from_str(&text)
            .map_err(|e| (format!("upstream sent invalid JSON: {e}"), true))?;
        if v.get("id").and_then(Value::as_i64) == Some(id) {
            Ok(Some(v))
        } else {
            Err((
                "upstream response did not match the request id".into(),
                true,
            ))
        }
    }
}

impl Drop for HttpConn {
    fn drop(&mut self) {
        // Best-effort session termination.
        if let Some(sid) = &self.session {
            let mut req = self.agent.delete(&self.url).header("Mcp-Session-Id", sid);
            if let Some(t) = &self.token {
                req = req.header("Authorization", &format!("Bearer {t}"));
            }
            let _ = req.call();
        }
    }
}

/// Read a server-sent-event stream until the response with `id` arrives.
fn read_sse(reader: impl BufRead, id: i64) -> ConnResult<Value> {
    let mut data = String::new();
    let dispatch = |data: &mut String| -> Option<Value> {
        let text = std::mem::take(data);
        let v: Value = serde_json::from_str(text.trim()).ok()?;
        (v.get("id").and_then(Value::as_i64) == Some(id) && v.get("method").is_none()).then_some(v)
    };
    for line in reader.lines() {
        let line = line.map_err(|e| (format!("reading upstream event stream: {e}"), true))?;
        if line.is_empty() {
            if let Some(v) = dispatch(&mut data) {
                return Ok(v);
            }
        } else if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
        }
        // `event:`, `id:`, `retry:` and `:` comments are ignored.
    }
    if let Some(v) = dispatch(&mut data) {
        return Ok(v);
    }
    Err((
        "upstream event stream ended without a response".into(),
        true,
    ))
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

fn initialize_params() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSIONS[0],
        "capabilities": {},
        "clientInfo": {"name": "airlock-gateway", "version": env!("CARGO_PKG_VERSION")}
    })
}

/// Extract `result` from a JSON-RPC response. An `error` keeps the connection.
fn rpc_result(msg: &Value) -> ConnResult<Value> {
    if let Some(err) = msg.get("error") {
        return Err((format!("upstream error: {err}"), false));
    }
    Ok(msg.get("result").cloned().unwrap_or(Value::Null))
}

enum Conn {
    Stdio(StdioConn),
    Http(HttpConn),
}

impl Conn {
    fn request(&mut self, method: &str, params: Value) -> ConnResult<Value> {
        match self {
            Conn::Stdio(c) => c.request(method, params),
            Conn::Http(c) => c.request(method, params),
        }
    }
}

/// The policy's upstreams, connected lazily on first use.
pub struct PolicyUpstreams {
    configs: BTreeMap<String, UpstreamConfig>,
    conns: BTreeMap<String, Conn>,
    timeout: Duration,
}

impl PolicyUpstreams {
    pub fn from_policy(policy: &Policy) -> PolicyUpstreams {
        PolicyUpstreams {
            configs: policy
                .upstreams
                .iter()
                .map(|u| (u.name.clone(), u.clone()))
                .collect(),
            conns: BTreeMap::new(),
            timeout: Duration::from_secs(policy.gateway.upstream_timeout_secs.max(1)),
        }
    }

    fn connect(&self, cfg: &UpstreamConfig) -> Result<Conn, String> {
        match (&cfg.command, &cfg.url) {
            (Some(cmd), _) => StdioConn::connect(cmd, &cfg.env, self.timeout)
                .map(Conn::Stdio)
                .map_err(|Broken(m)| m),
            (None, Some(url)) => {
                let token = match &cfg.bearer_token_env {
                    Some(var) => Some(std::env::var(var).map_err(|_| {
                        format!(
                            "upstream {:?}: environment variable {var} is not set",
                            cfg.name
                        )
                    })?),
                    None => None,
                };
                HttpConn::connect(url, token, self.timeout)
                    .map(Conn::Http)
                    .map_err(|Broken(m)| m)
            }
            (None, None) => Err(format!("upstream {:?} has no command or url", cfg.name)),
        }
    }

    fn request(&mut self, upstream: &str, method: &str, params: Value) -> Result<Value, String> {
        if !self.conns.contains_key(upstream) {
            let cfg = self
                .configs
                .get(upstream)
                .ok_or_else(|| format!("no upstream {upstream:?}"))?;
            let conn = self.connect(cfg)?;
            self.conns.insert(upstream.to_string(), conn);
        }
        let conn = self.conns.get_mut(upstream).expect("inserted above");
        match conn.request(method, params) {
            Ok(v) => Ok(v),
            Err((msg, broken)) => {
                if broken {
                    self.conns.remove(upstream);
                }
                Err(msg)
            }
        }
    }
}

impl Upstreams for PolicyUpstreams {
    fn list_tools(&mut self, upstream: &str) -> Result<Vec<Value>, String> {
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        // Follow pagination, with a hard cap so a misbehaving server cannot loop us.
        for _ in 0..100 {
            let params = match &cursor {
                Some(c) => json!({"cursor": c}),
                None => json!({}),
            };
            let result = self.request(upstream, "tools/list", params)?;
            if let Some(arr) = result.get("tools").and_then(Value::as_array) {
                tools.extend(arr.iter().cloned());
            }
            cursor = result
                .get("nextCursor")
                .and_then(Value::as_str)
                .map(str::to_string);
            if cursor.is_none() {
                break;
            }
        }
        Ok(tools)
    }

    fn call_tool(&mut self, upstream: &str, tool: &str, args: &Value) -> Result<Value, String> {
        self.request(
            upstream,
            "tools/call",
            json!({"name": tool, "arguments": args}),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_finds_the_matching_response() {
        let stream =
            "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n\
                      : keepalive\n\
                      data: {\"jsonrpc\":\"2.0\",\"id\":7,\n\
                      data:  \"result\":{\"ok\":true}}\n\n";
        let v = read_sse(stream.as_bytes(), 7).ok().unwrap();
        assert_eq!(v["result"]["ok"], json!(true));
    }

    #[test]
    fn sse_without_response_is_an_error() {
        let stream = "data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n";
        assert!(read_sse(stream.as_bytes(), 2).is_err());
    }

    #[test]
    fn sse_ignores_server_requests_with_the_same_id() {
        let stream =
            "data: {\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"sampling/createMessage\"}\n\n\
                      data: {\"jsonrpc\":\"2.0\",\"id\":3,\"result\":{\"x\":1}}\n\n";
        let v = read_sse(stream.as_bytes(), 3).ok().unwrap();
        assert_eq!(v["result"]["x"], json!(1));
    }
}
