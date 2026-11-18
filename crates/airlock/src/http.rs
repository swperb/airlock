//! MCP streamable HTTP transport, facing the agent.
//!
//! One endpoint, `/mcp`:
//!
//! * `POST` carries one JSON-RPC message. A request gets a JSON response; a
//!   notification or response gets `202 Accepted`. The first message of a
//!   session must be `initialize`; its response carries an `Mcp-Session-Id`
//!   header that every later request must send back.
//! * `DELETE` with `Mcp-Session-Id` ends the session.
//! * `GET` returns `405`: airlock never sends server-initiated messages, so it
//!   offers no event stream.
//!
//! Each MCP session gets its own [`Gateway`] (and its own upstream
//! connections), but taint and budgets are shared by every session of the task
//! (see [`airlock_core::gateway::TaskState`]), so opening a new session does
//! not reset them.
//!
//! Hardening: a bearer token is required unless the listener is loopback-only;
//! requests carrying an `Origin` header are refused unless that origin is
//! explicitly allowed (DNS-rebinding defence); bodies, sessions and idle time
//! are bounded. TLS is not terminated here: put a reverse proxy in front for
//! anything beyond localhost.

use std::collections::HashMap;
use std::io::Read;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use airlock_core::gateway::PROTOCOL_VERSIONS;
use airlock_core::{Gateway, Upstreams};
use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

pub const ENDPOINT: &str = "/mcp";

/// Settings for the HTTP listener.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Address to bind, e.g. `127.0.0.1:8787`.
    pub listen: String,
    /// Bearer token agents must present. Required for non-loopback listeners.
    pub token: Option<String>,
    /// Origins allowed to call the endpoint. Requests with any other `Origin`
    /// header are refused; requests without one (non-browser clients) pass.
    pub allowed_origins: Vec<String>,
    pub workers: usize,
    pub max_sessions: usize,
    pub idle_timeout: Duration,
    pub max_body_bytes: usize,
}

impl HttpConfig {
    pub fn new(listen: &str) -> HttpConfig {
        HttpConfig {
            listen: listen.to_string(),
            token: None,
            allowed_origins: Vec::new(),
            workers: 8,
            max_sessions: 256,
            idle_timeout: Duration::from_secs(3600),
            max_body_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Builds the gateway for a new session, given its session id.
pub type GatewayFactory<U> = dyn Fn(&str) -> Result<Gateway<U>, String> + Send + Sync;

struct Session<U: Upstreams> {
    gw: Gateway<U>,
    last_used: Instant,
}

struct Shared<U: Upstreams> {
    cfg: HttpConfig,
    factory: Box<GatewayFactory<U>>,
    sessions: Mutex<HashMap<String, Arc<Mutex<Session<U>>>>>,
}

/// A running HTTP gateway.
pub struct HttpGateway {
    server: Arc<Server>,
    workers: Vec<JoinHandle<()>>,
    addr: SocketAddr,
}

impl HttpGateway {
    /// The bound address (useful when listening on port 0).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// The endpoint URL agents should use.
    pub fn url(&self) -> String {
        format!("http://{}{ENDPOINT}", self.addr)
    }

    /// Block until the server stops.
    pub fn join(self) {
        for w in self.workers {
            let _ = w.join();
        }
    }

    /// Stop accepting requests and wait for the workers to finish.
    pub fn shutdown(self) {
        for _ in &self.workers {
            self.server.unblock();
        }
        self.join();
    }
}

/// Bind and start serving. Refuses to listen on a non-loopback address
/// without a token.
pub fn start<U>(cfg: HttpConfig, factory: Box<GatewayFactory<U>>) -> Result<HttpGateway, String>
where
    U: Upstreams + Send + 'static,
{
    let wanted: SocketAddr = cfg
        .listen
        .parse()
        .map_err(|e| format!("invalid listen address {:?}: {e}", cfg.listen))?;
    if !wanted.ip().is_loopback() && cfg.token.is_none() {
        return Err(format!(
            "refusing to listen on non-loopback address {wanted} without a bearer token; set AIRLOCK_HTTP_TOKEN"
        ));
    }
    if cfg.token.as_deref().is_some_and(|t| t.len() < 16) {
        return Err("AIRLOCK_HTTP_TOKEN must be at least 16 characters".into());
    }
    let server = Server::http(wanted).map_err(|e| format!("binding {wanted}: {e}"))?;
    let addr = server
        .server_addr()
        .to_ip()
        .ok_or("listener has no IP address")?;
    let server = Arc::new(server);
    let workers_n = cfg.workers.max(1);
    let shared = Arc::new(Shared {
        cfg,
        factory,
        sessions: Mutex::new(HashMap::new()),
    });
    let mut workers = Vec::new();
    for _ in 0..workers_n {
        let server = Arc::clone(&server);
        let shared = Arc::clone(&shared);
        workers.push(std::thread::spawn(move || {
            while let Ok(rq) = server.recv() {
                handle(&shared, rq);
            }
        }));
    }
    Ok(HttpGateway {
        server,
        workers,
        addr,
    })
}

fn header<'a>(rq: &'a Request, name: &str) -> Option<&'a str> {
    rq.headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case(name))
        .map(|h| h.value.as_str())
}

fn hdr(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("valid header")
}

fn text(status: u16, msg: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(format!("{msg}\n"))
        .with_status_code(status)
        .with_header(hdr("Content-Type", "text/plain; charset=utf-8"))
}

fn json_response(status: u16, body: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body.to_string())
        .with_status_code(status)
        .with_header(hdr("Content-Type", "application/json"))
}

fn rpc_error(
    status: u16,
    id: &Value,
    code: i64,
    message: &str,
) -> Response<std::io::Cursor<Vec<u8>>> {
    json_response(
        status,
        &json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}),
    )
}

/// Constant-time comparison, so response timing does not reveal the token.
fn token_matches(given: &str, expected: &str) -> bool {
    let (a, b) = (given.as_bytes(), expected.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn new_session_id() -> Result<String, String> {
    let mut bytes = [0u8; 24];
    getrandom::fill(&mut bytes).map_err(|e| format!("no system randomness: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn handle<U: Upstreams + Send + 'static>(shared: &Shared<U>, mut rq: Request) {
    let resp = route(shared, &mut rq);
    let _ = rq.respond(resp);
}

fn route<U: Upstreams + Send + 'static>(
    shared: &Shared<U>,
    rq: &mut Request,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let path = rq.url().split('?').next().unwrap_or("");
    if path != ENDPOINT {
        return text(404, "not found; the MCP endpoint is /mcp");
    }

    // DNS-rebinding defence: browsers always send Origin; refuse unknown ones.
    if let Some(origin) = header(rq, "Origin") {
        if !shared.cfg.allowed_origins.iter().any(|o| o == origin) {
            return text(403, "origin not allowed");
        }
    }

    if let Some(expected) = &shared.cfg.token {
        let given = header(rq, "Authorization").and_then(|v| {
            let (scheme, rest) = v.split_once(' ')?;
            scheme.eq_ignore_ascii_case("bearer").then(|| rest.trim())
        });
        if !given.is_some_and(|g| token_matches(g, expected)) {
            return text(401, "missing or invalid bearer token")
                .with_header(hdr("WWW-Authenticate", "Bearer realm=\"airlock\""));
        }
    }

    if let Some(v) = header(rq, "MCP-Protocol-Version") {
        if !PROTOCOL_VERSIONS.contains(&v) {
            return text(400, &format!("unsupported MCP-Protocol-Version {v:?}"));
        }
    }

    let session_id = header(rq, "Mcp-Session-Id").map(str::to_string);
    match rq.method() {
        Method::Post => post(shared, rq, session_id),
        Method::Delete => match session_id {
            Some(sid) => {
                let removed = shared
                    .sessions
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&sid);
                if removed.is_some() {
                    text(200, "session ended")
                } else {
                    text(404, "unknown session")
                }
            }
            None => text(400, "DELETE needs an Mcp-Session-Id header"),
        },
        Method::Get => text(405, "airlock sends no server-initiated messages; use POST")
            .with_header(hdr("Allow", "POST, DELETE")),
        _ => text(405, "method not allowed").with_header(hdr("Allow", "POST, DELETE")),
    }
}

fn post<U: Upstreams + Send + 'static>(
    shared: &Shared<U>,
    rq: &mut Request,
    session_id: Option<String>,
) -> Response<std::io::Cursor<Vec<u8>>> {
    let content_type = header(rq, "Content-Type")
        .unwrap_or("")
        .to_ascii_lowercase();
    if !content_type.starts_with("application/json") {
        return text(415, "Content-Type must be application/json");
    }

    // Read at most max_body_bytes + 1 so an oversized body is detected
    // without buffering all of it.
    let limit = shared.cfg.max_body_bytes;
    let mut body = Vec::new();
    if rq
        .as_reader()
        .take(limit as u64 + 1)
        .read_to_end(&mut body)
        .is_err()
    {
        return text(400, "could not read request body");
    }
    if body.len() > limit {
        return text(413, &format!("request body exceeds {limit} bytes"));
    }

    let msg: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return rpc_error(400, &Value::Null, -32700, &format!("parse error: {e}")),
    };
    if msg.is_array() {
        return rpc_error(
            400,
            &Value::Null,
            -32600,
            "JSON-RPC batches are not supported",
        );
    }

    let session = match session_id {
        Some(sid) => {
            let found = shared
                .sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&sid)
                .cloned();
            match found {
                Some(s) => (sid, s),
                None => return text(404, "unknown or expired session; initialize a new one"),
            }
        }
        None => {
            let is_initialize = msg.get("method").and_then(Value::as_str) == Some("initialize")
                && msg.get("id").is_some();
            if !is_initialize {
                return text(
                    400,
                    "missing Mcp-Session-Id; the first request must be initialize",
                );
            }
            match create_session(shared) {
                Ok(pair) => pair,
                Err(resp) => return resp,
            }
        }
    };

    let (sid, session) = session;
    let reply = {
        let mut s = session.lock().unwrap_or_else(|e| e.into_inner());
        s.last_used = Instant::now();
        s.gw.handle(&msg)
    };
    let resp = match reply {
        Some(v) => json_response(200, &v),
        None => Response::from_string(String::new()).with_status_code(202),
    };
    resp.with_header(hdr("Mcp-Session-Id", &sid))
}

#[allow(clippy::type_complexity)]
fn create_session<U: Upstreams + Send + 'static>(
    shared: &Shared<U>,
) -> Result<(String, Arc<Mutex<Session<U>>>), Response<std::io::Cursor<Vec<u8>>>> {
    let sid = new_session_id().map_err(|e| text(500, &e))?;
    let mut sessions = shared.sessions.lock().unwrap_or_else(|e| e.into_inner());

    // Drop idle sessions that nobody is using right now.
    let idle = shared.cfg.idle_timeout;
    sessions.retain(|_, s| match s.try_lock() {
        Ok(s) => s.last_used.elapsed() < idle,
        Err(_) => true,
    });
    if sessions.len() >= shared.cfg.max_sessions {
        return Err(text(
            503,
            "too many open sessions; end one with DELETE or try later",
        ));
    }

    let gw = (shared.factory)(&sid).map_err(|e| {
        eprintln!("airlock: could not start session: {e}");
        text(
            500,
            "could not start a gateway session; see the gateway log",
        )
    })?;
    let session = Arc::new(Mutex::new(Session {
        gw,
        last_used: Instant::now(),
    }));
    sessions.insert(sid.clone(), Arc::clone(&session));
    Ok((sid, session))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_comparison() {
        assert!(token_matches("abcdefghijklmnop", "abcdefghijklmnop"));
        assert!(!token_matches("abcdefghijklmnoq", "abcdefghijklmnop"));
        assert!(!token_matches("short", "abcdefghijklmnop"));
    }

    #[test]
    fn session_ids_are_random_and_long() {
        let a = new_session_id().unwrap();
        let b = new_session_id().unwrap();
        assert_eq!(a.len(), 48);
        assert_ne!(a, b);
    }
}
