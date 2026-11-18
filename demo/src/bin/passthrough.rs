//! A no-policy passthrough multiplexer: the "without airlock" baseline.
//!
//! It fronts the same three upstream servers with the same `upstream.tool`
//! names the gateway uses, but enforces nothing. This is what the hijacked
//! agent talks to in the unprotected run, so the only difference between the
//! two runs is airlock itself.

use airlock_demo::Client;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};

fn main() {
    // The demo servers are built alongside this binary (target/debug, or
    // demo/.run/bin when run.sh copies them), so find them next to it rather
    // than relative to the current directory.
    let exe = std::env::current_exe().expect("locate passthrough binary");
    let dir = exe.parent().expect("binary has a parent directory");
    let server = |name: &str| vec![dir.join(name).to_string_lossy().into_owned()];
    let upstreams = [
        ("db", server("db-server")),
        ("mail", server("mail-server")),
        ("web", server("web-server")),
    ];
    let mut clients: BTreeMap<&str, Client> = BTreeMap::new();
    for (name, cmd) in &upstreams {
        clients.insert(name, Client::spawn(cmd).expect("spawn upstream"));
    }

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
            "initialize" => {
                json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "passthrough", "version": "0.1.0"}})
            }
            "tools/list" => {
                let mut tools = Vec::new();
                for (name, c) in clients.iter_mut() {
                    let r = c
                        .request("tools/list", json!({}))
                        .unwrap_or(json!({"tools": []}));
                    if let Some(arr) = r["tools"].as_array() {
                        for t in arr {
                            let mut t = t.clone();
                            t["name"] =
                                json!(format!("{name}.{}", t["name"].as_str().unwrap_or("")));
                            tools.push(t);
                        }
                    }
                }
                json!({"tools": tools})
            }
            "tools/call" => {
                let full = msg["params"]["name"].as_str().unwrap_or("");
                let args = msg["params"].get("arguments").cloned().unwrap_or(json!({}));
                match full.split_once('.') {
                    Some((up, tool)) if clients.contains_key(up) => clients
                        .get_mut(up)
                        .unwrap()
                        .request("tools/call", json!({"name": tool, "arguments": args}))
                        .unwrap_or_else(
                            |e| json!({"content": [{"type": "text", "text": e}], "isError": true}),
                        ),
                    _ => {
                        json!({"content": [{"type": "text", "text": format!("unknown tool {full}")}], "isError": true})
                    }
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
