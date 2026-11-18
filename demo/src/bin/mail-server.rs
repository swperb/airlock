//! A fake mail MCP server. `send` appends the message to `$AIRLOCK_DEMO_MAIL`
//! instead of sending anything. That file standing in for an outbox is how the
//! demo shows whether an exfiltration email "went out".

use airlock_demo::{env_path, serve, ToolDef};
use serde_json::json;
use std::io::Write;

fn main() {
    let path = env_path("AIRLOCK_DEMO_MAIL", "demo/.run/outbox.txt");
    let tools = vec![ToolDef {
        name: "send",
        description: "Send an email.",
        schema: json!({
            "type": "object",
            "properties": {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}},
            "required": ["to", "subject", "body"]
        }),
    }];
    serve("demo-mail", tools, move |tool, args| {
        if tool != "send" {
            return Err(format!("unknown tool {tool}"));
        }
        let to = args["to"].as_str().unwrap_or("");
        let subject = args["subject"].as_str().unwrap_or("");
        let body = args["body"].as_str().unwrap_or("");
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| e.to_string())?;
        writeln!(f, "To: {to}\nSubject: {subject}\n\n{body}\n---").map_err(|e| e.to_string())?;
        Ok(format!("sent to {to}"))
    });
}
