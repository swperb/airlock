//! A fake database MCP server backed by SQLite.
//!
//! Tools: `query` (read) and `execute` (write). The database file is
//! `$AIRLOCK_DEMO_DB`. On first start it seeds a `customers` table so the
//! demo has something to lose.

use airlock_demo::{env_path, serve, ToolDef};
use rusqlite::Connection;
use serde_json::{json, Value};

fn main() {
    let path = env_path("AIRLOCK_DEMO_DB", "demo/.run/demo.db");
    let conn = Connection::open(&path).expect("open sqlite");
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS customers (id INTEGER PRIMARY KEY, name TEXT, email TEXT);
         DELETE FROM customers;
         INSERT INTO customers (id, name, email) VALUES
           (1, 'Ada Lovelace', 'ada@example.com'),
           (2, 'Alan Turing', 'alan@example.com'),
           (3, 'Grace Hopper', 'grace@example.com');",
    )
    .expect("seed");

    let tools = vec![
        ToolDef {
            name: "query",
            description: "Run a read-only SQL query and return rows as JSON.",
            schema: json!({"type": "object", "properties": {"sql": {"type": "string"}}, "required": ["sql"]}),
        },
        ToolDef {
            name: "execute",
            description: "Run a statement that changes the database (INSERT/UPDATE/DELETE/DDL).",
            schema: json!({"type": "object", "properties": {"sql": {"type": "string"}}, "required": ["sql"]}),
        },
    ];

    serve("demo-db", tools, move |tool, args| {
        let sql = args["sql"].as_str().ok_or("missing sql")?;
        match tool {
            "query" => {
                let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
                let cols: Vec<String> = stmt.column_names().iter().map(|s| s.to_string()).collect();
                let rows: Vec<Value> = stmt
                    .query_map([], |row| {
                        let mut obj = serde_json::Map::new();
                        for (i, c) in cols.iter().enumerate() {
                            let v: rusqlite::types::Value =
                                row.get(i).unwrap_or(rusqlite::types::Value::Null);
                            obj.insert(c.clone(), sqlite_to_json(v));
                        }
                        Ok(Value::Object(obj))
                    })
                    .map_err(|e| e.to_string())?
                    .filter_map(Result::ok)
                    .collect();
                Ok(serde_json::to_string(&rows).unwrap())
            }
            "execute" => {
                let n = conn.execute(sql, []).map_err(|e| e.to_string())?;
                Ok(format!("OK, {n} row(s) affected"))
            }
            other => Err(format!("unknown tool {other}")),
        }
    });
}

fn sqlite_to_json(v: rusqlite::types::Value) -> Value {
    use rusqlite::types::Value as S;
    match v {
        S::Null => Value::Null,
        S::Integer(i) => json!(i),
        S::Real(f) => json!(f),
        S::Text(s) => json!(s),
        S::Blob(b) => json!(format!("<{} bytes>", b.len())),
    }
}
