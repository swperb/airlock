//! Small shared helpers: time, hashing, canonical JSON, redaction.

use serde_json::Value;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Current time as Unix seconds.
pub fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// Format Unix seconds as RFC 3339.
pub fn rfc3339(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| unix.to_string())
}

/// Hex SHA-256 of the given bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Canonical JSON text. `serde_json` maps are sorted (no `preserve_order`),
/// so serialising a `Value` is already canonical.
pub fn canonical(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

/// Replace the values of any keys in `keys` (case-insensitive, any depth).
pub fn redact(v: &Value, keys: &[String]) -> Value {
    if keys.is_empty() {
        return v.clone();
    }
    match v {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, val)| {
                    if keys.iter().any(|r| r.eq_ignore_ascii_case(k)) {
                        (k.clone(), Value::String("[redacted]".into()))
                    } else {
                        (k.clone(), redact(val, keys))
                    }
                })
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.iter().map(|i| redact(i, keys)).collect()),
        other => other.clone(),
    }
}

/// Every string in a JSON value, with its JSON-pointer path.
pub fn strings_with_paths(v: &Value) -> Vec<(String, &str)> {
    fn walk<'a>(v: &'a Value, path: String, out: &mut Vec<(String, &'a str)>) {
        match v {
            Value::String(s) => out.push((path, s)),
            Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    walk(item, format!("{path}/{i}"), out);
                }
            }
            Value::Object(map) => {
                for (k, item) in map {
                    let esc = k.replace('~', "~0").replace('/', "~1");
                    walk(item, format!("{path}/{esc}"), out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, String::new(), &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_nested_keys() {
        let v = json!({"a": {"Password": "x", "b": [{"token": "t"}]}, "c": 1});
        let r = redact(&v, &["password".into(), "TOKEN".into()]);
        assert_eq!(
            r,
            json!({"a": {"Password": "[redacted]", "b": [{"token": "[redacted]"}]}, "c": 1})
        );
    }

    #[test]
    fn canonical_is_key_sorted() {
        let a: Value = serde_json::from_str(r#"{"b":1,"a":2}"#).unwrap();
        assert_eq!(canonical(&a), r#"{"a":2,"b":1}"#);
    }
}
