//! Argument limits from the grant, and deny patterns from the tool definition.

use serde_json::Value;

use crate::policy::{ArgLimit, Constraint, Tool};
use crate::util::strings_with_paths;

/// Check deny patterns against every string in the arguments, at any depth.
/// A match refuses the call outright; approval cannot override it.
pub fn check_deny_patterns(tool: &Tool, args: &Value) -> Result<(), String> {
    for (path, s) in strings_with_paths(args) {
        for re in &tool.deny_patterns {
            if re.is_match(s) {
                return Err(format!(
                    "argument {} matches deny pattern {:?} for {} (denied even with approval)",
                    display_path(&path),
                    re.as_str(),
                    tool.name
                ));
            }
        }
    }
    Ok(())
}

fn display_path(p: &str) -> String {
    if p.is_empty() {
        "(root)".into()
    } else {
        p.to_string()
    }
}

/// Check one grant limit against the call's arguments.
///
/// A constrained argument must be present: a missing value is refused rather
/// than guessed at. The value may be a string or an array of strings; every
/// element must pass.
pub fn check_limit(limit: &ArgLimit, args: &Value) -> Result<(), String> {
    let Some(value) = args.get(&limit.arg) else {
        return Err(format!(
            "argument {:?} is constrained by {} but missing",
            limit.arg, limit.key
        ));
    };
    let values: Vec<&str> = match value {
        Value::String(s) => vec![s.as_str()],
        Value::Array(items) => {
            let mut out = Vec::new();
            for item in items {
                match item {
                    Value::String(s) => out.push(s.as_str()),
                    _ => {
                        return Err(format!(
                            "argument {:?} must contain only strings for {}",
                            limit.arg, limit.key
                        ))
                    }
                }
            }
            if out.is_empty() {
                return Err(format!("argument {:?} is empty", limit.arg));
            }
            out
        }
        _ => {
            return Err(format!(
                "argument {:?} must be a string or array of strings for {}",
                limit.arg, limit.key
            ))
        }
    };
    for v in values {
        check_one(limit, v)?;
    }
    Ok(())
}

fn check_one(limit: &ArgLimit, v: &str) -> Result<(), String> {
    match &limit.constraint {
        Constraint::Domains(domains) => {
            // One address per value: separators would let `a@ok.com, b@evil.com` through.
            if v.chars()
                .any(|c| c.is_whitespace() || matches!(c, ',' | ';' | '<' | '>' | '"' | '(' | ')'))
            {
                return Err(format!(
                    "argument {:?} value {v:?} must be a single bare address",
                    limit.arg
                ));
            }
            let Some((local, domain)) = v.rsplit_once('@') else {
                return Err(format!(
                    "argument {:?} value {v:?} is not an address",
                    limit.arg
                ));
            };
            if local.is_empty() || local.contains('@') {
                return Err(format!(
                    "argument {:?} value {v:?} is not a valid address",
                    limit.arg
                ));
            }
            let domain = domain.trim_end_matches('.').to_ascii_lowercase();
            let ok = domains
                .iter()
                .any(|d| domain == *d || domain.ends_with(&format!(".{d}")));
            if ok {
                Ok(())
            } else {
                Err(format!(
                    "argument {:?} domain {domain:?} is not in {} {:?}",
                    limit.arg, limit.key, domains
                ))
            }
        }
        Constraint::OneOf(allowed) => {
            if allowed.iter().any(|a| a == v) {
                Ok(())
            } else {
                Err(format!(
                    "argument {:?} value {v:?} is not in {} {:?}",
                    limit.arg, limit.key, allowed
                ))
            }
        }
        Constraint::Matches(re) => {
            if re.is_match(v) {
                Ok(())
            } else {
                Err(format!(
                    "argument {:?} value {v:?} does not match {}",
                    limit.arg, limit.key
                ))
            }
        }
        Constraint::MaxLen(n) => {
            if v.chars().count() <= *n {
                Ok(())
            } else {
                Err(format!(
                    "argument {:?} is longer than {} ({n})",
                    limit.arg, limit.key
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use regex::Regex;
    use serde_json::json;

    fn domains() -> ArgLimit {
        ArgLimit {
            arg: "to".into(),
            key: "to_domains".into(),
            constraint: Constraint::Domains(vec!["example.com".into()]),
        }
    }

    #[test]
    fn domain_allowlist() {
        let l = domains();
        assert!(check_limit(&l, &json!({"to": "a@example.com"})).is_ok());
        assert!(check_limit(&l, &json!({"to": "a@Sub.Example.COM"})).is_ok());
        assert!(check_limit(&l, &json!({"to": ["a@example.com", "b@example.com"]})).is_ok());
        assert!(check_limit(&l, &json!({"to": "a@attacker.example"})).is_err());
        assert!(check_limit(&l, &json!({"to": "a@notexample.com"})).is_err());
        assert!(check_limit(&l, &json!({"to": "a@example.com.evil.io"})).is_err());
        assert!(check_limit(&l, &json!({"to": "a@example.com, b@evil.io"})).is_err());
        assert!(check_limit(&l, &json!({"to": "Bob <b@evil.io>"})).is_err());
        assert!(check_limit(&l, &json!({"to": ["a@example.com", "b@evil.io"]})).is_err());
        assert!(check_limit(&l, &json!({"to": "a@b@example.com"})).is_err());
        assert!(check_limit(&l, &json!({"to": 5})).is_err());
        assert!(check_limit(&l, &json!({"to": []})).is_err());
        assert!(
            check_limit(&l, &json!({})).is_err(),
            "missing constrained arg is refused"
        );
    }

    #[test]
    fn one_of_matches_max_len() {
        let l = ArgLimit {
            arg: "table".into(),
            key: "table_in".into(),
            constraint: Constraint::OneOf(vec!["tickets".into()]),
        };
        assert!(check_limit(&l, &json!({"table": "tickets"})).is_ok());
        assert!(check_limit(&l, &json!({"table": "customers"})).is_err());
        let l = ArgLimit {
            arg: "id".into(),
            key: "id_matches".into(),
            constraint: Constraint::Matches(Regex::new("^(?:[0-9]+)$").unwrap()),
        };
        assert!(check_limit(&l, &json!({"id": "123"})).is_ok());
        assert!(check_limit(&l, &json!({"id": "123; drop"})).is_err());
        let l = ArgLimit {
            arg: "body".into(),
            key: "body_max_len".into(),
            constraint: Constraint::MaxLen(3),
        };
        assert!(check_limit(&l, &json!({"body": "abc"})).is_ok());
        assert!(check_limit(&l, &json!({"body": "abcd"})).is_err());
    }

    #[test]
    fn deny_patterns_check_nested_strings() {
        let tool = Tool {
            name: "db.execute".into(),
            upstream: "db".into(),
            upstream_tool: "execute".into(),
            class: crate::Class::Destructive,
            deny_patterns: vec![Regex::new(r"(?i)\bdrop\b").unwrap()],
            two_person: false,
        };
        assert!(check_deny_patterns(&tool, &json!({"sql": "UPDATE t SET a=1"})).is_ok());
        assert!(check_deny_patterns(&tool, &json!({"sql": "drop table customers"})).is_err());
        assert!(check_deny_patterns(&tool, &json!({"batch": [{"sql": "DROP TABLE x"}]})).is_err());
        assert!(check_deny_patterns(&tool, &json!({"sql": "SELECT dropbox FROM t"})).is_ok());
    }
}
