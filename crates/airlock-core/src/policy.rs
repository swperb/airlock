//! The policy file: upstream servers, tool definitions and task grants.
//!
//! Parsing is strict. Unknown fields are an error, every tool a grant names
//! must be defined, and every regex must compile. A policy either loads
//! completely or not at all.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::Error;

/// How reversible an operation is. Comes only from policy, never from the
/// agent or the upstream server's own description of the tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Read,
    ReversibleWrite,
    Destructive,
    IrreversibleExternal,
}

impl Class {
    pub const fn as_str(self) -> &'static str {
        match self {
            Class::Read => "read",
            Class::ReversibleWrite => "reversible_write",
            Class::Destructive => "destructive",
            Class::IrreversibleExternal => "irreversible_external",
        }
    }

    /// Classes that need a person before they run.
    pub const fn is_high_risk(self) -> bool {
        matches!(self, Class::Destructive | Class::IrreversibleExternal)
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Where a tool's output came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    Trusted,
    #[default]
    Internal,
    /// Web pages, email, tickets, uploaded documents: anything an attacker can write.
    Untrusted,
}

impl Provenance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Provenance::Trusted => "trusted",
            Provenance::Internal => "internal",
            Provenance::Untrusted => "untrusted",
        }
    }
}

// ---------------------------------------------------------------------------
// Raw TOML shape
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPolicy {
    #[serde(default)]
    gateway: GatewayConfig,
    #[serde(default)]
    audit: AuditConfig,
    #[serde(default)]
    upstream: Vec<UpstreamConfig>,
    #[serde(default)]
    tool: Vec<RawTool>,
    #[serde(default)]
    grant: Vec<RawGrant>,
}

/// `[gateway]` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Directory for approvals, the freeze file and alerts. Relative paths
    /// resolve against the policy file's directory. Default `.airlock`.
    #[serde(default)]
    pub state_dir: Option<PathBuf>,
    /// Minimum length of a shared substring for an argument to count as
    /// derived from untrusted output.
    #[serde(default = "default_min_taint_len")]
    pub min_taint_len: usize,
    /// How long a pending approval stays valid.
    #[serde(default = "default_approval_ttl")]
    pub approval_ttl_secs: u64,
    /// Plain `http://` URL that receives a JSON POST for every alert.
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// Seconds to wait for an upstream response before failing the call.
    #[serde(default = "default_upstream_timeout")]
    pub upstream_timeout_secs: u64,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        GatewayConfig {
            state_dir: None,
            min_taint_len: default_min_taint_len(),
            approval_ttl_secs: default_approval_ttl(),
            webhook_url: None,
            upstream_timeout_secs: default_upstream_timeout(),
        }
    }
}

fn default_min_taint_len() -> usize {
    8
}
fn default_approval_ttl() -> u64 {
    600
}
fn default_upstream_timeout() -> u64 {
    30
}

/// `[audit]` table.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Audit log path. Relative paths resolve against the state directory.
    /// Default `audit.jsonl`.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Argument keys (case-insensitive, at any depth) whose values are
    /// replaced with `"[redacted]"` in the audit log and approval records.
    #[serde(default)]
    pub redact: Vec<String>,
}

/// `[[upstream]]` entry: an MCP server the gateway fronts. Exactly one of
/// `command` (a local server spoken to over stdio) or `url` (a remote server
/// spoken to over MCP streamable HTTP) must be set.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    pub name: String,
    #[serde(default)]
    pub command: Option<Vec<String>>,
    /// `http://` or `https://` endpoint of a streamable HTTP MCP server.
    #[serde(default)]
    pub url: Option<String>,
    /// Name of an environment variable (in the gateway's environment) holding
    /// a bearer token for a `url` upstream. The token itself never appears in
    /// the policy file and is never shown to the agent.
    #[serde(default)]
    pub bearer_token_env: Option<String>,
    /// Label applied to everything this server returns. Default `internal`.
    #[serde(default)]
    pub provenance: Provenance,
    /// Extra environment for the server process (credentials live here, in
    /// the gateway's configuration, never in the agent's hands).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawTool {
    name: String,
    class: Class,
    #[serde(default)]
    deny_patterns: Vec<String>,
    #[serde(default)]
    two_person: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGrant {
    task: String,
    expires: String,
    tools: Vec<String>,
    #[serde(default)]
    limits: BTreeMap<String, BTreeMap<String, toml::Value>>,
    #[serde(default)]
    budget: BTreeMap<String, RawBudget>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBudget {
    per_hour: u32,
}

// ---------------------------------------------------------------------------
// Compiled policy
// ---------------------------------------------------------------------------

/// A tool definition after validation.
#[derive(Debug, Clone)]
pub struct Tool {
    /// Full name, `upstream.tool`.
    pub name: String,
    pub upstream: String,
    /// Name of the tool on the upstream server.
    pub upstream_tool: String,
    pub class: Class,
    pub deny_patterns: Vec<Regex>,
    pub two_person: bool,
}

/// One constraint on one argument of one tool.
#[derive(Debug, Clone)]
pub enum Constraint {
    /// Every address must be `local@domain` with domain in (or under) the list.
    Domains(Vec<String>),
    /// Value must be one of these strings.
    OneOf(Vec<String>),
    /// Value must fully match this regex.
    Matches(Regex),
    /// Value must be at most this many characters.
    MaxLen(usize),
}

/// A constraint attached to a named argument.
#[derive(Debug, Clone)]
pub struct ArgLimit {
    pub arg: String,
    /// The policy key it came from, e.g. `to_domains`, for error messages.
    pub key: String,
    pub constraint: Constraint,
}

/// A task grant after validation.
#[derive(Debug, Clone)]
pub struct Grant {
    pub task: String,
    pub expires: OffsetDateTime,
    pub tools: BTreeSet<String>,
    pub limits: BTreeMap<String, Vec<ArgLimit>>,
    pub budgets: BTreeMap<String, u32>,
}

/// A fully validated policy.
#[derive(Debug, Clone)]
pub struct Policy {
    pub gateway: GatewayConfig,
    pub audit: AuditConfig,
    pub upstreams: Vec<UpstreamConfig>,
    pub tools: BTreeMap<String, Tool>,
    pub grants: BTreeMap<String, Grant>,
    /// Directory relative paths resolve against (the policy file's directory).
    pub base_dir: PathBuf,
}

impl Policy {
    /// Load and validate a policy file.
    pub fn load(path: &Path) -> Result<Policy, Error> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Policy(format!("reading {}: {e}", path.display())))?;
        let base = path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let base = if base.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            base
        };
        Policy::parse(&text, base)
    }

    /// Parse and validate policy text. `base_dir` anchors relative paths.
    pub fn parse(text: &str, base_dir: PathBuf) -> Result<Policy, Error> {
        let raw: RawPolicy = toml::from_str(text).map_err(|e| Error::Policy(e.to_string()))?;
        compile(raw, base_dir)
    }

    /// The resolved state directory.
    pub fn state_dir(&self) -> PathBuf {
        match &self.gateway.state_dir {
            Some(p) if p.is_absolute() => p.clone(),
            Some(p) => self.base_dir.join(p),
            None => self.base_dir.join(".airlock"),
        }
    }

    /// The resolved audit log path.
    pub fn audit_path(&self) -> PathBuf {
        match &self.audit.path {
            Some(p) if p.is_absolute() => p.clone(),
            Some(p) => self.state_dir().join(p),
            None => self.state_dir().join("audit.jsonl"),
        }
    }

    pub fn upstream(&self, name: &str) -> Option<&UpstreamConfig> {
        self.upstreams.iter().find(|u| u.name == name)
    }
}

fn err(msg: impl Into<String>) -> Error {
    Error::Policy(msg.into())
}

fn compile(raw: RawPolicy, base_dir: PathBuf) -> Result<Policy, Error> {
    if raw.gateway.min_taint_len == 0 {
        return Err(err("gateway.min_taint_len must be at least 1"));
    }
    if raw.gateway.approval_ttl_secs == 0 {
        return Err(err("gateway.approval_ttl_secs must be at least 1"));
    }
    if let Some(url) = &raw.gateway.webhook_url {
        if !url.starts_with("http://") {
            return Err(err(format!(
                "gateway.webhook_url must be a plain http:// URL in this version (got {url:?})"
            )));
        }
    }

    let mut upstream_names = BTreeSet::new();
    for u in &raw.upstream {
        if u.name.is_empty() || u.name.contains('.') {
            return Err(err(format!(
                "upstream name {:?} must be non-empty and contain no '.'",
                u.name
            )));
        }
        if !upstream_names.insert(u.name.clone()) {
            return Err(err(format!("duplicate upstream {:?}", u.name)));
        }
        match (&u.command, &u.url) {
            (Some(cmd), None) => {
                if cmd.is_empty() || cmd[0].is_empty() {
                    return Err(err(format!("upstream {:?} has an empty command", u.name)));
                }
                if u.bearer_token_env.is_some() {
                    return Err(err(format!(
                        "upstream {:?}: bearer_token_env only applies to url upstreams; pass stdio credentials with env",
                        u.name
                    )));
                }
            }
            (None, Some(url)) => {
                if !(url.starts_with("http://") || url.starts_with("https://")) {
                    return Err(err(format!(
                        "upstream {:?}: url must start with http:// or https:// (got {url:?})",
                        u.name
                    )));
                }
                if !u.env.is_empty() {
                    return Err(err(format!(
                        "upstream {:?}: env only applies to command upstreams; use bearer_token_env for url upstreams",
                        u.name
                    )));
                }
                if let Some(var) = &u.bearer_token_env {
                    if var.is_empty() {
                        return Err(err(format!(
                            "upstream {:?}: bearer_token_env is empty",
                            u.name
                        )));
                    }
                }
            }
            (Some(_), Some(_)) => {
                return Err(err(format!(
                    "upstream {:?} sets both command and url; set exactly one",
                    u.name
                )));
            }
            (None, None) => {
                return Err(err(format!(
                    "upstream {:?} needs either command or url",
                    u.name
                )));
            }
        }
    }

    let mut tools = BTreeMap::new();
    for t in raw.tool {
        let Some((up, local)) = t.name.split_once('.') else {
            return Err(err(format!(
                "tool {:?} must be named <upstream>.<tool>",
                t.name
            )));
        };
        if !upstream_names.contains(up) {
            return Err(err(format!(
                "tool {:?} refers to unknown upstream {up:?}",
                t.name
            )));
        }
        if local.is_empty() {
            return Err(err(format!("tool {:?} has an empty tool name", t.name)));
        }
        let mut deny = Vec::new();
        for p in &t.deny_patterns {
            deny.push(
                Regex::new(p)
                    .map_err(|e| err(format!("tool {:?}: bad deny pattern {p:?}: {e}", t.name)))?,
            );
        }
        let tool = Tool {
            name: t.name.clone(),
            upstream: up.to_string(),
            upstream_tool: local.to_string(),
            class: t.class,
            deny_patterns: deny,
            two_person: t.two_person,
        };
        if tools.insert(t.name.clone(), tool).is_some() {
            return Err(err(format!("duplicate tool {:?}", t.name)));
        }
    }

    let mut grants = BTreeMap::new();
    for g in raw.grant {
        let expires =
            OffsetDateTime::parse(&g.expires, &time::format_description::well_known::Rfc3339)
                .map_err(|e| {
                    err(format!(
                        "grant {:?}: bad expires {:?}: {e}",
                        g.task, g.expires
                    ))
                })?;
        let mut granted = BTreeSet::new();
        for name in &g.tools {
            if !tools.contains_key(name) {
                return Err(err(format!(
                    "grant {:?} names tool {name:?}, which is not defined in [[tool]]",
                    g.task
                )));
            }
            granted.insert(name.clone());
        }
        let mut limits = BTreeMap::new();
        for (tool, table) in g.limits {
            if !granted.contains(&tool) {
                return Err(err(format!(
                    "grant {:?} has limits for {tool:?}, which it does not grant",
                    g.task
                )));
            }
            let mut list = Vec::new();
            for (key, value) in table {
                list.push(compile_limit(&g.task, &tool, &key, value)?);
            }
            limits.insert(tool, list);
        }
        let mut budgets = BTreeMap::new();
        for (tool, b) in g.budget {
            if !granted.contains(&tool) {
                return Err(err(format!(
                    "grant {:?} has a budget for {tool:?}, which it does not grant",
                    g.task
                )));
            }
            budgets.insert(tool, b.per_hour);
        }
        let grant = Grant {
            task: g.task.clone(),
            expires,
            tools: granted,
            limits,
            budgets,
        };
        if grants.insert(g.task.clone(), grant).is_some() {
            return Err(err(format!("duplicate grant for task {:?}", g.task)));
        }
    }

    Ok(Policy {
        gateway: raw.gateway,
        audit: raw.audit,
        upstreams: raw.upstream,
        tools,
        grants,
        base_dir,
    })
}

fn string_list(
    task: &str,
    tool: &str,
    key: &str,
    value: &toml::Value,
) -> Result<Vec<String>, Error> {
    let bad = || {
        err(format!(
            "grant {task:?}: {tool}.{key} must be an array of strings"
        ))
    };
    let arr = value.as_array().ok_or_else(bad)?;
    arr.iter()
        .map(|v| v.as_str().map(str::to_string).ok_or_else(bad))
        .collect()
}

fn compile_limit(task: &str, tool: &str, key: &str, value: toml::Value) -> Result<ArgLimit, Error> {
    const SUFFIXES: [&str; 4] = ["_domains", "_in", "_matches", "_max_len"];
    let Some(suffix) = SUFFIXES
        .iter()
        .find(|s| key.ends_with(*s) && key.len() > s.len())
    else {
        return Err(err(format!(
            "grant {task:?}: unknown limit {tool}.{key} (expected <arg>_domains, <arg>_in, <arg>_matches or <arg>_max_len)"
        )));
    };
    let arg = key[..key.len() - suffix.len()].to_string();
    let constraint = match *suffix {
        "_domains" => Constraint::Domains(
            string_list(task, tool, key, &value)?
                .into_iter()
                .map(|d| d.to_ascii_lowercase())
                .collect(),
        ),
        "_in" => Constraint::OneOf(string_list(task, tool, key, &value)?),
        "_matches" => {
            let s = value
                .as_str()
                .ok_or_else(|| err(format!("grant {task:?}: {tool}.{key} must be a string")))?;
            let anchored = format!("^(?:{s})$");
            Constraint::Matches(
                Regex::new(&anchored)
                    .map_err(|e| err(format!("grant {task:?}: {tool}.{key}: {e}")))?,
            )
        }
        _ => {
            let n = value.as_integer().filter(|n| *n >= 0).ok_or_else(|| {
                err(format!(
                    "grant {task:?}: {tool}.{key} must be a non-negative integer"
                ))
            })?;
            Constraint::MaxLen(n as usize)
        }
    };
    Ok(ArgLimit {
        arg,
        key: key.to_string(),
        constraint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const SAMPLE: &str = r#"
[[upstream]]
name = "db"
command = ["postgres-mcp", "--dsn-env", "DB_DSN"]

[[upstream]]
name = "mail"
command = ["mail-mcp"]

[[upstream]]
name = "web"
command = ["fetch-mcp"]
provenance = "untrusted"

[[tool]]
name = "db.query"
class = "read"

[[tool]]
name = "db.execute"
class = "destructive"
deny_patterns = ["(?i)\\bdrop\\b", "(?i)\\btruncate\\b"]

[[tool]]
name = "mail.send"
class = "irreversible_external"

[[tool]]
name = "web.fetch"
class = "read"

[[grant]]
task = "support-triage"
expires = "2026-12-01T00:00:00Z"
tools = ["db.query", "mail.send", "web.fetch"]
[grant.limits]
"mail.send".to_domains = ["example.com"]
[grant.budget]
"mail.send" = { per_hour = 20 }
"db.query"  = { per_hour = 500 }
"#;

    #[test]
    fn parses_the_brief_sample() {
        let p = Policy::parse(SAMPLE, PathBuf::from("/x")).unwrap();
        assert_eq!(p.tools["db.execute"].class, Class::Destructive);
        assert_eq!(p.tools["db.execute"].deny_patterns.len(), 2);
        let g = &p.grants["support-triage"];
        assert_eq!(g.budgets["mail.send"], 20);
        let lim = &g.limits["mail.send"][0];
        assert_eq!(lim.arg, "to");
        assert!(
            matches!(&lim.constraint, Constraint::Domains(d) if d == &vec!["example.com".to_string()])
        );
        assert_eq!(p.upstream("web").unwrap().provenance, Provenance::Untrusted);
        assert_eq!(p.state_dir(), PathBuf::from("/x/.airlock"));
    }

    #[test]
    fn unknown_fields_are_errors() {
        let bad = SAMPLE.replace(
            "class = \"read\"\n\n[[tool]]\nname = \"db.execute\"",
            "class = \"read\"\nclas = \"x\"\n\n[[tool]]\nname = \"db.execute\"",
        );
        assert!(Policy::parse(&bad, PathBuf::new()).is_err());
        assert!(Policy::parse("[gateway]\nmystery = 1\n", PathBuf::new()).is_err());
        assert!(Policy::parse("bogus = 1\n", PathBuf::new()).is_err());
    }

    #[test]
    fn grant_must_name_defined_tools() {
        let bad = SAMPLE.replace(
            r#"tools = ["db.query", "mail.send", "web.fetch"]"#,
            r#"tools = ["db.query", "shell.exec"]"#,
        );
        let e = Policy::parse(&bad, PathBuf::new()).unwrap_err().to_string();
        assert!(e.contains("shell.exec"), "{e}");
    }

    #[test]
    fn unknown_limit_kind_is_an_error() {
        let bad = SAMPLE.replace("to_domains", "to_whatever");
        assert!(Policy::parse(&bad, PathBuf::new()).is_err());
    }

    #[test]
    fn url_upstreams_are_validated() {
        let base = "[[upstream]]\nname = \"r\"\n";
        let ok = format!(
            "{base}url = \"https://mcp.example.com/mcp\"\nbearer_token_env = \"R_TOKEN\"\n"
        );
        let p = Policy::parse(&ok, PathBuf::new()).unwrap();
        assert_eq!(
            p.upstreams[0].url.as_deref(),
            Some("https://mcp.example.com/mcp")
        );
        for bad in [
            format!("{base}url = \"ftp://x\"\n"),
            format!("{base}url = \"http://x\"\ncommand = [\"y\"]\n"),
            base.to_string(),
            format!("{base}command = [\"y\"]\nbearer_token_env = \"T\"\n"),
            format!("{base}url = \"http://x\"\nenv = {{ A = \"b\" }}\n"),
            format!("{base}command = []\n"),
        ] {
            assert!(
                Policy::parse(&bad, PathBuf::new()).is_err(),
                "should reject: {bad}"
            );
        }
    }

    #[test]
    fn bad_regex_and_bad_class_are_errors() {
        let bad = SAMPLE.replace(r"(?i)\\bdrop\\b", "(unclosed");
        assert!(Policy::parse(&bad, PathBuf::new()).is_err());
        let bad = SAMPLE.replace("class = \"destructive\"", "class = \"spicy\"");
        assert!(Policy::parse(&bad, PathBuf::new()).is_err());
    }
}
