# airlock

An **agent action firewall**: an MCP gateway that sits between AI agents and
the MCP servers they use, and deterministically limits what the agents can do.
The goal is a safety net, not a smarter guard: even a fully hijacked agent (one
that read a prompt injection and is doing whatever an attacker wrote) cannot
cause serious damage, because the damage-causing actions are refused at a
chokepoint the agent does not control.

This is the first version. It is a working MCP stdio gateway with a policy
engine, approvals, a tamper-evident audit log and a kill switch, plus a demo
that shows a prompt-injection attack succeeding without the gateway and being
blocked with it.

## Why action-level, not prompt-level

Guarding the model or filtering prompts is probabilistic: attackers adapt, and
a classifier that is right 99% of the time is a classifier an attacker tries
1,000 times. airlock does not look at prompt text or ask a model whether a call
is safe. Every decision comes from three things only:

- the **policy file** (which tools exist, what they can do, what a task is
  allowed to use),
- each tool's **reversibility class** (from policy, never from the tool's own
  description), and
- the **provenance** of the arguments (whether a value was derived from
  untrusted content earlier in the session).

Nothing the agent says about itself (its claimed task, its stated reason, a
field in its request that says `"approved": true`) changes a decision.

## Threat model

- **In scope.** An agent whose instructions have been subverted (prompt
  injection via a web page, email, ticket or document; a poisoned tool result;
  a confused deputy) and which then issues tool calls through MCP. airlock
  assumes the agent is fully compromised and still bounds the blast radius: it
  blocks destructive and irreversible-external actions, blocks exfiltration to
  disallowed recipients, blocks laundering untrusted data into an outbound
  action without a person, caps volume with budgets, and freezes everything on
  command.
- **Assumed trustworthy.** The policy file, the upstream MCP servers
  themselves, and the out-of-band approval channel (the operator's terminal /
  the webhook target). airlock mediates the *agent's* access to the servers; it
  is not a sandbox for a malicious server or a malicious operator.
- **Not yet addressed** (documented extension points, see below): a hosted
  multi-tenant service, OAuth token exchange / a credential broker, network
  egress control, an endpoint agent for desktop/computer-use, and the HTTP
  transport.

## Layout

```
crates/airlock-core   the deterministic engine: policy, classes, provenance,
                      budgets, approvals, audit chain, kill switch, pipeline
crates/airlock        the binary: MCP stdio transport, upstream clients, CLI
demo/                 fake MCP servers, a scripted hijacked agent, run.sh
```

## Policy format (TOML)

```toml
[gateway]
state_dir     = ".airlock"   # approvals, freeze file, alerts (relative to this file)
min_taint_len = 8            # shortest shared run that counts as "derived from untrusted"
approval_ttl_secs = 600

[audit]
path   = "audit.jsonl"       # relative to state_dir
redact = ["password", "token"]   # these argument keys are redacted in the log

[[upstream]]
name = "db"
command = ["postgres-mcp", "--dsn-env", "DB_DSN"]
# env = { DB_DSN = "..." }   # credentials live here, never in the agent's hands

[[upstream]]
name = "web"
command = ["fetch-mcp"]
provenance = "untrusted"     # everything this server returns is labelled untrusted

[[tool]]
name  = "db.query"
class = "read"               # read | reversible_write | destructive | irreversible_external

[[tool]]
name  = "db.execute"
class = "destructive"
deny_patterns = ["(?i)\\bdrop\\b", "(?i)\\btruncate\\b"]  # refused outright, even with approval

[[tool]]
name = "mail.send"
class = "irreversible_external"

[[grant]]
task    = "support-triage"
expires = "2026-12-01T00:00:00Z"
tools   = ["db.query", "db.execute", "mail.send", "web.fetch"]
[grant.limits]
"mail.send".to_domains = ["example.com"]   # <arg>_domains | <arg>_in | <arg>_matches | <arg>_max_len
[grant.budget]
"mail.send" = { per_hour = 20 }
"db.query"  = { per_hour = 500 }
```

Rules: a tool not listed in `[[tool]]` is denied; a tool not in the active
grant is denied; unknown fields are an error (no silent defaults); every regex
must compile or the policy fails to load. Check a policy with
`airlock policy check --policy policy.toml`.

### Argument limits

Each key under `[grant.limits]."<tool>"` names an argument and a constraint:

- `<arg>_domains = [...]`: every value must be a single bare address
  `local@domain` whose domain is in, or a subdomain of, the list. Addresses
  with display names, commas or angle brackets are rejected (so
  `a@ok.com, b@evil.com` cannot slip through).
- `<arg>_in = [...]`: value (or every array element) must be one of these.
- `<arg>_matches = "regex"`: value must fully match (the regex is anchored).
- `<arg>_max_len = N`: value must be at most N characters.

A constrained argument that is missing is refused, not waved through.

## Decision pipeline

For every `tools/call`, in order:

1. **Defined & not frozen.** Unknown tool → deny. Kill switch on → every
   non-`read` call is denied; reads still pass.
2. **Grant.** Tool must be in the active task's grant and the grant unexpired.
3. **Deny patterns & limits.** A deny-pattern match refuses the call outright
   (approval cannot override it). Every argument limit must pass.
4. **Provenance.** Arguments are checked against everything returned by
   `untrusted` upstreams this session (by exact match or a shared run of at
   least `min_taint_len` characters). Tainted arguments to a `destructive` or
   `irreversible_external` tool force an approval. This deterministically
   breaks "read malicious content, then act on it".
5. **Approval.** `destructive` and `irreversible_external` calls always need a
   person: airlock returns a dry-run description and opens a pending approval.
   The identical call after approval goes through once. `two_person = true`
   tools need two distinct approvers.
6. **Forward.** Allowed calls are forwarded; the result is labelled with the
   upstream's provenance (and recorded, if untrusted, for step 4).

Budgets are charged once per logical action (each read/reversible call; the
first attempt of a destructive/external call, not the approved retry). When a
tool exceeds its hourly budget the circuit breaker trips and that tool stays
refused for the rest of the session.

**Fail-open / fail-closed by class.** If airlock cannot evaluate a policy (a
state file is unreadable, the audit log cannot be written), reads are allowed
with a logged warning so a clinical lookup never stalls on the gateway, while
`destructive` and `irreversible_external` calls fail closed.

## Approvals (out-of-band only)

Pending approvals live as files in `<state_dir>/approvals/`. The MCP connection
can **only** create and consume them; it has no method that can approve one.
Approving or rejecting happens through a separate channel:

```bash
airlock pending   --state-dir .airlock
airlock approve   ap-abc123 --by alice --state-dir .airlock
airlock reject    ap-abc123 --by alice --state-dir .airlock
```

A property test throws arbitrary agent messages, including ones crafted to
look like approvals, at a gateway holding a pending destructive call and
asserts it is never forwarded. The only path to forwarding is a real
`airlock approve`.

## Audit log

Append-only JSON Lines, hash-chained with SHA-256 (`hash = SHA-256(prev_hash ||
entry)`). Each entry records the session, task, tool, redacted arguments,
class, decision, reason, the provenance of the arguments, and any approvers.
Editing, deleting or reordering any line breaks the chain.

```bash
airlock audit tail   --state-dir .airlock --n 20
airlock audit verify --state-dir .airlock   # reports the first broken line, if any
```

## Kill switch

```bash
airlock freeze   --state-dir .airlock   # every non-read call now fails
airlock unfreeze --state-dir .airlock
```

Freezing writes a file the gateway checks on **every** call, so it works even
if the control CLI cannot reach the gateway process, and every gateway sharing
the state directory sees it at once. You can trip it by hand with
`touch .airlock/FREEZE`.

## Running the gateway

```bash
airlock run --policy policy.toml --task support-triage
```

airlock speaks MCP (JSON-RPC 2.0) over stdio: it is an MCP server to the agent
and an MCP client to each upstream server listed in the policy. Point your
agent's MCP client at `airlock run ...` instead of at the servers directly. The
agent sees each tool namespaced as `upstream.tool`, with its class noted in the
description.

## The demo

```bash
./demo/run.sh
```

It runs one scripted, hijacked agent twice against the same injected "GitHub
issue" (which says: delete the `customers` table and email an export to an
outside address):

- **Without airlock:** the `DROP TABLE` runs and the exfiltration email is sent.
- **With airlock:** reading the issue is allowed, but the `DROP` is denied by a
  deny pattern and the email is denied by the recipient limit; the table
  survives, the outbox is empty, and every attempt is in the audit log.

Nothing touches the network: the "database" is a local SQLite file and the
"mail server" appends to a file.

## Testing airlock itself

The safety guarantee is tested by **attacking the gateway, not real systems.**
What is under test is airlock's decision, which is where the guarantee lives, so
the harness drives the engine against mock upstreams with hostile inputs and
asserts the verdict. There is deliberately no working exploit against any real
infrastructure in this repository, and none is needed.

- `crates/airlock-core/tests/pipeline.rs`: every pipeline branch end to end
  (deny patterns, limits, holds, approvals, two-person, freeze, budget/breaker,
  expiry, taint-forced holds, audit).
- `crates/airlock-core/tests/self_approval.rs`: the property that an agent
  cannot approve its own action.
- `crates/airlock-core/tests/scenarios.rs`: an adversarial scenario corpus.
  Sector realism (healthcare clinical-lookup, production change control with a
  two-person rule, refund-laundering via an untrusted ticket) is expressed as
  **policy fixtures**: the cases check that the policy can state the rule and
  the engine enforces it the same way every time.
- `demo/tests/demo.rs`: runs the demo both ways and asserts the outcomes.

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## What is NOT protected yet

Left as clear extension points, intentionally unbuilt in this version:

- **Credential broker** (OAuth 2.0 token exchange, RFC 8693). Today upstream
  credentials sit in the policy's per-upstream `env` and are never handed to
  the agent, but there is no short-lived-token exchange yet.
- **Network egress control**: confining agent runtimes to the hosts a task
  needs.
- **Endpoint enforcer**: the same policies on a desktop/computer-use agent.
- **Streamable HTTP transport**: only stdio is implemented. The gateway and
  upstream client are written against small transport-agnostic seams
  (`stdio::serve`, the `Upstreams` trait) so HTTP slots in beside them.
- **Hosted service, web UI, multi-tenant management**, and **customer-held
  signing keys** for policies.

## Design notes

- Rust, stable toolchain, `unsafe` forbidden workspace-wide.
- The engine (`airlock-core`) has no I/O-bound dependencies beyond the standard
  library plus `serde`/`toml`/`regex`/`sha2`/`time`; the transport and process
  management live in the `airlock` binary.
- The grant, dry-run and audit ideas are adapted from the capability model in a
  separate OS project, but airlock is standalone and depends on none of it.

## Contributing and security

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
ground rules, how to run the checks, and how to sign off commits (the project
uses the Developer Certificate of Origin). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md), never in a public issue.

## Licence

Apache-2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)).

airlock is **open core**. The engine, gateway, CLI and demo in this repository
are Apache-2.0: free to use, audit, self-host, fork and improve. A firewall is
only trustworthy if its enforcement can be inspected, so the part that makes the
safety decisions is open on purpose. Commercial components built on top (a
hosted multi-tenant control plane, managed and signed policies, SSO/RBAC, SIEM
integrations and support) are not part of this repository and are licensed
separately.
