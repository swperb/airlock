# Security policy

airlock is a safety net for AI agents, so a flaw in it can matter more than a
flaw in most software. Reports are welcome and taken seriously.

## Reporting a vulnerability

Please report privately through GitHub's private vulnerability reporting:

**https://github.com/swperb/airlock/security/advisories/new**

Do not open a public issue, pull request or discussion for a suspected
vulnerability.

Useful details: the version or commit, the policy involved (redact anything
sensitive), the sequence of agent messages or tool results, what airlock
decided, and what you expected it to decide.

## What counts

In scope, for example:

- An agent getting a `destructive` or `irreversible_external` call forwarded
  without the required approval.
- Anything reachable from the MCP connection approving, rejecting, unfreezing
  or changing policy.
- Bypassing a deny pattern, an argument limit, a budget or the freeze.
- Untrusted content reaching a high-risk tool without the provenance check
  catching it, in a way the README does not already describe as a limitation.
- Breaking the audit chain without `airlock audit verify` noticing.
- Upstream credentials leaking to the agent.
- A gateway with trusted keys configured loading a policy that is unsigned,
  altered after signing, signed by an untrusted key, or older than one it
  already accepted.

Out of scope: limitations the README lists under "What is NOT protected yet",
and attacks that need control of the policy file, the upstream servers or the
operator's approval channel (those are trusted in the threat model).

## Supported versions

airlock is pre-1.0. Fixes land on `main` and in the next release.
