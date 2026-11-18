# Contributing to airlock

Thanks for helping. airlock is a security tool, so the bar is: every change
keeps decisions deterministic, keeps the agent unable to widen its own
authority, and comes with tests that prove it.

## Ground rules

These come from the project's principles and are not up for negotiation in a
single PR:

- **Deterministic only.** No LLM, classifier or heuristic score decides whether
  a call is allowed. Decisions come from policy, tool class and provenance.
- **Control actions, not prompts.** Don't inspect or filter prompt text.
- **The agent is assumed compromised.** Nothing the agent sends (its reason,
  claimed task, claimed approval, extra fields) may change a verdict. Nothing
  reachable from the MCP connection may approve, reject, unfreeze or change
  policy.
- **Fail closed for writes, fail open for reads.**
- **No secrets in agent hands.** Upstream credentials are never returned to
  the agent.

If a change needs to bend one of these, open an issue to discuss the design
first.

## Development

You need stable Rust (the minimum supported version is 1.89) and Python 3 for
the demo script.

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
./demo/run.sh
```

CI runs all of these on Linux and macOS and checks that the code still builds
on Rust 1.89. A PR needs green CI before it is merged.

`unsafe` code is forbidden across the workspace. Keep dependencies lean and
mainstream; explain any new one in the PR.

## Tests

- New pipeline behaviour gets a test in `crates/airlock-core/tests/pipeline.rs`.
- New attack patterns or sector rules belong in the scenario corpus,
  `crates/airlock-core/tests/scenarios.rs`, as policy fixtures plus the
  verdict they must produce. The corpus attacks airlock's decisions against
  mock upstreams; it never targets real systems, and exploits against real
  software do not belong in this repository.
- Anything that touches approvals must keep
  `crates/airlock-core/tests/self_approval.rs` passing, and should extend it
  if it adds a new way for messages to reach the gateway.

## Sign your commits (DCO)

airlock uses the [Developer Certificate of Origin](https://developercertificate.org/)
(DCO) instead of a contributor licence agreement. By signing off a commit you
certify that you wrote it, or otherwise have the right to submit it, under the
project's licence (Apache-2.0). Contributions are licensed inbound under the
same licence they are distributed under.

Sign off by adding a line to every commit message, using your real name and the
email address the commit is authored with:

```text
Signed-off-by: Your Name <you@example.com>
```

Git adds it for you with `-s`:

```bash
git commit -s -m "Explain what this change does"
```

Forgot? Fix the commits on your branch, then force-push:

```bash
git rebase --signoff main
git push --force-with-lease
```

CI checks that every commit in a pull request carries a sign-off matching its
author.

## Pull requests

- Keep PRs small and focused; one logical change each.
- Describe what changed, why, and how you tested it.
- Update the README when you change the policy format, CLI or threat model.
- Note anything that is not yet protected rather than implying it is.

## Reporting security issues

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Licence

By contributing you agree that your contributions are licensed under the
Apache License, Version 2.0, as described above.
