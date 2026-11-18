## What and why

## How it was tested

## Checklist

- [ ] Every commit is signed off (`git commit -s`, see CONTRIBUTING.md)
- [ ] `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` pass
- [ ] Decisions stay deterministic and nothing on the MCP connection can widen the agent's authority
- [ ] README updated if the policy format, CLI or threat model changed
