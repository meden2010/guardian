# Guardian

> A low-noise, zero-infra, BYOK open-source PR code reviewer in Rust that only comments logical bugs and edge cases it can back with a concrete failure scenario.

*(Status: **Phase 2 (`v0.2` part 1)** — 7-stage deterministic noise funnel, SHA-256 cross-commit deduplication, intra-PR pattern grouping, `--record`/`--replay`, and `guardian eval` benchmark suite.)*

## Quick Local Usage (`v0.2`)

```bash
# Run Level A deterministic offline benchmark suite (zero network, <50ms)
cargo run -p guardian-pr-cli -- eval --offline

# Run Level B live benchmark suite against local Ollama over Tailscale/LAN
cargo run -p guardian-pr-cli -- eval \
  --base-url http://100.82.189.71:11434/v1 \
  --model qwen2.5-coder:7b \
  --allow-insecure-http \
  --language es

# Check environment and LLM connectivity
cargo run -p guardian-pr-cli -- doctor \
  --base-url http://100.82.189.71:11434/v1 \
  --model qwen2.5-coder:14b \
  --allow-insecure-http \
  --check-network

# Dry-run review on a local unified diff (supports --record / --replay)
cargo run -p guardian-pr-cli -- review \
  --diff-file evals/smoke/div_by_zero.diff \
  --base-url http://100.82.189.71:11434/v1 \
  --model qwen2.5-coder:14b \
  --allow-insecure-http \
  --language es \
  --dry-run

# Review and publish on a real GitHub PR (with automatic SHA-256 deduplication)
GITHUB_TOKEN=$(gh auth token) cargo run -p guardian-pr-cli -- review \
  --pr meden2010/guardian#1 \
  --base-url http://100.82.189.71:11434/v1 \
  --model qwen2.5-coder:14b \
  --allow-insecure-http \
  --language es
```

## What Guardian does NOT do

- No style, formatting, or traditional linter rules (use `clippy`, `eslint`, `ruff`, etc.).
- No hosted multi-tenant SaaS or telemetry.
- No automatic commits or auto-fixes.
- No GitLab / Bitbucket in `v1.0`.

## Architecture

- [`guardian-core`](crates/guardian-core): Pure library (diff parsing, prompt construction, deterministic noise filtering, validation) with zero network or filesystem side effects.
- [`guardian-cli`](crates/guardian-cli): CLI and GitHub Action runner (`guardian`).

## Security

See [SECURITY.md](SECURITY.md) for the security model (including fork PR handling via `pull_request_target` without `actions/checkout`, and prompt-injection isolation).

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
