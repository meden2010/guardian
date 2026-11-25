# Guardian

> A low-noise, zero-infra, BYOK open-source PR code reviewer in Rust that only comments logical bugs and edge cases it can back with a concrete failure scenario.

*(Status: **Phase 1 (`v0.1`)** — End-to-end vertical slice: diff parsing, secret redaction, OpenAI-compatible LLM review, deterministic diff validation, and atomic GitHub PR comments.)*

## Quick Local Usage (`v0.1`)

```bash
# Check environment and LLM connectivity (e.g. local Ollama over Tailscale/LAN)
cargo run -p guardian-pr-cli -- doctor \
  --base-url http://100.82.189.71:11434/v1 \
  --model qwen2.5-coder:14b \
  --allow-insecure-http \
  --check-network

# Dry-run review on a local unified diff
cargo run -p guardian-pr-cli -- review \
  --diff-file evals/smoke/div_by_zero.diff \
  --base-url http://100.82.189.71:11434/v1 \
  --model qwen2.5-coder:14b \
  --allow-insecure-http \
  --language es \
  --dry-run

# Review and publish on a real GitHub PR
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
