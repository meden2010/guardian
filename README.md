# Guardian

> A low-noise, zero-infra, BYOK open-source PR code reviewer in Rust that only comments logical bugs and edge cases it can back with a concrete failure scenario.

*(Status: **Phase 0** — Cargo workspace & CI foundation. Currently in active development.)*

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
