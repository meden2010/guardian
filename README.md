# 🛡️ Guardian

> **Low-noise, zero-infra, BYOK open-source PR code reviewer in Rust** — strictly focused on logical bugs and runtime edge cases backed by a concrete failure scenario.

[Leer en Español (README.es.md)](README.es.md) · [Privacy & Data Handling](PRIVACY.md) · [Security Model](SECURITY.md) · [Contributing](CONTRIBUTING.md)

<p align="center">
  <img src="assets/guardian-processing.svg" alt="Guardian knight slicing incoming bugs" width="336" height="120" />
</p>

## Why Guardian?

Most AI PR reviewers flood pull requests with style nitpicks, hallucinated line numbers, and repeated comments on every push. Guardian is built around a **deterministic 7-stage noise funnel** in Rust:

```text
PR Diff + Tree-sitter AST Context (Rust / TS / Python / PHP)
   │
   ▼
Secret Redaction ([REDACTED:...]) ──▶ Your LLM Endpoint (BYOK: OpenAI / Ollama / vLLM)
   │
   ▼
7-Stage Deterministic Funnel:
  1. Diff anchor check (drops hallucinated paths/lines)
  2. Introduced-by-PR check (drops legacy code complaints)
  3. Category & severity gate (bug / edge_case only)
  4. Concrete failure scenario required (no vague warnings)
  5. Intra-PR pattern grouping (collapses duplicates)
  6. SHA-256 + GraphQL isResolved deduplication (never re-opens resolved threads)
  7. Inline `guardian-ignore` & comment cap
   │
   ▼
Atomic PR Review + Native 1-Click ```suggestion``` + Check Run ("Guardian Review")
```

## 5-Minute Quickstart

### 1. Add `.guardian.yml` to your default branch (`main`)

```yaml
version: 1
language: en # or "es"
review:
  min_severity: medium
  max_comments: 6
  ignore_paths:
    - "docs/**"
    - "migrations/**"
limits:
  max_files: 30
rules:
  - id: guard-zero-div
    text: "Always guard against zero divisors in billing and pricing calculations."
behavior:
  suggestions: true
  fail_on_error: false
```

Validate it locally anytime with `guardian validate .guardian.yml`.

### 2. Add `.github/workflows/guardian.yml`

```yaml
name: Guardian Review

on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review]

permissions:
  contents: read
  pull-requests: write
  checks: write

concurrency:
  group: guardian-${{ github.event.pull_request.number }}
  cancel-in-progress: true

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: meden2010/guardian@v1.0.0
        with:
          model: gpt-4o-mini
          api_key: ${{ secrets.GUARDIAN_LLM_API_KEY }}
```

> **Using a local model (Ollama / vLLM) on a private self-hosted runner?**
> Pass `base_url: http://<host>:11434/v1`, `model: qwen2.5-coder:7b`, and `allow_insecure_http: "true"` — zero code leaves your network.

## What Guardian Does NOT Do

- **No style, formatting, or linter rules** — use `clippy`, `eslint`, `ruff`, or `phpstan`.
- **No SaaS backend or telemetry** — your code only travels from your runner to your configured LLM endpoint.
- **No automatic commits** — Guardian posts `COMMENT` reviews and safe 1-click ```` ```suggestion ```` blocks for humans to approve.
- **No untrusted code execution** — never requires `actions/checkout` on PR heads; `.guardian.yml` is always read from `base_sha`.

## CLI Commands

```bash
guardian review --diff-file changes.diff --model gpt-4o-mini --dry-run
guardian validate .guardian.yml
guardian doctor --base-url https://api.openai.com/v1 --model gpt-4o-mini --check-network
guardian eval --offline
```

## Architecture

- [`guardian-core`](crates/guardian-core): Pure Rust library (diff parsing, secret redaction, Tree-sitter AST context for Rust/TS/Python/PHP, prompt builder, 7-stage filter, config validator, SHA-256 fingerprinting).
- [`guardian-cli`](crates/guardian-cli): Single static CLI binary + GitHub Composite Action (`action.yml` with SHA-256 binary verification).

## License

Dual-licensed under either of:

- Apache License, Version 2.0
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
