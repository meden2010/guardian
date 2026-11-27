# Contributing to Guardian

Thank you for helping keep Guardian fast, accurate, and low-noise!

## Architecture Overview

- [`crates/guardian-core`](crates/guardian-core): Pure Rust library with zero network or filesystem I/O (diff parsing, secret redaction, Tree-sitter AST context, prompt construction, 7-stage deterministic noise filter, `.guardian.yml` validator, SHA-256 fingerprinting).
- [`crates/guardian-cli`](crates/guardian-cli): Thin CLI & GitHub Action runner (`guardian review`, `guardian validate`, `guardian eval`, `guardian doctor`).
- [`evals/cases`](evals/cases): Deterministic evaluation suite covering real logical bugs, clean PRs, AST prior-guard cases, and adversarial prompt-injection cases.

## Running Local Checks

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p guardian-pr-cli -- eval --offline
```

All four commands run in CI on every Pull Request and complete in seconds with zero network calls.

## Adding an Evaluation Case

Every reported false positive or missed logical bug should become a permanent case in `evals/cases/<NN>-<slug>/`:

- `case.toml`: expected severity, line range, and kind (`bug`, `clean`, `adversarial`).
- `diff.patch`: minimal unified diff.
- `files/` (optional): full source files for Tree-sitter AST intra-file context.
- `recorded_llm.json`: recorded LLM output for deterministic Level A (`--offline`) replay.

## Developer Certificate of Origin (DCO)

All commits must include a `Signed-off-by:` trailer (`git commit -s`) certifying that you have the right to submit your contribution under Guardian's dual license (`MIT OR Apache-2.0`).

## Reporting False Positives

If Guardian leaves a noisy or incorrect comment on a PR, please open an issue using the **False Positive Report** template so we can add it to the eval suite and harden the filter/prompt.
