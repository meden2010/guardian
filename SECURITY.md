# Security Policy

## Reporting a Vulnerability

Please report security vulnerabilities privately via GitHub Security Advisories on this repository instead of opening a public issue.

## Security Model (Core Invariants)

1. **Fork PRs (`pull_request_target` without checkout):**
   Guardian never executes code from a Pull Request. When used in `pull_request_target` workflows, the workflow MUST NOT run `actions/checkout` on the PR head ref. Guardian reads diffs and file contents passively via the GitHub API.
2. **Untrusted PR Content (Prompt Injection):**
   PR titles, descriptions, and diffs are treated as untrusted data, wrapped in explicit delimiters, and passed to the LLM without tool-calling or action capabilities. Every finding is deterministically validated against the real diff before publishing.
3. **Configuration Integrity:**
   Repository configuration (`.guardian.yml`) is read from the base commit SHA (`base_sha`), never from the PR head.
4. **Zero Telemetry:**
   Guardian sends no data to any Guardian-controlled server. Code fragments only leave the runner toward the LLM provider configured by the user.
