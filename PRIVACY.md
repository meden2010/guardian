# Privacy & Data Handling

Guardian is designed as a **zero-infrastructure, BYOK (Bring Your Own Key)** reviewer. There is **no Guardian backend, no SaaS proxy, and zero telemetry**.

## Data Flow Matrix

| Data | Where it goes | Redaction / Protection | Retention |
| :--- | :--- | :--- | :--- |
| **PR diff hunks & AST context** (enclosing functions + imports) | Only to the LLM endpoint (`base_url`) configured by you | Secret patterns (API keys, GitHub tokens, PEM keys, JWTs, high-entropy assignments) are replaced with `[REDACTED:<type>]` before leaving the runner | Controlled solely by your LLM provider (or stays 100% local with Ollama/vLLM) |
| **PR title, description & `.guardian.yml` rules** | Only to your configured LLM endpoint | Wrapped in explicit untrusted delimiters + secret redaction | Same as above |
| **Sensitive files** (`.env*`, `*.pem`, `*.key`, `id_rsa*`, `*.tfstate`, lockfiles, binaries) | **Never sent** | Excluded deterministically before prompt construction | None |
| **Review comments & SHA-256 fingerprints** | GitHub PR (Comments / Checks API) | Fingerprints store only a 64-char `SHA-256` hash (`<!-- guardian:fp=v1:... -->`), never raw code or secrets | Stored in your GitHub PR |
| **Runner logs & `GITHUB_STEP_SUMMARY`** | GitHub Actions logs | Metadata only (counts, funnel trace, token counts, duration, redacted error messages). Never diffs, prompts, or API keys | GitHub Actions log retention |
| **Telemetry / Analytics** | **Nowhere** | Guardian emits zero analytics, crash reports, or phone-home requests | None |

## Security & Privacy Guarantees

1. **No server in the middle:** Guardian runs directly inside your GitHub Actions runner (hosted or self-hosted) and talks directly to GitHub and your chosen LLM endpoint.
2. **Base-branch config integrity:** `.guardian.yml` is fetched strictly from `base_sha` — an untrusted PR cannot redirect `base_url` or inject malicious config.
3. **Strict secret redaction is defense-in-depth:** Pattern-based secret redaction reduces accidental exposure risk, but is not a replacement for secret scanning (e.g. GitHub Push Protection) or proper secrets management.
4. **Local / air-gapped enterprise use:** For teams that cannot send code to external cloud LLM APIs, Guardian supports any OpenAI-compatible local server (such as Ollama or vLLM) on a private self-hosted runner (`--allow-insecure-http` for private LAN/Tailscale endpoints).
5. **Your LLM provider's terms:** Because Guardian is BYOK, data retention and training policies are governed by the agreement between you and your chosen LLM provider. Check your provider's zero-data-retention / enterprise options before enabling on proprietary repositories.
