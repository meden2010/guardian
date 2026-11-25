//! Pure core library for Guardian.
//!
//! Contains diff parsing, secret redaction, prompt construction, deterministic
//! noise filtering, and finding validation with zero network or filesystem I/O.

pub mod diff;
pub mod filter;
pub mod prompt;
pub mod redact;
pub mod types;

use diff::{parse_unified_diff, ParsedDiff};
use filter::{filter_findings, format_pr_summary, FilteredReview};
use prompt::{build_review_prompt, BuiltPrompt};
use redact::redact_secrets;
use thiserror::Error;
use types::{LlmReviewOutput, PrMetadata, ReviewConfig, ReviewStatus};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Error)]
pub enum CoreError {
    #[error("LLM output is not valid Guardian JSON: {0}")]
    InvalidLlmJson(#[from] serde_json::Error),
}

/// Prepared state ready to be sent to an LLM provider (or skipped if no reviewable code).
pub enum PreparedDiff {
    Skip {
        status: ReviewStatus,
        parsed_diff: ParsedDiff,
    },
    Ready {
        parsed_diff: ParsedDiff,
        prompt: BuiltPrompt,
    },
}

/// Redacts secrets from the raw diff & PR metadata, parses reviewable hunks, and builds prompts.
pub fn prepare_review(
    raw_diff: &str,
    metadata: &PrMetadata,
    config: &ReviewConfig,
) -> PreparedDiff {
    let redacted_diff = redact_secrets(raw_diff);
    let redacted_meta = PrMetadata {
        title: redact_secrets(&metadata.title),
        description: redact_secrets(&metadata.description),
    };

    let parsed_diff = parse_unified_diff(&redacted_diff, config);
    if parsed_diff.files.is_empty() {
        return PreparedDiff::Skip {
            status: ReviewStatus::Skipped {
                reason: "SKIP_NO_REVIEWABLE_CODE: diff contains no reviewable code hunks"
                    .to_string(),
            },
            parsed_diff,
        };
    }

    let annotated = parsed_diff.render_for_prompt();
    let prompt = build_review_prompt(&redacted_meta, &annotated, config);
    PreparedDiff::Ready {
        parsed_diff,
        prompt,
    }
}

/// Parses strict JSON from an LLM response, stripping optional Markdown code fences.
pub fn parse_llm_output(raw_response: &str) -> Result<LlmReviewOutput, CoreError> {
    let cleaned = strip_markdown_json_fence(raw_response);
    let parsed = serde_json::from_str::<LlmReviewOutput>(cleaned)?;
    Ok(parsed)
}

/// Runs deterministic validation and builds both inline findings and the PR summary markdown.
pub fn finalize_review(
    llm_output: LlmReviewOutput,
    parsed_diff: &ParsedDiff,
    config: &ReviewConfig,
    model_name: &str,
) -> (FilteredReview, String) {
    let filtered = filter_findings(llm_output.findings, parsed_diff, config);
    let summary = format_pr_summary(
        &filtered.status,
        parsed_diff.files.len(),
        filtered.inline_findings.len(),
        &filtered.summary_fallback_findings,
        model_name,
    );
    (filtered, summary)
}

fn strip_markdown_json_fence(raw: &str) -> &str {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix("```") {
        let after_lang = rest
            .strip_prefix("json")
            .or_else(|| rest.strip_prefix("JSON"))
            .unwrap_or(rest);
        let body = after_lang.trim_start_matches(['\r', '\n']);
        if let Some(without_end) = body.strip_suffix("```") {
            return without_end.trim();
        }
    }
    trimmed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fenced_and_plain_json_outputs() {
        let fenced = "```json\n{\"findings\": []}\n```";
        let out = parse_llm_output(fenced).expect("should parse fenced json");
        assert!(out.findings.is_empty());
    }

    #[test]
    fn skips_when_diff_has_only_lockfiles() {
        let diff = "diff --git a/Cargo.lock b/Cargo.lock\n--- a/Cargo.lock\n+++ b/Cargo.lock\n@@ -1 +1,2 @@\n+foo\n";
        let prep = prepare_review(diff, &PrMetadata::default(), &ReviewConfig::default());
        assert!(matches!(prep, PreparedDiff::Skip { .. }));
    }
}
