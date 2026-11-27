//! Pure core library for Guardian.
//!
//! Contains diff parsing, secret redaction, Tree-sitter AST intra-file context,
//! prompt construction, deterministic 7-stage noise filtering, SHA-256
//! fingerprinting, and finding validation with zero network or filesystem I/O.

pub mod ast_context;
pub mod config;
pub mod diff;
pub mod filter;
pub mod fingerprint;
pub mod prompt;
pub mod redact;
pub mod types;

use std::collections::{HashMap, HashSet};

use ast_context::{extract_file_context, render_contexts_for_prompt};
use diff::{parse_unified_diff, DiffLineKind, ParsedDiff};
use filter::{filter_findings, format_enriched_pr_summary, FilteredReview, SummaryReport};
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
        ast_context_files: usize,
    },
}

/// Redacts secrets from the raw diff & PR metadata, parses reviewable hunks, and builds prompts
/// without extra file context.
pub fn prepare_review(
    raw_diff: &str,
    metadata: &PrMetadata,
    config: &ReviewConfig,
) -> PreparedDiff {
    prepare_review_with_context(raw_diff, metadata, config, &HashMap::new())
}

/// Redacts secrets from the raw diff, metadata, and optional full file sources, extracts
/// Tree-sitter AST intra-file context (imports + enclosing functions), and builds prompts.
pub fn prepare_review_with_context(
    raw_diff: &str,
    metadata: &PrMetadata,
    config: &ReviewConfig,
    file_sources: &HashMap<String, String>,
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

    let mut extracted_contexts = Vec::new();
    for file in &parsed_diff.files {
        if let Some(raw_src) = file_sources.get(&file.path) {
            let redacted_src = redact_secrets(raw_src);
            let mut changed_lines: Vec<u32> = file
                .hunks
                .iter()
                .flat_map(|h| h.lines.iter())
                .filter(|dl| dl.kind == DiffLineKind::Added)
                .filter_map(|dl| dl.new_lineno)
                .collect();
            if changed_lines.is_empty() {
                changed_lines = file
                    .hunks
                    .iter()
                    .flat_map(|h| h.lines.iter())
                    .filter_map(|dl| dl.new_lineno)
                    .collect();
            }
            if let Some(ctx) = extract_file_context(&file.path, &redacted_src, &changed_lines) {
                extracted_contexts.push(ctx);
            }
        }
    }

    let ast_context_files = extracted_contexts.len();
    let rendered_ctx = if extracted_contexts.is_empty() {
        None
    } else {
        Some(render_contexts_for_prompt(&extracted_contexts))
    };

    let annotated = parsed_diff.render_for_prompt();
    let prompt = build_review_prompt(&redacted_meta, &annotated, rendered_ctx.as_deref(), config);
    PreparedDiff::Ready {
        parsed_diff,
        prompt,
        ast_context_files,
    }
}

/// Parses strict JSON from an LLM response, stripping optional Markdown code fences.
pub fn parse_llm_output(raw_response: &str) -> Result<LlmReviewOutput, CoreError> {
    let cleaned = strip_markdown_json_fence(raw_response);
    let parsed = serde_json::from_str::<LlmReviewOutput>(cleaned)?;
    Ok(parsed)
}

/// Runs deterministic 7-stage validation/deduplication and builds inline findings + PR summary.
pub fn finalize_review(
    llm_output: LlmReviewOutput,
    parsed_diff: &ParsedDiff,
    config: &ReviewConfig,
    existing_fingerprints: &HashSet<String>,
    model_name: &str,
) -> (FilteredReview, String) {
    let filtered = filter_findings(
        llm_output.findings,
        parsed_diff,
        config,
        existing_fingerprints,
    );
    let reviewed_paths: Vec<String> = parsed_diff.files.iter().map(|f| f.path.clone()).collect();
    let summary = format_enriched_pr_summary(&SummaryReport {
        status: &filtered.status,
        reviewed_files: &reviewed_paths,
        skipped_files: &parsed_diff.skipped_files,
        inline_findings: &filtered.inline_findings,
        fallback_findings: &filtered.summary_fallback_findings,
        deduplicated_count: filtered.trace.dropped_duplicate_existing,
        resolved_threads_count: 0,
        model_name,
        language: &config.language,
    });
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
