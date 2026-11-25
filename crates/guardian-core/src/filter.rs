//! Deterministic noise-filtering pipeline and PR summary formatter.

use crate::diff::{DiffMatch, ParsedDiff};
use crate::types::{
    DropReason, DroppedFinding, FilterTrace, LlmFinding, ReviewConfig, ReviewStatus,
    SkipFileReason, ValidatedFinding,
};

pub const SUMMARY_MARKER: &str = "<!-- guardian:summary:v1 -->";

#[derive(Debug, Clone)]
pub struct FilteredReview {
    pub status: ReviewStatus,
    pub inline_findings: Vec<ValidatedFinding>,
    pub summary_fallback_findings: Vec<ValidatedFinding>,
    pub trace: FilterTrace,
}

pub fn filter_findings(
    candidates: Vec<LlmFinding>,
    parsed_diff: &ParsedDiff,
    config: &ReviewConfig,
) -> FilteredReview {
    let mut trace = FilterTrace {
        generated: candidates.len(),
        ..FilterTrace::default()
    };

    let mut valid_inline: Vec<ValidatedFinding> = Vec::new();
    let mut valid_fallback: Vec<ValidatedFinding> = Vec::new();

    for cand in candidates {
        // Stage 1: Deterministic validation against the redacted diff.
        let (resolved_line, matched_line_text, route_to_inline) =
            match parsed_diff.validate_finding(&cand.path, cand.line, &cand.code_snippet) {
                DiffMatch::Inline {
                    resolved_line,
                    line_content,
                    ..
                } => (resolved_line, line_content, true),
                DiffMatch::FallbackRemovedLine { line_content } => (cand.line, line_content, false),
                DiffMatch::PathNotFound => {
                    trace.dropped_outside_diff += 1;
                    trace.drops.push(DroppedFinding {
                        path: cand.path,
                        line: cand.line,
                        reason: DropReason::OutsideDiffPath,
                    });
                    continue;
                }
                DiffMatch::SnippetMismatch => {
                    trace.dropped_outside_diff += 1;
                    trace.drops.push(DroppedFinding {
                        path: cand.path,
                        line: cand.line,
                        reason: DropReason::OutsideDiffSnippet,
                    });
                    continue;
                }
            };

        // Stage 2: Relevance to current change (no pre-existing legacy issues).
        if !cand.introduced_by_change {
            trace.dropped_legacy += 1;
            trace.drops.push(DroppedFinding {
                path: cand.path,
                line: resolved_line,
                reason: DropReason::LegacyNotIntroduced,
            });
            continue;
        }

        // Stage 3: Category & severity gate.
        if !cand.category.is_allowed_in_v1() {
            trace.dropped_category_or_severity += 1;
            trace.drops.push(DroppedFinding {
                path: cand.path,
                line: resolved_line,
                reason: DropReason::UnsupportedCategory,
            });
            continue;
        }
        if cand.severity < config.min_severity {
            trace.dropped_category_or_severity += 1;
            trace.drops.push(DroppedFinding {
                path: cand.path,
                line: resolved_line,
                reason: DropReason::BelowSeverity,
            });
            continue;
        }

        // Stage 4: Concrete failure scenario check.
        if !has_concrete_scenario(&cand.scenario) {
            trace.dropped_missing_scenario += 1;
            trace.drops.push(DroppedFinding {
                path: cand.path,
                line: resolved_line,
                reason: DropReason::MissingScenario,
            });
            continue;
        }

        // Stage 7a: Inline escape hatch (`guardian-ignore`).
        if has_guardian_ignore(&matched_line_text) {
            trace.dropped_ignored_inline += 1;
            trace.drops.push(DroppedFinding {
                path: cand.path,
                line: resolved_line,
                reason: DropReason::IgnoredInline,
            });
            continue;
        }

        let normalized_path = cand
            .path
            .trim_start_matches("b/")
            .trim_start_matches("./")
            .to_string();

        let validated = ValidatedFinding {
            path: normalized_path,
            line: resolved_line,
            code_snippet: matched_line_text,
            category: cand.category,
            severity: cand.severity,
            scenario: cand.scenario.trim().to_string(),
            message: cand.message.trim().to_string(),
            suggestion: cand.suggestion.filter(|s| !s.trim().is_empty()),
        };

        if route_to_inline {
            valid_inline.push(validated);
        } else {
            valid_fallback.push(validated);
        }
    }

    // Sort highest severity first.
    valid_inline.sort_by_key(|a| std::cmp::Reverse(a.severity));
    valid_fallback.sort_by_key(|a| std::cmp::Reverse(a.severity));

    // Stage 7b: Enforce max_comments across inline + fallback (prioritizing inline).
    let mut budget = config.max_comments;
    if valid_inline.len() > budget {
        let excess = valid_inline.split_off(budget);
        for dropped in excess {
            trace.dropped_over_max_comments += 1;
            trace.drops.push(DroppedFinding {
                path: dropped.path,
                line: dropped.line,
                reason: DropReason::OverMaxComments,
            });
        }
        budget = 0;
    } else {
        budget -= valid_inline.len();
    }

    if valid_fallback.len() > budget {
        let excess = valid_fallback.split_off(budget);
        for dropped in excess {
            trace.dropped_over_max_comments += 1;
            trace.drops.push(DroppedFinding {
                path: dropped.path,
                line: dropped.line,
                reason: DropReason::OverMaxComments,
            });
        }
    }

    trace.published_inline = valid_inline.len();
    trace.published_fallback = valid_fallback.len();

    let truncated_files = parsed_diff
        .skipped_files
        .iter()
        .filter(|(_, r)| *r == SkipFileReason::OverMaxFiles)
        .count();

    let status = if truncated_files > 0 {
        ReviewStatus::ReviewedPartial {
            reason: format!(
                "Reviewed {} files ({} skipped due to max_files={})",
                parsed_diff.files.len(),
                truncated_files,
                config.max_files
            ),
        }
    } else if valid_inline.is_empty() && valid_fallback.is_empty() {
        ReviewStatus::ReviewedClean
    } else {
        ReviewStatus::ReviewedWithFindings
    };

    FilteredReview {
        status,
        inline_findings: valid_inline,
        summary_fallback_findings: valid_fallback,
        trace,
    }
}

/// Formats an individual inline PR comment in Markdown.
pub fn format_inline_comment(finding: &ValidatedFinding) -> String {
    let mut body = format!(
        "**[{sev} | {cat}]** {msg}\n\n**Failure scenario:** {scenario}",
        sev = finding.severity.as_str().to_uppercase(),
        cat = finding.category.as_str(),
        msg = finding.message,
        scenario = finding.scenario,
    );

    if let Some(sugg) = &finding.suggestion {
        body.push_str("\n\nSuggested fix:\n```\n");
        body.push_str(sugg.trim_end());
        body.push_str("\n```");
    }

    body.push_str("\n\n<sub>Suppress false positive with `guardian-ignore` on the line.</sub>");
    body
}

/// Formats the fixed PR summary comment (`<!-- guardian:summary:v1 -->`).
pub fn format_pr_summary(
    status: &ReviewStatus,
    reviewed_files: usize,
    inline_count: usize,
    fallback_findings: &[ValidatedFinding],
    model_name: &str,
) -> String {
    let mut out = String::from(SUMMARY_MARKER);
    out.push_str("\n### Guardian Code Review\n\n");

    match status {
        ReviewStatus::ReviewedClean => {
            out.push_str(&format!(
                "**Status:** Reviewed ({reviewed_files} file(s)) — no high-confidence logical bugs or edge cases found.\n"
            ));
        }
        ReviewStatus::ReviewedWithFindings => {
            let total = inline_count + fallback_findings.len();
            out.push_str(&format!(
                "**Status:** Reviewed ({reviewed_files} file(s)) — **{total}** finding(s) reported.\n"
            ));
        }
        ReviewStatus::ReviewedPartial { reason } => {
            out.push_str(&format!("**Status:** Partially reviewed — {reason}.\n"));
        }
        ReviewStatus::Skipped { reason } => {
            out.push_str(&format!("**Status:** Skipped — {reason}.\n"));
        }
        ReviewStatus::Error { reason } => {
            out.push_str(&format!("**Status:** Error — {reason}.\n"));
        }
    }

    if !fallback_findings.is_empty() {
        out.push_str("\n#### Additional Findings (outside inline diff range)\n\n");
        for f in fallback_findings {
            out.push_str(&format!(
                "- **`{path}:{line}`** [{sev} | {cat}]: {msg} *(Scenario: {scenario})*\n",
                path = f.path,
                line = f.line,
                sev = f.severity.as_str().to_uppercase(),
                cat = f.category.as_str(),
                msg = f.message,
                scenario = f.scenario,
            ));
        }
    }

    out.push_str(&format!(
        "\n<sub>Model: `{model_name}` | Guardian v{ver}</sub>\n",
        ver = crate::VERSION
    ));
    out
}

fn has_concrete_scenario(scenario: &str) -> bool {
    let trimmed = scenario.trim();
    if trimmed.len() < 12 {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    !matches!(
        lower.as_str(),
        "none" | "n/a" | "unknown" | "might fail" | "could fail" | "podría fallar"
    )
}

fn has_guardian_ignore(line: &str) -> bool {
    line.contains("guardian-ignore")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::parse_unified_diff;
    use crate::types::{FindingCategory, Severity};

    const DIFF: &str = "\
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,5 @@
 pub fn divide(a: i64, b: i64) -> i64 {
+    let _x = a / b; // guardian-ignore
+    a / b
 }
";

    fn base_finding(line: u32, snippet: &str) -> LlmFinding {
        LlmFinding {
            path: "src/lib.rs".to_string(),
            line,
            code_snippet: snippet.to_string(),
            category: FindingCategory::EdgeCase,
            severity: Severity::High,
            introduced_by_change: true,
            scenario: "When b == 0, integer division panics at runtime.".to_string(),
            message: "Guard against b == 0 before dividing.".to_string(),
            suggestion: None,
        }
    }

    #[test]
    fn funnel_enforces_diff_validation_ignore_and_caps() {
        let config = ReviewConfig {
            max_comments: 1,
            ..ReviewConfig::default()
        };
        let parsed = parse_unified_diff(DIFF, &config);

        let mut hallucinated = base_finding(99, "nonexistent_call()");
        hallucinated.severity = Severity::Critical;

        let ignored = base_finding(2, "let _x = a / b; // guardian-ignore");

        let mut legacy = base_finding(3, "a / b");
        legacy.introduced_by_change = false;

        let valid_high = base_finding(3, "a / b");
        let mut valid_medium = base_finding(3, "a / b");
        valid_medium.severity = Severity::Medium;

        let res = filter_findings(
            vec![hallucinated, ignored, legacy, valid_medium, valid_high],
            &parsed,
            &config,
        );

        assert_eq!(res.trace.generated, 5);
        assert_eq!(res.trace.dropped_outside_diff, 1);
        assert_eq!(res.trace.dropped_ignored_inline, 1);
        assert_eq!(res.trace.dropped_legacy, 1);
        assert_eq!(res.trace.dropped_over_max_comments, 1);
        assert_eq!(res.inline_findings.len(), 1);
        assert_eq!(res.inline_findings[0].severity, Severity::High);
    }
}
