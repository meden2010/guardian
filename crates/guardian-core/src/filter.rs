//! Deterministic 7-stage noise-filtering pipeline and PR comment/summary formatters.

use std::collections::HashSet;

use crate::diff::{DiffMatch, ParsedDiff};
use crate::fingerprint::{compute_fingerprint, format_fp_marker};
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
    existing_fingerprints: &HashSet<String>,
) -> FilteredReview {
    let mut trace = FilterTrace {
        generated: candidates.len(),
        ..FilterTrace::default()
    };

    let mut raw_inline: Vec<ValidatedFinding> = Vec::new();
    let mut raw_fallback: Vec<ValidatedFinding> = Vec::new();

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

        // Stage 7a: Inline escape hatch (`guardian-ignore`) before grouping/dedup.
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

        let fingerprint = compute_fingerprint(&normalized_path, &matched_line_text, cand.category);

        // Stage 6: Cross-commit deduplication against existing PR comments.
        if existing_fingerprints.contains(&fingerprint) {
            trace.dropped_duplicate_existing += 1;
            trace.drops.push(DroppedFinding {
                path: normalized_path,
                line: resolved_line,
                reason: DropReason::DuplicateExistingComment,
            });
            continue;
        }

        let validated = ValidatedFinding {
            path: normalized_path,
            line: resolved_line,
            also_at_lines: Vec::new(),
            fingerprint,
            code_snippet: matched_line_text,
            category: cand.category,
            severity: cand.severity,
            scenario: cand.scenario.trim().to_string(),
            message: cand.message.trim().to_string(),
            suggestion: cand.suggestion.filter(|s| !s.trim().is_empty()),
        };

        if route_to_inline {
            raw_inline.push(validated);
        } else {
            raw_fallback.push(validated);
        }
    }

    // Sort highest severity first before Stage 5 grouping so highest-severity item becomes anchor.
    raw_inline.sort_by_key(|a| std::cmp::Reverse(a.severity));
    raw_fallback.sort_by_key(|a| std::cmp::Reverse(a.severity));

    // Stage 5: Intra-PR grouping of repeated patterns within the same file & category.
    let mut valid_inline = group_intra_pr(raw_inline, &mut trace);
    let mut valid_fallback = group_intra_pr(raw_fallback, &mut trace);

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

fn group_intra_pr(items: Vec<ValidatedFinding>, trace: &mut FilterTrace) -> Vec<ValidatedFinding> {
    let mut grouped: Vec<ValidatedFinding> = Vec::new();

    for cand in items {
        let existing_anchor = grouped.iter_mut().find(|anchor| {
            anchor.path == cand.path
                && anchor.category == cand.category
                && (anchor.fingerprint == cand.fingerprint
                    || messages_share_pattern(&anchor.message, &cand.message))
        });

        if let Some(anchor) = existing_anchor {
            if cand.line != anchor.line && !anchor.also_at_lines.contains(&cand.line) {
                anchor.also_at_lines.push(cand.line);
                anchor.also_at_lines.sort_unstable();
            }
            trace.grouped_intra_pr += 1;
            trace.drops.push(DroppedFinding {
                path: cand.path,
                line: cand.line,
                reason: DropReason::GroupedIntraPr,
            });
        } else {
            grouped.push(cand);
        }
    }

    grouped
}

/// Checks if two finding messages in the same file/category describe the same repeated bug pattern
/// (>= 60% Jaccard overlap on significant words of length >= 4).
fn messages_share_pattern(a: &str, b: &str) -> bool {
    let words_a: HashSet<String> = significant_words(a);
    let words_b: HashSet<String> = significant_words(b);
    if words_a.len() < 3 || words_b.len() < 3 {
        return a.trim().eq_ignore_ascii_case(b.trim());
    }
    let inter = words_a.intersection(&words_b).count();
    let union = words_a.union(&words_b).count();
    union > 0 && (inter * 100 / union) >= 60
}

fn significant_words(s: &str) -> HashSet<String> {
    s.split(|c: char| !c.is_alphanumeric() && c != '_')
        .map(str::to_lowercase)
        .filter(|w| w.len() >= 4)
        .collect()
}

/// Formats an individual inline PR comment using GitHub-native Markdown alerts and a hidden fingerprint marker.
/// Emits a native 1-click ```` ```suggestion ```` block only when `suggestions_enabled` is true and
/// the suggestion passes range & code-safety validation.
pub fn format_inline_comment(
    finding: &ValidatedFinding,
    language: &str,
    suggestions_enabled: bool,
) -> String {
    let is_es = is_spanish(language);
    let (alert, sev_icon, sev_label) = match finding.severity {
        crate::types::Severity::Critical => ("CAUTION", "🔴", "Critical"),
        crate::types::Severity::High => ("WARNING", "🟠", "High"),
        crate::types::Severity::Medium => ("IMPORTANT", "🟣", "Medium"),
        crate::types::Severity::Low => ("NOTE", "🔵", "Low"),
    };

    let cat_label = finding.category.as_str();
    let scenario_label = if is_es {
        "Escenario de fallo"
    } else {
        "Failure scenario"
    };
    let suggestion_label = if is_es {
        "💡 Sugerencia de corrección"
    } else {
        "💡 Suggested fix"
    };
    let footer = if is_es {
        "<sub>Silencia falsos positivos agregando `guardian-ignore` en esta línea.</sub>"
    } else {
        "<sub>Suppress false positives by adding `guardian-ignore` on this line.</sub>"
    };

    let also_lines_note = if finding.also_at_lines.is_empty() {
        String::new()
    } else {
        let joined = finding
            .also_at_lines
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        if is_es {
            format!(" *(también en línea(s): {joined})*")
        } else {
            format!(" *(also on line(s): {joined})*")
        }
    };

    let msg_quoted = quote_multiline(&finding.message);
    let scenario_quoted = quote_multiline(&finding.scenario);

    let mut body = format!(
        "{fp_marker}\n\
         > [!{alert}]\n\
         > {sev_icon} **{sev_label}** · `{cat_label}`{also_lines_note}\n\
         >\n\
         > {msg_quoted}\n\
         >\n\
         > **{scenario_label}:** `{scenario_quoted}`\n",
        fp_marker = format_fp_marker(&finding.fingerprint),
    );

    if let Some(sugg) = &finding.suggestion {
        let trimmed = sugg.trim_end();
        if suggestions_enabled && is_applicable_code_suggestion(trimmed, finding) {
            body.push_str("\n```suggestion\n");
            body.push_str(trimmed);
            body.push_str("\n```\n");
        } else {
            body.push_str(&format!(
                "\n<details>\n<summary>{suggestion_label}</summary>\n\n```\n{trimmed}\n```\n\n</details>\n"
            ));
        }
    }

    body.push('\n');
    body.push_str(footer);
    body
}

/// Validates that a suggestion is safe to emit as a 1-click GitHub `suggestion` block:
/// single-line target (not grouped across multiple lines), no nested code fences, concise,
/// and looks like code rather than natural-language prose.
fn is_applicable_code_suggestion(sugg: &str, finding: &ValidatedFinding) -> bool {
    let trimmed = sugg.trim();
    if trimmed.is_empty()
        || !finding.also_at_lines.is_empty()
        || trimmed.contains("```")
        || trimmed.lines().count() > 4
    {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    let prose_prefixes = [
        "add ",
        "check ",
        "consider ",
        "change ",
        "use ",
        "make sure ",
        "ensure ",
        "validate ",
        "handle ",
        "añadir ",
        "agregar ",
        "verificar ",
        "comprobar ",
        "cambiar ",
        "considera ",
        "asegúrate ",
        "validar ",
    ];
    !prose_prefixes.iter().any(|p| lower.starts_with(p))
}

/// Formats the fixed PR summary comment (`<!-- guardian:summary:v1 -->`) with GitHub Alerts.
pub fn format_pr_summary(
    status: &ReviewStatus,
    reviewed_files: usize,
    inline_count: usize,
    fallback_findings: &[ValidatedFinding],
    deduplicated_count: usize,
    model_name: &str,
    language: &str,
) -> String {
    let is_es = is_spanish(language);
    let total = inline_count + fallback_findings.len();

    let (alert, status_label, headline) = match status {
        ReviewStatus::ReviewedClean => (
            "TIP",
            if is_es { "Limpio" } else { "Clean" },
            if is_es {
                if deduplicated_count > 0 {
                    format!(
                        "Sin hallazgos nuevos en **{reviewed_files}** archivo(s) revisado(s) (*{deduplicated_count} ya reportado(s) previamente*)."
                    )
                } else {
                    format!(
                        "Sin bugs lógicos ni *edge cases* de alta confianza en **{reviewed_files}** archivo(s) revisado(s)."
                    )
                }
            } else if deduplicated_count > 0 {
                format!(
                    "No new findings across **{reviewed_files}** reviewed file(s) (*{deduplicated_count} previously reported*)."
                )
            } else {
                format!(
                    "No high-confidence logical bugs or edge cases found across **{reviewed_files}** reviewed file(s)."
                )
            },
        ),
        ReviewStatus::ReviewedWithFindings => (
            "IMPORTANT",
            if is_es {
                "Revisado con hallazgos"
            } else {
                "Reviewed with findings"
            },
            if is_es {
                format!(
                    "Se detectaron **{total}** hallazgo(s) nuevo(s) de alta confianza en **{reviewed_files}** archivo(s) revisado(s)."
                )
            } else {
                format!(
                    "Detected **{total}** new high-confidence finding(s) across **{reviewed_files}** reviewed file(s)."
                )
            },
        ),
        ReviewStatus::ReviewedPartial { reason } => (
            "WARNING",
            if is_es {
                "Revisado parcialmente"
            } else {
                "Partially reviewed"
            },
            if is_es {
                format!("Revisión parcial — {reason}.")
            } else {
                format!("Partially reviewed — {reason}.")
            },
        ),
        ReviewStatus::Skipped { reason } => (
            "NOTE",
            if is_es { "Omitido" } else { "Skipped" },
            if is_es {
                format!("Revisión omitida — {reason}.")
            } else {
                format!("Review skipped — {reason}.")
            },
        ),
        ReviewStatus::Error { reason } => (
            "CAUTION",
            "Error",
            if is_es {
                format!("No se pudo completar la revisión — {reason}.")
            } else {
                format!("Review could not complete — {reason}.")
            },
        ),
    };

    let title = if is_es {
        "🛡️ Guardian · Revisión de Código"
    } else {
        "🛡️ Guardian · Code Review"
    };
    let details_title = if is_es {
        "Detalles de la ejecución"
    } else {
        "Run details"
    };
    let (h_metric, h_val, r_status, r_files, r_inline, r_dedup, r_model) = if is_es {
        (
            "Métrica",
            "Valor",
            "Estado",
            "Archivos revisados",
            "Comentarios inline nuevos",
            "Duplicados omitidos",
            "Modelo",
        )
    } else {
        (
            "Metric",
            "Value",
            "Status",
            "Files reviewed",
            "New inline comments",
            "Deduplicated skipped",
            "Model",
        )
    };

    let dedup_row = if deduplicated_count > 0 {
        format!("> | **{r_dedup}** | {deduplicated_count} |\n")
    } else {
        String::new()
    };

    let mut out = format!(
        "{SUMMARY_MARKER}\n\
         > [!{alert}]\n\
         > ### {title}\n\
         >\n\
         > {headline}\n\
         >\n\
         > <details>\n\
         > <summary>⚙️ {details_title}</summary>\n\
         >\n\
         > | {h_metric} | {h_val} |\n\
         > | :--- | :--- |\n\
         > | **{r_status}** | {status_label} |\n\
         > | **{r_files}** | {reviewed_files} |\n\
         > | **{r_inline}** | {inline_count} |\n\
         {dedup_row}\
         > | **{r_model}** | `{model_name}` |\n\
         > </details>\n"
    );

    if !fallback_findings.is_empty() {
        let fallback_heading = if is_es {
            "#### Hallazgos adicionales (fuera de rango inline del diff)"
        } else {
            "#### Additional Findings (outside inline diff range)"
        };
        let scen_lbl = if is_es { "Escenario" } else { "Scenario" };
        out.push_str(&format!("\n{fallback_heading}\n\n"));
        for f in fallback_findings {
            out.push_str(&format!(
                "- {fp} **`{path}:{line}`** `{sev}` · `{cat}`: {msg} *({scen_lbl}: {scenario})*\n",
                fp = format_fp_marker(&f.fingerprint),
                path = f.path,
                line = f.line,
                sev = f.severity.as_str().to_uppercase(),
                cat = f.category.as_str(),
                msg = f.message,
                scenario = f.scenario,
            ));
        }
    }

    let footer = if is_es {
        format!(
            "\n---\n<sub>🛡️ **Guardian** `v{ver}` · Enfoque estricto en bugs lógicos y *edge cases*</sub>\n",
            ver = crate::VERSION
        )
    } else {
        format!(
            "\n---\n<sub>🛡️ **Guardian** `v{ver}` · Strictly focused on logical bugs and edge cases</sub>\n",
            ver = crate::VERSION
        )
    };
    out.push_str(&footer);
    out
}

fn has_concrete_scenario(scenario: &str) -> bool {
    let trimmed = scenario.trim();
    if trimmed.len() < 6 {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    !matches!(
        lower.as_str(),
        "none" | "n/a" | "unknown" | "might fail" | "could fail" | "podría fallar"
    )
}

fn is_spanish(language: &str) -> bool {
    language.trim().to_ascii_lowercase().starts_with("es")
}

fn quote_multiline(text: &str) -> String {
    text.trim().replace('\n', "\n> ")
}

fn has_guardian_ignore(line: &str) -> bool {
    line.contains("guardian-ignore")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::parse_unified_diff;
    use crate::fingerprint::extract_fingerprints;
    use crate::types::{FindingCategory, Severity};

    const DIFF: &str = "\
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,7 @@
 pub fn divide(a: i64, b: i64, c: i64) -> i64 {
+    let _x = a / b; // guardian-ignore
+    let y = a / b;
+    let z = c / b;
+    y + z
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
            message: "Guard against b == 0 before integer division.".to_string(),
            suggestion: None,
        }
    }

    #[test]
    fn funnel_enforces_validation_grouping_dedup_ignore_and_caps() {
        let config = ReviewConfig {
            max_comments: 2,
            ..ReviewConfig::default()
        };
        let parsed = parse_unified_diff(DIFF, &config);

        let hallucinated = base_finding(99, "nonexistent_call()");
        let ignored = base_finding(2, "let _x = a / b; // guardian-ignore");
        let mut legacy = base_finding(3, "let y = a / b;");
        legacy.introduced_by_change = false;

        // Two findings in the same file/category with the same pattern -> Stage 5 merges line 4 into line 3!
        let valid_line_3 = base_finding(3, "let y = a / b;");
        let valid_line_4 = base_finding(4, "let z = c / b;");

        let res = filter_findings(
            vec![hallucinated, ignored, legacy, valid_line_3, valid_line_4],
            &parsed,
            &config,
            &HashSet::new(),
        );

        assert_eq!(res.trace.generated, 5);
        assert_eq!(res.trace.dropped_outside_diff, 1);
        assert_eq!(res.trace.dropped_ignored_inline, 1);
        assert_eq!(res.trace.dropped_legacy, 1);
        assert_eq!(res.trace.grouped_intra_pr, 1);
        assert_eq!(res.inline_findings.len(), 1);
        assert_eq!(res.inline_findings[0].line, 3);
        assert_eq!(res.inline_findings[0].also_at_lines, vec![4]);

        let inline_md = format_inline_comment(&res.inline_findings[0], "es", true);
        assert!(inline_md
            .contains("> [!WARNING]\n> 🟠 **High** · `edge_case` *(también en línea(s): 4)*"));

        // Extract fingerprint from formatted comment and verify Stage 6 suppresses it on re-run!
        let existing_fps: HashSet<String> = extract_fingerprints(&inline_md).into_iter().collect();
        assert_eq!(existing_fps.len(), 1);

        let rerun = filter_findings(
            vec![base_finding(3, "let y = a / b;")],
            &parsed,
            &config,
            &existing_fps,
        );
        assert_eq!(rerun.trace.dropped_duplicate_existing, 1);
        assert!(rerun.inline_findings.is_empty());
        assert_eq!(rerun.status, ReviewStatus::ReviewedClean);
    }

    #[test]
    fn formats_native_suggestion_for_code_and_details_for_prose() {
        let mut finding = ValidatedFinding {
            path: "src/lib.rs".into(),
            line: 3,
            also_at_lines: Vec::new(),
            fingerprint: "v1:deadbeef".into(),
            code_snippet: "let y = a / b;".into(),
            category: FindingCategory::EdgeCase,
            severity: Severity::High,
            scenario: "When b == 0, division panics.".into(),
            message: "Guard against zero divisor.".into(),
            suggestion: Some("let y = a.checked_div(b).unwrap_or(0);".into()),
        };

        let native = format_inline_comment(&finding, "es", true);
        assert!(native.contains("```suggestion\nlet y = a.checked_div(b).unwrap_or(0);\n```"));

        let disabled = format_inline_comment(&finding, "es", false);
        assert!(!disabled.contains("```suggestion"));
        assert!(disabled.contains("<details>"));

        finding.suggestion = Some("Check if b is zero before dividing.".into());
        let prose = format_inline_comment(&finding, "es", true);
        assert!(!prose.contains("```suggestion"));
        assert!(prose.contains("<details>"));
    }
}
