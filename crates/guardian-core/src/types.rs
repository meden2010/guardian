use serde::{Deserialize, Serialize};

/// Severity level assigned to a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Category reported by the model. Unknown values deserialize to `Other` and are filtered out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    Bug,
    EdgeCase,
    #[serde(other)]
    Other,
}

impl FindingCategory {
    pub fn is_allowed_in_v1(self) -> bool {
        matches!(self, Self::Bug | Self::EdgeCase)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bug => "bug",
            Self::EdgeCase => "edge_case",
            Self::Other => "other",
        }
    }
}

/// Optional repository-specific rule declared in `.guardian.yml`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamRule {
    #[serde(default)]
    pub id: Option<String>,
    pub text: String,
}

/// Configuration for a review execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewConfig {
    pub language: String,
    pub min_severity: Severity,
    pub max_comments: usize,
    pub max_files: usize,
    pub ignore_paths: Vec<String>,
    pub skip_drafts: bool,
    pub skip_bots: bool,
    pub fail_on_error: bool,
    pub suggestions_enabled: bool,
    pub rules: Vec<TeamRule>,
}

impl Default for ReviewConfig {
    fn default() -> Self {
        Self {
            language: "en".to_string(),
            min_severity: Severity::Medium,
            max_comments: 8,
            max_files: 40,
            ignore_paths: Vec::new(),
            skip_drafts: true,
            skip_bots: true,
            fail_on_error: false,
            suggestions_enabled: true,
            rules: Vec::new(),
        }
    }
}

/// Untrusted PR metadata passed inside explicit prompt delimiters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrMetadata {
    pub title: String,
    pub description: String,
}

/// Top-level strict JSON envelope expected from the LLM.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LlmReviewOutput {
    #[serde(default)]
    pub findings: Vec<LlmFinding>,
}

/// Raw finding candidate returned by the LLM before deterministic validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmFinding {
    pub path: String,
    pub line: u32,
    pub code_snippet: String,
    pub category: FindingCategory,
    pub severity: Severity,
    pub introduced_by_change: bool,
    pub scenario: String,
    pub message: String,
    #[serde(default)]
    pub suggestion: Option<String>,
}

/// Validated finding that passed all deterministic and schema gates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatedFinding {
    pub path: String,
    pub line: u32,
    /// Additional lines in the same file merged during Stage 5 intra-PR grouping.
    #[serde(default)]
    pub also_at_lines: Vec<u32>,
    pub fingerprint: String,
    pub code_snippet: String,
    pub category: FindingCategory,
    pub severity: Severity,
    pub scenario: String,
    pub message: String,
    pub suggestion: Option<String>,
}

/// Stable reason codes explaining why a finding candidate was dropped or merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DropReason {
    OutsideDiffPath,
    OutsideDiffSnippet,
    LegacyNotIntroduced,
    UnsupportedCategory,
    BelowSeverity,
    MissingScenario,
    GroupedIntraPr,
    DuplicateExistingComment,
    IgnoredInline,
    OverMaxComments,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DroppedFinding {
    pub path: String,
    pub line: u32,
    pub reason: DropReason,
}

/// Funnel counts across all 7 filtering stages for observability (`GITHUB_STEP_SUMMARY`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterTrace {
    pub generated: usize,
    pub dropped_outside_diff: usize,
    pub dropped_legacy: usize,
    pub dropped_category_or_severity: usize,
    pub dropped_missing_scenario: usize,
    pub grouped_intra_pr: usize,
    pub dropped_duplicate_existing: usize,
    pub dropped_ignored_inline: usize,
    pub dropped_over_max_comments: usize,
    pub published_inline: usize,
    pub published_fallback: usize,
    pub drops: Vec<DroppedFinding>,
}

impl FilterTrace {
    pub fn format_funnel(&self) -> String {
        format!(
            "{} generated -> -{} s1(diff) -> -{} s2(legacy) -> -{} s3(cat/sev) -> -{} s4(scenario) -> -{} s5(grouped) -> -{} s6(dedup) -> -{} s7(ignored) -> -{} s7(cap) => {} inline + {} fallback",
            self.generated,
            self.dropped_outside_diff,
            self.dropped_legacy,
            self.dropped_category_or_severity,
            self.dropped_missing_scenario,
            self.grouped_intra_pr,
            self.dropped_duplicate_existing,
            self.dropped_ignored_inline,
            self.dropped_over_max_comments,
            self.published_inline,
            self.published_fallback,
        )
    }
}

/// Closed set of review execution outcomes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ReviewStatus {
    ReviewedClean,
    ReviewedWithFindings,
    ReviewedPartial { reason: String },
    Skipped { reason: String },
    Error { reason: String },
}

/// Reason a file was excluded before calling the LLM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipFileReason {
    Binary,
    Lockfile,
    Generated,
    SensitivePath,
    ConfiguredIgnore,
    OverMaxFiles,
}
