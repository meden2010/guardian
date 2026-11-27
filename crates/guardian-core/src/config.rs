//! Parser and validator for `.guardian.yml` (always read from `base_sha`, never PR head).

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::redact::redact_secrets;
use crate::types::{ReviewConfig, Severity, TeamRule};

const MAX_RULES: usize = 10;
const MAX_RULES_CHARS: usize = 2_000;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("ERR_CONFIG_YAML: invalid YAML syntax: {0}")]
    InvalidYaml(#[from] serde_yaml::Error),
    #[error("ERR_CONFIG_VERSION: unsupported or missing `version` (expected `version: 1`)")]
    UnsupportedVersion,
    #[error("ERR_CONFIG_SECRET_DETECTED: `.guardian.yml` must never contain API keys or secrets; use environment variable names instead")]
    SecretDetected,
    #[error(
        "ERR_CONFIG_RULES_LIMIT: too many rules (max {MAX_RULES} rules / {MAX_RULES_CHARS} chars)"
    )]
    RulesLimitExceeded,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoConfigFile {
    pub version: Option<u32>,
    pub language: Option<String>,
    #[serde(default)]
    pub review: RepoReviewSection,
    #[serde(default)]
    pub limits: RepoLimitsSection,
    #[serde(default)]
    pub rules: Vec<TeamRule>,
    #[serde(default)]
    pub behavior: RepoBehaviorSection,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoReviewSection {
    pub min_severity: Option<Severity>,
    pub max_comments: Option<usize>,
    pub ignore_paths: Option<Vec<String>>,
    pub skip_drafts: Option<bool>,
    pub skip_bots: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoLimitsSection {
    pub max_files: Option<usize>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoBehaviorSection {
    pub fail_on_error: Option<bool>,
    pub suggestions: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct ParsedRepoConfig {
    pub file: RepoConfigFile,
    pub warnings: Vec<String>,
}

/// Parses and validates `.guardian.yml`, rejecting embedded secrets and flagging unknown keys as warnings.
pub fn parse_repo_config(raw_yaml: &str) -> Result<ParsedRepoConfig, ConfigError> {
    // Reject embedded secrets (5.2: API keys never go in `.guardian.yml`).
    if redact_secrets(raw_yaml) != raw_yaml {
        return Err(ConfigError::SecretDetected);
    }

    let raw_val: serde_yaml::Value = serde_yaml::from_str(raw_yaml)?;
    let warnings = collect_unknown_key_warnings(&raw_val);

    let file: RepoConfigFile = serde_yaml::from_value(raw_val)?;
    if file.version != Some(1) {
        return Err(ConfigError::UnsupportedVersion);
    }

    let total_rule_chars: usize = file.rules.iter().map(|r| r.text.len()).sum();
    if file.rules.len() > MAX_RULES || total_rule_chars > MAX_RULES_CHARS {
        return Err(ConfigError::RulesLimitExceeded);
    }

    Ok(ParsedRepoConfig { file, warnings })
}

/// Applies `.guardian.yml` values on top of `base` (defaults), before CLI/workflow overrides.
pub fn apply_repo_config(base: &ReviewConfig, repo: &RepoConfigFile) -> ReviewConfig {
    let mut cfg = base.clone();
    if let Some(lang) = &repo.language {
        if !lang.trim().is_empty() {
            cfg.language = lang.trim().to_string();
        }
    }
    if let Some(sev) = repo.review.min_severity {
        cfg.min_severity = sev;
    }
    if let Some(max_c) = repo.review.max_comments {
        cfg.max_comments = max_c;
    }
    if let Some(paths) = &repo.review.ignore_paths {
        cfg.ignore_paths = paths.clone();
    }
    if let Some(skip_d) = repo.review.skip_drafts {
        cfg.skip_drafts = skip_d;
    }
    if let Some(skip_b) = repo.review.skip_bots {
        cfg.skip_bots = skip_b;
    }
    if let Some(max_f) = repo.limits.max_files {
        cfg.max_files = max_f;
    }
    if !repo.rules.is_empty() {
        cfg.rules = repo.rules.clone();
    }
    if let Some(foe) = repo.behavior.fail_on_error {
        cfg.fail_on_error = foe;
    }
    if let Some(sugg) = repo.behavior.suggestions {
        cfg.suggestions_enabled = sugg;
    }
    cfg
}

fn collect_unknown_key_warnings(val: &serde_yaml::Value) -> Vec<String> {
    let mut warnings = Vec::new();
    let Some(map) = val.as_mapping() else {
        return warnings;
    };

    let known_top = [
        "version", "language", "review", "limits", "models", "rules", "behavior",
    ];
    for (k, v) in map {
        if let Some(key_str) = k.as_str() {
            if !known_top.contains(&key_str) {
                warnings.push(format!(
                    "unknown top-level key `{key_str}` in `.guardian.yml`"
                ));
            } else if key_str == "review" {
                check_nested_keys(
                    v,
                    "review",
                    &[
                        "min_severity",
                        "max_comments",
                        "ignore_paths",
                        "skip_drafts",
                        "skip_bots",
                    ],
                    &mut warnings,
                );
            } else if key_str == "limits" {
                check_nested_keys(
                    v,
                    "limits",
                    &["max_files", "max_input_tokens", "max_cost_usd"],
                    &mut warnings,
                );
            } else if key_str == "behavior" {
                check_nested_keys(
                    v,
                    "behavior",
                    &["fail_on_error", "suggestions"],
                    &mut warnings,
                );
            }
        }
    }

    warnings
}

fn check_nested_keys(
    val: &serde_yaml::Value,
    section: &str,
    known: &[&str],
    warnings: &mut Vec<String>,
) {
    if let Some(map) = val.as_mapping() {
        for (k, _) in map {
            if let Some(key_str) = k.as_str() {
                if !known.contains(&key_str) {
                    warnings.push(format!(
                        "unknown key `{section}.{key_str}` in `.guardian.yml`"
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_config_and_warns_on_unknown_typo() {
        let yaml = r#"
version: 1
language: es
review:
  min_severity: high
  max_comments: 5
  max_comment: 3
  ignore_paths: ["docs/**"]
limits:
  max_files: 25
rules:
  - id: no-unwrap
    text: "Avoid .unwrap() in production code paths."
behavior:
  suggestions: true
"#;
        let parsed = parse_repo_config(yaml).expect("valid config");
        assert_eq!(parsed.warnings.len(), 1);
        assert!(parsed.warnings[0].contains("review.max_comment"));

        let merged = apply_repo_config(&ReviewConfig::default(), &parsed.file);
        assert_eq!(merged.language, "es");
        assert_eq!(merged.min_severity, Severity::High);
        assert_eq!(merged.max_comments, 5);
        assert_eq!(merged.max_files, 25);
        assert_eq!(merged.rules.len(), 1);
        assert!(merged.suggestions_enabled);
    }

    #[test]
    fn rejects_missing_version_and_embedded_secrets() {
        assert!(matches!(
            parse_repo_config("language: es\n"),
            Err(ConfigError::UnsupportedVersion)
        ));

        let leaky =
            "version: 1\nrules:\n  - text: \"use ghp_1234567890abcdef1234567890abcdef1234\"\n";
        assert!(matches!(
            parse_repo_config(leaky),
            Err(ConfigError::SecretDetected)
        ));
    }
}
