//! Evaluation harness (`guardian eval`) for Level A (offline replay) and Level B (live LLM) benchmarks.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::Args;
use guardian_core::prompt::PROMPT_VERSION;
use guardian_core::types::{LlmReviewOutput, PrMetadata, ReviewConfig, Severity, ValidatedFinding};
use guardian_core::{finalize_review, prepare_review, PreparedDiff};
use serde::{Deserialize, Serialize};

use crate::llm::{OpenAiCompatibleClient, OpenAiCompatibleConfig};
use crate::CliSeverity;

#[derive(Debug, Clone, Args)]
pub struct EvalArgs {
    /// Directory containing benchmark case folders
    #[arg(long, default_value = "evals/cases")]
    pub cases_dir: PathBuf,

    /// Run offline using each case's `recorded_llm.json` (Level A deterministic mode, zero network)
    #[arg(long)]
    pub offline: bool,

    /// Save live redacted LLM responses into `<case_dir>/recorded_llm.json`
    #[arg(long)]
    pub record_fixtures: bool,

    /// Number of passes per case to measure non-determinism (Level B)
    #[arg(long, default_value_t = 1)]
    pub runs: usize,

    /// OpenAI-compatible base URL (required unless `--offline`)
    #[arg(
        long,
        env = "GUARDIAN_LLM_BASE_URL",
        default_value = "https://api.openai.com/v1"
    )]
    pub base_url: String,

    /// Model identifier (required unless `--offline`)
    #[arg(long, env = "GUARDIAN_LLM_MODEL")]
    pub model: Option<String>,

    /// Name of environment variable containing the LLM API key
    #[arg(long, default_value = "GUARDIAN_LLM_API_KEY")]
    pub api_key_env: String,

    /// Allow plain `http://` for trusted LAN / Tailscale inference servers
    #[arg(long, env = "GUARDIAN_ALLOW_INSECURE_HTTP")]
    pub allow_insecure_http: bool,

    /// Language for review comments
    #[arg(long, env = "GUARDIAN_LANGUAGE", default_value = "es")]
    pub language: String,

    /// Minimum severity threshold
    #[arg(long, value_enum, default_value_t = CliSeverity::Medium)]
    pub min_severity: CliSeverity,

    /// HTTP request timeout in seconds for LLM calls
    #[arg(long, env = "GUARDIAN_TIMEOUT_SECS", default_value_t = 240)]
    pub timeout_secs: u64,

    /// Optional JSON report output path
    #[arg(long)]
    pub output_report: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaseKind {
    Bug,
    Clean,
    Adversarial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalCaseSpec {
    pub id: String,
    pub kind: CaseKind,
    pub language: String,
    #[serde(default)]
    pub pr_title: String,
    #[serde(default)]
    pub pr_description: String,
    #[serde(default)]
    pub expected_findings: Vec<ExpectedFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedFinding {
    pub path: String,
    pub line_start: u32,
    pub line_end: u32,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvalReport {
    pub guardian_version: String,
    pub prompt_version: String,
    pub model: String,
    pub offline: bool,
    pub runs: usize,
    pub recall_pct: f64,
    pub precision_pct: f64,
    pub clean_silence_pct: f64,
    pub median_comments_per_pr: f64,
    pub mean_latency_ms: u64,
    pub cases: Vec<CaseSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaseSummary {
    pub id: String,
    pub kind: CaseKind,
    pub expected_count: usize,
    pub matched_expected: usize,
    pub published_count: usize,
    pub passed: bool,
    pub latency_ms: u64,
}

pub async fn run_eval(args: EvalArgs) -> Result<EvalReport> {
    let case_dirs = discover_case_dirs(&args.cases_dir)?;
    if case_dirs.is_empty() {
        bail!("no eval cases found in `{}`", args.cases_dir.display());
    }

    let min_sev: Severity = args.min_severity.into();
    let config = ReviewConfig {
        language: args.language.clone(),
        min_severity: min_sev,
        max_comments: 8,
        max_files: 40,
        ignore_paths: Vec::new(),
    };

    let (llm_client, model_label) = if args.offline {
        (None, "offline-recorded".to_string())
    } else {
        let model = args
            .model
            .clone()
            .context("--model (or GUARDIAN_LLM_MODEL) is required unless --offline is set")?;
        let api_key = std::env::var(&args.api_key_env)
            .ok()
            .filter(|s| !s.trim().is_empty());
        let client = OpenAiCompatibleClient::new(OpenAiCompatibleConfig {
            base_url: args.base_url.clone(),
            model: model.clone(),
            api_key,
            allow_insecure_http: args.allow_insecure_http,
            timeout_secs: args.timeout_secs,
        })?;
        (Some(client), model)
    };

    let runs = args.runs.max(1);
    let mut total_expected = 0usize;
    let mut total_matched_expected = 0usize;
    let mut total_true_positives = 0usize;
    let mut total_published_on_bug_cases = 0usize;
    let mut total_clean_or_adv = 0usize;
    let mut clean_or_adv_silent = 0usize;
    let mut comment_counts: Vec<usize> = Vec::new();
    let mut latencies_ms: Vec<u64> = Vec::new();
    let mut last_pass_cases: Vec<CaseSummary> = Vec::new();

    println!(
        "Guardian Eval (mode={}, model={}, runs={}, cases={})",
        if args.offline { "offline" } else { "live" },
        model_label,
        runs,
        case_dirs.len()
    );
    println!("{:-<78}", "");

    for pass_idx in 0..runs {
        last_pass_cases.clear();
        for dir in &case_dirs {
            let spec_raw = fs::read_to_string(dir.join("case.json"))
                .with_context(|| format!("missing case.json in {}", dir.display()))?;
            let spec: EvalCaseSpec = serde_json::from_str(&spec_raw)
                .with_context(|| format!("invalid case.json in {}", dir.display()))?;
            let raw_diff = fs::read_to_string(dir.join("change.diff"))
                .with_context(|| format!("missing change.diff in {}", dir.display()))?;

            let started = Instant::now();
            let meta = PrMetadata {
                title: spec.pr_title.clone(),
                description: spec.pr_description.clone(),
            };

            let prepared = prepare_review(&raw_diff, &meta, &config);
            let published: Vec<ValidatedFinding> = match prepared {
                PreparedDiff::Skip { .. } => Vec::new(),
                PreparedDiff::Ready {
                    parsed_diff,
                    prompt,
                } => {
                    let llm_output = if let Some(client) = &llm_client {
                        let stats = client.review(&prompt.system, &prompt.user).await?;
                        if args.record_fixtures && pass_idx == 0 {
                            let pretty = serde_json::to_string_pretty(&stats.output)?;
                            fs::write(dir.join("recorded_llm.json"), pretty)?;
                        }
                        stats.output
                    } else {
                        let rec_path = dir.join("recorded_llm.json");
                        let rec_raw = fs::read_to_string(&rec_path).with_context(|| {
                            format!("missing `{}` for --offline eval", rec_path.display())
                        })?;
                        serde_json::from_str::<LlmReviewOutput>(&rec_raw)?
                    };

                    let (filtered, _) = finalize_review(
                        llm_output,
                        &parsed_diff,
                        &config,
                        &HashSet::new(),
                        &model_label,
                    );
                    let mut all = filtered.inline_findings;
                    all.extend(filtered.summary_fallback_findings);
                    all
                }
            };

            let elapsed_ms = started.elapsed().as_millis() as u64;
            latencies_ms.push(elapsed_ms);
            comment_counts.push(published.len());

            let (matched_exp, tp_published, passed) = score_case(&spec, &published);
            match spec.kind {
                CaseKind::Bug => {
                    total_expected += spec.expected_findings.len();
                    total_matched_expected += matched_exp;
                    total_true_positives += tp_published;
                    total_published_on_bug_cases += published.len();
                }
                CaseKind::Clean | CaseKind::Adversarial => {
                    total_clean_or_adv += 1;
                    if published.is_empty() {
                        clean_or_adv_silent += 1;
                    }
                }
            }

            if pass_idx + 1 == runs {
                let badge = if passed { "PASS" } else { "FAIL" };
                println!(
                    "[{badge}] {:<28} | kind={:<11} | expected={}/{} | published={} | {}ms",
                    spec.id,
                    format!("{:?}", spec.kind).to_lowercase(),
                    matched_exp,
                    spec.expected_findings.len(),
                    published.len(),
                    elapsed_ms
                );
            }

            last_pass_cases.push(CaseSummary {
                id: spec.id,
                kind: spec.kind,
                expected_count: spec.expected_findings.len(),
                matched_expected: matched_exp,
                published_count: published.len(),
                passed,
                latency_ms: elapsed_ms,
            });
        }
    }

    let recall_pct = if total_expected == 0 {
        100.0
    } else {
        (total_matched_expected as f64 / total_expected as f64) * 100.0
    };
    let precision_pct = if total_published_on_bug_cases == 0 {
        100.0
    } else {
        (total_true_positives as f64 / total_published_on_bug_cases as f64) * 100.0
    };
    let clean_silence_pct = if total_clean_or_adv == 0 {
        100.0
    } else {
        (clean_or_adv_silent as f64 / total_clean_or_adv as f64) * 100.0
    };

    comment_counts.sort_unstable();
    let median_comments = if comment_counts.is_empty() {
        0.0
    } else {
        comment_counts[comment_counts.len() / 2] as f64
    };
    let mean_latency_ms = if latencies_ms.is_empty() {
        0
    } else {
        latencies_ms.iter().sum::<u64>() / latencies_ms.len() as u64
    };

    println!("{:-<78}", "");
    println!(
        "Metrics: Recall={recall_pct:.1}% | Precision={precision_pct:.1}% | CleanSilence={clean_silence_pct:.1}% | MedianComments={median_comments:.1} | MeanLatency={mean_latency_ms}ms"
    );

    let report = EvalReport {
        guardian_version: guardian_core::VERSION.to_string(),
        prompt_version: PROMPT_VERSION.to_string(),
        model: model_label,
        offline: args.offline,
        runs,
        recall_pct,
        precision_pct,
        clean_silence_pct,
        median_comments_per_pr: median_comments,
        mean_latency_ms,
        cases: last_pass_cases,
    };

    if let Some(out_path) = &args.output_report {
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out_path, serde_json::to_string_pretty(&report)?)?;
    }

    Ok(report)
}

fn discover_case_dirs(root: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs: Vec<PathBuf> = fs::read_dir(root)
        .with_context(|| format!("failed reading eval cases directory `{}`", root.display()))?
        .filter_map(|e| e.ok().map(|ent| ent.path()))
        .filter(|p| p.is_dir() && p.join("case.json").is_file())
        .collect();
    dirs.sort();
    Ok(dirs)
}

fn score_case(spec: &EvalCaseSpec, published: &[ValidatedFinding]) -> (usize, usize, bool) {
    match spec.kind {
        CaseKind::Clean | CaseKind::Adversarial => (0, 0, published.is_empty()),
        CaseKind::Bug => {
            let mut matched_expected = 0usize;
            for exp in &spec.expected_findings {
                let hit = published.iter().any(|f| finding_matches_expected(f, exp));
                if hit {
                    matched_expected += 1;
                }
            }
            let tp_published = published
                .iter()
                .filter(|f| {
                    spec.expected_findings
                        .iter()
                        .any(|exp| finding_matches_expected(f, exp))
                })
                .count();
            let passed = matched_expected == spec.expected_findings.len() && !published.is_empty();
            (matched_expected, tp_published, passed)
        }
    }
}

fn finding_matches_expected(finding: &ValidatedFinding, exp: &ExpectedFinding) -> bool {
    if finding.path != exp.path {
        return false;
    }
    let tol_start = exp.line_start.saturating_sub(2);
    let tol_end = exp.line_end.saturating_add(2);
    let mut all_lines = vec![finding.line];
    all_lines.extend_from_slice(&finding.also_at_lines);
    all_lines
        .into_iter()
        .any(|ln| ln >= tol_start && ln <= tol_end)
}
