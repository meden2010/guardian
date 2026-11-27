pub mod eval;
pub mod github;
pub mod llm;
pub mod serve;

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use github::{GitHubClient, PrRef, PublishOutcome, PublishReviewParams};
use guardian_core::ast_context::SupportedLanguage;
use guardian_core::config::{apply_repo_config, parse_repo_config};
use guardian_core::diff::parse_unified_diff;
use guardian_core::filter::{format_enriched_pr_summary, SummaryReport};
use guardian_core::types::{LlmReviewOutput, PrMetadata, ReviewConfig, ReviewStatus, Severity};
use guardian_core::{finalize_review, prepare_review_with_context, PreparedDiff};
use llm::{OpenAiCompatibleClient, OpenAiCompatibleConfig, TokenUsage};

#[derive(Debug, Parser)]
#[command(
    name = "guardian",
    version,
    about = "Low-noise, zero-infra PR code reviewer in Rust"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CliSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl From<CliSeverity> for Severity {
    fn from(val: CliSeverity) -> Self {
        match val {
            CliSeverity::Low => Self::Low,
            CliSeverity::Medium => Self::Medium,
            CliSeverity::High => Self::High,
            CliSeverity::Critical => Self::Critical,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Review a GitHub Pull Request or a local unified diff file
    Review {
        /// Local unified diff path (for offline / dry-run testing)
        #[arg(long)]
        diff_file: Option<PathBuf>,

        /// GitHub PR (`owner/repo#123` or URL). Auto-detected in GitHub Actions if omitted.
        #[arg(long, env = "GUARDIAN_PR")]
        pr: Option<String>,

        /// OpenAI-compatible base URL (e.g. `https://api.openai.com/v1` or `http://100.82.189.71:11434/v1`)
        #[arg(
            long,
            env = "GUARDIAN_LLM_BASE_URL",
            default_value = "https://api.openai.com/v1"
        )]
        base_url: String,

        /// Model identifier (required unless `--replay` is used)
        #[arg(long, env = "GUARDIAN_LLM_MODEL")]
        model: Option<String>,

        /// Name of environment variable containing the LLM API key (optional for local servers)
        #[arg(long, default_value = "GUARDIAN_LLM_API_KEY")]
        api_key_env: String,

        /// Allow plain `http://` for trusted LAN / Tailscale inference servers
        #[arg(long, env = "GUARDIAN_ALLOW_INSECURE_HTTP")]
        allow_insecure_http: bool,

        /// Language for review comments (e.g. `en`, `es`). Overrides `.guardian.yml`.
        #[arg(long, env = "GUARDIAN_LANGUAGE")]
        language: Option<String>,

        /// Minimum severity to report. Overrides `.guardian.yml`.
        #[arg(long, env = "GUARDIAN_MIN_SEVERITY", value_enum)]
        min_severity: Option<CliSeverity>,

        /// Maximum comments published per PR. Overrides `.guardian.yml`.
        #[arg(long, env = "GUARDIAN_MAX_COMMENTS")]
        max_comments: Option<usize>,

        /// Maximum files analyzed per execution. Overrides `.guardian.yml`.
        #[arg(long, env = "GUARDIAN_MAX_FILES")]
        max_files: Option<usize>,

        /// Disable GitHub native ```suggestion blocks (always render `<details>` instead)
        #[arg(long, env = "GUARDIAN_NO_SUGGESTIONS")]
        no_suggestions: bool,

        /// Local `.guardian.yml` path (only used in `--diff-file` mode; PR mode always reads `base_sha`)
        #[arg(long)]
        config: Option<PathBuf>,

        /// HTTP request timeout in seconds for LLM calls
        #[arg(long, env = "GUARDIAN_TIMEOUT_SECS", default_value_t = 240)]
        timeout_secs: u64,

        /// Record raw redacted LLM response JSON into `<DIR>/llm_response.json`
        #[arg(long)]
        record: Option<PathBuf>,

        /// Replay raw LLM response JSON from `<DIR>/llm_response.json` without calling the LLM
        #[arg(long)]
        replay: Option<PathBuf>,

        /// Run the full pipeline without posting comments to GitHub
        #[arg(long, env = "GUARDIAN_DRY_RUN")]
        dry_run: bool,

        /// Exit with non-zero code on operational errors (default false = fail-open)
        #[arg(long, env = "GUARDIAN_FAIL_ON_ERROR")]
        fail_on_error: bool,

        /// Override GitHub REST API base URL (used for GitHub Enterprise or testing)
        #[arg(long, env = "GITHUB_API_URL", default_value = "https://api.github.com")]
        github_api_url: String,
    },

    /// Validate a `.guardian.yml` repository configuration file
    Validate {
        /// Path to the `.guardian.yml` file to validate
        #[arg(default_value = ".guardian.yml")]
        path: PathBuf,
    },

    /// Run benchmark evaluation suite (`evals/cases`) in live LLM or offline replay mode
    Eval(eval::EvalArgs),

    /// Run a self-hosted GitHub App webhook server listening for PR events
    Serve(serve::ServeArgs),

    /// Validate environment, URL safety, and LLM / GitHub connectivity
    Doctor {
        #[arg(
            long,
            env = "GUARDIAN_LLM_BASE_URL",
            default_value = "https://api.openai.com/v1"
        )]
        base_url: String,

        #[arg(long, env = "GUARDIAN_LLM_MODEL")]
        model: Option<String>,

        #[arg(long, default_value = "GUARDIAN_LLM_API_KEY")]
        api_key_env: String,

        #[arg(long, env = "GUARDIAN_ALLOW_INSECURE_HTTP")]
        allow_insecure_http: bool,

        /// Actively ping `/models` on the configured LLM endpoint
        #[arg(long)]
        check_network: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Doctor {
            base_url,
            model,
            api_key_env,
            allow_insecure_http,
            check_network,
        } => {
            run_doctor(
                &base_url,
                model.as_deref(),
                &api_key_env,
                allow_insecure_http,
                check_network,
            )
            .await
        }
        Commands::Validate { path } => run_validate(&path),
        Commands::Eval(args) => {
            eval::run_eval(args).await?;
            Ok(())
        }
        Commands::Serve(args) => serve::run_serve(args).await,
        cmd @ Commands::Review { .. } => {
            let mut fail_on_error = matches!(
                &cmd,
                Commands::Review {
                    fail_on_error: true,
                    ..
                }
            );
            if let Err(err) = run_review(cmd, &mut fail_on_error).await {
                let safe_err = guardian_core::redact::redact_secrets(&format!("{err:#}"));
                eprintln!("::warning::Guardian review did not complete: {safe_err}");
                append_step_summary(&format!(
                    "### Guardian Operator Summary\n- **Status:** Error (`{safe_err}`)\n"
                ));
                if fail_on_error {
                    std::process::exit(1);
                }
            }
            Ok(())
        }
    }
}

async fn run_doctor(
    base_url: &str,
    model: Option<&str>,
    api_key_env: &str,
    allow_insecure_http: bool,
    check_network: bool,
) -> Result<()> {
    let validated_url = llm::validate_base_url(base_url, allow_insecure_http)?;
    let has_llm_key = std::env::var(api_key_env)
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);
    let has_gh_token = std::env::var("GITHUB_TOKEN")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false);

    println!("Guardian v{} doctor", guardian_core::VERSION);
    println!("  base_url       : {validated_url} (OK)");
    println!(
        "  model          : {}",
        model.unwrap_or("<not set: pass --model or GUARDIAN_LLM_MODEL>")
    );
    println!(
        "  {api_key_env:<14} : {}",
        if has_llm_key {
            "present (masked)"
        } else {
            "not set (OK for unauthenticated local models)"
        }
    );
    println!(
        "  GITHUB_TOKEN   : {}",
        if has_gh_token {
            "present (masked)"
        } else {
            "not set (required for --pr mode)"
        }
    );

    if check_network {
        let client = OpenAiCompatibleClient::new(OpenAiCompatibleConfig {
            base_url: validated_url,
            model: model.unwrap_or("doctor-probe").to_string(),
            api_key: std::env::var(api_key_env).ok().filter(|s| !s.is_empty()),
            allow_insecure_http,
            timeout_secs: 15,
        })?;
        client.check_models_endpoint().await?;
        println!("  LLM /models    : reachable (OK)");
    }

    Ok(())
}

fn run_validate(path: &Path) -> Result<()> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed reading config file `{}`", path.display()))?;
    let parsed = parse_repo_config(&raw)?;
    for warning in &parsed.warnings {
        eprintln!("Warning: {warning}");
    }
    let effective = apply_repo_config(&ReviewConfig::default(), &parsed.file);

    println!(
        "Guardian v{} — `{}` is valid",
        guardian_core::VERSION,
        path.display()
    );
    println!("  language       : {}", effective.language);
    println!("  min_severity   : {}", effective.min_severity.as_str());
    println!("  max_comments   : {}", effective.max_comments);
    println!("  max_files      : {}", effective.max_files);
    println!("  suggestions    : {}", effective.suggestions_enabled);
    println!("  skip_drafts    : {}", effective.skip_drafts);
    println!("  skip_bots      : {}", effective.skip_bots);
    println!("  fail_on_error  : {}", effective.fail_on_error);
    println!(
        "  ignore_paths   : {} pattern(s)",
        effective.ignore_paths.len()
    );
    println!("  team rules     : {} rule(s)", effective.rules.len());
    if !parsed.warnings.is_empty() {
        println!("  warnings       : {}", parsed.warnings.len());
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct CliConfigOverrides {
    pub language: Option<String>,
    pub min_severity: Option<CliSeverity>,
    pub max_comments: Option<usize>,
    pub max_files: Option<usize>,
    pub no_suggestions: bool,
    pub fail_on_error: bool,
}

pub struct ReviewExecutionParams {
    pub diff_file: Option<PathBuf>,
    pub pr: Option<String>,
    pub base_url: String,
    pub model: Option<String>,
    pub api_key_env: String,
    pub allow_insecure_http: bool,
    pub overrides: CliConfigOverrides,
    pub local_config_path: Option<PathBuf>,
    pub timeout_secs: u64,
    pub record: Option<PathBuf>,
    pub replay: Option<PathBuf>,
    pub dry_run: bool,
    pub github_api_url: String,
    pub github_token_override: Option<String>,
}

fn resolve_effective_config(
    repo_yaml: Option<&str>,
    overrides: &CliConfigOverrides,
) -> Result<ReviewConfig> {
    let mut cfg = ReviewConfig::default();
    if let Some(raw) = repo_yaml {
        let parsed = parse_repo_config(raw)?;
        for warning in &parsed.warnings {
            eprintln!("::warning::{warning}");
        }
        cfg = apply_repo_config(&cfg, &parsed.file);
    }

    if let Some(lang) = &overrides.language {
        if !lang.trim().is_empty() {
            cfg.language = lang.trim().to_string();
        }
    }
    if let Some(sev) = overrides.min_severity {
        cfg.min_severity = sev.into();
    }
    if let Some(max_c) = overrides.max_comments {
        cfg.max_comments = max_c;
    }
    if let Some(max_f) = overrides.max_files {
        cfg.max_files = max_f;
    }
    if overrides.no_suggestions {
        cfg.suggestions_enabled = false;
    }
    if overrides.fail_on_error {
        cfg.fail_on_error = true;
    }
    Ok(cfg)
}

async fn run_review(cmd: Commands, effective_fail_on_error: &mut bool) -> Result<()> {
    let Commands::Review {
        diff_file,
        pr,
        base_url,
        model,
        api_key_env,
        allow_insecure_http,
        language,
        min_severity,
        max_comments,
        max_files,
        no_suggestions,
        config: local_config_path,
        timeout_secs,
        record,
        replay,
        dry_run,
        fail_on_error,
        github_api_url,
    } = cmd
    else {
        unreachable!()
    };

    execute_review_with_token(
        ReviewExecutionParams {
            diff_file,
            pr,
            base_url,
            model,
            api_key_env,
            allow_insecure_http,
            overrides: CliConfigOverrides {
                language,
                min_severity,
                max_comments,
                max_files,
                no_suggestions,
                fail_on_error,
            },
            local_config_path,
            timeout_secs,
            record,
            replay,
            dry_run,
            github_api_url,
            github_token_override: None,
        },
        effective_fail_on_error,
    )
    .await
}

pub async fn execute_review_with_token(
    params: ReviewExecutionParams,
    effective_fail_on_error: &mut bool,
) -> Result<()> {
    let ReviewExecutionParams {
        diff_file,
        pr,
        base_url,
        model,
        api_key_env,
        allow_insecure_http,
        overrides,
        local_config_path,
        timeout_secs,
        record,
        replay,
        dry_run,
        github_api_url,
        github_token_override,
    } = params;

    let started = Instant::now();

    let model_label = match (&model, &replay) {
        (Some(m), _) => m.clone(),
        (None, Some(_)) => "replay".to_string(),
        (None, None) => {
            anyhow::bail!(
                "ERR_MISSING_MODEL: pass --model (or GUARDIAN_LLM_MODEL) unless --replay is set"
            )
        }
    };

    // Resolve input source: `--diff-file` (local) vs `--pr` / GitHub Actions event.
    let (
        raw_diff,
        metadata,
        config,
        config_source,
        existing_fps,
        resolved_threads,
        file_sources,
        gh_ctx,
    ) = if let Some(path) = diff_file {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed reading diff file `{}`", path.display()))?;
        let (repo_yaml, src_label) = if let Some(cfg_path) = &local_config_path {
            let raw = fs::read_to_string(cfg_path)
                .with_context(|| format!("failed reading config file `{}`", cfg_path.display()))?;
            (Some(raw), cfg_path.display().to_string())
        } else {
            (None, "defaults".to_string())
        };
        let config = resolve_effective_config(repo_yaml.as_deref(), &overrides)?;
        *effective_fail_on_error = config.fail_on_error;
        (
            content,
            PrMetadata::default(),
            config,
            src_label,
            HashSet::new(),
            0usize,
            HashMap::new(),
            None,
        )
    } else {
        let pr_spec = match pr {
            Some(s) => s,
            None => detect_pr_from_github_env()?,
        };
        let pr_ref = PrRef::parse(&pr_spec)?;
        let gh_token = match github_token_override {
            Some(tok) if !tok.trim().is_empty() => tok,
            _ => std::env::var("GITHUB_TOKEN")
                .context("ERR_MISSING_GITHUB_TOKEN: set GITHUB_TOKEN for PR review")?,
        };
        let gh = GitHubClient::new(github_api_url, gh_token)?;
        let pr_info = gh.fetch_pr(&pr_ref).await?;

        // Security invariant: ALWAYS read `.guardian.yml` from `base.sha`, NEVER from PR `head.sha`.
        let repo_yaml = gh
            .fetch_file_at_ref(&pr_ref, ".guardian.yml", &pr_info.base.sha)
            .await?;
        let config_source = if repo_yaml.is_some() {
            format!(
                ".guardian.yml@{}",
                &pr_info.base.sha[..pr_info.base.sha.len().min(7)]
            )
        } else {
            "defaults".to_string()
        };
        let config = resolve_effective_config(repo_yaml.as_deref(), &overrides)?;
        *effective_fail_on_error = config.fail_on_error;

        if let Some(skip_reason) = pr_info.skip_reason(config.skip_drafts, config.skip_bots) {
            println!("Guardian skipped PR: {skip_reason}");
            append_step_summary(&format!(
                "### Guardian Operator Summary\n- **Status:** Skipped (`{skip_reason}`)\n"
            ));
            return Ok(());
        }

        let head_sha = pr_info.head.sha.clone();
        let check_run_id = if !dry_run {
            let custom_svg = std::env::var("GUARDIAN_PROCESSING_SVG_URL")
                .ok()
                .filter(|s| !s.trim().is_empty());
            let cid = gh
                .start_check_run(&pr_ref, &head_sha, &config.language)
                .await;
            if let Err(e) = gh
                .publish_processing_state(&pr_ref, &config.language, custom_svg.as_deref())
                .await
            {
                tracing::warn!(error = %e, "Could not post initial processing banner");
            }
            cid
        } else {
            None
        };

        let diff_text = gh.fetch_pr_diff(&pr_ref).await?;
        let existing = gh.fetch_existing_fingerprints(&pr_ref).await?;

        // Passively fetch full sources for AST-supported files via GitHub API (no checkout).
        let preview_parsed = parse_unified_diff(&diff_text, &config);
        let mut sources: HashMap<String, String> = HashMap::new();
        for file in preview_parsed.files.iter().take(20) {
            if SupportedLanguage::from_path(&file.path).is_some() {
                if let Ok(Some(src)) = gh.fetch_file_at_ref(&pr_ref, &file.path, &head_sha).await {
                    sources.insert(file.path.clone(), src);
                }
            }
        }

        (
            diff_text,
            pr_info.to_metadata(),
            config,
            config_source,
            existing.fingerprints,
            existing.resolved_threads,
            sources,
            Some((gh, pr_ref, head_sha, check_run_id)),
        )
    };

    let prepared = prepare_review_with_context(&raw_diff, &metadata, &config, &file_sources);
    let (parsed_diff, prompt, ast_context_files) = match prepared {
        PreparedDiff::Skip {
            status: ReviewStatus::Skipped { reason },
            parsed_diff,
        } => {
            println!(
                "Guardian skipped review: {reason} (skipped_files={})",
                parsed_diff.skipped_files.len()
            );
            if !dry_run {
                if let Some((gh, pr_ref, head_sha, check_run_id)) = &gh_ctx {
                    let skip_status = ReviewStatus::Skipped {
                        reason: reason.clone(),
                    };
                    let _ = gh
                        .publish_review(
                            pr_ref,
                            &PublishReviewParams {
                                expected_head_sha: head_sha,
                                status: &skip_status,
                                reviewed_files: &[],
                                skipped_files: &parsed_diff.skipped_files,
                                inline_findings: &[],
                                fallback_findings: &[],
                                deduplicated_count: 0,
                                resolved_threads_count: resolved_threads,
                                model_name: &model_label,
                                language: &config.language,
                                suggestions_enabled: config.suggestions_enabled,
                            },
                        )
                        .await;
                    if let Some(cid) = check_run_id {
                        gh.complete_check_run(pr_ref, *cid, "neutral", "Skipped", &reason)
                            .await;
                    }
                }
            }
            append_step_summary(&format!(
                "### Guardian Operator Summary\n- **Status:** Skipped (`{reason}`)\n- **Skipped files:** {}\n",
                parsed_diff.skipped_files.len()
            ));
            return Ok(());
        }
        PreparedDiff::Skip { .. } => return Ok(()),
        PreparedDiff::Ready {
            parsed_diff,
            prompt,
            ast_context_files,
        } => (parsed_diff, prompt, ast_context_files),
    };

    let llm_result: Result<(LlmReviewOutput, TokenUsage)> = async {
        if let Some(replay_dir) = &replay {
            let replay_file = replay_dir.join("llm_response.json");
            let raw = fs::read_to_string(&replay_file).with_context(|| {
                format!("failed reading replay file `{}`", replay_file.display())
            })?;
            let out: LlmReviewOutput =
                serde_json::from_str(&raw).context("invalid JSON in replay file")?;
            Ok((out, TokenUsage::default()))
        } else {
            let api_key = std::env::var(&api_key_env)
                .ok()
                .filter(|s| !s.trim().is_empty());
            let llm_client = OpenAiCompatibleClient::new(OpenAiCompatibleConfig {
                base_url,
                model: model_label.clone(),
                api_key,
                allow_insecure_http,
                timeout_secs,
            })?;
            let stats = llm_client.review(&prompt.system, &prompt.user).await?;
            if let Some(rec_dir) = &record {
                fs::create_dir_all(rec_dir)?;
                let pretty = serde_json::to_string_pretty(&stats.output)?;
                fs::write(rec_dir.join("llm_response.json"), pretty)?;
            }
            Ok((stats.output, stats.usage))
        }
    }
    .await;

    let (llm_output, usage) = match llm_result {
        Ok(pair) => pair,
        Err(err) => {
            if !dry_run {
                if let Some((gh, pr_ref, _, check_run_id)) = &gh_ctx {
                    let safe_reason = guardian_core::redact::redact_secrets(&format!("{err:#}"));
                    gh.publish_error_summary(pr_ref, &safe_reason, &model_label, &config.language)
                        .await;
                    if let Some(cid) = check_run_id {
                        gh.complete_check_run(
                            pr_ref,
                            *cid,
                            "neutral",
                            "Review could not complete",
                            &safe_reason,
                        )
                        .await;
                    }
                }
            }
            return Err(err);
        }
    };

    let (filtered, _default_summary_md) = finalize_review(
        llm_output,
        &parsed_diff,
        &config,
        &existing_fps,
        &model_label,
    );
    let reviewed_paths: Vec<String> = parsed_diff.files.iter().map(|f| f.path.clone()).collect();
    let summary_md = format_enriched_pr_summary(&SummaryReport {
        status: &filtered.status,
        reviewed_files: &reviewed_paths,
        skipped_files: &parsed_diff.skipped_files,
        inline_findings: &filtered.inline_findings,
        fallback_findings: &filtered.summary_fallback_findings,
        deduplicated_count: filtered.trace.dropped_duplicate_existing,
        resolved_threads_count: resolved_threads,
        model_name: &model_label,
        language: &config.language,
    });
    let elapsed = started.elapsed();

    if dry_run || gh_ctx.is_none() {
        println!("{summary_md}");
        println!("Funnel: {}", filtered.trace.format_funnel());
        for f in &filtered.inline_findings {
            println!(
                "\n--- INLINE {}:{} [{} | {}] (fp={}) ---\n{}\nScenario: {}",
                f.path,
                f.line,
                f.severity.as_str(),
                f.category.as_str(),
                &f.fingerprint[..15],
                f.message,
                f.scenario
            );
        }
    } else if let Some((gh, pr_ref, head_sha, check_run_id)) = gh_ctx {
        let outcome = gh
            .publish_review(
                &pr_ref,
                &PublishReviewParams {
                    expected_head_sha: &head_sha,
                    status: &filtered.status,
                    reviewed_files: &reviewed_paths,
                    skipped_files: &parsed_diff.skipped_files,
                    inline_findings: &filtered.inline_findings,
                    fallback_findings: &filtered.summary_fallback_findings,
                    deduplicated_count: filtered.trace.dropped_duplicate_existing,
                    resolved_threads_count: resolved_threads,
                    model_name: &model_label,
                    language: &config.language,
                    suggestions_enabled: config.suggestions_enabled,
                },
            )
            .await?;
        match outcome {
            PublishOutcome::Published {
                inline_posted,
                fallback_posted,
            } => {
                let total_posted = inline_posted + fallback_posted;
                if let Some(cid) = check_run_id {
                    let (conclusion, title) = if total_posted == 0 {
                        ("success", "No new high-confidence findings")
                    } else {
                        ("neutral", "High-confidence findings reported")
                    };
                    gh.complete_check_run(&pr_ref, cid, conclusion, title, &summary_md)
                        .await;
                }
                println!(
                    "Guardian published review on {}#{}: {} inline, {} fallback ({} deduplicated, {} resolved threads respected)",
                    pr_ref.repo,
                    pr_ref.number,
                    inline_posted,
                    fallback_posted,
                    filtered.trace.dropped_duplicate_existing,
                    resolved_threads
                );
            }
            PublishOutcome::AbortedStaleState { reason } => {
                if let Some(cid) = check_run_id {
                    gh.complete_check_run(
                        &pr_ref,
                        cid,
                        "neutral",
                        "Superseded by newer commit",
                        &reason,
                    )
                    .await;
                }
                println!("Guardian aborted publishing stale review: {reason}");
            }
        }
    }

    append_step_summary(&format!(
        "### Guardian Operator Summary\n\
         - **Config:** `{config_source}` (rules: {}, suggestions: {})\n\
         - **Model:** `{model_label}`\n\
         - **Files reviewed:** {} (skipped: {}, AST context: {ast_context_files})\n\
         - **Resolved threads respected:** {resolved_threads}\n\
         - **Funnel:** `{}`\n\
         - **Tokens:** {} in / {} out\n\
         - **Duration:** {:.2}s\n",
        config.rules.len(),
        config.suggestions_enabled,
        parsed_diff.files.len(),
        parsed_diff.skipped_files.len(),
        filtered.trace.format_funnel(),
        usage.prompt_tokens,
        usage.completion_tokens,
        elapsed.as_secs_f64(),
    ));

    Ok(())
}

fn detect_pr_from_github_env() -> Result<String> {
    let repo = std::env::var("GITHUB_REPOSITORY")
        .context("neither --pr/--diff-file nor GITHUB_REPOSITORY was provided")?;
    let event_path = std::env::var("GITHUB_EVENT_PATH")
        .context("GITHUB_EVENT_PATH is not set; pass --pr owner/repo#number")?;
    let raw = fs::read_to_string(&event_path).context("failed reading GITHUB_EVENT_PATH")?;
    let json: serde_json::Value =
        serde_json::from_str(&raw).context("invalid JSON in GITHUB_EVENT_PATH")?;
    let number = json
        .get("pull_request")
        .and_then(|pr| pr.get("number"))
        .and_then(|n| n.as_u64())
        .or_else(|| json.get("number").and_then(|n| n.as_u64()))
        .ok_or_else(|| {
            anyhow::anyhow!("could not find pull_request.number in GITHUB_EVENT_PATH")
        })?;
    Ok(format!("{repo}#{number}"))
}

fn append_step_summary(markdown: &str) {
    if let Ok(path) = std::env::var("GITHUB_STEP_SUMMARY") {
        if !path.trim().is_empty() {
            let _ = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .and_then(|mut f| std::io::Write::write_all(&mut f, markdown.as_bytes()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_precedence_defaults_then_repo_then_cli() {
        let yaml = r#"
version: 1
language: es
review:
  min_severity: high
  max_comments: 5
  skip_drafts: false
limits:
  max_files: 20
behavior:
  suggestions: true
  fail_on_error: false
"#;
        let overrides = CliConfigOverrides {
            language: Some("en".to_string()),
            min_severity: None,
            max_comments: Some(3),
            max_files: None,
            no_suggestions: true,
            fail_on_error: true,
        };

        let effective = resolve_effective_config(Some(yaml), &overrides).expect("resolve");
        assert_eq!(effective.language, "en"); // CLI overrides .guardian.yml
        assert_eq!(effective.min_severity, Severity::High); // from .guardian.yml
        assert_eq!(effective.max_comments, 3); // CLI overrides .guardian.yml
        assert_eq!(effective.max_files, 20); // from .guardian.yml
        assert!(!effective.skip_drafts); // from .guardian.yml
        assert!(effective.skip_bots); // default
        assert!(!effective.suggestions_enabled); // CLI --no-suggestions wins
        assert!(effective.fail_on_error); // CLI --fail-on-error wins
    }
}
