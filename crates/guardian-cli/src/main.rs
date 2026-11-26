pub mod eval;
pub mod github;
pub mod llm;

use std::collections::HashSet;
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use github::{GitHubClient, PrRef, PublishOutcome};
use guardian_core::types::{LlmReviewOutput, PrMetadata, ReviewConfig, ReviewStatus, Severity};
use guardian_core::{finalize_review, prepare_review, PreparedDiff};
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

        /// Language for review comments (e.g. `en`, `es`)
        #[arg(long, env = "GUARDIAN_LANGUAGE", default_value = "en")]
        language: String,

        /// Minimum severity to report
        #[arg(long, value_enum, default_value_t = CliSeverity::Medium)]
        min_severity: CliSeverity,

        /// Maximum comments published per PR
        #[arg(long, default_value_t = 8)]
        max_comments: usize,

        /// Maximum files analyzed per execution
        #[arg(long, default_value_t = 40)]
        max_files: usize,

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

    /// Run benchmark evaluation suite (`evals/cases`) in live LLM or offline replay mode
    Eval(eval::EvalArgs),

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
        Commands::Eval(args) => {
            eval::run_eval(args).await?;
            Ok(())
        }
        cmd @ Commands::Review { .. } => {
            let fail_on_error = matches!(
                &cmd,
                Commands::Review {
                    fail_on_error: true,
                    ..
                }
            );
            if let Err(err) = run_review(cmd).await {
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

async fn run_review(cmd: Commands) -> Result<()> {
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
        timeout_secs,
        record,
        replay,
        dry_run,
        github_api_url,
        ..
    } = cmd
    else {
        unreachable!()
    };

    let started = Instant::now();
    let config = ReviewConfig {
        language,
        min_severity: min_severity.into(),
        max_comments,
        max_files,
        ignore_paths: Vec::new(),
    };

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
    let (raw_diff, metadata, existing_fps, gh_ctx) = if let Some(path) = diff_file {
        let content = fs::read_to_string(&path)
            .with_context(|| format!("failed reading diff file `{}`", path.display()))?;
        (content, PrMetadata::default(), HashSet::new(), None)
    } else {
        let pr_spec = match pr {
            Some(s) => s,
            None => detect_pr_from_github_env()?,
        };
        let pr_ref = PrRef::parse(&pr_spec)?;
        let gh_token = std::env::var("GITHUB_TOKEN")
            .context("ERR_MISSING_GITHUB_TOKEN: set GITHUB_TOKEN for PR review")?;
        let gh = GitHubClient::new(github_api_url, gh_token)?;
        let pr_info = gh.fetch_pr(&pr_ref).await?;

        if let Some(skip_reason) = pr_info.skip_reason(true, true) {
            println!("Guardian skipped PR: {skip_reason}");
            append_step_summary(&format!(
                "### Guardian Operator Summary\n- **Status:** Skipped (`{skip_reason}`)\n"
            ));
            return Ok(());
        }

        let diff_text = gh.fetch_pr_diff(&pr_ref).await?;
        let existing_fps = gh.fetch_existing_fingerprints(&pr_ref).await?;
        let head_sha = pr_info.head.sha.clone();
        (
            diff_text,
            pr_info.to_metadata(),
            existing_fps,
            Some((gh, pr_ref, head_sha)),
        )
    };

    let prepared = prepare_review(&raw_diff, &metadata, &config);
    let (parsed_diff, prompt) = match prepared {
        PreparedDiff::Skip {
            status: ReviewStatus::Skipped { reason },
            parsed_diff,
        } => {
            println!(
                "Guardian skipped review: {reason} (skipped_files={})",
                parsed_diff.skipped_files.len()
            );
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
        } => (parsed_diff, prompt),
    };

    let (llm_output, usage) = if let Some(replay_dir) = &replay {
        let replay_file = replay_dir.join("llm_response.json");
        let raw = fs::read_to_string(&replay_file)
            .with_context(|| format!("failed reading replay file `{}`", replay_file.display()))?;
        let out: LlmReviewOutput =
            serde_json::from_str(&raw).context("invalid JSON in replay file")?;
        (out, TokenUsage::default())
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
        (stats.output, stats.usage)
    };

    let (filtered, summary_md) = finalize_review(
        llm_output,
        &parsed_diff,
        &config,
        &existing_fps,
        &model_label,
    );
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
    } else if let Some((gh, pr_ref, head_sha)) = gh_ctx {
        let outcome = gh
            .publish_review(
                &pr_ref,
                &head_sha,
                &filtered.status,
                parsed_diff.files.len(),
                &filtered.inline_findings,
                &filtered.summary_fallback_findings,
                filtered.trace.dropped_duplicate_existing,
                &model_label,
                &config.language,
            )
            .await?;
        match outcome {
            PublishOutcome::Published {
                inline_posted,
                fallback_posted,
            } => {
                println!(
                    "Guardian published review on {}#{}: {} inline, {} fallback ({} deduplicated)",
                    pr_ref.repo,
                    pr_ref.number,
                    inline_posted,
                    fallback_posted,
                    filtered.trace.dropped_duplicate_existing
                );
            }
            PublishOutcome::AbortedStaleState { reason } => {
                println!("Guardian aborted publishing stale review: {reason}");
            }
        }
    }

    append_step_summary(&format!(
        "### Guardian Operator Summary\n\
         - **Model:** `{model_label}`\n\
         - **Files reviewed:** {} (skipped: {})\n\
         - **Funnel:** `{}`\n\
         - **Tokens:** {} in / {} out\n\
         - **Duration:** {:.2}s\n",
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
