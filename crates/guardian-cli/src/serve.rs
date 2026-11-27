//! Self-hosted GitHub App webhook server (`guardian serve`).
//! Listens for `pull_request` webhooks, verifies `X-Hub-Signature-256`, mints
//! short-lived GitHub App installation tokens, and dispatches PR reviews with
//! per-PR concurrency cancellation.

use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Args;
use hmac::{Hmac, Mac};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::Mutex;
use tokio::task::AbortHandle;

use crate::llm::validate_base_url;
use crate::{execute_review_with_token, CliConfigOverrides, CliSeverity, ReviewExecutionParams};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Socket address to bind the webhook HTTP server
    #[arg(long, env = "GUARDIAN_SERVE_BIND", default_value = "127.0.0.1:8787")]
    pub bind: SocketAddr,

    /// GitHub App webhook secret for verifying `X-Hub-Signature-256`
    #[arg(long, env = "GUARDIAN_WEBHOOK_SECRET")]
    pub webhook_secret: String,

    /// GitHub App ID (numeric)
    #[arg(long, env = "GUARDIAN_APP_ID")]
    pub app_id: u64,

    /// GitHub App PEM private key string (or use `--app-private-key-file`)
    #[arg(long, env = "GUARDIAN_APP_PRIVATE_KEY")]
    pub app_private_key: Option<String>,

    /// Path to GitHub App `.pem` private key file
    #[arg(long, env = "GUARDIAN_APP_PRIVATE_KEY_FILE")]
    pub app_private_key_file: Option<PathBuf>,

    /// OpenAI-compatible base URL (e.g. `http://127.0.0.1:11434/v1`)
    #[arg(
        long,
        env = "GUARDIAN_LLM_BASE_URL",
        default_value = "https://api.openai.com/v1"
    )]
    pub base_url: String,

    /// Model identifier used for reviews
    #[arg(long, env = "GUARDIAN_LLM_MODEL")]
    pub model: String,

    /// Name of environment variable containing the LLM API key (optional for local servers)
    #[arg(long, default_value = "GUARDIAN_LLM_API_KEY")]
    pub api_key_env: String,

    /// Allow plain `http://` for trusted LAN / Tailscale / localhost inference servers
    #[arg(long, env = "GUARDIAN_ALLOW_INSECURE_HTTP")]
    pub allow_insecure_http: bool,

    /// Default language override (falls back to `.guardian.yml`)
    #[arg(long, env = "GUARDIAN_LANGUAGE")]
    pub language: Option<String>,

    /// Default minimum severity override (falls back to `.guardian.yml`)
    #[arg(long, env = "GUARDIAN_MIN_SEVERITY", value_enum)]
    pub min_severity: Option<CliSeverity>,

    /// Default max comments override (falls back to `.guardian.yml`)
    #[arg(long, env = "GUARDIAN_MAX_COMMENTS")]
    pub max_comments: Option<usize>,

    /// Default max files override (falls back to `.guardian.yml`)
    #[arg(long, env = "GUARDIAN_MAX_FILES")]
    pub max_files: Option<usize>,

    /// Disable native GitHub ```suggestion blocks
    #[arg(long, env = "GUARDIAN_NO_SUGGESTIONS")]
    pub no_suggestions: bool,

    /// HTTP request timeout in seconds for LLM calls
    #[arg(long, env = "GUARDIAN_TIMEOUT_SECS", default_value_t = 240)]
    pub timeout_secs: u64,

    /// Override GitHub REST API base URL (used for GitHub Enterprise or testing)
    #[arg(long, env = "GITHUB_API_URL", default_value = "https://api.github.com")]
    pub github_api_url: String,
}

#[derive(Clone)]
struct ServerState {
    webhook_secret: Vec<u8>,
    app_id: u64,
    private_key_pem: String,
    http: Client,
    github_api_url: String,
    llm_base_url: String,
    model: String,
    api_key_env: String,
    allow_insecure_http: bool,
    timeout_secs: u64,
    overrides: CliConfigOverrides,
    in_flight: Arc<Mutex<HashMap<String, AbortHandle>>>,
}

#[derive(Debug, Serialize)]
struct AppJwtClaims {
    iat: u64,
    exp: u64,
    iss: String,
}

#[derive(Debug, Deserialize)]
struct InstallationTokenResponse {
    token: String,
}

#[derive(Debug, Deserialize)]
struct PullRequestWebhook {
    action: String,
    number: u64,
    repository: WebhookRepo,
    installation: Option<WebhookInstallation>,
}

#[derive(Debug, Deserialize)]
struct WebhookRepo {
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct WebhookInstallation {
    id: u64,
}

/// Verifies GitHub's `X-Hub-Signature-256` (`sha256=<hex>`) in constant time.
pub fn verify_github_signature(secret: &[u8], body: &[u8], signature_header: Option<&str>) -> bool {
    let Some(header) = signature_header else {
        return false;
    };
    let Some(hex_sig) = header.trim().strip_prefix("sha256=") else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(hex_sig) else {
        return false;
    };
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        return false;
    };
    mac.update(body);
    mac.verify_slice(&sig_bytes).is_ok()
}

/// Builds a short-lived RS256 GitHub App JWT valid for 9 minutes.
pub fn create_app_jwt(app_id: u64, private_key_pem: &str) -> Result<String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before UNIX_EPOCH")?
        .as_secs();
    let claims = AppJwtClaims {
        iat: now.saturating_sub(60),
        exp: now + 540,
        iss: app_id.to_string(),
    };
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
        .context("ERR_INVALID_APP_PRIVATE_KEY: failed parsing RSA PEM private key")?;
    encode(&Header::new(Algorithm::RS256), &claims, &key).context("failed signing GitHub App JWT")
}

async fn mint_installation_token(
    http: &Client,
    github_api_url: &str,
    app_id: u64,
    private_key_pem: &str,
    installation_id: u64,
) -> Result<String> {
    let jwt = create_app_jwt(app_id, private_key_pem)?;
    let url = format!(
        "{}/app/installations/{}/access_tokens",
        github_api_url.trim_end_matches('/'),
        installation_id
    );
    let resp = http
        .post(&url)
        .header(USER_AGENT, "guardian-pr-reviewer")
        .header(ACCEPT, "application/vnd.github+json")
        .header(AUTHORIZATION, format!("Bearer {jwt}"))
        .send()
        .await
        .context("ERR_GITHUB_APP_AUTH: failed requesting installation access token")?;

    if !resp.status().is_success() {
        bail!(
            "ERR_GITHUB_APP_AUTH: HTTP {} minting installation token for installation {}",
            resp.status(),
            installation_id
        );
    }
    let parsed: InstallationTokenResponse = resp
        .json()
        .await
        .context("failed parsing installation access token response")?;
    Ok(parsed.token)
}

fn load_private_key_pem(args: &ServeArgs) -> Result<String> {
    if let Some(inline) = &args.app_private_key {
        let trimmed = inline.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.replace("\\n", "\n"));
        }
    }
    if let Some(path) = &args.app_private_key_file {
        let pem = fs::read_to_string(path)
            .with_context(|| format!("failed reading PEM file `{}`", path.display()))?;
        return Ok(pem);
    }
    bail!("ERR_MISSING_APP_PRIVATE_KEY: set GUARDIAN_APP_PRIVATE_KEY or --app-private-key-file");
}

pub async fn run_serve(args: ServeArgs) -> Result<()> {
    if args.webhook_secret.trim().is_empty() {
        bail!("ERR_MISSING_WEBHOOK_SECRET: GUARDIAN_WEBHOOK_SECRET must not be empty");
    }
    let validated_llm_url = validate_base_url(&args.base_url, args.allow_insecure_http)?;
    let private_key_pem = load_private_key_pem(&args)?;
    // Validate PEM key upfront so startup fails fast if misconfigured.
    let _ = create_app_jwt(args.app_id, &private_key_pem)?;

    let state = ServerState {
        webhook_secret: args.webhook_secret.as_bytes().to_vec(),
        app_id: args.app_id,
        private_key_pem,
        http: Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?,
        github_api_url: args.github_api_url.trim_end_matches('/').to_string(),
        llm_base_url: validated_llm_url,
        model: args.model,
        api_key_env: args.api_key_env,
        allow_insecure_http: args.allow_insecure_http,
        timeout_secs: args.timeout_secs,
        overrides: CliConfigOverrides {
            language: args.language,
            min_severity: args.min_severity,
            max_comments: args.max_comments,
            max_files: args.max_files,
            no_suggestions: args.no_suggestions,
            fail_on_error: false,
        },
        in_flight: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(args.bind)
        .await
        .with_context(|| format!("failed binding webhook server to `{}`", args.bind))?;

    println!(
        "Guardian v{} webhook server listening on http://{}/webhook (app_id={})",
        guardian_core::VERSION,
        args.bind,
        args.app_id
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("webhook server exited with error")?;

    Ok(())
}

fn build_router(state: ServerState) -> Router {
    Router::new()
        .route("/healthz", get(healthz_handler))
        .route("/webhook", post(webhook_handler))
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .with_state(state)
}

async fn healthz_handler() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "version": guardian_core::VERSION
    }))
}

async fn webhook_handler(
    State(state): State<ServerState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let sig = headers
        .get("x-hub-signature-256")
        .and_then(|v| v.to_str().ok());
    if !verify_github_signature(&state.webhook_secret, &body, sig) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid webhook signature"})),
        );
    }

    let event = headers
        .get("x-github-event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if event == "ping" {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "event": "ping"})),
        );
    }

    if event != "pull_request" {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "ignored_event": event})),
        );
    }

    let payload: PullRequestWebhook = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("invalid payload: {err}")})),
            );
        }
    };

    if !matches!(
        payload.action.as_str(),
        "opened" | "synchronize" | "reopened" | "ready_for_review"
    ) {
        return (
            StatusCode::OK,
            Json(serde_json::json!({"ok": true, "ignored_action": payload.action})),
        );
    }

    let Some(installation) = payload.installation else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "missing installation.id in pull_request webhook"})),
        );
    };

    let pr_spec = format!("{}#{}", payload.repository.full_name, payload.number);
    let pr_key = pr_spec.clone();
    let state_clone = state.clone();

    let handle = tokio::spawn(async move {
        if let Err(err) = dispatch_pr_review(&state_clone, &pr_spec, installation.id).await {
            let safe = guardian_core::redact::redact_secrets(&format!("{err:#}"));
            tracing::error!(pr = %pr_spec, error = %safe, "Webhook PR review failed");
        }
    });

    // Cancel any older in-flight review for the same PR (per-PR concurrency).
    let mut guard = state.in_flight.lock().await;
    if let Some(prev) = guard.insert(pr_key, handle.abort_handle()) {
        prev.abort();
    }

    (
        StatusCode::ACCEPTED,
        Json(
            serde_json::json!({"accepted": true, "pr": format!("{}#{}", payload.repository.full_name, payload.number)}),
        ),
    )
}

async fn dispatch_pr_review(
    state: &ServerState,
    pr_spec: &str,
    installation_id: u64,
) -> Result<()> {
    let token = mint_installation_token(
        &state.http,
        &state.github_api_url,
        state.app_id,
        &state.private_key_pem,
        installation_id,
    )
    .await?;

    let mut fail_on_error = false;
    execute_review_with_token(
        ReviewExecutionParams {
            diff_file: None,
            pr: Some(pr_spec.to_string()),
            base_url: state.llm_base_url.clone(),
            model: Some(state.model.clone()),
            api_key_env: state.api_key_env.clone(),
            allow_insecure_http: state.allow_insecure_http,
            overrides: state.overrides.clone(),
            local_config_path: None,
            timeout_secs: state.timeout_secs,
            record: None,
            replay: None,
            dry_run: false,
            github_api_url: state.github_api_url.clone(),
            github_token_override: Some(token),
        },
        &mut fail_on_error,
    )
    .await
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("Shutdown signal received; stopping webhook server");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign_body(secret: &[u8], body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret).expect("hmac");
        mac.update(body);
        let hex_str = hex::encode(mac.finalize().into_bytes());
        format!("sha256={hex_str}")
    }

    #[test]
    fn verifies_hmac_sha256_signatures() {
        let secret = b"super-secret-webhook";
        let payload = br#"{"zen":"Keep it logically awesome."}"#;
        let valid = sign_body(secret, payload);

        assert!(verify_github_signature(secret, payload, Some(&valid)));
        assert!(!verify_github_signature(
            secret,
            payload,
            Some("sha256=deadbeef")
        ));
        assert!(!verify_github_signature(secret, payload, None));
        assert!(!verify_github_signature(b"wrong", payload, Some(&valid)));
    }

    #[tokio::test]
    async fn webhook_rejects_invalid_signature_and_accepts_signed_ping() {
        let state = ServerState {
            webhook_secret: b"test-secret".to_vec(),
            app_id: 5928531,
            private_key_pem: String::new(),
            http: Client::new(),
            github_api_url: "https://api.github.com".into(),
            llm_base_url: "https://api.openai.com/v1".into(),
            model: "qwen2.5-coder:7b".into(),
            api_key_env: "GUARDIAN_LLM_API_KEY".into(),
            allow_insecure_http: false,
            timeout_secs: 60,
            overrides: CliConfigOverrides {
                language: None,
                min_severity: None,
                max_comments: None,
                max_files: None,
                no_suggestions: false,
                fail_on_error: false,
            },
            in_flight: Arc::new(Mutex::new(HashMap::new())),
        };

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_task = tokio::spawn(async move {
            axum::serve(listener, build_router(state)).await.ok();
        });

        let client = Client::new();
        let base = format!("http://{addr}");

        // 1. Healthcheck -> 200
        let health = client
            .get(format!("{base}/healthz"))
            .send()
            .await
            .expect("healthz");
        assert_eq!(health.status(), reqwest::StatusCode::OK);

        // 2. Unsigned webhook -> 401
        let bad = client
            .post(format!("{base}/webhook"))
            .header("x-github-event", "ping")
            .body("{}")
            .send()
            .await
            .expect("unsigned webhook");
        assert_eq!(bad.status(), reqwest::StatusCode::UNAUTHORIZED);

        // 3. Signed ping -> 200
        let body = br#"{"zen":"testing"}"#;
        let sig = sign_body(b"test-secret", body);
        let good = client
            .post(format!("{base}/webhook"))
            .header("x-github-event", "ping")
            .header("x-hub-signature-256", sig)
            .body(&body[..])
            .send()
            .await
            .expect("signed ping");
        assert_eq!(good.status(), reqwest::StatusCode::OK);

        server_task.abort();
    }
}
