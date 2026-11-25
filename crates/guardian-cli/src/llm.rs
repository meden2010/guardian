//! OpenAI-compatible LLM adapter (`/v1/chat/completions`) with URL safety, retries, and JSON repair.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use guardian_core::parse_llm_output;
use guardian_core::types::LlmReviewOutput;
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct OpenAiCompatibleConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub allow_insecure_http: bool,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct OpenAiCompatibleClient {
    http: Client,
    cfg: OpenAiCompatibleConfig,
}

#[derive(Debug, Serialize)]
struct ChatRequest<'a> {
    model: &'a str,
    temperature: f32,
    response_format: ResponseFormat<'a>,
    messages: Vec<ChatMessage<'a>>,
}

#[derive(Debug, Serialize)]
struct ResponseFormat<'a> {
    #[serde(rename = "type")]
    kind: &'a str,
}

#[derive(Debug, Serialize)]
struct ChatMessage<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
    #[serde(default)]
    usage: Option<TokenUsage>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatChoiceMessage,
}

#[derive(Debug, Deserialize)]
struct ChatChoiceMessage {
    content: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TokenUsage {
    #[serde(default)]
    pub prompt_tokens: u64,
    #[serde(default)]
    pub completion_tokens: u64,
}

pub struct LlmCallStats {
    pub output: LlmReviewOutput,
    pub usage: TokenUsage,
}

/// Validates `base_url` against exfiltration/cleartext rules:
/// - `https://` is always allowed.
/// - `http://localhost` and `http://127.0.0.1` are always allowed.
/// - Other `http://` hosts (such as LAN / Tailscale `100.x.y.z`) require `allow_insecure_http = true`.
pub fn validate_base_url(base_url: &str, allow_insecure_http: bool) -> Result<String> {
    let trimmed = base_url.trim().trim_end_matches('/');
    if trimmed.starts_with("https://") {
        return Ok(trimmed.to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("http://") {
        let host_port = rest.split('/').next().unwrap_or("");
        let host = host_port.split(':').next().unwrap_or("");
        if host == "localhost" || host == "127.0.0.1" || allow_insecure_http {
            return Ok(trimmed.to_string());
        }
        bail!(
            "ERR_INSECURE_BASE_URL: plain HTTP base_url `{host}` is rejected by default; use https://, localhost, or pass --allow-insecure-http for trusted LAN/Tailscale hosts"
        );
    }
    bail!("ERR_INVALID_BASE_URL: base_url must start with https:// or http://");
}

impl OpenAiCompatibleClient {
    pub fn new(mut cfg: OpenAiCompatibleConfig) -> Result<Self> {
        cfg.base_url = validate_base_url(&cfg.base_url, cfg.allow_insecure_http)?;
        if cfg.model.trim().is_empty() {
            bail!("ERR_MISSING_MODEL: LLM model name is required (no silent default)");
        }
        let http = Client::builder()
            .timeout(Duration::from_secs(cfg.timeout_secs.max(5)))
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self { http, cfg })
    }

    pub async fn check_models_endpoint(&self) -> Result<()> {
        let url = format!("{}/models", self.cfg.base_url);
        let mut req = self.http.get(&url);
        if let Some(key) = &self.cfg.api_key {
            req = req.bearer_auth(key);
        }
        let resp = req
            .send()
            .await
            .context("failed to reach LLM /models endpoint")?;
        if !resp.status().is_success() {
            bail!("LLM /models returned HTTP {}", resp.status());
        }
        Ok(())
    }

    pub async fn review(&self, system_prompt: &str, user_prompt: &str) -> Result<LlmCallStats> {
        let (first_text, mut usage) = self
            .send_chat(vec![
                ChatMessage {
                    role: "system",
                    content: system_prompt,
                },
                ChatMessage {
                    role: "user",
                    content: user_prompt,
                },
            ])
            .await?;

        match parse_llm_output(&first_text) {
            Ok(output) => Ok(LlmCallStats { output, usage }),
            Err(first_err) => {
                tracing::warn!(error = %first_err, "Malformed JSON from LLM; retrying once for repair");
                let repair_prompt = format!(
                    "Your previous response was not valid JSON matching `{{\"findings\": [...]}}` (error: {first_err}). Return ONLY corrected valid JSON."
                );
                let (second_text, retry_usage) = self
                    .send_chat(vec![
                        ChatMessage {
                            role: "system",
                            content: system_prompt,
                        },
                        ChatMessage {
                            role: "user",
                            content: user_prompt,
                        },
                        ChatMessage {
                            role: "assistant",
                            content: &first_text,
                        },
                        ChatMessage {
                            role: "user",
                            content: &repair_prompt,
                        },
                    ])
                    .await?;
                usage.prompt_tokens += retry_usage.prompt_tokens;
                usage.completion_tokens += retry_usage.completion_tokens;
                let output = parse_llm_output(&second_text)
                    .context("ERR_LLM_MALFORMED_JSON: retry also returned invalid JSON")?;
                Ok(LlmCallStats { output, usage })
            }
        }
    }

    async fn send_chat(&self, messages: Vec<ChatMessage<'_>>) -> Result<(String, TokenUsage)> {
        let url = format!("{}/chat/completions", self.cfg.base_url);
        let body = ChatRequest {
            model: &self.cfg.model,
            temperature: 0.1,
            response_format: ResponseFormat {
                kind: "json_object",
            },
            messages,
        };

        let mut attempt = 0u32;
        let max_retries = 2u32;

        loop {
            let mut req = self.http.post(&url).json(&body);
            if let Some(key) = &self.cfg.api_key {
                req = req.bearer_auth(key);
            }

            let resp = req
                .send()
                .await
                .context("ERR_LLM_NETWORK: failed sending chat completion request")?;

            let status = resp.status();
            if status.is_success() {
                let parsed: ChatResponse = resp
                    .json()
                    .await
                    .context("ERR_LLM_ENVELOPE: invalid OpenAI chat response JSON")?;
                let content = parsed
                    .choices
                    .into_iter()
                    .next()
                    .and_then(|c| c.message.content)
                    .unwrap_or_default();
                return Ok((content, parsed.usage.unwrap_or_default()));
            }

            let retryable = status == StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
            if retryable && attempt < max_retries {
                let retry_after_ms = resp
                    .headers()
                    .get("retry-after")
                    .and_then(|h| h.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .map(|secs| secs * 1000)
                    .unwrap_or_else(|| 400 * (1u64 << attempt));
                attempt += 1;
                tracing::warn!(%status, attempt, retry_after_ms, "Transient LLM HTTP error; backing off");
                tokio::time::sleep(Duration::from_millis(retry_after_ms.min(5_000))).await;
                continue;
            }

            bail!("ERR_LLM_HTTP: provider returned HTTP {status}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn rejects_plain_http_for_non_localhost_unless_opted_in() {
        assert!(validate_base_url("https://api.openai.com/v1", false).is_ok());
        assert!(validate_base_url("http://localhost:11434/v1", false).is_ok());
        assert!(validate_base_url("http://127.0.0.1:11434/v1", false).is_ok());
        assert!(validate_base_url("http://100.82.189.71:11434/v1", false).is_err());
        assert!(validate_base_url("http://100.82.189.71:11434/v1", true).is_ok());
    }

    #[tokio::test]
    async fn retries_once_when_first_llm_response_is_malformed_json() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"content": "not valid json at all"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5}
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "choices": [{"message": {"content": "{\"findings\": []}"}}],
                "usage": {"prompt_tokens": 12, "completion_tokens": 4}
            })))
            .mount(&server)
            .await;

        let client = OpenAiCompatibleClient::new(OpenAiCompatibleConfig {
            base_url: format!("{}/v1", server.uri()),
            model: "qwen2.5-coder:14b".to_string(),
            api_key: None,
            allow_insecure_http: true,
            timeout_secs: 10,
        })
        .expect("client init");

        let stats = client
            .review("sys", "usr")
            .await
            .expect("retry should succeed");
        assert!(stats.output.findings.is_empty());
        assert_eq!(stats.usage.prompt_tokens, 22);
    }
}
