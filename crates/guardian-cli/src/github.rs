//! Lightweight GitHub REST adapter for fetching PR diffs, fingerprints, and publishing atomic reviews.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use guardian_core::filter::{
    format_enriched_pr_summary, format_inline_comment, format_processing_summary, SummaryReport,
    SUMMARY_MARKER,
};
use guardian_core::fingerprint::extract_fingerprints;
use guardian_core::types::{PrMetadata, ReviewStatus, SkipFileReason, ValidatedFinding};
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

pub const CHECK_RUN_NAME: &str = "Guardian Review";

pub struct PublishReviewParams<'a> {
    pub expected_head_sha: &'a str,
    pub status: &'a ReviewStatus,
    pub reviewed_files: &'a [String],
    pub skipped_files: &'a [(String, SkipFileReason)],
    pub inline_findings: &'a [ValidatedFinding],
    pub fallback_findings: &'a [ValidatedFinding],
    pub deduplicated_count: usize,
    pub resolved_threads_count: usize,
    pub model_name: &'a str,
    pub language: &'a str,
    pub suggestions_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrRef {
    pub owner: String,
    pub repo: String,
    pub number: u64,
}

impl PrRef {
    /// Parses `owner/repo#123` or `https://github.com/owner/repo/pull/123`.
    pub fn parse(spec: &str) -> Result<Self> {
        let trimmed = spec.trim().trim_end_matches('/');
        if let Some(rest) = trimmed
            .strip_prefix("https://github.com/")
            .or_else(|| trimmed.strip_prefix("http://github.com/"))
        {
            let parts: Vec<&str> = rest.split('/').collect();
            if parts.len() >= 4 && parts[2] == "pull" {
                let number = parts[3]
                    .parse::<u64>()
                    .context("invalid PR number in GitHub URL")?;
                return Ok(Self {
                    owner: parts[0].to_string(),
                    repo: parts[1].to_string(),
                    number,
                });
            }
        }

        if let Some((repo_slug, num_str)) = trimmed.split_once('#') {
            if let Some((owner, repo)) = repo_slug.split_once('/') {
                let number = num_str.parse::<u64>().context("invalid PR number")?;
                if !owner.is_empty() && !repo.is_empty() {
                    return Ok(Self {
                        owner: owner.to_string(),
                        repo: repo.to_string(),
                        number,
                    });
                }
            }
        }

        bail!("ERR_INVALID_PR_SPEC: expected `owner/repo#123` or `https://github.com/owner/repo/pull/123`");
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PullRequestInfo {
    pub state: String,
    #[serde(default)]
    pub draft: bool,
    pub title: Option<String>,
    pub body: Option<String>,
    pub head: GitRefSha,
    pub base: GitRefSha,
    pub user: PrUser,
    #[serde(default)]
    pub labels: Vec<PrLabel>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GitRefSha {
    pub sha: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PrUser {
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PrLabel {
    pub name: String,
}

impl PullRequestInfo {
    pub fn to_metadata(&self) -> PrMetadata {
        PrMetadata {
            title: self.title.clone().unwrap_or_default(),
            description: self.body.clone().unwrap_or_default(),
        }
    }

    /// Evaluates automatic skip conditions (`draft`, `bot`, `guardian-skip`, vs `guardian-review`).
    pub fn skip_reason(&self, skip_drafts: bool, skip_bots: bool) -> Option<String> {
        let force_review = self.labels.iter().any(|l| l.name == "guardian-review");
        if force_review {
            return None;
        }
        if self.state != "open" {
            return Some(format!("SKIP_NOT_OPEN: PR state is `{}`", self.state));
        }
        if self.labels.iter().any(|l| l.name == "guardian-skip") {
            return Some("SKIP_LABEL: PR has `guardian-skip` label".to_string());
        }
        if skip_drafts && self.draft {
            return Some("SKIP_DRAFT: PR is in draft state".to_string());
        }
        if skip_bots && self.user.kind.eq_ignore_ascii_case("Bot") {
            return Some("SKIP_BOT: PR author is a bot account".to_string());
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishOutcome {
    Published {
        inline_posted: usize,
        fallback_posted: usize,
    },
    AbortedStaleState {
        reason: String,
    },
}

pub struct GitHubClient {
    http: Client,
    api_base: String,
    token: String,
}

#[derive(Debug, Serialize)]
struct CreateReviewRequest<'a> {
    commit_id: &'a str,
    event: &'a str,
    comments: Vec<InlineReviewComment<'a>>,
}

#[derive(Debug, Serialize)]
struct InlineReviewComment<'a> {
    path: &'a str,
    line: u32,
    side: &'a str,
    body: String,
}

#[derive(Debug, Deserialize)]
struct CommentNode {
    #[serde(default)]
    id: u64,
    #[serde(default)]
    body: String,
}

#[derive(Debug, Clone, Default)]
pub struct ExistingFingerprints {
    pub fingerprints: HashSet<String>,
    pub resolved_threads: usize,
}

#[derive(Debug, Deserialize)]
struct GraphQlResponse {
    data: Option<GraphQlData>,
}

#[derive(Debug, Deserialize)]
struct GraphQlData {
    repository: Option<GraphQlRepo>,
}

#[derive(Debug, Deserialize)]
struct GraphQlRepo {
    #[serde(rename = "pullRequest")]
    pull_request: Option<GraphQlPr>,
}

#[derive(Debug, Deserialize)]
struct GraphQlPr {
    #[serde(rename = "reviewThreads")]
    review_threads: GraphQlThreadConnection,
}

#[derive(Debug, Deserialize)]
struct GraphQlThreadConnection {
    #[serde(default)]
    nodes: Vec<GraphQlThread>,
}

#[derive(Debug, Deserialize)]
struct GraphQlThread {
    #[serde(rename = "isResolved", default)]
    is_resolved: bool,
    comments: GraphQlCommentConnection,
}

#[derive(Debug, Deserialize)]
struct GraphQlCommentConnection {
    #[serde(default)]
    nodes: Vec<GraphQlComment>,
}

#[derive(Debug, Deserialize)]
struct GraphQlComment {
    #[serde(default)]
    body: String,
}

#[derive(Debug, Serialize)]
struct CommentBody<'a> {
    body: &'a str,
}

impl GitHubClient {
    pub fn new(api_base: String, token: String) -> Result<Self> {
        if token.trim().is_empty() {
            bail!("ERR_MISSING_GITHUB_TOKEN: GITHUB_TOKEN is empty");
        }
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("failed to build GitHub HTTP client")?;
        Ok(Self {
            http,
            api_base: api_base.trim_end_matches('/').to_string(),
            token,
        })
    }

    pub async fn fetch_pr(&self, pr: &PrRef) -> Result<PullRequestInfo> {
        let url = format!(
            "{}/repos/{}/{}/pulls/{}",
            self.api_base, pr.owner, pr.repo, pr.number
        );
        let resp = self
            .http
            .get(&url)
            .header(USER_AGENT, "guardian-pr-reviewer")
            .header(ACCEPT, "application/vnd.github+json")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .await
            .context("ERR_GITHUB_NETWORK: failed fetching PR metadata")?;

        if resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED {
            bail!(
                "ERR_GITHUB_PERMISSIONS: HTTP {} reading PR metadata (check GITHUB_TOKEN permissions)",
                resp.status()
            );
        }
        if !resp.status().is_success() {
            bail!("ERR_GITHUB_HTTP: GET PR returned HTTP {}", resp.status());
        }
        resp.json::<PullRequestInfo>()
            .await
            .context("failed parsing GitHub PR metadata")
    }

    pub async fn fetch_pr_diff(&self, pr: &PrRef) -> Result<String> {
        let url = format!(
            "{}/repos/{}/{}/pulls/{}",
            self.api_base, pr.owner, pr.repo, pr.number
        );
        let resp = self
            .http
            .get(&url)
            .header(USER_AGENT, "guardian-pr-reviewer")
            .header(ACCEPT, "application/vnd.github.v3.diff")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .await
            .context("ERR_GITHUB_NETWORK: failed fetching PR diff")?;

        if !resp.status().is_success() {
            bail!("ERR_GITHUB_DIFF_HTTP: HTTP {}", resp.status());
        }
        resp.text().await.context("failed reading PR diff text")
    }

    /// Passively fetches raw file contents at `git_ref` via GitHub Contents API (no checkout).
    /// Rejects path traversal (`..`, leading `/`, `\`) and skips files larger than 200 KB.
    pub async fn fetch_file_at_ref(
        &self,
        pr: &PrRef,
        path: &str,
        git_ref: &str,
    ) -> Result<Option<String>> {
        let clean = path.trim();
        if clean.is_empty()
            || clean.starts_with('/')
            || clean.contains("..")
            || clean.contains('\\')
        {
            bail!("ERR_UNSAFE_FILE_PATH: rejected unsafe repository path `{clean}`");
        }

        let url = format!(
            "{}/repos/{}/{}/contents/{}?ref={}",
            self.api_base, pr.owner, pr.repo, clean, git_ref
        );
        let resp = self
            .http
            .get(&url)
            .header(USER_AGENT, "guardian-pr-reviewer")
            .header(ACCEPT, "application/vnd.github.raw+json")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .await
            .context("ERR_GITHUB_NETWORK: failed fetching file contents")?;

        if resp.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            tracing::warn!(path = clean, status = %resp.status(), "Could not fetch file context");
            return Ok(None);
        }

        let text = resp.text().await.context("failed reading file body")?;
        if text.len() > 200_000 {
            return Ok(None);
        }
        Ok(Some(text))
    }

    /// Reads existing PR review threads via GraphQL (including `isResolved: true` threads)
    /// and merges with REST review/issue comments to extract all `<!-- guardian:fp=... -->` hashes.
    pub async fn fetch_existing_fingerprints(&self, pr: &PrRef) -> Result<ExistingFingerprints> {
        let mut result = ExistingFingerprints::default();

        // 1. GraphQL query for `reviewThreads { isResolved }` (not exposed by REST).
        let gql_url = format!("{}/graphql", self.api_base);
        let gql_query = r#"
            query($owner: String!, $repo: String!, $number: Int!) {
                repository(owner: $owner, name: $repo) {
                    pullRequest(number: $number) {
                        reviewThreads(first: 100) {
                            nodes {
                                isResolved
                                comments(first: 20) {
                                    nodes { body }
                                }
                            }
                        }
                    }
                }
            }
        "#;
        let gql_body = serde_json::json!({
            "query": gql_query,
            "variables": {
                "owner": pr.owner,
                "repo": pr.repo,
                "number": pr.number,
            }
        });

        if let Ok(resp) = self
            .http
            .post(&gql_url)
            .header(USER_AGENT, "guardian-pr-reviewer")
            .header(ACCEPT, "application/vnd.github+json")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .json(&gql_body)
            .send()
            .await
        {
            if resp.status().is_success() {
                if let Ok(parsed) = resp.json::<GraphQlResponse>().await {
                    if let Some(threads) = parsed
                        .data
                        .and_then(|d| d.repository)
                        .and_then(|r| r.pull_request)
                        .map(|p| p.review_threads.nodes)
                    {
                        for thread in threads {
                            let mut thread_has_fp = false;
                            for comment in thread.comments.nodes {
                                for fp in extract_fingerprints(&comment.body) {
                                    result.fingerprints.insert(fp);
                                    thread_has_fp = true;
                                }
                            }
                            if thread.is_resolved && thread_has_fp {
                                result.resolved_threads += 1;
                            }
                        }
                    }
                }
            }
        }

        // 2. REST comments (covers fallback summary comments and degrades gracefully if GraphQL fails).
        let review_comments_url = format!(
            "{}/repos/{}/{}/pulls/{}/comments?per_page=100",
            self.api_base, pr.owner, pr.repo, pr.number
        );
        let issue_comments_url = format!(
            "{}/repos/{}/{}/issues/{}/comments?per_page=100",
            self.api_base, pr.owner, pr.repo, pr.number
        );

        for url in [review_comments_url, issue_comments_url] {
            let resp = self
                .http
                .get(&url)
                .header(USER_AGENT, "guardian-pr-reviewer")
                .header(ACCEPT, "application/vnd.github+json")
                .header(AUTHORIZATION, format!("Bearer {}", self.token))
                .send()
                .await
                .context("ERR_GITHUB_NETWORK: failed fetching existing PR comments")?;

            if resp.status().is_success() {
                let items: Vec<CommentNode> = resp.json().await.unwrap_or_default();
                for item in items {
                    for fp in extract_fingerprints(&item.body) {
                        result.fingerprints.insert(fp);
                    }
                }
            }
        }

        Ok(result)
    }

    /// Starts a native GitHub Check Run (`Guardian Review`) in `in_progress` state.
    /// Degrades gracefully (`None`) when running with a classic PAT or without `checks: write`.
    pub async fn start_check_run(&self, pr: &PrRef, head_sha: &str, language: &str) -> Option<u64> {
        let is_es = language.trim().to_ascii_lowercase().starts_with("es");
        let (title, summary) = if is_es {
            (
                "Analizando Pull Request...",
                "Guardian está revisando cambios lógicos, contexto AST y *edge cases*.",
            )
        } else {
            (
                "Analyzing Pull Request...",
                "Guardian is reviewing logical changes, AST context, and runtime edge cases.",
            )
        };

        let url = format!(
            "{}/repos/{}/{}/check-runs",
            self.api_base, pr.owner, pr.repo
        );
        let payload = serde_json::json!({
            "name": CHECK_RUN_NAME,
            "head_sha": head_sha,
            "status": "in_progress",
            "output": {
                "title": title,
                "summary": summary,
            }
        });

        let resp = self
            .http
            .post(&url)
            .header(USER_AGENT, "guardian-pr-reviewer")
            .header(ACCEPT, "application/vnd.github+json")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .json(&payload)
            .send()
            .await
            .ok()?;

        if !resp.status().is_success() {
            tracing::debug!(
                status = %resp.status(),
                "Check Run API unavailable for current token; continuing without native Check Run"
            );
            return None;
        }

        let val: serde_json::Value = resp.json().await.ok()?;
        val.get("id").and_then(|v| v.as_u64())
    }

    /// Completes a previously created GitHub Check Run (`Guardian Review`).
    pub async fn complete_check_run(
        &self,
        pr: &PrRef,
        check_run_id: u64,
        conclusion: &str,
        title: &str,
        summary: &str,
    ) {
        let url = format!(
            "{}/repos/{}/{}/check-runs/{}",
            self.api_base, pr.owner, pr.repo, check_run_id
        );
        let payload = serde_json::json!({
            "status": "completed",
            "conclusion": conclusion,
            "output": {
                "title": title,
                "summary": summary,
            }
        });

        if let Ok(resp) = self
            .http
            .patch(&url)
            .header(USER_AGENT, "guardian-pr-reviewer")
            .header(ACCEPT, "application/vnd.github+json")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .json(&payload)
            .send()
            .await
        {
            if !resp.status().is_success() {
                tracing::warn!(status = %resp.status(), "Failed completing Check Run");
            }
        }
    }

    /// Posts or updates the fixed PR summary comment with the animated `"⏳ Procesando..."` banner.
    pub async fn publish_processing_state(
        &self,
        pr: &PrRef,
        language: &str,
        svg_url: Option<&str>,
    ) -> Result<()> {
        let body = format_processing_summary(language, svg_url);
        self.upsert_summary_comment(pr, &body).await
    }

    /// Best-effort cleanup so a PR comment never stays stuck on `"⏳ Procesando..."` if an error occurs.
    pub async fn publish_error_summary(
        &self,
        pr: &PrRef,
        reason: &str,
        model_name: &str,
        language: &str,
    ) {
        let status = ReviewStatus::Error {
            reason: reason.to_string(),
        };
        let md = format_enriched_pr_summary(&SummaryReport {
            status: &status,
            reviewed_files: &[],
            skipped_files: &[],
            inline_findings: &[],
            fallback_findings: &[],
            deduplicated_count: 0,
            resolved_threads_count: 0,
            model_name,
            language,
        });
        let _ = self.upsert_summary_comment(pr, &md).await;
    }

    /// Atomically publishes inline review comments + upserts the single fixed summary comment.
    /// Re-verifies `state == "open"` and `head.sha` before posting, and falls back to summary on HTTP 422.
    pub async fn publish_review(
        &self,
        pr: &PrRef,
        params: &PublishReviewParams<'_>,
    ) -> Result<PublishOutcome> {
        let latest = self.fetch_pr(pr).await?;
        if latest.state != "open" {
            return Ok(PublishOutcome::AbortedStaleState {
                reason: format!("PR is now `{}`", latest.state),
            });
        }
        if latest.head.sha != params.expected_head_sha {
            return Ok(PublishOutcome::AbortedStaleState {
                reason: format!(
                    "PR head moved from `{}` to `{}` during review",
                    params.expected_head_sha, latest.head.sha
                ),
            });
        }

        let mut combined_fallback: Vec<ValidatedFinding> = params.fallback_findings.to_vec();
        let mut inline_posted = 0usize;

        if !params.inline_findings.is_empty() {
            let comments: Vec<InlineReviewComment<'_>> = params
                .inline_findings
                .iter()
                .map(|f| InlineReviewComment {
                    path: &f.path,
                    line: f.line,
                    side: "RIGHT",
                    body: format_inline_comment(f, params.language, params.suggestions_enabled),
                })
                .collect();

            let review_url = format!(
                "{}/repos/{}/{}/pulls/{}/reviews",
                self.api_base, pr.owner, pr.repo, pr.number
            );
            let payload = CreateReviewRequest {
                commit_id: params.expected_head_sha,
                event: "COMMENT",
                comments,
            };

            let resp = self
                .http
                .post(&review_url)
                .header(USER_AGENT, "guardian-pr-reviewer")
                .header(ACCEPT, "application/vnd.github+json")
                .header(AUTHORIZATION, format!("Bearer {}", self.token))
                .json(&payload)
                .send()
                .await
                .context("ERR_GITHUB_NETWORK: failed posting PR review")?;

            if resp.status().is_success() {
                inline_posted = params.inline_findings.len();
            } else if resp.status() == StatusCode::UNPROCESSABLE_ENTITY {
                tracing::warn!("GitHub rejected inline line positions (HTTP 422); routing findings to summary fallback");
                combined_fallback.extend_from_slice(params.inline_findings);
            } else if resp.status() == StatusCode::FORBIDDEN
                || resp.status() == StatusCode::UNAUTHORIZED
            {
                bail!(
                    "ERR_GITHUB_PERMISSIONS: HTTP {} posting PR review (fork PR without write token?)",
                    resp.status()
                );
            } else {
                bail!("ERR_GITHUB_REVIEW_HTTP: HTTP {}", resp.status());
            }
        }

        let effective_inline = if inline_posted > 0 {
            params.inline_findings
        } else {
            &[]
        };
        let summary_md = format_enriched_pr_summary(&SummaryReport {
            status: params.status,
            reviewed_files: params.reviewed_files,
            skipped_files: params.skipped_files,
            inline_findings: effective_inline,
            fallback_findings: &combined_fallback,
            deduplicated_count: params.deduplicated_count,
            resolved_threads_count: params.resolved_threads_count,
            model_name: params.model_name,
            language: params.language,
        });
        self.upsert_summary_comment(pr, &summary_md).await?;

        Ok(PublishOutcome::Published {
            inline_posted,
            fallback_posted: combined_fallback.len(),
        })
    }

    async fn upsert_summary_comment(&self, pr: &PrRef, body: &str) -> Result<()> {
        let list_url = format!(
            "{}/repos/{}/{}/issues/{}/comments?per_page=100",
            self.api_base, pr.owner, pr.repo, pr.number
        );
        let list_resp = self
            .http
            .get(&list_url)
            .header(USER_AGENT, "guardian-pr-reviewer")
            .header(ACCEPT, "application/vnd.github+json")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .send()
            .await
            .context("failed listing PR issue comments")?;

        if list_resp.status().is_success() {
            let existing: Vec<CommentNode> = list_resp.json().await.unwrap_or_default();
            if let Some(found) = existing
                .into_iter()
                .find(|c| c.body.contains(SUMMARY_MARKER))
            {
                let patch_url = format!(
                    "{}/repos/{}/{}/issues/comments/{}",
                    self.api_base, pr.owner, pr.repo, found.id
                );
                let patch_resp = self
                    .http
                    .patch(&patch_url)
                    .header(USER_AGENT, "guardian-pr-reviewer")
                    .header(ACCEPT, "application/vnd.github+json")
                    .header(AUTHORIZATION, format!("Bearer {}", self.token))
                    .json(&CommentBody { body })
                    .send()
                    .await
                    .context("failed updating fixed summary comment")?;
                if patch_resp.status().is_success() {
                    return Ok(());
                }
            }
        }

        let create_url = format!(
            "{}/repos/{}/{}/issues/{}/comments",
            self.api_base, pr.owner, pr.repo, pr.number
        );
        let create_resp = self
            .http
            .post(&create_url)
            .header(USER_AGENT, "guardian-pr-reviewer")
            .header(ACCEPT, "application/vnd.github+json")
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .json(&CommentBody { body })
            .send()
            .await
            .context("failed creating PR summary comment")?;

        if !create_resp.status().is_success() {
            bail!(
                "ERR_GITHUB_COMMENT_HTTP: HTTP {} creating summary comment",
                create_resp.status()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use guardian_core::fingerprint::{compute_fingerprint, format_fp_marker};
    use guardian_core::types::{FindingCategory, Severity};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn parses_pr_specs() {
        let a = PrRef::parse("meden2010/guardian#42").expect("slug");
        assert_eq!(
            a,
            PrRef {
                owner: "meden2010".into(),
                repo: "guardian".into(),
                number: 42
            }
        );

        let b = PrRef::parse("https://github.com/meden2010/guardian/pull/7/").expect("url");
        assert_eq!(b.number, 7);
    }

    #[tokio::test]
    async fn fetches_existing_fingerprints_from_review_and_issue_comments() {
        let server = MockServer::start().await;
        let fp1 = compute_fingerprint("src/a.rs", "a / b", FindingCategory::Bug);
        let fp2 = compute_fingerprint("src/b.rs", "arr[i]", FindingCategory::EdgeCase);

        Mock::given(method("GET"))
            .and(path("/repos/meden2010/guardian/pulls/5/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 1, "body": format!("{}\nInline comment", format_fp_marker(&fp1))}
            ])))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/repos/meden2010/guardian/issues/5/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 2, "body": format!("{SUMMARY_MARKER}\n- {} fallback", format_fp_marker(&fp2))}
            ])))
            .mount(&server)
            .await;

        let gh = GitHubClient::new(server.uri(), "tok".into()).expect("gh init");
        let pr = PrRef::parse("meden2010/guardian#5").expect("pr");
        let fps = gh.fetch_existing_fingerprints(&pr).await.expect("fps");
        assert!(fps.fingerprints.contains(&fp1));
        assert!(fps.fingerprints.contains(&fp2));
        assert_eq!(fps.fingerprints.len(), 2);
        assert_eq!(fps.resolved_threads, 0);
    }

    #[tokio::test]
    async fn fetches_resolved_thread_fingerprints_via_graphql() {
        let server = MockServer::start().await;
        let fp_resolved = compute_fingerprint("src/app.ts", "x / y", FindingCategory::EdgeCase);

        Mock::given(method("POST"))
            .and(path("/graphql"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "repository": {
                        "pullRequest": {
                            "reviewThreads": {
                                "nodes": [
                                    {
                                        "isResolved": true,
                                        "comments": {
                                            "nodes": [
                                                { "body": format!("{}\nResolved finding", format_fp_marker(&fp_resolved)) }
                                            ]
                                        }
                                    }
                                ]
                            }
                        }
                    }
                }
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/repos/meden2010/guardian/pulls/8/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/repos/meden2010/guardian/issues/8/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        let gh = GitHubClient::new(server.uri(), "tok".into()).expect("gh init");
        let pr = PrRef::parse("meden2010/guardian#8").expect("pr");
        let fps = gh.fetch_existing_fingerprints(&pr).await.expect("fps");
        assert!(fps.fingerprints.contains(&fp_resolved));
        assert_eq!(fps.resolved_threads, 1);
    }

    #[tokio::test]
    async fn fetches_raw_file_and_rejects_path_traversal() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/meden2010/guardian/contents/src/app.ts"))
            .respond_with(ResponseTemplate::new(200).set_body_string("export const ok = 1;\n"))
            .mount(&server)
            .await;

        let gh = GitHubClient::new(server.uri(), "tok".into()).expect("gh init");
        let pr = PrRef::parse("meden2010/guardian#5").expect("pr");

        let ok = gh
            .fetch_file_at_ref(&pr, "src/app.ts", "abc123")
            .await
            .expect("valid file");
        assert_eq!(ok.as_deref(), Some("export const ok = 1;\n"));

        let bad = gh.fetch_file_at_ref(&pr, "../etc/passwd", "abc123").await;
        assert!(bad.is_err());
    }

    #[tokio::test]
    async fn aborts_publish_when_head_sha_changes_mid_run() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/meden2010/guardian/pulls/1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "open",
                "draft": false,
                "title": "Test",
                "body": "",
                "head": {"sha": "new_sha_999"},
                "base": {"sha": "base_sha_000"},
                "user": {"type": "User"},
                "labels": []
            })))
            .mount(&server)
            .await;

        let gh = GitHubClient::new(server.uri(), "test_tok".into()).expect("gh init");
        let pr = PrRef::parse("meden2010/guardian#1").expect("pr");
        let files = vec!["src/lib.rs".to_string()];
        let outcome = gh
            .publish_review(
                &pr,
                &PublishReviewParams {
                    expected_head_sha: "old_sha_111",
                    status: &ReviewStatus::ReviewedClean,
                    reviewed_files: &files,
                    skipped_files: &[],
                    inline_findings: &[],
                    fallback_findings: &[],
                    deduplicated_count: 0,
                    resolved_threads_count: 0,
                    model_name: "qwen2.5-coder:14b",
                    language: "es",
                    suggestions_enabled: true,
                },
            )
            .await
            .expect("publish call");

        assert!(matches!(outcome, PublishOutcome::AbortedStaleState { .. }));
    }

    #[tokio::test]
    async fn manages_check_run_lifecycle_and_processing_banner() {
        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/repos/meden2010/guardian/check-runs"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"id": 777})))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("PATCH"))
            .and(path("/repos/meden2010/guardian/check-runs/777"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": 777})))
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/repos/meden2010/guardian/issues/9/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/repos/meden2010/guardian/issues/9/comments"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"id": 888})))
            .expect(1)
            .mount(&server)
            .await;

        let gh = GitHubClient::new(server.uri(), "app_tok".into()).expect("gh init");
        let pr = PrRef::parse("meden2010/guardian#9").expect("pr");

        let check_id = gh.start_check_run(&pr, "sha_999", "es").await;
        assert_eq!(check_id, Some(777));

        gh.publish_processing_state(&pr, "es", None)
            .await
            .expect("processing banner posted");

        gh.complete_check_run(&pr, 777, "success", "Clean", "0 findings")
            .await;
    }

    #[tokio::test]
    async fn falls_back_to_summary_comment_on_http_422_and_edits_existing_marker() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/repos/meden2010/guardian/pulls/2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "state": "open",
                "draft": false,
                "title": "Test",
                "body": "",
                "head": {"sha": "sha_abc"},
                "base": {"sha": "sha_base"},
                "user": {"type": "User"},
                "labels": []
            })))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/repos/meden2010/guardian/pulls/2/reviews"))
            .respond_with(ResponseTemplate::new(422))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/repos/meden2010/guardian/issues/2/comments"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"id": 555, "body": "<!-- guardian:summary:v1 -->\nOld summary"}
            ])))
            .mount(&server)
            .await;

        Mock::given(method("PATCH"))
            .and(path("/repos/meden2010/guardian/issues/comments/555"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": 555})))
            .expect(1)
            .mount(&server)
            .await;

        let gh = GitHubClient::new(server.uri(), "test_tok".into()).expect("gh init");
        let pr = PrRef::parse("meden2010/guardian#2").expect("pr");
        let finding = ValidatedFinding {
            path: "src/lib.rs".into(),
            line: 10,
            also_at_lines: Vec::new(),
            fingerprint: compute_fingerprint("src/lib.rs", "a / b", FindingCategory::Bug),
            code_snippet: "a / b".into(),
            category: FindingCategory::Bug,
            severity: Severity::High,
            scenario: "When b == 0, division panics.".into(),
            message: "Check for zero divisor.".into(),
            suggestion: None,
        };

        let files = vec!["src/lib.rs".to_string()];
        let outcome = gh
            .publish_review(
                &pr,
                &PublishReviewParams {
                    expected_head_sha: "sha_abc",
                    status: &ReviewStatus::ReviewedWithFindings,
                    reviewed_files: &files,
                    skipped_files: &[],
                    inline_findings: &[finding],
                    fallback_findings: &[],
                    deduplicated_count: 0,
                    resolved_threads_count: 0,
                    model_name: "qwen2.5-coder:14b",
                    language: "es",
                    suggestions_enabled: true,
                },
            )
            .await
            .expect("422 fallback should succeed");

        assert_eq!(
            outcome,
            PublishOutcome::Published {
                inline_posted: 0,
                fallback_posted: 1
            }
        );
    }
}
