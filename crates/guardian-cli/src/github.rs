//! Lightweight GitHub REST adapter for fetching PR diffs, fingerprints, and publishing atomic reviews.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use guardian_core::filter::{format_inline_comment, format_pr_summary, SUMMARY_MARKER};
use guardian_core::fingerprint::extract_fingerprints;
use guardian_core::types::{PrMetadata, ReviewStatus, ValidatedFinding};
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Serialize};

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

    /// Reads existing PR review comments + issue comments and extracts all `<!-- guardian:fp=... -->` hashes.
    pub async fn fetch_existing_fingerprints(&self, pr: &PrRef) -> Result<HashSet<String>> {
        let mut fps = HashSet::new();

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
                        fps.insert(fp);
                    }
                }
            }
        }

        Ok(fps)
    }

    /// Atomically publishes inline review comments + upserts the single fixed summary comment.
    /// Re-verifies `state == "open"` and `head.sha` before posting, and falls back to summary on HTTP 422.
    #[allow(clippy::too_many_arguments)]
    pub async fn publish_review(
        &self,
        pr: &PrRef,
        expected_head_sha: &str,
        status: &ReviewStatus,
        reviewed_files: usize,
        inline_findings: &[ValidatedFinding],
        fallback_findings: &[ValidatedFinding],
        deduplicated_count: usize,
        model_name: &str,
        language: &str,
    ) -> Result<PublishOutcome> {
        let latest = self.fetch_pr(pr).await?;
        if latest.state != "open" {
            return Ok(PublishOutcome::AbortedStaleState {
                reason: format!("PR is now `{}`", latest.state),
            });
        }
        if latest.head.sha != expected_head_sha {
            return Ok(PublishOutcome::AbortedStaleState {
                reason: format!(
                    "PR head moved from `{expected_head_sha}` to `{}` during review",
                    latest.head.sha
                ),
            });
        }

        let mut combined_fallback: Vec<ValidatedFinding> = fallback_findings.to_vec();
        let mut inline_posted = 0usize;

        if !inline_findings.is_empty() {
            let comments: Vec<InlineReviewComment<'_>> = inline_findings
                .iter()
                .map(|f| InlineReviewComment {
                    path: &f.path,
                    line: f.line,
                    side: "RIGHT",
                    body: format_inline_comment(f, language),
                })
                .collect();

            let review_url = format!(
                "{}/repos/{}/{}/pulls/{}/reviews",
                self.api_base, pr.owner, pr.repo, pr.number
            );
            let payload = CreateReviewRequest {
                commit_id: expected_head_sha,
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
                inline_posted = inline_findings.len();
            } else if resp.status() == StatusCode::UNPROCESSABLE_ENTITY {
                tracing::warn!("GitHub rejected inline line positions (HTTP 422); routing findings to summary fallback");
                combined_fallback.extend_from_slice(inline_findings);
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

        let summary_md = format_pr_summary(
            status,
            reviewed_files,
            inline_posted,
            &combined_fallback,
            deduplicated_count,
            model_name,
            language,
        );
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
        assert!(fps.contains(&fp1));
        assert!(fps.contains(&fp2));
        assert_eq!(fps.len(), 2);
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
        let outcome = gh
            .publish_review(
                &pr,
                "old_sha_111",
                &ReviewStatus::ReviewedClean,
                1,
                &[],
                &[],
                0,
                "qwen2.5-coder:14b",
                "es",
            )
            .await
            .expect("publish call");

        assert!(matches!(outcome, PublishOutcome::AbortedStaleState { .. }));
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

        let outcome = gh
            .publish_review(
                &pr,
                "sha_abc",
                &ReviewStatus::ReviewedWithFindings,
                1,
                &[finding],
                &[],
                0,
                "qwen2.5-coder:14b",
                "es",
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
