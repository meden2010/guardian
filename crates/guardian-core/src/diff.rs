//! Unified diff parser, path filter, and deterministic line/snippet lookup.

use crate::types::{ReviewConfig, SkipFileReason};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffLineKind {
    Context,
    Added,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffLine {
    pub kind: DiffLineKind,
    pub old_lineno: Option<u32>,
    pub new_lineno: Option<u32>,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hunk {
    pub header: String,
    pub old_start: u32,
    pub new_start: u32,
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileDiff {
    pub path: String,
    pub hunks: Vec<Hunk>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedDiff {
    pub files: Vec<FileDiff>,
    pub skipped_files: Vec<(String, SkipFileReason)>,
}

/// Outcome of validating a finding's `(path, line, code_snippet)` against the parsed diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffMatch {
    /// Matched a `RIGHT`-side line (`+` or context) inside a hunk; can be posted as an inline PR comment.
    Inline {
        resolved_line: u32,
        line_content: String,
        is_added: bool,
    },
    /// Matched a removed (`-`) line in the hunk; valid finding, but route to PR summary fallback.
    FallbackRemovedLine { line_content: String },
    /// File path is not in the reviewed diff.
    PathNotFound,
    /// Snippet does not match real diff content near the cited line.
    SnippetMismatch,
}

const LOCKFILES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "uv.lock",
    "poetry.lock",
    "Gemfile.lock",
    "composer.lock",
    "go.sum",
];

/// Parses a unified diff, applying path exclusions and `max_files` cap.
pub fn parse_unified_diff(raw_diff: &str, config: &ReviewConfig) -> ParsedDiff {
    let mut parsed = ParsedDiff::default();
    let chunks = split_file_sections(raw_diff);

    for chunk in chunks {
        let Some((path, is_binary)) = extract_file_metadata(&chunk) else {
            continue;
        };

        if is_binary {
            parsed.skipped_files.push((path, SkipFileReason::Binary));
            continue;
        }
        if let Some(reason) = classify_excluded_path(&path, &config.ignore_paths) {
            parsed.skipped_files.push((path, reason));
            continue;
        }
        if parsed.files.len() >= config.max_files {
            parsed
                .skipped_files
                .push((path, SkipFileReason::OverMaxFiles));
            continue;
        }

        let hunks = parse_hunks(&chunk);
        if !hunks.is_empty() {
            parsed.files.push(FileDiff { path, hunks });
        }
    }

    parsed
}

impl ParsedDiff {
    /// Renders the kept diff with explicit right-side line numbers so the LLM cites exact lines.
    pub fn render_for_prompt(&self) -> String {
        let mut out = String::new();
        for file in &self.files {
            out.push_str("--- a/");
            out.push_str(&file.path);
            out.push('\n');
            out.push_str("+++ b/");
            out.push_str(&file.path);
            out.push('\n');
            for hunk in &file.hunks {
                out.push_str(&hunk.header);
                out.push('\n');
                for line in &hunk.lines {
                    match (line.kind, line.new_lineno) {
                        (DiffLineKind::Added, Some(n)) => {
                            out.push_str(&format!("{n:>5} | +{}\n", line.content));
                        }
                        (DiffLineKind::Context, Some(n)) => {
                            out.push_str(&format!("{n:>5} |  {}\n", line.content));
                        }
                        (DiffLineKind::Removed, _) => {
                            out.push_str(&format!("      | -{}\n", line.content));
                        }
                        _ => {}
                    }
                }
            }
        }
        out
    }

    /// Deterministically validates `(path, line, code_snippet)` against the parsed diff.
    pub fn validate_finding(&self, path: &str, line: u32, code_snippet: &str) -> DiffMatch {
        let normalized_path = path.trim_start_matches("b/").trim_start_matches("./");
        let Some(file) = self.files.iter().find(|f| f.path == normalized_path) else {
            return DiffMatch::PathNotFound;
        };

        let needle = normalize_ws(code_snippet);
        if needle.is_empty() {
            return DiffMatch::SnippetMismatch;
        }

        // 1. Check exact line or +/- 2 tolerance on RIGHT-side lines (`Added` / `Context`).
        let mut best_inline: Option<(u32, &DiffLine)> = None;
        for hunk in &file.hunks {
            for dline in &hunk.lines {
                if let Some(new_ln) = dline.new_lineno {
                    let dist = new_ln.abs_diff(line);
                    if dist <= 2 && snippet_matches(&dline.content, &needle) {
                        match best_inline {
                            None => best_inline = Some((dist, dline)),
                            Some((best_dist, _)) if dist < best_dist => {
                                best_inline = Some((dist, dline));
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        if let Some((_, dline)) = best_inline {
            return DiffMatch::Inline {
                resolved_line: dline.new_lineno.unwrap_or(line),
                line_content: dline.content.clone(),
                is_added: dline.kind == DiffLineKind::Added,
            };
        }

        // 2. If snippet uniquely matches a RIGHT-side line anywhere in the file's hunks, snap to it.
        let all_right_matches: Vec<&DiffLine> = file
            .hunks
            .iter()
            .flat_map(|h| h.lines.iter())
            .filter(|dl| dl.new_lineno.is_some() && snippet_matches(&dl.content, &needle))
            .collect();
        if all_right_matches.len() == 1 {
            let dline = all_right_matches[0];
            return DiffMatch::Inline {
                resolved_line: dline.new_lineno.unwrap_or(line),
                line_content: dline.content.clone(),
                is_added: dline.kind == DiffLineKind::Added,
            };
        }

        // 3. Check if snippet matches a removed (`-`) line in the diff -> summary fallback.
        for hunk in &file.hunks {
            for dline in &hunk.lines {
                if dline.kind == DiffLineKind::Removed && snippet_matches(&dline.content, &needle) {
                    return DiffMatch::FallbackRemovedLine {
                        line_content: dline.content.clone(),
                    };
                }
            }
        }

        DiffMatch::SnippetMismatch
    }
}

fn snippet_matches(line_content: &str, normalized_snippet: &str) -> bool {
    let norm_line = normalize_ws(line_content);
    if norm_line.is_empty() {
        return false;
    }
    // Support multi-line snippets by checking the first non-empty line as well.
    let first_snippet_line = normalized_snippet
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or(normalized_snippet);

    norm_line.contains(first_snippet_line) || first_snippet_line.contains(&norm_line)
}

fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn split_file_sections(raw_diff: &str) -> Vec<String> {
    let mut sections = Vec::new();
    let mut current = String::new();

    for line in raw_diff.lines() {
        if line.starts_with("diff --git ") {
            if !current.trim().is_empty() {
                sections.push(current);
                current = String::new();
            }
        } else if line.starts_with("--- ") && current.contains("\n@@ ") {
            sections.push(current);
            current = String::new();
        }
        current.push_str(line);
        current.push('\n');
    }
    if !current.trim().is_empty() {
        sections.push(current);
    }
    sections
}

fn extract_file_metadata(chunk: &str) -> Option<(String, bool)> {
    let mut is_binary = false;
    let mut plus_path: Option<String> = None;
    let mut git_header_path: Option<String> = None;

    for line in chunk.lines() {
        if line.starts_with("Binary files ") || line.starts_with("GIT binary patch") {
            is_binary = true;
        } else if let Some(rest) = line.strip_prefix("diff --git ") {
            if let Some((_, b_part)) = rest.rsplit_once(" b/") {
                git_header_path = Some(b_part.trim().to_string());
            }
        } else if let Some(rest) = line.strip_prefix("+++ ") {
            let trimmed = rest.trim();
            if trimmed == "/dev/null" {
                // Deleted file — skip in v0.1 unless needed; no RIGHT lines exist anyway.
                return None;
            }
            let clean = trimmed.strip_prefix("b/").unwrap_or(trimmed);
            plus_path = Some(clean.to_string());
        }
    }

    plus_path.or(git_header_path).map(|p| (p, is_binary))
}

fn classify_excluded_path(path: &str, ignore_paths: &[String]) -> Option<SkipFileReason> {
    let file_name = path.rsplit('/').next().unwrap_or(path);

    if LOCKFILES.contains(&file_name) {
        return Some(SkipFileReason::Lockfile);
    }

    if is_sensitive_path(path, file_name) {
        return Some(SkipFileReason::SensitivePath);
    }

    if is_generated_path(path, file_name) {
        return Some(SkipFileReason::Generated);
    }

    if ignore_paths
        .iter()
        .any(|pat| matches_simple_glob(pat, path))
    {
        return Some(SkipFileReason::ConfiguredIgnore);
    }

    None
}

fn is_sensitive_path(path: &str, file_name: &str) -> bool {
    if file_name == ".env.example" || file_name == ".env.sample" {
        return false;
    }
    file_name == ".env"
        || file_name.starts_with(".env.")
        || file_name.ends_with(".pem")
        || file_name.ends_with(".key")
        || file_name.starts_with("id_rsa")
        || file_name.starts_with("id_ed25519")
        || file_name.ends_with(".tfstate")
        || path.starts_with("secrets/")
        || path.contains("/secrets/")
}

fn is_generated_path(path: &str, file_name: &str) -> bool {
    path.starts_with("dist/")
        || path.contains("/dist/")
        || path.starts_with("build/")
        || path.contains("/build/")
        || path.starts_with("vendor/")
        || path.contains("/vendor/")
        || path.contains("/generated/")
        || file_name.ends_with(".min.js")
        || file_name.ends_with(".min.css")
        || file_name.ends_with(".pb.go")
}

fn matches_simple_glob(pattern: &str, path: &str) -> bool {
    let pat = pattern.trim_start_matches("**/").trim_end_matches("/**");
    if pat.is_empty() {
        return false;
    }
    path == pat || path.starts_with(&format!("{pat}/")) || path.contains(pat)
}

fn parse_hunks(chunk: &str) -> Vec<Hunk> {
    let mut hunks = Vec::new();
    let mut current: Option<Hunk> = None;
    let mut old_ln = 0u32;
    let mut new_ln = 0u32;

    for line in chunk.lines() {
        if line.starts_with("@@ ") {
            if let Some(h) = current.take() {
                hunks.push(h);
            }
            let (old_start, new_start) = parse_hunk_header(line).unwrap_or((1, 1));
            old_ln = old_start;
            new_ln = new_start;
            current = Some(Hunk {
                header: line.to_string(),
                old_start,
                new_start,
                lines: Vec::new(),
            });
            continue;
        }

        let Some(hunk) = current.as_mut() else {
            continue;
        };

        if line.starts_with("\\ No newline at end of file") {
            continue;
        } else if let Some(added) = line.strip_prefix('+') {
            hunk.lines.push(DiffLine {
                kind: DiffLineKind::Added,
                old_lineno: None,
                new_lineno: Some(new_ln),
                content: added.to_string(),
            });
            new_ln += 1;
        } else if let Some(removed) = line.strip_prefix('-') {
            hunk.lines.push(DiffLine {
                kind: DiffLineKind::Removed,
                old_lineno: Some(old_ln),
                new_lineno: None,
                content: removed.to_string(),
            });
            old_ln += 1;
        } else {
            let ctx = line.strip_prefix(' ').unwrap_or(line);
            hunk.lines.push(DiffLine {
                kind: DiffLineKind::Context,
                old_lineno: Some(old_ln),
                new_lineno: Some(new_ln),
                content: ctx.to_string(),
            });
            old_ln += 1;
            new_ln += 1;
        }
    }

    if let Some(h) = current {
        hunks.push(h);
    }
    hunks
}

fn parse_hunk_header(header: &str) -> Option<(u32, u32)> {
    // Format: @@ -old_start[,old_count] +new_start[,new_count] @@
    let body = header.strip_prefix("@@ ")?;
    let (ranges, _) = body.split_once(" @@")?;
    let (old_part, new_part) = ranges.split_once(' ')?;
    let old_start = old_part
        .strip_prefix('-')?
        .split(',')
        .next()?
        .parse::<u32>()
        .ok()?;
    let new_start = new_part
        .strip_prefix('+')?
        .split(',')
        .next()?
        .parse::<u32>()
        .ok()?;
    Some((old_start, new_start))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DIFF: &str = "\
diff --git a/Cargo.lock b/Cargo.lock
--- a/Cargo.lock
+++ b/Cargo.lock
@@ -1,2 +1,3 @@
+version = 3
diff --git a/.env.production b/.env.production
--- a/.env.production
+++ b/.env.production
@@ -1 +1 @@
+SECRET=123
diff --git a/src/math.rs b/src/math.rs
--- a/src/math.rs
+++ b/src/math.rs
@@ -10,4 +10,5 @@
 pub fn avg(items: &[i64]) -> i64 {
     let sum: i64 = items.iter().sum();
-    sum / items.len().max(1) as i64
+    sum / items.len() as i64
+    // computed
 }
";

    #[test]
    fn filters_lockfiles_and_sensitive_paths_and_parses_lines() {
        let parsed = parse_unified_diff(SAMPLE_DIFF, &ReviewConfig::default());
        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].path, "src/math.rs");
        assert_eq!(parsed.skipped_files.len(), 2);

        let m = parsed.validate_finding("src/math.rs", 12, "sum / items.len() as i64");
        assert_eq!(
            m,
            DiffMatch::Inline {
                resolved_line: 12,
                line_content: "    sum / items.len() as i64".to_string(),
                is_added: true,
            }
        );

        assert_eq!(
            parsed.validate_finding("src/other.rs", 12, "sum"),
            DiffMatch::PathNotFound
        );
        assert_eq!(
            parsed.validate_finding("src/math.rs", 12, "invented_hallucinated_call()"),
            DiffMatch::SnippetMismatch
        );
    }
}
