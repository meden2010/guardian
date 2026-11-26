//! Stable, line-number-independent SHA-256 fingerprints for cross-commit deduplication.

use sha2::{Digest, Sha256};

use crate::types::FindingCategory;

pub const FP_VERSION: &str = "v1";
const MARKER_PREFIX: &str = "<!-- guardian:fp=";
const MARKER_SUFFIX: &str = " -->";

/// Computes `v1:<64-hex-sha256>` over `normalized_path + "\n" + normalized_code + "\n" + category`.
///
/// Intentionally excludes line numbers so moving code up/down across commits preserves the hash,
/// and hashes the snippet so cleartext source code is never stored inside hidden markers.
pub fn compute_fingerprint(path: &str, code_snippet: &str, category: FindingCategory) -> String {
    let norm_path = path
        .trim()
        .trim_start_matches("b/")
        .trim_start_matches("./");
    let norm_code = normalize_code_for_fp(code_snippet);

    let mut hasher = Sha256::new();
    hasher.update(norm_path.as_bytes());
    hasher.update(b"\n");
    hasher.update(norm_code.as_bytes());
    hasher.update(b"\n");
    hasher.update(category.as_str().as_bytes());
    let digest = hasher.finalize();

    let mut hex = String::with_capacity(FP_VERSION.len() + 1 + 64);
    hex.push_str(FP_VERSION);
    hex.push(':');
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

/// Formats a fingerprint into an invisible HTML comment marker: `<!-- guardian:fp=v1:... -->`.
pub fn format_fp_marker(fingerprint: &str) -> String {
    format!("{MARKER_PREFIX}{fingerprint}{MARKER_SUFFIX}")
}

/// Extracts all `v1:...` (or future versioned) fingerprints from existing GitHub comment bodies.
pub fn extract_fingerprints(comment_body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = comment_body;

    while let Some(start) = rest.find(MARKER_PREFIX) {
        let after = &rest[start + MARKER_PREFIX.len()..];
        if let Some(end) = after.find(MARKER_SUFFIX) {
            let candidate = after[..end].trim();
            if is_valid_fp(candidate) {
                out.push(candidate.to_string());
            }
            rest = &after[end + MARKER_SUFFIX.len()..];
        } else {
            break;
        }
    }

    out
}

fn is_valid_fp(s: &str) -> bool {
    let Some((ver, hex)) = s.split_once(':') else {
        return false;
    };
    !ver.is_empty()
        && ver.bytes().all(|b| b.is_ascii_alphanumeric())
        && hex.len() >= 16
        && hex.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Collapses whitespace and strips trailing `guardian-ignore` directives so minor reformatting
/// does not alter the fingerprint.
pub fn normalize_code_for_fp(snippet: &str) -> String {
    snippet.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_across_indentation_and_line_shifts() {
        let fp1 = compute_fingerprint("src/billing.rs", "    let x = a / b;", FindingCategory::Bug);
        let fp2 = compute_fingerprint(
            "b/src/billing.rs",
            "\tlet   x = a / b;  ",
            FindingCategory::Bug,
        );
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("v1:"));
        assert_eq!(fp1.len(), 3 + 64);

        let fp_diff_cat = compute_fingerprint(
            "src/billing.rs",
            "let x = a / b;",
            FindingCategory::EdgeCase,
        );
        assert_ne!(fp1, fp_diff_cat);
    }

    #[test]
    fn roundtrips_markers_from_markdown_bodies() {
        let fp1 = compute_fingerprint("a.rs", "x / y", FindingCategory::Bug);
        let fp2 = compute_fingerprint("b.rs", "arr[i]", FindingCategory::EdgeCase);
        let body = format!(
            "{}\n> [!WARNING]\n> Bug here\nAlso fallback: {}",
            format_fp_marker(&fp1),
            format_fp_marker(&fp2)
        );
        let extracted = extract_fingerprints(&body);
        assert_eq!(extracted, vec![fp1, fp2]);
    }
}
