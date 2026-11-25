//! Conservative secret redaction applied before prompting and before Stage 1 validation.

const PEM_BEGIN: &str = "-----BEGIN ";
const PEM_END: &str = "-----END ";

const KNOWN_TOKEN_PREFIXES: &[(&str, &str)] = &[
    ("github_pat_", "github_token"),
    ("ghp_", "github_token"),
    ("gho_", "github_token"),
    ("ghs_", "github_token"),
    ("ghu_", "github_token"),
    ("sk-ant-", "anthropic_key"),
    ("sk-proj-", "openai_key"),
    ("sk-", "api_key"),
    ("AKIA", "aws_access_key"),
    ("AIza", "google_api_key"),
    ("xoxb-", "slack_token"),
    ("xoxp-", "slack_token"),
];

/// Redacts conservative secret patterns from text, replacing matches with `[REDACTED:<kind>]`.
pub fn redact_secrets(input: &str) -> String {
    let without_pem = redact_pem_blocks(input);
    let mut out = String::with_capacity(without_pem.len());

    for (idx, line) in without_pem.split('\n').enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(&redact_line(line));
    }

    out
}

fn redact_pem_blocks(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(start) = rest.find(PEM_BEGIN) {
        result.push_str(&rest[..start]);
        let after_start = &rest[start..];
        let header_end = after_start.find('\n').unwrap_or(after_start.len());
        let header = &after_start[..header_end];

        if header.contains("PRIVATE KEY-----") {
            if let Some(end_idx) = after_start.find(PEM_END) {
                let tail = &after_start[end_idx..];
                let end_line_len = tail.find('\n').unwrap_or(tail.len());
                result.push_str("[REDACTED:private_key]");
                rest = &tail[end_line_len..];
                continue;
            }
        }

        result.push_str(header);
        rest = &after_start[header_end..];
    }

    result.push_str(rest);
    result
}

fn redact_line(line: &str) -> String {
    let mut current = redact_known_prefixes(line);
    current = redact_jwts(&current);
    redact_secret_assignments(&current)
}

fn is_token_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

fn redact_known_prefixes(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;

    while i < bytes.len() {
        let slice = &line[i..];
        let prev_is_token = i > 0 && is_token_char(bytes[i - 1]);

        let mut matched = None;
        if !prev_is_token {
            for &(prefix, label) in KNOWN_TOKEN_PREFIXES {
                if slice.starts_with(prefix) {
                    let mut end = prefix.len();
                    while i + end < bytes.len() && is_token_char(bytes[i + end]) {
                        end += 1;
                    }
                    let min_len = if prefix == "AKIA" {
                        16
                    } else {
                        prefix.len() + 12
                    };
                    if end >= min_len {
                        matched = Some((end, label));
                        break;
                    }
                }
            }
        }

        if let Some((len, label)) = matched {
            out.push_str("[REDACTED:");
            out.push_str(label);
            out.push(']');
            i += len;
        } else {
            let ch = slice.chars().next().unwrap_or('\0');
            out.push(ch);
            i += ch.len_utf8();
        }
    }

    out
}

fn is_b64url_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn redact_jwts(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut i = 0;

    while i < bytes.len() {
        let slice = &line[i..];
        let prev_is_b64 = i > 0 && is_b64url_char(bytes[i - 1]);
        if !prev_is_b64 && slice.starts_with("eyJ") {
            let mut end = 0;
            while i + end < bytes.len()
                && (is_b64url_char(bytes[i + end]) || bytes[i + end] == b'.')
            {
                end += 1;
            }
            let candidate = &slice[..end];
            let parts: Vec<&str> = candidate.split('.').collect();
            if parts.len() == 3
                && parts[0].len() >= 8
                && parts[1].len() >= 10
                && parts[2].len() >= 10
            {
                out.push_str("[REDACTED:jwt]");
                i += end;
                continue;
            }
        }

        let ch = slice.chars().next().unwrap_or('\0');
        out.push(ch);
        i += ch.len_utf8();
    }

    out
}

fn redact_secret_assignments(line: &str) -> String {
    let lower = line.to_ascii_lowercase();
    let sensitive_names = [
        "api_key",
        "apikey",
        "secret",
        "password",
        "passwd",
        "access_token",
        "auth_token",
    ];
    if !sensitive_names.iter().any(|k| lower.contains(k)) {
        return line.to_string();
    }

    // Look for quoted literal values `= "..."` or `: '...'` of length >= 16 without spaces.
    for quote in ['"', '\''] {
        if let Some(eq_pos) = line.find(['=', ':']) {
            let rhs = &line[eq_pos + 1..];
            if let Some(q1_rel) = rhs.find(quote) {
                let after_q1 = &rhs[q1_rel + 1..];
                if let Some(q2_rel) = after_q1.find(quote) {
                    let val = &after_q1[..q2_rel];
                    if val.len() >= 16
                        && !val.contains(' ')
                        && !val.starts_with("[REDACTED:")
                        && has_mixed_entropy(val)
                    {
                        let val_start = eq_pos + 1 + q1_rel + 1;
                        let val_end = val_start + q2_rel;
                        let mut redacted = String::with_capacity(line.len());
                        redacted.push_str(&line[..val_start]);
                        redacted.push_str("[REDACTED:secret]");
                        redacted.push_str(&line[val_end..]);
                        return redacted;
                    }
                }
            }
        }
    }

    line.to_string()
}

fn has_mixed_entropy(val: &str) -> bool {
    let has_digit = val.bytes().any(|b| b.is_ascii_digit());
    let has_upper = val.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = val.bytes().any(|b| b.is_ascii_lowercase());
    (has_digit && (has_upper || has_lower)) || (has_upper && has_lower && val.len() >= 24)
}

#[cfg(test)]
mod tests {
    use super::redact_secrets;

    #[test]
    fn redacts_github_and_openai_tokens() {
        let raw = "const t = \"ghp_1234567890abcdef1234567890abcdef1234\";\nlet k = \"sk-proj-abcdef1234567890abcdef\";";
        let out = redact_secrets(raw);
        assert!(out.contains("[REDACTED:github_token]"));
        assert!(out.contains("[REDACTED:openai_key]"));
        assert!(!out.contains("ghp_1234"));
        assert!(!out.contains("sk-proj-"));
    }

    #[test]
    fn redacts_pem_private_key() {
        let raw = "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\nafter";
        let out = redact_secrets(raw);
        assert_eq!(out, "before\n[REDACTED:private_key]\nafter");
    }

    #[test]
    fn redacts_jwt_and_secret_assignment() {
        let jwt = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIzNDU2";
        assert_eq!(redact_secrets(jwt), "Bearer [REDACTED:jwt]");

        let assign = "const api_key = \"Abcdef1234567890ZYXW\";";
        assert_eq!(
            redact_secrets(assign),
            "const api_key = \"[REDACTED:secret]\";"
        );
    }
}
