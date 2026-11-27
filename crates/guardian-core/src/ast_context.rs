//! Tree-sitter AST intra-file context extractor for Rust, TypeScript/TSX, Python, and PHP.
//!
//! Operates strictly in memory on already-redacted source text (never executes PR code).

use tree_sitter::{Language, Node, Parser};

const MAX_IMPORT_LINES: usize = 25;
const MAX_SCOPE_LINES: usize = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupportedLanguage {
    Rust,
    TypeScript,
    Tsx,
    Python,
    Php,
}

impl SupportedLanguage {
    pub fn from_path(path: &str) -> Option<Self> {
        let ext = path.rsplit('.').next()?.to_ascii_lowercase();
        match ext.as_str() {
            "rs" => Some(Self::Rust),
            "ts" | "mts" | "cts" | "js" | "mjs" | "cjs" => Some(Self::TypeScript),
            "tsx" | "jsx" => Some(Self::Tsx),
            "py" => Some(Self::Python),
            "php" => Some(Self::Php),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::TypeScript => "typescript",
            Self::Tsx => "tsx",
            Self::Python => "python",
            Self::Php => "php",
        }
    }

    fn ts_language(self) -> Language {
        match self {
            Self::Rust => tree_sitter_rust::LANGUAGE.into(),
            Self::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
            Self::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
            Self::Python => tree_sitter_python::LANGUAGE.into(),
            Self::Php => tree_sitter_php::LANGUAGE_PHP.into(),
        }
    }

    fn is_import_node(self, kind: &str) -> bool {
        match self {
            Self::Rust => matches!(kind, "use_declaration" | "extern_crate_declaration"),
            Self::TypeScript | Self::Tsx => matches!(kind, "import_statement" | "import_alias"),
            Self::Python => matches!(kind, "import_statement" | "import_from_statement"),
            Self::Php => matches!(
                kind,
                "namespace_definition"
                    | "namespace_use_declaration"
                    | "require_expression"
                    | "require_once_expression"
                    | "include_expression"
                    | "include_once_expression"
            ),
        }
    }

    fn is_primary_scope(self, kind: &str) -> bool {
        match self {
            Self::Rust => matches!(kind, "function_item"),
            Self::TypeScript | Self::Tsx => matches!(
                kind,
                "function_declaration" | "method_definition" | "arrow_function"
            ),
            Self::Python => matches!(kind, "function_definition"),
            Self::Php => matches!(kind, "method_declaration" | "function_definition"),
        }
    }

    fn is_fallback_scope(self, kind: &str) -> bool {
        match self {
            Self::Rust => matches!(
                kind,
                "impl_item" | "struct_item" | "enum_item" | "trait_item"
            ),
            Self::TypeScript | Self::Tsx => matches!(
                kind,
                "class_declaration" | "interface_declaration" | "lexical_declaration"
            ),
            Self::Python => matches!(kind, "class_definition"),
            Self::Php => matches!(kind, "class_declaration" | "trait_declaration"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclosingScope {
    pub start_line: u32,
    pub end_line: u32,
    pub kind: String,
    pub numbered_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileContext {
    pub path: String,
    pub language: &'static str,
    pub imports: Vec<String>,
    pub scopes: Vec<EnclosingScope>,
}

/// Extracts top-level imports and enclosing function/class scopes around `changed_lines` (1-based).
pub fn extract_file_context(
    path: &str,
    redacted_source: &str,
    changed_lines: &[u32],
) -> Option<FileContext> {
    let lang = SupportedLanguage::from_path(path)?;
    if redacted_source.trim().is_empty() || changed_lines.is_empty() {
        return None;
    }

    let mut parser = Parser::new();
    parser.set_language(&lang.ts_language()).ok()?;
    let tree = parser.parse(redacted_source, None)?;
    let root = tree.root_node();

    let source_lines: Vec<&str> = redacted_source.lines().collect();
    if source_lines.is_empty() {
        return None;
    }

    let mut imports = Vec::new();
    collect_imports(root, lang, redacted_source, &mut imports);

    // Collect unique enclosing scopes for each changed line (1-based).
    let mut raw_ranges: Vec<(u32, u32, String)> = Vec::new();
    for &line_1based in changed_lines {
        if line_1based == 0 || (line_1based as usize) > source_lines.len() {
            continue;
        }
        let row = (line_1based - 1) as usize;
        if let Some(scope_node) = find_enclosing_scope(root, row, lang) {
            let start = scope_node.start_position().row as u32 + 1;
            let end = scope_node.end_position().row as u32 + 1;
            let kind = scope_node.kind().to_string();
            if !raw_ranges.iter().any(|(s, e, _)| *s <= start && *e >= end) {
                raw_ranges.push((start, end, kind));
            }
        }
    }

    raw_ranges.sort_by_key(|(s, _, _)| *s);
    raw_ranges.dedup_by(|a, b| a.0 == b.0 && a.1 == b.1);

    let mut scopes = Vec::new();
    for (start, end, kind) in raw_ranges {
        let (clamped_start, clamped_end) =
            clamp_scope_window(start, end, changed_lines, MAX_SCOPE_LINES as u32);
        let numbered_code = render_numbered_slice(&source_lines, clamped_start, clamped_end);
        scopes.push(EnclosingScope {
            start_line: clamped_start,
            end_line: clamped_end,
            kind,
            numbered_code,
        });
    }

    if imports.is_empty() && scopes.is_empty() {
        return None;
    }

    Some(FileContext {
        path: path.to_string(),
        language: lang.as_str(),
        imports,
        scopes,
    })
}

/// Renders extracted AST contexts into a compact prompt block.
pub fn render_contexts_for_prompt(contexts: &[FileContext]) -> String {
    let mut out = String::new();
    for ctx in contexts {
        out.push_str(&format!("=== File: {} ({}) ===\n", ctx.path, ctx.language));
        if !ctx.imports.is_empty() {
            out.push_str("-- Imports --\n");
            for imp in &ctx.imports {
                out.push_str(imp);
                out.push('\n');
            }
        }
        for scope in &ctx.scopes {
            out.push_str(&format!(
                "-- Enclosing {} (lines {}-{}) --\n",
                scope.kind, scope.start_line, scope.end_line
            ));
            out.push_str(&scope.numbered_code);
        }
        out.push('\n');
    }
    out
}

fn collect_imports(
    node: Node<'_>,
    lang: SupportedLanguage,
    source: &str,
    imports: &mut Vec<String>,
) {
    if imports.len() >= MAX_IMPORT_LINES {
        return;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if imports.len() >= MAX_IMPORT_LINES {
            break;
        }
        if lang.is_import_node(child.kind()) {
            if let Ok(text) = child.utf8_text(source.as_bytes()) {
                let first_line = text.trim().lines().next().unwrap_or("").trim();
                if !first_line.is_empty() {
                    imports.push(first_line.to_string());
                }
            }
        } else if lang == SupportedLanguage::Php && child.kind() == "program" {
            collect_imports(child, lang, source, imports);
        }
    }
}

fn find_enclosing_scope<'a>(
    root: Node<'a>,
    row_0based: usize,
    lang: SupportedLanguage,
) -> Option<Node<'a>> {
    let point = tree_sitter::Point {
        row: row_0based,
        column: 0,
    };
    let mut current = root.descendant_for_point_range(point, point)?;
    let mut fallback: Option<Node<'a>> = None;

    loop {
        let kind = current.kind();
        if lang.is_primary_scope(kind) {
            // For TypeScript `const foo = (...) => { ... }`, prefer the parent declaration if present.
            if kind == "arrow_function" {
                if let Some(p) = current.parent() {
                    if let Some(gp) = p.parent() {
                        if gp.kind() == "lexical_declaration" || gp.kind() == "export_statement" {
                            return Some(gp);
                        }
                    }
                }
            }
            return Some(current);
        }
        if fallback.is_none() && lang.is_fallback_scope(kind) {
            fallback = Some(current);
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => return fallback,
        }
    }
}

fn clamp_scope_window(start: u32, end: u32, changed_lines: &[u32], max_lines: u32) -> (u32, u32) {
    if end.saturating_sub(start) < max_lines {
        return (start, end);
    }
    let focus = changed_lines
        .iter()
        .copied()
        .find(|&ln| ln >= start && ln <= end)
        .unwrap_or(start);
    let half = max_lines / 2;
    let win_start = focus.saturating_sub(half).max(start);
    let win_end = (win_start + max_lines - 1).min(end);
    (win_start, win_end)
}

fn render_numbered_slice(lines: &[&str], start_1based: u32, end_1based: u32) -> String {
    let mut out = String::new();
    let start_idx = start_1based.saturating_sub(1) as usize;
    let end_idx = (end_1based as usize).min(lines.len());
    for (offset, line) in lines[start_idx..end_idx].iter().enumerate() {
        let ln = start_1based + offset as u32;
        out.push_str(&format!("{ln:>5} | {line}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_typescript_imports_and_enclosing_function() {
        let src = "\
import { Invoice } from './types';

export function splitAmount(total: number, seats: number): number {
  if (seats <= 0) {
    return 0;
  }
  const adjusted = total - 10;
  return adjusted / seats;
}
";
        let ctx = extract_file_context("src/billing.ts", src, &[8]).expect("ts context");
        assert_eq!(ctx.language, "typescript");
        assert_eq!(ctx.imports, vec!["import { Invoice } from './types';"]);
        assert_eq!(ctx.scopes.len(), 1);
        assert_eq!(ctx.scopes[0].start_line, 3);
        assert!(ctx.scopes[0].numbered_code.contains("if (seats <= 0)"));
    }

    #[test]
    fn extracts_rust_use_and_function_item() {
        let src = "\
use std::collections::HashMap;

pub fn safe_div(a: i64, b: i64) -> Option<i64> {
    if b == 0 {
        return None;
    }
    Some(a / b)
}
";
        let ctx = extract_file_context("src/math.rs", src, &[7]).expect("rust context");
        assert_eq!(ctx.language, "rust");
        assert_eq!(ctx.imports, vec!["use std::collections::HashMap;"]);
        assert_eq!(ctx.scopes.len(), 1);
        assert!(ctx.scopes[0].numbered_code.contains("if b == 0"));
    }

    #[test]
    fn extracts_python_imports_and_function_definition() {
        let src = "\
from decimal import Decimal

def unit_price(total: Decimal, qty: int) -> Decimal:
    if qty <= 0:
        raise ValueError('invalid qty')
    return total / qty
";
        let ctx = extract_file_context("src/pricing.py", src, &[6]).expect("py context");
        assert_eq!(ctx.language, "python");
        assert_eq!(ctx.imports, vec!["from decimal import Decimal"]);
        assert_eq!(ctx.scopes.len(), 1);
        assert!(ctx.scopes[0].numbered_code.contains("if qty <= 0:"));
    }

    #[test]
    fn extracts_php_namespace_use_and_method() {
        let src = "\
<?php
namespace App\\Services;

use App\\Models\\Order;

class BillingService {
    public function split(float $total, int $seats): float {
        if ($seats <= 0) {
            return 0.0;
        }
        return $total / $seats;
    }
}
";
        let ctx = extract_file_context("app/Services/BillingService.php", src, &[11])
            .expect("php context");
        assert_eq!(ctx.language, "php");
        assert!(ctx
            .imports
            .iter()
            .any(|i| i.contains("use App\\Models\\Order;")));
        assert_eq!(ctx.scopes.len(), 1);
        assert!(ctx.scopes[0].numbered_code.contains("if ($seats <= 0)"));
    }
}
