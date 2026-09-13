//! The stylesheet is one file that every page shares, so a selector written
//! twice is a rule that silently loses to its later twin. The forms once
//! vanished that way: `.stack` named a form column and, further down, a
//! six-pixel bar. Every rule is declared once.

const STYLE: &str = include_str!("../../../server/src/web/style.css");

/// Top-level selectors and the at-rule scope they sit in, one entry per
/// selector in a comma-separated list. Declarations are skipped, comments
/// are ignored, and at-rules (`@media`, `@keyframes`) open a scope of their
/// own so a narrow-screen override of `.trow` is not a duplicate of `.trow`.
fn selectors(css: &str) -> Vec<(Vec<String>, String)> {
    let mut out = Vec::new();
    let mut scope: Vec<String> = Vec::new();
    let mut head = String::new();
    let mut chars = css.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if c == '/' && css[i..].starts_with("/*") {
            let end = css[i..].find("*/").map(|n| i + n + 2).unwrap_or(css.len());
            while let Some(&(j, _)) = chars.peek() {
                if j >= end {
                    break;
                }
                chars.next();
            }
            continue;
        }
        match c {
            '{' => {
                let text = head.split_whitespace().collect::<Vec<_>>().join(" ");
                head.clear();
                if text.starts_with('@') {
                    scope.push(text);
                    continue;
                }
                for sel in text.split(',') {
                    let sel = sel.split_whitespace().collect::<Vec<_>>().join(" ");
                    if !sel.is_empty() {
                        out.push((scope.clone(), sel));
                    }
                }
                // Declarations never contain a brace; skip to the rule's end.
                for (_, d) in chars.by_ref() {
                    if d == '}' {
                        break;
                    }
                }
            }
            '}' => {
                scope.pop();
                head.clear();
            }
            _ => head.push(c),
        }
    }
    out
}

#[test]
fn every_selector_is_declared_once() {
    let mut seen = std::collections::HashSet::new();
    let mut twice = Vec::new();
    for (scope, sel) in selectors(STYLE) {
        if !seen.insert((scope.clone(), sel.clone())) {
            twice.push(match scope.last() {
                Some(at) => format!("{sel} (inside {at})"),
                None => sel,
            });
        }
    }
    assert!(
        twice.is_empty(),
        "declared more than once, so one copy silently loses: {}",
        twice.join(", ")
    );
}

#[test]
fn the_parser_sees_scopes_and_lists() {
    let css = "/* a { */ .a, .b { color: red } @media (x) { .a { color: blue } } .c{}";
    let got = selectors(css);
    assert_eq!(got[0], (vec![], ".a".to_string()));
    assert_eq!(got[1], (vec![], ".b".to_string()));
    assert_eq!(got[2], (vec!["@media (x)".to_string()], ".a".to_string()));
    assert_eq!(got[3], (vec![], ".c".to_string()));
}
