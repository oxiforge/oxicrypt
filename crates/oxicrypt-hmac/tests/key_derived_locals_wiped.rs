//! Every digest the HMAC construction computes on its way to the MAC, and
//! every padded-key array it builds, is key-derived. This scan reads the
//! crate's source outside its test module and requires each local bound to
//! a `block_finalize` result or to a `[0u8; N]` array to be either returned
//! as the function's tail expression or wiped with
//! `oxicrypt_zeroize::zeroize` on a straight-line path before its function
//! ends.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::print_stdout,
    clippy::indexing_slicing,
    reason = "a source scan over a file of known size, run only as a test"
)]

use std::fs;
use std::path::Path;

/// The production part of `source`: everything before the first
/// `#[cfg(test)]` line, which must introduce `mod tests`.
fn production(source: &str) -> &str {
    let lines: Vec<&str> = source.lines().collect();
    let Some(cfg) = lines
        .iter()
        .position(|l| l.trim_start().starts_with("#[cfg(test)]"))
    else {
        return source;
    };
    assert!(
        lines[cfg + 1..]
            .iter()
            .take(3)
            .any(|l| l.trim_start().starts_with("mod tests")),
        "the first #[cfg(test)] at line {} does not introduce `mod tests`; the scan would stop early",
        cfg + 1
    );
    let end: usize = lines[..cfg].iter().map(|l| l.len() + 1).sum();
    &source[..end.min(source.len())]
}

/// `(line, name)` for every `let [mut] <name> = <expr>.block_finalize(` and
/// every `let [mut] <name> = [0u8; …]` in the production source. A `let`
/// whose pattern is not a plain name fails the scan.
fn bindings(source: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (idx, line) in production(source).lines().enumerate() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("let ") else {
            continue;
        };
        let is_finalize = trimmed.contains(".block_finalize(");
        let is_array = trimmed.contains("= [0u8;");
        if !(is_finalize || is_array) {
            continue;
        }
        let rest = rest.strip_prefix("mut ").unwrap_or(rest);
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        assert!(
            !name.is_empty(),
            "line {}: a key-derived binding with a pattern the scan cannot name",
            idx + 1
        );
        out.push((idx + 1, name));
    }
    out
}

/// Every non-declaration occurrence of `block_finalize(` in the production
/// source, so a call the binding scan does not see is still counted.
fn finalize_calls(source: &str) -> usize {
    production(source)
        .lines()
        .filter(|l| l.contains("block_finalize(") && !l.trim_start().starts_with("fn "))
        .count()
}

/// The lines after `line` (one-based) up to the end of the enclosing
/// function: the first later line that is only a closing brace at an
/// indentation no deeper than the binding's enclosing `fn`.
fn rest_of_function(source: &str, line: usize) -> Vec<&str> {
    let lines: Vec<&str> = source.lines().collect();
    let fn_indent = lines[..line]
        .iter()
        .rev()
        .find(|l| l.trim_start().starts_with("pub fn ") || l.trim_start().starts_with("fn "))
        .map_or(0, |l| l.len() - l.trim_start().len());
    let mut body = Vec::new();
    for l in &lines[line..] {
        let indent = l.len() - l.trim_start().len();
        if l.trim() == "}" && indent <= fn_indent {
            break;
        }
        body.push(*l);
    }
    body
}

/// The bindings neither returned as the tail expression nor wiped on a
/// straight-line path (no `return` and no `?` between binding and wipe).
fn unwiped(source: &str) -> Vec<(usize, String)> {
    bindings(source)
        .into_iter()
        .filter(|(line, name)| {
            let body = rest_of_function(source, *line);
            let code: Vec<&str> = body
                .iter()
                .map(|l| l.trim())
                .filter(|l| !l.starts_with("//"))
                .collect();
            let wipe = format!("oxicrypt_zeroize::zeroize(&mut {name});");
            let wiped = code.iter().position(|l| **l == wipe).is_some_and(|at| {
                !code[..at]
                    .iter()
                    .any(|l| l.starts_with("return") || l.contains('?'))
            });
            let returned = code
                .iter()
                .rev()
                .find(|l| !l.is_empty())
                .is_some_and(|l| *l == name.as_str());
            !(wiped || returned)
        })
        .collect()
}

#[test]
fn every_key_derived_local_is_returned_or_wiped() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let source = fs::read_to_string(&path).expect("read src/lib.rs");
    let found = bindings(&source);
    println!("key-derived locals checked: {}", found.len());
    let finalizes = found
        .iter()
        .filter(|(line, _)| {
            source
                .lines()
                .nth(line - 1)
                .is_some_and(|l| l.contains(".block_finalize("))
        })
        .count();
    assert_eq!(
        finalizes,
        finalize_calls(&source),
        "a block_finalize call is not bound to a named local the scan can follow"
    );
    assert_eq!(
        found.len(),
        6,
        "the construction has three digests and three padded-key arrays"
    );
    let left = unwiped(&source);
    assert!(
        left.is_empty(),
        "key-derived locals neither returned nor wiped: {left:?}"
    );
}

#[test]
fn the_scan_flags_leaks_and_passes_wiped_or_returned_locals() {
    let fixture = "\
impl X {
    pub fn a(h: H) -> [u8; 32] {
        let mut d = h.block_finalize(s);
        use_it(&d);
        oxicrypt_zeroize::zeroize(&mut d);
        other()
    }
    pub fn b(h: H) -> [u8; 32] {
        let mac = h.block_finalize(s);
        mac
    }
    fn c(h: H) -> [u8; 32] {
        let leaked = h.block_finalize(s);
        use_it(&leaked);
        other()
    }
    fn d(h: H) {
        let mut leaked = h.block_finalize(s);
        oxicrypt_zeroize::zeroize(&mut leaked);
    }
    fn e(h: H) -> Result<(), E> {
        let mut early = h.block_finalize(s);
        may_fail()?;
        oxicrypt_zeroize::zeroize(&mut early);
        Ok(())
    }
    fn f() {
        let mut only_comment = [0u8; 64];
        // oxicrypt_zeroize::zeroize(&mut only_comment);
    }
    fn g() {
        let mut k = [0u8; 64];
        if x {
            oxicrypt_zeroize::zeroize(&mut k);
        }
    }
}
#[cfg(test)]
mod tests {
    fn t(h: H) {
        let ignored = h.block_finalize(s);
    }
}
";
    assert_eq!(bindings(fixture).len(), 7);
    assert_eq!(finalize_calls(fixture), 5);
    assert_eq!(
        unwiped(fixture),
        vec![
            (13, "leaked".to_string()),
            (22, "early".to_string()),
            (28, "only_comment".to_string()),
        ]
    );
}
