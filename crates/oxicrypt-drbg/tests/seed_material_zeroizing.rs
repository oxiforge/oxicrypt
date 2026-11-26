//! A byte-array scan of the HMAC_DRBG and CTR_DRBG source. These files
//! hold seed material, keys, `V`, and material derived from them in local
//! byte arrays. The scan requires each such local to be created already
//! wrapped, so its bytes are wiped when it drops, unless it is listed in
//! [`PUBLIC`] as public data. It reads the crate's own source and checks
//! every declaration outside the test modules.
//!
//! A `let` that starts its line is counted when its declared type is
//! `[u8; N]`, or its initialiser contains a `u8` array literal such as
//! `[0u8; N]`, starts with `self.v`, `self.key`, `*` or `Wiped::<`, or
//! contains `.finalize(` or `SeedDraw::new(`. A counted initialiser must
//! start with `Zeroizing::new(`, `oxicrypt_zeroize::Zeroizing::new(`,
//! `SeedDraw::new(`, the seed-draw type that wraps `Zeroizing`, or
//! `Wiped::<`, the generate temporary that wipes on drop. Two further
//! checks cover the source as a whole: no function returns `-> [u8;`, and
//! no `Zeroizing::new(self.` copies a state field.
//!
//! The scan cannot see an array literal with an inferred element type
//! (`[0; N]`), an array built by `core::array::from_fn`, a `let` that does
//! not start its line, an array passed or returned by value other than as
//! `-> [u8;`, or a `const` or `static` array.

/// Initialisers a counted declaration may start with.
const WRAPPED: &[&str] = &[
    "Zeroizing::new(",
    "oxicrypt_zeroize::Zeroizing::new(",
    "SeedDraw::new(",
    "Wiped::<",
];

/// Declarations of public byte arrays, exempt in one file only, by their
/// exact text and the text of the line after them: the HMAC_DRBG update
/// separators `0x00` and `0x01` (SP 800-90A §10.1.2.2), and the
/// Block_Cipher_df key `K = 00 01 02 ...` (SP 800-90A §10.3.2).
const PUBLIC: &[(&str, &str, &str)] = &[
    (
        "src/hmac.rs",
        "let sep0 = [0x00u8];",
        "let mut new_key = oxicrypt_zeroize::Zeroizing::new([0u8; MAX_OUTLEN]);",
    ),
    (
        "src/hmac.rs",
        "let sep1 = [0x01u8];",
        "let mut v_slice2 = Wiped::<MAX_OUTLEN>::new(WipedBuffer::HmacUpdateV);",
    ),
    (
        "src/ctr.rs",
        "let mut k = [0u8; MAX_KEY_LEN];",
        "for i in 0..F::KEY_LEN {",
    ),
];

/// Each scanned source file, its text, and the number of counted
/// declarations it holds outside [`PUBLIC`]. A count that changes means a
/// local was added, removed or renamed, and the scan is checked against
/// the new code.
const SOURCES: &[(&str, &str, usize)] = &[
    ("src/hmac.rs", include_str!("../src/hmac.rs"), 14),
    ("src/ctr.rs", include_str!("../src/ctr.rs"), 21),
];

/// The source before the first line that opens a test module with
/// `#[cfg(test)]` at the start of the line.
fn production(source: &str) -> &str {
    source
        .find("\n#[cfg(test)]")
        .map_or(source, |end| &source[..end])
}

/// The statement `text` starts with, through the first `;` outside
/// brackets, so the `;` of an array type or repeat expression does not end
/// it.
fn statement(text: &str) -> &str {
    let mut depth = 0_usize;
    for (i, byte) in text.bytes().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth = depth.saturating_add(1),
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b';' if depth == 0 => return &text[..=i],
            _ => {}
        }
    }
    text
}

/// Whether `text` contains an array literal whose first element is a
/// `u8`-suffixed integer, such as `[0u8; N]` or `[0x01u8]`.
fn has_byte_array_literal(text: &str) -> bool {
    text.match_indices('[').any(|(open, _)| {
        let rest = text[open..].trim_start_matches('[').trim_start();
        let token: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        token.starts_with(|c: char| c.is_ascii_digit()) && token.ends_with("u8")
    })
}

/// The type part and the initialiser of the `let` statement `text`, the
/// initialiser with leading whitespace removed.
fn split_let(text: &str) -> (&str, &str) {
    let (head, init) = text.split_once('=').unwrap_or((text, ""));
    (head, init.trim_start())
}

/// Whether the `let` statement `text` is counted.
fn is_counted(text: &str) -> bool {
    let (head, init) = split_let(text);
    head.contains("[u8;")
        || has_byte_array_literal(init)
        || init.starts_with("self.v")
        || init.starts_with("self.key")
        || init.starts_with('*')
        || init.starts_with("Wiped::<")
        || init.contains(".finalize(")
        || init.contains("SeedDraw::new(")
}

/// Whether the counted statement `text` creates its value already wrapped.
fn is_wrapped(text: &str) -> bool {
    let (_, init) = split_let(text);
    WRAPPED.iter().any(|prefix| init.starts_with(prefix))
}

/// Whether `text` at line `line` of `path` is a [`PUBLIC`] exemption: its
/// text matches, in the same file, and the next line matches too.
fn is_public(path: &str, source: &str, line: usize, text: &str) -> bool {
    let next = source.lines().nth(line).map(str::trim);
    PUBLIC
        .iter()
        .any(|&(file, exempt, after)| file == path && exempt == text && next == Some(after))
}

/// Each counted declaration in `source` outside [`PUBLIC`], as its
/// one-based line number and the statement text from `let` to the closing
/// `;`. Only a `let` that starts its line counts, so commented-out code and
/// doc examples do not.
fn declarations<'s>(path: &str, source: &'s str) -> Vec<(usize, &'s str)> {
    let mut found = Vec::new();
    for (start, _) in source.match_indices("let ") {
        let before = &source[..start];
        let line_start = before.rsplit('\n').next().unwrap_or(before);
        let text = statement(&source[start..]);
        let line = before.split('\n').count();
        if line_start.trim().is_empty() && is_counted(text) && !is_public(path, source, line, text)
        {
            found.push((line, text));
        }
    }
    found
}

/// The counted declarations in `source` whose initialiser does not start
/// with a wrapper.
fn unwrapped<'s>(path: &str, source: &'s str) -> Vec<(usize, &'s str)> {
    declarations(path, source)
        .into_iter()
        .filter(|&(_, text)| !is_wrapped(text))
        .collect()
}

/// The lines of `source` that contain `needle`, one-based.
fn lines_with<'s>(source: &'s str, needle: &str) -> Vec<(usize, &'s str)> {
    (1..)
        .zip(source.lines())
        .filter(|(_, line)| line.contains(needle))
        .collect()
}

#[test]
#[allow(
    clippy::print_stdout,
    reason = "the count checked is part of the result"
)]
fn byte_array_locals_are_zeroizing() {
    let mut checked = 0_usize;
    for &(path, source, expected) in SOURCES {
        let source = production(source);
        let plain = unwrapped(path, source);
        assert!(
            plain.is_empty(),
            "{path}: byte-array locals not created wrapped: {plain:#?}"
        );
        let by_value = lines_with(source, "-> [u8;");
        assert!(
            by_value.is_empty(),
            "{path}: functions returning a byte array by value: {by_value:#?}"
        );
        let field_copy = lines_with(source, "Zeroizing::new(self.");
        assert!(
            field_copy.is_empty(),
            "{path}: state fields copied into a wrapper: {field_copy:#?}"
        );
        let found = declarations(path, source);
        assert_eq!(found.len(), expected, "{path}: {found:#?}");
        checked = checked.saturating_add(found.len());
    }
    println!("byte-array locals checked: {checked}");
    assert!(checked > 0, "no byte-array local found");
    // Each exemption still matches exactly one line, in its own file and
    // before its pinned neighbour, so a stale one cannot hide a secret
    // buffer that took its text.
    for &(file, exempt, after) in PUBLIC {
        let matches: usize = SOURCES
            .iter()
            .filter(|&&(path, _, _)| path == file)
            .map(|&(path, source, _)| {
                let source = production(source);
                lines_with(source, exempt)
                    .into_iter()
                    .filter(|&(line, text)| is_public(path, source, line, text.trim()))
                    .count()
            })
            .sum();
        assert_eq!(matches, 1, "public exemption {exempt:?} before {after:?}");
    }
}

#[test]
fn scan_flags_an_unwrapped_local_and_passes_a_wrapped_one() {
    let source = "\
fn seed() {
    let mut seed_material = Zeroizing::new([0u8; MAX_DF_INPUT]);
    let mut provided = [0u8; MAX_SEED_LEN];
    let mut derived =
        Zeroizing::new([0u8; MAX_SEED_LEN]);
    // let mut derived = [0u8; MAX_SEED_LEN];
    let mut key: [u8; 32] = derive();
    let mut scratch = [0x5au8; 8];
    let tag = h.finalize()?;
    let v = self.v;
    let copy = *chaining;
    let mut draw = SeedDraw::new();
    let hidden = core::convert::identity(Zeroizing::new([0u8; 4]));
    let sep0 = [0x00u8];
    let empty: &[u8] = &[];
    let (next, carry) = v[i].overflowing_add(1);
    let mut provided_len = 0;
}
#[cfg(test)]
mod tests {
    fn fixture() {
        let mut derived = [0u8; 4];
    }
}
";
    let production = production(source);
    assert_eq!(declarations("fixture.rs", production).len(), 11);
    assert_eq!(
        unwrapped("fixture.rs", production),
        vec![
            (3, "let mut provided = [0u8; MAX_SEED_LEN];"),
            (7, "let mut key: [u8; 32] = derive();"),
            (8, "let mut scratch = [0x5au8; 8];"),
            (9, "let tag = h.finalize()?;"),
            (10, "let v = self.v;"),
            (11, "let copy = *chaining;"),
            (
                13,
                "let hidden = core::convert::identity(Zeroizing::new([0u8; 4]));"
            ),
            (14, "let sep0 = [0x00u8];"),
        ]
    );
}
