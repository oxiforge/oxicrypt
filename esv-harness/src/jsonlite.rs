//! A small, lossless JSON reader for ESV **response** bodies.
//!
//! # Why a second reader?
//!
//! The workspace's shared [`acvp_harness::json`] codec is deliberately
//! integer-only — it rejects any fractional or scientific-notation number
//! (that constraint is correct for ACVP vector sets and for every ESV
//! *request* this harness builds, where all numbers are integers). But one
//! ESV *response* carries floats: the `Run Successful` data-file assessment
//! (min-entropy values like `0.7275`, and NIST may emit them in e-notation).
//! Reading the `status` / `id` fields out of that body with the integer-only
//! codec is impossible.
//!
//! An earlier revision worked around this with a `neutralize_fractionals`
//! textual pre-pass that stripped the fractional part of every number before
//! handing the mangled copy to the integer-only codec. An adversarial review
//! refuted that *design*, not merely its bugs: a byte-level rewrite that has
//! to track JSON string state to avoid touching decimals inside strings is
//! exactly a JSON parser, only one that silently corrupts its input and
//! cannot see e-notation (`1.2e-05` → `1e-05`, still unparseable) or reject
//! malformed numerals (`1.2.3` sailed straight through). This module replaces
//! that pre-pass with a real parser.
//!
//! # What it is
//!
//! A complete recursive-descent JSON reader (RFC 8259 grammar: objects,
//! arrays, strings with the full escape set including `\uXXXX` surrogate
//! pairs, `true`/`false`/`null`, and numbers with the *complete* int / frac /
//! exponent grammar) with one deliberate departure from a normalizing parser:
//! **numbers are captured as their raw source token** ([`JsonLite::Number`]
//! holds the exact `&str` slice, owned) and are **never** interpreted as any
//! numeric type. So `0.7275`, `1.2e-05`, and `-3` all round-trip byte-for-byte
//! while remaining fully parseable. Reading a status/id field is exact and
//! lossless; a float value is preserved verbatim if it is ever surfaced.
//!
//! It is strict where it must be — an invalid numeral (`1.2.3`, a bare
//! exponent `1e`, a leading zero `01`), trailing garbage after the value, an
//! unterminated string, or a truncated body are all typed parse errors, never
//! silently promoted — and it has a bounded recursion depth so a hostile
//! deeply-nested body fails typed rather than exhausting the stack.
//!
//! Zero third-party dependencies (workspace policy); it does not touch the
//! proven [`acvp_harness::json`] codec, which every float-free ESV
//! request/response path keeps using.

use core::fmt;

/// Maximum array/object nesting depth before [`ParseError::DepthExceeded`].
///
/// A `Run Successful` assessment nests only a few levels; 64 is a
/// conservative ceiling that fails a hostile deeply-nested body typed rather
/// than risking stack exhaustion.
pub const MAX_DEPTH: usize = 64;

/// A decoded JSON value, with numbers kept as their raw source token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonLite {
    /// JSON `null`.
    Null,
    /// JSON `true` / `false`.
    Bool(bool),
    /// A JSON number captured as its **raw source token** (e.g. `"0.7275"`,
    /// `"1.2e-05"`, `"-3"`), never interpreted as any numeric type — so the
    /// exact bytes survive whatever the value's magnitude or notation.
    Number(String),
    /// A JSON string, UTF-8 decoded with all escapes expanded.
    String(String),
    /// A JSON array.
    Array(Vec<JsonLite>),
    /// A JSON object as an order-preserving `(key, value)` list.
    Object(Vec<(String, JsonLite)>),
}

impl JsonLite {
    /// Borrow this value as a slice if it is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[JsonLite]> {
        match self {
            Self::Array(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    /// Borrow this value as an object's `(key, value)` slice.
    #[must_use]
    pub fn as_object(&self) -> Option<&[(String, JsonLite)]> {
        match self {
            Self::Object(o) => Some(o.as_slice()),
            _ => None,
        }
    }

    /// Borrow this value as a `&str` if it is a string.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Borrow the **raw source token** of this value if it is a number
    /// (e.g. `"0.7275"`, `"42"`). Never parsed into a numeric type — the
    /// bytes are returned as captured.
    #[must_use]
    pub fn as_number_str(&self) -> Option<&str> {
        match self {
            Self::Number(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Read this value as a `bool` if it is a boolean.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// True if this value is JSON `null`.
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// Look up an object field by key (first match wins, matching the read-
    /// only, first-wins semantics this reader gives duplicate keys).
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&JsonLite> {
        let obj = self.as_object()?;
        for (k, v) in obj {
            if k == key {
                return Some(v);
            }
        }
        None
    }

    /// Look up an object field by key, **rejecting a duplicate**.
    ///
    /// Unlike the first-wins [`Self::get`] — correct for the verbatim-capture
    /// path, where RFC 8259 leaves duplicate keys undefined — this is the
    /// strict accessor for a **trusted-envelope read** (the NIST data-file
    /// status body), where a repeated `status` / `id` key is a malformed or
    /// hostile signal that must fail closed rather than silently pick one.
    /// `Ok(None)` when the key is absent, `Ok(Some(v))` on a single match, and
    /// an error on two or more. A non-object value has no keys → `Ok(None)`.
    ///
    /// # Errors
    /// [`DuplicateKey`] when `key` appears more than once in the object.
    pub fn get_unique(&self, key: &str) -> Result<Option<&JsonLite>, DuplicateKey> {
        let Some(obj) = self.as_object() else {
            return Ok(None);
        };
        let mut found: Option<&JsonLite> = None;
        for (k, v) in obj {
            if k == key {
                if found.is_some() {
                    return Err(DuplicateKey {
                        key: key.to_string(),
                    });
                }
                found = Some(v);
            }
        }
        Ok(found)
    }
}

/// A duplicate-key rejection from [`JsonLite::get_unique`] — a key required to
/// be unique appeared more than once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuplicateKey {
    /// The key that appeared more than once.
    pub key: String,
}

impl fmt::Display for DuplicateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "duplicate object key {:?}", self.key)
    }
}

impl std::error::Error for DuplicateKey {}

/// A [`parse`] failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Input ended in the middle of a value.
    UnexpectedEof,
    /// A byte could not appear at the current position.
    UnexpectedByte {
        /// Zero-based byte offset of the offending byte.
        pos: usize,
        /// The byte that was not expected.
        byte: u8,
    },
    /// An invalid `\`-escape (or a lone/again-surrogate `\u` pair) in a
    /// string literal.
    InvalidEscape {
        /// Byte offset of the offending escape.
        pos: usize,
    },
    /// A number literal did not match the RFC 8259 grammar (leading zero,
    /// bare exponent, a fractional point with no following digit, …).
    InvalidNumber {
        /// Byte offset where the number started.
        pos: usize,
    },
    /// A string literal held bytes that are not valid UTF-8.
    InvalidUtf8 {
        /// Byte offset where the string started.
        pos: usize,
    },
    /// Nesting depth exceeded [`MAX_DEPTH`].
    DepthExceeded {
        /// Byte offset at which the depth limit tripped.
        pos: usize,
    },
    /// Non-whitespace content followed the top-level value.
    TrailingData {
        /// Byte offset of the first unexpected byte.
        pos: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of input"),
            Self::UnexpectedByte { pos, byte } => {
                write!(f, "unexpected byte {byte:#04x} at position {pos}")
            }
            Self::InvalidEscape { pos } => write!(f, "invalid string escape at position {pos}"),
            Self::InvalidNumber { pos } => write!(f, "invalid number at position {pos}"),
            Self::InvalidUtf8 { pos } => {
                write!(f, "invalid UTF-8 in string literal at position {pos}")
            }
            Self::DepthExceeded { pos } => {
                write!(f, "JSON nesting depth exceeded at position {pos}")
            }
            Self::TrailingData { pos } => {
                write!(f, "trailing data after JSON value at position {pos}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a complete JSON document, keeping numbers as their raw source
/// tokens (see [`JsonLite::Number`]).
///
/// # Errors
/// A [`ParseError`] for any deviation from the RFC 8259 grammar, trailing
/// content after the value, an over-deep nesting, or a truncated body.
pub fn parse(input: &str) -> Result<JsonLite, ParseError> {
    let mut p = Parser {
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.skip_ws();
    let v = p.parse_value(0)?;
    p.skip_ws();
    if p.pos != p.bytes.len() {
        return Err(ParseError::TrailingData { pos: p.pos });
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

#[allow(clippy::arithmetic_side_effects)]
// Every `self.pos += n` runs only after a bounds-checked `peek()`/`bump()`
// that established a byte exists at the current position, so the index never
// advances past `bytes.len()` and cannot wrap.
impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn expect(&mut self, want: u8) -> Result<(), ParseError> {
        match self.peek() {
            Some(b) if b == want => {
                self.pos += 1;
                Ok(())
            }
            Some(byte) => Err(ParseError::UnexpectedByte {
                pos: self.pos,
                byte,
            }),
            None => Err(ParseError::UnexpectedEof),
        }
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonLite, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError::DepthExceeded { pos: self.pos });
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => self.parse_string().map(JsonLite::String),
            Some(b't' | b'f') => self.parse_bool(),
            Some(b'n') => self.parse_null(),
            Some(b) if b == b'-' || b.is_ascii_digit() => self.parse_number(),
            Some(byte) => Err(ParseError::UnexpectedByte {
                pos: self.pos,
                byte,
            }),
            None => Err(ParseError::UnexpectedEof),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonLite, ParseError> {
        self.expect(b'{')?;
        let mut out: Vec<(String, JsonLite)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonLite::Object(out));
        }
        loop {
            self.skip_ws();
            let key = self.parse_string()?;
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value(depth + 1)?;
            out.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonLite::Object(out));
                }
                Some(byte) => {
                    return Err(ParseError::UnexpectedByte {
                        pos: self.pos,
                        byte,
                    });
                }
                None => return Err(ParseError::UnexpectedEof),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonLite, ParseError> {
        self.expect(b'[')?;
        let mut out: Vec<JsonLite> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonLite::Array(out));
        }
        loop {
            let v = self.parse_value(depth + 1)?;
            out.push(v);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonLite::Array(out));
                }
                Some(byte) => {
                    return Err(ParseError::UnexpectedByte {
                        pos: self.pos,
                        byte,
                    });
                }
                None => return Err(ParseError::UnexpectedEof),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, ParseError> {
        let start = self.pos;
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let b = self.peek().ok_or(ParseError::UnexpectedEof)?;
            match b {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\\' => {
                    self.pos += 1;
                    self.parse_escape(&mut out, start)?;
                }
                // Unescaped control characters are not permitted in a string.
                0x00..=0x1f => {
                    return Err(ParseError::UnexpectedByte {
                        pos: self.pos,
                        byte: b,
                    });
                }
                _ => {
                    // Copy one whole UTF-8 scalar so multi-byte characters
                    // survive intact.
                    let ch_len = utf8_len(b);
                    let end = self.pos + ch_len;
                    let slice = self
                        .bytes
                        .get(self.pos..end)
                        .ok_or(ParseError::UnexpectedEof)?;
                    let s = core::str::from_utf8(slice)
                        .map_err(|_| ParseError::InvalidUtf8 { pos: start })?;
                    out.push_str(s);
                    self.pos = end;
                }
            }
        }
    }

    fn parse_escape(&mut self, out: &mut String, str_start: usize) -> Result<(), ParseError> {
        let esc = self.bump().ok_or(ParseError::UnexpectedEof)?;
        match esc {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'b' => out.push('\u{0008}'),
            b'f' => out.push('\u{000c}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => {
                let cp = self.parse_hex4()?;
                if (0xD800..=0xDBFF).contains(&cp) {
                    // High surrogate: require a following low-surrogate escape.
                    if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                        return Err(ParseError::InvalidEscape { pos: self.pos });
                    }
                    let low = self.parse_hex4()?;
                    if !(0xDC00..=0xDFFF).contains(&low) {
                        return Err(ParseError::InvalidEscape { pos: self.pos });
                    }
                    let combined = 0x1_0000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                    match char::from_u32(combined) {
                        Some(c) => out.push(c),
                        None => return Err(ParseError::InvalidEscape { pos: self.pos }),
                    }
                } else if (0xDC00..=0xDFFF).contains(&cp) {
                    // A lone low surrogate is invalid.
                    return Err(ParseError::InvalidEscape { pos: self.pos });
                } else {
                    match char::from_u32(cp) {
                        Some(c) => out.push(c),
                        None => return Err(ParseError::InvalidEscape { pos: self.pos }),
                    }
                }
            }
            _ => return Err(ParseError::InvalidEscape { pos: str_start }),
        }
        Ok(())
    }

    fn parse_hex4(&mut self) -> Result<u32, ParseError> {
        let mut v: u32 = 0;
        for _ in 0..4 {
            let b = self.bump().ok_or(ParseError::UnexpectedEof)?;
            let d: u32 = match b {
                b'0'..=b'9' => u32::from(b - b'0'),
                b'a'..=b'f' => u32::from(b - b'a') + 10,
                b'A'..=b'F' => u32::from(b - b'A') + 10,
                _ => return Err(ParseError::InvalidEscape { pos: self.pos }),
            };
            v = (v << 4) | d;
        }
        Ok(v)
    }

    /// Parse a number per the full RFC 8259 grammar
    /// `[minus] int [frac] [exp]`, capturing the exact source slice without
    /// interpreting it.
    fn parse_number(&mut self) -> Result<JsonLite, ParseError> {
        let start = self.pos;
        // Optional leading minus.
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        // int = "0" / ( digit1-9 *DIGIT )  — a leading zero admits no more
        // integer digits.
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b) if (b'1'..=b'9').contains(&b) => {
                self.pos += 1;
                self.consume_digits();
            }
            _ => return Err(ParseError::InvalidNumber { pos: start }),
        }
        // frac = "." 1*DIGIT
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
                return Err(ParseError::InvalidNumber { pos: start });
            }
            self.consume_digits();
        }
        // exp = ("e" / "E") ["-" / "+"] 1*DIGIT
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
                return Err(ParseError::InvalidNumber { pos: start });
            }
            self.consume_digits();
        }
        let slice = self
            .bytes
            .get(start..self.pos)
            .ok_or(ParseError::InvalidNumber { pos: start })?;
        // The slice is all ASCII digits/sign/`.`/`e`, so it is valid UTF-8.
        let raw =
            core::str::from_utf8(slice).map_err(|_| ParseError::InvalidNumber { pos: start })?;
        Ok(JsonLite::Number(raw.to_string()))
    }

    fn consume_digits(&mut self) {
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.pos += 1;
        }
    }

    fn parse_bool(&mut self) -> Result<JsonLite, ParseError> {
        let rest = self.bytes.get(self.pos..).unwrap_or(&[]);
        if rest.starts_with(b"true") {
            self.pos += 4;
            Ok(JsonLite::Bool(true))
        } else if rest.starts_with(b"false") {
            self.pos += 5;
            Ok(JsonLite::Bool(false))
        } else {
            Err(ParseError::UnexpectedByte {
                pos: self.pos,
                byte: rest.first().copied().unwrap_or(0),
            })
        }
    }

    fn parse_null(&mut self) -> Result<JsonLite, ParseError> {
        let rest = self.bytes.get(self.pos..).unwrap_or(&[]);
        if rest.starts_with(b"null") {
            self.pos += 4;
            Ok(JsonLite::Null)
        } else {
            Err(ParseError::UnexpectedByte {
                pos: self.pos,
                byte: rest.first().copied().unwrap_or(0),
            })
        }
    }
}

/// Length in bytes of the UTF-8 scalar whose leading byte is `b` (1..=4). An
/// ASCII byte, a continuation byte, or an invalid leading byte all yield 1, so
/// the UTF-8 validation on the resulting slice catches any malformation.
fn utf8_len(b: u8) -> usize {
    match b {
        0xc0..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf7 => 4,
        _ => 1,
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    fn num(s: &str) -> JsonLite {
        JsonLite::Number(s.to_string())
    }
    fn s(s: &str) -> JsonLite {
        JsonLite::String(s.to_string())
    }

    // ── Numbers: full grammar, raw-token capture ──────────────────────

    #[test]
    fn integers_capture_raw_token() {
        assert_eq!(parse("0").unwrap(), num("0"));
        assert_eq!(parse("42").unwrap(), num("42"));
        assert_eq!(parse("-3").unwrap(), num("-3"));
        assert_eq!(parse("-0").unwrap(), num("-0"));
    }

    #[test]
    fn fractional_and_exponent_floats_parse_and_preserve_the_raw_token() {
        for lit in [
            "0.7275", "1.0", "-2.5", "1.2e-05", "3E10", "6.022e23", "0.0",
        ] {
            assert_eq!(parse(lit).unwrap(), num(lit), "literal {lit}");
        }
    }

    #[test]
    fn e_notation_float_raw_token_is_byte_exact() {
        // The centerpiece property: `1.2e-05` survives verbatim.
        let v = parse("1.2e-05").unwrap();
        assert_eq!(v.as_number_str(), Some("1.2e-05"));
    }

    #[test]
    fn malformed_numerals_are_parse_errors_never_promoted() {
        // `1.2.3` — the review's exact bad case. `1.2` parses, `.3` is
        // trailing garbage.
        assert!(matches!(
            parse("1.2.3"),
            Err(ParseError::TrailingData { .. })
        ));
        // Bare exponent.
        assert!(matches!(parse("1e"), Err(ParseError::InvalidNumber { .. })));
        assert!(matches!(
            parse("1e+"),
            Err(ParseError::InvalidNumber { .. })
        ));
        // Fractional point with no digit.
        assert!(matches!(parse("1."), Err(ParseError::InvalidNumber { .. })));
        // Leading zero on a multi-digit run.
        assert!(matches!(parse("01"), Err(ParseError::TrailingData { .. })));
        // Lone minus.
        assert!(matches!(parse("-"), Err(ParseError::InvalidNumber { .. })));
    }

    // ── Strings: escapes and float-inside-string untouched ────────────

    #[test]
    fn strings_decode_standard_escapes() {
        assert_eq!(parse(r#""a\"b\\c\/d""#).unwrap(), s("a\"b\\c/d"));
        assert_eq!(parse(r#""tab\tnl\n""#).unwrap(), s("tab\tnl\n"));
        assert_eq!(parse(r#""A""#).unwrap(), s("A"));
    }

    #[test]
    fn surrogate_pair_escape_decodes() {
        // U+1F600 GRINNING FACE as a surrogate pair.
        assert_eq!(parse(r#""😀""#).unwrap(), s("\u{1F600}"));
        // A lone high surrogate is rejected.
        assert!(parse(r#""\uD83D""#).is_err());
    }

    #[test]
    fn anti_path_bad_escapes_controls_and_surrogates_fail_typed() {
        // A bare unknown escape (`\q`) is not in the RFC 8259 escape set.
        assert!(matches!(
            parse(r#""\q""#),
            Err(ParseError::InvalidEscape { .. })
        ));
        // An unescaped control character (< 0x20) is not permitted in a string.
        assert!(matches!(
            parse("\"a\u{01}b\""),
            Err(ParseError::UnexpectedByte { .. })
        ));
        // A truncated / non-hex `\u` escape.
        assert!(parse(r#""\uD8""#).is_err());
        assert!(parse(r#""\uZZZZ""#).is_err());
        // A high surrogate followed by a well-formed `\u` escape that is NOT a
        // low surrogate (`A` = 'A', outside the 0xDC00..=0xDFFF range).
        assert!(matches!(
            parse(r#""\uD83DA""#),
            Err(ParseError::InvalidEscape { .. })
        ));
    }

    #[test]
    fn a_decimal_inside_a_string_is_left_as_text_not_a_number() {
        // The `esvVersion` "1.0" is a STRING and must stay a string — the old
        // pre-pass's whole hazard was touching decimals inside strings.
        let v = parse(r#"{"esvVersion":"1.0","h":0.5}"#).unwrap();
        assert_eq!(v.get("esvVersion"), Some(&s("1.0")));
        assert_eq!(v.get("h"), Some(&num("0.5")));
    }

    // ── Structure + envelope-shaped reads ─────────────────────────────

    #[test]
    fn objects_arrays_and_scalars_round_trip() {
        let v = parse(
            r#"[{"esvVersion":"1.0"},{"id":42,"status":"Run Successful","x":true,"y":null}]"#,
        )
        .unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(
            arr[0].get("esvVersion").and_then(JsonLite::as_str),
            Some("1.0")
        );
        let payload = &arr[1];
        assert_eq!(
            payload.get("id").and_then(JsonLite::as_number_str),
            Some("42")
        );
        assert_eq!(
            payload.get("status").and_then(JsonLite::as_str),
            Some("Run Successful")
        );
        assert_eq!(payload.get("x").and_then(JsonLite::as_bool), Some(true));
        assert!(payload.get("y").unwrap().is_null());
    }

    #[test]
    fn assessment_body_with_e_notation_reads_status_and_preserves_floats() {
        // A Run Successful body carrying an e-notation min-entropy.
        let body =
            r#"[{"esvVersion":"1.0"},{"id":7,"status":"Run Successful","minEntropy":1.2e-05}]"#;
        let v = parse(body).unwrap();
        let payload = &v.as_array().unwrap()[1];
        assert_eq!(
            payload.get("status").and_then(JsonLite::as_str),
            Some("Run Successful")
        );
        assert_eq!(
            payload.get("minEntropy").and_then(JsonLite::as_number_str),
            Some("1.2e-05")
        );
    }

    #[test]
    fn whitespace_between_tokens_is_insignificant() {
        let v = parse("  {\n  \"a\" : [ 1 , 2 ]\n}  ").unwrap();
        assert_eq!(v.get("a").unwrap().as_array().unwrap().len(), 2);
    }

    // ── Hostile / truncated bodies fail typed ─────────────────────────

    #[test]
    fn truncated_and_hostile_bodies_fail_typed() {
        assert!(matches!(parse("{\"a\":"), Err(ParseError::UnexpectedEof)));
        assert!(matches!(parse("[1,2"), Err(ParseError::UnexpectedEof)));
        assert!(parse(r#""unterminated"#).is_err());
        assert!(parse("").is_err());
        // Trailing content after a complete value.
        assert!(matches!(
            parse("{} garbage"),
            Err(ParseError::TrailingData { .. })
        ));
        // Not JSON at all (a 502 HTML page).
        assert!(parse("<html><body>502 Bad Gateway</body></html>").is_err());
    }

    #[test]
    fn over_deep_nesting_fails_typed() {
        let deep = "[".repeat(MAX_DEPTH + 2);
        assert!(matches!(
            parse(&deep),
            Err(ParseError::DepthExceeded { .. })
        ));
    }

    #[test]
    fn duplicate_keys_are_first_wins_for_reads() {
        // A response reader tolerates duplicate keys (RFC 8259 leaves them
        // undefined); `get` returns the first.
        let v = parse(r#"{"status":"Uploaded","status":"Run Failed"}"#).unwrap();
        assert_eq!(v.get("status").and_then(JsonLite::as_str), Some("Uploaded"));
    }

    #[test]
    fn get_unique_rejects_a_duplicate_key_but_reads_a_single_one() {
        // The strict accessor for a trusted-envelope read fails closed on a
        // duplicate `status`, where `get` would silently first-win.
        let dup = parse(r#"{"status":"Uploaded","status":"Run Failed"}"#).unwrap();
        assert_eq!(
            dup.get_unique("status"),
            Err(DuplicateKey {
                key: "status".to_string()
            })
        );
        // A single key returns it; an absent key is Ok(None).
        let ok = parse(r#"{"status":"Uploaded","id":7}"#).unwrap();
        assert_eq!(
            ok.get_unique("status").unwrap().and_then(JsonLite::as_str),
            Some("Uploaded")
        );
        assert!(ok.get_unique("missing").unwrap().is_none());
        // A non-object value has no keys.
        assert!(parse("42").unwrap().get_unique("x").unwrap().is_none());
    }
}
