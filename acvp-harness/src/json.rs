//! Minimal in-crate JSON parser and serializer for ACVP vector sets.
//!
//! # Scope and non-goals
//!
//! This module intentionally implements *only* the subset of JSON
//! that ACVP vector sets actually use:
//!
//!   * objects with string keys
//!   * arrays
//!   * strings with the JSON escape set `\"`, `\\`, `\/`, `\n`, `\r`,
//!     `\t`, `\b`, `\f`, and `\uXXXX`
//!   * integers in `i64`'s range (negatives supported as of
//!     2026-04-26 — required for live ACVP session-metadata fields
//!     such as `sizeConstraint: -1` returned by the demo server)
//!   * the literals `true`, `false`, `null`
//!   * insignificant whitespace (`' '`, `\t`, `\n`, `\r`) between tokens
//!
//! Floating-point numbers, scientific notation, and duplicate keys in
//! objects are still rejected. ACVP *vector sets* themselves never use
//! these — every data field is a hex-encoded string and every counter
//! (`tgId`, `tcId`, `keyLen`, `msgLen`, `macLen`, `len`, `outLen`) is
//! non-negative — but the live ACVP login/registration responses
//! contain negative integers in metadata, so the parser was relaxed.
//!
//! # Why in-crate instead of serde_json?
//!
//! oxicrypt has a workspace-wide zero-third-party-dependencies policy.
//! The entire cryptographic module — and the validation harness that
//! feeds it to a CAVP lab — is written in-tree so the supply-chain
//! story on the CMVP submission is "no external code, period". This
//! module is the ACVP-dispatch half of that: roughly 350 lines of
//! recursive-descent with a bounded recursion depth, no `unsafe`, no
//! indirect `unwrap`, and local unit tests covering every value type
//! and the standard parse-error paths.
//!
//! # Numbers
//!
//! [`JsonValue::Number`] holds an `i64`. All ACVP integer fields fit
//! comfortably — the largest value seen in a real vector set is the
//! `len` field on a SHAKE test case, which is bounded by a few
//! megabits, far inside `i64::MAX`. If a future vector set needs
//! 128-bit integers we'll widen this enum.

#![allow(clippy::arithmetic_side_effects)]
// Parser index arithmetic is bounded by input length and always
// performed after an explicit `pos < end` check, so wrap-on-overflow
// is not reachable. The cryptographic workspace policy that forbids
// silent integer wraparound is a CSP-protection measure and does not
// apply to a JSON lexer operating on untrusted-but-already-in-memory
// text.

use core::fmt;

/// Maximum recursion depth for nested arrays and objects.
///
/// ACVP vector sets nest at most four levels deep
/// (`{ testGroups: [ { tests: [ { ... } ] } ] }`), so 64 is
/// conservative. A deeper input is rejected with
/// [`ParseError::DepthExceeded`] rather than risking stack exhaustion
/// on adversarial input.
pub const MAX_DEPTH: usize = 64;

/// A decoded JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonValue {
    /// JSON `null`.
    Null,
    /// JSON `true` / `false`.
    Bool(bool),
    /// JSON integer. Fractional and scientific notation are rejected.
    Number(i64),
    /// JSON string, already UTF-8 decoded with escapes expanded.
    String(String),
    /// JSON array.
    Array(Vec<JsonValue>),
    /// Preserved-order key/value list. ACVP response serialization is
    /// sensitive to field ordering inside test-case objects (CAVP
    /// diff tools are not forgiving about reordered keys on close
    /// inspection), so we never use a hash map here.
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    /// Borrow this value as an `&[JsonValue]` if it is an array.
    #[must_use]
    pub fn as_array(&self) -> Option<&[JsonValue]> {
        match self {
            Self::Array(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    /// Borrow this value as an object's `(key, value)` slice.
    #[must_use]
    pub fn as_object(&self) -> Option<&[(String, JsonValue)]> {
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

    /// Read this value as an `i64` if it is a number.
    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Read this value as a `u64` if it is a non-negative number.
    #[must_use]
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(n) if *n >= 0 => Some((*n).cast_unsigned()),
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

    /// Look up a field of an object by key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        let obj = self.as_object()?;
        for (k, v) in obj {
            if k == key {
                return Some(v);
            }
        }
        None
    }
}

/// Errors produced by [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Input ended in the middle of a JSON token.
    UnexpectedEof,
    /// A byte could not appear at the current parser position.
    UnexpectedByte {
        /// Zero-based byte offset of the offending byte.
        pos: usize,
        /// The byte that was not expected.
        byte: u8,
    },
    /// An invalid `\`-escape sequence inside a string literal.
    InvalidEscape {
        /// Byte offset of the offending escape sequence.
        pos: usize,
    },
    /// A number literal could not be tokenized (leading zero, etc.).
    InvalidNumber {
        /// Byte offset where the number started.
        pos: usize,
    },
    /// A string literal contained bytes that aren't valid UTF-8.
    InvalidUtf8 {
        /// Byte offset where the string started.
        pos: usize,
    },
    /// A number literal is valid but outside `i64`'s range.
    NumberOutOfRange {
        /// Byte offset where the number started.
        pos: usize,
    },
    /// Nesting depth exceeded [`MAX_DEPTH`].
    DepthExceeded {
        /// Byte offset at which the depth limit was tripped.
        pos: usize,
    },
    /// Non-whitespace content followed the top-level JSON value.
    TrailingData {
        /// Byte offset of the first unexpected byte.
        pos: usize,
    },
    /// An object contained two entries with the same key.
    DuplicateKey {
        /// Byte offset where the second entry's key started.
        pos: usize,
        /// The duplicate key.
        key: String,
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
            Self::NumberOutOfRange { pos } => {
                write!(f, "number at position {pos} exceeds i64::MAX")
            }
            Self::DepthExceeded { pos } => {
                write!(f, "JSON nesting depth exceeded at position {pos}")
            }
            Self::TrailingData { pos } => {
                write!(f, "trailing data after top-level value at position {pos}")
            }
            Self::DuplicateKey { pos, key } => {
                write!(f, "duplicate key {key:?} at position {pos}")
            }
        }
    }
}

/// Parse a JSON document.
pub fn parse(input: &str) -> Result<JsonValue, ParseError> {
    let bytes = input.as_bytes();
    let mut p = Parser { bytes, pos: 0 };
    p.skip_ws();
    let v = p.parse_value(0)?;
    p.skip_ws();
    if p.pos != bytes.len() {
        return Err(ParseError::TrailingData { pos: p.pos });
    }
    Ok(v)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

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
            Some(b) => Err(ParseError::UnexpectedByte {
                pos: self.pos,
                byte: b,
            }),
            None => Err(ParseError::UnexpectedEof),
        }
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, ParseError> {
        if depth > MAX_DEPTH {
            return Err(ParseError::DepthExceeded { pos: self.pos });
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => self.parse_string().map(JsonValue::String),
            Some(b't' | b'f') => self.parse_bool(),
            Some(b'n') => self.parse_null(),
            Some(b) if b.is_ascii_digit() || b == b'-' => self.parse_number(),
            Some(b) => Err(ParseError::UnexpectedByte {
                pos: self.pos,
                byte: b,
            }),
            None => Err(ParseError::UnexpectedEof),
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, ParseError> {
        self.expect(b'{')?;
        let mut out: Vec<(String, JsonValue)> = Vec::new();
        self.skip_ws();
        if let Some(b'}') = self.peek() {
            self.pos += 1;
            return Ok(JsonValue::Object(out));
        }
        loop {
            self.skip_ws();
            let key_pos = self.pos;
            let key = self.parse_string()?;
            if out.iter().any(|(k, _)| k == &key) {
                return Err(ParseError::DuplicateKey { pos: key_pos, key });
            }
            self.skip_ws();
            self.expect(b':')?;
            let value = self.parse_value(depth + 1)?;
            out.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(out));
                }
                Some(b) => {
                    return Err(ParseError::UnexpectedByte {
                        pos: self.pos,
                        byte: b,
                    });
                }
                None => return Err(ParseError::UnexpectedEof),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, ParseError> {
        self.expect(b'[')?;
        let mut out: Vec<JsonValue> = Vec::new();
        self.skip_ws();
        if let Some(b']') = self.peek() {
            self.pos += 1;
            return Ok(JsonValue::Array(out));
        }
        loop {
            let v = self.parse_value(depth + 1)?;
            out.push(v);
            self.skip_ws();
            match self.peek() {
                Some(b',') => {
                    self.pos += 1;
                }
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(out));
                }
                Some(b) => {
                    return Err(ParseError::UnexpectedByte {
                        pos: self.pos,
                        byte: b,
                    });
                }
                None => return Err(ParseError::UnexpectedEof),
            }
        }
    }

    fn parse_string(&mut self) -> Result<String, ParseError> {
        self.expect(b'"')?;
        let start = self.pos;
        let mut out = String::new();
        let mut has_escape = false;
        loop {
            let b = self.peek().ok_or(ParseError::UnexpectedEof)?;
            if b == b'"' {
                if !has_escape {
                    // Fast path: no escapes, the body is a direct
                    // UTF-8 slice of the input.
                    let slice = self
                        .bytes
                        .get(start..self.pos)
                        .ok_or(ParseError::UnexpectedEof)?;
                    let s = core::str::from_utf8(slice)
                        .map_err(|_| ParseError::InvalidUtf8 { pos: start })?;
                    out.push_str(s);
                }
                self.pos += 1;
                return Ok(out);
            }
            if b == b'\\' {
                if !has_escape {
                    // Flush everything collected on the fast path.
                    let slice = self
                        .bytes
                        .get(start..self.pos)
                        .ok_or(ParseError::UnexpectedEof)?;
                    let s = core::str::from_utf8(slice)
                        .map_err(|_| ParseError::InvalidUtf8 { pos: start })?;
                    out.push_str(s);
                    has_escape = true;
                }
                self.pos += 1;
                self.parse_escape(&mut out)?;
                continue;
            }
            if b < 0x20 {
                return Err(ParseError::UnexpectedByte {
                    pos: self.pos,
                    byte: b,
                });
            }
            if has_escape {
                out.push(b as char);
            }
            self.pos += 1;
        }
    }

    fn parse_escape(&mut self, out: &mut String) -> Result<(), ParseError> {
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
                // ACVP vector sets never use surrogate pairs, so we
                // reject them rather than implement the pairing dance.
                if (0xD800..=0xDFFF).contains(&cp) {
                    return Err(ParseError::InvalidEscape { pos: self.pos });
                }
                match char::from_u32(cp) {
                    Some(c) => out.push(c),
                    None => return Err(ParseError::InvalidEscape { pos: self.pos }),
                }
            }
            _ => return Err(ParseError::InvalidEscape { pos: self.pos }),
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

    fn parse_number(&mut self) -> Result<JsonValue, ParseError> {
        let start = self.pos;
        // Optional leading minus per RFC 8259 §6.
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits_start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        let digits = self
            .bytes
            .get(digits_start..self.pos)
            .ok_or(ParseError::UnexpectedEof)?;
        if digits.is_empty() {
            // A lone `-` with no digits, or empty input.
            return Err(ParseError::InvalidNumber { pos: start });
        }
        // Reject a leading zero on a multi-digit digit-run (e.g. "00",
        // "01", "-01"). A bare `0` or `-0` is fine.
        if digits.len() > 1 && digits.first() == Some(&b'0') {
            return Err(ParseError::InvalidNumber { pos: start });
        }
        let slice = self
            .bytes
            .get(start..self.pos)
            .ok_or(ParseError::UnexpectedEof)?;
        let s =
            core::str::from_utf8(slice).map_err(|_| ParseError::InvalidNumber { pos: start })?;
        let n: i64 = s
            .parse()
            .map_err(|_| ParseError::NumberOutOfRange { pos: start })?;
        Ok(JsonValue::Number(n))
    }

    fn parse_bool(&mut self) -> Result<JsonValue, ParseError> {
        let rest = self.bytes.get(self.pos..).unwrap_or(&[]);
        if rest.starts_with(b"true") {
            self.pos += 4;
            Ok(JsonValue::Bool(true))
        } else if rest.starts_with(b"false") {
            self.pos += 5;
            Ok(JsonValue::Bool(false))
        } else {
            Err(ParseError::UnexpectedByte {
                pos: self.pos,
                byte: rest.first().copied().unwrap_or(0),
            })
        }
    }

    fn parse_null(&mut self) -> Result<JsonValue, ParseError> {
        let rest = self.bytes.get(self.pos..).unwrap_or(&[]);
        if rest.starts_with(b"null") {
            self.pos += 4;
            Ok(JsonValue::Null)
        } else {
            Err(ParseError::UnexpectedByte {
                pos: self.pos,
                byte: rest.first().copied().unwrap_or(0),
            })
        }
    }
}

/// Serialize a [`JsonValue`] into pretty-printed JSON with two-space
/// indentation.
///
/// The output shape matches what NIST's ACVP-Server produces for
/// `internalProjection.json` files, modulo trailing newline.
#[must_use]
pub fn to_pretty_string(value: &JsonValue) -> String {
    let mut out = String::new();
    write_value(&mut out, value, 0);
    out
}

/// Serialize a JSON value to a compact, single-line string — no
/// indentation, no newlines between tokens, one space nowhere.
///
/// Pairs with [`to_pretty_string`]: identical value model and identical
/// string escaping (via the same `write_string`, so a string field never
/// emits a raw newline), but the output occupies exactly one line. This is
/// the form the ESV harness's session store appends to its JSON-lines event
/// log, where every record must be exactly one line so a torn final write
/// costs only the last event.
#[must_use]
pub fn to_compact_string(value: &JsonValue) -> String {
    let mut out = String::new();
    write_value_compact(&mut out, value);
    out
}

fn write_value_compact(out: &mut String, value: &JsonValue) {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Number(n) => out.push_str(&n.to_string()),
        JsonValue::String(s) => write_string(out, s),
        JsonValue::Array(a) => {
            out.push('[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value_compact(out, v);
            }
            out.push(']');
        }
        JsonValue::Object(o) => {
            out.push('{');
            for (i, (k, v)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, k);
                out.push(':');
                write_value_compact(out, v);
            }
            out.push('}');
        }
    }
}

fn write_value(out: &mut String, value: &JsonValue, indent: usize) {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Number(n) => {
            // i64::to_string is allocation-stable and never panics.
            out.push_str(&n.to_string());
        }
        JsonValue::String(s) => write_string(out, s),
        JsonValue::Array(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            let inner = indent + 1;
            for (i, v) in a.iter().enumerate() {
                out.push('\n');
                push_indent(out, inner);
                write_value(out, v, inner);
                if i + 1 < a.len() {
                    out.push(',');
                }
            }
            out.push('\n');
            push_indent(out, indent);
            out.push(']');
        }
        JsonValue::Object(o) => {
            if o.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            let inner = indent + 1;
            for (i, (k, v)) in o.iter().enumerate() {
                out.push('\n');
                push_indent(out, inner);
                write_string(out, k);
                out.push_str(": ");
                write_value(out, v, inner);
                if i + 1 < o.len() {
                    out.push(',');
                }
            }
            out.push('\n');
            push_indent(out, indent);
            out.push('}');
        }
    }
}

fn push_indent(out: &mut String, level: usize) {
    for _ in 0..level {
        out.push_str("  ");
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                // Control character.
                let cp = c as u32;
                out.push_str("\\u");
                for shift in (0..4).rev() {
                    let nib = (cp >> (shift * 4)) & 0xF;
                    let b = if nib < 10 {
                        b'0' + nib as u8
                    } else {
                        b'a' + (nib as u8 - 10)
                    };
                    out.push(b as char);
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn n(v: i64) -> JsonValue {
        JsonValue::Number(v)
    }
    fn s(v: &str) -> JsonValue {
        JsonValue::String(v.to_string())
    }

    #[test]
    fn parse_primitives() {
        assert_eq!(parse("null").unwrap(), JsonValue::Null);
        assert_eq!(parse("true").unwrap(), JsonValue::Bool(true));
        assert_eq!(parse("false").unwrap(), JsonValue::Bool(false));
        assert_eq!(parse("0").unwrap(), n(0));
        assert_eq!(parse("42").unwrap(), n(42));
        assert_eq!(parse("\"hello\"").unwrap(), s("hello"));
    }

    #[test]
    fn parse_escapes() {
        assert_eq!(parse("\"a\\\"b\"").unwrap(), s("a\"b"));
        assert_eq!(parse("\"\\n\\t\\r\"").unwrap(), s("\n\t\r"));
        assert_eq!(parse("\"\\u0041\"").unwrap(), s("A"));
    }

    #[test]
    fn parse_rejects_leading_zero() {
        assert!(matches!(parse("01"), Err(ParseError::InvalidNumber { .. })));
    }

    #[test]
    fn parse_negative_integer() {
        assert_eq!(parse("-1").unwrap(), n(-1));
        assert_eq!(parse("-12345").unwrap(), n(-12_345));
        // Embedded in object, the original failure mode from ACVP login
        // metadata returning `sizeConstraint: -1`.
        let v = parse("{\"sizeConstraint\":-1}").unwrap();
        assert_eq!(v.get("sizeConstraint"), Some(&n(-1)));
    }

    #[test]
    fn parse_rejects_lone_minus() {
        assert!(matches!(parse("-"), Err(ParseError::InvalidNumber { .. })));
    }

    #[test]
    fn parse_rejects_negative_leading_zero() {
        assert!(matches!(
            parse("-01"),
            Err(ParseError::InvalidNumber { .. })
        ));
    }

    #[test]
    fn parse_rejects_trailing_data() {
        assert!(matches!(parse("1 2"), Err(ParseError::TrailingData { .. })));
    }

    #[test]
    fn parse_rejects_duplicate_keys() {
        assert!(matches!(
            parse("{\"a\":1,\"a\":2}"),
            Err(ParseError::DuplicateKey { .. })
        ));
    }

    #[test]
    fn parse_array_and_object() {
        let v = parse("[1,2,[3,4]]").unwrap();
        assert_eq!(
            v,
            JsonValue::Array(vec![n(1), n(2), JsonValue::Array(vec![n(3), n(4)])])
        );

        let v = parse("{\"k\":[null,true]}").unwrap();
        assert_eq!(
            v,
            JsonValue::Object(vec![(
                "k".to_string(),
                JsonValue::Array(vec![JsonValue::Null, JsonValue::Bool(true)])
            )])
        );
    }

    #[test]
    fn round_trip_pretty() {
        let src = "{\n  \"a\": 1,\n  \"b\": [\n    2,\n    3\n  ],\n  \"c\": \"x\"\n}";
        let v = parse(src).unwrap();
        let out = to_pretty_string(&v);
        assert_eq!(out, src);
    }

    #[test]
    fn compact_is_single_line_and_round_trips() {
        let v = parse("{\n  \"a\": 1,\n  \"b\": [2, 3],\n  \"c\": \"x\"\n}").unwrap();
        let compact = to_compact_string(&v);
        // No structural whitespace at all.
        assert_eq!(compact, r#"{"a":1,"b":[2,3],"c":"x"}"#);
        assert!(!compact.contains('\n'), "compact output is one line");
        // And it re-parses to the same value.
        assert_eq!(parse(&compact).unwrap(), v);
    }

    #[test]
    fn compact_escapes_newlines_in_strings() {
        // A string field carrying a newline must be escaped, so the compact
        // record stays a single physical line (the JSON-lines invariant).
        let compact = to_compact_string(&s("line1\nline2"));
        assert_eq!(compact, r#""line1\nline2""#);
        assert!(!compact.contains('\n'));
    }

    #[test]
    fn compact_empty_containers() {
        assert_eq!(to_compact_string(&JsonValue::Array(vec![])), "[]");
        assert_eq!(to_compact_string(&JsonValue::Object(vec![])), "{}");
    }

    #[test]
    fn depth_limit() {
        let mut s = String::new();
        for _ in 0..MAX_DEPTH + 2 {
            s.push('[');
        }
        s.push('1');
        for _ in 0..MAX_DEPTH + 2 {
            s.push(']');
        }
        assert!(matches!(parse(&s), Err(ParseError::DepthExceeded { .. })));
    }

    #[test]
    fn reject_control_char_in_string() {
        assert!(matches!(
            parse("\"\x01\""),
            Err(ParseError::UnexpectedByte { .. })
        ));
    }

    #[test]
    fn serialize_escapes() {
        assert_eq!(to_pretty_string(&s("a\"b\\c")), "\"a\\\"b\\\\c\"");
        assert_eq!(to_pretty_string(&s("\x01")), "\"\\u0001\"");
    }

    #[test]
    fn empty_containers() {
        assert_eq!(parse("[]").unwrap(), JsonValue::Array(vec![]));
        assert_eq!(parse("{}").unwrap(), JsonValue::Object(vec![]));
        assert_eq!(to_pretty_string(&JsonValue::Array(vec![])), "[]");
        assert_eq!(to_pretty_string(&JsonValue::Object(vec![])), "{}");
    }
}
