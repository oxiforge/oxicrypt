//! Minimal CAVP `.rsp` parser for SHS (SHA / SHA-2 / SHA-512/t) byte
//! vectors.
//!
//! The CAVP Secure Hash Standard (SHS) validation test set is
//! distributed as plain-text `.rsp` response files, not as the ACVP
//! `internalProjection.json` envelope the R10 dispatcher consumes.
//! R11′ recorded why: upstream `usnistgov/ACVP-Server` ships no plain
//! FIPS 180-4 hashing vectors at the pinned commit — CAVP SHS is the
//! only path — and this module is the "second envelope shape" R11′
//! promised.
//!
//! # File format
//!
//! CAVP SHS short-message `.rsp` files look like this (from
//! `vendor/nist/cavp-shs/shabytetestvectors/SHA256ShortMsg.rsp`):
//!
//! ```text
//! #  CAVS 11.0
//! #  "SHA-256 ShortMsg" information
//! #  SHA-256 tests are configured for BYTE oriented implementations
//! #  Generated on Tue Mar 15 08:23:38 2011
//!
//! [L = 32]
//!
//! Len = 0
//! Msg = 00
//! MD = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
//!
//! Len = 8
//! Msg = d3
//! MD = 28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1
//! …
//! ```
//!
//! The grammar this parser accepts is:
//!
//! - `#` comment lines are skipped.
//! - Blank lines (CR/LF only) are skipped.
//! - Exactly one `[L = N]` header declares the digest length in
//!   **bytes**. It must appear before the first record.
//! - Records are three consecutive `key = value` lines in fixed order:
//!   `Len = <bits>`, `Msg = <hex>`, `MD = <hex>`. The `Len = 0` edge
//!   case uses a sentinel `Msg = 00` byte that represents the empty
//!   message; the parser does not treat it specially — the handler
//!   slices `msg[..len/8]` which is the empty slice for `len = 0`,
//!   matching the same byte-oriented rule R10 uses for the ACVP SHA-3
//!   AFT handler.
//! - Trailing whitespace on any line is ignored. UNIX (`\n`) and DOS
//!   (`\r\n`) line endings are both accepted.
//!
//! Anything else is a parse error. The intent is to match NIST's
//! own layout byte-for-byte, not to tolerate arbitrary hand edits.

use crate::hex::{self, HexError};
use core::fmt;

/// Errors produced by [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RspError {
    /// The `[L = N]` header was missing or malformed.
    MissingLengthHeader,
    /// A record line had the wrong field name. `expected` holds the
    /// key the parser was looking for next, `got` is the line as seen.
    UnexpectedField {
        /// Line number (1-indexed) where the error was observed.
        line: usize,
        /// The key the parser expected next (`"Len"`, `"Msg"`, or `"MD"`).
        expected: &'static str,
        /// Up to 64 bytes of the offending line for diagnostic output.
        got: String,
    },
    /// A numeric field could not be parsed as a non-negative integer.
    InvalidInteger {
        /// Line number (1-indexed) where the error was observed.
        line: usize,
        /// The field whose value failed to parse (`"L"` or `"Len"`).
        field: &'static str,
    },
    /// A hex value could not be decoded.
    InvalidHex {
        /// Line number (1-indexed) where the error was observed.
        line: usize,
        /// The field whose hex payload failed to decode.
        field: &'static str,
        /// The underlying hex decoding error.
        source: HexError,
    },
    /// A record was not terminated before end of file.
    TruncatedRecord,
}

impl fmt::Display for RspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingLengthHeader => {
                write!(f, ".rsp: missing `[L = N]` digest-length header")
            }
            Self::UnexpectedField {
                line,
                expected,
                got,
            } => write!(f, ".rsp:{line}: expected `{expected} = …` got {got:?}"),
            Self::InvalidInteger { line, field } => {
                write!(
                    f,
                    ".rsp:{line}: field `{field}` is not a non-negative integer"
                )
            }
            Self::InvalidHex {
                line,
                field,
                source,
            } => write!(f, ".rsp:{line}: field `{field}` hex: {source}"),
            Self::TruncatedRecord => {
                write!(f, ".rsp: truncated record at end of file")
            }
        }
    }
}

/// One parsed CAVP SHS short-message record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RspCase {
    /// Message length in bits (as declared by `Len = …`).
    pub len_bits: u64,
    /// Decoded hex from `Msg = …`. The real message is
    /// `msg[..len_bits / 8]`; any trailing bytes (including the
    /// sentinel `00` that CAVP uses for `Len = 0`) are ignored by the
    /// handler.
    pub msg: Vec<u8>,
    /// Decoded hex from `MD = …` — the expected digest.
    pub md: Vec<u8>,
}

/// Fully parsed CAVP SHS short-message `.rsp` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RspDocument {
    /// Digest length in bytes, from `[L = N]`.
    pub digest_length_bytes: usize,
    /// All parsed records, in file order.
    pub cases: Vec<RspCase>,
}

/// Parse a CAVP SHS `.rsp` file into an [`RspDocument`].
///
/// The parser is deliberately strict — duplicate keys, out-of-order
/// records, and unexpected fields are all errors. See the module
/// rustdoc for the grammar.
pub fn parse(src: &str) -> Result<RspDocument, RspError> {
    let mut digest_length: Option<usize> = None;
    let mut cases: Vec<RspCase> = Vec::new();
    // The record builder: fields fill in order Len → Msg → MD.
    let mut pending_len: Option<u64> = None;
    let mut pending_msg: Option<Vec<u8>> = None;
    // 1-indexed line numbers for diagnostics.
    for (idx, raw) in src.split('\n').enumerate() {
        let line_no = idx + 1;
        // Strip trailing `\r` (DOS line endings) and surrounding space.
        let line = raw.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            // `[L = 32]` header.
            let (k, v) = split_kv(rest).ok_or(RspError::MissingLengthHeader)?;
            if k != "L" {
                return Err(RspError::MissingLengthHeader);
            }
            let parsed: usize = v.parse().map_err(|_| RspError::InvalidInteger {
                line: line_no,
                field: "L",
            })?;
            digest_length = Some(parsed);
            continue;
        }
        let (key, value) = split_kv(line).ok_or(RspError::UnexpectedField {
            line: line_no,
            expected: next_expected(pending_len.as_ref(), pending_msg.as_ref()),
            got: clip(line),
        })?;
        match (key, &pending_len, &pending_msg) {
            ("Len", None, None) => {
                let parsed: u64 = value.parse().map_err(|_| RspError::InvalidInteger {
                    line: line_no,
                    field: "Len",
                })?;
                pending_len = Some(parsed);
            }
            ("Msg", Some(_), None) => {
                let decoded = hex::decode(value).map_err(|e| RspError::InvalidHex {
                    line: line_no,
                    field: "Msg",
                    source: e,
                })?;
                pending_msg = Some(decoded);
            }
            ("MD", Some(len_bits), Some(msg)) => {
                let decoded = hex::decode(value).map_err(|e| RspError::InvalidHex {
                    line: line_no,
                    field: "MD",
                    source: e,
                })?;
                cases.push(RspCase {
                    len_bits: *len_bits,
                    msg: msg.clone(),
                    md: decoded,
                });
                pending_len = None;
                pending_msg = None;
            }
            _ => {
                return Err(RspError::UnexpectedField {
                    line: line_no,
                    expected: next_expected(pending_len.as_ref(), pending_msg.as_ref()),
                    got: clip(line),
                });
            }
        }
    }
    if pending_len.is_some() || pending_msg.is_some() {
        return Err(RspError::TruncatedRecord);
    }
    let digest_length_bytes = digest_length.ok_or(RspError::MissingLengthHeader)?;
    Ok(RspDocument {
        digest_length_bytes,
        cases,
    })
}

/// Split a `"key = value"` line into `(key, value)` with both sides
/// trimmed. Returns `None` if the `=` is absent.
fn split_kv(line: &str) -> Option<(&str, &str)> {
    let eq = line.find('=')?;
    let (k, rest) = line.split_at(eq);
    // `rest` starts with `=`; drop it.
    let v = rest.get(1..)?;
    Some((k.trim(), v.trim()))
}

/// Return the name of the field the parser was expecting next, for
/// use in [`RspError::UnexpectedField`] messages.
fn next_expected(pending_len: Option<&u64>, pending_msg: Option<&Vec<u8>>) -> &'static str {
    match (pending_len, pending_msg) {
        (None, _) => "Len",
        (Some(_), None) => "Msg",
        (Some(_), Some(_)) => "MD",
    }
}

/// Clip a diagnostic line to at most 64 bytes so error output stays
/// readable even when the offending line is a 2 KiB hex blob.
fn clip(line: &str) -> String {
    const MAX: usize = 64;
    if line.len() <= MAX {
        line.to_string()
    } else {
        let mut out = String::with_capacity(MAX + 1);
        // Find a safe char boundary ≤ MAX so we never slice inside a
        // multi-byte UTF-8 sequence. CAVP files are ASCII, but be safe.
        let mut end = MAX;
        while end > 0 && !line.is_char_boundary(end) {
            end -= 1;
        }
        out.push_str(&line[..end]);
        out.push('…');
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_two_record_file() {
        let src = "\
#  CAVS 11.0
#  \"SHA-256 ShortMsg\" information

[L = 32]

Len = 0
Msg = 00
MD = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

Len = 8
Msg = d3
MD = 28969cdfa74a12c82f3bad960b0b000aca2ac329deea5c2328ebc6f2ba9802c1
";
        let doc = parse(src).unwrap();
        assert_eq!(doc.digest_length_bytes, 32);
        assert_eq!(doc.cases.len(), 2);
        assert_eq!(doc.cases[0].len_bits, 0);
        assert_eq!(doc.cases[0].msg, vec![0x00]);
        assert_eq!(doc.cases[0].md.len(), 32);
        assert_eq!(doc.cases[1].len_bits, 8);
        assert_eq!(doc.cases[1].msg, vec![0xd3]);
    }

    #[test]
    fn tolerates_crlf_line_endings() {
        let src =
            "[L = 20]\r\nLen = 0\r\nMsg = 00\r\nMD = da39a3ee5e6b4b0d3255bfef95601890afd80709\r\n";
        let doc = parse(src).unwrap();
        assert_eq!(doc.digest_length_bytes, 20);
        assert_eq!(doc.cases.len(), 1);
        assert_eq!(doc.cases[0].md.len(), 20);
    }

    #[test]
    fn missing_length_header_is_error() {
        let src = "Len = 0\nMsg = 00\nMD = da39a3ee5e6b4b0d3255bfef95601890afd80709\n";
        assert!(matches!(parse(src), Err(RspError::MissingLengthHeader)));
    }

    #[test]
    fn out_of_order_field_is_error() {
        let src = "[L = 32]\nMsg = 00\nLen = 0\nMD = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n";
        let err = parse(src).unwrap_err();
        assert!(matches!(
            err,
            RspError::UnexpectedField {
                expected: "Len",
                ..
            }
        ));
    }

    #[test]
    fn truncated_record_is_error() {
        let src = "[L = 32]\nLen = 0\nMsg = 00\n"; // missing MD
        assert!(matches!(parse(src), Err(RspError::TruncatedRecord)));
    }

    #[test]
    fn non_integer_len_is_error() {
        let src = "[L = 32]\nLen = notanumber\nMsg = 00\nMD = 00\n";
        let err = parse(src).unwrap_err();
        assert!(matches!(err, RspError::InvalidInteger { field: "Len", .. }));
    }

    #[test]
    fn invalid_hex_is_error() {
        let src = "[L = 32]\nLen = 8\nMsg = zz\nMD = 00\n";
        let err = parse(src).unwrap_err();
        assert!(matches!(err, RspError::InvalidHex { field: "Msg", .. }));
    }
}
