//! Minimal hex codec for ACVP data fields.
//!
//! ACVP emits hex strings with uppercase `A`-`F` (e.g. `"04058B18..."`).
//! We accept either case on decode and always emit uppercase on encode
//! so that diffing generated responses against NIST's reference
//! `internalProjection.json` files is byte-identical.
//!
//! Kept in-tree (rather than pulled from a third-party crate) for the
//! same reason [`crate::json`] is in-tree: zero external deps in the
//! validation harness, matching the module itself.

use core::fmt;

/// Errors produced by [`decode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HexError {
    /// The input length is not a multiple of two.
    OddLength,
    /// A byte at `pos` is not a valid hex digit.
    InvalidChar {
        /// Zero-based offset of the offending byte inside the input.
        pos: usize,
        /// The offending byte value.
        byte: u8,
    },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength => write!(f, "hex string has odd length"),
            Self::InvalidChar { pos, byte } => {
                write!(f, "invalid hex digit {byte:#04x} at position {pos}")
            }
        }
    }
}

/// Decode a hex string into raw bytes.
pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    let mut out = Vec::with_capacity(b.len() / 2);
    let mut i = 0;
    while i < b.len() {
        let hi = nibble(b[i], i)?;
        let lo = nibble(b[i + 1], i + 1)?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn nibble(b: u8, pos: usize) -> Result<u8, HexError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(HexError::InvalidChar { pos, byte: b }),
    }
}

/// Encode bytes as uppercase hex.
#[must_use]
pub fn encode_upper(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(data.len() * 2);
    for &byte in data {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_upper() {
        assert_eq!(decode("AB01CD").unwrap(), vec![0xAB, 0x01, 0xCD]);
        assert_eq!(encode_upper(&[0xAB, 0x01, 0xCD]), "AB01CD");
    }

    #[test]
    fn decode_accepts_mixed_case() {
        assert_eq!(decode("aB01cD").unwrap(), vec![0xAB, 0x01, 0xCD]);
    }

    #[test]
    fn decode_rejects_odd_length() {
        assert!(matches!(decode("abc"), Err(HexError::OddLength)));
    }

    #[test]
    fn decode_rejects_bad_char() {
        assert!(matches!(
            decode("zz"),
            Err(HexError::InvalidChar { pos: 0, .. })
        ));
    }

    #[test]
    fn empty_round_trip() {
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(encode_upper(&[]), "");
    }
}
