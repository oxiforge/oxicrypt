//! Helpers for ACVP XOF Monte Carlo Tests (MCT).
//!
//! Implements the support functions defined in draft-celi-acvp-xof
//! §6.2.4 used by the cSHAKE / TupleHash / ParallelHash MCT state
//! machines. All bit-string operations here assume byte alignment
//! because every length parameter in the ACVP XOF MCT prompts (`msg`,
//! `outputLen`, `outLenIncrement`, `blockSize`) is byte-aligned.

/// §6.2.4.1 BitsToString — for each byte in `bits`, append ASCII char
/// equal to `(byte % 26) + 65`, producing a string of uppercase
/// letters `A`..=`Z`. The output length in bytes equals the input
/// length in bytes.
pub fn bits_to_string(bits: &[u8]) -> Vec<u8> {
    bits.iter().map(|&b| (b % 26) + 65).collect()
}

/// §6.2.4.2 Left — leftmost `num_bits` bits of `bits`. Panics if
/// `num_bits` is not byte-aligned. Returns an owned vector so that
/// callers can pass it forward without lifetime entanglement.
pub fn left(bits: &[u8], num_bits: usize) -> Vec<u8> {
    assert_eq!(num_bits % 8, 0, "Left() requires byte-aligned num_bits");
    let n = num_bits / 8;
    if n <= bits.len() {
        bits[..n].to_vec()
    } else {
        // Pad with zeros on the right to reach n bytes — matches the
        // spec's "Left(Output || ZeroBits(N), N)" idiom where the
        // input is padded out before slicing.
        let mut out = Vec::with_capacity(n);
        out.extend_from_slice(bits);
        out.resize(n, 0u8);
        out
    }
}

/// §6.2.4.3 Right — rightmost `num_bits` bits of `bits`. Panics if
/// `num_bits` is not byte-aligned. If `bits` is shorter than the
/// requested length, the result is zero-padded on the left.
pub fn right(bits: &[u8], num_bits: usize) -> Vec<u8> {
    assert_eq!(num_bits % 8, 0, "Right() requires byte-aligned num_bits");
    let n = num_bits / 8;
    if bits.len() >= n {
        bits[bits.len() - n..].to_vec()
    } else {
        let mut out = vec![0u8; n - bits.len()];
        out.extend_from_slice(bits);
        out
    }
}

/// §6.2.4.4 ZeroBits — all-zero bit string of length `num_bits` bits.
/// Panics if `num_bits` is not byte-aligned.
pub fn zero_bits(num_bits: usize) -> Vec<u8> {
    assert_eq!(num_bits % 8, 0, "ZeroBits() requires byte-aligned num_bits");
    vec![0u8; num_bits / 8]
}

/// Interpret a 16-bit big-endian byte pair as a `usize`. The XOF MCT
/// pseudocode says the rightmost-16-bits value is "interpreted as a
/// little-endian-encoded number, where the first 8-bits are the
/// most-significant byte" — that wording is contradictory, but the
/// "first byte = most significant" half is the operational rule
/// (matches the SHA-3 MCT convention and the ACVP-Server reference
/// generator). This helper exists so all three MCT state machines
/// route through one well-named function and the convention is
/// settled in one place.
pub fn be_u16_from_2_bytes(bytes: &[u8]) -> u16 {
    debug_assert_eq!(bytes.len(), 2, "be_u16_from_2_bytes expects 2 bytes");
    (u16::from(bytes[0]) << 8) | u16::from(bytes[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_to_string_maps_each_byte_to_letter() {
        assert_eq!(bits_to_string(&[]), b"");
        assert_eq!(bits_to_string(&[0]), b"A");
        assert_eq!(bits_to_string(&[25]), b"Z");
        assert_eq!(bits_to_string(&[26]), b"A");
        assert_eq!(bits_to_string(&[51]), b"Z");
        assert_eq!(bits_to_string(&[0, 1, 25, 26]), b"ABZA");
    }

    #[test]
    fn left_takes_prefix_bytes() {
        assert_eq!(left(&[1, 2, 3, 4, 5], 24), vec![1, 2, 3]);
        assert_eq!(left(&[1, 2, 3, 4, 5], 0), vec![]);
        assert_eq!(left(&[1, 2, 3, 4, 5], 40), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn left_pads_with_zeros_when_input_is_short() {
        // "Left(Output || ZeroBits(128), 128)" applied to a 2-byte
        // Output should yield 16 bytes: the 2 input bytes followed
        // by 14 zero bytes.
        assert_eq!(left(&[0xAA, 0xBB], 128), {
            let mut v = vec![0xAA, 0xBB];
            v.resize(16, 0);
            v
        });
    }

    #[test]
    fn right_takes_suffix_bytes() {
        assert_eq!(right(&[1, 2, 3, 4, 5], 16), vec![4, 5]);
        assert_eq!(right(&[1, 2, 3, 4, 5], 0), vec![]);
        assert_eq!(right(&[1, 2, 3, 4, 5], 40), vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn right_pads_with_zeros_when_input_is_short() {
        assert_eq!(right(&[0xAA], 16), vec![0x00, 0xAA]);
    }

    #[test]
    fn zero_bits_produces_zero_buffer() {
        assert_eq!(zero_bits(128), vec![0u8; 16]);
        assert_eq!(zero_bits(0), Vec::<u8>::new());
    }

    #[test]
    fn be_u16_unpacks_first_byte_as_msb() {
        assert_eq!(be_u16_from_2_bytes(&[0x12, 0x34]), 0x1234);
        assert_eq!(be_u16_from_2_bytes(&[0xFF, 0xFF]), 0xFFFF);
        assert_eq!(be_u16_from_2_bytes(&[0x00, 0x01]), 1);
    }

    #[test]
    #[should_panic(expected = "Left() requires byte-aligned num_bits")]
    fn left_panics_on_non_byte_aligned_request() {
        let _ = left(&[1, 2, 3], 7);
    }

    #[test]
    #[should_panic(expected = "Right() requires byte-aligned num_bits")]
    fn right_panics_on_non_byte_aligned_request() {
        let _ = right(&[1, 2, 3], 7);
    }

    #[test]
    #[should_panic(expected = "ZeroBits() requires byte-aligned num_bits")]
    fn zero_bits_panics_on_non_byte_aligned_request() {
        let _ = zero_bits(7);
    }
}
