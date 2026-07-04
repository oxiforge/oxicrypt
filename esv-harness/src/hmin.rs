//! Exact `hminEstimate` serialization from the module's fixed-point
//! min-entropy type (ISC-109).
//!
//! # Why an exact path
//!
//! The registration payload carries `hminEstimate` — the claimed min-entropy
//! per sample. The oxicrypt module represents min-entropy as
//! [`oxicrypt_entropy::h::MinEntropy`]: an exact fixed-point number in steps
//! of 1/256 bit, so that no `f64` ever sits on the claim path (the module's
//! "no floats on the claim or cutoff path" principle). Rendering that value
//! through an `f64` would reintroduce the very float this crate's fixed-point
//! `H` exists to avoid.
//!
//! Every 1/256-bit step is a dyadic rational `n/256` with denominator
//! `2^8`, so it is **always finitely representable in decimal** — exactly, in
//! at most eight fractional digits (`1/256 = 0.003_906_25`,
//! `128/256 = 0.5`, `193/256 = 0.753_906_25`). [`serialize_hmin`] produces
//! that exact decimal string with pure integer arithmetic — never an `f64`,
//! never a rounding step — by scaling the fractional steps by
//! `10^8 / 256 = 390_625` (an exact quotient, since `256 · 390_625 = 10^8`).
//!
//! # Bounds
//!
//! The vendored NIST metadata schema (and server rule `hMinEstimate.json`)
//! constrain `0.0 <= hminEstimate <= bitsPerSample`. [`hmin_wire_token`]
//! enforces that upper bound against the fixed-point value before rendering,
//! returning a typed [`HminError`] rather than emitting an over-claim. The
//! lower bound holds structurally: [`oxicrypt_entropy::h::MinEntropy`] is a
//! `u32` step count, so it can never be negative.
//!
//! # Round-trip
//!
//! The emitted token is a valid RFC 8259 JSON number and round-trips
//! byte-for-byte through the crate's lossless [`crate::jsonlite`] reader (it
//! is captured as a raw source token, never reinterpreted) — proven in the
//! module tests, which reconstruct every `n/256` value from the parsed token
//! and confirm the exact decimal.

use oxicrypt_entropy::h::{H_STEPS_PER_BIT, MinEntropy};

/// `10^8 / H_STEPS_PER_BIT`. Exact because `H_STEPS_PER_BIT` (256) divides
/// `10^8` evenly (`256 · 390_625 = 100_000_000`): one 1/256-bit step is
/// exactly `390_625 · 10^-8`, so `rem` steps scale to `rem · 390_625` as the
/// eight-digit fractional part. (The exact-divisibility invariant is asserted
/// in the tests.)
const FRAC_SCALE_1E8: u64 = 390_625;

/// A reason an `hminEstimate` cannot be serialized for a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HminError {
    /// The claimed min-entropy exceeds `bitsPerSample` (schema/rule
    /// `hMinEstimate.json`: `hminEstimate <= bitsPerSample`) — a min-entropy
    /// claim wider than one sample's width is never emitted.
    AboveBitsPerSample {
        /// The claimed value in 1/256-bit steps.
        steps: u32,
        /// The `bitsPerSample` ceiling from the registration.
        bits_per_sample: i64,
    },
    /// `bitsPerSample` was negative, so it names no valid ceiling.
    NegativeBitsPerSample {
        /// The offending value.
        bits_per_sample: i64,
    },
}

impl core::fmt::Display for HminError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AboveBitsPerSample {
                steps,
                bits_per_sample,
            } => write!(
                f,
                "hminEstimate {steps}/256 bits exceeds bitsPerSample {bits_per_sample}"
            ),
            Self::NegativeBitsPerSample { bits_per_sample } => {
                write!(f, "bitsPerSample {bits_per_sample} is negative")
            }
        }
    }
}

impl std::error::Error for HminError {}

/// Serialize a fixed-point min-entropy to its **exact** decimal JSON-number
/// token — pure integer arithmetic, no `f64`, no rounding.
///
/// A whole-bit value renders as a bare integer (`2`), matching the wire
/// renderer's integer form; a fractional value renders as
/// `<whole>.<fraction>` with trailing zeros stripped (`128/256` → `0.5`,
/// `193/256` → `0.75390625`).
///
/// This performs **no** bounds check; use [`hmin_wire_token`] to enforce the
/// `<= bitsPerSample` schema bound before emitting into a payload.
#[must_use]
// `per_bit` is the nonzero constant 256, so `/` and `%` cannot panic; `rem`
// is in `0..256`, so `rem * 390_625 <= 99_609_375` cannot overflow `u64`.
#[allow(clippy::arithmetic_side_effects, clippy::integer_division)]
pub fn serialize_hmin(h: MinEntropy) -> String {
    let steps = u64::from(h.steps());
    let per_bit = u64::from(H_STEPS_PER_BIT);
    let whole = steps / per_bit;
    let rem = steps % per_bit;
    if rem == 0 {
        return whole.to_string();
    }
    // rem ∈ 1..=255 → frac ∈ [390_625, 99_609_375], always < 10^8, so the
    // fractional part is a proper eight-digit decimal (leading zeros kept).
    let frac = rem * FRAC_SCALE_1E8;
    let padded = format!("{frac:08}");
    let trimmed = padded.trim_end_matches('0');
    format!("{whole}.{trimmed}")
}

/// True iff `h` is within the schema bound `0 <= h <= bits_per_sample`.
///
/// The lower bound is structural ([`MinEntropy`] is non-negative); this
/// checks the upper bound in exact integer steps.
#[must_use]
pub fn hmin_within_bits(h: MinEntropy, bits_per_sample: i64) -> bool {
    let Ok(bits) = u64::try_from(bits_per_sample) else {
        return false; // negative bitsPerSample bounds nothing
    };
    u64::from(h.steps()) <= bits.saturating_mul(u64::from(H_STEPS_PER_BIT))
}

/// Serialize a fixed-point min-entropy to its exact decimal JSON-number
/// token, first enforcing the schema bound `0 <= h <= bits_per_sample`.
///
/// # Errors
/// [`HminError::NegativeBitsPerSample`] if `bits_per_sample` is negative;
/// [`HminError::AboveBitsPerSample`] if `h` exceeds `bits_per_sample` bits.
pub fn hmin_wire_token(h: MinEntropy, bits_per_sample: i64) -> Result<String, HminError> {
    if bits_per_sample < 0 {
        return Err(HminError::NegativeBitsPerSample { bits_per_sample });
    }
    if !hmin_within_bits(h, bits_per_sample) {
        return Err(HminError::AboveBitsPerSample {
            steps: h.steps(),
            bits_per_sample,
        });
    }
    Ok(serialize_hmin(h))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp
)]
mod tests {
    use super::*;
    use crate::jsonlite::{self, JsonLite};

    /// The scale constant divides 10^8 exactly (the invariant that makes the
    /// fractional decimal exact) and equals `10^8 / H_STEPS_PER_BIT`.
    #[test]
    fn frac_scale_divides_1e8_exactly() {
        assert_eq!(FRAC_SCALE_1E8 * u64::from(H_STEPS_PER_BIT), 100_000_000);
    }

    /// Exact decimal for representative grid points (the fixed-point steps
    /// n/256 → their exact decimal expansions).
    #[test]
    fn serializes_grid_points_exactly() {
        assert_eq!(serialize_hmin(MinEntropy::from_steps(0)), "0");
        assert_eq!(serialize_hmin(MinEntropy::from_steps(1)), "0.00390625"); // 1/256
        assert_eq!(serialize_hmin(MinEntropy::from_steps(128)), "0.5"); // 128/256
        assert_eq!(serialize_hmin(MinEntropy::from_steps(192)), "0.75"); // 192/256
        assert_eq!(serialize_hmin(MinEntropy::from_steps(193)), "0.75390625"); // 193/256
        assert_eq!(serialize_hmin(MinEntropy::from_bits(2)), "2"); // whole bits → bare int
        assert_eq!(serialize_hmin(MinEntropy::from_bits(8)), "8");
    }

    /// Every one of the 256 fractional residues renders to a token that (a)
    /// round-trips byte-for-byte through the lossless jsonlite reader, and
    /// (b) reconstructs the exact n/256 value.
    #[test]
    fn all_256_residues_round_trip_byte_exact_and_reconstruct() {
        for whole in [0u32, 1, 3] {
            for rem in 0u32..256 {
                let steps = whole * 256 + rem;
                let h = MinEntropy::from_steps(steps);
                let token = serialize_hmin(h);

                // (a) The token is a valid JSON number captured verbatim.
                let parsed = jsonlite::parse(&token).unwrap();
                assert_eq!(
                    parsed,
                    JsonLite::Number(token.clone()),
                    "token {token} did not round-trip byte-for-byte"
                );

                // (b) It reconstructs the exact value: token · 256 == steps.
                let value: f64 = token.parse().unwrap();
                // Exact (dyadic) reconstruction: token · 256 == steps, in f64
                // that carries no rounding because n/256 is exactly representable.
                assert_eq!(
                    value,
                    f64::from(steps) / 256.0,
                    "token {token} reconstructed the wrong value"
                );
            }
        }
    }

    /// No emitted fractional token carries a trailing zero or a bare
    /// trailing point (both would be non-canonical).
    #[test]
    fn fractional_tokens_are_trimmed() {
        for rem in 1u32..256 {
            let token = serialize_hmin(MinEntropy::from_steps(rem));
            assert!(token.contains('.'), "{token} should be fractional");
            assert!(!token.ends_with('0'), "{token} has a trailing zero");
            assert!(!token.ends_with('.'), "{token} has a bare trailing point");
        }
    }

    #[test]
    fn within_bits_enforces_the_upper_bound() {
        // 4 bits = 1024 steps: exactly at the ceiling is in-bounds.
        assert!(hmin_within_bits(MinEntropy::from_bits(4), 4));
        assert!(hmin_within_bits(MinEntropy::from_steps(1023), 4));
        // One step over the ceiling is out.
        assert!(!hmin_within_bits(MinEntropy::from_steps(1025), 4));
        // Negative bitsPerSample bounds nothing.
        assert!(!hmin_within_bits(MinEntropy::from_steps(1), -1));
        // Zero entropy is always in-bounds for any non-negative ceiling.
        assert!(hmin_within_bits(MinEntropy::ZERO, 0));
    }

    #[test]
    fn wire_token_rejects_over_claim_and_negative_ceiling() {
        // 193/256 bits under a 4-bit ceiling → fine.
        assert_eq!(
            hmin_wire_token(MinEntropy::from_steps(193), 4).unwrap(),
            "0.75390625"
        );
        // 5 bits claimed under a 4-bit ceiling → typed refusal.
        assert_eq!(
            hmin_wire_token(MinEntropy::from_bits(5), 4),
            Err(HminError::AboveBitsPerSample {
                steps: 5 * 256,
                bits_per_sample: 4,
            })
        );
        // Negative ceiling → typed refusal.
        assert_eq!(
            hmin_wire_token(MinEntropy::from_steps(1), -1),
            Err(HminError::NegativeBitsPerSample {
                bits_per_sample: -1,
            })
        );
    }
}
