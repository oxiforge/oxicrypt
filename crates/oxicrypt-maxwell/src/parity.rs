//! Parity harness: check the MCV and Collision estimators against the NIST EA
//! tool v1.1.8.
//!
//! The reference table ([`REFERENCE_TABLE`]) records, per dataset, the
//! filename, declared bits-per-symbol, the dataset's SHA-256 (provenance), the
//! EA tool's literal and (where applicable) bitstring MCV min-entropy values,
//! and the EA tool's **bitstring Collision** min-entropy value (SP 800-90B
//! §6.3.2). The harness loads each present dataset, verifies its SHA-256 against
//! the recorded digest, computes both MCV tracks **and** the collision estimate,
//! and compares all of them against the reference values at the pre-registered
//! **1.0e-6 bits** absolute tolerance (`docs/estimator-parity-tolerances.md`).
//!
//! The collision estimator runs on the bitstring track only (the EA tool calls
//! `collision_test(data.bsymbols, …)`), so every dataset — including 1-bit data
//! — carries one collision reference value. The `normal` dataset is the
//! "Could Not Find p" edge case (collision min-entropy `1.0`); see
//! [`crate::collision`].
//!
//! A dataset whose file is **absent** is reported [`Outcome::Skip`] — not a
//! failure. A present dataset whose computed value diverges by more than the
//! tolerance, or whose on-disk SHA-256 does not match its recorded provenance
//! digest, is [`Outcome::Fail`].

use std::path::{Path, PathBuf};

use crate::collision::collision;
use crate::{McvResult, mcv};

/// Pre-registered absolute parity tolerance, in bits of min-entropy.
///
/// Matches `docs/estimator-parity-tolerances.md`. Do not loosen without the
/// written numerical-analysis rationale and project-lead sign-off described
/// there (and never in response to a failing result).
pub const PARITY_TOLERANCE_BITS: f64 = 1.0e-6;

/// One row of the EA-tool reference table.
#[derive(Debug, Clone, Copy)]
pub struct Reference {
    /// Short dataset name.
    pub name: &'static str,
    /// File name within the dataset directory.
    pub file: &'static str,
    /// Declared symbol width in bits, `1..=8`.
    pub bits_per_symbol: u8,
    /// Lowercase hex SHA-256 of the dataset file (provenance).
    pub sha256: &'static str,
    /// EA tool "Literal MCV min entropy" value.
    pub literal_min_entropy: f64,
    /// EA tool "Bitstring MCV min entropy" value; `None` for 1-bit data.
    pub bitstring_min_entropy: Option<f64>,
    /// EA tool §6.3.2 **bitstring** Collision min-entropy value. The collision
    /// estimator always runs on the bitstring track, so every dataset (including
    /// 1-bit data) declares one. `normal` is the "Could Not Find p" edge case
    /// (`1.0`).
    pub collision_min_entropy: f64,
}

/// The 11 EA-distribution reference datasets and their EA tool v1.1.8 MCV
/// min-entropy values. Datasets are NIST-distributed and referenced by path,
/// never vendored; the SHA-256 column is their provenance fingerprint.
pub const REFERENCE_TABLE: &[Reference] = &[
    Reference {
        name: "biased-random-bits",
        file: "biased-random-bits.bin",
        bits_per_symbol: 1,
        sha256: "481cdac6e2d65d45656c21234125eaf26df18a49037f15ffd40002b35e547586",
        literal_min_entropy: 0.028_633_069_781_464_744,
        bitstring_min_entropy: None,
        collision_min_entropy: 0.028_513_792_826_254_068,
    },
    Reference {
        name: "biased-random-bytes",
        file: "biased-random-bytes.bin",
        bits_per_symbol: 8,
        sha256: "146bd7497d8e2d61a6e8559c9342ee79f6005a390ee4d776ba43500d00eb508d",
        literal_min_entropy: 0.319_650_651_838_182_03,
        bitstring_min_entropy: Some(0.151_827_325_076_523_44),
        collision_min_entropy: 0.072_705_888_458_565_96,
    },
    Reference {
        name: "data.pi",
        file: "data.pi.bin",
        bits_per_symbol: 1,
        sha256: "d9a7de4e1f170f363bcb2a85570e4b6ed2320d5500abc5795bc4bfadcb93b928",
        literal_min_entropy: 0.811_140_579_704_074_4,
        bitstring_min_entropy: None,
        collision_min_entropy: 0.569_537_593_457_779,
    },
    Reference {
        name: "normal",
        file: "normal.bin",
        bits_per_symbol: 8,
        sha256: "a70ce92a71b9b0c6dee80335ef570dea618631ee64cc735b033e9f402f14bc7d",
        literal_min_entropy: 5.622_155_277_204_775,
        bitstring_min_entropy: Some(0.996_315_460_805_651_6),
        // Edge case: X̄' ≥ 2.5 → "Could Not Find p" → p = 0.5, H = 1.0.
        collision_min_entropy: 1.0,
    },
    Reference {
        name: "rand1_short",
        file: "rand1_short.bin",
        bits_per_symbol: 1,
        sha256: "3814404497a3b912f8d3db6bc05a99338f0986cd75fe54af2a5f1bdb0a12a583",
        literal_min_entropy: 0.961_058_825_700_550_8,
        bitstring_min_entropy: None,
        collision_min_entropy: 0.691_464_120_997_246_6,
    },
    Reference {
        name: "rand4_short",
        file: "rand4_short.bin",
        bits_per_symbol: 4,
        sha256: "a9e2169cb1accc78cd23892d793a232b84b0cd13ccc3923526e0b20762bd77ac",
        literal_min_entropy: 3.790_037_390_213_974,
        bitstring_min_entropy: Some(0.979_189_482_962_402_2),
        collision_min_entropy: 0.898_179_448_381_018_8,
    },
    Reference {
        name: "rand8_short",
        file: "rand8_short.bin",
        bits_per_symbol: 8,
        sha256: "17d2eaf9544cd6aea3e245bec362f494376d0b1ca6140c475a35f1ad1f8c2803",
        literal_min_entropy: 7.010_454_037_736_041,
        bitstring_min_entropy: Some(0.983_386_784_659_150_3),
        collision_min_entropy: 0.832_052_982_215_248,
    },
    Reference {
        name: "ringOsc-nist",
        file: "ringOsc-nist.bin",
        bits_per_symbol: 1,
        sha256: "7d37dc3795e9b2927beb779008d7f4b4630dd7f2c058a2b14cee9d41a658dd68",
        literal_min_entropy: 0.993_514_068_761_158_6,
        bitstring_min_entropy: None,
        collision_min_entropy: 0.126_445_736_196_048_68,
    },
    Reference {
        name: "truerand_1bit",
        file: "truerand_1bit.bin",
        bits_per_symbol: 1,
        sha256: "f9ea8832af4c4205f518845b264465800921688fc2c4d566fbc087664aeb2313",
        literal_min_entropy: 0.995_043_015_131_225_7,
        bitstring_min_entropy: None,
        collision_min_entropy: 0.900_935_726_908_247_5,
    },
    Reference {
        name: "truerand_4bit",
        file: "truerand_4bit.bin",
        bits_per_symbol: 4,
        sha256: "489bc841bb364ba86da70b1617138aef76b25dd9196ad669eef40c1441b6cb88",
        literal_min_entropy: 3.971_194_336_729_609_6,
        bitstring_min_entropy: Some(0.997_730_385_822_156_6),
        collision_min_entropy: 0.928_360_945_304_648,
    },
    Reference {
        name: "truerand_8bit",
        file: "truerand_8bit.bin",
        bits_per_symbol: 8,
        sha256: "c7e56911d2657fa9b6e86c03d4477474d6ec698691c5f32d3918ec513713e3c3",
        literal_min_entropy: 7.865_118_002_899_59,
        bitstring_min_entropy: Some(0.998_199_280_119_827_5),
        collision_min_entropy: 0.958_406_295_418_469_6,
    },
];

/// Outcome of comparing one dataset against its reference row.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// File present, all checked estimators within tolerance, provenance
    /// verified.
    Pass {
        /// Absolute delta on the MCV literal track.
        literal_delta: f64,
        /// Absolute delta on the MCV bitstring track (`None` for 1-bit data).
        bitstring_delta: Option<f64>,
        /// Absolute delta on the §6.3.2 bitstring Collision estimate.
        collision_delta: f64,
    },
    /// File absent — not counted as a failure.
    Skip {
        /// Reason the dataset was skipped (e.g. file not found).
        reason: String,
    },
    /// File present but provenance or a tolerance check failed.
    Fail {
        /// Human-readable failure reason.
        reason: String,
    },
}

/// A single dataset's parity result.
#[derive(Debug, Clone)]
pub struct DatasetResult {
    /// Dataset name (from [`Reference::name`]).
    pub name: &'static str,
    /// The outcome.
    pub outcome: Outcome,
}

impl DatasetResult {
    /// One-line human-readable summary, e.g.
    /// `PASS rand8_short            lit Δ=0.0e0  bit Δ=0.0e0`.
    #[must_use]
    pub fn line(&self) -> String {
        match &self.outcome {
            Outcome::Pass {
                literal_delta,
                bitstring_delta,
                collision_delta,
            } => {
                let bit = bitstring_delta
                    .map_or_else(|| "  bit -".to_string(), |d| format!("  bit Δ={d:.1e}"));
                format!(
                    "PASS {:24} lit Δ={:.1e}{}  col Δ={:.1e}",
                    self.name, literal_delta, bit, collision_delta
                )
            }
            Outcome::Skip { reason } => format!("SKIP {:24} {}", self.name, reason),
            Outcome::Fail { reason } => format!("FAIL {:24} {}", self.name, reason),
        }
    }
}

/// Resolve the dataset directory.
///
/// Precedence: explicit `dir` argument, then `OXICRYPT_EA_DATA`, then the
/// default `~/repos/SP800-90B_EntropyAssessment/bin` (expanding `~` via `HOME`).
#[must_use]
pub fn resolve_datasets_dir(dir: Option<&Path>) -> PathBuf {
    if let Some(d) = dir {
        return d.to_path_buf();
    }
    if let Ok(env) = std::env::var("OXICRYPT_EA_DATA")
        && !env.is_empty()
    {
        return PathBuf::from(env);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join("repos/SP800-90B_EntropyAssessment/bin")
}

/// Lowercase-hex encode a digest.
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        // Two hex nibbles per byte; write! into a String cannot fail.
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Power the validated module up to `Operational` with the real SHA-256 KAT
/// set so the gated `oxicrypt_sha::sha256` provenance hash can run. Idempotent
/// and concurrency-safe: the module's state machine lets exactly one caller win
/// the `PowerOff -> SelfTest` transition; every later call returns
/// `AlreadyInitialized`, which is success for our purposes.
fn ensure_module_powered_up() -> Result<(), oxicrypt_module::Error> {
    match oxicrypt_module::initialize_with_tests(oxicrypt_sha::KATS) {
        Ok(()) | Err(oxicrypt_module::Error::AlreadyInitialized) => Ok(()),
        Err(e) => Err(e),
    }
}

/// Verify the on-disk `data` matches the reference's recorded SHA-256.
///
/// Returns `Err` with the same failure messages `check_one` would emit on a
/// provenance mismatch or a SHA-256 service error.
fn verify_provenance(reference: &Reference, data: &[u8]) -> Result<(), String> {
    match oxicrypt_sha::sha256(data) {
        Ok(digest) => {
            let got = hex(&digest);
            if got != reference.sha256 {
                return Err(format!(
                    "provenance mismatch: expected {}, got {got}",
                    reference.sha256
                ));
            }
            Ok(())
        }
        Err(e) => Err(format!("sha256 error: {e:?}")),
    }
}

/// Compute both MCV tracks for `data` and compare them to the reference's
/// recorded values.
///
/// Returns `(literal_delta, bitstring_delta)` on success, or the same failure
/// message `check_one` would emit on a tolerance breach or a track-presence
/// mismatch. Extracted from `check_one` so that function stays within the line
/// budget; the comparison logic is byte-for-byte the same.
fn check_mcv(reference: &Reference, data: &[u8]) -> Result<(f64, Option<f64>), String> {
    let result: McvResult = mcv(data, reference.bits_per_symbol);

    let literal_delta = (result.literal.min_entropy - reference.literal_min_entropy).abs();
    if literal_delta > PARITY_TOLERANCE_BITS {
        return Err(format!(
            "literal Δ={literal_delta:.3e} > {PARITY_TOLERANCE_BITS:.0e} \
             (got {}, ref {})",
            result.literal.min_entropy, reference.literal_min_entropy
        ));
    }

    // Bitstring track: compare only when the reference declares one.
    let bitstring_delta = match (reference.bitstring_min_entropy, result.bitstring) {
        (Some(ref_bs), Some(got_bs)) => {
            let d = (got_bs.min_entropy - ref_bs).abs();
            if d > PARITY_TOLERANCE_BITS {
                return Err(format!(
                    "bitstring Δ={d:.3e} > {PARITY_TOLERANCE_BITS:.0e} \
                     (got {}, ref {ref_bs})",
                    got_bs.min_entropy
                ));
            }
            Some(d)
        }
        (None, None) => None,
        (Some(_), None) => {
            return Err(
                "reference declares a bitstring track but computation produced none".to_string(),
            );
        }
        (None, Some(_)) => {
            return Err(
                "computation produced a bitstring track but reference declares none".to_string(),
            );
        }
    };

    Ok((literal_delta, bitstring_delta))
}

/// Compute the §6.3.2 collision estimate for `data` and compare it to the
/// reference's recorded value.
///
/// Returns the absolute delta on success, or the same failure message
/// `check_one` would emit when the collision delta exceeds the tolerance.
/// Extracted from `check_one` so that function stays within the line budget.
fn check_collision(reference: &Reference, data: &[u8]) -> Result<f64, String> {
    let collision_est = collision(data, reference.bits_per_symbol);
    let collision_delta = (collision_est.min_entropy - reference.collision_min_entropy).abs();
    if collision_delta > PARITY_TOLERANCE_BITS {
        return Err(format!(
            "collision Δ={collision_delta:.3e} > {PARITY_TOLERANCE_BITS:.0e} \
             (got {}, ref {})",
            collision_est.min_entropy, reference.collision_min_entropy
        ));
    }
    Ok(collision_delta)
}

/// Check one dataset against its reference row (MCV + Collision).
///
/// Skips when the dataset file is absent; fails on a read error, a provenance
/// (SHA-256) mismatch, a SHA-256 service error, or any estimator's min-entropy
/// delta above [`PARITY_TOLERANCE_BITS`] (MCV literal, MCV bitstring where
/// declared, or §6.3.2 collision); otherwise passes with the per-estimator
/// deltas.
pub fn check_one(reference: &Reference, dir: &Path) -> DatasetResult {
    if let Err(e) = ensure_module_powered_up() {
        return DatasetResult {
            name: reference.name,
            outcome: Outcome::Fail {
                reason: format!("module power-up failed: {e:?}"),
            },
        };
    }

    let path = dir.join(reference.file);

    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return DatasetResult {
                name: reference.name,
                outcome: Outcome::Skip {
                    reason: format!("file absent ({})", path.display()),
                },
            };
        }
        Err(e) => {
            return DatasetResult {
                name: reference.name,
                outcome: Outcome::Fail {
                    reason: format!("read error: {e}"),
                },
            };
        }
    };

    // Provenance: the on-disk file must match the recorded SHA-256.
    if let Err(reason) = verify_provenance(reference, &data) {
        return DatasetResult {
            name: reference.name,
            outcome: Outcome::Fail { reason },
        };
    }

    let (literal_delta, bitstring_delta) = match check_mcv(reference, &data) {
        Ok(deltas) => deltas,
        Err(reason) => {
            return DatasetResult {
                name: reference.name,
                outcome: Outcome::Fail { reason },
            };
        }
    };

    // §6.3.2 Collision estimate — always on the bitstring track, so every
    // dataset (including 1-bit data) carries a reference value to check.
    let collision_delta = match check_collision(reference, &data) {
        Ok(d) => d,
        Err(reason) => {
            return DatasetResult {
                name: reference.name,
                outcome: Outcome::Fail { reason },
            };
        }
    };

    DatasetResult {
        name: reference.name,
        outcome: Outcome::Pass {
            literal_delta,
            bitstring_delta,
            collision_delta,
        },
    }
}

/// Run the full parity table against `dir`. Returns one result per reference
/// row, in table order.
#[must_use]
pub fn run_parity(dir: &Path) -> Vec<DatasetResult> {
    REFERENCE_TABLE.iter().map(|r| check_one(r, dir)).collect()
}

/// Aggregate verdict across a set of dataset results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// Number of datasets that passed.
    pub passed: usize,
    /// Number of datasets skipped (file absent).
    pub skipped: usize,
    /// Number of datasets that failed.
    pub failed: usize,
}

impl Verdict {
    /// Tally a slice of results.
    #[must_use]
    pub fn tally(results: &[DatasetResult]) -> Self {
        let mut v = Verdict {
            passed: 0,
            skipped: 0,
            failed: 0,
        };
        for r in results {
            match r.outcome {
                Outcome::Pass { .. } => v.passed = v.passed.saturating_add(1),
                Outcome::Skip { .. } => v.skipped = v.skipped.saturating_add(1),
                Outcome::Fail { .. } => v.failed = v.failed.saturating_add(1),
            }
        }
        v
    }

    /// True when no dataset failed (skips are acceptable).
    #[must_use]
    pub fn ok(&self) -> bool {
        self.failed == 0
    }
}

#[cfg(test)]
#[allow(
    // Tests panic on parity failures and assert exact structural invariants.
    clippy::panic,
    clippy::unwrap_used,
    clippy::expect_used
)]
mod tests {
    use super::*;

    /// Full parity table against `OXICRYPT_EA_DATA` (or the default path).
    /// Absent files SKIP; present files must pass both tracks within 1e-6.
    #[test]
    fn parity_table_within_tolerance() {
        let dir = resolve_datasets_dir(None);
        let results = run_parity(&dir);
        // Present files must pass both tracks; a failure is fatal. Datasets that
        // are simply absent on this host SKIP, which is an accepted outcome (the
        // all-SKIP verdict conveys it) — so no assertion fires on absence.
        for r in &results {
            if let Outcome::Fail { reason } = &r.outcome {
                panic!("dataset {} FAILED parity: {reason}", r.name);
            }
        }
    }

    #[test]
    fn reference_table_is_well_formed() {
        for r in REFERENCE_TABLE {
            assert!(
                (1..=8).contains(&r.bits_per_symbol),
                "{}: bits_per_symbol out of range",
                r.name
            );
            assert_eq!(r.sha256.len(), 64, "{}: sha256 not 64 hex chars", r.name);
            assert!(
                r.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
                "{}: sha256 not hex",
                r.name
            );
            // 1-bit data must declare no bitstring track; multi-bit must.
            if r.bits_per_symbol == 1 {
                assert!(
                    r.bitstring_min_entropy.is_none(),
                    "{}: 1-bit has bitstring",
                    r.name
                );
            } else {
                assert!(
                    r.bitstring_min_entropy.is_some(),
                    "{}: multi-bit missing bitstring",
                    r.name
                );
            }
            // Collision is a bitstring (binary) min-entropy in (0, 1]: H = -log2(p)
            // with p ∈ [0.5, 1], so 0 < H ≤ 1 always.
            assert!(
                r.collision_min_entropy > 0.0 && r.collision_min_entropy <= 1.0,
                "{}: collision min-entropy {} out of (0, 1]",
                r.name,
                r.collision_min_entropy
            );
        }
        assert_eq!(REFERENCE_TABLE.len(), 11);
    }
}
