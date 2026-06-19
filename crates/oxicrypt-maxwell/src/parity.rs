//! Parity harness: check the MCV, Collision, Markov, Compression, t-Tuple, LRS,
//! MultiMCW, Lag, MultiMMC, and LZ78Y estimators against the NIST EA tool v1.1.8.
//! LZ78Y (§6.3.10) completes the SP 800-90B §6.3 non-IID estimator suite.
//!
//! The reference table ([`REFERENCE_TABLE`]) records, per dataset, the
//! filename, declared bits-per-symbol, the dataset's SHA-256 (provenance), the
//! EA tool's literal and (where applicable) bitstring MCV min-entropy values,
//! the EA tool's **bitstring Collision** min-entropy value (SP 800-90B §6.3.2),
//! the EA tool's **bitstring Markov** min-entropy value (SP 800-90B §6.3.3), and
//! the EA tool's **bitstring Compression** min-entropy value (SP 800-90B
//! §6.3.4). The harness loads each present dataset, verifies its SHA-256 against
//! the recorded digest, computes both MCV tracks, the collision estimate, the
//! Markov estimate, **and** the compression estimate, and compares all of them
//! against the reference values at the pre-registered **1.0e-6 bits** absolute
//! tolerance (`docs/estimator-parity-tolerances.md`).
//!
//! The collision, Markov, and compression estimators all run on the bitstring
//! track only (the EA tool calls `collision_test(data.bsymbols, …)`,
//! `markov_test(data.bsymbols, …)`, and `compression_test(data.bsymbols, …)`),
//! so every dataset — including 1-bit data — carries one collision, one Markov,
//! and one compression reference value. The `normal` dataset is the collision
//! "Could Not Find p" edge case (collision min-entropy `1.0`); see
//! [`crate::collision`]. The Markov and compression reference values are the
//! verbose "min entropy" line of the EA tool's `selftest/*.res` files (the
//! controlling track per dataset — "Bitstring" for multi-bit data, "Literal"
//! for 1-bit data, which are the same binary computation); see [`crate::markov`]
//! and [`crate::compression`].
//!
//! A dataset whose file is **absent** is reported [`Outcome::Skip`] — not a
//! failure. A present dataset whose computed value diverges by more than the
//! tolerance, or whose on-disk SHA-256 does not match its recorded provenance
//! digest, is [`Outcome::Fail`].

use std::path::{Path, PathBuf};

use crate::chi_square::chi_square_tests;
use crate::collision::collision;
use crate::compression::compression;
use crate::iid_lrs::len_lrs_iid_test;
use crate::lag::lag;
use crate::lrs::lrs;
use crate::lz78y::lz78y;
use crate::markov::markov;
use crate::multi_mcw::multi_mcw;
use crate::multi_mmc::multi_mmc;
use crate::permutation::{permutation_stats, run_permutation};
use crate::{McvResult, mcv};

/// Pre-registered absolute parity tolerance, in bits of min-entropy.
///
/// Matches `docs/estimator-parity-tolerances.md`. Do not loosen without the
/// written numerical-analysis rationale and project-lead sign-off described
/// there (and never in response to a failing result).
pub const PARITY_TOLERANCE_BITS: f64 = 1.0e-6;

/// Version of the NIST EA reference tool the reference table was generated
/// against (`ea_iid` / `ea_non_iid` from `SP800-90B_EntropyAssessment`). Stamped
/// into the `maxwell parity` header for provenance (ISC-62). A documented
/// constant, not a runtime probe — the EA tool is referenced by path, never
/// vendored or invoked.
pub const EA_TOOL_VERSION: &str = "1.1.8";

/// Number of §5.1 permutation-battery L1 statistics checked for parity: all 19
/// statistics (EA index `0..=18`), including the compression slot (EA index 18),
/// which is now computed bit-exactly vs the EA tool.
pub const PERM_STATS_PARITY_COUNT: usize = 19;

/// Number of deterministic shuffles for the §5 L2 verdict parity check. Far
/// below the spec [`crate::permutation::PERMS`] (10_000) because the three short
/// datasets' verdicts are decided by extreme/deterministic statistics, not by a
/// marginal shuffle count; keeps the harness fast while the verdict is stable.
pub const PERM_VERDICT_PARITY_SHUFFLES: usize = 1500;

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
    /// EA tool §6.3.3 **bitstring** Markov min-entropy value. The Markov
    /// estimator always runs on the bitstring track, so every dataset (including
    /// 1-bit data) declares one. Recorded from the verbose "min entropy" line of
    /// the EA tool's `selftest/*.res` files; per-bit and capped at `1.0`.
    pub markov_min_entropy: f64,
    /// EA tool §6.3.4 **bitstring** Compression min-entropy value. The
    /// compression estimator always runs on the bitstring track, so every
    /// dataset (including 1-bit data) declares one. Recorded from the verbose
    /// "min entropy" line of the EA tool's `selftest/*.res` files (the
    /// controlling track — "Bitstring" for multi-bit data, "Literal" for 1-bit
    /// data); per-bit and in `(0, 1]`.
    pub compression_min_entropy: f64,
    /// EA tool §6.3.5 **bitstring** t-Tuple min-entropy value. The t-Tuple
    /// estimator's controlling assessment for these datasets runs on the
    /// bitstring track (the EA tool computes both a "Bitstring" and a "Literal"
    /// estimate for multi-bit data; the bitstring one is the controlling per-bit
    /// value, and for 1-bit data the single "Literal" estimate equals the
    /// bitstring one). Recorded from the verbose "t-Tuple Estimate: min entropy"
    /// line of the EA tool's `selftest/*.res` files; per-bit and in `(0, 1]`.
    pub t_tuple_min_entropy: f64,
    /// EA tool §6.3.6 **bitstring** LRS (Longest Repeated Substring)
    /// min-entropy value. Same track convention as the t-Tuple value (both are
    /// derived from the one suffix-array/LCP pass). Recorded from the verbose
    /// "LRS Estimate: min entropy" line of the EA tool's `selftest/*.res` files;
    /// per-bit and in `(0, 1]`.
    pub lrs_min_entropy: f64,
    /// EA tool §6.3.7 **bitstring** MultiMCW prediction min-entropy value. The
    /// MultiMCW estimator's controlling assessment runs on the bitstring track
    /// (`multi_mcw_test(data.bsymbols, data.blen, 2, …)`); for 1-bit data the
    /// single "Literal" estimate equals the bitstring one (`bsymbols ==
    /// symbols`). Recorded from the verbose "MultiMCW Prediction Estimate: min
    /// entropy" line of the EA tool's `selftest/*.res` files (the controlling
    /// track — "Bitstring" for multi-bit data, "Literal" for 1-bit data);
    /// per-bit and in `(0, 1]`. `normal` is the edge case where the predictor
    /// reaches the per-bit ceiling (`1.0`).
    pub multi_mcw_min_entropy: f64,
    /// EA tool §6.3.8 **bitstring** Lag prediction min-entropy value. The Lag
    /// estimator's controlling assessment runs on the bitstring track
    /// (`lag_test(data.bsymbols, data.blen, 2, …)`); for 1-bit data the single
    /// "Literal" estimate equals the bitstring one (`bsymbols == symbols`).
    /// Recorded from the verbose "Lag Prediction Estimate: min entropy" line of
    /// the EA tool's `selftest/*.res` files (the controlling track — "Bitstring"
    /// for multi-bit data, "Literal" for 1-bit data); per-bit and in `(0, 1]`.
    pub lag_min_entropy: f64,
    /// EA tool §6.3.9 **bitstring** MultiMMC (Multi Markov Model with Counting)
    /// prediction min-entropy value. The MultiMMC estimator's controlling
    /// assessment runs on the bitstring track (`multi_mmc_test(data.bsymbols,
    /// data.blen, 2, …)`, which dispatches to the binary fast path); for 1-bit
    /// data the single "Literal" estimate equals the bitstring one (`bsymbols ==
    /// symbols`). Recorded from the verbose "MultiMMC Prediction Estimate: min
    /// entropy" line of the EA tool (`-i -a -v -v`, the controlling track —
    /// "Bitstring" for multi-bit data, "Literal" for 1-bit data); per-bit and in
    /// `(0, 1]`.
    pub multi_mmc_min_entropy: f64,
    /// EA tool §6.3.10 **bitstring** LZ78Y prediction min-entropy value. The
    /// LZ78Y estimator's controlling assessment runs on the bitstring track
    /// (`LZ78Y_test(data.bsymbols, data.blen, 2, …)`, which dispatches to the
    /// binary fast path); for 1-bit data the single "Literal" estimate equals the
    /// bitstring one (`bsymbols == symbols`). Recorded from the verbose "LZ78Y
    /// Prediction Estimate: min entropy" line of the EA tool's `selftest/*.res`
    /// files (the controlling track — "Bitstring" for multi-bit data, "Literal"
    /// for 1-bit data); per-bit and in `(0, 1]`. LZ78Y completes the §6.3 non-IID
    /// estimator suite.
    pub lz78y_min_entropy: f64,
    /// Optional SP 800-90B §5.1 **L1** parity reference: the 19 unpermuted
    /// permutation-battery statistics in EA index order `0..=18`, INCLUDING the
    /// compression statistic (index 18), now computed bit-exactly vs the EA tool
    /// (pure-Rust bzip2 length). Recorded verbatim from the EA tool's
    /// `ea_iid -v -v -v` unpermuted-statistics block. Populated only for the
    /// three SHORT (10k-sample) datasets — the §5 battery is skipped for the
    /// 1M-sample datasets to keep the harness tractable; `None` elsewhere. When
    /// `Some`, `check_one` compares `permutation_stats(data).values[0..19]` to
    /// these at a relative-or-absolute `PARITY_TOLERANCE_BITS` tolerance (the
    /// excursion statistic, index 0, accumulates a long-double-vs-f64 delta that
    /// a pure absolute tolerance would not cover; see `check_perm_stats`).
    pub perm_stats_ref: Option<[f64; 19]>,
    /// Optional SP 800-90B §5.1 permutation-battery **L2 verdict** reference
    /// (EA ground truth: `run_permutation(data, 1500).is_iid`). Populated only
    /// for the three SHORT datasets; `None` elsewhere.
    pub perm_verdict_ref: Option<bool>,
    /// Optional SP 800-90B §5.2 chi-square IID **verdict** reference (EA ground
    /// truth: `chi_square_tests(data).passed`). Populated only for the three
    /// SHORT datasets; `None` elsewhere.
    pub chi_verdict_ref: Option<bool>,
    /// Optional SP 800-90B §5.3 LRS IID **verdict** reference (EA ground truth:
    /// `len_lrs_iid_test(data).passed`). Populated only for the three SHORT
    /// datasets; `None` elsewhere.
    pub lrs_verdict_ref: Option<bool>,
}

/// The 11 EA-distribution reference datasets and their EA tool v1.1.8 MCV
/// min-entropy values. Datasets are NIST-distributed and referenced by path,
/// never vendored; the SHA-256 column is their provenance fingerprint.
// The §5.1 L1 reference statistics (`perm_stats_ref`) are recorded VERBATIM from
// the EA tool's `ea_iid -v -v -v` output, which prints `long double` values; a
// few (excursion, avgCollision) carry more decimal digits than an `f64` can
// represent. Keeping the literal verbatim documents the exact EA source value —
// it still parses to the nearest `f64`, so behavior is identical to a truncated
// form — so `excessive_precision` is allowed only on this table.
#[allow(clippy::excessive_precision)]
pub const REFERENCE_TABLE: &[Reference] = &[
    Reference {
        name: "biased-random-bits",
        file: "biased-random-bits.bin",
        bits_per_symbol: 1,
        sha256: "481cdac6e2d65d45656c21234125eaf26df18a49037f15ffd40002b35e547586",
        literal_min_entropy: 0.028_633_069_781_464_744,
        bitstring_min_entropy: None,
        collision_min_entropy: 0.028_513_792_826_254_068,
        markov_min_entropy: 0.029_123_023_940_057_06,
        compression_min_entropy: 0.017_766_579_116_465_193,
        t_tuple_min_entropy: 0.026_489_257_053_630_97,
        lrs_min_entropy: 0.055_881_394_003_087_38,
        multi_mcw_min_entropy: 0.028_634_892_142_081_356,
        lag_min_entropy: 0.040_599_763_274_887_825,
        multi_mmc_min_entropy: 0.028_634_586_256_344_21,
        lz78y_min_entropy: 0.028_635_020_154_766_915,
        // §5 battery skipped for the 1M-sample datasets (kept tractable).
        perm_stats_ref: None,
        perm_verdict_ref: None,
        chi_verdict_ref: None,
        lrs_verdict_ref: None,
    },
    Reference {
        name: "biased-random-bytes",
        file: "biased-random-bytes.bin",
        bits_per_symbol: 8,
        sha256: "146bd7497d8e2d61a6e8559c9342ee79f6005a390ee4d776ba43500d00eb508d",
        literal_min_entropy: 0.319_650_651_838_182_03,
        bitstring_min_entropy: Some(0.151_827_325_076_523_44),
        collision_min_entropy: 0.072_705_888_458_565_96,
        markov_min_entropy: 0.091_604_387_916_422_43,
        compression_min_entropy: 0.063_135_493_215_718_44,
        t_tuple_min_entropy: 0.032_217_608_875_810_14,
        lrs_min_entropy: 0.064_801_730_063_926_1,
        multi_mcw_min_entropy: 0.041_925_133_646_315_87,
        lag_min_entropy: 0.042_001_643_639_251_546,
        multi_mmc_min_entropy: 0.041_925_153_682_126_653,
        lz78y_min_entropy: 0.041_925_148_755_351_95,
        // §5 battery skipped for the 1M-sample datasets (kept tractable).
        perm_stats_ref: None,
        perm_verdict_ref: None,
        chi_verdict_ref: None,
        lrs_verdict_ref: None,
    },
    Reference {
        name: "data.pi",
        file: "data.pi.bin",
        bits_per_symbol: 1,
        sha256: "d9a7de4e1f170f363bcb2a85570e4b6ed2320d5500abc5795bc4bfadcb93b928",
        literal_min_entropy: 0.811_140_579_704_074_4,
        bitstring_min_entropy: None,
        collision_min_entropy: 0.569_537_593_457_779,
        markov_min_entropy: 0.723_180_781_990_045_4,
        compression_min_entropy: 0.601_559_190_632_196_5,
        t_tuple_min_entropy: 0.701_860_994_150_4,
        lrs_min_entropy: 0.908_803_656_483_348,
        multi_mcw_min_entropy: 0.812_333_232_591_738_2,
        lag_min_entropy: 0.811_434_612_614_889_9,
        multi_mmc_min_entropy: 0.811_183_696_803_481_3,
        lz78y_min_entropy: 0.811_158_644_364_686_8,
        // §5 battery skipped for the 1M-sample datasets (kept tractable).
        perm_stats_ref: None,
        perm_verdict_ref: None,
        chi_verdict_ref: None,
        lrs_verdict_ref: None,
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
        markov_min_entropy: 0.993_792_543_295_742_4,
        compression_min_entropy: 0.512_511_972_888_792_1,
        t_tuple_min_entropy: 0.772_905_580_775_291_5,
        lrs_min_entropy: 0.828_399_020_572_124_7,
        // Edge case: predictor reaches the per-bit ceiling, H = 1.0.
        multi_mcw_min_entropy: 1.0,
        lag_min_entropy: 0.997_707_478_296_022_1,
        // MultiMMC does NOT hit the ceiling here (it counts per-context, so the
        // byte-structured `normal` data is partly predictable bit-to-bit).
        multi_mmc_min_entropy: 0.676_757_600_522_602_7,
        lz78y_min_entropy: 0.992_460_632_843_158_1,
        // §5 battery skipped for the 1M-sample datasets (kept tractable).
        perm_stats_ref: None,
        perm_verdict_ref: None,
        chi_verdict_ref: None,
        lrs_verdict_ref: None,
    },
    Reference {
        name: "rand1_short",
        file: "rand1_short.bin",
        bits_per_symbol: 1,
        sha256: "3814404497a3b912f8d3db6bc05a99338f0986cd75fe54af2a5f1bdb0a12a583",
        literal_min_entropy: 0.961_058_825_700_550_8,
        bitstring_min_entropy: None,
        collision_min_entropy: 0.691_464_120_997_246_6,
        markov_min_entropy: 0.987_596_104_459_409,
        compression_min_entropy: 0.611_716_204_793_945_1,
        t_tuple_min_entropy: 0.867_624_430_817_073_7,
        lrs_min_entropy: 0.962_625_803_832_787_2,
        multi_mcw_min_entropy: 0.952_618_060_532_626_5,
        lag_min_entropy: 0.943_333_706_575_771_2,
        multi_mmc_min_entropy: 0.961_616_667_828_880_8,
        lz78y_min_entropy: 0.961_446_245_952_478,
        // §5.1 L1 stats (EA `ea_iid -v -v -v`, indices 0..=18; compression slot
        // 18 included). §5 verdicts: IID under all three §5 tests.
        perm_stats_ref: Some([
            68.691_199_999_999_881_242_73,
            793.0,
            7.0,
            746.0,
            5044.0,
            12.0,
            22.943_396_226_415_092_797_88,
            53.0,
            222.0,
            230.0,
            224.0,
            224.0,
            235.0,
            20021.0,
            19982.0,
            20092.0,
            19719.0,
            19526.0,
            1611.0,
        ]),
        perm_verdict_ref: Some(true),
        chi_verdict_ref: Some(true),
        lrs_verdict_ref: Some(true),
    },
    Reference {
        name: "rand4_short",
        file: "rand4_short.bin",
        bits_per_symbol: 4,
        sha256: "a9e2169cb1accc78cd23892d793a232b84b0cd13ccc3923526e0b20762bd77ac",
        literal_min_entropy: 3.790_037_390_213_974,
        bitstring_min_entropy: Some(0.979_189_482_962_402_2),
        collision_min_entropy: 0.898_179_448_381_018_8,
        markov_min_entropy: 0.990_616_807_770_947_5,
        compression_min_entropy: 0.803_872_066_969_184_1,
        t_tuple_min_entropy: 0.898_777_229_390_377_4,
        lrs_min_entropy: 0.932_969_314_495_336_3,
        multi_mcw_min_entropy: 0.986_560_864_592_317,
        lag_min_entropy: 0.982_641_821_735_989_1,
        multi_mmc_min_entropy: 0.977_696_512_087_203,
        lz78y_min_entropy: 0.980_145_173_356_401,
        // §5.1 L1 stats (EA `ea_iid -v -v -v`, indices 0..=18; compression slot
        // 18 included). §5 verdicts: NOT IID — EA periodicity(1) is extreme.
        perm_stats_ref: Some([
            450.376_000_000_000_544_787_3,
            6669.0,
            7.0,
            5269.0,
            4990.0,
            13.0,
            5.742_102_240_091_901_066_421,
            14.0,
            547.0,
            604.0,
            664.0,
            692.0,
            598.0,
            562_563.0,
            562_511.0,
            569_110.0,
            568_260.0,
            561_023.0,
            5520.0,
        ]),
        perm_verdict_ref: Some(false),
        chi_verdict_ref: Some(true),
        lrs_verdict_ref: Some(true),
    },
    Reference {
        name: "rand8_short",
        file: "rand8_short.bin",
        bits_per_symbol: 8,
        sha256: "17d2eaf9544cd6aea3e245bec362f494376d0b1ca6140c475a35f1ad1f8c2803",
        literal_min_entropy: 7.010_454_037_736_041,
        bitstring_min_entropy: Some(0.983_386_784_659_150_3),
        collision_min_entropy: 0.832_052_982_215_248,
        markov_min_entropy: 0.997_724_976_727_965_3,
        compression_min_entropy: 0.732_611_718_060_656_2,
        t_tuple_min_entropy: 0.910_786_445_735_414_1,
        lrs_min_entropy: 0.981_930_357_736_374_3,
        multi_mcw_min_entropy: 0.994_537_115_514_506,
        lag_min_entropy: 0.989_693_493_887_954_9,
        multi_mmc_min_entropy: 0.987_814_544_042_294_1,
        lz78y_min_entropy: 0.988_081_803_799_903_1,
        // §5.1 L1 stats (EA `ea_iid -v -v -v`, indices 0..=18; compression slot
        // 18 included). §5 verdicts: NOT IID under chi-square (independence
        // fails); permutation and LRS are IID-consistent.
        perm_stats_ref: Some([
            6_638.535_999_999_970_954_377,
            6727.0,
            6.0,
            5006.0,
            4938.0,
            13.0,
            20.304_878_048_780_487_631_57,
            67.0,
            34.0,
            30.0,
            49.0,
            49.0,
            35.0,
            163_045_111.0,
            163_784_454.0,
            162_563_680.0,
            162_531_901.0,
            161_376_389.0,
            10987.0,
        ]),
        perm_verdict_ref: Some(true),
        chi_verdict_ref: Some(false),
        lrs_verdict_ref: Some(true),
    },
    Reference {
        name: "ringOsc-nist",
        file: "ringOsc-nist.bin",
        bits_per_symbol: 1,
        sha256: "7d37dc3795e9b2927beb779008d7f4b4630dd7f2c058a2b14cee9d41a658dd68",
        literal_min_entropy: 0.993_514_068_761_158_6,
        bitstring_min_entropy: None,
        collision_min_entropy: 0.126_445_736_196_048_68,
        markov_min_entropy: 0.257_979_392_450_108_65,
        compression_min_entropy: 0.159_322_697_721_578_98,
        t_tuple_min_entropy: 0.201_708_508_170_827_92,
        lrs_min_entropy: 0.365_798_634_802_780_9,
        multi_mcw_min_entropy: 0.290_519_227_365_944_9,
        lag_min_entropy: 0.251_066_953_571_429,
        multi_mmc_min_entropy: 0.251_068_940_815_654_1,
        lz78y_min_entropy: 0.251_073_056_820_698,
        // §5 battery skipped for the 1M-sample datasets (kept tractable).
        perm_stats_ref: None,
        perm_verdict_ref: None,
        chi_verdict_ref: None,
        lrs_verdict_ref: None,
    },
    Reference {
        name: "truerand_1bit",
        file: "truerand_1bit.bin",
        bits_per_symbol: 1,
        sha256: "f9ea8832af4c4205f518845b264465800921688fc2c4d566fbc087664aeb2313",
        literal_min_entropy: 0.995_043_015_131_225_7,
        bitstring_min_entropy: None,
        collision_min_entropy: 0.900_935_726_908_247_5,
        markov_min_entropy: 0.998_486_475_556_110_6,
        compression_min_entropy: 0.829_677_083_234_114_4,
        t_tuple_min_entropy: 0.914_226_367_459_774,
        lrs_min_entropy: 0.985_818_337_227_197_7,
        multi_mcw_min_entropy: 0.996_972_248_016_237_1,
        lag_min_entropy: 0.998_291_666_366_299_7,
        multi_mmc_min_entropy: 0.996_659_943_803_952_2,
        lz78y_min_entropy: 0.997_050_047_578_971_5,
        // §5 battery skipped for the 1M-sample datasets (kept tractable).
        perm_stats_ref: None,
        perm_verdict_ref: None,
        chi_verdict_ref: None,
        lrs_verdict_ref: None,
    },
    Reference {
        name: "truerand_4bit",
        file: "truerand_4bit.bin",
        bits_per_symbol: 4,
        sha256: "489bc841bb364ba86da70b1617138aef76b25dd9196ad669eef40c1441b6cb88",
        literal_min_entropy: 3.971_194_336_729_609_6,
        bitstring_min_entropy: Some(0.997_730_385_822_156_6),
        collision_min_entropy: 0.928_360_945_304_648,
        markov_min_entropy: 0.999_469_539_754_720_5,
        compression_min_entropy: 0.900_626_592_141_759_6,
        t_tuple_min_entropy: 0.929_433_736_387_771_6,
        lrs_min_entropy: 0.986_687_395_175_927_9,
        multi_mcw_min_entropy: 0.998_080_076_228_014_5,
        lag_min_entropy: 0.998_648_590_128_694_9,
        multi_mmc_min_entropy: 0.998_205_084_168_765_3,
        lz78y_min_entropy: 0.999_355_023_599_717_7,
        // §5 battery skipped for the 1M-sample datasets (kept tractable).
        perm_stats_ref: None,
        perm_verdict_ref: None,
        chi_verdict_ref: None,
        lrs_verdict_ref: None,
    },
    Reference {
        name: "truerand_8bit",
        file: "truerand_8bit.bin",
        bits_per_symbol: 8,
        sha256: "c7e56911d2657fa9b6e86c03d4477474d6ec698691c5f32d3918ec513713e3c3",
        literal_min_entropy: 7.865_118_002_899_59,
        bitstring_min_entropy: Some(0.998_199_280_119_827_5),
        collision_min_entropy: 0.958_406_295_418_469_6,
        markov_min_entropy: 0.999_439_303_166_861_9,
        compression_min_entropy: 0.904_232_681_897_311_9,
        t_tuple_min_entropy: 0.933_569_244_303_778_1,
        lrs_min_entropy: 0.998_671_087_964_553_4,
        multi_mcw_min_entropy: 0.999_562_833_166_665_5,
        lag_min_entropy: 0.998_401_559_830_912_8,
        multi_mmc_min_entropy: 0.999_660_367_563_434_2,
        lz78y_min_entropy: 0.998_465_328_046_531_1,
        // §5 battery skipped for the 1M-sample datasets (kept tractable).
        perm_stats_ref: None,
        perm_verdict_ref: None,
        chi_verdict_ref: None,
        lrs_verdict_ref: None,
    },
];

/// §5 (IID-battery) parity deltas/results for a dataset that declares §5
/// reference data (the three short datasets). Carried inside [`Outcome::Pass`]
/// only when the reference row's §5 `Option` fields are `Some`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Section5Result {
    /// Maximum per-statistic delta across the 19 checked §5.1 L1 statistics,
    /// measured on the relative-or-absolute scale used by the check (so a value
    /// `<= PARITY_TOLERANCE_BITS` means every statistic passed). `None` if the
    /// reference declared no L1 statistics (it always declares them when §5 is
    /// present, so this is `Some` in practice).
    pub max_l1_scaled_delta: Option<f64>,
    /// EA §5.1 permutation-battery IID verdict, reproduced and matched.
    pub perm_verdict: bool,
    /// EA §5.2 chi-square IID verdict, reproduced and matched.
    pub chi_verdict: bool,
    /// EA §5.3 LRS IID verdict, reproduced and matched.
    pub lrs_verdict: bool,
}

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
        /// Absolute delta on the §6.3.3 bitstring Markov estimate.
        markov_delta: f64,
        /// Absolute delta on the §6.3.4 bitstring Compression estimate.
        compression_delta: f64,
        /// Absolute delta on the §6.3.5 bitstring t-Tuple estimate.
        t_tuple_delta: f64,
        /// Absolute delta on the §6.3.6 bitstring LRS estimate.
        lrs_delta: f64,
        /// Absolute delta on the §6.3.7 bitstring MultiMCW prediction estimate.
        multi_mcw_delta: f64,
        /// Absolute delta on the §6.3.8 bitstring Lag prediction estimate.
        lag_delta: f64,
        /// Absolute delta on the §6.3.9 bitstring MultiMMC prediction estimate.
        multi_mmc_delta: f64,
        /// Absolute delta on the §6.3.10 bitstring LZ78Y prediction estimate.
        lz78y_delta: f64,
        /// §5 IID-battery parity result; `Some` only for datasets whose
        /// reference row declares §5 data (the three short datasets), `None`
        /// otherwise (the §5 battery is skipped for the 1M-sample datasets).
        section5: Option<Section5Result>,
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
                markov_delta,
                compression_delta,
                t_tuple_delta,
                lrs_delta,
                multi_mcw_delta,
                lag_delta,
                multi_mmc_delta,
                lz78y_delta,
                section5,
            } => {
                let bit = bitstring_delta
                    .map_or_else(|| "  bit -".to_string(), |d| format!("  bit Δ={d:.1e}"));
                let sec5 = section5.map_or_else(String::new, |s| {
                    let l1 = s
                        .max_l1_scaled_delta
                        .map_or_else(|| "-".to_string(), |d| format!("{d:.1e}"));
                    format!(
                        "  §5.1 maxΔ={l1}  perm={}  chi={}  iidlrs={}",
                        if s.perm_verdict { "IID" } else { "nonIID" },
                        if s.chi_verdict { "IID" } else { "nonIID" },
                        if s.lrs_verdict { "IID" } else { "nonIID" },
                    )
                });
                format!(
                    "PASS {:24} lit Δ={:.1e}{}  col Δ={:.1e}  mkv Δ={:.1e}  cmp Δ={:.1e}  \
                     ttu Δ={:.1e}  lrs Δ={:.1e}  mcw Δ={:.1e}  lag Δ={:.1e}  mmc Δ={:.1e}  \
                     lzy Δ={:.1e}{}",
                    self.name,
                    literal_delta,
                    bit,
                    collision_delta,
                    markov_delta,
                    compression_delta,
                    t_tuple_delta,
                    lrs_delta,
                    multi_mcw_delta,
                    lag_delta,
                    multi_mmc_delta,
                    lz78y_delta,
                    sec5
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

/// Compute the §6.3.3 Markov estimate for `data` and compare it to the
/// reference's recorded value.
///
/// Returns the absolute delta on success, or the same failure message
/// `check_one` would emit when the Markov delta exceeds the tolerance.
/// Extracted from `check_one` so that function stays within the line budget.
fn check_markov(reference: &Reference, data: &[u8]) -> Result<f64, String> {
    let markov_est = markov(data, reference.bits_per_symbol);
    let markov_delta = (markov_est.min_entropy - reference.markov_min_entropy).abs();
    if markov_delta > PARITY_TOLERANCE_BITS {
        return Err(format!(
            "markov Δ={markov_delta:.3e} > {PARITY_TOLERANCE_BITS:.0e} \
             (got {}, ref {})",
            markov_est.min_entropy, reference.markov_min_entropy
        ));
    }
    Ok(markov_delta)
}

/// Compute the §6.3.4 compression estimate for `data` and compare it to the
/// reference's recorded value.
///
/// Returns the absolute delta on success, or the same failure message
/// `check_one` would emit when the compression delta exceeds the tolerance, or
/// when the estimator unexpectedly reports insufficient data (a negative
/// `min_entropy`) for a dataset the reference table declares a value for.
/// Extracted from `check_one` so that function stays within the line budget.
fn check_compression(reference: &Reference, data: &[u8]) -> Result<f64, String> {
    let compression_est = compression(data, reference.bits_per_symbol);
    // A negative min-entropy is the EA tool's "not enough samples" sentinel; the
    // reference table only declares compression values for datasets with enough
    // blocks, so a negative here is a genuine mismatch (not a parity miss).
    if compression_est.min_entropy < 0.0 {
        return Err(format!(
            "compression reported insufficient data (min_entropy {}), \
             but reference declares {}",
            compression_est.min_entropy, reference.compression_min_entropy
        ));
    }
    let compression_delta = (compression_est.min_entropy - reference.compression_min_entropy).abs();
    if compression_delta > PARITY_TOLERANCE_BITS {
        return Err(format!(
            "compression Δ={compression_delta:.3e} > {PARITY_TOLERANCE_BITS:.0e} \
             (got {}, ref {})",
            compression_est.min_entropy, reference.compression_min_entropy
        ));
    }
    Ok(compression_delta)
}

/// Compute the §6.3.5 t-Tuple and §6.3.6 LRS estimates for `data` (one shared
/// suffix-array/LCP pass) and compare both to the reference's recorded values.
///
/// Returns `(t_tuple_delta, lrs_delta)` on success, or the same failure message
/// `check_one` would emit when either delta exceeds the tolerance, or when the
/// estimator unexpectedly reports an estimate could not run (a negative
/// `min_entropy`) for a dataset the reference table declares a value for. Both
/// estimates come from one [`crate::lrs::lrs`] call, mirroring the EA tool's
/// single `SAalgs` invocation. Extracted from `check_one` so that function stays
/// within the line budget.
fn check_lrs_pair(reference: &Reference, data: &[u8]) -> Result<(f64, f64), String> {
    let est = lrs(data, reference.bits_per_symbol);

    // A negative min-entropy is the EA tool's "estimate failed / could not run"
    // sentinel; the reference table only declares values for datasets where both
    // estimates run, so a negative here is a genuine mismatch (not a parity miss).
    if est.t_tuple_min_entropy < 0.0 {
        return Err(format!(
            "t-Tuple reported estimate-failed (min_entropy {}), but reference declares {}",
            est.t_tuple_min_entropy, reference.t_tuple_min_entropy
        ));
    }
    if est.lrs_min_entropy < 0.0 {
        return Err(format!(
            "LRS reported could-not-run (min_entropy {}), but reference declares {}",
            est.lrs_min_entropy, reference.lrs_min_entropy
        ));
    }

    let t_tuple_delta = (est.t_tuple_min_entropy - reference.t_tuple_min_entropy).abs();
    if t_tuple_delta > PARITY_TOLERANCE_BITS {
        return Err(format!(
            "t-Tuple Δ={t_tuple_delta:.3e} > {PARITY_TOLERANCE_BITS:.0e} \
             (got {}, ref {})",
            est.t_tuple_min_entropy, reference.t_tuple_min_entropy
        ));
    }

    let lrs_delta = (est.lrs_min_entropy - reference.lrs_min_entropy).abs();
    if lrs_delta > PARITY_TOLERANCE_BITS {
        return Err(format!(
            "LRS Δ={lrs_delta:.3e} > {PARITY_TOLERANCE_BITS:.0e} \
             (got {}, ref {})",
            est.lrs_min_entropy, reference.lrs_min_entropy
        ));
    }

    Ok((t_tuple_delta, lrs_delta))
}

/// Compute the §6.3.7 MultiMCW prediction estimate for `data` and compare it to
/// the reference's recorded value.
///
/// Returns the absolute delta on success, or the same failure message
/// `check_one` would emit when the MultiMCW delta exceeds the tolerance, or when
/// the estimator unexpectedly reports it could not run (a negative `min_entropy`)
/// for a dataset the reference table declares a value for. Extracted from
/// `check_one` so that function stays within the line budget.
fn check_multi_mcw(reference: &Reference, data: &[u8]) -> Result<f64, String> {
    let est = multi_mcw(data, reference.bits_per_symbol);
    let got = est.min_entropy();
    // A negative min-entropy is the EA tool's "estimate could not run" sentinel
    // (fewer than 4096 samples); the reference table only declares values for the
    // ≥ 1e6-bit datasets, so a negative here is a genuine mismatch.
    if got < 0.0 {
        return Err(format!(
            "MultiMCW reported could-not-run (min_entropy {got}), but reference declares {}",
            reference.multi_mcw_min_entropy
        ));
    }
    let multi_mcw_delta = (got - reference.multi_mcw_min_entropy).abs();
    if multi_mcw_delta > PARITY_TOLERANCE_BITS {
        return Err(format!(
            "MultiMCW Δ={multi_mcw_delta:.3e} > {PARITY_TOLERANCE_BITS:.0e} \
             (got {got}, ref {})",
            reference.multi_mcw_min_entropy
        ));
    }
    Ok(multi_mcw_delta)
}

/// Compute the §6.3.8 Lag prediction estimate for `data` and compare it to the
/// reference's recorded value.
///
/// Returns the absolute delta on success, or the same failure message
/// `check_one` would emit when the Lag delta exceeds the tolerance, or when the
/// estimator unexpectedly reports it could not run (a negative `min_entropy`) for
/// a dataset the reference table declares a value for. Extracted from `check_one`
/// so that function stays within the line budget.
fn check_lag(reference: &Reference, data: &[u8]) -> Result<f64, String> {
    let est = lag(data, reference.bits_per_symbol);
    let got = est.min_entropy();
    // A negative min-entropy is the "estimate could not run" sentinel (fewer than
    // 2 samples); the reference table only declares values for the ≥ 1e6-bit
    // datasets, so a negative here is a genuine mismatch.
    if got < 0.0 {
        return Err(format!(
            "Lag reported could-not-run (min_entropy {got}), but reference declares {}",
            reference.lag_min_entropy
        ));
    }
    let lag_delta = (got - reference.lag_min_entropy).abs();
    if lag_delta > PARITY_TOLERANCE_BITS {
        return Err(format!(
            "Lag Δ={lag_delta:.3e} > {PARITY_TOLERANCE_BITS:.0e} \
             (got {got}, ref {})",
            reference.lag_min_entropy
        ));
    }
    Ok(lag_delta)
}

/// Compute the §6.3.9 MultiMMC prediction estimate for `data` and compare it to
/// the reference's recorded value.
///
/// Returns the absolute delta on success, or the same failure message `check_one`
/// would emit when the MultiMMC delta exceeds the tolerance, or when the estimator
/// unexpectedly reports it could not run (a negative `min_entropy`) for a dataset
/// the reference table declares a value for. Extracted from `check_one` so that
/// function stays within the line budget.
fn check_multi_mmc(reference: &Reference, data: &[u8]) -> Result<f64, String> {
    let est = multi_mmc(data, reference.bits_per_symbol);
    let got = est.min_entropy();
    // A negative min-entropy is the EA tool's "estimate could not run" sentinel
    // (fewer than 4 samples); the reference table only declares values for the
    // ≥ 1e6-bit datasets, so a negative here is a genuine mismatch.
    if got < 0.0 {
        return Err(format!(
            "MultiMMC reported could-not-run (min_entropy {got}), but reference declares {}",
            reference.multi_mmc_min_entropy
        ));
    }
    let multi_mmc_delta = (got - reference.multi_mmc_min_entropy).abs();
    if multi_mmc_delta > PARITY_TOLERANCE_BITS {
        return Err(format!(
            "MultiMMC Δ={multi_mmc_delta:.3e} > {PARITY_TOLERANCE_BITS:.0e} \
             (got {got}, ref {})",
            reference.multi_mmc_min_entropy
        ));
    }
    Ok(multi_mmc_delta)
}

/// Compute the §6.3.10 LZ78Y prediction estimate for `data` and compare it to the
/// reference's recorded value.
///
/// Returns the absolute delta on success, or the same failure message `check_one`
/// would emit when the LZ78Y delta exceeds the tolerance, or when the estimator
/// unexpectedly reports it could not run (a negative `min_entropy`) for a dataset
/// the reference table declares a value for. Extracted from `check_one` so that
/// function stays within the line budget.
fn check_lz78y(reference: &Reference, data: &[u8]) -> Result<f64, String> {
    let est = lz78y(data, reference.bits_per_symbol);
    let got = est.min_entropy();
    // A negative min-entropy is the EA tool's "estimate could not run" sentinel
    // (fewer than B_len + 3 samples); the reference table only declares values for
    // the ≥ 1e6-bit datasets, so a negative here is a genuine mismatch.
    if got < 0.0 {
        return Err(format!(
            "LZ78Y reported could-not-run (min_entropy {got}), but reference declares {}",
            reference.lz78y_min_entropy
        ));
    }
    let lz78y_delta = (got - reference.lz78y_min_entropy).abs();
    if lz78y_delta > PARITY_TOLERANCE_BITS {
        return Err(format!(
            "LZ78Y Δ={lz78y_delta:.3e} > {PARITY_TOLERANCE_BITS:.0e} \
             (got {got}, ref {})",
            reference.lz78y_min_entropy
        ));
    }
    Ok(lz78y_delta)
}

/// Check the optional SP 800-90B §5 (IID-battery) parity for `data` against the
/// reference's §5 fields.
///
/// Returns `Ok(None)` when the reference declares no §5 data (the 1M-sample
/// datasets), `Ok(Some(result))` when every §5 check passes, or the same kind of
/// failure message `check_one` would emit on any §5.1 L1 statistic exceeding the
/// tolerance or any §5 L2 verdict (permutation / chi-square / LRS) diverging from
/// the EA ground truth.
///
/// **L1 (§5.1 statistics).** Compares `permutation_stats(data).values[0..19]` to
/// `perm_stats_ref` (all 19 statistics, including the compression slot at index
/// 18, now computed bit-exactly vs the EA tool). The tolerance is **relative-or-absolute**
/// at [`PARITY_TOLERANCE_BITS`] (`1e-6`): a statistic passes when
/// `|got - ref| <= 1e-6` OR `|got - ref| <= 1e-6 * |ref|`. The relative arm is
/// required for the excursion statistic (index 0), which carries a
/// long-double-vs-f64 accumulation delta of up to ~3e-8 absolute on the
/// 6638-scale `rand8_short` value (a relative delta of ~5e-12) — far inside the
/// relative bound but it would breach a pure-absolute 1e-6 on some larger
/// statistics' rounding. All other statistics are bit-exact or fp-noise and
/// satisfy both arms.
///
/// **L2 (§5 verdicts).** Reproduces the three §5 verdicts and asserts they equal
/// the recorded EA ground truth:
/// `run_permutation(data, PERM_VERDICT_PARITY_SHUFFLES).is_iid == perm_verdict_ref`,
/// `chi_square_tests(data).passed == chi_verdict_ref`, and
/// `len_lrs_iid_test(data).passed == lrs_verdict_ref`.
fn check_section5(reference: &Reference, data: &[u8]) -> Result<Option<Section5Result>, String> {
    // §5 is present iff the reference declares its L1 statistics. The L2 verdict
    // fields are populated in lockstep for the same datasets.
    let Some(ref_stats) = reference.perm_stats_ref else {
        return Ok(None);
    };

    // §5.1 L1: all 19 statistics (including the compression slot at EA index 18,
    // now computed bit-exactly), relative-or-absolute tolerance. `ref_stats`
    // carries all 19, matching the 19-element `values`/`TEST_NAMES` arrays one
    // for one (no panicking index).
    let got = permutation_stats(data).values;
    let mut max_scaled_delta = 0.0_f64;
    for ((i, &ref_v), (&got_v, &stat_name)) in ref_stats
        .iter()
        .enumerate()
        .zip(got.iter().zip(crate::permutation::TEST_NAMES.iter()))
    {
        let abs_delta = (got_v - ref_v).abs();
        // Relative-or-absolute: pass on either arm. The scaled delta we report is
        // the smaller of (absolute, relative) so a reported value <= tolerance
        // means the statistic passed.
        let rel_delta = if ref_v == 0.0 {
            abs_delta
        } else {
            abs_delta / ref_v.abs()
        };
        let scaled = abs_delta.min(rel_delta);
        if scaled > max_scaled_delta {
            max_scaled_delta = scaled;
        }
        if abs_delta > PARITY_TOLERANCE_BITS && rel_delta > PARITY_TOLERANCE_BITS {
            return Err(format!(
                "§5.1 statistic[{i}] ({stat_name}) Δ_abs={abs_delta:.3e} Δ_rel={rel_delta:.3e} \
                 both > {PARITY_TOLERANCE_BITS:.0e} (got {got_v}, ref {ref_v})"
            ));
        }
    }

    // §5.1 L2 verdict (permutation battery).
    let perm_verdict = run_permutation(data, PERM_VERDICT_PARITY_SHUFFLES).is_iid;
    if let Some(ref_perm) = reference.perm_verdict_ref
        && perm_verdict != ref_perm
    {
        return Err(format!(
            "§5.1 permutation verdict mismatch: got {perm_verdict}, EA ref {ref_perm}"
        ));
    }

    // §5.2 L2 verdict (chi-square IID tests).
    let chi_verdict = chi_square_tests(data).passed;
    if let Some(ref_chi) = reference.chi_verdict_ref
        && chi_verdict != ref_chi
    {
        return Err(format!(
            "§5.2 chi-square verdict mismatch: got {chi_verdict}, EA ref {ref_chi}"
        ));
    }

    // §5.3 L2 verdict (LRS IID test).
    let lrs_verdict = len_lrs_iid_test(data).passed;
    if let Some(ref_lrs) = reference.lrs_verdict_ref
        && lrs_verdict != ref_lrs
    {
        return Err(format!(
            "§5.3 LRS-IID verdict mismatch: got {lrs_verdict}, EA ref {ref_lrs}"
        ));
    }

    Ok(Some(Section5Result {
        max_l1_scaled_delta: Some(max_scaled_delta),
        perm_verdict,
        chi_verdict,
        lrs_verdict,
    }))
}

/// Check one dataset against its reference row (MCV + Collision + Markov +
/// Compression + t-Tuple + LRS + MultiMCW + Lag + MultiMMC + LZ78Y).
///
/// Skips when the dataset file is absent; fails on a read error, a provenance
/// (SHA-256) mismatch, a SHA-256 service error, or any estimator's min-entropy
/// delta above [`PARITY_TOLERANCE_BITS`] (MCV literal, MCV bitstring where
/// declared, §6.3.2 collision, §6.3.3 Markov, §6.3.4 compression, §6.3.5
/// t-Tuple, §6.3.6 LRS, §6.3.7 MultiMCW, §6.3.8 Lag, §6.3.9 MultiMMC, or §6.3.10
/// LZ78Y); otherwise passes with the per-estimator deltas. The §6.3 non-IID
/// estimator suite is complete with LZ78Y.
///
/// For datasets whose reference row declares SP 800-90B §5 (IID-battery) data —
/// the three short datasets — `check_one` additionally checks the §5.1 L1
/// statistics (relative-or-absolute tolerance) and the three §5 L2 verdicts
/// (permutation / chi-square / LRS) against EA ground truth; any divergence is a
/// parity failure. This §5 check is purely additive and does not touch the §6.3
/// estimator logic above.
// Grows by one sequential comparison block per estimator added to the suite;
// the length is inherent to covering every estimator in one place.
#[allow(clippy::too_many_lines)]
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

    // §6.3.3 Markov estimate — also always on the bitstring track, so every
    // dataset (including 1-bit data) carries a reference value to check.
    let markov_delta = match check_markov(reference, &data) {
        Ok(d) => d,
        Err(reason) => {
            return DatasetResult {
                name: reference.name,
                outcome: Outcome::Fail { reason },
            };
        }
    };

    // §6.3.4 Compression estimate — also always on the bitstring track, so every
    // dataset (including 1-bit data) carries a reference value to check.
    let compression_delta = match check_compression(reference, &data) {
        Ok(d) => d,
        Err(reason) => {
            return DatasetResult {
                name: reference.name,
                outcome: Outcome::Fail { reason },
            };
        }
    };

    // §6.3.5 t-Tuple and §6.3.6 LRS estimates — derived from one shared
    // suffix-array/LCP pass; the bitstring track is controlling, so every dataset
    // (including 1-bit data) carries a reference value for each to check.
    let (t_tuple_delta, lrs_delta) = match check_lrs_pair(reference, &data) {
        Ok(d) => d,
        Err(reason) => {
            return DatasetResult {
                name: reference.name,
                outcome: Outcome::Fail { reason },
            };
        }
    };

    // §6.3.7 MultiMCW prediction estimate — also on the bitstring track, so every
    // dataset (including 1-bit data) carries a reference value to check.
    let multi_mcw_delta = match check_multi_mcw(reference, &data) {
        Ok(d) => d,
        Err(reason) => {
            return DatasetResult {
                name: reference.name,
                outcome: Outcome::Fail { reason },
            };
        }
    };

    // §6.3.8 Lag prediction estimate — also on the bitstring track, so every
    // dataset (including 1-bit data) carries a reference value to check.
    let lag_delta = match check_lag(reference, &data) {
        Ok(d) => d,
        Err(reason) => {
            return DatasetResult {
                name: reference.name,
                outcome: Outcome::Fail { reason },
            };
        }
    };

    // §6.3.9 MultiMMC prediction estimate — also on the bitstring track, so every
    // dataset (including 1-bit data) carries a reference value to check.
    let multi_mmc_delta = match check_multi_mmc(reference, &data) {
        Ok(d) => d,
        Err(reason) => {
            return DatasetResult {
                name: reference.name,
                outcome: Outcome::Fail { reason },
            };
        }
    };

    // §6.3.10 LZ78Y prediction estimate — also on the bitstring track, so every
    // dataset (including 1-bit data) carries a reference value to check. This is
    // the last estimator in the §6.3 non-IID suite.
    let lz78y_delta = match check_lz78y(reference, &data) {
        Ok(d) => d,
        Err(reason) => {
            return DatasetResult {
                name: reference.name,
                outcome: Outcome::Fail { reason },
            };
        }
    };

    // SP 800-90B §5 IID battery — additive, fires only for datasets whose
    // reference row declares §5 data (the three short datasets). `Ok(None)` for
    // the 1M-sample datasets (battery skipped). Any §5.1 L1 statistic out of
    // tolerance or any §5 L2 verdict mismatch is a parity failure.
    let section5 = match check_section5(reference, &data) {
        Ok(s) => s,
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
            markov_delta,
            compression_delta,
            t_tuple_delta,
            lrs_delta,
            multi_mcw_delta,
            lag_delta,
            multi_mmc_delta,
            lz78y_delta,
            section5,
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
        // The §5 IID battery is declared only for these three short datasets.
        const SHORT_DATASETS: [&str; 3] = ["rand1_short", "rand4_short", "rand8_short"];

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

        // §5 coverage guard: any short dataset that is PRESENT (not skipped)
        // must have actually exercised the §5 battery — i.e. its Pass outcome
        // must carry a `Some(section5)`. This prevents the §5 path silently
        // degrading to a no-op. Absent (skipped) datasets impose no requirement.
        for r in &results {
            if SHORT_DATASETS.contains(&r.name)
                && let Outcome::Pass { section5, .. } = &r.outcome
            {
                assert!(
                    section5.is_some(),
                    "{}: present short dataset passed §6.3 but did not run the §5 battery",
                    r.name
                );
            }
        }
    }

    // Asserts a fixed structural invariant per estimator column plus the §5
    // option-field lockstep; the length is inherent to covering every column.
    #[allow(clippy::too_many_lines)]
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
            // Markov is a per-bit (binary) min-entropy capped at 1.0:
            // entEst = min(H_min/128, 1.0), so 0 ≤ H ≤ 1. Every EA dataset has
            // non-degenerate transitions, so H > 0 here.
            assert!(
                r.markov_min_entropy > 0.0 && r.markov_min_entropy <= 1.0,
                "{}: markov min-entropy {} out of (0, 1]",
                r.name,
                r.markov_min_entropy
            );
            // Compression is a per-bit (binary) min-entropy in (0, 1]:
            // entEst = -log2(p)/b with p in (1/64, 1], so 0 <= H <= 1. Every EA
            // dataset has enough blocks and finds p, so H > 0 here.
            assert!(
                r.compression_min_entropy > 0.0 && r.compression_min_entropy <= 1.0,
                "{}: compression min-entropy {} out of (0, 1]",
                r.name,
                r.compression_min_entropy
            );
            // t-Tuple and LRS are per-bit (bitstring-track) min-entropies in
            // (0, 1]: H = -log2(p_u) with p_u in [0.5, 1] for binary data, so
            // 0 <= H <= 1. Every EA dataset has a repeated substring and clears
            // the t-Tuple threshold, so both are > 0 here.
            assert!(
                r.t_tuple_min_entropy > 0.0 && r.t_tuple_min_entropy <= 1.0,
                "{}: t-Tuple min-entropy {} out of (0, 1]",
                r.name,
                r.t_tuple_min_entropy
            );
            assert!(
                r.lrs_min_entropy > 0.0 && r.lrs_min_entropy <= 1.0,
                "{}: LRS min-entropy {} out of (0, 1]",
                r.name,
                r.lrs_min_entropy
            );
            // MultiMCW is a per-bit (bitstring-track) prediction min-entropy in
            // (0, 1]: H = -log2(max(1/2, p_global', p_local)) with the inner max
            // in [0.5, 1] for binary data, so 0 <= H <= 1. Every EA dataset runs
            // the estimator (>= 1e6 bits) and is non-degenerate, so H > 0 here;
            // `normal` reaches the ceiling at exactly 1.0.
            assert!(
                r.multi_mcw_min_entropy > 0.0 && r.multi_mcw_min_entropy <= 1.0,
                "{}: MultiMCW min-entropy {} out of (0, 1]",
                r.name,
                r.multi_mcw_min_entropy
            );
            // Lag is a per-bit (bitstring-track) prediction min-entropy in
            // (0, 1]: H = -log2(max(1/2, p_global', p_local)) with the inner max
            // in [0.5, 1] for binary data, so 0 <= H <= 1. Every EA dataset runs
            // the estimator (>= 1e6 bits) and is non-degenerate, so H > 0 here.
            assert!(
                r.lag_min_entropy > 0.0 && r.lag_min_entropy <= 1.0,
                "{}: Lag min-entropy {} out of (0, 1]",
                r.name,
                r.lag_min_entropy
            );
            // MultiMMC is a per-bit (bitstring-track) prediction min-entropy in
            // (0, 1]: H = -log2(max(1/2, p_global', p_local)) with the inner max
            // in [0.5, 1] for binary data, so 0 <= H <= 1. Every EA dataset runs
            // the estimator (>= 1e6 bits) and is non-degenerate, so H > 0 here.
            assert!(
                r.multi_mmc_min_entropy > 0.0 && r.multi_mmc_min_entropy <= 1.0,
                "{}: MultiMMC min-entropy {} out of (0, 1]",
                r.name,
                r.multi_mmc_min_entropy
            );
            // LZ78Y is a per-bit (bitstring-track) prediction min-entropy in
            // (0, 1]: H = -log2(max(1/2, p_global', p_local)) with the inner max
            // in [0.5, 1] for binary data, so 0 <= H <= 1. Every EA dataset runs
            // the estimator (>= 1e6 bits) and is non-degenerate, so H > 0 here.
            assert!(
                r.lz78y_min_entropy > 0.0 && r.lz78y_min_entropy <= 1.0,
                "{}: LZ78Y min-entropy {} out of (0, 1]",
                r.name,
                r.lz78y_min_entropy
            );
            // §5 reference fields move in lockstep: a row either declares all
            // four (L1 stats + three L2 verdicts) or none of them.
            let has_l1 = r.perm_stats_ref.is_some();
            assert_eq!(
                r.perm_verdict_ref.is_some(),
                has_l1,
                "{}: §5 perm_verdict_ref present-ness disagrees with perm_stats_ref",
                r.name
            );
            assert_eq!(
                r.chi_verdict_ref.is_some(),
                has_l1,
                "{}: §5 chi_verdict_ref present-ness disagrees with perm_stats_ref",
                r.name
            );
            assert_eq!(
                r.lrs_verdict_ref.is_some(),
                has_l1,
                "{}: §5 lrs_verdict_ref present-ness disagrees with perm_stats_ref",
                r.name
            );
            // Declared §5.1 L1 statistics must all be finite — including the
            // compression slot (index 18), now a real bzip2 length in the
            // 19-element reference array.
            if let Some(stats) = r.perm_stats_ref {
                assert_eq!(stats.len(), PERM_STATS_PARITY_COUNT);
                for (i, v) in stats.iter().enumerate() {
                    assert!(v.is_finite(), "{}: §5.1 stat[{i}] not finite ({v})", r.name);
                }
            }
        }
        assert_eq!(REFERENCE_TABLE.len(), 11);
        // Exactly the three short datasets carry §5 reference data.
        let with_section5 = REFERENCE_TABLE
            .iter()
            .filter(|r| r.perm_stats_ref.is_some())
            .count();
        assert_eq!(with_section5, 3, "exactly 3 datasets must declare §5 data");
    }
}
