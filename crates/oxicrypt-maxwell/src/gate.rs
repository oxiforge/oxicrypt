//! SP 800-90B §6.3 per-OE entropy-source **reuse / acceptance gate**.
//!
//! This module encodes the four SP 800-90B §6.3 conditions that must all hold
//! before a previously-analyzed entropy source's analysis may be **reused** on a
//! new operational environment (OE) without a fresh full 90B assessment. It is
//! **out of the cryptographic boundary** — pure offline acceptance tooling, like
//! the rest of `oxicrypt-maxwell`, and `#![forbid(unsafe_code)]` at the crate
//! level. It produces no security parameters; it renders an accept/reject
//! decision over min-entropy values measured elsewhere.
//!
//! # The §6.3 reuse recipe (the four conditions)
//!
//! Per the NIST-reviewed §6.3 reuse recipe (transcribed from the jent v3.7.0
//! reference write-up, ch. 6 §6.3 — see the constant docs below for the exact
//! clause each threshold is taken from), to claim an existing analysis on a new
//! platform **all four** of the following must hold:
//!
//! 1. **Raw rate** `H_raw > 0.333` bit/delta.
//! 2. **Restart sanity** — the §3.1.4.3 restart sanity check passes.
//! 3. **Restart half-raw** — `min(H_restart_row, H_restart_col) >= 0.5 * H_raw`.
//! 4. **Restart floor** — `min(H_restart_row, H_restart_col) > 0.333` bit/delta.
//!
//! Meeting all four means no new 90B analysis is needed for the OE. The
//! min-entropy inputs are the **minimum over all applicable estimators** for
//! each dataset (raw, restart-row, restart-col); the decision logic here is
//! agnostic to *which* tool produced them.
//!
//! # Constants are transcribed, never recalled
//!
//! Every numeric threshold below is a named `const` carrying an inline citation
//! to the exact §6.3 clause it was transcribed from. The decision logic refers
//! only to these named constants — it never embeds a bare literal — so the
//! threshold provenance is auditable against the source document.
//!
//! # Decision logic is pure and panic-free
//!
//! [`evaluate`] takes a [`GateInputs`] (four measured/observed values) and
//! returns a [`GateDecision`]. It performs only real-valued comparisons and a
//! boolean check; it allocates nothing and cannot panic. The CLI/ingestion
//! layer ([`crate::gate::load_inputs`] and the `maxwell gate` subcommand)
//! surfaces I/O and parse errors via `Result`, never panic.
//!
//! # Floats
//!
//! The §6.3 thresholds are min-entropy bit/delta values (e.g. `0.333`). These
//! are genuine real-valued comparisons in this out-of-boundary tool; `maxwell`
//! already uses `f64` for estimates. The no-`f64` rule applies only to the
//! in-boundary health-cutoff path and does **not** apply here.

use std::path::Path;

/// SP 800-90B §6.3 raw-rate acceptance floor, in bits per delta.
///
/// Transcribed from the §6.3 reuse recipe (jent v3.7.0 reference write-up,
/// ch. 6 §6.3): *"raw noise on target → EA tool → rate **> 0.333 bit/delta**"*.
/// The floor corresponds to the default oversampling rate `osr = 3`
/// (`h_t = 1/osr = 0.333…`), as noted in the same clause
/// (*"0.333 floor ↔ osr=3 default: h_t=1/osr"*).
// SP 800-90B §6.3 / jent v3.7.0 §6.3 reuse recipe, condition (1).
pub const RAW_RATE_FLOOR: f64 = 0.333;

/// SP 800-90B §6.3 restart-rate acceptance floor, in bits per delta.
///
/// Transcribed from the §6.3 reuse recipe (jent v3.7.0 reference write-up,
/// ch. 6 §6.3): *"… AND restart rate **> 0.333**"*. Numerically equal to
/// [`RAW_RATE_FLOOR`] but kept as a distinct named constant because §6.3
/// states it as a separate condition on the restart estimate.
// SP 800-90B §6.3 / jent v3.7.0 §6.3 reuse recipe, condition (4).
pub const RESTART_RATE_FLOOR: f64 = 0.333;

/// SP 800-90B §6.3 restart-vs-raw ratio: the restart estimate must be at least
/// this fraction of the raw estimate.
///
/// Transcribed from the §6.3 reuse recipe (jent v3.7.0 reference write-up,
/// ch. 6 §6.3): *"min(row,col) rate ≥ **half** the raw rate"*. Encoded as the
/// multiplicative factor applied to the raw rate.
// SP 800-90B §6.3 / jent v3.7.0 §6.3 reuse recipe, condition (3) ("half").
pub const RESTART_HALF_RAW_FACTOR: f64 = 0.5;

/// Which of the four §6.3 conditions a gate evaluation checks.
///
/// The order matches the §6.3 recipe enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Condition {
    /// (1) `H_raw > 0.333` bit/delta.
    RawRate,
    /// (2) §3.1.4.3 restart sanity check passes.
    RestartSanity,
    /// (3) `min(restart_row, restart_col) >= 0.5 * H_raw`.
    RestartHalfRaw,
    /// (4) `min(restart_row, restart_col) > 0.333` bit/delta.
    RestartRate,
}

impl Condition {
    /// A short, stable human label for the condition (used in CLI output and
    /// test assertions).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::RawRate => "raw rate > 0.333 bit/delta (§6.3 cond 1)",
            Self::RestartSanity => "restart §3.1.4.3 sanity check passes (§6.3 cond 2)",
            Self::RestartHalfRaw => "restart min(row,col) >= 0.5 * raw (§6.3 cond 3)",
            Self::RestartRate => "restart min(row,col) > 0.333 bit/delta (§6.3 cond 4)",
        }
    }
}

/// The four measured/observed inputs the §6.3 gate decides over.
///
/// All min-entropy values are the **minimum over all applicable estimators**
/// for that dataset (raw / restart-row / restart-col), in bits per delta.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GateInputs {
    /// Raw-dataset per-sample min-entropy `H_raw` (bit/delta), min over
    /// estimators.
    pub raw_min_entropy: f64,
    /// Restart **row**-matrix min-entropy (bit/delta), min over estimators.
    pub restart_row_min_entropy: f64,
    /// Restart **column**-matrix min-entropy (bit/delta), min over estimators.
    pub restart_col_min_entropy: f64,
    /// Whether the §3.1.4.3 restart sanity check passed.
    pub restart_sanity_pass: bool,
}

impl GateInputs {
    /// The §6.3 restart estimate: the smaller of the row and column matrix
    /// min-entropy values (`min(row, col)`).
    ///
    /// Uses [`f64::min`], which propagates a comparison over the two finite
    /// estimates; NaN inputs would propagate to a NaN result, which the
    /// downstream `>`/`>=` comparisons treat as a (correct) failure.
    #[must_use]
    pub fn restart_min(&self) -> f64 {
        self.restart_row_min_entropy
            .min(self.restart_col_min_entropy)
    }
}

/// The per-condition pass/fail breakdown of a §6.3 evaluation.
///
/// Four bools by design: §6.3 has exactly four independent conditions, and the
/// caller needs each one's pass/fail individually (to report *which* failed).
/// This is a result record, not a configuration flag-bag — the
/// `struct_excessive_bools` heuristic does not apply.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConditionResults {
    /// (1) raw rate above the floor.
    pub raw_rate: bool,
    /// (2) restart sanity check passed.
    pub restart_sanity: bool,
    /// (3) restart estimate at least half the raw estimate.
    pub restart_half_raw: bool,
    /// (4) restart estimate above the floor.
    pub restart_rate: bool,
}

impl ConditionResults {
    /// Look up a single condition's pass/fail.
    #[must_use]
    pub const fn get(&self, c: Condition) -> bool {
        match c {
            Condition::RawRate => self.raw_rate,
            Condition::RestartSanity => self.restart_sanity,
            Condition::RestartHalfRaw => self.restart_half_raw,
            Condition::RestartRate => self.restart_rate,
        }
    }
}

/// The outcome of a §6.3 gate evaluation: an overall verdict plus the
/// per-condition breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateDecision {
    /// `true` only when **all four** §6.3 conditions hold.
    pub accept: bool,
    /// Per-condition pass/fail.
    pub conditions: ConditionResults,
}

impl GateDecision {
    /// The conditions that failed, in §6.3 recipe order.
    ///
    /// Empty when [`Self::accept`] is `true`.
    #[must_use]
    pub fn failed(&self) -> Vec<Condition> {
        const ALL: [Condition; 4] = [
            Condition::RawRate,
            Condition::RestartSanity,
            Condition::RestartHalfRaw,
            Condition::RestartRate,
        ];
        ALL.into_iter()
            .filter(|&c| !self.conditions.get(c))
            .collect()
    }
}

/// Evaluate the four SP 800-90B §6.3 reuse conditions over `inputs`.
///
/// Returns a [`GateDecision`] whose `accept` is `true` iff **all four**
/// conditions hold. Pure, allocation-free, and panic-free: it performs only
/// real-valued comparisons (against the cited named constants) and a boolean
/// check.
///
/// # Conditions (all must hold)
///
/// 1. `raw_min_entropy > RAW_RATE_FLOOR`
/// 2. `restart_sanity_pass`
/// 3. `restart_min() >= RESTART_HALF_RAW_FACTOR * raw_min_entropy`
/// 4. `restart_min() > RESTART_RATE_FLOOR`
///
/// where `restart_min() = min(restart_row_min_entropy,
/// restart_col_min_entropy)`.
///
/// # NaN handling
///
/// If any min-entropy input is NaN, the `>`/`>=` comparisons against it are
/// `false`, so the affected condition fails and the gate (correctly) rejects.
#[must_use]
pub fn evaluate(inputs: &GateInputs) -> GateDecision {
    let restart_min = inputs.restart_min();

    // (1) raw rate above the §6.3 floor.
    let raw_rate = inputs.raw_min_entropy > RAW_RATE_FLOOR;

    // (2) restart §3.1.4.3 sanity check.
    let restart_sanity = inputs.restart_sanity_pass;

    // (3) restart estimate at least half the raw estimate.
    let restart_half_raw = restart_min >= RESTART_HALF_RAW_FACTOR * inputs.raw_min_entropy;

    // (4) restart estimate above the §6.3 floor.
    let restart_rate = restart_min > RESTART_RATE_FLOOR;

    let conditions = ConditionResults {
        raw_rate,
        restart_sanity,
        restart_half_raw,
        restart_rate,
    };
    let accept = raw_rate && restart_sanity && restart_half_raw && restart_rate;

    GateDecision { accept, conditions }
}

// ── ingestion ───────────────────────────────────────────────────────────────

/// File name of the per-OE §6.3 results sidecar the operator places in the OE
/// directory.
///
/// See [`load_inputs`] for the schema and the rationale for a structured
/// sidecar (rather than scraping EA stdout).
pub const RESULTS_FILE: &str = "gate-results.json";

/// An error raised while loading or parsing the §6.3 gate inputs.
#[derive(Debug)]
pub struct GateError(pub String);

impl std::fmt::Display for GateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for GateError {}

/// Load the four §6.3 gate inputs for an OE directory.
///
/// The gate reads a small **`gate-results.json`** sidecar that the operator
/// places in the OE directory after running the entropy assessment (the EA tool
/// today; `maxwell` once the estimator suite is parity-complete — the gate is
/// agnostic to which produced the numbers). The schema is:
///
/// ```json
/// {
///   "raw_min_entropy": 0.95,
///   "restart_row_min_entropy": 0.80,
///   "restart_col_min_entropy": 0.78,
///   "restart_sanity_pass": true
/// }
/// ```
///
/// All four keys are required. Each min-entropy value is the **minimum over all
/// applicable estimators** for that dataset (the operator computes the min when
/// recording the sidecar). The decision logic ([`evaluate`]) is decoupled from
/// the assessment tool by design (per the §6.3 oracle-sequencing decision: EA
/// now, `maxwell` once parity-complete, EA retained as a permanent cross-check).
///
/// # Errors
///
/// Returns [`GateError`] if the sidecar is missing, unreadable, or any required
/// key is absent or malformed.
pub fn load_inputs(oe_dir: &Path) -> Result<GateInputs, GateError> {
    let path = oe_dir.join(RESULTS_FILE);
    let text = std::fs::read_to_string(&path).map_err(|e| {
        GateError(format!(
            "cannot read §6.3 results sidecar '{}': {e}",
            path.display()
        ))
    })?;
    parse_results(&text).map_err(|e| {
        GateError(format!(
            "malformed §6.3 results sidecar '{}': {e}",
            path.display()
        ))
    })
}

/// Parse the `gate-results.json` schema from text into [`GateInputs`].
///
/// A small dependency-free JSON-field extractor: the sidecar is a flat object
/// of four scalar fields, so it is parsed by locating each key and reading its
/// scalar value rather than pulling in a JSON crate (matching the crate's
/// minimal-dependency posture). Whitespace around tokens is tolerated.
///
/// # Errors
///
/// Returns a description string if any of the four required fields is missing or
/// cannot be parsed as its expected scalar type.
pub fn parse_results(text: &str) -> Result<GateInputs, String> {
    let raw_min_entropy = parse_f64_field(text, "raw_min_entropy")?;
    let restart_row_min_entropy = parse_f64_field(text, "restart_row_min_entropy")?;
    let restart_col_min_entropy = parse_f64_field(text, "restart_col_min_entropy")?;
    let restart_sanity_pass = parse_bool_field(text, "restart_sanity_pass")?;
    Ok(GateInputs {
        raw_min_entropy,
        restart_row_min_entropy,
        restart_col_min_entropy,
        restart_sanity_pass,
    })
}

/// Extract the scalar token following `"key"` and its colon, up to the next
/// `,` or `}`.
fn scalar_after_key<'a>(text: &'a str, key: &str) -> Result<&'a str, String> {
    let needle = format!("\"{key}\"");
    let key_at = text
        .find(&needle)
        .ok_or_else(|| format!("missing required field \"{key}\""))?;
    // Advance past the key, then the colon.
    let after_key = text
        .get(key_at.saturating_add(needle.len())..)
        .unwrap_or_default();
    let colon_rel = after_key
        .find(':')
        .ok_or_else(|| format!("field \"{key}\" has no ':' separator"))?;
    let after_colon = after_key
        .get(colon_rel.saturating_add(1)..)
        .unwrap_or_default();
    // The value runs until the next ',' or '}'.
    let end = after_colon.find([',', '}']).unwrap_or(after_colon.len());
    let token = after_colon.get(..end).unwrap_or_default().trim();
    if token.is_empty() {
        return Err(format!("field \"{key}\" has an empty value"));
    }
    Ok(token)
}

/// Parse a required `f64`-valued field.
fn parse_f64_field(text: &str, key: &str) -> Result<f64, String> {
    let token = scalar_after_key(text, key)?;
    token
        .parse::<f64>()
        .map_err(|e| format!("field \"{key}\" is not a number ('{token}'): {e}"))
}

/// Parse a required `bool`-valued field.
fn parse_bool_field(text: &str, key: &str) -> Result<bool, String> {
    let token = scalar_after_key(text, key)?;
    match token {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!(
            "field \"{key}\" is not a boolean ('{other}', want true/false)"
        )),
    }
}

#[cfg(test)]
#[allow(
    // Tests assert exact verdicts and index fixed-size fixtures — fine in test
    // code (mirrors the lib.rs / apt.rs test posture). The constants and parsed
    // values are exact (no arithmetic), so float_cmp is the precise assertion.
    clippy::float_cmp,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    /// An all-pass tuple comfortably above every threshold.
    fn all_pass() -> GateInputs {
        GateInputs {
            raw_min_entropy: 1.0,
            restart_row_min_entropy: 0.8,
            restart_col_min_entropy: 0.7,
            restart_sanity_pass: true,
        }
    }

    /// The cited constants must match the §6.3 recipe exactly.
    #[test]
    fn constants_match_spec() {
        assert_eq!(RAW_RATE_FLOOR, 0.333, "§6.3 cond 1 floor");
        assert_eq!(RESTART_RATE_FLOOR, 0.333, "§6.3 cond 4 floor");
        assert_eq!(RESTART_HALF_RAW_FACTOR, 0.5, "§6.3 cond 3 half-factor");
    }

    /// All-pass tuple ⇒ accept, no failed conditions.
    #[test]
    fn all_conditions_pass_accepts() {
        let d = evaluate(&all_pass());
        assert!(d.accept, "all-pass tuple must accept");
        assert!(d.failed().is_empty(), "no condition should fail");
        assert!(d.conditions.raw_rate);
        assert!(d.conditions.restart_sanity);
        assert!(d.conditions.restart_half_raw);
        assert!(d.conditions.restart_rate);
    }

    /// Condition (1): raw rate at/below the 0.333 floor ⇒ reject on RawRate.
    ///
    /// Raw = 0.333 exactly (not strictly greater) trips cond 1. It also pulls
    /// the restart values down to keep them valid relative to the (now-failing)
    /// raw — but the binding failure asserted here is RawRate.
    #[test]
    fn raw_rate_at_floor_fails_cond1() {
        let mut i = all_pass();
        i.raw_min_entropy = RAW_RATE_FLOOR; // == 0.333, not > 0.333
        let d = evaluate(&i);
        assert!(!d.accept);
        assert!(
            !d.conditions.raw_rate,
            "raw==floor must fail cond 1 (strict >)"
        );
        assert!(d.failed().contains(&Condition::RawRate));
    }

    /// Condition (2): restart sanity check fails ⇒ reject on RestartSanity,
    /// with all numeric conditions still passing (isolates cond 2).
    #[test]
    fn restart_sanity_false_fails_cond2() {
        let mut i = all_pass();
        i.restart_sanity_pass = false;
        let d = evaluate(&i);
        assert!(!d.accept);
        assert!(
            !d.conditions.restart_sanity,
            "sanity=false must fail cond 2"
        );
        // The three numeric conditions are untouched and still pass.
        assert!(d.conditions.raw_rate);
        assert!(d.conditions.restart_half_raw);
        assert!(d.conditions.restart_rate);
        assert_eq!(d.failed(), vec![Condition::RestartSanity]);
    }

    /// Condition (3): restart min below half the raw rate ⇒ reject on
    /// RestartHalfRaw, while the restart floor (cond 4) still passes.
    ///
    /// raw = 1.0 ⇒ half-raw threshold = 0.5; set restart min to 0.45 (> 0.333,
    /// so cond 4 passes) but < 0.5 (cond 3 fails). This isolates cond 3.
    #[test]
    fn restart_below_half_raw_fails_cond3_only() {
        let mut i = all_pass();
        i.raw_min_entropy = 1.0;
        i.restart_row_min_entropy = 0.45;
        i.restart_col_min_entropy = 0.46;
        let d = evaluate(&i);
        assert!(!d.accept);
        assert!(
            !d.conditions.restart_half_raw,
            "0.45 < 0.5 must fail cond 3"
        );
        assert!(d.conditions.restart_rate, "0.45 > 0.333 must pass cond 4");
        assert!(d.conditions.raw_rate);
        assert!(d.conditions.restart_sanity);
        assert_eq!(d.failed(), vec![Condition::RestartHalfRaw]);
    }

    /// Condition (4): restart min at/below the 0.333 floor ⇒ reject on
    /// RestartRate. With a small raw, cond 3 (half-raw) can still pass, so this
    /// isolates cond 4.
    ///
    /// raw = 0.40 ⇒ half-raw threshold = 0.20; restart min = 0.333 (== floor,
    /// not > floor ⇒ cond 4 fails) and 0.333 >= 0.20 ⇒ cond 3 passes. raw 0.40
    /// > 0.333 ⇒ cond 1 passes.
    #[test]
    fn restart_at_floor_fails_cond4_only() {
        let i = GateInputs {
            raw_min_entropy: 0.40,
            restart_row_min_entropy: RESTART_RATE_FLOOR, // 0.333, not > 0.333
            restart_col_min_entropy: 0.50,
            restart_sanity_pass: true,
        };
        let d = evaluate(&i);
        assert!(!d.accept);
        assert!(
            !d.conditions.restart_rate,
            "restart==floor must fail cond 4"
        );
        assert!(
            d.conditions.restart_half_raw,
            "0.333 >= 0.20 must pass cond 3"
        );
        assert!(d.conditions.raw_rate, "0.40 > 0.333 must pass cond 1");
        assert_eq!(d.failed(), vec![Condition::RestartRate]);
    }

    /// `restart_min` takes the smaller of row/col (the §6.3 estimate).
    #[test]
    fn restart_min_is_smaller_of_row_col() {
        let i = GateInputs {
            raw_min_entropy: 1.0,
            restart_row_min_entropy: 0.9,
            restart_col_min_entropy: 0.4,
            restart_sanity_pass: true,
        };
        assert_eq!(i.restart_min(), 0.4);
        // 0.4 < 0.5 ⇒ cond 3 fails even though the row value alone would pass.
        let d = evaluate(&i);
        assert!(!d.conditions.restart_half_raw);
    }

    /// NaN raw ⇒ all numeric conditions fail (no panic), gate rejects.
    #[test]
    fn nan_raw_rejects_without_panic() {
        let mut i = all_pass();
        i.raw_min_entropy = f64::NAN;
        let d = evaluate(&i);
        assert!(!d.accept);
        assert!(!d.conditions.raw_rate, "NaN > floor is false");
    }

    /// Ingestion: well-formed sidecar parses to the expected inputs.
    #[test]
    fn parse_results_well_formed() {
        let json = r#"{
            "raw_min_entropy": 0.95,
            "restart_row_min_entropy": 0.80,
            "restart_col_min_entropy": 0.78,
            "restart_sanity_pass": true
        }"#;
        let i = parse_results(json).unwrap();
        assert_eq!(i.raw_min_entropy, 0.95);
        assert_eq!(i.restart_row_min_entropy, 0.80);
        assert_eq!(i.restart_col_min_entropy, 0.78);
        assert!(i.restart_sanity_pass);
        assert!(evaluate(&i).accept);
    }

    /// Ingestion: a missing field is a parse error, not a silent default.
    #[test]
    fn parse_results_missing_field_errors() {
        let json = r#"{ "raw_min_entropy": 0.95, "restart_row_min_entropy": 0.80 }"#;
        let err = parse_results(json).unwrap_err();
        assert!(err.contains("restart_col_min_entropy"), "err: {err}");
    }

    /// Ingestion: a non-numeric value is a parse error.
    #[test]
    fn parse_results_bad_number_errors() {
        let json = r#"{
            "raw_min_entropy": "high",
            "restart_row_min_entropy": 0.80,
            "restart_col_min_entropy": 0.78,
            "restart_sanity_pass": true
        }"#;
        let err = parse_results(json).unwrap_err();
        assert!(err.contains("raw_min_entropy"), "err: {err}");
    }

    /// Ingestion: a non-boolean sanity value is a parse error.
    #[test]
    fn parse_results_bad_bool_errors() {
        let json = r#"{
            "raw_min_entropy": 0.95,
            "restart_row_min_entropy": 0.80,
            "restart_col_min_entropy": 0.78,
            "restart_sanity_pass": yes
        }"#;
        let err = parse_results(json).unwrap_err();
        assert!(err.contains("restart_sanity_pass"), "err: {err}");
    }
}
