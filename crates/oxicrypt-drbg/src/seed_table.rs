//! The assessed operational environments: the targets whose seed comes
//! from the in-boundary SP 800-90B jitter source, and the labels every
//! surface uses to name the seed path.
//!
//! Each row mirrors one row of the Security Policy's §9.3.0 table, and the
//! `claim_table_matches_policy` test compares the two.

use oxicrypt_entropy::h::MinEntropy;
use oxicrypt_entropy::jitter::JitterSource;
use oxicrypt_entropy::pipeline::EntropyPipeline;
use oxicrypt_entropy::source::TimerSource;
use oxicrypt_entropy::timer::PlatformTimer;

use crate::seed::SourceKind;

/// One assessed operational environment.
#[derive(Debug)]
pub(crate) struct EnvRow {
    /// The `target_arch` the row covers.
    pub(crate) arch: &'static str,
    /// The `target_os` the row covers.
    pub(crate) os: &'static str,
    /// The timer the jitter source reads on this target.
    pub(crate) timer: TimerSource,
    /// The assessed min-entropy per sample, never below [`MIN_CLAIM`].
    pub(crate) claimed_h: MinEntropy,
    /// The SP 800-90B source the row draws from.
    pub(crate) source: SourceKind,
    /// The row id in the Security Policy's §9.3.0 table.
    pub(crate) policy_ref: &'static str,
}

/// The lowest min-entropy per sample any row may claim.
pub(crate) const MIN_CLAIM: MinEntropy = MinEntropy::from_fraction_floor_const(1, 2);

/// The assessed operational environments, in Security Policy order.
pub(crate) const ROWS: &[EnvRow] = &[EnvRow {
    arch: "x86_64",
    os: "linux",
    timer: TimerSource::RawCounter,
    claimed_h: MinEntropy::from_fraction_floor_const(1, 2),
    source: SourceKind::Jitter,
    policy_ref: "OE-1",
}];

/// Whether every row claims at least [`MIN_CLAIM`].
const fn rows_meet_floor(mut rows: &[EnvRow]) -> bool {
    while let [row, rest @ ..] = rows {
        if row.claimed_h.steps() < MIN_CLAIM.steps() {
            return false;
        }
        rows = rest;
    }
    true
}

const _: () = assert!(
    rows_meet_floor(ROWS),
    "an assessed environment row claims less than 1/2 bit of min-entropy per sample"
);

/// The label of the operating-system path when no row matches the target.
pub(crate) const LABEL_OPERATING_SYSTEM: &str =
    "operating-system generator (untested operational environment, IG 9.3.A AC2)";

/// The label of the operating-system path when a matching row's timer
/// failed the adequacy check.
pub(crate) const LABEL_OPERATING_SYSTEM_TIMER_INADEQUATE: &str = "operating-system generator (untested operational environment, IG 9.3.A AC2); timer adequacy not met";

/// The label of the assessed path for row `OE-1`.
pub(crate) const LABEL_ASSESSED_OE_1: &str = "jitter source, assessed row OE-1";

/// Why the seed path is the operating system's generator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OsReason {
    /// No row matches the running target.
    NoRow,
    /// A row matches, and its timer failed the construction-time adequacy
    /// check.
    TimerInadequate,
}

/// The seed path decided for this process.
#[derive(Clone, Copy, Debug)]
pub(crate) enum SeedChoice {
    /// The jitter source, under the matching row.
    Assessed(&'static EnvRow),
    /// The operating system's generator.
    Os(OsReason),
}

impl SeedChoice {
    /// The path name a [`crate::SeedPathReport`] carries.
    pub(crate) const fn path(self) -> &'static str {
        match self {
            Self::Assessed(_) => "assessed",
            Self::Os(_) => "operating-system",
        }
    }

    /// The label every surface uses for this path.
    pub(crate) fn label(self) -> &'static str {
        match self {
            // A row outside the shipped table has no assessed label of its
            // own; it is named by its source alone.
            Self::Assessed(row) => match row.policy_ref {
                "OE-1" => LABEL_ASSESSED_OE_1,
                _ => "jitter source",
            },
            Self::Os(OsReason::NoRow) => LABEL_OPERATING_SYSTEM,
            Self::Os(OsReason::TimerInadequate) => LABEL_OPERATING_SYSTEM_TIMER_INADEQUATE,
        }
    }
}

/// The jitter pipeline the assessed path draws from.
pub(crate) type Pipeline = EntropyPipeline<JitterSource<'static, PlatformTimer>>;

/// The process's seed-path decision and, on the assessed path, its
/// started pipeline.
pub(crate) struct SeedState {
    /// The decided path.
    pub(crate) choice: SeedChoice,
    /// The started pipeline, present on the assessed path.
    pub(crate) pipeline: Option<Pipeline>,
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::print_stderr,
        reason = "test assertions panic by design, and a skipped policy check is reported on stderr"
    )]

    use std::path::PathBuf;
    use std::string::{String, ToString};
    use std::vec::Vec;

    use super::{MIN_CLAIM, ROWS};
    use oxicrypt_entropy::h::MinEntropy;
    use oxicrypt_entropy::source::TimerSource;

    /// The Security Policy, resolved as `tools/doc-guard` resolves it.
    fn policy_path() -> PathBuf {
        if let Some(value) = std::env::var("OXICRYPT_SECURITY_POLICY")
            .ok()
            .filter(|v| !v.is_empty())
        {
            let path = PathBuf::from(value);
            return if path.is_dir() {
                path.join("security-policy.md")
            } else {
                path
            };
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home)
            .join("repos/oxicrypt-policy")
            .join("security-policy.md")
    }

    fn timer_name(timer: TimerSource) -> &'static str {
        match timer {
            TimerSource::RawCounter => "raw counter",
            TimerSource::OsNanoClock => "os nanosecond clock",
            TimerSource::InternalTimerThread => "internal timer thread",
        }
    }

    /// Parses `num/den` into the value `from_fraction_floor_const` gives.
    fn parse_h(text: &str) -> MinEntropy {
        let (num, den) = text
            .split_once('/')
            .unwrap_or_else(|| panic!("H `{text}` is not a fraction num/den"));
        MinEntropy::from_fraction_floor_const(
            num.trim().parse().unwrap(),
            den.trim().parse().unwrap(),
        )
    }

    /// The `(id, arch, os, timer, H)` rows of the §9.3 environment table.
    fn policy_rows(policy: &str) -> Vec<(String, String, String, String, u32)> {
        let mut lines = policy.lines();
        lines
            .by_ref()
            .find(|line| line.starts_with('#') && line.contains("9.3"))
            .expect("the Security Policy has a §9.3 heading");
        lines
            .by_ref()
            .find(|line| line.trim() == "| id | arch | os | timer | H |")
            .expect("§9.3 holds the `| id | arch | os | timer | H |` table");
        let separator = lines.next().expect("the table has a separator row");
        assert!(
            separator.starts_with("|---"),
            "unexpected separator {separator:?}"
        );
        lines
            .take_while(|line| line.trim_start().starts_with('|'))
            .map(|line| {
                let cells: Vec<&str> = line
                    .trim()
                    .trim_matches('|')
                    .split('|')
                    .map(str::trim)
                    .collect();
                assert_eq!(cells.len(), 5, "row {line:?} does not have five cells");
                (
                    cells[0].to_string(),
                    cells[1].to_string(),
                    cells[2].to_string(),
                    cells[3].to_string(),
                    parse_h(cells[4]).steps(),
                )
            })
            .collect()
    }

    #[test]
    fn claim_table_matches_policy() {
        assert!(!ROWS.is_empty());
        for row in ROWS {
            assert!(
                row.claimed_h >= MIN_CLAIM,
                "row {} claims below 1/2",
                row.policy_ref
            );
        }

        let path = policy_path();
        let Ok(policy) = std::fs::read_to_string(&path) else {
            let optional =
                std::env::var("OXICRYPT_SECURITY_POLICY_OPTIONAL").is_ok_and(|v| v == "1");
            assert!(
                optional,
                "the Security Policy is not readable at {}; set OXICRYPT_SECURITY_POLICY, or \
                 OXICRYPT_SECURITY_POLICY_OPTIONAL=1 to skip this comparison",
                path.display()
            );
            std::eprintln!(
                "SKIP claim_table_matches_policy: the Security Policy is not provisioned at {}",
                path.display()
            );
            return;
        };

        let mut from_policy = policy_rows(&policy);
        let mut from_table: Vec<_> = ROWS
            .iter()
            .map(|row| {
                (
                    row.policy_ref.to_string(),
                    row.arch.to_string(),
                    row.os.to_string(),
                    timer_name(row.timer).to_string(),
                    row.claimed_h.steps(),
                )
            })
            .collect();
        from_policy.sort();
        from_table.sort();
        assert_eq!(from_table, from_policy);
    }
}
