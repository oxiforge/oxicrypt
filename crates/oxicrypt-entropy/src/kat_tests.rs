//! Health-test known-answer tests over the shipped synthetic vector files.
//!
//! The vectors in `testdata/` are committed artifacts with documented,
//! deterministic generation and known RCT/APT outcomes:
//!
//! - `rct_dead_source.bin` — 64 × `0xAA` (dead source). Known outcome:
//!   RCT failure at exactly sample C = 11 under H = 2.0, α = 2⁻²⁰.
//! - `apt_low_variety.bin` — 1024 bytes alternating `0x00`/`0x01` on an
//!   8-bit alphabet. Known outcome under an H = 8 claim (W = 512, C = 13):
//!   APT failure at the 13th reference occurrence — sample index 24
//!   (0-based), i.e. the 25th sample.
//! - `healthy_stream.bin` — 4096 bytes of xorshift32 (seed `0x1234_5678`,
//!   low byte). Known outcome: passes both tests in full under H = 2.0,
//!   α = 2⁻²⁰.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use crate::h::MinEntropy;
use crate::health::{Alpha, HealthError, HealthMonitor, HealthTest};

const RCT_DEAD: &[u8] = include_bytes!("../testdata/rct_dead_source.bin");
const APT_LOW_VARIETY: &[u8] = include_bytes!("../testdata/apt_low_variety.bin");
const HEALTHY: &[u8] = include_bytes!("../testdata/healthy_stream.bin");

fn alpha20() -> Alpha {
    Alpha::from_exp(20).unwrap()
}

#[test]
fn kat_dead_source_trips_rct_at_cutoff() {
    let mut m = HealthMonitor::new(MinEntropy::from_bits(2), false, alpha20()).unwrap();
    let mut tripped_at = None;
    for (i, &b) in RCT_DEAD.iter().enumerate() {
        match m.feed(b) {
            Ok(()) => (),
            Err(e) => {
                assert_eq!(e, HealthError::Failed(HealthTest::Rct));
                tripped_at = Some(i);
                break;
            }
        }
    }
    // C = 11 → the failure lands on the 11th sample, index 10.
    assert_eq!(tripped_at, Some(10));
}

#[test]
fn kat_low_variety_trips_apt_in_first_window() {
    let mut m = HealthMonitor::new(MinEntropy::from_bits(8), false, alpha20()).unwrap();
    let mut tripped_at = None;
    for (i, &b) in APT_LOW_VARIETY.iter().enumerate() {
        match m.feed(b) {
            Ok(()) => (),
            Err(e) => {
                assert_eq!(e, HealthError::Failed(HealthTest::Apt));
                tripped_at = Some(i);
                break;
            }
        }
    }
    // C = 13, reference 0x00 at even indices → 13th occurrence at index 24,
    // well inside the first W = 512 window.
    assert_eq!(tripped_at, Some(24));
}

#[test]
fn kat_healthy_stream_passes_in_full() {
    let mut m = HealthMonitor::new(MinEntropy::from_bits(2), false, alpha20()).unwrap();
    for &b in HEALTHY {
        m.feed(b).unwrap();
    }
    assert!(!m.is_poisoned());
}
