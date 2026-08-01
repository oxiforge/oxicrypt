//! Write a deterministic non-IID sample file for the `maxwell` assessment
//! timing recorded in `docs/entropy-performance.md`.
//!
//! The documented non-IID figure is a single wall-clock CLI run rather than a
//! criterion statistic, because criterion's 10-sample floor would make that one
//! case run for hours. A number produced outside the benchmark harness is only
//! trustworthy if the input is reproducible, so the generator is committed
//! rather than described.
//!
//! ```sh
//! cargo run -p oxicrypt-bench --features entropy-bench --example gen_noniid -- /tmp/noniid.bin 1000000 8
//! /usr/bin/time -f 'WALL=%e s' ./target/release/maxwell iid-gate /tmp/noniid.bin 8
//! ```
//!
//! The chain is the same shape the `maxwell` benchmark synthesises in-process:
//! a first-order Markov chain with a 5% switch probability, which routes
//! non-IID because its samples are dependent, not because anything forces the
//! verdict.

#![allow(
    clippy::expect_used,
    clippy::print_stderr,
    // The `as u8` narrowing is the operation: these are `width`-bit symbols
    // drawn from the low bits of a 64-bit PRNG word.
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects,
    missing_docs
)]

use std::io::Write as _;

struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let Some(path) = args.get(1) else {
        eprintln!("usage: gen_noniid <path> [samples=1000000] [width_bits=8]");
        std::process::exit(2);
    };
    let samples: usize = args
        .get(2)
        .map_or(1_000_000, |s| s.parse().expect("samples must be a number"));
    let width: u32 = args
        .get(3)
        .map_or(8, |s| s.parse().expect("width must be a number"));
    assert!(
        (1..=8).contains(&width),
        "width must be 1..=8 bits; the module's own jitter source emits 4"
    );
    let mask = (1u64 << width) - 1;

    // Fixed seed: the documented figure must be reproducible byte for byte.
    let mut rng = SplitMix64(0x00D3_9E7D_00D3_9E7D);
    let mut cur = 0u8;
    let mut out = Vec::with_capacity(samples);
    for _ in 0..samples {
        if rng.next() % 100 < 5 {
            cur = ((rng.next() >> 33) & mask) as u8;
        }
        out.push(cur);
    }

    let mut f = std::fs::File::create(path).expect("create output file");
    f.write_all(&out).expect("write samples");
    f.sync_all().expect("sync");
    eprintln!("wrote {samples} samples of {width}-bit symbols to {path}");
}
