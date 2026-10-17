#![allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    missing_docs
)]

//! LMS (SP 800-208) verification benchmarks.
//!
//! Two groups:
//!
//! - `verify` — SHA-256/M=32 family, H ∈ {5, 10, 15} × W ∈ {4, 8}, each on
//!   the passing NIST ACVP sigVer vector `oxicrypt-lms` keeps for that pair
//!   in `crates/oxicrypt-lms/tests/data/`. Verification cost is dominated by
//!   the LM-OTS chains (P chains of up to 2^W − 1 steps) plus H Merkle
//!   hashes, so it grows with W far faster than with H.
//! - `cast` — each of the four power-up CASTs in `oxicrypt_lms::KATS`, one
//!   accept and one reject verification at H = 5, W = 1 per hash adapter.

use std::time::Duration;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use oxicrypt_lms::{
    lms_sha256_m32_h5_w4 as h5_w4, lms_sha256_m32_h5_w8 as h5_w8, lms_sha256_m32_h10_w4 as h10_w4,
    lms_sha256_m32_h10_w8 as h10_w8, lms_sha256_m32_h15_w4 as h15_w4,
    lms_sha256_m32_h15_w8 as h15_w8,
};

/// Reads one NIST sigVer fixture (`pk`, `msg` or `sig`) for a pair from
/// `oxicrypt-lms`'s test data.
fn fixture(slug: &str, part: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../crates/oxicrypt-lms/tests/data")
        .join(format!("{slug}_sigver_{part}.bin"));
    std::fs::read(&path).expect("LMS sigVer fixture in crates/oxicrypt-lms/tests/data")
}

/// Verify bench for one (LMS, LM-OTS) pair, on its NIST sigVer fixture.
macro_rules! lms_verify_bench {
    ($fn_name:ident, $pair:ident, $slug:literal, $label:literal) => {
        fn $fn_name(c: &mut Criterion) {
            oxicrypt_bench::init_module();

            let pk: [u8; $pair::PUBLIC_KEY_LEN] =
                fixture($slug, "pk").try_into().expect("public key length");
            let msg: Vec<u8> = fixture($slug, "msg");
            let msg: &[u8] = &msg;
            let sig: [u8; $pair::SIGNATURE_LEN] =
                fixture($slug, "sig").try_into().expect("signature length");
            $pair::verify(&pk, msg, &sig).expect("NIST vector verifies");

            let mut group = c.benchmark_group("LMS-SHA256/M32 verify");
            group.warm_up_time(Duration::from_secs(1));
            group.bench_function($label, |b| {
                b.iter(|| $pair::verify(black_box(&pk), black_box(msg), black_box(&sig)));
            });
            group.finish();
        }
    };
}

lms_verify_bench!(
    bench_lms_verify_h5_w4,
    h5_w4,
    "lms_sha256_m32_h5_w4",
    "H5/W4"
);
lms_verify_bench!(
    bench_lms_verify_h5_w8,
    h5_w8,
    "lms_sha256_m32_h5_w8",
    "H5/W8"
);
lms_verify_bench!(
    bench_lms_verify_h10_w4,
    h10_w4,
    "lms_sha256_m32_h10_w4",
    "H10/W4"
);
lms_verify_bench!(
    bench_lms_verify_h10_w8,
    h10_w8,
    "lms_sha256_m32_h10_w8",
    "H10/W8"
);
lms_verify_bench!(
    bench_lms_verify_h15_w4,
    h15_w4,
    "lms_sha256_m32_h15_w4",
    "H15/W4"
);
lms_verify_bench!(
    bench_lms_verify_h15_w8,
    h15_w8,
    "lms_sha256_m32_h15_w8",
    "H15/W8"
);

/// Each power-up CAST, timed as the module runs it.
fn bench_lms_cast(c: &mut Criterion) {
    // The KATs call `*_internal` functions, which refuse until the
    // module's self-tests have started.
    oxicrypt_bench::init_module();
    let mut group = c.benchmark_group("LMS CAST");
    group.warm_up_time(Duration::from_secs(1));
    for kat in oxicrypt_lms::KATS {
        (kat.run)().expect("CAST passes");
        group.bench_function(kat.name, |b| b.iter(|| (kat.run)()));
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_lms_verify_h5_w4,
    bench_lms_verify_h5_w8,
    bench_lms_verify_h10_w4,
    bench_lms_verify_h10_w8,
    bench_lms_verify_h15_w4,
    bench_lms_verify_h15_w8,
    bench_lms_cast,
);
criterion_main!(benches);
