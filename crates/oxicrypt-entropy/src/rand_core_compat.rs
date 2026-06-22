//! `rand_core` 0.9 compatibility shim (behind the default-off `rand-core`
//! feature).
//!
//! Exposes the entropy pipeline's **vetted conditioned output** as a
//! standard `rand_core::TryRngCore` generator so callers wired to the
//! `rand` ecosystem can draw from this source without bespoke glue.
//!
//! # Why the *fallible* trait
//!
//! The pipeline is fallible by design: it refuses output before startup
//! ([`crate::error::EntropyError::NotReady`]), and any health-test failure poisons it
//! permanently. That is exactly the contract `TryRngCore` models — a
//! generator whose draws may fail — so this shim implements
//! `TryRngCore` (with `Error = EntropyError`), **not** the infallible
//! `rand_core::RngCore`. There is no panicking fallback path: an error
//! from the pipeline propagates out verbatim, and a poisoned pipeline keeps
//! returning errors forever.
//!
//! # Owning, not borrowing
//!
//! [`crate::rand_core_compat::EntropyRng`] **owns** its [`crate::pipeline::EntropyPipeline`]. The `rand_core` blanket
//! impl `impl<R: RngCore> TryRngCore for R` deliberately does *not* cover
//! `&mut R`, so a borrowing adapter could not satisfy generic bounds like
//! `R: TryRngCore` taken by value anyway; an owning newtype is the
//! idiomatic, friction-free shape (it can be moved into `rand` combinators
//! that take `R: TryRngCore`). Callers retain full control of the wrapped
//! pipeline through [`crate::rand_core_compat::EntropyRng::pipeline`], [`crate::rand_core_compat::EntropyRng::pipeline_mut`],
//! and [`crate::rand_core_compat::EntropyRng::into_inner`] — including running startup, which the
//! shim never does implicitly.
//!
//! # Output semantics
//!
//! Every byte handed out is conditioned full-entropy output drawn through
//! [`crate::pipeline::EntropyPipeline::conditioned_block`] (the sole vetted output path).
//! Bytes are consumed in 32-byte conditioned blocks; the unused tail of the
//! last block fetched is buffered inside [`crate::rand_core_compat::EntropyRng`] and spent before any
//! new block is drawn, so no conditioned output is ever wasted.
//! `try_next_u32` / `try_next_u64` read 4 / 8 bytes via the same byte path
//! and assemble them **little-endian**.

use crate::conditioner::CONDITIONED_BLOCK_LEN;
use crate::error::EntropyError;
use crate::pipeline::EntropyPipeline;
use crate::source::NoiseSource;

use rand_core::{TryCryptoRng, TryRngCore};

/// A `rand_core` generator backed by an entropy pipeline's vetted
/// conditioned output.
///
/// Implements the **fallible** `TryRngCore` (and the `TryCryptoRng`
/// marker, since conditioned output is CSPRNG-quality). Draws may fail with
/// [`crate::error::EntropyError`] — most importantly [`crate::error::EntropyError::NotReady`] before
/// [`crate::pipeline::EntropyPipeline::run_startup`] has passed, and after permanent
/// poisoning.
///
/// The wrapper buffers the unconsumed tail of the most recent conditioned
/// block so partial reads never discard vetted output.
#[derive(Debug)]
pub struct EntropyRng<S: NoiseSource> {
    pipeline: EntropyPipeline<S>,
    /// The most recently fetched conditioned block.
    block: [u8; CONDITIONED_BLOCK_LEN],
    /// Bytes `[pos, CONDITIONED_BLOCK_LEN)` of `block` are unconsumed.
    /// `pos == CONDITIONED_BLOCK_LEN` means the buffer is empty.
    pos: usize,
}

impl<S: NoiseSource> EntropyRng<S> {
    /// Wraps a pipeline as a `rand_core` generator.
    ///
    /// Does **not** run startup — the caller drives lifecycle. Until
    /// [`crate::pipeline::EntropyPipeline::run_startup`] has passed, every `try_*` draw
    /// returns [`crate::error::EntropyError::NotReady`].
    #[must_use]
    pub fn new(pipeline: EntropyPipeline<S>) -> Self {
        Self {
            pipeline,
            block: [0u8; CONDITIONED_BLOCK_LEN],
            pos: CONDITIONED_BLOCK_LEN, // start empty
        }
    }

    /// Shared access to the wrapped pipeline.
    #[must_use]
    pub fn pipeline(&self) -> &EntropyPipeline<S> {
        &self.pipeline
    }

    /// Mutable access to the wrapped pipeline (e.g. to run startup).
    ///
    /// Mutating the pipeline through this handle does not invalidate any
    /// already-buffered conditioned output, which remains vetted full-entropy
    /// bytes regardless of subsequent lifecycle calls.
    pub fn pipeline_mut(&mut self) -> &mut EntropyPipeline<S> {
        &mut self.pipeline
    }

    /// Unwraps the generator, returning the pipeline. Any buffered
    /// conditioned-output tail is discarded.
    #[must_use]
    pub fn into_inner(self) -> EntropyPipeline<S> {
        self.pipeline
    }

    /// Fills `dst` from buffered conditioned output, drawing fresh blocks as
    /// needed. On any pipeline error nothing further is written and the
    /// error propagates; the buffer is left in a consistent state (the
    /// failed block is not partially exposed).
    ///
    /// Driven byte-by-byte over a destination iterator with slice `get`
    /// accessors and saturating arithmetic so the body carries no
    /// panicking index/slice or overflowing op (the crate forbids both).
    fn fill(&mut self, dst: &mut [u8]) -> Result<(), EntropyError> {
        for out in dst.iter_mut() {
            if self.pos >= CONDITIONED_BLOCK_LEN {
                // Buffer empty: draw a fresh conditioned block. Any error
                // (NotReady, Health, Source, ...) propagates verbatim.
                self.block = self.pipeline.conditioned_block()?;
                self.pos = 0;
            }
            // `pos < CONDITIONED_BLOCK_LEN` holds here, so `get` is `Some`;
            // the `unreachable_*` fallback keeps the path panic-free for the
            // restriction lints without an `expect`/`unwrap`.
            *out = self.block.get(self.pos).copied().unwrap_or(0);
            self.pos = self.pos.saturating_add(1);
        }
        Ok(())
    }
}

impl<S: NoiseSource> TryRngCore for EntropyRng<S> {
    type Error = EntropyError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.fill(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.fill(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.fill(dst)
    }
}

// Conditioned output is CSPRNG-quality (vetted SHA-256 full-entropy output
// under the 90C input margin), so the generator carries the cryptographic
// marker. This does not conflict with rand_core's blanket
// `impl<R: CryptoRng> TryCryptoRng for R`: `EntropyRng` implements neither
// `RngCore` nor `CryptoRng`, so the blanket impl does not apply to it.
impl<S: NoiseSource> TryCryptoRng for EntropyRng<S> {}

#[cfg(all(test, feature = "rand-core"))]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::h::MinEntropy;
    use crate::health::Alpha;
    use crate::source::{
        NoiseSource, RawSample, SourceError, SourceMetadata, SourceSpec, sealed::Sealed,
    };

    fn alpha20() -> Alpha {
        Alpha::from_exp(20).unwrap()
    }

    fn meta() -> SourceMetadata<'static> {
        SourceMetadata {
            timer_source: None,
            counter_frequency_hz: None,
            cpu_model: "test",
            os: "test",
            collection_params: "rand-core compat test",
        }
    }

    /// Deterministic xorshift byte source (mirrors pipeline.rs PrngMock):
    /// healthy, 8-bit alphabet, identical stream from identical seed.
    #[derive(Debug)]
    struct PrngMock {
        state: u32,
    }
    impl PrngMock {
        fn new() -> Self {
            Self { state: 0x1234_5678 }
        }
    }
    impl Sealed for PrngMock {}
    impl NoiseSource for PrngMock {
        fn spec(&self) -> SourceSpec {
            SourceSpec::new(8).unwrap()
        }
        fn max_claimable_h(&self) -> MinEntropy {
            MinEntropy::from_bits(4)
        }
        fn sample(&mut self) -> Result<RawSample, SourceError> {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.state = x;
            Ok((x & 0xFF) as u8)
        }
        fn metadata(&self) -> SourceMetadata<'_> {
            meta()
        }
    }

    /// Dead source: constant output. Trips the RCT during startup so the
    /// pipeline poisons — used for the error-after-poison path.
    #[derive(Debug)]
    struct DeadMock;
    impl Sealed for DeadMock {}
    impl NoiseSource for DeadMock {
        fn spec(&self) -> SourceSpec {
            SourceSpec::new(8).unwrap()
        }
        fn max_claimable_h(&self) -> MinEntropy {
            MinEntropy::from_bits(4)
        }
        fn sample(&mut self) -> Result<RawSample, SourceError> {
            Ok(0xAA)
        }
        fn metadata(&self) -> SourceMetadata<'_> {
            meta()
        }
    }

    fn started_rng() -> EntropyRng<PrngMock> {
        let mut p =
            EntropyPipeline::new(PrngMock::new(), MinEntropy::from_bits(2), alpha20()).unwrap();
        p.run_startup().unwrap();
        EntropyRng::new(p)
    }

    // (a) try_fill_bytes of several lengths returns Ok after startup and
    //     fills exactly the requested length (including spanning blocks).
    #[test]
    fn fill_bytes_various_lengths_fill_exactly() {
        // Fixed 128-byte backing array (no alloc; no_std-test friendly); the
        // guard byte just past `len` proves the write extent is exact.
        for &len in &[0usize, 1, 31, 32, 33, 100] {
            let mut rng = started_rng();
            let mut backing = [0xEEu8; 128];
            backing[len] = 0x5A; // guard byte just past the requested region
            rng.try_fill_bytes(&mut backing[..len]).unwrap();
            assert_eq!(backing[len], 0x5A, "wrote past requested length at {len}");
        }
    }

    // (b) determinism: two generators over the same deterministic mock +
    //     same startup produce identical streams.
    #[test]
    fn deterministic_streams_match() {
        let mut a = started_rng();
        let mut b = started_rng();
        // Cross several blocks (200 bytes > 6 conditioned blocks) and a
        // non-block-aligned span to exercise the tail buffer.
        let mut ba = [0u8; 200];
        let mut bb = [0u8; 200];
        a.try_fill_bytes(&mut ba).unwrap();
        b.try_fill_bytes(&mut bb).unwrap();
        assert_eq!(ba, bb);
        // Subsequent draws stay in lockstep.
        assert_eq!(a.try_next_u64().unwrap(), b.try_next_u64().unwrap());
        assert_eq!(a.try_next_u32().unwrap(), b.try_next_u32().unwrap());
    }

    // (c) try_next_u32 / try_next_u64 are LE-consistent with the bytes
    //     try_fill_bytes would have produced at the same stream position.
    #[test]
    fn next_uints_are_le_of_fill_bytes() {
        // u32 consistency.
        {
            let mut a = started_rng();
            let mut b = started_rng();
            let mut le4 = [0u8; 4];
            a.try_fill_bytes(&mut le4).unwrap();
            assert_eq!(b.try_next_u32().unwrap(), u32::from_le_bytes(le4));
        }
        // u64 consistency.
        {
            let mut a = started_rng();
            let mut b = started_rng();
            let mut le8 = [0u8; 8];
            a.try_fill_bytes(&mut le8).unwrap();
            assert_eq!(b.try_next_u64().unwrap(), u64::from_le_bytes(le8));
        }
    }

    // (d) error propagation: before startup, and after poisoning, every
    //     try_* method returns Err(the EntropyError) and never panics.
    #[test]
    fn before_startup_all_methods_error_not_ready() {
        let p = EntropyPipeline::new(PrngMock::new(), MinEntropy::from_bits(2), alpha20()).unwrap();
        let mut rng = EntropyRng::new(p);
        assert_eq!(rng.try_next_u32().unwrap_err(), EntropyError::NotReady);
        assert_eq!(rng.try_next_u64().unwrap_err(), EntropyError::NotReady);
        let mut buf = [0u8; 16];
        assert_eq!(
            rng.try_fill_bytes(&mut buf).unwrap_err(),
            EntropyError::NotReady
        );
    }

    #[test]
    fn after_poisoning_all_methods_error() {
        // DeadMock trips the RCT at startup → permanently poisoned. Every
        // draw then errors (NotReady, the poisoned-state error) and none panic.
        let mut p = EntropyPipeline::new(DeadMock, MinEntropy::from_bits(2), alpha20()).unwrap();
        let _ = p.run_startup();
        assert!(p.is_poisoned());
        let mut rng = EntropyRng::new(p);
        assert_eq!(rng.try_next_u32().unwrap_err(), EntropyError::NotReady);
        assert_eq!(rng.try_next_u64().unwrap_err(), EntropyError::NotReady);
        let mut buf = [0u8; 8];
        assert_eq!(
            rng.try_fill_bytes(&mut buf).unwrap_err(),
            EntropyError::NotReady
        );
    }

    // Zero-length fill is a no-op success even before startup (no block
    // is drawn, so the not-ready pipeline is never consulted).
    #[test]
    fn zero_length_fill_is_ok_without_drawing() {
        let p = EntropyPipeline::new(PrngMock::new(), MinEntropy::from_bits(2), alpha20()).unwrap();
        let mut rng = EntropyRng::new(p);
        let mut empty: [u8; 0] = [];
        assert!(rng.try_fill_bytes(&mut empty).is_ok());
    }

    // The tail buffer is actually reused: after a 1-byte draw, the next 31
    // bytes complete the first block before any second block is drawn.
    // Verified by determinism against a single 32-byte read.
    #[test]
    fn partial_block_tail_is_buffered_not_discarded() {
        let mut split = started_rng();
        let mut whole = started_rng();
        let mut one = [0u8; 1];
        let mut rest = [0u8; 31];
        split.try_fill_bytes(&mut one).unwrap();
        split.try_fill_bytes(&mut rest).unwrap();
        let mut whole32 = [0u8; 32];
        whole.try_fill_bytes(&mut whole32).unwrap();
        assert_eq!(one[0], whole32[0]);
        assert_eq!(rest, whole32[1..]);
    }
}
