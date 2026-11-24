//! A fixed-stream [`Rbg`] for tests, compiled only with the
//! `fault-injection` feature or in this crate's own tests.

use oxicrypt_module::{Rbg, RbgError};

/// An [`Rbg`] that serves a fixed byte string in order.
///
/// A request the remaining bytes cannot serve in full returns
/// [`RbgError::RequestTooLong`] and consumes nothing, so a test that
/// over-draws fails rather than wraps.
#[derive(Clone, Debug)]
pub struct FixedStream {
    bytes: &'static [u8],
    pos: usize,
    strength_bits: u32,
}

impl FixedStream {
    /// A stream serving `bytes`, reporting `strength_bits` as its
    /// security strength.
    #[must_use]
    pub const fn new(bytes: &'static [u8], strength_bits: u32) -> Self {
        Self {
            bytes,
            pos: 0,
            strength_bits,
        }
    }
}

impl Rbg for FixedStream {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RbgError> {
        let served = self.pos.checked_add(out.len()).and_then(|end| {
            let source = self.bytes.get(self.pos..end)?;
            out.copy_from_slice(source);
            self.pos = end;
            Some(())
        });
        served.ok_or_else(|| {
            oxicrypt_zeroize::zeroize(out);
            RbgError::RequestTooLong
        })
    }

    fn strength_bits(&self) -> u32 {
        self.strength_bits
    }
}

#[cfg(test)]
mod tests {
    use oxicrypt_module::{Rbg, RbgError};

    use super::FixedStream;

    #[test]
    fn fixed_stream_serves_in_order_then_refuses() {
        let mut stream = FixedStream::new(&[1, 2, 3, 4, 5], 128);
        assert_eq!(stream.strength_bits(), 128);
        let mut out = [0_u8; 3];
        assert_eq!(stream.fill(&mut out), Ok(()));
        assert_eq!(out, [1, 2, 3]);
        assert_eq!(stream.fill(&mut out), Err(RbgError::RequestTooLong));
        assert_eq!(out, [0; 3]);
        let mut rest = [0_u8; 2];
        assert_eq!(stream.fill(&mut rest), Ok(()));
        assert_eq!(rest, [4, 5]);
    }
}
