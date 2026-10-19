//! Types that hold secret bytes, and the primitive that zeroes them.
//!
//! Each type zeroes its bytes when dropped and prints only its name from
//! `Debug`. A seed is consumed by the call that uses it, and each seed role
//! has its own type. None implements `Clone`, `Copy`, `PartialEq`, `Eq`, `Hash`,
//! `Display`, `Deref` or `AsRef<[u8]>`: comparison is the library's. Bytes
//! come out only through `as_bytes` and go in only through `from_bytes`.
//!
//! The library writes each secret directly into the storage that will zero
//! it: the owner is constructed zeroed before the call and the library is
//! handed a pointer into it. A failed call drops the owner, which zeroes it.
//!
//! `Drop` zeroes the value's final resting place. Moving a value can leave an
//! unzeroed copy in a dead stack frame or a register; the two large keys and
//! [`Okm`] are boxed so that a move carries a pointer, and for the 32- and
//! 48-byte types that is a stated limitation. Copies the application makes
//! are the application's.

use core::fmt;
use core::sync::atomic::{Ordering, compiler_fence};

use crate::{
    HKDF_SHA384_PRK_LEN, ML_DSA_87_SECRET_KEY_LEN, ML_DSA_87_SEED_LEN,
    ML_KEM_1024_DECAPSULATION_KEY_LEN, ML_KEM_1024_SEED_LEN, ML_KEM_1024_SHARED_SECRET_LEN,
};

/// Writes zero to every byte of `buf` with volatile stores, then a compiler
/// fence, so the stores are not removed as dead.
pub(crate) fn wipe(buf: &mut [u8]) {
    let ptr = buf.as_mut_ptr();
    for i in 0..buf.len() {
        // SAFETY: U8, `i < buf.len()`, so `ptr.add(i)` is inside the
        // exclusively borrowed slice.
        unsafe { core::ptr::write_volatile(ptr.add(i), 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

macro_rules! stack_secret {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        pub struct $name {
            pub(crate) bytes: [u8; $len],
        }

        impl $name {
            /// Takes a copy of `bytes`; the copy is zeroed when this value
            /// is dropped. The caller's array is the caller's to zero.
            #[must_use]
            pub fn from_bytes(bytes: &[u8; $len]) -> Self {
                let mut out = Self::zeroed();
                out.bytes.copy_from_slice(bytes);
                out
            }

            /// The secret bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.bytes
            }

            pub(crate) const fn zeroed() -> Self {
                Self { bytes: [0; $len] }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                wipe(&mut self.bytes);
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

macro_rules! boxed_secret {
    ($(#[$doc:meta])* $name:ident, $len:expr) => {
        $(#[$doc])*
        pub struct $name {
            pub(crate) bytes: Box<[u8; $len]>,
        }

        impl $name {
            /// Takes a copy of `bytes` on the heap; the copy is zeroed when
            /// this value is dropped. The caller's array is the caller's to
            /// zero.
            #[must_use]
            pub fn from_bytes(bytes: &[u8; $len]) -> Self {
                let mut out = Self::zeroed();
                out.bytes.copy_from_slice(bytes);
                out
            }

            /// The secret bytes.
            #[must_use]
            pub fn as_bytes(&self) -> &[u8; $len] {
                &self.bytes
            }

            pub(crate) fn zeroed() -> Self {
                Self { bytes: Box::new([0; $len]) }
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                wipe(&mut self.bytes[..]);
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(stringify!($name))
            }
        }
    };
}

stack_secret!(
    /// A 48-byte HKDF-SHA384 pseudorandom key, from
    /// [`Module::hkdf_sha384_extract`](crate::Module::hkdf_sha384_extract).
    HkdfPrk,
    HKDF_SHA384_PRK_LEN
);

stack_secret!(
    /// A 32-byte ML-KEM-1024 shared secret.
    SharedSecret,
    ML_KEM_1024_SHARED_SECRET_LEN
);

stack_secret!(
    /// The 32-byte seed `ξ` of ML-DSA-87 key generation (FIPS 204 §6.1).
    /// Consumed by [`Module::ml_dsa_87_keygen`](crate::Module::ml_dsa_87_keygen).
    MlDsa87KeySeed,
    ML_DSA_87_SEED_LEN
);

stack_secret!(
    /// The 32-byte seed `d` of ML-KEM-1024 key generation (FIPS 203 §6.1).
    /// Consumed by [`Module::ml_kem_1024_keygen`](crate::Module::ml_kem_1024_keygen).
    MlKem1024KeySeedD,
    ML_KEM_1024_SEED_LEN
);

stack_secret!(
    /// The 32-byte implicit-rejection seed `z` of ML-KEM-1024 key generation
    /// (FIPS 203 §6.1). Consumed by
    /// [`Module::ml_kem_1024_keygen`](crate::Module::ml_kem_1024_keygen).
    MlKem1024KeySeedZ,
    ML_KEM_1024_SEED_LEN
);

stack_secret!(
    /// The 32-byte randomness `m` of one ML-KEM-1024 encapsulation
    /// (FIPS 203 §6.2), which must be fresh for each. Consumed by
    /// [`Module::ml_kem_1024_encapsulate`](crate::Module::ml_kem_1024_encapsulate).
    MlKem1024EncapsSeed,
    ML_KEM_1024_SEED_LEN
);

mod sealed {
    /// Implemented only by this crate's seed types.
    pub trait Sealed {
        fn zeroed_seed() -> Self;
        fn seed_bytes_mut(&mut self) -> &mut [u8; 32];
    }
}

/// A seed type the module's DRBG can fill with
/// [`HmacDrbgSha256::seed`](crate::HmacDrbgSha256::seed): the four seed types
/// of this crate, and no others.
///
/// A seed drawn from the module's DRBG comes from inside the module; a seed
/// passed to `from_bytes` comes from outside it.
pub trait DrbgSeed: sealed::Sealed {}

macro_rules! drbg_seed {
    ($($name:ident),*) => {$(
        impl sealed::Sealed for $name {
            fn zeroed_seed() -> Self {
                Self::zeroed()
            }
            fn seed_bytes_mut(&mut self) -> &mut [u8; 32] {
                &mut self.bytes
            }
        }
        impl DrbgSeed for $name {}
    )*};
}

drbg_seed!(
    MlDsa87KeySeed,
    MlKem1024KeySeedD,
    MlKem1024KeySeedZ,
    MlKem1024EncapsSeed
);

/// A zeroed seed of type `S`, and the 32 bytes the DRBG writes into it.
pub(crate) fn zeroed_seed<S: DrbgSeed>() -> S {
    S::zeroed_seed()
}

pub(crate) fn seed_bytes_mut<S: DrbgSeed>(seed: &mut S) -> &mut [u8; 32] {
    seed.seed_bytes_mut()
}

boxed_secret!(
    /// An ML-DSA-87 secret key, 4,896 bytes on the heap.
    MlDsa87SecretKey,
    ML_DSA_87_SECRET_KEY_LEN
);

boxed_secret!(
    /// An ML-KEM-1024 decapsulation key, 3,168 bytes on the heap. Borrowed,
    /// never cloned, to decapsulate many ciphertexts.
    MlKem1024DecapsulationKey,
    ML_KEM_1024_DECAPSULATION_KEY_LEN
);

/// HKDF-SHA384 output key material of a length chosen at the call, on the
/// heap. From [`Module::hkdf_sha384_expand`](crate::Module::hkdf_sha384_expand).
pub struct Okm {
    pub(crate) bytes: Box<[u8]>,
}

impl Okm {
    /// The secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn zeroed(len: usize) -> Self {
        Self {
            bytes: vec![0; len].into_boxed_slice(),
        }
    }
}

impl Drop for Okm {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl fmt::Debug for Okm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Okm")
    }
}
