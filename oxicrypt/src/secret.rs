//! Types that hold secret bytes, and the primitive that zeroes them.
//!
//! Each type zeroes its bytes when dropped and prints only its name from
//! `Debug`. Each parameter set has its own seed and key types, so a value of
//! one set cannot reach another set's call. None implements `Clone`, `Copy`,
//! `PartialEq`, `Eq`, `Hash`, `Display`, `Deref` or `AsRef<[u8]>`: comparison
//! is the library's. Bytes come out only through `as_bytes` and go in only
//! through `from_bytes`.
//!
//! The library writes each secret directly into the storage that will zero
//! it: the owner is constructed zeroed before the call and the library is
//! handed a pointer into it. A failed call drops the owner, which zeroes it.
//!
//! `Drop` zeroes the value's final resting place. Moving a value can leave an
//! unzeroed copy in a dead stack frame or a register; the secret and
//! decapsulation keys and [`Okm`] are boxed so that a move carries a pointer,
//! and for the 32-, 48- and 64-byte types that is a stated limitation. Copies
//! the application makes are the application's.

use core::fmt;
use core::sync::atomic::{Ordering, compiler_fence};

use crate::{
    HKDF_SHA384_PRK_LEN, ML_DSA_44_SECRET_KEY_LEN, ML_DSA_44_SEED_LEN, ML_DSA_65_SECRET_KEY_LEN,
    ML_DSA_65_SEED_LEN, ML_DSA_87_SECRET_KEY_LEN, ML_DSA_87_SEED_LEN,
    ML_KEM_512_DECAPSULATION_KEY_LEN, ML_KEM_512_SEED_LEN, ML_KEM_768_DECAPSULATION_KEY_LEN,
    ML_KEM_768_SEED_LEN, ML_KEM_1024_DECAPSULATION_KEY_LEN, ML_KEM_1024_SEED_LEN,
    ML_KEM_SHARED_SECRET_LEN,
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
    /// A 32-byte ML-KEM shared secret, the same length for every parameter
    /// set.
    SharedSecret,
    ML_KEM_SHARED_SECRET_LEN
);

stack_secret!(
    /// The 32-byte seed `ξ` of ML-DSA-44 key generation (FIPS 204 §6.1),
    /// from [`Module::ml_dsa_44_keygen_with_seed`](crate::Module::ml_dsa_44_keygen_with_seed)
    /// and read by [`Module::ml_dsa_44_expand_key`](crate::Module::ml_dsa_44_expand_key).
    /// It computes the secret key and needs the same protection (FIPS 204
    /// §3.6.3).
    MlDsa44Seed,
    ML_DSA_44_SEED_LEN
);

stack_secret!(
    /// The 32-byte seed `ξ` of ML-DSA-65 key generation (FIPS 204 §6.1),
    /// from [`Module::ml_dsa_65_keygen_with_seed`](crate::Module::ml_dsa_65_keygen_with_seed)
    /// and read by [`Module::ml_dsa_65_expand_key`](crate::Module::ml_dsa_65_expand_key).
    /// It computes the secret key and needs the same protection (FIPS 204
    /// §3.6.3).
    MlDsa65Seed,
    ML_DSA_65_SEED_LEN
);

stack_secret!(
    /// The 32-byte seed `ξ` of ML-DSA-87 key generation (FIPS 204 §6.1),
    /// from [`Module::ml_dsa_87_keygen_with_seed`](crate::Module::ml_dsa_87_keygen_with_seed)
    /// and read by [`Module::ml_dsa_87_expand_key`](crate::Module::ml_dsa_87_expand_key).
    /// It computes the secret key and needs the same protection (FIPS 204
    /// §3.6.3).
    MlDsa87Seed,
    ML_DSA_87_SEED_LEN
);

stack_secret!(
    /// The 64-byte seed `d ‖ z` of ML-KEM-512 key generation (FIPS 203
    /// §6.1): the K-PKE seed `d` in the first 32 bytes, the
    /// implicit-rejection seed `z` in the last 32. From
    /// [`Module::ml_kem_512_keygen_with_seed`](crate::Module::ml_kem_512_keygen_with_seed)
    /// and read by [`Module::ml_kem_512_expand_key`](crate::Module::ml_kem_512_expand_key).
    MlKem512Seed,
    ML_KEM_512_SEED_LEN
);

stack_secret!(
    /// The 64-byte seed `d ‖ z` of ML-KEM-768 key generation (FIPS 203
    /// §6.1): the K-PKE seed `d` in the first 32 bytes, the
    /// implicit-rejection seed `z` in the last 32. From
    /// [`Module::ml_kem_768_keygen_with_seed`](crate::Module::ml_kem_768_keygen_with_seed)
    /// and read by [`Module::ml_kem_768_expand_key`](crate::Module::ml_kem_768_expand_key).
    MlKem768Seed,
    ML_KEM_768_SEED_LEN
);

stack_secret!(
    /// The 64-byte seed `d ‖ z` of ML-KEM-1024 key generation (FIPS 203
    /// §6.1): the K-PKE seed `d` in the first 32 bytes, the
    /// implicit-rejection seed `z` in the last 32. From
    /// [`Module::ml_kem_1024_keygen_with_seed`](crate::Module::ml_kem_1024_keygen_with_seed)
    /// and read by [`Module::ml_kem_1024_expand_key`](crate::Module::ml_kem_1024_expand_key).
    MlKem1024Seed,
    ML_KEM_1024_SEED_LEN
);

boxed_secret!(
    /// An ML-DSA-44 secret key, 2,560 bytes on the heap.
    MlDsa44SecretKey,
    ML_DSA_44_SECRET_KEY_LEN
);

boxed_secret!(
    /// An ML-DSA-65 secret key, 4,032 bytes on the heap.
    MlDsa65SecretKey,
    ML_DSA_65_SECRET_KEY_LEN
);

boxed_secret!(
    /// An ML-DSA-87 secret key, 4,896 bytes on the heap.
    MlDsa87SecretKey,
    ML_DSA_87_SECRET_KEY_LEN
);

boxed_secret!(
    /// An ML-KEM-512 decapsulation key, 1,632 bytes on the heap. Borrowed,
    /// never cloned, to decapsulate many ciphertexts.
    MlKem512DecapsulationKey,
    ML_KEM_512_DECAPSULATION_KEY_LEN
);

boxed_secret!(
    /// An ML-KEM-768 decapsulation key, 2,400 bytes on the heap. Borrowed,
    /// never cloned, to decapsulate many ciphertexts.
    MlKem768DecapsulationKey,
    ML_KEM_768_DECAPSULATION_KEY_LEN
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
