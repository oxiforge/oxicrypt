//! AES-CMAC per SP 800-38B
//!
//! # Status
//!
//! Phase 1 scaffold. No algorithm code yet. The crate exists so that
//! the workspace, CI, and `fips-module` wiring can be exercised end
//! to end before real implementations land.
#![no_std]
#![forbid(unsafe_code)]

/// Placeholder returning the crate name. Will be removed once real
/// public API is added.
#[doc(hidden)]
pub const fn __phase1_placeholder() -> &'static str {
    "fips_cmac"
}

#[cfg(test)]
mod tests {
    use super::__phase1_placeholder;

    #[test]
    fn placeholder_name_matches_crate() {
        assert_eq!(__phase1_placeholder(), "fips_cmac");
    }
}
