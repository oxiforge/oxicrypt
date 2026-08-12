//! The oxicrypt library ships as a family of `oxicrypt-*` crates.
//!
//! This crate holds the `oxicrypt` name and contains no code. There is no
//! single crate that is "oxicrypt" — the module is composed of separate
//! crates so that a consumer links only the algorithms they use, and so that
//! the FIPS module boundary is stated per crate rather than inferred.
//!
//! **Start with [`oxicrypt-module`](https://crates.io/crates/oxicrypt-module).**
//! It initializes the module and runs the power-up self-tests that the
//! algorithm crates require before they will operate.
//!
//! The command-line interface is
//! [`oxicrypt-cli`](https://crates.io/crates/oxicrypt-cli), which installs an
//! `oxi` binary.
//!
//! Prebuilt C libraries — shared and static objects with `oxicrypt.h` — are
//! attached to each [GitHub release](https://github.com/oxiforge/oxicrypt/releases).
//!
//! The full crate list, and what each one provides, is at
//! <https://oxicrypt.dev>.
#![no_std]
