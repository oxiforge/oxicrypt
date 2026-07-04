//! oxicrypt ESV harness library.
//!
//! This crate is the library half of the `esv-harness` package: the
//! `src/main.rs` binary is a thin CLI wrapper, while the substance —
//! the ESVP (Entropy Source Validation Protocol) request builders,
//! response parsers, and the login/refresh state machine — lives here
//! so that unit tests can exercise it directly against fixtures without
//! any network contact.
//!
//! # The load-bearing discovery
//!
//! `acvp-harness` already contains the transport ESV needs. ESVP §2
//! authentication is near-identical to ACVP: the same versioned-array
//! envelope, mutual-TLS transport, RFC-6238 TOTP (30-second step,
//! 8 digits, HMAC-SHA-256 via oxicrypt's own HMAC), a 30-minute JWT,
//! and bearer authorization on all non-login endpoints. So esv-harness
//! is mostly *new resources over a proven transport*, not a new
//! transport: it reuses acvp-harness's TOTP generation
//! ([`acvp_harness::transport::totp_now`]), base64 secret decoding
//! ([`acvp_harness::transport::decode_totp_secret`]), access-token
//! extraction ([`acvp_harness::transport::extract_access_token`]),
//! JSON codec ([`acvp_harness::json`]), and the proactive-margin /
//! reactive-retry token-lifecycle decisions
//! ([`acvp_harness::transport::token_needs_refresh`],
//! [`acvp_harness::transport::submit_should_refresh_retry`]).
//!
//! ESV adds exactly one auth mechanism ACVP lacks: **bulk refresh** —
//! a single POST that refreshes an array of per-object JWTs in one TOTP
//! touch, for certify-time freshness (see [`login::bulk_refresh`]).
//!
//! # Protocol sources
//!
//! Endpoint paths, envelope shapes, and TOTP parameters are transcribed
//! from the ESVP protocol digest (`esvp-protocol-digest-2026-06-12.md`)
//! and the NIST reference client (`usnistgov/ESV-Server`,
//! `client/authentication/{login,totp}.py`,
//! `client/jsons/config.demo.json`). The relevant citations appear at
//! each protocol constant in [`login`].
//!
//! # Attended-credential tradition
//!
//! Like ACVTS, ESV submissions are attended: credentials (the PIV PIN,
//! the TOTP secret) never enter this harness's configuration or an AI's
//! context. This library computes and validates everything; the live,
//! credentialed run is a separate attended session.

#![forbid(unsafe_code)]

pub mod login;
