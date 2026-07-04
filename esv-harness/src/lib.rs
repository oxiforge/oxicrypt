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
//! # Registration (slice S2)
//!
//! [`registration`] builds the ESVP §3 entropy-source metadata payload
//! (multi-OE via `numberOfOEs`, the vetted SHA2-256 conditioning entry
//! with its CAVP `validationNumber` as required config — D2) and parses
//! the per-OE registration response. [`preflight`] validates that payload
//! **offline, before any server contact**, against a constraint table
//! transcribed from — and drift-guarded against — the vendored NIST
//! metadata schema (`vendor/entropy-source-metadata-schema.json`,
//! ESV-Server `59e0438`).
//!
//! # Data files (slice S3)
//!
//! [`datafiles`] builds the ESVP §6.1 multipart upload request (the
//! `dataFile` part plus the v1.8-capitalized `DataFileSampleSize` field),
//! drives the processing-status polling state machine over all seven
//! documented statuses (capturing NIST's returned assessment on
//! `Run Successful` — the second maxwell oracle), and enforces the vetted ⇒
//! no-conditioned-bits-upload refusal (ISC-107). The request builder and
//! the status decision function are pure; the polling loop is generic over
//! the transport trait with the injectable sleeper.
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
//! Like ACVTS, ESV submissions are attended. Credentials (the PIV PIN,
//! the TOTP secret) are process-lifetime values supplied interactively at
//! an attended run: the TOTP secret is piped in on **stdin** (see
//! `src/main.rs`), never passed on argv (world-readable via `/proc`, and
//! it lands in shell history) and never read from the environment or a
//! config file. This library computes and validates everything; the live,
//! credentialed run is a separate attended session.

#![forbid(unsafe_code)]

pub mod datafiles;
pub mod login;
pub mod preflight;
pub mod registration;
