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
//! 8 digits, HMAC-SHA-256 via oxicrypt's own HMAC), a short-lived JWT,
//! and bearer authorization on all non-login endpoints. So esv-harness
//! is mostly *new resources over a proven transport*, not a new
//! transport: it reuses acvp-harness's TOTP generation
//! ([`acvp_harness::transport::totp_now`]), base64 secret decoding
//! ([`acvp_harness::transport::decode_totp_secret`]), the JSON codec
//! ([`acvp_harness::json`]) and [`acvp_harness::transport::HttpResponse`]
//! type, the ACVP-measured proactive-refresh default
//! ([`acvp_harness::transport::TOKEN_REFRESH_MARGIN_SECS`]), and the
//! reactive-retry decision
//! ([`acvp_harness::transport::submit_should_refresh_retry`]).
//!
//! ESV deliberately does **not** reuse two acvp-harness helpers that its
//! hardening pass replaced: the permissive `extract_access_token` (which
//! also accepts a bare `{accessToken}` object) — ESV responses are always
//! the versioned envelope, so [`login::parse_access_token`] is a stricter
//! fail-closed parser — and `token_needs_refresh`, because the ESV session
//! carries a **tunable** refresh margin (defaulting to
//! `TOKEN_REFRESH_MARGIN_SECS`) so it can be aligned to the measured ESV
//! token TTL at the attended smoke.
//!
//! ESV adds exactly one auth mechanism ACVP lacks: **bulk refresh** —
//! a single POST that refreshes an array of per-object JWTs in one TOTP
//! touch, for certify-time freshness (see [`login::bulk_refresh`]).
//!
//! # Registration
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
//! # Data files
//!
//! [`datafiles`] builds the ESVP §6.1 multipart upload request (the
//! `dataFile` part plus the v1.8-capitalized `DataFileSampleSize` field),
//! drives the processing-status polling state machine over all seven
//! documented statuses (capturing NIST's returned assessment on
//! `Run Successful` — the second maxwell oracle), and enforces the vetted ⇒
//! no-conditioned-bits-upload refusal (ISC-107). The request builder and
//! the status decision function are pure; the polling loop is generic over
//! the transport trait with the injectable sleeper, is bounded on both the
//! consecutive not-yet-processed and the total poll counts, tolerates a
//! bounded run of transient transport/parse failures, and takes a token
//! provider so a poll can outlive the JWT TTL. The `Run Successful`
//! assessment carries fractional min-entropy numbers the integer-only
//! [`acvp_harness::json`] codec cannot read, so the status response is
//! parsed by the float-tolerant, raw-token [`jsonlite`] reader (the
//! assessment body itself is still captured verbatim).
//!
//! # Supporting docs, certify, and the session store
//!
//! [`supportdocs`] builds the ESVP §6.2 supporting-document upload (the
//! `sdType` classification, a fail-closed PDF-only content guard, and the
//! multipart request over the shared [`datafiles::serialize_multipart`]
//! encoder). [`certify`] builds the three §7 request bodies — the full
//! submission, the AddOE append, and the UpdatePUD swap — enforcing at
//! construction the exactly-one-EAR / exactly-one-PUD / at-most-one-DCA
//! supporting-document constraints and the required ACVTS `moduleId` +
//! per-assessment `oeId` (typed required-config, no defaults). [`session`]
//! is the per-submission session directory (the `acvp-harness` `SessionDir`
//! philosophy): an append-only JSON-lines event log makes the submission's
//! progress durable **before** each network submit, so a fresh process can
//! reload it and know exactly where the submission stands (registered /
//! files-uploaded / docs-uploaded / certified).
//!
//! # File preflight and exact hmin
//!
//! [`preflight`] gains a second half: [`preflight::preflight_data_file`]
//! validates a **data file on disk** against the ESV wire constraints
//! (exactly 1,000,000 one-byte-per-sample symbols, symbols within the
//! effective `min(bitsPerSample, 8)` width, the mandated 1000×1000 restart
//! layout, and `DataFileSampleSize` consistency) — all **offline**, checked
//! against the module's own SP 800-90B constants so the harness cannot drift
//! from the dataset emitters (`oxicrypt_entropy`). [`hmin`] serializes
//! `hminEstimate` **exactly** from the module's fixed-point min-entropy type
//! ([`oxicrypt_entropy::h::MinEntropy`], 1/256-bit steps) as a finite decimal
//! with pure integer arithmetic — no `f64` on the claim path — round-tripped
//! byte-for-byte through the lossless [`jsonlite`] reader. The registration
//! builder carries an optional exact-hmin path
//! ([`registration::EntropyRegistration::set_hmin_exact`]) that renders that
//! token verbatim on the wire while leaving the `f64` field for the
//! assessment-outcome and preflight-bounds paths.
//!
//! # Protocol sources
//!
//! Endpoint paths, envelope shapes, and TOTP parameters are transcribed
//! from the ESV protocol specification and the NIST reference client
//! (`usnistgov/ESV-Server`,
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

pub mod certify;
pub mod datafiles;
pub mod hmin;
pub mod jsonlite;
pub mod login;
pub mod preflight;
pub mod registration;
pub mod session;
pub mod supportdocs;
