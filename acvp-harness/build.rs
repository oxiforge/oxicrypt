//! Build script for the ACVP harness binary.
//!
//! Stamps the current git commit hash so the `--lama` manifest output
//! can identify the exact build. The LAMA YAML itself is embedded via
//! `include_str!` in `main.rs` (multiline content cannot pass through
//! `cargo:rustc-env`).

fn main() {
    // ── Git commit hash ─────────────────────────────────────────────
    let commit = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=OXICRYPT_COMMIT={commit}");

    // Re-run if the manifest changes (so Cargo knows to rebuild).
    println!("cargo:rerun-if-changed=../docs/llm-api-manifest/llm-api.yaml");
}
