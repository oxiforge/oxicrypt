//! Build script for the `oxi` CLI binary.
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
    // ...and if HEAD moves. Emitting any `rerun-if-changed` REPLACES cargo's
    // default "rerun when any file in the package changed", so without these
    // the stamp is computed once and then frozen: a later commit rebuilds
    // nothing and the binary reports a commit it was not built from. A stale
    // stamp is worse than an absent one, because the whole reason the spec
    // asks for it is so an agent can trust the manifest matches the code.
    for p in git_head_paths() {
        println!("cargo:rerun-if-changed={p}");
    }
}

/// Paths whose contents change when HEAD moves: `.git/HEAD` itself, and the
/// ref it points at when HEAD is symbolic — the usual case, where committing
/// on a branch leaves `.git/HEAD` untouched and moves only the ref file.
///
/// Returns nothing when there is no git directory, which is the state a
/// published `.crate` builds in; the stamp is then `unknown` and there is
/// nothing to track.
fn git_head_paths() -> Vec<String> {
    let Some(git_dir) = std::process::Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    else {
        return Vec::new();
    };

    let mut paths = vec![format!("{git_dir}/HEAD")];
    if let Some(refname) = std::process::Command::new("git")
        .args(["symbolic-ref", "--quiet", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|r| !r.is_empty())
    {
        // A packed ref leaves no loose file; naming a path that does not exist
        // is harmless to cargo and becomes correct the moment it is unpacked.
        paths.push(format!("{git_dir}/{refname}"));
        paths.push(format!("{git_dir}/packed-refs"));
    }
    paths
}
