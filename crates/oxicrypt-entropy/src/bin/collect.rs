//! Off-boundary raw-data collection binary.
//!
//! This binary builds ONLY with `--features collection` (it declares
//! `required-features = ["collection"]` in `Cargo.toml`), so it is absent
//! from the default and library build graphs. It is a thin operator
//! front-end: all logic lives in [`oxicrypt_entropy::collection`]. The
//! collector itself ([`oxicrypt_entropy`]'s `RawCollector`) is crate-private
//! and never reachable from here — this binary calls only the single public
//! [`oxicrypt_entropy::collection::run`] entry point.
//!
//! Errors are surfaced to the operator via the process exit code (the tool
//! boundary); the sample/health hot path inside the library never panics.

fn main() {
    use std::io::Write as _;
    let args: std::vec::Vec<std::string::String> = std::env::args().skip(1).collect();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    if let Err(e) = oxicrypt_entropy::collection::run(&args, &mut out) {
        // Tool boundary: surface the error to the operator's stderr and exit
        // non-zero. `writeln!` (not the print_stderr-denied `eprintln!`).
        let stderr = std::io::stderr();
        let mut err = stderr.lock();
        let _ = writeln!(err, "collect: {e}");
        std::process::exit(1);
    }
}
