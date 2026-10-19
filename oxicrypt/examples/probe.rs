//! Initialises the library in one of several shapes and prints each result,
//! one line per initialisation. The crate's control tests run it against
//! modified and unsigned libraries through the loader's environment, which
//! overrides the run-time search path the crate's build gives its own
//! targets.
//!
//! ```text
//! probe init <profile>...              Module::init with each profile in turn
//! probe c-first <profile> <profile>... oxi_init called directly, as a C
//!                                      caller would, then Module::init
//! probe threads <profile> <profile>    Module::init on two threads at once
//! probe services <profile>             Module::init, then is_operational and
//!                                      one AES-256-GCM encryption
//! ```
//!
//! A profile is a C ABI code, or `u<code>` for `Profile::Unknown(code)`.
//! Each line names the requested profile and, on a refusal, the error code,
//! the integrity indicator and whether the library supplied detail text.
//! Exit status 0 when the last initialisation succeeded (for `threads`, when
//! exactly one did), else 1.

#![allow(clippy::print_stdout)]

use std::process::ExitCode;

#[cfg(any(oxicrypt_pinned, oxicrypt_unpinned))]
fn parse(arg: &str) -> Option<oxicrypt::Profile> {
    match arg.strip_prefix('u') {
        Some(code) => code.parse().ok().map(oxicrypt::Profile::Unknown),
        None => arg.parse().ok().map(oxicrypt::Profile::from_code),
    }
}

#[cfg(any(oxicrypt_pinned, oxicrypt_unpinned))]
fn init(profile: oxicrypt::Profile) -> bool {
    init_module(profile).is_some()
}

#[cfg(any(oxicrypt_pinned, oxicrypt_unpinned))]
fn init_module(profile: oxicrypt::Profile) -> Option<oxicrypt::Module> {
    use oxicrypt::Module;
    #[cfg(oxicrypt_pinned)]
    let result = Module::init(profile);
    #[cfg(not(oxicrypt_pinned))]
    let result = Module::init_unpinned(profile);
    match result {
        Ok(module) => {
            println!("init {profile:?}: ok");
            Some(module)
        }
        Err(e) => {
            let detail = match e.detail {
                Ok(Some(_)) => "some",
                Ok(None) => "none",
                Err(_) => "unreadable",
            };
            println!(
                "init {profile:?}: err code={:?} integrity={:?} detail={detail}",
                e.code, e.integrity
            );
            None
        }
    }
}

/// After a successful initialisation: the live operational state, then an
/// AES-256-GCM encryption into a buffer filled with 0xAA, and what the buffer
/// holds after it.
#[cfg(any(oxicrypt_pinned, oxicrypt_unpinned))]
fn services(profile: oxicrypt::Profile) -> bool {
    let Some(module) = init_module(profile) else {
        return false;
    };
    println!("is_operational: {}", module.is_operational());
    let Ok(key) = module.aes256_key(&[7; 32]) else {
        println!("aes256_key: failed");
        return false;
    };
    let mut out = [0xAAu8; 16];
    let result = module.aes256_gcm_encrypt(&key, &[1; 12], b"", &[2; 16], &mut out);
    let held = if out.iter().all(|b| *b == 0) {
        "zeroed"
    } else if out.iter().all(|b| *b == 0xAA) {
        "untouched"
    } else {
        "written"
    };
    println!(
        "encrypt: {} output={held}",
        if result.is_ok() { "ok" } else { "err" }
    );
    if let Err(e) = result {
        println!("encrypt error: {e:?}");
    }
    true
}

/// Initialises with each profile in order; whether the last one succeeded.
#[cfg(any(oxicrypt_pinned, oxicrypt_unpinned))]
fn init_each(profiles: &[oxicrypt::Profile]) -> bool {
    let mut ok = false;
    for profile in profiles {
        ok = init(*profile);
    }
    ok
}

#[cfg(any(oxicrypt_pinned, oxicrypt_unpinned))]
fn main() -> ExitCode {
    unsafe extern "C" {
        fn oxi_init(profile: core::ffi::c_int) -> core::ffi::c_int;
    }

    let args: Vec<String> = std::env::args().skip(1).collect();
    let profiles: Vec<oxicrypt::Profile> = args.iter().skip(1).filter_map(|a| parse(a)).collect();
    let ok = match (args.first().map(String::as_str), profiles.split_first()) {
        (Some("init"), Some(_)) => init_each(&profiles),
        (Some("services"), Some((profile, []))) => services(*profile),
        (Some("c-first"), Some((first, rest))) => {
            let first = first.code();
            // SAFETY: the C ABI's declaration; no pointers.
            let code = unsafe { oxi_init(first) };
            println!("c oxi_init({first}): {code}");
            init_each(rest)
        }
        (Some("threads"), Some((a, [b]))) => {
            let (a, b) = (*a, *b);
            let ta = std::thread::spawn(move || init(a));
            let tb = std::thread::spawn(move || init(b));
            let oks = [ta.join(), tb.join()]
                .into_iter()
                .filter(|r| matches!(r, Ok(true)))
                .count();
            oks == 1
        }
        _ => {
            println!("usage: probe init|c-first|threads|services <profile>...");
            false
        }
    };
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(not(any(oxicrypt_pinned, oxicrypt_unpinned)))]
fn main() -> ExitCode {
    println!("built without a library; set OXICRYPT_LIB_DIR and a fingerprint");
    ExitCode::from(2)
}
