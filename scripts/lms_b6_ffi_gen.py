#!/usr/bin/env python3
"""B6 one-shot: emit 240 oxi_lms_<family>_m<N>_h<H>_w<W>_{keygen,sign,verify}
C-ABI fn definitions for `crates/oxicrypt-ffi/src/lib.rs`.

Per-pair byte counts derived from RFC 8554 §4.1 + RFC 8708 §3.1/§4.1:
- PUBLIC_KEY_LEN  = 24 + N        (4 LMS_TYPE + 4 LMOTS_TYPE + 16 I + N root)
- PRIVATE_KEY_LEN = 20 + N        (N seed + 16 I + 4 leaf_index)
- OTS_SIG_LEN     = 4 + N + P*N
- SIGNATURE_LEN   = 4 + OTS_SIG_LEN + 4 + H*N

The generator emits raw Rust source referencing per-pair module
constants (`oxicrypt_lms::lms_<…>::SIGNATURE_LEN`) rather than
hand-typed numeric literals; per-fn rustdoc carries the explicit
byte counts so the values remain reviewer-visible at the source
boundary (the R71 CMVP gem).

Modes:
  python lms_b6_ffi_gen.py emit         # 240 fn definitions (stdout)
  python lms_b6_ffi_gen.py preview      # show byte counts for one pair
"""
from __future__ import annotations

import sys

FAMILY_ORDER = [
    ("sha256", 32, "Sha256N32", "SHA-256", "M=32", "RFC 8554 §A.1+§A.2"),
    ("sha256", 24, "Sha256N24", "SHA-256", "M=24", "RFC 8708 §4.1"),
    ("shake", 32, "Shake256N32", "SHAKE-256", "M=32", "RFC 8708 §3.1"),
    ("shake", 24, "Shake256N24", "SHAKE-256", "M=24", "RFC 8708 §4.2"),
]
HEIGHTS = [5, 10, 15, 20, 25]
WINTERNITZ = [1, 2, 4, 8]

UV_TABLE = {
    (32, 1): (256, 9, 265, 7),
    (32, 2): (128, 5, 133, 6),
    (32, 4): (64, 3, 67, 4),
    (32, 8): (32, 2, 34, 0),
    (24, 1): (192, 8, 200, 8),
    (24, 2): (96, 5, 101, 6),
    (24, 4): (48, 3, 51, 4),
    (24, 8): (24, 2, 26, 0),
}


def lengths(n: int, w: int, h: int):
    u, v, p, _ls = UV_TABLE[(n, w)]
    pub = 24 + n
    priv = 20 + n
    ots_sig = 4 + n + p * n
    sig = 4 + ots_sig + 4 + h * n
    return pub, priv, sig


def pairs():
    for family, m, _adapter, hash_human, m_tag, spec in FAMILY_ORDER:
        for h in HEIGHTS:
            for w in WINTERNITZ:
                file_stem = f"lms_{family}_m{m}_h{h}_w{w}"
                pub, priv, sig = lengths(m, w, h)
                yield {
                    "module": file_stem,
                    "fn_name_base": f"oxi_{file_stem}",
                    "family": family,
                    "m": m,
                    "h": h,
                    "w": w,
                    "hash_human": hash_human,
                    "m_tag": m_tag,
                    "spec": spec,
                    "pub_len": pub,
                    "priv_len": priv,
                    "sig_len": sig,
                }


def emit_fn_keygen(p):
    return f"""\
/// Generate an LMS key pair for {p['hash_human']} {p['m_tag']} H={p['h']} W={p['w']}.
///
/// Reads 32 bytes from `xi_ptr`, writes a {p['priv_len']}-byte opaque
/// private-key blob into `sk_out` and a {p['pub_len']}-byte public key
/// into `pk_out`. Spec: {p['spec']}. See [`oxi_lms_keygen`] for the
/// LMS-family contract (deterministic derivation from `xi`,
/// persistence-of-record format, profile gating).
///
/// # Safety
///
/// `xi_ptr` must be valid for 32 bytes. `sk_out` must be a non-NULL
/// writable pointer to ≥{p['priv_len']} bytes. `pk_out` must be a
/// non-NULL writable pointer to ≥{p['pub_len']} bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn {p['fn_name_base']}_keygen(
    xi_ptr: *const u8,
    sk_out: *mut u8,
    pk_out: *mut u8,
) -> c_int {{
    let xi_slice = match unsafe {{ slice_from_raw(xi_ptr, 32) }} {{
        Ok(s) => s,
        Err(e) => return e,
    }};
    if sk_out.is_null() || pk_out.is_null() {{
        return R::NullPointer as c_int;
    }}
    let Ok(xi) = <&[u8; 32]>::try_from(xi_slice) else {{
        return R::Internal as c_int;
    }};
    let (sk, pk) = match oxicrypt_lms::{p['module']}::keygen(xi) {{
        Ok(pair) => pair,
        Err(e) => return R::from(e) as c_int,
    }};
    let sk_bytes = sk.to_bytes();
    unsafe {{
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::{p['module']}::PRIVATE_KEY_LEN,
        );
    }};
    unsafe {{
        core::ptr::copy_nonoverlapping(
            pk.as_ptr(),
            pk_out,
            oxicrypt_lms::{p['module']}::PUBLIC_KEY_LEN,
        );
    }};
    R::Ok as c_int
}}"""


def emit_fn_sign(p):
    return f"""\
/// Sign a message with the LMS {p['hash_human']} {p['m_tag']} H={p['h']} W={p['w']} variant.
///
/// Reads the {p['priv_len']}-byte opaque private-key blob from
/// `sk_in_ptr`, signs `msg_len` bytes from `msg_ptr`, advances the
/// leaf index, writes the updated blob to `sk_out`, and writes the
/// {p['sig_len']}-byte signature into `sig_out`. Spec: {p['spec']}.
/// See [`oxi_lms_sign`] for the persistence contract (`sk_out` MUST
/// be persisted before using `sig_out`).
///
/// # Safety
///
/// `sk_in_ptr` must be valid for {p['priv_len']} bytes. `msg_ptr`
/// must be valid for `msg_len` bytes (NULL with len=0 permitted).
/// `sk_out` ≥{p['priv_len']} bytes, `sig_out` ≥{p['sig_len']} bytes.
/// `sk_in_ptr` and `sk_out` may alias.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn {p['fn_name_base']}_sign(
    sk_in_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sk_out: *mut u8,
    sig_out: *mut u8,
) -> c_int {{
    let sk_in = match unsafe {{
        slice_from_raw(sk_in_ptr, oxicrypt_lms::{p['module']}::PRIVATE_KEY_LEN)
    }} {{
        Ok(s) => s,
        Err(e) => return e,
    }};
    let msg = match unsafe {{ slice_from_raw(msg_ptr, msg_len) }} {{
        Ok(s) => s,
        Err(e) => return e,
    }};
    if sk_out.is_null() || sig_out.is_null() {{
        return R::NullPointer as c_int;
    }}
    let Some(mut sk) = oxicrypt_lms::{p['module']}::LmsPrivateKey::from_bytes(sk_in) else {{
        return R::InvalidInput as c_int;
    }};
    let sig = match oxicrypt_lms::{p['module']}::sign(&mut sk, msg) {{
        Ok(s) => s,
        Err(oxicrypt_module::Error::InvalidInput) => return R::InvalidInput as c_int,
        Err(e) => return R::from(e) as c_int,
    }};
    let sk_bytes = sk.to_bytes();
    unsafe {{
        core::ptr::copy_nonoverlapping(
            sk_bytes.as_ptr(),
            sk_out,
            oxicrypt_lms::{p['module']}::PRIVATE_KEY_LEN,
        );
    }};
    unsafe {{
        core::ptr::copy_nonoverlapping(
            sig.as_ptr(),
            sig_out,
            oxicrypt_lms::{p['module']}::SIGNATURE_LEN,
        );
    }};
    R::Ok as c_int
}}"""


def emit_fn_verify(p):
    return f"""\
/// Verify an LMS signature for the {p['hash_human']} {p['m_tag']} H={p['h']} W={p['w']} variant.
///
/// Reads {p['pub_len']}-byte pk, `msg_len`-byte message, and
/// {p['sig_len']}-byte signature. Returns `TagMismatch=22` on any
/// verification failure (parse / structural / cryptographic — upstream
/// collapses into a single `Err(InvalidInput)`; same convention as
/// every other oxicrypt verify FFI). Spec: {p['spec']}.
///
/// # Safety
///
/// `pk_ptr` must be valid for {p['pub_len']} bytes. `msg_ptr` must
/// be valid for `msg_len` bytes (NULL with len=0 permitted). `sig_ptr`
/// must be valid for {p['sig_len']} bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn {p['fn_name_base']}_verify(
    pk_ptr: *const u8,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
) -> c_int {{
    let pk_slice = match unsafe {{
        slice_from_raw(pk_ptr, oxicrypt_lms::{p['module']}::PUBLIC_KEY_LEN)
    }} {{
        Ok(s) => s,
        Err(e) => return e,
    }};
    let msg = match unsafe {{ slice_from_raw(msg_ptr, msg_len) }} {{
        Ok(s) => s,
        Err(e) => return e,
    }};
    let sig_slice = match unsafe {{
        slice_from_raw(sig_ptr, oxicrypt_lms::{p['module']}::SIGNATURE_LEN)
    }} {{
        Ok(s) => s,
        Err(e) => return e,
    }};
    let Ok(pk) =
        <&[u8; oxicrypt_lms::{p['module']}::PUBLIC_KEY_LEN]>::try_from(pk_slice)
    else {{
        return R::Internal as c_int;
    }};
    let Ok(sig) =
        <&[u8; oxicrypt_lms::{p['module']}::SIGNATURE_LEN]>::try_from(sig_slice)
    else {{
        return R::Internal as c_int;
    }};
    match oxicrypt_lms::{p['module']}::verify(pk, msg, sig) {{
        Ok(()) => R::Ok as c_int,
        Err(oxicrypt_module::Error::InvalidInput) => R::TagMismatch as c_int,
        Err(e) => R::from(e) as c_int,
    }}
}}"""


def emit_block():
    out = []
    prev_family = None
    for p in pairs():
        family_tag = (p["family"], p["m"])
        if family_tag != prev_family:
            out.append("")
            out.append(
                f"// ── {p['hash_human']} / {p['m_tag']} family "
                f"({p['spec']}) — 20 pairs × 3 ops = 60 fns ──"
            )
            prev_family = family_tag
        out.append("")
        out.append(emit_fn_keygen(p))
        out.append("")
        out.append(emit_fn_sign(p))
        out.append("")
        out.append(emit_fn_verify(p))
    return "\n".join(out)


def preview():
    for p in pairs():
        if p["module"] == "lms_sha256_m32_h10_w4":
            print(
                f"module={p['module']} pub={p['pub_len']} "
                f"priv={p['priv_len']} sig={p['sig_len']}"
            )
        if p["module"] == "lms_shake_m24_h5_w1":
            print(
                f"module={p['module']} pub={p['pub_len']} "
                f"priv={p['priv_len']} sig={p['sig_len']}"
            )
        if p["module"] == "lms_sha256_m32_h25_w8":
            print(
                f"module={p['module']} pub={p['pub_len']} "
                f"priv={p['priv_len']} sig={p['sig_len']}"
            )


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "emit":
        print(emit_block())
    elif cmd == "preview":
        preview()
    else:
        print(f"unknown command: {cmd}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
