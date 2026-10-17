// A fixture for the guard sweep in scripts/check-lama-coverage.ts: more text
// the sweep's lexer must read correctly. The functions and invocations below
// are real and unguarded, so the sweep must count and reject them; the
// `*_phantom_internal` names sit in C-string literals and must not count.

pub extern "C" fn abi_internal() -> u8 {
    let byte = 0;
    require_self_test_started()?;
    byte
}

const QUOTES: [char; 2] = ['\'', '"']; define_keygen! { generate = after_escaped_quote_internal; }

const CSTR: &CStr = c"define_keygen! { generate = cstring_phantom_internal; }";

const CRAW: &CStr = cr#"define_keygen! { generate = craw_phantom_internal; } "q""#;

define_keygen ! { generate = spaced_bang_internal; }

pub fn r#raw_ident_internal() -> u8 {
    let byte = 0;
    require_self_test_started()?;
    byte
}

define_keygen! { generate = r#raw_gen_internal; }
