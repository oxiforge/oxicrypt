// A fixture for the guard sweep in scripts/check-lama-coverage.ts: text the
// sweep's lexer must read correctly. Two invocations and one function are
// real and unguarded, so the sweep must count and reject them; everything
// named `*_phantom_internal` or `commented_guarded_internal` sits in a
// comment or a literal and must not be counted.

/* An outer comment /* with a nested one */ that is still open:
define_keygen! {
    generate = nested_phantom_internal;
}
*/

const PHANTOM: &str = "define_keygen! { generate = string_phantom_internal; }";

const RAW_PHANTOM: &str = r#"define_keygen! { generate = raw_phantom_internal; } "quoted""#;

// pub fn commented_guarded_internal() -> Result<(), Error> {
//     require_self_test_started()?;
//     Ok(())
// }

const SLASHES: &str = "//"; define_keygen! { generate = after_slash_internal; }

define_keygen!(generate = paren_form_internal;);

const QUOTE: char = '"';

pub fn lifetime_internal<'a>(input: &'a [u8]) -> Result<&'a [u8], Error> {
    let rest = input.get(1..).unwrap_or(input);
    require_self_test_started()?;
    Ok(rest)
}
