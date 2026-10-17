// A fixture for the guard sweep in scripts/check-lama-coverage.ts: a macro
// that defines a public function under a name its caller passes, without
// the guard. Each real invocation in `macro_call.rs` must be rejected.

macro_rules! define_keygen {
    (generate = $gen:ident;) => {
        pub fn $gen(input: &[u8]) -> Result<u8, Error> {
            let first = input.first().copied().unwrap_or(0);
            require_self_test_started()?;
            Ok(first)
        }
    };
}
