// A fixture for the guard sweep in scripts/check-lama-coverage.ts: one public
// `*_internal` function whose body does not open with the guard. The sweep
// must fail on this directory.

pub fn derive_internal(input: &[u8]) -> Result<u8, Error> {
    let first = input.first().copied().unwrap_or(0);
    require_self_test_started()?;
    Ok(first)
}
