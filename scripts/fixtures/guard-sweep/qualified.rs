// A fixture for the guard sweep in scripts/check-lama-coverage.ts: a public
// `*_internal` function declared with `pub` on its own line and an `unsafe`
// qualifier, whose body does not open with the guard. The sweep must see it
// and fail on it.

pub
unsafe fn seal_internal(input: &[u8]) -> Result<u8, Error> {
    let first = input.first().copied().unwrap_or(0);
    require_self_test_started()?;
    Ok(first)
}
