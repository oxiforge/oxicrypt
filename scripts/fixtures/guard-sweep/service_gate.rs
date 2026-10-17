// A fixture for the guard sweep in scripts/check-lama-coverage.ts: a public
// `*_internal` function that opens with the service gate rather than the
// SelfTest-admitting guard. A CAST could not call it during SelfTest, so the
// sweep must reject it.

pub fn expand_internal(input: &[u8]) -> Result<u8, Error> {
    require_operational()?;
    Ok(input.first().copied().unwrap_or(0))
}
