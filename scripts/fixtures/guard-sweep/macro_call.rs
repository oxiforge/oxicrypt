// A fixture for the guard sweep in scripts/check-lama-coverage.ts: one real
// invocation of the unguarded macro in `macro_def.rs`, which the sweep must
// count and reject, and one invocation that exists only in a comment, which
// it must not count:
//
// define_keygen! {
//     generate = commented_keygen_internal;
// }

define_keygen! {
    generate = fixture_keygen_internal;
}
