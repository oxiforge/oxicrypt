/// The C interface's ABI number, returned by `oxi_abi_version`, carried in
/// the library's Linux `SONAME` (`liboxicrypt_ffi.so.<number>`) and macOS
/// install name, and checked against `abi/v<number>.txt` by the abi tests.
///
/// It is independent of the release version. It changes only when the C
/// interface breaks compatibility: a function removed, a parameter or return
/// type changed, or an output size changed. Adding a function does not change
/// it. Included as source by `build.rs` and `lib.rs`, so both read one value.
const OXI_ABI_VERSION: i32 = 1;
