# Examples

Each directory holds a minimal program that loads the oxicrypt C library from an extracted release bundle, calls `oxi_init(0)`, computes SHA-256 of `"abc"` with `oxi_sha256` and prints the digest:

```
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
```

If `oxi_init` returns anything other than 0, the program prints the code and exits 1. The library has then failed its power-up self-tests or its integrity test, and refuses every service.

| Directory | Language | Binding |
|---|---|---|
| [`go/`](go/) | Go | cgo against `oxicrypt.h` |
| [`node/`](node/) | Node.js | `koffi` |
| [`java/`](java/) | Java | Foreign Function & Memory API |
| [`csharp/`](csharp/) | C# | P/Invoke (`DllImport`) |

Each directory's `run.sh <bundle-dir>` builds the program if it needs building and runs it against the bundle. The release workflow runs, against every library it ships for a host it can execute on, each example whose toolchain that host has, and fails if a toolchain the host is known to have is missing.
