# Go

`main.go` calls the library through cgo, including `oxicrypt.h` from the bundle. cgo links the library when the program is built, so the bundle directory is given to the build, not to the program: `CGO_CFLAGS` names the header's directory and `CGO_LDFLAGS` the library. On Linux and macOS the build records the bundle directory as the program's run-time search path. On Windows the loader finds `oxicrypt_ffi.dll` through `PATH`.

Build and run against an extracted bundle on Linux or macOS:

```bash
DIR=$PWD/oxicrypt-ffi-<version>-<platform>     # the extracted bundle
CGO_ENABLED=1 CGO_CFLAGS="-I$DIR" CGO_LDFLAGS="-L$DIR -loxicrypt_ffi -Wl,-rpath,$DIR" go build -o sha256 .
./sha256
```

On Windows, with MinGW's `gcc` on `PATH`, `CGO_LDFLAGS` names the DLL itself and `PATH` holds the bundle; `run.sh` does both. `./run.sh "$DIR"` does the same on every platform.

Verified on Linux x86_64 with Go 1.26.11 and GCC 15.2.0 against the 0.26.1 `linux-x86_64` bundle. `go.mod` declares Go 1.24.
