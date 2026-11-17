# C#

`Program.cs` declares `oxi_init` and `oxi_sha256` with `DllImport` and registers a `NativeLibrary.SetDllImportResolver` that loads the library from the bundle directory given as the program's first argument, so no search path has to be set.

Build and run against an extracted bundle:

```bash
DIR=$PWD/oxicrypt-ffi-<version>-<platform>     # the extracted bundle
dotnet build -o bin/out
dotnet bin/out/Sha256.dll "$DIR"
```

`dotnet run -- "$DIR"` builds and runs in one step. `./run.sh "$DIR"` runs the same commands with a temporary output directory in place of `bin/out`. The project targets .NET 10 and needs its SDK; `RollForward` set to `Major` lets the program run on a later runtime when .NET 10 is not installed.

Verified on Linux x86_64 with the .NET SDK 10.0.404 against the 0.26.1 `linux-x86_64` bundle.
