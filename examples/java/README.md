# Java

`Sha256.java` loads the library with the Foreign Function & Memory API from the bundle directory given as its first argument, and calls `oxi_init` and `oxi_sha256` through downcall handles.

The Foreign Function & Memory API was chosen over JNI because it calls the library directly. JNI needs a C shim library compiled for each platform, which a user would have to build and ship beside the bundle. The API is final from Java 22, so the example needs a JDK of 22 or later; under Java 21 it is a preview API with a different surface, and the example does not compile.

Build and run against an extracted bundle:

```bash
DIR=$PWD/oxicrypt-ffi-<version>-<platform>     # the extracted bundle
javac -d build Sha256.java
java --enable-native-access=ALL-UNNAMED -cp build Sha256 "$DIR"
```

`--enable-native-access=ALL-UNNAMED` grants the program the native access the API asks for; without it the JDK prints a warning. `./run.sh "$DIR"` does the same.

Verified on Linux x86_64 with Temurin 25.0.5 against the 0.26.1 `linux-x86_64` bundle, and compiled with `javac --release 22`.
