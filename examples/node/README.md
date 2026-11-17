# Node.js

`sha256.js` loads the library with [`koffi`](https://koffi.dev/) from the bundle directory given as its first argument and declares the two functions it calls from their C prototypes in `oxicrypt.h`.

`koffi` was chosen over an N-API addon because it loads a shared library with no compile step: `npm ci` fetches a prebuilt binary for the platform, so a user needs no C compiler, Python or `node-gyp`. The cost is one dependency, pinned with its integrity hashes in `package-lock.json`. An N-API addon would need a C++ toolchain on every machine that installs it.

Run against an extracted bundle:

```bash
DIR=$PWD/oxicrypt-ffi-<version>-<platform>     # the extracted bundle
npm ci
node sha256.js "$DIR"
```

`./run.sh "$DIR"` does the same.

Verified on Linux x86_64 with Node.js 22.23.4, npm 10.9.9 and `koffi` 3.3.8 against the 0.26.1 `linux-x86_64` bundle.
