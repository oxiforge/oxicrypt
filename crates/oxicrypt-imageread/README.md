# oxicrypt-imageread

Kernel-mediated reads of the module's own loaded image, for the pre-operational
software integrity test.

`oxicrypt-integrity` keeps `#![forbid(unsafe_code)]`. On Linux and Android it can:
the loaded image is reachable through `/proc/self/mem` or through the backing
file, so every acquisition is an ordinary positioned file read and a wrong offset
produces a short read rather than undefined behaviour.

Darwin and Windows offer no file-shaped route to a process's own memory. Reading
the image there takes a system call, and a system call takes an `extern`
declaration — so the declarations live here, in a crate that does nothing else.

Both mechanisms are kernel-mediated copies, and that is why they were chosen over
a pointer read. The addresses come from a range table inside the artifact; a
corrupt table can name an address that is not mapped. Dereferencing it would
fault and take the process down — a denial of service triggered by exactly the
malformed input the integrity test exists to detect. `mach_vm_read_overwrite` and
`ReadProcessMemory` return a status instead, so an unreadable range becomes an
error and the module enters its error state.

The crate compiles to a single `NoMechanism` stub on every other target,
including Linux and Android, which need no exception.

## License

See the repository root.
