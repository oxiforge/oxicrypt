# oxicrypt-imageread

Kernel-mediated access to the module's own loaded image, for the pre-operational
software integrity test.

`oxicrypt-integrity` keeps `#![forbid(unsafe_code)]`. Everything the integrity test
needs from the operating system that is not an ordinary file read takes an `extern`
declaration, so the declarations live here, in a crate that does nothing else.

| Interface | Linux, Android | Darwin | Windows |
|---|---|---|---|
| `read_self` | `process_vm_readv` on the calling process | `mach_vm_read_overwrite` | `ReadProcessMemory` |
| `image_path` | `dladdr`, used where `/proc/self/maps` cannot be read | `dladdr` | `GetModuleHandleExW` + `GetModuleFileNameW` |
| `page_size` | `getauxval(AT_PAGESZ)` | not provided | not provided |
| `resolve_symbol` | not provided | `dlopen(RTLD_NOLOAD)` + `dlsym` | `GetModuleHandleExW` + `GetProcAddress` |
| `loaded_image` | not provided | `_dyld_image_count` + `_dyld_get_image_name` + `_dyld_get_image_header` | not provided |
| `range_in_image` | not provided | not provided | `VirtualQuery` |
| `current_thread_id` | `gettid` | `pthread_threadid_np` | `GetCurrentThreadId` |

The memory reads are kernel-mediated copies, and that is why they were chosen over
a pointer read. The addresses come from a table inside the artifact; a corrupt table
can name an address that is not mapped. Dereferencing it would fault and take the
process down, a denial of service triggered by exactly the malformed input the
integrity test exists to detect. Each mechanism returns a status instead, so an
unreadable address becomes an error and the module enters its error state.

On Linux and Android, `process_vm_readv` is the second memory route after
`/proc/self/mem`: it passes the same ptrace access check a process always passes
against itself, so it still works for a non-dumpable process.

Every other target compiles each interface to a `NoMechanism` stub.

## License

See the repository root.
