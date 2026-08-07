# oxicrypt

The oxicrypt library ships as a family of `oxicrypt-*` crates. This crate holds the `oxicrypt` name and contains no code.

**Start with [`oxicrypt-module`](https://crates.io/crates/oxicrypt-module)** — it initializes the module and runs the power-up self-tests that every other crate requires before it will operate.

```toml
[dependencies]
oxicrypt-module = "*"
oxicrypt-sha = "*"      # and whichever algorithm crates you need
```

The command-line interface is [`oxicrypt-cli`](https://crates.io/crates/oxicrypt-cli), which installs an `oxi` binary:

```sh
cargo install oxicrypt-cli
```

Prebuilt C libraries — shared and static objects with `oxicrypt.h` — are attached to each [GitHub release](https://github.com/oxiforge/oxicrypt/releases), so consuming the module from C needs no Rust toolchain.

The full crate list is at <https://oxicrypt.dev>.

## Licence

Apache-2.0 OR MIT. The licences grant rights in the code, not in the `oxicrypt`&trade; name.
