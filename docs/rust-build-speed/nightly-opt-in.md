# Nightly-only commands

Do not put these in the default `Cargo.toml`. On Cargo 1.97 a
`codegen-backend` profile fails to parse on stable.

Cold `cargo build` on nightly 1.102.0, same machine, incremental on.
Median of three runs:

| Command | Median | Raw |
| --- | ---: | --- |
| `cargo +nightly build --locked` | 28.19s | 28.45, 28.19, 27.75 |
| `RUSTFLAGS="-Z codegen-backend=cranelift" cargo +nightly build --locked` | 25.71s | 25.83, 25.71, 25.34 |
| `RUSTFLAGS="-Zthreads=4" cargo +nightly build --locked` | 24.59s | 24.50, 24.69, 24.59 |

Cranelift needs the `rustc-codegen-cranelift` component. Both are
about 9–13% faster than nightly's default backend on this crate.
Stable 1.97 with the dev profile in `profiles.toml` and the thin
binary was already 28.36s, so neither nightly flag beats that setup
by enough to leave stable.

They do not apply when CI or contributors are pinned to stable.
