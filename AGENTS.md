# AI Agents

See [CLAUDE.md](CLAUDE.md) for product, build, and API instructions.

## Agent loop

MaxIO is one Cargo package, `maxio`, not a workspace. Do not invent crate boundaries, and do not split the package as part of a compile-time experiment. `cargo check -p maxio` checks this package. There is no reverse-dependency graph across crates: the binary and the integration tests live in the same package, and they are the dependents of the library.

`scripts/agent-check.sh` is the loop. `just agent-check` runs it against `origin/main`. Pass `--base REF` for another base. `--print-plan` prints the decision and runs nothing.

The script diffs the working tree, including untracked files, against the base and picks targets:

| Changed paths | What runs |
| --- | --- |
| `src/main.rs` only | `cargo check` / `clippy` / `cargo test` for `--bin maxio` |
| Any other `src/**/*.rs` | `--all-targets` (library, binary, and every test). The binary compiles those modules itself, and the integration tests link the library. |
| `tests/<name>.rs` only | `--test <name>` |
| `src/main.rs` and `tests/<name>.rs` | `--bin maxio` and those `--test` targets |
| `Cargo.toml`, `Cargo.lock`, `build.rs`, `rust-toolchain.toml` | `--all-targets` |
| `ui/**` | `bun run lint` and `bun run test` in `ui/`. Cargo is not run. |
| Docs, `scripts/**`, `justfile`, `.github/**` | Nothing |
| Anything else | Full Rust `--all-targets` loop and the UI. An unrecognized path fails open. |

Rust and UI both run when both trees change. Clippy uses `--all-features -- -D warnings`, matching CI. The script does not pass `--offline` or `--locked`.

A library edit does not skip integration tests. Skipping work is only safe when the changed files cannot affect the other targets.

### Crate split

Not part of this loop. Cold `cargo build --timings` on this machine showed the library and the binary as the two largest units, because `src/main.rs` repeats the library's `mod` tree instead of depending on the library. Incremental rebuilds of a leaf module and of `validate_bucket_name` were both a few seconds, so the incremental cache already drops most of a clean library compile. Splitting modules into crates would not shrink the dependency graph that dominates a cold build. The timings and the machine are in the compile-time experiment notes on the dev-profile pull request.
