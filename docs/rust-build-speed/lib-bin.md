# One library, one thin binary

If `src/main.rs` repeats `mod foo;` for modules that `src/lib.rs` also
declares, Cargo compiles that tree twice.

```rust
// src/main.rs
use myapp::config;
use myapp::server;

fn main() {
    server::run(config::Config::parse());
}
```

Items the binary calls must be `pub`. `pub(crate)` is visible only
inside the library crate.

On MaxIO this cut the cold `cargo build` from 41.44s to 28.36s. The
binary unit fell from 13.9s to about 2s. Incremental rebuilds of a
leaf file fell from 4.55s to 2.77s. Warm `cargo test` fell from 74.41s
to 56.57s because the binary stopped re-running the library's unit
tests.

It does not help if the binary is already a thin wrapper, or if the
only slow units are dependencies.
