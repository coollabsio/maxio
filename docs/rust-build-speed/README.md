# Rust build speed kit

Templates that got faster on MaxIO, a single Cargo package, measured
on one 4 vCPU machine (rustc 1.97.1 unless noted). Each number is the
median of three wall-clock runs. Copy a file only when the condition
matches your crate.

| File | What it saved on MaxIO | When it does not apply |
| --- | --- | --- |
| `profiles.toml` | Cold `cargo build` 46.86s to 40.66s (−6.20s, −13%). Line tables on the package, no debuginfo on dependencies. | Dependency `opt-level = 1` was slower: cold build 69.77s, `cargo check` 44.08s. Leave dependency opt-level at 0. |
| `lib-bin.md` | Cold build 41.44s to 28.36s (−13.08s, −32%) after the binary stopped redeclaring the library modules. Warm `cargo test` 74.41s to 56.57s. | The binary is already `use myapp::...`. |
| `ci-rust-cache.yml` | Restored target: `cargo build` 0.12s. Same tree plus a one-line library edit: 2.84s. Cold build was 28.36s. | You cannot persist `target/` between CI jobs. sccache 0.19 then did 7.46s, but only with incremental compilation off, and it skipped bins and proc-macros. |
| `agent-check.sh` | On the pre-split tree, a library edit ran check, clippy, and the full tests in 87s. A hit of the v1 fingerprint skipped `cargo test` and finished in 0.41s. A UI-only diff was 1.23s and did not run Cargo. One integration-test file was 2.49s median. | You have a real workspace with reverse dependencies. This script maps paths inside one package. A corrupt cache runs the tests. |
| `nightly-opt-in.md` | Nightly cold build 28.19s. Cranelift 25.71s (−8.8%). `-Zthreads=4` 24.59s (−12.8%). | Stable Cargo 1.97 rejects `codegen-backend` in `Cargo.toml`, so these stay command-line opt-ins. |

## Measured and left out

Merging four integration-test binaries into `tests/it` made cold `cargo test` 104.62s to 99.91s and warm `cargo test` 56.57s to 64.72s. `cargo nextest` stayed at 21.5s. The warm `cargo test` regression is why that layout is not a template here.

`cargo nextest` is faster than `cargo test` on this suite (cold 60.66s vs 104.62s, warm 21.51s vs 56.57s, after the thin binary). MaxIO's CI job does not run `cargo test`, so CI was not switched. Use nextest locally when the suite is large and tests do not share a process-wide fixture. These tests use random ports and temp directories. None use a global lock or `serial_test`.

`cargo +nightly udeps --all-targets` reported every direct dependency used. No features were turned off.

Editing a leaf module and editing `validate_bucket_name` took the same time after the thin binary (2.77s vs 2.79s). Splitting modules inside one crate did not change incremental rebuilds; codegen-units already do that.

A workspace spike that moved `src/xml` into `maxio-xml` (`cursor/compile-time-workspace-spike-72a4`) did not help. Cold build 29.34s (29.62, 29.34, 29.18) against 28.36s for the single crate. A leaf edit in the new crate was 3.03s (2.98, 3.03, 3.04) against 2.77s in-crate. A storage edit was 2.94s (4.04, 2.87, 2.94). Cold `cargo test` was 95.14s (95.14, 108.23, 94.78) against 104.62s. The public XML API change still rebuilt the main crate. A split pays off when a leaf crate's rmeta does not change, or when the leaf is large enough that not rebuilding the parent dominates the link.

## Test time

Cargo 1.97's `--timings` report does not separate the linker from codegen. Unit totals below are compile plus link. Run time is a warm `cargo test` (artifacts already fresh) and, separately, warm nextest.

PR #37 state, one `cargo test --timings --no-run`: 49.65s wall. Largest units: bin tests 15.44s, lib tests 15.29s, non-test bin 14.88s, lib 14.73s (frontend 9.95s, codegen 4.78s), integration tests 7.49s, limits 2.54s, virtual_host 2.25s, iam_enforcement 2.02s. Warm `cargo test` median 74.41s. Cold `cargo test` median 121.76s.

Round 2 end state (thin binary, same four integration binaries), one `--no-run`: 40.39s wall. Lib tests 16.03s, lib 15.06s, integration 6.52s, limits 2.90s, iam_enforcement 2.38s, non-test bin 2.25s, bin tests 0.97s, virtual_host 1.95s. Warm `cargo test` median 56.57s. Cold `cargo test` median 104.62s.

Warm nextest, 767 tests across 6 binaries at the PR #37 state, wall 26.67s. Summed test time is higher than the wall because tests run in parallel. Slowest binaries by summed test time: integration 65.4s (274 tests), the binary's copy of the unit tests 12.1s (238), the library unit tests 11.9s (237), limits 4.3s (7). After the thin binary, nextest ran 530 tests in 21.51s and the binary kept a single test. The duplicated storage checks were gone.

Slowest individual tests at the end state, and what they do:

| Test | Time | What it does | Safe speedup |
| --- | ---: | --- | --- |
| `storage::check::tests::truncated_unversioned_sse_sidecar_is_not_served` | 4.86s | Four iterations of temp dirs, a 5 MiB multipart object, SSE, and a filesystem check. No sleep. | A smaller fixture would change what the test proves. Not changed. |
| `test_upload_part_copy_into_sse_s3_dest` | 3.57s | Starts a real server, multipart upload, SSE-S3, disk. | A shared server would couple tests that currently use their own temp dir. Not changed. |
| `test_multipart_sse_s3_parts_encrypted_on_disk` | 3.38s | Same shape: server plus encrypted parts on disk. | Same as above. |
| `tampered_sse_sidecar_size_is_an_issue_and_not_plaintext` | 2.41s | Temp dir, SSE object, check. | Not changed. |
| `external_master_key_check_does_not_rebuild_sse_without_the_key` | 2.36s | Temp dir and keyring. | Not changed. |
| `limits` idle, inflight, and RSS tests | 1.2–1.4s | Bind `127.0.0.1:0`, sleep 200–1200ms, or a 30s sleep that is a timeout the server aborts before. | The short sleeps are the behavior under test. The 30s sleeps are not the elapsed time. Not changed. |

Most integration tests between 0.4s and 0.7s call `start_server` (a real listener and temp dir) for one request. They already run in parallel under nextest. A process-wide shared server would be faster and would make failures harder to attribute. It was not changed.

No test in `tests/` uses `serial_test`, `set_var`, or a fixed port. Nextest's default parallelism matched `cargo test`'s results (every nextest run in this round exited 0).
