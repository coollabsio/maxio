# Lessons

- UI screenshots at a fixed viewport: the agent-browser `--viewport` option is ignored here (always 1280x577). Use Playwright from `ui/node_modules/playwright` in a script outside the repo (e.g. `/tmp`) with `newPage({ viewport })`.
- `just e2e` `console-features` currently fails at the version-history step on `main` too (only one version is listed). Compare against `git stash` before you blame a UI change.
- `tests/aws_cli_test.sh` runs `maxio keyring rotate` on the data dir you pass. Run it against a throwaway server (`--data-dir /tmp/...`), never the dev `./data`.
- Real S3 clients without local installs: Docker `amazon/aws-cli`, `rclone/rclone`, `bitnamilegacy/minio-client` (the `minio/mc` image is gone), all with `--network host`. AWS CLI v2 sends `STREAMING-UNSIGNED-PAYLOAD-TRAILER` only over HTTPS: put a TLS proxy (Caddy `--internal-certs`) in front and use `--no-verify-ssl`.
