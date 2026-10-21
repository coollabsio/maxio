#!/usr/bin/env bash
# Re-run the every-file corruption sweep: versioned and unversioned objects,
# single-part and the legacy multipart divergence case, plaintext and SSE-S3.
# Repair must not serve older or corrupt bytes in place of a positively
# verified copy, and must not overwrite an unverifiable archive from an
# unverifiable current object.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo test --lib -- \
    corruption_sweep_versioned_unversioned_and_sse \
    unverifiable_multipart_divergence_is_not_repaired \
    put_stores_content_hash_and_repair_restores_from_it \
    single_file_corruption_never_serves_older_than_newest_intact \
    corrupt_older_version_meta_does_not_replace_current \
    corrupt_sse_sidecar_is_restored_from_the_archive_not_synthesized \
    unversioned_sse_sidecar_is_not_synthesized \
    truncated_unversioned_sse_sidecar_is_not_served \
    truncated_versioned_sse_current_is_restored_when_archive_meta_is_intact \
    versioned_sse_without_archive_meta_is_not_synthesized \
    plain_empty_sidecar_is_rebuilt_without_a_keyring \
    plain_truncated_sidecar_is_rebuilt_even_when_a_keyring_exists \
    external_master_key_check_does_not_rebuild_sse_without_the_key \
    frame_shaped_bytes_are_not_rebuilt_as_plaintext \
    binary_sidecar_does_not_abort_the_check \
    rebuilt_plain_sidecar_keeps_multipart_etag \
    restore_unverifiable_from_archive_replaces_corrupt_current \
    hashed_multipart_etag_is_not_reported_unverifiable \
    -- --test-threads=8
