#!/usr/bin/env bash
# Print the Keep a Changelog section for one version.
# Usage: scripts/release-notes.sh 1.0.0
#        scripts/release-notes.sh v1.0.0
#
# Exits 1 when that version has no heading, or the section has no body.
# An empty ## [Unreleased] is not a substitute for a missing version.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: scripts/release-notes.sh <version>" >&2
    exit 2
fi

version="${1#v}"
root="$(cd "$(dirname "$0")/.." && pwd)"
changelog="$root/CHANGELOG.md"

if [ ! -f "$changelog" ]; then
    echo "missing $changelog" >&2
    exit 1
fi

notes="$(awk -v heading="$version" '
    function section_name(line,   name) {
        name = line
        sub(/^## \[/ , "", name)
        sub(/\].*/, "", name)
        return name
    }
    /^## \[/ {
        if (capture) {
            exit
        }
        if (section_name($0) == heading) {
            capture = 1
            print
            next
        }
    }
    capture { print }
    END {
        if (!capture) {
            exit 1
        }
    }
' "$changelog")" || {
    echo "no changelog section for ${version}" >&2
    exit 1
}

if ! printf '%s\n' "$notes" | awk 'NR > 1 && $0 !~ /^[[:space:]]*$/ { found = 1 } END { exit !found }'; then
    echo "changelog section for ${version} is empty" >&2
    exit 1
fi

printf '%s\n' "$notes"
