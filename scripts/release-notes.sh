#!/usr/bin/env bash
# Print the Keep a Changelog section for one version.
# Usage: scripts/release-notes.sh 1.0.0
#        scripts/release-notes.sh v1.0.0
#
# Prefers "## [1.0.0]". If that heading is absent, prints "## [Unreleased]"
# with the heading rewritten to the requested version so a first tag still
# gets notes. Exits 1 when neither section exists.
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

extract() {
    local heading="$1"
    local replace_heading="${2:-}"
    awk -v heading="$heading" -v replace="$replace_heading" '
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
                if (replace != "") {
                    print replace
                } else {
                    print
                }
                next
            }
        }
        capture { print }
        END {
            if (!capture) {
                exit 1
            }
        }
    ' "$changelog"
}

if notes="$(extract "$version")"; then
    printf '%s\n' "$notes"
    exit 0
fi

if notes="$(extract "Unreleased" "## [${version}]")"; then
    printf '%s\n' "$notes"
    exit 0
fi

echo "no changelog section for ${version} or Unreleased" >&2
exit 1
