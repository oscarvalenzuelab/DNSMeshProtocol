#!/usr/bin/env bash
# Update the canonical version across every file that carries it.
#
# Usage:
#   scripts/release/set-version.sh <new-version>
#   scripts/release/set-version.sh 0.2.0
#
# Single source of truth is enforced across two files that the publish
# workflows read back to verify the tag:
#   setup.py           version="..."
#   dmp/__init__.py    __version__ = "..."
#
# The script refuses to run if those files already disagree, so a stale
# merge gets caught before it becomes a tagged release.

set -euo pipefail

NEW="${1:-}"
if [[ -z "$NEW" ]]; then
    echo "usage: $0 <new-version>  (e.g. 0.2.0)" >&2
    exit 2
fi
# Accepts vanilla semver plus prerelease / build suffixes
# (e.g. 1.2.3, 1.2.3-rc1, 1.2.3.dev0).
if [[ ! "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]]; then
    echo "refusing $NEW: not a recognised version shape" >&2
    exit 2
fi

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

OLD_SETUP=$(sed -nE 's/^ *version="([^"]+)",$/\1/p' setup.py | head -n1)
OLD_INIT=$(sed -nE 's/^__version__ = "([^"]+)"$/\1/p' dmp/__init__.py | head -n1)

if [[ -z "$OLD_SETUP" || -z "$OLD_INIT" ]]; then
    echo "couldn't read current version — is the repo layout still correct?" >&2
    echo "  setup.py         = '${OLD_SETUP}'" >&2
    echo "  dmp/__init__.py  = '${OLD_INIT}'" >&2
    exit 1
fi
if [[ "$OLD_SETUP" != "$OLD_INIT" ]]; then
    echo "version drift detected — fix by hand before bumping:" >&2
    echo "  setup.py         = $OLD_SETUP" >&2
    echo "  dmp/__init__.py  = $OLD_INIT" >&2
    exit 1
fi

if [[ "$OLD_SETUP" == "$NEW" ]]; then
    echo "already at $NEW — no change"
    exit 0
fi

# Portable in-place sed (BSD sed on macOS + GNU sed on Linux).
portable_sed() {
    sed -E -i.bak "$2" "$1"
    rm -f "$1.bak"
}
portable_sed setup.py         "s/^( *version=)\"[^\"]+\"(,)$/\1\"$NEW\"\2/"
portable_sed dmp/__init__.py  "s/^(__version__ = )\"[^\"]+\"$/\1\"$NEW\"/"

echo "bumped $OLD_SETUP -> $NEW"
echo "  setup.py"
echo "  dmp/__init__.py"
echo
echo "next:"
echo "  git add setup.py dmp/__init__.py"
echo "  git commit -m \"chore: bump version to $NEW\""
echo "  scripts/release/tag.sh all           # or: image | sdk | cli"
