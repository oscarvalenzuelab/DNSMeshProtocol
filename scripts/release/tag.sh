#!/usr/bin/env bash
# Create release tag(s) for one or more artifact kinds.
#
# Usage:
#   scripts/release/tag.sh {image|sdk|cli|all} [version]
#
# Tag scheme is one prefix per artifact, each triggering a dedicated
# publish workflow:
#   image-vX.Y.Z  -> publish-image.yml    (Docker Hub)
#   sdk-vX.Y.Z    -> publish-pypi.yml     (PyPI)
#   cli-vX.Y.Z    -> publish-binaries.yml (GitHub Release + PyInstaller)
#
# If <version> is omitted it's read from dmp/__init__.py. The tag
# always points at HEAD — commit your version bump first.
#
# The script only creates local tags. Push them with:
#   git push origin <tag>           # one at a time, safer
#   git push origin --tags          # or all pending tags at once
# so you control when the publish workflows actually fire.

set -euo pipefail

KIND="${1:-}"
VERSION="${2:-}"

case "$KIND" in
    image|sdk|cli|all) ;;
    *)
        echo "usage: $0 {image|sdk|cli|all} [version]" >&2
        exit 2
        ;;
esac

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

if [[ -z "$VERSION" ]]; then
    VERSION=$(sed -nE 's/^__version__ = "([^"]+)"$/\1/p' dmp/__init__.py | head -n1)
    if [[ -z "$VERSION" ]]; then
        echo "couldn't read __version__ from dmp/__init__.py" >&2
        exit 1
    fi
fi

# The publish workflows read setup.py / __init__.py back at the tagged
# commit to verify the version matches — mismatches only show up in CI,
# so catch them here instead.
SRC_INIT=$(sed -nE 's/^__version__ = "([^"]+)"$/\1/p' dmp/__init__.py | head -n1)
SRC_SETUP=$(sed -nE 's/^ *version="([^"]+)",$/\1/p' setup.py | head -n1)
if [[ "$VERSION" != "$SRC_INIT" || "$VERSION" != "$SRC_SETUP" ]]; then
    echo "version mismatch — did you run set-version.sh and commit?" >&2
    echo "  target          = $VERSION" >&2
    echo "  __init__.py     = $SRC_INIT" >&2
    echo "  setup.py        = $SRC_SETUP" >&2
    exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
    echo "working tree is not clean; commit or stash before tagging" >&2
    exit 1
fi

KINDS=()
if [[ "$KIND" == "all" ]]; then
    KINDS=(image sdk cli)
else
    KINDS=("$KIND")
fi

created=()
for k in "${KINDS[@]}"; do
    tag="${k}-v${VERSION}"
    if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
        echo "tag $tag already exists; skipping"
        continue
    fi
    git tag -a "$tag" -m "release: $k v$VERSION"
    created+=("$tag")
    echo "tagged $tag"
done

if [[ ${#created[@]} -eq 0 ]]; then
    echo "no new tags created."
    exit 0
fi

echo
echo "push to trigger the publish workflow(s):"
for t in "${created[@]}"; do
    echo "  git push origin $t"
done
