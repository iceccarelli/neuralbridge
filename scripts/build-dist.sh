#!/usr/bin/env bash
# Build the PyPI distributions and check them. NEVER uploads anything: this is the build-only /
# dry-run path, and it is exactly what the `build` job of .github/workflows/publish-pypi.yml runs.
#
#   scripts/build-dist.sh [--out DIR] [--expect-tag vX.Y.Z]
#
#   --out DIR          where the sdist and wheel are written (default: ./dist-check; must not exist
#                      or must be empty, so a stale file can never be published by mistake)
#   --expect-tag TAG   fail unless TAG (v-prefix optional) equals [project].version in pyproject.toml
#
# Steps: python -m build (sdist + wheel), twine check --strict, one sdist and one wheel present, the
# wheel and sdist name and version agree with pyproject.toml, then a SHA-256 list. Prints no secret
# and reads none.
#
# Needs: pip install build twine
# Exit: 0 built and checked | 1 a check failed | 2 could not run (missing tool, bad argument).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

PYTHON="${PYTHON:-python}"
OUT="dist-check"
EXPECT_TAG=""
die() { echo "FAILED: $*" >&2; exit 1; }
unchecked() { echo "UNCHECKED: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --out)        [ $# -ge 2 ] || unchecked "--out needs a value"; OUT="$2"; shift 2 ;;
    --expect-tag) [ $# -ge 2 ] || unchecked "--expect-tag needs a value"; EXPECT_TAG="$2"; shift 2 ;;
    -h|--help)    sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *)            unchecked "unknown argument: $1" ;;
  esac
done

"$PYTHON" -c 'import build' 2>/dev/null || unchecked "the 'build' package is not installed (pip install build twine)"
"$PYTHON" -c 'import twine' 2>/dev/null || unchecked "the 'twine' package is not installed (pip install build twine)"

if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
  unchecked "$OUT exists and is not empty; refusing to mix old files into a build"
fi

NAME_VERSION="$("$PYTHON" -c 'import tomllib; p = tomllib.load(open("pyproject.toml", "rb"))["project"]; print(p["name"].replace("-", "_").lower(), p["version"])')" \
  || unchecked "cannot read [project] from pyproject.toml"
NAME="${NAME_VERSION% *}"; VERSION="${NAME_VERSION#* }"

if [ -n "$EXPECT_TAG" ]; then
  [ "${EXPECT_TAG#v}" = "$VERSION" ] || die "tag $EXPECT_TAG does not match the pyproject.toml version $VERSION; bump the version or tag the right commit"
fi

echo "== build $NAME $VERSION into $OUT" >&2
LOG="$(mktemp "${TMPDIR:-/tmp}/build-dist.XXXXXX")" || unchecked "no temp file"
if ! "$PYTHON" -m build --outdir "$OUT" . >"$LOG" 2>&1; then
  tail -25 "$LOG" >&2; rm -f "$LOG"; die "python -m build failed"
fi
rm -f "$LOG"

echo "== twine check --strict" >&2
"$PYTHON" -m twine check --strict "$OUT"/* || die "twine check failed"

shopt -s nullglob
wheels=("$OUT"/*.whl); sdists=("$OUT"/*.tar.gz)
[ "${#wheels[@]}" -eq 1 ] || die "expected exactly one wheel in $OUT, found ${#wheels[@]}"
[ "${#sdists[@]}" -eq 1 ] || die "expected exactly one sdist in $OUT, found ${#sdists[@]}"
case "$(basename "${wheels[0]}")" in "${NAME}-${VERSION}-"*.whl) ;; *) die "wheel name ${wheels[0]} does not match ${NAME} ${VERSION}" ;; esac
case "$(basename "${sdists[0]}")" in "${NAME}-${VERSION}.tar.gz") ;; *) die "sdist name ${sdists[0]} does not match ${NAME} ${VERSION}" ;; esac

echo "== sha256" >&2
( cd "$OUT" && sha256sum -- *.whl *.tar.gz )
echo "OK: built and checked ${NAME} ${VERSION}. Nothing was uploaded." >&2
