#!/bin/sh
# Install commit-trust v1.4.3: downloads commit_trust.py from the GitHub release, checks it against the
# SHA-256 below, and installs a `commit-trust` command into $PREFIX/bin (default ~/.local/bin). No sudo.
# Read this script before running it.
set -eu
VERSION="v1.4.3"
SHA256="1dbfd7a5d86e3d6701bc30c19162954f1e836e19d9206dfc11c48c87c4322546"
REPO="seb-lewis/commit-trust"
PREFIX="${PREFIX:-$HOME/.local}"
URL="https://github.com/$REPO/releases/download/$VERSION/commit_trust.py"

need() { command -v "$1" >/dev/null 2>&1 || { echo "commit-trust needs $1" >&2; exit 1; }; }
need python3; need git; need curl
python3 -I -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' || { echo "python3 >= 3.8 required" >&2; exit 1; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$URL" -o "$tmp/commit_trust.py"
if command -v sha256sum >/dev/null 2>&1; then got=$(sha256sum "$tmp/commit_trust.py" | cut -d' ' -f1)
else got=$(shasum -a 256 "$tmp/commit_trust.py" | cut -d' ' -f1); fi
[ "$got" = "$SHA256" ] || { echo "checksum mismatch: expected $SHA256, got $got. Not installing." >&2; exit 1; }

mkdir -p "$PREFIX/lib/commit-trust" "$PREFIX/bin"
cp "$tmp/commit_trust.py" "$PREFIX/lib/commit-trust/commit_trust.py"
chmod 0644 "$PREFIX/lib/commit-trust/commit_trust.py"
printf '#!/bin/sh\nexec python3 -I "%s" "$@"\n' "$PREFIX/lib/commit-trust/commit_trust.py" > "$PREFIX/bin/commit-trust"
chmod 0755 "$PREFIX/bin/commit-trust"
echo "installed commit-trust $VERSION to $PREFIX/bin/commit-trust (sha256 $SHA256)"
case ":$PATH:" in *":$PREFIX/bin:"*) ;; *) echo "note: add $PREFIX/bin to your PATH" ;; esac
