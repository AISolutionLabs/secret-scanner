#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Install a secretscan release binary after verifying its SHA-256 checksum.
#
#   curl -fsSL https://raw.githubusercontent.com/AISolutionLabs/secret-scanner/main/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- v1.0.0            # a specific version
#   curl -fsSL .../install.sh | BINDIR=/usr/local/bin sh   # another directory
#
# Nothing is installed if the download or the checksum check fails.
set -eu

REPO="AISolutionLabs/secret-scanner"
VERSION="${1:-${SECRETSCAN_VERSION:-latest}}"
BINDIR="${BINDIR:-$HOME/.local/bin}"

say() { printf 'secretscan-install: %s\n' "$*" >&2; }
die() { say "error: $*"; exit 1; }

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "unsupported OS $(uname -s); on Windows download the .exe from https://github.com/$REPO/releases" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  die "curl or wget is required"
fi
if command -v sha256sum >/dev/null 2>&1; then
  sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
  die "sha256sum or shasum is required to verify the download"
fi

if [ "$VERSION" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  case "$VERSION" in v*) ;; *) VERSION="v$VERSION" ;; esac
  base="https://github.com/$REPO/releases/download/$VERSION"
fi
asset="secretscan-$os-$arch"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
say "downloading $asset ($VERSION)"
fetch "$base/$asset" "$tmp/$asset" || die "download failed: $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"

want="$(awk -v f="$asset" '$2 == f || $2 == "*"f {print $1}' "$tmp/SHA256SUMS")"
[ -n "$want" ] || die "$asset is not listed in SHA256SUMS"
got="$(sha "$tmp/$asset")"
[ "$want" = "$got" ] || die "checksum mismatch for $asset (want $want, got $got)"
say "checksum verified"

mkdir -p "$BINDIR"
chmod 0755 "$tmp/$asset"
mv "$tmp/$asset" "$BINDIR/secretscan"
say "installed $("$BINDIR/secretscan" version) to $BINDIR/secretscan"
case ":$PATH:" in *":$BINDIR:"*) ;; *) say "note: $BINDIR is not on your PATH" ;; esac
