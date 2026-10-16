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
#
# The checksum file is signed by the release workflow with Sigstore (keyless).
# If cosign is installed the signature is verified too, which authenticates
# the publisher, not just the download. SECRETSCAN_REQUIRE_SIGNATURE=1 makes
# the signature check mandatory.
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

# Signature on SHA256SUMS: issued to this repository's release workflow for a
# v* tag, via GitHub's OIDC issuer.
if command -v cosign >/dev/null 2>&1; then
  fetch "$base/SHA256SUMS.sigstore.json" "$tmp/SHA256SUMS.sigstore.json" || die "download failed: SHA256SUMS.sigstore.json"
  cosign verify-blob "$tmp/SHA256SUMS" --bundle "$tmp/SHA256SUMS.sigstore.json" \
    --certificate-identity-regexp "^https://github.com/$REPO/\.github/workflows/release\.yml@refs/tags/v" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com >/dev/null 2>&1 ||
    die "signature verification of SHA256SUMS failed"
  say "signature verified (release workflow of $REPO)"
elif [ "${SECRETSCAN_REQUIRE_SIGNATURE:-0}" = 1 ]; then
  die "SECRETSCAN_REQUIRE_SIGNATURE=1 but cosign is not installed"
else
  say "note: install cosign to also verify the publisher's signature (see README)"
fi

mkdir -p "$BINDIR"
chmod 0755 "$tmp/$asset"
mv "$tmp/$asset" "$BINDIR/secretscan"
say "installed $("$BINDIR/secretscan" version) to $BINDIR/secretscan"
case ":$PATH:" in *":$BINDIR:"*) ;; *) say "note: $BINDIR is not on your PATH" ;; esac
