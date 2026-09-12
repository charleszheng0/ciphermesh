#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
version="${1:-$(sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | head -n 1)}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "This installer must be built on macOS." >&2
  exit 1
fi

cargo build --release

arch="$(uname -m)"
case "$arch" in
  x86_64) package_arch="x64" ;;
  arm64) package_arch="arm64" ;;
  *) echo "Unsupported macOS architecture: $arch" >&2; exit 1 ;;
esac

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
install -d "$stage/root/usr/local/bin"
install -m 755 target/release/ciphermesh "$stage/root/usr/local/bin/ciphermesh"

if [[ -n "${MACOS_APPLICATION_IDENTITY:-}" ]]; then
  codesign --force --options runtime --timestamp \
    --sign "$MACOS_APPLICATION_IDENTITY" \
    "$stage/root/usr/local/bin/ciphermesh"
fi

mkdir -p dist
output="dist/CipherMesh-${version}-macos-${package_arch}.pkg"
args=(
  --root "$stage/root"
  --identifier io.github.charleszheng0.ciphermesh
  --version "$version"
  --install-location /
)
if [[ -n "${MACOS_INSTALLER_IDENTITY:-}" ]]; then
  args+=(--sign "$MACOS_INSTALLER_IDENTITY")
fi
pkgbuild "${args[@]}" "$output"

if [[ -n "${APPLE_NOTARY_PROFILE:-}" ]]; then
  xcrun notarytool submit "$output" --keychain-profile "$APPLE_NOTARY_PROFILE" --wait
  xcrun stapler staple "$output"
fi

echo "Packaged: $repo_root/$output"
