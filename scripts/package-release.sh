#!/usr/bin/env bash
set -euo pipefail

out_dir="${OUT_DIR:-dist}"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

mkdir -p "$out_dir"

echo ">>> cargo build --release"
cargo build --release

os_name="$(uname -s | tr '[:upper:]' '[:lower:]')"
case "$os_name" in
  darwin) os_name="macos" ;;
  linux) os_name="linux" ;;
  mingw*|msys*|cygwin*) os_name="windows" ;;
esac

arch="$(uname -m)"
case "$arch" in
  x86_64|amd64) arch="x64" ;;
  arm64|aarch64) arch="arm64" ;;
esac

binary_name="ciphermesh"
if [[ "$os_name" == "windows" ]]; then
  binary_name="ciphermesh.exe"
fi

source="target/release/$binary_name"
dest="$out_dir/ciphermesh-$os_name-$arch-$binary_name"

cp "$source" "$dest"
echo "Packaged: $dest"
