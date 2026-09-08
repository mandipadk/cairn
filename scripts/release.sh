#!/usr/bin/env bash
# Build a release of the forge for the machine this runs on, and package it
# the way a release is expected to arrive: one archive holding the binary,
# the licence and the README, beside a SHA256SUMS file that covers it.
# The version comes from the tree (`cairn --version`), so tag first.
#
#   scripts/release.sh                 # writes dist/<version>/
#   S3_ENDPOINT=... S3_BUCKET=... S3_ACCESS_KEY_ID=... S3_SECRET_ACCESS_KEY=... \
#   scripts/release.sh                 # and uploads both files under releases/<version>/
set -euo pipefail
cd "$(dirname "$0")/.."

cargo build --release --quiet --bin cairn
BIN=$(cargo build --release --quiet --bin cairn --message-format=json | python3 -c '
import json, sys
for line in sys.stdin:
    d = json.loads(line)
    if d.get("reason") == "compiler-artifact" and d.get("executable") and d["target"]["name"] == "cairn":
        print(d["executable"])' | tail -1)
version=$("$BIN" --version | awk '{print $2}')
[ -n "$version" ] || { echo "!! the binary reports no version"; exit 1; }
arch=$(uname -m)
os=$(uname -s | tr '[:upper:]' '[:lower:]')
name="cairn-$version-$arch-$os"
out="dist/$version"
mkdir -p "$out"
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
mkdir "$stage/$name"
cp "$BIN" LICENSE README.md "$stage/$name/"
tar -C "$stage" -czf "$out/$name.tar.gz" "$name"
(cd "$out" && { command -v sha256sum >/dev/null && sha256sum "$name.tar.gz" || shasum -a 256 "$name.tar.gz"; } > SHA256SUMS)
echo "release $version:"
ls -l "$out" | awk 'NR>1 {print "  " $5 " " $9}'
cat "$out/SHA256SUMS"

if [ -n "${S3_BUCKET:-}" ]; then
  python3 scripts/upload-s3.py "$out/$name.tar.gz" "releases/$version/$name.tar.gz"
  python3 scripts/upload-s3.py "$out/SHA256SUMS" "releases/$version/SHA256SUMS"
fi
