#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Install the pinned ORAS CLI for Linux amd64 with hash verification.
# No Docker required. Pins must match p11lab.publish.ORAS_PIN (parity-tested).
# Usage: install-oras.sh --output-dir DIR
set -eu

ORAS_VERSION=1.3.4
ORAS_REVISION=db9e29505c3059f2b8fde34ae8cae266c5c765e9
ORAS_URL=https://github.com/oras-project/oras/releases/download/v1.3.4/oras_1.3.4_linux_amd64.tar.gz
ORAS_SHA256=f27adb935022d94df8dc77719c322dda592c78a0d57a6f7dcdd8d900b248c454
ORAS_SIZE=4679642

output_dir=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output-dir) output_dir="$2"; shift 2 ;;
    --output-dir=*) output_dir="${1#--output-dir=}"; shift ;;
    *) echo "install-oras.sh: unexpected argument: $1" >&2; exit 2 ;;
  esac
done
if [ -z "$output_dir" ]; then
  echo "install-oras.sh: --output-dir is required" >&2; exit 2
fi
if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "install-oras.sh: this installer covers Linux amd64 only" >&2; exit 2
fi
for tool in curl tar sha256sum; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "install-oras.sh: required tool missing: $tool" >&2; exit 2
  fi
done

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
archive="$work/oras.tar.gz"
curl --fail --silent --show-error --location --proto '=https' --retry 3 --output "$archive" "$ORAS_URL"
size="$(wc -c < "$archive")"
if [ "$size" != "$ORAS_SIZE" ]; then
  echo "install-oras.sh: size mismatch: got $size want $ORAS_SIZE" >&2; exit 1
fi
digest="$(sha256sum "$archive")"
digest="${digest%% *}"
if [ "$digest" != "$ORAS_SHA256" ]; then
  echo "install-oras.sh: checksum mismatch: got $digest" >&2; exit 1
fi
roster="$(tar -tzf "$archive" | LC_ALL=C sort)"
if [ "$roster" != "LICENSE
oras" ]; then
  echo "install-oras.sh: unexpected archive roster" >&2; exit 1
fi
tar -xzf "$archive" -C "$work"
chmod 755 "$work/oras"
report="$("$work/oras" version)"
case "$report" in
  *"Version:"*"$ORAS_VERSION"*) ;;
  *) echo "install-oras.sh: version self-report mismatch" >&2; exit 1 ;;
esac
case "$report" in
  *"commit:"*"$ORAS_REVISION"*) ;;
  *) echo "install-oras.sh: commit self-report mismatch" >&2; exit 1 ;;
esac
mkdir -p "$output_dir"
cp "$work/oras" "$output_dir/oras"
cp "$work/LICENSE" "$output_dir/ORAS-LICENSE"
chmod 755 "$output_dir/oras"
echo "$output_dir/oras"
