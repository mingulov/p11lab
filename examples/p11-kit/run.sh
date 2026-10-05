#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# p11-kit demonstration driver (host phase).
#
# Builds the demo vessel, then runs demo-inner.sh inside it with the network
# disabled: one SoftHSM p11-kit server/client Unix-socket route with an owned
# socket, an OpenSC compatible client, and an independent RSA sign/verify
# crypto operation. Reads the reviewed native archive the operator supplies;
# P11Lab rebuilds nothing here.
set -eu

EXAMPLE_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
TAG=p11lab-p11kit-demo:local
REBUILD=0
ARCHIVE=
SHA256=
PIN_FILE=
SO_PIN_FILE=
OUTPUT_DIR=

usage() {
    cat <<'EOF'
usage: run.sh --archive PATH --sha256 HEX --pin-file PATH --so-pin-file PATH --output-dir DIR [--tag NAME] [--rebuild]

  --archive PATH      reviewed SoftHSM native archive (release channel)
  --sha256 HEX        expected SHA256 of that archive (64 lowercase hex)
  --pin-file PATH     existing private user PIN file, no final newline
  --so-pin-file PATH  existing private SO PIN file, no final newline
  --output-dir DIR    fresh directory receiving work state and evidence
  --tag NAME          demo vessel tag (default: p11lab-p11kit-demo:local)
  --rebuild           rebuild the vessel without the docker cache
EOF
}

refuse() {
    echo "refused: $1" >&2
    exit 2
}

while [ $# -gt 0 ]; do
    case "$1" in
        --archive) ARCHIVE=${2:-}; shift 2 ;;
        --sha256) SHA256=${2:-}; shift 2 ;;
        --pin-file) PIN_FILE=${2:-}; shift 2 ;;
        --so-pin-file) SO_PIN_FILE=${2:-}; shift 2 ;;
        --output-dir) OUTPUT_DIR=${2:-}; shift 2 ;;
        --tag) TAG=${2:-}; shift 2 ;;
        --rebuild) REBUILD=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) refuse "unknown argument: $1" ;;
    esac
done

[ -n "$ARCHIVE" ] || refuse "--archive is required"
[ -n "$SHA256" ] || refuse "--sha256 is required"
[ -n "$PIN_FILE" ] || refuse "--pin-file is required"
[ -n "$SO_PIN_FILE" ] || refuse "--so-pin-file is required"
[ -n "$OUTPUT_DIR" ] || refuse "--output-dir is required"
case "$SHA256" in
    *[!0-9a-f]*|"") refuse "--sha256 must be 64 lowercase hex characters" ;;
esac
[ "${#SHA256}" = "64" ] || refuse "--sha256 must be 64 lowercase hex characters"
[ -f "$ARCHIVE" ] || refuse "archive is not a regular file: $ARCHIVE"
[ -s "$ARCHIVE" ] || refuse "archive is empty: $ARCHIVE"
[ -f "$PIN_FILE" ] || refuse "pin file is not a regular file: $PIN_FILE"
[ -s "$PIN_FILE" ] || refuse "pin file is empty: $PIN_FILE"
[ -f "$SO_PIN_FILE" ] || refuse "so pin file is not a regular file: $SO_PIN_FILE"
[ -s "$SO_PIN_FILE" ] || refuse "so pin file is empty: $SO_PIN_FILE"
[ -e "$OUTPUT_DIR" ] && refuse "output dir already exists, pass a fresh path: $OUTPUT_DIR"
command -v docker >/dev/null 2>&1 || refuse "docker is required on PATH"

mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/work"
chmod 700 "$OUTPUT_DIR/work"

# argv, not a string: every path stays one word even with spaces.
set -- --platform linux/amd64 --provenance=false --tag "$TAG" \
    --iidfile "$OUTPUT_DIR/demo-image.id" -f "$EXAMPLE_DIR/Dockerfile.demo"
if [ "$REBUILD" = "1" ]; then
    set -- "$@" --no-cache
fi
docker build "$@" "$EXAMPLE_DIR" >"$OUTPUT_DIR/docker-build.log" 2>&1
IMAGE_ID=$(cat "$OUTPUT_DIR/demo-image.id")
docker image inspect --format '{{.Id}} {{.Size}} {{json .RepoDigests}}' "$IMAGE_ID" >"$OUTPUT_DIR/demo-image-inspect.txt" 2>&1
printf 'vessel image: %s\n' "$IMAGE_ID"

docker run --rm --platform linux/amd64 --network none \
    --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$EXAMPLE_DIR/../../src,dst=/mnt/p11lab-src,readonly" \
    --mount "type=bind,src=$ARCHIVE,dst=/mnt/native/softhsm2-native.tar.gz,readonly" \
    --mount "type=bind,src=$PIN_FILE,dst=/mnt/pin/user-pin,readonly" \
    --mount "type=bind,src=$SO_PIN_FILE,dst=/mnt/pin/so-pin,readonly" \
    --mount "type=bind,src=$EXAMPLE_DIR/demo-inner.sh,dst=/mnt/demo-inner.sh,readonly" \
    --mount "type=bind,src=$EXAMPLE_DIR/lib.sh,dst=/mnt/demo-lib.sh,readonly" \
    --mount "type=bind,src=$OUTPUT_DIR/work,dst=/work" \
    --env WORK=/work \
    --env P11LAB_NATIVE_ARCHIVE=/mnt/native/softhsm2-native.tar.gz \
    --env "P11LAB_NATIVE_SHA256=$SHA256" \
    --env P11LAB_PIN_FILE=/mnt/pin/user-pin \
    --env P11LAB_SO_PIN_FILE=/mnt/pin/so-pin \
    --env P11LAB_SRC=/mnt/p11lab-src \
    --env DEMO_LIB=/mnt/demo-lib.sh \
    "$IMAGE_ID" sh /mnt/demo-inner.sh 2>&1 | tee "$OUTPUT_DIR/demo.log"
# The RESULT file is authoritative, not the pipe status: tee always exits 0.

RESULT=$(cat "$OUTPUT_DIR/work/RESULT" 2>/dev/null || true)
[ "$RESULT" = "P11KIT_DEMO_OK" ] || { echo "demo failed, see $OUTPUT_DIR/demo.log" >&2; exit 1; }
if [ -n "$(ls -A "$OUTPUT_DIR/work/xdg/p11-kit" 2>/dev/null)" ]; then
    echo "server socket directory not shut down: $OUTPUT_DIR/work/xdg/p11-kit" >&2
    exit 1
fi
printf 'P11KIT_DEMO_OK evidence in %s\n' "$OUTPUT_DIR"
