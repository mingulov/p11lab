#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# p11scope demonstration driver (host phase).
#
# Phase 1 (always, unprivileged): fetch the pinned observer bundle, verify
# its hash, and record --version plus doctor/doctor --extra-strict
# preflight. Phase 2 (only with --privileged): run one small own-process
# capture in a disposable privileged vessel and retain the observed
# profile. Tracing stays optional: phase 1 alone is a complete
# observation on hosts without capture privileges.
set -eu

EXAMPLE_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
# shellcheck source=pins.env
. "$EXAMPLE_DIR/pins.env"
# shellcheck source=lib.sh
. "$EXAMPLE_DIR/lib.sh"

TAG=p11lab-p11scope-demo:local
REBUILD=0
PRIVILEGED=0
OUTPUT_DIR=

usage() {
    cat <<'EOF'
usage: run.sh --output-dir DIR [--privileged] [--tag NAME] [--rebuild]

  --output-dir DIR  fresh directory receiving the bundle and evidence
  --privileged      also run the live-capture phase in a disposable
                    privileged container (host PID namespace, root,
                    debugfs/bpffs mounted inside, no network)
  --tag NAME        demo vessel tag (default: p11lab-p11scope-demo:local)
  --rebuild         rebuild the vessel without the docker cache
EOF
}

refuse() {
    echo "refused: $1" >&2
    exit 2
}

# check_doctor_output OUTPUT RC_FILE
# Refuse unless the recorded doctor invocation completed and printed a
# verdict. doctor is a probe, not a gate: rc 0 (clean) and rc 1 (issues
# found) are both honest reports. Anything else — usage error, exec
# failure, signal death — means doctor itself failed. Either way the
# capability-tier line must be present; without it there is no verdict
# to report.
check_doctor_output() {
    _out=$1
    _rc_file=$2
    _rc=$(cat "$_rc_file" 2>/dev/null || true)
    case "$_rc" in
        0|1) ;;
        *) refuse "doctor did not complete (rc ${_rc:-missing}), see $_out and $_rc_file" ;;
    esac
    grep -q -E '^capability tier: ' "$_out" 2>/dev/null || \
        refuse "doctor printed no capability-tier verdict (rc $_rc), see $_out"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --output-dir) OUTPUT_DIR=${2:-}; shift 2 ;;
        --privileged) PRIVILEGED=1; shift ;;
        --tag) TAG=${2:-}; shift 2 ;;
        --rebuild) REBUILD=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) refuse "unknown argument: $1" ;;
    esac
done

[ -n "$OUTPUT_DIR" ] || refuse "--output-dir is required"
[ -e "$OUTPUT_DIR" ] && refuse "output dir already exists, pass a fresh path: $OUTPUT_DIR"
command -v curl >/dev/null 2>&1 || refuse "curl is required on PATH"
command -v sha256sum >/dev/null 2>&1 || refuse "sha256sum is required on PATH"
command -v tar >/dev/null 2>&1 || refuse "tar is required on PATH"
if [ "$PRIVILEGED" = "1" ]; then
    command -v docker >/dev/null 2>&1 || refuse "docker is required for --privileged"
fi

mkdir -p "$OUTPUT_DIR"
chmod 700 "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/work"
chmod 700 "$OUTPUT_DIR/work"
cp "$EXAMPLE_DIR/pins.env" "$OUTPUT_DIR/pins.env"

printf 'fetching %s\n' "$P11SCOPE_BUNDLE_URL"
curl -fSLsS --proto '=https' --retry 3 -o "$OUTPUT_DIR/work/bundle.tar.gz" "$P11SCOPE_BUNDLE_URL"
verify_sha256 "$OUTPUT_DIR/work/bundle.tar.gz" "$P11SCOPE_BUNDLE_SHA256"
printf '%s  bundle.tar.gz\n' "$P11SCOPE_BUNDLE_SHA256" >"$OUTPUT_DIR/work/bundle-sha256.txt"
mkdir -p "$OUTPUT_DIR/work/bundle"
tar -xzf "$OUTPUT_DIR/work/bundle.tar.gz" -C "$OUTPUT_DIR/work/bundle"
P11SCOPE_BIN=$(ls -d "$OUTPUT_DIR"/work/bundle/*/p11scope 2>/dev/null || true)
[ -n "$P11SCOPE_BIN" ] || refuse "bundle holds no p11scope binary"
test "$(printf '%s\n' "$P11SCOPE_BIN" | wc -l)" = "1" || refuse "bundle holds several p11scope binaries"
BUNDLE_TOP=$(dirname "$P11SCOPE_BIN")
test -f "$BUNDLE_TOP/LICENSE" || refuse "bundle carries no LICENSE"
test -f "$BUNDLE_TOP/RELEASE.json" || refuse "bundle carries no RELEASE.json"

set +e
"$P11SCOPE_BIN" --version >"$OUTPUT_DIR/work/version.txt" 2>&1
printf '%s\n' "$?" >"$OUTPUT_DIR/work/version-rc.txt"
set -e
cat "$OUTPUT_DIR/work/version.txt"
VERSION_RC=$(cat "$OUTPUT_DIR/work/version-rc.txt")
[ "$VERSION_RC" = "0" ] || refuse "p11scope --version exited $VERSION_RC, see $OUTPUT_DIR/work/version.txt"
VERSION_LINE=$(head -n 1 "$OUTPUT_DIR/work/version.txt")
[ "$VERSION_LINE" = "p11scope $P11SCOPE_VERSION" ] || \
    refuse "p11scope --version is not 'p11scope $P11SCOPE_VERSION', see $OUTPUT_DIR/work/version.txt"
set +e
"$P11SCOPE_BIN" doctor >"$OUTPUT_DIR/work/doctor.txt" 2>&1
printf '%s\n' "$?" >"$OUTPUT_DIR/work/doctor-rc.txt"
"$P11SCOPE_BIN" doctor --extra-strict >"$OUTPUT_DIR/work/doctor-extra-strict.txt" 2>&1
printf '%s\n' "$?" >"$OUTPUT_DIR/work/doctor-extra-strict-rc.txt"
set -e
check_doctor_output "$OUTPUT_DIR/work/doctor.txt" "$OUTPUT_DIR/work/doctor-rc.txt"
check_doctor_output "$OUTPUT_DIR/work/doctor-extra-strict.txt" "$OUTPUT_DIR/work/doctor-extra-strict-rc.txt"
TIER=$(grep -E '^capability tier:' "$OUTPUT_DIR/work/doctor.txt")
printf '%s\n' "$TIER" | tee "$OUTPUT_DIR/work/tier.txt"
printf 'PHASE1_DONE\n' >"$OUTPUT_DIR/work/PHASE1"

if [ "$PRIVILEGED" != "1" ]; then
    printf 'phase 1 complete (tier: %s); pass --privileged for live capture\n' "$TIER"
    printf 'P11SCOPE_DEMO_OK evidence in %s\n' "$OUTPUT_DIR"
    exit 0
fi

printf '%s\n' 'privileged phase: disposable container, --privileged, host PID namespace,'
printf '%s\n' 'root inside, debugfs/bpffs mounted inside, no network, caller-owned outputs.'

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

docker run --rm --platform linux/amd64 --privileged --pid=host --network none \
    --user 0:0 \
    --mount "type=bind,src=$BUNDLE_TOP,dst=/mnt/p11scope,readonly" \
    --mount "type=bind,src=$EXAMPLE_DIR/demo-inner.sh,dst=/mnt/demo-inner.sh,readonly" \
    --mount "type=bind,src=$EXAMPLE_DIR/lib.sh,dst=/mnt/demo-lib.sh,readonly" \
    --mount "type=bind,src=$OUTPUT_DIR/work,dst=/work" \
    --env WORK=/work \
    --env P11SCOPE_DIR=/mnt/p11scope \
    --env "HOST_UID=$(id -u)" \
    --env "HOST_GID=$(id -g)" \
    --env DEMO_LIB=/mnt/demo-lib.sh \
    "$IMAGE_ID" sh /mnt/demo-inner.sh 2>&1 | tee "$OUTPUT_DIR/phase2.log"
# The RESULT file is authoritative, not the pipe status: tee always exits 0.

RESULT=$(cat "$OUTPUT_DIR/work/RESULT" 2>/dev/null || true)
case "$RESULT" in
    P11SCOPE_DEMO_OK) printf 'P11SCOPE_DEMO_OK evidence in %s\n' "$OUTPUT_DIR" ;;
    P11SCOPE_DEMO_UNSUPPORTED)
        printf 'P11SCOPE_DEMO_UNSUPPORTED evidence in %s (capture unavailable, see unsupported.txt)\n' "$OUTPUT_DIR"
        ;;
    *) echo "demo failed, see $OUTPUT_DIR/phase2.log" >&2; exit 1 ;;
esac
