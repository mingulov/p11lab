#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Clean Linux container consumer: run an arbitrary application, then a
# deliberate wrong-PIN failure, from a handoff bundle only. Needs Docker,
# python3 (venv), openssl, tar. Usage:
#   run-container.sh --bundle-dir DIR --work-dir DIR [--local-proof]
# --local-proof acknowledges a blocked admission verdict for local mechanics
# proof; without it a non-eligible handoff is refused.
set -eu

bundle_dir=""
work_dir=""
local_proof=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle-dir) bundle_dir="$2"; shift 2 ;;
    --bundle-dir=*) bundle_dir="${1#--bundle-dir=}"; shift ;;
    --work-dir) work_dir="$2"; shift 2 ;;
    --work-dir=*) work_dir="${1#--work-dir=}"; shift ;;
    --local-proof) local_proof="1"; shift ;;
    *) echo "run-container.sh: unexpected argument: $1" >&2; exit 2 ;;
  esac
done
if [ -z "$bundle_dir" ] || [ -z "$work_dir" ]; then
  echo "run-container.sh: --bundle-dir and --work-dir are required" >&2; exit 2
fi
for tool in python3 docker openssl sha256sum tar; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "run-container.sh: required tool missing: $tool" >&2; exit 2
  fi
done
if [ -e "$work_dir" ]; then
  echo "run-container.sh: work directory must be fresh: $work_dir" >&2; exit 2
fi
mkdir -p "$work_dir"

echo "=== verify the handoff bundle ==="
(cd "$bundle_dir" && sha256sum -c sha256sum.txt)
HANDOFF="$bundle_dir/handoff.json"
WHEEL="$(ls "$bundle_dir"/p11lab-*.whl)"
ORAS_TARBALL="$(ls "$bundle_dir"/oras_*.tar.gz)"
ORAS=""

echo "=== install the pinned p11lab wheel ==="
python3 -m venv "$work_dir/venv"
VENV="$work_dir/venv/bin"
"$VENV/pip" install --no-index --quiet "$WHEEL"
WHEEL_SHA="$(sha256sum "$WHEEL")"; WHEEL_SHA="${WHEEL_SHA%% *}"
"$VENV/python" -c '
import json, sys
handoff = json.load(open(sys.argv[1]))
want = handoff["producer"]["p11lab_wheel_sha256"]
assert sys.argv[2] == want, "wheel digest differs from the handoff producer pin"
print("wheel ok:", want)
' "$HANDOFF" "$WHEEL_SHA"

echo "=== verify and unpack the pinned ORAS release tarball ==="
ORAS_SHA="$(sha256sum "$ORAS_TARBALL")"; ORAS_SHA="${ORAS_SHA%% *}"
"$VENV/python" -c '
import sys
from p11lab.publish import ORAS_PIN
want = ORAS_PIN["artifacts"]["linux/amd64"]
assert sys.argv[1] == want["sha256"], "ORAS digest differs from the pin"
print("oras ok:", want["sha256"], ORAS_PIN["version"], ORAS_PIN["source"]["revision"])
' "$ORAS_SHA"
mkdir -p "$work_dir/oras"
ROSTER="$(tar -tzf "$ORAS_TARBALL" | LC_ALL=C sort)"
if [ "$ROSTER" != "LICENSE
oras" ]; then
  echo "run-container.sh: unexpected ORAS tarball roster" >&2; exit 1
fi
tar -xzf "$ORAS_TARBALL" -C "$work_dir/oras"
chmod 755 "$work_dir/oras/oras"
ORAS="$work_dir/oras/oras"
"$ORAS" version | head -4

echo "=== read the handoff bindings ==="
"$VENV/python" -m p11lab publish show-handoff --handoff "$HANDOFF" > "$work_dir/bindings.json"
ENVIRONMENT="$("$VENV/python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["catalogue"]["environment"])' "$work_dir/bindings.json")"
CHANNEL="$("$VENV/python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["catalogue"]["channel"])' "$work_dir/bindings.json")"
ROLE="$("$VENV/python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["catalogue"]["runtime_role"])' "$work_dir/bindings.json")"
VERDICT="$("$VENV/python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["admission"]["status"])' "$work_dir/bindings.json")"
BINARY_REF="$("$VENV/python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["binary"]["reference"])' "$work_dir/bindings.json")"
echo "environment=$ENVIRONMENT channel=$CHANNEL role=$ROLE verdict=$VERDICT"
echo "binary=$BINARY_REF"
if [ "$ROLE" != "runtime" ]; then
  echo "run-container.sh: this consumer needs a runtime handoff" >&2; exit 1
fi
if [ "$VERDICT" != "eligible" ] && [ -z "$local_proof" ]; then
  echo "run-container.sh: handoff admission is not eligible; refusing to run" >&2; exit 1
fi
if [ "$VERDICT" != "eligible" ]; then
  echo "LOCAL-PROOF OVERRIDE: proceeding despite blocked admission:"
  "$VENV/python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["admission"]["blockers"])' "$work_dir/bindings.json"
fi

echo "=== pull the binary anonymously ==="
mkdir -p "$work_dir/docker-config" "$work_dir/caller"
ls -la "$work_dir/docker-config"
DOCKER_CONFIG="$work_dir/docker-config" docker pull "$BINARY_REF"
ENGINE_ID="$(DOCKER_CONFIG="$work_dir/docker-config" docker image inspect --format '{{.Id}}' "$BINARY_REF")"
echo "engine=$ENGINE_ID"
DOCKER_CONFIG="$work_dir/docker-config" docker image inspect --format '{{.Os}}/{{.Architecture}}' "$BINARY_REF"

echo "=== build the consumer derivative from the installed package ==="
if [ "$ENVIRONMENT" != "softhsm2" ]; then
  echo "run-container.sh: consumer derivative is not yet authored for $ENVIRONMENT" >&2; exit 1
fi
"$VENV/python" "$bundle_dir/prepare-consumer.py" --channel "$CHANNEL" --output-dir "$work_dir/consumer-context"
docker tag "$ENGINE_ID" p11lab-local-provider:consumer-parent
test "$(docker image inspect --format '{{.Id}}' p11lab-local-provider:consumer-parent)" = "$ENGINE_ID"
docker build --platform linux/amd64 --provenance=false \
  --build-arg PROVIDER_IMAGE=p11lab-local-provider:consumer-parent \
  --iidfile "$work_dir/consumer-id" "$work_dir/consumer-context"
CONSUMER_ID="$(cat "$work_dir/consumer-id")"
echo "consumer=$CONSUMER_ID"
MODULE="$("$VENV/python" -c 'import sys; from p11lab.catalog import load_environment; print(load_environment(sys.argv[1], sys.argv[2])["module_path"])' "$ENVIRONMENT" "$CHANNEL")"
echo "module=$MODULE"

echo "=== arbitrary application with real crypto ==="
printf '1234' > "$work_dir/pin"
printf '12345678' > "$work_dir/so-pin"
printf '9999' > "$work_dir/wrong-pin"
chmod 600 "$work_dir/pin" "$work_dir/so-pin" "$work_dir/wrong-pin"
"$VENV/python" -m p11lab run "$ENVIRONMENT" --channel "$CHANNEL" --artifact "$CONSUMER_ID" \
  --input "P11LAB_PIN_FILE=$work_dir/pin" --input "P11LAB_SO_PIN_FILE=$work_dir/so-pin" \
  --output-dir "$work_dir/app-run" --cwd "$work_dir/caller" --timeout 600 -- \
  p11lab-smoke --module "$MODULE" \
  --token-label P11Lab --pin-file /run/p11lab-input/P11LAB_PIN_FILE \
  --output /p11lab-output/crypto --key-mode generated
"$VENV/python" -c 'import sys; from p11lab.catalog import package_data; from pathlib import Path; Path(sys.argv[1]).write_bytes(package_data("consumer/verify.py").read_bytes())' "$work_dir/verify.py"
"$VENV/python" "$work_dir/verify.py" "$work_dir/app-run/crypto" --openssl "$(command -v openssl)"

echo "=== deliberate wrong-PIN startup failure ==="
mkdir -p "$work_dir/persist-state"
"$VENV/python" -m p11lab run "$ENVIRONMENT" --channel "$CHANNEL" --artifact "$CONSUMER_ID" \
  --input "P11LAB_PIN_FILE=$work_dir/pin" --input "P11LAB_SO_PIN_FILE=$work_dir/so-pin" \
  --state-dir "$work_dir/persist-state" \
  --output-dir "$work_dir/provision-run" --cwd "$work_dir/caller" --timeout 600 -- \
  p11lab-smoke --module "$MODULE" \
  --token-label P11Lab --pin-file /run/p11lab-input/P11LAB_PIN_FILE \
  --output /p11lab-output/crypto --key-mode generated
set +e
"$VENV/python" -m p11lab run "$ENVIRONMENT" --channel "$CHANNEL" --artifact "$CONSUMER_ID" \
  --input "P11LAB_PIN_FILE=$work_dir/wrong-pin" --input "P11LAB_SO_PIN_FILE=$work_dir/so-pin" \
  --state-dir "$work_dir/persist-state" \
  --output-dir "$work_dir/negative-run" --cwd "$work_dir/caller" --timeout 600 -- \
  p11lab-smoke --module "$MODULE" \
  --token-label P11Lab --pin-file /run/p11lab-input/P11LAB_PIN_FILE \
  --output /p11lab-output/crypto --key-mode generated
code=$?
set -e
if [ "$code" -eq 0 ]; then
  echo "run-container.sh: wrong-PIN run unexpectedly succeeded" >&2; exit 1
fi
"$VENV/python" -c '
import json, sys
record = json.load(open(sys.argv[1]))
assert record["exit_code"] != 0, "failure receipt claims success"
print("failure preserved: exit", record["exit_code"], "app", record["app_returncode"])
' "$work_dir/negative-run/receipt.json"

echo "=== consumer evidence ==="
echo "handoff:  $(sha256sum "$HANDOFF" | cut -d' ' -f1)"
echo "engine:   $ENGINE_ID"
echo "consumer: $CONSUMER_ID"
echo "receipts: $work_dir/app-run/receipt.json $work_dir/negative-run/receipt.json"
