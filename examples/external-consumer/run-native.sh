#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Clean Linux native consumer: fetch the bundle by digest without Docker,
# install it, run an arbitrary application, optionally run the checker at its
# pinned revision, then a deliberate wrong-PIN failure. Docker must be
# absent: this lane proves native acquisition needs none. Debian 13 amd64
# with python3 (venv), gcc with libc headers, openssl, tar, and
# ca-certificates is required; --checker additionally needs git and network
# access to the pinned checker revision. Usage:
#   run-native.sh --bundle-dir DIR --work-dir DIR [--local-proof] [--checker]
set -eu

bundle_dir=""
work_dir=""
local_proof=""
checker=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle-dir) bundle_dir="$2"; shift 2 ;;
    --bundle-dir=*) bundle_dir="${1#--bundle-dir=}"; shift ;;
    --work-dir) work_dir="$2"; shift 2 ;;
    --work-dir=*) work_dir="${1#--work-dir=}"; shift ;;
    --local-proof) local_proof="1"; shift ;;
    --checker) checker="1"; shift ;;
    *) echo "run-native.sh: unexpected argument: $1" >&2; exit 2 ;;
  esac
done
if [ -z "$bundle_dir" ] || [ -z "$work_dir" ]; then
  echo "run-native.sh: --bundle-dir and --work-dir are required" >&2; exit 2
fi
if command -v docker >/dev/null 2>&1; then
  echo "run-native.sh: docker is present; native installation must not need it" >&2; exit 1
fi
for tool in python3 cc openssl sha256sum tar; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "run-native.sh: required tool missing: $tool" >&2; exit 2
  fi
done
if [ -n "$checker" ] && ! command -v git >/dev/null 2>&1; then
  echo "run-native.sh: --checker requires git" >&2; exit 2
fi
if [ -e "$work_dir" ]; then
  echo "run-native.sh: work directory must be fresh: $work_dir" >&2; exit 2
fi
mkdir -p "$work_dir"
CDPATH=""
here="$(cd -- "$(dirname -- "$0")" && pwd)"

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
  echo "run-native.sh: unexpected ORAS tarball roster" >&2; exit 1
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
BINARY_SHA="$("$VENV/python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["binary"]["file_sha256"])' "$work_dir/bindings.json")"
BINARY_PLATFORM="$("$VENV/python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["binary"]["platform"])' "$work_dir/bindings.json")"
echo "environment=$ENVIRONMENT channel=$CHANNEL role=$ROLE verdict=$VERDICT"
echo "binary=$BINARY_REF"
if [ "$ROLE" != "native" ]; then
  echo "run-native.sh: this consumer needs a native handoff" >&2; exit 1
fi
if [ "$VERDICT" != "eligible" ] && [ -z "$local_proof" ]; then
  echo "run-native.sh: handoff admission is not eligible; refusing to run" >&2; exit 1
fi
if [ "$VERDICT" != "eligible" ]; then
  echo "LOCAL-PROOF OVERRIDE: proceeding despite blocked admission:"
  "$VENV/python" -c 'import json,sys; print(json.load(open(sys.argv[1]))["admission"]["blockers"])' "$work_dir/bindings.json"
fi

echo "=== pull the bundle anonymously (no docker) ==="
mkdir -p "$work_dir/anon/home" "$work_dir/pulled" "$work_dir/caller"
printf '{"auths":{}}\n' > "$work_dir/anon/auth.json"
ls -la "$work_dir/anon"
case "$BINARY_REF" in
  localhost*|127.0.0.1*) PLAIN="--plain-http" ;;
  *) PLAIN="" ;;
esac
if [ -n "$PLAIN" ]; then
  env -i "PATH=/usr/bin:/bin" "HOME=$work_dir/anon/home" \
    "$ORAS" pull --registry-config "$work_dir/anon/auth.json" --no-tty \
    --plain-http -o "$work_dir/pulled" "$BINARY_REF"
else
  env -i "PATH=/usr/bin:/bin" "HOME=$work_dir/anon/home" \
    "$ORAS" pull --registry-config "$work_dir/anon/auth.json" --no-tty \
    -o "$work_dir/pulled" "$BINARY_REF"
fi
ls -la "$work_dir/pulled"
PULLED_SHA="$(sha256sum "$work_dir"/pulled/*.tar.gz)"; PULLED_SHA="${PULLED_SHA%% *}"
test "$PULLED_SHA" = "$BINARY_SHA"

echo "=== install the bundle ==="
"$VENV/python" -m p11lab install "$ENVIRONMENT" --channel "$CHANNEL" --platform "$BINARY_PLATFORM" \
  --artifact "$work_dir"/pulled/*.tar.gz --sha256 "$BINARY_SHA" --prefix "$work_dir/prefix"

echo "=== build the caller smoke tool from the installed package ==="
mkdir -p "$work_dir/tools" "$work_dir/tools-src"
"$VENV/python" -c '
import sys
from p11lab.catalog import package_data
from pathlib import Path
out = Path(sys.argv[1])
(out / "vendor").mkdir(exist_ok=True)
for name in ("smoke.c", "p256.c", "p256.h", "verify.py"):
    (out / name).write_bytes(package_data("consumer/" + name).read_bytes())
(out / "vendor" / "pkcs11.h").write_bytes(package_data("consumer/vendor/pkcs11.h").read_bytes())
' "$work_dir/tools-src"
cc -std=c11 -O2 -Wall -Wextra -Werror -pedantic "$work_dir/tools-src/smoke.c" "$work_dir/tools-src/p256.c" -ldl -o "$work_dir/tools/p11lab-smoke"
cp "$work_dir/tools-src/verify.py" "$work_dir/verify.py"

echo "=== arbitrary application with real crypto ==="
printf '1234' > "$work_dir/pin"
printf '12345678' > "$work_dir/so-pin"
printf '9999' > "$work_dir/wrong-pin"
chmod 600 "$work_dir/pin" "$work_dir/so-pin" "$work_dir/wrong-pin"
"$VENV/python" -m p11lab run "$ENVIRONMENT" --channel "$CHANNEL" --mode native \
  --installed-prefix "$work_dir/prefix" --cwd "$work_dir/caller" \
  --input "P11LAB_PIN_FILE=$work_dir/pin" --input "P11LAB_SO_PIN_FILE=$work_dir/so-pin" \
  --output-dir "$work_dir/app-run" --timeout 600 -- \
  "$VENV/python" "$here/consumer-app.py" "$work_dir/tools/p11lab-smoke"
"$VENV/python" "$work_dir/verify.py" "$work_dir/app-run/crypto" --openssl "$(command -v openssl)"

if [ -n "$checker" ]; then
  echo "=== optional checker at the pinned revision ==="
  git init -q "$work_dir/checker-src"
  git -C "$work_dir/checker-src" config core.autocrlf false
  git -C "$work_dir/checker-src" fetch -q --depth 1 https://github.com/mingulov/pkcs11-check.git de4db3d2ee738a9f99d0654e4baf568cdbd4774a
  git -C "$work_dir/checker-src" checkout -q FETCH_HEAD
  test "$(git -C "$work_dir/checker-src" rev-parse HEAD)" = "de4db3d2ee738a9f99d0654e4baf568cdbd4774a"
  "$VENV/pip" install --quiet "$work_dir/checker-src"
  "$VENV/pip" freeze | sort | tee "$work_dir/checker-pip-freeze.txt"
  "$VENV/python" -c "import importlib.metadata; assert importlib.metadata.version('pkcs11-check') == '0.2.2'"
  "$VENV/python" -m p11lab run "$ENVIRONMENT" --channel "$CHANNEL" --mode native \
    --installed-prefix "$work_dir/prefix" --cwd "$work_dir/caller" \
    --input "P11LAB_PIN_FILE=$work_dir/pin" --input "P11LAB_SO_PIN_FILE=$work_dir/so-pin" \
    --output-dir "$work_dir/checker-run" --timeout 1500 -- \
    "$VENV/python" "$here/checker-driver.py"
  "$VENV/python" -c '
import json, sys
results = json.load(open(sys.argv[1]))
summary = results.get("summary", results)
print("checker results:", json.dumps(summary)[:400])
' "$work_dir/checker-run/checker/results.json"
fi

echo "=== deliberate wrong-PIN startup failure ==="
mkdir -p "$work_dir/persist-state"
"$VENV/python" -m p11lab run "$ENVIRONMENT" --channel "$CHANNEL" --mode native \
  --installed-prefix "$work_dir/prefix" --cwd "$work_dir/caller" \
  --input "P11LAB_PIN_FILE=$work_dir/pin" --input "P11LAB_SO_PIN_FILE=$work_dir/so-pin" \
  --state-dir "$work_dir/persist-state" \
  --output-dir "$work_dir/provision-run" --timeout 600 -- \
  "$VENV/python" "$here/consumer-app.py" "$work_dir/tools/p11lab-smoke"
set +e
"$VENV/python" -m p11lab run "$ENVIRONMENT" --channel "$CHANNEL" --mode native \
  --installed-prefix "$work_dir/prefix" --cwd "$work_dir/caller" \
  --input "P11LAB_PIN_FILE=$work_dir/wrong-pin" --input "P11LAB_SO_PIN_FILE=$work_dir/so-pin" \
  --state-dir "$work_dir/persist-state" \
  --output-dir "$work_dir/negative-run" --timeout 600 -- \
  "$VENV/python" "$here/consumer-app.py" "$work_dir/tools/p11lab-smoke"
code=$?
set -e
if [ "$code" -eq 0 ]; then
  echo "run-native.sh: wrong-PIN run unexpectedly succeeded" >&2; exit 1
fi
"$VENV/python" -c '
import json, sys
record = json.load(open(sys.argv[1]))
assert record["exit_code"] != 0, "failure receipt claims success"
print("failure preserved: exit", record["exit_code"], "app", record["app_returncode"])
' "$work_dir/negative-run/receipt.json"

echo "=== consumer evidence ==="
echo "handoff:  $(sha256sum "$HANDOFF" | cut -d' ' -f1)"
echo "bundle:   $BINARY_SHA"
echo "receipts: $work_dir/app-run/receipt.json $work_dir/negative-run/receipt.json"
