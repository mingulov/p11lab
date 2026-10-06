#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# p11-kit demo, container phase. Runs as the caller's uid inside the demo
# vessel built from Dockerfile.demo. Reads only mounted inputs, writes only
# $WORK. Never prints credentials; retained logs hold no PINs.
set -eu

: "${WORK:?container work directory required}"
: "${P11LAB_NATIVE_ARCHIVE:?mounted native archive required}"
: "${P11LAB_NATIVE_SHA256:?native archive sha256 required}"
: "${P11LAB_PIN_FILE:?mounted user PIN file required}"
: "${P11LAB_SO_PIN_FILE:?mounted SO PIN file required}"
: "${P11LAB_SRC:?mounted p11lab source directory required}"
: "${DEMO_LIB:?mounted lib.sh required}"

# shellcheck source=lib.sh
. "$DEMO_LIB"

TOKEN_LABEL=P11Lab
CLIENT_MODULE=/usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so
KEY_ID=10

log() {
    printf '%s\n' "$*"
}

log "== versions =="
cat /etc/os-release | grep -E '^(PRETTY_NAME|VERSION_ID)=' | tee "$WORK/os-release.txt"
dpkg -l p11-kit opensc openssl python3 2>/dev/null | grep '^ii' | tee "$WORK/dpkg-versions.txt"
test -f "$CLIENT_MODULE" || { echo "missing client module: $CLIENT_MODULE" >&2; exit 1; }

log "== install accepted native SoftHSM runtime (no rebuild) =="
export PYTHONPATH="$P11LAB_SRC"
export P11LAB_PIN_FILE P11LAB_SO_PIN_FILE
python3 -m p11lab install softhsm2 --channel release --platform linux/amd64 \
    --artifact "$P11LAB_NATIVE_ARCHIVE" --sha256 "$P11LAB_NATIVE_SHA256" \
    --prefix "$WORK/prefix" >"$WORK/install.json" 2>"$WORK/install.log"
MODULE=$WORK/prefix/payload/lib/libsofthsm2.so
ADAPTER=$WORK/prefix/payload/bin/p11lab-provider
UTIL=$WORK/prefix/payload/bin/softhsm2-util

log "== init + health (local module) =="
"$ADAPTER" --prefix "$WORK/prefix" --state "$WORK/state" --control "$WORK/control" init >>"$WORK/adapter.log" 2>&1
"$ADAPTER" --prefix "$WORK/prefix" --state "$WORK/state" --control "$WORK/control" health >>"$WORK/adapter.log" 2>&1
export P11LAB_MODULE="$MODULE"
export SOFTHSM2_CONF="$WORK/control/softhsm2.conf"
"$UTIL" --module "$MODULE" --show-slots >"$WORK/slots-local.txt" 2>&1
grep -q "Label: *$TOKEN_LABEL" "$WORK/slots-local.txt" || { echo "token label $TOKEN_LABEL not initialized" >&2; exit 1; }

log "== start p11-kit server on an owned socket =="
own_private_dir "$WORK/xdg"
export XDG_RUNTIME_DIR="$WORK/xdg"
# Redirect to a file, never a pipe: the daemonized server holds stdout open.
timeout 60 p11-kit server --provider "$MODULE" "pkcs11:token=$TOKEN_LABEL" --sh >"$WORK/server-env.sh" 2>"$WORK/server.err"
# shellcheck disable=SC1091
. "$WORK/server-env.sh"
export P11_KIT_SERVER_ADDRESS
case "$P11_KIT_SERVER_ADDRESS" in
    unix:path=/*) ;;
    *) echo "refused: server address is not an absolute unix path: $P11_KIT_SERVER_ADDRESS" >&2; exit 1 ;;
esac
SOCK=${P11_KIT_SERVER_ADDRESS#unix:path=}
FOUND=$(single_socket "$WORK/xdg/p11-kit")
test "$FOUND" = "$SOCK" || { echo "refused: address $SOCK is not the single socket $FOUND" >&2; exit 1; }
assert_owned_socket "$SOCK"
{
    printf 'address=%s\n' "$P11_KIT_SERVER_ADDRESS"
    printf 'pid=%s\n' "$P11_KIT_SERVER_PID"
    stat -c 'socket uid=%u gid=%g mode=%a' "$SOCK"
    stat -c 'parent uid=%u gid=%g mode=%a' "$(dirname "$SOCK")"
} | tee "$WORK/socket.txt"

log "== list slots through the remote route =="
timeout 120 pkcs11-tool --module "$CLIENT_MODULE" -L >"$WORK/slots-remote.txt" 2>&1
grep -q "token label.*: $TOKEN_LABEL" "$WORK/slots-remote.txt" || { echo "remote slot listing missed token $TOKEN_LABEL" >&2; exit 1; }

log "== independent crypto op through the route (RSA keygen + sign) =="
PIN=$(cat "$P11LAB_PIN_FILE")
timeout 120 pkcs11-tool --module "$CLIENT_MODULE" --login --pin "$PIN" \
    --keypairgen --key-type rsa:2048 --id $KEY_ID --label demo-rsa >"$WORK/keygen.txt" 2>&1
printf 'p11-kit demo message' >"$WORK/msg.bin"
timeout 120 pkcs11-tool --module "$CLIENT_MODULE" --login --pin "$PIN" \
    --sign --mechanism SHA256-RSA-PKCS --id $KEY_ID \
    --input-file "$WORK/msg.bin" --output-file "$WORK/sig.bin" >"$WORK/sign.txt" 2>&1
timeout 120 pkcs11-tool --module "$CLIENT_MODULE" --login --pin "$PIN" \
    --read-object --type pubkey --id $KEY_ID --output-file "$WORK/pub.der" >"$WORK/readpub.txt" 2>&1
unset PIN
# pkcs11-tool exports the RSA public key as PKCS#1 DER on this stack.
openssl rsa -RSAPublicKey_in -in "$WORK/pub.der" -inform DER -out "$WORK/pub.pem" 2>"$WORK/openssl-pubkey.log"
openssl dgst -sha256 -verify "$WORK/pub.pem" -signature "$WORK/sig.bin" "$WORK/msg.bin" >"$WORK/verify-ok.txt" 2>&1
grep -q 'Verified OK' "$WORK/verify-ok.txt" || { echo "oracle rejected the route signature" >&2; exit 1; }
printf 'p11-kit demo messagf' >"$WORK/msg-altered.bin"
if openssl dgst -sha256 -verify "$WORK/pub.pem" -signature "$WORK/sig.bin" "$WORK/msg-altered.bin" >"$WORK/verify-altered.txt" 2>&1; then
    echo "oracle accepted an altered message" >&2
    exit 1
fi
grep -q 'Verification failure' "$WORK/verify-altered.txt" || { echo "altered-message oracle gave no verdict" >&2; exit 1; }
log "oracle: original accepted, altered rejected"

log "== stop server, prove socket shutdown =="
kill "$P11_KIT_SERVER_PID"
i=0
while [ $i -lt 10 ] && [ -e "$SOCK" ]; do sleep 1; i=$((i + 1)); done
if [ -e "$SOCK" ]; then
    echo "server socket still present after SIGTERM: $SOCK" >&2
    exit 1
fi
"$ADAPTER" --prefix "$WORK/prefix" --state "$WORK/state" --control "$WORK/control" health >>"$WORK/adapter.log" 2>&1
printf 'P11KIT_DEMO_OK\n' >"$WORK/RESULT"
log "P11KIT_DEMO_OK"
