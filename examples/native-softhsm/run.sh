#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Supply verified PREFIX, separate STATE/CONTROL, private PIN_FILE/SO_PIN_FILE.
set -eu
: "${PREFIX:?verified installed prefix required}"
: "${STATE:?separate disposable or persistent state required}"
: "${CONTROL:?separate private control directory required}"
: "${P11LAB_PIN_FILE:?private user credential file required}"
: "${P11LAB_SO_PIN_FILE:?private SO credential file required}"
export P11LAB_PIN_FILE P11LAB_SO_PIN_FILE
adapter="$PREFIX/payload/bin/p11lab-provider"
"$adapter" --prefix "$PREFIX" --state "$STATE" --control "$CONTROL" init
"$adapter" --prefix "$PREFIX" --state "$STATE" --control "$CONTROL" health
export P11LAB_MODULE="$PREFIX/payload/lib/libsofthsm2.so"
export SOFTHSM2_CONF="$CONTROL/softhsm2.conf"
"$PREFIX/payload/bin/softhsm2-util" --module "$P11LAB_MODULE" --show-slots
[ "$#" -gt 0 ] || { echo 'pass your application and literal arguments' >&2; exit 2; }
exec "$adapter" --prefix "$PREFIX" --state "$STATE" --control "$CONTROL" exec -- "$@"
