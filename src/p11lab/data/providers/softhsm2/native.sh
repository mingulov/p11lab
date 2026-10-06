#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
[ "$#" -ge 7 ] && [ "$1" = --prefix ] && [ "$3" = --state ] && [ "$5" = --control ] || { echo 'usage: p11lab-provider --prefix DIR --state DIR --control DIR init|health|exec -- ARGV...' >&2; exit 1; }
prefix=$(realpath -e -- "$2")
state=$(realpath -m -- "$4")
control=$(realpath -m -- "$6")
shift 6
. "$prefix/payload/share/p11lab/common.sh"
for writable in "$state" "$control"; do
    case "$writable/" in "$prefix/"*) p11lab_die "writable path overlaps installation prefix" ;; esac
    case "$prefix/" in "$writable/"*) p11lab_die "writable path contains installation prefix" ;; esac
    case "$writable" in *'#'*|*'
'*|*''*) p11lab_die "path cannot be represented in SoftHSM configuration" ;; esac
done
case "$state/" in "$control/"*) p11lab_die "state and control overlap" ;; esac
case "$control/" in "$state/"*) p11lab_die "state and control overlap" ;; esac
. /etc/os-release
[ "$ID" = debian ] && [ "${VERSION_ID%%.*}" = 13 ] && [ "$(uname -m)" = x86_64 ] || p11lab_die "requires Debian 13 amd64"
for binary in "$prefix/payload/lib/libsofthsm2.so" "$prefix/payload/bin/softhsm2-util"; do
    /lib64/ld-linux-x86-64.so.2 --list "$binary" >/dev/null || p11lab_die "missing or incompatible host runtime"
done
owned=$state/softhsm2
export SOFTHSM2_CONF=$control/softhsm2.conf
export P11LAB_MODULE="$prefix/payload/lib/libsofthsm2.so"
label=${P11LAB_LABEL-P11Lab}

configure() {
    p11lab_writable_directory "$control"
    [ ! -L "$SOFTHSM2_CONF" ] || p11lab_die "configuration cannot be a symlink"
    printf '%s\n' "directories.tokendir = $owned/tokens" 'objectstore.backend = file' 'log.level = ERROR' 'slots.removable = false' > "$control/config.$$"
    mv -f -- "$control/config.$$" "$SOFTHSM2_CONF"
}
expected_marker() {
    case "$label" in ''|*[!a-zA-Z0-9\ ._-]*) p11lab_die "label must use printable ASCII letters, digits, spaces, dot, underscore or hyphen" ;; esac
    [ "${#label}" -le 32 ] || p11lab_die "label exceeds 32 bytes"
    printf '%s\n' 'schema=1' 'provider=softhsm2' "artifact=$(cat "$prefix/payload/share/p11lab/native-id")" "label=$label" 'backend=file'
}
complete() {
    [ ! -L "$owned" ] && [ ! -L "$owned/complete" ] && [ ! -L "$owned/tokens" ] || p11lab_die "partial or unsafe state"
    [ -f "$owned/complete" ] && [ -d "$owned/tokens" ] || p11lab_die "partial state: missing completion marker or token directory"
    [ -n "$(find "$owned/tokens" -mindepth 1 -maxdepth 1 -type d -print -quit)" ] || p11lab_die "partial state: missing initialized token"
    # Do not enter native enumeration on wholly lost contents: SoftHSM creates
    # auxiliary generation bookkeeping even when opening an invalid empty token.
    [ -n "$(find "$owned/tokens" -mindepth 1 -type f -print -quit)" ] || p11lab_die "partial state: missing token contents"
    [ "$(cat "$owned/complete")" = "$(expected_marker)" ] || p11lab_die "incompatible non-secret initialization configuration"
    [ -z "$(find "$state" -mindepth 1 -maxdepth 1 ! -name softhsm2 -print -quit)" ] || p11lab_die "partial state: unknown files"
    [ -z "$(find "$owned" -mindepth 1 -maxdepth 1 ! -name tokens ! -name complete -print -quit)" ] || p11lab_die "partial state: unknown owned files"
    if slots=$("$prefix/payload/bin/softhsm2-util" --module "$P11LAB_MODULE" --show-slots); then
        # This pinned stock utility reports C_GetTokenInfo flags and padded label.
        # Successful enumeration alone also includes the uninitialized free slot.
        printf '%s\n' "$slots" | awk -v expected="$label" '
            function ready() { return initialized == "yes" && user_initialized == "yes" && serial != "" && token_label == expected }
            BEGIN { sub(/ +$/, "", expected) }
            /^Slot [0-9]+$/ {
                if (ready()) found = 1
                initialized = user_initialized = serial = token_label = ""
            }
            /^        Initialized:      / { initialized = substr($0, 27) }
            /^        User PIN init\.:   / { user_initialized = substr($0, 27) }
            /^        Serial number:    / { serial = substr($0, 27); sub(/ +$/, "", serial) }
            /^        Label:            / { token_label = substr($0, 27); sub(/ +$/, "", token_label) }
            END { if (ready()) found = 1; exit !found }
        ' || p11lab_die "partial state: expected initialized token is not ready"
    else
        status=$?
        printf '%s\n' 'p11lab: native slot enumeration failed' >&2
        exit "$status"
    fi
}
case "${1-}" in
    describe)
        [ "$#" -eq 1 ] || p11lab_die "describe takes no arguments"
        cat "$prefix/payload/share/p11lab/provider.json"
        ;;
    init)
        [ "$#" -eq 1 ] || p11lab_die "init takes no arguments"
        p11lab_no_credential_conflict P11LAB_PIN P11LAB_PIN_FILE
        p11lab_no_credential_conflict P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        p11lab_writable_directory "$state"
        configure
        if [ -e "$owned/complete" ]; then complete; exit 0; fi
        [ -z "$(find "$state" -mindepth 1 -maxdepth 1 -print -quit)" ] || p11lab_die "partial state: refusing to initialize nonempty volume"
        expected_marker > "$control/marker.$$"
        p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
        user_credential=$credential
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
        trap 'rmdir "$state/.init-lock" 2>/dev/null || :; rm -f "$control/marker.$$" "$control/init.$$"' EXIT HUP INT TERM
        mkdir -m 700 "$owned" "$owned/tokens"
        if "$prefix/payload/bin/softhsm2-util" --module "$P11LAB_MODULE" --init-token --free --label "$label" --pin "$user_credential" --so-pin "$credential" > "$control/init.$$" 2>&1; then
            cp -- "$control/marker.$$" "$owned/.complete.$$"
            mv -- "$owned/.complete.$$" "$owned/complete"
        else
            status=$?
            printf '%s\n' 'p11lab: native token initialization failed; partial state retained' >&2
            exit "$status"
        fi
        ;;
    health)
        [ "$#" -eq 1 ] || p11lab_die "health takes no arguments"
        configure
        complete
        printf '%s\n' "$slots"
        ;;
    exec)
        shift
        [ "${1-}" = -- ] || p11lab_die "exec requires -- followed by argv"
        shift
        [ "$#" -gt 0 ] || p11lab_die "exec requires an application"
        configure
        complete
        exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|health|exec -- ARGV..." ;;
esac
