#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
state=/var/lib/p11lab
owned=$state/softhsm2
control=/run/p11lab
export SOFTHSM2_CONF=$control/softhsm2.conf
export P11LAB_MODULE=/usr/local/lib/p11lab/libsofthsm2.so
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
    printf '%s\n' 'schema=1' 'provider=softhsm2' "artifact=$(cat /usr/share/p11lab/runtime-id)" "label=$label" 'backend=file'
}
complete() {
    [ ! -L "$owned" ] && [ ! -L "$owned/complete" ] && [ ! -L "$owned/tokens" ] || p11lab_die "partial or unsafe state"
    [ -f "$owned/complete" ] && [ -d "$owned/tokens" ] || p11lab_die "partial state: missing completion marker or token directory"
    p11lab_check_find present "partial state: missing initialized token" "$owned/tokens" -mindepth 1 -maxdepth 1 -type d -print -quit
    # Do not enter native enumeration on wholly lost contents: SoftHSM creates
    # auxiliary generation bookkeeping even when opening an invalid empty token.
    p11lab_check_find present "partial state: missing token contents" "$owned/tokens" -mindepth 1 -type f -print -quit
    [ "$(cat "$owned/complete")" = "$(expected_marker)" ] || p11lab_die "incompatible non-secret initialization configuration"
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name softhsm2 -print -quit
    p11lab_check_find empty "partial state: unknown owned files" "$owned" -mindepth 1 -maxdepth 1 ! -name tokens ! -name complete -print -quit
    if slots=$(softhsm2-util --module "$P11LAB_MODULE" --show-slots); then
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
        cat /usr/share/p11lab/provider.json
        ;;
    init)
        [ "$#" -eq 1 ] || p11lab_die "init takes no arguments"
        p11lab_no_credential_conflict P11LAB_PIN P11LAB_PIN_FILE
        p11lab_no_credential_conflict P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        p11lab_writable_directory "$state"
        configure
        if [ -e "$owned/complete" ]; then complete; exit 0; fi
        p11lab_check_find empty "partial state: refusing to initialize nonempty volume" "$state" -mindepth 1 -maxdepth 1 -print -quit
        expected_marker > "$control/marker.$$"
        p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
        user_credential=$credential
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
        trap 'rmdir "$state/.init-lock" 2>/dev/null || :; rm -f "$control/marker.$$" "$control/init.$$"' EXIT HUP INT TERM
        mkdir -m 700 "$owned" "$owned/tokens"
        if softhsm2-util --module "$P11LAB_MODULE" --init-token --free --label "$label" --pin "$user_credential" --so-pin "$credential" > "$control/init.$$" 2>&1; then
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
