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
read_metadata() {
    [ ! -L "$1" ] && [ -f "$1" ] && [ -r "$1" ] || p11lab_die "identity or completion marker must be a readable non-symlink regular file"
    metadata_size=$(wc -c < "$1") || p11lab_die "cannot count identity or completion marker bytes"
    # Keep every trailing LF; a failed read must not become successful output.
    metadata=$(cat -- "$1" && printf '.') || p11lab_die "cannot read identity or completion marker"
    metadata=${metadata%.}
    # Shell variables cannot retain NUL. Count bytes, not locale-dependent
    # characters, without changing the caller's label-validation locale.
    retained_size=$(LC_ALL=C; printf '%s' "${#metadata}") || p11lab_die "cannot count retained metadata bytes"
    [ "$retained_size" = "$metadata_size" ] || p11lab_die "identity or completion marker contains unsupported bytes"
}
validate_label() {
    case "$label" in ''|*[!a-zA-Z0-9\ ._-]*) p11lab_die "label must use printable ASCII letters, digits, spaces, dot, underscore or hyphen" ;; esac
    [ "${#label}" -le 32 ] || p11lab_die "label exceeds 32 bytes"
}
validate_identity() {
    read_metadata /usr/share/p11lab/runtime-id
    [ "$metadata_size" = 65 ] || p11lab_die "invalid build-input identity"
    case "$metadata" in *'
') artifact=${metadata%'
'} ;; *) p11lab_die "invalid build-input identity framing" ;; esac
    case "$artifact" in *[!0123456789abcdef]*) p11lab_die "invalid build-input identity" ;; esac
    [ "${#artifact}" -eq 64 ] || p11lab_die "invalid build-input identity"
}
expected_marker() {
    printf '%s\n' 'schema=1' 'provider=softhsm2' "artifact=$artifact" "label=$label" 'backend=file'
}
init_signal() {
    if [ "$cleaning_up" -eq 1 ]; then
        # Finish cleanup rather than exit midway. Preserve the first observed
        # failure, including one captured before its primary-status update.
        if [ "$init_status" -eq 0 ]; then
            if [ "$cleanup_status" -ne 0 ]; then
                init_status=$cleanup_status
            else
                init_status=$1
            fi
        fi
    else
        exit "$1"
    fi
}
cleanup_init() {
    # Enter cleanup and capture its incoming status in one command; the signal
    # handlers stay installed throughout rather than briefly remaining exits.
    init_status=$? cleaning_up=1 cleanup_status=0
    trap - EXIT
    # Try both owned resources even if a command fails or a stop is received.
    rmdir -- "$state/.init-lock" 2>/dev/null || {
        cleanup_status=$?
        if [ "$init_status" -eq 0 ]; then init_status=$cleanup_status; fi
    }
    rm -f -- "$control/marker.$$" "$control/init.$$" || {
        cleanup_status=$?
        if [ "$init_status" -eq 0 ]; then init_status=$cleanup_status; fi
    }
    if [ "$cleanup_status" -ne 0 ]; then
        printf '%s\n' 'p11lab: initialization cleanup failed' >&2 || :
    fi
    exit "$init_status"
}
complete() {
    [ ! -L "$owned" ] && [ ! -L "$owned/complete" ] && [ ! -L "$owned/tokens" ] || p11lab_die "partial or unsafe state"
    [ -f "$owned/complete" ] && [ -d "$owned/tokens" ] || p11lab_die "partial state: missing completion marker or token directory"
    p11lab_check_find present "partial state: missing initialized token" "$owned/tokens" -mindepth 1 -maxdepth 1 -type d -print -quit
    # Do not enter native enumeration on wholly lost contents: SoftHSM creates
    # auxiliary generation bookkeeping even when opening an invalid empty token.
    p11lab_check_find present "partial state: missing token contents" "$owned/tokens" -mindepth 1 -type f -print -quit
    read_metadata "$owned/complete"
    expected=$(expected_marker && printf '.') || p11lab_die "cannot generate completion marker"
    expected=${expected%.}
    [ "$metadata" = "$expected" ] || p11lab_die "incompatible non-secret initialization configuration"
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
        printf '%s\n' 'p11lab: native slot enumeration failed' >&2 || :
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
        validate_identity
        p11lab_writable_directory "$state"
        configure
        validate_label
        if [ -e "$owned/complete" ]; then complete; exit 0; fi
        p11lab_check_find empty "partial state: refusing to initialize nonempty volume" "$state" -mindepth 1 -maxdepth 1 -print -quit
        p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
        user_credential=$credential
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
        cleaning_up=0
        trap cleanup_init EXIT
        # Foreground native children may defer these traps until they return.
        # Once handled, a stop must not resume initialization or publish complete.
        trap 'init_signal 129' HUP
        trap 'init_signal 130' INT
        trap 'init_signal 143' TERM
        expected_marker > "$control/marker.$$"
        mkdir -m 700 "$owned" "$owned/tokens"
        if softhsm2-util --module "$P11LAB_MODULE" --init-token --free --label "$label" --pin "$user_credential" --so-pin "$credential" > "$control/init.$$" 2>&1; then
            cp -- "$control/marker.$$" "$owned/.complete.$$"
            mv -- "$owned/.complete.$$" "$owned/complete"
        else
            status=$?
            printf '%s\n' 'p11lab: native token initialization failed; partial state retained' >&2 || :
            exit "$status"
        fi
        ;;
    health)
        [ "$#" -eq 1 ] || p11lab_die "health takes no arguments"
        validate_identity
        configure
        validate_label
        complete
        printf '%s\n' "$slots"
        ;;
    exec)
        shift
        [ "${1-}" = -- ] || p11lab_die "exec requires -- followed by argv"
        shift
        [ "$#" -gt 0 ] || p11lab_die "exec requires an application"
        validate_identity
        configure
        validate_label
        complete
        exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|health|exec -- ARGV..." ;;
esac
