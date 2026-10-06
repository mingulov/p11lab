#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
export LC_ALL=C
. /usr/share/p11lab/common.sh
# Reassign imported scalars as unexported shell variables before any child
# process is started. File controls contain paths only. Prefer those files.
if [ "${P11LAB_PIN+x}" = x ]; then
    scalar_input=$P11LAB_PIN
    unset P11LAB_PIN
    P11LAB_PIN=$scalar_input
    unset scalar_input
fi
if [ "${P11LAB_SO_PIN+x}" = x ]; then
    scalar_input=$P11LAB_SO_PIN
    unset P11LAB_SO_PIN
    P11LAB_SO_PIN=$scalar_input
    unset scalar_input
fi
state=/var/lib/p11lab
owned=$state/wolfpkcs11
control=/run/p11lab
tool=/usr/local/bin/p11lab-wolfpkcs11
export P11LAB_MODULE=/usr/local/lib/p11lab/libwolfpkcs11.so
export P11LAB_LABEL="${P11LAB_LABEL-P11Lab}"
label=$P11LAB_LABEL

configure() {
    case "$label" in ''|*[!a-zA-Z0-9\ ._-]*) p11lab_die "label must use ASCII letters, digits, spaces, dot, underscore or hyphen" ;; esac
    [ "${#label}" -le 32 ] || p11lab_die "label exceeds 32 bytes"
    [ "${WOLFPKCS11_TOKEN_PATH-$owned}" = "$owned" ] || p11lab_die "conflicting managed token directory"
    export WOLFPKCS11_TOKEN_PATH=$owned
    p11lab_writable_directory "$control"
    [ ! -L "$control/expected-marker" ] || p11lab_die "control file cannot be a symlink"
    printf '%s\n' 'schema=1' 'provider=wolfpkcs11' "artifact=$(cat /usr/share/p11lab/runtime-id)" \
        "label=$label" 'slot=1' 'backend=file' > "$control/marker.$$"
    mv -f -- "$control/marker.$$" "$control/expected-marker"
}

validate_static() {
    [ ! -L "$state" ] && [ -d "$state" ] || p11lab_die "partial or unsafe state"
    [ "$(stat -c %u "$state")" = "$(id -u)" ] || p11lab_die "state ownership mismatch"
    [ ! -L "$state/.init-lock" ] && [ ! -e "$state/.init-lock" ] || p11lab_die "state initialization is already in progress"
    [ ! -L "$owned" ] && [ -d "$owned" ] && [ -w "$owned" ] && [ -x "$owned" ] || p11lab_die "partial or unsafe owned state"
    [ "$(stat -c %u "$owned")" = "$(id -u)" ] || p11lab_die "owned directory ownership mismatch"
    [ "$(stat -c %a "$owned")" = 700 ] || p11lab_die "owned directory permissions mismatch"
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name wolfpkcs11 -print -quit
    # Match the native file store for slot 1. Leftover temporary files denote
    # an interrupted writer and are retained for caller investigation.
    p11lab_check_find empty "partial state: unknown or unsafe owned files" "$owned" -regextype posix-extended -mindepth 1 -maxdepth 1 \
        ! \( -type f \( -name complete -o -name wp11_token_0000000000000001 \
        -o -regex '.*/wp11_(obj|symmkey|rsakey_priv|rsakey_pub|ecckey_priv|ecckey_pub|dhkey_priv|dhkey_pub|cert|trust|data)_0000000000000001_[0-9a-f]{16}' \) \) -print -quit
    p11lab_check_find empty "owned file ownership mismatch" "$owned" -mindepth 1 -maxdepth 1 ! -uid "$(id -u)" -print -quit
    p11lab_check_find empty "unsafe owned file permissions or hard links" "$owned" -mindepth 1 -maxdepth 1 ! \( -perm 600 -links 1 \) -print -quit
    for file in complete wp11_token_0000000000000001; do
        [ -f "$owned/$file" ] && [ -s "$owned/$file" ] && [ -r "$owned/$file" ] || p11lab_die "partial state: missing provisioned file $file"
    done
    cmp -s -- "$control/expected-marker" "$owned/complete" || p11lab_die "incompatible non-secret initialization configuration"
    # Parse bounded native metadata read-only before allowing C_Initialize to
    # open persistent state. This does not replace native errors or crypto.
    "$tool" inspect
}

complete() {
    validate_static
    "$tool" health
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
        [ "$(stat -c %u "$state")" = "$(id -u)" ] || p11lab_die "state ownership mismatch"
        configure
        if [ -e "$owned/complete" ]; then complete; exit 0; fi
        p11lab_check_find empty "partial state: refusing to initialize nonempty volume" "$state" -mindepth 1 -maxdepth 1 -print -quit
        p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
        [ "${#credential}" -ge 4 ] && [ "${#credential}" -le 32 ] || p11lab_die "user PIN must contain 4..32 bytes"
        user_credential=$credential
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        [ "${#credential}" -ge 4 ] && [ "${#credential}" -le 32 ] || p11lab_die "SO PIN must contain 4..32 bytes"
        so_credential=$credential
        mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
        trap 'rmdir "$state/.init-lock" 2>/dev/null || :' EXIT HUP INT TERM
        mkdir -m 700 "$owned"
        # A bind mount may inherit setgid from its parent. Clear special bits
        # only on this newly created directory, never on occupied state.
        chmod 00700 "$owned"
        # Shell builtin printf and inherited pipes keep PINs out of child argv,
        # process environments, persistent adapter files and receipts.
        if printf '%s' "$user_credential" | {
            exec 3<&0
            printf '%s' "$so_credential" | "$tool" init 4<&0
        }; then
            cp -- "$control/expected-marker" "$owned/.complete.$$"
            mv -- "$owned/.complete.$$" "$owned/complete"
        else
            status=$?
            printf '%s\n' 'p11lab: native initialization failed; partial state retained' >&2
            exit "$status"
        fi
        ;;
    health)
        [ "$#" -eq 1 ] || p11lab_die "health takes no arguments"
        configure
        complete
        ;;
    exec)
        shift
        [ "${1-}" = -- ] || p11lab_die "exec requires -- followed by argv"
        shift
        [ "$#" -gt 0 ] || p11lab_die "exec requires an application"
        configure
        complete >/dev/null
        exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|health|exec -- ARGV..." ;;
esac
