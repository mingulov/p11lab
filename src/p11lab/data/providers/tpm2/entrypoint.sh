#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
state=/var/lib/p11lab
owned=$state/tpm2
control=/run/p11lab/tpm2
tool=/usr/local/bin/p11lab-tpm2
export P11LAB_MODULE=/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so
export P11LAB_LABEL="${P11LAB_LABEL-P11Lab}"
label=$P11LAB_LABEL

configure() {
    case "$label" in ''|*[!a-zA-Z0-9\ ._-]*) p11lab_die "label must use ASCII letters, digits, spaces, dot, underscore or hyphen" ;; esac
    [ "${#label}" -le 32 ] || p11lab_die "label exceeds 32 bytes"
    # These controls can redirect native state, tracing, transports or identities.
    # They are not supported recipe inputs; do not silently overwrite them.
    for name in TPM2_PKCS11_STORE TPM2_PKCS11_TCTI TPM2TOOLS_TCTI DBUS_SYSTEM_BUS_ADDRESS DBUS_SESSION_BUS_ADDRESS OPENSSL_CONF OPENSSL_MODULES LD_PRELOAD NSS_WRAPPER_PASSWD NSS_WRAPPER_GROUP; do
        eval 'present=${'"$name"'+x}'
        [ "$present" != x ] || p11lab_die "unsupported native override: $name"
    done
    p11lab_writable_directory /run/p11lab
    p11lab_writable_directory "$control"
    [ "$(stat -c %u "$control")" = "$(id -u)" ] || p11lab_die "control directory ownership mismatch"
    p11lab_check_find empty "unsafe control files" "$control" -mindepth 1 -maxdepth 1 ! \( -type f -o -type d -o -type s \) -print -quit
    for directory in bus logs; do
        p11lab_writable_directory "$control/$directory"
        [ "$(stat -c %u "$control/$directory")" = "$(id -u)" ] || p11lab_die "control directory ownership mismatch"
    done
    p11lab_check_find empty "unsafe bus entries" "$control/bus" -mindepth 1 ! -type s -print -quit
    p11lab_check_find empty "unsafe daemon logs" "$control/logs" -mindepth 1 ! \( -type f \( -name swtpm.log -o -name dbus.log -o -name abrmd.log -o -name provision.log \) \) -print -quit
    p11lab_check_find empty "ephemeral file ownership or hardlink mismatch" "$control/bus" "$control/logs" -mindepth 1 -type f \( ! -uid "$(id -u)" -o -links +1 \) -print -quit
    # Stale supervisor debris from a killed run cannot be adopted safely:
    # pid values may already be reused. Refuse; a container restart clears this.
    for stale in swtpm.pid dbus.pid abrmd.pid system_bus_socket; do
        if [ -e "$control/$stale" ] || [ -e "$control/bus/$stale" ]; then
            p11lab_die "stale daemon control state from an unclean shutdown"
        fi
    done
    printf '%s\n' 'schema=1' 'provider=tpm2' "artifact=$(cat /usr/share/p11lab/runtime-id)" "label=$label" 'slot=1' 'backend=swtpm+tabrmd' 'transients=100' 'sessions=4' > "$control/marker.$$"
    mv -f -- "$control/marker.$$" "$control/expected-marker"
}

validate_static() {
    [ ! -L "$state" ] && [ -d "$state" ] || p11lab_die "partial or unsafe state"
    [ ! -L "$state/.init-lock" ] && [ ! -e "$state/.init-lock" ] || p11lab_die "state initialization is already in progress"
    [ ! -L "$owned" ] && [ -d "$owned" ] || p11lab_die "partial or unsafe owned state"
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name tpm2 -print -quit
    p11lab_check_find empty "partial state: unknown owned files" "$owned" -mindepth 1 -maxdepth 1 ! -name complete ! -name lease ! -name store ! -name tpmstate -print -quit
    for directory in "$owned" "$owned/store" "$owned/tpmstate"; do
        [ ! -L "$directory" ] && [ -d "$directory" ] && [ -w "$directory" ] && [ -x "$directory" ] || p11lab_die "partial or unsafe state directory"
        [ "$(stat -c %u "$directory")" = "$(id -u)" ] || p11lab_die "state directory ownership mismatch"
    done
    p11lab_check_find empty "unexpected store files" "$owned/store" -mindepth 1 -maxdepth 1 ! \( -type f -name tpm2_pkcs11.sqlite3 \) -print -quit
    p11lab_check_find empty "unexpected emulator state entries" "$owned/tpmstate" -mindepth 1 -maxdepth 1 ! -name .lock ! -name tpm2-00.permall -print -quit
    p11lab_check_find empty "state file ownership or hardlink mismatch" "$owned/store" "$owned/tpmstate" -mindepth 1 -type f \( ! -uid "$(id -u)" -o -links +1 \) -print -quit
    for file in "$owned/complete" "$owned/lease" "$owned/store/tpm2_pkcs11.sqlite3"; do
        [ ! -L "$file" ] && [ -f "$file" ] && [ -r "$file" ] && [ -w "$file" ] || p11lab_die "partial or unsafe provisioned file"
        [ "$(stat -c %u "$file")" = "$(id -u)" ] && [ "$(stat -c %h "$file")" = 1 ] || p11lab_die "provisioned file ownership or hardlink mismatch"
    done
    # A provisioned store is never empty, and the emulator state is exactly
    # the swtpm lock plus the persistent blob. Refuse before any daemon
    # starts: native open would otherwise mutate the store or the blob.
    [ -s "$owned/store/tpm2_pkcs11.sqlite3" ] || p11lab_die "partial or unsafe provisioned file"
    for file in "$owned/tpmstate/.lock" "$owned/tpmstate/tpm2-00.permall"; do
        [ ! -L "$file" ] && [ -f "$file" ] && [ -r "$file" ] && [ -w "$file" ] || p11lab_die "partial or unsafe emulator state"
        [ "$(stat -c %u "$file")" = "$(id -u)" ] && [ "$(stat -c %h "$file")" = 1 ] || p11lab_die "emulator state ownership or hardlink mismatch"
    done
    [ -s "$owned/tpmstate/tpm2-00.permall" ] || p11lab_die "partial or unsafe emulator state"
    cmp -s -- "$control/expected-marker" "$owned/complete" || p11lab_die "incompatible non-secret initialization configuration"
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
        if [ -e "$owned/complete" ]; then validate_static; exec "$tool" health; fi
        p11lab_check_find empty "partial state: refusing to initialize nonempty volume" "$state" -mindepth 1 -maxdepth 1 -print -quit
        p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
        user_credential=$credential
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        so_credential=$credential
        # Native tpm2_ptool accepts any non-empty PIN through 4096 bytes; the
        # supervisor and driver re-enforce the byte bound and single-line shape.
        [ "$(printf '%s' "$user_credential" | wc -c)" -le 4096 ] || p11lab_die "credential input exceeds 4096-byte bound"
        [ "$(printf '%s' "$so_credential" | wc -c)" -le 4096 ] || p11lab_die "credential input exceeds 4096-byte bound"
        unset P11LAB_PIN P11LAB_SO_PIN credential
        mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
        trap 'rmdir "$state/.init-lock" 2>/dev/null || :' EXIT
        mkdir -m 700 "$owned" "$owned/store" "$owned/tpmstate"
        : > "$owned/lease"
        # Explicitly seal this adapter-owned lock file: inherited default ACLs
        # can give shell redirection a group mask despite the process umask.
        chmod 600 "$owned/lease"
        # The bounded stdin record has one separator LF; each secret is single
        # line. The supervisor reads and erases it before launching children.
        # Forward container signals to that supervisor and wait for cleanup.
        printf '%s\n%s' "$user_credential" "$so_credential" | "$tool" init &
        worker=$!
        unset user_credential so_credential
        trap 'kill -TERM "$worker" 2>/dev/null || :; wait "$worker" || :; exit 143' TERM
        trap 'kill -INT "$worker" 2>/dev/null || :; wait "$worker" || :; exit 130' INT
        trap 'kill -HUP "$worker" 2>/dev/null || :; wait "$worker" || :; exit 129' HUP
        if wait "$worker"; then
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
        validate_static
        exec "$tool" health
        ;;
    exec)
        shift
        [ "${1-}" = -- ] || p11lab_die "exec requires -- followed by argv"
        shift
        [ "$#" -gt 0 ] || p11lab_die "exec requires an application"
        configure
        validate_static
        exec "$tool" exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|health|exec -- ARGV..." ;;
esac
