#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
state=/var/lib/p11lab
owned=$state/opensc-pico
control=/run/p11lab/opensc-pico
sockets=/run/pcscd
tool=/usr/local/bin/p11lab-opensc-pico
export P11LAB_MODULE=/usr/local/lib/p11lab/opensc-pkcs11.so

configure() {
    # The token label is fixed by the firmware ("SmartCard-HSM": the
    # post-initialize relabel path corrupts this emulator, so the
    # recipe never relabels). Default an unset label to it for
    # supervised applications (checker token selection); refuse any
    # other value rather than relabeling.
    export P11LAB_LABEL="${P11LAB_LABEL-SmartCard-HSM}"
    [ "$P11LAB_LABEL" = 'SmartCard-HSM' ] || p11lab_die "token label is fixed to SmartCard-HSM"
    # These controls can redirect native state, tracing, transports or identities.
    # They are not supported recipe inputs; do not silently overwrite them.
    for name in PCSCLITE_CSOCK_NAME OPENSC_CONF OPENSC_DEBUG OPENSSL_CONF OPENSSL_MODULES LD_PRELOAD NSS_WRAPPER_PASSWD NSS_WRAPPER_GROUP; do
        eval 'present=${'"$name"'+x}'
        [ "$present" != x ] || p11lab_die "unsupported native override: $name"
    done
    p11lab_writable_directory /run/p11lab
    p11lab_writable_directory "$control"
    [ "$(stat -c %u "$control")" = "$(id -u)" ] || p11lab_die "control directory ownership mismatch"
    p11lab_check_find empty "unsafe control files" "$control" -mindepth 1 -maxdepth 1 ! \( -type f -o -type d \) -print -quit
    p11lab_writable_directory "$control/logs"
    [ "$(stat -c %u "$control/logs")" = "$(id -u)" ] || p11lab_die "control directory ownership mismatch"
    p11lab_check_find empty "unsafe daemon logs" "$control/logs" -mindepth 1 ! \( -type f \( -name pcscd.log -o -name emulator.log -o -name provision.log \) \) -print -quit
    p11lab_check_find empty "ephemeral file ownership or hardlink mismatch" "$control/logs" -mindepth 1 -type f \( ! -uid "$(id -u)" -o -links +1 \) -print -quit
    # pcscd serves a fixed socket path. /run/pcscd is an in-image symlink
    # into the private control tmpfs, so no caller mount is required; a
    # caller mount over the path lands on the same target and is validated
    # identically. Any other redirect is refused.
    if [ -L "$sockets" ]; then
        [ "$(readlink "$sockets")" = "$control/pcscd" ] || p11lab_die "unexpected pcscd socket redirect"
        socketdir=$control/pcscd
    else
        socketdir=$sockets
    fi
    p11lab_writable_directory "$socketdir"
    [ "$(stat -c %u "$socketdir")" = "$(id -u)" ] || p11lab_die "pcscd socket directory ownership mismatch"
    # Stale supervisor debris from a killed run cannot be adopted safely:
    # pid values may already be reused. Refuse; a container restart clears this.
    # (service-lock persists across operations by design; its flock arbitrates.)
    if [ -e "$control/pcscd.pid" ] || [ -e "$control/emulator.pid" ]; then
        p11lab_die "stale daemon control state from an unclean shutdown"
    fi
    for stale in pcscd.comm pcscd.pid; do
        if [ -e "$sockets/$stale" ]; then
            p11lab_die "stale pcscd socket state from an unclean shutdown"
        fi
    done
}

validate_static() {
    [ ! -L "$state" ] && [ -d "$state" ] || p11lab_die "partial or unsafe state"
    [ ! -L "$state/.init-lock" ] && [ ! -e "$state/.init-lock" ] || p11lab_die "state initialization is already in progress"
    [ ! -L "$owned" ] && [ -d "$owned" ] || p11lab_die "partial or unsafe owned state"
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name opensc-pico -print -quit
    p11lab_check_find empty "partial state: unknown owned files" "$owned" -mindepth 1 -maxdepth 1 ! -name complete ! -name lease ! -name memory.flash -print -quit
    [ ! -L "$owned" ] && [ -d "$owned" ] && [ -w "$owned" ] && [ -x "$owned" ] || p11lab_die "partial or unsafe state directory"
    [ "$(stat -c %u "$owned")" = "$(id -u)" ] || p11lab_die "state directory ownership mismatch"
    for file in "$owned/complete" "$owned/lease" "$owned/memory.flash"; do
        [ ! -L "$file" ] && [ -f "$file" ] && [ -r "$file" ] && [ -w "$file" ] || p11lab_die "partial or unsafe provisioned file"
        [ "$(stat -c %u "$file")" = "$(id -u)" ] && [ "$(stat -c %h "$file")" = 1 ] || p11lab_die "provisioned file ownership or hardlink mismatch"
    done
    [ "$(stat -c %a "$owned/memory.flash")" = 600 ] || p11lab_die "provisioned flash file mode mismatch"
    [ "$(wc -c < "$owned/memory.flash")" = 8388608 ] || p11lab_die "provisioned flash file size mismatch"
    printf '%s\n' 'schema=1' 'provider=opensc-pico' "artifact=$(cat /usr/share/p11lab/runtime-id)" 'label=SmartCard-HSM' 'slot=0' 'keys=01:p256,02:rsa2048,03:p384' > "$control/expected-marker"
    cmp -s -- "$control/expected-marker" "$owned/complete" || p11lab_die "incompatible non-secret initialization configuration"
}

write_marker() {
    printf '%s\n' 'schema=1' 'provider=opensc-pico' "artifact=$(cat /usr/share/p11lab/runtime-id)" 'label=SmartCard-HSM' 'slot=0' 'keys=01:p256,02:rsa2048,03:p384' > "$owned/.complete.$$"
    mv -- "$owned/.complete.$$" "$owned/complete"
}

read_credentials() {
    p11lab_no_credential_conflict P11LAB_PIN P11LAB_PIN_FILE
    p11lab_no_credential_conflict P11LAB_SO_PIN P11LAB_SO_PIN_FILE
    p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
    user_credential=$credential
    p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
    so_credential=$credential
    # Native SmartCard-HSM bounds, proven: the user PIN verifies and
    # rotates only at 6..15 bytes (the init tool message allows 16,
    # but a 16-byte PIN can never verify); the SO-PIN is exactly 16
    # hexadecimal characters. The supervisor re-enforces the same
    # bounds and shape.
    user_bytes=$(printf '%s' "$user_credential" | wc -c)
    [ "$user_bytes" -ge 6 ] && [ "$user_bytes" -le 15 ] || p11lab_die "user credential input must be 6..15 bytes (native SmartCard-HSM bounds)"
    [ "$(printf '%s' "$so_credential" | wc -c)" = 16 ] || p11lab_die "SO credential input must be exactly 16 hexadecimal characters"
    case "$so_credential" in *[!0-9a-fA-F]*) p11lab_die "SO credential input must be exactly 16 hexadecimal characters" ;; esac
    unset P11LAB_PIN P11LAB_SO_PIN credential user_bytes
}

run_tool() {
    # The bounded stdin record has one separator LF; the user secret is
    # 6..15 bytes and the SO secret is 16 hex characters, both
    # single-line. The supervisor reads and erases it before launching
    # children. Forward container signals and wait for cleanup.
    printf '%s\n%s' "$user_credential" "$so_credential" | "$tool" "$@" &
    worker=$!
    unset user_credential so_credential
    trap 'kill -TERM "$worker" 2>/dev/null || :; wait "$worker" || :; exit 143' TERM
    trap 'kill -INT "$worker" 2>/dev/null || :; wait "$worker" || :; exit 130' INT
    trap 'kill -HUP "$worker" 2>/dev/null || :; wait "$worker" || :; exit 129' HUP
    wait "$worker"
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
        # The flash persists across operations and INITIALIZE is
        # destructive, so a repeated init never re-provisions: it
        # validates the provisioned state and checks readiness, exactly
        # like health, without consuming credentials.
        if [ -e "$owned/complete" ]; then validate_static; exec "$tool" health; fi
        p11lab_check_find empty "partial state: refusing to initialize nonempty volume" "$state" -mindepth 1 -maxdepth 1 -print -quit
        read_credentials
        mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
        trap 'rmdir "$state/.init-lock" 2>/dev/null || :' EXIT
        mkdir -m 700 "$owned"
        : > "$owned/lease"
        # Explicitly seal this adapter-owned lock file: inherited default ACLs
        # can give shell redirection a group mask despite the process umask.
        chmod 600 "$owned/lease"
        if run_tool init; then
            write_marker
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
        # Shellcheck SC2086 would split the application argv; exec
        # preserves the caller argv exactly through the supervisor.
        exec "$tool" exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|health|exec -- ARGV..." ;;
esac
