#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
state=/var/lib/p11lab
owned=$state/ykcs11
control=/run/p11lab/ykcs11
sockets=/run/pcscd
tool=/usr/local/bin/p11lab-ykcs11
export P11LAB_MODULE=/usr/local/lib/libykcs11.so.2

configure() {
    # The token label is fixed by the module/card pair ("YubiKey PIV #0").
    # Default an unset label to it for supervised applications (checker
    # token selection); refuse any other value rather than relabeling.
    export P11LAB_LABEL="${P11LAB_LABEL-YubiKey PIV #0}"
    [ "$P11LAB_LABEL" = 'YubiKey PIV #0' ] || p11lab_die "token label is fixed to YubiKey PIV #0"
    # These controls can redirect native state, tracing, transports or identities.
    # They are not supported recipe inputs; do not silently overwrite them.
    for name in PCSCLITE_CSOCK_NAME OPENSSL_CONF OPENSSL_MODULES LD_PRELOAD NSS_WRAPPER_PASSWD NSS_WRAPPER_GROUP; do
        eval 'present=${'"$name"'+x}'
        [ "$present" != x ] || p11lab_die "unsupported native override: $name"
    done
    p11lab_writable_directory /run/p11lab
    p11lab_writable_directory "$control"
    [ "$(stat -c %u "$control")" = "$(id -u)" ] || p11lab_die "control directory ownership mismatch"
    p11lab_check_find empty "unsafe control files" "$control" -mindepth 1 -maxdepth 1 ! \( -type f -o -type d \) -print -quit
    for directory in logs provisioning; do
        p11lab_writable_directory "$control/$directory"
        [ "$(stat -c %u "$control/$directory")" = "$(id -u)" ] || p11lab_die "control directory ownership mismatch"
    done
    p11lab_check_find empty "unsafe daemon logs" "$control/logs" -mindepth 1 ! \( -type f \( -name pcscd.log -o -name provision.log \) \) -print -quit
    p11lab_check_find empty "unsafe provisioning files" "$control/provisioning" -mindepth 1 ! \( -type f \( -name key9a-pub.pem -o -name cert9a.pem \) \) -print -quit
    p11lab_check_find empty "ephemeral file ownership or hardlink mismatch" "$control/logs" "$control/provisioning" -mindepth 1 -type f \( ! -uid "$(id -u)" -o -links +1 \) -print -quit
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
    # The virtual card fabricates its flash at a fixed path under /tmp;
    # /tmp must be writable (a private tmpfs in the standard bindings).
    : > "/tmp/.p11lab-ykcs11-write-test.$$" || p11lab_die "/tmp is not writable (virtual card flash)"
    rm -f -- "/tmp/.p11lab-ykcs11-write-test.$$"
    # Stale supervisor debris from a killed run cannot be adopted safely:
    # pid values may already be reused. Refuse; a container restart clears this.
    # (service-lock persists across operations by design; its flock arbitrates.)
    if [ -e "$control/pcscd.pid" ]; then
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
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name ykcs11 -print -quit
    p11lab_check_find empty "partial state: unknown owned files" "$owned" -mindepth 1 -maxdepth 1 ! -name complete ! -name lease ! -name key9a.pem ! -name cert9a.pem -print -quit
    [ ! -L "$owned" ] && [ -d "$owned" ] && [ -w "$owned" ] && [ -x "$owned" ] || p11lab_die "partial or unsafe state directory"
    [ "$(stat -c %u "$owned")" = "$(id -u)" ] || p11lab_die "state directory ownership mismatch"
    for file in "$owned/complete" "$owned/lease" "$owned/key9a.pem" "$owned/cert9a.pem"; do
        [ ! -L "$file" ] && [ -f "$file" ] && [ -r "$file" ] && [ -w "$file" ] || p11lab_die "partial or unsafe provisioned file"
        [ "$(stat -c %u "$file")" = "$(id -u)" ] && [ "$(stat -c %h "$file")" = 1 ] || p11lab_die "provisioned file ownership or hardlink mismatch"
    done
    [ "$(stat -c %a "$owned/key9a.pem")" = 600 ] || p11lab_die "provisioned key file mode mismatch"
    [ "$(stat -c %a "$owned/cert9a.pem")" = 600 ] || p11lab_die "provisioned certificate file mode mismatch"
    [ -s "$owned/key9a.pem" ] || p11lab_die "partial or unsafe provisioned file"
    [ -s "$owned/cert9a.pem" ] || p11lab_die "partial or unsafe provisioned file"
    [ "$(wc -c < "$owned/key9a.pem")" -le 65536 ] || p11lab_die "provisioned key file exceeds bound"
    [ "$(wc -c < "$owned/cert9a.pem")" -le 65536 ] || p11lab_die "provisioned certificate file exceeds bound"
    printf '%s\n' 'schema=1' 'provider=ykcs11' "artifact=$(cat /usr/share/p11lab/runtime-id)" 'slot=9a' "key_sha256=$(sha256sum < "$owned/key9a.pem" | cut -d' ' -f1)" "cert_sha256=$(sha256sum < "$owned/cert9a.pem" | cut -d' ' -f1)" > "$control/expected-marker"
    cmp -s -- "$control/expected-marker" "$owned/complete" || p11lab_die "incompatible non-secret initialization configuration"
}

write_marker() {
    printf '%s\n' 'schema=1' 'provider=ykcs11' "artifact=$(cat /usr/share/p11lab/runtime-id)" 'slot=9a' "key_sha256=$(sha256sum < "$owned/key9a.pem" | cut -d' ' -f1)" "cert_sha256=$(sha256sum < "$owned/cert9a.pem" | cut -d' ' -f1)" > "$owned/.complete.$$"
    mv -- "$owned/.complete.$$" "$owned/complete"
}

read_credentials() {
    p11lab_no_credential_conflict P11LAB_PIN P11LAB_PIN_FILE
    p11lab_no_credential_conflict P11LAB_SO_PIN P11LAB_SO_PIN_FILE
    p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
    user_credential=$credential
    p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
    so_credential=$credential
    # Native PIV bounds, proven: change-pin/change-puk enforce 6..8
    # bytes. The supervisor re-enforces the same bound and shape.
    for value in "$user_credential" "$so_credential"; do
        bytes=$(printf '%s' "$value" | wc -c)
        [ "$bytes" -ge 6 ] && [ "$bytes" -le 8 ] || p11lab_die "credential input must be 6..8 bytes (native PIV bounds)"
    done
    unset P11LAB_PIN P11LAB_SO_PIN credential bytes value
}

run_tool() {
    # The bounded stdin record has one separator LF; each secret is 6..8
    # bytes single-line. The supervisor reads and erases it before
    # launching children. Forward container signals and wait for cleanup.
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
        p11lab_writable_directory "$state"
        configure
        read_credentials
        if [ -e "$owned/complete" ]; then
            validate_static
            # The card is factory-fresh every operation, so repeated init
            # re-personalizes with the given caller PIN/PUK and re-imports
            # the stored identity; no cross-operation PIN continuity exists.
            if run_tool reprovision; then
                :
            else
                status=$?
                printf '%s\n' 'p11lab: native reprovisioning failed; state retained' >&2
                exit "$status"
            fi
        else
            p11lab_check_find empty "partial state: refusing to initialize nonempty volume" "$state" -mindepth 1 -maxdepth 1 -print -quit
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
        fi
        ;;
    health)
        [ "$#" -eq 1 ] || p11lab_die "health takes no arguments"
        configure
        read_credentials
        validate_static
        run_tool reprovision
        ;;
    exec)
        shift
        [ "${1-}" = -- ] || p11lab_die "exec requires -- followed by argv"
        shift
        [ "$#" -gt 0 ] || p11lab_die "exec requires an application"
        configure
        read_credentials
        validate_static
        # Shellcheck SC2086 would split the application argv; the quoted
        # "$@" preserves the caller argv exactly through the supervisor.
        run_tool exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|health|exec -- ARGV..." ;;
esac
