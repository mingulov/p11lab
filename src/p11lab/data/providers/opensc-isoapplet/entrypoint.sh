#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
state=/var/lib/p11lab
owned=$state/opensc-isoapplet
control=/run/p11lab/opensc-isoapplet
sockets=/run/pcscd
tool=/usr/local/bin/p11lab-opensc-isoapplet
export P11LAB_MODULE=/usr/local/lib/p11lab/opensc-pkcs11.so
# The card is RAM-only: every operation provisions a fresh card with
# caller credentials and nothing persists across operations. The
# marker binds the non-secret configuration only.
marker_label='JavaCard isoApplet'

configure() {
    # The token label is the applet default ("JavaCard isoApplet":
    # --label could change it per card, but every card is fresh, so
    # a fixed label keeps the census and token selection exact).
    # Default an unset label to it for supervised applications
    # (checker token selection); refuse any other value.
    export P11LAB_LABEL="${P11LAB_LABEL-$marker_label}"
    [ "$P11LAB_LABEL" = "$marker_label" ] || p11lab_die "token label is fixed to $marker_label"
    # These controls can redirect native state, tracing, transports,
    # JVM flags or identities. They are not supported recipe inputs;
    # do not silently overwrite them.
    for name in PCSCLITE_CSOCK_NAME OPENSC_CONF OPENSC_DEBUG OPENSSL_CONF OPENSSL_MODULES LD_PRELOAD NSS_WRAPPER_PASSWD NSS_WRAPPER_GROUP JAVA_TOOL_OPTIONS JDK_JAVA_OPTIONS _JAVA_OPTIONS CLASSPATH JAVA_HOME; do
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
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name opensc-isoapplet -print -quit
    p11lab_check_find empty "partial state: unknown owned files" "$owned" -mindepth 1 -maxdepth 1 ! -name complete ! -name lease -print -quit
    [ ! -L "$owned" ] && [ -d "$owned" ] && [ -w "$owned" ] && [ -x "$owned" ] || p11lab_die "partial or unsafe state directory"
    [ "$(stat -c %u "$owned")" = "$(id -u)" ] || p11lab_die "state directory ownership mismatch"
    for file in "$owned/complete" "$owned/lease"; do
        [ ! -L "$file" ] && [ -f "$file" ] && [ -r "$file" ] && [ -w "$file" ] || p11lab_die "partial or unsafe provisioned file"
        [ "$(stat -c %u "$file")" = "$(id -u)" ] && [ "$(stat -c %h "$file")" = 1 ] || p11lab_die "provisioned file ownership or hardlink mismatch"
    done
    # Write-then-rename: rename(2) replaces any pre-existing
    # expected-marker entry without following a planted symlink or
    # truncating through a planted hardlink (a direct > redirect
    # would do either on a raced plant). The staging file is created
    # 0600 by mktemp; a crashed run's leftover staging file is a
    # regular owned 0600 file holding the same non-secret bytes and
    # is ignored (never read).
    marker_tmp=$(mktemp "$control/.expected-marker.XXXXXX") || p11lab_die "cannot stage expected marker"
    printf '%s\n' 'schema=1' 'provider=opensc-isoapplet' "artifact=$(cat /usr/share/p11lab/runtime-id)" "label=$marker_label" 'slot=0' 'keys=01:p256,02:rsa2048,03:p384' > "$marker_tmp"
    mv -- "$marker_tmp" "$control/expected-marker"
    cmp -s -- "$control/expected-marker" "$owned/complete" || p11lab_die "incompatible non-secret initialization configuration"
}

write_marker() {
    printf '%s\n' 'schema=1' 'provider=opensc-isoapplet' "artifact=$(cat /usr/share/p11lab/runtime-id)" "label=$marker_label" 'slot=0' 'keys=01:p256,02:rsa2048,03:p384' > "$owned/.complete.$$"
    mv -- "$owned/.complete.$$" "$owned/complete"
}

read_credentials() {
    p11lab_no_credential_conflict P11LAB_PIN P11LAB_PIN_FILE
    p11lab_no_credential_conflict P11LAB_SO_PIN P11LAB_SO_PIN_FILE
    p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
    user_credential=$credential
    p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
    puk_credential=$credential
    # Native IsoApplet bounds, proven: the user PIN verifies at
    # 4..16 bytes and the SO-PUK (unblock code) is exactly 16 bytes
    # of any value (non-hex accepted). ETX (0x03) can never be
    # provisioned exactly (util_getpass treats it as EOF); NUL, CR
    # and LF are already refused by the shared secret primitive. The
    # supervisor re-enforces the same bounds and byte set.
    user_bytes=$(printf '%s' "$user_credential" | wc -c)
    [ "$user_bytes" -ge 4 ] && [ "$user_bytes" -le 16 ] || p11lab_die "user credential input must be 4..16 bytes (native IsoApplet bounds)"
    [ "$(printf '%s' "$puk_credential" | wc -c)" = 16 ] || p11lab_die "SO credential input must be exactly 16 bytes (native PUK length)"
    # Shellcheck SC3003/SC3037 would flag $'..' in POSIX sh; command
    # substitution carries the single ETX byte portably.
    case "$user_credential$puk_credential" in *"$(printf '\003')"*) p11lab_die "credential input contains an unsupported byte" ;; esac
    unset P11LAB_PIN P11LAB_SO_PIN credential user_bytes
}

run_tool() {
    # The bounded stdin record has one separator LF; the user secret is
    # 4..16 bytes and the PUK secret is 16 bytes, both single-line.
    # The supervisor reads and erases it before launching children.
    # Forward container signals and wait for cleanup.
    printf '%s\n%s' "$user_credential" "$puk_credential" | "$tool" "$@" &
    worker=$!
    unset user_credential puk_credential
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
        # Every card is fresh (RAM-only emulator), so a repeated init
        # provisions a fresh card exactly like the first one and
        # consumes credentials; it never resumes card state because
        # there is none. The marker only binds the configuration.
        if [ -e "$owned/complete" ]; then
            validate_static
            read_credentials
            run_tool health
            exit "$?"
        fi
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
        read_credentials
        run_tool health
        ;;
    exec)
        shift
        [ "${1-}" = -- ] || p11lab_die "exec requires -- followed by argv"
        shift
        [ "$#" -gt 0 ] || p11lab_die "exec requires an application"
        configure
        validate_static
        read_credentials
        # Shellcheck SC2086 would split the application argv; the tool
        # argv stays fixed here while exec preserves the caller argv
        # exactly through the supervisor.
        run_tool exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|health|exec -- ARGV..." ;;
esac
