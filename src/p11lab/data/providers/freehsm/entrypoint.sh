#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
state=/var/lib/p11lab
owned=$state/freehsm
control=/run/p11lab
export FHSM_TOKENS_DIR=$owned
# Documented upstream dev-mode (no trixie FIPS provider exists, so stock
# initialization cannot run here; see provider constraints). The module
# self-identifies these runs as token model FreeHSM-TESTMODE.
export FHSM_INTEGRITY_ALLOW_UNSIGNED=1
export FHSM_KAT_ALLOW_FAIL=1
export P11LAB_MODULE=/usr/local/lib/p11lab/libfreehsm.so
tool=/usr/local/bin/fhsm-token

configure() {
    p11lab_writable_directory "$control"
}

expected_marker() {
    printf '%s\n' 'schema=1' 'provider=freehsm' "artifact=$(cat /usr/share/p11lab/runtime-id)" 'token=P11Lab' 'backend=tok'
}

allowed_owned() {
    # Token state plus the module's append-only audit traces (one audit.log
    # segment per process). Anything else is foreign or partial state.
    case "$1" in
        complete|slot0.tok|audit.key|audit.log.*) return 0 ;;
        *) return 1 ;;
    esac
}

complete() {
    [ ! -L "$owned" ] && [ ! -L "$owned/complete" ] || p11lab_die "partial or unsafe state"
    [ -f "$owned/complete" ] || p11lab_die "partial state: missing completion marker"
    [ "$(cat "$owned/complete")" = "$(expected_marker)" ] || p11lab_die "incompatible non-secret initialization configuration"
    for file in slot0.tok audit.key; do
        [ ! -L "$owned/$file" ] || p11lab_die "partial or unsafe state"
        [ -f "$owned/$file" ] && [ -s "$owned/$file" ] || p11lab_die "partial state: missing token file $file"
    done
    [ -z "$(find "$state" -mindepth 1 -maxdepth 1 ! -name freehsm -print -quit)" ] || p11lab_die "partial state: unknown files"
    for entry in "$owned"/*; do
        [ -e "$entry" ] || continue
        [ ! -L "$entry" ] || p11lab_die "partial or unsafe state"
        allowed_owned "$(basename "$entry")" || p11lab_die "partial state: unknown owned files"
    done
    if info=$("$tool" info --slot 0 --module "$P11LAB_MODULE" 2>&1); then
        # This pinned stock utility opens the real token; key authentication
        # stays with the application login, as with SoftHSM.
        label=$(printf '%s\n' "$info" | sed -n 's/^  label *//p')
        [ "$label" = P11Lab ] || p11lab_die "incompatible token label"
        token_info=$info
    else
        status=$?
        printf '%s\n' 'p11lab: native token health check failed' "$info" >&2
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
        if [ -e "$owned/slot0.tok" ]; then p11lab_die "partial state: token file without completion marker; refusing to reinitialize"; fi
        if [ -e "$owned" ]; then
            for entry in "$owned"/*; do
                [ -e "$entry" ] || continue
                case "$(basename "$entry")" in
                    audit.key|audit.log.*) ;;
                    *) p11lab_die "partial state: refusing to initialize nonempty volume" ;;
                esac
            done
        fi
        [ -z "$(find "$state" -mindepth 1 -maxdepth 1 ! -name freehsm -print -quit)" ] || p11lab_die "partial state: refusing to initialize nonempty volume"
        expected_marker > "$control/marker.$$"
        p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
        user_credential=$credential
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        so_credential=$credential
        mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
        trap 'rmdir "$state/.init-lock" 2>/dev/null || :; rm -f "$control/marker.$$" "$control/init.$$"' EXIT HUP INT TERM
        mkdir -p -m 700 "$owned"
        # fhsm-token takes PINs from its documented environment inputs only,
        # never from argv; inline assignment keeps them out of ps and logs.
        # It also refuses an initialized token without --force, so a slot
        # that appears between the check above and this call still fails
        # instead of being wiped.
        if FHSM_SO_PIN="$so_credential" FHSM_PIN="$user_credential" \
                "$tool" init --label P11Lab --slot 0 --module "$P11LAB_MODULE" > "$control/init.$$" 2>&1; then
            cp -- "$control/marker.$$" "$owned/.complete.$$"
            mv -- "$owned/.complete.$$" "$owned/complete"
        else
            status=$?
            printf '%s\n' 'p11lab: native token initialization failed; partial state retained' >&2
            cat -- "$control/init.$$" >&2
            exit "$status"
        fi
        ;;
    health)
        [ "$#" -eq 1 ] || p11lab_die "health takes no arguments"
        configure
        complete
        printf '%s\n' "$token_info"
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
