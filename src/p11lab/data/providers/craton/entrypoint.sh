#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
state=/var/lib/p11lab
owned=$state/craton
control=/run/p11lab
export CRATON_HSM_CONFIG=craton_hsm.toml
export P11LAB_MODULE=/usr/local/lib/p11lab/libcraton_hsm.so
export P11LAB_LABEL="${P11LAB_LABEL-P11Lab}"
label=$P11LAB_LABEL
tool=/usr/local/bin/p11lab-craton

configure() {
    [ "${CRATON_HSM_INTEGRITY_BYPASS-}" = unsafe-dev-only ] || p11lab_die "unsigned dev/test module requires explicit CRATON_HSM_INTEGRITY_BYPASS=unsafe-dev-only"
    [ "${CRATON_HSM_FIPS-0}" = 0 ] || p11lab_die "FIPS mode conflicts with this non-FIPS persistence configuration"
    case "$label" in ''|*[!a-zA-Z0-9\ ._-]*) p11lab_die "label must use ASCII letters, digits, spaces, dot, underscore or hyphen" ;; esac
    [ "${#label}" -le 32 ] || p11lab_die "label exceeds 32 bytes"
    p11lab_writable_directory "$control"
    [ "$(stat -c %u "$control")" = "$(id -u)" ] || p11lab_die "control directory ownership mismatch"
    for file in expected-config expected-marker redb-header; do
        [ ! -L "$control/$file" ] || p11lab_die "configuration cannot be a symlink"
    done
    printf '%s\n' '[token]' "label = \"$label\"" 'storage_path = "store"' 'persist_objects = true' 'slot_count = 1' '[audit]' 'enabled = false' > "$control/config.$$"
    mv -f -- "$control/config.$$" "$control/expected-config"
    printf '%s\n' 'schema=1' 'provider=craton' "artifact=$(cat /usr/share/p11lab/runtime-id)" "label=$label" 'slot=0' 'backend=encrypted-redb' 'config=craton_hsm.toml' 'storage=store' > "$control/marker.$$"
    mv -f -- "$control/marker.$$" "$control/expected-marker"
}

validate_static() {
    [ ! -L "$state" ] && [ -d "$state" ] || p11lab_die "partial or unsafe state"
    [ "$(stat -c %u "$state")" = "$(id -u)" ] || p11lab_die "state directory ownership mismatch"
    [ ! -L "$state/.init-lock" ] && [ ! -e "$state/.init-lock" ] || p11lab_die "state initialization is already in progress"
    for dir in "$owned" "$owned/store"; do
        [ ! -L "$dir" ] && [ -d "$dir" ] && [ -w "$dir" ] && [ -x "$dir" ] || p11lab_die "partial or unsafe owned state"
        [ "$(stat -c %u "$dir")" = "$(id -u)" ] || p11lab_die "owned directory ownership mismatch"
        [ "$(stat -c %a "$dir")" = 700 ] || p11lab_die "owned directory must have mode 0700"
    done
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name craton -print -quit
    p11lab_check_find empty "partial state: unknown or unsafe owned files" "$owned" -mindepth 1 -maxdepth 1 ! \( -type f \( -name complete -o -name craton_hsm.toml \) -o -type d -name store \) -print -quit
    p11lab_check_find empty "partial state: unknown or unsafe store files" "$owned/store" -mindepth 1 -maxdepth 1 ! \( -type f \( -name objects.redb -o -name objects.redb.lock -o -name token_state_0.json -o -name lockout_state.json \) \) -print -quit
    for file in "$owned/complete" "$owned/craton_hsm.toml" "$owned/store"/*; do
        [ -f "$file" ] && [ -r "$file" ] || p11lab_die "partial state: missing provisioned file"
        [ "$(stat -c %u "$file")" = "$(id -u)" ] || p11lab_die "owned file ownership mismatch"
        [ "$(stat -c %h "$file")" = 1 ] || p11lab_die "owned file cannot be a hard link"
        [ "$(stat -c %a "$file")" = 600 ] || p11lab_die "owned file must have mode 0600"
    done
    for file in complete craton_hsm.toml store/objects.redb store/token_state_0.json; do
        [ -s "$owned/$file" ] || p11lab_die "partial state: empty or missing provisioned file $file"
    done
    [ -f "$owned/store/objects.redb.lock" ] || p11lab_die "partial state: missing object-store lock file"
    cmp -s -- "$control/expected-marker" "$owned/complete" || p11lab_die "incompatible non-secret initialization configuration"
    cmp -s -- "$control/expected-config" "$owned/craton_hsm.toml" || p11lab_die "incompatible non-secret initialization configuration"
    # redb's documented on-disk magic; check before any native writable open.
    dd if="$owned/store/objects.redb" of="$control/header.$$" bs=9 count=1 2>/dev/null || p11lab_die "cannot read token database"
    printf 'redb\032\012\251\015\012' > "$control/redb-header"
    if ! cmp -s -- "$control/redb-header" "$control/header.$$"; then
        rm -f -- "$control/header.$$"
        p11lab_die "partial state: invalid redb token database"
    fi
    rm -f -- "$control/header.$$"
}

ready() {
    validate_static
    # Relative config and storage paths are resolved from this fixed CWD.
    (cd "$owned" && "$tool" health)
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
        configure
        [ ! -L "$state" ] || p11lab_die "state directory cannot be a symlink"
        if [ -e "$owned/complete" ] || [ -L "$owned/complete" ]; then ready; exit 0; fi
        if [ -e "$state" ]; then
            [ -d "$state" ] || p11lab_die "state path is not a directory"
            p11lab_check_find empty "partial state: refusing to initialize nonempty volume" "$state" -mindepth 1 -maxdepth 1 -print -quit
        fi
        p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
        user_credential=$credential
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        so_credential=$credential
        p11lab_writable_directory "$state"
        [ "$(stat -c %u "$state")" = "$(id -u)" ] || p11lab_die "state directory ownership mismatch"
        mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
        trap 'rmdir "$state/.init-lock" 2>/dev/null || :' EXIT HUP INT TERM
        mkdir -m 700 "$owned"
        # Explicit mode also limits a bind mount's inherited default ACL mask;
        # umask alone does not constrain upstream create_dir_all in that case.
        mkdir -m 700 "$owned/store"
        chmod u=rwx,go=,u-s,g-s "$owned" "$owned/store"
        cp -- "$control/expected-config" "$owned/craton_hsm.toml"
        cd "$owned"
        # Builtin printf and anonymous pipes keep PINs out of child argv/env,
        # persistent configuration, markers and receipts. No auto-init patch.
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
        ready
        ;;
    exec)
        shift
        [ "${1-}" = -- ] || p11lab_die "exec requires -- followed by argv"
        shift
        [ "$#" -gt 0 ] || p11lab_die "exec requires an application"
        configure
        ready >/dev/null
        cd "$owned"
        exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|health|exec -- ARGV..." ;;
esac
