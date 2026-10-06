#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
state=/var/lib/p11lab
owned=$state/rustssm
control=/run/p11lab
export RUSTSSM_DATABASE_URL=$owned/token.sqlite
export P11LAB_MODULE=/usr/local/lib/p11lab/librustssm.so
export P11LAB_LABEL="${P11LAB_LABEL-P11Lab}"
label=$P11LAB_LABEL
tool=/usr/local/bin/p11lab-rustssm

configure() {
    case "$label" in ''|*[!a-zA-Z0-9\ ._-]*) p11lab_die "label must use ASCII letters, digits, spaces, dot, underscore or hyphen" ;; esac
    [ "${#label}" -le 32 ] || p11lab_die "label exceeds 32 bytes"
    p11lab_writable_directory "$control"
    [ "$(stat -c %u "$control")" = "$(id -u)" ] || p11lab_die "control directory ownership mismatch"
    for file in expected-config expected-marker sqlite-header; do
        [ ! -L "$control/$file" ] || p11lab_die "configuration cannot be a symlink"
    done
    printf '%s\n' "RUSTSSM_DATABASE_URL=$RUSTSSM_DATABASE_URL" 'slot=0' 'backend=sqlite-wal' > "$control/config.$$"
    mv -f -- "$control/config.$$" "$control/expected-config"
    printf '%s\n' 'schema=1' 'provider=rustssm' "artifact=$(cat /usr/share/p11lab/runtime-id)" "label=$label" 'slot=0' 'backend=sqlite-wal' > "$control/marker.$$"
    mv -f -- "$control/marker.$$" "$control/expected-marker"
}

validate_static() {
    [ ! -L "$state" ] && [ -d "$state" ] || p11lab_die "partial or unsafe state"
    [ "$(stat -c %u "$state")" = "$(id -u)" ] || p11lab_die "state directory ownership mismatch"
    [ ! -L "$state/.init-lock" ] && [ ! -e "$state/.init-lock" ] || p11lab_die "state initialization is already in progress"
    [ ! -L "$owned" ] && [ -d "$owned" ] && [ -w "$owned" ] && [ -x "$owned" ] || p11lab_die "partial or unsafe owned state"
    [ "$(stat -c %u "$owned")" = "$(id -u)" ] || p11lab_die "owned directory ownership mismatch"
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name rustssm -print -quit
    p11lab_check_find empty "partial state: unknown or unsafe owned files" "$owned" -mindepth 1 -maxdepth 1 ! \( -type f \( -name complete -o -name rustssm.conf -o -name token.sqlite -o -name token.sqlite-journal -o -name token.sqlite-wal -o -name token.sqlite-shm \) \) -print -quit
    for file in "$owned"/*; do
        [ "$(stat -c %u "$file")" = "$(id -u)" ] || p11lab_die "owned file ownership mismatch"
        [ "$(stat -c %h "$file")" = 1 ] || p11lab_die "owned file cannot be a hard link"
    done
    for file in complete rustssm.conf token.sqlite; do
        [ -f "$owned/$file" ] && [ -s "$owned/$file" ] && [ -r "$owned/$file" ] || p11lab_die "partial state: missing provisioned file $file"
    done
    # Byte comparisons retain extra newlines and NULs. The config is a safety
    # record; RustSSM consumes the fixed namespaced environment value above.
    cmp -s -- "$control/expected-marker" "$owned/complete" || p11lab_die "incompatible non-secret initialization configuration"
    cmp -s -- "$control/expected-config" "$owned/rustssm.conf" || p11lab_die "incompatible non-secret initialization configuration"
    dd if="$owned/token.sqlite" of="$control/header.$$" bs=16 count=1 2>/dev/null || p11lab_die "cannot read token database"
    printf 'SQLite format 3\000' > "$control/sqlite-header"
    if ! cmp -s -- "$control/sqlite-header" "$control/header.$$"; then
        rm -f -- "$control/header.$$"
        p11lab_die "partial state: invalid SQLite token database"
    fi
    rm -f -- "$control/header.$$"
}

ready() {
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
        cp -- "$control/expected-config" "$owned/rustssm.conf"
        # Both printf calls are shell builtins. The helper consumes descriptors
        # 3/4 and wipes its buffers; credentials never enter child argv/env.
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
        # Serialize this finalized native preflight and all applications using
        # the same SQLite state. Parallel clients/shards need separate state.
        ready >/dev/null
        exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|health|exec -- ARGV..." ;;
esac
