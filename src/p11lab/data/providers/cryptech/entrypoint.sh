#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
state=/var/lib/p11lab
owned=$state/cryptech
control=/run/p11lab
tool=/usr/local/bin/p11lab-cryptech
export P11LAB_MODULE=/usr/local/lib/p11lab/libcryptech-pkcs11.so
export P11LAB_LABEL="${P11LAB_LABEL-Cryptech Token}"

configure() {
    [ "$P11LAB_LABEL" = 'Cryptech Token' ] || p11lab_die "token label is fixed to Cryptech Token"
    [ "${CRYPTECH_KEYSTORE_DIR-$owned}" = "$owned" ] || p11lab_die "CRYPTECH_KEYSTORE_DIR conflicts with managed state"
    export CRYPTECH_KEYSTORE_DIR=$owned
    # Optional inputs are assertions of the baked simulator credential. They
    # never provision or change a PIN; reject unequal inputs before opening HAL.
    for role in PIN SO_PIN; do
        scalar=P11LAB_$role
        file=P11LAB_${role}_FILE
        p11lab_no_credential_conflict "$scalar" "$file"
        eval 'supplied=${'"$scalar"'+x}${'"$file"'+x}'
        if [ -n "$supplied" ]; then
            p11lab_secret "$scalar" "$file"
            [ "$credential" = fnord ] || p11lab_die "caller credential does not match the fixed simulator PIN"
            unset credential
        fi
    done
    p11lab_writable_directory "$control"
    [ "$(stat -c %u "$control")" = "$(id -u)" ] || p11lab_die "control directory ownership mismatch"
    [ ! -L "$control/expected-marker" ] || p11lab_die "marker control cannot be a symlink"
    printf '%s\n' 'schema=1' 'provider=cryptech' "artifact=$(cat /usr/share/p11lab/runtime-id)" \
        'label=Cryptech Token' 'slot=0' 'backend=file-NOR-simulator' > "$control/marker.$$"
    mv -f -- "$control/marker.$$" "$control/expected-marker"
}

validate_static() {
    [ ! -L "$state" ] && [ -d "$state" ] || p11lab_die "partial or unsafe state"
    [ "$(stat -c %u "$state")" = "$(id -u)" ] || p11lab_die "state directory ownership mismatch"
    [ ! -L "$state/.init-lock" ] && [ ! -e "$state/.init-lock" ] || p11lab_die "state initialization is already in progress"
    [ ! -L "$owned" ] && [ -d "$owned" ] && [ -w "$owned" ] && [ -x "$owned" ] || p11lab_die "partial or unsafe owned state"
    [ "$(stat -c %u "$owned")" = "$(id -u)" ] || p11lab_die "owned directory ownership mismatch"
    [ "$(stat -c %a "$owned")" = 700 ] || p11lab_die "owned directory must have mode 0700"
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name cryptech -print -quit
    p11lab_check_find empty "partial state: unknown or unsafe owned files" "$owned" -mindepth 1 -maxdepth 1 ! \( -type f \( -name complete -o -name keystore.bin \) \) -print -quit
    for file in "$owned/complete" "$owned/keystore.bin"; do
        [ -f "$file" ] && [ -r "$file" ] && [ -s "$file" ] || p11lab_die "partial state: missing or empty provisioned file"
        [ "$(stat -c %u "$file")" = "$(id -u)" ] || p11lab_die "owned file ownership mismatch"
        [ "$(stat -c %h "$file")" = 1 ] || p11lab_die "owned file cannot be a hard link"
        [ "$(stat -c %a "$file")" = 600 ] || p11lab_die "owned file must have mode 0600"
    done
    cmp -s -- "$control/expected-marker" "$owned/complete" || p11lab_die "incompatible non-secret initialization configuration"
    [ "$(stat -c %s "$owned/keystore.bin")" = 524288 ] || p11lab_die "partial state: wrong NOR keystore size"
    # Read-only validation checks block headers/CRCs and exactly one live PIN
    # block before C_Initialize can repair/erase or create any provider state.
    "$tool" inspect "$owned/keystore.bin"
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
        configure
        [ ! -L "$state" ] || p11lab_die "state directory cannot be a symlink"
        if [ -e "$owned/complete" ] || [ -L "$owned/complete" ]; then ready; exit 0; fi
        if [ -e "$state" ]; then
            [ -d "$state" ] || p11lab_die "state path is not a directory"
            p11lab_check_find empty "partial state: refusing to initialize nonempty volume" "$state" -mindepth 1 -maxdepth 1 -print -quit
        fi
        p11lab_writable_directory "$state"
        [ "$(stat -c %u "$state")" = "$(id -u)" ] || p11lab_die "state directory ownership mismatch"
        mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
        trap 'rmdir "$state/.init-lock" 2>/dev/null || :' EXIT HUP INT TERM
        mkdir -m 700 "$owned"
        chmod u=rwx,go=,u-s,g-s "$owned"
        # Module-native C_Initialize creates the first NOR/PIN block. The helper
        # proves SO and user login; C_InitToken/C_InitPIN are unsupported.
        "$tool" init
        chmod u=rw,go=,u-s,g-s "$owned/keystore.bin"
        cp -- "$control/expected-marker" "$owned/.complete.$$"
        mv -- "$owned/.complete.$$" "$owned/complete"
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
        exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|health|exec -- ARGV..." ;;
esac
