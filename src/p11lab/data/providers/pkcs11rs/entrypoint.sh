#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
export LC_ALL=C
. /usr/share/p11lab/common.sh
# Reassign imported scalars before any child; pipe bytes supply native PINs.
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
owned=$state/pkcs11rs
token=$owned/tokens-v1/software-name-7031316c6162
control=/run/p11lab
tool=/usr/local/bin/p11lab-pkcs11rs
export P11LAB_MODULE=/usr/local/lib/p11lab/libpkcs11rs.so
export P11LAB_LABEL="${P11LAB_LABEL-P11Lab}"
label=$P11LAB_LABEL

configure() {
    case "$label" in ''|*[!a-zA-Z0-9\ ._-]*) p11lab_die "label must use ASCII letters, digits, spaces, dot, underscore or hyphen" ;; esac
    [ "${#label}" -le 32 ] || p11lab_die "label exceeds 32 bytes"
    [ "${PKCS11RS_TOKEN_STORAGE-$owned}" = "$owned" ] || p11lab_die "conflicting managed token directory"
    [ "${PKCS11RS_HARDWARE_DISCOVERY-0}" = 0 ] || p11lab_die "hardware discovery is excluded"
    [ "${PKCS11RS_SOFTWARE_SLOTS-p11lab}" = p11lab ] || p11lab_die "conflicting managed software slots"
    [ "${PKCS11RS_YUBIHSM_URLS+x}" != x ] || p11lab_die "remote YubiHSM devices are excluded"
    export PKCS11RS_TOKEN_STORAGE=$owned PKCS11RS_HARDWARE_DISCOVERY=0 PKCS11RS_SOFTWARE_SLOTS=p11lab
    p11lab_writable_directory "$control"
    [ ! -L "$control/expected-marker" ] || p11lab_die "control file cannot be a symlink"
    printf '%s\n' 'schema=1' 'provider=pkcs11rs' "artifact=$(cat /usr/share/p11lab/runtime-id)" \
        "label=$label" 'slot=0' 'software-name=p11lab' 'backend=encrypted-cbor' > "$control/marker.$$"
    mv -f -- "$control/marker.$$" "$control/expected-marker"
}

validate_static() {
    [ ! -L "$state" ] && [ -d "$state" ] || p11lab_die "partial or unsafe state"
    [ "$(stat -c %u "$state")" = "$(id -u)" ] || p11lab_die "state ownership mismatch"
    [ ! -L "$state/.init-lock" ] && [ ! -e "$state/.init-lock" ] || p11lab_die "state initialization is already in progress"
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name pkcs11rs -print -quit
    # Validate the complete fixed directory roster before C_Initialize can
    # create missing paths or apply native private-store permission changes.
    for directory in "$owned" "$owned/tokens-v1" "$token" "$token/private-keys-v1" \
        "$token/private-keys-v1/records" "$token/private-keys-v1/records/objects" \
        "$token/public-objects-v1" "$token/public-objects-v1/objects"; do
        [ ! -L "$directory" ] && [ -d "$directory" ] && [ -w "$directory" ] && [ -x "$directory" ] || p11lab_die "partial or unsafe owned directory"
        [ "$(stat -c %u "$directory")" = "$(id -u)" ] || p11lab_die "owned directory ownership mismatch"
        [ "$(stat -c %a "$directory")" = 700 ] || p11lab_die "owned directory permissions mismatch"
    done
    p11lab_check_find empty "partial state: unknown or unsafe owned files" "$owned" -regextype posix-extended -mindepth 1 \
        ! \( -type d \( -path "$owned/tokens-v1" -o -path "$token" -o -path "$token/private-keys-v1" \
        -o -path "$token/private-keys-v1/records" -o -path "$token/private-keys-v1/records/objects" \
        -o -path "$token/public-objects-v1" -o -path "$token/public-objects-v1/objects" \) \
        -o -type f \( -path "$owned/complete" -o -regex "$token/private-keys-v1/header-[0-9]{20}\.cbor" \
        -o -regex "$token/(private-keys-v1/records|public-objects-v1)/objects/sha3-256-[0-9a-f]{64}\.cbor" \) \) -print -quit
    p11lab_check_find empty "owned file ownership mismatch" "$owned" -mindepth 1 ! -uid "$(id -u)" -print -quit
    p11lab_check_find empty "unsafe owned file permissions, size or hard links" "$owned" -type f \
        ! \( -perm 600 -links 1 -size +0c ! -size +1048576c \) -print -quit
    [ -f "$owned/complete" ] && [ -r "$owned/complete" ] || p11lab_die "partial state: missing completion marker"
    p11lab_check_find present "partial state: missing token header" "$token/private-keys-v1" -regextype posix-extended \
        -maxdepth 1 -type f -regex '.*/header-[0-9]{20}\.cbor' -print -quit
    cmp -s -- "$control/expected-marker" "$owned/complete" || p11lab_die "incompatible non-secret initialization configuration"
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
        [ "${#credential}" -ge 8 ] && [ "${#credential}" -le 1024 ] || p11lab_die "user PIN must contain 8..1024 bytes"
        user_credential=$credential
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        [ "${#credential}" -ge 8 ] && [ "${#credential}" -le 1024 ] || p11lab_die "SO PIN must contain 8..1024 bytes"
        so_credential=$credential
        mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
        trap 'rmdir "$state/.init-lock" 2>/dev/null || :' EXIT HUP INT TERM
        mkdir -m 700 "$owned"
        chmod 00700 "$owned"
        # Default ACLs on a bind mount can override umask for native mkdir.
        # Create and seal every NEW directory ourselves; occupied state is
        # never chmod-ed or repaired by this adapter.
        for directory in "$owned/tokens-v1" "$token" "$token/private-keys-v1" \
            "$token/private-keys-v1/records" "$token/private-keys-v1/records/objects" \
            "$token/public-objects-v1" "$token/public-objects-v1/objects"; do
            mkdir -m 700 "$directory"
            chmod 00700 "$directory"
        done
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
