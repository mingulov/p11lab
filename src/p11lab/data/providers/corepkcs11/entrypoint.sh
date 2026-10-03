#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
export P11LAB_MODULE=/usr/local/lib/p11lab/libcore_pkcs.so
export P11LAB_LABEL="${P11LAB_LABEL-P11Lab}"

validate_controls() {
    # This is an application/object label hint, NOT a configurable token label.
    # Upstream C_GetTokenInfo and C_InitToken ignore their output/inputs.
    case "$P11LAB_LABEL" in ''|*[!a-zA-Z0-9\ ._-]*) p11lab_die "label must use ASCII letters, digits, spaces, dot, underscore or hyphen" ;; esac
    [ "${#P11LAB_LABEL}" -le 32 ] || p11lab_die "label exceeds 32 bytes"
    p11lab_no_credential_conflict P11LAB_PIN P11LAB_PIN_FILE
    p11lab_no_credential_conflict P11LAB_SO_PIN P11LAB_SO_PIN_FILE
    if [ "${P11LAB_PIN+x}${P11LAB_PIN_FILE+x}" != '' ]; then
        p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
        unset credential
    fi
    if [ "${P11LAB_SO_PIN+x}${P11LAB_SO_PIN_FILE+x}" != '' ]; then
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        unset credential
    fi
    # No state files, initialization markers, token reset or separate-process
    # native preflight. Applications call C_Initialize in their own process.
    [ -r "$P11LAB_MODULE" ] || p11lab_die "module is not readable"
}

case "${1-}" in
    describe)
        [ "$#" -eq 1 ] || p11lab_die "describe takes no arguments"
        cat /usr/share/p11lab/provider.json
        ;;
    init)
        [ "$#" -eq 1 ] || p11lab_die "init takes no arguments"
        validate_controls
        printf '%s\n' 'config validated; no token provisioned; state_mode=process-local; native PIN authentication is absent'
        ;;
    health)
        [ "$#" -eq 1 ] || p11lab_die "health takes no arguments"
        validate_controls
        # This standalone process checks module open/session/RNG usability only.
        # It cannot assert readiness or object state in the application's token.
        exec /usr/local/bin/p11lab-corepkcs11 health
        ;;
    exec)
        shift
        [ "${1-}" = -- ] || p11lab_die "exec requires -- followed by argv"
        shift
        [ "$#" -gt 0 ] || p11lab_die "exec requires an application"
        validate_controls
        exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|health|exec -- ARGV..." ;;
esac
