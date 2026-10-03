#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
tool=/usr/local/bin/p11lab-nethsm
case "${1-}" in
    describe)
        [ "$#" -eq 1 ] || p11lab_die "describe takes no arguments"
        cat /usr/share/p11lab/provider.json
        exit 0
        ;;
    init|health) [ "$#" -eq 1 ] || p11lab_die "operation takes no arguments" ;;
    exec) [ "$#" -ge 3 ] && [ "$2" = -- ] || p11lab_die "exec requires -- followed by argv" ;;
    *) p11lab_die "usage: describe|init|health|exec -- ARGV..." ;;
esac

# These controls could redirect the module, its logs, TLS or native state.
# The supported configuration is fixed and applied after rejecting overrides.
for name in P11NETHSM_CONFIG_FILE P11NETHSM_CONFIG_DIR P11NETHSM_LOG_FILE \
    P11NETHSM_LOG_LEVEL RUST_LOG RUST_LOG_STYLE RUST_BACKTRACE LD_PRELOAD LD_LIBRARY_PATH \
    SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE NETHSM_CONFIG_FILE ETCD_DATA_DIR \
    ETCD_LISTEN_CLIENT_URLS ETCD_LISTEN_PEER_URLS ADMINPW UNLOCKPW DEBUG_LOG; do
    eval 'present=${'"$name"'+x}'
    [ "$present" != x ] || p11lab_die "unsupported native override: $name"
done
export P11LAB_MODULE=/usr/local/lib/p11lab/libnethsm_pkcs11.so
export P11NETHSM_CONFIG_FILE=/var/lib/p11lab/nethsm/p11nethsm.conf
export P11LAB_LABEL="${P11LAB_LABEL-P11Lab}"
case "$P11LAB_LABEL" in ''|*[!a-zA-Z0-9\ ._-]*) p11lab_die "label requires ASCII letters, digits, spaces, dot, underscore or hyphen" ;; esac
[ "${#P11LAB_LABEL}" -le 32 ] || p11lab_die "label exceeds 32 bytes"

if [ "$1" = init ]; then
    p11lab_no_credential_conflict P11LAB_PIN P11LAB_PIN_FILE
    p11lab_no_credential_conflict P11LAB_SO_PIN P11LAB_SO_PIN_FILE
    # Static validation, including an existing completion marker, precedes
    # secret input. Repeated init preserves native credentials and objects.
    if "$tool" existing; then
        unset P11LAB_PIN P11LAB_SO_PIN
        exec "$tool" health
    else
        status=$?
        [ "$status" -eq 10 ] || exit "$status"
    fi
    p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
    user_credential=$credential
    p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
    so_credential=$credential
    LC_ALL=C
    export LC_ALL
    for credential in "$user_credential" "$so_credential"; do
        [ "${#credential}" -ge 10 ] && [ "${#credential}" -le 200 ] || p11lab_die "NetHSM passphrases require 10..200 ASCII characters"
        case "$credential" in *[!\ -~]*) p11lab_die "passphrase must use printable ASCII" ;; esac
    done
    unset credential P11LAB_PIN P11LAB_SO_PIN
    # Only a private anonymous pipe carries the operator/admin passphrases.
    # Forward signals to the C supervisor, which owns and reaps all services.
    printf '%s\n%s\n' "$user_credential" "$so_credential" | "$tool" init &
    supervisor=$!
    unset user_credential so_credential
    trap 'kill -TERM "$supervisor" 2>/dev/null || :' TERM
    trap 'kill -INT "$supervisor" 2>/dev/null || :' INT
    set +e
    wait "$supervisor"
    status=$?
    # wait can be interrupted before the supervisor has performed cleanup.
    if kill -0 "$supervisor" 2>/dev/null; then wait "$supervisor"; status=$?; fi
    exit "$status"
fi
unset P11LAB_PIN P11LAB_SO_PIN
exec "$tool" "$@"
