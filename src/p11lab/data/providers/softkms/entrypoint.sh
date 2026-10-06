#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
tool=/usr/local/bin/p11lab-softkms
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

# These controls could redirect the module, its daemon, TLS or native state.
# The supported configuration is fixed and applied after rejecting overrides.
for name in SOFTKMS_DAEMON_ADDR SOFTKMS_PKCS11_CONFIG SOFTKMS_GRPC_ADDR SOFTKMS_REST_ADDR \
    SOFTKMS_STORAGE_PATH SOFTKMS_TLS_CERT SOFTKMS_TLS_KEY SOFTKMS_TLS_CLIENT_CA \
    SOFTKMS_ALLOW_INSECURE_BIND SOFTKMS_LOG_FORMAT \
    RUST_LOG RUST_LOG_STYLE RUST_BACKTRACE LD_PRELOAD LD_LIBRARY_PATH \
    SSL_CERT_FILE SSL_CERT_DIR OPENSSL_CONF; do
    eval 'present=${'"$name"'+x}'
    [ "$present" != x ] || p11lab_die "unsupported native override: $name"
done
export P11LAB_MODULE=/usr/local/lib/p11lab/libsoftkms.so
export P11LAB_LABEL="${P11LAB_LABEL-softKMS}"
# The native token label is fixed to softKMS; binding any other label would
# misdescribe the token, so only the native value is accepted.
[ "$P11LAB_LABEL" = softKMS ] || p11lab_die "label is fixed to softKMS natively"

if [ "$1" = init ]; then
    p11lab_no_credential_conflict P11LAB_PIN P11LAB_PIN_FILE
    p11lab_no_credential_conflict P11LAB_SO_PIN P11LAB_SO_PIN_FILE
    # There is no distinct security-officer credential: native C_Login(CKU_SO)
    # succeeds with the identity token, exactly like CKU_USER. An SO input is
    # shape-checked for contract compatibility but its value is never used.
    if [ "${P11LAB_SO_PIN+x}" = x ] || [ "${P11LAB_SO_PIN_FILE+x}" = x ]; then
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        unset credential
    fi
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
    LC_ALL=C
    export LC_ALL
    [ "${#user_credential}" -ge 32 ] && [ "${#user_credential}" -le 200 ] || p11lab_die "softKMS admin passphrase requires 32..200 ASCII characters"
    case "$user_credential" in *[!\ -~]*) p11lab_die "passphrase must use printable ASCII" ;; esac
    unset credential P11LAB_PIN P11LAB_SO_PIN
    # Only a private anonymous pipe carries the admin passphrase. Forward
    # signals to the C supervisor, which owns and reaps the daemon.
    printf '%s\n' "$user_credential" | "$tool" init &
    supervisor=$!
    unset user_credential
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
