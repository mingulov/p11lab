#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
tool=/usr/local/bin/p11lab-kmsp11
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

# These controls could redirect the module, its config, logs or native state.
# The supported configuration is fixed and applied after rejecting overrides.
for name in KMS_PKCS11_CONFIG GRPC_GO_LOG_SEVERITY_LEVEL GRPC_GO_LOG_VERBOSITY_LEVEL \
    GRPC_TRACE GRPC_VERBOSITY GODEBUG GOTRACEBACK LD_PRELOAD LD_LIBRARY_PATH \
    SSL_CERT_FILE SSL_CERT_DIR OPENSSL_CONF; do
    eval 'present=${'"$name"'+x}'
    [ "$present" != x ] || p11lab_die "unsupported native override: $name"
done
export P11LAB_MODULE=/usr/local/lib/p11lab/libkmsp11.so
export P11LAB_LABEL="${P11LAB_LABEL-P11Lab}"
case "$P11LAB_LABEL" in ''|*[!a-zA-Z0-9\ ._-]*) p11lab_die "label requires ASCII letters, digits, spaces, dot, underscore or hyphen" ;; esac
[ "${#P11LAB_LABEL}" -le 32 ] || p11lab_die "label exceeds 32 bytes"

# The module has no security-officer role: the token presents SO as
# PIN-locked and native C_Login(CKU_SO) is CKR_PIN_LOCKED, so an SO
# credential cannot be provisioned.
if [ "${P11LAB_SO_PIN+x}" = x ] || [ "${P11LAB_SO_PIN_FILE+x}" = x ]; then
    p11lab_die "SO PIN has no native meaning for this provider"
fi
# A caller PIN is accepted for contract compatibility but ignored natively:
# C_Login(CKU_USER) succeeds with any value. Shape is still validated so a
# malformed secret file fails fast instead of being silently ignored.
if [ "${P11LAB_PIN+x}" = x ] || [ "${P11LAB_PIN_FILE+x}" = x ]; then
    p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
    unset credential
fi
unset P11LAB_PIN P11LAB_SO_PIN

if [ "$1" = init ]; then
    # Static validation, including an existing completion marker, precedes
    # any native launch. Repeated init preserves the marker and ignores
    # changed credential inputs.
    if "$tool" existing; then
        exec "$tool" health
    else
        status=$?
        [ "$status" -eq 10 ] || exit "$status"
    fi
    # No secret travels to the supervisor: provisioning needs no PIN.
    # Provisioning recreates every key per launch; upstream fakekms reuses
    # fixed RSA test vectors while EC/HMAC keys draw fresh random material.
    # Forward signals to the C supervisor, which owns and reaps fakekms.
    "$tool" init &
    supervisor=$!
    trap 'kill -TERM "$supervisor" 2>/dev/null || :' TERM
    trap 'kill -INT "$supervisor" 2>/dev/null || :' INT
    set +e
    wait "$supervisor"
    status=$?
    # wait can be interrupted before the supervisor has performed cleanup.
    if kill -0 "$supervisor" 2>/dev/null; then wait "$supervisor"; status=$?; fi
    exit "$status"
fi
exec "$tool" "$@"
