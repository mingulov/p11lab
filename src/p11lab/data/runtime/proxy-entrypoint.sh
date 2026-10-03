#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Provider-plus-daemon lifecycle. Provider init/health/exec/describe delegate
# unchanged to the provider adapter; daemon/cli add the pinned mTLS transport.
set -eu
umask 077
. /usr/share/p11lab/common.sh
p11lab_proxy_die() { printf '%s\n' "p11lab-proxy: $*" >&2; exit 1; }

p11lab_proxy_server_material() {
    for file in /run/p11lab-tls/ca.crt /run/p11lab-tls/server.crt; do
        [ -f "$file" ] && [ ! -L "$file" ] && [ -r "$file" ] || p11lab_proxy_die "server TLS file is not a readable regular file: $file"
        [ "$(stat -c %u "$file")" = "$(id -u)" ] || p11lab_proxy_die "server TLS file ownership mismatch: $file"
        p11lab_check_find empty "server TLS certificate must not be world-writable: $file" "$file" -perm -002 -print -quit
    done
    key=/run/p11lab-tls/server.key
    [ -f "$key" ] && [ ! -L "$key" ] && [ -r "$key" ] || p11lab_proxy_die "server TLS key is not a readable regular file"
    [ "$(stat -c %u "$key")" = "$(id -u)" ] || p11lab_proxy_die "server TLS key ownership mismatch"
    p11lab_check_find empty "server TLS key must have no group/other permissions" "$key" -perm /077 -print -quit
}

case "${1-}" in
    describe|init|health|exec) exec /usr/local/bin/p11lab-provider "$@" ;;
    daemon)
        [ "$#" -eq 2 ] || p11lab_proxy_die "usage: p11lab-proxy daemon /etc/p11lab/proxy.toml"
        case "$2" in /*) ;; *) p11lab_proxy_die "daemon config must be an absolute path" ;; esac
        [ -f "$2" ] && [ ! -L "$2" ] && [ -r "$2" ] || p11lab_proxy_die "daemon config is not a readable regular file"
        p11lab_proxy_server_material
        # Provider configuration is owned by the provider adapter: launching
        # the daemon through `p11lab-provider exec` applies the exact same
        # generated controls and environment as every other lifecycle phase
        # (SoftHSM writes its softhsm2.conf there; NSS writes its params
        # file; FreeHSM exports FHSM_*), for every present and future
        # provider. No provider-specific configuration lives in this script.
        exec /usr/local/bin/p11lab-provider exec -- /usr/local/bin/pkcs11-proxy-ng "$2"
        ;;
    cli)
        shift
        [ "$#" -gt 0 ] || p11lab_proxy_die "usage: p11lab-proxy cli --endpoint ... health"
        exec /usr/local/bin/pkcs11-proxy-ng-cli "$@"
        ;;
    proxy-build)
        [ "$#" -eq 1 ] || p11lab_proxy_die "proxy-build takes no arguments"
        cat /usr/share/p11lab/proxy/build.json
        ;;
    *) p11lab_proxy_die "usage: p11lab-proxy describe|init|health|exec -- ARGV...|daemon CONFIG|cli ARGS...|proxy-build" ;;
esac
