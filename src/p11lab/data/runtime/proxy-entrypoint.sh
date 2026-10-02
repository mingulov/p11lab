#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Provider-plus-daemon lifecycle. Provider init/health/exec/describe delegate
# unchanged to the provider adapter; daemon/cli add the pinned mTLS transport.
set -eu
umask 077
p11lab_proxy_die() { printf '%s\n' "p11lab-proxy: $*" >&2; exit 1; }

p11lab_proxy_server_material() {
    for file in /run/p11lab-tls/ca.crt /run/p11lab-tls/server.crt; do
        [ -f "$file" ] && [ ! -L "$file" ] && [ -r "$file" ] || p11lab_proxy_die "server TLS file is not a readable regular file: $file"
        [ "$(stat -c %u "$file")" = "$(id -u)" ] || p11lab_proxy_die "server TLS file ownership mismatch: $file"
        [ -z "$(find "$file" -perm -002 -print -quit)" ] || p11lab_proxy_die "server TLS certificate must not be world-writable: $file"
    done
    key=/run/p11lab-tls/server.key
    [ -f "$key" ] && [ ! -L "$key" ] && [ -r "$key" ] || p11lab_proxy_die "server TLS key is not a readable regular file"
    [ "$(stat -c %u "$key")" = "$(id -u)" ] || p11lab_proxy_die "server TLS key ownership mismatch"
    [ -z "$(find "$key" -perm /077 -print -quit)" ] || p11lab_proxy_die "server TLS key must have no group/other permissions"
}

case "${1-}" in
    describe|init|health|exec) exec /usr/local/bin/p11lab-provider "$@" ;;
    daemon)
        [ "$#" -eq 2 ] || p11lab_proxy_die "usage: p11lab-proxy daemon /etc/p11lab/proxy.toml"
        case "$2" in /*) ;; *) p11lab_proxy_die "daemon config must be an absolute path" ;; esac
        [ -f "$2" ] && [ ! -L "$2" ] && [ -r "$2" ] || p11lab_proxy_die "daemon config is not a readable regular file"
        p11lab_proxy_server_material
        # Provider configuration mirrors p11lab-provider configure(): the daemon
        # loads the provider in-process, so SOFTHSM2_CONF must exist here.
        control=/run/p11lab
        [ ! -L "$control/softhsm2.conf" ] || p11lab_proxy_die "configuration cannot be a symlink"
        mkdir -p -- "$control" || p11lab_proxy_die "cannot create control directory"
        printf '%s\n' "directories.tokendir = /var/lib/p11lab/softhsm2/tokens" 'objectstore.backend = file' 'log.level = ERROR' 'slots.removable = false' > "$control/daemon-config.$$"
        mv -f -- "$control/daemon-config.$$" "$control/softhsm2.conf"
        export SOFTHSM2_CONF=$control/softhsm2.conf
        exec /usr/local/bin/pkcs11-proxy-ng "$2"
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
