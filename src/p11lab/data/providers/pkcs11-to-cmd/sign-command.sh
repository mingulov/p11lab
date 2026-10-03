#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# P11Lab wiring only. Run upstream's byte-exact script in the private IO
# directory because its ECDSA conversion uses relative r.bin/s.bin files.
set -eu
umask 077
. /usr/share/p11lab/common.sh
sign_dir=${P2C_DATA%/data.bin}
suffix=${sign_dir#/run/p11lab/p2c.}
case "$suffix" in ''|*[!a-zA-Z0-9]*) p11lab_die "invalid private signing directory" ;; esac
[ "${#suffix}" -eq 10 ] && [ "$sign_dir" = "/run/p11lab/p2c.$suffix" ] || p11lab_die "invalid private signing directory"
[ "$P2C_SIG" = "$sign_dir/signature.bin" ] || p11lab_die "signature path conflicts with signing directory"
[ ! -L "$sign_dir" ] && [ -d "$sign_dir" ] && [ "$(stat -c %u "$sign_dir")" = "$(id -u)" ] && [ "$(stat -c %a "$sign_dir")" = 700 ] || p11lab_die "signing directory must be private and caller-owned"
for file in "$P2C_DATA" "$P2C_SIG"; do
    [ ! -L "$file" ] || p11lab_die "signing files cannot be links"
    if [ -e "$file" ]; then
        [ -f "$file" ] && [ "$(stat -c %h "$file")" = 1 ] && [ "$(stat -c %u "$file")" = "$(id -u)" ] && [ "$(stat -c %a "$file")" = 600 ] || p11lab_die "signing files must be private and caller-owned"
    fi
done
cd -- "$sign_dir"
exec /usr/local/libexec/p11lab/pkcs11-to-cmd-sign
