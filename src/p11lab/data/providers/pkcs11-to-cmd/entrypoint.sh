#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
state=/var/lib/p11lab
owned=$state/pkcs11-to-cmd
control=/run/p11lab
tool=/usr/local/bin/p11lab-p2c-health
run_dir=
locked=0

cleanup() {
    if [ "$locked" = 1 ]; then rmdir -- "$state/.init-lock"; fi
    if [ -n "$run_dir" ]; then rm -rf -- "$run_dir"; fi
}

fixed_control() {
    # Names are adapter constants; never evaluate caller text as shell code.
    eval 'present=${'"$1"'+x}; value=${'"$1"'-}'
    [ "$present" != x ] || [ "$value" = "$2" ] || p11lab_die "native wiring conflicts with managed state"
    export "$1=$2"
}

configure() {
    for name in P11LAB_PIN P11LAB_PIN_FILE P11LAB_SO_PIN P11LAB_SO_PIN_FILE P11LAB_LABEL; do
        eval 'present=${'"$name"'+x}'
        [ "$present" != x ] || p11lab_die "this signer has no PIN or selectable token label"
    done
    fixed_control P2C_SLOT_CERT_0 "$owned/rsa.pem"
    fixed_control P2C_SLOT_CERT_2 "$owned/ec.pem"
    fixed_control P2C_CMD /usr/local/bin/p11lab-p2c-sign
    fixed_control P2C_DEBUG 0
    for name in P2C_SLOT_CERT_1 P2C_SLOT_CERT_3 P2C_SLOT_CERT_4 P2C_SLOT_CERT_5 P2C_SLOT_CERT_6 P2C_SLOT_CERT_7 P2C_SLOT_CERT_8 P2C_SLOT_CERT_9 P2C_DATA P2C_SIG P2C_CERT P2C_MECHANISM; do
        eval 'present=${'"$name"'+x}'
        [ "$present" != x ] || p11lab_die "native wiring conflicts with private per-invocation paths"
    done
    export P11LAB_MODULE=/usr/local/lib/p11lab/libpkcs11-to-cmd.so
    p11lab_writable_directory "$control"
    [ "$(stat -c %u "$control")" = "$(id -u)" ] && [ "$(stat -c %a "$control")" = 700 ] || p11lab_die "control directory must be owned and private"
    run_dir=$(mktemp -d "$control/p2c.XXXXXXXXXX") || p11lab_die "cannot reserve private signing directory"
    chmod 700 "$run_dir"
    trap cleanup 0
    trap 'exit 1' HUP INT TERM
    export P2C_DATA="$run_dir/data.bin" P2C_SIG="$run_dir/signature.bin"
    printf '%s\n' "P2C_SLOT_CERT_0=$P2C_SLOT_CERT_0" "P2C_SLOT_CERT_2=$P2C_SLOT_CERT_2" "P2C_CMD=$P2C_CMD" 'P2C_DEBUG=0' > "$run_dir/wiring"
    printf '%s\n' 'schema=1' 'provider=pkcs11-to-cmd' "artifact=$(cat /usr/share/p11lab/runtime-id)" \
        'auth=none' 'slot_0=RSA-2048' 'slot_1=empty' 'slot_2=P-256' 'keys=runtime-generated' > "$run_dir/marker"
}

validate_root() {
    [ ! -L "$state" ] && [ -d "$state" ] && [ -w "$state" ] && [ -x "$state" ] || p11lab_die "partial or unsafe state directory"
    [ "$(stat -c %u "$state")" = "$(id -u)" ] || p11lab_die "state directory ownership mismatch"
    [ ! -L "$state/.init-lock" ] && [ ! -e "$state/.init-lock" ] || p11lab_die "state initialization is already in progress"
}

validate_static() {
    validate_root
    [ ! -L "$owned" ] && [ -d "$owned" ] && [ -w "$owned" ] && [ -x "$owned" ] || p11lab_die "partial or unsafe owned state"
    [ "$(stat -c %u "$owned")" = "$(id -u)" ] && [ "$(stat -c %a "$owned")" = 700 ] || p11lab_die "owned state must be private and caller-owned"
    p11lab_check_find empty "partial state: unexpected root entry" "$state" -mindepth 1 -maxdepth 1 ! -name pkcs11-to-cmd -print -quit
    p11lab_check_find empty "partial state: unexpected or linked file" "$owned" -mindepth 1 -maxdepth 1 ! \( -type f \( -name rsa.key -o -name rsa.pem -o -name ec.key -o -name ec.pem -o -name wiring.env -o -name complete \) \) -print -quit
    for name in rsa.key rsa.pem ec.key ec.pem wiring.env complete; do
        file=$owned/$name
        [ -f "$file" ] && [ -r "$file" ] && [ -s "$file" ] || p11lab_die "partial state: provisioned file missing or empty"
        [ "$(stat -c %u "$file")" = "$(id -u)" ] && [ "$(stat -c %a "$file")" = 600 ] || p11lab_die "owned files must be private and caller-owned"
        [ "$(stat -c %h "$file")" = 1 ] || p11lab_die "owned files cannot be hard links"
        [ "$(stat -c %s "$file")" -le 16384 ] || p11lab_die "owned file exceeds bound"
    done
    cmp -s -- "$run_dir/marker" "$owned/complete" || p11lab_die "incompatible non-secret completion marker"
    cmp -s -- "$run_dir/wiring" "$owned/wiring.env" || p11lab_die "incompatible non-secret wiring"
}

validate_pairs() {
    for key in rsa ec; do
        openssl pkey -in "$owned/$key.key" -check -noout >/dev/null 2>&1 || p11lab_die "invalid private key"
        openssl pkey -in "$owned/$key.key" -pubout -out "$run_dir/$key.key-public" 2>/dev/null || p11lab_die "cannot read private key"
        openssl x509 -in "$owned/$key.pem" -pubkey -noout > "$run_dir/$key.cert-public" 2>/dev/null || p11lab_die "invalid certificate"
        cmp -s -- "$run_dir/$key.key-public" "$run_dir/$key.cert-public" || p11lab_die "certificate and signing key disagree"
        openssl pkey -pubin -in "$run_dir/$key.key-public" -text -noout > "$run_dir/$key.public-info" 2>/dev/null || p11lab_die "cannot inspect public key"
        case "$key" in
            rsa) grep -q '^Public-Key: (2048 bit)$' "$run_dir/$key.public-info" || p11lab_die "RSA key must be 2048 bits" ;;
            ec) grep -q '^ASN1 OID: prime256v1$' "$run_dir/$key.public-info" || p11lab_die "EC key must be P-256" ;;
        esac
    done
}

ready() {
    validate_static
    validate_pairs
    "$tool"
}

case "${1-}" in
    describe)
        [ "$#" -eq 1 ] || p11lab_die "describe takes no arguments"
        cat /usr/share/p11lab/provider.json
        ;;
    init)
        [ "$#" -eq 1 ] || p11lab_die "init takes no arguments"
        configure
        p11lab_writable_directory "$state"
        validate_root
        if [ -e "$owned" ] || [ -L "$owned" ]; then ready; exit 0; fi
        p11lab_check_find empty "partial state: refusing occupied directory" "$state" -mindepth 1 -maxdepth 1 -print -quit
        mkdir -- "$state/.init-lock" || p11lab_die "state initialization is already in progress"
        locked=1
        mkdir -- "$owned"
        chmod 700 "$owned"
        # Seal modes before OpenSSL writes any private material, including on
        # filesystems with inherited default ACLs.
        : > "$owned/rsa.key"
        : > "$owned/ec.key"
        chmod 600 "$owned/rsa.key" "$owned/ec.key"
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$owned/rsa.key" 2>/dev/null || p11lab_die "RSA key generation failed; partial state retained"
        openssl req -new -x509 -key "$owned/rsa.key" -out "$owned/rsa.pem" -days 3650 -subj /CN=P11Lab-p2c-RSA || p11lab_die "RSA certificate generation failed"
        openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$owned/ec.key" || p11lab_die "P-256 key generation failed"
        openssl req -new -x509 -key "$owned/ec.key" -out "$owned/ec.pem" -days 3650 -subj /CN=P11Lab-p2c-EC || p11lab_die "P-256 certificate generation failed"
        cp -- "$run_dir/wiring" "$owned/wiring.env"
        chmod 600 "$owned/rsa.key" "$owned/rsa.pem" "$owned/ec.key" "$owned/ec.pem" "$owned/wiring.env"
        validate_pairs
        "$tool"
        cp -- "$run_dir/marker" "$owned/complete"
        chmod 600 "$owned/complete"
        rmdir -- "$state/.init-lock"
        locked=0
        ;;
    health)
        [ "$#" -eq 1 ] || p11lab_die "health takes no arguments"
        configure
        ready
        ;;
    exec)
        shift
        [ "${1-}" = -- ] || p11lab_die "exec requires -- before application argv"
        shift
        [ "$#" -gt 0 ] || p11lab_die "application argv is absent"
        configure
        ready
        # The command wrapper isolates upstream's relative conversion files;
        # the application retains its requested working directory.
        exec "$@"
        ;;
    *) p11lab_die "supported operations: describe, init, health, exec -- ARGV..." ;;
esac
