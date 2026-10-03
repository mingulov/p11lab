#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
set -eu
umask 077
. /usr/share/p11lab/common.sh
state=/var/lib/p11lab
owned=$state/haskoki
config=$owned/haskoki.toml
store=$owned/token.sqlite
# The provisioned store config is PIN-free and deterministic: the home token
# (slot 0, haskoki-demo) carries the upstream-fixed provisioned PINs, so no
# caller secret is stored in state, markers, logs or receipts.
export HASKOKI_CONFIG=$config
export P11LAB_MODULE=/usr/local/lib/p11lab/libhaskoki.so
label=${P11LAB_LABEL-haskoki-demo}
provision=/usr/local/bin/haskoki-provision
ctl=/usr/local/bin/haskoki-ctl
control=/run/p11lab
expected=$control/expected-haskoki.toml

expected_config() {
    printf '%s\n' 'schema_version = 1' 'profile = "real-crypto"' '' \
        '[storage]' 'kind = "sqlite"' "path = \"$store\"" '' \
        '[engine]' 'kind = "openssl"' '' \
        '[trace]' 'enabled = false'
}

configure() {
    p11lab_writable_directory "$control"
    [ ! -L "$expected" ] || p11lab_die "configuration cannot be a symlink"
    expected_config > "$control/expected.$$"
    mv -f -- "$control/expected.$$" "$expected"
}

expected_marker() {
    printf '%s\n' 'schema=1' 'provider=haskoki' "artifact=$(cat /usr/share/p11lab/runtime-id)" "token=$label" 'backend=sqlite' 'engine=openssl' 'profile=real-crypto'
}

allowed_owned() {
    # Provisioned store plus its config and marker. The O_EXCL sidecar lock
    # is tolerated: a clean close removes it, a crashed run may leave a
    # stale one (the next open takes it over), and a live one never blocks
    # lock-safe health inspection. Anything else is foreign or partial.
    case "$1" in
        complete|haskoki.toml|token.sqlite|token.sqlite.lock) return 0 ;;
        *) return 1 ;;
    esac
}

complete() {
    [ "$label" = haskoki-demo ] || p11lab_die "incompatible label: this provider serves only haskoki-demo on slot 0"
    [ ! -L "$owned" ] && [ ! -L "$owned/complete" ] || p11lab_die "partial or unsafe state"
    [ -f "$owned/complete" ] || p11lab_die "partial state: missing completion marker"
    [ "$(cat "$owned/complete")" = "$(expected_marker)" ] || p11lab_die "incompatible non-secret initialization configuration"
    for file in haskoki.toml token.sqlite; do
        [ ! -L "$owned/$file" ] || p11lab_die "partial or unsafe state"
        [ -f "$owned/$file" ] && [ -s "$owned/$file" ] || p11lab_die "partial state: missing provisioned file $file"
    done
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name haskoki -print -quit
    for entry in "$owned"/*; do
        [ -e "$entry" ] || continue
        [ ! -L "$entry" ] || p11lab_die "partial or unsafe state"
        allowed_owned "$(basename "$entry")" || p11lab_die "partial state: unknown owned files"
    done
    # The stored config is PIN-free and deterministic: any drift from the
    # expected bytes is an incompatible configuration, never silently kept.
    cmp -s -- "$expected" "$config" || p11lab_die "incompatible non-secret initialization configuration"
    # Lock-safe readiness only: the stock validator parses the config and
    # SELECT-only store inspection counts the seated token. Neither takes
    # the single-writer ownership lock, so health never contends with a
    # live application, daemon or peer health check. The module is never
    # opened here; key authentication stays with the application login.
    if checked=$("$ctl" config check --config "$config" 2>&1); then
        config_report=$checked
    else
        status=$?
        printf '%s\n' 'p11lab: native config validation failed' "$checked" >&2
        exit "$status"
    fi
    if inspected=$("$ctl" store inspect --path "$store" 2>&1); then
        printf '%s\n' "$inspected" | grep -q '^tokens: 1$' || p11lab_die "partial state: expected exactly one seated token"
        store_report=$inspected
    else
        status=$?
        printf '%s\n' 'p11lab: native store inspection failed' "$inspected" >&2
        exit "$status"
    fi
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
        configure
        if [ -e "$owned/complete" ]; then complete; exit 0; fi
        [ "$label" = haskoki-demo ] || p11lab_die "label policy: this provider serves only haskoki-demo on slot 0; refusing other labels"
        p11lab_check_find empty "partial state: refusing to initialize nonempty volume" "$state" -mindepth 1 -maxdepth 1 -print -quit
        expected_marker > "$control/marker.$$"
        p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
        user_credential=$credential
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        so_credential=$credential
        # Upstream provisions fixed PINs at open with no PIN-change path;
        # anything else can never authenticate, so refuse it explicitly
        # instead of provisioning a token the caller cannot open.
        # (Values compared here are the public upstream-fixed provisioned
        # PINs; they are never written to markers, logs or receipts.)
        [ "$user_credential" = '1234' ] || p11lab_die "caller PIN does not match the provider-provisioned PIN"
        [ "$so_credential" = '5678' ] || p11lab_die "caller SO PIN does not match the provider-provisioned SO PIN"
        mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
        trap 'rmdir "$state/.init-lock" 2>/dev/null || :; rm -f "$control/marker.$$" "$control/init.$$"' EXIT HUP INT TERM
        mkdir -p -m 700 "$owned"
        cp -- "$expected" "$owned/.haskoki.toml.$$"
        mv -- "$owned/.haskoki.toml.$$" "$config"
        if ! checked=$("$ctl" config check --config "$config" > "$control/init.$$" 2>&1); then
            status=$?
            printf '%s\n' 'p11lab: native token initialization failed; partial state retained' >&2
            cat -- "$control/init.$$" >&2
            exit "$status"
        fi
        # The single provisioning open runs only here, under the init lock,
        # against state this init created. It seats and commits the token,
        # asserts the slot 0 label policy, and preserves native errors.
        if "$provision" "$P11LAB_MODULE" > "$control/init.$$" 2>&1; then
            if inspected=$("$ctl" store inspect --path "$store" 2>&1) \
                && printf '%s\n' "$inspected" | grep -q '^tokens: 1$'; then
                cp -- "$control/marker.$$" "$owned/.complete.$$"
                mv -- "$owned/.complete.$$" "$owned/complete"
            else
                printf '%s\n' 'p11lab: native token initialization failed; partial state retained' "$inspected" >&2
                exit 1
            fi
        else
            status=$?
            printf '%s\n' 'p11lab: native token initialization failed; partial state retained' >&2
            cat -- "$control/init.$$" >&2
            exit "$status"
        fi
        ;;
    health)
        [ "$#" -eq 1 ] || p11lab_die "health takes no arguments"
        configure
        complete
        printf '%s\n' "$config_report" "$store_report"
        ;;
    exec)
        shift
        [ "${1-}" = -- ] || p11lab_die "exec requires -- followed by argv"
        shift
        [ "$#" -gt 0 ] || p11lab_die "exec requires an application"
        configure
        complete
        exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|health|exec -- ARGV..." ;;
esac
