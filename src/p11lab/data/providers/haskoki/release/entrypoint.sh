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
# (slot 0, haskoki-demo) starts with the demo PINs by explicit adapter
# policy. Upstream v0.5 supports durable native PIN changes; repeated init
# remains validate-only and does not restore the initial PINs. Caller PIN
# bytes are never written to config, markers, logs or receipts.
export HASKOKI_CONFIG=$config
export P11LAB_MODULE=/usr/local/lib/p11lab/libhaskoki.so
label=${P11LAB_LABEL-haskoki-demo}
provision=/usr/local/bin/haskoki-provision
ctl=/usr/local/bin/haskoki-ctl
control=/run/p11lab
expected=$control/expected-haskoki.toml
runtime_id=/usr/share/p11lab/runtime-id

load_runtime_identity() {
    [ -f "$runtime_id" ] && [ ! -L "$runtime_id" ] || p11lab_die "missing or unsafe runtime identity"
    artifact_id=$(cat -- "$runtime_id") || p11lab_die "cannot read runtime identity"
    case "$artifact_id" in ''|*[!0-9a-f]*) p11lab_die "invalid runtime identity" ;; esac
    [ "${#artifact_id}" -eq 64 ] || p11lab_die "invalid runtime identity"
    # Command substitution strips trailing newlines (and some shells strip
    # NUL), so also compare exact bytes to the build's SHA-256-plus-LF file.
    printf '%s\n' "$artifact_id" | cmp -s -- - "$runtime_id" || p11lab_die "invalid runtime identity"
}

expected_config() {
    printf '%s\n' 'schema_version = 1' 'profile = "real-crypto"' '' \
        '[storage]' 'kind = "sqlite"' "path = \"$store\"" '' \
        '[engine]' 'kind = "openssl"' '' \
        '[trace]' 'enabled = false'
}

configure() {
    load_runtime_identity
    p11lab_writable_directory "$control"
    [ ! -L "$expected" ] || p11lab_die "configuration cannot be a symlink"
    expected_config > "$control/expected.$$"
    mv -f -- "$control/expected.$$" "$expected"
}

expected_marker() {
    printf '%s\n' 'schema=1' 'provider=haskoki' "artifact=$artifact_id" "token=$label" 'backend=sqlite' 'engine=openssl' 'profile=real-crypto'
}

single_token_report() {
    if token_lines=$(printf '%s\n' "$1" | grep '^tokens:'); then
        [ "$token_lines" = 'tokens: 1' ]
    else
        return 1
    fi
}

init_signal() {
    if [ "$cleaning_up" -eq 1 ]; then
        # A stop during cleanup must not abort the remaining owned removals
        # or replace an already-observed native, cleanup or signal failure.
        if [ "$init_status" -eq 0 ]; then
            if [ "$cleanup_status" -ne 0 ]; then
                init_status=$cleanup_status
            else
                init_status=$1
            fi
        fi
    else
        exit "$1"
    fi
}

cleanup_init() {
    # Capture the primary status and enter cleanup in one command while the
    # same signal handlers remain installed throughout.
    init_status=$? cleaning_up=1 cleanup_status=0
    trap - EXIT
    rmdir -- "$state/.init-lock" || {
        cleanup_status=1
        [ "$init_status" -ne 0 ] || init_status=$cleanup_status
        printf '%s\n' 'p11lab: initialization lock cleanup failed' >&2 || :
    }
    rm -f -- "$control/marker.$$" "$control/init.$$" || {
        cleanup_status=1
        [ "$init_status" -ne 0 ] || init_status=$cleanup_status
        printf '%s\n' 'p11lab: initialization temporary-file cleanup failed' >&2 || :
    }
    # The native failure remains primary. Cleanup failure still prevents a
    # successful init from being reported when owned resources remain.
    [ "$init_status" -ne 0 ] || init_status=$cleanup_status
    exit "$init_status"
}

complete() {
    [ "$label" = haskoki-demo ] || p11lab_die "incompatible label: this provider serves only haskoki-demo on slot 0"
    [ ! -L "$state" ] && [ -d "$state" ] || p11lab_die "partial or unsafe state"
    [ ! -L "$owned" ] && [ ! -L "$owned/complete" ] || p11lab_die "partial or unsafe state"
    [ -f "$owned/complete" ] || p11lab_die "partial state: missing completion marker"
    expected_marker | cmp -s -- - "$owned/complete" || p11lab_die "incompatible non-secret initialization configuration"
    for file in haskoki.toml token.sqlite; do
        [ ! -L "$owned/$file" ] || p11lab_die "partial or unsafe state"
        [ -f "$owned/$file" ] && [ -s "$owned/$file" ] || p11lab_die "partial state: missing provisioned file $file"
    done
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name haskoki -print -quit
    # A checked traversal must succeed before a glob can prove the roster:
    # unreadable directories otherwise look like an empty glob. The native
    # sidecar may remain after a crash or while a live owner holds the store.
    p11lab_check_find empty "partial state: unknown owned files" "$owned" -mindepth 1 -maxdepth 1 ! -name complete ! -name haskoki.toml ! -name token.sqlite ! -name token.sqlite.lock -print -quit
    for entry in "$owned"/* "$owned"/.[!.]* "$owned"/..?*; do
        [ -e "$entry" ] || [ -L "$entry" ] || continue
        [ ! -L "$entry" ] && [ -f "$entry" ] || p11lab_die "partial or unsafe state"
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
        printf '%s\n' 'p11lab: native config validation failed' "$checked" >&2 || :
        exit "$status"
    fi
    if inspected=$("$ctl" store inspect --path "$store" 2>&1); then
        single_token_report "$inspected" || p11lab_die "partial state: expected exactly one seated token"
        store_report=$inspected
    else
        status=$?
        printf '%s\n' 'p11lab: native store inspection failed' "$inspected" >&2 || :
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
        p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
        user_credential=$credential
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        so_credential=$credential
        # P11Lab adapter policy: initial provisioning accepts only the
        # upstream demo PINs. Native InitToken/InitPIN/SetPIN are supported
        # by v0.5, but arbitrary initial provisioning is not added here.
        # Later native PIN changes persist; complete-state init above is
        # validate-only. These public demo values are never logged.
        [ "$user_credential" = '1234' ] || p11lab_die "caller PIN does not match the provider-provisioned PIN"
        [ "$so_credential" = '5678' ] || p11lab_die "caller SO PIN does not match the provider-provisioned SO PIN"
        mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
        cleaning_up=0
        trap cleanup_init EXIT
        trap 'init_signal 129' HUP
        trap 'init_signal 130' INT
        trap 'init_signal 143' TERM
        expected_marker > "$control/marker.$$"
        mkdir -p -m 700 "$owned"
        cp -- "$expected" "$owned/.haskoki.toml.$$"
        mv -- "$owned/.haskoki.toml.$$" "$config"
        if "$ctl" config check --config "$config" > "$control/init.$$" 2>&1; then
            :
        else
            status=$?
            printf '%s\n' 'p11lab: native token initialization failed; partial state retained' >&2 || :
            cat -- "$control/init.$$" >&2 || :
            exit "$status"
        fi
        # The single provisioning open runs only here, under the init lock,
        # against state this init created. It seats and commits the token,
        # asserts the slot 0 label policy, and preserves native errors.
        if "$provision" "$P11LAB_MODULE" > "$control/init.$$" 2>&1; then
            if inspected=$("$ctl" store inspect --path "$store" 2>&1); then
                single_token_report "$inspected" || {
                    printf '%s\n' 'p11lab: native token initialization failed; partial state retained' "$inspected" >&2
                    exit 1
                }
                cp -- "$control/marker.$$" "$owned/.complete.$$"
                mv -- "$owned/.complete.$$" "$owned/complete"
            else
                status=$?
                printf '%s\n' 'p11lab: native token initialization failed; partial state retained' "$inspected" >&2 || :
                exit "$status"
            fi
        else
            status=$?
            printf '%s\n' 'p11lab: native token initialization failed; partial state retained' >&2 || :
            cat -- "$control/init.$$" >&2 || :
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
