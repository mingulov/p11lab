#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# BouncyHSM container lifecycle. Each phase starts its own owned server on
# fixed container-loopback endpoints, requires HTTP health plus a native
# PKCS#11 probe plus the provisioned slot, then stops the server; exec leaves
# the server as a child of the application so container teardown ends both.
# HTTP uses bash /dev/tcp only; no curl, python or checker is required.
set -eu
umask 077
. /usr/share/p11lab/common.sh
state=/var/lib/p11lab
owned=$state/bouncyhsm
control=/run/p11lab
http_host=127.0.0.1
http_port=8080
tcp_host=127.0.0.1
tcp_port=8765
dotnet=/usr/share/dotnet/dotnet
server_dll=/opt/bouncyhsm/server/BouncyHsm.dll
server_dir=/opt/bouncyhsm/server
export P11LAB_MODULE=/usr/local/lib/p11lab/libBouncyHsm.Pkcs11.so
export BOUNCY_HSM_CFG_STRING="Server=$tcp_host;Port=$tcp_port;"
probe=/usr/local/bin/bouncyhsm-probe
label=${P11LAB_LABEL-P11Lab}
server_pid=

server_env() {
    export ASPNETCORE_URLS="http://$http_host:$http_port"
    export ASPNETCORE_ENVIRONMENT=Production
    export BouncyHsm_PersistenceStorageType=LiteDb
    export BouncyHsm_LiteDbPersistentRepositorySetup__DbFilePath="$owned/BouncyHsm.db"
    export BouncyHsm_BouncyHsmSetup__TcpEndpoint__Endpoint="$tcp_host:$tcp_port"
    export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
    export HOME="$control"
}

http_request() { # $1 = METHOD, $2 = path, $3 = body or empty
    local status header body_file=$control/http.$$
    exec 3<>"/dev/tcp/$http_host/$http_port" || return 1
    {
        printf '%s %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n' "$1" "$2" "$http_host"
        if [ -n "${3-}" ]; then
            printf 'Content-Type: application/json\r\nContent-Length: %s\r\n' "${#3}"
        fi
        printf '\r\n%s' "${3-}"
    } >&3
    IFS= read -r -t 10 status <&3 || { exec 3<&-; return 1; }
    terminated=
    while IFS= read -r -t 10 header <&3; do
        if [ "$header" = "$(printf '\r')" ] || [ -z "$header" ]; then terminated=1; break; fi
    done
    [ -n "$terminated" ] || { exec 3<&-; return 1; }
    cat <&3 > "$body_file" || { exec 3<&-; return 1; }
    exec 3<&-
    case "$status" in
        HTTP/*" "200*) cat "$body_file"; rm -f "$body_file"; return 0 ;;
        *) printf '%s\n' "http: unexpected status: $status" >&2; rm -f "$body_file"; return 1 ;;
    esac
}

start_server() {
    p11lab_writable_directory "$owned"
    p11lab_writable_directory "$control"
    [ ! -L "$owned" ] || p11lab_die "state directory cannot be a symlink"
    server_env
    cd "$server_dir"
    "$dotnet" "$server_dll" >>"$control/server.log" 2>&1 &
    server_pid=$!
    cd /
}

stop_server() {
    [ -n "$server_pid" ] || return 0
    kill "$server_pid" 2>/dev/null || { server_pid=; return 0; }
    for _ in $(seq 1 100); do
        kill -0 "$server_pid" 2>/dev/null || { server_pid=; return 0; }
        sleep 0.1
    done
    kill -9 "$server_pid" 2>/dev/null || :
    server_pid=
}

wait_health() { # bounded HTTP readiness; native proof happens separately
    local _
    for _ in $(seq 1 120); do
        kill -0 "$server_pid" 2>/dev/null || {
            printf '%s\n' 'p11lab: server process exited during startup' >&2
            cat "$control/server.log" >&2
            return 1
        }
        if http_request GET /health >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    printf '%s\n' 'p11lab: server HTTP health did not become ready' >&2
    cat "$control/server.log" >&2
    return 1
}

native_slots() { # prints "all present"; native errors are preserved
    local out rc
    out=$("$probe" --module "$P11LAB_MODULE" --server "$tcp_host" --port "$tcp_port" 2>"$control/probe.$$"); rc=$?
    if [ "$rc" -ne 0 ]; then
        cat "$control/probe.$$" >&2
        rm -f "$control/probe.$$"
        return 1
    fi
    rm -f "$control/probe.$$"
    printf '%s\n' "$out" | sed -n 's/^version=[0-9.]* slots=\([0-9]*\) present=\([0-9]*\)$/\1 \2/p' | grep . || return 1
}

slot_json() {
    http_request GET /Slot 2>/dev/null || p11lab_die "slot listing failed"
}

# Single-slot policy: one token per state directory. Zero slots means fresh
# state; exactly our labeled slot means compatible state; anything else is
# foreign or ambiguous and is refused, never adopted or reset.
selected_slot() { # prints SlotId or nothing; fails on foreign/ambiguous state
    local body="$1" ids labels
    [ "$body" = "[]" ] && return 0
    ids=$(printf '%s' "$body" | grep -o '"SlotId":[0-9]*' | wc -l | tr -d ' ')
    labels=$(printf '%s' "$body" | grep -o -F "\"Label\":\"$label\"" | wc -l | tr -d ' ')
    [ "$ids" = 1 ] && [ "$labels" = 1 ] || p11lab_die "partial state: foreign or ambiguous slots"
    printf '%s' "$body" | grep -o '"SlotId":[0-9]*' | head -1 | cut -d: -f2
}

validate_label() {
    case "$label" in ''|*[!a-zA-Z0-9\ ._-]*) p11lab_die "label must use printable ASCII letters, digits, spaces, dot, underscore or hyphen" ;; esac
    [ "${#label}" -le 32 ] || p11lab_die "label exceeds 32 bytes"
}

expected_marker() {
    validate_label
    printf '%s\n' 'schema=1' 'provider=bouncyhsm' "artifact=$(cat /usr/share/p11lab/runtime-id)" "label=$label" "slot=$1" 'backend=litedb'
}

complete() { # server must already run; verifies marker, files and live slot
    local slot counts
    [ ! -L "$owned" ] && [ ! -L "$owned/complete" ] && [ ! -L "$owned/BouncyHsm.db" ] || p11lab_die "partial or unsafe state"
    [ -f "$owned/complete" ] && [ -f "$owned/BouncyHsm.db" ] || p11lab_die "partial state: missing completion marker or database"
    p11lab_check_find empty "partial state: unknown files" "$state" -mindepth 1 -maxdepth 1 ! -name bouncyhsm ! -name .init-lock -print -quit
    p11lab_check_find empty "partial state: unknown owned files" "$owned" -mindepth 1 -maxdepth 1 ! -name complete ! -name BouncyHsm.db ! -name BouncyHsm-log.db -print -quit
    counts=$(native_slots) || p11lab_die "native slot probe failed"
    slot=$(selected_slot "$(slot_json)")
    [ -n "$slot" ] || p11lab_die "partial state: expected slot is absent"
    [ "$(cat "$owned/complete")" = "$(expected_marker "$slot")" ] || p11lab_die "incompatible non-secret initialization configuration"
    [ "$(printf '%s' "$counts" | cut -d' ' -f2)" -ge 1 ] || p11lab_die "partial state: expected token is not present"
}

ready_server() { # start, require HTTP health plus native operation, keep running
    start_server
    wait_health || { stop_server; return 1; }
    native_slots >/dev/null || { printf '%s\n' 'p11lab: native readiness failed' >&2; stop_server; return 1; }
}

case "${1-}" in
    describe)
        [ "$#" -eq 1 ] || p11lab_die "describe takes no arguments"
        cat /usr/share/p11lab/provider.json
        ;;
    server)
        # Foreground server for supervision (proxy-daemon composition). The
        # state must already be provisioned; nothing is initialized here.
        [ "$#" -eq 1 ] || p11lab_die "server takes no arguments"
        p11lab_writable_directory "$owned"
        p11lab_writable_directory "$control"
        server_env
        cd "$server_dir"
        exec "$dotnet" "$server_dll"
        ;;
    server-ready)
        # Verify an already-running server: HTTP health, native operation and
        # the provisioned labeled slot. Used by external supervisors.
        [ "$#" -eq 1 ] || p11lab_die "server-ready takes no arguments"
        validate_label
        server_pid=$(cat "$control/server.pid" 2>/dev/null || true)
        [ -n "$server_pid" ] || p11lab_die "server-ready requires a supervised server pid file"
        kill -0 "$server_pid" 2>/dev/null || p11lab_die "supervised server is not running"
        wait_health || exit 1
        native_slots >/dev/null || p11lab_die "native readiness failed"
        complete
        ;;
    init)
        [ "$#" -eq 1 ] || p11lab_die "init takes no arguments"
        validate_label
        p11lab_no_credential_conflict P11LAB_PIN P11LAB_PIN_FILE
        p11lab_no_credential_conflict P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        p11lab_writable_directory "$state"
        p11lab_writable_directory "$control"
        if [ -e "$owned/complete" ]; then
            ready_server || exit 1
            trap stop_server EXIT HUP INT TERM
            complete
            exit 0
        fi
        p11lab_check_find empty "partial state: refusing to initialize nonempty volume" "$state" -mindepth 1 -maxdepth 1 -print -quit
        p11lab_secret P11LAB_PIN P11LAB_PIN_FILE
        user_credential=$credential
        p11lab_secret P11LAB_SO_PIN P11LAB_SO_PIN_FILE
        mkdir "$state/.init-lock" || p11lab_die "state initialization is already in progress"
        trap 'stop_server; rmdir "$state/.init-lock" 2>/dev/null || :; rm -f "$control/marker.$$" "$control/slot.$$"' EXIT HUP INT TERM
        ready_server || exit 1
        [ "$(slot_json)" = "[]" ] || p11lab_die "partial state: refusing to provision over existing slots"
        dto=$(printf '{"IsHwDevice":false,"IsRemovableDevice":false,"Description":"%s","Token":{"Label":"%s","SerialNumber":"0001","SimulateHwRng":true,"SimulateHwMechanism":true,"SimulateQualifiedArea":false,"SimulateProtectedAuthPath":false,"SpeedMode":"WithoutRestriction","UserPin":"%s","SoPin":"%s"}}' "$label" "$label" "$user_credential" "$credential")
        unset user_credential credential
        http_request POST /Slot "$dto" >"$control/slot.$$" || p11lab_die "slot provisioning failed; partial state retained"
        slot=$(selected_slot "$(slot_json)")
        [ -n "$slot" ] || p11lab_die "slot provisioning failed; partial state retained"
        expected_marker "$slot" > "$control/marker.$$"
        cp -- "$control/marker.$$" "$owned/.complete.$$"
        mv -- "$owned/.complete.$$" "$owned/complete"
        ;;
    health)
        [ "$#" -eq 1 ] || p11lab_die "health takes no arguments"
        validate_label
        p11lab_writable_directory "$control"
        ready_server || exit 1
        trap stop_server EXIT HUP INT TERM
        complete
        slot_json
        ;;
    exec)
        shift
        [ "${1-}" = -- ] || p11lab_die "exec requires -- followed by argv"
        shift
        [ "$#" -gt 0 ] || p11lab_die "exec requires an application"
        validate_label
        p11lab_writable_directory "$control"
        ready_server || exit 1
        complete
        exec "$@"
        ;;
    *) p11lab_die "usage: p11lab-provider describe|init|health|exec -- ARGV...|server|server-ready" ;;
esac
