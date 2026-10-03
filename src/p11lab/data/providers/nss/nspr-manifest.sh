#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Build-only loader: the pinned manifest is data, never sourced shell code.
p11lab_nspr_manifest() {
    manifest=$1
    if ! [ -f "$manifest" ] || ! [ -r "$manifest" ]; then
        printf '%s\n' 'invalid NSPR manifest: unreadable input' >&2
        return 1
    fi
    # Universal validation closes the existential grep hole. Quotes are
    # allowed only around a numeric version with its optional Beta suffix.
    manifest_lines=$(wc -l < "$manifest") || return 1
    if [ "$manifest_lines" -ne 6 ]; then
        printf '%s\n' 'invalid NSPR manifest: expected six lines' >&2
        return 1
    fi
    if grep -Ev '^(NSPR_(TAG|REVISION|URL|SHA256|SIZE)=[A-Za-z0-9_./:+-]+|NSPR_VERSION=([0-9]+(\.[0-9]+)+|"[0-9]+(\.[0-9]+)+( Beta)?"))$' "$manifest" >&2; then
        printf '%s\n' 'invalid NSPR manifest: malformed field' >&2
        return 1
    else
        grep_status=$?
        [ "$grep_status" = 1 ] || return "$grep_status"
    fi
    for field in TAG REVISION VERSION URL SHA256 SIZE; do
        [ "$(grep -c "^NSPR_$field=" "$manifest")" = 1 ] || {
            printf '%s\n' "invalid NSPR manifest: missing or duplicate $field" >&2
            return 1
        }
    done
    while IFS='=' read -r field value; do
        case "$value" in \"*\") value=${value#\"}; value=${value%\"} ;; esac
        export "$field=$value"
    done < "$manifest"
}
