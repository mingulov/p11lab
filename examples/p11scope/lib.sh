# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=sh
# Shared helpers for the p11scope demonstration. Sourced by run.sh and
# demo-inner.sh. Must stay POSIX sh and must not print secrets.

# verify_sha256 FILE EXPECTED
# Refuse unless FILE hashes exactly to EXPECTED (64 lowercase hex).
verify_sha256() {
    _file=$1
    _want=$2
    case "$_want" in
        *[!0-9a-f]*|"") echo "refused: expected sha256 is not hex: $_want" >&2; return 1 ;;
    esac
    [ "${#_want}" = "64" ] || { echo "refused: expected sha256 is not 64 hex: $_want" >&2; return 1; }
    [ -f "$_file" ] || { echo "refused: not a regular file: $_file" >&2; return 1; }
    _have=$(sha256sum "$_file" | cut -d' ' -f1) || return 1
    if [ "$_have" != "$_want" ]; then
        echo "refused: sha256 mismatch for $_file" >&2
        return 1
    fi
}

# finalize_result RESULT_FILE CONTENT WORK UID GID
# Record a completion marker only after caller ownership is proven.
# Ownership first, marker last: chown the work tree, then write the
# marker, then chown the marker itself so it stays caller-owned. Any
# chown failure removes the marker (when written) and returns nonzero,
# so a failed chown never leaves a success marker behind. The host
# treats the RESULT file as authoritative, never the pipe status.
finalize_result() {
    _result_file=$1
    _result_content=$2
    _work=$3
    _uid=$4
    _gid=$5
    chown -R "$_uid:$_gid" "$_work" || return 1
    printf '%s\n' "$_result_content" >"$_result_file" || return 1
    chown "$_uid:$_gid" "$_result_file" || {
        rm -f "$_result_file"
        return 1
    }
}
