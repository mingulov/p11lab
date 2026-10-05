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
