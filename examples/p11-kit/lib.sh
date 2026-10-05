# SPDX-License-Identifier: Apache-2.0
# shellcheck shell=sh
# Owned-path guards for the p11-kit demonstration.
#
# This file is sourced by run.sh and demo-inner.sh. It must stay POSIX sh,
# must not start servers or attach to any, and must not print secrets.
# Every refusal exits nonzero with a single `refused:` line on stderr.

# own_private_dir DIR [EXPECTED_UID]
# Create (or adopt, when already empty) a private directory and prove it is
# owned by EXPECTED_UID (default: current euid) with mode 0700. Refuse any
# path that already holds foreign content: the demo never attaches to
# another user's service through a pre-existing socket directory.
own_private_dir() {
    _dir=$1
    _want_uid=${2:-$(id -u)}
    if [ -e "$_dir" ] && [ ! -d "$_dir" ]; then
        echo "refused: socket parent exists and is not a directory: $_dir" >&2
        return 1
    fi
    mkdir -p "$_dir" || return 1
    _have_uid=$(stat -c '%u' "$_dir") || return 1
    if [ "$_have_uid" != "$_want_uid" ]; then
        echo "refused: socket parent owned by uid $_have_uid, want $_want_uid: $_dir" >&2
        return 1
    fi
    if [ -n "$(ls -A "$_dir")" ]; then
        echo "refused: socket parent is not empty, will not share it: $_dir" >&2
        return 1
    fi
    chmod 700 "$_dir" || return 1
    _mode=$(stat -c '%a' "$_dir") || return 1
    if [ "$_mode" != "700" ]; then
        echo "refused: socket parent mode is $_mode, want 700: $_dir" >&2
        return 1
    fi
}

# assert_owned_socket SOCK [EXPECTED_UID]
# Prove SOCK is a Unix socket owned by EXPECTED_UID (default: current euid)
# directly under a 0700 directory owned by the same uid. The p11-kit server
# creates the socket file itself (mode 710 as observed); privacy comes
# from the parent directory, so the parent check is the load-bearing one.
assert_owned_socket() {
    _sock=$1
    _want_uid=${2:-$(id -u)}
    if [ ! -S "$_sock" ]; then
        echo "refused: not a socket: $_sock" >&2
        return 1
    fi
    _have_uid=$(stat -c '%u' "$_sock") || return 1
    if [ "$_have_uid" != "$_want_uid" ]; then
        echo "refused: socket owned by uid $_have_uid, want $_want_uid: $_sock" >&2
        return 1
    fi
    _parent=$(dirname "$_sock")
    _parent_uid=$(stat -c '%u' "$_parent") || return 1
    _parent_mode=$(stat -c '%a' "$_parent") || return 1
    if [ "$_parent_uid" != "$_want_uid" ] || [ "$_parent_mode" != "700" ]; then
        echo "refused: socket parent uid=$_parent_uid mode=$_parent_mode, want uid=$_want_uid mode=700: $_parent" >&2
        return 1
    fi
}

# single_socket DIR
# Print the one socket entry directly under DIR, refusing zero or several:
# a fresh private server directory holds exactly the server we started.
single_socket() {
    _dir=$1
    _count=0
    _found=
    for _entry in "$_dir"/*; do
        [ -e "$_entry" ] || continue
        _count=$((_count + 1))
        _found=$_entry
    done
    if [ "$_count" != "1" ]; then
        echo "refused: want exactly one server socket under $_dir, found $_count" >&2
        return 1
    fi
    printf '%s\n' "$_found"
}
