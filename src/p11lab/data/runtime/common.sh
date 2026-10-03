#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Common provider lifecycle primitives. Never include secrets in markers or logs.
p11lab_die() { printf '%s\n' "p11lab: $*" >&2; exit 1; }

p11lab_check_find() {
    # Capture status before interpreting stdout: a failed traversal is never
    # evidence of either an empty roster or a missing token/TLS permission.
    find_expectation=$1
    find_message=$2
    shift 2
    find_entries=$(find "$@") || p11lab_die "cannot enumerate $1"
    case "$find_expectation" in
        empty) [ -z "$find_entries" ] || p11lab_die "$find_message" ;;
        present) [ -n "$find_entries" ] || p11lab_die "$find_message" ;;
        *) p11lab_die "invalid enumeration check" ;;
    esac
}

p11lab_no_credential_conflict() {
    eval 'scalar_set=${'"$1"'+x}; file_set=${'"$2"'+x}'
    [ "$scalar_set$file_set" != xx ] || p11lab_die "conflicting value and file credential inputs"
}

p11lab_secret() {
    # $1 names the scalar, $2 names the file control. Preserve unset versus empty.
    eval 'scalar_set=${'"$1"'+x}; file_set=${'"$2"'+x}'
    [ "$scalar_set$file_set" != xx ] || p11lab_die "conflicting value and file credential inputs"
    if [ "$file_set" = x ]; then
        eval 'credential_file=${'"$2"'}'
        [ -n "$credential_file" ] && [ -f "$credential_file" ] && [ -r "$credential_file" ] || p11lab_die "credential file is not readable"
        [ "$(wc -c < "$credential_file")" -le 4096 ] || p11lab_die "credential input exceeds 4096-byte bound"
        # A sentinel preserves ALL trailing LFs through command substitution.
        # Compare the retained byte count so shells cannot silently discard NUL.
        credential=$(cat -- "$credential_file" && printf '.') || p11lab_die "cannot read credential file"
        credential=${credential%.}
        [ "$(printf '%s' "$credential" | wc -c)" = "$(wc -c < "$credential_file")" ] || p11lab_die "credential file contains unsupported bytes"
        case "$credential" in *'
') credential=${credential%'
'} ;; esac
    elif [ "$scalar_set" = x ]; then
        eval 'credential=${'"$1"'}'
    else
        p11lab_die "required credential input is absent"
    fi
    [ -n "$credential" ] || p11lab_die "credential input is empty"
    case "$credential" in *'
'*) p11lab_die "credential input must be a single line" ;; esac
    case "$credential" in *"$(printf '\r')"*) p11lab_die "credential input must be a single line" ;; esac
}

p11lab_writable_directory() {
    [ ! -L "$1" ] || p11lab_die "state/control directory cannot be a symlink"
    mkdir -p -- "$1" || p11lab_die "cannot create state/control directory (permissions)"
    [ -d "$1" ] && [ -w "$1" ] && [ -x "$1" ] || p11lab_die "state/control directory is not writable (permissions)"
}
