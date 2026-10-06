#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Split only DWARF/debug sections; keep runtime and ordinary static symbols.
set -eu
original=$1
shipped=$2
companion=$3
shift 3
mkdir -p "$shipped" "$companion"
: > "$companion/binaries.tsv"
objcopy --version > "$companion/binutils.txt"
for name do
    case "$name" in ''|*[!a-zA-Z0-9._-]*|.|..) echo 'invalid binary name' >&2; exit 2;; esac
    cp "$original/$name" "$shipped/$name"
    objcopy --only-keep-debug "$original/$name" "$companion/$name.debug"
    objcopy --strip-debug "$shipped/$name"
    objcopy --add-gnu-debuglink="$companion/$name.debug" "$shipped/$name"
    # Exact symbol values/names and dynamic linking metadata must survive.
    nm --defined-only "$original/$name" > "$companion/$name.symbols"
    nm --defined-only "$shipped/$name" > "$companion/$name.shipped-symbols"
    cmp "$companion/$name.symbols" "$companion/$name.shipped-symbols"
    readelf --wide --dyn-syms --dynamic "$original/$name" > "$companion/$name.dynamic"
    readelf --wide --dyn-syms --dynamic "$shipped/$name" > "$companion/$name.shipped-dynamic"
    cmp "$companion/$name.dynamic" "$companion/$name.shipped-dynamic"
    original_id=$(readelf -n "$original/$name" | awk '/Build ID:/ {print $3}')
    shipped_id=$(readelf -n "$shipped/$name" | awk '/Build ID:/ {print $3}')
    debug_id=$(readelf -n "$companion/$name.debug" | awk '/Build ID:/ {print $3}')
    [ -n "$original_id" ] && [ "$original_id" = "$shipped_id" ] && [ "$original_id" = "$debug_id" ]
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$name" \
        "$(sha256sum "$original/$name" | cut -d ' ' -f 1)" "$(stat -c %s "$original/$name")" \
        "$(sha256sum "$shipped/$name" | cut -d ' ' -f 1)" "$(stat -c %s "$shipped/$name")" \
        "$(sha256sum "$companion/$name.debug" | cut -d ' ' -f 1)" "$(stat -c %s "$companion/$name.debug")" "$original_id" \
        >> "$companion/binaries.tsv"
done
