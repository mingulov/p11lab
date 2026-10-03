#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Sealed archive bytes plus APK's signature verification; no package resolver
# accesses a mutable repository. The base supplies its own frozen APK keys.
set -eu
case "$1" in runtime|builder) ;; *) exit 2 ;; esac
mkdir -p /tmp/p11lab-apks
while read -r phase sha256 filename url; do
    if [ "$phase" = "$1" ]; then
        wget -q -O "/tmp/p11lab-apks/$filename" "$url"
        printf '%s  %s\n' "$sha256" "/tmp/p11lab-apks/$filename" | sha256sum -c -
    fi
done < /tmp/apk-inputs.txt
apk --no-network --repositories-file /dev/null add --no-cache /tmp/p11lab-apks/*.apk
rm -rf /tmp/p11lab-apks
