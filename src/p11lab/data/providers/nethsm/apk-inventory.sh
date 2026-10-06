#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# APK origin is the source package. Subpackages share its exact package version.
set -eu
awk 'BEGIN { RS=""; FS="\n" }
  { name=""; version=""; arch=""; origin="";
    for (i=1;i<=NF;i++) {
      if ($i ~ /^P:/) name=substr($i,3);
      if ($i ~ /^V:/) version=substr($i,3);
      if ($i ~ /^A:/) arch=substr($i,3);
      if ($i ~ /^o:/) origin=substr($i,3);
    }
    if (name != "") {
      if (origin == "") origin=name;
      printf "%s\t%s\t%s\t%s\t%s\n", name,version,arch,origin,version;
    }
  }' /lib/apk/db/installed | sort
