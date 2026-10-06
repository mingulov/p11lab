"""Fetch the sealed Maven Central jar for the opensc-isoapplet recipe.

SPDX-License-Identifier: Apache-2.0
Only the builder runs this helper. The URL, size and hashes come from the
sealed P11Lab channel manifest (maven.json, a hashed lock asset), never a
repository index or a Maven resolver. The expected URL is pinned in this
helper as well: any manifest drift is refused, never fetched.
"""
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

EXPECTED_URL = "https://repo1.maven.org/maven2/com/klinec/jcardsim/3.0.6.0/jcardsim-3.0.6.0.jar"


def main():
    manifest = json.loads(Path("/tmp/maven.json").read_text())
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported maven manifest schema")
    entries = manifest.get("artifacts", [])
    if len(entries) != 1:
        raise ValueError("maven manifest must seal exactly one jar")
    entry = entries[0]
    if entry["url"] != EXPECTED_URL:
        raise ValueError("jar URL differs from the sealed archive identity")
    if not entry["file"].endswith(".jar") or "/" in entry["file"]:
        raise ValueError("unsafe jar file name")
    with urllib.request.urlopen(EXPECTED_URL, timeout=180) as response:
        data = response.read()
    if len(data) != entry["size"]:
        raise ValueError("jar size mismatch: %d bytes" % len(data))
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("jar archive checksum mismatch")
    destination = Path("/build/maven")
    destination.mkdir(parents=True, exist_ok=False)
    target = destination / entry["file"]
    target.write_bytes(data)
    target.chmod(0o644)
    print("sealed jar: %s %d bytes sha256=%s"
          % (entry["file"], len(data), entry["sha256"]))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("fetch-jar: %s" % error, file=sys.stderr)
        raise SystemExit(1)
