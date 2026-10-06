"""Populate a Bazel distdir and repository cache from sealed archives.

SPDX-License-Identifier: Apache-2.0
Only the builder runs this helper. URLs and archive hashes come from the
P11Lab channel manifest, never a live resolver or version index. The Go SDK
hash is pinned by the WORKSPACE patch (no go.dev index lookup); go_repository
zips additionally carry their h1 sums for Bazel-side verification. Gazelle's
fetch_repo bypasses the Bazel downloader, so the verified zips are also laid
out as a sealed file:// module proxy (zip bytes plus the .mod extracted from
the zip itself) for the offline compile step.
"""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import urllib.request
import zipfile


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def fetch(urls, expected, names, distdir, cache, inventory):
    distdir.mkdir(parents=True, exist_ok=True)
    cache.mkdir(parents=True, exist_ok=True)
    last = None
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=300) as response:
                data = response.read()
        except Exception as error:  # noqa: BLE001 - try the next mirror
            last = error
            continue
        if sha256(data) != expected:
            raise ValueError('archive checksum mismatch: ' + url)
        for name in names:
            if PurePosixPath(name).name != name or name in {'.', '..'}:
                raise ValueError('unsafe archive name: ' + name)
            (distdir / name).write_bytes(data)
        (cache / expected).write_bytes(data)
        inventory.append({'sha256': expected, 'bytes': len(data),
                          'names': sorted(names), 'url': url})
        print(f'ok {len(data):>10} {sorted(names)[0]}', flush=True)
        return
    raise ValueError(f'all mirrors failed for {sorted(names)[0]}: {last}')


def main():
    manifest = json.loads(Path('/tmp/bazel-deps.json').read_text())
    distdir = Path('/build/bazel-distdir')
    cache = Path('/build/bazel-repocache')
    distdir.mkdir(parents=True)
    cache.mkdir(parents=True)
    inventory = []
    bazel = manifest['bazel']
    fetch(bazel['urls'], bazel['sha256'], ['bazel'], Path('/build/bazel-bin'),
          cache, inventory)
    Path('/build/bazel-bin/bazel').chmod(0o755)
    entries = list(manifest['archives'])
    sdk = manifest['go_sdk']
    entries.append({'repo': 'go_sdk', 'urls': sdk['urls'], 'sha256': sdk['sha256']})
    for gz in manifest['go_zips']:
        entries.append({'repo': gz['repo'], 'urls': gz['urls'], 'sha256': gz['zip_sha256']})
    seen = {}
    for entry in entries:
        names = sorted({os.path.basename(url) for url in entry['urls']})
        for name in names:
            if name in seen and seen[name] != entry['sha256']:
                raise ValueError('distdir basename collision: ' + name)
            seen[name] = entry['sha256']
        fetch(entry['urls'], entry['sha256'], names, distdir, cache, inventory)
    proxy = Path('/build/goproxy')
    for gz in manifest['go_zips']:
        escaped = ''.join('!' + c.lower() if c.isupper() else c for c in gz['importpath'])
        target = proxy / escaped / '@v'
        target.mkdir(parents=True, exist_ok=True)
        data = (distdir / os.path.basename(gz['urls'][0])).read_bytes()
        if sha256(data) != gz['zip_sha256']:
            raise ValueError('go zip checksum mismatch: ' + gz['repo'])
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            mod = archive.read(gz['importpath'] + '@' + gz['version'] + '/go.mod')
        (target / (gz['version'] + '.zip')).write_bytes(data)
        (target / (gz['version'] + '.mod')).write_bytes(mod)
        (target / (gz['version'] + '.info')).write_text(json.dumps({'Version': gz['version']}) + '\n')
        inventory.append({'sha256': gz['zip_sha256'], 'bytes': len(data), 'mod_bytes': len(mod),
                          'names': [gz['importpath'] + '@' + gz['version']], 'url': gz['urls'][0]})
    Path('/build/bazel-fetch-inventory.json').write_text(json.dumps(inventory, indent=1) + '\n')
    print(f'fetched {len(inventory)} sealed archives', flush=True)


main()
