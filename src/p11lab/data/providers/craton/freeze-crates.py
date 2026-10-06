"""Reconstruct Craton's offline Cargo source from its upstream locked archives.

SPDX-License-Identifier: Apache-2.0
Adapted from P11Lab's Kryoptic helper. No registry index or resolver is used.
The optional path arguments permit independent acquisition/inventory readbacks.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import urllib.request


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, default=Path('/tmp/crates.json'))
    parser.add_argument('--source', type=Path, default=Path('/build/craton'))
    parser.add_argument('--vendor', type=Path, default=Path('/build/vendor'))
    parser.add_argument('--inventory', type=Path, default=Path('/build/crate-file-inventory.json'))
    parser.add_argument('--archives', type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    if sha256((args.source / 'Cargo.lock').read_bytes()) != manifest['cargo_lock_sha256']:
        raise ValueError('upstream Cargo.lock differs from the frozen snapshot')
    args.vendor.mkdir()
    if args.archives:
        args.archives.mkdir()
    inventory = []
    for crate in manifest['crates']:
        name = crate['name'] + '-' + crate['version']
        expected_url = 'https://static.crates.io/crates/' + crate['name'] + '/' + name + '.crate'
        if crate['url'] != expected_url:
            raise ValueError('crate URL differs from the sealed archive identity')
        with urllib.request.urlopen(expected_url, timeout=180) as response:
            data = response.read()
        if sha256(data) != crate['sha256']:
            raise ValueError('crate archive checksum mismatch: ' + name)
        if args.archives:
            (args.archives / (name + '.crate')).write_bytes(data)
        root = args.vendor / name
        root.mkdir()
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
            for member in archive.getmembers():
                parts = PurePosixPath(member.name).parts
                if not parts or parts[0] != name or any(p in {'.', '..'} for p in parts):
                    raise ValueError('unsafe crate archive path')
                if member.isdir():
                    continue
                if not member.isfile() or len(parts) < 2:
                    raise ValueError('crate archive requires regular files')
                target = root.joinpath(*parts[1:])
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    raise ValueError('duplicate crate archive member')
                target.write_bytes(archive.extractfile(member).read())
                target.chmod(0o755 if member.mode & 0o111 else 0o644)
        files = {p.relative_to(root).as_posix(): sha256(p.read_bytes())
                 for p in sorted(root.rglob('*')) if p.is_file()}
        (root / '.cargo-checksum.json').write_text(json.dumps({'files': files, 'package': crate['sha256']}))
        inventory.append(crate | {'files': files})
    args.inventory.write_text(json.dumps(inventory, indent=2) + '\n')
    config = args.source / '.cargo/config.toml'
    config.parent.mkdir(exist_ok=True)
    if config.exists():
        raise ValueError('upstream Cargo source configuration needs review')
    config.write_text('[source.crates-io]\nreplace-with = "p11lab-sealed"\n'
                      '[source.p11lab-sealed]\ndirectory = ' + json.dumps(str(args.vendor.resolve())) + '\n')


if __name__ == '__main__':
    main()
