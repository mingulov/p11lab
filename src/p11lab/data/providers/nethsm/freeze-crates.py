"""Reconstruct an offline Cargo directory source from sealed crate archives.

SPDX-License-Identifier: Apache-2.0
Adapted from the P11Lab Kryoptic helper (Apache-2.0); only the builder runs this helper. Versions and archive hashes come from the
P11Lab channel manifest, never a registry index or a Cargo resolver.
"""
import hashlib
import io
import json
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    manifest = json.loads(Path('/tmp/crates.json').read_text())
    destination = Path('/build/vendor')
    destination.mkdir()
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
        root = destination / name
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
    Path('/build/crate-file-inventory.json').write_text(json.dumps(inventory, indent=2) + '\n')
    config = Path('/build/nethsm/.cargo/config.toml')
    config.parent.mkdir(exist_ok=True)
    if config.exists():
        raise ValueError('upstream Cargo source configuration needs review')
    config.write_text('[source.crates-io]\nreplace-with = "p11lab-sealed"\n'
                      '[source.p11lab-sealed]\ndirectory = "/build/vendor"\n')


if __name__ == '__main__':
    main()
