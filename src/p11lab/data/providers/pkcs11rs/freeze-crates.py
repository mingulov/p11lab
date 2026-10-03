"""Reconstruct a sealed Cargo closure; adapted from P11Lab's Kryoptic helper.

SPDX-License-Identifier: Apache-2.0
Registry bytes are verified against the exact upstream Cargo.lock. The separate
sealed signatures checkout supplies Cargo's Git source without Git or network
resolution at compile time. No upstream manifests or source files are patched.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import tarfile
import tomllib
import urllib.request


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def inventory(root):
    return {p.relative_to(root).as_posix(): sha256(p.read_bytes())
            for p in sorted(root.rglob('*')) if p.is_file() and p.name != '.cargo-checksum.json'}


def acquire(crate, destination, archives):
    name = crate['name'] + '-' + crate['version']
    url = 'https://static.crates.io/crates/' + crate['name'] + '/' + name + '.crate'
    if crate['url'] != url:
        raise ValueError('crate URL differs from sealed identity')
    cached = archives / (name + '.crate') if archives else None
    if cached and cached.exists():
        data = cached.read_bytes()
    else:
        with urllib.request.urlopen(url, timeout=180) as response:
            data = response.read()
    if sha256(data) != crate['sha256']:
        raise ValueError('crate archive checksum mismatch: ' + name)
    if cached:
        cached.write_bytes(data)
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
    files = inventory(root)
    (root / '.cargo-checksum.json').write_text(json.dumps({'files': files, 'package': crate['sha256']}))
    package = tomllib.loads((root / 'Cargo.toml').read_text())['package']
    return crate | {'license': package.get('license'), 'license_file': package.get('license-file'), 'files': files}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--manifest', type=Path, default=Path('/tmp/crates.json'))
    parser.add_argument('--source', type=Path, default=Path('/build/pkcs11rs'))
    parser.add_argument('--vendor', type=Path, default=Path('/build/vendor'))
    parser.add_argument('--git-source', type=Path, default=Path('/build/signatures'))
    parser.add_argument('--inventory', type=Path, default=Path('/build/crate-file-inventory.json'))
    parser.add_argument('--archives', type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    lock_bytes = (args.source / 'Cargo.lock').read_bytes()
    if sha256(lock_bytes) != manifest['cargo_lock_sha256']:
        raise ValueError('upstream Cargo.lock differs from the frozen snapshot')
    locked = tomllib.loads(lock_bytes.decode())['package']
    expected = {(p['name'], p['version'], p['checksum']) for p in locked if p.get('source', '').startswith('registry+')}
    actual = {(p['name'], p['version'], p['sha256']) for p in manifest['crates']}
    if expected != actual or len(actual) != len(manifest['crates']):
        raise ValueError('registry manifest differs from the exact locked roster')
    args.vendor.mkdir()
    if args.archives:
        args.archives.mkdir(exist_ok=True)
    with ThreadPoolExecutor(max_workers=4) as pool:
        records = list(pool.map(lambda crate: acquire(crate, args.vendor, args.archives), manifest['crates']))
    # Cargo can consume this sealed Git checkout as a directory source. Keep
    # its original workspace root for the package's inherited lint settings.
    # Checksums are generated metadata; no upstream manifest is rewritten.
    for directory in sorted(args.git_source.iterdir()):
        if not directory.is_dir() or not (directory / 'Cargo.toml').is_file():
            continue
        package = tomllib.loads((directory / 'Cargo.toml').read_text()).get('package')
        if package:
            files = inventory(directory)
            (directory / '.cargo-checksum.json').write_text(json.dumps({'files': files, 'package': None}))
    git = manifest['git_packages']
    if len(git) != 1 or {k: git[0].get(k) for k in ('name', 'version', 'source', 'revision', 'path')} != {'name': 'ml-dsa', 'version': '0.1.1', 'source': 'https://github.com/qpernil/signatures.git',
                                 'revision': 'e06d2e28699428fbcc135c388516883bbb71f170', 'path': 'ml-dsa'}:
        raise ValueError('unreviewed Git source roster')
    package = tomllib.loads((args.git_source / 'ml-dsa/Cargo.toml').read_text())['package']
    if (package['name'], package['version']) != ('ml-dsa', '0.1.1'):
        raise ValueError('Git package identity mismatch')
    records.append(git[0] | {'license': package['license'], 'files': inventory(args.git_source / 'ml-dsa')})
    args.inventory.write_text(json.dumps(records, indent=2) + '\n')
    config = args.source / '.cargo/config.toml'
    config.parent.mkdir(exist_ok=True)
    original = config.read_bytes() if config.exists() else b''
    if sha256(original) != manifest['source_config_sha256'] or 'source' in tomllib.loads(original.decode()):
        raise ValueError('upstream Cargo source configuration differs from reviewed aliases')
    config.write_text(original.decode() + '\n[source.crates-io]\nreplace-with = "p11lab-sealed"\n'
                      '[source.p11lab-sealed]\ndirectory = ' + json.dumps(str(args.vendor.resolve())) + '\n'
                      '[source.qpernil-signatures]\ngit = "https://github.com/qpernil/signatures.git"\n'
                      'rev = "e06d2e28699428fbcc135c388516883bbb71f170"\nreplace-with = "p11lab-signatures"\n'
                      '[source.p11lab-signatures]\ndirectory = ' + json.dumps(str(args.git_source.resolve())) + '\n')
    print('sealed registry archives:', len(manifest['crates']), '; Git packages:', len(git), flush=True)


if __name__ == '__main__':
    main()
