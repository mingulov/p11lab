"""Reconstruct a sealed Cargo closure; adapted from P11Lab's pkcs11rs helper.

SPDX-License-Identifier: Apache-2.0
Registry bytes are verified against the P11Lab-frozen Cargo.lock (upstream
ships none). The separate sealed ed25519-bip32 checkout supplies Cargo's Git
source as a directory source without Git or network resolution at compile
time. No upstream manifests or source files are patched.
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
    parser.add_argument('--source', type=Path, default=Path('/build/softkms'))
    parser.add_argument('--vendor', type=Path, default=Path('/build/vendor'))
    parser.add_argument('--git-source', type=Path, default=Path('/build/xhd'))
    parser.add_argument('--inventory', type=Path, default=Path('/build/crate-file-inventory.json'))
    parser.add_argument('--archives', type=Path)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text())
    lock_bytes = (args.source / 'Cargo.lock').read_bytes()
    if sha256(lock_bytes) != manifest['cargo_lock_sha256']:
        raise ValueError('Cargo.lock differs from the frozen snapshot')
    locked = tomllib.loads(lock_bytes.decode())['package']
    expected = {(p['name'], p['version'], p['checksum']) for p in locked if p.get('source', '').startswith('registry+')}
    actual = {(p['name'], p['version'], p['sha256']) for p in manifest['crates']}
    if expected != actual or len(actual) != len(manifest['crates']):
        raise ValueError('registry manifest differs from the exact locked roster')
    git_locked = [p for p in locked if p.get('source', '').startswith('git+')]
    if len(git_locked) != 1 or (git_locked[0]['name'], git_locked[0]['version']) != ('ed25519-bip32', '0.4.1'):
        raise ValueError('locked Git roster differs from the reviewed dependency')
    if git_locked[0]['source'] != ('git+https://github.com/algorandfoundation/xHD-Wallet-API-rs/'
                                   '?rev=3cafd074e840971a2de791593918bb1c0707cd04'
                                   '#3cafd074e840971a2de791593918bb1c0707cd04'):
        raise ValueError('locked Git revision differs from the reviewed pin')
    args.vendor.mkdir()
    if args.archives:
        args.archives.mkdir(exist_ok=True)
    with ThreadPoolExecutor(max_workers=4) as pool:
        records = list(pool.map(lambda crate: acquire(crate, args.vendor, args.archives), manifest['crates']))
    # Cargo consumes the sealed Git checkout as a directory source. The
    # recipe extracts the checkout root as the ed25519-bip32 package
    # directory; checksums are generated metadata, no upstream manifest is
    # rewritten.
    for directory in sorted(args.git_source.iterdir()):
        if not directory.is_dir() or not (directory / 'Cargo.toml').is_file():
            continue
        package = tomllib.loads((directory / 'Cargo.toml').read_text()).get('package')
        if package:
            files = inventory(directory)
            (directory / '.cargo-checksum.json').write_text(json.dumps({'files': files, 'package': None}))
    git = manifest['git_packages']
    if len(git) != 1 or {k: git[0].get(k) for k in ('name', 'version', 'source', 'revision', 'path')} != {
            'name': 'ed25519-bip32', 'version': '0.4.1',
            'source': 'https://github.com/algorandfoundation/xHD-Wallet-API-rs',
            'revision': '3cafd074e840971a2de791593918bb1c0707cd04', 'path': 'ed25519-bip32'}:
        raise ValueError('unreviewed Git source roster')
    package = tomllib.loads((args.git_source / 'ed25519-bip32/Cargo.toml').read_text())['package']
    if (package['name'], package['version']) != ('ed25519-bip32', '0.4.1'):
        raise ValueError('Git package identity mismatch')
    records.append(git[0] | {'license': package['license'], 'files': inventory(args.git_source / 'ed25519-bip32')})
    args.inventory.write_text(json.dumps(records, indent=2) + '\n')
    config = args.source / '.cargo/config.toml'
    if config.exists():
        raise ValueError('upstream Cargo source configuration needs review')
    config.parent.mkdir(exist_ok=True)
    config.write_text('[source.crates-io]\nreplace-with = "p11lab-sealed"\n'
                      '[source.p11lab-sealed]\ndirectory = ' + json.dumps(str(args.vendor.resolve())) + '\n'
                      '[source.algorand-xhd]\ngit = "https://github.com/algorandfoundation/xHD-Wallet-API-rs/"\n'
                      'rev = "3cafd074e840971a2de791593918bb1c0707cd04"\nreplace-with = "p11lab-xhd"\n'
                      '[source.p11lab-xhd]\ndirectory = ' + json.dumps(str(args.git_source.resolve())) + '\n')
    print('sealed registry archives:', len(manifest['crates']), '; Git packages:', len(git), flush=True)


if __name__ == '__main__':
    main()
