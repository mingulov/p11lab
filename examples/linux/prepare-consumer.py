#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Prepare a closed installed-package C consumer build context, without building."""
import argparse
import hashlib
import json
from pathlib import Path

from p11lab.build import inventory_text
from p11lab.catalog import load_environment, package_data


def prepare(channel, output):
    spec = load_environment('softhsm2', channel)
    lock = spec['lock']
    output.mkdir(parents=True, exist_ok=False)
    assets = ('smoke.c', 'p256.c', 'p256.h', 'vendor/pkcs11.h', 'LICENSE', 'PROVENANCE.md', 'README.md', 'verify.py')
    for name in assets:
        destination = output / 'consumer' / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(package_data('consumer/' + name).read_bytes())
    (output / 'Dockerfile').write_bytes(package_data('consumer/Dockerfile').read_bytes())
    snapshot = lock['apt_snapshot']
    (output / 'snapshot.sources').write_text(f'Types: deb deb-src\nURIs: http://snapshot.debian.org/archive/debian/{snapshot}/\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\nCheck-Valid-Until: no\n\nTypes: deb deb-src\nURIs: http://snapshot.debian.org/archive/debian-security/{snapshot}/\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\nCheck-Valid-Until: no\n')
    (output / 'builder-requested.txt').write_text('\n'.join(lock['builder_requested']) + '\n')
    (output / 'base-packages.tsv').write_text(inventory_text([p for p in lock['packages'] if p['phase'] == 'runtime']))
    (output / 'builder-packages.tsv').write_text(inventory_text(lock['packages']))
    return {p.relative_to(output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.rglob('*')) if p.is_file()}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--channel', required=True, choices=('release', 'rolling'))
    parser.add_argument('--output-dir', required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.channel, args.output_dir), indent=2, sort_keys=True))
