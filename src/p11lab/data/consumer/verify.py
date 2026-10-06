#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Independent positive and negative OpenSSL oracle, Linux and native Windows."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

MESSAGE = b'P11Lab independent PKCS11 smoke v1\n'


def bounded(path, limit):
    with path.open('rb') as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError('artifact exceeds size limit')
    return value


def verify(directory, openssl):
    directory = directory.resolve(strict=True)
    message = bounded(directory / 'message.bin', 128)
    digest = bounded(directory / 'digest.bin', 32)
    if message != MESSAGE or digest != hashlib.sha256(message).digest():
        raise ValueError('smoke message or SHA256 digest does not match the v1 contract')
    if len(bounded(directory / 'signature.raw', 64)) != 64:
        raise ValueError('P256 raw signature must contain exactly 64 bytes')
    bounded(directory / 'signature.der', 72)
    bounded(directory / 'public-key.pem', 192)
    command = [openssl, 'dgst', '-sha256', '-verify', str(directory / 'public-key.pem'),
               '-signature', str(directory / 'signature.der')]
    positive = subprocess.run(command + [str(directory / 'message.bin')], capture_output=True)
    if positive.returncode != 0:
        raise ValueError('OpenSSL rejected the original message signature')
    with tempfile.TemporaryDirectory(prefix='p11lab-negative-') as work:
        altered = Path(work) / 'altered-message.bin'
        altered.write_bytes(message + b'altered\n')
        negative = subprocess.run(command + [str(altered)], capture_output=True)
        if negative.returncode == 0:
            raise ValueError('OpenSSL accepted the altered message')
    print('OpenSSL verified original signature; altered message rejected.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--openssl', default='openssl', help='OpenSSL executable path')
    args = parser.parse_args()
    try:
        verify(args.directory, args.openssl)
    except (OSError, ValueError) as exc:
        # Artifacts are public data. Keep errors generic and do not echo file contents.
        print(f'p11lab verification failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
