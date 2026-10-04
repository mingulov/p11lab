"""Fetch the sealed Go module closure; the compile step stays offline.

SPDX-License-Identifier: Apache-2.0
Only the builder runs this helper. Module versions come from the patched
go.mod/go.sum (no `go get`, no tidy, no resolver); every archive is verified
against go.sum during download, re-verified with `go mod verify`, and the
resolved module set is compared to the P11Lab channel manifest.
"""
import json
import os
from pathlib import Path
import subprocess

SOURCE = Path('/build/kms')
MANIFEST = Path('/tmp/go-modules.json')


def run(argv, **kwargs):
    env = dict(os.environ)
    env.update({'GOPROXY': 'https://proxy.golang.org', 'GOSUMDB': 'sum.golang.org',
                'GOFLAGS': '-mod=readonly', 'GOMAXPROCS': '2', 'GOTOOLCHAIN': 'local'})
    result = subprocess.run(argv, cwd=SOURCE, env=env, capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise SystemExit(f'command failed: {argv[:3]}\n{result.stderr[-2000:]}')
    return result


def main():
    expected = {(m['module'], m['version']) for m in json.loads(MANIFEST.read_text())['modules']}
    before_mod = (SOURCE / 'go.mod').read_bytes()
    before_sum = (SOURCE / 'go.sum').read_bytes()
    go = os.environ.get('P11LAB_GO', 'go')
    run([go, 'mod', 'download', 'all'])
    verified = run([go, 'mod', 'verify'])
    if 'all modules verified' not in verified.stdout:
        raise SystemExit('go mod verify did not confirm the module closure')
    listed = run([go, 'list', '-m', 'all']).stdout.splitlines()
    actual = set()
    for line in listed[1:]:
        parts = line.split()
        if len(parts) >= 2:
            actual.add((parts[0], parts[1]))
    if actual != expected:
        raise SystemExit(f'module set differs from manifest: {sorted(actual ^ expected)[:8]}')
    if (SOURCE / 'go.mod').read_bytes() != before_mod or (SOURCE / 'go.sum').read_bytes() != before_sum:
        raise SystemExit('go.mod/go.sum mutated during frozen fetch')
    Path('/build/gomod-inventory.json').write_text(json.dumps(
        {'modules': sorted(f'{m} {v}' for m, v in sorted(actual)),
         'verify': verified.stdout.strip()}, indent=1) + '\n')
    print(f'verified {len(actual)} sealed Go modules', flush=True)


main()
