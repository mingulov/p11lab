"""Narrow deterministic checks for the p11scope demonstration.

Covers only what is cheap without network or Docker: the frozen pin
shape, example wiring (README links, vessel pin, CLI refusals), and the
hash-verify refusal cases. Bundle fetch, preflight, and live capture
stay in run.sh with its own retained evidence.
"""
import hashlib
import re
import subprocess
from pathlib import Path


EXAMPLE = Path(__file__).resolve().parent.parent / 'examples' / 'p11scope'
LIB = EXAMPLE / 'lib.sh'
RUN = EXAMPLE / 'run.sh'
PINS = EXAMPLE / 'pins.env'


def read_pins():
    script = (f". '{PINS}' && printf '%s\\n' \"$P11SCOPE_VERSION\" "
              f"\"$P11SCOPE_TAG_OBJECT\" \"$P11SCOPE_REV\" "
              f"\"$P11SCOPE_BUNDLE_URL\" \"$P11SCOPE_BUNDLE_SHA256\"")
    proc = subprocess.run(['sh', '-c', script], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.splitlines()


def test_pins_shape_and_consistency():
    version, tag_object, rev, url, digest = read_pins()
    assert re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', version), version
    assert re.fullmatch(r'[0-9a-f]{40}', tag_object), tag_object
    assert re.fullmatch(r'[0-9a-f]{40}', rev), rev
    assert re.fullmatch(r'[0-9a-f]{64}', digest), digest
    expect = (f'https://github.com/mingulov/p11scope/releases/download/'
              f'v{version}/p11scope-{version}-x86_64-linux-musl.tar.gz')
    assert url == expect, url


def test_readme_relative_links_resolve():
    text = (EXAMPLE / 'README.md').read_text()
    targets = re.findall(r'\]\(([^)#]+)(?:#[^)]*)?\)', text)
    relative = [t for t in targets
                if not re.match(r'[a-zA-Z][a-zA-Z0-9+.-]*:', t)]
    assert relative, 'README has no relative links to check'
    for target in relative:
        assert (EXAMPLE / target).exists(), target


def test_vessel_base_is_digest_pinned():
    dockerfile = (EXAMPLE / 'Dockerfile.demo').read_text()
    match = re.search(r'^FROM debian:13\.6-slim@sha256:([0-9a-f]{64})$',
                      dockerfile, re.MULTILINE)
    assert match, 'vessel base must pin the debian digest'


def test_run_help_lists_inputs():
    proc = subprocess.run([str(RUN), '--help'], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0
    for flag in ('--output-dir', '--privileged', '--tag', '--rebuild'):
        assert flag in proc.stdout


def test_run_refuses_missing_output_dir(tmp_path):
    proc = subprocess.run([str(RUN)], capture_output=True, text=True,
                          timeout=60, cwd=tmp_path)
    assert proc.returncode == 2
    assert 'refused: --output-dir is required' in proc.stderr


def test_run_refuses_existing_output_dir(tmp_path):
    out = tmp_path / 'out'
    out.mkdir()
    proc = subprocess.run([str(RUN), '--output-dir', str(out)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2
    assert 'refused: output dir already exists' in proc.stderr


def test_run_refuses_unknown_argument(tmp_path):
    proc = subprocess.run([str(RUN), '--bogus', 'x'], capture_output=True,
                          text=True, timeout=60, cwd=tmp_path)
    assert proc.returncode == 2
    assert 'refused: unknown argument' in proc.stderr


def guard_call(function, *args):
    quoted = ' '.join(f"'{a}'" for a in args)
    return subprocess.run(['sh', '-c', f". '{LIB}'; {function} {quoted}"],
                          capture_output=True, text=True, timeout=60)


def test_verify_sha256_happy_path(tmp_path):
    target = tmp_path / 'file.bin'
    target.write_bytes(b'pinned-bytes')
    digest = hashlib.sha256(b'pinned-bytes').hexdigest()
    proc = guard_call('verify_sha256', str(target), digest)
    assert proc.returncode == 0, proc.stderr


def test_verify_sha256_refuses_mismatch(tmp_path):
    target = tmp_path / 'file.bin'
    target.write_bytes(b'other-bytes')
    proc = guard_call('verify_sha256', str(target), '0' * 64)
    assert proc.returncode == 1
    assert 'refused: sha256 mismatch' in proc.stderr


def test_verify_sha256_refuses_bad_shapes(tmp_path):
    target = tmp_path / 'file.bin'
    target.write_bytes(b'x')
    proc = guard_call('verify_sha256', str(target), 'zz')
    assert proc.returncode == 1
    assert 'refused: expected sha256 is not hex' in proc.stderr
    proc = guard_call('verify_sha256', str(tmp_path / 'missing'), '0' * 64)
    assert proc.returncode == 1
    assert 'refused: not a regular file' in proc.stderr


def test_pinned_bundle_hash_is_plausible():
    _, _, _, _, digest = read_pins()
    assert digest != '0' * 64
