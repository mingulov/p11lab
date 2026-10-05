"""Narrow deterministic checks for the p11-kit demonstration.

Covers only what is cheap without Docker or network: example wiring
(README links, vessel pin, CLI refusals) and the owned-socket guard
refusal cases. The live server/client route stays in run.sh with its
own retained evidence.
"""
import os
import re
import socket
import stat
import subprocess
from pathlib import Path

import pytest


EXAMPLE = Path(__file__).resolve().parent.parent / 'examples' / 'p11-kit'
LIB = EXAMPLE / 'lib.sh'
RUN = EXAMPLE / 'run.sh'


def run_sh(stdin_script):
    return subprocess.run(['sh', '-c', stdin_script], capture_output=True,
                          text=True, timeout=60)


def guard_call(function, *args):
    quoted = ' '.join(f"'{a}'" for a in args)
    return run_sh(f". '{LIB}'; {function} {quoted}")


def test_readme_relative_links_resolve():
    text = (EXAMPLE / 'README.md').read_text()
    targets = re.findall(r'\]\(([^)#]+)(?:#[^)]*)?\)', text)
    assert targets, 'README has no relative links to check'
    for target in targets:
        if re.match(r'[a-zA-Z][a-zA-Z0-9+.-]*:', target):
            continue
        resolved = (EXAMPLE / target).resolve()
        assert resolved.exists(), target


def test_vessel_base_is_digest_pinned():
    dockerfile = (EXAMPLE / 'Dockerfile.demo').read_text()
    match = re.search(r'^FROM debian:13\.6-slim@sha256:([0-9a-f]{64})$',
                      dockerfile, re.MULTILINE)
    assert match, 'vessel base must pin the debian digest'


def test_run_help_lists_required_inputs():
    proc = subprocess.run([str(RUN), '--help'], capture_output=True,
                          text=True, timeout=60)
    assert proc.returncode == 0
    for flag in ('--archive', '--sha256', '--pin-file', '--so-pin-file',
                 '--output-dir'):
        assert flag in proc.stdout


@pytest.mark.parametrize('argv,reason', [
    (['--archive', 'x'], '--sha256 is required'),
    (['--archive', 'x', '--sha256', 'zz', '--pin-file', 'p',
      '--so-pin-file', 's', '--output-dir', 'o'],
     '--sha256 must be 64 lowercase hex characters'),
    (['--archive', 'no-such-file', '--sha256', '0' * 64, '--pin-file', 'p',
      '--so-pin-file', 's', '--output-dir', 'o'],
     'archive is not a regular file'),
])
def test_run_refuses_bad_inputs_without_docker(tmp_path, argv, reason):
    proc = subprocess.run([str(RUN), *argv], capture_output=True, text=True,
                          timeout=60, cwd=tmp_path)
    assert proc.returncode == 2
    assert f'refused: {reason}' in proc.stderr


def test_run_refuses_existing_output_dir(tmp_path):
    archive = tmp_path / 'a.tar.gz'
    archive.write_bytes(b'x')
    pin = tmp_path / 'pin'
    pin.write_bytes(b'1')
    out = tmp_path / 'out'
    out.mkdir()
    proc = subprocess.run(
        [str(RUN), '--archive', str(archive), '--sha256', '0' * 64,
         '--pin-file', str(pin), '--so-pin-file', str(pin),
         '--output-dir', str(out)],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 2
    assert 'refused: output dir already exists' in proc.stderr


def test_own_private_dir_happy_path(tmp_path):
    target = tmp_path / 'xdg'
    proc = guard_call('own_private_dir', str(target))
    assert proc.returncode == 0, proc.stderr
    mode = stat.S_IMODE(target.stat().st_mode)
    assert mode == 0o700
    assert target.stat().st_uid == os.geteuid()


def test_own_private_dir_refuses_foreign_content(tmp_path):
    target = tmp_path / 'xdg'
    target.mkdir()
    (target / 'pkcs11-1').write_bytes(b'alien')
    proc = guard_call('own_private_dir', str(target))
    assert proc.returncode == 1
    assert 'refused: socket parent is not empty' in proc.stderr


def test_own_private_dir_refuses_file_at_path(tmp_path):
    target = tmp_path / 'xdg'
    target.write_bytes(b'alien')
    proc = guard_call('own_private_dir', str(target))
    assert proc.returncode == 1
    assert 'refused: socket parent exists and is not a directory' in proc.stderr


def test_own_private_dir_refuses_foreign_uid(tmp_path):
    target = tmp_path / 'xdg'
    proc = guard_call('own_private_dir', str(target), '424242')
    assert proc.returncode == 1
    assert 'want 424242' in proc.stderr


def bind_owned_socket(directory):
    directory.mkdir(mode=0o700)
    path = directory / 'pkcs11-test'
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    return path, server


def test_assert_owned_socket_happy_path(tmp_path):
    path, server = bind_owned_socket(tmp_path / 'p11-kit')
    try:
        proc = guard_call('assert_owned_socket', str(path))
        assert proc.returncode == 0, proc.stderr
    finally:
        server.close()


def test_assert_owned_socket_refuses_plain_file(tmp_path):
    target = tmp_path / 'not-a-socket'
    target.write_bytes(b'x')
    proc = guard_call('assert_owned_socket', str(target))
    assert proc.returncode == 1
    assert 'refused: not a socket' in proc.stderr


def test_assert_owned_socket_refuses_foreign_uid(tmp_path):
    path, server = bind_owned_socket(tmp_path / 'p11-kit')
    try:
        proc = guard_call('assert_owned_socket', str(path), '424242')
        assert proc.returncode == 1
        assert 'want 424242' in proc.stderr
    finally:
        server.close()


def test_single_socket_counts_entries(tmp_path):
    empty = tmp_path / 'empty'
    empty.mkdir()
    proc = guard_call('single_socket', str(empty))
    assert proc.returncode == 1
    assert 'found 0' in proc.stderr
    two = tmp_path / 'two'
    two.mkdir()
    (two / 'a').write_bytes(b'x')
    (two / 'b').write_bytes(b'x')
    proc = guard_call('single_socket', str(two))
    assert proc.returncode == 1
    assert 'found 2' in proc.stderr
    one = tmp_path / 'one'
    one.mkdir()
    only = one / 'pkcs11-9'
    only.write_bytes(b'x')
    proc = guard_call('single_socket', str(one))
    assert proc.returncode == 0
    assert proc.stdout.strip() == str(only)
