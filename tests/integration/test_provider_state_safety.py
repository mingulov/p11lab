"""Real-image refusal checks; bind P11LAB_TEST_STATE_IMAGES explicitly."""
import hashlib
import json
import os
import stat
import subprocess

import pytest


IMAGES = json.loads(os.environ.get('P11LAB_TEST_STATE_IMAGES', '{}'))
CASES = [(provider, channel, image) for provider, channels in IMAGES.items()
         for channel, image in channels.items()]


def snapshot(directory):
    result = {}
    for path in sorted(directory.rglob('*')):
        mode = path.lstat().st_mode
        payload = (os.readlink(path) if stat.S_ISLNK(mode) else
                   hashlib.sha256(path.read_bytes()).hexdigest() if stat.S_ISREG(mode) else '')
        result[str(path.relative_to(directory))] = (mode, payload)
    return result


def initialize(image, state, target=None, so_pin='12345678', operation='init'):
    argv = ['docker', 'run', '--rm', '--network', 'none', '--read-only',
            '--user', f'{os.getuid()}:{os.getgid()}', '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges',
            '--tmpfs', f'/run/p11lab:rw,nosuid,nodev,uid={os.getuid()},gid={os.getgid()},mode=0700',
            '--tmpfs', '/tmp:rw,nosuid,nodev',
            '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '-e', 'P11LAB_PIN=1234', '-e', f'P11LAB_SO_PIN={so_pin}']
    if target:
        argv += ['--mount', f'type=bind,src={target},dst=/foreign-target']
    phase = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'echo APP-RAN']
    return subprocess.run(argv + [image, *phase], capture_output=True, text=True, timeout=180)


@pytest.mark.parametrize('provider,channel,image', CASES or [pytest.param('', '', '', marks=pytest.mark.skip(reason='explicit state images required'))])
def test_unreadable_nonempty_state_is_refused_without_provisioning(tmp_path, provider, channel, image):
    state = tmp_path / 'state'
    state.mkdir()
    (state / 'foreign').write_text('must survive')
    before = snapshot(state)
    state.chmod(0o300)  # write/search allowed, enumeration forbidden
    try:
        result = initialize(image, state, so_pin='5678' if provider == 'haskoki' else '12345678')
    finally:
        state.chmod(0o700)
    assert result.returncode != 0, (provider, channel, result.stdout, result.stderr)
    assert 'cannot enumerate' in result.stderr, result.stderr
    assert snapshot(state) == before


@pytest.mark.parametrize('channel,image', [(c, i) for c, i in IMAGES.get('freehsm', {}).items()] or
                         [pytest.param('', '', marks=pytest.mark.skip(reason='explicit FreeHSM images required'))])
@pytest.mark.parametrize('kind', ['owned-link', 'owned-dangling', 'owned-file', 'dotfile',
                                 'dangling-entry', 'audit-directory', 'audit-fifo', 'audit-link', 'audit-name', 'owned-owner'])
def test_freehsm_foreign_state_never_provisions(tmp_path, channel, image, kind):
    state, target = tmp_path / 'state', tmp_path / 'target'
    state.mkdir()
    target.mkdir()
    owned = state / 'freehsm'
    if kind == 'owned-link':
        owned.symlink_to('/foreign-target', target_is_directory=True)
    elif kind == 'owned-dangling':
        owned.symlink_to('/missing')
    elif kind == 'owned-file':
        owned.write_text('foreign')
    elif kind == 'owned-owner':
        state.chmod(0o777)
        foreign_uid = 65534 if os.getuid() != 65534 else 65533
        prepared = subprocess.run(['docker', 'run', '--rm', '--network', 'none',
                                   '--user', f'{foreign_uid}:{os.getgid()}',
                                   '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
                                   '--entrypoint', 'sh', image, '-c',
                                   'mkdir -m 777 /var/lib/p11lab/freehsm'],
                                  capture_output=True, text=True, timeout=30)
        assert prepared.returncode == 0, prepared.stderr
        state.chmod(0o700)
        assert owned.stat().st_uid != os.getuid()
    else:
        owned.mkdir()
        if kind == 'dotfile':
            (owned / '.foreign').write_text('foreign')
        elif kind == 'dangling-entry':
            (owned / 'dangling').symlink_to('/missing')
        elif kind == 'audit-directory':
            (owned / 'audit.log.123').mkdir()
        elif kind == 'audit-fifo':
            os.mkfifo(owned / 'audit.log.123')
        elif kind == 'audit-link':
            (owned / 'audit.log.123').symlink_to('/foreign-target/missing')
        elif kind == 'audit-name':
            (owned / 'audit.log.foreign').write_text('foreign')
    before, target_before = snapshot(state), snapshot(target)
    result = initialize(image, state, target)
    assert result.returncode != 0, (kind, result.stdout, result.stderr)
    assert snapshot(state) == before
    assert snapshot(target) == target_before


@pytest.mark.parametrize('channel,image', [(c, i) for c, i in IMAGES.get('freehsm', {}).items()] or
                         [pytest.param('', '', marks=pytest.mark.skip(reason='explicit FreeHSM images required'))])
@pytest.mark.parametrize('kind', ['dotfile', 'dangling-entry', 'audit-directory', 'audit-name'])
@pytest.mark.parametrize('operation', ['init', 'health', 'exec'])
def test_freehsm_completed_state_refuses_foreign_entries_before_native_calls(tmp_path, channel, image, kind, operation):
    state = tmp_path / 'state'
    state.mkdir()
    result = initialize(image, state)
    assert result.returncode == 0, result.stderr
    owned = state / 'freehsm'
    if kind == 'dotfile':
        (owned / '.foreign').write_text('foreign')
    elif kind == 'dangling-entry':
        (owned / 'dangling').symlink_to('/missing')
    elif kind == 'audit-directory':
        (owned / 'audit.log.999999').mkdir()
    else:
        (owned / 'audit.log.foreign').write_text('foreign')
    before = snapshot(state)
    result = initialize(image, state, operation=operation)
    assert result.returncode != 0, (kind, operation, result.stdout, result.stderr)
    assert 'APP-RAN' not in result.stdout
    # Native info/init would rotate audit logs, so exact equality also proves
    # the refusal precedes module loading, as well as token provisioning.
    assert snapshot(state) == before
