"""Run real image acceptance with P11LAB_TEST_RUNTIME_IMAGES (comma-separated IDs).

P11LAB_TEST_CONSUMER_IMAGE supplies a separate compatible OpenSC consumer.
The base image is never modified by the tests.
"""
import json
import os
from pathlib import Path
import subprocess
from uuid import uuid4

import pytest

IMAGES = os.environ.get('P11LAB_TEST_RUNTIME_IMAGES', '').split(',')
pytestmark = pytest.mark.skipif(not IMAGES[0], reason='explicit built runtime images required')


def docker(*args, check=True):
    return subprocess.run(['docker', *args], capture_output=True, text=True, check=check)


@pytest.mark.parametrize('image', IMAGES)
def test_real_standalone_lifecycle(image, tmp_path):
    volume = 'p11lab-t2-' + uuid4().hex
    partial = volume + '-partial'
    consumer = json.loads(os.environ['P11LAB_TEST_CONSUMER_IMAGES'])[image] if 'P11LAB_TEST_CONSUMER_IMAGES' in os.environ else os.environ['P11LAB_TEST_CONSUMER_IMAGE']
    docker('volume', 'create', volume)
    docker('volume', 'create', partial)
    secrets = tmp_path / 'secrets'
    secrets.mkdir()
    (secrets / 'pin').write_text('1234')
    (secrets / 'so-pin').write_text('12345678')
    base = ['run', '--rm', '--network', 'none', '-v', volume + ':/var/lib/p11lab', '-v', str(secrets) + ':/run/secrets:ro']
    controls = ['-e', 'P11LAB_LABEL=acceptance', '-e', 'P11LAB_PIN_FILE=/run/secrets/pin', '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so-pin']
    try:
        description = json.loads(docker('run', '--rm', image, 'describe').stdout)
        assert description['module_path'] == '/usr/local/lib/p11lab/libsofthsm2.so'
        assert docker(*base, *controls, image, 'init').returncode == 0
        before = docker(*base, *controls, image, 'exec', '--', 'sh', '-c', 'find /var/lib/p11lab -type f -exec sha256sum {} + | sort').stdout
        (secrets / 'pin').write_text('5678')
        (secrets / 'so-pin').write_text('87654321')
        docker(*base, *controls, image, 'init')
        after = docker(*base, *controls, image, 'exec', '--', 'sh', '-c', 'find /var/lib/p11lab -type f -exec sha256sum {} + | sort').stdout
        assert before == after
        docker(*base, *controls, image, 'health')
        changed = docker(*base, '-e', 'P11LAB_LABEL=different', image, 'init', check=False)
        assert changed.returncode != 0 and 'incompatible' in changed.stderr
        # Derivative consumer has only OpenSC plus the compatible provider closure.
        listed = docker(*base, '-e', 'P11LAB_LABEL=acceptance', consumer, 'exec', '--', 'pkcs11-tool', '--module', description['module_path'], '--list-token-slots').stdout
        assert 'acceptance' in listed
        assert 'Slot 0' in listed
        docker(*base, '-e', 'P11LAB_LABEL=acceptance', consumer, 'exec', '--', 'pkcs11-tool', '--module', description['module_path'], '--login', '--pin', '1234', '--list-objects')
        conflict = docker(*base, *controls, '-e', 'P11LAB_PIN=other', image, 'init', check=False)
        assert conflict.returncode != 0 and 'conflicting' in conflict.stderr
        stripped = docker(*base, *controls, image, 'exec', '--', 'sh', '-c', 'command -v python python3 pkcs11-check pkcs11-tool; exit 0').stdout
        assert stripped == ''
        result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c', 'printf "%s\\n" "$SOFTHSM2_CONF" "$P11LAB_MODULE" "$1"; exit 37', 'caller', 'literal $argument with spaces', check=False)
        assert result.returncode == 37
        assert result.stdout.splitlines() == ['/run/p11lab/softhsm2.conf', description['module_path'], 'literal $argument with spaces']
        docker('run', '--rm', '-v', partial + ':/var/lib/p11lab', '--entrypoint', 'sh', image, '-c', 'touch /var/lib/p11lab/unknown')
        result = docker('run', '--rm', '-v', partial + ':/var/lib/p11lab', *controls, image, 'init', check=False)
        assert result.returncode != 0 and 'partial' in result.stderr
        marker = docker(*base, *controls, image, 'exec', '--', 'cat', '/var/lib/p11lab/softhsm2/complete').stdout
        assert {line.split('=', 1)[0] for line in marker.splitlines()} == {'schema', 'provider', 'artifact', 'label', 'backend'}
        assert 'label=acceptance' in marker
        assert 'pin' not in marker.lower()
    finally:
        docker('volume', 'rm', volume, check=False)
        docker('volume', 'rm', partial, check=False)


@pytest.mark.parametrize('image', IMAGES)
@pytest.mark.parametrize('controls, message', [
    ([], 'absent'),
    (['-e', 'P11LAB_PIN=', '-e', 'P11LAB_SO_PIN=12345678'], 'empty'),
    (['-e', 'P11LAB_PIN=1234'], 'absent'),
    (['-e', 'P11LAB_PIN=1234', '-e', 'P11LAB_PIN_FILE=/missing', '-e', 'P11LAB_SO_PIN=12345678'], 'conflicting'),
    (['-e', 'P11LAB_PIN_FILE=/missing', '-e', 'P11LAB_SO_PIN=12345678'], 'readable'),
])
def test_initial_credentials_fail_explicitly(image, controls, message):
    result = docker('run', '--rm', '--network', 'none', *controls, image, 'init', check=False)
    assert result.returncode != 0 and message in result.stderr


@pytest.mark.parametrize('image', IMAGES)
def test_permissions_fail_before_native_initialization(image):
    result = docker('run', '--rm', '--network', 'none', '--user', '65534:65534', '-e', 'P11LAB_PIN=1234', '-e', 'P11LAB_SO_PIN=12345678', image, 'init', check=False)
    assert result.returncode != 0 and 'permissions' in result.stderr


@pytest.mark.parametrize('image', IMAGES)
def test_completion_marker_rename_stays_on_state_filesystem(image, tmp_path):
    # A real separate tmpfs for controls and Docker volume for state make cross-
    # filesystem mv observable. The wrapper enforces rename's required boundary;
    # it delegates every same-device move to the stock mv executable.
    tools = tmp_path / 'tools'
    tools.mkdir()
    move = tools / 'mv'
    move.write_text('''#!/bin/sh
while [ "$1" = -- ] || [ "$1" = -f ]; do shift; done
[ "$(stat -c %d "$1")" = "$(stat -c %d "$(dirname "$2")")" ] || { echo 'non-atomic cross-filesystem marker move' >&2; exit 88; }
exec /usr/bin/mv "$@"
''')
    move.chmod(0o755)
    volume = 'p11lab-t2-atomic-' + uuid4().hex
    docker('volume', 'create', volume)
    try:
        result = docker('run', '--rm', '--network', 'none', '--tmpfs', '/run/p11lab', '-v', volume + ':/var/lib/p11lab', '-v', str(tools) + ':/acceptance-tools:ro', '-e', 'PATH=/acceptance-tools:/usr/local/bin:/usr/bin:/bin', '-e', 'P11LAB_PIN=1234', '-e', 'P11LAB_SO_PIN=12345678', image, 'init', check=False)
        assert result.returncode == 0, result.stderr
        docker('run', '--rm', '--network', 'none', '-v', volume + ':/var/lib/p11lab', image, 'health')
    finally:
        docker('volume', 'rm', volume, check=False)


@pytest.mark.parametrize('image', IMAGES)
@pytest.mark.parametrize('state', ['fresh', 'unknown-partial', 'incompatible'])
def test_exec_does_not_reach_caller_before_readiness(image, state):
    setup = {
        'fresh': ':',
        'unknown-partial': 'touch /var/lib/p11lab/unknown',
        'incompatible': 'p11lab-provider init && export P11LAB_LABEL=different',
    }[state]
    command = setup + '''
status=0
p11lab-provider exec -- sh -c 'echo APP-RAN; touch /tmp/app-ran' || status=$?
[ ! -e /tmp/app-ran ] || exit 90
exit "$status"
'''
    result = docker('run', '--rm', '--network', 'none', '--entrypoint', 'sh', '-e', 'P11LAB_PIN=1234', '-e', 'P11LAB_SO_PIN=12345678', image, '-c', command, check=False)
    assert result.returncode != 0 and result.returncode != 90
    assert 'APP-RAN' not in result.stdout
    assert ('incompatible' if state == 'incompatible' else 'partial') in result.stderr


@pytest.mark.parametrize('image', IMAGES)
@pytest.mark.parametrize('lost', ['all-files', 'token-object'])
def test_lost_token_contents_are_not_reinitialized_or_ready(image, lost):
    volume = 'p11lab-t2-lost-' + uuid4().hex
    docker('volume', 'create', volume)
    base = ['run', '--rm', '--network', 'none', '-v', volume + ':/var/lib/p11lab']
    try:
        docker(*base, '-e', 'P11LAB_PIN=1234', '-e', 'P11LAB_SO_PIN=12345678', image, 'init')
        deletion = 'find /var/lib/p11lab/softhsm2/tokens -type f'
        if lost == 'token-object':
            deletion += ' -name token.object'
        docker(*base, '--entrypoint', 'sh', image, '-c', deletion + ' -delete')
        snapshot = ['--entrypoint', 'sh', image, '-c', 'find /var/lib/p11lab -type f -exec sha256sum {} + | sort']
        before = docker(*base, *snapshot).stdout
        for operation in ('init', 'health'):
            result = docker(*base, image, operation, check=False)
            assert result.returncode != 0 and 'partial' in result.stderr
        result = docker(*base, image, 'exec', '--', 'sh', '-c', 'echo APP-RAN', check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert docker(*base, *snapshot).stdout == before
    finally:
        docker('volume', 'rm', volume, check=False)
