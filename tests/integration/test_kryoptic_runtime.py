# Migrated from P11Lab kryoptic-runtime worktree at bc6e5fc941ce54150a3c2902e00fcc4c3da59c34.
# Original test SHA-256: 05325623bb997e20f7117cf541870378dab570eb0c0d79b125238316aeb6f7cc; Apache-2.0.
"""Focused Kryoptic lifecycle and independent C/OpenSSL application acceptance.

Set P11LAB_KRYOPTIC_IMAGES and P11LAB_KRYOPTIC_CONSUMERS to JSON channel/engine-ID
maps. No implicit reuse of images or provider builds occurs during this suite.
"""
from dataclasses import replace
import hashlib
import json
import itertools
import os
from pathlib import Path
import subprocess

import pytest

from p11lab.build import runtime_inputs
from p11lab.catalog import load_environment, validate_build_inputs, package_data
from p11lab.identity import artifact_key
from p11lab.models import ArtifactRef, RunSpec
from p11lab.run import run_application

MODULE = '/usr/local/lib/p11lab/libkryoptic_pkcs11.so'
IMAGES = json.loads(os.environ.get('P11LAB_KRYOPTIC_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_KRYOPTIC_CONSUMERS', '{}'))
CHECKERS = json.loads(os.environ.get('P11LAB_KRYOPTIC_CHECKERS', '{}'))
DAEMONS = json.loads(os.environ.get('P11LAB_KRYOPTIC_PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_KRYOPTIC_CLIENTS', '{}'))
CALLER = os.environ.get('P11LAB_KRYOPTIC_CALLER', '')
COMMANDS = itertools.count()



@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_kryoptic_packaged_runtime_inputs_are_closed(channel):
    spec = load_environment('kryoptic', channel)
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    assert artifact_key('runtime', inputs)
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['cargo_features'] == ['pqc']
    assert inputs['features']['default_features'] is True
    assert any(item['name'] == 'rust' and item['sha256'] for item in inputs['toolchain'])


def docker(*args, check=True):
    argv = ['docker', *args]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    evidence = os.environ.get('P11LAB_KRYOPTIC_EVIDENCE')
    if evidence:
        root = Path(evidence) / 'commands'
        root.mkdir(parents=True, exist_ok=True)
        path = root / f'{next(COMMANDS):04d}.json'
        path.write_text(json.dumps({'argv': argv, 'env': {}, 'returncode': result.returncode,
                                   'stdout': result.stdout, 'stderr': result.stderr}, indent=2) + '\n')
    if check:
        assert result.returncode == 0, result.stderr
    return result


@pytest.fixture(params=list(IMAGES) or ['unconfigured'])
def runtime(request, tmp_path):
    if request.param not in IMAGES:
        pytest.skip('explicit Kryoptic runtime IDs required')
    channel = request.param
    root = Path(os.environ.get('P11LAB_KRYOPTIC_EVIDENCE', str(tmp_path))) / request.node.name
    root.mkdir(parents=True, exist_ok=False)
    state = root / 'state'
    state.mkdir(mode=0o700)
    secrets = root / 'secrets'
    secrets.mkdir(mode=0o700)
    for name, value in [('pin', b'1234'), ('so', b'12345678')]:
        (secrets / name).write_bytes(value)
        (secrets / name).chmod(0o600)
    image = IMAGES[channel]
    base = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', f'/run/p11lab:uid={os.getuid()},gid={os.getgid()},mode=0700',
            '--tmpfs', '/tmp', '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly']
    controls = ['-e', 'P11LAB_LABEL=acceptance', '-e', 'P11LAB_PIN_FILE=/run/secrets/pin', '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so']
    yield channel, root, state, secrets, image, base, controls
    # Test-only credentials are removed from durable evidence.
    for child in secrets.iterdir():
        child.unlink()


def test_native_lifecycle_preserves_state_and_errors(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert json.loads(docker('run', '--rm', image, 'describe').stdout)['module_path'] == MODULE
    assert docker(*base, image, 'init', check=False).returncode != 0
    assert list(state.iterdir()) == []
    docker(*base, *controls, image, 'init')
    first = (state / 'kryoptic/token.sqlite').read_bytes()
    (secrets / 'pin').write_bytes(b'5678')
    (secrets / 'so').write_bytes(b'87654321')
    docker(*base, *controls, image, 'init')
    assert (state / 'kryoptic/token.sqlite').read_bytes() == first
    docker(*base, *controls, image, 'health')
    changed = docker(*base, *controls, '-e', 'P11LAB_LABEL=different', image, 'init', check=False)
    assert changed.returncode != 0 and 'incompatible' in changed.stderr
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c', 'printf "%s\\n" "$KRYOPTIC_CONF" "$P11LAB_MODULE" "$1"; exit 37', 'caller', 'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == ['/var/lib/p11lab/kryoptic/kryoptic.conf', MODULE, 'literal $argument with spaces']
    assert 'pin' not in (state / 'kryoptic/complete').read_text().lower()
    config = (state / 'kryoptic/kryoptic.conf').read_text()
    assert config == '[[slots]]\nslot = 1\ndbtype = "sqlite"\ndbargs = "/var/lib/p11lab/kryoptic/token.sqlite"\n'
    health = docker(*base, *controls, image, 'health')
    assert 'native_slot=1 token_present_index=0 label=acceptance' in health.stdout
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c', 'command -v cargo rustc python3 pkcs11-tool; exit 0').stdout == ''
    (state / 'unexpected').write_bytes(b'partial-state')
    for operation in ['init', 'health']:
        assert docker(*base, *controls, image, operation, check=False).returncode != 0
    assert (state / 'unexpected').read_bytes() == b'partial-state'
    assert (state / 'kryoptic/token.sqlite').read_bytes() == first


def oracle(output):
    result = subprocess.run(['python3', str(package_data('consumer/verify.py')), str(output)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'altered message rejected' in result.stdout
    (output.parent / 'oracle.txt').write_text(result.stdout)


def test_application_crypto_reopens_persistent_key_and_rejects_wrong_pin(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    consumer = CONSUMERS[channel]
    artifact = ArtifactRef('docker-local', consumer, consumer.removeprefix('sha256:'), 'linux/amd64')
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
              'P11LAB_SO_PIN_FILE': str(secrets / 'so'), 'P11LAB_LABEL': 'acceptance'}
    argv = ('p11lab-smoke', '--module', MODULE, '--token-label', 'acceptance', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
            '--output', '/p11lab-output/crypto', '--key-mode', 'generated')
    spec = RunSpec('kryoptic', channel, 'direct', artifact, 'provider', None, None, argv, inputs, root / 'generated', root, 90)
    generated = run_application(spec)
    assert generated.exit_code == 0, generated
    oracle(spec.output_dir / 'crypto')
    provision = replace(spec, output_dir=root / 'provision', argv=('p11lab-token', '--module', MODULE, '--token-label', 'acceptance', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--key-id', '42'))
    assert run_application(provision).exit_code == 0
    public = []
    for number in range(2):
        reopened = replace(spec, output_dir=root / f'reopen-{number}', argv=(*argv[:-1], 'existing', '--key-id', '42'))
        result = run_application(reopened)
        assert result.exit_code == 0, result
        oracle(reopened.output_dir / 'crypto')
        public.append((reopened.output_dir / 'crypto/public-key.der').read_bytes())
        assert not json.loads(result.receipt_path.read_text())['cleanup_errors']
    assert public[0] == public[1]
    (secrets / 'pin').write_bytes(b'wrong-test-pin')
    failed = run_application(replace(spec, output_dir=root / 'wrong-pin'))
    assert failed.app_returncode != 0 and failed.exit_code != 0
    assert 'C_Login: CK_RV=0x000000a0' in (root / 'wrong-pin/application.stderr.log').read_text()
    missing = replace(spec, inputs={k: v for k, v in inputs.items() if k != 'P11LAB_PIN_FILE'}, output_dir=root / 'missing-pin')
    assert run_application(missing).exit_code != 0
    other = root / 'other-state'
    other.mkdir(mode=0o700)
    absent = replace(spec, inputs=inputs | {'P11LAB_STATE_DIR': str(other)}, output_dir=root / 'separate', argv=(*argv[:-1], 'existing', '--key-id', '42'))
    (secrets / 'pin').write_bytes(b'1234')
    assert run_application(absent).exit_code != 0
    assert (other / 'kryoptic/token.sqlite').is_file()
    # Durable public logs/markers never contain PINs or credential hashes.
    for path in root.rglob('*.log'):
        assert b'wrong-test-pin' not in path.read_bytes() and b'12345678' not in path.read_bytes()



def snapshot(state):
    return {str(p.relative_to(state)): ('symlink', os.readlink(p)) if p.is_symlink()
            else ('file', hashlib.sha256(p.read_bytes()).hexdigest()) if p.is_file()
            else ('directory', None) for p in state.rglob('*')}


@pytest.mark.parametrize('damage', ['missing-db', 'empty-db', 'missing-marker', 'marker-extra-lf',
                                  'config-drift', 'hidden-file', 'dangling-link', 'db-link', 'busy-init'])
def test_static_damage_refused_before_open_or_application(runtime, damage):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    owned = state / 'kryoptic'
    if damage == 'missing-db':
        (owned / 'token.sqlite').unlink()
    elif damage == 'empty-db':
        (owned / 'token.sqlite').write_bytes(b'')
    elif damage == 'missing-marker':
        (owned / 'complete').unlink()
    elif damage == 'marker-extra-lf':
        with (owned / 'complete').open('ab') as marker:
            marker.write(b'\n')
    elif damage == 'config-drift':
        (owned / 'kryoptic.conf').write_text('[[slots]]\nslot = 2\n')
    elif damage == 'hidden-file':
        (owned / '.foreign').write_bytes(b'foreign')
    elif damage == 'dangling-link':
        (owned / 'token.sqlite-journal').symlink_to('absent')
    elif damage == 'db-link':
        (owned / 'token.sqlite').rename(owned / 'original.sqlite')
        (owned / 'token.sqlite').symlink_to('original.sqlite')
    else:
        (state / '.init-lock').mkdir()
    before = snapshot(state)
    for operation in ('init', 'health', 'exec'):
        argv = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'echo APP-RAN']
        result = docker(*base, *controls, image, *argv, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert snapshot(state) == before, (damage, operation)


@pytest.mark.parametrize('bad', ['absent-so', 'empty', 'multiline', 'nul', 'too-large', 'conflict'])
def test_bad_credentials_never_create_state(runtime, bad):
    channel, root, state, secrets, image, base, controls = runtime
    if bad == 'absent-so':
        controls = controls[:-2]
    elif bad == 'conflict':
        controls = [*controls, '-e', 'P11LAB_PIN=']
    else:
        (secrets / 'pin').write_bytes({'empty': b'', 'multiline': b'line1\nline2',
                                      'nul': b'nul\0byte', 'too-large': b'x' * 4097}[bad])
    result = docker(*base, *controls, image, 'init', check=False)
    assert result.returncode != 0
    assert list(state.iterdir()) == []
    assert 'conflicting-scalar' not in result.stdout + result.stderr


def as_ref(image):
    return ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')


def lane_root(name, channel, tmp_path):
    evidence = os.environ.get('P11LAB_KRYOPTIC_EVIDENCE')
    root = Path(evidence) / name / channel if evidence else tmp_path
    root.mkdir(parents=True, exist_ok=True)
    caller = root / 'caller'
    caller.mkdir()
    pin, so = root / 'pin', root / 'so'
    pin.write_bytes(b'1234')
    so.write_bytes(b'12345678')
    pin.chmod(0o600)
    so.chmod(0o600)
    return root, caller, pin, so


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_installed_checker_observations(channel, tmp_path):
    if channel not in CHECKERS:
        pytest.skip('explicit installed Kryoptic checker derivative required')
    from p11lab.checker import run_checker
    root, caller, pin, so = lane_root('direct-checker', channel, tmp_path)
    try:
        spec = RunSpec('kryoptic', channel, 'direct', as_ref(CHECKERS[channel]), 'provider', None, None, (),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so)}, root / 'output', caller, 1200)
        result = run_checker(spec, 'smoke-v1')
        assert not result.cleanup_errors
        record = json.loads((spec.output_dir / 'checker/checker-receipt.json').read_text())
        assert record['evidence']['observations_complete'], record
        assert len(record['nodes']) == 23
        assert record['token']['native_slot_id'] == 1 and record['token']['token_present_index'] == 0
        assert record['token']['label'] == 'P11Lab'
        # A completed provider finding is valid evidence, never normalized.
        print(f'checker direct/{channel}: exit={result.exit_code} evidence={record["evidence"]}')
    finally:
        pin.unlink(missing_ok=True)
        so.unlink(missing_ok=True)


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_preferred_proxy_independent_crypto(channel, tmp_path):
    if channel not in DAEMONS or channel not in CLIENTS or not CALLER:
        pytest.skip('explicit pinned Kryoptic daemon, client bundle and caller required')
    root, caller, pin, so = lane_root('proxy-crypto', channel, tmp_path)
    try:
        bundle = Path(CLIENTS[channel])
        client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
        spec = RunSpec('kryoptic', channel, 'proxy', as_ref(DAEMONS[channel]), 'container', as_ref(CALLER), client,
                       ('p11lab-smoke', '--module', '/run/p11lab-client/libpkcs11_proxy_ng_shim.so',
                        '--token-label', 'P11Lab', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
                        '--output', '/p11lab-output/crypto', '--key-mode', 'generated'),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so)}, root / 'output', caller, 600)
        result = run_application(spec)
        assert result.exit_code == 0, result
        assert not result.cleanup_errors
        assert (spec.output_dir / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
        oracle(spec.output_dir / 'crypto')
    finally:
        pin.unlink(missing_ok=True)
        so.unlink(missing_ok=True)
