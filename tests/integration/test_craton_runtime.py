# SPDX-License-Identifier: Apache-2.0
"""Focused Craton lifecycle and independent C/OpenSSL application acceptance.

Set P11LAB_CRATON_IMAGES and P11LAB_CRATON_CONSUMERS to JSON channel/engine-ID
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

MODULE = '/usr/local/lib/p11lab/libcraton_hsm.so'
IMAGES = json.loads(os.environ.get('P11LAB_CRATON_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_CRATON_CONSUMERS', '{}'))
CHECKERS = json.loads(os.environ.get('P11LAB_CRATON_CHECKERS', '{}'))
DAEMONS = json.loads(os.environ.get('P11LAB_CRATON_PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_CRATON_CLIENTS', '{}'))
CALLER = os.environ.get('P11LAB_CRATON_CALLER', '')
COMMANDS = itertools.count()



@pytest.mark.parametrize('channel', ['rolling'])
def test_craton_packaged_runtime_inputs_are_closed(channel):
    spec = load_environment('craton', channel)
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    assert artifact_key('runtime', inputs)
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['cargo_features'] == []
    assert inputs['features']['default_features'] is True
    assert any(item['name'] == 'rust' and item['sha256'] for item in inputs['toolchain'])
    assert spec['channels']['release']['status'] == 'unavailable'
    assert spec['distribution']['status'] == 'unreviewed'
    assert inputs['patches'] == []
    assert inputs['features']['insecure_rustcrypto_rsa_private_ops'] is False
    assert spec['state_mode'] == 'persistent'


def docker(*args, check=True):
    argv = ['docker', *args]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    evidence = os.environ.get('P11LAB_CRATON_EVIDENCE')
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
        pytest.skip('explicit Craton runtime IDs required')
    channel = request.param
    root = Path(os.environ.get('P11LAB_CRATON_EVIDENCE', str(tmp_path))) / request.node.name
    root.mkdir(parents=True, exist_ok=False)
    state = root / 'state'
    state.mkdir(mode=0o700)
    secrets = root / 'secrets'
    secrets.mkdir(mode=0o700)
    for name, value in [('pin', b'UserPin1'), ('so', b'SoPin1234')]:
        (secrets / name).write_bytes(value)
        (secrets / name).chmod(0o600)
    image = IMAGES[channel]
    base = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', f'/run/p11lab:uid={os.getuid()},gid={os.getgid()},mode=0700',
            '--tmpfs', '/tmp', '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly']
    controls = ['-e', 'CRATON_HSM_INTEGRITY_BYPASS=unsafe-dev-only', '-e', 'P11LAB_LABEL=acceptance', '-e', 'P11LAB_PIN_FILE=/run/secrets/pin', '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so']
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
    # redb updates its recovery/transaction header on normal open/close.
    # Auth state must survive repeated init; key identity is checked below.
    first = (state / 'craton/store/token_state_0.json').read_bytes()
    (secrets / 'pin').write_bytes(b'ChangedPin8')
    (secrets / 'so').write_bytes(b'ChangedSo8')
    docker(*base, *controls, image, 'init')
    assert (state / 'craton/store/token_state_0.json').read_bytes() == first
    docker(*base, *controls, image, 'health')
    changed = docker(*base, *controls, '-e', 'P11LAB_LABEL=different', image, 'init', check=False)
    assert changed.returncode != 0 and 'incompatible' in changed.stderr
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c', 'printf "%s\\n" "$CRATON_HSM_CONFIG" "$P11LAB_MODULE" "$1"; exit 37', 'caller', 'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == ['craton_hsm.toml', MODULE, 'literal $argument with spaces']
    assert 'pin' not in (state / 'craton/complete').read_text().lower()
    config = (state / 'craton/craton_hsm.toml').read_text()
    assert config == '[token]\nlabel = "acceptance"\nstorage_path = "store"\npersist_objects = true\nslot_count = 1\n[audit]\nenabled = false\n'
    health = docker(*base, *controls, image, 'health')
    assert 'native_slot=0 token_present_index=0 label=acceptance' in health.stdout
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c', 'command -v cargo rustc python3 pkcs11-tool; exit 0').stdout == ''
    (state / 'unexpected').write_bytes(b'partial-state')
    for operation in ['init', 'health']:
        assert docker(*base, *controls, image, operation, check=False).returncode != 0
    assert (state / 'unexpected').read_bytes() == b'partial-state'
    assert (state / 'craton/store/token_state_0.json').read_bytes() == first


def oracle(output):
    argv = ['python3', str(package_data('consumer/verify.py')), str(output)]
    result = subprocess.run(argv, capture_output=True, text=True)
    (output.parent / 'oracle-result.json').write_text(json.dumps({
        'argv': argv, 'env': {}, 'returncode': result.returncode,
        'stdout': result.stdout, 'stderr': result.stderr}, indent=2) + '\n')
    assert result.returncode == 0, result.stderr
    assert 'altered message rejected' in result.stdout
    (output.parent / 'oracle.txt').write_text(result.stdout)


def test_application_crypto_reopens_persistent_key_and_rejects_wrong_pin(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    consumer = CONSUMERS[channel]
    artifact = ArtifactRef('docker-local', consumer, consumer.removeprefix('sha256:'), 'linux/amd64')
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
              'P11LAB_SO_PIN_FILE': str(secrets / 'so'), 'P11LAB_LABEL': 'acceptance', 'CRATON_HSM_INTEGRITY_BYPASS': 'unsafe-dev-only'}
    argv = ('p11lab-smoke', '--module', MODULE, '--token-label', 'acceptance', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
            '--output', '/p11lab-output/crypto', '--key-mode', 'generated')
    spec = RunSpec('craton', channel, 'direct', artifact, 'provider', None, None, argv, inputs, root / 'generated', root, 90)
    generated = run_application(spec)
    assert generated.exit_code == 0, generated
    oracle_failures = []
    try:
        oracle(spec.output_dir / 'crypto')
    except AssertionError as error:
        oracle_failures.append(str(error))
    provision = replace(spec, output_dir=root / 'provision', argv=('p11lab-token', '--module', MODULE, '--token-label', 'acceptance', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--key-id', '42'))
    assert run_application(provision).exit_code == 0
    public = []
    for number in range(2):
        reopened = replace(spec, output_dir=root / f'reopen-{number}', argv=(*argv[:-1], 'existing', '--key-id', '42'))
        result = run_application(reopened)
        assert result.exit_code == 0, result
        try:
            oracle(reopened.output_dir / 'crypto')
        except AssertionError as error:
            oracle_failures.append(str(error))
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
    (secrets / 'pin').write_bytes(b'UserPin1')
    assert run_application(absent).exit_code != 0
    assert (other / 'craton/store/objects.redb').is_file()
    # Durable public logs/markers never contain PINs or credential hashes.
    for path in root.rglob('*.log'):
        assert b'wrong-test-pin' not in path.read_bytes() and b'SoPin1234' not in path.read_bytes()
    # Every promised persistence/error probe runs even when the provider's
    # independent crypto oracle fails. The failure remains an acceptance block.
    assert not oracle_failures, oracle_failures



def snapshot(state):
    def content(p):
        # Ownership tests deliberately make files unreadable to the test user;
        # byte equality there is verified by the privileged container readback.
        if p.is_symlink():
            return ('symlink', os.readlink(p))
        if p.is_file():
            try:
                return ('file', hashlib.sha256(p.read_bytes()).hexdigest())
            except PermissionError:
                return ('unreadable', None)
        return ('directory', None)
    return {str(p.relative_to(state)): {
        'content': content(p),
        'uid': p.lstat().st_uid, 'mode': p.lstat().st_mode, 'links': p.lstat().st_nlink,
    } for p in [state, *state.rglob('*')]}


@pytest.mark.parametrize('damage', ['missing-db', 'empty-db', 'missing-marker', 'marker-extra-lf',
                                  'marker-nul', 'bad-db-header', 'config-drift', 'hidden-file', 'hard-link', 'dangling-link', 'db-link', 'busy-init'])
def test_static_damage_refused_before_open_or_application(runtime, damage):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    docker(*base, *controls, image, 'health')
    owned = state / 'craton'
    if damage == 'missing-db':
        (owned / 'store/objects.redb').unlink()
    elif damage == 'empty-db':
        (owned / 'store/objects.redb').write_bytes(b'')
    elif damage == 'missing-marker':
        (owned / 'complete').unlink()
    elif damage == 'marker-extra-lf':
        with (owned / 'complete').open('ab') as marker:
            marker.write(b'\n')
    elif damage == 'marker-nul':
        with (owned / 'complete').open('ab') as marker:
            marker.write(b'\0')
    elif damage == 'bad-db-header':
        (owned / 'store/objects.redb').write_bytes(b'not-a-redb-database')
    elif damage == 'hard-link':
        os.link(owned / 'complete', root / 'foreign-marker')
    elif damage == 'config-drift':
        (owned / 'craton_hsm.toml').write_text('[[slots]]\nslot = 2\n')
    elif damage == 'hidden-file':
        (owned / '.foreign').write_bytes(b'foreign')
    elif damage == 'dangling-link':
        (owned / 'store/foreign-lock').symlink_to('absent')
    elif damage == 'db-link':
        (owned / 'store/objects.redb').rename(owned / 'store/original.redb')
        (owned / 'store/objects.redb').symlink_to('original.redb')
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


@pytest.mark.parametrize('target', ['root', 'owned', 'database'])
def test_state_ownership_mismatch_refused_before_open(runtime, target):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    docker(*base, *controls, image, 'health')
    path = {'root': '/var/lib/p11lab', 'owned': '/var/lib/p11lab/craton',
            'database': '/var/lib/p11lab/craton/store/objects.redb'}[target]
    # Only this fixture's state mount is changed, then restored by exact path.
    owner = os.getuid() + 1
    management = ['run', '--rm', '--network', 'none', '--mount',
                  f'type=bind,src={state},dst=/var/lib/p11lab', '--entrypoint', 'chown', image]
    docker(*management, str(owner), path)
    try:
        before = snapshot(state)
        content_command = ['run', '--rm', '--network', 'none', '--mount',
                           f'type=bind,src={state},dst=/var/lib/p11lab,readonly',
                           '--entrypoint', 'sh', image, '-c',
                           'find /var/lib/p11lab -type f -exec sha256sum {} + | sort']
        contents = docker(*content_command).stdout
        for operation in ('init', 'health', 'exec'):
            argv = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'echo APP-RAN']
            result = docker(*base, *controls, image, *argv, check=False)
            assert result.returncode != 0 and 'APP-RAN' not in result.stdout
            assert snapshot(state) == before
            # The test user cannot traverse a now foreign-owned mode-0700
            # directory. An inert privileged read checks every DB/WAL/file byte.
            assert docker(*content_command).stdout == contents
    finally:
        docker(*management, f'{os.getuid()}:{os.getgid()}', path)


def as_ref(image):
    return ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')


def lane_root(name, channel, tmp_path):
    evidence = os.environ.get('P11LAB_CRATON_EVIDENCE')
    root = Path(evidence) / name / channel if evidence else tmp_path
    root.mkdir(parents=True, exist_ok=True)
    caller = root / 'caller'
    caller.mkdir()
    pin, so = root / 'pin', root / 'so'
    pin.write_bytes(b'UserPin1')
    so.write_bytes(b'SoPin1234')
    pin.chmod(0o600)
    so.chmod(0o600)
    return root, caller, pin, so


@pytest.mark.parametrize('channel', ['rolling'])
def test_installed_checker_observations(channel, tmp_path):
    if channel not in CHECKERS:
        pytest.skip('explicit installed Craton checker derivative required')
    from p11lab.checker import run_checker
    root, caller, pin, so = lane_root('direct-checker', channel, tmp_path)
    try:
        spec = RunSpec('craton', channel, 'direct', as_ref(CHECKERS[channel]), 'provider', None, None, (),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so), 'CRATON_HSM_INTEGRITY_BYPASS': 'unsafe-dev-only'}, root / 'output', caller, 1200)
        result = run_checker(spec, 'smoke-v1')
        assert not result.cleanup_errors
        record = json.loads((spec.output_dir / 'checker/checker-receipt.json').read_text())
        # Record the real lane result; a test pass means evidence retained, not smoke qualification.
        (root / 'lane-observation.json').write_text(json.dumps({'exit_code': result.exit_code, 'evidence': record['evidence'], 'nodes': record['nodes']}, indent=2) + '\n')
        assert len(record['nodes']) == 23
        assert record['token']['native_slot_id'] == 0 and record['token']['token_present_index'] == 0
        assert record['token']['label'] == 'P11Lab'
        # A completed provider finding is valid evidence, never normalized.
        print(f'checker direct/{channel}: exit={result.exit_code} evidence={record["evidence"]}')
    finally:
        pin.unlink(missing_ok=True)
        so.unlink(missing_ok=True)


@pytest.mark.parametrize('channel', ['rolling'])
def test_preferred_proxy_independent_crypto(channel, tmp_path):
    if channel not in DAEMONS or channel not in CLIENTS or not CALLER:
        pytest.skip('explicit pinned Craton daemon, client bundle and caller required')
    root, caller, pin, so = lane_root('proxy-crypto', channel, tmp_path)
    try:
        bundle = Path(CLIENTS[channel])
        client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
        spec = RunSpec('craton', channel, 'proxy', as_ref(DAEMONS[channel]), 'container', as_ref(CALLER), client,
                       ('p11lab-smoke', '--module', '/run/p11lab-client/libpkcs11_proxy_ng_shim.so',
                        '--token-label', 'P11Lab', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
                        '--output', '/p11lab-output/crypto', '--key-mode', 'generated'),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so), 'CRATON_HSM_INTEGRITY_BYPASS': 'unsafe-dev-only'}, root / 'output', caller, 600)
        result = run_application(spec)
        assert result.app_returncode == 0, result
        assert not result.cleanup_errors
        assert (spec.output_dir / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
        errors = list(result.lifecycle_errors)
        try:
            oracle(spec.output_dir / 'crypto')
        except AssertionError as error:
            errors.append(str(error))
        assert result.exit_code == 0 and not errors, errors
    finally:
        pin.unlink(missing_ok=True)
        so.unlink(missing_ok=True)


def test_unsigned_runtime_requires_explicit_integrity_opt_in(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    absent = controls[2:]
    for value in (None, '', 'true'):
        options = absent if value is None else [*absent, '-e', 'CRATON_HSM_INTEGRITY_BYPASS=' + value]
        result = docker(*base, *options, image, 'init', check=False)
        assert result.returncode != 0 and 'requires explicit' in result.stderr
        assert list(state.iterdir()) == []
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    for argv in (('health',), ('exec', '--', 'sh', '-c', 'echo APP-RAN')):
        result = docker(*base, *absent, image, *argv, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert snapshot(state) == before


def test_occupied_native_store_preserves_error_and_state(runtime):
    import fcntl
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    docker(*base, *controls, image, 'health')
    before = snapshot(state)
    with (state / 'craton/store/objects.redb.lock').open('r+b') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for argv in (('health',), ('exec', '--', 'sh', '-c', 'echo APP-RAN')):
            result = docker(*base, *controls, image, *argv, check=False)
            assert result.returncode != 0 and 'C_Initialize: CK_RV=0x00000005' in result.stderr
            assert 'APP-RAN' not in result.stdout and 'panicked' not in result.stderr
            assert snapshot(state) == before
    docker(*base, *controls, image, 'health')


@pytest.mark.parametrize('role', ['pin', 'so'])
def test_digit_only_pin_retains_native_policy_error(runtime, role):
    channel, root, state, secrets, image, base, controls = runtime
    (secrets / role).write_bytes(b'12345678')
    result = docker(*base, *controls, image, 'init', check=False)
    assert result.returncode != 0 and 'CK_RV=0x000000a1' in result.stderr
    assert not (state / 'craton/complete').exists()
    before = snapshot(state)
    refused = docker(*base, *controls, image, 'init', check=False)
    assert refused.returncode != 0 and 'nonempty volume' in refused.stderr
    assert snapshot(state) == before


@pytest.mark.parametrize('damage', ['missing-auth', 'empty-auth', 'public-auth', 'store-link', 'auth-hard-link'])
def test_persistent_auth_and_store_safety(runtime, damage):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    docker(*base, *controls, image, 'health')
    owned = state / 'craton'
    auth = owned / 'store/token_state_0.json'
    if damage == 'missing-auth':
        auth.unlink()
    elif damage == 'empty-auth':
        auth.write_bytes(b'')
    elif damage == 'public-auth':
        auth.chmod(0o644)
    elif damage == 'store-link':
        (owned / 'store').rename(root / 'foreign-store')
        (owned / 'store').symlink_to(root / 'foreign-store', target_is_directory=True)
    else:
        os.link(auth, root / 'foreign-auth')
    before = snapshot(state)
    for argv in (('init',), ('health',), ('exec', '--', 'sh', '-c', 'echo APP-RAN')):
        result = docker(*base, *controls, image, *argv, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert snapshot(state) == before


@pytest.mark.parametrize('channel', ['rolling'])
def test_preferred_proxy_installed_checker_observations(channel, tmp_path):
    if channel not in DAEMONS or channel not in CLIENTS or channel not in CHECKERS:
        pytest.skip('explicit pinned proxy/checker/client artifacts required')
    from p11lab.checker import run_checker
    root, caller, pin, so = lane_root('proxy-checker', channel, tmp_path)
    try:
        bundle = Path(CLIENTS[channel])
        client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
        spec = RunSpec('craton', channel, 'proxy', as_ref(DAEMONS[channel]), 'container', as_ref(CHECKERS[channel]), client, (),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so),
                        'CRATON_HSM_INTEGRITY_BYPASS': 'unsafe-dev-only'}, root / 'output', caller, 1200)
        result = run_checker(spec, 'smoke-v1')
        assert not result.cleanup_errors
        path = spec.output_dir / 'checker/checker-receipt.json'
        observation = {'exit_code': result.exit_code, 'lifecycle_errors': result.lifecycle_errors,
                       'checker_receipt_present': path.is_file()}
        if path.is_file():
            record = json.loads(path.read_text())
            assert len(record['nodes']) == 23
            observation['evidence'] = record['evidence']
        (root / 'lane-observation.json').write_text(json.dumps(observation, indent=2) + '\n')
        print('checker proxy/' + channel + ': ' + json.dumps(observation))
    finally:
        pin.unlink(missing_ok=True)
        so.unlink(missing_ok=True)
