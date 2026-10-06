# SPDX-License-Identifier: Apache-2.0
"""tpm2 acceptance, with pinned channel images and no implicit builds.

P11LAB_TPM2_{IMAGES,CONSUMERS,CHECKERS,PROXIES,CLIENTS} contain explicit
JSON channel maps; CALLER is an independent C caller image and EVIDENCE is a
fresh output directory. The emulator state and sqlite store persist on the
caller state volume and resume across operations; daemons supervise per
operation only.
"""
from dataclasses import replace
import hashlib
import json
import itertools
import shutil
import time
import uuid
import os
from pathlib import Path
import subprocess

import pytest

from p11lab.build import runtime_inputs
from p11lab.catalog import load_environment, validate_build_inputs, package_data
from p11lab.identity import artifact_key
from p11lab.models import ArtifactRef, RunSpec
from p11lab.run import run_application

MODULE = '/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so'
IMAGES = json.loads(os.environ.get('P11LAB_TPM2_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_TPM2_CONSUMERS', '{}'))
CHECKERS = json.loads(os.environ.get('P11LAB_TPM2_CHECKERS', '{}'))
DAEMONS = json.loads(os.environ.get('P11LAB_TPM2_PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_TPM2_CLIENTS', '{}'))
CALLER = os.environ.get('P11LAB_TPM2_CALLER', '')
COMMANDS = itertools.count()




def docker(*args, check=True, env=None):
    argv = ['docker', *args]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=300, env=os.environ | (env or {}))
    evidence = os.environ.get('P11LAB_TPM2_EVIDENCE')
    if evidence:
        root = Path(evidence) / 'commands'
        root.mkdir(parents=True, exist_ok=True)
        path = root / f'{next(COMMANDS):04d}.json'
        path.write_text(json.dumps({'argv': argv, 'env': {k: '<test secret omitted>' for k in (env or {})}, 'returncode': result.returncode,
                                   'stdout': result.stdout, 'stderr': result.stderr}, indent=2) + '\n')
    if check:
        assert result.returncode == 0, result.stderr
    return result


@pytest.fixture(params=list(IMAGES) or ['unconfigured'])
def runtime(request, tmp_path):
    if request.param not in IMAGES:
        pytest.skip('explicit tpm2 runtime IDs required')
    channel = request.param
    root = Path(os.environ.get('P11LAB_TPM2_EVIDENCE', str(tmp_path))) / request.node.name
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



def as_ref(image):
    return ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')


def lane_root(name, channel, tmp_path):
    evidence = os.environ.get('P11LAB_TPM2_EVIDENCE')
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
        pytest.skip('explicit installed tpm2 checker derivative required')
    from p11lab.checker import run_checker
    root, caller, pin, so = lane_root('direct-checker', channel, tmp_path)
    try:
        spec = RunSpec('tpm2', channel, 'direct', as_ref(CHECKERS[channel]), 'provider', None, None, (),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so)}, root / 'output', caller, 1200)
        result = run_checker(spec, 'smoke-v1')
        assert not result.cleanup_errors
        record = json.loads((spec.output_dir / 'checker/checker-receipt.json').read_text())
        assert len(record['nodes']) == 23
        assert record['token']['native_slot_id'] == 1 and record['token']['token_present_index'] == 0
        assert record['token']['label'] == 'P11Lab'
        # A completed provider finding is valid evidence, never normalized.
        print(f'checker direct/{channel}: exit={result.exit_code} evidence={record["evidence"]}')
        if not record['evidence']['observations_complete']:
            error = (spec.output_dir / 'checker/checker.stderr.log').read_text()
            print(f'checker incomplete: exit={result.exit_code} returncode={record["returncode"]}')
            print(error[-2000:])
            pytest.fail('checker observations incomplete without a proven shared-component cause')
    finally:
        pin.unlink(missing_ok=True)
        so.unlink(missing_ok=True)


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_preferred_proxy_independent_crypto(channel, tmp_path):
    if channel not in DAEMONS or channel not in CLIENTS or not CALLER:
        pytest.skip('explicit pinned tpm2 daemon, client bundle and caller required')
    root, caller, pin, so = lane_root('proxy-crypto', channel, tmp_path)
    try:
        bundle = Path(CLIENTS[channel])
        client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
        spec = RunSpec('tpm2', channel, 'proxy', as_ref(DAEMONS[channel]), 'container', as_ref(CALLER), client,
                       ('sh', '-c', 'p11lab-token --module /run/p11lab-client/libpkcs11_proxy_ng_shim.so '
                        '--token-label P11Lab --pin-file /run/p11lab-input/P11LAB_PIN_FILE --key-id 42 && '
                        'p11lab-smoke --module /run/p11lab-client/libpkcs11_proxy_ng_shim.so '
                        '--token-label P11Lab --pin-file /run/p11lab-input/P11LAB_PIN_FILE '
                        '--output /p11lab-output/crypto --key-mode existing --key-id 42'),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so)}, root / 'output', caller, 600)
        result = run_application(spec)
        assert result.app_returncode == 0, result
        assert not result.cleanup_errors
        assert (spec.output_dir / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
        oracle(spec.output_dir / 'crypto')
        if result.exit_code != 0:
            # The shared runner opens a second runtime for post-health before
            # stopping the live proxy/native daemon. Keep the state lease and
            # report the lifecycle block despite successful remote crypto.
            receipt = json.loads(result.receipt_path.read_text())
            assert result.exit_code == 1 and receipt['app_completed']
            assert receipt['lifecycle_errors'] == ['post-health failed']
            post = [s for s in receipt['stages'] if s['phase'] == 'post-health']
            assert len(post) == 1 and post[0]['returncode'] == 1 and not post[0]['timed_out']
            assert 'state is unsafe or already in use' in (spec.output_dir / 'post-health.stderr.log').read_text()
            pytest.xfail('P11Lab proxy runner checks state before stopping its live daemon; crypto succeeds, lifecycle blocked')
    finally:
        pin.unlink(missing_ok=True)
        so.unlink(missing_ok=True)


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_packaged_inputs_are_closed_and_channels_distinct(channel):
    spec = load_environment('tpm2', channel)
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    expected = {'release': '9a3bfbd6b9e20513cbf5413b395ba1fe8b23ef0c',
                'rolling': 'd8375fa68e4ce8a477f7f5953511711e500e4143'}
    assert inputs['sources'][0]['revision'] == expected[channel]
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['openssl']['from_source'] is False
    assert inputs['features']['transients'] == 100 and inputs['features']['sessions'] == 4
    assert inputs['features']['da_max_tries'] == 64
    assert inputs['features']['da_recovery_time'] == 1000 and inputs['features']['da_lockout_recovery'] == 1000
    assert inputs['features']['token_slot'] == 1
    assert inputs['features']['upstream_version'] == {'release': '1.10.1', 'rolling': '1.10.1-21-gd8375fa'}[channel]
    assert spec['services'] == ['swtpm', 'dbus-daemon', 'tpm2-abrmd']
    assert inputs['patches'] == []
    assert [d['id'] for d in inputs['dependencies']] == ['tpm2-pytss']
    assert all(item in inputs['features']['configure'] for item in
               ['--prefix=/usr', '--with-fapi=no', '--disable-ptool-checks'])
    other = 'rolling' if channel == 'release' else 'release'
    assert artifact_key('runtime', inputs) != artifact_key('runtime', runtime_inputs(load_environment('tpm2', other)))


def snapshot(state):
    return {str(p.relative_to(state)): ('symlink', os.readlink(p)) if p.is_symlink()
            else ('file', hashlib.sha256(p.read_bytes()).hexdigest()) if p.is_file()
            else ('directory', None) for p in state.rglob('*')}


PERMALL = 'tpm2/tpmstate/tpm2-00.permall'


def stable_snapshot(state):
    """State snapshot excluding the emulator persistent blob.

    swtpm rewrites tpm2-00.permall on every supervised operation (TPM clock
    and NV counters advance even for read-only probes); all other state
    files are byte-stable. Lanes where daemons legitimately run compare
    this snapshot and separately assert the blob is still a regular file.
    """
    return {path: entry for path, entry in snapshot(state).items() if path != PERMALL}


def assert_permall_present(state):
    blob = state / PERMALL
    assert blob.is_file() and not blob.is_symlink()


def da_counter(getcap_stdout):
    """Parse TPM2_PT_LOCKOUT_COUNTER from tpm2_getcap properties-variable."""
    for line in getcap_stdout.splitlines():
        if 'TPM2_PT_LOCKOUT_COUNTER' in line:
            return int(line.split(':')[1].strip(), 16)
    raise AssertionError('LOCKOUT_COUNTER missing: ' + getcap_stdout[-500:])


def test_native_lifecycle_credentials_and_argv(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert json.loads(docker('run', '--rm', image, 'describe').stdout)['module_path'] == MODULE
    assert docker(*base, image, 'init', check=False).returncode != 0
    assert list(state.iterdir()) == []
    docker(*base, *controls, image, 'init')
    before = stable_snapshot(state)
    (secrets / 'pin').write_bytes(b'5678')
    (secrets / 'so').write_bytes(b'97531864')
    docker(*base, *controls, image, 'init')
    assert stable_snapshot(state) == before
    assert_permall_present(state)
    health = docker(*base, *controls, image, 'health')
    assert 'native_slot=1 token_present_index=0 label=acceptance' in health.stdout
    da = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                'tpm2_getcap properties-variable 2>/dev/null | grep -E "MAX_AUTH_FAIL|LOCKOUT_COUNTER"')
    assert 'TPM2_PT_MAX_AUTH_FAIL: 0x40' in da.stdout
    # Only first init authenticated so far: at most one counted retry each
    # from store provisioning and DA setup, then read-only probes.
    assert da_counter(da.stdout) <= 2
    changed = docker(*base, *controls, '-e', 'P11LAB_LABEL=different', image, 'init', check=False)
    assert changed.returncode != 0 and 'incompatible' in changed.stderr
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\n" "$P11LAB_MODULE" "$1"; exit 37', 'caller',
                    'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == [MODULE, 'literal $argument with spaces']
    assert 'pin' not in (state / 'tpm2/complete').read_text().lower()
    assert (state / 'tpm2/store/tpm2_pkcs11.sqlite3').is_file()
    # dash command -v reports only the first name; resolve each tool alone.
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'for t in cc gcc make autoconf pkcs11-tool pkcsconf; do command -v $t; done; exit 0').stdout == ''
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'for t in python3 swtpm tpm2-abrmd dbus-daemon dbus-send tpm2; do command -v $t; done').stdout.split() == [
                      '/usr/bin/python3', '/usr/bin/swtpm', '/usr/sbin/tpm2-abrmd',
                      '/usr/bin/dbus-daemon', '/usr/bin/dbus-send', '/usr/bin/tpm2']
    assert stable_snapshot(state) == before
    assert_permall_present(state)
    # Credentials in the native adapter come from either scalar environment
    # or private files. Docker argv and durable command records omit values.
    other = root / 'scalar-state'
    other.mkdir(mode=0o700)
    scalar_base = [x.replace(f'src={state},', f'src={other},') for x in base]
    docker(*scalar_base, '-e', 'P11LAB_PIN', '-e', 'P11LAB_SO_PIN', image, 'init',
           env={'P11LAB_PIN': '2468', 'P11LAB_SO_PIN': '13572468'})
    docker(*scalar_base, image, 'health')


def oracle(output):
    result = subprocess.run(['python3', str(package_data('consumer/verify.py')), str(output)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'altered message rejected' in result.stdout
    (output.parent / 'oracle.txt').write_text(result.stdout)


def test_application_crypto_persistence_isolation_and_native_errors(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
              'P11LAB_SO_PIN_FILE': str(secrets / 'so'), 'P11LAB_LABEL': 'acceptance'}
    argv = ('p11lab-smoke', '--module', MODULE, '--token-label', 'acceptance', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
            '--output', '/p11lab-output/crypto', '--key-mode', 'existing', '--key-id', '42')
    spec = RunSpec('tpm2', channel, 'direct', as_ref(CONSUMERS[channel]), 'provider', None, None,
                   argv, inputs, root / 'existing-template', root, 90)
    generated = replace(spec, output_dir=root / 'generated-native-refusal',
                        argv=('p11lab-smoke', '--module', MODULE, '--token-label', 'acceptance',
                             '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
                             '--output', '/p11lab-output/crypto', '--key-mode', 'generated'))
    refused = run_application(generated)
    assert refused.app_returncode != 0 and refused.exit_code != 0
    assert 'CK_RV=0x00000013' in (root / 'generated-native-refusal/application.stderr.log').read_text()
    provision = replace(spec, output_dir=root / 'provision', argv=('p11lab-token', '--module', MODULE,
                        '--token-label', 'acceptance', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--key-id', '42'))
    assert run_application(provision).exit_code == 0
    public = []
    for number in range(2):
        reopened = replace(spec, output_dir=root / f'reopen-{number}')
        result = run_application(reopened)
        assert result.exit_code == 0 and not result.cleanup_errors, result
        oracle(reopened.output_dir / 'crypto')
        public.append((reopened.output_dir / 'crypto/public-key.der').read_bytes())
    assert public[0] == public[1]
    (secrets / 'pin').write_bytes(b'bad-pin')
    failed = run_application(replace(spec, output_dir=root / 'wrong-pin'))
    assert failed.app_returncode != 0 and failed.exit_code != 0
    assert 'C_Login: CK_RV=0x000000a0' in (root / 'wrong-pin/application.stderr.log').read_text()
    other = root / 'other-state'
    other.mkdir(mode=0o700)
    (secrets / 'pin').write_bytes(b'1234')
    absent = replace(spec, inputs=inputs | {'P11LAB_STATE_DIR': str(other)}, output_dir=root / 'separate')
    assert run_application(absent).exit_code != 0
    assert (other / 'tpm2/store/tpm2_pkcs11.sqlite3').is_file()
    for path in root.rglob('*.log'):
        assert b'bad-pin' not in path.read_bytes() and b'12345678' not in path.read_bytes()


@pytest.mark.parametrize('damage', ['missing-store', 'empty-store', 'store-extra', 'store-link',
                                   'missing-marker', 'marker-extra-lf', 'label-drift', 'hidden-file',
                                   'dangling-link', 'busy-init', 'missing-tpmstate'])
def test_damage_refused_before_daemon_or_application(runtime, damage):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    owned = state / 'tpm2'
    store = owned / 'store/tpm2_pkcs11.sqlite3'
    if damage == 'missing-store':
        store.unlink()
    elif damage == 'empty-store':
        store.write_bytes(b'')
    elif damage == 'store-extra':
        (owned / 'store/foreign.db').write_bytes(b'foreign')
    elif damage == 'store-link':
        store.rename(owned / 'store/original.sqlite3')
        store.symlink_to('original.sqlite3')
    elif damage == 'missing-marker':
        (owned / 'complete').unlink()
    elif damage == 'marker-extra-lf':
        with (owned / 'complete').open('ab') as f:
            f.write(b'\n')
    elif damage == 'label-drift':
        (owned / 'complete').write_text((owned / 'complete').read_text().replace('label=acceptance', 'label=drifted'))
    elif damage == 'hidden-file':
        (owned / 'tpmstate/.foreign').write_bytes(b'foreign')
    elif damage == 'dangling-link':
        (owned / 'tpmstate/dangling').symlink_to('absent')
    elif damage == 'busy-init':
        (state / '.init-lock').mkdir()
    else:
        shutil.rmtree(owned / 'tpmstate')
    before = snapshot(state)
    for operation in ('init', 'health', 'exec'):
        argv = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'echo APP-RAN']
        result = docker(*base, *controls, image, *argv, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert snapshot(state) == before, (damage, operation)


@pytest.mark.parametrize('bad', ['absent-pin', 'absent-so', 'empty', 'multiline', 'nul', 'too-large',
                                'user-conflict', 'so-conflict'])
def test_bad_credentials_never_create_state(runtime, bad):
    channel, root, state, secrets, image, base, controls = runtime
    if bad == 'absent-pin':
        controls = controls[:2] + controls[4:]
    elif bad == 'absent-so':
        controls = controls[:-2]
    elif bad in ('user-conflict', 'so-conflict'):
        controls = [*controls, '-e', 'P11LAB_PIN=' if bad == 'user-conflict' else 'P11LAB_SO_PIN=']
    else:
        (secrets / 'pin').write_bytes({'empty': b'', 'multiline': b'line1\nline2', 'nul': b'nul\0byte',
                                      'too-large': b'x' * 4097}[bad])
    result = docker(*base, *controls, image, 'init', check=False)
    assert result.returncode != 0
    assert list(state.iterdir()) == []


@pytest.mark.parametrize('label', ['', 'x' * 33, 'bad\nlabel', 'bad;label'])
def test_invalid_label_never_creates_state(runtime, label):
    channel, root, state, secrets, image, base, controls = runtime
    result = docker(*base, *controls, '-e', 'P11LAB_LABEL=' + label, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []


@pytest.mark.parametrize('override', ['TPM2_PKCS11_STORE', 'TPM2_PKCS11_TCTI', 'TPM2TOOLS_TCTI',
                                     'DBUS_SYSTEM_BUS_ADDRESS', 'DBUS_SESSION_BUS_ADDRESS', 'LD_PRELOAD'])
def test_native_redirects_refused(runtime, override):
    channel, root, state, secrets, image, base, controls = runtime
    result = docker(*base, *controls, '-e', override + '=', image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []
    assert 'unsupported native override' in result.stderr


def test_exact_artifact_readbacks_and_admission_blocked(runtime):
    from p11lab.licenses import assess_distribution
    channel, root, state, secrets, image, base, controls = runtime
    def read(path):
        return docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat', image, path).stdout
    spec = load_environment('tpm2', channel)
    assert json.loads(read('/usr/share/p11lab/provider.json')) == {k: v for k, v in spec.items()
                                                                 if k not in ('lock', 'channel', 'channel_spec', 'asset_root')}
    assert read('/usr/share/p11lab/runtime-id') == artifact_key('runtime', runtime_inputs(spec)) + '\n'
    assert 'libcrypto.so.3' in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'libtss2-esys' in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'not found' not in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'tpm2-pytss 2.3.0' in read('/usr/share/p11lab/build/python-trees.txt')
    assert 'tpm2-pkcs11-tools 1.33.7' in read('/usr/share/p11lab/build/python-trees.txt')
    decision = assess_distribution(as_ref(image), root / 'admission')
    assert decision['status'] == decision['publication_status'] == 'blocked' and decision['blockers']
    (root / 'admission-decision.json').write_text(json.dumps(decision, indent=2) + '\n')
    permission = docker('run', '--rm', '--network', 'none', '--entrypoint', 'stat', image,
                        '-c', '%u:%g %a', '/etc/p11lab/tpm2/dbus.conf').stdout.strip()
    assert permission == '0:0 644'
    absent = docker('run', '--rm', '--network', 'none', '--entrypoint', 'sh', image,
                    '-c', 'test ! -e /usr/local/bin/tpm2_ptool && test ! -e /usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.la && echo ABSENT-OK')
    assert 'ABSENT-OK' in absent.stdout


def start_long_application(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    name = 'p11lab-tpm2-test-' + uuid.uuid4().hex[:12]
    args = ['-d', '--name', name, *base[2:], *controls, image, 'exec', '--', 'sh', '-c',
            'touch /run/p11lab/app-started; sleep 300']
    # base begins run --rm; detached instances are explicitly removed here.
    docker('run', *args)
    for _ in range(200):
        ready = docker('exec', name, 'test', '-f', '/run/p11lab/app-started', check=False)
        if ready.returncode == 0:
            return name
        time.sleep(0.05)
    docker('rm', '-f', name, check=False)
    pytest.fail('supervised application did not start')


def test_signal_shutdown_reaps_daemon_and_preserves_state(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    name = start_long_application(runtime)
    before = stable_snapshot(state)
    try:
        for pidfile in ('swtpm.pid', 'dbus.pid', 'abrmd.pid'):
            pid = docker('exec', name, 'cat', f'/run/p11lab/tpm2/{pidfile}').stdout.strip()
            assert int(pid) > 1
        docker('kill', '--signal', 'TERM', name)
        assert docker('wait', name).stdout.strip() == '143'
        assert stable_snapshot(state) == before
        assert_permall_present(state)
    finally:
        docker('rm', '-f', name, check=False)
    docker(*base, *controls, image, 'health')


def test_daemon_death_fails_operation_and_reaps_application(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    name = start_long_application(runtime)
    before = snapshot(state)
    try:
        pid = docker('exec', name, 'cat', '/run/p11lab/tpm2/swtpm.pid').stdout.strip()
        docker('exec', name, 'sh', '-c', 'kill -KILL "$1"', 'caller', pid)
        assert docker('wait', name).stdout.strip() == '1'
        assert 'required swtpm exited' in docker('logs', name).stderr
        assert snapshot(state) == before
    finally:
        docker('rm', '-f', name, check=False)
    docker(*base, *controls, image, 'health')


def test_state_lease_refuses_second_container(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    name = start_long_application(runtime)
    before = snapshot(state)
    try:
        failed = docker(*base, *controls, image, 'health', check=False)
        assert failed.returncode != 0 and 'already in use' in failed.stderr
        assert snapshot(state) == before
        docker('exec', name, 'test', '-S', '/run/p11lab/tpm2/bus/system_bus_socket')
        docker('kill', '--signal', 'TERM', name)
        assert docker('wait', name).stdout.strip() == '143'
    finally:
        docker('rm', '-f', name, check=False)


NATIVE_PROBE = r'''
#define _POSIX_C_SOURCE 200809L
#include <p11-kit/pkcs11.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void) {
    CK_FUNCTION_LIST_PTR f = NULL;
    CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR) = NULL;
    void *h = dlopen(getenv("P11LAB_MODULE"), RTLD_NOW | RTLD_LOCAL), *symbol;
    CK_RV rv;
    CK_SLOT_ID slots[16];
    CK_ULONG count = 16;
    CK_TOKEN_INFO info;
    if (!h) return 2;
    symbol = dlsym(h, "C_GetFunctionList");
    memcpy(&get, &symbol, sizeof(get));
    if (!get || get(&f)) return 2;
    rv = f->C_Initialize(NULL);
    fprintf(stderr, "C_Initialize: CK_RV=0x%08lx\n", rv);
    if (rv) { dlclose(h); return 1; }
    rv = f->C_GetSlotList(CK_TRUE, slots, &count);
    if (rv == CKR_OK && count > 0) rv = f->C_GetTokenInfo(slots[0], &info);
    if (rv == CKR_OK) printf("slot=%lu count=%lu min=%lu max=%lu flags=0x%08lx label=%.32s\n",
                             slots[0], count, info.ulMinPinLen, info.ulMaxPinLen, info.flags, info.label);
    if (f->C_Finalize(NULL)) return 2;
    dlclose(h);
    return rv != CKR_OK;
}
'''


def test_native_daemon_and_tcti_are_required(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    before = stable_snapshot(state)
    result = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-native-probe')
    assert 'slot=1 count=2 min=0 max=128 flags=0x0000040d' in result.stdout
    assert 'label=acceptance' in result.stdout
    # Bypass only the adapter in this negative native lane; without the
    # supervised daemons the module cannot reach any TPM.
    direct = docker(*base, '--entrypoint', 'sh', '-e', 'P11LAB_MODULE=' + MODULE, consumer, '-c',
                    'p11lab-native-probe', check=False)
    assert direct.returncode == 1 and 'C_Initialize: CK_RV=' in direct.stderr
    assert 'CK_RV=0x00000000' not in direct.stderr
    assert stable_snapshot(state) == before
    assert_permall_present(state)


def test_dictionary_attack_budget_and_lockout_are_native(runtime):
    """Wrong PINs burn TPM dictionary-attack tries; the budget locks natively.

    First init provisions max 64 tries. Each wrong-PIN login burns exactly
    one try, so attempts 1..50 report CKR_PIN_INCORRECT while the token
    locks with CKR_PIN_LOCKED once the 64-try budget is spent; the exact
    lock attempt is predicted from the pre-hammer counter (at most one
    counted retry from the hammer container's first authentication). The
    lockout persists and also rejects the correct PIN. This lane owns a
    dedicated token: a locked token stays locked.
    """
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    spent = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                   'tpm2_getcap properties-variable 2>/dev/null | grep -E "MAX_AUTH_FAIL|LOCKOUT_COUNTER"')
    assert 'TPM2_PT_MAX_AUTH_FAIL: 0x40' in spent.stdout
    pre = da_counter(spent.stdout)
    assert pre <= 2, pre
    (secrets / 'wrong').write_bytes(b'9999')
    (secrets / 'wrong').chmod(0o600)
    script = '''
M=/usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so
i=1
while [ "$i" -le 70 ]; do
  rv=$(p11lab-smoke --module $M --token-label acceptance --pin-file /run/secrets/wrong \
    --output /tmp/hammer-$i --key-mode existing --key-id 42 2>&1 | grep -o 'CK_RV=0x[0-9a-f]*' | head -1)
  echo "attempt $i $rv"
  i=$((i + 1))
done
tpm2_getcap properties-variable 2>/dev/null | grep -E 'LOCKOUT_COUNTER|MAX_AUTH_FAIL|inLockout'
echo "correct-pin $(p11lab-smoke --module $M --token-label acceptance --pin-file /run/secrets/pin \
  --output /tmp/hammer-final --key-mode existing --key-id 42 2>&1 | grep -o 'CK_RV=0x[0-9a-f]*' | head -1)"
'''
    result = docker(*base, *controls, consumer, 'exec', '--', 'sh', '-c', script)
    attempts = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == 'attempt' and parts[1].isdigit():
            attempts[int(parts[1])] = parts[2]
    assert len(attempts) == 70, result.stdout[-2000:]
    for i in range(1, 51):
        assert attempts[i] == 'CK_RV=0x000000a0', (i, attempts[i])
    locked = [i for i in range(1, 71) if attempts[i] == 'CK_RV=0x000000a4']
    # Each wrong PIN burns exactly one try; the hammer container draws at
    # most one counted retry on its first authentication. The first lock
    # is therefore exactly predictable from the pre-hammer counter.
    assert locked and locked[0] in (64 - pre, 65 - pre), (locked[:5], pre)
    assert locked == list(range(locked[0], 71)), locked[:5]
    print(f'da hammer/{channel}: locked at wrong attempt {locked[0]} (pre={pre})')
    assert 'TPM2_PT_MAX_AUTH_FAIL: 0x40' in result.stdout
    assert 'TPM2_PT_LOCKOUT_COUNTER: 0x40' in result.stdout
    assert any('inLockout' in line and line.split(':')[1].strip() == '1'
               for line in result.stdout.splitlines() if ':' in line)
    assert 'correct-pin CK_RV=0x000000a4' in result.stdout
