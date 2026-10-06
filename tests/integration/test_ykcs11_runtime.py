# SPDX-License-Identifier: Apache-2.0
"""ykcs11 acceptance, with pinned channel images and no implicit builds.

P11LAB_YKCS11_{IMAGES,CONSUMERS,CHECKERS,PROXIES,CLIENTS} contain explicit
JSON channel maps; CALLER is an independent C caller image and EVIDENCE is a
fresh output directory. The stored slot-9a identity persists on the caller
state volume and is re-imported onto a factory-fresh virtual card every
operation; daemons supervise per operation only.
"""
from dataclasses import replace
import hashlib
import json
import itertools
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

MODULE = '/usr/local/lib/libykcs11.so.2'
LABEL = 'YubiKey PIV #0'
IMAGES = json.loads(os.environ.get('P11LAB_YKCS11_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_YKCS11_CONSUMERS', '{}'))
CHECKERS = json.loads(os.environ.get('P11LAB_YKCS11_CHECKERS', '{}'))
DAEMONS = json.loads(os.environ.get('P11LAB_YKCS11_PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_YKCS11_CLIENTS', '{}'))
CALLER = os.environ.get('P11LAB_YKCS11_CALLER', '')
COMMANDS = itertools.count()




def docker(*args, check=True, env=None):
    argv = ['docker', *args]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=300, env=os.environ | (env or {}))
    evidence = os.environ.get('P11LAB_YKCS11_EVIDENCE')
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
        pytest.skip('explicit ykcs11 runtime IDs required')
    channel = request.param
    root = Path(os.environ.get('P11LAB_YKCS11_EVIDENCE', str(tmp_path))) / request.node.name
    root.mkdir(parents=True, exist_ok=False)
    state = root / 'state'
    state.mkdir(mode=0o700)
    secrets = root / 'secrets'
    secrets.mkdir(mode=0o700)
    for name, value in [('pin', b'654321'), ('so', b'87654321')]:
        (secrets / name).write_bytes(value)
        (secrets / name).chmod(0o600)
    image = IMAGES[channel]
    base = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', f'/run/p11lab:uid={os.getuid()},gid={os.getgid()},mode=0700',
            '--tmpfs', '/tmp', '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly']
    controls = ['-e', 'P11LAB_PIN_FILE=/run/secrets/pin', '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so']
    yield channel, root, state, secrets, image, base, controls
    # Test-only credentials are removed from durable evidence.
    for child in secrets.iterdir():
        child.unlink()



def as_ref(image):
    return ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')


def lane_root(name, channel, tmp_path):
    evidence = os.environ.get('P11LAB_YKCS11_EVIDENCE')
    root = Path(evidence) / name / channel if evidence else tmp_path
    root.mkdir(parents=True, exist_ok=True)
    caller = root / 'caller'
    caller.mkdir()
    pin, so = root / 'pin', root / 'so'
    pin.write_bytes(b'654321')
    so.write_bytes(b'87654321')
    pin.chmod(0o600)
    so.chmod(0o600)
    return root, caller, pin, so


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_installed_checker_observations(channel, tmp_path):
    if channel not in CHECKERS:
        pytest.skip('explicit installed ykcs11 checker derivative required')
    from p11lab.checker import run_checker
    root, caller, pin, so = lane_root('direct-checker', channel, tmp_path)
    try:
        spec = RunSpec('ykcs11', channel, 'direct', as_ref(CHECKERS[channel]), 'provider', None, None, (),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so), 'P11LAB_LABEL': LABEL}, root / 'output', caller, 1200)
        result = run_checker(spec, 'smoke-v1')
        assert not result.cleanup_errors
        record = json.loads((spec.output_dir / 'checker/checker-receipt.json').read_text())
        assert len(record['nodes']) == 23
        assert record['token']['native_slot_id'] == 0 and record['token']['token_present_index'] == 0
        assert record['token']['label'] == LABEL
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
        pytest.skip('explicit pinned ykcs11 daemon, client bundle and caller required')
    root, caller, pin, so = lane_root('proxy-crypto', channel, tmp_path)
    try:
        bundle = Path(CLIENTS[channel])
        client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
        spec = RunSpec('ykcs11', channel, 'proxy', as_ref(DAEMONS[channel]), 'container', as_ref(CALLER), client,
                       ('sh', '-c', 'p11lab-smoke --module /run/p11lab-client/libpkcs11_proxy_ng_shim.so '
                        f'--token-label "{LABEL}" --pin-file /run/p11lab-input/P11LAB_PIN_FILE '
                        '--output /p11lab-output/crypto --key-mode existing --key-id 01'),
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
    spec = load_environment('ykcs11', channel)
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    expected = {'release': 'ed1cd7862d39a92502c0476f53dfcf93f195007a',
                'rolling': 'c987afb892a565d210d5d674fa2e3300e19e14da'}
    assert inputs['sources'][0]['revision'] == expected[channel]
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['openssl']['from_source'] is False
    assert inputs['features']['token_slot'] == 0 and inputs['features']['token_present_index'] == 0
    assert inputs['features']['token_label'] == LABEL and inputs['features']['token_flags'] == '0x40d'
    assert inputs['features']['pinlen_min'] == 6 and inputs['features']['pinlen_max'] == 8
    assert inputs['features']['user_retries'] == 3 and inputs['features']['puk_retries'] == 3
    assert inputs['features']['slot'] == '9a'
    assert inputs['features']['upstream_version'] == {'release': '2.7.3', 'rolling': '2.7.3-5-gc987afb'}[channel]
    assert spec['services'] == ['pcscd']
    assert [(p['path'], p['target_source']) for p in inputs['patches']] == [
        ('patches/0001-virtcard-without-sanitizers.patch', 'canokey-core'),
        ('patches/0002-virtcard-quiet-ifd.patch', 'canokey-core')]
    assert [d['id'] for d in inputs['dependencies']] == ['canokey-core', 'canokey-crypto', 'littlefs', 'tinycbor',
                                                         'tf-psa-crypto', 'mlkem-native', 'mldsa-native', 'mbedtls-framework']
    assert inputs['features']['canokey_core']['revision'] == 'e4a756d61e7a094f84895c7042d4029f7c135820'
    assert all(item in inputs['features']['cmake']['canokey'] for item in
               ['-DVIRTCARD=ON', '-DCMAKE_POSITION_INDEPENDENT_CODE=ON', '-DENABLE_DEBUG_OUTPUT=OFF'])
    assert inputs['features']['extraction']['whole_count'] == 7
    other = 'rolling' if channel == 'release' else 'release'
    assert artifact_key('runtime', inputs) != artifact_key('runtime', runtime_inputs(load_environment('ykcs11', other)))


def snapshot(state):
    return {str(p.relative_to(state)): ('symlink', os.readlink(p)) if p.is_symlink()
            else ('file', hashlib.sha256(p.read_bytes()).hexdigest()) if p.is_file()
            else ('directory', None) for p in state.rglob('*')}


def test_native_lifecycle_credentials_and_argv(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert json.loads(docker('run', '--rm', image, 'describe').stdout)['module_path'] == MODULE
    assert docker(*base, image, 'init', check=False).returncode != 0
    assert list(state.iterdir()) == []
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    (secrets / 'pin').write_bytes(b'112233')
    (secrets / 'so').write_bytes(b'44556677')
    docker(*base, *controls, image, 'init')
    assert snapshot(state) == before
    health = docker(*base, *controls, image, 'health')
    assert 'native_slot=0 token_present_index=0 label=YubiKey PIV #0' in health.stdout
    # The tool defaults to -r Yubikey, which never matches the CanoKey
    # reader; the recipe reader name selects it explicitly.
    tries = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                   'yubico-piv-tool -r Canokey -a status 2>/dev/null | grep "PIN tries left"')
    assert 'PIN tries left:' in tries.stdout and tries.stdout.strip().endswith('3')
    changed = docker(*base, *controls, '-e', 'P11LAB_LABEL=different', image, 'init', check=False)
    assert changed.returncode != 0 and 'token label is fixed' in changed.stderr
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\\n" "$P11LAB_MODULE" "$1"; exit 37', 'caller',
                    'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == [MODULE, 'literal $argument with spaces']
    assert 'pin' not in (state / 'ykcs11/complete').read_text().lower()
    assert (state / 'ykcs11/key9a.pem').is_file() and (state / 'ykcs11/cert9a.pem').is_file()
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'for t in cc gcc make cmake python3 pkcs11-tool; do command -v $t; done; exit 0').stdout == ''
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'for t in yubico-piv-tool pcscd openssl; do command -v $t; done').stdout.split() == [
                      '/usr/local/bin/yubico-piv-tool', '/usr/sbin/pcscd', '/usr/bin/openssl']
    assert snapshot(state) == before
    # Credentials in the native adapter come from either scalar environment
    # or private files. Docker argv and durable command records omit values.
    other = root / 'scalar-state'
    other.mkdir(mode=0o700)
    scalar_base = [x.replace(f'src={state},', f'src={other},') for x in base]
    docker(*scalar_base, '-e', 'P11LAB_PIN', '-e', 'P11LAB_SO_PIN', image, 'init',
           env={'P11LAB_PIN': '246810', 'P11LAB_SO_PIN': '13572468'})
    # Unlike persistent-token providers, health re-personalizes a fresh
    # card, so it authenticates with the same caller credentials.
    docker(*scalar_base, '-e', 'P11LAB_PIN', '-e', 'P11LAB_SO_PIN', image, 'health',
           env={'P11LAB_PIN': '246810', 'P11LAB_SO_PIN': '13572468'})


def oracle(output):
    result = subprocess.run(['python3', str(package_data('consumer/verify.py')), str(output)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'altered message rejected' in result.stdout
    (output.parent / 'oracle.txt').write_text(result.stdout)


def test_application_crypto_reimport_isolation_and_native_errors(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
              'P11LAB_SO_PIN_FILE': str(secrets / 'so')}
    argv = ('p11lab-smoke', '--module', MODULE, '--token-label', LABEL, '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
            '--output', '/p11lab-output/crypto', '--key-mode', 'existing', '--key-id', '01')
    spec = RunSpec('ykcs11', channel, 'direct', as_ref(CONSUMERS[channel]), 'provider', None, None,
                   argv, inputs, root / 'existing-template', root, 90)
    generated = replace(spec, output_dir=root / 'generated-native-refusal',
                        argv=('p11lab-smoke', '--module', MODULE, '--token-label', LABEL,
                             '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
                             '--output', '/p11lab-output/crypto', '--key-mode', 'generated'))
    refused = run_application(generated)
    assert refused.app_returncode != 0 and refused.exit_code != 0
    assert 'CK_RV=0x00000013' in (root / 'generated-native-refusal/application.stderr.log').read_text()
    provision = replace(spec, output_dir=root / 'provision-native-refusal', argv=('p11lab-token', '--module', MODULE,
                        '--token-label', LABEL, '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--key-id', '42'))
    keygen = run_application(provision)
    assert keygen.app_returncode != 0 and keygen.exit_code != 0
    assert 'CK_RV=0x13' in (root / 'provision-native-refusal/application.stderr.log').read_text()
    public = []
    for number in range(2):
        reopened = replace(spec, output_dir=root / f'reopen-{number}')
        result = run_application(reopened)
        assert result.exit_code == 0 and not result.cleanup_errors, result
        oracle(reopened.output_dir / 'crypto')
        public.append((reopened.output_dir / 'crypto/public-key.der').read_bytes())
    assert public[0] == public[1]
    # Every operation re-personalizes the fresh card with the given caller
    # PIN, so a wrong PIN only exists within one operation: the adapter
    # provisions with the caller PIN while the application presents another.
    (secrets / 'wrong').write_bytes(b'bad-pin')
    (secrets / 'wrong').chmod(0o600)
    failed = docker(*base, *controls, CONSUMERS[channel], 'exec', '--', 'p11lab-smoke',
                    '--module', MODULE, '--token-label', LABEL, '--pin-file', '/run/secrets/wrong',
                    '--output', '/tmp/wrong-pin', '--key-mode', 'existing', '--key-id', '01', check=False)
    assert failed.returncode != 0
    assert 'C_Login: CK_RV=0x000000a0' in failed.stderr
    other = root / 'other-state'
    other.mkdir(mode=0o700)
    separate = run_application(replace(spec, inputs=inputs | {'P11LAB_STATE_DIR': str(other)}, output_dir=root / 'separate'))
    assert separate.exit_code == 0 and not separate.cleanup_errors, separate
    assert (other / 'ykcs11/key9a.pem').is_file()
    # A separate state provisions an independent working token, never the
    # original identity: fresh key material, not a view onto old keys.
    assert (root / 'separate/crypto/public-key.der').read_bytes() != public[0]
    for path in root.rglob('*.log'):
        assert b'bad-pin' not in path.read_bytes() and b'87654321' not in path.read_bytes()


@pytest.mark.parametrize('damage', ['missing-key', 'empty-key', 'key-extra', 'key-link',
                                   'missing-cert', 'empty-cert', 'missing-marker', 'marker-extra-lf',
                                   'hidden-file', 'dangling-link', 'busy-init'])
def test_damage_refused_before_daemon_or_application(runtime, damage):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    owned = state / 'ykcs11'
    key = owned / 'key9a.pem'
    if damage == 'missing-key':
        key.unlink()
    elif damage == 'empty-key':
        key.write_bytes(b'')
    elif damage == 'key-extra':
        (owned / 'foreign.pem').write_bytes(b'foreign')
    elif damage == 'key-link':
        key.rename(owned / 'original.pem')
        key.symlink_to('original.pem')
    elif damage == 'missing-cert':
        (owned / 'cert9a.pem').unlink()
    elif damage == 'empty-cert':
        (owned / 'cert9a.pem').write_bytes(b'')
    elif damage == 'missing-marker':
        (owned / 'complete').unlink()
    elif damage == 'marker-extra-lf':
        with (owned / 'complete').open('ab') as f:
            f.write(b'\n')
    elif damage == 'hidden-file':
        (owned / '.foreign').write_bytes(b'foreign')
    elif damage == 'dangling-link':
        (owned / 'dangling').symlink_to('absent')
    else:
        (state / '.init-lock').mkdir()
    before = snapshot(state)
    for operation in ('init', 'health', 'exec'):
        argv = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'echo APP-RAN']
        result = docker(*base, *controls, image, *argv, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert snapshot(state) == before, (damage, operation)


@pytest.mark.parametrize('bad', ['absent-pin', 'absent-so', 'short', 'long', 'multiline', 'nul',
                                'user-conflict', 'so-conflict'])
def test_bad_credentials_never_create_state(runtime, bad):
    channel, root, state, secrets, image, base, controls = runtime
    if bad == 'absent-pin':
        controls = controls[2:]
    elif bad == 'absent-so':
        controls = controls[:2]
    elif bad in ('user-conflict', 'so-conflict'):
        controls = [*controls, '-e', 'P11LAB_PIN=' if bad == 'user-conflict' else 'P11LAB_SO_PIN=']
    else:
        (secrets / 'pin').write_bytes({'short': b'12345', 'long': b'123456789', 'multiline': b'ab\ncdef',
                                      'nul': b'ab\x00cdef'}[bad])
    result = docker(*base, *controls, image, 'init', check=False)
    assert result.returncode != 0
    assert list(state.iterdir()) == []


@pytest.mark.parametrize('label', ['', 'acceptance', 'x' * 33, 'bad\nlabel'])
def test_invalid_label_never_creates_state(runtime, label):
    channel, root, state, secrets, image, base, controls = runtime
    result = docker(*base, *controls, '-e', 'P11LAB_LABEL=' + label, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []


@pytest.mark.parametrize('override', ['PCSCLITE_CSOCK_NAME', 'OPENSSL_CONF', 'OPENSSL_MODULES',
                                     'LD_PRELOAD', 'NSS_WRAPPER_PASSWD', 'NSS_WRAPPER_GROUP'])
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
    spec = load_environment('ykcs11', channel)
    assert json.loads(read('/usr/share/p11lab/provider.json')) == {k: v for k, v in spec.items()
                                                                 if k not in ('lock', 'channel', 'channel_spec', 'asset_root')}
    assert read('/usr/share/p11lab/runtime-id') == artifact_key('runtime', runtime_inputs(spec)) + '\n'
    assert 'libcrypto.so.3' in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'libpcsclite' in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'not found' not in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'u2f-virt-card' in read('/usr/share/p11lab/build/options.txt')
    assert 'libu2f-virt-card.so' in read('/usr/share/p11lab/build/module-hashes.sha256')
    decision = assess_distribution(as_ref(image), root / 'admission')
    assert decision['status'] == decision['publication_status'] == 'blocked' and decision['blockers']
    (root / 'admission-decision.json').write_text(json.dumps(decision, indent=2) + '\n')
    permission = docker('run', '--rm', '--network', 'none', '--entrypoint', 'stat', image,
                        '-c', '%u:%g %a', '/usr/share/p11lab/provider.json').stdout.strip()
    assert permission == '0:0 644'
    absent = docker('run', '--rm', '--network', 'none', '--entrypoint', 'sh', image,
                    '-c', 'test ! -e /usr/local/lib/libykcs11.la && test ! -e /usr/local/lib/libykpiv.a && echo ABSENT-OK')
    assert 'ABSENT-OK' in absent.stdout


def start_long_application(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    name = 'p11lab-ykcs11-test-' + uuid.uuid4().hex[:12]
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
    before = snapshot(state)
    try:
        pid = docker('exec', name, 'cat', '/run/p11lab/ykcs11/pcscd.pid').stdout.strip()
        assert int(pid) > 1
        docker('kill', '--signal', 'TERM', name)
        assert docker('wait', name).stdout.strip() == '143'
        assert snapshot(state) == before
    finally:
        docker('rm', '-f', name, check=False)
    docker(*base, *controls, image, 'health')


def test_daemon_death_fails_operation_and_reaps_application(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    name = start_long_application(runtime)
    before = snapshot(state)
    try:
        pid = docker('exec', name, 'cat', '/run/p11lab/ykcs11/pcscd.pid').stdout.strip()
        docker('exec', name, 'sh', '-c', 'kill -KILL "$1"', 'caller', pid)
        assert docker('wait', name).stdout.strip() == '1'
        assert 'required pcscd exited' in docker('logs', name).stderr
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
        docker('exec', name, 'test', '-S', '/run/pcscd/pcscd.comm')
        docker('kill', '--signal', 'TERM', name)
        assert docker('wait', name).stdout.strip() == '143'
    finally:
        docker('rm', '-f', name, check=False)


NATIVE_PROBE = r'''
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vendor/pkcs11.h"
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
    if (rv) { fprintf(stderr, "C_GetSlotList: CK_RV=0x%08lx\n", rv); f->C_Finalize(NULL); dlclose(h); return 1; }
    if (!count) { fprintf(stderr, "no token-present slots\n"); f->C_Finalize(NULL); dlclose(h); return 1; }
    rv = f->C_GetTokenInfo(slots[0], &info);
    if (rv) { fprintf(stderr, "C_GetTokenInfo: CK_RV=0x%08lx\n", rv); f->C_Finalize(NULL); dlclose(h); return 1; }
    printf("slot=%lu count=%lu min=%lu max=%lu flags=0x%08lx label=%.32s\n",
           slots[0], count, info.ulMinPinLen, info.ulMaxPinLen, info.flags, info.label);
    if (f->C_Finalize(NULL)) return 2;
    dlclose(h);
    return 0;
}
'''


def test_native_daemon_and_reader_are_required(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    result = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-native-probe')
    assert 'slot=0 count=1 min=6 max=64 flags=0x0000040d' in result.stdout
    assert 'label=YubiKey PIV #0' in result.stdout
    # Bypass only the adapter in this negative native lane; without the
    # supervised pcscd and virtual card the module reaches no reader.
    direct = docker(*base, '--entrypoint', 'sh', '-e', 'P11LAB_MODULE=' + MODULE, consumer, '-c',
                    'p11lab-native-probe', check=False)
    assert direct.returncode == 1 and 'C_GetSlotList: CK_RV=0x00000030' in direct.stderr
    assert snapshot(state) == before


def test_pin_retry_budget_and_lockout_are_native(runtime):
    """Wrong PINs burn PIV tries; the 3-try budget locks natively.

    Fresh card provisions 3 tries. Wrong-PIN logins burn exactly one try
    each: attempts 1..2 report CKR_PIN_INCORRECT, the third wrong attempt
    locks with CKR_PIN_LOCKED, every later attempt stays locked, and the
    correct PIN is then also rejected. The next operation starts from a
    factory-fresh card (documented ephemeral semantic), so the budget is
    whole again and correct-PIN crypto succeeds.
    """
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    (secrets / 'wrong').write_bytes(b'999999')
    (secrets / 'wrong').chmod(0o600)
    script = '''
M=/usr/local/lib/libykcs11.so.2
i=1
while [ "$i" -le 8 ]; do
  rv=$(p11lab-smoke --module $M --token-label "YubiKey PIV #0" --pin-file /run/secrets/wrong \
    --output /tmp/hammer-$i --key-mode existing --key-id 01 2>&1 | grep -o 'CK_RV=0x[0-9a-f]*' | head -1)
  echo "attempt $i $rv"
  i=$((i + 1))
done
echo "correct-pin $(p11lab-smoke --module $M --token-label "YubiKey PIV #0" --pin-file /run/secrets/pin \
  --output /tmp/hammer-final --key-mode existing --key-id 01 2>&1 | grep -o 'CK_RV=0x[0-9a-f]*' | head -1)"
'''
    result = docker(*base, *controls, consumer, 'exec', '--', 'sh', '-c', script)
    attempts = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == 'attempt' and parts[1].isdigit():
            attempts[int(parts[1])] = parts[2]
    assert len(attempts) == 8, result.stdout[-2000:]
    assert attempts[1] == 'CK_RV=0x000000a0' and attempts[2] == 'CK_RV=0x000000a0'
    locked = [i for i in range(1, 9) if attempts[i] == 'CK_RV=0x000000a4']
    # Each wrong PIN burns exactly one of 3 tries; the third wrong attempt
    # locks immediately and every later attempt stays locked.
    assert locked[0] == 3, (locked, attempts)
    assert locked == list(range(3, 9)), locked
    print(f'pin hammer/{channel}: locked at wrong attempt {locked[0]}')
    assert 'correct-pin CK_RV=0x000000a4' in result.stdout
    # The next operation provisions a factory-fresh card: budget restored.
    docker(*base, *controls, image, 'health')
    recovered = docker(*base, *controls, consumer, 'exec', '--', 'sh', '-c',
                       'p11lab-smoke --module /usr/local/lib/libykcs11.so.2 --token-label "YubiKey PIV #0" '
                       '--pin-file /run/secrets/pin --output /tmp/recovered --key-mode existing --key-id 01')
    assert 'P256 signature exported' in recovered.stdout


