# SPDX-License-Identifier: Apache-2.0
"""sc-hsm acceptance, with pinned channel images and no implicit builds.

P11LAB_SC_HSM_{IMAGES,CONSUMERS,CHECKERS,PROXIES,CLIENTS} contain
explicit JSON channel maps; CALLER is an independent C caller image and
EVIDENCE is a fresh output directory. The initialized emulator flash
persists on the state volume across operations; INITIALIZE is destructive
and never re-runs, pcscd plus the emulator supervise per operation only,
and general-token applications may persist their own on-card objects.
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

MODULE = '/usr/local/lib/p11lab/libsc-hsm-pkcs11.so'
LABEL = 'SmartCard-HSM'
IMAGES = json.loads(os.environ.get('P11LAB_SC_HSM_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_SC_HSM_CONSUMERS', '{}'))
CHECKERS = json.loads(os.environ.get('P11LAB_SC_HSM_CHECKERS', '{}'))
DAEMONS = json.loads(os.environ.get('P11LAB_SC_HSM_PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_SC_HSM_CLIENTS', '{}'))
CALLER = os.environ.get('P11LAB_SC_HSM_CALLER', '')
COMMANDS = itertools.count()




def docker(*args, check=True, env=None):
    argv = ['docker', *args]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=300, env=os.environ | (env or {}))
    evidence = os.environ.get('P11LAB_SC_HSM_EVIDENCE')
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
        pytest.skip('explicit sc-hsm runtime IDs required')
    channel = request.param
    root = Path(os.environ.get('P11LAB_SC_HSM_EVIDENCE', str(tmp_path))) / request.node.name
    root.mkdir(parents=True, exist_ok=False)
    state = root / 'state'
    state.mkdir(mode=0o700)
    secrets = root / 'secrets'
    secrets.mkdir(mode=0o700)
    for name, value in [('pin', b'654321'), ('so', b'0011223344556677')]:
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
    evidence = os.environ.get('P11LAB_SC_HSM_EVIDENCE')
    root = Path(evidence) / name / channel if evidence else tmp_path
    root.mkdir(parents=True, exist_ok=True)
    caller = root / 'caller'
    caller.mkdir()
    pin, so = root / 'pin', root / 'so'
    pin.write_bytes(b'654321')
    so.write_bytes(b'0011223344556677')
    pin.chmod(0o600)
    so.chmod(0o600)
    return root, caller, pin, so


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_installed_checker_observations(channel, tmp_path):
    if channel not in CHECKERS:
        pytest.skip('explicit installed sc-hsm checker derivative required')
    from p11lab.checker import run_checker
    root, caller, pin, so = lane_root('direct-checker', channel, tmp_path)
    try:
        spec = RunSpec('sc-hsm', channel, 'direct', as_ref(CHECKERS[channel]), 'provider', None, None, (),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so), 'P11LAB_LABEL': LABEL}, root / 'output', caller, 1200)
        result = run_checker(spec, 'smoke-v1')
        assert not result.cleanup_errors
        record = json.loads((spec.output_dir / 'checker/checker-receipt.json').read_text())
        assert len(record['nodes']) == 23
        assert record['token']['native_slot_id'] == 1 and record['token']['token_present_index'] == 0
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
        pytest.skip('explicit pinned sc-hsm daemon, client bundle and caller required')
    root, caller, pin, so = lane_root('proxy-crypto', channel, tmp_path)
    try:
        bundle = Path(CLIENTS[channel])
        client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
        spec = RunSpec('sc-hsm', channel, 'proxy', as_ref(DAEMONS[channel]), 'container', as_ref(CALLER), client,
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
    spec = load_environment('sc-hsm', channel)
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    expected = {'release': 'da7e3623bc3cb8c126eaa5128b2c24501919c728',
                'rolling': 'ae01b29dbe1585a174de14c1eabb123dafc96c4a'}
    assert inputs['sources'][0]['revision'] == expected[channel]
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['openssl']['from_source'] is False
    assert inputs['features']['token_slot'] == 1 and inputs['features']['token_present_index'] == 0
    assert inputs['features']['token_label'] == LABEL and inputs['features']['token_flags'] == '0x40d'
    assert inputs['features']['pinlen_min'] == 6 and inputs['features']['pinlen_max'] == 16
    assert inputs['features']['soplen_hex'] == 16
    assert inputs['features']['user_retries'] == 3
    assert inputs['features']['keys'] == '01:p256,02:rsa2048,03:p384'
    assert inputs['features']['mechanisms'] == 24
    assert inputs['features']['objects_total'] == {'release': 4, 'rolling': 3}[channel]
    assert inputs['features']['autotools']['sc_hsm_embedded'] == ['--prefix=/usr/local', '--enable-libcrypto']
    assert inputs['features']['upstream_version'] == {'release': 'V2.12', 'rolling': 'master-ae01b29dbe15'}[channel]
    assert spec['services'] == ['pico-hsm', 'pcscd', 'vpcd']
    assert [(p['path'], p['target_source']) for p in inputs['patches']] == [
        ('patches/0001-pico-keys-sdk-frozen-mbedtls.patch', 'pico-keys-sdk'),
        ('patches/0002-pico-hsm-termca-bare-cvc.patch', 'pico-hsm')]
    assert [d['id'] for d in inputs['dependencies']] == ['pico-hsm', 'pico-keys-sdk', 'mbedtls', 'mbedtls-framework',
                                                         'mlkem-native', 'tinycbor', 'vsmartcard']
    assert inputs['features']['pico_hsm']['revision'] == '251b35dd9c4fd929923fc3b192f6793826efeaef'
    assert inputs['features']['vsmartcard']['revision'] == '82bc5ad066b26ee057d2af200c1a66e3a65a9743'
    assert all(item in inputs['features']['cmake']['pico_hsm'] for item in
               ['-DENABLE_EMULATION=1', '-D__FOR_CI=1'])
    assert inputs['features']['extraction']['whole_count'] == 6
    other = 'rolling' if channel == 'release' else 'release'
    assert artifact_key('runtime', inputs) != artifact_key('runtime', runtime_inputs(load_environment('sc-hsm', other)))


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
    # INITIALIZE is destructive, so a repeated init never re-provisions:
    # it validates the provisioned state and checks readiness without
    # consuming credentials at all.
    (secrets / 'pin').write_bytes(b'112233')
    (secrets / 'so').write_bytes(b'4455667788990011')
    docker(*base, *controls, image, 'init')
    assert snapshot(state) == before
    health = docker(*base, *controls, image, 'health')
    assert 'native_slot=1 token_present_index=0 label=SmartCard-HSM' in health.stdout
    changed = docker(*base, *controls, '-e', 'P11LAB_LABEL=different', image, 'init', check=False)
    assert changed.returncode != 0 and 'token label is fixed' in changed.stderr
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\\n" "$P11LAB_MODULE" "$1"; exit 37', 'caller',
                    'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == [MODULE, 'literal $argument with spaces']
    assert 'pin' not in (state / 'sc-hsm/complete').read_text().lower()
    assert (state / 'sc-hsm/memory.flash').is_file() and (state / 'sc-hsm/lease').is_file()
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'for t in cc gcc make cmake python3 pkcs11-tool openssl sc-hsm-tool; do command -v $t; done; exit 0').stdout == ''
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'for t in pico_hsm pcscd; do command -v $t; done').stdout.split() == [
                      '/usr/local/bin/pico_hsm', '/usr/sbin/pcscd']
    # The other module is never bundled: no silent OpenSC provisioner.
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'test ! -e /usr/local/lib/p11lab/opensc-pkcs11.so && echo ABSENT-OK').stdout.strip() == 'ABSENT-OK'
    assert snapshot(state) == before
    # Credentials in the native adapter come from either scalar environment
    # or private files. Docker argv and durable command records omit values.
    other = root / 'scalar-state'
    other.mkdir(mode=0o700)
    scalar_base = [x.replace(f'src={state},', f'src={other},') for x in base]
    docker(*scalar_base, '-e', 'P11LAB_PIN', '-e', 'P11LAB_SO_PIN', image, 'init',
           env={'P11LAB_PIN': '246810', 'P11LAB_SO_PIN': '0011223344556677'})
    # Health re-validates the persistent provisioned state; it consumes no
    # credentials, so the scalar environment is simply ignored here.
    docker(*scalar_base, '-e', 'P11LAB_PIN', '-e', 'P11LAB_SO_PIN', image, 'health',
           env={'P11LAB_PIN': '246810', 'P11LAB_SO_PIN': '0011223344556677'})


def oracle(output):
    result = subprocess.run(['python3', str(package_data('consumer/verify.py')), str(output)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert 'altered message rejected' in result.stdout
    (output.parent / 'oracle.txt').write_text(result.stdout)


def test_application_crypto_persistence_isolation_and_native_errors(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
              'P11LAB_SO_PIN_FILE': str(secrets / 'so')}
    argv = ('p11lab-smoke', '--module', MODULE, '--token-label', LABEL, '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
            '--output', '/p11lab-output/crypto', '--key-mode', 'existing', '--key-id', '01')
    spec = RunSpec('sc-hsm', channel, 'direct', as_ref(CONSUMERS[channel]), 'provider', None, None,
                   argv, inputs, root / 'existing-template', root, 90)
    public = []
    for number in range(2):
        reopened = replace(spec, output_dir=root / f'reopen-{number}')
        result = run_application(reopened)
        assert result.exit_code == 0 and not result.cleanup_errors, result
        oracle(reopened.output_dir / 'crypto')
        public.append((reopened.output_dir / 'crypto/public-key.der').read_bytes())
    # The provisioned on-card key persists across operations: same key.
    assert public[0] == public[1]
    # Session key pairs are natively rejected: the module gates
    # C_GenerateKeyPair with CKA_TOKEN=false to
    # CKR_TEMPLATE_INCONSISTENT (0xd1), so generated mode fails with
    # that exact native error and never touches the flash census.
    census_before = snapshot(state)
    for number in range(2):
        made = replace(spec, output_dir=root / f'session-{number}',
                       argv=('p11lab-smoke', '--module', MODULE, '--token-label', LABEL,
                            '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
                            '--output', '/p11lab-output/crypto', '--key-mode', 'generated'))
        result = run_application(made)
        assert result.app_returncode != 0 and not result.cleanup_errors, result
        assert 'C_GenerateKeyPair: CK_RV=0x000000d1' in (made.output_dir / 'application.stderr.log').read_text()
    assert snapshot(state) == census_before
    provision = replace(spec, output_dir=root / 'provision-native', argv=('p11lab-token', '--module', MODULE,
                        '--token-label', LABEL, '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--key-id', '42'))
    created = run_application(provision)
    assert created.exit_code == 0 and not created.cleanup_errors, created
    applied = []
    for number in range(2):
        reused = replace(spec, output_dir=root / f'applied-{number}',
                         argv=('p11lab-smoke', '--module', MODULE, '--token-label', LABEL,
                              '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
                              '--output', '/p11lab-output/crypto', '--key-mode', 'existing', '--key-id', '42'))
        result = run_application(reused)
        assert result.exit_code == 0 and not result.cleanup_errors, result
        oracle(reused.output_dir / 'crypto')
        applied.append((reused.output_dir / 'crypto/public-key.der').read_bytes())
    # An application-provisioned on-card key persists and stays usable;
    # later operations must not mistake it for foreign state.
    assert applied[0] == applied[1]
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
    assert (other / 'sc-hsm/memory.flash').is_file()
    # A separate state provisions an independent card, never a view onto
    # the original keys: fresh key material, not the same identity.
    assert (root / 'separate/crypto/public-key.der').read_bytes() != public[0]
    for path in root.rglob('*.log'):
        assert b'bad-pin' not in path.read_bytes() and b'0011223344556677' not in path.read_bytes()


@pytest.mark.parametrize('damage', ['missing-flash', 'empty-flash', 'truncated-flash', 'flash-mode', 'flash-link',
                                   'missing-marker', 'marker-extra-lf', 'missing-lease', 'hidden-file',
                                   'dangling-link', 'busy-init'])
def test_damage_refused_before_daemon_or_application(runtime, damage):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    owned = state / 'sc-hsm'
    flash = owned / 'memory.flash'
    if damage == 'missing-flash':
        flash.unlink()
    elif damage == 'empty-flash':
        flash.write_bytes(b'')
    elif damage == 'truncated-flash':
        flash.write_bytes(flash.read_bytes()[:1048576])
    elif damage == 'flash-mode':
        flash.chmod(0o644)
    elif damage == 'flash-link':
        flash.rename(owned / 'original.flash')
        flash.symlink_to('original.flash')
    elif damage == 'missing-marker':
        (owned / 'complete').unlink()
    elif damage == 'marker-extra-lf':
        with (owned / 'complete').open('ab') as f:
            f.write(b'\n')
    elif damage == 'missing-lease':
        (owned / 'lease').unlink()
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
                                'user-conflict', 'so-conflict', 'bad-so-length', 'bad-so-shape'])
def test_bad_credentials_never_create_state(runtime, bad):
    channel, root, state, secrets, image, base, controls = runtime
    if bad == 'absent-pin':
        controls = controls[2:]
    elif bad == 'absent-so':
        controls = controls[:2]
    elif bad in ('user-conflict', 'so-conflict'):
        controls = [*controls, '-e', 'P11LAB_PIN=' if bad == 'user-conflict' else 'P11LAB_SO_PIN=']
    elif bad in ('bad-so-length', 'bad-so-shape'):
        (secrets / 'so').write_bytes(b'1234' if bad == 'bad-so-length' else b'0123456789abcdeg')
    else:
        (secrets / 'pin').write_bytes({'short': b'12345', 'long': b'12345678901234567', 'multiline': b'ab\ncdef',
                                      'nul': b'ab\x00cdef'}[bad])
    result = docker(*base, *controls, image, 'init', check=False)
    assert result.returncode != 0
    assert list(state.iterdir()) == []


def test_sixteen_byte_pin_accepted_and_verifies(runtime):
    """A 16-byte user PIN initializes and verifies natively here.

    The recipe bound is 6..16: 16 verifies through this module
    (differs from the sibling stack, proven natively), 17 is
    refused, and 5 is refused as below the advertised minimum.
    """
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    (secrets / 'pin').write_bytes(b'1234567890123456')
    docker(*base, *controls, image, 'init')
    docker(*base, *controls, image, 'health')
    signed = docker(*base, *controls, CONSUMERS[channel], 'exec', '--', 'p11lab-smoke',
                    '--module', MODULE, '--token-label', LABEL, '--pin-file', '/run/secrets/pin',
                    '--output', '/tmp/sixteen', '--key-mode', 'existing', '--key-id', '01')
    assert 'P256 signature exported' in signed.stdout
    for path in root.rglob('*.log'):
        assert b'1234567890123456' not in path.read_bytes()


def test_letter_so_init_accepted_but_module_unblock_rejected(runtime):
    """Letter SO-PINs initialize natively but hit the upstream bug.

    INITIALIZE stores any 16-hex SO-PIN on the card (raw APDU, no
    module parsing), so init plus user crypto works. But the
    module's parseSOPIN converts hex letters without the +10 nibble
    offset (upstream sc-hsm-embedded defect, both frozen revs), so
    a letter SO-PIN can never satisfy the SO-gated C_InitPIN: the
    value-deferred SO login passes and C_InitPIN fails 0xa0. The
    recipe documents this; it never restricts caller SO-PINs to
    dodge it.
    """
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    (secrets / 'so').write_bytes(b'0123456789abcdef')
    (secrets / 'newpin').write_bytes(b'112233')
    (secrets / 'newpin').chmod(0o600)
    docker(*base, *controls, image, 'init')
    docker(*base, *controls, image, 'health')
    signed = docker(*base, *controls, CONSUMERS[channel], 'exec', '--', 'p11lab-smoke',
                    '--module', MODULE, '--token-label', LABEL, '--pin-file', '/run/secrets/pin',
                    '--output', '/tmp/letter-so', '--key-mode', 'existing', '--key-id', '01')
    assert 'P256 signature exported' in signed.stdout
    reset = docker(*base, *controls, CONSUMERS[channel], 'exec', '--', 'p11lab-so-reset',
                   '/run/secrets/so', '/run/secrets/newpin', check=False)
    assert reset.returncode != 0
    assert 'C_Login(so): CK_RV=0x00000000' in reset.stderr
    assert 'C_InitPIN: CK_RV=0x000000a0' in reset.stderr
    for path in root.rglob('*.log'):
        assert b'0123456789abcdef' not in path.read_bytes() and b'112233' not in path.read_bytes()


@pytest.mark.parametrize('label', ['', 'acceptance', 'x' * 33, 'bad\nlabel'])
def test_invalid_label_never_creates_state(runtime, label):
    channel, root, state, secrets, image, base, controls = runtime
    result = docker(*base, *controls, '-e', 'P11LAB_LABEL=' + label, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []


@pytest.mark.parametrize('override', ['PCSCLITE_CSOCK_NAME', 'OPENSSL_CONF', 'OPENSSL_MODULES',
                                     'LD_PRELOAD', 'NSS_WRAPPER_PASSWD', 'NSS_WRAPPER_GROUP',
                                     'PKCS11_READER_FILTER', 'PKCS11_PREALLOCATE_VIRTUAL_SLOTS',
                                     'PKCS11_IGNORE_PINPAD', 'PKCS11_LOGIN_URL'])
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
    spec = load_environment('sc-hsm', channel)
    assert json.loads(read('/usr/share/p11lab/provider.json')) == {k: v for k, v in spec.items()
                                                                 if k not in ('lock', 'channel', 'channel_spec', 'asset_root')}
    assert read('/usr/share/p11lab/runtime-id') == artifact_key('runtime', runtime_inputs(spec)) + '\n'
    assert 'libcrypto.so.3' in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'libpcsclite' in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'not found' not in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'ENABLE_EMULATION' in read('/usr/share/p11lab/build/options.txt')
    assert 'ifd-vpcd' in read('/usr/share/p11lab/build/options.txt')
    assert 'libsc-hsm-pkcs11.so' in read('/usr/share/p11lab/build/module-hashes.sha256')
    assert 'pico_hsm' in read('/usr/share/p11lab/build/module-hashes.sha256')
    assert 'p11lab-sc-hsm' in read('/usr/share/p11lab/build/module-hashes.sha256')
    assert 'mech-style sc-hsm=' in read('/usr/share/p11lab/build/mech-style.txt')
    assert 'libusb' not in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    decision = assess_distribution(as_ref(image), root / 'admission')
    assert decision['status'] == decision['publication_status'] == 'blocked' and decision['blockers']
    (root / 'admission-decision.json').write_text(json.dumps(decision, indent=2) + '\n')
    permission = docker('run', '--rm', '--network', 'none', '--entrypoint', 'stat', image,
                        '-c', '%u:%g %a', '/usr/share/p11lab/provider.json').stdout.strip()
    assert permission == '0:0 644'
    absent = docker('run', '--rm', '--network', 'none', '--entrypoint', 'sh', image,
                    '-c', 'test ! -e /usr/local/lib/p11lab/libsc-hsm-pkcs11.la '
                         '&& test ! -e /usr/local/lib/libctccid.so '
                         '&& test ! -e /usr/local/lib/p11lab/opensc-pkcs11.so '
                         '&& test ! -e /usr/local/bin/sc-hsm-tool '
                         '&& test ! -e /usr/local/bin/vicc && test ! -e /usr/local/bin/vpcd-config && echo ABSENT-OK')
    assert 'ABSENT-OK' in absent.stdout


def start_long_application(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    name = 'p11lab-sc-hsm-test-' + uuid.uuid4().hex[:12]
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
        pid = docker('exec', name, 'cat', '/run/p11lab/sc-hsm/pcscd.pid').stdout.strip()
        assert int(pid) > 1
        emulator = docker('exec', name, 'cat', '/run/p11lab/sc-hsm/emulator.pid').stdout.strip()
        assert int(emulator) > 1 and emulator != pid
        docker('kill', '--signal', 'TERM', name)
        assert docker('wait', name).stdout.strip() == '143'
        assert snapshot(state) == before
    finally:
        docker('rm', '-f', name, check=False)
    docker(*base, *controls, image, 'health')


@pytest.mark.parametrize('daemon', ['pcscd', 'emulator'])
def test_daemon_death_fails_operation_and_reaps_application(runtime, daemon):
    channel, root, state, secrets, image, base, controls = runtime
    name = start_long_application(runtime)
    before = snapshot(state)
    try:
        pid = docker('exec', name, 'cat', f'/run/p11lab/sc-hsm/{daemon}.pid').stdout.strip()
        docker('exec', name, 'sh', '-c', 'kill -KILL "$1"', 'caller', pid)
        assert docker('wait', name).stdout.strip() == '1'
        assert f'required {daemon} exited' in docker('logs', name).stderr
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


SO_RESET_PROBE = r'''
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vendor/pkcs11.h"
/* T7 acceptance-only SO unblock probe (test-only, never shipped).
 * usage: p11lab-so-reset SO_PIN_FILE NEW_USER_PIN_FILE
 * SO login plus C_InitPIN restores the user retry budget after lockout. */
static int read_bounded(const char *path, unsigned char *out, size_t cap, size_t *length)
{
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f) { fprintf(stderr, "cannot open %s\n", path); return 0; }
    n = fread(out, 1, cap + 1, f);
    fclose(f);
    if (!n || n > cap) { fprintf(stderr, "bad pin file %s\n", path); return 0; }
    *length = n;
    return 1;
}
int main(int argc, char **argv)
{
    CK_FUNCTION_LIST_PTR f = NULL;
    CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR) = NULL;
    void *h, *symbol;
    CK_RV rv;
    CK_SLOT_ID slots[16];
    CK_ULONG count = 16;
    CK_SESSION_HANDLE session = 0;
    unsigned char so[64], user[64];
    size_t so_len = 0, user_len = 0;
    int ok = 0;
    if (argc != 3) { fprintf(stderr, "usage: p11lab-so-reset SO_PIN_FILE NEW_USER_PIN_FILE\n"); return 2; }
    if (!read_bounded(argv[1], so, sizeof(so), &so_len)) return 2;
    if (!read_bounded(argv[2], user, sizeof(user), &user_len)) return 2;
    h = dlopen(getenv("P11LAB_MODULE"), RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "cannot load module\n"); return 2; }
    symbol = dlsym(h, "C_GetFunctionList");
    memcpy(&get, &symbol, sizeof(get));
    if (!get || get(&f)) { fprintf(stderr, "no function list\n"); return 2; }
    rv = f->C_Initialize(NULL);
    if (rv) { fprintf(stderr, "C_Initialize: CK_RV=0x%08lx\n", rv); goto done; }
    rv = f->C_GetSlotList(CK_TRUE, slots, &count);
    if (rv || !count) { fprintf(stderr, "C_GetSlotList: CK_RV=0x%08lx\n", rv); goto done; }
    rv = f->C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv) { fprintf(stderr, "C_OpenSession: CK_RV=0x%08lx\n", rv); goto done; }
    rv = f->C_Login(session, CKU_SO, so, (CK_ULONG)so_len);
    fprintf(stderr, "C_Login(so): CK_RV=0x%08lx\n", rv);
    if (rv) goto done;
    rv = f->C_InitPIN(session, user, (CK_ULONG)user_len);
    fprintf(stderr, "C_InitPIN: CK_RV=0x%08lx\n", rv);
    if (rv) goto done;
    f->C_Logout(session);
    rv = f->C_Login(session, CKU_USER, user, (CK_ULONG)user_len);
    fprintf(stderr, "C_Login(user): CK_RV=0x%08lx\n", rv);
    if (rv) goto done;
    ok = 1;
done:
    memset(so, 0, sizeof(so));
    memset(user, 0, sizeof(user));
    if (session) f->C_CloseSession(session);
    f->C_Finalize(NULL);
    return ok ? 0 : 1;
}
'''


def test_native_daemon_and_reader_are_required(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    result = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-native-probe')
    assert 'slot=1 count=1 min=6 max=16 flags=0x0000040d' in result.stdout
    assert 'label=SmartCard-HSM' in result.stdout
    # Bypass only the adapter in this negative native lane; without the
    # supervised pcscd, emulator and reader the module cannot enumerate
    # slots at all (CKR_DEVICE_ERROR, not an empty list: it needs the
    # resource manager to list readers).
    direct = docker(*base, '--entrypoint', 'sh', '-e', 'P11LAB_MODULE=' + MODULE, consumer, '-c',
                    'p11lab-native-probe', check=False)
    assert direct.returncode == 1 and 'C_GetSlotList: CK_RV=0x00000030' in direct.stderr
    assert snapshot(state) == before


def test_pin_retry_budget_and_lockout_are_native(runtime):
    """Wrong PINs burn SmartCard-HSM tries; the 3-try budget locks natively.

    Fresh provisioning sets 3 tries. Wrong-PIN logins burn exactly one try
    each: attempts 1..2 report CKR_PIN_INCORRECT, the third wrong attempt
    locks with CKR_PIN_LOCKED, every later attempt stays locked, and the
    correct PIN is then also rejected. The persistent token keeps the
    lockout across operations (no silent reset); only the SO-gated
    C_InitPIN restores the whole budget, and a wrong SO value fails at
    C_InitPIN after a value-deferred SO login.
    """
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    (secrets / 'wrong').write_bytes(b'999999')
    (secrets / 'wrong').chmod(0o600)
    (secrets / 'wrongso').write_bytes(b'9999999999999999')
    (secrets / 'wrongso').chmod(0o600)
    script = '''
M=/usr/local/lib/p11lab/libsc-hsm-pkcs11.so
i=1
while [ "$i" -le 8 ]; do
  rv=$(p11lab-smoke --module $M --token-label "SmartCard-HSM" --pin-file /run/secrets/wrong \
    --output /tmp/hammer-$i --key-mode existing --key-id 01 2>&1 | grep -o 'CK_RV=0x[0-9a-f]*' | head -1)
  echo "attempt $i $rv"
  i=$((i + 1))
done
echo "correct-pin $(p11lab-smoke --module $M --token-label "SmartCard-HSM" --pin-file /run/secrets/pin \
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
    # The locked bit is observed live, then health stays servable with it.
    observed = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-native-probe')
    assert 'flags=0x0004040d' in observed.stdout
    # Lockout persists across operations: health stays servable but the
    # correct PIN is still rejected. No silent reset.
    docker(*base, *controls, image, 'health')
    stale = docker(*base, *controls, consumer, 'exec', '--', 'sh', '-c',
                   'p11lab-smoke --module /usr/local/lib/p11lab/libsc-hsm-pkcs11.so --token-label "SmartCard-HSM" '
                   '--pin-file /run/secrets/pin --output /tmp/stale --key-mode existing --key-id 01', check=False)
    assert stale.returncode != 0 and 'CK_RV=0x000000a4' in stale.stderr
    # A wrong SO value passes the value-deferred SO login and fails at the
    # SO-gated C_InitPIN; only the correct SO value restores the budget.
    bad_so = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-so-reset',
                    '/run/secrets/wrongso', '/run/secrets/pin', check=False)
    assert bad_so.returncode != 0
    assert 'C_Login(so): CK_RV=0x00000000' in bad_so.stderr
    assert 'C_InitPIN: CK_RV=0x000000a0' in bad_so.stderr
    reset = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-so-reset',
                   '/run/secrets/so', '/run/secrets/pin')
    assert 'C_InitPIN: CK_RV=0x00000000' in reset.stderr
    assert 'C_Login(user): CK_RV=0x00000000' in reset.stderr
    # The restored budget is whole: a wrong PIN burns one try again and the
    # correct PIN signs.
    single = docker(*base, *controls, consumer, 'exec', '--', 'sh', '-c',
                    'p11lab-smoke --module /usr/local/lib/p11lab/libsc-hsm-pkcs11.so --token-label "SmartCard-HSM" '
                    '--pin-file /run/secrets/wrong --output /tmp/single --key-mode existing --key-id 01', check=False)
    assert single.returncode != 0 and 'CK_RV=0x000000a0' in single.stderr
    # One burned try sets COUNT_LOW; operations stay servable with it.
    low = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-native-probe')
    assert 'flags=0x0001040d' in low.stdout
    recovered = docker(*base, *controls, consumer, 'exec', '--', 'sh', '-c',
                       'p11lab-smoke --module /usr/local/lib/p11lab/libsc-hsm-pkcs11.so --token-label "SmartCard-HSM" '
                       '--pin-file /run/secrets/pin --output /tmp/recovered --key-mode existing --key-id 01')
    assert 'P256 signature exported' in recovered.stdout
    # A correct VERIFY restores the whole budget, so two more wrong PINs
    # leave one try: FINAL_TRY is observed live, health stays servable
    # with it, and the correct PIN signs again.
    pair = docker(*base, *controls, consumer, 'exec', '--', 'sh', '-c',
                  'p11lab-smoke --module /usr/local/lib/p11lab/libsc-hsm-pkcs11.so --token-label "SmartCard-HSM" '
                  '--pin-file /run/secrets/wrong --output /tmp/pair-1 --key-mode existing --key-id 01 2>&1 | '
                  "grep -o 'CK_RV=0x[0-9a-f]*' | head -1; "
                  'p11lab-smoke --module /usr/local/lib/p11lab/libsc-hsm-pkcs11.so --token-label "SmartCard-HSM" '
                  '--pin-file /run/secrets/wrong --output /tmp/pair-2 --key-mode existing --key-id 01 2>&1 | '
                  "grep -o 'CK_RV=0x[0-9a-f]*' | head -1", check=False)
    assert pair.stdout.split() == ['CK_RV=0x000000a0', 'CK_RV=0x000000a0']
    final = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-native-probe')
    assert 'flags=0x0003040d' in final.stdout
    docker(*base, *controls, image, 'health')
    whole = docker(*base, *controls, consumer, 'exec', '--', 'sh', '-c',
                   'p11lab-smoke --module /usr/local/lib/p11lab/libsc-hsm-pkcs11.so --token-label "SmartCard-HSM" '
                   '--pin-file /run/secrets/pin --output /tmp/whole --key-mode existing --key-id 01')
    assert 'P256 signature exported' in whole.stdout
