# SPDX-License-Identifier: Apache-2.0
"""Both frozen wolfPKCS11/wolfSSL pairs, lifecycle and independent applications.

Bind explicit channel/engine-ID maps in P11LAB_WOLFPKCS11_IMAGES, _CONSUMERS,
_CHECKERS, _PROXIES and bundle paths in _CLIENTS; _CALLER is an independent
caller image. Derivatives contain p11lab-smoke, p11lab-token and the original
NATIVE_PROBE below, compiled against the consumer's retained p11-kit header.
No implicit provider builds or mutable image discovery occur in this suite.
"""
from dataclasses import replace
import hashlib
import itertools
import json
import os
from pathlib import Path
import subprocess

import pytest

from p11lab.build import runtime_inputs
from p11lab.catalog import load_environment, package_data, validate_build_inputs
from p11lab.identity import artifact_key
from p11lab.models import ArtifactRef, RunSpec
from p11lab.run import run_application

CHANNELS = ('release', 'rolling')
MODULE = '/usr/local/lib/p11lab/libwolfpkcs11.so'
TOKEN = 'wp11_token_0000000000000001'
PIN = b'Caller-test-U9'
SO = b'Caller-test-SO19'
IMAGES = json.loads(os.environ.get('P11LAB_WOLFPKCS11_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_WOLFPKCS11_CONSUMERS', '{}'))
CHECKERS = json.loads(os.environ.get('P11LAB_WOLFPKCS11_CHECKERS', '{}'))
PROXIES = json.loads(os.environ.get('P11LAB_WOLFPKCS11_PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_WOLFPKCS11_CLIENTS', '{}'))
CALLER = os.environ.get('P11LAB_WOLFPKCS11_CALLER', '')
EVIDENCE = os.environ.get('P11LAB_WOLFPKCS11_EVIDENCE')
COMMANDS = itertools.count()

NATIVE_PROBE = r'''/* SPDX-License-Identifier: Apache-2.0 */
#include "consumer/vendor/pkcs11.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static CK_RV log_rv(const char *op, CK_RV rv) {
    printf("%s: CK_RV=0x%08lx\n", op, rv); return rv;
}
static size_t secret(int fd, unsigned char *pin) {
    size_t n = 0; ssize_t r;
    while ((r = read(fd, pin+n, 33-n)) > 0) {
        n += (size_t)r; if (n > 32) return 0;
    }
    return r < 0 ? 0 : n;
}
int main(int argc, char **argv) {
    CK_FUNCTION_LIST_PTR f = NULL;
    CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR) = NULL;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_SLOT_ID slot = 1; CK_ULONG count = 1, i;
    CK_MECHANISM_TYPE mechanisms[256];
    unsigned char pin[33] = {0}, so[33] = {0};
    CK_RV rv; void *handle, *symbol; int initialized = 0, status = 1;
    const char *module = getenv("P11LAB_MODULE");
    size_t plen, slen;
    if (argc != 2 || !module) return 2;
    handle = dlopen(module, RTLD_NOW | RTLD_LOCAL); if (!handle) return 1;
    symbol = dlsym(handle, "C_GetFunctionList");
    _Static_assert(sizeof(symbol)==sizeof(get), "ABI");
    memcpy(&get, &symbol, sizeof(get));
    if (!get || log_rv("C_GetFunctionList", get(&f)) || !f) goto out;
    if (log_rv("C_Initialize", f->C_Initialize(NULL))) goto out;
    initialized = 1;
    if (log_rv("C_GetSlotList", f->C_GetSlotList(CK_TRUE, &slot, &count)) || count != 1 || slot != 1) goto out;
    if (!strcmp(argv[1], "login")) {
        plen = secret(3, pin); slen = secret(4, so);
        if (!plen || !slen) goto out;
        if (log_rv("C_OpenSession", f->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session))) goto out;
        if (log_rv("C_Login(SO)", f->C_Login(session, CKU_SO, so, (CK_ULONG)slen))) goto out;
        if (log_rv("C_Logout", f->C_Logout(session))) goto out;
        if (log_rv("C_Login(USER)", f->C_Login(session, CKU_USER, pin, (CK_ULONG)plen))) goto out;
        if (log_rv("C_Logout", f->C_Logout(session))) goto out;
    } else if (!strcmp(argv[1], "mechanisms")) {
        count = 256;
        if (log_rv("C_GetMechanismList", f->C_GetMechanismList(slot, mechanisms, &count))) goto out;
        for (i = 0; i < count; i++) printf("mechanism=%08lx\n", mechanisms[i]);
    } else goto out;
    status = 0;
out:
    if (session != CK_INVALID_HANDLE) {
        rv = log_rv("C_CloseSession", f->C_CloseSession(session)); if (rv) status = 1;
    }
    if (initialized) { rv = log_rv("C_Finalize", f->C_Finalize(NULL)); if (rv) status = 1; }
    memset(pin, 0, sizeof(pin)); memset(so, 0, sizeof(so)); dlclose(handle); return status;
}
'''


def docker(*args, check=True):
    argv = ['docker', *args]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    if EVIDENCE:
        root = Path(EVIDENCE) / 'commands'
        root.mkdir(parents=True, exist_ok=True)
        (root / f'{next(COMMANDS):04d}.json').write_text(json.dumps({
            'argv': argv, 'env': {}, 'returncode': result.returncode,
            'stdout': result.stdout, 'stderr': result.stderr,
        }, indent=2) + '\n')
    if check:
        assert result.returncode == 0, result.stderr
    return result


def snapshot(state):
    return {str(p.relative_to(state)): ('symlink', os.readlink(p)) if p.is_symlink()
            else ('file', hashlib.sha256(p.read_bytes()).hexdigest()) if p.is_file()
            else ('directory', None) for p in state.rglob('*')}


@pytest.fixture(params=CHANNELS)
def runtime(request, tmp_path):
    channel = request.param
    if channel not in IMAGES:
        pytest.skip('explicit wolfPKCS11 channel runtime ID required')
    root = Path(EVIDENCE) / request.node.name if EVIDENCE else tmp_path / channel
    root.mkdir(parents=True, exist_ok=False)
    state, secrets = root / 'state', root / 'secrets'
    state.mkdir(mode=0o700)
    secrets.mkdir(mode=0o700)
    for name, value in [('pin', PIN), ('so', SO)]:
        (secrets / name).write_bytes(value)
        (secrets / name).chmod(0o600)
    base = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', '/tmp',
            '--tmpfs', f'/run/p11lab:uid={os.getuid()},gid={os.getgid()},mode=0700',
            '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly']
    controls = ['-e', 'P11LAB_LABEL=acceptance', '-e', 'P11LAB_PIN_FILE=/run/secrets/pin',
                '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so']
    yield channel, root, state, secrets, IMAGES[channel], base, controls
    # Test secrets and env files never survive as durable evidence.
    for p in secrets.iterdir():
        p.unlink()


@pytest.mark.parametrize('channel', CHANNELS)
def test_packaged_pairs_are_closed_and_identity_is_deterministic(channel):
    spec = load_environment('wolfpkcs11', channel)
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    assert artifact_key('runtime', inputs) == artifact_key('runtime', runtime_inputs(spec))
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['patches'] == [] and len(inputs['dependencies']) == 1
    assert inputs['dependencies'][0]['id'] == 'wolfssl'
    assert inputs['sources'][0]['revision'] == {
        'release': 'caeaaa5693ad7b4253d6bc585e642381033a6a87',
        'rolling': '15691bd6accf45cad54b44eb07839e08c11b50fc',
    }[channel]
    assert inputs['dependencies'][0]['revision'] == {
        'release': 'ac01707f552c611fbd135cc723b2682b3e7f80f2',
        'rolling': '2411aae3f74d0fc6ccb09d3d6dfdc69e7b32c632',
    }[channel]
    for source in inputs['sources'] + inputs['dependencies']:
        assert source['archive_sha256'] and source['license_evidence']
        assert 'GPLv3' in source['license_observation']
    assert spec['distribution']['status'] == 'unreviewed'
    assert spec['application_profile'] == 'general-token'


def test_lifecycle_preserves_state_and_arbitrary_argv(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert json.loads(docker('run', '--rm', image, 'describe').stdout)['module_path'] == MODULE
    assert docker(*base, image, 'init', check=False).returncode != 0
    assert list(state.iterdir()) == []
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    (secrets / 'pin').write_bytes(b'different-user')
    (secrets / 'so').write_bytes(b'different-officer')
    docker(*base, *controls, image, 'init')
    assert snapshot(state) == before
    assert 'native_slot=1 token_present_index=0 label=acceptance' in docker(*base, *controls, image, 'health').stdout
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\\n" "$WOLFPKCS11_TOKEN_PATH" "$P11LAB_MODULE" "$1"; exit 37',
                    'caller', 'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == ['/var/lib/p11lab/wolfpkcs11', MODULE, 'literal $argument with spaces']
    assert snapshot(state) == before
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'command -v gcc cc make python3 pkcs11-tool wolfpkcs11-init-token; exit 0').stdout == ''
    marker = (state / 'wolfpkcs11/complete').read_bytes()
    assert PIN not in marker and SO not in marker and b'pin' not in marker.lower()
    (state / 'foreign').write_bytes(b'caller-owned')
    frozen = snapshot(state)
    for operation in ('init', 'health'):
        assert docker(*base, *controls, image, operation, check=False).returncode != 0
        assert snapshot(state) == frozen


def oracle(output):
    result = subprocess.run(['python3', str(package_data('consumer/verify.py')), str(output)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert 'altered message rejected' in result.stdout
    (output.parent / 'oracle.txt').write_text(result.stdout)


def as_ref(image):
    return ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')


def test_general_token_crypto_persistent_reopen_and_native_wrong_pin(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible C consumer derivative required'
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
              'P11LAB_SO_PIN_FILE': str(secrets / 'so'), 'P11LAB_LABEL': 'acceptance'}
    argv = ('p11lab-smoke', '--module', MODULE, '--token-label', 'acceptance',
            '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--output', '/p11lab-output/crypto', '--key-mode', 'generated')
    spec = RunSpec('wolfpkcs11', channel, 'direct', as_ref(CONSUMERS[channel]), 'provider', None, None,
                   argv, inputs, root / 'generated', root, 90)
    result = run_application(spec)
    assert result.exit_code == 0 and not result.cleanup_errors, result
    oracle(spec.output_dir / 'crypto')
    provision = replace(spec, output_dir=root / 'provision', argv=(
        'p11lab-token', '--module', MODULE, '--token-label', 'acceptance',
        '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--key-id', '42'))
    assert run_application(provision).exit_code == 0
    public = []
    for number in range(2):
        reopened = replace(spec, output_dir=root / f'reopen-{number}', argv=(*argv[:-1], 'existing', '--key-id', '42'))
        result = run_application(reopened)
        assert result.exit_code == 0 and not result.cleanup_errors, result
        oracle(reopened.output_dir / 'crypto')
        public.append((reopened.output_dir / 'crypto/public-key.der').read_bytes())
    assert public[0] == public[1]
    (secrets / 'pin').write_bytes(b'wrong-test-pin')
    wrong = run_application(replace(spec, output_dir=root / 'wrong-pin'))
    assert wrong.exit_code != 0 and wrong.app_returncode != 0
    assert 'C_Login: CK_RV=0x000000a0' in (root / 'wrong-pin/application.stderr.log').read_text()
    for path in root.rglob('*.log'):
        assert all(value not in path.read_bytes() for value in (PIN, SO, b'wrong-test-pin'))


@pytest.mark.parametrize('role', ['PIN', 'SO_PIN'])
@pytest.mark.parametrize('kind', ['file', 'scalar'])
def test_caller_pins_are_set_and_reference_defaults_rejected(runtime, role, kind):
    channel, root, state, secrets, image, base, controls = runtime
    if kind == 'scalar':
        # Docker reads a private env file; credential values never enter argv
        # or command evidence. The adapter unexports scalars before children.
        controls = controls[:2]
        envfile = secrets / 'scalar.env'
        envfile.write_bytes(b'P11LAB_PIN=' + PIN + b'\nP11LAB_SO_PIN=' + SO + b'\n')
        envfile.chmod(0o600)
        controls += ['--env-file', str(envfile)]
    docker(*base, *controls, image, 'init')
    assert channel in CONSUMERS
    probe = ['exec', '--', 'sh', '-c', 'exec 3</run/secrets/pin 4</run/secrets/so; exec p11lab-native-probe login']
    docker(*base, *controls, CONSUMERS[channel], *probe)
    no_env = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'if env | grep -E "^P11LAB_(PIN|SO_PIN)=" >/dev/null; then exit 7; fi')
    assert no_env.returncode == 0
    (secrets / ('pin' if role == 'PIN' else 'so')).write_bytes(b'1234' if role == 'PIN' else b'12345678')
    failed = docker(*base, *controls, CONSUMERS[channel], *probe, check=False)
    assert failed.returncode != 0
    assert f'C_Login({"USER" if role == "PIN" else "SO"}): CK_RV=0x000000a0' in failed.stdout
    assert PIN.decode() not in failed.stdout + failed.stderr and SO.decode() not in failed.stdout + failed.stderr


@pytest.mark.parametrize('damage', ['missing-token', 'empty-token', 'short-token', 'bad-pin-framing',
                                  'bad-object-count', 'missing-marker', 'marker-extra-lf', 'hidden-file',
                                  'dangling-link', 'token-link', 'busy-init', 'interrupted-writer'])
def test_static_damage_refused_before_native_open_or_application(runtime, damage):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    owned = state / 'wolfpkcs11'
    token = owned / TOKEN
    if damage == 'missing-token':
        token.unlink()
    elif damage == 'empty-token':
        token.write_bytes(b'')
    elif damage == 'short-token':
        token.write_bytes(token.read_bytes()[:-1])
    elif damage in ('bad-pin-framing', 'bad-object-count'):
        data = bytearray(token.read_bytes())
        offset = 32 if damage == 'bad-pin-framing' else 192
        data[offset:offset + 4] = b'\xff' * 4
        token.write_bytes(data)
    elif damage == 'missing-marker':
        (owned / 'complete').unlink()
    elif damage == 'marker-extra-lf':
        with (owned / 'complete').open('ab') as marker:
            marker.write(b'\n')
    elif damage == 'hidden-file':
        (owned / '.foreign').write_bytes(b'foreign')
    elif damage == 'dangling-link':
        (owned / 'wp11_obj_0000000000000001_0000000000000000').symlink_to('absent')
    elif damage == 'token-link':
        token.rename(owned / 'original')
        token.symlink_to('original')
    elif damage == 'busy-init':
        (state / '.init-lock').mkdir()
    else:
        (owned / 'wp11_tmp_interrupted').write_bytes(b'partial-write')
    before = snapshot(state)
    for operation in ('init', 'health', 'exec'):
        argv = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'echo APP-RAN']
        result = docker(*base, *controls, image, *argv, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert snapshot(state) == before, (damage, operation)


@pytest.mark.parametrize('bad', ['absent-pin', 'absent-so', 'empty', 'multiline', 'nul', 'too-large',
                               'native-too-short', 'native-too-long', 'conflict-user', 'conflict-so'])
def test_bad_credentials_create_no_owned_state(runtime, bad):
    channel, root, state, secrets, image, base, controls = runtime
    if bad == 'absent-pin':
        controls = controls[:2] + controls[4:]
    elif bad == 'absent-so':
        controls = controls[:-2]
    elif bad in ('conflict-user', 'conflict-so'):
        controls = [*controls, '-e', 'P11LAB_PIN=' if bad == 'conflict-user' else 'P11LAB_SO_PIN=']
    else:
        (secrets / 'pin').write_bytes({'empty': b'', 'multiline': b'line1\nline2', 'nul': b'nul\0byte',
                                      'too-large': b'x' * 4097, 'native-too-short': b'123',
                                      'native-too-long': b'x' * 33}[bad])
    result = docker(*base, *controls, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []
    assert PIN.decode() not in result.stdout + result.stderr and SO.decode() not in result.stdout + result.stderr


@pytest.mark.parametrize('control', ['P11LAB_LABEL=different', 'WOLFPKCS11_TOKEN_PATH=/tmp/other'])
def test_conflicting_label_and_native_store_preserve_state(runtime, control):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    for operation in ('init', 'health', 'exec'):
        argv = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'echo APP-RAN']
        result = docker(*base, *controls, '-e', control, image, *argv, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert snapshot(state) == before


@pytest.mark.parametrize('target', ['root', 'owned', 'token'])
def test_foreign_state_ownership_preserves_all_bytes(runtime, target):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    path = {'root': '/var/lib/p11lab', 'owned': '/var/lib/p11lab/wolfpkcs11',
            'token': '/var/lib/p11lab/wolfpkcs11/' + TOKEN}[target]
    mount = ['--mount', f'type=bind,src={state},dst=/var/lib/p11lab']
    try:
        docker('run', '--rm', '--network', 'none', '--user', '0:0', *mount,
               '--entrypoint', 'chown', image, '999:999', path)
        for operation in ('init', 'health', 'exec'):
            argv = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'echo APP-RAN']
            result = docker(*base, *controls, image, *argv, check=False)
            assert result.returncode != 0 and 'APP-RAN' not in result.stdout
    finally:
        docker('run', '--rm', '--network', 'none', '--user', '0:0', *mount,
               '--entrypoint', 'chown', image, f'{os.getuid()}:{os.getgid()}', path)
    assert snapshot(state) == before


def test_independent_state_uses_random_seeds_and_does_not_reopen_other_keys(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    other = root / 'other-state'
    other.mkdir(mode=0o700)
    second = [arg.replace(f'src={state},', f'src={other},') for arg in base]
    docker(*second, *controls, image, 'init')
    assert (state / 'wolfpkcs11' / TOKEN).read_bytes() != (other / 'wolfpkcs11' / TOKEN).read_bytes()
    assert channel in CONSUMERS
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
              'P11LAB_SO_PIN_FILE': str(secrets / 'so'), 'P11LAB_LABEL': 'acceptance'}
    spec = RunSpec('wolfpkcs11', channel, 'direct', as_ref(CONSUMERS[channel]), 'provider', None, None,
                   ('p11lab-token', '--module', MODULE, '--token-label', 'acceptance',
                    '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--key-id', '42'),
                   inputs, root / 'create-key', root, 90)
    created = run_application(spec)
    assert created.exit_code == 0 and not created.cleanup_errors, created
    isolated = replace(spec, inputs=inputs | {'P11LAB_STATE_DIR': str(other)}, output_dir=root / 'isolated',
                       argv=('p11lab-smoke', '--module', MODULE, '--token-label', 'acceptance',
                             '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--output', '/p11lab-output/crypto',
                             '--key-mode', 'existing', '--key-id', '42'))
    absent = run_application(isolated)
    assert absent.exit_code != 0 and absent.app_returncode != 0 and not absent.cleanup_errors
    before = snapshot(state)
    (other / 'wolfpkcs11/complete').unlink()
    assert docker(*second, *controls, image, 'init', check=False).returncode != 0
    assert snapshot(state) == before


def test_native_provision_helper_refuses_reset(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'exec 3</run/secrets/pin 4</run/secrets/so; exec p11lab-wolfpkcs11 init', check=False)
    assert result.returncode != 0 and 'refusing to reset' in result.stderr
    assert snapshot(state) == before


def test_exact_image_identity_mechanism_coverage_and_admission_block(runtime):
    from p11lab.licenses import assess_distribution
    channel, root, state, secrets, image, base, controls = runtime
    spec = load_environment('wolfpkcs11', channel)
    assert json.loads(docker('image', 'inspect', image).stdout)[0]['Id'] == image
    metadata = docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat', image,
                      '/usr/share/p11lab/provider.json').stdout
    assert json.loads(metadata) == json.loads(package_data('providers/wolfpkcs11/provider.json').read_text())
    runtime_id = docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat', image,
                        '/usr/share/p11lab/runtime-id').stdout
    assert runtime_id == artifact_key('runtime', runtime_inputs(spec)) + '\n'
    assert IMAGES.get('release') != IMAGES.get('rolling')
    docker(*base, *controls, image, 'init')
    assert channel in CONSUMERS
    result = docker(*base, *controls, CONSUMERS[channel], 'exec', '--', 'p11lab-native-probe', 'mechanisms')
    observed = {int(line.split('=')[1], 16) for line in result.stdout.splitlines() if line.startswith('mechanism=')}
    # RSA keygen/PSS, EC keygen/ECDSA/ECDH, AES keygen/ECB/CBC/CTR/GCM/CCM/
    # CTS/CMAC/keywrap, SHA-256/SHA-3, HMAC, PBKDF2. Presence is not crypto
    # qualification of all these surfaces; the full list is retained.
    required = {0x0, 0xD, 0x1040, 0x1041, 0x1050, 0x1080, 0x1081, 0x1082,
                0x1086, 0x1087, 0x1088, 0x1089, 0x108A, 0x2109, 0x210A,
                0x250, 0x251, 0x2B0, 0x3B0}
    assert required <= observed, required - observed
    decision = assess_distribution(as_ref(image), root / 'admission')
    assert decision['status'] == 'blocked' and decision['blockers']
    assert decision['publication_status'] == 'blocked'


def lane_root(name, channel, tmp_path):
    root = Path(EVIDENCE) / name / channel if EVIDENCE else tmp_path
    root.mkdir(parents=True, exist_ok=True)
    caller = root / 'caller'
    caller.mkdir()
    pin, so = root / 'pin', root / 'so'
    pin.write_bytes(PIN)
    so.write_bytes(SO)
    pin.chmod(0o600)
    so.chmod(0o600)
    return root, caller, pin, so


@pytest.mark.parametrize('channel', CHANNELS)
def test_installed_checker_observations_complete(channel, tmp_path):
    if channel not in CHECKERS:
        pytest.skip('explicit installed checker derivative required')
    from p11lab.checker import run_checker
    root, caller, pin, so = lane_root('direct-checker', channel, tmp_path)
    try:
        spec = RunSpec('wolfpkcs11', channel, 'direct', as_ref(CHECKERS[channel]), 'provider', None, None, (),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so)}, root / 'output', caller, 1200)
        result = run_checker(spec, 'smoke-v1')
        assert not result.cleanup_errors
        receipt = json.loads((spec.output_dir / 'checker/checker-receipt.json').read_text())
        assert receipt['evidence']['observations_complete'], receipt
        assert len(receipt['nodes']) == 23
        assert receipt['token']['native_slot_id'] == 1 and receipt['token']['token_present_index'] == 0
        assert receipt['token']['label'] == 'P11Lab'
        # Completed native provider findings remain valid negative observations.
        print(f'checker direct/{channel}: exit={result.exit_code} evidence={receipt["evidence"]}')
    finally:
        pin.unlink(missing_ok=True)
        so.unlink(missing_ok=True)


@pytest.mark.parametrize('channel', CHANNELS)
def test_preferred_proxy_independent_crypto(channel, tmp_path):
    if channel not in PROXIES or channel not in CLIENTS or not CALLER:
        pytest.skip('explicit pinned daemon, client bundle and caller required')
    root, caller, pin, so = lane_root('proxy-crypto', channel, tmp_path)
    try:
        bundle = Path(CLIENTS[channel])
        client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
        spec = RunSpec('wolfpkcs11', channel, 'proxy', as_ref(PROXIES[channel]), 'container', as_ref(CALLER), client,
                       ('p11lab-smoke', '--module', '/run/p11lab-client/libpkcs11_proxy_ng_shim.so',
                        '--token-label', 'P11Lab', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
                        '--output', '/p11lab-output/crypto', '--key-mode', 'generated'),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so)}, root / 'output', caller, 600)
        result = run_application(spec)
        assert result.exit_code == 0 and not result.cleanup_errors, result
        assert (spec.output_dir / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
        oracle(spec.output_dir / 'crypto')
    finally:
        pin.unlink(missing_ok=True)
        so.unlink(missing_ok=True)


def test_invalid_dispatch_does_not_start_app_or_create_state(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    for argv in [('server',), ('server-ready',), ('init', 'extra'), ('health', 'extra'),
                 ('exec',), ('exec', '--'), ('exec', 'sh', '-c', 'echo APP-RAN')]:
        result = docker(*base, *controls, image, *argv, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert list(state.iterdir()) == []
