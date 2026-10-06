# SPDX-License-Identifier: Apache-2.0
# Adapted from the P11Lab wolfPKCS11 acceptance suite at e8b978a.
"""Frozen rolling-only pkcs11rs closure, lifecycle and independent applications.

Bind explicit channel/engine-ID maps in P11LAB_PKCS11RS_IMAGES, _CONSUMERS,
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

CHANNELS = ('rolling',)
MODULE = '/usr/local/lib/p11lab/libpkcs11rs.so'
TOKEN = 'tokens-v1/software-name-7031316c6162/private-keys-v1/header-00000000000000000002.cbor'
PIN = b'Caller-test-U9'
SO = b'Caller-test-SO19'
IMAGES = json.loads(os.environ.get('P11LAB_PKCS11RS_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_PKCS11RS_CONSUMERS', '{}'))
CHECKERS = json.loads(os.environ.get('P11LAB_PKCS11RS_CHECKERS', '{}'))
PROXIES = json.loads(os.environ.get('P11LAB_PKCS11RS_PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_PKCS11RS_CLIENTS', '{}'))
CALLER = os.environ.get('P11LAB_PKCS11RS_CALLER', '')
EVIDENCE = os.environ.get('P11LAB_PKCS11RS_EVIDENCE')
COMMANDS = itertools.count()

NATIVE_PROBE = r'''/* SPDX-License-Identifier: Apache-2.0
 * Original P11Lab direct probe. Credentials are inherited pipe bytes only. */
#include "consumer/vendor/pkcs11.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static CK_RV rv(const char *op, CK_RV value) {
    printf("%s: CK_RV=0x%08lx\n", op, value); return value;
}
static size_t secret(int fd, unsigned char *pin) {
    size_t n = 0; ssize_t r;
    while ((r = read(fd, pin+n, 1025-n)) > 0) { n += (size_t)r; if (n > 1024) return 0; }
    return r < 0 ? 0 : n;
}
static void erase(void *p, size_t n) { volatile unsigned char *b=p; while (n--) *b++=0; }
int main(int argc, char **argv) {
    CK_FUNCTION_LIST_PTR f=NULL; CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR)=NULL;
    CK_SESSION_HANDLE s=CK_INVALID_HANDLE; CK_SLOT_ID slot=0; CK_ULONG n=1,i;
    CK_TOKEN_INFO info; CK_MECHANISM_TYPE mechanisms[512];
    unsigned char pin[1025]={0},so[1025]={0},label[32]; size_t pn=0,sn=0;
    void *h=NULL,*symbol; int initialized=0,status=1;
    const char *module=getenv("P11LAB_MODULE"), *name=getenv("P11LAB_LABEL");
    if(argc!=2 || !module || !name || strlen(name)>32) return 2;
    memset(label,' ',32); memcpy(label,name,strlen(name));
    h=dlopen(module,RTLD_NOW|RTLD_LOCAL); if(!h) { fputs("cannot load module\n",stderr); goto out; }
    symbol=dlsym(h,"C_GetFunctionList"); _Static_assert(sizeof(symbol)==sizeof(get),"ABI"); memcpy(&get,&symbol,sizeof(get));
    if(!get || rv("C_GetFunctionList",get(&f)) || !f) goto out;
    if(rv("C_Initialize",f->C_Initialize(NULL))) goto out;
    initialized=1;
    if(rv("C_GetSlotList",f->C_GetSlotList(CK_TRUE,&slot,&n)) || n!=1) goto out;
    if(rv("C_GetTokenInfo",f->C_GetTokenInfo(slot,&info))) goto out;
    printf("native_slot=%lu token_present_index=0 pin_min=%lu pin_max=%lu flags=0x%lx\n",slot,info.ulMinPinLen,info.ulMaxPinLen,info.flags);
    if(!strcmp(argv[1],"init")) {
        pn=secret(3,pin); sn=secret(4,so); if(!pn || !sn) goto out;
        if(rv("C_InitToken",f->C_InitToken(slot,so,(CK_ULONG)sn,label))) goto out;
        if(rv("C_OpenSession",f->C_OpenSession(slot,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&s))) goto out;
        if(rv("C_Login(SO)",f->C_Login(s,CKU_SO,so,(CK_ULONG)sn))) goto out;
        if(rv("C_InitPIN",f->C_InitPIN(s,pin,(CK_ULONG)pn))) goto out;
        if(rv("C_Logout",f->C_Logout(s))) goto out;
        if(rv("C_Login(USER)",f->C_Login(s,CKU_USER,pin,(CK_ULONG)pn))) goto out;
        if(rv("C_Logout",f->C_Logout(s))) goto out;
    } else if(!strcmp(argv[1],"login")) {
        pn=secret(3,pin); sn=secret(4,so); if(!pn || !sn) goto out;
        if(rv("C_OpenSession",f->C_OpenSession(slot,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&s))) goto out;
        if(rv("C_Login(SO)",f->C_Login(s,CKU_SO,so,(CK_ULONG)sn))) goto out;
        if(rv("C_Logout",f->C_Logout(s))) goto out;
        if(rv("C_Login(USER)",f->C_Login(s,CKU_USER,pin,(CK_ULONG)pn))) goto out;
        if(rv("C_Logout",f->C_Logout(s))) goto out;
    } else if(!strcmp(argv[1],"mechanisms")) {
        n=512; if(rv("C_GetMechanismList",f->C_GetMechanismList(slot,mechanisms,&n))) goto out;
        for(i=0;i<n;i++) printf("mechanism=%08lx\n",mechanisms[i]);
    } else if(strcmp(argv[1],"health")) goto out;
    if(strcmp(argv[1],"mechanisms") && (rv("C_GetTokenInfo(after)",f->C_GetTokenInfo(slot,&info)) || memcmp(info.label,label,32) ||
       (info.flags&(CKF_TOKEN_INITIALIZED|CKF_USER_PIN_INITIALIZED))!=(CKF_TOKEN_INITIALIZED|CKF_USER_PIN_INITIALIZED))) goto out;
    status=0;
out:
    if(s!=CK_INVALID_HANDLE && rv("C_CloseSession",f->C_CloseSession(s))) status=1;
    if(initialized && rv("C_Finalize",f->C_Finalize(NULL))) status=1;
    erase(pin,sizeof(pin)); erase(so,sizeof(so)); if(h) dlclose(h); return status;
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
        pytest.skip('explicit pkcs11rs rolling runtime ID required')
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
def test_packaged_rolling_closure_is_sealed_and_identity_is_deterministic(channel):
    spec = load_environment('pkcs11rs', channel)
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    assert artifact_key('runtime', inputs) == artifact_key('runtime', runtime_inputs(spec))
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['default_features'] is False
    assert inputs['features']['cargo_features'] == []
    assert inputs['patches'] == [] and len(inputs['dependencies']) == 4
    expected = {
        'pkcs11rs': '646736043d1ce4949d812ed9e161949e635121c4',
        'software-key-core': '903e7fe3b94b37d96b2d6cd42593dba821f62383',
        'virtual-yubikey': 'dc2941a8ac2e5af51fabad6434e6c1488b130da7',
        'virtual-yubihsm': 'd71705ca4b298c1945fe05bd9aec824ec1e7b4ad',
        'signatures': 'e06d2e28699428fbcc135c388516883bbb71f170',
    }
    assert {s['id']: s['revision'] for s in inputs['sources'] + inputs['dependencies']} == expected
    for source in inputs['sources'] + inputs['dependencies']:
        assert source['archive_sha256'] and source['license_evidence']
        assert source['license_selection'] == 'Apache-2.0'
    manifest = json.loads(package_data('providers/pkcs11rs/crates.json').read_text())
    assert len(manifest['crates']) == 290 and len(manifest['git_packages']) == 1
    upstream = package_data('providers/pkcs11rs/Cargo.lock').read_bytes()
    assert hashlib.sha256(upstream).hexdigest() == manifest['cargo_lock_sha256']
    assert all(p['license_selection'] and p['license_evidence'] for p in manifest['crates'])
    assert spec['distribution']['status'] == 'unreviewed'
    assert spec['application_profile'] == 'general-token'
    release = load_environment('pkcs11rs', 'release')
    assert release['channel_spec']['status'] == 'unavailable' and 'lock' not in release
    from p11lab.catalog import CatalogError
    with pytest.raises(CatalogError, match='planned or unavailable'):
        validate_build_inputs(release)


def test_lifecycle_preserves_state_and_arbitrary_argv(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert json.loads(docker('run', '--rm', image, 'describe').stdout)['module_path'] == MODULE
    assert docker(*base, image, 'init', check=False).returncode != 0
    assert list(state.iterdir()) == []
    docker(*base, *controls, image, 'init')
    for path in (state / 'pkcs11rs').rglob('*'):
        assert path.stat().st_mode & 0o7777 == (0o700 if path.is_dir() else 0o600)
    before = snapshot(state)
    (secrets / 'pin').write_bytes(b'different-user')
    (secrets / 'so').write_bytes(b'different-officer')
    docker(*base, *controls, image, 'init')
    assert snapshot(state) == before
    assert 'native_slot=0 token_present_index=0 label=acceptance' in docker(*base, *controls, image, 'health').stdout
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\\n" "$PKCS11RS_TOKEN_STORAGE" "$P11LAB_MODULE" "$1"; exit 37',
                    'caller', 'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == ['/var/lib/p11lab/pkcs11rs', MODULE, 'literal $argument with spaces']
    assert snapshot(state) == before
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'command -v gcc cc make python3 pkcs11-tool pkcs11rs-init-token; exit 0').stdout == ''
    marker = (state / 'pkcs11rs/complete').read_bytes()
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
    spec = RunSpec('pkcs11rs', channel, 'direct', as_ref(CONSUMERS[channel]), 'provider', None, None,
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
    (secrets / ('pin' if role == 'PIN' else 'so')).write_bytes(b'12345678')
    failed = docker(*base, *controls, CONSUMERS[channel], *probe, check=False)
    assert failed.returncode != 0
    assert f'C_Login({"USER" if role == "PIN" else "SO"}): CK_RV=0x000000a0' in failed.stdout
    assert PIN.decode() not in failed.stdout + failed.stderr and SO.decode() not in failed.stdout + failed.stderr


@pytest.mark.parametrize('damage', ['missing-header', 'empty-header', 'malformed-header', 'bad-generation',
                                  'missing-directory', 'missing-marker', 'marker-extra-lf', 'hidden-file',
                                  'dangling-link', 'header-link', 'busy-init', 'interrupted-writer'])
def test_static_damage_refused_before_application_and_preserved(runtime, damage):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    owned = state / 'pkcs11rs'
    token = owned / TOKEN
    if damage == 'missing-header':
        token.unlink()
    elif damage == 'empty-header':
        token.write_bytes(b'')
    elif damage == 'malformed-header':
        token.write_bytes(b'\x80')
    elif damage == 'bad-generation':
        token.rename(token.with_name('header-invalid.cbor'))
    elif damage == 'missing-directory':
        (owned / 'tokens-v1/software-name-7031316c6162/public-objects-v1/objects').rmdir()
    elif damage == 'missing-marker':
        (owned / 'complete').unlink()
    elif damage == 'marker-extra-lf':
        with (owned / 'complete').open('ab') as marker:
            marker.write(b'\n')
    elif damage == 'hidden-file':
        (owned / '.foreign').write_bytes(b'foreign')
    elif damage == 'dangling-link':
        (token.parent / 'header-00000000000000000003.cbor').symlink_to('absent')
    elif damage == 'header-link':
        token.rename(token.with_name('original'))
        token.symlink_to('original')
    elif damage == 'busy-init':
        (state / '.init-lock').mkdir()
    else:
        (token.parent / '.pkcs11rs-header-interrupted.tmp').write_bytes(b'partial-write')
    before = snapshot(state)
    for operation in ('init', 'health', 'exec'):
        argv = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'echo APP-RAN']
        result = docker(*base, *controls, image, *argv, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert snapshot(state) == before, (damage, operation)
        if damage == 'malformed-header':
            assert 'CK_RV=0x00000020' in result.stderr


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
                                      'too-large': b'x' * 4097, 'native-too-short': b'1234567',
                                      'native-too-long': b'x' * 1025}[bad])
    result = docker(*base, *controls, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []
    assert PIN.decode() not in result.stdout + result.stderr and SO.decode() not in result.stdout + result.stderr


@pytest.mark.parametrize('control', ['P11LAB_LABEL=different', 'PKCS11RS_TOKEN_STORAGE=/tmp/other'])
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
    path = {'root': '/var/lib/p11lab', 'owned': '/var/lib/p11lab/pkcs11rs',
            'token': '/var/lib/p11lab/pkcs11rs/' + TOKEN}[target]
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
    assert (state / 'pkcs11rs' / TOKEN).read_bytes() != (other / 'pkcs11rs' / TOKEN).read_bytes()
    assert channel in CONSUMERS
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
              'P11LAB_SO_PIN_FILE': str(secrets / 'so'), 'P11LAB_LABEL': 'acceptance'}
    spec = RunSpec('pkcs11rs', channel, 'direct', as_ref(CONSUMERS[channel]), 'provider', None, None,
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
    (other / 'pkcs11rs/complete').unlink()
    assert docker(*second, *controls, image, 'init', check=False).returncode != 0
    assert snapshot(state) == before


def test_native_provision_helper_refuses_reset(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'exec 3</run/secrets/pin 4</run/secrets/so; exec p11lab-pkcs11rs init', check=False)
    assert result.returncode != 0 and 'refusing to reset' in result.stderr
    assert snapshot(state) == before


def test_exact_image_identity_mechanism_coverage_and_admission_block(runtime):
    from p11lab.licenses import assess_distribution
    channel, root, state, secrets, image, base, controls = runtime
    spec = load_environment('pkcs11rs', channel)
    assert json.loads(docker('image', 'inspect', image).stdout)[0]['Id'] == image
    metadata = docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat', image,
                      '/usr/share/p11lab/provider.json').stdout
    assert json.loads(metadata) == json.loads(package_data('providers/pkcs11rs/provider.json').read_text())
    runtime_id = docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat', image,
                        '/usr/share/p11lab/runtime-id').stdout
    assert runtime_id == artifact_key('runtime', runtime_inputs(spec)) + '\n'
    assert set(IMAGES) == {'rolling'}
    docker(*base, *controls, image, 'init')
    assert channel in CONSUMERS
    result = docker(*base, *controls, CONSUMERS[channel], 'exec', '--', 'p11lab-native-probe', 'mechanisms')
    observed = {int(line.split('=')[1], 16) for line in result.stdout.splitlines() if line.startswith('mechanism=')}
    # Presence of bounded native mechanisms is separate from crypto coverage.
    required = {0x0, 0xD, 0x1040, 0x1041, 0x1080, 0x1081, 0x1082, 0x1087, 0x250, 0x251}
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
        spec = RunSpec('pkcs11rs', channel, 'direct', as_ref(CHECKERS[channel]), 'provider', None, None, (),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so)}, root / 'output', caller, 1200)
        result = run_checker(spec, 'smoke-v1')
        assert not result.cleanup_errors
        receipt = json.loads((spec.output_dir / 'checker/checker-receipt.json').read_text())
        assert receipt['evidence']['observations_complete'], receipt
        assert len(receipt['nodes']) == 23
        assert receipt['token']['native_slot_id'] == 0 and receipt['token']['token_present_index'] == 0
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
        spec = RunSpec('pkcs11rs', channel, 'proxy', as_ref(PROXIES[channel]), 'container', as_ref(CALLER), client,
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

    for control in ('PKCS11RS_HARDWARE_DISCOVERY=1', 'PKCS11RS_SOFTWARE_SLOTS=another',
                    'PKCS11RS_YUBIHSM_URLS=http://excluded', 'P11LAB_LABEL=',
                    'P11LAB_LABEL=label,another', 'P11LAB_LABEL=' + 'x' * 33):
        result = docker(*base, *controls, '-e', control, image, 'init', check=False)
        assert result.returncode != 0 and list(state.iterdir()) == []
