# SPDX-License-Identifier: Apache-2.0
"""Explicitly pinned pkcs11-to-cmd runtimes: no authentication, native findings.

Set channel/engine-ID maps in P11LAB_PKCS11_TO_CMD_IMAGES, _CONSUMERS,
_CHECKERS, _PROXIES; _CLIENTS holds independently sealed shim bundles and
_CALLER an independent C caller image. No implicit builds or tag discovery.
The direct probe observes explicit mechanisms, separately from the falsified
common signing baseline; it never repairs provider metadata or return values.
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
MODULE = '/usr/local/lib/p11lab/libpkcs11-to-cmd.so'
REVISION = '8fddf3b4cec6bf5d4287f71f5c3c4a7cfc9c7aa3'
SCRIPT_SHA256 = '966f6fba1869f40f9249b5b6ab39bb98a33d9f6d8a97f9faddde8e31a43929eb'
PREFIX = 'P11LAB_PKCS11_TO_CMD_'
IMAGES = json.loads(os.environ.get(PREFIX + 'IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get(PREFIX + 'CONSUMERS', '{}'))
CHECKERS = json.loads(os.environ.get(PREFIX + 'CHECKERS', '{}'))
PROXIES = json.loads(os.environ.get(PREFIX + 'PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get(PREFIX + 'CLIENTS', '{}'))
CALLER = os.environ.get(PREFIX + 'CALLER', '')
EVIDENCE = os.environ.get(PREFIX + 'EVIDENCE')
COMMANDS = itertools.count()

NATIVE_PROBE = r'''/* SPDX-License-Identifier: Apache-2.0
 * Original P11Lab bounded direct observation; never fabricates native success. */
#include <p11-kit/pkcs11.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static CK_RV report(const char *op, CK_RV value) {
    printf("%s: CK_RV=0x%08lx\n", op, value); return value;
}
#define OBS(op, call) do { if (report(op, call) != CKR_OK) goto out; } while (0)
#define UNSUP(op, call) do { if (report(op, call) != CKR_FUNCTION_NOT_SUPPORTED) goto out; } while (0)
static int write_public(const char *dir, const char *name, const void *data, size_t n) {
    char path[4096]; FILE *file; int okay;
    int r=snprintf(path,sizeof(path),"%s/%s",dir,name);
    if(r<0 || (size_t)r>=sizeof(path)) return 0;
    file=fopen(path,"wb"); if(!file) return 0;
    okay=fwrite(data,1,n,file)==n; if(fclose(file)) okay=0; return okay;
}
int main(int argc, char **argv) {
    CK_FUNCTION_LIST_PTR f=NULL; CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR)=NULL;
    CK_SESSION_HANDLE session=CK_INVALID_HANDLE; CK_SLOT_ID slots[10]={0}, slot;
    CK_ULONG n=10, count=0; CK_TOKEN_INFO token; CK_SLOT_INFO empty;
    CK_MECHANISM_INFO info; CK_SESSION_INFO si;
    CK_OBJECT_HANDLE object=CK_INVALID_HANDLE; CK_OBJECT_CLASS kind=CKO_PRIVATE_KEY;
    CK_KEY_TYPE type; CK_ATTRIBUTE attr={CKA_CLASS,&kind,sizeof(kind)};
    CK_MECHANISM mechanism={CKM_ECDSA,NULL,0};
    unsigned char signature[512]={0}; CK_ULONG length=sizeof(signature);
    const unsigned char message[]="P11Lab independent PKCS11 smoke v1\n";
    const unsigned char digest[]={0xe8,0x23,0x4d,0xb4,0xec,0x58,0xc8,0x6b,0xb2,0xf2,0x25,0x42,0x3b,0xc8,0xd8,0xee,0x8a,0xbd,0xc5,0x28,0xae,0xf8,0x8c,0x92,0xdf,0x63,0x2f,0x82,0xa9,0x15,0x73,0xf3};
    const char *module=getenv("P11LAB_MODULE"); void *h=NULL,*symbol; int initialized=0,status=1;
    if(argc<2 || !module) return 2;
    h=dlopen(module,RTLD_NOW|RTLD_LOCAL); if(!h) {fputs("cannot load module\n",stderr);goto out;}
    symbol=dlsym(h,"C_GetFunctionList"); _Static_assert(sizeof(symbol)==sizeof(get),"ABI"); memcpy(&get,&symbol,sizeof(get));
    if(!get) goto out;
    OBS("C_GetFunctionList",get(&f)); if(!f) goto out;
    printf("interface=%u.%u\n",f->version.major,f->version.minor);
    OBS("C_Initialize",f->C_Initialize(NULL)); initialized=1;
    OBS("C_GetSlotList(all)",f->C_GetSlotList(CK_FALSE,slots,&n));
    printf("slots_all=%lu ids=%lu,%lu,%lu\n",n,slots[0],slots[1],slots[2]); if(n!=3) goto out;
    n=10; OBS("C_GetSlotList(present)",f->C_GetSlotList(CK_TRUE,slots,&n));
    printf("slots_present=%lu ids=%lu,%lu,%lu\n",n,slots[0],slots[1],slots[2]); if(n!=3) goto out;
    OBS("C_GetSlotInfo(empty)",f->C_GetSlotInfo(slots[1],&empty));
    printf("empty_slot_flags=0x%lx\n",empty.flags);
    int rsa_mode=(argc>=3 && !strcmp(argv[2],"rsa"));
    slot=slots[rsa_mode?0:2];
    OBS("C_GetTokenInfo",f->C_GetTokenInfo(slot,&token));
    printf("native_slot=%lu pin_min=%lu pin_max=%lu flags=0x%lx label_hex=",slot,token.ulMinPinLen,token.ulMaxPinLen,token.flags);
    for(size_t i=0;i<sizeof(token.label);i++) { printf("%02x",token.label[i]); }
    puts("");
    if(token.flags!=CKF_TOKEN_INITIALIZED || token.ulMinPinLen || token.ulMaxPinLen) goto out;
    OBS("C_OpenSession",f->C_OpenSession(slot,CKF_SERIAL_SESSION,NULL,NULL,&session));
    OBS("C_GetSessionInfo",f->C_GetSessionInfo(session,&si));
    printf("session_state=%lu\n",si.state);
    if(!strcmp(argv[1],"auth")) {
        OBS("C_Login(USER absent)",f->C_Login(session,CKU_USER,NULL,0));
        OBS("C_Logout",f->C_Logout(session));
        OBS("C_Login(USER arbitrary)",f->C_Login(session,CKU_USER,(CK_UTF8CHAR_PTR)"arbitrary",9));
        OBS("C_Login(SO arbitrary)",f->C_Login(session,CKU_SO,(CK_UTF8CHAR_PTR)"different",9));
        OBS("C_Login(invalid role and session)",f->C_Login(CK_INVALID_HANDLE,999,NULL,0));
        UNSUP("C_InitToken",f->C_InitToken(slot,NULL,0,NULL));
        UNSUP("C_InitPIN",f->C_InitPIN(session,NULL,0));
        UNSUP("C_SetPIN",f->C_SetPIN(session,NULL,0,NULL,0));
    } else if(!strcmp(argv[1],"unsupported") || !strcmp(argv[1],"discovery")) {
        UNSUP("C_GetMechanismList",f->C_GetMechanismList(slot,NULL,&count));
        UNSUP("C_GetMechanismInfo",f->C_GetMechanismInfo(slot,CKM_ECDSA,&info));
        if(!strcmp(argv[1],"discovery")) {status=0;goto out;}
        UNSUP("C_CreateObject",f->C_CreateObject(session,NULL,0,&object));
        UNSUP("C_DestroyObject",f->C_DestroyObject(session,0));
        UNSUP("C_EncryptInit",f->C_EncryptInit(session,&mechanism,0));
        UNSUP("C_DecryptInit",f->C_DecryptInit(session,&mechanism,0));
        UNSUP("C_DigestInit",f->C_DigestInit(session,&mechanism));
        UNSUP("C_VerifyInit",f->C_VerifyInit(session,&mechanism,0));
        UNSUP("C_GenerateKey",f->C_GenerateKey(session,&mechanism,NULL,0,&object));
        UNSUP("C_GenerateKeyPair",f->C_GenerateKeyPair(session,&mechanism,NULL,0,NULL,0,&object,&object));
        UNSUP("C_WrapKey",f->C_WrapKey(session,&mechanism,0,0,NULL,&count));
        UNSUP("C_UnwrapKey",f->C_UnwrapKey(session,&mechanism,0,NULL,0,NULL,0,&object));
        UNSUP("C_DeriveKey",f->C_DeriveKey(session,&mechanism,0,NULL,0,&object));
        UNSUP("C_GenerateRandom",f->C_GenerateRandom(session,signature,1));
    } else if(!strcmp(argv[1],"sign") || !strcmp(argv[1],"command-failure")) {
        if(argc!=4) goto out;
        OBS("C_FindObjectsInit",f->C_FindObjectsInit(session,&attr,1));
        OBS("C_FindObjects",f->C_FindObjects(session,&object,1,&count));
        OBS("C_FindObjectsFinal",f->C_FindObjectsFinal(session)); if(count!=1) goto out;
        attr=(CK_ATTRIBUTE){CKA_KEY_TYPE,&type,sizeof(type)};
        OBS("C_GetAttributeValue(key type)",f->C_GetAttributeValue(session,object,&attr,1));
        if(type!=(rsa_mode?CKK_RSA:CKK_EC)) goto out;
        mechanism.mechanism=rsa_mode?CKM_RSA_PKCS:CKM_ECDSA;
        OBS("C_SignInit(no login)",f->C_SignInit(session,&mechanism,object));
        CK_RV rv=report("C_Sign(no login)",f->C_Sign(session,(CK_BYTE_PTR)digest,sizeof(digest),signature,&length));
        if(!strcmp(argv[1],"command-failure")) {if(rv!=CKR_FUNCTION_FAILED) goto out;}
        else {
            if(rv!=CKR_OK || length!=(rsa_mode?256:64)) goto out;
            if(!write_public(argv[3],"signature.bin",signature,length) || !write_public(argv[3],"message.bin",message,sizeof(message)-1) || !write_public(argv[3],"digest.bin",digest,sizeof(digest))) goto out;
        }
    } else goto out;
    status=0;
out:
    if(session!=CK_INVALID_HANDLE && f && report("C_CloseSession",f->C_CloseSession(session))) status=1;
    if(initialized && report("C_Finalize",f->C_Finalize(NULL))) status=1;
    if(h) dlclose(h);
    return status;
}
'''

def docker(*args, check=True):
    argv = ['docker', *map(str, args)]
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


def as_ref(image):
    return ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')


def oracle(output, cert, algorithm):
    """Host OpenSSL independently checks provider output and altered input.

    RSA intentionally checks upstream raw-digest pkeyutl semantics; it is not
    a claim of standard DigestInfo/dgst compatibility. EC verifies the message.
    """
    public = output / 'public-key.pem'
    public.write_bytes(subprocess.check_output(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout']))
    signature = output / 'signature.bin'
    if algorithm == 'ec':
        raw = signature.read_bytes()
        assert len(raw) == 64

        def integer(value):
            value = value.lstrip(b'\0') or b'\0'
            if value[0] & 0x80:
                value = b'\0' + value
            return b'\x02' + bytes([len(value)]) + value

        rs = integer(raw[:32]) + integer(raw[32:])
        signature = output / 'signature.der'
        signature.write_bytes(b'\x30' + bytes([len(rs)]) + rs)
        original = output / 'message.bin'
        prefix = ['openssl', 'dgst', '-sha256', '-verify', str(public), '-signature', str(signature)]
    else:
        assert len(signature.read_bytes()) == 256
        original = output / 'digest.bin'
        prefix = ['openssl', 'pkeyutl', '-verify', '-pubin', '-inkey', str(public),
                  '-sigfile', str(signature), '-in']
    positive = subprocess.run([*prefix, str(original)], capture_output=True, text=True)
    assert positive.returncode == 0, positive.stderr
    altered = output / 'altered.bin'
    altered.write_bytes(original.read_bytes() + b'altered')
    negative = subprocess.run([*prefix, str(altered)], capture_output=True, text=True)
    assert negative.returncode != 0
    (output / 'oracle.json').write_text(json.dumps({
        'positive': {'argv': [*prefix, str(original)], 'returncode': positive.returncode,
                     'stdout': positive.stdout, 'stderr': positive.stderr},
        'negative': {'argv': [*prefix, str(altered)], 'returncode': negative.returncode,
                     'stdout': negative.stdout, 'stderr': negative.stderr},
    }, indent=2) + '\n')


@pytest.fixture(params=CHANNELS)
def runtime(request, tmp_path):
    channel = request.param
    if channel not in IMAGES:
        pytest.skip('explicit channel/runtime engine ID required')
    root = Path(EVIDENCE) / request.node.name if EVIDENCE else tmp_path / channel
    root.mkdir(parents=True, exist_ok=False)
    state = root / 'state'
    state.mkdir(mode=0o700)
    state.chmod(0o700)
    base = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', '/tmp',
            '--tmpfs', f'/run/p11lab:uid={os.getuid()},gid={os.getgid()},mode=0700',
            '--mount', f'type=bind,src={state},dst=/var/lib/p11lab']
    yield channel, root, state, IMAGES[channel], base
    # Generated private material is never retained as durable review evidence.
    # All paths below belong to this one test's explicitly created directory.
    for path in root.rglob('*.key'):
        path.unlink()


@pytest.mark.parametrize('channel', CHANNELS)
def test_frozen_channel_recipe_and_deterministic_identity(channel):
    spec = load_environment('pkcs11-to-cmd', channel)
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    assert inputs['sources'][0]['revision'] == REVISION
    selector = inputs['sources'][0]['selector']
    assert selector == {'kind': 'tag' if channel == 'release' else 'branch',
                        'value': 'v1.0.0' if channel == 'release' else 'main'}
    assert inputs['sources'][0]['archive_sha256'] == 'f5e6e394c066ac81a323d0d2e506d35ec1200acd0ebd121d02eca12494ec03cd'
    assert inputs['sources'][0]['license_selection'] == 'MIT'
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['coverage'] is False
    assert inputs['features']['auth'] == 'none'
    assert inputs['features']['signing_command']['sha256'] == SCRIPT_SHA256
    assert inputs['patches'] == inputs['dependencies'] == []
    assert spec['inputs'] == {} and spec['application_profile'] == 'pkcs11-to-cmd-signing'
    assert artifact_key('runtime', inputs) == artifact_key('runtime', runtime_inputs(spec))
    other = load_environment('pkcs11-to-cmd', 'rolling' if channel == 'release' else 'release')
    assert artifact_key('runtime', inputs) != artifact_key('runtime', runtime_inputs(other))
    assert {r['name'] for r in spec['runtime_env']} == {'P2C_SLOT_CERT_0', 'P2C_SLOT_CERT_2', 'P2C_CMD', 'P2C_DEBUG'}
    assert len(spec['lock']['packages']) == 161
    assert sum(p['phase'] == 'runtime' for p in spec['lock']['packages']) == 78


def test_lifecycle_runtime_keys_readiness_and_exact_argv(runtime):
    channel, root, state, image, base = runtime
    assert json.loads(docker('run', '--rm', image, 'describe').stdout)['inputs'] == {}
    assert docker(*base, image, 'health', check=False).returncode != 0
    assert list(state.iterdir()) == []
    docker(*base, image, 'init')
    owned = state / 'pkcs11-to-cmd'
    assert {p.name for p in owned.iterdir()} == {'complete', 'wiring.env', 'rsa.key', 'rsa.pem', 'ec.key', 'ec.pem'}
    assert owned.stat().st_mode & 0o7777 == 0o700
    assert all(p.stat().st_mode & 0o7777 == 0o600 for p in owned.iterdir())
    before = snapshot(state)
    docker(*base, image, 'init')
    health = docker(*base, image, 'health').stdout
    assert 'native_slot=0 label=pkcs11-to-cmd-0 pin_min=0 pin_max=0 login_required=false' in health
    assert 'native_slot=2 label=pkcs11-to-cmd-2 pin_min=0 pin_max=0 login_required=false' in health
    outputs = []
    controls = [x for entry in load_environment('pkcs11-to-cmd', channel)['runtime_env']
                for x in ('-e', entry['name'] + '=' + entry['value'])]
    for options in ([], controls):
        result = docker(*base, *options, '--workdir', '/tmp', image, 'exec', '--', 'sh', '-c',
                        'printf "WIRE %s|%s|%s|%s|%s|%s\\n" "$P2C_CMD" "$P2C_SLOT_CERT_0" "$P2C_SLOT_CERT_2" "$P2C_DATA" "$P2C_SIG" "$PWD"; printf "ARG %s\\n" "$1"; exit 37',
                        'caller', 'literal $argument with spaces', check=False)
        assert result.returncode == 37 and 'ARG literal $argument with spaces' in result.stdout
        line = next(line for line in result.stdout.splitlines() if line.startswith('WIRE '))
        command, rsa, ec, data, sig, cwd = line[5:].split('|')
        assert command == '/usr/local/bin/p11lab-p2c-sign'
        assert rsa == '/var/lib/p11lab/pkcs11-to-cmd/rsa.pem'
        assert ec == '/var/lib/p11lab/pkcs11-to-cmd/ec.pem'
        assert data.startswith('/run/p11lab/p2c.') and data.endswith('/data.bin')
        assert sig == data.removesuffix('/data.bin') + '/signature.bin'
        assert cwd == '/tmp'
        outputs.append(data)
    assert outputs[0] != outputs[1] and snapshot(state) == before
    # Explicit caller reset is separate from init; old public identity changes.
    cert = (owned / 'ec.pem').read_bytes()
    for p in owned.iterdir():
        p.unlink()
    owned.rmdir()
    docker(*base, image, 'init')
    assert (owned / 'ec.pem').read_bytes() != cert


def test_native_absence_of_authentication_and_unsupported_surface(runtime):
    channel, root, state, image, base = runtime
    assert channel in CONSUMERS
    docker(*base, image, 'init')
    auth = docker(*base, CONSUMERS[channel], 'exec', '--', 'p11lab-native-probe', 'auth').stdout
    for op in ('C_Login(USER absent)', 'C_Login(USER arbitrary)', 'C_Login(SO arbitrary)', 'C_Login(invalid role and session)'):
        assert op + ': CK_RV=0x00000000' in auth
    for op in ('C_InitToken', 'C_InitPIN', 'C_SetPIN'):
        assert op + ': CK_RV=0x00000054' in auth
    assert 'slots_present=3 ids=0,1,2' in auth and 'empty_slot_flags=0x0' in auth
    observed = docker(*base, CONSUMERS[channel], 'exec', '--', 'p11lab-native-probe', 'unsupported').stdout
    for op in ('C_GetMechanismList', 'C_GetMechanismInfo', 'C_CreateObject', 'C_DestroyObject',
               'C_EncryptInit', 'C_DecryptInit', 'C_DigestInit', 'C_VerifyInit', 'C_GenerateKey',
               'C_GenerateKeyPair', 'C_WrapKey', 'C_UnwrapKey', 'C_DeriveKey', 'C_GenerateRandom'):
        assert op + ': CK_RV=0x00000054' in observed


@pytest.mark.parametrize('algorithm', ['rsa', 'ec'])
def test_native_signing_persistent_reopen_and_independent_oracle(runtime, algorithm):
    channel, root, state, image, base = runtime
    assert channel in CONSUMERS
    caller = root / 'caller'
    caller.mkdir()
    spec = RunSpec('pkcs11-to-cmd', channel, 'direct', as_ref(CONSUMERS[channel]), 'provider', None, None,
                   ('p11lab-native-probe', 'sign', algorithm, '/p11lab-output'),
                   {'P11LAB_STATE_DIR': str(state)}, root / 'first', caller, 300)
    public = []
    for name in ('first', 'restart'):
        result = run_application(replace(spec, output_dir=root / name))
        assert result.exit_code == 0 and not result.cleanup_errors, result
        assert 'C_Sign(no login): CK_RV=0x00000000' in (root / name / 'application.stdout.log').read_text()
        oracle(root / name, state / 'pkcs11-to-cmd' / (algorithm + '.pem'), algorithm)
        public.append((root / name / 'public-key.pem').read_bytes())
    assert public[0] == public[1]
    # A caller with file access can choose another shell command. Preserve its
    # native failure; the managed entrypoint does not impose authentication.
    failure = docker(*base, CONSUMERS[channel], 'exec', '--', 'env', 'P2C_CMD=/bin/false',
                     'p11lab-native-probe', 'command-failure', algorithm, '/tmp').stdout
    assert 'C_Sign(no login): CK_RV=0x00000006' in failure


def test_common_signing_baseline_is_falsified_without_normalization(runtime):
    channel, root, state, image, base = runtime
    docker(*base, image, 'init')
    before = snapshot(state)
    result = docker(*base, CONSUMERS[channel], 'exec', '--', 'p11lab-smoke', '--module', MODULE,
                    '--token-label', 'pkcs11-to-cmd-2', '--output', '/tmp/common-baseline',
                    '--key-mode', 'existing', '--key-id', '02', check=False)
    assert result.returncode != 0 and 'no token matches the exact padded label' in result.stderr
    raw = docker(*base, CONSUMERS[channel], 'exec', '--', 'p11lab-native-probe', 'unsupported').stdout
    assert 'C_GetMechanismList: CK_RV=0x00000054' in raw
    assert snapshot(state) == before


def test_independent_state_has_independent_keys_and_signing_authority(runtime):
    channel, root, state, image, base = runtime
    docker(*base, image, 'init')
    other = root / 'other-state'
    other.mkdir(mode=0o700)
    other.chmod(0o700)
    second = [a.replace(str(state), str(other)) for a in base]
    docker(*second, image, 'init')
    for algorithm in ('rsa', 'ec'):
        assert (state / 'pkcs11-to-cmd' / (algorithm + '.pem')).read_bytes() != (other / 'pkcs11-to-cmd' / (algorithm + '.pem')).read_bytes()
    output = root / 'isolated-output'
    output.mkdir()
    docker(*base, '--mount', f'type=bind,src={output},dst=/output', CONSUMERS[channel],
           'exec', '--', 'p11lab-native-probe', 'sign', 'ec', '/output')
    oracle(output, state / 'pkcs11-to-cmd/ec.pem', 'ec')
    wrong = root / 'wrong-public.pem'
    wrong.write_bytes(subprocess.check_output(['openssl', 'x509', '-in', str(other / 'pkcs11-to-cmd/ec.pem'), '-pubkey', '-noout']))
    mismatch = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(wrong),
                               '-signature', str(output / 'signature.der'), str(output / 'message.bin')], capture_output=True)
    assert mismatch.returncode != 0


def test_dispatch_and_no_pin_inputs_do_not_create_state_or_start_application(runtime):
    channel, root, state, image, base = runtime
    for argv in (('server',), ('server-ready',), ('init', 'extra'), ('health', 'extra'),
                 ('describe', 'extra'), ('exec',), ('exec', '--'), ('exec', 'sh', '-c', 'echo APP-RAN')):
        result = docker(*base, image, *argv, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert list(state.iterdir()) == []
    for name in ('P11LAB_PIN', 'P11LAB_PIN_FILE', 'P11LAB_SO_PIN', 'P11LAB_SO_PIN_FILE', 'P11LAB_LABEL'):
        result = docker(*base, '-e', name + '=', image, 'init', check=False)
        assert result.returncode != 0 and list(state.iterdir()) == []


@pytest.mark.parametrize('group', ['certificates', 'command', 'io'])
def test_native_wiring_conflicts_are_refused_before_any_state_open(runtime, group):
    channel, root, state, image, base = runtime
    if group == 'certificates':
        controls = [f'P2C_SLOT_CERT_{i}=/tmp/other.pem' for i in range(10)]
    elif group == 'command':
        controls = ['P2C_CMD=/bin/false', 'P2C_CMD=', 'P2C_DEBUG=1']
    else:
        controls = ['P2C_DATA=/tmp/shared', 'P2C_SIG=/tmp/shared', 'P2C_CERT=/tmp/other', 'P2C_MECHANISM=CKM_RSA_PKCS']
    for control in controls:
        assert docker(*base, '-e', control, image, 'init', check=False).returncode != 0
        assert list(state.iterdir()) == []
    docker(*base, image, 'init')
    before = snapshot(state)
    for control in controls:
        result = docker(*base, '-e', control, image, 'exec', '--', 'sh', '-c', 'echo APP-RAN', check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert snapshot(state) == before


@pytest.mark.parametrize('damage', ['key', 'certificate', 'seal', 'links', 'ownership', 'roster'])
def test_damaged_or_foreign_state_is_retained_before_application(runtime, damage):
    channel, root, state, image, base = runtime
    docker(*base, image, 'init')
    owned = state / 'pkcs11-to-cmd'
    cert = owned / 'rsa.pem'
    if damage == 'key':
        key = owned / 'rsa.key'
        key.write_bytes(b'invalid private key')
    elif damage == 'certificate':
        cert.write_bytes((owned / 'ec.pem').read_bytes())
    elif damage == 'seal':
        (owned / 'complete').write_bytes((owned / 'complete').read_bytes() + b'\n')
    elif damage == 'links':
        cert.unlink()
        cert.symlink_to('ec.pem')
    elif damage == 'ownership':
        original = cert.read_bytes()
        root_base = ['run', '--rm', '--network', 'none', '--user', '0:0',
                     '--mount', f'type=bind,src={state},dst=/state', '--entrypoint', 'chown']
        docker(*root_base, image, f'{os.getuid()+1}:{os.getgid()+1}', '/state/pkcs11-to-cmd/rsa.pem')
        try:
            result = docker(*base, image, 'exec', '--', 'sh', '-c', 'echo APP-RAN', check=False)
            assert result.returncode != 0 and 'APP-RAN' not in result.stdout
            assert 'p11lab:' in result.stderr and 'CK_RV=' not in result.stderr
        finally:
            docker(*root_base, image, f'{os.getuid()}:{os.getgid()}', '/state/pkcs11-to-cmd/rsa.pem')
        assert cert.read_bytes() == original
        return
    else:
        (owned / '.unexpected').write_bytes(b'preserve this partial state')
    before = snapshot(state)
    for op in (('health',), ('init',), ('exec', '--', 'sh', '-c', 'echo APP-RAN')):
        result = docker(*base, image, *op, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert snapshot(state) == before


def test_exact_artifact_readbacks_and_distribution_remains_blocked(runtime):
    from p11lab.licenses import assess_distribution
    channel, root, state, image, base = runtime
    assert json.loads(docker('image', 'inspect', image).stdout)[0]['Id'] == image
    metadata = docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat', image,
                      '/usr/share/p11lab/provider.json').stdout
    assert json.loads(metadata) == json.loads(package_data('providers/pkcs11-to-cmd/provider.json').read_text())
    installed = docker('run', '--rm', '--network', 'none', '--entrypoint', 'sha256sum', image,
                       '/usr/local/libexec/p11lab/pkcs11-to-cmd-sign').stdout
    assert installed.split()[0] == SCRIPT_SHA256
    runtime_id = docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat', image,
                        '/usr/share/p11lab/runtime-id').stdout
    assert runtime_id == artifact_key('runtime', runtime_inputs(load_environment('pkcs11-to-cmd', channel))) + '\n'
    # The image root is immutable and has no provisioned private keys/fixtures.
    assert docker('run', '--rm', '--entrypoint', 'find', image, '/var/lib/p11lab', '-mindepth', '1').stdout == ''
    assert docker('run', '--rm', '--entrypoint', 'sh', image, '-c',
                  'for tool in python3 cc cmake pkcs11-check pkcs11-tool; do if command -v "$tool"; then exit 1; fi; done').returncode == 0
    decision = assess_distribution(as_ref(image), root / 'admission')
    assert decision['status'] == decision['publication_status'] == 'blocked'
    assert decision['blockers']


def test_installed_checker_boundary_and_shared_no_auth_launcher_gap(runtime):
    channel, root, state, image, base = runtime
    if channel not in CHECKERS:
        pytest.skip('explicit installed checker derivative required')
    from p11lab.checker import run_checker
    caller = root / 'caller'
    caller.mkdir()
    spec = RunSpec('pkcs11-to-cmd', channel, 'direct', as_ref(CHECKERS[channel]), 'provider', None, None,
                   (), {}, root / 'shared-launcher', caller, 300)
    blocked = run_checker(spec, 'smoke-v1')
    assert blocked.exit_code != 0 and not blocked.cleanup_errors
    assert 'token identity must select exactly one token-present slot' in (spec.output_dir / 'application.stderr.log').read_text()
    assert not json.loads(blocked.receipt_path.read_text())['checker']['observations_complete']
    # Independently exercise the existing explicit-index installed checker API.
    # This does not fix/qualify run_checker; its blocker and no-auth assumptions
    # stay visible above. Empty fixture credentials are NOT provider PIN inputs.
    code = ('from pathlib import Path; from p11lab.checker import installed_identity,load_profile,execute_checker; '
            'i=installed_identity(); r=execute_checker(installed_root=Path(i["installed_root"]), '
            f'module=Path("{MODULE}"), slot=0, nodes=load_profile()["nodes"], '
            'output_dir=Path("/p11lab-output/checker"), pin="", so_pin="", identity=i); '
            'print(r["evidence"]); raise SystemExit(r["returncode"])')
    explicit = replace(spec, argv=('/opt/p11lab-checker/bin/python', '-c', code), output_dir=root / 'explicit-checker')
    result = run_application(explicit)
    assert not result.cleanup_errors
    receipt = json.loads((explicit.output_dir / 'checker/checker-receipt.json').read_text())
    assert result.exit_code == receipt['returncode'] == 2
    assert len(receipt['nodes']) == 23
    assert receipt['evidence']['complete'] is False
    assert receipt['evidence']['observations_complete'] is False
    assert receipt['evidence']['provider_statuses'] == []
    assert 'missing or malformed durable evidence' in receipt['evidence']['errors']
    stderr = (explicit.output_dir / 'checker/checker.stderr.log').read_text()
    assert 'C_GetMechanismList (count) failed:' in stderr and '0x00000054' in stderr
    print(f'checker explicit-index/{channel}: exit={result.exit_code} evidence={receipt["evidence"]}')


def test_preferred_proxy_native_ec_signature_and_unsupported_rv(runtime):
    channel, root, state, image, base = runtime
    if channel not in PROXIES or channel not in CLIENTS or not CALLER:
        pytest.skip('explicit pinned daemon/client/caller artifacts required')
    caller = root / 'caller'
    caller.mkdir()
    bundle = Path(CLIENTS[channel])
    client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
    spec = RunSpec('pkcs11-to-cmd', channel, 'proxy', as_ref(PROXIES[channel]), 'container', as_ref(CALLER), client,
                   ('env', 'P11LAB_MODULE=/run/p11lab-client/libpkcs11_proxy_ng_shim.so',
                    'p11lab-native-probe', 'sign', 'ec', '/p11lab-output'),
                   {'P11LAB_STATE_DIR': str(state)}, root / 'proxy-crypto', caller, 600)
    result = run_application(spec)
    assert result.exit_code == 0 and not result.cleanup_errors, result
    assert (spec.output_dir / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
    oracle(spec.output_dir, state / 'pkcs11-to-cmd/ec.pem', 'ec')
    unsupported = replace(spec, argv=('env', 'P11LAB_MODULE=/run/p11lab-client/libpkcs11_proxy_ng_shim.so',
                                      'p11lab-native-probe', 'discovery'), output_dir=root / 'proxy-unsupported')
    result = run_application(unsupported)
    assert result.exit_code == 0 and not result.cleanup_errors, result
    assert 'C_GetMechanismList: CK_RV=0x00000054' in (unsupported.output_dir / 'application.stdout.log').read_text()
