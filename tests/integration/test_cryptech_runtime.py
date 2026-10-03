"""Cryptech local simulator checks; provider failures remain qualification blocks.

Set exact P11LAB_CRYPTECH_IMAGES and P11LAB_CRYPTECH_CONSUMERS engine IDs.
Builds happen separately. Forty passing checks do not certify RNG, key crypto,
hardware storage or redistribution. NATIVE_APP belongs only to a test derivative.
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
from p11lab.catalog import CatalogError, load_environment, validate_build_inputs
from p11lab.identity import artifact_key
from p11lab.models import ArtifactRef, RunSpec
from p11lab.run import run_application

MODULE = '/usr/local/lib/p11lab/libcryptech-pkcs11.so'
IMAGES = json.loads(os.environ.get('P11LAB_CRYPTECH_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_CRYPTECH_CONSUMERS', '{}'))
COMMANDS = itertools.count()

NATIVE_APP = r'''/* SPDX-License-Identifier: Apache-2.0 */
#include "vendor/pkcs11.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    const char *module=getenv("P11LAB_MODULE");
    if (!module || argc<2) return 2;
    void *library=dlopen(module,RTLD_NOW|RTLD_LOCAL);
    if (!library) return 2;
    CK_RV (*get_list)(CK_FUNCTION_LIST_PTR_PTR)=NULL;
    void *symbol=dlsym(library,"C_GetFunctionList");
    memcpy(&get_list,&symbol,sizeof(get_list));
    CK_FUNCTION_LIST_PTR f=NULL;
    if (!get_list || get_list(&f)!=CKR_OK || !f) return 2;
    CK_RV rv=f->C_Initialize(NULL);
    if (rv) { fprintf(stderr,"C_Initialize: CK_RV=0x%08lx\n",rv); return 1; }
    CK_SESSION_HANDLE session=CK_INVALID_HANDLE;
    rv=f->C_OpenSession(0,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&session);
    if (rv) { fprintf(stderr,"C_OpenSession: CK_RV=0x%08lx\n",rv); return 1; }
    CK_BYTE right[]="fnord",wrong[]="wrong-probe-value";
    int status=0;
    if (!strcmp(argv[1],"facts")) {
        CK_BYTE label[32];memset(label,' ',sizeof(label));
        CK_RV token=f->C_InitToken(0,right,5,label);
        CK_RV init=f->C_InitPIN(session,right,5);
        CK_RV set=f->C_SetPIN(session,right,5,wrong,sizeof(wrong)-1);
        CK_TOKEN_INFO info;memset(&info,0,sizeof(info));
        CK_RV metadata=f->C_GetTokenInfo(0,&info);
        CK_ULONG mechanisms=0;
        CK_RV listing=f->C_GetMechanismList(0,NULL,&mechanisms);
        printf("{\"init_token\":%lu,\"init_pin\":%lu,\"set_pin\":%lu,\"metadata\":%lu,\"flags\":%lu,\"mechanism_list\":%lu,\"mechanisms\":%lu}\n",
               token,init,set,metadata,info.flags,listing,mechanisms);
    } else if (!strcmp(argv[1],"login") && argc==4) {
        CK_USER_TYPE role=!strcmp(argv[2],"so")?CKU_SO:CKU_USER;
        CK_BYTE_PTR value=!strcmp(argv[3],"right")?right:wrong;
        CK_ULONG length=value==right?5:sizeof(wrong)-1;
        rv=f->C_Login(session,role,value,length);
        printf("{\"login\":%lu}\n",rv);
        if (!rv) rv=f->C_Logout(session);
        status=rv?1:0;
    } else if (!strcmp(argv[1],"digest")) {
        CK_BYTE message[]="P11Lab Cryptech SHA256 oracle",digest[32];
        CK_ULONG length=sizeof(digest);CK_MECHANISM sha={CKM_SHA256,NULL,0};
        rv=f->C_DigestInit(session,&sha);
        if (!rv) rv=f->C_Digest(session,message,sizeof(message)-1,digest,&length);
        if (rv || length!=32) { fprintf(stderr,"C_Digest: CK_RV=0x%08lx\n",rv); status=1; }
        else { for (size_t i=0;i<sizeof(digest);i++) printf("%02x",digest[i]);puts(""); }
    } else if (!strcmp(argv[1],"random")) {
        CK_BYTE value[32];rv=f->C_GenerateRandom(session,value,sizeof(value));
        printf("{\"generate_random\":%lu}\n",rv);status=rv?1:0;
    } else if (!strcmp(argv[1],"keypair")) {
        CK_BBOOL yes=CK_TRUE;CK_KEY_TYPE type=CKK_EC;
        CK_BYTE oid[]={0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};
        CK_BYTE id[]={0x42};CK_OBJECT_HANDLE pub=CK_INVALID_HANDLE,priv=CK_INVALID_HANDLE;
        CK_MECHANISM mechanism={CKM_EC_KEY_PAIR_GEN,NULL,0};
        CK_ATTRIBUTE pa[]={{CKA_KEY_TYPE,&type,sizeof(type)},{CKA_EC_PARAMS,oid,sizeof(oid)},
            {CKA_VERIFY,&yes,sizeof(yes)},{CKA_TOKEN,&yes,sizeof(yes)},{CKA_ID,id,sizeof(id)}};
        CK_ATTRIBUTE pr[]={{CKA_KEY_TYPE,&type,sizeof(type)},{CKA_SIGN,&yes,sizeof(yes)},
            {CKA_PRIVATE,&yes,sizeof(yes)},{CKA_TOKEN,&yes,sizeof(yes)},{CKA_ID,id,sizeof(id)}};
        rv=f->C_Login(session,CKU_USER,right,5);
        if (!rv) rv=f->C_GenerateKeyPair(session,&mechanism,pa,5,pr,5,&pub,&priv);
        printf("{\"generate_keypair\":%lu}\n",rv);status=rv?1:0;
        if (pub!=CK_INVALID_HANDLE && f->C_DestroyObject(session,pub)) status=1;
        if (priv!=CK_INVALID_HANDLE && f->C_DestroyObject(session,priv)) status=1;
    } else status=2;
    rv=f->C_CloseSession(session);
    if (rv) {fprintf(stderr,"C_CloseSession: CK_RV=0x%08lx\n",rv);status=1;}
    rv=f->C_Finalize(NULL);
    if (rv) {fprintf(stderr,"C_Finalize: CK_RV=0x%08lx\n",rv);status=1;}
    dlclose(library);return status;
}
'''


def docker(*args, check=True):
    argv = ['docker', *args]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    evidence = os.environ.get('P11LAB_CRYPTECH_EVIDENCE')
    if evidence:
        root = Path(evidence) / 'commands'
        root.mkdir(parents=True, exist_ok=True)
        (root / f'{next(COMMANDS):04d}.json').write_text(json.dumps({
            'argv': argv, 'returncode': result.returncode, 'stdout': result.stdout,
            'stderr': result.stderr}, indent=2) + '\n')
    if check:
        assert result.returncode == 0, result.stderr
    return result


@pytest.fixture(params=['rolling'])
def runtime(request, tmp_path):
    channel = request.param
    if channel not in IMAGES or channel not in CONSUMERS:
        pytest.skip('exact Cryptech runtime and probe consumer images required')
    evidence = os.environ.get('P11LAB_CRYPTECH_EVIDENCE')
    root = Path(evidence) / 'cases' / request.node.name if evidence else tmp_path
    root.mkdir(parents=True, exist_ok=True)
    state, secrets = root / 'state', root / 'secrets'
    state.mkdir(mode=0o700)
    secrets.mkdir(mode=0o700)
    for name in ('pin', 'so'):
        (secrets / name).write_bytes(b'fnord')
        (secrets / name).chmod(0o600)
    base = ['run', '--rm', '--network', 'none', '--read-only', '--user', f'{os.getuid()}:{os.getgid()}',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--tmpfs', f'/run/p11lab:rw,nosuid,nodev,uid={os.getuid()},gid={os.getgid()},mode=0700',
            '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly']
    controls = ['-e', 'P11LAB_PIN_FILE=/run/secrets/pin', '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/so']
    yield channel, root, state, secrets, IMAGES[channel], base, controls
    for path in secrets.iterdir():
        path.unlink()
    secrets.rmdir()


def test_packaged_runtime_inputs_are_closed_and_grants_blocked():
    spec = load_environment('cryptech', 'rolling')
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    assert artifact_key('runtime', inputs)
    assert len(inputs['sources']) == 1 and len(inputs['dependencies']) == 3
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['loopback_port_dependency'] is False
    assert inputs['features']['wrapper_patch_shipped'] is False
    assert [p['target_source'] for p in inputs['patches']] == ['libhal'] * 4
    assert [Path(p['path']).name[:4] for p in inputs['patches']] == ['0001', '0002', '0003', '0004']
    assert all(p['license_status'] == 'missing' for p in inputs['patches'])
    assert len(spec['lock']['migrated_file_provenance']) == 5
    assert all(p['license_status'] == 'missing' for p in spec['lock']['migrated_file_provenance'])
    assert spec['distribution']['status'] == 'blocked'
    assert spec['application_profile'] == 'cryptech-fixed-credential-simulator'
    assert all(spec['inputs'][name] == {'secret': True, 'required': False}
               for name in ('P11LAB_PIN', 'P11LAB_SO_PIN', 'P11LAB_PIN_FILE', 'P11LAB_SO_PIN_FILE'))


def test_release_channel_stays_unavailable_and_cannot_build(tmp_path):
    from p11lab.build import build_artifact
    spec = load_environment('cryptech', 'release')
    assert spec['channel_spec']['status'] == 'unavailable'
    with pytest.raises(CatalogError, match='locked'):
        build_artifact(spec, 'runtime', tmp_path / 'release')
    assert not (tmp_path / 'release').exists()


def test_lifecycle_keeps_persistent_bytes_and_execs_arbitrary_argv(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert json.loads(docker(*base, image, 'describe').stdout)['id'] == 'cryptech'
    docker(*base, image, 'init')  # absence is explicitly accepted, never ignored
    first = snapshot(state)
    for options in ([], controls):
        for operation in ('init', 'health'):
            result = docker(*base, *options, image, operation)
            assert 'native_slot=0 token_present_index=0 label=Cryptech Token' in result.stdout
            assert snapshot(state) == first
    assert docker(*base, image, 'exec', '--', 'sh', '-c', 'printf "%s" "$CRYPTECH_KEYSTORE_DIR"').stdout == '/var/lib/p11lab/cryptech'
    assert docker(*base, image, 'exec', '--', 'sh', '-c', 'exit 23', check=False).returncode == 23
    assert docker(*base, image, 'exec', '--', 'sh', '-c', 'command -v cc make python3 pkcs11-tool; exit 0').stdout == ''
    assert snapshot(state) == first


def probe(runtime, *args, check=True):
    channel, root, state, secrets, image, base, controls = runtime
    return docker(*base, *controls, CONSUMERS[channel], 'exec', '--', 'p11lab-cryptech-probe', *args, check=check)


def test_native_provisioning_stays_unsupported(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    facts = json.loads(probe(runtime, 'facts').stdout)
    assert [facts[k] for k in ('init_token', 'init_pin', 'set_pin')] == [0x54] * 3
    assert facts['metadata'] == facts['mechanism_list'] == 0 and facts['mechanisms'] > 0
    assert snapshot(state) == before


@pytest.mark.parametrize('role', ['so', 'user'])
def test_native_correct_and_wrong_pin_errors_survive(runtime, role):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    assert json.loads(probe(runtime, 'login', role, 'right').stdout)['login'] == 0
    wrong = probe(runtime, 'login', role, 'wrong', check=False)
    assert wrong.returncode == 1 and json.loads(wrong.stdout)['login'] == 0xa0
    assert snapshot(state) == before


@pytest.mark.parametrize('role', ['PIN', 'SO_PIN'])
@pytest.mark.parametrize('kind', ['scalar', 'file'])
@pytest.mark.parametrize('equal', [True, False])
def test_supplied_credentials_validate_equal_before_every_operation(runtime, role, kind, equal):
    channel, root, state, secrets, image, base, controls = runtime
    value = 'fnord' if equal else 'different-private-input'
    if kind == 'file':
        (secrets / 'candidate').write_text(value + '\n')
        options = ['-e', f'P11LAB_{role}_FILE=/run/secrets/candidate']
    else:
        # Use an env-file so even test evidence excludes unequal credential bytes.
        envfile = secrets / 'env'
        envfile.write_text(f'P11LAB_{role}={value}\n')
        options = ['--env-file', str(envfile)]
    result = docker(*base, *options, image, 'init', check=False)
    assert (result.returncode == 0) == equal
    assert value not in result.stdout + result.stderr
    if not equal:
        assert list(state.iterdir()) == []
        docker(*base, image, 'init')
    before = snapshot(state)
    for operation in ('init', 'health', 'exec'):
        argv = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'printf APP-RAN']
        result = docker(*base, *options, image, *argv, check=False)
        assert (result.returncode == 0) == equal
        assert ('APP-RAN' in result.stdout) == (equal and operation == 'exec')
        assert value not in result.stdout + result.stderr
        assert snapshot(state) == before
    if kind == 'scalar':
        # Exercise catalogue admission and the supported runner too, including
        # privacy and owned cleanup on a refused scalar assertion.
        artifact = ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')
        spec = RunSpec('cryptech', channel, 'direct', artifact, 'provider', None, None,
                       ('sh', '-c', 'printf APP-RAN'),
                       {'P11LAB_STATE_DIR': str(state), f'P11LAB_{role}': value},
                       root / 'scalar-run', root, 120)
        result = run_application(spec)
        assert (result.exit_code == 0) == equal and not result.cleanup_errors
        assert result.app_returncode == (0 if equal else None)
        if not equal:
            assert value not in result.receipt_path.read_text()
            assert value not in ''.join(p.read_text() for p in spec.output_dir.glob('*.log'))
        assert snapshot(state) == before


@pytest.mark.parametrize('bad', ['empty', 'multiline', 'nul', 'too-large', 'conflict'])
def test_bad_credential_syntax_creates_no_state(runtime, bad):
    channel, root, state, secrets, image, base, controls = runtime
    if bad == 'conflict':
        controls = [*controls, '-e', 'P11LAB_PIN=']
    else:
        (secrets / 'pin').write_bytes({'empty': b'', 'multiline': b'fnord\n\n',
                                    'nul': b'fnord\0', 'too-large': b'x' * 4097}[bad])
    result = docker(*base, *controls, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []


@pytest.mark.parametrize('control', ['P11LAB_LABEL=P11Lab', 'CRYPTECH_KEYSTORE_DIR=/tmp/other'])
def test_native_fixed_label_and_managed_directory_conflicts_fail(runtime, control):
    channel, root, state, secrets, image, base, controls = runtime
    result = docker(*base, '-e', control, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []


def snapshot(state):
    result = {}
    for path in [state, *state.rglob('*')]:
        stat = path.lstat()
        if path.is_symlink():
            content = ('symlink', os.readlink(path))
        elif path.is_file():
            try:
                content = ('file', hashlib.sha256(path.read_bytes()).hexdigest())
            except PermissionError:
                content = ('unreadable', None)
        else:
            content = ('directory', None)
        result[str(path.relative_to(state))] = (content, stat.st_uid, stat.st_mode, stat.st_nlink)
    return result


@pytest.mark.parametrize('damage', ['missing-db', 'empty-db', 'short-db', 'bad-crc', 'no-pin-block',
                                  'missing-marker', 'marker-extra-lf', 'marker-nul',
                                  'hidden-file', 'hard-link', 'db-link', 'busy-init'])
def test_static_damage_refused_before_hal_open_or_application(runtime, damage):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    owned, database = state / 'cryptech', state / 'cryptech/keystore.bin'
    if damage == 'missing-db':
        database.unlink()
    elif damage == 'empty-db':
        database.write_bytes(b'')
    elif damage == 'short-db':
        database.write_bytes(database.read_bytes()[:-1])
    elif damage == 'bad-crc':
        content = bytearray(database.read_bytes())
        content[20] ^= 1
        database.write_bytes(content)
    elif damage == 'no-pin-block':
        database.write_bytes(b'\xff' * 524288)
    elif damage == 'missing-marker':
        (owned / 'complete').unlink()
    elif damage in ('marker-extra-lf', 'marker-nul'):
        with (owned / 'complete').open('ab') as marker:
            marker.write(b'\n' if damage == 'marker-extra-lf' else b'\0')
    elif damage == 'hidden-file':
        (owned / '.foreign').write_bytes(b'foreign')
    elif damage == 'hard-link':
        os.link(database, root / 'foreign-db')
    elif damage == 'db-link':
        database.rename(owned / 'original.bin')
        database.symlink_to('original.bin')
    else:
        (state / '.init-lock').mkdir()
    before = snapshot(state)
    for operation in ('init', 'health', 'exec'):
        argv = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'printf APP-RAN']
        refused = docker(*base, *controls, image, *argv, check=False)
        assert refused.returncode != 0 and 'APP-RAN' not in refused.stdout
        assert snapshot(state) == before


@pytest.mark.parametrize('target', ['root', 'owned', 'database'])
def test_foreign_state_ownership_preserves_all_bytes(runtime, target):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    path = {'root': '/var/lib/p11lab', 'owned': '/var/lib/p11lab/cryptech',
            'database': '/var/lib/p11lab/cryptech/keystore.bin'}[target]
    management = ['run', '--rm', '--network', 'none', '--mount',
                  f'type=bind,src={state},dst=/var/lib/p11lab', '--entrypoint', 'chown', image]
    docker(*management, str(os.getuid() + 1), path)
    readback = ['run', '--rm', '--network', 'none', '--mount',
                f'type=bind,src={state},dst=/var/lib/p11lab,readonly', '--entrypoint', 'sh', image,
                '-c', 'find /var/lib/p11lab -type f -exec sha256sum {} + | sort']
    try:
        contents = docker(*readback).stdout
        for argv in (('init',), ('health',), ('exec', '--', 'sh', '-c', 'printf APP-RAN')):
            refused = docker(*base, *controls, image, *argv, check=False)
            assert refused.returncode != 0 and 'APP-RAN' not in refused.stdout
            assert docker(*readback).stdout == contents
    finally:
        docker(*management, f'{os.getuid()}:{os.getgid()}', path)


def test_independent_state_isolation_and_fixed_pbkdf2(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    content = (state / 'cryptech/keystore.bin').read_bytes()
    expected = hashlib.pbkdf2_hmac('sha256', b'fnord', b'\0' * 16, 2000, 64)
    for offset in (8 + 84, 8 + 84 * 2):
        assert int.from_bytes(content[offset:offset + 4], 'little') == 2000
        assert content[offset + 4:offset + 68] == expected
        assert content[offset + 68:offset + 84] == b'\0' * 16
    other = root / 'other-state'
    other.mkdir(mode=0o700)
    other_base = [argument.replace(f'src={state},', f'src={other},') for argument in base]
    docker(*other_base, image, 'init')
    assert (other / 'cryptech/keystore.bin').read_bytes() == content
    # Corruption in one independent shard cannot repair/reset or affect another.
    (other / 'cryptech/keystore.bin').write_bytes(b'bad')
    assert docker(*other_base, image, 'health', check=False).returncode != 0
    docker(*base, image, 'health')
    assert (state / 'cryptech/keystore.bin').read_bytes() == content


def test_sha256_matches_independent_standard_library_oracle(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    result = probe(runtime, 'digest')
    assert result.stdout.strip() == hashlib.sha256(b'P11Lab Cryptech SHA256 oracle').hexdigest()


def test_advertised_rng_preserves_hardware_failure(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    assert json.loads(probe(runtime, 'facts').stdout)['flags'] & 1
    result = probe(runtime, 'random', check=False)
    assert result.returncode == 1 and json.loads(result.stdout)['generate_random'] == 0x06


def test_general_token_crypto_falsified_with_receipt_and_owned_cleanup(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    artifact = ArtifactRef('docker-local', CONSUMERS[channel], CONSUMERS[channel].removeprefix('sha256:'), 'linux/amd64')
    spec = RunSpec('cryptech', channel, 'direct', artifact, 'provider', None, None,
                   ('p11lab-smoke', '--module', MODULE, '--token-label', 'Cryptech Token',
                    '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--output', '/p11lab-output/crypto',
                    '--key-mode', 'generated'),
                   {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
                    'P11LAB_SO_PIN_FILE': str(secrets / 'so'), 'P11LAB_LABEL': 'Cryptech Token'},
                   root / 'general-token', root, 120)
    result = run_application(spec)
    assert result.app_returncode != 0 and result.exit_code != 0 and not result.cleanup_errors
    assert 'C_GenerateKeyPair: CK_RV=0x00000006' in (spec.output_dir / 'application.stderr.log').read_text()
    keypair = run_application(replace(spec, output_dir=root / 'native-keypair',
                                     argv=('p11lab-cryptech-probe', 'keypair')))
    assert keypair.app_returncode != 0 and keypair.exit_code != 0 and not keypair.cleanup_errors
    record = json.loads((root / 'native-keypair/application.stdout.log').read_text())
    assert record['generate_keypair'] == 0x06
    assert json.loads(result.receipt_path.read_text())['cleanup_errors'] == []
