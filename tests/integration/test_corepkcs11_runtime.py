"""Raw corePKCS11 process-local acceptance; no shim or provider normalization.

Real lanes require exact engine IDs in P11LAB_COREPKCS11_{IMAGES,CONSUMERS,
CHECKERS,PROXIES}, provider-bound CLIENTS and a CALLER. Builds never occur here.
The C application below deliberately uses only implemented embedded operations;
the existing general-token consumer and installed checker are exercised too,
with their actual unsupported/incomplete outcomes retained.
"""
from dataclasses import asdict
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

MODULE = '/usr/local/lib/p11lab/libcore_pkcs.so'
IMAGES = json.loads(os.environ.get('P11LAB_COREPKCS11_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_COREPKCS11_CONSUMERS', '{}'))
CHECKERS = json.loads(os.environ.get('P11LAB_COREPKCS11_CHECKERS', '{}'))
PROXIES = json.loads(os.environ.get('P11LAB_COREPKCS11_PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_COREPKCS11_CLIENTS', '{}'))
CALLER = os.environ.get('P11LAB_COREPKCS11_CALLER', '')
COMMANDS = itertools.count()

# Original test-only application; compiled into an optional consumer derivative,
# never the basic runtime. p256.c only encodes public outputs for the OpenSSL oracle.
NATIVE_APP = r'''/* SPDX-License-Identifier: Apache-2.0 */
#define _POSIX_C_SOURCE 200809L
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#define CK_PTR *
#define CK_DEFINE_FUNCTION(r,n) r n
#define CK_DECLARE_FUNCTION(r,n) r n
#define CK_DECLARE_FUNCTION_POINTER(r,n) r (*n)
#define CK_CALLBACK_FUNCTION(r,n) r (*n)
#define NULL_PTR 0
#include <pkcs11.h>
#include "p256.h"
static CK_FUNCTION_LIST_PTR f;
static CK_SESSION_HANDLE session;
static CK_BYTE priv_label[] = "p11lab arbitrary private";
static CK_BYTE pub_label[] = "p11lab arbitrary public";
static const CK_BYTE message[] = "P11Lab independent PKCS11 smoke v1\n";
static int good(const char *name, CK_RV rv) {
    if (rv == CKR_OK) return 1;
    fprintf(stderr, "%s: CK_RV=0x%08lx\n", name, (unsigned long)rv);
    return 0;
}
static int find(CK_SESSION_HANDLE s, CK_BYTE *label, CK_ULONG length, CK_OBJECT_HANDLE *object, CK_ULONG *count) {
    CK_ATTRIBUTE attr = {CKA_LABEL, label, length};
    *object = CK_INVALID_HANDLE; *count = 0;
    if (!good("C_FindObjectsInit", f->C_FindObjectsInit(s, &attr, 1))) return 0;
    CK_RV rv = f->C_FindObjects(s, object, 1, count);
    CK_RV end = f->C_FindObjectsFinal(s);
    return good("C_FindObjects", rv) && good("C_FindObjectsFinal", end);
}
static int pair(CK_OBJECT_HANDLE *pub, CK_OBJECT_HANDLE *priv) {
    CK_BBOOL yes = CK_TRUE;
    CK_BYTE oid[] = {0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07};
    CK_MECHANISM mechanism = {CKM_EC_KEY_PAIR_GEN, NULL, 0};
    CK_ATTRIBUTE pa[] = {{CKA_LABEL,pub_label,sizeof(pub_label)-1},
        {CKA_EC_PARAMS,oid,sizeof(oid)}, {CKA_VERIFY,&yes,sizeof(yes)}, {CKA_TOKEN,&yes,sizeof(yes)}};
    CK_ATTRIBUTE pr[] = {{CKA_LABEL,priv_label,sizeof(priv_label)-1},
        {CKA_PRIVATE,&yes,sizeof(yes)}, {CKA_SIGN,&yes,sizeof(yes)}, {CKA_TOKEN,&yes,sizeof(yes)}};
    return good("C_GenerateKeyPair", f->C_GenerateKeyPair(session,&mechanism,pa,4,pr,4,pub,priv));
}
static int login(void) {
    /* The same standard private-key caller sequence in direct and proxy lanes.
     * Test-only interoperability input; native facts separately prove that this
     * upstream port ignores it. No authentication or PIN-rejection claim. */
    CK_BYTE pin[]={'0','0','0','0'};
    return good("C_Login",f->C_Login(session,CKU_USER,pin,sizeof(pin)));
}
static int write_file(const char *root,const char *name,const void *value,size_t size) {
    char path[4096];
    int n=snprintf(path,sizeof(path),"%s/%s",root,name);
    if (n<0 || (size_t)n>=sizeof(path)) return 0;
    FILE *out=fopen(path,"wb");
    if (!out) return 0;
    int ok=fwrite(value,1,size,out)==size;
    return fclose(out)==0 && ok;
}
static int crypto(const char *output, int reinitialize) {
    CK_OBJECT_HANDLE pub=CK_INVALID_HANDLE,priv=CK_INVALID_HANDLE,found=CK_INVALID_HANDLE;
    CK_ULONG count=0;
    CK_SESSION_HANDLE second=CK_INVALID_HANDLE;
    CK_BYTE digest[32],raw[64],encoded_point[67],point[65],spki[91],der[72];
    char pem[192];
    size_t der_len=sizeof(der),pem_len;
    CK_ULONG digest_len=sizeof(digest),raw_len=sizeof(raw);
    CK_MECHANISM sha={CKM_SHA256,NULL,0},sign={CKM_ECDSA,NULL,0};
    CK_ATTRIBUTE point_attr={CKA_EC_POINT,encoded_point,sizeof(encoded_point)};
    int ok=login() && pair(&pub,&priv);
    if (ok) ok=good("C_OpenSession(second)",f->C_OpenSession(1,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&second));
    if (ok) puts("stage=cross-session-find");
    if (ok) ok=find(second,priv_label,sizeof(priv_label)-1,&found,&count) && count==1;
    if (second!=CK_INVALID_HANDLE) ok=good("C_CloseSession(second)",f->C_CloseSession(second)) && ok;
    if (ok) ok=good("C_GetAttributeValue(EC_POINT)",f->C_GetAttributeValue(session,pub,&point_attr,1));
    if (ok) ok=p11_ec_point(encoded_point,point_attr.ulValueLen,point);
    if (ok) ok=good("C_DigestInit",f->C_DigestInit(session,&sha));
    if (ok) ok=good("C_DigestUpdate",f->C_DigestUpdate(session,(CK_BYTE_PTR)message,sizeof(message)-1));
    if (ok) ok=good("C_DigestFinal",f->C_DigestFinal(session,digest,&digest_len)) && digest_len==32;
    if (ok) ok=good("C_SignInit",f->C_SignInit(session,&sign,priv));
    if (ok) ok=good("C_Sign",f->C_Sign(session,digest,sizeof(digest),raw,&raw_len)) && raw_len==64;
    if (ok) ok=p11_signature_der(raw,sizeof(raw),der,&der_len);
    if (ok) puts("stage=signature-produced");
    /* A separate lifecycle observation, not a prerequisite for the live-context
     * crypto lane. Direct reinitialization keeps the SAME loaded library. Proxy
     * client reinitialization changes its context within the SAME daemon. */
    if (ok && reinitialize) {
        ok=good("C_CloseSession",f->C_CloseSession(session));
        if (ok) ok=good("C_Finalize",f->C_Finalize(NULL));
        if (ok) ok=good("C_Initialize(reinit)",f->C_Initialize(NULL));
        if (ok) ok=good("C_OpenSession(reinit)",f->C_OpenSession(1,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&session));
        if (ok) ok=login();
        if (ok) puts("stage=client-reinitialize-find");
        if (ok) ok=find(session,priv_label,sizeof(priv_label)-1,&priv,&count) && count==1;
        if (ok) ok=find(session,pub_label,sizeof(pub_label)-1,&pub,&count) && count==1;
    }
    if (priv!=CK_INVALID_HANDLE) ok=good("C_DestroyObject(private)",f->C_DestroyObject(session,priv)) && ok;
    if (pub!=CK_INVALID_HANDLE) ok=good("C_DestroyObject(public)",f->C_DestroyObject(session,pub)) && ok;
    if (ok) ok=find(session,priv_label,sizeof(priv_label)-1,&found,&count) && count==0;
    if (!ok) return 0;
    if (mkdir(output,0700)!=0) return 0;
    p11_make_spki(point,spki);pem_len=p11_public_pem(point,pem);
    char record[160];
    int record_len=snprintf(record,sizeof(record),"{\"same_process_reinitialize\":%s,\"cross_session_visible\":true,\"owned_objects_destroyed\":true,\"persistent\":false}\n",reinitialize?"true":"false");
    if (record_len<0 || (size_t)record_len>=sizeof(record)) return 0;
    return write_file(output,"message.bin",message,sizeof(message)-1) &&
        write_file(output,"digest.bin",digest,sizeof(digest)) && write_file(output,"signature.raw",raw,sizeof(raw)) &&
        write_file(output,"signature.der",der,der_len) && write_file(output,"public-key.der",spki,sizeof(spki)) &&
        write_file(output,"public-key.pem",pem,pem_len) && write_file(output,"result.json",record,(size_t)record_len);
}
static int facts(void) {
    CK_TOKEN_INFO info, before;
    CK_MECHANISM_INFO mi;
    memset(&info,0xa5,sizeof(info));before=info;
    CK_RV token=f->C_GetTokenInfo(1,&info);
    CK_BYTE default_pin[]={'0','0','0','0'},wrong[]={'x','x','x','x','x'};
    CK_RV login=f->C_Login(session,CKU_USER,default_pin,sizeof(default_pin));
    CK_RV wrong_login=f->C_Login(session,CKU_USER,wrong,sizeof(wrong));
    CK_RV invalid_login=f->C_Login(CK_INVALID_HANDLE,CKU_USER,NULL,0);
    CK_RV rsa=f->C_GetMechanismInfo(1,CKM_RSA_PKCS,&mi);
    CK_FLAGS flags=mi.flags;
    CK_RV hmac=f->C_GetMechanismInfo(1,CKM_SHA256_HMAC,&mi);
    CK_RV cmac=f->C_GetMechanismInfo(1,CKM_AES_CMAC,&mi);
    CK_RV invalid=f->C_GetSlotList(CK_TRUE,NULL,NULL);
    printf("{\"get_info_null\":%s,\"slot_info_null\":%s,\"mechanism_list_null\":%s,\"digest_null\":%s,"
           "\"token_rv\":%lu,\"token_output_unchanged\":%s,\"login_rv\":%lu,\"wrong_pin_rv\":%lu,"
           "\"invalid_session_login_rv\":%lu,\"rsa_rv\":%lu,\"rsa_flags\":%lu,\"hmac_rv\":%lu,\"cmac_rv\":%lu,\"bad_count_rv\":%lu}\n",
           f->C_GetInfo?"false":"true",f->C_GetSlotInfo?"false":"true",f->C_GetMechanismList?"false":"true",f->C_Digest?"false":"true",
           (unsigned long)token,memcmp(&info,&before,sizeof(info))==0?"true":"false",(unsigned long)login,(unsigned long)wrong_login,
           (unsigned long)invalid_login,(unsigned long)rsa,(unsigned long)flags,(unsigned long)hmac,(unsigned long)cmac,(unsigned long)invalid);
    return 1;
}
/* Direct PAL observations are separately identified; not PKCS#11 conformance. */
static int pal(void *library) {
    CK_OBJECT_HANDLE (*save)(CK_ATTRIBUTE_PTR,CK_BYTE_PTR,CK_ULONG);
    CK_OBJECT_HANDLE (*lookup)(CK_BYTE_PTR,CK_ULONG);
    CK_RV (*get)(CK_OBJECT_HANDLE,CK_BYTE_PTR *,CK_ULONG_PTR,CK_BBOOL *);
    CK_RV (*destroy)(CK_OBJECT_HANDLE);
    void (*release)(CK_BYTE_PTR,CK_ULONG);
    void *symbol=dlsym(library,"PKCS11_PAL_SaveObject");memcpy(&save,&symbol,sizeof(save));
    symbol=dlsym(library,"PKCS11_PAL_FindObject");memcpy(&lookup,&symbol,sizeof(lookup));
    symbol=dlsym(library,"PKCS11_PAL_GetObjectValue");memcpy(&get,&symbol,sizeof(get));
    symbol=dlsym(library,"PKCS11_PAL_DestroyObject");memcpy(&destroy,&symbol,sizeof(destroy));
    symbol=dlsym(library,"PKCS11_PAL_GetObjectValueCleanup");memcpy(&release,&symbol,sizeof(release));
    if (!save||!lookup||!get||!destroy||!release) return 0;
    CK_BYTE binary_label[]={'a',0,'b'},data[]={0x30,0x03,0x02,0x01,0x01},public_data[]={0x30,0x03,0x30,0x01,0x01};
    CK_ATTRIBUTE label={CKA_LABEL,binary_label,sizeof(binary_label)};
    CK_OBJECT_HANDLE a=save(&label,data,sizeof(data));
    CK_BYTE *copy=NULL;CK_ULONG size=0;CK_BBOOL private=CK_FALSE;
    int ok=a!=CK_INVALID_HANDLE && lookup(binary_label,sizeof(binary_label))==a && lookup(binary_label,1)==CK_INVALID_HANDLE;
    if (ok) ok=good("PAL_GetObjectValue",get(a,&copy,&size,&private)) && size==sizeof(data) && private==CK_TRUE;
    if (!ok) return 0;
    CK_OBJECT_HANDLE overwritten=save(&label,public_data,sizeof(public_data));
    ok=overwritten==a && memcmp(copy,data,sizeof(data))==0;release(copy,size);
    if (ok) ok=good("PAL_GetObjectValue(overwrite)",get(a,&copy,&size,&private)) && private==CK_FALSE;
    release(copy,size);
    if (ok) ok=good("PAL_DestroyObject",destroy(a)) && lookup(binary_label,sizeof(binary_label))==CK_INVALID_HANDLE;
    CK_RV stale=get(a,&copy,&size,&private);
    CK_BYTE too_long[33];memset(too_long,'z',sizeof(too_long));label.pValue=too_long;label.ulValueLen=33;
    ok=ok && stale==CKR_OBJECT_HANDLE_INVALID && save(&label,data,sizeof(data))==CK_INVALID_HANDLE;
    label.ulValueLen=0;ok=ok && save(&label,data,sizeof(data))==CK_INVALID_HANDLE;
    label.ulValueLen=32;a=save(&label,data,sizeof(data));ok=ok && a!=CK_INVALID_HANDLE;
    if (a!=CK_INVALID_HANDLE) ok=good("PAL_DestroyObject(32)",destroy(a)) && ok;
    CK_OBJECT_HANDLE handles[256];size_t used=0;
    for (size_t i=0;ok && i<256;i++) {
        char name[32];int n=snprintf(name,sizeof(name),"entry-%zu",i);
        label.pValue=name;label.ulValueLen=(CK_ULONG)n;
        handles[used]=save(&label,public_data,sizeof(public_data));
        if (handles[used]==CK_INVALID_HANDLE) ok=0;else used++;
    }
    label.pValue=(void *)"overflow";label.ulValueLen=8;
    ok=ok && used==256 && save(&label,public_data,sizeof(public_data))==CK_INVALID_HANDLE;
    if (used) {
        CK_OBJECT_HANDLE reusable=handles[0];ok=good("PAL_DestroyObject(reuse)",destroy(reusable)) && ok;
        handles[0]=save(&label,public_data,sizeof(public_data));ok=ok && handles[0]==reusable;
    }
    for (size_t i=0;i<used;i++) ok=good("PAL_DestroyObject(cleanup)",destroy(handles[i])) && ok;
    if (ok) puts("{\"pal_entries\":256,\"binary_label\":true,\"same_label_overwrites\":true,\"snapshot_reads\":true,\"der_privacy_heuristic\":true,\"handle_reused\":true}");
    return ok;
}
int main(int argc,char **argv) {
    if (argc<2 || argc>3) return 2;
    setvbuf(stdout,NULL,_IONBF,0);
    const char *module=getenv("P11LAB_MODULE");
    if (!module) return 2;
    void *library=dlopen(module,RTLD_NOW|RTLD_LOCAL);
    if (!library) {fputs("module load failed\n",stderr);return 1;}
    CK_C_GetFunctionList list;void *symbol=dlsym(library,"C_GetFunctionList");
    _Static_assert(sizeof(list)==sizeof(symbol),"POSIX function pointer ABI");memcpy(&list,&symbol,sizeof(list));
    if (!list || !good("C_GetFunctionList",list(&f)) || !f) return 1;
    if (!good("C_Initialize",f->C_Initialize(NULL))) return 1;
    if (!good("C_OpenSession",f->C_OpenSession(1,CKF_SERIAL_SESSION|CKF_RW_SESSION,NULL,NULL,&session))) return 1;
    int ok=0;
    if (strcmp(argv[1],"facts")==0) ok=facts();
    else if (strcmp(argv[1],"pal")==0) ok=pal(library);
    else if (strcmp(argv[1],"crypto")==0 && argc==3) ok=crypto(argv[2],0);
    else if (strcmp(argv[1],"crypto-reinitialize")==0 && argc==3) ok=crypto(argv[2],1);
    else if (strcmp(argv[1],"leave")==0) {CK_OBJECT_HANDLE pub,priv;ok=pair(&pub,&priv);if(ok) puts("objects created in this process only");}
    else if (strcmp(argv[1],"find")==0) {CK_OBJECT_HANDLE object;CK_ULONG count;ok=find(session,priv_label,sizeof(priv_label)-1,&object,&count);if(ok) printf("{\"fresh_process_object_count\":%lu}\n",(unsigned long)count);}
    ok=good("C_CloseSession(final)",f->C_CloseSession(session)) && ok;
    ok=good("C_Finalize(final)",f->C_Finalize(NULL)) && ok;
    if (dlclose(library)!=0) ok=0;
    return ok?0:1;
}
'''


def ref(image):
    return ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')


def evidence_root(name, tmp_path):
    evidence = os.environ.get('P11LAB_COREPKCS11_EVIDENCE')
    root = Path(evidence) / name if evidence else tmp_path / name
    root.mkdir(parents=True, exist_ok=False)
    return root


def record_run(spec, *, profile=None):
    # Exact lane bindings, with credential paths/presence but never their bytes.
    record = asdict(spec) | {'module_lifetime': 'application process' if spec.mode == 'direct' else 'one managed backend in the daemon process; one logical client/trusted domain',
                            'expected_module_env': MODULE if spec.mode == 'direct' else '/run/p11lab-client/libpkcs11_proxy_ng_shim.so',
                            'profile': profile}
    (spec.output_dir.parent / 'run-spec.json').write_text(json.dumps(record, default=str, indent=2) + '\n')


def docker(*args, check=True):
    argv = ['docker', *args]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    evidence = os.environ.get('P11LAB_COREPKCS11_EVIDENCE')
    if evidence:
        root = Path(evidence) / 'commands'
        root.mkdir(parents=True, exist_ok=True)
        (root / f'{next(COMMANDS):04d}.json').write_text(json.dumps(
            {'argv': argv, 'env': {}, 'returncode': result.returncode,
             'stdout': result.stdout, 'stderr': result.stderr}, indent=2) + '\n')
    if check:
        assert result.returncode == 0, result.stderr
    return result


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_corepkcs11_lock_preserves_raw_port_and_frozen_closure(channel):
    spec = load_environment('corepkcs11', channel)
    validate_build_inputs(spec)
    assert spec['module_path'] == MODULE and spec['state_mode'] == 'process-local'
    inputs = runtime_inputs(spec)
    assert artifact_key('runtime', inputs)
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['adapter_shim_shipped'] is False
    assert inputs['features']['configure_build_network'] == 'none'
    assert len(inputs['features']['fetchcontent_inputs']) == 2
    assert len(inputs['patches']) == 2
    assert inputs['patches'][0]['sha256'] == '4ae87789e185d58adbbf1c8b43fdb6ebff2035f5e8a976cae3bd0834eeed9611'
    assert spec['distribution']['status'] == 'unreviewed'
    assert all(p['license_status'] == 'missing' for p in spec['lock']['migrated_file_provenance'])


@pytest.fixture(params=['release', 'rolling'])
def runtime(request, tmp_path):
    channel = request.param
    if channel not in IMAGES:
        pytest.skip('explicit corePKCS11 runtime engine IDs required')
    root = evidence_root(request.node.name, tmp_path)
    state = root / 'state'
    state.mkdir(mode=0o700)
    base = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--user', f'{os.getuid()}:{os.getgid()}',
            '--mount', f'type=bind,src={state},dst=/var/lib/p11lab,readonly']
    return channel, root, state, IMAGES[channel], base


def test_corepkcs11_no_provisioned_state_or_exec_preflight(runtime):
    channel, root, state, image, base = runtime
    (state / '.foreign').write_bytes(b'caller owned')
    before = (state / '.foreign').read_bytes()
    assert json.loads(docker(*base, image, 'describe').stdout)['module_path'] == MODULE
    for _ in range(2):
        assert 'no token provisioned' in docker(*base, image, 'init').stdout
        assert 'no application-token claim' in docker(*base, image, 'health').stdout
    result = docker(*base, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\\n" "$P11LAB_MODULE" "$1"; exit 37', 'app',
                    'literal $argument with spaces', check=False)
    assert result.returncode == 37 and result.stdout.splitlines() == [MODULE, 'literal $argument with spaces']
    assert (state / '.foreign').read_bytes() == before
    assert list(state.iterdir()) == [state / '.foreign']
    assert docker(*base, image, 'exec', '--', 'sh', '-c',
                  'command -v python3 gcc cmake ninja pkcs11-tool; exit 0').stdout == ''
    assert docker(*base, image, 'server', check=False).returncode != 0


@pytest.mark.parametrize('value', ['', 'x' * 33, 'invalid/label'], ids=['empty', 'over-bound', 'invalid-character'])
def test_corepkcs11_invalid_labels_refused_without_state(runtime, value):
    channel, root, state, image, base = runtime
    result = docker(*base, '-e', 'P11LAB_LABEL=' + value, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []


@pytest.mark.parametrize('value', [b'', b'line1\nline2', b'line\x00two', b'x' * 4097], ids=['empty', 'multiline', 'nul', 'over-bound'])
def test_corepkcs11_bad_optional_secret_is_validation_only(runtime, value):
    channel, root, state, image, base = runtime
    secret = root / 'pin'
    secret.write_bytes(value)
    secret.chmod(0o600)
    try:
        result = docker(*base, '--mount', f'type=bind,src={secret},dst=/run/input,readonly',
                        '-e', 'P11LAB_PIN_FILE=/run/input', image, 'init', check=False)
        assert result.returncode != 0 and list(state.iterdir()) == []
    finally:
        secret.unlink()


def test_corepkcs11_native_metadata_errors_and_ignored_pin_preserved(runtime):
    channel, root, state, image, base = runtime
    assert channel in CONSUMERS, 'explicit compatible embedded consumer derivative required'
    record = json.loads(docker(*base, CONSUMERS[channel], 'exec', '--', 'p11lab-corepkcs11-app', 'facts').stdout)
    assert all(record[name] for name in ['get_info_null', 'slot_info_null', 'mechanism_list_null', 'digest_null', 'token_output_unchanged'])
    assert record['token_rv'] == record['login_rv'] == record['wrong_pin_rv'] == record['invalid_session_login_rv'] == 0
    assert record['hmac_rv'] == record['cmac_rv'] == 0x70
    assert record['rsa_rv'] == 0 and record['rsa_flags'] == 0x800
    assert record['bad_count_rv'] == 7
    (root / 'native-observations.json').write_text(json.dumps(record, indent=2) + '\n')


def test_corepkcs11_pal_storage_label_privacy_and_capacity_deltas(runtime):
    channel, root, state, image, base = runtime
    assert channel in CONSUMERS
    record = json.loads(docker(*base, CONSUMERS[channel], 'exec', '--', 'p11lab-corepkcs11-app', 'pal').stdout)
    assert record == {'pal_entries': 256, 'binary_label': True, 'same_label_overwrites': True,
                      'snapshot_reads': True, 'der_privacy_heuristic': True, 'handle_reused': True}
    (root / 'pal-observations.json').write_text(json.dumps(record, indent=2) + '\n')


def test_corepkcs11_fresh_process_has_no_prior_objects(runtime):
    channel, root, state, image, base = runtime
    assert channel in CONSUMERS
    docker(*base, CONSUMERS[channel], 'exec', '--', 'p11lab-corepkcs11-app', 'leave')
    absent = json.loads(docker(*base, CONSUMERS[channel], 'exec', '--', 'p11lab-corepkcs11-app', 'find').stdout)
    assert absent['fresh_process_object_count'] == 0
    assert list(state.iterdir()) == []
    (root / 'fresh-process-observation.json').write_text(json.dumps(absent) + '\n')


@pytest.mark.parametrize('reinitialize', [False, True], ids=['live-context', 'same-library-reinitialize'])
def test_corepkcs11_in_process_crypto_and_owned_cleanup(runtime, reinitialize):
    channel, root, state, image, base = runtime
    assert channel in CONSUMERS
    caller = root / 'caller'
    caller.mkdir()
    spec = RunSpec('corepkcs11', channel, 'direct', ref(CONSUMERS[channel]), 'provider', None, None,
                   ('p11lab-corepkcs11-app', 'crypto-reinitialize' if reinitialize else 'crypto', '/p11lab-output/crypto'),
                   {}, root / 'output', caller, 90)
    record_run(spec)
    result = run_application(spec)
    assert result.exit_code == 0 and not result.cleanup_errors, result
    record = json.loads((spec.output_dir / 'crypto/result.json').read_text())
    assert record == {'same_process_reinitialize': reinitialize, 'cross_session_visible': True,
                      'owned_objects_destroyed': True, 'persistent': False}
    oracle = subprocess.run(['python3', str(package_data('consumer/verify.py')), str(spec.output_dir / 'crypto')],
                            capture_output=True, text=True, timeout=60)
    (root / 'oracle-command.json').write_text(json.dumps({'argv': oracle.args, 'env': {}, 'returncode': oracle.returncode}) + '\n')
    (root / 'oracle.log').write_text(oracle.stdout + oracle.stderr)
    assert oracle.returncode == 0 and 'altered message rejected' in oracle.stdout, oracle.stderr


def test_corepkcs11_general_token_consumer_has_honest_unsupported_outcome(runtime):
    channel, root, state, image, base = runtime
    assert channel in CONSUMERS
    caller = root / 'caller'
    caller.mkdir()
    spec = RunSpec('corepkcs11', channel, 'direct', ref(CONSUMERS[channel]), 'provider', None, None,
                   ('p11lab-smoke', '--module', MODULE, '--token-label', 'P11Lab',
                    '--output', '/p11lab-output/crypto', '--key-mode', 'generated'), {}, root / 'output', caller, 90)
    record_run(spec)
    result = run_application(spec)
    assert result.app_returncode == 1 and result.exit_code != 0 and not result.cleanup_errors
    assert 'provider function list lacks required operations' in (spec.output_dir / 'application.stderr.log').read_text()


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_corepkcs11_installed_checker_lane_retains_incompleteness(channel, tmp_path):
    if channel not in CHECKERS:
        pytest.skip('explicit installed checker derivative required')
    from p11lab.checker import run_checker
    root = evidence_root('direct-checker-' + channel, tmp_path)
    caller = root / 'caller'
    caller.mkdir()
    pin, so = root / 'pin', root / 'so'
    pin.write_bytes(b'local-test-user-pin')
    so.write_bytes(b'local-test-so-pin')
    pin.chmod(0o600)
    so.chmod(0o600)
    try:
        spec = RunSpec('corepkcs11', channel, 'direct', ref(CHECKERS[channel]), 'provider', None, None, (),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so)}, root / 'output', caller, 1200)
        record_run(spec, profile='smoke-v1')
        result = run_checker(spec, 'smoke-v1')
        (root / 'lane-result.json').write_text(json.dumps(asdict(result), default=str, indent=2) + '\n')
        assert result.exit_code != 0 and not result.cleanup_errors
        # Metadata discovery is not supplied by the raw provider. This lane is
        # not qualified by the host test passing its evidence assertions.
        assert not (spec.output_dir / 'checker/results.json').exists()
        assert not (spec.output_dir / 'checker/checker-receipt.json').exists()
    finally:
        pin.unlink()
        so.unlink()


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_corepkcs11_preferred_proxy_lane_preserves_provider_failure(channel, tmp_path):
    if channel not in PROXIES or channel not in CLIENTS or not CALLER:
        pytest.skip('explicit pinned proxy derivative/client/caller required')
    root = evidence_root('proxy-application-' + channel, tmp_path)
    caller = root / 'caller'
    caller.mkdir()
    bundle = Path(CLIENTS[channel])
    client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
    spec = RunSpec('corepkcs11', channel, 'proxy', ref(PROXIES[channel]), 'container', ref(CALLER), client,
                   ('p11lab-smoke', '--module', '/run/p11lab-client/libpkcs11_proxy_ng_shim.so',
                    '--token-label', 'P11Lab', '--output', '/p11lab-output/crypto', '--key-mode', 'generated'),
                   {}, root / 'output', caller, 300)
    record_run(spec)
    result = run_application(spec)
    (root / 'lane-result.json').write_text(json.dumps(asdict(result), default=str, indent=2) + '\n')
    assert result.exit_code != 0 and not result.cleanup_errors
    assert not (spec.output_dir / 'crypto/signature.der').exists()


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_corepkcs11_preferred_proxy_embedded_crypto(channel, tmp_path):
    if channel not in PROXIES or channel not in CLIENTS or not CALLER:
        pytest.skip('explicit pinned proxy derivative/client/embedded caller required')
    root = evidence_root('proxy-embedded-' + channel, tmp_path)
    caller = root / 'caller'
    caller.mkdir()
    bundle = Path(CLIENTS[channel])
    client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
    spec = RunSpec('corepkcs11', channel, 'proxy', ref(PROXIES[channel]), 'container', ref(CALLER), client,
                   ('p11lab-corepkcs11-app', 'crypto', '/p11lab-output/crypto'), {}, root / 'output', caller, 300)
    record_run(spec)
    result = run_application(spec)
    (root / 'lane-result.json').write_text(json.dumps(asdict(result), default=str, indent=2) + '\n')
    assert result.exit_code == 0 and not result.cleanup_errors, result
    assert (spec.output_dir / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
    crypto_record = json.loads((spec.output_dir / 'crypto/result.json').read_text())
    assert crypto_record == {'same_process_reinitialize': False, 'cross_session_visible': True,
                             'owned_objects_destroyed': True, 'persistent': False}
    oracle = subprocess.run(['python3', str(package_data('consumer/verify.py')), str(spec.output_dir / 'crypto')],
                            capture_output=True, text=True, timeout=60)
    (root / 'oracle-command.json').write_text(json.dumps({'argv': oracle.args, 'env': {}, 'returncode': oracle.returncode}) + '\n')
    (root / 'oracle.log').write_text(oracle.stdout + oracle.stderr)
    assert oracle.returncode == 0 and 'altered message rejected' in oracle.stdout, oracle.stderr


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_corepkcs11_proxy_client_reinitialize_has_blocked_object_rediscovery(channel, tmp_path):
    if channel not in PROXIES or channel not in CLIENTS or not CALLER:
        pytest.skip('explicit pinned proxy derivative/client/embedded caller required')
    root = evidence_root('proxy-client-reinitialize-block-' + channel, tmp_path)
    caller = root / 'caller'
    caller.mkdir()
    bundle = Path(CLIENTS[channel])
    client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
    spec = RunSpec('corepkcs11', channel, 'proxy', ref(PROXIES[channel]), 'container', ref(CALLER), client,
                   ('p11lab-corepkcs11-app', 'crypto-reinitialize', '/p11lab-output/crypto'),
                   {}, root / 'output', caller, 300)
    record_run(spec)
    result = run_application(spec)
    (root / 'lane-result.json').write_text(json.dumps(asdict(result), default=str, indent=2) + '\n')
    assessment = {'status': 'blocked', 'complete': False, 'owned_object_cleanup_completed': False,
                  'reason': 'object rediscovery after proxy client reinitialization returned CKR_FUNCTION_FAILED',
                  'provider_qualification': False}
    (root / 'lane-assessment.json').write_text(json.dumps(assessment, indent=2) + '\n')
    assert result.app_returncode == 1 and result.exit_code != 0 and not result.cleanup_errors, result
    stdout = (spec.output_dir / 'application.stdout.log').read_text()
    assert 'stage=signature-produced' in stdout and 'stage=client-reinitialize-find' in stdout
    assert 'C_FindObjects: CK_RV=0x00000006' in (spec.output_dir / 'application.stderr.log').read_text()
    assert not (spec.output_dir / 'crypto/result.json').exists()


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_corepkcs11_preferred_proxy_checker_retains_metadata_block(channel, tmp_path):
    if channel not in PROXIES or channel not in CLIENTS or channel not in CHECKERS:
        pytest.skip('explicit pinned proxy/checker/client required')
    from p11lab.checker import load_profile
    root = evidence_root('proxy-checker-' + channel, tmp_path)
    caller = root / 'caller'
    caller.mkdir()
    bundle = Path(CLIENTS[channel])
    client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
    spec = RunSpec('corepkcs11', channel, 'proxy', ref(PROXIES[channel]), 'container', ref(CHECKERS[channel]), client,
                   ('/opt/p11lab-checker/bin/python', '-m', 'p11lab.checker', 'execute',
                    json.dumps(load_profile()['nodes'], separators=(',', ':'))), {}, root / 'output', caller, 300)
    record_run(spec, profile='smoke-v1')
    result = run_application(spec)
    (root / 'lane-result.json').write_text(json.dumps(asdict(result), default=str, indent=2) + '\n')
    assert result.exit_code != 0 and not result.cleanup_errors
    assert 'token identity must select exactly one token-present slot' in (spec.output_dir / 'application.stderr.log').read_text()
    assert not (spec.output_dir / 'checker/results.json').exists()
