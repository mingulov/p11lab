# SPDX-License-Identifier: Apache-2.0
"""Direct observations of every unchanged advertised RustSSM mechanism.

The probe uses native exported PKCS#11 calls; cryptography/OpenSSL is the
independent oracle in the separate installed checker derivative. Each attempt
has independent SQLite state and retains native failures as provider findings.
"""
import json
import os
from pathlib import Path

import pytest

from p11lab.models import ArtifactRef, RunSpec
from p11lab.run import run_application

CHECKERS = json.loads(os.environ.get('P11LAB_RUSTSSM_CHECKERS', '{}'))
MECHANISMS = ['RSA_PKCS_KEY_PAIR_GEN', 'RSA_PKCS', 'SHA256_HMAC', 'GENERIC_SECRET_KEY_GEN',
              'EC_KEY_PAIR_GEN', 'ECDSA', 'AES_KEY_GEN', 'AES_ECB', 'AES_CBC',
              'AES_CBC_PAD', 'AES_GCM', 'AES_KEY_WRAP_PAD']

PROBE = r'''
import ctypes as C
import hashlib, hmac, json, os, sys
from pathlib import Path
import cryptography
from cryptography.hazmat.backends.openssl.backend import backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding, aes_key_unwrap_with_padding
U, V = C.c_ulong, C.c_void_p
P = C.POINTER
class Attribute(C.Structure):
    _fields_ = [('type', U), ('value', V), ('length', U)]
class Mechanism(C.Structure):
    _fields_ = [('id', U), ('parameter', V), ('length', U)]
class Info(C.Structure):
    _fields_ = [('min', U), ('max', U), ('flags', U)]
class GCM(C.Structure):
    _fields_ = [('iv', V), ('iv_length', U), ('iv_bits', U), ('aad', V), ('aad_length', U), ('tag_bits', U)]
module = os.environ['P11LAB_MODULE']
lib = C.CDLL(module)
calls = []
class NativeError(Exception):
    def __init__(self, operation, rv):
        self.operation, self.rv = operation, rv
        super().__init__(f'{operation}: CK_RV=0x{rv:08x}')
def call(name, types, *args, expected=0):
    fn = getattr(lib, name)
    fn.argtypes, fn.restype = types, U
    rv = fn(*args)
    calls.append({'operation': name, 'rv': f'0x{rv:08x}'})
    if rv != expected:
        raise NativeError(name, rv)
    return rv
class Template:
    def __init__(self, pairs):
        self.values = []
        rows = []
        for kind, value in pairs:
            item = C.c_ubyte(value) if isinstance(value, bool) else U(value) if isinstance(value, int) else C.create_string_buffer(value, len(value))
            self.values.append(item)
            rows.append(Attribute(kind, C.cast(C.pointer(item), V), C.sizeof(item)))
        self.array = (Attribute * len(rows))(*rows)
    def args(self):
        return self.array, U(len(self.array))
def mech(mid, parameter=None):
    return Mechanism(mid, C.cast(C.pointer(parameter), V) if parameter is not None else None, C.sizeof(parameter) if parameter is not None else 0)
def create(pairs):
    t, handle = Template(pairs), U()
    call('C_CreateObject', [U,P(Attribute),U,P(U)], session, *t.args(), C.byref(handle))
    handles.append(handle)
    return handle
def secret(key, kind=0x1f):
    return create([(0,4),(0x100,kind),(0x11,key),(0x108,True),(0x109,True),
                   (0x104,True),(0x105,True),(0x106,True),(0x107,True),(0x162,True),(0x103,False)])
def generate(mid, length):
    t, handle, m = Template([(0,4),(0x161,length),(0x162,True),(0x103,False),(0x108,True)]), U(), mech(mid)
    call('C_GenerateKey', [U,P(Mechanism),P(Attribute),U,P(U)], session,C.byref(m),*t.args(),C.byref(handle))
    handles.append(handle)
    return handle
def pair(ec_key):
    m = mech(0x1040 if ec_key else 0)
    pub = Template([(0x180,bytes.fromhex('06082a8648ce3d030107')),(0x10a,True)]) if ec_key else Template([(0x121,2048),(0x122,b'\x01\x00\x01'),(0x10a,True)])
    priv, a, b = Template([(0x108,True)]), U(), U()
    call('C_GenerateKeyPair', [U,P(Mechanism),P(Attribute),U,P(Attribute),U,P(U),P(U)], session,C.byref(m),*pub.args(),*priv.args(),C.byref(a),C.byref(b))
    handles.extend([a,b])
    return a,b
def attr(handle, kind):
    out = C.create_string_buffer(4096)
    a = Attribute(kind,C.cast(out,V),len(out))
    call('C_GetAttributeValue',[U,U,P(Attribute),U],session,handle,C.byref(a),1)
    assert a.length<=len(out)
    return out.raw[:a.length]
def sign_verify(mid, private, public, data):
    m, signature, length = mech(mid), C.create_string_buffer(4096), U(4096)
    call('C_SignInit',[U,P(Mechanism),U],session,C.byref(m),private)
    call('C_Sign',[U,V,U,V,P(U)],session,data,len(data),signature,C.byref(length))
    signed=signature.raw[:length.value]
    call('C_VerifyInit',[U,P(Mechanism),U],session,C.byref(m),public)
    call('C_Verify',[U,V,U,V,U],session,data,len(data),signed,len(signed))
    changed=bytes([data[0]^1])+data[1:]
    call('C_VerifyInit',[U,P(Mechanism),U],session,C.byref(m),public)
    call('C_Verify',[U,V,U,V,U],session,changed,len(changed),signed,len(signed),expected=0xc0)
    return signed
def encrypt_decrypt(m, handle, data, expected):
    out, length = C.create_string_buffer(4096), U(4096)
    call('C_EncryptInit',[U,P(Mechanism),U],session,C.byref(m),handle)
    call('C_Encrypt',[U,V,U,V,P(U)],session,data,len(data),out,C.byref(length))
    cipher=out.raw[:length.value]
    assert cipher==expected, 'independent ciphertext mismatch'
    length.value=len(out)
    call('C_DecryptInit',[U,P(Mechanism),U],session,C.byref(m),handle)
    call('C_Decrypt',[U,V,U,V,P(U)],session,cipher,len(cipher),out,C.byref(length))
    assert out.raw[:length.value]==data, 'decrypt mismatch'
def wrap(kek, handle):
    m,out,length=mech(0x210a),C.create_string_buffer(4096),U(4096)
    call('C_WrapKey',[U,P(Mechanism),U,U,V,P(U)],session,C.byref(m),kek,handle,out,C.byref(length))
    return out.raw[:length.value]
name, pin_file, output = sys.argv[1:]
session, handles, initialized = U(), [], False
record={'mechanism':name,'module':module,'database':os.environ['RUSTSSM_DATABASE_URL'],
        'oracle':{'cryptography':cryptography.__version__,'openssl':backend.openssl_version_text()},'calls':calls}
status=0
try:
    call('C_Initialize',[V],None)
    initialized=True
    count=U(12)
    advertised=(U*12)()
    call('C_GetMechanismList',[U,P(U),P(U)],0,advertised,C.byref(count))
    ids=[0,1,0x251,0x350,0x1040,0x1041,0x1080,0x1081,0x1082,0x1085,0x1087,0x210a]
    assert count.value==12 and list(advertised)==ids, 'advertisement changed'
    record['advertised_ids']=list(advertised)
    info=Info()
    selected_id=ids[['RSA_PKCS_KEY_PAIR_GEN','RSA_PKCS','SHA256_HMAC','GENERIC_SECRET_KEY_GEN','EC_KEY_PAIR_GEN','ECDSA','AES_KEY_GEN','AES_ECB','AES_CBC','AES_CBC_PAD','AES_GCM','AES_KEY_WRAP_PAD'].index(name)] if name!='AES_GCM_192_GAP' else 0x1087
    call('C_GetMechanismInfo',[U,U,P(Info)],0,selected_id,C.byref(info))
    record['mechanism_info']={'min':info.min,'max':info.max,'flags':info.flags}
    call('C_OpenSession',[U,U,V,V,P(U)],0,6,None,None,C.byref(session))
    pin=bytearray(Path(pin_file).read_bytes().removesuffix(b'\n'))
    try:
        buf=(C.c_ubyte*len(pin)).from_buffer(pin)
        call('C_Login',[U,U,V,U],session,1,buf,len(pin))
    finally:
        pin[:]=b'\0'*len(pin)
    message=b'P11Lab RustSSM independent oracle'
    if name in ('RSA_PKCS_KEY_PAIR_GEN','RSA_PKCS','EC_KEY_PAIR_GEN','ECDSA'):
        is_ec=name in ('EC_KEY_PAIR_GEN','ECDSA')
        public,private=pair(is_ec)
        if is_ec:
            data=hashlib.sha256(message).digest()
            signed=sign_verify(0x1041,private,public,data)
            point=attr(public,0x181)
            assert point[:2]==b'\x04\x41' and len(point)==67
            key=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),point[2:])
            der=utils.encode_dss_signature(int.from_bytes(signed[:32],'big'),int.from_bytes(signed[32:],'big'))
            key.verify(der,data,ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            try:
                key.verify(der,hashlib.sha256(message+b'!').digest(),ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            except cryptography.exceptions.InvalidSignature:
                pass
            else:
                raise AssertionError('altered ECDSA message accepted by oracle')
        else:
            data=bytes.fromhex('3031300d060960864801650304020105000420')+hashlib.sha256(message).digest()
            signed=sign_verify(1,private,public,data)
            key=rsa.RSAPublicNumbers(int.from_bytes(attr(public,0x122),'big'),int.from_bytes(attr(public,0x120),'big')).public_key()
            key.verify(signed,message,padding.PKCS1v15(),hashes.SHA256())
            try:
                key.verify(signed,message+b'!',padding.PKCS1v15(),hashes.SHA256())
            except cryptography.exceptions.InvalidSignature:
                pass
            else:
                raise AssertionError('altered RSA message accepted by oracle')
        record['oracle_result']='original accepted; altered message rejected'
    elif name=='SHA256_HMAC':
        key=b'P11Lab-test-HMAC-key'
        handle=secret(key,0x10)
        signed=sign_verify(0x251,handle,handle,message)
        assert signed==hmac.digest(key,message,'sha256')
        assert signed!=hmac.digest(key,message+b'!','sha256')
        record['oracle_result']='HMAC matches independent original; altered rejected'
    elif name in ('AES_KEY_GEN','GENERIC_SECRET_KEY_GEN'):
        length=32 if name=='AES_KEY_GEN' else 21
        key=generate(0x1080 if name=='AES_KEY_GEN' else 0x350,length)
        kek_bytes=bytes(range(32))
        wrapped=wrap(secret(kek_bytes),key)
        material=aes_key_unwrap_with_padding(kek_bytes,wrapped)
        assert len(material)==length
        assert aes_key_wrap_with_padding(kek_bytes,material)==wrapped
        record['oracle_result']='generated key recovered with independent AES-KWP; correct length'
    elif name=='AES_KEY_WRAP_PAD':
        kek_bytes=bytes(range(32))
        key_bytes=bytes(range(21))
        kek,key=secret(kek_bytes),secret(key_bytes,0x10)
        wrapped=wrap(kek,key)
        assert wrapped==aes_key_wrap_with_padding(kek_bytes,key_bytes)
        m,t,unwrapped=mech(0x210a),Template([(0,4),(0x100,0x10),(0x108,True)]),U()
        call('C_UnwrapKey',[U,P(Mechanism),U,V,U,P(Attribute),U,P(U)],session,C.byref(m),kek,wrapped,len(wrapped),*t.args(),C.byref(unwrapped))
        handles.append(unwrapped)
        signed=sign_verify(0x251,unwrapped,unwrapped,message)
        assert signed==hmac.digest(key_bytes,message,'sha256')
        record['oracle_result']='AES-KWP wrap matches independent bytes; unwrap restores HMAC'
    else:
        key_bytes=bytes(range(24 if name=='AES_GCM_192_GAP' else 32))
        key=secret(key_bytes)
        if name in ('AES_GCM','AES_GCM_192_GAP'):
            iv,aad=bytes(range(12)),b'P11Lab AAD'
            ivbuf,aadbuf=C.create_string_buffer(iv,len(iv)),C.create_string_buffer(aad,len(aad))
            params=GCM(C.cast(ivbuf,V),len(iv),96,C.cast(aadbuf,V),len(aad),128)
            m=mech(0x1087,params)
            expected=AESGCM(key_bytes).encrypt(iv,message,aad)
            encrypt_decrypt(m,key,message,expected)
            changed=expected[:-1]+bytes([expected[-1]^1])
            call('C_DecryptInit',[U,P(Mechanism),U],session,C.byref(m),key)
            out,length=C.create_string_buffer(4096),U(4096)
            call('C_Decrypt',[U,V,U,V,P(U)],session,changed,len(changed),out,C.byref(length),expected=0x40)
        else:
            data=message if name=='AES_CBC_PAD' else b'0123456789abcdef'
            iv=bytes(range(16))
            ivbuf=C.create_string_buffer(iv,len(iv))
            m=mech({'AES_ECB':0x1081,'AES_CBC':0x1082,'AES_CBC_PAD':0x1085}[name],None if name=='AES_ECB' else ivbuf)
            oracle=Cipher(algorithms.AES(key_bytes),modes.ECB() if name=='AES_ECB' else modes.CBC(iv)).encryptor()
            padded=data+bytes([16-len(data)%16])*(16-len(data)%16) if name=='AES_CBC_PAD' else data
            encrypt_decrypt(m,key,data,oracle.update(padded)+oracle.finalize())
        record['oracle_result']='ciphertext matches independent oracle; plaintext recovered'
    record['status']='passed'
except NativeError as error:
    record.update(status='provider-finding',operation=error.operation,native_rv=f'0x{error.rv:08x}',reason=str(error))
    status=3
except AssertionError as error:
    record.update(status='provider-finding',reason=str(error),oracle_mismatch=True)
    status=3
finally:
    if initialized:
        try:
            for handle in reversed(handles):
                call('C_DestroyObject',[U,U],session,handle)
            if session.value:
                call('C_CloseSession',[U],session)
            call('C_Finalize',[V],None)
        except NativeError as error:
            record.update(cleanup_native_error=str(error))
            status=3
    Path(output).write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record))
sys.exit(status)
'''


@pytest.mark.parametrize('mechanism', MECHANISMS + ['AES_GCM_192_GAP'])
def test_each_advertised_mechanism_observation(mechanism, tmp_path):
    if 'rolling' not in CHECKERS:
        pytest.skip('explicit installed RustSSM derivative required')
    evidence = os.environ.get('P11LAB_RUSTSSM_EVIDENCE')
    root = Path(evidence) / 'mechanisms' / mechanism if evidence else tmp_path
    root.mkdir(parents=True, exist_ok=True)
    caller = root / 'caller'
    caller.mkdir()
    pin, so = root / 'pin', root / 'so'
    pin.write_bytes(b'1234')
    so.write_bytes(b'12345678')
    pin.chmod(0o600)
    so.chmod(0o600)
    image = CHECKERS['rolling']
    ref = ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')
    try:
        spec = RunSpec('rustssm', 'rolling', 'direct', ref, 'provider', None, None,
                       ('python', '-c', PROBE, mechanism, '/run/p11lab-input/P11LAB_PIN_FILE',
                        '/p11lab-output/observation.json'),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so)},
                       root / 'output', caller, 120)
        result = run_application(spec)
        assert not result.lifecycle_errors and not result.cleanup_errors, result
        record = json.loads((spec.output_dir / 'observation.json').read_text())
        assert record['mechanism'] == mechanism and len(record['advertised_ids']) == 12
        assert 'cleanup_native_error' not in record
        if mechanism == 'AES_GCM_192_GAP':
            assert record['status'] == 'provider-finding'
            assert record['operation'] == 'C_EncryptInit' and record['native_rv'] == '0x00000062'
            assert result.app_returncode == 3
        else:
            # A finding is retained as completed evidence, never converted to a
            # functional pass. The task report must count statuses separately.
            assert record['status'] in {'passed', 'provider-finding'}
            assert result.app_returncode == (0 if record['status'] == 'passed' else 3)
        print(f"mechanism {mechanism}: {record['status']} {record.get('reason', record.get('oracle_result'))}")
    finally:
        pin.unlink(missing_ok=True)
        so.unlink(missing_ok=True)
