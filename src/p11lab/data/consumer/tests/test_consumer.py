# SPDX-License-Identifier: Apache-2.0
"""Standalone consumer contracts. Run: python3 -m unittest discover -s tests -v."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MESSAGE = b'P11Lab independent PKCS11 smoke v1\n'
SOFTHSM = Path('/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so')


class ConsumerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='p11lab-consumer-test-')
        cls.work = Path(cls.temp.name)
        cls.binary = cls.work / 'p11lab-smoke'
        cls.pin = cls.work / 'pin bytes'
        cls.available = (ROOT / 'smoke.c').exists() and (ROOT / 'p256.c').exists()
        if cls.available:
            subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic',
                            str(ROOT / 'smoke.c'), str(ROOT / 'p256.c'), '-ldl',
                            '-o', str(cls.binary)], check=True)
            lib = cls.work / 'p256.so'
            subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic',
                            '-shared', '-fPIC', str(ROOT / 'p256.c'), '-o', str(lib)], check=True)
            cls.der = ctypes.CDLL(str(lib))
            cls.stub = cls.work / 'provider.so'
            if (ROOT / 'tests/provider_fixture.c').exists():
                subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic',
                                '-shared', '-fPIC', str(ROOT / 'tests/provider_fixture.c'),
                                '-o', str(cls.stub)], check=True)
            cls.der.p11_ec_point.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p]
            cls.der.p11_signature_der.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                                  ctypes.POINTER(ctypes.c_size_t)]
        cls.real = cls.available and SOFTHSM.exists() and bool(shutil.which('softhsm2-util'))
        if cls.real:
            tokens = cls.work / 'tokens'
            tokens.mkdir()
            conf = cls.work / 'softhsm.conf'
            conf.write_text(f'directories.tokendir = {tokens}\nobjectstore.backend = file\nlog.level = ERROR\n')
            cls.env = dict(os.environ, SOFTHSM2_CONF=str(conf))
            subprocess.run(['softhsm2-util', '--init-token', '--free', '--label', 'Smoke token',
                            '--so-pin', '87342591', '--pin', '62197643'], env=cls.env,
                           capture_output=True, check=True)
            cls.pin = cls.work / 'pin bytes'
            cls.pin.write_bytes(b'62197643')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def run_smoke(self, *args, **kwargs):
        self.assertTrue(self.available, 'independent consumer implementation is missing')
        return subprocess.run([str(self.binary), *map(str, args)], capture_output=True, text=True,
                              env=kwargs.get('env'))

    def real_smoke(self, name, *args):
        self.assertTrue(self.available, 'independent consumer implementation is missing')
        if not self.real:
            self.skipTest('host SoftHSM unavailable')
        output = self.work / name
        return self.run_smoke('--module', SOFTHSM, '--token-label', 'Smoke token',
                              '--output', output, '--key-mode', 'generated', *args, env=self.env), output

    def test_windows_sdk_interface_macro_does_not_break_consumer_compile(self):
        self.assertTrue(self.available, 'independent consumer implementation is missing')
        result = subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic',
                                 '-fsyntax-only', '-Dinterface=struct', str(ROOT / 'smoke.c')],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_and_bad_module_do_not_expose_credentials(self):
        self.assertEqual(self.run_smoke('--help').returncode, 0)
        pin = self.work / 'credential-file'
        pin.write_bytes(b'PIN_CONTENT_NOT_FOR_LOGS')
        result = self.run_smoke('--module', self.work / 'missing module.so', '--token-label', 't',
                                '--pin-file', pin, '--output', self.work / 'bad', '--key-mode', 'generated')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('PIN_CONTENT_NOT_FOR_LOGS', result.stdout + result.stderr)

    def test_argument_selection_contract(self):
        for args in [[], ['--unknown'], ['--module'],
                     ['--module','x','--token-label','t','--output','o','--key-mode','existing'],
                     ['--module','x','--token-label','t','--output','o','--key-mode','bad'],
                     ['--module','x','--token-label','t','--output','o','--key-mode','existing','--key-id','zz']]:
            with self.subTest(args=args):
                self.assertNotEqual(self.run_smoke(*args).returncode, 0)

    def test_ec_point_der_rejects_noncanonical_and_trailing_encodings(self):
        self.assertTrue(self.available, 'independent consumer implementation is missing')
        point = b'\x04' + bytes(range(1,65))
        out = ctypes.create_string_buffer(65)
        self.assertEqual(self.der.p11_ec_point(b'\x04\x41'+point,67,out),1)
        self.assertEqual(out.raw,point)
        for blob in [point, b'\x04\x81\x41'+point, b'\x04\x80'+point+b'\0\0',
                     b'\x04\x41'+point+b'\0', b'\x04\x42'+point, b'\x03\x41'+point,
                     b'\x04\x41\x02'+point[1:], b'\x04\xff', b'\x04', b'']:
            with self.subTest(blob=blob[:4]):
                self.assertEqual(self.der.p11_ec_point(blob,len(blob),out),0)

    def test_signature_der_handles_sign_bit_zero_and_bounds(self):
        self.assertTrue(self.available, 'independent consumer implementation is missing')
        fixtures = [(bytes(31)+b'\x01'+bytes(31)+b'\x02',bytes.fromhex('3006020101020102')),
                    (b'\x80'+bytes(31)+bytes(31)+b'\x01',b'\x30\x26\x02\x21\0\x80'+bytes(31)+b'\x02\x01\x01')]
        for raw,want in fixtures:
            out = ctypes.create_string_buffer(72)
            size = ctypes.c_size_t(72)
            self.assertEqual(self.der.p11_signature_der(raw,len(raw),out,ctypes.byref(size)),1)
            self.assertEqual(out.raw[:size.value],want)
        for raw in [bytes(64),bytes(63),bytes(65),bytes(32)+bytes(31)+b'\1',b'\xff'*64]:
            out = ctypes.create_string_buffer(72)
            size = ctypes.c_size_t(72)
            self.assertEqual(self.der.p11_signature_der(raw,len(raw),out,ctypes.byref(size)),0)
        out = ctypes.create_string_buffer(72)
        size = ctypes.c_size_t(7)
        raw = bytes(31)+b'\1'+bytes(31)+b'\2'
        self.assertEqual(self.der.p11_signature_der(raw,64,out,ctypes.byref(size)),0)

    def test_real_generated_signature_independent_openssl_and_no_overwrite(self):
        result, output = self.real_smoke('successful output with spaces', '--pin-file', self.pin)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((output/'message.bin').read_bytes(),MESSAGE)
        self.assertEqual((output/'digest.bin').read_bytes(),hashlib.sha256(MESSAGE).digest())
        self.assertEqual(len((output/'signature.raw').read_bytes()),64)
        record=json.loads((output/'result.json').read_text())
        self.assertEqual(record['mechanism'],'CKM_ECDSA')
        verified=subprocess.run([sys.executable,str(ROOT/'verify.py'),str(output)],capture_output=True,text=True)
        self.assertEqual(verified.returncode,0,verified.stderr)
        self.assertIn('altered message rejected',verified.stdout)
        again, _ = self.real_smoke('successful output with spaces', '--pin-file', self.pin)
        self.assertNotEqual(again.returncode,0)
        (output/'message.bin').write_bytes(MESSAGE+b'wrong')
        bad=subprocess.run([sys.executable,str(ROOT/'verify.py'),str(output)],capture_output=True,text=True)
        self.assertNotEqual(bad.returncode,0)

    def test_absent_empty_and_wrong_pin_preserve_native_error(self):
        absent,_=self.real_smoke('absent-pin')
        self.assertNotEqual(absent.returncode,0)
        self.assertIn('PIN file required',absent.stderr)
        for name,content in [('empty',b''),('wrong',b'87651234')]:
            pin=self.work/(name+'.pin');pin.write_bytes(content)
            result,_=self.real_smoke(name+'-pin','--pin-file',pin)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('C_Login: CK_RV=0x000000a0',result.stderr)
            if content: self.assertNotIn(content.decode(),result.stdout+result.stderr)

    def test_declared_spki_rejects_wrong_curve_compressed_and_trailing_input(self):
        self.assertTrue(self.available, 'independent consumer implementation is missing')
        point = b'\x04' + bytes(range(1,65))
        prefix = bytes.fromhex('3059301306072a8648ce3d020106082a8648ce3d030107034200')
        out = ctypes.create_string_buffer(65)
        valid = prefix + point
        self.assertEqual(self.der.p11_spki(valid,len(valid),out),1)
        self.assertEqual(out.raw,point)
        for blob in [valid+b'\0',valid[:-1],prefix+b'\x02'+point[1:],
                     valid[:22]+b'\x08'+valid[23:],b'']:
            self.assertEqual(self.der.p11_spki(blob,len(blob),out),0)

    def test_existing_key_by_id_and_declared_public_input(self):
        self.assertTrue(self.available, 'independent consumer implementation is missing')
        if not self.real or not shutil.which('pkcs11-tool'):
            self.skipTest('host provisioning tool unavailable')
        # Two real keys ensure that ignoring CKA_ID cannot select an arbitrary key.
        for key_id in ['42', '43']:
            provision=subprocess.run(['pkcs11-tool','--module',str(SOFTHSM),'--token-label','Smoke token',
                                      '--login','--pin','62197643','--keypairgen','--key-type','EC:prime256v1',
                                      '--id',key_id],env=self.env,capture_output=True,text=True)
            self.assertEqual(provision.returncode,0,provision.stderr)
        base=['--module',SOFTHSM,'--token-label','Smoke token','--pin-file',self.pin,
              '--key-mode','existing','--key-id','42']
        output=self.work/'existing-key'
        result=self.run_smoke(*base,'--output',output,env=self.env)
        self.assertEqual(result.returncode,0,result.stderr)
        check=subprocess.run([sys.executable,str(ROOT/'verify.py'),str(output)],capture_output=True,text=True)
        self.assertEqual(check.returncode,0,check.stderr)
        second=self.work/'existing-declared'
        result=self.run_smoke(*base,'--output',second,'--public-key',output/'public-key.der',env=self.env)
        self.assertEqual(result.returncode,0,result.stderr)
        check=subprocess.run([sys.executable,str(ROOT/'verify.py'),str(second)],capture_output=True,text=True)
        self.assertEqual(check.returncode,0,check.stderr)
        record=json.loads((second/'result.json').read_text())
        self.assertEqual(record['public_key_source'],'declared-input')
        # A second invocation proves existing objects survived session/finalize cleanup.
        base[-1] = '44'
        missing=self.run_smoke(*base,'--output',self.work/'missing-key',env=self.env)
        self.assertNotEqual(missing.returncode,0)
        self.assertIn('no EC private key',missing.stderr)

    def test_paginated_duplicate_key_is_rejected(self):
        self.assertTrue(self.available, 'independent consumer implementation is missing')
        self.assertTrue(self.stub.exists(), 'native provider fixture is missing')
        env=dict(os.environ, P11_FIXTURE_MODE='duplicate-key')
        result=self.run_smoke('--module',self.stub,'--token-label','Fixture','--output',self.work/'dup-key',
                              '--key-mode','existing','--key-id','42',env=env)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('multiple EC objects',result.stderr)

    def test_native_failures_and_malformed_outputs_are_not_retried(self):
        self.assertTrue(self.available, 'independent consumer implementation is missing')
        self.assertTrue(self.stub.exists(), 'native provider fixture is missing')
        for mode,want in [('sign-error','C_Sign: CK_RV=0x00000030'),
                          ('sign-oversize','exactly 64 bytes'),
                          ('attribute-oversize','attribute unavailable or exceeds bound'),
                          ('cleanup-error','C_CloseSession(cleanup): CK_RV=0x00000006'),
                          ('attribute-growth','attribute length exceeds supplied capacity'),
                          ('point-malformed','invalid DER OCTET STRING'),
                          ('sign-buffer-too-small','C_Sign: CK_RV=0x00000150'),
                          ('sign-and-cleanup-error','C_Sign: CK_RV=0x00000030')]:
            with self.subTest(mode=mode):
                log=self.work/(mode+'.calls')
                env=dict(os.environ,P11_FIXTURE_MODE=mode,P11_FIXTURE_LOG=str(log))
                result=self.run_smoke('--module',self.stub,'--token-label','Fixture',
                                      '--output',self.work/mode,'--key-mode','generated',env=env)
                self.assertNotEqual(result.returncode,0)
                self.assertIn(want,result.stderr)
                if mode == 'sign-and-cleanup-error':
                    self.assertIn('C_CloseSession(cleanup): CK_RV=0x00000006',result.stderr)
                calls=log.read_text().splitlines()
                self.assertLessEqual(calls.count('Sign'),1)
                self.assertEqual(calls.count('GenerateKeyPair'),1)
                self.assertNotIn('Login',calls)
                self.assertIn('CloseSession',calls)
                self.assertIn('Finalize',calls)
                self.assertFalse((self.work/mode/'result.json').exists())

    def test_empty_pin_is_a_nonnull_native_login_argument(self):
        self.assertTrue(self.available, 'independent consumer implementation is missing')
        self.assertTrue(self.stub.exists(), 'native provider fixture is missing')
        pin=self.work/'fixture-empty.pin';pin.write_bytes(b'')
        env=dict(os.environ,P11_FIXTURE_MODE='empty-pin')
        result=self.run_smoke('--module',self.stub,'--token-label','Fixture','--pin-file',pin,
                              '--output',self.work/'fixture-empty','--key-mode','generated',env=env)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_signing_only_provider_accepts_existing_key_readonly_session(self):
        self.assertTrue(self.available, 'independent consumer implementation is missing')
        env=dict(os.environ,P11_FIXTURE_MODE='readonly-existing')
        result=self.run_smoke('--module',self.stub,'--token-label','Fixture','--output',self.work/'readonly-key',
                              '--key-mode','existing','--key-id','42',env=env)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_discovery_native_error_has_no_legacy_fallback(self):
        self.assertTrue(self.available, 'independent consumer implementation is missing')
        env=dict(os.environ,P11_FIXTURE_MODE='interface-error')
        result=self.run_smoke('--module',self.stub,'--token-label','Fixture','--output',self.work/'interface-error',
                              '--key-mode','generated',env=env)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('C_GetInterface: CK_RV=0x00000054',result.stderr)

    def test_missing_and_duplicate_token_are_errors(self):
        self.assertTrue(self.available, 'independent consumer implementation is missing')
        if not self.real: self.skipTest('host SoftHSM unavailable')
        base=['--module',SOFTHSM,'--output',self.work/'selection','--key-mode','generated']
        missing=self.run_smoke(*base,'--token-label','nonexistent',env=self.env)
        self.assertNotEqual(missing.returncode,0)
        self.assertIn('no token',missing.stderr)
        for _ in range(2):
            subprocess.run(['softhsm2-util','--init-token','--free','--label','Duplicate',
                            '--so-pin','87342591','--pin','62197643'],env=self.env,capture_output=True,check=True)
        base[3] = self.work/'duplicate-selection'
        duplicate=self.run_smoke(*base,'--token-label','Duplicate',env=self.env)
        self.assertNotEqual(duplicate.returncode,0)
        self.assertIn('multiple tokens',duplicate.stderr)


if __name__ == '__main__':
    unittest.main()
