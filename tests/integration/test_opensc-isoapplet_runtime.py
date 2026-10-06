# SPDX-License-Identifier: Apache-2.0
"""opensc-isoapplet acceptance, with pinned channel images and no implicit builds.

P11LAB_OPENSC_ISOAPPLET_{IMAGES,CONSUMERS,CHECKERS,PROXIES,CLIENTS} contain
explicit JSON channel maps; CALLER is an independent C caller image and
EVIDENCE is a fresh output directory. The emulator is RAM-only: every
init, health and exec provisions a fresh card with caller credentials
(pty-driven pkcs15-init create plus in-process on-card keygen) and
proves it with a native census; nothing persists across operations and
re-provisioning is explicit documented semantics, never a silent reset.
The marker binds the non-secret configuration only.

The general-token profile is falsified natively (the card offers no raw
CKM_ECDSA, so P-256 ECDSA consumers cannot run). The isoapplet-signing
profile holds narrowly: on-card RSA-2048 plus P-256/P-384 keygen,
RSA-2048 SHA256 sign with on-card verify plus raw RSA-PKCS sign with
host-side oracle only (the generated-mode raw signature has no
oracle check), P-256 ECDSA_SHA1 sign with independent oracle,
SHA-256 digests, session AES import/create/destroy-by-handle with
the driver-dropped label (find-by-label reads empty before and
after destroy) and token DATA lifecycle.
"""
from dataclasses import replace
import base64
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
from p11lab.catalog import load_environment, validate_build_inputs
from p11lab.identity import artifact_key
from p11lab.models import ArtifactRef, RunSpec
from p11lab.run import run_application

MODULE = '/usr/local/lib/p11lab/opensc-pkcs11.so'
LABEL = 'JavaCard isoApplet'
IMAGES = json.loads(os.environ.get('P11LAB_OPENSC_ISOAPPLET_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_OPENSC_ISOAPPLET_CONSUMERS', '{}'))
CHECKERS = json.loads(os.environ.get('P11LAB_OPENSC_ISOAPPLET_CHECKERS', '{}'))
DAEMONS = json.loads(os.environ.get('P11LAB_OPENSC_ISOAPPLET_PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_OPENSC_ISOAPPLET_CLIENTS', '{}'))
CALLER = os.environ.get('P11LAB_OPENSC_ISOAPPLET_CALLER', '')
COMMANDS = itertools.count()




def docker(*args, check=True, env=None):
    argv = ['docker', *args]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=300, env=os.environ | (env or {}))
    evidence = os.environ.get('P11LAB_OPENSC_ISOAPPLET_EVIDENCE')
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
        pytest.skip('explicit opensc-isoapplet runtime IDs required')
    channel = request.param
    root = Path(os.environ.get('P11LAB_OPENSC_ISOAPPLET_EVIDENCE', str(tmp_path))) / request.node.name
    root.mkdir(parents=True, exist_ok=False)
    state = root / 'state'
    state.mkdir(mode=0o700)
    secrets = root / 'secrets'
    secrets.mkdir(mode=0o700)
    for name, value in [('pin', b'654321'), ('so', b'1234567812345678')]:
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
    evidence = os.environ.get('P11LAB_OPENSC_ISOAPPLET_EVIDENCE')
    root = Path(evidence) / name / channel if evidence else tmp_path
    root.mkdir(parents=True, exist_ok=True)
    caller = root / 'caller'
    caller.mkdir()
    pin, so = root / 'pin', root / 'so'
    pin.write_bytes(b'654321')
    so.write_bytes(b'1234567812345678')
    pin.chmod(0o600)
    so.chmod(0o600)
    return root, caller, pin, so


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_installed_checker_observations(channel, tmp_path):
    if channel not in CHECKERS:
        pytest.skip('explicit installed opensc-isoapplet checker derivative required')
    from p11lab.checker import run_checker
    root, caller, pin, so = lane_root('direct-checker', channel, tmp_path)
    try:
        spec = RunSpec('opensc-isoapplet', channel, 'direct', as_ref(CHECKERS[channel]), 'provider', None, None, (),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so), 'P11LAB_LABEL': LABEL}, root / 'output', caller, 1200)
        result = run_checker(spec, 'smoke-v1')
        assert not result.cleanup_errors
        record = json.loads((spec.output_dir / 'checker/checker-receipt.json').read_text())
        assert len(record['nodes']) == 23
        assert record['token']['native_slot_id'] == 0 and record['token']['token_present_index'] == 0
        assert record['token']['label'] == LABEL
        # A completed provider finding is valid evidence, never normalized.
        print(f'checker direct/{channel}: exit={result.exit_code} evidence={record["evidence"]}')
        summary = record['evidence']['summary']
        assert summary['failed'] == 0 and summary['error'] == 0
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
        pytest.skip('explicit pinned opensc-isoapplet daemon, client bundle and caller required')
    root, caller, pin, so = lane_root('proxy-crypto', channel, tmp_path)
    try:
        bundle = Path(CLIENTS[channel])
        client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
        spec = RunSpec('opensc-isoapplet', channel, 'proxy', as_ref(DAEMONS[channel]), 'container', as_ref(CALLER), client,
                       ('p11lab-rsa-probe', 'rsa-existing', '/run/p11lab-client/libpkcs11_proxy_ng_shim.so',
                        '/run/p11lab-input/P11LAB_PIN_FILE', '/p11lab-output/crypto'),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so)}, root / 'output', caller, 600)
        result = run_application(spec)
        assert result.app_returncode == 0, result
        assert not result.cleanup_errors
        assert (spec.output_dir / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
        oracle_rsa_sha256(spec.output_dir / 'crypto')
        oracle_rsa_raw(spec.output_dir / 'crypto')
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
    spec = load_environment('opensc-isoapplet', channel)
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    expected = {'release': '19868984dc4dc697af6a86d65ab32a1f19a43ea4',
                'rolling': '4f3ff5111314bde380c3d4e9e25bb1fa0169196d'}
    assert inputs['sources'][0]['revision'] == expected[channel]
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['openssl']['from_source'] is False
    assert inputs['features']['token_slot'] == 0 and inputs['features']['token_present_index'] == 0
    assert inputs['features']['token_label'] == LABEL and inputs['features']['token_flags'] == '0x40d'
    assert inputs['features']['pinlen_min'] == 4 and inputs['features']['pinlen_max'] == 16
    assert inputs['features']['puklen'] == 16
    assert inputs['features']['user_retries'] == 3
    assert inputs['features']['keys'] == '01:p256,02:rsa2048,03:p384'
    assert inputs['features']['upstream_version'] == {'release': '0.27.1', 'rolling': '0.27.1-339-g4f3ff51'}[channel]
    assert spec['services'] == ['jcardsim', 'pcscd', 'vpcd']
    assert inputs['patches'] == []
    assert [d['id'] for d in inputs['dependencies']] == ['isoapplet', 'vsmartcard', 'jcardsim-src']
    assert inputs['features']['isoapplet']['revision'] == '6810ffc269dad4d844cad899dec6a0d7ca3241db'
    assert inputs['features']['vsmartcard']['revision'] == '82bc5ad066b26ee057d2af200c1a66e3a65a9743'
    assert inputs['features']['java']['jar_sha256'] == 'db6de7ffde71651c45d00df7e160771685cec3e14e444bf36b796658d289942f'
    assert inputs['features']['java']['jar_size'] == 1202576
    assert inputs['features']['extraction']['whole_count'] == 7
    other = 'rolling' if channel == 'release' else 'release'
    assert artifact_key('runtime', inputs) != artifact_key('runtime', runtime_inputs(load_environment('opensc-isoapplet', other)))


def snapshot(state):
    return {str(p.relative_to(state)): ('symlink', os.readlink(p)) if p.is_symlink()
            else ('file', hashlib.sha256(p.read_bytes()).hexdigest()) if p.is_file()
            else ('directory', None) for p in state.rglob('*')}


def test_native_lifecycle_credentials_and_argv(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    consumer = CONSUMERS[channel]
    assert json.loads(docker('run', '--rm', image, 'describe').stdout)['module_path'] == MODULE
    assert docker(*base, image, 'init', check=False).returncode != 0
    assert list(state.iterdir()) == []
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    # The card is RAM-only, so a repeated init provisions a fresh card with
    # the presented credentials exactly like the first one; only the
    # non-secret configuration marker is comparable across provisions.
    (secrets / 'pin').write_bytes(b'112233')
    (secrets / 'so').write_bytes(b'445566778899aabb')
    docker(*base, *controls, image, 'init')
    assert snapshot(state) == before
    # The fresh card answers to the new credentials and rejects the old ones.
    (secrets / 'oldpin').write_bytes(b'654321')
    (secrets / 'oldpin').chmod(0o600)
    fresh = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-rsa-probe',
                   'login', MODULE, '/run/secrets/pin')
    assert 'login rv=0x0' in fresh.stdout
    stale = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-rsa-probe',
                   'login', MODULE, '/run/secrets/oldpin', check=False)
    assert stale.returncode != 0 and 'C_Login: CK_RV=0x000000a0' in stale.stderr
    (secrets / 'pin').write_bytes(b'654321')
    (secrets / 'so').write_bytes(b'1234567812345678')
    health = docker(*base, *controls, image, 'health')
    assert 'native_slot=0 token_present_index=0 label=JavaCard isoApplet' in health.stdout
    assert snapshot(state) == before
    # Health re-provisions too, so it consumes credentials as well.
    assert docker(*base, image, 'health', check=False).returncode != 0
    assert snapshot(state) == before
    changed = docker(*base, *controls, '-e', 'P11LAB_LABEL=different', image, 'init', check=False)
    assert changed.returncode != 0 and 'token label is fixed' in changed.stderr
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\\n" "$P11LAB_MODULE" "$1"; exit 37', 'caller',
                    'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == [MODULE, 'literal $argument with spaces']
    assert 'pin' not in (state / 'opensc-isoapplet/complete').read_text().lower()
    assert (state / 'opensc-isoapplet/complete').is_file() and (state / 'opensc-isoapplet/lease').is_file()
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'for t in cc gcc make cmake python3 pkcs11-tool openssl javac mvn; do command -v $t; done; exit 0').stdout == ''
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'command -v pkcs15-init').stdout.split() == ['/usr/local/bin/pkcs15-init']
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'test -x /usr/sbin/pcscd && test -x /usr/lib/jvm/java-21-openjdk-amd64/bin/java && echo PRESENT').stdout.strip() == 'PRESENT'
    assert snapshot(state) == before
    # Credentials in the native adapter come from either scalar environment
    # or private files. Docker argv and durable command records omit values.
    other = root / 'scalar-state'
    other.mkdir(mode=0o700)
    scalar_base = [x.replace(f'src={state},', f'src={other},') for x in base]
    docker(*scalar_base, '-e', 'P11LAB_PIN', '-e', 'P11LAB_SO_PIN', image, 'init',
           env={'P11LAB_PIN': '246810', 'P11LAB_SO_PIN': '0011223344556677'})
    # Health re-provisions the fresh card, so scalar credentials work here too.
    docker(*scalar_base, '-e', 'P11LAB_PIN', '-e', 'P11LAB_SO_PIN', image, 'health',
           env={'P11LAB_PIN': '246810', 'P11LAB_SO_PIN': '0011223344556677'})


def _der_len(n):
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(raw)]) + raw


def _der_int(x):
    x = x.lstrip(b'\x00') or b'\x00'
    if x[0] & 0x80:
        x = b'\x00' + x
    return b'\x02' + _der_len(len(x)) + x


def _rsa_spki(mod, exp):
    key = _der_int(mod) + _der_int(exp)
    key = b'\x30' + _der_len(len(key)) + key
    alg = b'\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00'
    body = alg + b'\x03' + _der_len(len(key) + 1) + b'\x00' + key
    return b'\x30' + _der_len(len(body)) + body


def _ec_spki_p256(point):
    assert point[0] == 0x04 and len(point) == 65, (len(point), point[:4].hex())
    alg = b'\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07'
    body = alg + b'\x03' + _der_len(len(point) + 1) + b'\x00' + point
    return b'\x30' + _der_len(len(body)) + body


def _pem(der, tag):
    text = base64.encodebytes(der).decode().strip()
    return f'-----BEGIN {tag}-----\n{text}\n-----END {tag}-----\n'.encode()


def _openssl(*args):
    return subprocess.run(['openssl', *args], capture_output=True, text=True)


def oracle_rsa_sha256(output):
    # The SPKI is built locally from raw exported bytes, never trusting the
    # provider's encoding; OpenSSL is the independent verifier.
    mod, exp = (output / 'rsa.mod').read_bytes(), (output / 'rsa.exp').read_bytes()
    assert len(mod) == 256
    (output / 'rsa.pem').write_bytes(_pem(_rsa_spki(mod, exp), 'PUBLIC KEY'))
    good = _openssl('dgst', '-sha256', '-verify', str(output / 'rsa.pem'),
                    '-signature', str(output / 'rsa-sha256.sig'), str(output / 'msg'))
    assert 'Verified OK' in good.stdout + good.stderr, good.stderr
    altered = output / 'msg.alt'
    msg = (output / 'msg').read_bytes()
    altered.write_bytes(b'X' + msg[1:])
    bad = _openssl('dgst', '-sha256', '-verify', str(output / 'rsa.pem'),
                   '-signature', str(output / 'rsa-sha256.sig'), str(altered))
    assert 'Verified OK' not in bad.stdout + bad.stderr
    (output / 'oracle-rsa.txt').write_text(good.stdout + bad.stdout + 'altered message rejected\n')


def oracle_rsa_raw(output):
    recovered = subprocess.run(['openssl', 'rsautl', '-verify', '-pubin', '-inkey', str(output / 'rsa.pem'),
                                '-in', str(output / 'rsa-raw.sig')], capture_output=True)
    expect = bytes.fromhex('3031300d060960864801650304020105000420') + hashlib.sha256((output / 'msg').read_bytes()).digest()
    assert recovered.returncode == 0 and recovered.stdout == expect


def oracle_ec_sha1(output):
    wrapped = (output / 'ec.point').read_bytes()
    assert wrapped[0] == 0x04
    hdr = 2 + (wrapped[1] & 0x7F) if wrapped[1] & 0x80 else 2
    (output / 'ec.pem').write_bytes(_pem(_ec_spki_p256(wrapped[hdr:]), 'PUBLIC KEY'))
    raw = (output / 'ec-sha1.sig').read_bytes()
    assert len(raw) == 64
    # PKCS#11 ECDSA signatures are raw R||S; OpenSSL verifies DER.
    half = len(raw) // 2
    body = _der_int(raw[:half]) + _der_int(raw[half:])
    (output / 'ec-sha1.der').write_bytes(b'\x30' + _der_len(len(body)) + body)
    good = _openssl('dgst', '-sha1', '-verify', str(output / 'ec.pem'),
                    '-signature', str(output / 'ec-sha1.der'), str(output / 'msg'))
    assert 'Verified OK' in good.stdout + good.stderr, good.stderr
    altered = output / 'msg.alt'
    msg = (output / 'msg').read_bytes()
    altered.write_bytes(b'X' + msg[1:])
    bad = _openssl('dgst', '-sha1', '-verify', str(output / 'ec.pem'),
                   '-signature', str(output / 'ec-sha1.der'), str(altered))
    assert 'Verified OK' not in bad.stdout + bad.stderr
    (output / 'oracle-ec.txt').write_text(good.stdout + bad.stdout + 'altered message rejected\n')


def oracle_digest(output):
    assert hashlib.sha256((output / 'msg').read_bytes()).digest() == (output / 'msg.sha256').read_bytes()


def test_application_crypto_isolation_and_native_errors(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
              'P11LAB_SO_PIN_FILE': str(secrets / 'so')}
    spec = RunSpec('opensc-isoapplet', channel, 'direct', as_ref(CONSUMERS[channel]), 'provider', None, None,
                   ('p11lab-rsa-probe', 'rsa-existing', MODULE, '/run/p11lab-input/P11LAB_PIN_FILE', '/p11lab-output/crypto'),
                   inputs, root / 'existing-template', root, 300)
    public = []
    for number in range(2):
        # Every operation provisions a fresh card: reopening never resumes
        # a previous card. Freshness is proven by object absence (below),
        # not by key uniqueness: this emulator's keygen is deterministic.
        reopened = replace(spec, output_dir=root / f'reopen-{number}')
        result = run_application(reopened)
        assert result.exit_code == 0 and not result.cleanup_errors, result
        crypto = reopened.output_dir / 'crypto'
        oracle_rsa_sha256(crypto)
        oracle_rsa_raw(crypto)
        assert 'oncard-verify=0x0' in (crypto / 'result.txt').read_text()
        public.append((crypto / 'rsa.mod').read_bytes())
    # Frozen jcardsim 3.0.6.0 generates every on-card key from a fresh
    # UNSEEDED BouncyCastle DigestRandomGenerator (KeyPairImpl field
    # `rnd = new SecureRandomNullProvider()`; the randomdata.seed/secure
    # knobs govern RandomData only, never keygen): independent fresh
    # cards carry byte-identical key material -- proven across
    # operations, states, channels, and provisioned-vs-session keygen
    # (modulus sha256 a3cd738f... in 7 independent observations, both
    # channels). Key uniqueness across operations is an explicitly
    # unqualified surface of this emulator, never a freshness signal.
    assert public[0] == public[1]
    made = replace(spec, output_dir=root / 'session-rsa',
                   argv=('p11lab-rsa-probe', 'rsa-generated', MODULE, '/run/p11lab-input/P11LAB_PIN_FILE', '/p11lab-output/crypto'))
    result = run_application(made)
    assert result.exit_code == 0 and not result.cleanup_errors, result
    generated = made.output_dir / 'crypto'
    oracle_rsa_sha256(generated)
    assert 'destroy-pub=0x0' in (generated / 'result.txt').read_text()
    # Session keygen draws from its own fresh unseeded DRBG: the same
    # deterministic key as the provisioned pair (proven G1==E1 natively).
    assert (generated / 'rsa.mod').read_bytes() == public[0]
    sha1 = replace(spec, output_dir=root / 'ec-sha1',
                   argv=('p11lab-rsa-probe', 'ec-sha1', MODULE, '/run/p11lab-input/P11LAB_PIN_FILE', '/p11lab-output/crypto'))
    result = run_application(sha1)
    assert result.exit_code == 0 and not result.cleanup_errors, result
    oracle_ec_sha1(sha1.output_dir / 'crypto')
    dgst = replace(spec, output_dir=root / 'digest',
                   argv=('p11lab-rsa-probe', 'digest', MODULE, '/run/p11lab-input/P11LAB_PIN_FILE', '/p11lab-output/crypto'))
    result = run_application(dgst)
    assert result.exit_code == 0 and not result.cleanup_errors, result
    oracle_digest(dgst.output_dir / 'crypto')
    applied = replace(spec, output_dir=root / 'provision-native',
                      argv=('p11lab-rsa-probe', 'rsa-provision', MODULE, '/run/p11lab-input/P11LAB_PIN_FILE',
                           '/p11lab-output/crypto', '42'))
    created = run_application(applied)
    assert created.exit_code == 0 and not created.cleanup_errors, created
    oracle_rsa_sha256(applied.output_dir / 'crypto')
    assert 'roundtrip=1' in (applied.output_dir / 'crypto/result.txt').read_text()
    # RAM-only isolation: the id-42 pair existed within that operation
    # (roundtrip=1 above); the next operation provisions a fresh card
    # without it. A fresh census is exactly objects=4 (3 provisioned
    # public keys + the PKCS#15 auth object); a surviving app pair
    # would census 6.
    fresh = docker(*base, *controls, image, 'health')
    assert 'objects=4' in fresh.stdout
    (secrets / 'wrong').write_bytes(b'bad-pin')
    (secrets / 'wrong').chmod(0o600)
    failed = docker(*base, *controls, CONSUMERS[channel], 'exec', '--', 'p11lab-rsa-probe',
                    'login', MODULE, '/run/secrets/wrong', check=False)
    assert failed.returncode != 0
    assert 'C_Login: CK_RV=0x000000a0' in failed.stderr
    other = root / 'other-state'
    other.mkdir(mode=0o700)
    separate = run_application(replace(spec, inputs=inputs | {'P11LAB_STATE_DIR': str(other)}, output_dir=root / 'separate'))
    assert separate.exit_code == 0 and not separate.cleanup_errors, separate
    # A separate state provisions an independent card, never a view onto
    # the original card: its own ready census is exactly objects=4 (the
    # id-42 pair created above is absent there), while the deterministic
    # emulator keygen yields the same key material (proven mechanism).
    assert 'objects=4' in (root / 'separate/ready.stdout.log').read_text()
    assert (root / 'separate/crypto/rsa.mod').read_bytes() == public[0]
    for path in root.rglob('*.log'):
        assert b'bad-pin' not in path.read_bytes() and b'1234567812345678' not in path.read_bytes()


@pytest.mark.parametrize('damage', ['missing-marker', 'marker-extra-lf', 'marker-tamper', 'missing-lease', 'lease-link',
                                    'hidden-file', 'dangling-link', 'unknown-topfile', 'busy-init'])
def test_damage_refused_before_daemon_or_application(runtime, damage):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    owned = state / 'opensc-isoapplet'
    if damage == 'missing-marker':
        (owned / 'complete').unlink()
    elif damage == 'marker-extra-lf':
        with (owned / 'complete').open('ab') as f:
            f.write(b'\n')
    elif damage == 'marker-tamper':
        (owned / 'complete').write_bytes((owned / 'complete').read_bytes().replace(b'slot=0', b'slot=1'))
    elif damage == 'missing-lease':
        (owned / 'lease').unlink()
    elif damage == 'lease-link':
        (owned / 'lease').rename(owned / 'original.lease')
        (owned / 'lease').symlink_to('original.lease')
    elif damage == 'hidden-file':
        (owned / '.foreign').write_bytes(b'foreign')
    elif damage == 'dangling-link':
        (owned / 'dangling').symlink_to('absent')
    elif damage == 'unknown-topfile':
        (state / 'foreign').write_bytes(b'foreign')
    else:
        (state / '.init-lock').mkdir()
    before = snapshot(state)
    for operation in ('init', 'health', 'exec'):
        argv = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'echo APP-RAN']
        result = docker(*base, *controls, image, *argv, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert snapshot(state) == before, (damage, operation)


@pytest.mark.parametrize('bad', ['absent-pin', 'absent-so', 'short', 'long', 'multiline', 'nul', 'etx',
                                'user-conflict', 'so-conflict', 'bad-so-short', 'bad-so-long'])
def test_bad_credentials_never_create_state(runtime, bad):
    channel, root, state, secrets, image, base, controls = runtime
    if bad == 'absent-pin':
        controls = controls[2:]
    elif bad == 'absent-so':
        controls = controls[:2]
    elif bad in ('user-conflict', 'so-conflict'):
        controls = [*controls, '-e', 'P11LAB_PIN=' if bad == 'user-conflict' else 'P11LAB_SO_PIN=']
    elif bad in ('bad-so-short', 'bad-so-long'):
        (secrets / 'so').write_bytes(b'123456789012345' if bad == 'bad-so-short' else b'12345678901234567')
    else:
        (secrets / 'pin').write_bytes({'short': b'123', 'long': b'12345678901234567', 'multiline': b'ab\ncdef',
                                      'nul': b'ab\x00cdef', 'etx': b'ab\x03cdef'}[bad])
    result = docker(*base, *controls, image, 'init', check=False)
    assert result.returncode != 0
    assert list(state.iterdir()) == []


@pytest.mark.parametrize('pin,so,tag', [(b'1234', b'1234567812345678', 'min-pin'),
                                       (b'1234567890123456', b'1234567812345678', 'max-pin'),
                                       (b'654321', b'0123456789abcdeg', 'nonhex-puk'),
                                       (b'\x01\x02\x7f\x80\xff\x41', b'\xff' * 16, 'high-bytes')])
def test_credential_bounds_accepted(runtime, pin, so, tag):
    channel, root, state, secrets, image, base, controls = runtime
    (secrets / 'pin').write_bytes(pin)
    (secrets / 'so').write_bytes(so)
    docker(*base, *controls, image, 'init')
    health = docker(*base, *controls, image, 'health')
    assert 'native_slot=0 token_present_index=0' in health.stdout


@pytest.mark.parametrize('label', ['', 'acceptance', 'x' * 33, 'bad\nlabel'])
def test_invalid_label_never_creates_state(runtime, label):
    channel, root, state, secrets, image, base, controls = runtime
    result = docker(*base, *controls, '-e', 'P11LAB_LABEL=' + label, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []


@pytest.mark.parametrize('override', ['PCSCLITE_CSOCK_NAME', 'OPENSC_CONF', 'OPENSC_DEBUG', 'OPENSSL_CONF', 'OPENSSL_MODULES',
                                     'LD_PRELOAD', 'NSS_WRAPPER_PASSWD', 'NSS_WRAPPER_GROUP', 'JAVA_TOOL_OPTIONS',
                                     'JDK_JAVA_OPTIONS', '_JAVA_OPTIONS', 'CLASSPATH', 'JAVA_HOME'])
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
    spec = load_environment('opensc-isoapplet', channel)
    assert json.loads(read('/usr/share/p11lab/provider.json')) == {k: v for k, v in spec.items()
                                                                 if k not in ('lock', 'channel', 'channel_spec', 'asset_root')}
    assert read('/usr/share/p11lab/runtime-id') == artifact_key('runtime', runtime_inputs(spec)) + '\n'
    assert 'libcrypto.so.3' in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'libpcsclite' in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'not found' not in read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'opensc unpatched' in read('/usr/share/p11lab/build/options.txt')
    assert 'ifd-vpcd' in read('/usr/share/p11lab/build/options.txt')
    assert 'make -j2' in read('/usr/share/p11lab/build/options.txt')
    assert 'opensc-pkcs11.so' in read('/usr/share/p11lab/build/module-hashes.sha256')
    assert 'jcardsim.jar' in read('/usr/share/p11lab/build/module-hashes.sha256')
    assert 'IsoApplet.class' in read('/usr/share/p11lab/build/module-hashes.sha256')
    assert 'pkcs15+onepin 4-prompt' in read('/usr/share/p11lab/build/prompt-matrix.txt')
    assert 'openjdk version' in read('/usr/share/p11lab/build/java.txt')
    decision = assess_distribution(as_ref(image), root / 'admission')
    assert decision['status'] == decision['publication_status'] == 'blocked' and decision['blockers']
    (root / 'admission-decision.json').write_text(json.dumps(decision, indent=2) + '\n')
    permission = docker('run', '--rm', '--network', 'none', '--entrypoint', 'stat', image,
                        '-c', '%u:%g %a', '/usr/share/p11lab/provider.json').stdout.strip()
    assert permission == '0:0 644'
    absent = docker('run', '--rm', '--network', 'none', '--entrypoint', 'sh', image,
                    '-c', 'test ! -e /usr/local/lib/libopensc.la && test ! -e /usr/local/lib/libopensc.a '
                         '&& test ! -e /usr/local/lib/p11lab/onepin-opensc-pkcs11.so '
                         '&& test ! -e /usr/local/lib/p11lab/pkcs11-spy.so '
                         '&& test ! -e /usr/bin/javac && test ! -e /usr/bin/python3 '
                         '&& test ! -e /usr/lib/jvm/java-21-openjdk-amd64/bin/javac && echo ABSENT-OK')
    assert 'ABSENT-OK' in absent.stdout


def start_long_application(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    name = 'p11lab-opensc-isoapplet-test-' + uuid.uuid4().hex[:12]
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
        pid = docker('exec', name, 'cat', '/run/p11lab/opensc-isoapplet/pcscd.pid').stdout.strip()
        assert int(pid) > 1
        emulator = docker('exec', name, 'cat', '/run/p11lab/opensc-isoapplet/emulator.pid').stdout.strip()
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
        pid = docker('exec', name, 'cat', f'/run/p11lab/opensc-isoapplet/{daemon}.pid').stdout.strip()
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


def _tcp_listeners(table):
    # Parse /proc/net/tcp{,6}: (address-hex, port-hex) for LISTEN (0A) rows.
    found = []
    for line in table.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 4 and parts[3] == '0A':
            addr, port = parts[1].rsplit(':', 1)
            found.append((addr, port))
    return found


def test_reloader_8099_closed_to_bridge_peers(runtime):
    # The frozen VSmartCard reloader is disabled via a non-numeric port
    # (pre-fix, a bare bridge-peer TCP connect to 8099 tore down the
    # card and killed the emulator). While a supervised application
    # runs on a bridge network: no 8099 listener exists inside the
    # runtime, the reloader death marker is in emulator.log, and a
    # bridge-peer container gets ECONNREFUSED on 8099 while the
    # disclosed wildcard vpcd listeners still answer (positive
    # controls proving the peer really reaches the runtime).
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CHECKERS, 'explicit checker derivative required as bridge peer'
    docker(*base, *controls, image, 'init')
    net = 'p11lab-isoapplet-8099-' + uuid.uuid4().hex[:12]
    name = 'p11lab-isoapplet-8099-' + uuid.uuid4().hex[:12]
    docker('network', 'create', net)
    try:
        args = list(base[2:])
        args[args.index('--network') + 1] = net
        docker('run', '-d', '--name', name, *args, *controls, image, 'exec', '--', 'sh', '-c',
               'touch /run/p11lab/app-started; sleep 300')
        for _ in range(300):
            started = docker('exec', name, 'test', '-f', '/run/p11lab/app-started', check=False)
            if started.returncode == 0:
                break
            time.sleep(0.05)
        else:
            pytest.fail('supervised application did not start')
        tcp = docker('exec', name, 'cat', '/proc/net/tcp').stdout
        tcp6 = docker('exec', name, 'sh', '-c', 'cat /proc/net/tcp6 2>/dev/null || true').stdout
        (root / 'tcp-listen.txt').write_text(tcp + tcp6)
        listeners = _tcp_listeners(tcp) + _tcp_listeners(tcp6)
        (root / 'tcp-listeners.json').write_text(json.dumps(listeners, indent=2) + '\n')
        ports = {port for _, port in listeners}
        assert '1FA3' not in ports, listeners
        # The frozen vpcd handler listens wildcard (disclosed): pin it
        # so a future loopback-only change forces a doc update.
        assert ('00000000', '8C7B') in listeners and ('00000000', '8C7C') in listeners, listeners
        emulator = docker('exec', name, 'cat', '/run/p11lab/opensc-isoapplet/logs/emulator.log').stdout
        (root / 'emulator.log').write_text(emulator)
        assert 'Start reloader server' not in emulator
        assert 'NumberFormatException' in emulator and 'ReloadThread' in emulator
        assert 'For input string: "disabled"' in emulator
        runtime_ip = json.loads(docker('network', 'inspect', net).stdout)[0]['Containers']
        runtime_ip = next(iter(runtime_ip.values()))['IPv4Address'].split('/')[0]
        probe = ('import socket,sys;ip=sys.argv[1];'
                 's=socket.create_connection((ip,35963),timeout=10);s.close();print("vpcd-35963:connected");'
                 's=socket.create_connection((ip,35964),timeout=10);s.close();print("vpcd-35964:connected");'
                 'print("reloader-8099:connect_ex=%d" % socket.socket().connect_ex((ip,8099)))')
        peer = docker('run', '--rm', '--network', net, '--entrypoint', '/opt/p11lab-checker/bin/python3',
                      CHECKERS[channel], '-c', probe, runtime_ip)
        (root / 'bridge-peer.txt').write_text(peer.stdout)
        assert 'vpcd-35963:connected' in peer.stdout
        assert 'vpcd-35964:connected' in peer.stdout
        assert 'reloader-8099:connect_ex=111' in peer.stdout, peer.stdout
        # The positive-control probes are non-disruptive: the card
        # keeps serving afterwards.
        docker('exec', name, 'test', '-f', '/run/p11lab/app-started')
    finally:
        docker('rm', '-f', name, check=False)
        docker('network', 'rm', net, check=False)


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


RSA_PROBE = r'''
/* T-isoapplet acceptance-only RSA/EC sign probe (test-only, never shipped).
 * usage: p11lab-rsa-probe SUBCOMMAND MODULE ... (PINs travel in files;
 * argv carries paths, never secrets). Each crypto lane writes public
 * artifacts plus result.txt for independent OpenSSL-oracle verification. */
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "vendor/pkcs11.h"
static CK_FUNCTION_LIST_PTR f;
static const unsigned char EXP[3] = {0x01,0x00,0x01};
static const unsigned char MSG[] = "p11lab-isoapplet-crypto-v1";
static const unsigned char DI256[19] = {
    0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20
};
static int read_bounded(const char *path, unsigned char *out, size_t cap, size_t *length)
{
    FILE *o = fopen(path, "rb");
    size_t n;
    if (!o) { fprintf(stderr, "cannot open %s\n", path); return 0; }
    n = fread(out, 1, cap + 1, o);
    fclose(o);
    if (!n || n > cap) { fprintf(stderr, "bad pin file %s\n", path); return 0; }
    *length = n;
    return 1;
}
static CK_OBJECT_HANDLE find1(CK_SESSION_HANDLE se, CK_OBJECT_CLASS class, CK_KEY_TYPE *kt,
                              unsigned char *id, size_t idlen)
{
    CK_ATTRIBUTE flt[3];
    CK_ULONG n = 0, got = 0;
    CK_OBJECT_HANDLE hs[4];
    flt[n++] = (CK_ATTRIBUTE){CKA_CLASS, &class, sizeof(class)};
    if (kt) flt[n++] = (CK_ATTRIBUTE){CKA_KEY_TYPE, kt, sizeof(*kt)};
    if (id) flt[n++] = (CK_ATTRIBUTE){CKA_ID, id, idlen};
    if (f->C_FindObjectsInit(se, flt, n)) return 0;
    f->C_FindObjects(se, hs, 4, &got);
    f->C_FindObjectsFinal(se);
    return got == 1 ? hs[0] : 0;
}
static CK_RV readattr(CK_SESSION_HANDLE se, CK_OBJECT_HANDLE h, CK_ATTRIBUTE_TYPE t,
                      unsigned char *buf, CK_ULONG bufsz, CK_ULONG *outlen)
{
    CK_ATTRIBUTE a = {t, buf, bufsz};
    CK_RV rv = f->C_GetAttributeValue(se, h, &a, 1);
    if (!rv) *outlen = a.ulValueLen;
    return rv;
}
static void save(const char *dir, const char *name, unsigned char *p, size_t n)
{
    char path[512];
    FILE *o;
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    o = fopen(path, "wb");
    if (o) { fwrite(p, 1, n, o); fclose(o); }
}
static int open_first_slot(CK_SLOT_ID *slot)
{
    CK_SLOT_ID slots[16];
    CK_ULONG n = 16;
    CK_RV rv = f->C_GetSlotList(CK_TRUE, slots, &n);
    if (rv || !n) { fprintf(stderr, "C_GetSlotList: CK_RV=0x%08lx\n", rv); return 0; }
    *slot = slots[0];
    return 1;
}
static int cmd_login(CK_SLOT_ID slot, unsigned char *pin, size_t pinlen)
{
    CK_SESSION_HANDLE se = 0;
    CK_RV rv, second;
    rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &se);
    if (rv) { fprintf(stderr, "C_OpenSession: CK_RV=0x%08lx\n", rv); return 1; }
    rv = f->C_Login(se, CKU_USER, pin, (CK_ULONG)pinlen);
    printf("login rv=0x%lx\n", (unsigned long)rv);
    if (rv) { fprintf(stderr, "C_Login: CK_RV=0x%08lx\n", rv); f->C_CloseSession(se); return 1; }
    second = f->C_Login(se, CKU_USER, pin, (CK_ULONG)pinlen);
    printf("second rv=0x%lx\n", (unsigned long)second);
    f->C_Logout(se);
    f->C_CloseSession(se);
    return 0;
}
static int cmd_mechanisms(CK_SLOT_ID slot)
{
    CK_MECHANISM_TYPE list[64];
    CK_ULONG count = 64;
    CK_RV rv = f->C_GetMechanismList(slot, list, &count);
    if (rv) { fprintf(stderr, "C_GetMechanismList: CK_RV=0x%08lx\n", rv); return 1; }
    printf("mechanisms=%lu\n", (unsigned long)count);
    for (CK_ULONG i = 0; i < count; i++) {
        CK_MECHANISM_INFO details;
        rv = f->C_GetMechanismInfo(slot, list[i], &details);
        if (rv) { fprintf(stderr, "C_GetMechanismInfo: CK_RV=0x%08lx\n", rv); return 1; }
        printf("mech 0x%04lx flags=0x%08lx\n", (unsigned long)list[i], (unsigned long)details.flags);
    }
    return 0;
}
static int rsa_lane(CK_SESSION_HANDLE se, CK_OBJECT_HANDLE pub, CK_OBJECT_HANDLE priv,
                    const char *dir, FILE *res)
{
    /* Export, SHA256 sign, on-card verify, raw DigestInfo sign. */
    unsigned char big[4096], sig[512], dgst[64];
    CK_ULONG biglen = 0, siglen, dgstlen = sizeof(dgst);
    CK_MECHANISM m;
    CK_RV rv;
    rv = readattr(se, pub, CKA_MODULUS, big, sizeof(big), &biglen);
    if (rv || biglen != 256) { fprintf(stderr, "modulus: CK_RV=0x%08lx len=%lu\n", rv, (unsigned long)biglen); return 1; }
    save(dir, "rsa.mod", big, biglen);
    rv = readattr(se, pub, CKA_PUBLIC_EXPONENT, big, sizeof(big), &biglen);
    if (rv) { fprintf(stderr, "exponent: CK_RV=0x%08lx\n", rv); return 1; }
    save(dir, "rsa.exp", big, biglen);
    memset(&m, 0, sizeof(m));
    m.mechanism = CKM_SHA256_RSA_PKCS;
    rv = f->C_SignInit(se, &m, priv);
    if (rv) { fprintf(stderr, "C_SignInit: CK_RV=0x%08lx\n", rv); return 1; }
    siglen = sizeof(sig);
    rv = f->C_Sign(se, (unsigned char *)MSG, sizeof(MSG) - 1, sig, &siglen);
    if (rv || siglen != 256) { fprintf(stderr, "C_Sign: CK_RV=0x%08lx\n", rv); return 1; }
    save(dir, "rsa-sha256.sig", sig, siglen);
    fprintf(res, "sign=0x0 siglen=%lu\n", (unsigned long)siglen);
    rv = f->C_VerifyInit(se, &m, pub);
    if (rv) { fprintf(stderr, "C_VerifyInit: CK_RV=0x%08lx\n", rv); return 1; }
    rv = f->C_Verify(se, (unsigned char *)MSG, sizeof(MSG) - 1, sig, siglen);
    fprintf(res, "oncard-verify=0x%lx\n", (unsigned long)rv);
    if (rv) { fprintf(stderr, "C_Verify: CK_RV=0x%08lx\n", rv); return 1; }
    memset(&m, 0, sizeof(m));
    m.mechanism = CKM_SHA256;
    rv = f->C_DigestInit(se, &m);
    if (rv) return 1;
    rv = f->C_Digest(se, (unsigned char *)MSG, sizeof(MSG) - 1, dgst, &dgstlen);
    if (rv || dgstlen != 32) return 1;
    {
        unsigned char dmsg[19 + 32];
        memcpy(dmsg, DI256, 19);
        memcpy(dmsg + 19, dgst, 32);
        memset(&m, 0, sizeof(m));
        m.mechanism = CKM_RSA_PKCS;
        rv = f->C_SignInit(se, &m, priv);
        if (rv) { fprintf(stderr, "raw C_SignInit: CK_RV=0x%08lx\n", rv); return 1; }
        siglen = sizeof(sig);
        rv = f->C_Sign(se, dmsg, sizeof(dmsg), sig, &siglen);
        if (rv) { fprintf(stderr, "raw C_Sign: CK_RV=0x%08lx\n", rv); return 1; }
        save(dir, "rsa-raw.sig", sig, siglen);
        fprintf(res, "raw-sign=0x0\n");
    }
    return 0;
}
static int cmd_rsa_existing(CK_SLOT_ID slot, unsigned char *pin, size_t pinlen, const char *dir)
{
    CK_SESSION_HANDLE se = 0;
    CK_KEY_TYPE rsa = CKK_RSA;
    unsigned char id = 0x02;
    CK_OBJECT_HANDLE pub, priv;
    CK_RV rv;
    FILE *res;
    char path[512];
    int rc = 1;
    mkdir(dir, 0700);
    save(dir, "msg", (unsigned char *)MSG, sizeof(MSG) - 1);
    snprintf(path, sizeof(path), "%s/result.txt", dir);
    res = fopen(path, "w");
    if (!res) return 1;
    rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &se);
    if (rv) goto done;
    rv = f->C_Login(se, CKU_USER, pin, (CK_ULONG)pinlen);
    if (rv) { fprintf(stderr, "C_Login: CK_RV=0x%08lx\n", rv); goto done; }
    pub = find1(se, CKO_PUBLIC_KEY, &rsa, &id, 1);
    priv = find1(se, CKO_PRIVATE_KEY, &rsa, &id, 1);
    if (!pub || !priv) { fprintf(stderr, "id=02 pair not found\n"); goto done; }
    fprintf(res, "found=1\n");
    rc = rsa_lane(se, pub, priv, dir, res);
    f->C_Logout(se);
done:
    if (se) f->C_CloseSession(se);
    fclose(res);
    return rc;
}
static int cmd_rsa_generated(CK_SLOT_ID slot, unsigned char *pin, size_t pinlen, const char *dir)
{
    CK_SESSION_HANDLE se = 0;
    CK_OBJECT_CLASS pubc = CKO_PUBLIC_KEY, privc = CKO_PRIVATE_KEY;
    CK_KEY_TYPE rsa = CKK_RSA;
    CK_BBOOL yes = 1, no = 0;
    CK_ULONG bits = 2048;
    CK_MECHANISM gm;
    CK_ATTRIBUTE puba[6], priva[5];
    CK_OBJECT_HANDLE sph = 0, svh = 0;
    CK_RV rv;
    FILE *res;
    char path[512];
    int rc = 1;
    mkdir(dir, 0700);
    save(dir, "msg", (unsigned char *)MSG, sizeof(MSG) - 1);
    snprintf(path, sizeof(path), "%s/result.txt", dir);
    res = fopen(path, "w");
    if (!res) return 1;
    rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &se);
    if (rv) goto done;
    rv = f->C_Login(se, CKU_USER, pin, (CK_ULONG)pinlen);
    if (rv) { fprintf(stderr, "C_Login: CK_RV=0x%08lx\n", rv); goto done; }
    memset(&gm, 0, sizeof(gm));
    gm.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    puba[0] = (CK_ATTRIBUTE){CKA_CLASS, &pubc, sizeof(pubc)};
    puba[1] = (CK_ATTRIBUTE){CKA_TOKEN, &no, sizeof(no)};
    puba[2] = (CK_ATTRIBUTE){CKA_KEY_TYPE, &rsa, sizeof(rsa)};
    puba[3] = (CK_ATTRIBUTE){CKA_VERIFY, &yes, sizeof(yes)};
    puba[4] = (CK_ATTRIBUTE){CKA_MODULUS_BITS, &bits, sizeof(bits)};
    puba[5] = (CK_ATTRIBUTE){CKA_PUBLIC_EXPONENT, (void *)EXP, 3};
    priva[0] = (CK_ATTRIBUTE){CKA_CLASS, &privc, sizeof(privc)};
    priva[1] = (CK_ATTRIBUTE){CKA_TOKEN, &no, sizeof(no)};
    priva[2] = (CK_ATTRIBUTE){CKA_PRIVATE, &yes, sizeof(yes)};
    priva[3] = (CK_ATTRIBUTE){CKA_KEY_TYPE, &rsa, sizeof(rsa)};
    priva[4] = (CK_ATTRIBUTE){CKA_SIGN, &yes, sizeof(yes)};
    rv = f->C_GenerateKeyPair(se, &gm, puba, 6, priva, 5, &sph, &svh);
    fprintf(res, "keygen=0x%lx\n", (unsigned long)rv);
    if (rv) { fprintf(stderr, "C_GenerateKeyPair: CK_RV=0x%08lx\n", rv); goto done; }
    rc = rsa_lane(se, sph, svh, dir, res);
    rv = f->C_DestroyObject(se, sph);
    fprintf(res, "destroy-pub=0x%lx\n", (unsigned long)rv);
    if (rv) rc = 1;
    rv = f->C_DestroyObject(se, svh);
    fprintf(res, "destroy-priv=0x%lx\n", (unsigned long)rv);
    if (rv) rc = 1;
    f->C_Logout(se);
done:
    if (se) f->C_CloseSession(se);
    fclose(res);
    return rc;
}
static int cmd_rsa_provision(CK_SLOT_ID slot, unsigned char *pin, size_t pinlen,
                             const char *dir, unsigned idval)
{
    CK_SESSION_HANDLE se = 0;
    CK_OBJECT_CLASS pubc = CKO_PUBLIC_KEY, privc = CKO_PRIVATE_KEY;
    CK_KEY_TYPE rsa = CKK_RSA;
    CK_BBOOL yes = 1, no = 0;
    CK_ULONG bits = 2048;
    CK_MECHANISM gm;
    CK_ATTRIBUTE puba[10], priva[10];
    CK_ULONG npub = 0, npriv = 0;
    CK_OBJECT_HANDLE sph = 0, svh = 0;
    unsigned char id = (unsigned char)idval;
    char label[] = "p11lab-applied-rsa";
    CK_RV rv;
    FILE *res;
    char path[512];
    int rc = 1;
    mkdir(dir, 0700);
    save(dir, "msg", (unsigned char *)MSG, sizeof(MSG) - 1);
    snprintf(path, sizeof(path), "%s/result.txt", dir);
    res = fopen(path, "w");
    if (!res) return 1;
    rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &se);
    if (rv) goto done;
    rv = f->C_Login(se, CKU_USER, pin, (CK_ULONG)pinlen);
    if (rv) { fprintf(stderr, "C_Login: CK_RV=0x%08lx\n", rv); goto done; }
    memset(&gm, 0, sizeof(gm));
    gm.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    puba[npub++] = (CK_ATTRIBUTE){CKA_CLASS, &pubc, sizeof(pubc)};
    puba[npub++] = (CK_ATTRIBUTE){CKA_TOKEN, &yes, sizeof(yes)};
    puba[npub++] = (CK_ATTRIBUTE){CKA_KEY_TYPE, &rsa, sizeof(rsa)};
    puba[npub++] = (CK_ATTRIBUTE){CKA_ID, &id, 1};
    puba[npub++] = (CK_ATTRIBUTE){CKA_LABEL, label, sizeof(label) - 1};
    puba[npub++] = (CK_ATTRIBUTE){CKA_VERIFY, &yes, sizeof(yes)};
    puba[npub++] = (CK_ATTRIBUTE){CKA_ENCRYPT, &yes, sizeof(yes)};
    puba[npub++] = (CK_ATTRIBUTE){CKA_MODULUS_BITS, &bits, sizeof(bits)};
    puba[npub++] = (CK_ATTRIBUTE){CKA_PUBLIC_EXPONENT, (void *)EXP, 3};
    priva[npriv++] = (CK_ATTRIBUTE){CKA_CLASS, &privc, sizeof(privc)};
    priva[npriv++] = (CK_ATTRIBUTE){CKA_TOKEN, &yes, sizeof(yes)};
    priva[npriv++] = (CK_ATTRIBUTE){CKA_PRIVATE, &yes, sizeof(yes)};
    priva[npriv++] = (CK_ATTRIBUTE){CKA_KEY_TYPE, &rsa, sizeof(rsa)};
    priva[npriv++] = (CK_ATTRIBUTE){CKA_ID, &id, 1};
    priva[npriv++] = (CK_ATTRIBUTE){CKA_LABEL, label, sizeof(label) - 1};
    priva[npriv++] = (CK_ATTRIBUTE){CKA_SIGN, &yes, sizeof(yes)};
    priva[npriv++] = (CK_ATTRIBUTE){CKA_SENSITIVE, &yes, sizeof(yes)};
    priva[npriv++] = (CK_ATTRIBUTE){CKA_EXTRACTABLE, &no, sizeof(no)};
    priva[npriv++] = (CK_ATTRIBUTE){CKA_DECRYPT, &yes, sizeof(yes)};
    rv = f->C_GenerateKeyPair(se, &gm, puba, npub, priva, npriv, &sph, &svh);
    fprintf(res, "keygen=0x%lx\n", (unsigned long)rv);
    if (rv) { fprintf(stderr, "C_GenerateKeyPair: CK_RV=0x%08lx\n", rv); goto done; }
    if (!find1(se, CKO_PUBLIC_KEY, &rsa, &id, 1) || !find1(se, CKO_PRIVATE_KEY, &rsa, &id, 1)) {
        fprintf(stderr, "applied id round-trip failed\n");
        goto done;
    }
    fprintf(res, "roundtrip=1\n");
    rc = rsa_lane(se, sph, svh, dir, res);
    f->C_Logout(se);
done:
    if (se) f->C_CloseSession(se);
    fclose(res);
    return rc;
}
static int cmd_ec_sha1(CK_SLOT_ID slot, unsigned char *pin, size_t pinlen, const char *dir)
{
    CK_SESSION_HANDLE se = 0;
    CK_KEY_TYPE ec = CKK_EC;
    unsigned char id = 0x01;
    CK_OBJECT_HANDLE pub, priv;
    unsigned char big[4096], sig[512];
    CK_ULONG biglen = 0, siglen;
    CK_MECHANISM m;
    CK_RV rv;
    FILE *res;
    char path[512];
    int rc = 1;
    mkdir(dir, 0700);
    save(dir, "msg", (unsigned char *)MSG, sizeof(MSG) - 1);
    snprintf(path, sizeof(path), "%s/result.txt", dir);
    res = fopen(path, "w");
    if (!res) return 1;
    rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &se);
    if (rv) goto done;
    rv = f->C_Login(se, CKU_USER, pin, (CK_ULONG)pinlen);
    if (rv) { fprintf(stderr, "C_Login: CK_RV=0x%08lx\n", rv); goto done; }
    pub = find1(se, CKO_PUBLIC_KEY, &ec, &id, 1);
    priv = find1(se, CKO_PRIVATE_KEY, &ec, &id, 1);
    if (!pub || !priv) { fprintf(stderr, "id=01 pair not found\n"); goto done; }
    rv = readattr(se, pub, CKA_EC_POINT, big, sizeof(big), &biglen);
    if (rv) { fprintf(stderr, "ec-point: CK_RV=0x%08lx\n", rv); goto done; }
    save(dir, "ec.point", big, biglen);
    memset(&m, 0, sizeof(m));
    m.mechanism = CKM_ECDSA_SHA1;
    rv = f->C_SignInit(se, &m, priv);
    if (rv) { fprintf(stderr, "C_SignInit: CK_RV=0x%08lx\n", rv); goto done; }
    siglen = sizeof(sig);
    rv = f->C_Sign(se, (unsigned char *)MSG, sizeof(MSG) - 1, sig, &siglen);
    if (rv || siglen != 64) { fprintf(stderr, "C_Sign: CK_RV=0x%08lx\n", rv); goto done; }
    save(dir, "ec-sha1.sig", sig, siglen);
    fprintf(res, "sign=0x0 siglen=%lu\n", (unsigned long)siglen);
    rc = 0;
    f->C_Logout(se);
done:
    if (se) f->C_CloseSession(se);
    if (res) fclose(res);
    return rc;
}
static int cmd_ecdsa_boundary(CK_SLOT_ID slot, unsigned char *pin, size_t pinlen)
{
    CK_SESSION_HANDLE se = 0;
    CK_KEY_TYPE ec = CKK_EC;
    unsigned char id = 0x01;
    CK_OBJECT_HANDLE priv;
    CK_MECHANISM m;
    CK_RV rv;
    rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &se);
    if (rv) return 1;
    rv = f->C_Login(se, CKU_USER, pin, (CK_ULONG)pinlen);
    if (rv) { f->C_CloseSession(se); return 1; }
    priv = find1(se, CKO_PRIVATE_KEY, &ec, &id, 1);
    if (!priv) { f->C_CloseSession(se); return 1; }
    memset(&m, 0, sizeof(m));
    m.mechanism = CKM_ECDSA;
    rv = f->C_SignInit(se, &m, priv);
    printf("raw-ecdsa rv=0x%lx\n", (unsigned long)rv);
    f->C_Logout(se);
    f->C_CloseSession(se);
    return 0;
}
static int cmd_digest(CK_SLOT_ID slot, unsigned char *pin, size_t pinlen, const char *dir)
{
    CK_SESSION_HANDLE se = 0;
    unsigned char dgst[64];
    CK_ULONG dgstlen = sizeof(dgst);
    CK_MECHANISM m;
    CK_RV rv;
    mkdir(dir, 0700);
    save(dir, "msg", (unsigned char *)MSG, sizeof(MSG) - 1);
    rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &se);
    if (rv) return 1;
    rv = f->C_Login(se, CKU_USER, pin, (CK_ULONG)pinlen);
    if (rv) { f->C_CloseSession(se); return 1; }
    memset(&m, 0, sizeof(m));
    m.mechanism = CKM_SHA256;
    rv = f->C_DigestInit(se, &m);
    if (rv) { f->C_CloseSession(se); return 1; }
    rv = f->C_Digest(se, (unsigned char *)MSG, sizeof(MSG) - 1, dgst, &dgstlen);
    if (rv || dgstlen != 32) { f->C_CloseSession(se); return 1; }
    save(dir, "msg.sha256", dgst, dgstlen);
    printf("digest len=%lu\n", (unsigned long)dgstlen);
    f->C_Logout(se);
    f->C_CloseSession(se);
    return 0;
}
static CK_ULONG count_label(CK_SESSION_HANDLE se, char *label, size_t labellen)
{
    CK_ATTRIBUTE flt[1] = {{CKA_LABEL, label, labellen}};
    CK_OBJECT_HANDLE hs[16];
    CK_ULONG got = 0, total = 0;
    if (f->C_FindObjectsInit(se, flt, 1)) return 9999;
    while (f->C_FindObjects(se, hs, 16, &got) == 0 && got > 0) total += got;
    f->C_FindObjectsFinal(se);
    return total;
}
static int cmd_aes_lifecycle(CK_SLOT_ID slot, unsigned char *pin, size_t pinlen)
{
    CK_SESSION_HANDLE se = 0;
    CK_OBJECT_CLASS sc = CKO_SECRET_KEY;
    CK_KEY_TYPE aes = CKK_AES;
    CK_BBOOL no = 0, yes = 1;
    char label[] = "p11lab-aes-probe";
    unsigned char value[16];
    unsigned char rbuf[64];
    CK_ATTRIBUTE rd[1];
    CK_OBJECT_HANDLE oh = 0;
    CK_RV rv, rc;
    int ok;
    memset(value, 0x5A, sizeof(value));
    rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &se);
    if (rv) return 1;
    rv = f->C_Login(se, CKU_USER, pin, (CK_ULONG)pinlen);
    if (rv) { f->C_CloseSession(se); return 1; }
    {
        CK_ATTRIBUTE t[6] = {{CKA_CLASS, &sc, sizeof(sc)}, {CKA_TOKEN, &no, sizeof(no)},
                             {CKA_KEY_TYPE, &aes, sizeof(aes)}, {CKA_LABEL, label, sizeof(label) - 1},
                             {CKA_VALUE, value, sizeof(value)}, {CKA_PRIVATE, &yes, sizeof(yes)}};
        rc = f->C_CreateObject(se, t, 6, &oh);
    }
    printf("aes create=0x%lx", (unsigned long)rc);
    if (rc) { printf("\n"); f->C_CloseSession(se); return 1; }
    printf(" find0=%lu", (unsigned long)count_label(se, label, sizeof(label) - 1));
    rd[0] = (CK_ATTRIBUTE){CKA_LABEL, rbuf, sizeof(rbuf)};
    rv = f->C_GetAttributeValue(se, oh, rd, 1);
    printf(" label-rv=0x%lx label-len=%lu", (unsigned long)rv, (unsigned long)(rv ? 9999 : rd[0].ulValueLen));
    rd[0] = (CK_ATTRIBUTE){CKA_KEY_TYPE, rbuf, sizeof(rbuf)};
    rv = f->C_GetAttributeValue(se, oh, rd, 1);
    ok = !rv && rd[0].ulValueLen == sizeof(aes) && !memcmp(rbuf, &aes, sizeof(aes));
    printf(" keytype-ok=%d", ok);
    rd[0] = (CK_ATTRIBUTE){CKA_CLASS, rbuf, sizeof(rbuf)};
    rv = f->C_GetAttributeValue(se, oh, rd, 1);
    ok = !rv && rd[0].ulValueLen == sizeof(sc) && !memcmp(rbuf, &sc, sizeof(sc));
    printf(" class-ok=%d", ok);
    rc = f->C_DestroyObject(se, oh);
    printf(" destroy=0x%lx", (unsigned long)rc);
    printf(" find1=%lu\n", (unsigned long)count_label(se, label, sizeof(label) - 1));
    f->C_Logout(se);
    f->C_CloseSession(se);
    return 0;
}
static int cmd_data_lifecycle(CK_SLOT_ID slot, unsigned char *pin, size_t pinlen)
{
    CK_SESSION_HANDLE se = 0;
    CK_OBJECT_CLASS dc = CKO_DATA;
    CK_BBOOL yes = 1;
    char label[] = "p11lab-data-probe";
    unsigned char value[] = "token-data-value-9";
    unsigned char rbuf[64];
    CK_ATTRIBUTE rd[1];
    CK_OBJECT_HANDLE oh = 0;
    CK_RV rv, rc;
    int match;
    rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &se);
    if (rv) return 1;
    rv = f->C_Login(se, CKU_USER, pin, (CK_ULONG)pinlen);
    if (rv) { f->C_CloseSession(se); return 1; }
    {
        CK_ATTRIBUTE t[4] = {{CKA_CLASS, &dc, sizeof(dc)}, {CKA_TOKEN, &yes, sizeof(yes)},
                             {CKA_LABEL, label, sizeof(label) - 1}, {CKA_VALUE, value, sizeof(value) - 1}};
        rc = f->C_CreateObject(se, t, 4, &oh);
    }
    printf("data create=0x%lx", (unsigned long)rc);
    if (rc) { printf("\n"); f->C_CloseSession(se); return 1; }
    printf(" find=%lu", (unsigned long)count_label(se, label, sizeof(label) - 1));
    rd[0] = (CK_ATTRIBUTE){CKA_VALUE, rbuf, sizeof(rbuf)};
    rv = f->C_GetAttributeValue(se, oh, rd, 1);
    match = !rv && rd[0].ulValueLen == sizeof(value) - 1 && !memcmp(rbuf, value, rd[0].ulValueLen);
    printf(" match=%d", match);
    rc = f->C_DestroyObject(se, oh);
    printf(" destroy=0x%lx", (unsigned long)rc);
    printf(" find-after=%lu\n", (unsigned long)count_label(se, label, sizeof(label) - 1));
    f->C_Logout(se);
    f->C_CloseSession(se);
    return 0;
}
static int cmd_data_boundary(CK_SLOT_ID slot, unsigned char *pin, size_t pinlen)
{
    CK_SESSION_HANDLE se = 0;
    CK_OBJECT_CLASS dc = CKO_DATA, cc = CKO_CERTIFICATE;
    CK_BBOOL no = 0;
    CK_CERTIFICATE_TYPE x509 = CKC_X_509;
    char label[] = "p11lab-boundary";
    unsigned char value[16];
    CK_OBJECT_HANDLE oh = 0;
    CK_RV rv, r1, r2, r3;
    memset(value, 0xAB, sizeof(value));
    rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &se);
    if (rv) return 1;
    rv = f->C_Login(se, CKU_USER, pin, (CK_ULONG)pinlen);
    if (rv) { f->C_CloseSession(se); return 1; }
    {
        CK_ATTRIBUTE t[4] = {{CKA_CLASS, &dc, sizeof(dc)}, {CKA_TOKEN, &no, sizeof(no)},
                             {CKA_LABEL, label, sizeof(label) - 1}, {CKA_VALUE, value, sizeof(value)}};
        r1 = f->C_CreateObject(se, t, 4, &oh);
    }
    {
        unsigned char app[] = "app";
        CK_ATTRIBUTE t[6] = {{CKA_CLASS, &dc, sizeof(dc)}, {CKA_TOKEN, &no, sizeof(no)},
                             {CKA_LABEL, label, sizeof(label) - 1}, {CKA_VALUE, value, sizeof(value)},
                             {CKA_APPLICATION, app, sizeof(app) - 1}, {CKA_PRIVATE, &no, sizeof(no)}};
        r2 = f->C_CreateObject(se, t, 6, &oh);
    }
    {
        CK_ATTRIBUTE t[5] = {{CKA_CLASS, &cc, sizeof(cc)}, {CKA_TOKEN, &no, sizeof(no)},
                             {CKA_CERTIFICATE_TYPE, &x509, sizeof(x509)},
                             {CKA_LABEL, label, sizeof(label) - 1}, {CKA_VALUE, value, sizeof(value)}};
        r3 = f->C_CreateObject(se, t, 5, &oh);
    }
    printf("data-sess-min=0x%lx data-sess-app=0x%lx cert-sess=0x%lx\n",
           (unsigned long)r1, (unsigned long)r2, (unsigned long)r3);
    f->C_Logout(se);
    f->C_CloseSession(se);
    return 0;
}
static int cmd_setpin(CK_SLOT_ID slot, unsigned char *pin, size_t pinlen,
                      unsigned char *fresh, size_t freshlen)
{
    CK_SESSION_HANDLE se = 0;
    CK_RV rv, rset, rnew, rold;
    rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &se);
    if (rv) return 1;
    rv = f->C_Login(se, CKU_USER, pin, (CK_ULONG)pinlen);
    if (rv) { f->C_CloseSession(se); return 1; }
    rset = f->C_SetPIN(se, pin, (CK_ULONG)pinlen, fresh, (CK_ULONG)freshlen);
    f->C_Logout(se);
    rnew = f->C_Login(se, CKU_USER, fresh, (CK_ULONG)freshlen);
    f->C_Logout(se);
    rold = f->C_Login(se, CKU_USER, pin, (CK_ULONG)pinlen);
    f->C_Logout(se);
    printf("setpin=0x%lx new-login=0x%lx old-login=0x%lx\n",
           (unsigned long)rset, (unsigned long)rnew, (unsigned long)rold);
    f->C_CloseSession(se);
    return rset == 0 && rnew == 0 && rold == 0xa0 ? 0 : 1;
}
static int cmd_so_boundary(CK_SLOT_ID slot, unsigned char *puk, size_t puklen)
{
    CK_SESSION_HANDLE se = 0;
    unsigned char initpin[] = "9999";
    unsigned char newpuk[16];
    CK_RV rv, rlogin, rinit, rset;
    rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &se);
    if (rv) return 1;
    rlogin = f->C_Login(se, CKU_SO, puk, (CK_ULONG)puklen);
    printf("so-login rv=0x%lx\n", (unsigned long)rlogin);
    if (rlogin) { f->C_CloseSession(se); return 1; }
    rinit = f->C_InitPIN(se, initpin, sizeof(initpin) - 1);
    printf("initpin rv=0x%lx\n", (unsigned long)rinit);
    memcpy(newpuk, puk, puklen < 16 ? puklen : 16);
    if (puklen == 16) newpuk[15] ^= 0x01;
    rset = f->C_SetPIN(se, puk, (CK_ULONG)puklen, newpuk, (CK_ULONG)puklen);
    printf("so-setpin rv=0x%lx\n", (unsigned long)rset);
    memset(newpuk, 0, sizeof(newpuk));
    f->C_Logout(se);
    f->C_CloseSession(se);
    return 0;
}
static int cmd_hammer(CK_SLOT_ID slot, unsigned char *pin, size_t pinlen, unsigned tries)
{
    CK_SESSION_HANDLE se = 0;
    CK_TOKEN_INFO info;
    CK_RV rv;
    rv = f->C_OpenSession(slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, NULL, NULL, &se);
    if (rv) return 1;
    for (unsigned i = 1; i <= tries; i++) {
        rv = f->C_Login(se, CKU_USER, pin, (CK_ULONG)pinlen);
        printf("attempt %u rv=0x%lx\n", i, (unsigned long)rv);
        if (!rv) f->C_Logout(se);
    }
    rv = f->C_GetTokenInfo(slot, &info);
    if (!rv) printf("flags=0x%lx\n", (unsigned long)info.flags);
    f->C_CloseSession(se);
    return 0;
}
int main(int argc, char **argv)
{
    CK_FUNCTION_LIST_PTR fl = NULL;
    CK_RV (*get)(CK_FUNCTION_LIST_PTR_PTR) = NULL;
    void *h = NULL, *symbol;
    CK_SLOT_ID slot = 0;
    CK_RV rv;
    unsigned char pin[64], aux[64];
    size_t pinlen = 0, auxlen = 0;
    const char *sub;
    int rc = 2;
    if (argc < 3) { fprintf(stderr, "usage: p11lab-rsa-probe SUBCOMMAND MODULE ...\n"); return 2; }
    sub = argv[1];
    h = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!h) { fprintf(stderr, "cannot load module\n"); return 2; }
    symbol = dlsym(h, "C_GetFunctionList");
    memcpy(&get, &symbol, sizeof(get));
    if (!get || get(&fl)) { fprintf(stderr, "no function list\n"); dlclose(h); return 2; }
    f = fl;
    rv = f->C_Initialize(NULL);
    if (rv) { fprintf(stderr, "C_Initialize: CK_RV=0x%08lx\n", rv); dlclose(h); return 1; }
    if (!open_first_slot(&slot)) { f->C_Finalize(NULL); dlclose(h); return 1; }
    if (!strcmp(sub, "mechanisms")) {
        rc = argc == 3 ? cmd_mechanisms(slot) : 2;
    } else if (!strcmp(sub, "login") && argc == 4) {
        if (read_bounded(argv[3], pin, sizeof(pin), &pinlen)) rc = cmd_login(slot, pin, pinlen);
    } else if (!strcmp(sub, "rsa-existing") && argc == 5) {
        if (read_bounded(argv[3], pin, sizeof(pin), &pinlen)) rc = cmd_rsa_existing(slot, pin, pinlen, argv[4]);
    } else if (!strcmp(sub, "rsa-generated") && argc == 5) {
        if (read_bounded(argv[3], pin, sizeof(pin), &pinlen)) rc = cmd_rsa_generated(slot, pin, pinlen, argv[4]);
    } else if (!strcmp(sub, "rsa-provision") && argc == 6) {
        if (read_bounded(argv[3], pin, sizeof(pin), &pinlen))
            rc = cmd_rsa_provision(slot, pin, pinlen, argv[4], (unsigned)strtoul(argv[5], NULL, 0));
    } else if (!strcmp(sub, "ec-sha1") && argc == 5) {
        if (read_bounded(argv[3], pin, sizeof(pin), &pinlen)) rc = cmd_ec_sha1(slot, pin, pinlen, argv[4]);
    } else if (!strcmp(sub, "ecdsa-boundary") && argc == 4) {
        if (read_bounded(argv[3], pin, sizeof(pin), &pinlen)) rc = cmd_ecdsa_boundary(slot, pin, pinlen);
    } else if (!strcmp(sub, "digest") && argc == 5) {
        if (read_bounded(argv[3], pin, sizeof(pin), &pinlen)) rc = cmd_digest(slot, pin, pinlen, argv[4]);
    } else if (!strcmp(sub, "aes-lifecycle") && argc == 4) {
        if (read_bounded(argv[3], pin, sizeof(pin), &pinlen)) rc = cmd_aes_lifecycle(slot, pin, pinlen);
    } else if (!strcmp(sub, "data-lifecycle") && argc == 4) {
        if (read_bounded(argv[3], pin, sizeof(pin), &pinlen)) rc = cmd_data_lifecycle(slot, pin, pinlen);
    } else if (!strcmp(sub, "data-boundary") && argc == 4) {
        if (read_bounded(argv[3], pin, sizeof(pin), &pinlen)) rc = cmd_data_boundary(slot, pin, pinlen);
    } else if (!strcmp(sub, "setpin") && argc == 5) {
        if (read_bounded(argv[3], pin, sizeof(pin), &pinlen) &&
            read_bounded(argv[4], aux, sizeof(aux), &auxlen)) rc = cmd_setpin(slot, pin, pinlen, aux, auxlen);
    } else if (!strcmp(sub, "so-boundary") && argc == 4) {
        if (read_bounded(argv[3], aux, sizeof(aux), &auxlen)) rc = cmd_so_boundary(slot, aux, auxlen);
    } else if (!strcmp(sub, "hammer") && argc == 5) {
        if (read_bounded(argv[3], pin, sizeof(pin), &pinlen))
            rc = cmd_hammer(slot, pin, pinlen, (unsigned)strtoul(argv[4], NULL, 10));
    } else {
        fprintf(stderr, "unknown subcommand\n");
    }
    memset(pin, 0, sizeof(pin));
    memset(aux, 0, sizeof(aux));
    f->C_Finalize(NULL);
    dlclose(h);
    return rc;
}
'''


def test_native_daemon_and_reader_are_required(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    before = snapshot(state)
    result = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-native-probe')
    assert 'slot=0 count=1 min=4 max=16 flags=0x0000040d' in result.stdout
    assert 'label=JavaCard isoApplet' in result.stdout
    # Bypass only the adapter in this negative native lane; without the
    # supervised pcscd, emulator and reader the module finds no token.
    direct = docker(*base, '--entrypoint', 'sh', '-e', 'P11LAB_MODULE=' + MODULE, consumer, '-c',
                    'p11lab-native-probe', check=False)
    assert direct.returncode == 1 and 'no token-present slots' in direct.stderr
    assert snapshot(state) == before


def test_pin_retry_budget_lockout_and_fresh_recovery(runtime):
    """Wrong PINs burn IsoApplet tries; the 3-try budget locks natively.

    Fresh provisioning sets 3 tries. Wrong-PIN logins burn exactly one try
    each and every attempt reports CKR_PIN_INCORRECT, including after the
    third wrong attempt locks the card: the driver never reports
    CKR_PIN_LOCKED (sticky 0xa0), and the correct PIN is then also
    rejected. The process that attempted the logins observes the lockout
    live as flags 0x4040d; a fresh process reports default flags 0x40d
    because this driver does not re-read the retry counter at
    C_Initialize (the card is genuinely locked -- the correct PIN is
    rejected in the fresh process too). The module offers no working
    unblock (C_InitPIN reports 0x20), so the locked card is restored by
    the next operation's fresh provision: the budget is whole again.
    """
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    (secrets / 'wrong').write_bytes(b'999999')
    (secrets / 'wrong').chmod(0o600)
    # The hammer, the correct-PIN attempt and the flag observation share
    # one operation (one card); a new operation would re-provision fresh.
    script = '''
M=/usr/local/lib/p11lab/opensc-pkcs11.so
p11lab-rsa-probe hammer $M /run/secrets/wrong 8
echo "correct-pin $(p11lab-rsa-probe login $M /run/secrets/pin 2>&1 | grep -o 'CK_RV=0x[0-9a-f]*' | head -1)"
p11lab-native-probe
'''
    result = docker(*base, *controls, consumer, 'exec', '--', 'sh', '-c', script)
    attempts = {}
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == 'attempt' and parts[1].isdigit():
            attempts[int(parts[1])] = parts[2]
    assert len(attempts) == 8, result.stdout[-2000:]
    assert all(rv == 'rv=0xa0' for rv in attempts.values()), attempts
    assert '0xa4' not in result.stdout and '0xa4' not in result.stderr
    print(f'pin hammer/{channel}: 8 wrong attempts all 0xa0, never 0xa4')
    assert 'correct-pin CK_RV=0x000000a0' in result.stdout
    # The hammering process observes the lockout live as flags=0x4040d
    # (unpadded %lx form). The fresh native-probe process below reports
    # default flags=0x0000040d (padded %08lx form): no counter re-read
    # at C_Initialize. Both observations are pinned exactly as proven
    # in both channels.
    assert 'flags=0x4040d' in result.stdout
    assert 'flags=0x0000040d' in result.stdout
    # Recovery is the next operation's fresh provision: health stays
    # servable and the correct PIN signs with a whole budget again.
    docker(*base, *controls, image, 'health')
    recovered = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-rsa-probe',
                       'login', MODULE, '/run/secrets/pin')
    assert 'login rv=0x0' in recovered.stdout
    assert 'second rv=0x100' in recovered.stdout
    # Two wrong PINs on the fresh card leave one try: FINAL_TRY is
    # observed live and the correct PIN still works.
    pair = docker(*base, *controls, consumer, 'exec', '--', 'sh', '-c',
                  'p11lab-rsa-probe hammer /usr/local/lib/p11lab/opensc-pkcs11.so /run/secrets/wrong 2 && '
                  'p11lab-native-probe && '
                  'p11lab-rsa-probe login /usr/local/lib/p11lab/opensc-pkcs11.so /run/secrets/pin')
    assert pair.stdout.count('rv=0xa0') == 2
    # Same-process FINAL_TRY (unpadded hammer form) plus the fresh-process
    # default (padded native-probe form): the two-observation contract.
    assert 'flags=0x2040d' in pair.stdout
    assert 'flags=0x0000040d' in pair.stdout
    assert 'login rv=0x0' in pair.stdout


def test_mechanism_roster_and_ecdsa_boundary(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    roster = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-rsa-probe', 'mechanisms', MODULE)
    assert 'mechanisms=19' in roster.stdout
    ids = {line.split()[1] for line in roster.stdout.splitlines() if line.startswith('mech ')}
    # Exact roster, proven byte-identical on both frozen channels: 8
    # digests (MD5, SHA-1, RIPEMD160, SHA224/256/384/512, GOSTR3411),
    # RSA PKCS keygen + RSA PKCS + 7 RSA-PKCS hash variants (MD5, SHA-1,
    # RIPEMD160, SHA224/256/384/512), and EC keygen + ECDSA_SHA1. ECDH
    # (0x1050) is NOT offered: EC keys generate and ECDSA_SHA1 signs,
    # but no derive mechanism exists (the census keygen templates set
    # CKA_DERIVE, which the card accepts; the mechanism roster simply
    # lacks ECDH).
    assert ids == {'0x0210', '0x0220', '0x0240', '0x0250', '0x0255', '0x0260', '0x0270', '0x1210',
                   '0x0000', '0x0001', '0x0005', '0x0006', '0x0008', '0x0040', '0x0041', '0x0042', '0x0046',
                   '0x1040', '0x1042'}
    # Raw CKM_ECDSA (0x1041) is absent from the roster: the general-token
    # boundary (kept as an explicit pin even though implied by the exact
    # set above).
    assert '0x1041' not in ids
    boundary = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-rsa-probe',
                      'ecdsa-boundary', MODULE, '/run/secrets/pin')
    assert 'raw-ecdsa rv=0x70' in boundary.stdout


def test_session_and_token_object_lanes(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    aes = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-rsa-probe',
                 'aes-lifecycle', MODULE, '/run/secrets/pin')
    # Session AES keys create and destroy, but the driver drops the label
    # natively: find-by-label selects nothing and the read-back is empty.
    assert 'aes create=0x0 find0=0 label-rv=0x0 label-len=0 keytype-ok=1 class-ok=1 destroy=0x0 find1=0' in aes.stdout
    data = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-rsa-probe',
                  'data-lifecycle', MODULE, '/run/secrets/pin')
    assert 'data create=0x0 find=1 match=1 destroy=0x0 find-after=0' in data.stdout
    boundary = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-rsa-probe',
                      'data-boundary', MODULE, '/run/secrets/pin')
    assert 'data-sess-min=0x7 data-sess-app=0x7 cert-sess=0x7' in boundary.stdout


def test_user_pin_change_and_so_boundaries(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible caller derivative required'
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    (secrets / 'newpin').write_bytes(b'112233')
    (secrets / 'newpin').chmod(0o600)
    changed = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-rsa-probe',
                     'setpin', MODULE, '/run/secrets/pin', '/run/secrets/newpin')
    assert 'setpin=0x0 new-login=0x0 old-login=0xa0' in changed.stdout
    # SO login succeeds with the PUK, but the module offers no working
    # unblock (C_InitPIN) and no SO PIN change; a locked card is
    # restored by the next operation's fresh provision instead.
    sob = docker(*base, *controls, consumer, 'exec', '--', 'p11lab-rsa-probe',
                 'so-boundary', MODULE, '/run/secrets/so')
    assert 'so-login rv=0x0' in sob.stdout
    assert 'initpin rv=0x20' in sob.stdout
    assert 'so-setpin rv=0x102' in sob.stdout


def test_profile_isoapplet_signing_holds_narrowly(runtime):
    channel, root, state, secrets, image, base, controls = runtime
    descriptor = json.loads(docker('run', '--rm', image, 'describe').stdout)
    assert descriptor['application_profile'] == 'isoapplet-signing'
    assert descriptor['state_mode'] == 'ephemeral'
    assert any('general-token profile is falsified natively' in c for c in descriptor['constraints'])
    assert any('isoapplet-signing profile holds narrowly' in c for c in descriptor['constraints'])
