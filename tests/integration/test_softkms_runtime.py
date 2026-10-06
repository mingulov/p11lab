# SPDX-License-Identifier: Apache-2.0
"""Explicit frozen softkms images; no implicit builds or provider-error xfails.

P11LAB_SOFTKMS_{IMAGES,CONSUMERS,BUILDS,CHECKER_ATTEMPTS,PROXY_ATTEMPTS}
are JSON channel maps. EVIDENCE is a fresh private output directory. Integration
blockers are conditional on exact owning-component failure evidence, never on
native provider behavior. The caller passphrase provisions the daemon admin
secret and never reaches PKCS#11; the server-issued 192-character identity
token IS the PKCS#11 PIN for both CKU_USER and CKU_SO (no distinct SO role).
general-token is falsified: generated objects expose no CKA_ID, private keys
expose no EC_POINT/EC_PARAMS, C_DestroyObject is unsupported, and find
ignores templates.
"""
import hashlib
import itertools
import json
import os
import re
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from p11lab.build import runtime_inputs
from p11lab.catalog import load_environment, package_data, validate_build_inputs
from p11lab.identity import artifact_key
from p11lab.models import ArtifactRef, RunSpec
from p11lab.run import run_application

MODULE = '/usr/local/lib/p11lab/libsoftkms.so'
IMAGES = json.loads(os.environ.get('P11LAB_SOFTKMS_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_SOFTKMS_CONSUMERS', '{}'))
BUILDS = json.loads(os.environ.get('P11LAB_SOFTKMS_BUILDS', '{}'))
CHECKER_ATTEMPTS = json.loads(os.environ.get('P11LAB_SOFTKMS_CHECKER_ATTEMPTS', '{}'))
PROXY_ATTEMPTS = json.loads(os.environ.get('P11LAB_SOFTKMS_PROXY_ATTEMPTS', '{}'))
DAEMONS = json.loads(os.environ.get('P11LAB_SOFTKMS_PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_SOFTKMS_CLIENTS', '{}'))
CALLER = os.environ.get('P11LAB_SOFTKMS_CALLER', '')
CHECKERS = json.loads(os.environ.get('P11LAB_SOFTKMS_CHECKERS', '{}'))
COMMANDS = itertools.count()
PIN = b'softkms-acceptance-pin-0123456789abcdef'
MESSAGE = b'softkms-acceptance-message-v1'
ED_ANCHOR_MESSAGE = b'ed25519-oracle-anchor-v1'
ED_ANCHOR_PUBLIC = bytes.fromhex(
    'd3e852d2c1b069cba4ba9494663228eab6cd6dc99fd20c682a7c382f4038996e')
ED_ANCHOR_SIGNATURE = bytes.fromhex(
    '7a24a04978e897d521b8470aba7380ee08b3804c88bc04ea3af29d2fe841b6f9f81fffb'
    'fd9245c741f8b20d9f61cdf34ac9bf055e87448f501611fcc304fc80a')
TOKEN_SHAPE = re.compile(rb'[A-Za-z0-9+/=]{192}\Z')
SERVICES = ['softkms-daemon']
SERVICE_PROCESSES = {'softkms-daemon': 'keykeeper'}
MECHANISMS = ['0x1001', '0x1041', '0x1042', '0x1043', '0x1044',
              '0x1040', '0x1050', '0x1057', '0x1080', '0x1087']
assert len(PIN) == 39


def docker(*args, check=True, env=None):
    argv = ['docker', *map(str, args)]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=180, check=False,
                            env=os.environ | (env or {}))
    evidence = os.environ.get('P11LAB_SOFTKMS_EVIDENCE')
    if evidence:
        root = Path(evidence) / 'commands'
        root.mkdir(parents=True, exist_ok=True)
        (root / f'{next(COMMANDS):04d}.json').write_text(json.dumps({
            'argv': argv, 'env': {k: '<test secret omitted>' for k in (env or {})},
            'returncode': result.returncode, 'stdout': result.stdout,
            'stderr': result.stderr}, indent=2) + '\n')
    if check:
        assert result.returncode == 0, result.stderr
    return result


@pytest.fixture(params=list(IMAGES) or ['unconfigured'])
def runtime(request, tmp_path):
    if request.param not in IMAGES:
        pytest.skip('explicit softkms runtime IDs required')
    channel = request.param
    root = Path(os.environ.get('P11LAB_SOFTKMS_EVIDENCE', str(tmp_path))) / request.node.name
    root.mkdir(parents=True, exist_ok=False)
    state = root / 'state'
    state.mkdir(mode=0o700)
    secrets = root / 'secrets'
    secrets.mkdir(mode=0o700)
    (secrets / 'pin').write_bytes(PIN)
    (secrets / 'pin').chmod(0o600)
    base = ['run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
            '--user', f'{os.getuid()}:{os.getgid()}',
            '--tmpfs', f'/run/p11lab:uid={os.getuid()},gid={os.getgid()},mode=0700',
            '--tmpfs', '/tmp', '--mount', f'type=bind,src={state},dst=/var/lib/p11lab',
            '--mount', f'type=bind,src={secrets},dst=/run/secrets,readonly']
    controls = ['-e', 'P11LAB_LABEL=softKMS', '-e', 'P11LAB_PIN_FILE=/run/secrets/pin']
    yield channel, root, state, secrets, IMAGES[channel], base, controls
    for child in secrets.iterdir():
        child.unlink()


def as_ref(image):
    return ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')


def snapshot(state):
    return {str(p.relative_to(state)): ('symlink', os.readlink(p)) if p.is_symlink()
            else ('file', hashlib.sha256(p.read_bytes()).hexdigest()) if p.is_file()
            else ('directory', None) for p in state.rglob('*')}


def probe_pin(state, secrets):
    """Seal the provisioned identity token as a native proof PIN file."""
    token = (state / 'softkms/identity-token').read_bytes()
    assert TOKEN_SHAPE.match(token), 'identity token is not 192 base64 characters'
    (secrets / 'probe-pin').write_bytes(token)
    (secrets / 'probe-pin').chmod(0o600)
    return '/run/secrets/probe-pin'


_P256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_N256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G256 = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
         0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def _add(field, p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1, x2, y2 = *p, *q
    if x1 == x2 and (y1 + y2) % field == 0:
        return None
    lam = ((3 * x1 * x1 - 3) * pow(2 * y1, -1, field) % field if p == q
           else (y2 - y1) * pow(x2 - x1, -1, field) % field)
    x3 = (lam * lam - x1 - x2) % field
    return (x3, (lam * (x1 - x3) - y1) % field)


def _mul(field, k, p):
    result = None
    while k:
        result, p, k = (_add(field, result, p) if k & 1 else result), _add(field, p, p), k >> 1
    return result


def ecdsa_verify_p256(prehashed, signature, ec_point):
    """Independent ECDSA oracle over raw r||s and a DER EC_POINT.

    The daemon always applies SHA-256 before signing, so callers pass the
    32-byte digest, never the raw message. The pre-hash is provider behavior
    and is asserted loudly at every call site.
    """
    assert len(prehashed) == 32
    point = bytes(ec_point)
    while len(point) != 65 or point[0] != 0x04:
        assert point[0] == 0x04 and len(point) >= 2 and point[1] < 0x80
        assert len(point) == 2 + point[1], point.hex()
        point = point[2:]
    x = int.from_bytes(point[1:33], 'big')
    y = int.from_bytes(point[33:], 'big')
    assert _mul(_P256, _N256, (x, y)) is None, 'public key not in the curve subgroup'
    assert len(signature) == 64
    r, s = int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big')
    assert 1 <= r < _N256 and 1 <= s < _N256
    w = pow(s, -1, _N256)
    digest = int.from_bytes(bytes(prehashed), 'big')
    found = _add(_P256, _mul(_P256, digest * w % _N256, _G256),
                 _mul(_P256, r * w % _N256, (x, y)))
    assert found is not None and found[0] % _N256 == r, 'signature does not verify'


_EDQ = 2 ** 255 - 19
_EDL = 2 ** 252 + 27742317777372353535851937790883648493
_EDD = -121665 * pow(121666, -1, _EDQ) % _EDQ
_EDI = pow(2, (_EDQ - 1) // 4, _EDQ)


def _ed_x_from_y(y):
    root = pow((y * y - 1) * pow(_EDD * y * y + 1, -1, _EDQ), (_EDQ + 3) // 8, _EDQ)
    if (root * root - (y * y - 1) * pow(_EDD * y * y + 1, -1, _EDQ)) % _EDQ:
        root = root * _EDI % _EDQ
    return root


def _ed_decode(data):
    assert len(data) == 32
    value = int.from_bytes(data, 'little')
    y = value & ((1 << 255) - 1)
    x = _ed_x_from_y(y)
    if x & 1 != value >> 255:
        x = _EDQ - x
    assert (-x * x + y * y - 1 - _EDD * x * x * y * y) % _EDQ == 0, 'point not on curve'
    return (x, y)


def _ed_encode(p):
    x, y = p
    return ((y & ((1 << 255) - 1)) | ((x & 1) << 255)).to_bytes(32, 'little')


def _ed_add(p, q):
    x1, y1, x2, y2 = *p, *q
    den = _EDD * x1 * x2 * y1 * y2 % _EDQ
    x3 = (x1 * y2 + x2 * y1) * pow(1 + den, -1, _EDQ) % _EDQ
    y3 = (y1 * y2 + x1 * x2) * pow(1 - den, -1, _EDQ) % _EDQ
    return (x3, y3)


def _ed_mul(k, p):
    result = (0, 1)
    while k:
        if k & 1:
            result = _ed_add(result, p)
        p, k = _ed_add(p, p), k >> 1
    return result


_EDG = _ed_decode(bytes.fromhex(
    '5866666666666666666666666666666666666666666666666666666666666666'))


def ed25519_verify(message, signature, public):
    """Independent Ed25519 oracle over a raw 32-byte key and 64-byte signature."""
    assert len(signature) == 64 and len(public) == 32
    r_bytes, s = signature[:32], int.from_bytes(signature[32:], 'little')
    assert s < _EDL, 'S out of range'
    point_r, point_a = _ed_decode(r_bytes), _ed_decode(bytes(public))
    digest = hashlib.sha512(r_bytes + bytes(public) + bytes(message)).digest()
    h = int.from_bytes(digest, 'little') % _EDL
    left = _ed_encode(_ed_mul(s, _EDG))
    right = _ed_encode(_ed_add(point_r, _ed_mul(h, point_a)))
    assert left == right, 'signature does not verify'


def test_ed25519_oracle_matches_openssl_anchor():
    # The oracle implementation is pinned to a signature produced and
    # verified by the host OpenSSL CLI, so a broken oracle cannot pass.
    ed25519_verify(ED_ANCHOR_MESSAGE, ED_ANCHOR_SIGNATURE, ED_ANCHOR_PUBLIC)
    tampered = bytearray(ED_ANCHOR_SIGNATURE)
    tampered[40] ^= 1
    with pytest.raises(AssertionError):
        ed25519_verify(ED_ANCHOR_MESSAGE, bytes(tampered), ED_ANCHOR_PUBLIC)


def test_packaged_inputs_are_closed():
    spec = load_environment('softkms', 'rolling')
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    assert inputs['sources'][0]['revision'] == 'f6235a4b8aee9394b1c03ce76cafb5b7652442e5'
    assert [p['path'] for p in inputs['patches']] == [
        'patches/01-function-list-order.patch', 'patches/02-attribute-encoding.patch',
        'patches/03-finalize-reset.patch', 'patches/04-info-outputs.patch',
        'patches/05-cli-provisioning-secrets.patch', 'patches/06-mechanism-flags.patch']
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['crate_freeze']['registry_crates'] == 487
    assert inputs['features']['crate_freeze']['git_packages'] == 1
    assert inputs['features']['git_checkout']['revision'] == '3cafd074e840971a2de791593918bb1c0707cd04'
    assert inputs['features']['falcon']['revision'] == 'ce15e75bceb372867daf6b8e81918ab6978686eb'
    assert inputs['features']['token_slot'] == 0
    assert inputs['features']['token_present_index'] == 0
    assert inputs['features']['token_flags'] == '0x404'
    assert inputs['features']['mechanism_entries'] == 10
    assert inputs['features']['authentication'] == (
        'caller-passphrase-provisions-admin-secret; server-issued-identity-token-is-pkcs11-pin')
    assert 'cargo build --locked --offline' in inputs['features']['build_command']
    assert '--jobs 2' in inputs['features']['build_command']
    assert spec['services'] == SERVICES
    assert spec['backend']['simulated'] is False
    assert spec['application_profile'] == 'softkms-local-token'
    assert spec['distribution']['status'] == 'blocked'


def test_release_channel_is_unavailable():
    raw = json.loads(package_data('providers/softkms/provider.json').read_text())
    assert raw['channels']['rolling']['status'] == 'locked'
    assert raw['channels']['release']['status'] == 'unavailable'


def test_native_lifecycle_credentials_and_argv(runtime):
    _channel, root, state, secrets, image, base, controls = runtime
    assert json.loads(docker('run', '--rm', '--network', 'none', image, 'describe').stdout)['module_path'] == MODULE
    default = root / 'default-state'
    default.mkdir(mode=0o700)
    default_base = [a.replace(f'src={state},', f'src={default},') for a in base]
    default_pin = 'd' * 64
    docker(*default_base, *controls[:2], '-e', 'P11LAB_PIN', image, 'init', env={'P11LAB_PIN': default_pin})
    marker = (default / 'softkms/complete').read_bytes()
    assert marker == (f'schema=1\nprovider=softkms\nartifact={marker.splitlines()[2].split(b"=")[1].decode()}'
                      f'\nlabel=softKMS\nslot=0\n').encode()
    assert re.fullmatch(rb'[0-9a-f]{64}', marker.splitlines()[2].split(b'=')[1])
    assert (default / 'softkms/complete').stat().st_mode & 0o777 == 0o600
    assert (default / 'softkms/admin-secret').read_bytes() == default_pin.encode()
    assert (default / 'softkms/admin-secret').stat().st_mode & 0o777 == 0o600
    assert TOKEN_SHAPE.match((default / 'softkms/identity-token').read_bytes())
    assert (default / 'softkms/identity-token').stat().st_mode & 0o777 == 0o600
    assert (default / 'softkms/storage').is_dir()
    docker(*base, *controls, image, 'init')
    owned = state / 'softkms'
    protected = (owned / 'complete').read_bytes()
    assert protected == marker
    assert PIN not in marker and PIN not in protected
    assert default_pin.encode() not in marker
    assert sorted(p.name for p in owned.iterdir()) == ['admin-secret', 'complete', 'identity-token',
                                                       'lease', 'storage']
    assert (owned / 'admin-secret').read_bytes() == PIN
    first_token = (owned / 'identity-token').read_bytes()
    assert TOKEN_SHAPE.match(first_token)
    assert first_token != (default / 'softkms/identity-token').read_bytes()
    (secrets / 'pin').write_bytes(b'changed-softkms-acceptance-pin-01234567')
    repeated = docker(*base, *controls, image, 'init')
    assert repeated.stdout == 'ready: native_slot=0 token_present_index=0 label=softKMS objects=0\n'
    assert (owned / 'complete').read_bytes() == protected
    assert (owned / 'admin-secret').read_bytes() == PIN
    assert (owned / 'identity-token').read_bytes() == first_token
    health = docker(*base, *controls, image, 'health')
    assert health.stdout == 'ready: native_slot=0 token_present_index=0 label=softKMS objects=0\n'
    incompatible = docker(*base, *controls[:2], '-e', 'P11LAB_LABEL=different', image, 'init', check=False)
    assert incompatible.returncode != 0 and 'label is fixed to softKMS natively' in incompatible.stderr
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\n" "$P11LAB_MODULE" "$1"; exit 37', 'caller',
                    'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == [MODULE, 'literal $argument with spaces']
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'command -v cc make python3 cargo go bazel pkcs11-tool protoc rustc; exit 0').stdout == ''
    other = root / 'scalar-state'
    other.mkdir(mode=0o700)
    scalar_base = [a.replace(f'src={state},', f'src={other},') for a in base]
    docker(*scalar_base, *controls[:2], '-e', 'P11LAB_PIN', image, 'init', env={'P11LAB_PIN': 'x' * 200})
    docker(*scalar_base, image, 'health')
    pinless = root / 'pinless-state'
    pinless.mkdir(mode=0o700)
    pinless_base = [a.replace(f'src={state},', f'src={pinless},') for a in base]
    missing = docker(*pinless_base, *controls[:2], image, 'init', check=False)
    assert missing.returncode != 0 and list(pinless.iterdir()) == []
    assert 'required credential input is absent' in missing.stderr
    for path in (root / 'secrets').iterdir():
        assert path.stat().st_mode & 0o777 == 0o600


def proof_fields(stdout):
    return dict(line.split('=', 1) for line in stdout.splitlines() if '=' in line)


def run_proof(base, controls, consumer, pin_path, mode, *extra):
    return docker(*base, *controls, consumer, 'exec', '--', 'softkms-proof',
                  '--module', MODULE, '--token-label', 'softKMS',
                  '--pin-file', pin_path, '--mode', mode, *extra).stdout


def sidecars(state):
    """Index daemon-persisted public keys by PKCS#11 label.

    PKCS#11 exposes no public key material at all (every CKA_EC_POINT read
    is unavailable, asserted below), so the independent oracles consume the
    sealed daemon's own persisted public key for the same label. The label
    binding is asserted at every call site.
    """
    found = {}
    for path in (state / 'softkms/storage/keys').glob('*/keys/*.json'):
        record = json.loads(path.read_bytes())
        assert record['label'] not in found, record['label']
        found[record['label']] = record
    return found


def test_crypto_restart_isolation_and_profile_falsification(runtime):
    channel, root, state, secrets, _image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible consumer required'
    consumer = CONSUMERS[channel]
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
              'P11LAB_LABEL': 'softKMS'}
    argv = ('p11lab-smoke', '--module', MODULE, '--token-label', 'softKMS',
            '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--output',
            '/p11lab-output/crypto', '--key-mode', 'generated')
    spec = RunSpec('softkms', channel, 'direct', as_ref(consumer), 'provider',
                   None, None, argv, inputs, root / 'generated', root, 180)
    generated = run_application(spec)
    assert generated.app_returncode == 1 and generated.exit_code != 0
    assert not generated.cleanup_errors
    error = (spec.output_dir / 'application.stderr.log').read_text()
    assert 'C_Login: CK_RV=0x000000a0' in error
    # The unchanged consumer's caller PIN is not the PKCS#11 PIN: native
    # login rejects it with 0xA0 before any key operation. Completed
    # provider observation, never a conditional xfail or pass.
    print(f'caller-credential/{channel}: native login rejects the caller PIN with 0xa0')
    docker(*base, *controls, consumer, 'init')
    pin_path = probe_pin(state, secrets)
    keygen = run_proof(base, controls, consumer, pin_path, 'keygen')
    assert 'C_GenerateKeyPair(p256-bare): CK_RV=0x00000000' in keygen
    assert 'C_GenerateKeyPair(p256): CK_RV=0x00000000' in keygen
    assert 'C_GenerateKeyPair(eddsa): CK_RV=0x00000000' in keygen
    assert 'C_GenerateKeyPair(rsa): CK_RV=0x00000070' in keygen
    assert 'total=6' in keygen
    assert 'C_DestroyObject: CK_RV=0x00000054' in keygen
    assert 'after-destroy total=6' in keygen
    assert docker(*base, *controls, consumer, 'health').stdout.endswith('objects=6\n')
    main = sidecars(state)
    assert sorted(main) == ['acceptance-generated-ed25519', 'acceptance-generated-p256', 'pkcs11-key']
    assert main['acceptance-generated-p256']['algorithm'] == 'p256'
    assert main['acceptance-generated-ed25519']['algorithm'] == 'ed25519'
    p256_one = run_proof(base, controls, consumer, pin_path, 'sign',
                             '--key-label', 'acceptance-generated-p256', '--mech', '0x1041')
    assert 'C_Sign: CK_RV=0x00000000 siglen=64' in p256_one
    first = proof_fields(p256_one)
    assert first['ecpoint'] == 'UNAVAILABLE rv=0x00000000 len=4294967295'
    ecdsa_verify_p256(hashlib.sha256(MESSAGE).digest(), bytes.fromhex(first['sig']),
                      bytes(main['acceptance-generated-p256']['public_key']))
    with pytest.raises(AssertionError):
        ecdsa_verify_p256(hashlib.sha256(b'softkms-acceptance-message-v2').digest(),
                          bytes.fromhex(first['sig']),
                          bytes(main['acceptance-generated-p256']['public_key']))
    p256_two = run_proof(base, controls, consumer, pin_path, 'sign',
                             '--key-label', 'acceptance-generated-p256', '--mech', '0x1041')
    assert 'C_Sign: CK_RV=0x00000000 siglen=64' in p256_two
    second = proof_fields(p256_two)
    # Native ECDSA is deterministic (RFC-6979-style): two separate exec
    # runs over the same message and key produce identical bytes. Both
    # signatures still verify independently below.
    assert second['sig'] == first['sig']
    ecdsa_verify_p256(hashlib.sha256(MESSAGE).digest(), bytes.fromhex(second['sig']),
                      bytes(main['acceptance-generated-p256']['public_key']))
    ed_one = run_proof(base, controls, consumer, pin_path, 'sign',
                        '--key-label', 'acceptance-generated-ed25519', '--mech', '0x1057')
    assert 'C_Sign: CK_RV=0x00000000 siglen=64' in ed_one
    ed_first = proof_fields(ed_one)
    assert ed_first['ecpoint'] == 'UNAVAILABLE rv=0x00000000 len=4294967295'
    ed25519_verify(MESSAGE, bytes.fromhex(ed_first['sig']),
                   bytes(main['acceptance-generated-ed25519']['public_key']))
    ed_second = proof_fields(run_proof(base, controls, consumer, pin_path, 'sign',
                                       '--key-label', 'acceptance-generated-ed25519',
                                       '--mech', '0x1057'))
    assert ed_second['sig'] == ed_first['sig']
    tampered = bytearray(bytes.fromhex(ed_first['sig']))
    tampered[40] ^= 1
    with pytest.raises(AssertionError):
        ed25519_verify(MESSAGE, bytes(tampered), bytes(main['acceptance-generated-ed25519']['public_key']))
    template = run_proof(base, controls, consumer, pin_path, 'find-template')
    assert 'find-template all=6 label=6 class=6 bogus=6' in template
    found = run_proof(base, controls, consumer, pin_path, 'find')
    assert 'object class=0x2 label=acceptance-generated-p256' in found
    assert 'object class=0x3 label=acceptance-generated-p256' in found
    assert 'attr CKA_EC_POINT len=4294967295 value=' in found
    assert 'attr CKA_EC_PARAMS len=4294967295 value=' in found
    assert 'attr CKA_ID len=4294967295 value=' in found
    assert 'find objects=6' in found
    other = root / 'other-state'
    other.mkdir(mode=0o700)
    other_base = [a.replace(f'src={state},', f'src={other},') for a in base]
    docker(*other_base, *controls, consumer, 'init')
    other_pin = probe_pin(other, secrets)
    assert 'C_GenerateKeyPair(p256): CK_RV=0x00000000' in run_proof(
        other_base, controls, consumer, other_pin, 'keygen')
    isolated = proof_fields(run_proof(other_base, controls, consumer, other_pin, 'sign',
                                      '--key-label', 'acceptance-generated-p256', '--mech', '0x1041'))
    separate = sidecars(other)
    assert bytes(separate['acceptance-generated-p256']['public_key']) != \
        bytes(main['acceptance-generated-p256']['public_key'])
    ecdsa_verify_p256(hashlib.sha256(MESSAGE).digest(), bytes.fromhex(isolated['sig']),
                      bytes(separate['acceptance-generated-p256']['public_key']))
    assert bytes.fromhex(isolated['sig']) != bytes.fromhex(first['sig'])
    assert (other / 'softkms/complete').is_file()
    assert 'objects=6' in docker(*other_base, *controls, consumer, 'health').stdout
    assert 'objects=6' in docker(*base, *controls, consumer, 'health').stdout
    smoke_state = root / 'smoke-state'
    smoke_state.mkdir(mode=0o700)
    smoke_base = [a.replace(f'src={state},', f'src={smoke_state},') for a in base]
    docker(*smoke_base, *controls, consumer, 'init')
    smoke_pin = probe_pin(smoke_state, secrets)
    native_smoke = docker(*smoke_base, *controls, consumer, 'exec', '--', 'p11lab-smoke',
                          '--module', MODULE, '--token-label', 'softKMS',
                          '--pin-file', smoke_pin, '--output', '/tmp/smoke-out',
                          '--key-mode', 'generated', check=False)
    assert native_smoke.returncode == 1
    assert 'attribute unavailable or exceeds bound' in native_smoke.stderr
    assert native_smoke.stderr.count('C_DestroyObject(private cleanup): CK_RV=0x00000054') == 1
    assert native_smoke.stderr.count('C_DestroyObject(public cleanup): CK_RV=0x00000054') == 1
    existing = docker(*smoke_base, *controls, consumer, 'exec', '--', 'p11lab-smoke',
                      '--module', MODULE, '--token-label', 'softKMS',
                      '--pin-file', smoke_pin, '--output', '/tmp/smoke-out2',
                      '--key-mode', 'existing', '--key-id', '01', check=False)
    assert existing.returncode == 1
    assert 'key ID selects multiple EC objects of the requested class' in existing.stderr
    # Even with the correct identity-token PIN, native keygen succeeds but
    # the public half is unreadable, cleanup is unsupported, and the ignored
    # find template defeats key selection. Completed provider observation.
    print(f'general-token/{channel}: FALSIFIED; no public attrs, no destroy, templates ignored')
    for path in root.rglob('*.log'):
        content = path.read_bytes()
        assert PIN not in content
        assert (state / 'softkms/identity-token').read_bytes() not in content


def test_native_proof_oracles_and_admin_model(runtime):
    channel, _root, state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    pin_path = probe_pin(state, secrets)
    info = run_proof(base, controls, consumer, pin_path, 'info')
    assert 'summary flags=0x404 mechanisms=10 zeros=0 objects=0' in info
    assert 'mechanisms=' + ','.join(MECHANISMS) in info
    admin = run_proof(base, controls, consumer, pin_path, 'token-admin')
    assert 'C_InitToken: CK_RV=0x00000000' in admin
    assert 'C_InitPIN: CK_RV=0x00000054' in admin
    assert 'C_SetPIN: CK_RV=0x00000054' in admin
    assert 'C_CreateObject: CK_RV=0x00000054' in admin
    assert 'C_Login(SO): CK_RV=0x00000000' in run_proof(base, controls, consumer, pin_path, 'login-so')
    assert 'C_Login: CK_RV=0x00000000' in run_proof(base, controls, consumer, pin_path, 'login')
    assert 'C_Login(empty): CK_RV=0x00000007' in run_proof(base, controls, consumer, pin_path, 'login-empty')
    assert 'C_Login(wrong): CK_RV=0x000000a0' in run_proof(
        base, controls, consumer, pin_path, 'login-wrong')
    keygen = run_proof(base, controls, consumer, pin_path, 'keygen')
    assert 'C_GenerateKeyPair(p256-bare): CK_RV=0x00000000' in keygen
    assert 'C_GenerateKeyPair(p256): CK_RV=0x00000000' in keygen
    assert 'C_GenerateKeyPair(eddsa): CK_RV=0x00000000' in keygen
    assert 'C_GenerateKeyPair(rsa): CK_RV=0x00000070' in keygen
    assert 'after-keygen' in keygen and 'total=6' in keygen
    assert 'C_DestroyObject: CK_RV=0x00000054' in keygen
    assert 'after-destroy total=6' in keygen
    repeat = run_proof(base, controls, consumer, pin_path, 'keygen')
    assert 'C_GenerateKeyPair(p256-bare): CK_RV=0x00000030' in repeat
    assert 'C_GenerateKeyPair(p256): CK_RV=0x00000030' in repeat
    assert 'C_GenerateKeyPair(eddsa): CK_RV=0x00000030' in repeat
    assert 'C_GenerateKeyPair(rsa): CK_RV=0x00000070' in repeat
    assert 'after-destroy total=6' in repeat
    # The info mode never logs in, so even with six persisted objects the
    # pre-login find sees zero — the same login gating no-login-sign proves.
    assert 'summary flags=0x404 mechanisms=10 zeros=0 objects=0' in run_proof(
        base, controls, consumer, pin_path, 'info')
    no_login = run_proof(base, controls, consumer, pin_path, 'no-login-sign',
                         '--key-label', 'acceptance-generated-p256')
    assert 'nologin-find=0' in no_login
    assert 'C_SignInit' not in no_login
    symmetric = run_proof(base, controls, consumer, pin_path, 'symmetric')
    assert 'C_GenerateKey(aes): CK_RV=0x00000054' in symmetric
    assert 'C_DeriveKey(ecdh): CK_RV=0x00000054' in symmetric
    random = run_proof(base, controls, consumer, pin_path, 'random')
    assert 'C_GenerateRandom: CK_RV=0x00000000' in random
    assert len(bytes.fromhex(proof_fields(random)['rand'])) == 32


@pytest.mark.parametrize('damage', [
    'missing-marker', 'missing-lease', 'marker-extra-lf', 'marker-drift',
    'hidden-file', 'data-link', 'busy-init', 'foreign-root'])
def test_damage_refused_before_native_launch(runtime, damage):
    _channel, _root, state, _secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    owned = state / 'softkms'
    marker = owned / 'complete'
    if damage == 'missing-marker':
        marker.unlink()
    elif damage == 'missing-lease':
        (owned / 'lease').unlink()
    elif damage == 'marker-extra-lf':
        with marker.open('ab') as file:
            file.write(b'\n')
    elif damage == 'marker-drift':
        with marker.open('ab') as file:
            file.write(b'x')
    elif damage == 'hidden-file':
        (owned / '.foreign').write_bytes(b'foreign')
    elif damage == 'data-link':
        marker.rename(owned / 'original')
        marker.symlink_to('original')
    elif damage == 'busy-init':
        (state / '.init-lock').mkdir()
    else:
        (state / 'foreign').write_bytes(b'foreign')
    before = snapshot(state)
    for operation in ['init', 'health', 'exec']:
        argv = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'echo APP-RAN']
        result = docker(*base, *controls, image, *argv, check=False)
        assert result.returncode != 0 and 'APP-RAN' not in result.stdout
        assert snapshot(state) == before, (damage, operation)


@pytest.mark.parametrize('bad,message', [
    ('empty', 'credential input is empty'),
    ('blank-line', 'credential input is empty'),
    ('multiline', 'credential input must be a single line'),
    ('nul', 'credential file contains unsupported bytes'),
    ('too-large', 'credential input exceeds 4096-byte bound'),
    ('short', 'softKMS admin passphrase requires 32..200 ASCII characters'),
    ('overlong', 'softKMS admin passphrase requires 32..200 ASCII characters'),
    ('non-ascii', 'passphrase must use printable ASCII'),
    ('conflict', 'conflicting value and file credential inputs')])
def test_bad_credentials_do_not_create_state(runtime, bad, message):
    _channel, _root, state, secrets, image, base, controls = runtime
    if bad == 'conflict':
        result = docker(*base, *controls, '-e', 'P11LAB_PIN=x', image, 'init', check=False)
    else:
        (secrets / 'pin').write_bytes({
            'empty': b'', 'blank-line': b'\n', 'multiline': b'line-one\nline-two',
            'nul': b'nul\0in-passphrase', 'too-large': b'x' * 4097, 'short': b'x' * 31,
            'overlong': b'x' * 201, 'non-ascii': b'x' * 31 + b'\xc3\xa9'}[bad])
        result = docker(*base, *controls, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []
    assert message in result.stderr


@pytest.mark.parametrize('case', ['so-scalar', 'so-file', 'so-conflict', 'so-empty'])
def test_so_inputs_are_shape_checked_and_ignored(runtime, case):
    _channel, _root, state, secrets, image, base, controls = runtime
    if case == 'so-scalar':
        docker(*base, *controls, '-e', 'P11LAB_SO_PIN=ignored-so-value', image, 'init')
        assert (state / 'softkms/complete').is_file()
        return
    if case == 'so-file':
        docker(*base, *controls, '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/pin', image, 'init')
        assert (state / 'softkms/complete').is_file()
        return
    if case == 'so-conflict':
        result = docker(*base, *controls, '-e', 'P11LAB_SO_PIN=x',
                        '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/pin', image, 'init', check=False)
        assert result.returncode != 0 and list(state.iterdir()) == []
        assert 'conflicting value and file credential inputs' in result.stderr
        return
    (secrets / 'empty-so').write_bytes(b'')
    (secrets / 'empty-so').chmod(0o600)
    result = docker(*base, *controls, '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/empty-so',
                    image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []
    assert 'credential input is empty' in result.stderr


@pytest.mark.parametrize('label', ['', 'x' * 33, 'bad\nlabel', 'bad!label'])
def test_invalid_label_never_creates_state(runtime, label):
    _channel, _root, state, _secrets, image, base, controls = runtime
    result = docker(*base, *controls[:2], '-e', 'P11LAB_LABEL=' + label, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []
    assert 'label is fixed to softKMS natively' in result.stderr


@pytest.mark.parametrize('override', ['SOFTKMS_DAEMON_ADDR', 'SOFTKMS_STORAGE_PATH',
                                      'RUST_LOG', 'LD_PRELOAD'])
def test_native_redirects_are_refused(runtime, override):
    _channel, _root, state, _secrets, image, base, controls = runtime
    result = docker(*base, *controls, '-e', override + '=', image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []
    assert 'unsupported native override' in result.stderr


def test_exact_artifact_readbacks_and_blocked_admission(runtime):
    from p11lab.licenses import assess_distribution, inspect_artifact
    channel, root, _state, _secrets, image, _base, _controls = runtime
    def read(path):
        return docker('run', '--rm', '--network', 'none', '--entrypoint', 'cat', image, path).stdout
    spec = load_environment('softkms', channel)
    assert json.loads(read('/usr/share/p11lab/provider.json')) == {
        k: v for k, v in spec.items() if k not in ('lock', 'channel', 'channel_spec', 'asset_root')}
    assert read('/usr/share/p11lab/runtime-id') == artifact_key('runtime', runtime_inputs(spec)) + '\n'
    assert 'rustc 1.98.1' in read('/usr/share/p11lab/build/rustc.txt')
    assert 'cargo 1.98.1' in read('/usr/share/p11lab/build/cargo.txt')
    assert 'libprotoc 3.21.12' in read('/usr/share/p11lab/build/protoc.txt')
    assert read('/usr/share/p11lab/build/compiler.txt').splitlines()[0] == 'cc (Debian 14.2.0-19) 14.2.0'
    options = read('/usr/share/p11lab/build/options.txt')
    assert 'cargo build --locked --offline' in options and '--jobs 2' in options
    assert ('patches=[01-function-list-order,02-attribute-encoding,03-finalize-reset,04-info-outputs,'
            '05-cli-provisioning-secrets,06-mechanism-flags]') in options
    assert 'falcon=ce15e75bceb372867daf6b8e81918ab6978686eb' in options
    assert 'xhd=3cafd074e840971a2de791593918bb1c0707cd04' in options
    assert read('/usr/share/p11lab/build/Cargo.lock') == \
        package_data('providers/softkms/rolling.Cargo.lock').read_text()
    assert read('/usr/share/p11lab/build/crates.json') == \
        package_data('providers/softkms/rolling.crates.json').read_text()
    linked = read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'not found' not in linked
    for required in ('libssl.so.3', 'libcrypto.so.3', 'libnettle.so.8', 'libhogweed.so.6',
                     'libgmp.so.10', 'libc.so.6'):
        assert required in linked, required
    assert 'AGPL-3.0' in read('/usr/share/licenses/softkms/FILE-NOTICES.txt')
    assert 'GNU AFFERO GENERAL PUBLIC LICENSE' in read('/usr/share/licenses/softkms/LICENSE.softkms-AGPL-3.0')
    inv = inspect_artifact(as_ref(image))
    (root / 'actual-content-inventory.json').write_text(json.dumps(inv, indent=2) + '\n')
    forbidden = ['/usr/bin/python3', '/usr/bin/cc', '/usr/local/bin/cargo', '/usr/local/bin/rustc',
                 '/usr/bin/protoc', '/usr/bin/openssl', '/usr/bin/pkcs11-tool', '/opt/p11lab-checker']
    assert not any(f['path'] in forbidden or f['path'].startswith('/var/lib/p11lab/')
                   or f['path'].endswith('.pem') for f in inv['files'])
    decision = assess_distribution(as_ref(image), root / 'admission')
    assert decision['status'] == decision['publication_status'] == 'blocked'
    assert decision['blockers'] and decision['source_companion'] is None


def start_long_application(runtime):
    _channel, _root, _state, _secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    name = 'p11lab-softkms-test-' + uuid.uuid4().hex[:12]
    # Keep an outer shell alive after the supervisor returns. Residual-process
    # assertions therefore cannot be satisfied by Docker's PID-1 cleanup.
    harness = ('/usr/local/bin/p11lab-provider exec -- sh -c '
               "'printf \"%s\\n\" \"$$\" > /run/p11lab/app.pid; "
               'sleep 300 & printf "%s\\n" "$!" > /run/p11lab/app-child.pid; '
               "touch /run/p11lab/app-started; wait' & "
               'supervisor=$!; printf "%s\\n" "$supervisor" > /run/p11lab/supervisor.pid; '
               'wait "$supervisor"; code=$?; printf "%s\\n" "$code" > /run/p11lab/supervisor-result; sleep 300')
    docker('run', '-d', '--name', name, *base[2:], *controls, '--entrypoint', 'sh', image, '-c', harness)
    pids = {'supervisor': '/run/p11lab/supervisor.pid', 'application': '/run/p11lab/app.pid',
            'app-child': '/run/p11lab/app-child.pid'}
    pids |= {service: f'/run/p11lab/softkms/{SERVICE_PROCESSES[service]}.pid' for service in SERVICES}
    # One docker invocation per poll: app-started is empty, so a clean read
    # yields exactly the pid lines in pids order. Any missing file fails
    # the read and the bounded loop retries.
    paths = ['/run/p11lab/app-started', *pids.values()]
    for _ in range(200):
        result = docker('exec', name, 'cat', *paths, check=False)
        if result.returncode == 0:
            try:
                values = [int(line) for line in result.stdout.splitlines()]
            except ValueError:
                values = []
            if len(values) == len(pids):
                return name, dict(zip(pids, values))
        time.sleep(0.05)
    logs = docker('logs', name, check=False)
    docker('rm', '-f', name, check=False)
    pytest.fail('supervised app did not start: ' + logs.stdout + logs.stderr)


def supervisor_result(name):
    for _ in range(200):
        result = docker('exec', name, 'cat', '/run/p11lab/supervisor-result', check=False)
        if result.returncode == 0:
            return int(result.stdout)
        time.sleep(0.05)
    pytest.fail('supervisor did not complete its bounded cleanup')


def assert_reaped_inside_live_container(name, pids):
    for role, pid in pids.items():
        assert docker('exec', name, 'test', '-e', f'/proc/{pid}', check=False).returncode != 0, role
    for service in SERVICES:
        assert docker('exec', name, 'test', '-e',
                      f'/run/p11lab/softkms/{SERVICE_PROCESSES[service]}.pid',
                      check=False).returncode != 0


def test_signal_shutdown_reaps_owned_processes(runtime):
    _channel, _root, _state, _secrets, image, base, controls = runtime
    name, pids = start_long_application(runtime)
    try:
        docker('exec', name, 'sh', '-c', 'kill -TERM "$1"', 'caller', str(pids['supervisor']))
        assert supervisor_result(name) == 143
        assert_reaped_inside_live_container(name, pids)
    finally:
        docker('rm', '-f', name, check=False)
    docker(*base, *controls, image, 'health')


@pytest.mark.parametrize('service', SERVICES)
def test_required_service_death_fails_and_reaps_application(runtime, service):
    _channel, _root, _state, _secrets, image, base, controls = runtime
    name, pids = start_long_application(runtime)
    try:
        docker('exec', name, 'sh', '-c', 'kill -KILL "$1"', 'caller', str(pids[service]))
        assert supervisor_result(name) == 1
        assert f'required {SERVICE_PROCESSES[service]} exited' in docker('logs', name).stderr
        assert_reaped_inside_live_container(name, pids)
    finally:
        docker('rm', '-f', name, check=False)
    docker(*base, *controls, image, 'health')


def test_volume_lease_refuses_a_second_container(runtime):
    _channel, _root, state, _secrets, image, base, controls = runtime
    name, pids = start_long_application(runtime)
    try:
        before = snapshot(state)
        result = docker(*base, *controls, image, 'health', check=False)
        assert result.returncode != 0 and 'already in use' in result.stderr
        assert snapshot(state) == before
        docker('exec', name, 'sh', '-c', 'kill -TERM "$1"', 'caller', str(pids['supervisor']))
        assert supervisor_result(name) == 143
        assert_reaped_inside_live_container(name, pids)
    finally:
        docker('rm', '-f', name, check=False)


def test_native_endpoints_are_loopback_even_on_a_bridge(runtime):
    _channel, _root, _state, _secrets, image, base, controls = runtime
    # Bridge exposure changes only the namespace interface roster; actual
    # listener addresses must remain loopback on the two fixed ports.
    bridge_base = [a if a != 'none' else 'bridge' for a in base]
    docker(*bridge_base, *controls, image, 'init')
    text = docker(*bridge_base, *controls, image, 'exec', '--', 'cat', '/proc/net/tcp', '/proc/net/tcp6').stdout
    listeners = [line.split()[1] for line in text.splitlines() if len(line.split()) > 3 and line.split()[3] == '0A']
    assert any(address.startswith('0100007F:') for address in listeners)
    assert not any(address.startswith('00000000:') or len(address.split(':')[0]) == 32 for address in listeners)


@pytest.mark.parametrize('channel', ['rolling'])
def test_shared_builder_native_build_observation(channel):
    if channel not in BUILDS:
        pytest.skip('explicit native build attempt required')
    out = Path(BUILDS[channel])
    record = json.loads((out / 'cli-command.json').read_text())
    assert record['returncode'] == 0
    assert (out / 'artifact.json').is_file()
    native = json.loads((out / 'native-artifact.json').read_text())
    assert native['artifact']['reference'] == IMAGES[channel]


def component_attempt(mapping, channel, role):
    if channel not in mapping:
        pytest.skip('explicit frozen ' + role + ' derivative attempt required')
    out = Path(mapping[channel])
    attempt = json.loads((out / 'attempt.json').read_text())
    assert attempt['runtime_image'] == IMAGES[channel]
    recipe = Path(attempt['context']) / 'Dockerfile'
    if role != 'consumer':
        assert recipe.read_bytes() == package_data('runtime/' + role + '.Dockerfile').read_bytes()
    assert hashlib.sha256(recipe.read_bytes()).hexdigest() == attempt['recipe_sha256']
    return attempt, out


@pytest.mark.parametrize('channel', ['rolling'])
def test_installed_checker_reports_caller_credential_rejection(channel, tmp_path):
    from p11lab.checker import run_checker
    attempt, out = component_attempt(CHECKER_ATTEMPTS, channel, 'checker')
    assert attempt['returncode'] == 0 and (out / 'image-id').read_text().strip() == CHECKERS[channel]
    root = Path(os.environ.get('P11LAB_SOFTKMS_EVIDENCE', str(tmp_path))) / 'direct-checker' / channel
    root.mkdir(parents=True)
    state, caller = root / 'state', root / 'caller'
    state.mkdir(mode=0o700)
    caller.mkdir()
    pin = root / 'pin'
    pin.write_bytes(PIN)
    pin.chmod(0o600)
    try:
        spec = RunSpec('softkms', channel, 'direct', as_ref(CHECKERS[channel]), 'provider',
                       None, None, (),
                       {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(pin),
                        'P11LAB_SO_PIN_FILE': str(pin), 'P11LAB_LABEL': 'softKMS'},
                       root / 'output', caller, 600)
        result = run_checker(spec, 'smoke-v1')
        assert result.exit_code == 1 and result.app_returncode == 1
        assert not result.cleanup_errors
        assert result.lifecycle_errors == ()
        record = json.loads((spec.output_dir / 'checker/checker-receipt.json').read_text())
        assert record['token'] == {'label': 'softKMS', 'native_slot_id': 0,
                                   'token_present_index': 0}
        assert record['slot_index'] == 0
        assert record['evidence']['complete'] is True
        assert record['evidence']['observations_complete'] is True
        summary = record['evidence']['summary']
        assert (summary['total'], summary['passed'], summary['error'], summary['skipped']) == (23, 5, 15, 3)
        stdout = (spec.output_dir / 'checker/checker.stdout.log').read_text()
        assert stdout.count('ERROR at setup') == 15
        assert 'Unexpected CK_RV CKR_PIN_INCORRECT' in stdout
        # The installed checker runs to completed evidence: its login-bearing
        # fixtures present the caller PIN, which the token rejects with 0xA0.
        # Provider behavior, never a conditional xfail or pass.
        print(f'checker/{channel}: 23 nodes, 5 passed, 15 setup errors on CKR_PIN_INCORRECT')
    finally:
        pin.unlink(missing_ok=True)


@pytest.mark.parametrize('channel', ['rolling'])
def test_preferred_proxy_independent_crypto(channel, tmp_path):
    attempt, out = component_attempt(PROXY_ATTEMPTS, channel, 'proxy')
    assert attempt['returncode'] == 0 and (out / 'image-id').read_text().strip() == DAEMONS[channel]
    assert channel in CLIENTS and CALLER
    root = Path(os.environ.get('P11LAB_SOFTKMS_EVIDENCE', str(tmp_path))) / 'proxy-crypto' / channel
    root.mkdir(parents=True)
    state, caller = root / 'state', root / 'caller'
    state.mkdir(mode=0o700)
    caller.mkdir()
    pin = root / 'pin'
    pin.write_bytes(PIN)
    pin.chmod(0o600)
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(pin),
              'P11LAB_LABEL': 'softKMS'}
    try:
        bundle = Path(CLIENTS[channel])
        client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
        spec = RunSpec('softkms', channel, 'proxy', as_ref(DAEMONS[channel]), 'container',
                       as_ref(CALLER), client, ('p11lab-smoke', '--module',
                       '/run/p11lab-client/libpkcs11_proxy_ng_shim.so', '--token-label',
                       'softKMS', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
                       '--output', '/p11lab-output/crypto', '--key-mode', 'existing', '--key-id', '01'),
                       inputs, root / 'output', caller, 600)
        result = run_application(spec)
        assert (spec.output_dir / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
        assert result.app_returncode == 1 and result.exit_code == 1
        assert not result.cleanup_errors
        # The proxy transports the native interaction faithfully: the stock
        # consumer's caller PIN is rejected remotely with 0xA0, the same
        # native outcome as the direct run, a completed app-level observation.
        assert (spec.output_dir / 'application.stderr.log').read_text().strip() == \
            'C_Login: CK_RV=0x000000a0'
        print(f'proxy/{channel}: SERVING; remote login rejection transported faithfully')
        receipt = json.loads(result.receipt_path.read_text())
        assert receipt['app_completed'] and receipt['lifecycle_errors'] == ['post-health failed']
        post = [s for s in receipt['stages'] if s['phase'] == 'post-health']
        assert len(post) == 1 and post[0]['returncode'] == 1 and not post[0]['timed_out']
        assert 'state is unsafe or already in use' in (spec.output_dir / 'post-health.stderr.log').read_text()
    finally:
        pin.unlink(missing_ok=True)
