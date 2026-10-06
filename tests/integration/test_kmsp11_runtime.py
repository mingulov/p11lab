# SPDX-License-Identifier: Apache-2.0
"""Explicit frozen kmsp11-fakekms images; no implicit builds or provider-error xfails.

P11LAB_KMSP11_{IMAGES,CONSUMERS,BUILDS,CHECKER_ATTEMPTS,PROXY_ATTEMPTS}
are JSON channel maps. EVIDENCE is a fresh private output directory. Integration
blockers are conditional on exact owning-component failure evidence, never on
native provider behavior. The caller PIN is accepted for contract
compatibility but ignored natively (C_Login(CKU_USER) succeeds with any
value); there is no security officer (native C_Login(CKU_SO) is 0xA4).
general-token is falsified: no import, no native keygen without the vendor
template, SO locked, login optional.
"""
import hashlib
import itertools
import json
import os
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

MODULE = '/usr/local/lib/p11lab/libkmsp11.so'
IMAGES = json.loads(os.environ.get('P11LAB_KMSP11_IMAGES', '{}'))
CONSUMERS = json.loads(os.environ.get('P11LAB_KMSP11_CONSUMERS', '{}'))
BUILDS = json.loads(os.environ.get('P11LAB_KMSP11_BUILDS', '{}'))
CHECKER_ATTEMPTS = json.loads(os.environ.get('P11LAB_KMSP11_CHECKER_ATTEMPTS', '{}'))
PROXY_ATTEMPTS = json.loads(os.environ.get('P11LAB_KMSP11_PROXY_ATTEMPTS', '{}'))
DAEMONS = json.loads(os.environ.get('P11LAB_KMSP11_PROXIES', '{}'))
CLIENTS = json.loads(os.environ.get('P11LAB_KMSP11_CLIENTS', '{}'))
CALLER = os.environ.get('P11LAB_KMSP11_CALLER', '')
CHECKERS = json.loads(os.environ.get('P11LAB_KMSP11_CHECKERS', '{}'))
COMMANDS = itertools.count()
PIN = b'kmsp11-acceptance-pin-0123456789abcdef12'
MESSAGE = b'kmsp11-acceptance-message-v1'
HMAC_MESSAGE = b'hmac-acceptance-message-v1'
SECP256R1_PARAMS = '06082a8648ce3d030107'
SECP384R1_PARAMS = '06052b81040022'
KEY_LABELS = ['rsa-sign-pkcs1-2048', 'rsa-sign-pss-2048', 'ec-sign-p256',
              'ec-sign-p384', 'rsa-decrypt-oaep-2048', 'hmac-sha256']
SERVICES = ['fakekms']
assert len(PIN) == 40


def docker(*args, check=True, env=None):
    argv = ['docker', *map(str, args)]
    result = subprocess.run(argv, capture_output=True, text=True, timeout=180, check=False,
                            env=os.environ | (env or {}))
    evidence = os.environ.get('P11LAB_KMSP11_EVIDENCE')
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
        pytest.skip('explicit kmsp11-fakekms runtime IDs required')
    channel = request.param
    root = Path(os.environ.get('P11LAB_KMSP11_EVIDENCE', str(tmp_path))) / request.node.name
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
    controls = ['-e', 'P11LAB_LABEL=acceptance', '-e', 'P11LAB_PIN_FILE=/run/secrets/pin']
    yield channel, root, state, secrets, IMAGES[channel], base, controls
    for child in secrets.iterdir():
        child.unlink()


def as_ref(image):
    return ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')


def snapshot(state):
    return {str(p.relative_to(state)): ('symlink', os.readlink(p)) if p.is_symlink()
            else ('file', hashlib.sha256(p.read_bytes()).hexdigest()) if p.is_file()
            else ('directory', None) for p in state.rglob('*')}


_P256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_N256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_G256 = (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
         0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)
_P384 = 2**384 - 2**128 - 2**96 + 2**32 - 1
_N384 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973
_G384 = (0xAA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7,
         0x3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F)


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


def ecdsa_verify(message, signature, ec_point, curve):
    """Independent ECDSA oracle over raw r||s and a DER EC_POINT."""
    field, order, base, digestmod, coord = curve
    point = bytes(ec_point)
    while len(point) != 1 + 2 * coord or point[0] != 0x04:
        assert point[0] == 0x04 and len(point) >= 2 and point[1] < 0x80
        assert len(point) == 2 + point[1], point.hex()
        point = point[2:]
    x, y = int.from_bytes(point[1:1 + coord], 'big'), int.from_bytes(point[1 + coord:], 'big')
    assert _mul(field, order, (x, y)) is None, 'public key not in the curve subgroup'
    assert len(signature) == 2 * coord
    r, s = int.from_bytes(signature[:coord], 'big'), int.from_bytes(signature[coord:], 'big')
    assert 1 <= r < order and 1 <= s < order
    w = pow(s, -1, order)
    digest = int.from_bytes(digestmod(message).digest(), 'big')
    found = _add(field, _mul(field, digest * w % order, base), _mul(field, r * w % order, (x, y)))
    assert found is not None and found[0] % order == r, 'signature does not verify'


P256 = (_P256, _N256, _G256, hashlib.sha256, 32)
P384 = (_P384, _N384, _G384, hashlib.sha384, 48)
SHA256_PREFIX = bytes.fromhex('3031300d060960864801650304020105000420')


def rsa_pkcs1_v15_verify(message, signature, modulus, exponent):
    """Independent RSASSA-PKCS1-v1_5/SHA-256 oracle over raw key attributes."""
    size = len(modulus)
    assert len(signature) == size and size == 256
    recovered = pow(int.from_bytes(signature, 'big'), int.from_bytes(exponent, 'big'),
                    int.from_bytes(modulus, 'big')).to_bytes(size, 'big')
    assert recovered[:2] == b'\x00\x01'
    padding_end = recovered.index(b'\x00', 2)
    assert padding_end >= 10 and set(recovered[2:padding_end]) == {0xFF}
    rest = recovered[padding_end + 1:]
    assert rest == SHA256_PREFIX + hashlib.sha256(message).digest()


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_packaged_inputs_are_closed_and_channels_distinct(channel):
    spec = load_environment('kmsp11-fakekms', channel)
    validate_build_inputs(spec)
    inputs = runtime_inputs(spec)
    expected = {'release': 'e01c9b66a4b1db63e42de956ae6b2cefde2fea67',
                'rolling': 'de849afa57f6e46c1268fbced15c161c532bff8b'}
    assert inputs['sources'][0]['revision'] == expected[channel]
    assert [p['path'] for p in inputs['patches']] == [
        'patches/01-workspace-sdk-pin.patch', 'patches/02-faultpb-generated.patch',
        'patches/03-kms-bump-v1.25.0.patch', 'patches/04-p11lab-bootstrap.patch']
    assert inputs['features']['compile_jobs'] == 2
    assert inputs['features']['bazel_freeze']['archives'] == 35
    assert inputs['features']['go_freeze']['modules'] == 86
    assert inputs['features']['go_freeze']['kms'] == 'v1.25.0'
    assert inputs['features']['keyring'] == 'projects/p/locations/global/keyRings/p11lab'
    assert inputs['features']['keys'] == KEY_LABELS
    assert inputs['features']['token_slot'] == 0
    assert inputs['features']['token_present_index'] == 0
    assert inputs['features']['mechanism_entries'] == 46
    assert inputs['features']['objects'] == 11
    assert 'bazel build --jobs=2' in inputs['features']['build_command']
    assert 'GOPROXY=off go build' in inputs['features']['build_command']
    assert spec['services'] == SERVICES
    assert spec['backend']['simulated'] is True
    assert spec['application_profile'] == 'kms-vendor-crypto'
    assert spec['distribution']['status'] == 'blocked'
    other = 'rolling' if channel == 'release' else 'release'
    assert artifact_key('runtime', inputs) != artifact_key(
        'runtime', runtime_inputs(load_environment('kmsp11-fakekms', other)))


def test_native_lifecycle_credentials_and_argv(runtime):
    _channel, root, state, secrets, image, base, controls = runtime
    assert json.loads(docker('run', '--rm', '--network', 'none', image, 'describe').stdout)['module_path'] == MODULE
    default = root / 'default-state'
    default.mkdir(mode=0o700)
    default_base = [a.replace(f'src={state},', f'src={default},') for a in base]
    docker(*default_base, image, 'init')
    marker = (default / 'kmsp11-fakekms/complete').read_bytes()
    assert b'provider=kmsp11-fakekms\n' in marker and b'label=P11Lab\n' in marker
    assert b'keyring=projects/p/locations/global/keyRings/p11lab\n' in marker
    assert (default / 'kmsp11-fakekms/complete').stat().st_mode & 0o777 == 0o600
    docker(*base, *controls, image, 'init')
    owned = state / 'kmsp11-fakekms'
    protected = (owned / 'complete').read_bytes()
    assert b'label=acceptance' in protected and b'keyring=projects/p/locations/global/keyRings/p11lab' in protected
    assert PIN not in marker and PIN not in protected
    assert sorted(p.name for p in owned.iterdir()) == ['complete', 'lease']
    (secrets / 'pin').write_bytes(b'changed-kmsp11-acceptance-pin-0123456789')
    docker(*base, *controls, image, 'init')
    assert (owned / 'complete').read_bytes() == protected
    health = docker(*base, *controls, image, 'health')
    assert health.stdout == 'ready: native_slot=0 token_present_index=0 label=acceptance keys=6 objects=11\n'
    incompatible = docker(*base, *controls, '-e', 'P11LAB_LABEL=different', image, 'init', check=False)
    assert incompatible.returncode != 0 and 'incompatible' in incompatible.stderr
    result = docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                    'printf "%s\n" "$P11LAB_MODULE" "$1"; exit 37', 'caller',
                    'literal $argument with spaces', check=False)
    assert result.returncode == 37
    assert result.stdout.splitlines() == [MODULE, 'literal $argument with spaces']
    assert docker(*base, *controls, image, 'exec', '--', 'sh', '-c',
                  'command -v cc make python3 cargo go bazel pkcs11-tool; exit 0').stdout == ''
    other = root / 'scalar-state'
    other.mkdir(mode=0o700)
    scalar_base = [a.replace(f'src={state},', f'src={other},') for a in base]
    docker(*scalar_base, '-e', 'P11LAB_PIN', image, 'init', env={'P11LAB_PIN': 'x' * 200})
    docker(*scalar_base, image, 'health')
    pinless = root / 'pinless-state'
    pinless.mkdir(mode=0o700)
    pinless_base = [a.replace(f'src={state},', f'src={pinless},') for a in base]
    docker(*pinless_base, *controls[:2], image, 'init')
    docker(*pinless_base, *controls[:2], image, 'health')
    for path in (root / 'secrets').iterdir():
        assert path.stat().st_mode & 0o777 == 0o600


def proof_fields(stdout):
    return dict(line.split('=', 1) for line in stdout.splitlines() if '=' in line)


def run_proof(base, controls, consumer, mode):
    return docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                  '--module', MODULE, '--token-label', 'acceptance',
                  '--pin-file', '/run/secrets/pin', '--mode', mode).stdout


def test_crypto_restart_isolation_and_profile_falsification(runtime):
    channel, root, state, secrets, _image, base, controls = runtime
    assert channel in CONSUMERS, 'explicit compatible consumer required'
    consumer = CONSUMERS[channel]
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(secrets / 'pin'),
              'P11LAB_LABEL': 'acceptance'}
    argv = ('p11lab-smoke', '--module', MODULE, '--token-label', 'acceptance',
            '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--output',
            '/p11lab-output/crypto', '--key-mode', 'generated')
    spec = RunSpec('kmsp11-fakekms', channel, 'direct', as_ref(consumer), 'provider',
                   None, None, argv, inputs, root / 'generated', root, 180)
    generated = run_application(spec)
    assert generated.app_returncode == 1 and generated.exit_code != 0
    assert not generated.cleanup_errors
    error = (spec.output_dir / 'application.stderr.log').read_text()
    assert 'C_GenerateKeyPair: CK_RV=0x000000d1' in error
    assert 'this token does not accept public key attributes' in error
    # The unchanged consumer's generated-key request fails natively: its EC
    # keygen template carries public-key attributes, which the token rejects
    # with 0xD1, while an empty template is 0xD0 and only the
    # CKA_KMS_ALGORITHM vendor template succeeds (keygen mode proves the
    # exact native triple). Completed provider observation, never a
    # conditional xfail or pass.
    print(f'general-token/{channel}: FALSIFIED; native keygen needs the vendor template')
    main = proof_fields(run_proof(base, controls, consumer, 'sign'))
    rsa_pkcs1_v15_verify(MESSAGE, bytes.fromhex(main['sig']),
                         bytes.fromhex(main['modulus']), bytes.fromhex(main['exponent']))
    with pytest.raises(AssertionError):
        rsa_pkcs1_v15_verify(b'kmsp11-acceptance-message-v2', bytes.fromhex(main['sig']),
                             bytes.fromhex(main['modulus']), bytes.fromhex(main['exponent']))
    main_mac = proof_fields(run_proof(base, controls, consumer, 'hmac'))
    assert main_mac['mac1'] == main_mac['mac2'] and len(bytes.fromhex(main_mac['mac1'])) == 32
    other = root / 'other-state'
    other.mkdir(mode=0o700)
    other_base = [a.replace(f'src={state},', f'src={other},') for a in base]
    docker(*other_base, *controls, consumer, 'init')
    isolated = proof_fields(docker(*other_base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                                   '--module', MODULE, '--token-label', 'acceptance',
                                   '--pin-file', '/run/secrets/pin', '--mode', 'sign').stdout)
    rsa_pkcs1_v15_verify(MESSAGE, bytes.fromhex(isolated['sig']),
                         bytes.fromhex(isolated['modulus']), bytes.fromhex(isolated['exponent']))
    # Upstream fakekms semantics are mixed: RSA keys are fixed pregenerated
    # test vectors (rsaKeyFactory loads embedded testdata/*.pem), so the
    # modulus repeats; EC and HMAC keys draw fresh crypto/rand material per
    # launch. All fake behavior, never real-KMS claims.
    assert bytes.fromhex(isolated['modulus']) == bytes.fromhex(main['modulus'])
    main_ec = proof_fields(run_proof(base, controls, consumer, 'ec-sign'))
    isolated_ec = proof_fields(docker(*other_base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                                      '--module', MODULE, '--token-label', 'acceptance',
                                      '--pin-file', '/run/secrets/pin', '--mode', 'ec-sign').stdout)
    ecdsa_verify(MESSAGE, bytes.fromhex(isolated_ec['sig']),
                 bytes.fromhex(isolated_ec['ecpoint']), P256)
    assert bytes.fromhex(isolated_ec['ecpoint']) != bytes.fromhex(main_ec['ecpoint'])
    isolated_mac = proof_fields(docker(*other_base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                                       '--module', MODULE, '--token-label', 'acceptance',
                                       '--pin-file', '/run/secrets/pin', '--mode', 'hmac').stdout)
    assert isolated_mac['mac1'] == isolated_mac['mac2']
    assert bytes.fromhex(isolated_mac['mac1']) != bytes.fromhex(main_mac['mac1'])
    assert (other / 'kmsp11-fakekms/complete').is_file()
    isolated_info = docker(*other_base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                           '--module', MODULE, '--token-label', 'acceptance',
                           '--pin-file', '/run/secrets/pin', '--mode', 'info').stdout
    for key_label in KEY_LABELS:
        assert f'label={key_label}' in isolated_info
    # Namespace isolation: a vendor key created and destroyed in the other
    # state leaves the main state untouched at 11 objects.
    other_keygen = docker(*other_base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                          '--module', MODULE, '--token-label', 'acceptance',
                          '--pin-file', '/run/secrets/pin', '--mode', 'keygen').stdout
    assert 'C_GenerateKeyPair(vendor): CK_RV=0x00000000' in other_keygen
    assert 'after-destroy count=0' in other_keygen
    main_info = docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                       '--module', MODULE, '--token-label', 'acceptance',
                       '--pin-file', '/run/secrets/pin', '--mode', 'info').stdout
    assert 'summary flags=0x400409 mechanisms=46 zeros=24 objects=11' in main_info
    for path in root.rglob('*.log'):
        assert PIN not in path.read_bytes()


def test_native_proof_oracles_and_admin_model(runtime):
    channel, _root, _state, secrets, image, base, controls = runtime
    assert channel in CONSUMERS
    consumer = CONSUMERS[channel]
    docker(*base, *controls, image, 'init')
    info = docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                  '--module', MODULE, '--token-label', 'acceptance',
                  '--pin-file', '/run/secrets/pin', '--mode', 'info')
    assert 'summary flags=0x400409 mechanisms=46 zeros=24 objects=11' in info.stdout
    admin = docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                   '--module', MODULE, '--token-label', 'acceptance',
                   '--pin-file', '/run/secrets/pin', '--mode', 'token-admin')
    assert 'C_InitToken: CK_RV=0x00000054' in admin.stdout
    assert 'C_InitPIN: CK_RV=0x00000054' in admin.stdout
    assert 'C_SetPIN: CK_RV=0x00000054' in admin.stdout
    assert 'C_CreateObject: CK_RV=0x00000054' in admin.stdout
    so = docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                '--module', MODULE, '--token-label', 'acceptance',
                '--pin-file', '/run/secrets/pin', '--mode', 'login-so')
    assert 'C_Login(SO): CK_RV=0x000000a4' in so.stdout
    login = docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                   '--module', MODULE, '--token-label', 'acceptance',
                   '--pin-file', '/run/secrets/pin', '--mode', 'login')
    assert 'C_Login: CK_RV=0x00000000' in login.stdout
    (secrets / 'pin').write_bytes(b'wrong-kmsp11-acceptance-pin-01234567890')
    wrong = docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                   '--module', MODULE, '--token-label', 'acceptance',
                   '--pin-file', '/run/secrets/pin', '--mode', 'login')
    assert 'C_Login: CK_RV=0x00000000' in wrong.stdout
    empty = docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                   '--module', MODULE, '--token-label', 'acceptance',
                   '--pin-file', '/run/secrets/pin', '--mode', 'login-empty')
    assert 'C_Login(empty): CK_RV=0x00000000' in empty.stdout
    no_login = docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                      '--module', MODULE, '--token-label', 'acceptance',
                      '--pin-file', '/run/secrets/pin', '--mode', 'no-login-sign')
    assert 'C_SignInit: CK_RV=0x00000000' in no_login.stdout
    assert 'C_Sign: CK_RV=0x00000000 siglen=256' in no_login.stdout
    pss = docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                 '--module', MODULE, '--token-label', 'acceptance',
                 '--pin-file', '/run/secrets/pin', '--mode', 'pss')
    assert 'C_SignInit(params): CK_RV=0x00000000' in pss.stdout
    assert 'C_Sign: CK_RV=0x00000000 siglen=256' in pss.stdout
    assert 'C_SignInit(bare): CK_RV=0x00000071' in pss.stdout
    ec = proof_fields(docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                             '--module', MODULE, '--token-label', 'acceptance',
                             '--pin-file', '/run/secrets/pin', '--mode', 'ec-sign').stdout)
    assert ec['ecparams'] == SECP256R1_PARAMS
    ecdsa_verify(MESSAGE, bytes.fromhex(ec['sig']), bytes.fromhex(ec['ecpoint']), P256)
    with pytest.raises(AssertionError):
        ecdsa_verify(b'kmsp11-acceptance-message-v2', bytes.fromhex(ec['sig']),
                     bytes.fromhex(ec['ecpoint']), P256)
    ec384 = proof_fields(docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                                '--module', MODULE, '--token-label', 'acceptance',
                                '--pin-file', '/run/secrets/pin', '--mode', 'ec384-sign').stdout)
    assert ec384['ecparams'] == SECP384R1_PARAMS
    ecdsa_verify(MESSAGE, bytes.fromhex(ec384['sig']), bytes.fromhex(ec384['ecpoint']), P384)
    with pytest.raises(AssertionError):
        ecdsa_verify(b'kmsp11-acceptance-message-v2', bytes.fromhex(ec384['sig']),
                     bytes.fromhex(ec384['ecpoint']), P384)
    decrypt = docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                     '--module', MODULE, '--token-label', 'acceptance',
                     '--pin-file', '/run/secrets/pin', '--mode', 'decrypt')
    assert 'C_Decrypt: CK_RV=0x00000000 match=1' in decrypt.stdout
    keygen = docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                    '--module', MODULE, '--token-label', 'acceptance',
                    '--pin-file', '/run/secrets/pin', '--mode', 'keygen')
    assert 'C_GenerateKeyPair(bare): CK_RV=0x000000d0' in keygen.stdout
    assert 'C_GenerateKeyPair(vendor): CK_RV=0x00000000' in keygen.stdout
    assert 'C_DestroyObject: CK_RV=0x00000000' in keygen.stdout
    assert 'after-destroy count=0' in keygen.stdout
    random = docker(*base, *controls, consumer, 'exec', '--', 'kmsp11-proof',
                    '--module', MODULE, '--token-label', 'acceptance',
                    '--pin-file', '/run/secrets/pin', '--mode', 'random')
    assert 'C_GenerateRandom: CK_RV=0x00000000' in random.stdout
    assert len(bytes.fromhex(proof_fields(random.stdout)['rand'])) == 32


@pytest.mark.parametrize('damage', [
    'missing-marker', 'missing-lease', 'marker-extra-lf', 'marker-drift',
    'hidden-file', 'data-link', 'busy-init', 'foreign-root'])
def test_damage_refused_before_native_launch(runtime, damage):
    _channel, _root, state, _secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    owned = state / 'kmsp11-fakekms'
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


@pytest.mark.parametrize('bad', ['empty', 'blank-line', 'multiline', 'nul',
                                'too-large', 'conflict', 'so-scalar', 'so-file'])
def test_bad_credentials_do_not_create_state(runtime, bad):
    _channel, _root, state, secrets, image, base, controls = runtime
    if bad == 'conflict':
        result = docker(*base, *controls, '-e', 'P11LAB_PIN=x', image, 'init', check=False)
        assert result.returncode != 0 and list(state.iterdir()) == []
        return
    elif bad == 'so-scalar':
        result = docker(*base, *controls, '-e', 'P11LAB_SO_PIN=x', image, 'init', check=False)
        assert result.returncode != 0 and list(state.iterdir()) == []
        assert 'SO PIN has no native meaning' in result.stderr
        return
    elif bad == 'so-file':
        result = docker(*base, *controls, '-e', 'P11LAB_SO_PIN_FILE=/run/secrets/pin',
                        image, 'init', check=False)
        assert result.returncode != 0 and list(state.iterdir()) == []
        assert 'SO PIN has no native meaning' in result.stderr
        return
    else:
        (secrets / 'pin').write_bytes({
            'empty': b'', 'blank-line': b'\n', 'multiline': b'line-one\nline-two',
            'nul': b'nul\0in-passphrase', 'too-large': b'x' * 4097}[bad])
    result = docker(*base, *controls, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []


@pytest.mark.parametrize('label', ['', 'x' * 33, 'bad\nlabel', 'bad!label'])
def test_invalid_label_never_creates_state(runtime, label):
    _channel, _root, state, _secrets, image, base, controls = runtime
    result = docker(*base, *controls, '-e', 'P11LAB_LABEL=' + label, image, 'init', check=False)
    assert result.returncode != 0 and list(state.iterdir()) == []


@pytest.mark.parametrize('override', ['KMS_PKCS11_CONFIG', 'GRPC_VERBOSITY',
                                      'LD_PRELOAD', 'OPENSSL_CONF'])
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
    spec = load_environment('kmsp11-fakekms', channel)
    assert json.loads(read('/usr/share/p11lab/provider.json')) == {
        k: v for k, v in spec.items() if k not in ('lock', 'channel', 'channel_spec', 'asset_root')}
    assert read('/usr/share/p11lab/runtime-id') == artifact_key('runtime', runtime_inputs(spec)) + '\n'
    assert 'go1.27' in read('/usr/share/p11lab/build/go-version.txt')
    assert '6.4.0' in read('/usr/share/p11lab/build/bazel-version.txt')
    assert read('/usr/share/p11lab/build/compiler.txt').splitlines()[0] == 'cc (Debian 14.2.0-19) 14.2.0'
    assert 'patches=[01-workspace-sdk-pin' in read('/usr/share/p11lab/build/options.txt')
    linked = read('/usr/share/p11lab/build/runtime-linked-dependencies.txt')
    assert 'not found' not in linked
    assert 'libstdc++.so.6' in linked and 'libgcc_s.so.1' in linked and 'libc.so.6' in linked
    assert 'Apache-2.0' in read('/usr/share/licenses/kmsp11-fakekms/FILE-NOTICES.txt')
    assert 'Apache' in read('/usr/share/licenses/kmsp11-fakekms/LICENSE.kms-integrations')
    inv = inspect_artifact(as_ref(image))
    (root / 'actual-content-inventory.json').write_text(json.dumps(inv, indent=2) + '\n')
    forbidden = ['/usr/bin/python3', '/usr/bin/cc', '/usr/local/bin/cargo', '/usr/local/go/bin/go',
                 '/usr/bin/openssl', '/usr/bin/pkcs11-tool', '/opt/p11lab-checker']
    assert not any(f['path'] in forbidden or f['path'].startswith('/var/lib/p11lab/')
                   or f['path'].endswith('.pem') for f in inv['files'])
    decision = assess_distribution(as_ref(image), root / 'admission')
    assert decision['status'] == decision['publication_status'] == 'blocked'
    assert decision['blockers'] and decision['source_companion'] is None


def start_long_application(runtime):
    _channel, _root, _state, _secrets, image, base, controls = runtime
    docker(*base, *controls, image, 'init')
    name = 'p11lab-kmsp11-test-' + uuid.uuid4().hex[:12]
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
    pids |= {service: f'/run/p11lab/kmsp11/{service}.pid' for service in SERVICES}
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
        assert docker('exec', name, 'test', '-e', f'/run/p11lab/kmsp11/{service}.pid',
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
        assert f'required {service} exited' in docker('logs', name).stderr
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
    # listener addresses must remain loopback. fakekms takes an ephemeral
    # loopback port, so only the address family is asserted, never a number.
    bridge_base = [a if a != 'none' else 'bridge' for a in base]
    docker(*bridge_base, *controls, image, 'init')
    text = docker(*bridge_base, *controls, image, 'exec', '--', 'cat', '/proc/net/tcp', '/proc/net/tcp6').stdout
    listeners = [line.split()[1] for line in text.splitlines() if len(line.split()) > 3 and line.split()[3] == '0A']
    assert any(address.startswith('0100007F:') for address in listeners)
    assert not any(address.startswith('00000000:') or len(address.split(':')[0]) == 32 for address in listeners)


@pytest.mark.parametrize('channel', ['release', 'rolling'])
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


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_installed_checker_so_gap_blocks_observations(channel, tmp_path):
    from p11lab.checker import run_checker
    attempt, out = component_attempt(CHECKER_ATTEMPTS, channel, 'checker')
    assert attempt['returncode'] == 0 and (out / 'image-id').read_text().strip() == CHECKERS[channel]
    root = Path(os.environ.get('P11LAB_KMSP11_EVIDENCE', str(tmp_path))) / 'direct-checker' / channel
    root.mkdir(parents=True)
    state, caller = root / 'state', root / 'caller'
    state.mkdir(mode=0o700)
    caller.mkdir()
    pin = root / 'pin'
    pin.write_bytes(PIN)
    pin.chmod(0o600)
    try:
        spec = RunSpec('kmsp11-fakekms', channel, 'direct', as_ref(CHECKERS[channel]), 'provider',
                       None, None, (),
                       {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(pin)},
                       root / 'output', caller, 600)
        result = run_checker(spec, 'smoke-v1')
        assert result.exit_code == 1 and result.app_returncode == 1
        assert not result.cleanup_errors
        assert result.lifecycle_errors == ('checker observation evidence incomplete or unavailable',)
        assert "KeyError: 'P11LAB_SO_PIN'" in (spec.output_dir / 'application.stderr.log').read_text()
        assert not (spec.output_dir / 'checker/checker-receipt.json').exists()
    finally:
        pin.unlink(missing_ok=True)
    pytest.xfail('shared run_checker requires P11LAB_SO_PIN unconditionally; '
                 'kmsp11-fakekms has no SO (native C_Login(CKU_SO)=0xa4, SO inputs refused)')


@pytest.mark.parametrize('channel', ['release', 'rolling'])
def test_preferred_proxy_independent_crypto(channel, tmp_path):
    attempt, out = component_attempt(PROXY_ATTEMPTS, channel, 'proxy')
    assert attempt['returncode'] == 0 and (out / 'image-id').read_text().strip() == DAEMONS[channel]
    assert channel in CLIENTS and CALLER
    root = Path(os.environ.get('P11LAB_KMSP11_EVIDENCE', str(tmp_path))) / 'proxy-crypto' / channel
    root.mkdir(parents=True)
    state, caller = root / 'state', root / 'caller'
    state.mkdir(mode=0o700)
    caller.mkdir()
    pin = root / 'pin'
    pin.write_bytes(PIN)
    pin.chmod(0o600)
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN_FILE': str(pin)}
    try:
        bundle = Path(CLIENTS[channel])
        client = ArtifactRef('bundle', str(bundle), hashlib.sha256(bundle.read_bytes()).hexdigest(), 'linux/amd64')
        spec = RunSpec('kmsp11-fakekms', channel, 'proxy', as_ref(DAEMONS[channel]), 'container',
                       as_ref(CALLER), client, ('p11lab-smoke', '--module',
                       '/run/p11lab-client/libpkcs11_proxy_ng_shim.so', '--token-label',
                       'P11Lab', '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE',
                       '--output', '/p11lab-output/crypto', '--key-mode', 'existing', '--key-id', '01'),
                       inputs, root / 'output', caller, 600)
        result = run_application(spec)
        assert (spec.output_dir / 'proxy-health.stdout.log').read_text().strip() == 'SERVING'
        assert result.app_returncode == 1 and result.exit_code == 1
        assert not result.cleanup_errors
        # The proxy transports the native interaction faithfully: the stock
        # consumer's key-id lookup completes remotely and reports no EC
        # private key for ID 01, a completed app-level observation.
        assert (spec.output_dir / 'application.stderr.log').read_text().strip() == \
            'p11lab-smoke: key ID selects no EC private key'
        print(f'proxy/{channel}: SERVING; remote key-id lookup completed with no match')
        receipt = json.loads(result.receipt_path.read_text())
        assert receipt['app_completed'] and receipt['lifecycle_errors'] == ['post-health failed']
        post = [s for s in receipt['stages'] if s['phase'] == 'post-health']
        assert len(post) == 1 and post[0]['returncode'] == 1 and not post[0]['timed_out']
        assert 'state is unsafe or already in use' in (spec.output_dir / 'post-health.stderr.log').read_text()
    finally:
        pin.unlink(missing_ok=True)
