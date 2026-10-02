"""Explicit real Docker application acceptance; no provider compilation here."""
from dataclasses import replace
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

import pytest

from p11lab.catalog import package_data
from p11lab.models import ArtifactRef, RunSpec
from p11lab.run import run_application

IMAGES = json.loads(os.environ.get('P11LAB_TEST_SMOKE_IMAGES', '{}'))
ORACLE = os.environ.get('P11LAB_TEST_ORACLE_IMAGE', '')
pytestmark = pytest.mark.skipif(not IMAGES or not ORACLE, reason='explicit compatible C consumer and independent oracle images required')


def command(*args, check=True):
    return subprocess.run(['docker', *args], capture_output=True, text=True, check=check)


@pytest.fixture(params=list(IMAGES.items()))
def invocation(request, tmp_path):
    channel, image = request.param
    root = Path(os.environ['P11LAB_TEST_APPLICATION_EVIDENCE']) / request.node.name if os.environ.get('P11LAB_TEST_APPLICATION_EVIDENCE') else tmp_path
    root.mkdir(parents=True, exist_ok=True)
    caller = root / 'caller with spaces'
    caller.mkdir()
    pin, so = caller / 'pin', caller / 'so-pin'
    pin.write_bytes(b'1234')
    so.write_bytes(b'12345678')
    pin.chmod(0o600)
    so.chmod(0o600)
    artifact = ArtifactRef('docker-local', image, image.removeprefix('sha256:'), 'linux/amd64')
    inputs = {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so), 'P11LAB_LABEL': 'P11Lab'}
    spec = RunSpec('softhsm2', channel, 'direct', artifact, 'provider', None, None,
        ('p11lab-smoke', '--module', '/usr/local/lib/p11lab/libsofthsm2.so', '--token-label', 'P11Lab',
         '--pin-file', '/run/p11lab-input/P11LAB_PIN_FILE', '--output', '/p11lab-output/crypto', '--key-mode', 'generated'),
        inputs, root / 'generated', caller, 60)
    yield spec
    pin.unlink(missing_ok=True)
    so.unlink(missing_ok=True)


def verify(spec, output):
    # Separate pinned image/process, no provider module or private token state.
    verifier = spec.cwd / 'verify.py'
    verifier.write_bytes(package_data('consumer/verify.py').read_bytes())
    result = command('run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
        '--user', f'{os.getuid()}:{os.getgid()}',
        '--tmpfs', '/tmp', '--mount', f'type=bind,src={output},dst=/crypto,readonly',
        '--mount', f'type=bind,src={verifier},dst=/verify.py,readonly',
        ORACLE, 'python3', '/verify.py', '/crypto')
    assert 'altered message rejected' in result.stdout
    (output.parent / 'oracle.json').write_text(json.dumps({'artifact': {'kind': 'docker-local', 'reference': ORACLE,
        'sha256': ORACLE.removeprefix('sha256:'), 'platform': 'linux/amd64'}, 'returncode': result.returncode,
        'stdout': result.stdout, 'positive': 'accepted', 'altered_message': 'rejected'}, indent=2))


def assert_clean(receipt):
    record = json.loads(receipt.read_text())
    assert not record['cleanup_errors']
    for item in record['owned_resources']:
        assert command(item['kind'], 'inspect', item['identity'], check=False).returncode != 0
    return record


def test_generated_crypto_independent_oracle(invocation):
    result = run_application(invocation)
    assert result.exit_code == 0, result
    metadata = json.loads((invocation.output_dir / 'crypto/result.json').read_text())
    assert metadata['key_mode'] == 'generated'
    verify(invocation, invocation.output_dir / 'crypto')
    assert_clean(result.receipt_path)


def test_persisted_key_reopens_in_fresh_containers(invocation):
    state = invocation.cwd.parent / 'persistent state'
    state.mkdir()
    inputs = invocation.inputs | {'P11LAB_STATE_DIR': str(state)}
    provision = replace(invocation, inputs=inputs, output_dir=invocation.cwd.parent / 'provision',
        argv=('pkcs11-tool', '--module', '/usr/local/lib/p11lab/libsofthsm2.so', '--token-label', 'P11Lab',
              '--login', '--pin', '1234', '--keypairgen', '--key-type', 'EC:prime256v1', '--id', '42'))
    provisioned = run_application(provision)
    assert provisioned.exit_code == 0, provisioned
    assert_clean(provisioned.receipt_path)
    results = []
    for index in range(2):
        reopen = replace(invocation, inputs=inputs, output_dir=invocation.cwd.parent / ('reopen-' + str(index)),
                         argv=(*invocation.argv[:-1], 'existing', '--key-id', '42'))
        result = run_application(reopen)
        assert result.exit_code == 0, result
        verify(reopen, reopen.output_dir / 'crypto')
        record = assert_clean(result.receipt_path)
        results.append(record['stages'][2]['container_id'])
        metadata = json.loads((reopen.output_dir / 'crypto/result.json').read_text())
        assert metadata['key_mode'] == 'existing'
        (reopen.output_dir / 'application-profile.json').write_text(json.dumps({
            'key_mode': 'existing', 'key_id_hex': '42',
            'public_key_source': metadata['public_key_source'], 'mechanism': metadata['mechanism'],
            'provider_derivative': reopen.artifact.reference, 'independent_oracle': ORACLE}, indent=2))
    assert results[0] != results[1]
    assert (invocation.cwd.parent / 'reopen-0/crypto/public-key.der').read_bytes() == (invocation.cwd.parent / 'reopen-1/crypto/public-key.der').read_bytes()


def test_caller_failure_literal_argv_and_workdir(invocation):
    argv = ('sh', '-c', 'printf "%s\\n" "$PWD" "$P11LAB_OUTPUT_DIR" "$1"; exit 7', 'caller', 'literal $(touch forbidden); spaces')
    result = run_application(replace(invocation, argv=argv))
    assert result.app_returncode == result.exit_code == 7
    assert (invocation.output_dir / 'application.stdout.log').read_text().splitlines() == ['/workspace', '/p11lab-output', argv[-1]]
    assert not (invocation.cwd / 'forbidden').exists()
    assert_clean(result.receipt_path)


def test_graceful_cli_interruption(invocation):
    # The installed acceptance script uses the same public CLI outside checkout.
    args = [sys.executable, '-m', 'p11lab', 'run', 'softhsm2', '--channel', invocation.channel,
            '--artifact', invocation.artifact.reference, '--cwd', str(invocation.cwd), '--output-dir', str(invocation.output_dir)]
    for key, value in invocation.inputs.items():
        args.extend(['--input', key + '=' + value])
    args.extend(['--', 'sh', '-c', 'trap "exit 0" TERM; touch /p11lab-output/app-ready; while :; do sleep 1; done'])
    process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               env=os.environ | {'PYTHONPATH': str(Path(__file__).resolve().parents[2] / 'src')})
    try:
        deadline = time.monotonic() + 30
        while not (invocation.output_dir / 'app-ready').exists():
            assert process.poll() is None
            assert time.monotonic() < deadline
            time.sleep(.05)
        process.send_signal(signal.SIGTERM)
        stdout, stderr = process.communicate(timeout=30)
        assert process.returncode == 143, (stdout, stderr)
        record = assert_clean(invocation.output_dir / 'receipt.json')
        assert record['interrupted_signal'] == signal.SIGTERM and not record['timeout']
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=10)


def test_application_zero_post_health_failure(invocation):
    result = run_application(replace(invocation, argv=('sh', '-c',
        'find /var/lib/p11lab/softhsm2/tokens -name token.object -delete')))
    assert result.app_returncode == 0 and result.exit_code == 1
    assert result.lifecycle_errors == ('post-health failed',)
    assert_clean(result.receipt_path)


def test_real_application_timeout(invocation):
    result = run_application(replace(invocation, argv=('sleep', '30'), timeout_seconds=8))
    assert result.app_returncode == 124 and result.exit_code == 124
    record = assert_clean(result.receipt_path)
    assert record['timeout'] and not record['interrupted_signal']


def test_neighbor_resources_survive(invocation):
    from uuid import uuid4
    name = 'p11lab-neighbor-' + uuid4().hex
    volume = command('volume', 'create', '--label', 'org.p11lab.run=another-owner', name).stdout.strip()
    neighbor = command('create', '--name', name, '--label', 'org.p11lab.run=another-owner',
                       '--entrypoint', 'sleep', invocation.artifact.reference, '30').stdout.strip()
    try:
        result = run_application(replace(invocation, argv=('true',)))
        assert result.exit_code == 0
        assert_clean(result.receipt_path)
        assert json.loads(command('container', 'inspect', neighbor).stdout)[0]['Id'] == neighbor
        assert json.loads(command('volume', 'inspect', volume).stdout)[0]['Name'] == volume
        (invocation.output_dir / 'neighbor.json').write_text(json.dumps({'container_id': neighbor,
            'volume_name': volume, 'retained_after_run': True}, indent=2))
    finally:
        # These are the test's exact created identities, not pre-existing pool resources.
        command('container', 'rm', '--force', neighbor)
        command('volume', 'rm', volume)
