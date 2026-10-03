"""Proxy placement, durable diagnostics and credential refusal regressions."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path

import pytest

from p11lab import native, run, tls
from p11lab.bundle import install_bundle
from p11lab.docker import CommandResult
from p11lab.models import ArtifactRef, RunSpec


IMAGE = ArtifactRef('docker-local', 'sha256:' + 'a' * 64, 'a' * 64, 'linux/amd64')


@pytest.fixture
def client(tmp_path, monkeypatch):
    for name in ('shim', 'cli', 'license'):
        (tmp_path / name).write_bytes(('fixture-' + name).encode())
    proxy = {'source_revision': tls.PROXY_SOURCE_REVISION, 'cargo_lock_sha256': tls.PROXY_CARGO_LOCK_SHA256,
             'source_archive_sha256': 'b' * 64, 'shim_sha256': hashlib.sha256((tmp_path / 'shim').read_bytes()).hexdigest(),
             'cli_sha256': hashlib.sha256((tmp_path / 'cli').read_bytes()).hexdigest(), 'toolchain': ['fixture']}
    artifact = native.build_native_client_bundle(
        proxy=proxy, shim=tmp_path / 'shim', cli=tmp_path / 'cli',
        licenses={f'share/licenses/proxy-ng/{name}': tmp_path / 'license' for name in ('LICENSE-APACHE', 'LICENSE-MIT')},
        output_dir=tmp_path / 'build', environment='softhsm2', channel='release')
    installed = install_bundle(artifact, tmp_path / 'prefix', environment='softhsm2', channel='release', platform='linux/amd64')
    monkeypatch.setattr(native, 'preflight_native_client', lambda *args: {
        'loader': 'fixture', 'architecture': 'x86_64', 'cli_version': 'fixture', 'closure': {'fixture': {'resolved': {}}}})
    return installed


def spec(tmp_path, client):
    return RunSpec('softhsm2', 'release', 'proxy', IMAGE, 'host', None, client.artifact,
                   ('true',), {'P11LAB_PIN': 'secret-test-pin', 'P11LAB_SO_PIN': 'secret-test-so'},
                   tmp_path / 'output', tmp_path, 0.5, client.prefix)


def snapshot(root):
    return {str(p.relative_to(root)): p.read_bytes() if p.is_file() else None for p in root.rglob('*')}


@pytest.mark.parametrize('alias', [False, True])
def test_proxy_output_overlap_preserves_installed_prefix(tmp_path, client, monkeypatch, alias):
    class Engine:
        def image(self, artifact):
            return {'Id': artifact.reference}
    monkeypatch.setattr(run, 'Docker', Engine)
    prefix = client.prefix
    if alias:
        prefix = tmp_path / 'alias'
        prefix.symlink_to(client.prefix, target_is_directory=True)
    selected = replace(spec(tmp_path, client), output_dir=prefix / 'new-output')
    before = snapshot(client.prefix)
    with pytest.raises(ValueError, match='overlap'):
        run.run_application(selected)
    assert snapshot(client.prefix) == before


@pytest.mark.parametrize('temporary', [False, True])
def test_proxy_retained_receipt_matches_placement(tmp_path, client, monkeypatch, temporary):
    class Engine:
        def image(self, artifact):
            return {'Id': artifact.reference}
        def create(self, *args):
            return 'fixture'
        def execute(self, *args):
            return CommandResult(1, '', '', False)
        def remove(self, *args):
            pass
    monkeypatch.setattr(run, 'Docker', Engine)
    selected = spec(tmp_path, client)
    if temporary:
        selected = replace(selected, installed_prefix=None)
    result = run.run_application(selected)
    record = json.loads(result.receipt_path.read_text())['proxy']['installation']
    assert record['temporary'] is temporary
    assert record['retained'] is (not temporary)
    assert Path(record['prefix']).exists() is (not temporary)


@pytest.mark.skipif(not hasattr(os, 'mkfifo'), reason='requires FIFO')
@pytest.mark.parametrize('mode', ['direct', 'proxy'])
def test_container_fifo_after_precheck_refuses_without_output(tmp_path, client, monkeypatch, mode):
    import multiprocessing
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    original = Path.is_file
    # Models replacement after the stat pre-check; opened-fd validation is required.
    monkeypatch.setattr(Path, 'is_file', lambda path: True if path == fifo else original(path))
    class Engine:
        def image(self, artifact):
            return {'Id': artifact.reference, 'Os': 'linux', 'Architecture': 'amd64'}
        def create(self, *args):
            return 'fixture'
        def execute(self, *args):
            proxy = client.manifest['source']['proxy']
            return CommandResult(0, json.dumps({'schema_version': 1, 'source_revision': proxy['source_revision'],
                                               'cargo_lock_sha256': proxy['cargo_lock_sha256'],
                                               'binaries': {'pkcs11-proxy-ng-cli': proxy['cli_sha256']}}), '', False)
        def remove(self, *args):
            pass
    monkeypatch.setattr(run, 'Docker', Engine)
    material = {'server_names': [], 'openssl_version': 'fixture', 'evidence': {'server': {}, 'client': {}}}
    for name in ('ca_cert', 'server_cert', 'server_key', 'client_cert', 'client_key'):
        material[name] = str(tmp_path / name)
    monkeypatch.setattr(tls, 'create_test_tls', lambda *args: material)
    monkeypatch.setattr(tls, 'cert_sha256', lambda *args: 'b' * 64)
    selected = replace(spec(tmp_path, client), inputs={'P11LAB_PIN_FILE': str(fifo)})
    if mode == 'direct':
        selected = replace(selected, mode='direct', execution_location='provider', installed_prefix=None, client_artifact=None)
    def attempt():
        try:
            run.run_application(selected)
        except ValueError as error:
            assert 'regular' in str(error)
            return
        raise AssertionError('FIFO intake reached resource creation')
    process = multiprocessing.get_context('fork').Process(target=attempt)
    process.start()
    process.join(1)
    blocked = process.is_alive()
    if blocked:
        process.terminate()
        process.join(2)
        if process.is_alive():
            process.kill()
            process.join(2)
    assert not blocked, 'credential intake blocked'
    assert process.exitcode == 0
    assert not selected.output_dir.exists()


def test_proxy_failure_diagnostics_use_secret_redactor(tmp_path, client, monkeypatch):
    class Engine:
        def __init__(self):
            self.argv = {}
        def volume(self, name, *args):
            return name
        def image(self, artifact):
            return {'Id': artifact.reference}
        def create(self, image, argv, options, labels, name):
            self.argv[name] = argv
            return name
        def execute(self, identity, *args):
            if self.argv[identity][0] == 'proxy-build':
                proxy = client.manifest['source']['proxy']
                return CommandResult(0, json.dumps({'schema_version': 1, 'source_revision': proxy['source_revision'],
                                                   'cargo_lock_sha256': proxy['cargo_lock_sha256'],
                                                   'binaries': {'pkcs11-proxy-ng-cli': proxy['cli_sha256']}}), '')
            if self.argv[identity][0] == 'init':
                return CommandResult(0, '', '')
            return CommandResult(2, 'secret-test-pin health', 'secret-test-so TLS failure', False, False, True)
        def command(self, args, **kwargs):
            if args[0] == 'port':
                return CommandResult(0, '127.0.0.1:12345', '')
            if args[0] == 'logs':
                return CommandResult(0, 'secret-test-pin daemon', 'secret-test-so error', False, True, False)
            return CommandResult(0, '', '')
        def remove(self, *args):
            pass
    monkeypatch.setattr(run, 'Docker', Engine)
    monkeypatch.setattr(run, '_create_proxy_network', lambda *args: 'fixture-network')
    result = run.run_application(replace(spec(tmp_path, client), timeout_seconds=1.5))
    assert result.exit_code != 0
    for name in ('proxy-health.stdout.log', 'proxy-health.stderr.log', 'daemon.stdout.log', 'daemon.stderr.log'):
        data = (result.receipt_path.parent / name).read_text()
        assert 'secret-test-pin' not in data and 'secret-test-so' not in data
    receipt = json.loads(result.receipt_path.read_text())
    assert any(stage['phase'] == 'daemon-diagnosis' and stage['stdout_truncated'] for stage in receipt['stages'])
