"""Completed archive evidence must reproduce its native identity and hashes."""
import hashlib
import json
import tarfile
import pytest

from p11lab.identity import artifact_key
from p11lab.native import build_bouncyhsm_bundle


@pytest.mark.parametrize('proof', ['identity', 'manifest-sha'])
def test_completed_bouncy_archive_has_one_identity(tmp_path, proof):
    payload = tmp_path / 'payload'
    (payload / 'server').mkdir(parents=True)
    # Acquisition-interface fixture; these bytes are never executed or qualified.
    for path in ('server/BouncyHsm.exe', 'BouncyHsm.Pkcs11Lib.dll', 'bouncyhsm-probe.exe', 'LICENSE'):
        (payload / path).write_bytes(('fixture: ' + path).encode())
    output = tmp_path / 'build'
    artifact = build_bouncyhsm_bundle(
        environment='bouncyhsm', channel='rolling', target='windows-amd64',
        output_dir=output, payload_dir=payload,
        build_meta={'source_revision': 'f09ab9a342741c56bb56621a707c1b94dfdeac4b',
                    'sdk_version': '10.0.401', 'toolset': 'v145', 'compiler': 'fixture'})
    with tarfile.open(artifact.reference) as archive:
        manifest_bytes = archive.extractfile('manifest.json').read()
        native_id = archive.extractfile('payload/share/p11lab/native-id').read().decode()
    manifest = json.loads(manifest_bytes)
    receipt = json.loads((output / 'artifact.json').read_text())
    if proof == 'identity':
        assert artifact_key('native', manifest['build']['identity']['inputs']) == manifest['build']['key'] == native_id
    else:
        assert receipt['manifest_sha256'] == hashlib.sha256(manifest_bytes).hexdigest()
    assert receipt['build_key'] == native_id
    assert receipt['manifest_sha256'] == hashlib.sha256(manifest_bytes).hexdigest()
    assert receipt['artifact']['sha256'] == artifact.sha256
