"""Admission rejects incomplete closure and verifies the bytes recipients receive."""
import hashlib
import json
from pathlib import Path
import tarfile
from dataclasses import asdict

import pytest

from p11lab.models import ArtifactRef
from p11lab import sources


def fixture_inventory(tmp_path):
    binary = tmp_path / 'binary.tar'
    import io
    with tarfile.open(binary, 'w') as tar:
        item = tarfile.TarInfo('demo.txt'); item.size = 4
        tar.addfile(item, io.BytesIO(b'demo'))
    artifact = ArtifactRef('bundle', str(binary), hashlib.sha256(binary.read_bytes()).hexdigest(), 'linux/amd64')
    payloads = []
    for path, role, text in [('sources/demo.tar', 'source', 'complete source'), ('notices/demo.txt', 'notice', 'original grant'), ('BUILD.md', 'build', 'portable build instructions')]:
        local = tmp_path / Path(path).name
        local.write_text(text)
        payloads.append({'path': path, 'role': role, 'local_path': str(local), 'sha256': hashlib.sha256(local.read_bytes()).hexdigest(), 'size': local.stat().st_size})
    inventory = {'schema_version': 1, 'artifact': asdict(artifact), 'role': 'runtime',
        'observation': {'artifact': asdict(artifact), 'packages': [], 'binaries': [], 'linked_libraries': [], 'files': [{'path': '/demo.txt', 'sha256': hashlib.sha256(b'demo').hexdigest(), 'size': 4, 'mode': 420, 'package': None}]},
        'content_reviews': [{'path': '/demo.txt', 'sha256': hashlib.sha256(b'demo').hexdigest(), 'source': 'demo=1', 'status': 'reviewed'}],
        'sources': [{'id': 'demo=1', 'name': 'demo', 'version': '1', 'payloads': ['sources/demo.tar']}],
        'components': [{'id': 'demo=1', 'source': 'demo=1', 'scope': 'runtime'}],
        'reviews': [{'source': 'demo=1', 'status': 'reviewed', 'grant_known': True, 'source_redistribution': True,
                     'license_declared': 'MIT', 'license_concluded': 'MIT', 'chosen_route': 'retain grant and complete source',
                     'notices': ['notices/demo.txt'], 'grant_evidence': ['notices/demo.txt'], 'obligations': ['source', 'notice'], 'modifications': 'unmodified'}],
        'patches': [], 'payloads': payloads, 'build_instructions': 'BUILD.md', 'limitations': []}
    return artifact, inventory


def assemble(tmp_path):
    artifact, inventory = fixture_inventory(tmp_path)
    output = tmp_path / 'evidence'
    archive = sources.collect_source_bundle(artifact, inventory, output)
    return artifact, inventory, output, archive


def test_source_companion_is_portable_and_source_only(tmp_path):
    artifact, inventory, output, archive = assemble(tmp_path)
    with tarfile.open(archive) as contents:
        public = contents.extractfile('inventory.json').read().decode()
        assert str(tmp_path) not in public
        assert contents.extractfile('sources/demo.tar').read() == b'complete source'
        assert 'binary.tar' not in contents.getnames()
    assert sources.verify_source_bundle(archive, tmp_path / 'clean')['artifact']['sha256'] == artifact.sha256


def test_complete_evidence_is_eligible_but_never_publicly_authorized(tmp_path):
    from p11lab.licenses import assess_distribution
    artifact, inventory, output, archive = assemble(tmp_path)
    result = assess_distribution(artifact, output)
    assert result['status'] == 'eligible'
    assert result['publication_status'] == 'blocked'
    assert result['publication_blockers'] == ['anonymous-source-first delivery not verified']
    sbom = json.loads((output / 'sbom.spdx.json').read_text())
    assert sbom['spdxVersion'] == 'SPDX-2.3'
    assert sbom['packages'][0]['licenseConcluded'] == 'MIT'


@pytest.mark.parametrize('damage', ['source', 'notice', 'build', 'grant', 'patch', 'dependency', 'binary', 'changed-image', 'agpl'])
def test_incomplete_or_changed_evidence_refuses_admission(tmp_path, damage):
    from p11lab.licenses import assess_distribution
    artifact, inventory = fixture_inventory(tmp_path)
    if damage in {'source', 'notice', 'build'}:
        inventory['payloads'] = [p for p in inventory['payloads'] if p['role'] != damage]
    elif damage == 'grant':
        inventory['reviews'][0]['grant_known'] = False
    elif damage == 'patch':
        inventory['patches'] = [{'sha256': 'a' * 64, 'status': 'unreviewed'}]
    elif damage == 'dependency':
        inventory['observation']['linked_libraries'] = [{'binary': 'demo', 'needed': 'libmissing.so', 'resolved': []}]
    elif damage == 'binary':
        Path(artifact.reference).write_bytes(b'changed binary')
    elif damage == 'changed-image':
        inventory['artifact']['sha256'] = 'f' * 64
    elif damage == 'agpl':
        inventory['reviews'][0]['obligations'].append('agpl-remote-source')
    with pytest.raises(ValueError):
        sources.collect_source_bundle(artifact, inventory, tmp_path / 'evidence')


def test_changed_companion_bytes_block_existing_admission(tmp_path):
    from p11lab.licenses import assess_distribution
    artifact, inventory, output, archive = assemble(tmp_path)
    with archive.open('ab') as stream:
        stream.write(b'corruption')
    result = assess_distribution(artifact, output)
    assert result['status'] == 'blocked'
    assert any('checksum' in reason for reason in result['blockers'])


def test_forged_inventory_cannot_authorize_an_unrelated_digest(tmp_path):
    from p11lab.licenses import assess_distribution
    artifact, inventory, output, archive = assemble(tmp_path)
    changed = ArtifactRef(artifact.kind, artifact.reference, 'b' * 64, artifact.platform)
    assert assess_distribution(changed, output)['status'] == 'blocked'


def test_source_checksum_mismatch_refuses_collection(tmp_path):
    artifact, inventory = fixture_inventory(tmp_path)
    Path(inventory['payloads'][0]['local_path']).write_text('wrong source')
    with pytest.raises(ValueError, match='checksum|size'):
        sources.collect_source_bundle(artifact, inventory, tmp_path / 'evidence')


def test_unsafe_archive_cannot_escape_clean_extraction(tmp_path):
    import io
    archive = tmp_path / 'evil.tar'
    with tarfile.open(archive, 'w') as contents:
        item = tarfile.TarInfo('../outside')
        item.size = 1
        contents.addfile(item, io.BytesIO(b'x'))
    with pytest.raises(ValueError):
        sources.verify_source_bundle(archive, tmp_path / 'extract')
    assert not (tmp_path / 'outside').exists()


def test_real_sqv_static_metadata_requires_complete_source_roster(tmp_path):
    from p11lab.licenses import validate_inventory, parse_dpkg_status
    text = 'Package: sqv\nStatus: install ok installed\nVersion: 1.3.0-3+b2\nArchitecture: amd64\nSource: rust-sequoia-sqv (1.3.0-3)\nBuilt-Using: rust-nettle (= 7.3.0-1), rustc (= 1.85.0+dfsg3-1)\nStatic-Built-Using: rust-nettle (= 7.3.0-1), rust-clap (= 4.5.23-1)\n'
    packages = parse_dpkg_status(text)
    assert packages[0]['source_version'] == '1.3.0-3'
    assert packages[0]['incorporated_sources'] == ['rust-clap=4.5.23-1', 'rust-nettle=7.3.0-1', 'rustc=1.85.0+dfsg3-1']
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['observation']['packages'] = packages
    reasons = validate_inventory(artifact, inventory)
    assert any('rustc=1.85.0+dfsg3-1' in reason for reason in reasons)
    assert any('rust-sequoia-sqv=1.3.0-3' in reason for reason in reasons)


def test_spdx_includes_actual_binary_and_incorporated_relationships(tmp_path):
    from p11lab.licenses import spdx_inventory
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['observation']['packages'] = [{'name': 'demo-bin', 'version': '1+b2', 'architecture': 'amd64',
        'source_package': 'demo', 'source_version': '1', 'incorporated_sources': ['helper=2']}]
    inventory['sources'].append({'id': 'helper=2', 'name': 'helper', 'version': '2', 'payloads': []})
    inventory['reviews'].append({'source': 'helper=2', 'license_declared': 'MIT', 'license_concluded': 'NOASSERTION'})
    sbom = spdx_inventory(artifact, inventory)
    assert any(p['name'] == 'demo-bin' and p['versionInfo'] == '1+b2' for p in sbom['packages'])
    assert any(r['relationshipType'] == 'STATIC_LINK' for r in sbom['relationships'])
    assert any(r['relationshipType'] == 'GENERATED_FROM' for r in sbom['relationships'])
    assert next(p for p in sbom['packages'] if p['name'] == 'helper')['licenseConcluded'] == 'NOASSERTION'


def test_missing_reviewed_grant_file_blocks_despite_known_license_label(tmp_path):
    from p11lab.licenses import validate_inventory
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['reviews'][0]['grant_evidence'] = ['notices/absent.txt']
    assert any('grant evidence' in reason for reason in validate_inventory(artifact, inventory))


def test_deleted_lower_layer_bytes_require_their_own_review(tmp_path):
    import io
    from p11lab.licenses import inspect_distribution_archive, validate_inventory
    layers = []
    for name, data in [('layer-a.tar', b'hidden unreviewed program'), ('layer-b.tar', b'')]:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as tar:
            item = tarfile.TarInfo('secret' if data else '.wh.secret')
            item.size = len(data)
            tar.addfile(item, io.BytesIO(data))
        layers.append((name, stream.getvalue()))
    archive = tmp_path / 'image-save.tar'
    config = b'{"architecture":"amd64","os":"linux"}'
    with tarfile.open(archive, 'w') as tar:
        entries = layers + [('config.json', config), ('manifest.json', json.dumps([{'Config':'config.json','Layers':[n for n,d in layers]}]).encode())]
        for name, data in entries:
            item=tarfile.TarInfo(name);item.size=len(data);tar.addfile(item,io.BytesIO(data))
    distribution = inspect_distribution_archive(archive, [])
    assert distribution['hidden_layer_files'][0]['path'] == '/secret'
    assert distribution['whiteouts'] == ['/secret']
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['observation']['distribution'] = distribution
    assert any('lower-layer' in reason for reason in validate_inventory(artifact, inventory))


def test_debian_dsc_requires_all_corresponding_payloads(tmp_path):
    artifact, inventory = fixture_inventory(tmp_path)
    dsc = tmp_path / 'demo.dsc'
    dsc.write_text('Format: 3.0 (quilt)\nSource: demo\nVersion: 1\nChecksums-Sha256:\n ' + '1'*64 + ' 12 demo.orig.tar.xz\n')
    inventory['payloads'][0] = {'path': 'sources/demo.dsc', 'local_path': str(dsc), 'role': 'source', 'size': dsc.stat().st_size, 'sha256': hashlib.sha256(dsc.read_bytes()).hexdigest()}
    inventory['sources'][0]['payloads'] = ['sources/demo.dsc']
    inventory['sources'][0]['format'] = 'debian'
    with pytest.raises(ValueError, match='Debian.*payload'):
        sources.collect_source_bundle(artifact, inventory, tmp_path / 'evidence')


def test_debug_admission_requires_exact_parent_relationship(tmp_path):
    from p11lab.licenses import validate_inventory
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['role'] = 'debug-companion'
    assert any('debug' in reason and 'parent' in reason for reason in validate_inventory(artifact, inventory))


def test_unreviewed_copied_script_blocks_known_package_inventory(tmp_path):
    from p11lab.licenses import validate_inventory
    artifact, inventory = fixture_inventory(tmp_path)
    inventory['observation']['files'].append({'path': '/new-script', 'sha256': 'f'*64, 'package': None})
    assert any('/new-script' in reason for reason in validate_inventory(artifact, inventory))
