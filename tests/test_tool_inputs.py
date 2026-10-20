"""A resolved file is evidence, never an authority for its own digest."""
import copy
import hashlib
import importlib
import json

import pytest


def module():
    return importlib.import_module('p11lab.tool_inputs')


def test_packaged_consumer_lock_has_exact_curated_inventory():
    lock = module().load_tool_input_lock('consumer', target='debian13-amd64')
    assert lock['apt_snapshot'] == '20260918T000000Z'
    assert lock['base_image'].endswith('@sha256:7792b1f7702a86946cd518db72b6a407302c3e9bc1635634368b878189e8221c')
    assert len(lock['parent_packages']) == 78
    assert len(lock['packages']) == 43
    assert len(lock['sources']) == 16
    assert sum(len(s['files']) for s in lock['sources']) == 48
    assert len(lock['metadata']) == 9
    assert len(lock['resources']) == 8
    assert len(lock['stages']['compiler']['packages']) == 114
    assert len(lock['stages']['consumer']['packages']) == 86
    assert sum(p['size'] for p in lock['packages']) == 60235540
    assert lock['license_status'] == 'unreviewed'


def test_curated_parent_matches_supported_softhsm_release_runtime():
    from p11lab.catalog import package_data
    lock = module().load_tool_input_lock('consumer', target='debian13-amd64')
    parent = json.loads(package_data('providers/softhsm2/release.lock.json').read_bytes())
    fields = ('name', 'version', 'architecture', 'source_package', 'source_version')
    runtime = [{k: p[k] for k in fields} for p in parent['packages'] if p['phase'] == 'runtime']
    assert lock['parent_packages'] == runtime
    assert lock['apt_snapshot'] == parent['apt_snapshot']
    assert lock['base_image'] == parent['base_images'][0]


@pytest.mark.parametrize('toolset,target', [('checker', 'debian13-amd64'), ('proxy', 'debian13-amd64'),
                                           ('../consumer', 'debian13-amd64'), ('consumer', 'windows-amd64')])
def test_tool_lock_rejects_unsupported_selection_before_output(toolset, target):
    with pytest.raises(ValueError, match='unsupported'):
        module().load_tool_input_lock(toolset, target=target)


def changed_asset(monkeypatch, transform):
    m = module()
    original = m.package_data
    class Asset:
        def __init__(self, data): self.data = data
        def read_bytes(self): return self.data
    def read(name):
        asset = original(name)
        if name.endswith('.lock.json'):
            data = json.loads(asset.read_bytes())
            transform(data)
            return Asset(json.dumps(data).encode())
        return asset
    monkeypatch.setattr(m, 'package_data', read)
    return m


@pytest.mark.parametrize('change', [
    lambda x: x.update(extra=True),
    lambda x: x['packages'][0].update(size=True),
    lambda x: x['packages'][0].update(size=-1),
    lambda x: x['packages'][0].update(size=0),
    lambda x: x['packages'][0].update(size=2**40),
    lambda x: x['packages'][0].update(sha256='A'*64),
    lambda x: x['packages'][0].update(architecture='arm64'),
    lambda x: x['packages'][0].update(source_version='wrong'),
    lambda x: x['packages'][0].update(index='trixie-updates.Packages'),
    lambda x: x['packages'].append(copy.deepcopy(x['packages'][0])),
    lambda x: x['packages'][0].update(path='../escape'),
    lambda x: x['packages'][0].update(path='/absolute'),
    lambda x: x['packages'][0].update(path='C:\\drive'),
    lambda x: x['packages'][1].update(path=x['packages'][0]['path']+'/child'),
    lambda x: x['sources'][0]['files'].pop(),
    lambda x: x['sources'][0]['files'][0].update(sha256='0'*64),
    lambda x: x['resources'][0].update(sha256='0'*64),
    lambda x: x['parent_packages'][0].update(version='wrong'),
    lambda x: x['stages']['compiler']['packages'].pop(),
    lambda x: x['provenance'].update(sha256='0'*64),
])
def test_tool_lock_rejects_ambiguous_records(monkeypatch, change):
    m = changed_asset(monkeypatch, change)
    with pytest.raises(ValueError):
        m.load_tool_input_lock('consumer', target='debian13-amd64')


def test_duplicate_json_keys_are_rejected(monkeypatch):
    m = module()
    original = m.package_data
    class Asset:
        def read_bytes(self): return b'{"schema_version":1,"schema_version":1}'
    monkeypatch.setattr(m, 'package_data', lambda name: Asset() if name.endswith('.lock.json') else original(name))
    with pytest.raises(ValueError, match='duplicate'):
        m.load_tool_input_lock('consumer', target='debian13-amd64')


@pytest.mark.parametrize('resource', ['consumer/smoke.c', 'tool-inputs/consumer.debian13-amd64.provenance.json'])
def test_tool_lock_verifies_provenance_and_owned_resources(monkeypatch, resource):
    m = module()
    original = m.package_data
    class Asset:
        def read_bytes(self): return b'altered packaged bytes'
    monkeypatch.setattr(m, 'package_data', lambda name: Asset() if name == resource else original(name))
    with pytest.raises(ValueError, match='checksum|provenance|resource'):
        m.load_tool_input_lock('consumer', target='debian13-amd64')


def alter_provenance(monkeypatch, transform):
    m = module()
    original = m.package_data
    lock = json.loads(original('tool-inputs/consumer.debian13-amd64.lock.json').read_bytes())
    proof = json.loads(original(lock['provenance']['path']).read_bytes())
    transform(proof)
    raw = json.dumps(proof).encode()
    lock['provenance']['sha256'] = hashlib.sha256(raw).hexdigest()
    class Asset:
        def __init__(self, data): self.data = data
        def read_bytes(self): return self.data
    def read(name):
        if name.endswith('.lock.json'): return Asset(json.dumps(lock).encode())
        if name == lock['provenance']['path']: return Asset(raw)
        return original(name)
    monkeypatch.setattr(m, 'package_data', read)
    return m


@pytest.mark.parametrize('change', [
    lambda p: p['relations']['compiler'].pop(),
    lambda p: p['relations']['consumer'].append(copy.deepcopy(p['relations']['consumer'][0])),
    lambda p: p['relations']['consumer'][0].update(selected_version='wrong'),
    lambda p: p['relations']['consumer'][0].update(selected_alternative='absent'),
    lambda p: p['relations']['consumer'][0].update(group='invented-dependency'),
    lambda p: p['source_bindings'][0]['files'].pop(),
    lambda p: p['parent_package_evidence'][0].update(version='wrong'),
    lambda p: p['conflicts']['compiler'].append('unexpected conflict'),
])
def test_fixed_proof_rejects_incomplete_or_substituted_witnesses(monkeypatch, change):
    m = alter_provenance(monkeypatch, change)
    with pytest.raises(ValueError):
        m.load_tool_input_lock('consumer', target='debian13-amd64')


def alter_authority(monkeypatch, change):
    """Reseal after mutation so structure, not only digest mismatch, is tested."""
    m = module()
    original = m.package_data
    lock = json.loads(original('tool-inputs/consumer.debian13-amd64.lock.json').read_bytes())
    proof = json.loads(original(lock['provenance']['path']).read_bytes())
    change(lock, proof)
    proof['lock_binding_sha256'] = m._digest(m._canonical({k: v for k, v in lock.items() if k != 'provenance'}))
    raw = json.dumps(proof).encode()
    lock['provenance']['sha256'] = hashlib.sha256(raw).hexdigest()
    class Asset:
        def __init__(self, data): self.data = data
        def read_bytes(self): return self.data
    def read(name):
        if name.endswith('.lock.json'): return Asset(json.dumps(lock).encode())
        if name == lock['provenance']['path']: return Asset(raw)
        return original(name)
    monkeypatch.setattr(m, 'package_data', read)
    return m


@pytest.mark.parametrize('change', [
    lambda l,p: p.update(schema_version=True),
    lambda l,p: p.update(metadata={}),
    lambda l,p: p['metadata']['trixie'].update(extra=True),
    lambda l,p: p['metadata']['trixie']['indexes'][0]['uncompressed'].update(size=True),
    lambda l,p: p['metadata']['trixie'].update(signatures=[]),
    lambda l,p: p['metadata']['verifier'].update(keyring_sha256='wrong'),
    lambda l,p: p['parent_package_evidence'][0]['relations'].update(Unknown='x'),
    lambda l,p: p['parent_package_evidence'][0].update(index='other.Packages'),
    lambda l,p: p.update(parent_incorporated_source_ids=['forged=1']),
    lambda l,p: p.update(limitations=None),
    lambda l,p: l['packages'][0].update(index='unknown.Packages'),
    lambda l,p: l['packages'][0].update(url=l['packages'][0]['url'].replace('20260918','20260919')),
    lambda l,p: l['metadata'][0].update(sha256='0'*64),
    lambda l,p: l['sources'][0].update(index='unknown.Sources'),
    lambda l,p: l['sources'][0]['files'][0].update(url='https://snapshot.debian.org/archive/wrong/file.dsc'),
    lambda l,p: l['packages'][0].update(name='../bad'),
])
def test_nested_provenance_structure_is_checked_even_when_resealed(monkeypatch, change):
    m = alter_authority(monkeypatch, change)
    with pytest.raises(ValueError):
        m.load_tool_input_lock('consumer', target='debian13-amd64')
