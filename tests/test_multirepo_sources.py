"""Owning-component repro: dependencies and patches must remain source-bound."""
import copy
import hashlib
import io
from pathlib import Path
import tarfile

import pytest

from p11lab.build import BuildError, prepare_context, validate_context
from p11lab.catalog import CatalogError, _lock, _provider_root, load_environment
from p11lab.sources import acquire_source, resolve_sources


def fixture_spec(tmp_path, monkeypatch):
    spec = copy.deepcopy(load_environment('cryptech', 'rolling'))
    sources = []
    for name in ('primary', 'hal', 'math'):
        archive = tmp_path / (name + '.tar')
        content = (name + '\n').encode()
        with tarfile.open(archive, 'w') as out:
            member = tarfile.TarInfo('data')
            member.size = len(content)
            out.addfile(member, io.BytesIO(content))
        sources.append({'id': name, 'kind': 'archive', 'url': archive.as_uri(),
                        'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()})
    spec['lock'].update(sources=sources[:1], dependencies=sources[1:], assets=[], patches=[])
    monkeypatch.setattr('p11lab.catalog.validate_build_inputs', lambda spec: None)
    monkeypatch.setattr('p11lab.sources.validate_build_inputs', lambda spec: None)
    return spec


def test_dependency_archives_keep_distinct_contents_and_hashes(tmp_path, monkeypatch):
    spec = fixture_spec(tmp_path, monkeypatch)
    resolved = resolve_sources(spec, output_dir=tmp_path / 'resolved')
    context = tmp_path / 'context'
    declared = prepare_context(spec, resolved, context)
    validate_context(context, declared)
    for filename, content in [('source.tar', b'primary\n'),
                              ('dependency-0.tar', b'hal\n'), ('dependency-1.tar', b'math\n')]:
        with tarfile.open(context / filename) as archive:
            assert archive.extractfile('data').read() == content
        assert (context / filename.replace('.tar', '.sha256')).read_text() == declared[filename] + '  ' + filename + '\n'


def test_targeted_patch_order_and_legacy_primary_default(tmp_path, monkeypatch):
    spec = fixture_spec(tmp_path, monkeypatch)
    patches = []
    for number, (old, new, target) in enumerate([('hal', 'first', 'hal'),
                                               ('primary', 'default', None), ('first', 'second', 'hal')]):
        path = tmp_path / f'{number}.patch'
        path.write_text(f'--- a/data\n+++ b/data\n@@ -1 +1 @@\n-{old}\n+{new}\n')
        record = {'path': str(path)}
        if target:
            record['target_source'] = target
        patches.append(record)
    spec['lock']['patches'] = patches
    monkeypatch.setattr('p11lab.sources.locked_asset', lambda environment, patch: Path(patch['path']))
    resolved = resolve_sources(spec, output_dir=tmp_path / 'resolved')
    assert (Path(resolved['sources'][0]['checkout']) / 'data').read_text() == 'default\n'
    assert (Path(resolved['dependencies'][0]['checkout']) / 'data').read_text() == 'second\n'
    assert (Path(resolved['dependencies'][1]['checkout']) / 'data').read_text() == 'math\n'
    # Original source archives remain untouched by every patch.
    for record in resolved['sources'] + resolved['dependencies']:
        assert hashlib.sha256(Path(record['archive']).read_bytes()).hexdigest() == record['source']['sha256']


@pytest.mark.parametrize('damage', ['reorder', 'omit', 'wrong-archive-hash', 'changed-archive-and-receipt'])
def test_dependency_roster_or_integrity_failure_emits_no_context_result(tmp_path, monkeypatch, damage):
    spec = fixture_spec(tmp_path, monkeypatch)
    resolved = resolve_sources(spec, output_dir=tmp_path / 'resolved')
    if damage == 'reorder':
        resolved['dependencies'].reverse()
    elif damage == 'omit':
        resolved['dependencies'].pop()
    elif damage == 'wrong-archive-hash':
        resolved['dependencies'][0]['sha256'] = '0' * 64
    else:
        record = resolved['dependencies'][0]
        archive = Path(record['archive'])
        archive.write_bytes(archive.read_bytes() + b'tampered')
        record['sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
    with pytest.raises(BuildError, match='roster|checksum'):
        prepare_context(spec, resolved, tmp_path / 'context')
    assert not (tmp_path / 'context/build-inputs.json').exists()


@pytest.mark.parametrize('damage', ['unknown-target', 'duplicate-source-id', 'invalid-source-id'])
def test_catalogue_rejects_ambiguous_patch_target_before_acquisition(damage):
    spec = load_environment('cryptech', 'rolling')
    lock = copy.deepcopy(spec['lock'])
    if damage == 'unknown-target':
        lock['patches'][0]['target_source'] = 'absent'
    elif damage == 'duplicate-source-id':
        lock['dependencies'][0]['id'] = lock['sources'][0]['id']
    else:
        lock['dependencies'][0]['id'] = '../hal'
    with pytest.raises(CatalogError, match='source IDs|target_source'):
        _lock(lock, _provider_root('cryptech'), 'cryptech')


def test_low_level_unmodified_source_acquisition_still_works(tmp_path, monkeypatch):
    spec = fixture_spec(tmp_path, monkeypatch)
    source = spec['lock']['sources'][0]
    acquired = acquire_source(source, tmp_path / 'standalone')
    assert acquired['source'] == source and acquired['sha256'] == source['sha256']
