import copy
import hashlib
import json

import pytest

from p11lab.catalog import (
    CatalogError, list_environments, load_environment, packaged_asset,
    package_data, validate_build_inputs, validate_descriptor, validate_tools,
)


EXPECTED_IDS = {
    'softhsm2', 'kryoptic', 'freehsm', 'haskoki', 'nss', 'wolfpkcs11',
    'pkcs11rs', 'opencryptoki', 'ykcs11', 'bouncyhsm', 'craton', 'cryptech',
    'corepkcs11', 'tpm2', 'opensc-pico', 'sc-hsm', 'opensc-isoapplet',
    'opensc-pivapplet', 'nethsm', 'siguldry', 'kmsp11-fakekms',
    'pkcs11-to-cmd', 'rustssm', 'softkms',
}


def test_full_cohort_has_distinct_module_and_backend_dispositions():
    entries = list_environments()
    assert {s['id'] for s in entries} == EXPECTED_IDS
    assert len(entries) == 24
    for spec in entries:
        validate_descriptor(spec)
        assert spec['module_implementation']['name']
        assert spec['backend']['name']
        assert spec['distribution']['status'] == 'unreviewed'
        assert set(spec['channels']) == {'release', 'rolling'}
    by_id = {s['id']: s for s in entries}
    assert by_id['opensc-pico']['module_implementation'] == by_id['opensc-isoapplet']['module_implementation']
    assert by_id['sc-hsm']['module_implementation'] != by_id['opensc-pico']['module_implementation']
    assert by_id['kmsp11-fakekms']['backend']['simulated'] is True
    assert by_id['corepkcs11']['state_mode'] == 'process-local'
    assert 'windows/amd64' in by_id['bouncyhsm']['runtime_platforms']


def test_planned_entries_can_be_described_but_not_built():
    spec = load_environment('softhsm2', 'release')
    assert spec['channel_spec']['status'] == 'planned'
    assert 'lock' not in spec
    assert 'lock' not in spec['channel_spec']
    assert 'recipe' not in spec['channel_spec']
    with pytest.raises(CatalogError, match='locked'):
        validate_build_inputs(spec)


@pytest.mark.parametrize('environment', ['haskoki', 'pkcs11rs'])
def test_absent_release_tags_report_unavailable_reason(environment):
    spec = load_environment(environment, 'release')
    assert spec['channel_spec']['status'] == 'unavailable'
    assert 'tag' in spec['channel_spec']['reason']
    with pytest.raises(CatalogError, match='locked'):
        validate_build_inputs(spec)


def test_unknown_channel_and_environment_are_errors():
    with pytest.raises(CatalogError, match='channel'):
        load_environment('softhsm2', 'typo')
    with pytest.raises(CatalogError, match='environment'):
        load_environment('../softhsm2', 'release')


def test_invalid_full_source_revision_is_rejected():
    spec = load_environment('softhsm2', 'release')
    spec['channels']['release']['source']['revision'] = '13e6e86'
    with pytest.raises(CatalogError, match='revision'):
        validate_descriptor(spec)


def test_license_status_is_required_even_for_unreviewed_source():
    spec = load_environment('softhsm2', 'release')
    del spec['channels']['release']['source']['license_status']
    with pytest.raises(CatalogError, match='license_status'):
        validate_descriptor(spec)


def test_descriptor_cannot_grant_distribution_permission():
    spec = load_environment('softhsm2', 'release')
    spec['distribution'] = {'status': 'eligible'}
    with pytest.raises(CatalogError, match='digest-bound'):
        validate_descriptor(spec)


@pytest.mark.parametrize('path', ['../tools.json', '/tmp/provider.json', 'a/../../tools.json', r'..\tools.json'])
def test_packaged_asset_rejects_escape(path):
    with pytest.raises(CatalogError, match='relative'):
        packaged_asset('softhsm2', path)


@pytest.fixture
def locked_environment(tmp_path):
    spec = load_environment('softhsm2', 'release')
    assets = []
    for role, path, content in [('recipe', 'Dockerfile', b'FROM scratch\n'), ('adapter', 'adapter.sh', b'#!/bin/sh\n')]:
        (tmp_path / path).write_bytes(content)
        assets.append({'role': role, 'path': path, 'sha256': hashlib.sha256(content).hexdigest()})
    lock = {
        'schema_version': 1,
        'sources': [{'kind': 'git', 'url': 'https://example.org/token.git', 'revision': 'a' * 40, 'license_status': 'unreviewed'}],
        'dependencies': [], 'patches': [],
        'base_images': ['example.org/base@sha256:' + 'b' * 64],
        'packages': [], 'toolchain': [], 'features': {}, 'assets': assets,
    }
    (tmp_path / 'release.lock.json').write_text(json.dumps(lock))
    spec['channels']['release'] = {'status': 'locked', 'lock': 'release.lock.json'}
    spec['channel_spec'] = copy.deepcopy(spec['channels']['release'])
    spec['lock'] = lock
    return spec, tmp_path


def test_locked_build_requires_real_verified_assets(locked_environment):
    spec, root = locked_environment
    validate_descriptor(spec, asset_root=root)
    validate_build_inputs(spec, asset_root=root)
    (root / 'adapter.sh').unlink()
    with pytest.raises(CatalogError, match='asset'):
        validate_build_inputs(spec, asset_root=root)


def test_locked_asset_content_mismatch_fails(locked_environment):
    spec, root = locked_environment
    (root / 'Dockerfile').write_text('changed')
    with pytest.raises(CatalogError, match='sha256'):
        validate_build_inputs(spec, asset_root=root)


def test_locked_paths_cannot_escape_provider_root(locked_environment):
    spec, root = locked_environment
    spec['channels']['release']['lock'] = '../release.lock.json'
    with pytest.raises(CatalogError, match='relative'):
        validate_descriptor(spec, asset_root=root)


def test_symlink_asset_cannot_escape_provider_root(locked_environment):
    spec, root = locked_environment
    outside = root.parent / 'outside-adapter.sh'
    outside.write_text('#!/bin/sh\n')
    (root / 'adapter.sh').unlink()
    (root / 'adapter.sh').symlink_to(outside)
    with pytest.raises(CatalogError, match='escape'):
        validate_build_inputs(spec, asset_root=root)


def test_nss_rolling_uses_actual_master_branch():
    spec = load_environment('nss', 'rolling')
    assert spec['channel_spec']['source']['selector'] == {'kind': 'branch', 'value': 'master'}


def test_tools_reject_truncated_commit_pins():
    tools = json.loads(package_data('tools.json').read_text())
    tools['tools']['checker']['source']['revision'] = 'de4db3d'
    with pytest.raises(CatalogError, match='revision'):
        validate_tools(tools)


def test_tools_require_explicit_artifact_disposition():
    tools = json.loads(package_data('tools.json').read_text())
    del tools['tools']['proxy']['status']
    with pytest.raises(CatalogError, match='status'):
        validate_tools(tools)


@pytest.mark.parametrize('field', [
    ('channels', 'release', 'source', 'license_status'),
    ('channels', 'release', 'source', 'kind'),
    ('channels', 'release', 'source', 'selector', 'kind'),
    ('state_mode',),
    ('distribution', 'status'),
])
@pytest.mark.parametrize('malformed', [[], {}])
def test_malformed_descriptor_enums_raise_catalog_error(field, malformed):
    spec = load_environment('softhsm2', 'release')
    parent = spec
    for key in field[:-1]:
        parent = parent[key]
    parent[field[-1]] = malformed
    with pytest.raises(CatalogError):
        validate_descriptor(spec)


def test_malformed_consumer_license_status_raises_catalog_error():
    tools = json.loads(package_data('tools.json').read_text())
    tools['tools']['consumer']['license_status'] = []
    with pytest.raises(CatalogError, match='license_status'):
        validate_tools(tools)


def test_malformed_patch_license_status_raises_catalog_error(locked_environment):
    spec, root = locked_environment
    spec['lock']['patches'] = [{'license_status': []}]
    (root / 'release.lock.json').write_text(json.dumps(spec['lock']))
    with pytest.raises(CatalogError, match='license_status'):
        validate_descriptor(spec, asset_root=root)
