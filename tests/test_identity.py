import copy
import json

import pytest

from p11lab.identity import IdentityError, artifact_key, public_identity


def runtime():
    return {
        'sources': [{'revision': 'a' * 40}], 'dependencies': [],
        'patches': ['b' * 64], 'base_images': ['c' * 64], 'packages': [],
        'toolchain': [], 'recipe': 'd' * 64, 'adapter': 'e' * 64,
        'metadata': 'f' * 64, 'platform': 'linux/amd64', 'features': {},
    }


def derivative(parent, wheel='1' * 64):
    return {
        'parent': {'kind': 'oci', 'reference': 'example.org/token@sha256:' + parent,
                   'sha256': parent, 'platform': 'linux/amd64'},
        'artifacts': [{'sha256': wheel}], 'dependency_locks': [],
        'recipe': '2' * 64, 'platform': 'linux/amd64', 'features': {},
    }


def run(artifact):
    return {
        'artifacts': [{'kind': 'oci', 'reference': 'example.org/checker@sha256:' + artifact,
                       'sha256': artifact, 'platform': 'linux/amd64'}],
        'profile': {'id': 'smoke-v1', 'sha256': 'b' * 64}, 'configuration': {}, 'initialization': {},
        'selection': ['test_module'], 'datasets': [], 'limits': {'timeout': 30},
        'attempt_id': '4eb1e1fa-38b4-4c58-8862-184c2421ed11',
    }


def test_checker_update_rebuilds_only_derivative_and_run():
    provider = runtime()
    parent = artifact_key('runtime', provider)
    old = artifact_key('checker', derivative(parent))
    new = artifact_key('checker', derivative(parent, '3' * 64))
    assert old != new
    assert artifact_key('run', run(old)) != artifact_key('run', run(new))
    assert artifact_key('runtime', provider) == parent


@pytest.mark.parametrize('field', ['adapter', 'metadata', 'patches', 'base_images'])
def test_runtime_input_changes_invalidate_descendant_identities(field):
    before = runtime()
    after = copy.deepcopy(before)
    after[field] = ['9' * 64] if isinstance(before[field], list) else '9' * 64
    old_parent = artifact_key('runtime', before)
    new_parent = artifact_key('runtime', after)
    assert old_parent != new_parent
    old = artifact_key('checker', derivative(old_parent))
    new = artifact_key('checker', derivative(new_parent))
    assert old != new
    assert artifact_key('run', run(old)) != artifact_key('run', run(new))


def test_map_order_preserves_identity():
    inputs = runtime()
    inputs['features'] = {'sqlite': True, 'crypto': {'name': 'openssl', 'version': '4'}}
    reordered = dict(reversed(list(inputs.items())))
    reordered['features'] = {'crypto': {'version': '4', 'name': 'openssl'}, 'sqlite': True}
    assert artifact_key('runtime', inputs) == artifact_key('runtime', reordered)


def test_secret_values_and_hashes_never_enter_public_identity():
    inputs = run('a' * 64)
    inputs['secrets'] = {'pin': 'private-pin-DO-NOT-PUBLISH'}
    public = public_identity('run', inputs)
    assert 'private-pin-DO-NOT-PUBLISH' not in json.dumps(public)
    assert 'secrets' not in public['inputs']
    other = copy.deepcopy(inputs)
    other['secrets']['pin'] = 'other-pin'
    other['attempt_id'] = '982a5ac4-26ed-4aa1-a1da-607ba5cfbe48'
    assert artifact_key('run', inputs) != artifact_key('run', other)


def test_credentials_outside_explicit_secret_map_are_rejected():
    inputs = run('a' * 64)
    inputs['initialization']['P11LAB_PIN'] = 'do-not-publish'
    with pytest.raises(IdentityError, match='secret'):
        public_identity('run', inputs)


@pytest.mark.parametrize('mutation', ['missing', 'typo', 'nonfinite', 'mutable_parent'])
def test_incomplete_or_ambiguous_identity_is_rejected(mutation):
    inputs = derivative('a' * 64)
    if mutation == 'missing':
        del inputs['parent']
    elif mutation == 'typo':
        inputs['receipe'] = inputs.pop('recipe')
    elif mutation == 'nonfinite':
        inputs['features']['bad'] = float('nan')
    else:
        inputs['parent']['reference'] = 'example.org/token:latest'
    with pytest.raises(IdentityError):
        artifact_key('checker', inputs)


def test_run_requires_opaque_attempt_identity():
    inputs = run('a' * 64)
    del inputs['attempt_id']
    with pytest.raises(IdentityError, match='attempt_id'):
        artifact_key('run', inputs)


@pytest.mark.parametrize('field', ['recipe', 'adapter', 'metadata', 'sources', 'base_images'])
def test_runtime_identity_rejects_unpinned_components(field):
    inputs = runtime()
    inputs[field] = [{'revision': 'main'}] if field == 'sources' else ['latest'] if field == 'base_images' else 'unknown'
    with pytest.raises(IdentityError):
        artifact_key('runtime', inputs)


def test_derivative_identity_rejects_unsealed_added_artifact():
    inputs = derivative('a' * 64)
    inputs['artifacts'] = [{'name': 'checker-wheel'}]
    with pytest.raises(IdentityError, match='sha256'):
        artifact_key('checker', inputs)


def test_run_profile_requires_content_identity():
    inputs = run('a' * 64)
    inputs['profile'] = 'smoke-v1'
    with pytest.raises(IdentityError, match='profile'):
        artifact_key('run', inputs)
