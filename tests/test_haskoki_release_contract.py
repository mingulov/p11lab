"""Source-level release candidate contracts, not module/runtime qualification."""
import hashlib
import json

from p11lab.catalog import load_environment, packaged_asset, validate_build_inputs

REVISION = '091a2223e6dc559af72913c7f5a061ca22af34dc'
ARCHIVE = 'be8bb8363ec624c05db9ab1c7132dab14348512cf10023b1dcc8c91882b1ec97'


def test_release_locks_exact_verified_source_without_replacing_rolling():
    release = load_environment('haskoki', 'release')
    assert release['channel_spec']['status'] == 'locked'
    validate_build_inputs(release)
    source, = release['lock']['sources']
    assert source['revision'] == REVISION
    assert source['archive_sha256'] == ARCHIVE
    assert source['selector'] == {'kind': 'tag', 'value': 'v0.5.0.0'}
    assert source['license_status'] == 'unreviewed'
    evidence, = source['license_evidence']
    assert evidence['sha256'] == 'c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4'
    assert REVISION in evidence['url'] and evidence['variant'] == 'release'
    rolling = load_environment('haskoki', 'rolling')['lock']
    assert rolling['sources'][0]['revision'] == 'e442a38dbbe12b1024c7852b0f0709130f92a112'
    assert hashlib.sha256(packaged_asset('haskoki', 'rolling.lock.json').read_bytes()).hexdigest() == '22b9c3aba07612e905d8e60d232b23fdfbdfaa9da15e1cf73bd9d860391b63e4'


def test_release_is_not_advertised_as_measured_or_distribution_eligible():
    spec = load_environment('haskoki', 'release')
    features = spec['lock']['features']
    assert features['validation_status'] == 'pending-cold-build-and-runtime'
    assert features['source_license_closure_status'] == 'pending-actual-build-review'
    assert features['fixed_auth_policy'] == 'adapter-fixed-demo-initialization'
    assert features['sqlite_schema_version'] == 3
    assert 'bundled_libhs_count' not in features
    assert 'glibc_floor' not in features
    assert features['required_build_gates'] == {'bundled_libhs_count': 24, 'glibc_floor': '2.38', 'hackage_sdist_count': 2}
    assert spec['distribution']['status'] == 'unreviewed'
    assert 'pending' in spec['distribution']['reason'].lower()
    assert not spec.get('native_targets')


def test_release_recipe_keeps_strict_gates_and_exact_ctl_version():
    spec = load_environment('haskoki', 'release')
    recipe, = [a for a in spec['lock']['assets'] if a['role'] == 'recipe']
    assert recipe['path'] == 'release/Dockerfile' and recipe['context_path'] == 'Dockerfile'
    text = packaged_asset('haskoki', recipe['path']).read_text()
    assert "haskoki-ctl 0\\.5\\.0\\.0" in text
    assert "[ \"$bundled\" = 24 ]" in text
    assert "[ \"$floor\" = GLIBC_2.38 ]" in text
    assert '[ "$hackage_count" = 2 ]' in text
    assert 'unexpected host dep outside' in text
    assert 'sha256sum -c source.sha256' in text
    assert 'dynamic libcrypto in module closure (must be static pinned)' in text


def test_release_schema_readiness_gap_is_explicit_not_silently_patched():
    spec = load_environment('haskoki', 'release')
    assert spec['lock']['features']['schema_readiness_status'] == 'pending-upstream-read-only-schema-validation'
    assert spec['lock']['patches'] == []
    assert 'schema-safe' in spec['distribution']['reason']


def test_release_assets_survive_installed_wheel_without_checkout(tmp_path):
    import os
    from pathlib import Path
    import subprocess
    root = Path(__file__).resolve().parents[1]
    wheels = tmp_path / 'wheels'
    subprocess.run(['uv', 'build', '--wheel', '--out-dir', str(wheels), str(root)],
                   check=True, capture_output=True, text=True, timeout=120)
    wheel = next(wheels.glob('*.whl'))
    import zipfile
    with zipfile.ZipFile(wheel) as archive:
        for name in ('release.lock.json', 'release/Dockerfile', 'release/entrypoint.sh', 'release/FILE-NOTICES.txt'):
            packaged = 'p11lab/data/providers/haskoki/' + name
            assert archive.read(packaged) == packaged_asset('haskoki', name).read_bytes()
    caller = tmp_path / 'caller'
    caller.mkdir()
    # Import from the wheel itself, without an editable source route.
    script = '''
import sys
sys.path.insert(0, sys.argv[1])
from p11lab.catalog import load_environment, validate_build_inputs
s = load_environment('haskoki', 'release')
validate_build_inputs(s)
assert s['lock']['sources'][0]['revision'] == '091a2223e6dc559af72913c7f5a061ca22af34dc'
print(s['channel_spec']['status'])
'''
    env = {k: v for k, v in os.environ.items() if k not in {'PYTHONPATH', 'PYTHONHOME'}}
    result = subprocess.run([__import__('sys').executable, '-I', '-c', script, str(wheel)],
                            cwd=caller, env=env, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == 'locked'


def test_release_recipe_reports_measured_gate_values_before_fail_closed_checks():
    text = packaged_asset('haskoki', 'release/Dockerfile').read_text()
    for field, value, gate in (
        ('bundled_libhs_count', '$bundled', '[ "$bundled" = 24 ]'),
        ('glibc_floor', '$floor', '[ "$floor" = GLIBC_2.38 ]'),
        ('hackage_archive_count', '$hackage_count', '[ "$hackage_count" = 2 ]'),
    ):
        diagnostic = f'printf \'p11lab-gate: {field}=%s\\n\' "{value}"'
        assert diagnostic in text
        assert text.index(diagnostic) < text.index(gate)


def test_release_adapter_retains_reviewed_rolling_executable_lifecycle():
    # Release-only changes explain adapter policy; executable shell behavior is
    # exactly the existing, adversarially-tested lifecycle, including persistent
    # init_signal handlers and atomic transition into cleanup. No new policy
    # branch is inferred from upstream version.
    def executable(path):
        return '\n'.join(line for line in packaged_asset('haskoki', path).read_text().splitlines()
                         if line.strip() and not line.lstrip().startswith('#'))
    assert executable('release/entrypoint.sh') == executable('entrypoint.sh')
