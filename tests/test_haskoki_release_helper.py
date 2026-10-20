"""Compile/test the test-only native helper; never claim provider behavior."""
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'tests/integration/haskoki/lifecycle.c'
HEADER = ROOT / 'src/p11lab/data/consumer/vendor'


@pytest.fixture(scope='module')
def helper(tmp_path_factory):
    if shutil.which('cc') is None:
        pytest.skip('C compiler required for test helper')
    binary = tmp_path_factory.mktemp('haskoki-helper') / 'lifecycle'
    build = subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-I' + str(HEADER), str(HELPER), '-ldl', '-o', str(binary)],
                           capture_output=True, text=True, timeout=60)
    assert build.returncode == 0, build.stderr
    return binary


def test_helper_usage_requires_explicit_operation(helper):
    result = subprocess.run([str(helper)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 2
    assert 'usage:' in result.stderr


def test_helper_preserves_module_load_failure_without_printing_secret(helper, tmp_path):
    secret = tmp_path / 'pin'
    secret.write_text('test-secret-never-in-output')
    result = subprocess.run([str(helper), '/nonexistent/module.so', 'login', 'user', str(secret)],
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 1
    assert 'dlopen failed' in result.stderr
    assert secret.read_text() not in result.stdout + result.stderr


@pytest.fixture(scope='module')
def threaded_module(tmp_path_factory):
    if shutil.which('cc') is None:
        pytest.skip('C compiler required for test helper')
    library = tmp_path_factory.mktemp('haskoki-threaded-fixture') / 'threaded.so'
    source = ROOT / 'tests/integration/haskoki/threaded-helper-fixture.c'
    build = subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-shared', '-fPIC', '-pthread', '-I' + str(HEADER),
                            str(source), '-ldl', '-o', str(library)],
                           capture_output=True, text=True, timeout=60)
    assert build.returncode == 0, build.stderr
    return library


@pytest.mark.parametrize('stop_signal', [15, 2], ids=['TERM', 'INT'])
@pytest.mark.parametrize('finalize_rv', [0, 5], ids=['finalize-ok', 'finalize-error'])
def test_holder_wakes_when_stop_runs_on_module_worker(helper, threaded_module, stop_signal, finalize_rv):
    import os
    env = os.environ | {'LD_PRELOAD': str(threaded_module), 'MOCK_STOP_SIGNAL': str(stop_signal),
                        'MOCK_FINALIZE_RV': str(finalize_rv)}
    try:
        result = subprocess.run([str(helper), str(threaded_module), 'hold'], env=env,
                                capture_output=True, text=True, timeout=3)
    except subprocess.TimeoutExpired:
        pytest.fail('holder lost worker-delivered stop and did not finalize')
    assert result.returncode == (0 if finalize_rv == 0 else 1), result.stderr
    assert 'holder-ready' in result.stdout
    assert 'worker-stop-delivered; finalize-called' in result.stderr
    if finalize_rv:
        assert 'C_Finalize failed (rv=0x5)' in result.stderr
        assert 'lifecycle: OK' not in result.stdout
    else:
        assert 'lifecycle: OK' in result.stdout
