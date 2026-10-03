"""Host supervision contains descendants and finishes logs before returning."""
import os
from pathlib import Path
import signal
import sys
import time

import pytest

from p11lab.run import _run_proxy_host_app


def alive(pid):
    if sys.platform.startswith('linux'):
        try:
            return Path(f'/proc/{pid}/stat').read_text().split(') ', 1)[1][0] != 'Z'
        except FileNotFoundError:
            return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


@pytest.mark.skipif(os.name != 'posix', reason='POSIX process-tree regression')
@pytest.mark.parametrize('parent_timeout', [False, True])
@pytest.mark.parametrize('escape', [False, True])
def test_host_application_descendants_end_before_receipt(tmp_path, parent_timeout, escape):
    child = 'import os,time; print("child-ready",flush=True); time.sleep(30)'
    argv = (sys.executable, '-c',
            'import subprocess,sys,time; from pathlib import Path; '
            f'p=subprocess.Popen([sys.executable,"-c",{child!r}],start_new_session={escape!r}); '
            f'Path({str(tmp_path / "child-pid")!r}).write_text(str(p.pid)); '
            'time.sleep(0.1); ' + ('time.sleep(30)' if parent_timeout else 'sys.exit(0)'))
    pid = None
    try:
        status, timed_out, evidence = _run_proxy_host_app(
            argv, cwd=tmp_path, env=dict(os.environ), output=tmp_path,
            timeout=0.5, interrupted=lambda: False, secrets=[])
        pid = int((tmp_path / 'child-pid').read_text())
        assert not alive(pid), 'owned descendant survived completed supervision'
        assert timed_out is parent_timeout
        assert status == (124 if parent_timeout else 0)
        assert evidence['drain_complete'] is True
        assert evidence['stragglers_detected'] is True
        assert evidence['stragglers_remaining'] == []
        before = (tmp_path / 'application.stdout.log').read_bytes()
        time.sleep(0.05)
        assert (tmp_path / 'application.stdout.log').read_bytes() == before
    finally:
        if pid is None and (tmp_path / 'child-pid').exists():
            pid = int((tmp_path / 'child-pid').read_text())
        if pid is not None and alive(pid):
            os.kill(pid, signal.SIGKILL)


@pytest.mark.parametrize('secret', ['supervision-secret', '1234'])
def test_host_log_prefix_is_bounded_and_redacted(tmp_path, secret):
    status, timed_out, evidence = _run_proxy_host_app(
        (sys.executable, '-c', f'import sys; sys.stdout.write(({secret!r}+"\\n")*300000)'),
        cwd=tmp_path, env=dict(os.environ), output=tmp_path,
        timeout=10, interrupted=lambda: False, secrets=[secret])
    assert status == 0 and not timed_out
    assert evidence['stdout_truncated']
    output = (tmp_path / 'application.stdout.log').read_text()
    assert secret not in output
    assert len(output.encode()) <= 1024 * 1024


@pytest.mark.skipif(os.name != 'posix', reason='POSIX termination race')
def test_exit_during_killpg_preserves_timeout_evidence(tmp_path, monkeypatch):
    original = os.killpg
    def concurrent_exit(pid, number):
        try:
            original(pid, number)
        except ProcessLookupError:
            pass
        raise ProcessLookupError('process exited concurrently')
    monkeypatch.setattr(os, 'killpg', concurrent_exit)
    status, timed_out, evidence = _run_proxy_host_app(
        (sys.executable, '-c', 'import time; time.sleep(30)'),
        cwd=tmp_path, env=dict(os.environ), output=tmp_path,
        timeout=.05, interrupted=lambda: False, secrets=[])
    assert status == 124 and timed_out
    assert evidence['drain_complete'] and not evidence['supervision_errors']


@pytest.mark.parametrize('failure', [None, 'timeout', 'missing'])
def test_windows_timeout_uses_taskkill_tree_and_job(monkeypatch, failure):
    from types import SimpleNamespace
    from p11lab import process
    owner = object.__new__(process.SupervisedProcess)
    owner.process = SimpleNamespace(pid=1234, poll=lambda: None)
    owner._discover = lambda: []
    owner.errors = []
    calls = []
    owner.job = SimpleNamespace(terminate=lambda: calls.append('job-terminate'))
    monkeypatch.setattr(process, 'os', SimpleNamespace(name='nt'))
    def taskkill(argv, **kwargs):
        calls.append(argv)
        if failure == 'timeout':
            raise process.subprocess.TimeoutExpired(argv, 2)
        if failure == 'missing':
            raise OSError('taskkill unavailable')
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(process.subprocess, 'run', taskkill)
    owner._signal_tree(force=True)
    assert calls == [['taskkill', '/PID', '1234', '/T', '/F'], 'job-terminate']
    assert bool(owner.errors) is bool(failure)
