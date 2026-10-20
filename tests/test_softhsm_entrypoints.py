"""SoftHSM adapter outcome proofs, not real-provider or native-host qualification.

Execute the packaged scripts and common helper, redirecting container paths.
The native fixture also redirects OS metadata, architecture and loader preflight;
this deliberately does not validate the supported host or a real module. The
utility is a deterministic fixture that creates opaque partial token state.
"""
import os
from pathlib import Path
import shlex
import shutil
import subprocess

import pytest

from p11lab.catalog import package_data


UTILITY = r'''#!/bin/sh
set -eu
case "$*" in
    *--init-token*)
        printf 'init\n' >> "$FIXTURE/calls"
        mkdir -p "$FIXTURE/state/softhsm2/tokens/fixture-token"
        printf 'opaque provider object\n' > "$FIXTURE/state/softhsm2/tokens/fixture-token/token.object"
        if [ -n "${NATIVE_SIGNAL-}" ]; then kill -"$NATIVE_SIGNAL" "$PPID"; fi
        exit "${INIT_STATUS-0}"
        ;;
    *--show-slots*)
        printf 'show\n' >> "$FIXTURE/calls"
        printf '%s\n' 'Slot 1' '        Initialized:      yes' '        User PIN init.:   yes' '        Serial number:    0000000000000001' '        Label:            P11Lab'
        exit "${SHOW_STATUS-0}"
        ;;
    *) exit 99 ;;
esac
'''


def executable(path, text):
    path.write_text(text)
    path.chmod(0o755)


class Adapter:
    def __init__(self, root, shell, kind):
        self.root, self.shell, self.kind = root, shell, kind
        self.state, self.control, self.bin = [root / name for name in ('state', 'control', 'bin')]
        for path in (self.state, self.control, self.bin):
            path.mkdir()
        # No host PATH fallback: missing/non-executable tools are real exec failures.
        for name in ('cat', 'mkdir', 'mv', 'cp', 'find', 'awk', 'rmdir', 'rm', 'wc', 'realpath'):
            target = shutil.which(name)
            if target is None:
                pytest.skip(f'{name} is required for POSIX adapter tests')
            (self.bin / name).symlink_to(target)
        executable(self.bin / 'uname', '#!/bin/sh\nprintf "x86_64\\n"\n')
        self.owned = self.state / 'softhsm2'
        self.marker = self.owned / 'complete'
        self.lock = self.state / '.init-lock'
        self.calls = root / 'calls'
        common = package_data('runtime/common.sh')
        if kind == 'container':
            identity = root / 'runtime-id'
            identity.write_bytes(b'a' * 64 + b'\n')
            text = package_data('providers/softhsm2/entrypoint.sh').read_bytes().decode()
            text = text.replace('. /usr/share/p11lab/common.sh', f'. {shlex.quote(str(common))}')
            for original, redirect in [('/var/lib/p11lab', self.state), ('/run/p11lab', self.control),
                                       ('/usr/share/p11lab/runtime-id', identity)]:
                text = text.replace(original, str(redirect))
            self.tool = self.bin / 'softhsm2-util'
            self.options = []
        else:
            prefix = root / 'prefix'
            share = prefix / 'payload/share/p11lab'
            share.mkdir(parents=True)
            (prefix / 'payload/bin').mkdir()
            shutil.copyfile(common, share / 'common.sh')
            (share / 'native-id').write_bytes(b'a' * 64 + b'\n')
            os_release, loader = root / 'os-release', root / 'loader'
            os_release.write_text('ID=debian\nVERSION_ID=13\n')
            executable(loader, '#!/bin/sh\nexit 0\n')
            text = package_data('providers/softhsm2/native.sh').read_bytes().decode()
            text = text.replace('/etc/os-release', str(os_release)).replace('/lib64/ld-linux-x86-64.so.2', str(loader))
            self.tool = prefix / 'payload/bin/softhsm2-util'
            self.options = ['--prefix', str(prefix), '--state', str(self.state), '--control', str(self.control)]
        executable(self.tool, UTILITY)
        self.script = root / 'provider'
        self.script.write_bytes(text.encode())

    def run(self, operation='init', *args, stderr=None, **changes):
        env = {key: value for key, value in os.environ.items()
               if not key.startswith('P11LAB_') and key not in ('BASH_ENV', 'ENV')}
        env.update(PATH=str(self.bin), FIXTURE=str(self.root), P11LAB_PIN='user-test', P11LAB_SO_PIN='so-test')
        for name, value in changes.items():
            if value is None:
                env.pop(name, None)
            else:
                env[name] = str(value)
        return subprocess.run([self.shell, str(self.script), *self.options, operation, *args],
                              env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE if stderr is None else stderr,
                              text=True, timeout=10)

    def install_wrapper(self, command, text):
        path = self.bin / command
        path.unlink()
        executable(path, text)

    def snapshot(self):
        return {str(path.relative_to(self.state)): path.read_bytes() if path.is_file() else None
                for path in self.state.rglob('*')}

    def assert_clean(self):
        assert not self.lock.exists()
        assert sorted(path.name for path in self.control.iterdir()) == ['softhsm2.conf']

    def assert_partial(self):
        assert not self.marker.exists()
        assert (self.owned / 'tokens/fixture-token/token.object').read_bytes() == b'opaque provider object\n'


@pytest.fixture(params=['dash', 'bash'])
def shell(request):
    path = shutil.which(request.param)
    if path is None:
        pytest.skip(f'{request.param} is required for this shell variant')
    return path


@pytest.fixture(params=['container', 'native'])
def adapter(tmp_path, shell, request):
    return Adapter(tmp_path, shell, request.param)


def initialize(adapter):
    result = adapter.run()
    assert result.returncode == 0, result.stderr
    adapter.assert_clean()


@pytest.mark.parametrize('status', [1, 37, 126, 127])
@pytest.mark.parametrize('operation', ['fresh-init', 'repeat-init', 'health', 'exec'])
def test_native_failure_status_survives(adapter, status, operation):
    if operation == 'fresh-init':
        result = adapter.run(INIT_STATUS=status)
        adapter.assert_partial()
    else:
        initialize(adapter)
        before = adapter.snapshot()
        result = adapter.run('init' if operation == 'repeat-init' else operation,
                             *(['--', adapter.shell, '-c', 'echo APPLICATION-RAN'] if operation == 'exec' else []),
                             SHOW_STATUS=status)
        assert adapter.snapshot() == before
        assert 'APPLICATION-RAN' not in result.stdout
    assert result.returncode == status, result.stderr
    adapter.assert_clean()


@pytest.mark.parametrize('signal,status', [('HUP', 129), ('INT', 130), ('TERM', 143)])
@pytest.mark.parametrize('stage', ['native', 'after-copy'])
def test_stop_signal_never_promotes_completion(adapter, signal, status, stage):
    changes = {'NATIVE_SIGNAL': signal} if stage == 'native' else {}
    if stage == 'after-copy':
        real_cp = shlex.quote(shutil.which('cp'))
        adapter.install_wrapper('cp', f'#!/bin/sh\n{real_cp} "$@" || exit $?\nkill -{signal} "$PPID"\nexit 0\n')
    result = adapter.run(**changes)
    assert result.returncode == status, result.stderr
    adapter.assert_partial()
    adapter.assert_clean()
    assert bool(list(adapter.owned.glob('.complete.*'))) == (stage == 'after-copy')
    before = adapter.snapshot()
    assert adapter.run().returncode != 0  # No implicit retry or reset of partial state.
    assert adapter.snapshot() == before
    assert adapter.calls.read_text() == 'init\n'


@pytest.mark.parametrize('failure', ['rmdir', 'rm', 'both'])
@pytest.mark.parametrize('primary', ['success', 'native', 'HUP', 'INT', 'TERM'])
def test_cleanup_attempts_both_steps_without_replacing_primary_failure(adapter, failure, primary):
    for command, failure_status in [('rmdir', 73), ('rm', 74)]:
        real_command = shlex.quote(shutil.which(command))
        action = f'exit {failure_status}' if failure in (command, 'both') else f'exec {real_command} "$@"'
        adapter.install_wrapper(command, f'#!/bin/sh\nprintf "{command}\\n" >> "$FIXTURE/cleanup"\n{action}\n')
    changes = {'INIT_STATUS': 37} if primary == 'native' else {'NATIVE_SIGNAL': primary} if primary != 'success' else {}
    result = adapter.run(**changes)
    assert result.returncode != 0, 'cleanup failure must not report clean success'
    if primary != 'success':
        assert result.returncode == {'native': 37, 'HUP': 129, 'INT': 130, 'TERM': 143}[primary], result.stderr
        adapter.assert_partial()
    else:
        assert adapter.marker.is_file()  # Native success is not rolled back.
    assert (adapter.root / 'cleanup').read_text() == 'rmdir\nrm\n'
    assert 'cleanup' in result.stderr
    assert adapter.lock.exists() == (failure in ('rmdir', 'both'))
    assert bool(list(adapter.control.glob('marker.*'))) == (failure in ('rm', 'both'))


@pytest.mark.parametrize('status', [1, 37, 126, 127])
@pytest.mark.parametrize('operation', ['fresh-init', 'repeat-init', 'health', 'exec'])
def test_failed_error_diagnostic_does_not_replace_native_status(adapter, status, operation):
    if not Path('/dev/full').exists():
        pytest.skip('/dev/full is required for write failure injection')
    if operation != 'fresh-init':
        initialize(adapter)
    with open('/dev/full', 'w') as sink:
        result = adapter.run('init' if operation.endswith('init') else operation,
                             *(['--', adapter.shell, '-c', 'echo APPLICATION-RAN'] if operation == 'exec' else []),
                             stderr=sink, INIT_STATUS=status, SHOW_STATUS=status)
    assert result.returncode == status
    assert 'APPLICATION-RAN' not in result.stdout
    adapter.assert_clean()


@pytest.mark.parametrize('credential', ['P11LAB_PIN', 'P11LAB_SO_PIN'])
@pytest.mark.parametrize('bad', ['absent', 'empty', 'multiline', 'missing-file', 'conflict'])
def test_rejected_credentials_leave_no_marker_or_owned_state(adapter, credential, bad):
    changes = {credential: {'absent': None, 'empty': '', 'multiline': 'one\ntwo',
                            'missing-file': None, 'conflict': 'value'}[bad]}
    if bad in ('missing-file', 'conflict'):
        changes[credential + '_FILE'] = str(adapter.root / 'missing-pin')
    result = adapter.run(**changes)
    assert result.returncode != 0
    assert 'credential' in result.stderr
    assert list(adapter.state.iterdir()) == []
    assert not adapter.calls.exists()
    assert not list(adapter.control.glob('marker.*'))
    assert not list(adapter.control.glob('init.*'))


def test_existing_foreign_lock_is_untouched(adapter):
    adapter.lock.mkdir()
    foreign = adapter.lock / 'owner'
    foreign.write_bytes(b'foreign owner\n')
    before = adapter.snapshot()
    result = adapter.run()
    assert result.returncode != 0
    assert adapter.snapshot() == before
    assert not adapter.calls.exists()
    assert not list(adapter.control.glob('marker.*'))


def test_failed_lock_acquisition_never_installs_cleanup_or_creates_marker(adapter):
    real_mkdir = shlex.quote(shutil.which('mkdir'))
    adapter.install_wrapper('mkdir', f'''#!/bin/sh
case "$*" in
    *"/.init-lock")
        {real_mkdir} "$@" || exit $?
        printf 'foreign owner\\n' > "$1/owner"
        exit 73 ;;
esac
exec {real_mkdir} "$@"
''')
    result = adapter.run()
    assert result.returncode != 0
    assert (adapter.lock / 'owner').read_bytes() == b'foreign owner\n'
    assert not adapter.owned.exists()
    assert not adapter.calls.exists()
    assert not list(adapter.control.glob('marker.*'))


@pytest.mark.parametrize('missing', [True, False])
@pytest.mark.parametrize('operation', ['fresh-init', 'health'])
def test_real_missing_or_nonexecutable_native_tool_status(adapter, missing, operation):
    if operation != 'fresh-init':
        initialize(adapter)
    if missing:
        adapter.tool.unlink()
    else:
        adapter.tool.chmod(0o644)
    # dash PATH lookup may return 127 for a non-executable file, while an
    # absolute command returns 126. Preserve what this shell actually reports.
    command = 'softhsm2-util' if adapter.kind == 'container' else shlex.quote(str(adapter.tool))
    direct = subprocess.run([adapter.shell, '-c', command], env={'PATH': str(adapter.bin)},
                            capture_output=True, text=True, timeout=10)
    assert direct.returncode in (126, 127), direct.stderr
    result = adapter.run('init' if operation == 'fresh-init' else operation)
    assert result.returncode == direct.returncode, result.stderr
    adapter.assert_clean()
    if operation == 'fresh-init':
        assert not adapter.marker.exists()
        assert adapter.owned.is_dir()


def test_success_repeat_and_application_argv_environment_status(adapter):
    initialize(adapter)
    marker = adapter.marker.read_bytes()
    before = adapter.snapshot()
    assert adapter.run(P11LAB_PIN='changed', P11LAB_SO_PIN='changed').returncode == 0
    assert adapter.run('health').returncode == 0
    app = adapter.root / 'app'
    executable(app, '#!/bin/sh\nprintf "%s\\n" "$@"\nprintf "%s\\n" "$SOFTHSM2_CONF" "$P11LAB_MODULE"\nexit 37\n')
    args = ['spaced value', '', '*literal*', 'semi;colon', 'quote"slash\\']
    result = adapter.run('exec', '--', str(app), *args, P11LAB_PIN=None, P11LAB_SO_PIN=None)
    module = '/usr/local/lib/p11lab/libsofthsm2.so' if adapter.kind == 'container' else str(adapter.root / 'prefix/payload/lib/libsofthsm2.so')
    assert result.returncode == 37, result.stderr
    assert result.stdout == '\n'.join([*args, str(adapter.control / 'softhsm2.conf'), module]) + '\n'
    assert adapter.marker.read_bytes() == marker
    assert adapter.snapshot() == before
    assert adapter.calls.read_text() == 'init\nshow\nshow\nshow\n'
    adapter.assert_clean()


@pytest.mark.parametrize('label', ['', 'non-ascii-ä', 'x' * 33])
def test_rejected_label_cleans_owned_lock_and_marker(adapter, label):
    result = adapter.run(P11LAB_LABEL=label)
    assert result.returncode != 0
    assert 'label' in result.stderr
    assert list(adapter.state.iterdir()) == []
    assert not adapter.calls.exists()
    adapter.assert_clean()


@pytest.mark.parametrize('command', ['cp', 'mv'])
def test_marker_publication_failure_retains_partial_state_and_status(adapter, command):
    real_command = shlex.quote(shutil.which(command))
    adapter.install_wrapper(command, f'''#!/bin/sh
case "$*" in
    *"/.complete."*)
        if [ "{command}" = cp ]; then {real_command} "$@" || exit $?; fi
        exit 73 ;;
esac
exec {real_command} "$@"
''')
    result = adapter.run()
    assert result.returncode == 73, result.stderr
    adapter.assert_partial()
    adapter.assert_clean()
    assert len(list(adapter.owned.glob('.complete.*'))) == 1


def test_cleanup_diagnostic_write_failure_keeps_native_status(adapter):
    if not Path('/dev/full').exists():
        pytest.skip('/dev/full is required for write failure injection')
    for command in ('rmdir', 'rm'):
        adapter.install_wrapper(command, f'#!/bin/sh\nprintf "{command}\\n" >> "$FIXTURE/cleanup"\nexit 74\n')
    with open('/dev/full', 'w') as sink:
        result = adapter.run(stderr=sink, INIT_STATUS=37)
    assert result.returncode == 37
    assert (adapter.root / 'cleanup').read_text() == 'rmdir\nrm\n'
    adapter.assert_partial()


def cleanup_wrapper(adapter, command, *, signal=None, status=0):
    """Inject a stop/error at one real cleanup boundary, after recording entry."""
    action = f'{shlex.quote(shutil.which(command))} "$@" || exit $?' if status == 0 else ':'
    stop = f'kill -{signal} "$PPID"' if signal else ':'
    adapter.install_wrapper(command, f'#!/bin/sh\nprintf "{command}\\n" >> "$FIXTURE/cleanup"\n{action}\n{stop}\nexit {status}\n')


@pytest.mark.parametrize('primary', [0, 37])
@pytest.mark.parametrize('signal,status', [('HUP', 129), ('INT', 130), ('TERM', 143)])
@pytest.mark.parametrize('stage', ['rmdir', 'rm'])
def test_cleanup_signal_finishes_both_steps_and_preserves_primary(adapter, primary, signal, status, stage):
    for command in ('rmdir', 'rm'):
        cleanup_wrapper(adapter, command, signal=signal if command == stage else None)
    result = adapter.run(INIT_STATUS=primary)
    assert result.returncode == (primary or status), result.stderr
    assert (adapter.root / 'cleanup').read_text() == 'rmdir\nrm\n'
    adapter.assert_clean()
    assert adapter.marker.exists() == (primary == 0)
    if primary:
        adapter.assert_partial()


@pytest.mark.parametrize('primary', [0, 37])
@pytest.mark.parametrize('first,second,status', [('HUP', 'INT', 129), ('INT', 'TERM', 130), ('TERM', 'HUP', 143)])
def test_first_cleanup_signal_is_not_replaced_by_later_signal(adapter, primary, first, second, status):
    cleanup_wrapper(adapter, 'rmdir', signal=first)
    cleanup_wrapper(adapter, 'rm', signal=second)
    result = adapter.run(INIT_STATUS=primary)
    assert result.returncode == (primary or status), result.stderr
    assert (adapter.root / 'cleanup').read_text() == 'rmdir\nrm\n'
    adapter.assert_clean()


@pytest.mark.parametrize('primary', [0, 37])
@pytest.mark.parametrize('first', ['failure', 'signal'])
def test_cleanup_preserves_first_observed_failure_or_signal(adapter, primary, first):
    cleanup_wrapper(adapter, 'rmdir', signal='HUP' if first == 'signal' else None,
                    status=73 if first == 'failure' else 0)
    cleanup_wrapper(adapter, 'rm', signal='TERM' if first == 'failure' else None,
                    status=74 if first == 'signal' else 0)
    result = adapter.run(INIT_STATUS=primary)
    assert result.returncode == (primary or (73 if first == 'failure' else 129)), result.stderr
    assert (adapter.root / 'cleanup').read_text() == 'rmdir\nrm\n'
    assert 'cleanup' in result.stderr
    assert adapter.lock.exists() == (first == 'failure')
    assert bool(list(adapter.control.glob('marker.*'))) == (first == 'signal')
