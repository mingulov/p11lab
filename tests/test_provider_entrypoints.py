"""Failure-path checks against the actual packaged lifecycle scripts."""
import os
import subprocess

import pytest

from p11lab.catalog import package_data


PROVIDERS = ('softhsm2', 'bouncyhsm', 'nss', 'freehsm', 'haskoki')


def run_script(text, directory, **env):
    script = directory / 'entrypoint.sh'
    script.write_text(text)
    return subprocess.run(['bash', str(script)], capture_output=True, text=True,
                          timeout=30, env=os.environ | env)


def enumeration_guards():
    for provider in PROVIDERS:
        text = package_data(f'providers/{provider}/entrypoint.sh').read_text()
        for index, line in enumerate(text.splitlines()):
            if '$(find ' in line or 'p11lab_check_find ' in line:
                yield pytest.param(line.strip(), id=f'{provider}-line-{index + 1}')


@pytest.mark.parametrize('guard', list(enumeration_guards()))
def test_state_enumeration_failure_is_never_an_empty_roster(tmp_path, guard):
    common = package_data('runtime/common.sh').read_text()
    result = run_script(common + '\n' +
                        'find() { echo "injected find I/O failure" >&2; return 73; }\n'
                        'state=/state; owned=/state/provider\n' + guard + '\n'
                        'echo ENUMERATION-FAILURE-IGNORED\n', tmp_path)
    assert result.returncode != 0, result.stdout + result.stderr
    assert 'ENUMERATION-FAILURE-IGNORED' not in result.stdout
    assert 'cannot enumerate' in result.stderr, result.stderr
    assert 'injected find I/O failure' in result.stderr


def freehsm_script(directory):
    state, control = directory / 'state', directory / 'control'
    state.mkdir()
    control.mkdir()
    runtime_id = directory / 'runtime-id'
    runtime_id.write_text('test-artifact\n')
    tool = directory / 'fhsm-token'
    tool.write_text(
        '#!/bin/sh\nset -eu\n'
        'printf "%s\\n" "$1" >> "$CALLS"\n'
        'printf "%s\\n" "native stdout: $1"\n'
        'printf "%s\\n" "native diagnostic: $1 ${KAT_WARNING-}" >&2\n'
        'case "$1" in\n'
        'init) printf token > "$FHSM_TOKENS_DIR/slot0.tok"; '
        'printf key > "$FHSM_TOKENS_DIR/audit.key" ;;\n'
        'info) printf "  label P11Lab\\n" ;;\n'
        'esac\n')
    tool.chmod(0o755)
    text = package_data('providers/freehsm/entrypoint.sh').read_text()
    text = text.replace('. /usr/share/p11lab/common.sh',
                        package_data('runtime/common.sh').read_text())
    for original, redirect in [('/var/lib/p11lab', state), ('/run/p11lab', control),
                               ('/usr/share/p11lab/runtime-id', runtime_id),
                               ('/usr/local/bin/fhsm-token', tool)]:
        text = text.replace(original, str(redirect))
    script = directory / 'provider'
    script.write_text(text)
    return script, state, control


def run_freehsm(script, operation, **env):
    return subprocess.run(['sh', str(script), operation], capture_output=True,
                          text=True, timeout=30, env=os.environ | {
                              'P11LAB_PIN': 'user-test', 'P11LAB_SO_PIN': 'so-test',
                              'CALLS': str(script.parent / 'native-calls')} | env)


@pytest.mark.parametrize('operation', ['init', 'health'])
@pytest.mark.parametrize('warning', ['', 'KAT FAIL: successful tool warning'])
def test_successful_freehsm_tools_preserve_both_streams(tmp_path, operation, warning):
    script, _, control = freehsm_script(tmp_path)
    assert run_freehsm(script, 'init').returncode == 0
    result = run_freehsm(script, operation, KAT_WARNING=warning)
    native_operation = 'info'  # Both health and an idempotent init reopen the token.
    assert result.returncode == 0, result.stderr
    assert f'native diagnostic: {native_operation}' in result.stderr
    assert 'native diagnostic:' not in result.stdout
    if operation == 'health':
        assert 'native stdout: info' in result.stdout
    if warning:
        assert warning in result.stderr
    assert not list(control.glob('init.*'))


def test_fresh_freehsm_init_preserves_success_diagnostics(tmp_path):
    script, _, control = freehsm_script(tmp_path)
    result = run_freehsm(script, 'init', KAT_WARNING='KAT FAIL: successful tool warning')
    assert result.returncode == 0, result.stderr
    assert 'native stdout: init' in result.stdout
    assert 'native diagnostic: init KAT FAIL:' in result.stderr
    assert 'native diagnostic:' not in result.stdout
    assert not list(control.glob('init.*'))


@pytest.mark.parametrize('data,accepted', [
    (b'1234', True), (b'1234\n', True), (b'1234\n\n', False),
    (b'12\n34', False), (b'1234\r\n', False), (b'1234\0', False),
])
def test_secret_file_has_exactly_one_text_line(tmp_path, data, accepted):
    source = tmp_path / 'pin'
    source.write_bytes(data)
    result = run_script(package_data('runtime/common.sh').read_text() +
                        '\np11lab_secret P11LAB_PIN P11LAB_PIN_FILE\n'
                        'printf "%s" "$credential"\n', tmp_path,
                        P11LAB_PIN_FILE=str(source))
    assert (result.returncode == 0) is accepted, result.stderr
    if accepted:
        assert result.stdout == '1234'
    else:
        assert 'credential' in result.stderr


@pytest.mark.parametrize('operation', ['init', 'health', 'server', 'exec'])
@pytest.mark.parametrize('damage', ['missing-db', 'db-link', 'log-link', 'marker-bytes', 'empty-owned'])
def test_bouncy_container_rejects_state_before_open(tmp_path, operation, damage):
    state, control = tmp_path / 'state', tmp_path / 'control'
    owned = state / 'bouncyhsm'
    owned.mkdir(parents=True)
    control.mkdir()
    runtime_id = tmp_path / 'runtime-id'
    runtime_id.write_text('fixture\n')
    (owned / 'complete').write_text('schema=1\nprovider=bouncyhsm\nartifact=fixture\nlabel=P11Lab\nslot=1\nbackend=litedb\n')
    (owned / 'BouncyHsm.db').write_bytes(b'original-db')
    outside = tmp_path / 'outside'
    outside.write_bytes(b'original-outside')
    if damage == 'missing-db':
        (owned / 'BouncyHsm.db').unlink()
    elif damage in ('db-link', 'log-link'):
        path = owned / ('BouncyHsm.db' if damage == 'db-link' else 'BouncyHsm-log.db')
        path.unlink(missing_ok=True)
        path.symlink_to(outside)
    elif damage == 'marker-bytes':
        with (owned / 'complete').open('ab') as stream:
            stream.write(b'\n')
    else:
        for path in owned.iterdir():
            path.unlink()
    server = tmp_path / 'dotnet'
    server.write_text('#!/bin/sh\necho opened >> "$CALLS"\nprintf mutated > "$BouncyHsm_LiteDbPersistentRepositorySetup__DbFilePath"\nexit 7\n')
    server.chmod(0o755)
    text = package_data('providers/bouncyhsm/entrypoint.sh').read_text()
    text = text.replace('. /usr/share/p11lab/common.sh', package_data('runtime/common.sh').read_text())
    for original, redirect in [('/var/lib/p11lab', state), ('/run/p11lab', control),
                               ('/usr/share/p11lab/runtime-id', runtime_id),
                               ('/usr/share/dotnet/dotnet', server),
                               ('/opt/bouncyhsm/server', tmp_path)]:
        text = text.replace(original, str(redirect))
    script = tmp_path / 'provider'
    script.write_text(text)
    def snapshot():
        return {str(p.relative_to(state)): p.readlink().as_posix() if p.is_symlink()
                else p.read_bytes() if p.is_file() else 'directory' for p in state.rglob('*')}
    before = snapshot()
    result = subprocess.run(['bash', str(script), operation, *(['--', 'true'] if operation == 'exec' else [])],
                            env=os.environ | {'CALLS': str(tmp_path / 'calls')},
                            capture_output=True, text=True, timeout=15)
    assert result.returncode != 0
    assert not (tmp_path / 'calls').exists(), 'rejected state reached the server'
    assert snapshot() == before
    assert outside.read_bytes() == b'original-outside'


def test_bouncy_slot_dto_preserves_quotes_backslashes_and_unicode(tmp_path):
    import json
    text = package_data('providers/bouncyhsm/entrypoint.sh').read_text()
    functions = text.split('case "${1-}" in', 1)[0]
    functions = functions.replace('. /usr/share/p11lab/common.sh', package_data('runtime/common.sh').read_text())
    dto = next(line.strip() for line in text.splitlines() if line.strip().startswith('dto='))
    pin = 'quote"slash\\tab\t\u00e4'
    result = run_script(functions + '\nlabel=P11Lab\nuser_credential=$TEST_PIN\ncredential=$TEST_PIN\n'
                        + dto + '\nprintf "%s" "$dto"\n', tmp_path, TEST_PIN=pin)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload['Token']['UserPin'] == payload['Token']['SoPin'] == pin
