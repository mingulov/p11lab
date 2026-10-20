"""Traversal-status proofs using the actual adapters, not provider qualification.

Reuse the adapter fixture's host-preflight redirection and deterministic native
utility. The previous outcome/identity tests remain unchanged.
"""
import os
import shlex
import shutil
import stat

import pytest

from test_softhsm_entrypoints import adapter, initialize, shell  # noqa: F401


CHECKS = [
    pytest.param('fresh-empty', 'fresh-init', id='fresh-empty-fresh-init'),
    *[pytest.param(guard, operation, id=f'{guard}-{operation}')
      for guard in ('token-directory', 'token-contents', 'state-unknown', 'owned-unknown')
      for operation in ('repeat-init', 'health', 'exec')],
]
MESSAGES = {
    'fresh-empty': 'partial state: refusing to initialize nonempty volume',
    'token-directory': 'partial state: missing initialized token',
    'token-contents': 'partial state: missing token contents',
    'state-unknown': 'partial state: unknown files',
    'owned-unknown': 'partial state: unknown owned files',
}


def state_snapshot(root):
    """Record modes/types and bytes without following links or opening specials."""
    result = {}

    def visit(path):
        mode = path.lstat().st_mode
        value = (mode, path.read_bytes() if stat.S_ISREG(mode)
                 else os.readlink(path) if stat.S_ISLNK(mode) else None)
        result[str(path.relative_to(root))] = value
        if stat.S_ISDIR(mode):
            for child in path.iterdir():
                visit(child)

    visit(root)
    return result


def prepare(adapter, operation, guard=None, *, invalid=False):
    if operation != 'fresh-init':
        initialize(adapter)
    if invalid:
        if guard in ('fresh-empty', 'state-unknown', 'owned-unknown'):
            parent = adapter.owned if guard == 'owned-unknown' else adapter.state
            foreign = parent / 'foreign'
            foreign.write_bytes(b'foreign state\x00\n')
            foreign.chmod(0o640)
        elif guard == 'token-directory':
            shutil.rmtree(adapter.owned / 'tokens/fixture-token')
        elif guard == 'token-contents':
            (adapter.owned / 'tokens/fixture-token/token.object').unlink()
    return state_snapshot(adapter.state)


def find_args(adapter, guard):
    return {
        'fresh-empty': [str(adapter.state), '-mindepth', '1', '-maxdepth', '1', '-print', '-quit'],
        'token-directory': [str(adapter.owned / 'tokens'), '-mindepth', '1', '-maxdepth', '1',
                            '-type', 'd', '-print', '-quit'],
        'token-contents': [str(adapter.owned / 'tokens'), '-mindepth', '1', '-type', 'f', '-print', '-quit'],
        'state-unknown': [str(adapter.state), '-mindepth', '1', '-maxdepth', '1', '!', '-name',
                          'softhsm2', '-print', '-quit'],
        'owned-unknown': [str(adapter.owned), '-mindepth', '1', '-maxdepth', '1', '!', '-name',
                          'tokens', '!', '-name', 'complete', '-print', '-quit'],
    }[guard]


def fail_find(adapter, guard, output):
    """Fail only the exact existing query, with empty or real partial output."""
    args = find_args(adapter, guard)
    match = ' && '.join([f'[ "$#" -eq {len(args)} ]',
                         *[f'[ "${{{index}}}" = {shlex.quote(arg)} ]'
                           for index, arg in enumerate(args, 1)]])
    real_find = shlex.quote(shutil.which('find'))
    emit = f'{real_find} "$@" || exit $?' if output == 'partial' else ':'
    adapter.install_wrapper('find', f'''#!/bin/sh
if {match}; then
    printf '%s\\0' "$@" >> "$FIXTURE/find-args"
    {emit}
    printf '%s\\n' 'injected find I/O failure' >&2
    exit 73
fi
exec {real_find} "$@"
''')
    return args


def invoke(adapter, operation, **changes):
    args = ['--', adapter.shell, '-c', 'printf APPLICATION-RAN; exit 37'] if operation == 'exec' else []
    return adapter.run('init' if operation.endswith('init') else operation, *args, **changes)


def calls(adapter):
    return adapter.calls.read_bytes() if adapter.calls.exists() else b''


def assert_refused_without_provider_access(adapter, result, before, previous_calls):
    assert result.returncode == 1, result.stdout + result.stderr
    assert 'APPLICATION-RAN' not in result.stdout
    assert calls(adapter) == previous_calls, 'rejected traversal reached the native utility'
    assert state_snapshot(adapter.state) == before
    adapter.assert_clean()  # Existing configure() may publish only the control configuration.
    assert not list(adapter.owned.glob('.complete.*'))


@pytest.mark.parametrize('guard,operation', CHECKS)
@pytest.mark.parametrize('output', ['empty', 'partial'])
def test_failed_find_rejects_before_provider_or_application(adapter, guard, operation, output):
    # Empty checks inspect genuine foreign state; partial presence output is a
    # real matching token path. Neither failed output shape is trustworthy.
    before = prepare(adapter, operation, guard, invalid=guard in ('fresh-empty', 'state-unknown', 'owned-unknown'))
    previous_calls = calls(adapter)
    args = fail_find(adapter, guard, output)
    result = invoke(adapter, operation)
    assert (adapter.root / 'find-args').read_bytes() == b''.join(os.fsencode(arg) + b'\0' for arg in args)
    assert 'injected find I/O failure' in result.stderr
    assert_refused_without_provider_access(adapter, result, before, previous_calls)
    # The shared helper reports adapter failure 1, not find's injected status 73.
    assert f'cannot enumerate {args[0]}' in result.stderr
    assert MESSAGES[guard] not in result.stderr


@pytest.mark.parametrize('guard,operation', CHECKS)
def test_successful_find_keeps_existing_refusal_predicates(adapter, guard, operation):
    before = prepare(adapter, operation, guard, invalid=True)
    previous_calls = calls(adapter)
    result = invoke(adapter, operation)
    assert_refused_without_provider_access(adapter, result, before, previous_calls)
    assert MESSAGES[guard] in result.stderr
    assert 'cannot enumerate' not in result.stderr


@pytest.mark.parametrize('operation', ['fresh-init', 'repeat-init', 'health', 'exec'])
def test_successful_find_preserves_ordinary_lifecycle(adapter, operation):
    before = prepare(adapter, operation)
    previous_calls = calls(adapter)
    changes = {} if operation == 'fresh-init' else {'P11LAB_PIN': None, 'P11LAB_SO_PIN': None}
    result = invoke(adapter, operation, **changes)
    assert result.returncode == (37 if operation == 'exec' else 0), result.stderr
    assert ('APPLICATION-RAN' in result.stdout) == (operation == 'exec')
    assert calls(adapter) == previous_calls + (b'init\n' if operation == 'fresh-init' else b'show\n')
    if operation != 'fresh-init':
        assert state_snapshot(adapter.state) == before
    else:
        assert adapter.marker.is_file()
        assert (adapter.owned / 'tokens/fixture-token/token.object').read_bytes() == b'opaque provider object\n'
    adapter.assert_clean()
