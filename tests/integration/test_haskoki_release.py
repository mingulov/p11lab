"""Unpatched v0.5 release acceptance, not silently xfailed for known gaps.

Uses exactly P11LAB_TEST_HASKOKI_IMAGES['release']. The test-only helper is
compiled on the Linux caller, then mounted read-only. No upstream build,
network, package installation, shared state, or workspace mount in runtime.
Schemas 1/2/future/missing-marker are known readiness gaps in upstream ctl;
these ordinary assertions intentionally report real acceptance failures.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import time
import uuid

import pytest

from p11lab.catalog import package_data
from p11lab.models import RunSpec
from p11lab.run import run_application
from test_haskoki import (IMAGES, MODULE, STORE, USER_PIN, SO_PIN, TOKEN_LABEL,
                          as_ref, docker, lifecycle_base, lifecycle_controls, write_pins)

HELPER = '/run/haskoki-test/lifecycle'


@pytest.fixture
def release_state(tmp_path):
    if 'release' not in IMAGES:
        pytest.skip('P11LAB_TEST_HASKOKI_IMAGES lacks release')
    state, secrets = tmp_path / 'state', tmp_path / 'secrets'
    state.mkdir()
    secrets.mkdir()
    write_pins(secrets)
    base = lifecycle_base(state, secrets)
    image = IMAGES['release']
    docker(*base, *lifecycle_controls(), image, 'init')
    return image, base, state, secrets


@pytest.fixture(scope='module')
def lifecycle_helper(tmp_path_factory):
    if 'release' not in IMAGES:
        pytest.skip('P11LAB_TEST_HASKOKI_IMAGES lacks release')
    if shutil.which('cc') is None:
        pytest.fail('release acceptance requires a caller C compiler')
    directory = tmp_path_factory.mktemp('release-native-test')
    (directory / 'pkcs11.h').write_bytes(package_data('consumer/vendor/pkcs11.h').read_bytes())
    source = Path(__file__).parent / 'haskoki/lifecycle.c'
    built = subprocess.run(['cc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                            '-I' + str(directory), str(source), '-ldl', '-o', str(directory / 'lifecycle')],
                           capture_output=True, text=True, timeout=60)
    assert built.returncode == 0, built.stderr
    return ['--mount', f'type=bind,src={directory},dst=/run/haskoki-test,readonly']


def native(release_state, lifecycle_helper, *args, check=True):
    image, base, _, _ = release_state
    return docker(*base, *lifecycle_helper, image, 'exec', '--', HELPER, MODULE, *args, check=check)


def snapshot(state):
    return {str(p.relative_to(state)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in state.rglob('*') if p.is_file()}


def assert_no_secret_output(result, *pins):
    assert all(pin not in result.stdout + result.stderr for pin in pins)


def test_release_fresh_store_is_schema3(release_state):
    _, _, state, _ = release_state
    with sqlite3.connect(f'file:{state}/haskoki/token.sqlite?mode=ro', uri=True) as database:
        assert database.execute("SELECT value FROM store_meta WHERE key='schema_version'").fetchall() == [('3',)]


@pytest.mark.parametrize('damage', ['schema1', 'schema2', 'schema4', 'missing-marker', 'corrupt', 'missing-store'])
@pytest.mark.parametrize('operation', ['init', 'health', 'exec'])
def test_release_incompatible_schema_refuses_before_application_without_mutation(release_state, damage, operation):
    image, base, state, _ = release_state
    store = state / 'haskoki/token.sqlite'
    if damage.startswith('schema'):
        with sqlite3.connect(store) as database:
            database.execute("UPDATE store_meta SET value=? WHERE key='schema_version'", (damage[-1],))
    elif damage == 'missing-marker':
        with sqlite3.connect(store) as database:
            database.execute("DELETE FROM store_meta WHERE key='schema_version'")
    elif damage == 'corrupt':
        store.write_bytes(b'not a sqlite database\n')
    else:
        store.unlink()
    before = snapshot(state)
    command = [operation] if operation != 'exec' else ['exec', '--', 'sh', '-c', 'echo APP-RAN']
    result = docker(*base, image, *command, check=False)
    # Check nonmutation even when readiness incorrectly succeeds.
    assert snapshot(state) == before, (damage, operation, 'state mutated')
    assert result.returncode != 0, (damage, operation, 'incompatible store accepted', result.stdout)
    assert 'APP-RAN' not in result.stdout


@pytest.mark.parametrize('termination', ['TERM', 'KILL'])
def test_release_real_module_holder_refuses_second_open_and_allows_parallel_health(release_state, lifecycle_helper, termination):
    image, base, state, _ = release_state
    name = 'p11lab-haskoki-holder-' + uuid.uuid4().hex
    docker('run', '--detach', '--name', name, *base[2:], *lifecycle_helper,
           image, 'exec', '--', HELPER, MODULE, 'hold')
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            logs = docker('logs', name)
            if 'holder-ready' in logs.stdout:
                break
            time.sleep(0.1)
        else:
            pytest.fail('module holder never became ready: ' + logs.stderr)
        assert (state / 'haskoki/token.sqlite.lock').is_file()
        import fcntl
        for path in (state / 'haskoki/token.sqlite', state / 'haskoki/token.sqlite.lock'):
            with path.open('rb') as locked:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
        before = snapshot(state)
        refused = native(release_state, lifecycle_helper, 'login', 'user', '/run/secrets/pin', check=False)
        assert refused.returncode == 1
        assert 'C_Initialize failed (rv=0x5)' in refused.stderr
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: docker(*base, image, 'health'), range(4)))
        assert all(r.returncode == 0 and 'tokens: 1' in r.stdout for r in results)
        assert snapshot(state) == before
        assert docker('inspect', '--format', '{{.State.Running}}', name).stdout.strip() == 'true'
        docker('kill', '--signal', termination, name)
        assert docker('wait', name).stdout.strip() == ('0' if termination == 'TERM' else '137')
        if termination == 'TERM':
            assert 'lifecycle: OK' in docker('logs', name).stdout
    finally:
        docker('rm', '--force', name, check=False)
    assert (state / 'haskoki/token.sqlite.lock').exists() is (termination == 'KILL')
    reopened = native(release_state, lifecycle_helper, 'login', 'user', '/run/secrets/pin')
    assert_no_secret_output(reopened, USER_PIN, SO_PIN)
    assert not (state / 'haskoki/token.sqlite.lock').exists()
    assert not (state / '.init-lock').exists()


def test_release_stale_sidecar_with_unrelated_live_pid_is_taken_over(release_state, lifecycle_helper):
    image, base, state, _ = release_state
    before = {name: (state / 'haskoki' / name).read_bytes() for name in ('complete', 'haskoki.toml')}
    script = ('sleep 60 & unrelated=$!; trap \'kill "$unrelated" 2>/dev/null || :; wait "$unrelated" 2>/dev/null || :\' EXIT; '
              'printf "%s\\n" "$unrelated" > ' + STORE + '.lock; '
              + HELPER + ' ' + MODULE + ' login user /run/secrets/pin; status=$?; '
              'kill -0 "$unrelated" || exit 99; test ! -e ' + STORE + '.lock || exit 98; exit "$status"')
    result = docker(*base, *lifecycle_helper, image, 'exec', '--', 'sh', '-c', script)
    assert result.returncode == 0 and 'lifecycle: OK' in result.stdout
    assert not (state / 'haskoki/token.sqlite.lock').exists()
    for name, content in before.items():
        assert (state / 'haskoki' / name).read_bytes() == content
    native(release_state, lifecycle_helper, 'login', 'user', '/run/secrets/pin')


@pytest.mark.parametrize('role,original', [('user', 'pin'), ('so', 'so-pin')])
def test_release_changed_pin_persists_and_reinit_never_restores_demo_pin(release_state, lifecycle_helper, role, original):
    image, base, state, secrets = release_state
    replacement = 'changed-user-7931' if role == 'user' else 'changed-so-8642'
    (secrets / 'replacement').write_text(replacement)
    before = {name: (state / 'haskoki' / name).read_bytes() for name in ('complete', 'haskoki.toml')}
    changed = native(release_state, lifecycle_helper, 'set-pin', role, '/run/secrets/' + original, '/run/secrets/replacement')
    accepted = native(release_state, lifecycle_helper, 'login', role, '/run/secrets/replacement')
    refused = native(release_state, lifecycle_helper, 'login', role, '/run/secrets/' + original, check=False)
    assert refused.returncode == 1 and 'C_Login failed (rv=0xa0)' in refused.stderr
    repeated = docker(*base, *lifecycle_controls(), image, 'init')
    native(release_state, lifecycle_helper, 'login', role, '/run/secrets/replacement')
    for name, content in before.items():
        assert (state / 'haskoki' / name).read_bytes() == content
        assert replacement.encode() not in content
    for result in (changed, accepted, refused, repeated):
        assert_no_secret_output(result, USER_PIN, SO_PIN, replacement)
    caller, output = state.parent / 'caller', state.parent / 'receipt-output'
    caller.mkdir()
    inputs = {'P11LAB_STATE_DIR': str(state), 'P11LAB_LABEL': TOKEN_LABEL,
              'P11LAB_PIN_FILE': str(secrets / ('replacement' if role == 'user' else 'pin')),
              'P11LAB_SO_PIN_FILE': str(secrets / ('replacement' if role == 'so' else 'so-pin'))}
    run = run_application(RunSpec('haskoki', 'release', 'direct', as_ref(image), 'provider', None, None,
                                 ('sh', '-c', 'printf caller-ok'), inputs, output, caller, 120))
    assert run.exit_code == 0 and run.app_returncode == 0, run
    receipt = Path(run.receipt_path).read_text()
    assert replacement not in receipt
    assert json.loads(receipt)['exit_code'] == 0
    for log in output.rglob('*.log'):
        assert replacement not in log.read_text()
    native(release_state, lifecycle_helper, 'login', role, '/run/secrets/replacement')


def test_release_init_token_and_init_pin_commit_across_processes(release_state, lifecycle_helper):
    image, base, state, secrets = release_state
    replacement = 'initialized-user-9526'
    (secrets / 'replacement').write_text(replacement)
    reset = native(release_state, lifecycle_helper, 'init-token', '/run/secrets/so-pin', TOKEN_LABEL)
    # Explicit native reset on this test's isolated disposable state only.
    initialized = native(release_state, lifecycle_helper, 'init-pin', '/run/secrets/so-pin', '/run/secrets/replacement')
    accepted = native(release_state, lifecycle_helper, 'login', 'user', '/run/secrets/replacement')
    refused = native(release_state, lifecycle_helper, 'login', 'user', '/run/secrets/pin', check=False)
    assert refused.returncode == 1 and 'C_Login failed (rv=0xa0)' in refused.stderr
    docker(*base, *lifecycle_controls(), image, 'init')
    native(release_state, lifecycle_helper, 'login', 'user', '/run/secrets/replacement')
    for result in (reset, initialized, accepted, refused):
        assert_no_secret_output(result, USER_PIN, SO_PIN, replacement)
    for name in ('complete', 'haskoki.toml'):
        assert replacement not in (state / 'haskoki' / name).read_text()


def test_release_checker_two_independent_frozen_shards(tmp_path):
    from test_haskoki import CHECKERS
    if 'release' not in CHECKERS:
        pytest.skip('P11LAB_TEST_HASKOKI_CHECKER_IMAGES lacks release')
    from p11lab.checker import load_profile, run_checker
    from test_checker_smoke import assert_native_build_identity, in_derivative
    image = CHECKERS['release']
    caller = tmp_path / 'caller'
    caller.mkdir()
    pin, so_pin = write_pins(caller)
    in_derivative(image, tmp_path, '''
from pathlib import Path
from p11lab.checker import installed_identity, load_profile
from p11lab.shards import plan_shards
identity = installed_identity()
plan_shards(Path(identity['installed_root']), load_profile()['nodes'], 2, Path('/evidence/plan'))
''')
    plan = json.loads((tmp_path / 'plan/plan.json').read_text())
    assert len(plan['shards']) == 2
    attempts, volumes = [], []
    for shard in plan['shards']:
        selection = caller / ('shard-' + str(shard['shard_id']) + '.json')
        selection.write_text(json.dumps(load_profile() | {'nodes': shard['nodes']}))
        output = tmp_path / ('shard-' + str(shard['shard_id']))
        spec = RunSpec('haskoki', 'release', 'direct', as_ref(image), 'provider', None, None, (),
                       {'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN_FILE': str(so_pin), 'P11LAB_LABEL': TOKEN_LABEL},
                       output, caller, 900)
        result = run_checker(spec, str(selection))
        receipt = json.loads((output / 'checker/checker-receipt.json').read_text())
        # Provider observations are retained as observations, never normalized.
        assert receipt['evidence']['observations_complete'] is True
        assert_native_build_identity(output / 'checker')
        outer = json.loads(Path(result.receipt_path).read_text())
        assert not outer['cleanup_errors']
        volumes.extend(r['identity'] for r in outer['owned_resources'] if r['kind'] == 'volume')
        attempts.append({'shard_id': shard['shard_id'], 'attempt_id': receipt['attempt_id'],
                         'directory': '/evidence/' + output.name + '/checker', 'nodes': receipt['nodes'],
                         'sources': receipt['sources'], 'checker': plan['checker'], 'selected': True})
    assert len(volumes) == len(set(volumes)) == 2
    assert len({attempt['attempt_id'] for attempt in attempts}) == 2
    (tmp_path / 'attempts.json').write_text(json.dumps(attempts))
    in_derivative(image, tmp_path, '''
import json
from pathlib import Path
from p11lab.shards import merge_shards
plan = json.loads(Path('/evidence/plan/plan.json').read_text())
attempts = json.loads(Path('/evidence/attempts.json').read_text())
merged = merge_shards(plan, attempts, Path('/evidence/merge'))
assert merged['complete'], merged
assert merged['summary']['total'] == len(plan['roster'])
assert not merge_shards(plan, attempts[:1], Path('/evidence/merge-missing'))['complete']
''')


@pytest.mark.parametrize('version', ['1', '2', '4'])
def test_release_native_open_does_not_migrate_incompatible_schema(release_state, lifecycle_helper, version):
    image, base, state, _ = release_state
    with sqlite3.connect(state / 'haskoki/token.sqlite') as database:
        database.execute("UPDATE store_meta SET value=? WHERE key='schema_version'", (version,))
    before = snapshot(state)
    # Bypass P11Lab readiness deliberately to distinguish the known adapter
    # inspection gap from the native module's refusal/migration behavior.
    result = docker(*base, *lifecycle_helper, '-e', 'HASKOKI_CONFIG=/var/lib/p11lab/haskoki/haskoki.toml',
                    '--entrypoint', HELPER, image, MODULE, 'login', 'user', '/run/secrets/pin', check=False)
    assert result.returncode == 1 and 'C_Initialize failed (rv=0x5)' in result.stderr
    assert snapshot(state) == before
