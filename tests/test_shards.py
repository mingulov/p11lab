import copy
import json
from pathlib import Path
import subprocess

import pytest

from p11lab.checker import load_profile
from p11lab.shards import merge_shards, plan_shards, validate_shard_roster
from test_checker_results import installed_root, write_evidence


@pytest.fixture
def prepared(tmp_path):
    profile = load_profile()
    plan = plan_shards(installed_root(), profile['nodes'], 2, tmp_path / 'plan')
    attempts = []
    for shard in plan['shards']:
        directory = tmp_path / ('shard-' + str(shard['shard_id']))
        write_evidence(directory, shard['nodes'])
        sources = {k: v for k, v in plan['sources'].items() if k in shard['files']}
        attempt = {'shard_id': shard['shard_id'], 'attempt_id': 'attempt-' + str(shard['shard_id']),
                   'directory': str(directory), 'nodes': shard['nodes'], 'sources': sources,
                   'checker': plan['checker'], 'selected': True}
        (directory / 'checker-receipt.json').write_text(json.dumps(attempt))
        attempts.append(attempt)
    return plan, attempts


def test_real_planner_and_exact_selected_roster(prepared):
    plan, attempts = prepared
    assert [len(s['nodes']) for s in plan['shards']] == [10, 13]
    assert validate_shard_roster(plan, attempts)['complete']
    inventory = Path(plan['planner_argv'][plan['planner_argv'].index('--testcases') + 1])
    assert len(list(inventory.glob('*.py'))) == 5
    assert all(p.is_symlink() for p in inventory.glob('*.py'))


@pytest.mark.parametrize('defect', ['omitted', 'duplicate-case', 'unknown-case', 'missing-evidence',
                                  'source-hash', 'wheel-hash', 'two-retries', 'receipt-identity'])
def test_refuse_incomplete_rosters(prepared, defect):
    plan, attempts = copy.deepcopy(prepared)
    if defect == 'omitted':
        attempts.pop()
    elif defect == 'duplicate-case':
        attempts[0]['nodes'].append(attempts[0]['nodes'][0])
    elif defect == 'unknown-case':
        attempts[0]['nodes'][0] += '_unknown'
    elif defect == 'missing-evidence':
        (Path(attempts[0]['directory']) / 'state.json').unlink()
    elif defect == 'source-hash':
        next(iter(attempts[0]['sources'].values()))['sha256'] = '0' * 64
    elif defect == 'wheel-hash':
        attempts[0]['checker'] = attempts[0]['checker'] | {'wheel_sha256': '0' * 64}
    elif defect == 'receipt-identity':
        attempts[0]['attempt_id'] = 'unrecorded-attempt'
    else:
        retry = copy.deepcopy(attempts[0])
        retry['attempt_id'] = 'retry-2'
        attempts.append(retry)
    result = validate_shard_roster(plan, attempts)
    assert not result['complete'], defect


def test_explicit_retry_selection_keeps_original(prepared):
    plan, attempts = prepared
    original = attempts[0] | {'selected': False, 'attempt_id': 'superseded'}
    assert validate_shard_roster(plan, [original, *attempts])['complete']


def test_merge_zero_does_not_clear_incomplete(prepared, tmp_path, monkeypatch):
    plan, attempts = prepared
    def fake_merge(argv, **kwargs):
        output = Path(argv[-1])
        output.mkdir()
        payload = {'summary': {'incomplete': True}, 'units': []}
        (output / 'results.json').write_text(json.dumps(payload))
        (output / 'report.jsonl').write_text('')
        return subprocess.CompletedProcess(argv, 0, '', '')
    monkeypatch.setattr('p11lab.shards.subprocess.run', fake_merge)
    result = merge_shards(plan, attempts, tmp_path / 'merged')
    assert result['returncode'] == 0
    assert not result['complete']


def test_invalid_roster_never_calls_merge(prepared, tmp_path, monkeypatch):
    plan, attempts = prepared
    def forbidden(*args, **kwargs):
        pytest.fail('invalid roster reached native merge')
    monkeypatch.setattr('p11lab.shards.subprocess.run', forbidden)
    assert not merge_shards(plan, attempts[:1], tmp_path / 'missing')['complete']


@pytest.mark.parametrize('location', ['state', 'raw'])
def test_extra_unit_evidence_never_reaches_merge(prepared, tmp_path, monkeypatch, location):
    plan, attempts = prepared
    directory = Path(attempts[0]['directory'])
    state = json.loads((directory / 'state.json').read_text())
    extra = copy.deepcopy(state['process_observations'][0])
    extra['target'] += '_unknown'
    if location == 'state':
        state['process_observations'].append(extra)
        (directory / 'state.json').write_text(json.dumps(state))
    else:
        with (directory / 'report.jsonl').open('a') as stream:
            stream.write(json.dumps({'$report_type': 'ProcessReport', 'target': extra['target'],
                                     'observation': extra}) + '\n')
    def forbidden(*args, **kwargs):
        pytest.fail('extra unit evidence reached native merge')
    monkeypatch.setattr('p11lab.shards.subprocess.run', forbidden)
    assert not merge_shards(plan, attempts, tmp_path / 'extra-unit')['complete']


@pytest.mark.parametrize('disposition', ['crashed', 'finalize'])
def test_native_merge_preserves_completed_failure(prepared, tmp_path, disposition):
    plan, attempts = prepared
    failed = tmp_path / 'complete-failure'
    write_evidence(failed, attempts[0]['nodes'], disposition)
    attempts[0]['directory'] = str(failed)
    (failed / 'checker-receipt.json').write_text(json.dumps(attempts[0]))
    result = merge_shards(plan, attempts, tmp_path / 'merge-failure')
    assert result['complete'], result
    merged = json.loads((tmp_path / 'merge-failure/merged/results.json').read_text())
    expected_status = 'failed' if disposition == 'finalize' else disposition
    assert expected_status in {u['status'] for u in merged['units']}


def test_merge_zero_with_missing_raw_evidence_is_rejected(prepared, tmp_path, monkeypatch):
    plan, attempts = prepared
    def fake_merge(argv, **kwargs):
        output = Path(argv[-1])
        output.mkdir()
        payloads = [json.loads((Path(a['directory']) / 'results.json').read_text()) for a in attempts]
        payload = {'summary': {'incomplete': False}, 'units': sum((p['units'] for p in payloads), [])}
        (output / 'results.json').write_text(json.dumps(payload))
        (output / 'report.jsonl').write_text('')
        return subprocess.CompletedProcess(argv, 0, '', '')
    monkeypatch.setattr('p11lab.shards.subprocess.run', fake_merge)
    result = merge_shards(plan, attempts, tmp_path / 'merged-empty-raw')
    assert result['returncode'] == 0
    assert not result['complete']
    assert 'merged raw evidence differs from selected attempts' in result['errors']


@pytest.mark.parametrize('mutation', ['hidden-finalize', 'returncode', 'cleared-timeout'])
def test_merge_reconciles_preserved_raw_classifications(prepared, tmp_path, monkeypatch, mutation):
    plan, attempts = prepared
    failed = tmp_path / 'finalize-failure'
    write_evidence(failed, attempts[0]['nodes'], 'finalize')
    attempts[0]['directory'] = str(failed)
    (failed / 'checker-receipt.json').write_text(json.dumps(attempts[0]))
    def fake_merge(argv, **kwargs):
        output = Path(argv[-1])
        output.mkdir()
        payloads = [json.loads((Path(a['directory']) / 'results.json').read_text()) for a in attempts]
        keys = payloads[0]['summary'].keys() - {'incomplete'}
        payload = {'summary': {k: sum(p['summary'].get(k, 0) for p in payloads) for k in keys},
                   'units': sum((p['units'] for p in payloads), [])}
        payload['summary']['incomplete'] = False
        if mutation == 'cleared-timeout':
            payload['summary']['timeout'] = 1
        elif mutation == 'returncode':
            payload['units'][0]['returncode'] = 0
        else:
            payload['units'][0]['tests'] = []
            payload['units'][0]['status'] = 'passed'
            payload['units'][0]['counts']['error'] = 0
        (output / 'results.json').write_text(json.dumps(payload))
        (output / 'report.jsonl').write_text(''.join((Path(a['directory']) / 'report.jsonl').read_text() for a in attempts))
        return subprocess.CompletedProcess(argv, 0, '', '')
    monkeypatch.setattr('p11lab.shards.subprocess.run', fake_merge)
    result = merge_shards(plan, attempts, tmp_path / 'contradictory-merge')
    assert result['returncode'] == 0
    assert not result['complete'], result



def test_native_timeout_is_observed_complete_but_aggregate_incomplete(prepared, tmp_path):
    from p11lab.checker import validate_results
    import sys
    plan, attempts = prepared
    timeout = tmp_path / 'observed-timeout'
    write_evidence(timeout, attempts[0]['nodes'], 'timeout')
    attempts[0]['directory'] = str(timeout)
    (timeout / 'checker-receipt.json').write_text(json.dumps(attempts[0]))
    evidence = validate_results(timeout, attempts[0]['nodes'], Path(plan['installed_root']))
    assert evidence['observations_complete'] and not evidence['complete']
    native = tmp_path / 'native-timeout-merge'
    command = subprocess.run([sys.executable, '-m', 'pkcs11_check', 'merge-shards',
                              *[a['directory'] for a in attempts], '--output', str(native)],
                             capture_output=True, text=True, check=True)
    assert command.returncode == 0
    payload = json.loads((native / 'results.json').read_text())
    assert payload['summary']['incomplete'] is True
    assert payload['summary']['timeout'] == 10
    assert not merge_shards(plan, attempts, tmp_path / 'orchestrated-timeout-merge')['complete']
