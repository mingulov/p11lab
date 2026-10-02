"""Opt-in installed direct smoke and two independent shards on accepted runtimes.

P11LAB_TEST_CHECKER_IMAGES is a JSON channel -> exact derivative engine-ID map.
The derivative contains the installed checker and adapter, so the only mounts
are caller inputs and output artifacts; no reference workspace is used.
"""
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess

import pytest

from p11lab.checker import load_profile, run_checker
from p11lab.models import ArtifactRef, RunSpec

IMAGES = json.loads(os.environ.get('P11LAB_TEST_CHECKER_IMAGES', '{}'))
pytestmark = pytest.mark.skipif(not IMAGES, reason='explicit installed checker derivatives required')


def in_derivative(image, root, script):
    result = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--read-only',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--user', f'{os.getuid()}:{os.getgid()}', '--tmpfs', '/tmp:rw,nosuid,nodev',
        '--mount', f'type=bind,src={root},dst=/evidence',
        '--entrypoint', '/opt/p11lab-checker/bin/python', image, '-c', script],
        capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, result.stderr
    return result


@pytest.mark.parametrize('channel,image', list(IMAGES.items()))
def test_installed_direct_and_two_shard_proof(channel, image, tmp_path):
    evidence = os.environ.get('P11LAB_TEST_CHECKER_EVIDENCE')
    root = Path(evidence).resolve() / channel if evidence else tmp_path
    root.mkdir(parents=True, exist_ok=True)
    caller = root / 'caller with spaces'
    caller.mkdir()
    spec = RunSpec('softhsm2', channel, 'direct', ArtifactRef('docker-local', image, image[7:], 'linux/amd64'),
                   'provider', None, None, (), {'P11LAB_PIN': '1234', 'P11LAB_SO_PIN': '12345678',
                   'P11LAB_LABEL': 'P11Lab'}, root / 'full', caller, 900)
    full = run_checker(spec, 'smoke-v1')
    assert full.exit_code == 0, full
    receipt = json.loads((root / 'full/checker/checker-receipt.json').read_text())
    assert receipt['evidence']['complete']
    assert len(receipt['nodes']) == 23
    assert receipt['evidence']['summary']['passed'] >= 10
    # Keep a clean-room interpreter/distribution roster and same-version pure Tomli proof.
    in_derivative(image, root, '''
import json,tomli
from pathlib import Path
from p11lab.checker import installed_identity,load_profile
from p11lab.shards import plan_shards
identity=installed_identity()
assert Path(tomli.__file__).suffix == '.py'
assert tomli.loads('answer = 42')['answer'] == 42
Path('/evidence/installation.json').write_text(json.dumps(identity,indent=2))
plan=plan_shards(Path(identity['installed_root']),load_profile()['nodes'],2,Path('/evidence/plan'))
assert [len(s['nodes']) for s in plan['shards']] == [10,13]
''')
    plan = json.loads((root / 'plan/plan.json').read_text())
    attempts, volumes = [], []
    for shard in plan['shards']:
        profile = load_profile() | {'nodes': shard['nodes']}
        selected = caller / ('shard-' + str(shard['shard_id']) + '.json')
        selected.write_text(json.dumps(profile))
        run = replace(spec, output_dir=root / ('shard-' + str(shard['shard_id'])))
        outcome = run_checker(run, str(selected))
        assert outcome.exit_code == 0, outcome
        receipt = json.loads((run.output_dir / 'checker/checker-receipt.json').read_text())
        assert receipt['evidence']['complete']
        outer = json.loads(outcome.receipt_path.read_text())
        assert not outer['cleanup_errors']
        volumes.extend(r['identity'] for r in outer['owned_resources'] if r['kind'] == 'volume')
        attempt = {'shard_id': shard['shard_id'], 'attempt_id': receipt['attempt_id'],
                   'directory': '/evidence/' + run.output_dir.name + '/checker', 'nodes': receipt['nodes'],
                   'sources': receipt['sources'], 'checker': plan['checker'], 'selected': True}
        attempts.append(attempt)
    assert len(volumes) == len(set(volumes)) == 2
    (root / 'attempts.json').write_text(json.dumps(attempts, indent=2))
    in_derivative(image, root, '''
import json,copy
from pathlib import Path
from p11lab.shards import merge_shards
p=json.loads(Path('/evidence/plan/plan.json').read_text());a=json.loads(Path('/evidence/attempts.json').read_text())
assert merge_shards(p,a,Path('/evidence/merge-success'))['complete']
assert not merge_shards(p,a[:1],Path('/evidence/merge-missing'))['complete']
r=copy.deepcopy(a[0]);r['attempt_id']='unrecorded-second-selected-retry'
assert not merge_shards(p,[*a,r],Path('/evidence/merge-two-selected'))['complete']
''')
    # Explicit retry is a separate new run/token; original receipts stay intact.
    retry_spec = replace(spec, output_dir=root / 'retry-shard-0')
    retry = run_checker(retry_spec, str(caller / 'shard-0.json'))
    assert retry.exit_code == 0, retry
    receipt = json.loads((retry_spec.output_dir / 'checker/checker-receipt.json').read_text())
    attempts[0]['selected'] = False
    attempts.append(attempts[0] | {'attempt_id': receipt['attempt_id'], 'selected': True,
                                  'directory': '/evidence/retry-shard-0/checker'})
    (root / 'retry-attempts.json').write_text(json.dumps(attempts, indent=2))
    in_derivative(image, root, '''
import json
from pathlib import Path
from p11lab.shards import merge_shards
p=json.loads(Path('/evidence/plan/plan.json').read_text());a=json.loads(Path('/evidence/retry-attempts.json').read_text())
assert merge_shards(p,a,Path('/evidence/merge-retry-selected'))['complete']
''')
    for name in ('merge-success', 'merge-retry-selected'):
        merged = json.loads((root / name / 'merge-receipt.json').read_text())
        assert merged['complete'] and merged['returncode'] == 0
        assert merged['summary']['total'] == 23
        assert merged['summary']['incomplete'] is False
