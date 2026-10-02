"""Freeze the public checker's file plan and validate selected shard attempts.

Planning/merge require the optional checker installed in sys.executable. No
balancer lives here. Attempts are explicit {shard_id, attempt_id, directory,
nodes, sources, checker, selected}; exactly one selected attempt per shard.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from .checker import LOCK, SOURCE, WHEEL, _lifecycle, canonical_node, source_inventory, validate_results


def plan_shards(installed_root: Path, roster: list[str], count: int, output_dir: Path) -> dict:
    if type(count) is not int or count < 1:
        raise ValueError('positive shard count required')
    import pkcs11_check.testcases as tests
    root = installed_root.resolve(strict=True)
    if root != Path(tests.__file__).resolve().parent:
        raise ValueError('planning requires this interpreter installed test root')
    sources = source_inventory(root, roster)
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    inventory = output_dir / 'planning'
    inventory.mkdir()
    for name, source in sources.items():
        link = inventory / name
        link.parent.mkdir(parents=True, exist_ok=True)
        link.symlink_to(source['path'])
    argv = [sys.executable, '-m', 'pkcs11_check', 'shard-units', '--shards', str(count),
            '--testcases', str(inventory), '--format', 'json']
    result = subprocess.run(argv, cwd=output_dir, capture_output=True, text=True, timeout=180)
    (output_dir / 'checker-plan.stdout.json').write_text(result.stdout)
    (output_dir / 'checker-plan.stderr.log').write_text(result.stderr)
    if result.returncode:
        raise ValueError('checker planning failed')
    groups = json.loads(result.stdout)['shards']
    if len(groups) != count:
        raise ValueError('planner shard count mismatch')
    assigned = set()
    shards = []
    for index, entries in enumerate(groups):
        names = []
        for entry in entries:
            path = Path(entry)
            name = path.relative_to(inventory).as_posix()
            if (name not in sources or name in assigned or not path.is_symlink()
                    or str(path.resolve(strict=True)) != sources[name]['path']
                    or hashlib.sha256(path.read_bytes()).hexdigest() != sources[name]['sha256']):
                raise ValueError('planner source substitution or duplicate ownership')
            assigned.add(name)
            names.append(name)
        selected = [n for n in roster if n.split('::', 1)[0] in names]
        if not selected:
            raise ValueError('empty selected shard')
        shards.append({'shard_id': index, 'files': names, 'nodes': selected})
    if assigned != set(sources):
        raise ValueError('missing planner source')
    plan = {'schema_version': 1, 'installed_root': str(root), 'roster': roster, 'sources': sources,
            'checker': {'source_revision': SOURCE, 'wheel_sha256': WHEEL, 'runtime_lock_sha256': LOCK},
            'shards': shards, 'planner_argv': argv}
    plan['plan_id'] = hashlib.sha256(json.dumps(plan, sort_keys=True).encode()).hexdigest()
    (output_dir / 'plan.json').write_text(json.dumps(plan, indent=2))
    return plan


def validate_shard_roster(expected: dict, attempts: list[dict]) -> dict:
    errors, selected, identities, assigned = [], [], set(), set()
    if expected.get('checker') != {'source_revision': SOURCE, 'wheel_sha256': WHEEL, 'runtime_lock_sha256': LOCK}:
        errors.append('frozen checker identity mismatch')
    sealed = {k: v for k, v in expected.items() if k != 'plan_id'}
    if expected.get('plan_id') != hashlib.sha256(json.dumps(sealed, sort_keys=True).encode()).hexdigest():
        errors.append('frozen plan seal mismatch')
    shards = {s['shard_id']: s for s in expected['shards']}
    try:
        if source_inventory(Path(expected['installed_root']), expected['roster']) != expected['sources']:
            errors.append('frozen source identity mismatch')
    except (OSError, ValueError):
        errors.append('frozen source identity mismatch')
    if len(shards) != len(expected['shards']):
        errors.append('duplicate expected shard')
    frozen = [n for s in shards.values() for n in s['nodes']]
    if len(frozen) != len(set(frozen)) or set(frozen) != set(expected['roster']):
        errors.append('invalid frozen roster')
    for attempt in attempts:
        identity = attempt.get('attempt_id')
        if not isinstance(identity, str) or not identity or identity in identities:
            errors.append('invalid or duplicate attempt identity')
        if isinstance(identity, str):
            identities.add(identity)
        if attempt.get('selected') is not True:
            continue
        shard = attempt.get('shard_id')
        if shard not in shards:
            errors.append('unknown shard')
            continue
        if shard in assigned:
            errors.append('two selected retries for shard')
        assigned.add(shard)
        if attempt.get('checker') != expected['checker']:
            errors.append('checker identity mismatch')
        nodes = attempt.get('nodes', [])
        if len(nodes) != len(set(nodes)) or set(nodes) != set(shards[shard]['nodes']):
            errors.append('shard node roster mismatch')
        sources = {k: v for k, v in expected['sources'].items() if k in shards[shard]['files']}
        if attempt.get('sources') != sources:
            errors.append('shard source identity mismatch')
        try:
            directory = Path(attempt['directory'])
            receipt = json.loads((directory / 'checker-receipt.json').read_text())
            if receipt['attempt_id'] != identity or receipt['nodes'] != nodes or receipt['sources'] != sources:
                errors.append('durable attempt receipt mismatch')
            if any(receipt['checker'].get(k) != v for k, v in expected['checker'].items()):
                errors.append('durable checker identity mismatch')
            assessment = validate_results(directory, nodes, Path(expected['installed_root']))
            if not assessment['complete']:
                errors.extend(assessment['errors'])
        except (OSError, ValueError, KeyError, TypeError):
            errors.append('missing durable attempt receipt')
        selected.append(attempt)
    if assigned != set(shards):
        errors.append('missing selected shard')
    directories = [str(Path(a['directory']).resolve()) for a in selected]
    if len(directories) != len(set(directories)):
        errors.append('selected attempts alias one directory')
    return {'complete': not errors, 'errors': sorted(set(errors)),
            'selected_attempts': [{'shard_id': a['shard_id'], 'attempt_id': a['attempt_id'], 'directory': a['directory']} for a in selected]}


def merge_shards(plan: dict, attempts: list[dict], output_dir: Path) -> dict:
    validation = validate_shard_roster(plan, attempts)
    output_dir = output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    if not validation['complete']:
        (output_dir / 'merge-receipt.json').write_text(json.dumps(validation, indent=2))
        return validation
    dirs = [a['directory'] for a in sorted(validation['selected_attempts'], key=lambda a: a['shard_id'])]
    argv = [sys.executable, '-m', 'pkcs11_check', 'merge-shards', *dirs, '--output', str(output_dir / 'merged')]
    process = subprocess.run(argv, cwd=output_dir, capture_output=True, text=True, timeout=180)
    (output_dir / 'merge.stdout.log').write_text(process.stdout)
    (output_dir / 'merge.stderr.log').write_text(process.stderr)
    errors = []
    try:
        payload = json.loads((output_dir / 'merged/results.json').read_text())
        raw = [json.loads(line) for line in (output_dir / 'merged/report.jsonl').read_text().splitlines() if line.strip()]
        nodes = {canonical_node(t['nodeid'], Path(plan['installed_root'])) for u in payload['units'] for t in u.get('tests', []) if not _lifecycle(t)}
        expected = {str(Path(plan['installed_root']) / n) for n in plan['roster']}
        executions = [o['target'] for u in payload['units'] for o in u.get('executions', []) if o.get('role') == 'unit']
        if not nodes <= expected or set(executions) != expected or len(executions) != len(expected):
            errors.append('merged membership mismatch')
        if payload['summary'].get('incomplete') is not False or any(u.get('incomplete') or u.get('completion_verified') is False for u in payload['units']):
            errors.append('merged checker evidence incomplete')
        if not {canonical_node(r['nodeid'], Path(plan['installed_root'])) for r in raw if r.get('$report_type') == 'TestReport' and not _lifecycle(r)} <= expected:
            errors.append('merged raw membership mismatch')
        # Native merge must retain raw classifications/process observations,
        # including complete provider failures. Grouped counts alone cannot
        # prove that the expected raw shard evidence survived the merge.
        def raw_evidence(records):
            return Counter(json.dumps(r, sort_keys=True) for r in records
                           if r.get('$report_type') in {'TestReport', 'ProcessReport', 'TeardownFinalize'})
        selected_raw = []
        for directory in dirs:
            selected_raw.extend(json.loads(line) for line in (Path(directory) / 'report.jsonl').read_text().splitlines() if line.strip())
        if raw_evidence(raw) != raw_evidence(selected_raw):
            errors.append('merged raw evidence differs from selected attempts')
        summary = payload['summary']
    except (OSError, ValueError, KeyError, TypeError):
        errors.append('missing or malformed merged evidence')
        summary = {}
    if process.returncode:
        errors.append('checker merge failed')
    record = validation | {'complete': not errors, 'errors': errors, 'returncode': process.returncode,
                           'summary': summary, 'plan_id': plan['plan_id'], 'argv': argv}
    (output_dir / 'merge-receipt.json').write_text(json.dumps(record, indent=2))
    return record
