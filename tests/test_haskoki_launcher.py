# SPDX-License-Identifier: Apache-2.0
"""Offline controller contracts. Never invoke a provider or dispatch a workflow."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / '.github/scripts/haskoki_launcher.py'
SHA = 'a' * 40
RUN = 40000000000
REPO = {'id': 1394988634, 'full_name': 'mingulov/p11lab', 'owner': {'id': 1794540}}


@pytest.fixture
def launcher():
    assert SCRIPT.is_file(), 'the admission helper has not been implemented'
    spec = importlib.util.spec_from_file_location('haskoki_launcher', SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def context():
    return {
        'GITHUB_REPOSITORY': 'mingulov/p11lab', 'GITHUB_REPOSITORY_ID': '1394988634',
        'GITHUB_REPOSITORY_OWNER_ID': '1794540', 'GITHUB_ACTOR_ID': '1794540',
        'GITHUB_SERVER_URL': 'https://github.com', 'GITHUB_API_URL': 'https://api.github.com',
        'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
        'GITHUB_REF_TYPE': 'branch', 'GITHUB_SHA': SHA, 'CONTROLLER_SHA': SHA,
        'CONTROLLER_WORKFLOW_REF': 'mingulov/p11lab/.github/workflows/haskoki-release-validation.yml@refs/heads/main',
        'REVIEWED_CONTROLLER_SHA': SHA, 'GITHUB_RUN_ID': str(RUN),
        'GITHUB_RUN_NUMBER': '3', 'GITHUB_RUN_ATTEMPT': '1',
    }


def event():
    return {'ref': 'main', 'repository': copy.deepcopy(REPO), 'sender': {'id': 1794540},
            'inputs': {'reviewed_controller_sha': SHA}}


def run(number=3):
    old = {1: (39461303417, '100d25a0119ee3612e993bda2ae8d9b5845abbe8', 'failure'),
           2: (39463132399, 'fca1b148f074bc0f3fd527bc02fe7920f33fa4cd', 'success')}
    rid, sha, conclusion = old.get(number, (RUN, SHA, None))
    return {'id': rid, 'workflow_id': 390791808,
            'path': '.github/workflows/haskoki-release-validation.yml',
            'name': 'haskoki-release-validation', 'run_number': number, 'run_attempt': 1,
            'event': 'workflow_dispatch' if number == 3 else 'pull_request',
            'head_sha': sha, 'head_branch': 'main' if number == 3 else 'candidate',
            'created_at': f'2026-10-{10 + number}T00:00:00Z',
            'status': 'in_progress' if number == 3 else 'completed', 'conclusion': conclusion,
            'actor': {'id': 1794540}, 'triggering_actor': {'id': 1794540},
            'repository': copy.deepcopy(REPO), 'head_repository': copy.deepcopy(REPO),
            'pull_requests': []}


def jobs(number):
    ids = {1: (118761165005, 118761167755), 2: (118767408221, 118767410829)}
    return {'total_count': 2, 'jobs': [
        {'id': jid, 'run_id': run(number)['id'], 'run_attempt': 1, 'name': name,
         'status': 'completed', 'conclusion': ('failure' if number == 1 else 'success')
         if name == 'static' else 'skipped', 'steps': []}
        for jid, name in zip(ids[number], ('static', 'runtime'))]}


class Reads:
    def __init__(self, records=None):
        self.records = records if records is not None else [run(3), run(2), run(1)]
        self.calls = []
        self.change = lambda route, data, count: data

    def __call__(self, route):
        self.calls.append(route)
        if route == '/repos/mingulov/p11lab':
            value = REPO | {'default_branch': 'main'}
        elif route.endswith('/git/ref/heads/main'):
            value = {'ref': 'refs/heads/main', 'object': {'type': 'commit', 'sha': SHA}}
        elif '/jobs?' in route:
            number = 1 if '/39461303417/' in route else 2
            value = jobs(number)
        elif '/actions/runs?' in route:
            page = int(route.rsplit('=', 1)[1])
            value = {'total_count': len(self.records), 'workflow_runs': self.records[(page-1)*100:page*100]}
        else:
            value = run()
        value = self.change(route, copy.deepcopy(value), self.calls.count(route))
        link = ''
        if '/actions/runs?' in route:
            page = int(route.rsplit('=', 1)[1])
            if page * 100 < len(self.records):
                link = f'<https://api.github.com/repos/mingulov/p11lab/actions/runs?per_page=100&page={page+1}>; rel="next"'
        return value, link


def admit(launcher, reads=None, env=None, ev=None):
    return launcher.admit(context() if env is None else env, event() if ev is None else ev,
                          SHA, reads or Reads())


def test_exact_active_run_three_with_complete_old_jobs_is_admitted(launcher):
    reads = Reads()
    result = admit(launcher, reads)
    assert len(result) == 64 and set(result) <= set('0123456789abcdef')
    assert len(reads.calls) == 8
    assert reads.calls.count('/repos/mingulov/p11lab/actions/runs?per_page=100&page=1') == 2
    assert all('filter=all&per_page=100&page=1' in x for x in reads.calls if '/jobs?' in x)


@pytest.mark.parametrize('key', list(context()))
def test_missing_context_refuses_before_network(launcher, key):
    env = context(); env.pop(key)
    reads = Reads()
    with pytest.raises(launcher.Refusal):
        admit(launcher, reads, env)
    assert reads.calls == []


@pytest.mark.parametrize(('key', 'value'), [
    ('GITHUB_EVENT_NAME', 'pull_request'), ('GITHUB_REF', 'refs/tags/main'),
    ('GITHUB_REF_TYPE', 'tag'), ('GITHUB_ACTOR_ID', '42'), ('GITHUB_REPOSITORY_ID', '42'),
    ('GITHUB_REPOSITORY', 'evil/p11lab'), ('GITHUB_REPOSITORY_OWNER_ID', '42'),
    ('GITHUB_RUN_ATTEMPT', '2'), ('GITHUB_RUN_NUMBER', '4'), ('GITHUB_RUN_ID', '0'),
    ('GITHUB_RUN_ID', '3\n'), ('REVIEWED_CONTROLLER_SHA', '$(touch unsafe)'),
    ('CONTROLLER_SHA', 'b'*40), ('GITHUB_SHA', 'b'*40),
    ('CONTROLLER_WORKFLOW_REF', 'mingulov/p11lab/other.yml@refs/heads/main'),
    ('GITHUB_SERVER_URL', 'https://example.org'), ('GITHUB_API_URL', 'https://example.org'),
])
def test_wrong_context_refuses_before_network(launcher, key, value):
    env = context(); env[key] = value
    reads = Reads()
    with pytest.raises(launcher.Refusal):
        admit(launcher, reads, env)
    assert reads.calls == []


@pytest.mark.parametrize('mutation', [
    lambda e: e.update(ref='other'), lambda e: e['repository'].update(id=True),
    lambda e: e['repository']['owner'].update(id=42), lambda e: e['sender'].update(id=42),
    lambda e: e['inputs'].update(reviewed_controller_sha='b'*40),
    lambda e: e['inputs'].update(payload='unreviewed'),
])
def test_event_identity_is_checked_without_printing_it(launcher, mutation):
    ev = event(); mutation(ev)
    with pytest.raises(launcher.Refusal):
        admit(launcher, ev=ev)


@pytest.mark.parametrize(('field', 'value'), [
    ('workflow_id', 42), ('path', 'other.yml'), ('name', 'other'),
    ('run_attempt', 2), ('run_number', True), ('head_sha', 'b'*40), ('head_branch', 'other'),
    ('event', 'pull_request'), ('status', 'completed'), ('status', 'queued'),
    ('status', None), ('status', 'unknown'), ('conclusion', 'success'),
    ('conclusion', 'cancelled'), ('actor', {'id': 42}),
    ('triggering_actor', {'id': 42}), ('repository', REPO | {'id': 1}),
    ('head_repository', REPO | {'id': 1}),
])
def test_bad_current_run_refuses(launcher, field, value):
    reads = Reads()
    reads.change = lambda route, data, count: data | {field: value} if route.endswith(str(RUN)) else data
    with pytest.raises(launcher.Refusal):
        admit(launcher, reads)


@pytest.mark.parametrize('mutation', [
    lambda rs: rs.pop(), lambda rs: rs.append(copy.deepcopy(rs[-1])),
    lambda rs: rs[1].update(run_attempt=2), lambda rs: rs[1].update(status='in_progress'),
    lambda rs: rs[1].update(conclusion='failure'), lambda rs: rs[1].update(head_sha='c'*40),
    lambda rs: rs[1].update(workflow_id=42), lambda rs: rs[1].update(path='wrong'),
    lambda rs: rs[1].update(name='wrong'), lambda rs: rs.reverse(),
    lambda rs: rs[1].update(created_at='invalid'),
])
def test_incomplete_colliding_or_changed_history_refuses(launcher, mutation):
    records = [run(3), run(2), run(1)]; mutation(records)
    with pytest.raises(launcher.Refusal):
        admit(launcher, Reads(records))


@pytest.mark.parametrize('mutation', [
    lambda d: d.update(total_count=True), lambda d: d.update(total_count=3),
    lambda d: d['jobs'].pop(), lambda d: d['jobs'][1].update(conclusion='success'),
    lambda d: d['jobs'][1].update(steps=[{'name': 'ran'}]),
    lambda d: d['jobs'][1].update(run_attempt=2), lambda d: d['jobs'][1].update(id=42),
    lambda d: d['jobs'][0].update(name='unknown'), lambda d: d['jobs'][0].update(status='queued'),
    lambda d: d['jobs'][0].update(run_id=42),
])
def test_missing_or_executed_historical_jobs_refuse(launcher, mutation):
    reads = Reads()
    def change(route, data, count):
        if '/jobs?' in route:
            mutation(data)
        return data
    reads.change = change
    with pytest.raises(launcher.Refusal):
        admit(launcher, reads)


def test_live_main_and_default_branch_must_still_match(launcher):
    for endpoint in ('/repos/mingulov/p11lab', '/repos/mingulov/p11lab/git/ref/heads/main'):
        reads = Reads()
        reads.change = lambda route, data, count: {} if route == endpoint else data
        with pytest.raises(launcher.Refusal):
            admit(launcher, reads)


@pytest.mark.parametrize('target', ['current', 'repeat'])
def test_visible_change_during_observation_refuses(launcher, target):
    reads = Reads()
    def change(route, data, count):
        if count == 2 and route.endswith(str(RUN)) and target == 'current':
            data.update(status='completed', conclusion='cancelled')
        if count == 2 and '/actions/runs?' in route and target != 'current':
            if target == 'repeat':
                data['workflow_runs'][1]['id'] += 10
            else:
                data['workflow_runs'][1]['pull_requests'] = [{'head': {'sha': 'b'*40}}]
        return data
    reads.change = change
    with pytest.raises(launcher.Refusal):
        admit(launcher, reads)


def unrelated(rid, created='2026-10-14T00:00:00Z'):
    return run() | {'id': rid, 'workflow_id': 42, 'name': 'linux-unit-validation',
                    'path': '.github/workflows/linux-unit-validation.yml', 'created_at': created}


def test_unrelated_new_run_between_independent_admissions_is_allowed(launcher):
    first = admit(launcher)
    second = admit(launcher, Reads([unrelated(50), run(3), run(2), run(1)]))
    assert first == second


def test_extra_haskoki_run_is_not_a_new_opportunity(launcher):
    with pytest.raises(launcher.Refusal):
        admit(launcher, Reads([run() | {'id': RUN + 1, 'run_number': 4}, run(3), run(2), run(1)]))


def test_admission_helper_exists():
    assert SCRIPT.is_file(), 'the admission helper has not been implemented'


@pytest.mark.parametrize('total', [100, 101, 500])
def test_complete_bounded_multi_page_history(launcher, total):
    records = [unrelated(1000+i) for i in range(total-3)] + [run(3), run(2), run(1)]
    reads = Reads(records)
    assert admit(launcher, reads) == admit(launcher)
    assert len(reads.calls) == 7 + (total+99)//100


def test_history_ceiling_is_not_silently_increased(launcher):
    with pytest.raises(launcher.Refusal):
        admit(launcher, Reads([unrelated(1000+i) for i in range(498)] + [run(3), run(2), run(1)]))


@pytest.mark.parametrize('url', [
    'https://api.github.com/other?per_page=100&page=2',
    'https://api.github.com/repos/mingulov/p11lab/actions/runs?per_page=100&page=3',
    'https://api.github.com/repos/mingulov/p11lab/actions/runs?per_page=100&page=2&event=pull_request',
    'https://api.github.com/repos/mingulov/p11lab/actions/runs?per_page=100&page=2&page=2',
    'https://api.github.com/repos/mingulov/p11lab/actions/runs?per_page=100&page=2#fragment',
    'https://api.github.com:443/repos/mingulov/p11lab/actions/runs?per_page=100&page=2',
    'https://user@api.github.com/repos/mingulov/p11lab/actions/runs?per_page=100&page=2',
    'https://api.github.com/repos/mingulov/p11lab/actions/%72uns?per_page=100&page=2',
    'http://api.github.com/repos/mingulov/p11lab/actions/runs?per_page=100&page=2',
])
def test_links_are_cross_checked_not_followed(launcher, url):
    with pytest.raises(launcher.Refusal):
        launcher.pagination(f'<{url}>; rel="next"', launcher.ROUTE + '/actions/runs', 1, 101)


@pytest.mark.parametrize('link', ['', '<https://api.github.com/repos/mingulov/p11lab/actions/runs?per_page=100&page=2>; rel="last"'])
def test_nonterminal_page_requires_next_link(launcher, link):
    with pytest.raises(launcher.Refusal):
        launcher.pagination(link, launcher.ROUTE + '/actions/runs', 1, 101)


def test_inconsistent_totals_and_short_pages_refuse(launcher):
    records = [unrelated(1000+i) for i in range(98)] + [run(3), run(2), run(1)]
    for mutation in ('total', 'length', 'duplicate'):
        reads = Reads(records)
        def change(route, data, count):
            if route.endswith('page=2'):
                if mutation == 'total': data['total_count'] += 1
                elif mutation == 'length': data['workflow_runs'] = []
                else: data['workflow_runs'] = [records[0]]
            return data
        reads.change = change
        with pytest.raises(launcher.Refusal):
            admit(launcher, reads)


def test_unobserved_replacement_on_later_page_is_an_explicit_limitation(launcher):
    # Two individually consistent snapshots can differ outside repeated page 1.
    # This test documents that no global atomic snapshot is claimed.
    records = [unrelated(1000+i) for i in range(101)] + [run(3), run(2), run(1)]
    reads = Reads(records)
    def change(route, data, count):
        if route.endswith('page=2'):
            data['workflow_runs'][0]['id'] = 9999
        return data
    reads.change = change
    assert admit(launcher, reads) == admit(launcher)


def test_unrelated_progress_may_change_on_first_page_repeat(launcher):
    reads = Reads([unrelated(50), run(3), run(2), run(1)])
    def change(route, data, count):
        if '/actions/runs?' in route and count == 2:
            data['workflow_runs'][0].update(status='completed', conclusion='success')
        return data
    reads.change = change
    assert admit(launcher, reads) == admit(launcher)


class Response:
    def __init__(self, body=b'{}', status=200, headers=None, url=None):
        import io
        self.stream = io.BytesIO(body)
        self.status = status
        self.headers = {'Content-Type': 'application/json'} if headers is None else headers
        self.url = url
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def read(self, count): return self.stream.read(count)
    def geturl(self): return self.url or 'https://api.github.com/repos/mingulov/p11lab'


def test_transport_contract_is_implemented(launcher):
    assert hasattr(launcher, 'PublicReads'), 'bounded unauthenticated transport is missing'


def test_public_reads_never_send_credentials_and_bound_reads(launcher):
    calls = []
    def open_request(request, timeout):
        calls.append((request, timeout)); return Response(b'{"id":1}')
    reader = launcher.PublicReads(open_request=open_request)
    assert reader('/repos/mingulov/p11lab') == ({'id': 1}, '')
    req, timeout = calls[0]
    assert req.full_url == 'https://api.github.com/repos/mingulov/p11lab'
    assert req.method == 'GET' and req.data is None and timeout <= 10
    assert not any(x.lower() in ('authorization', 'cookie') for x in req.headers)


@pytest.mark.parametrize('response', [
    Response(status=302), Response(status=429), Response(status=500),
    Response(url='https://api.github.com/other'), Response(body=b'<html>'),
    Response(body=b'{"a":1,"a":2}'), Response(body=b'{"a":NaN}'),
    Response(headers={'Content-Type': 'text/html'}),
    Response(headers={'Content-Type': 'application/json', 'Content-Encoding': 'gzip'}),
    Response(headers={'Content-Type': 'application/json', 'Content-Length': '100'}),
    Response(body=b'['), Response(body=b'{}\xff'),
])
def test_transport_refuses_uncertain_or_malformed_responses(launcher, response):
    reader = launcher.PublicReads(open_request=lambda *a, **k: response)
    with pytest.raises(launcher.Refusal):
        reader('/repos/mingulov/p11lab')


@pytest.mark.parametrize('route', [
    'https://evil.invalid', '/repos/mingulov/p11lab/actions/workflows',
    '/repos/mingulov/p11lab/actions/runs?per_page=100&page=1&event=push',
    '/repos/mingulov/p11lab/actions/runs/0',
    '/repos/mingulov/p11lab/actions/runs/42/jobs?per_page=100&page=1',
])
def test_transport_only_constructs_the_approved_fixed_routes(launcher, route):
    calls = []
    reader = launcher.PublicReads(open_request=lambda *a, **k: calls.append(a))
    with pytest.raises(launcher.Refusal): reader(route)
    assert not calls


def test_transport_response_and_total_byte_caps(launcher):
    body = b'{"v":"' + b'x' * (4*1024*1024) + b'"}'
    reader = launcher.PublicReads(open_request=lambda *a, **k: Response(body))
    with pytest.raises(launcher.Refusal): reader('/repos/mingulov/p11lab')
    body = b'{"v":"' + b'x' * (4*1024*1024-8) + b'"}'
    reader = launcher.PublicReads(open_request=lambda *a, **k: Response(body))
    for _ in range(6): reader('/repos/mingulov/p11lab')
    with pytest.raises(launcher.Refusal): reader('/repos/mingulov/p11lab')


def test_transport_request_and_deadline_caps(launcher):
    now = [0.0]
    reader = launcher.PublicReads(open_request=lambda *a, **k: Response(), clock=lambda: now[0])
    for _ in range(12): reader('/repos/mingulov/p11lab')
    with pytest.raises(launcher.Refusal): reader('/repos/mingulov/p11lab')
    reader = launcher.PublicReads(open_request=lambda *a, **k: Response(), clock=lambda: now[0])
    now[0] = 61
    with pytest.raises(launcher.Refusal): reader('/repos/mingulov/p11lab')


def test_transport_deadline_applies_during_blocking_read(launcher, monkeypatch):
    import signal
    import time
    monkeypatch.setattr(launcher, 'REQUEST_SECONDS', .03)
    class Slow(Response):
        def read(self, count): time.sleep(.2); return super().read(count)
    before = signal.getsignal(signal.SIGALRM)
    reader = launcher.PublicReads(open_request=lambda *a, **k: Slow())
    start = time.monotonic()
    with pytest.raises(launcher.Refusal): reader('/repos/mingulov/p11lab')
    assert time.monotonic() - start < .15
    assert signal.getsignal(signal.SIGALRM) == before


def test_redirect_handler_refuses_instead_of_following(launcher):
    assert launcher.NoRedirect().redirect_request(None, None, 302, 'moved', {}, 'https://api.github.com/other') is None


@pytest.fixture
def checkout(launcher, tmp_path, monkeypatch):
    import subprocess
    workspace = tmp_path / 'workspace'; workspace.mkdir()
    controller = workspace / 'controller'; controller.mkdir()
    payload = workspace / 'payload'; payload.mkdir()
    def git(*args):
        return subprocess.check_output(['git', '-C', str(payload), *args], stderr=subprocess.DEVNULL).decode().strip()
    git('init', '-q')
    (payload / 'src').mkdir()
    (payload / 'src/source.py').write_bytes(b'print("original")\n')
    (payload / 'driver.py').write_bytes(b'# original driver\n')
    (payload / 'driver.py').chmod(0o755)
    (payload / '.gitattributes').write_text('* text=auto eol=lf\n')
    (payload / '.gitignore').write_text('__pycache__/\n.local/\n')
    git('add', '.')
    git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
    monkeypatch.setattr(launcher, 'PAYLOAD_SHA', git('rev-parse', 'HEAD'))
    monkeypatch.setattr(launcher, 'PAYLOAD_TREE', git('rev-parse', 'HEAD^{tree}'))
    monkeypatch.setattr(launcher, 'FILE_COUNTS', {'100644': 3, '100755': 1}, raising=False)
    return workspace, controller, payload


def test_raw_payload_verifier_is_implemented(launcher):
    assert hasattr(launcher, 'verify_payload'), 'raw checkout verifier is missing'


def test_exact_raw_ordinary_checkout_is_accepted(launcher, checkout):
    assert launcher.verify_payload(*checkout) is None


@pytest.mark.parametrize('attack', ['bytes', 'crlf', 'mode', 'setuid', 'symlink', 'hardlink',
                                     'fifo', 'extra', 'ignored', 'pyc', 'directory', 'nestedgit', 'missing'])
def test_raw_payload_byte_type_mode_and_extra_input_attacks_refuse(launcher, checkout, attack):
    import os
    workspace, controller, payload = checkout
    target = payload / 'src/source.py'
    if attack == 'bytes': target.write_bytes(b'print("changed")\n')
    elif attack == 'crlf': target.write_bytes(target.read_bytes().replace(b'\n', b'\r\n'))
    elif attack == 'mode': target.chmod(0o755)
    elif attack == 'setuid': target.chmod(0o4644)
    elif attack == 'symlink': target.unlink(); target.symlink_to(payload / 'driver.py')
    elif attack == 'hardlink': os.link(target, workspace / 'linked')
    elif attack == 'fifo': target.unlink(); os.mkfifo(target)
    elif attack == 'extra': (payload / 'extra.py').write_text('extra')
    elif attack == 'ignored': (payload / '.local').mkdir(); (payload / '.local/source.py').write_text('extra')
    elif attack == 'pyc': (payload / '__pycache__').mkdir(); (payload / '__pycache__/source.pyc').write_bytes(b'extra')
    elif attack == 'directory': (payload / 'empty-extra').mkdir()
    elif attack == 'nestedgit': (payload / 'src/.git').mkdir()
    elif attack == 'missing': target.unlink()
    with pytest.raises(launcher.Refusal): launcher.verify_payload(*checkout)


@pytest.mark.parametrize('attack', ['controller', 'workspace', 'symlink', 'gitfile', 'gitlink'])
def test_payload_alias_or_administrative_path_refuses(launcher, checkout, attack):
    import shutil
    workspace, controller, payload = checkout
    if attack == 'controller': payload = controller
    elif attack == 'workspace': payload = workspace
    elif attack == 'symlink':
        moved = workspace / 'elsewhere'; payload.rename(moved); payload.symlink_to(moved, target_is_directory=True)
    elif attack == 'gitfile':
        shutil.rmtree(payload / '.git'); (payload / '.git').write_text('gitdir: elsewhere')
    else:
        moved = workspace / 'gitdir'; (payload / '.git').rename(moved); (payload / '.git').symlink_to(moved, target_is_directory=True)
    with pytest.raises(launcher.Refusal): launcher.verify_payload(workspace, controller, payload)


def test_wrong_commit_or_tree_refuses(launcher, checkout, monkeypatch):
    monkeypatch.setattr(launcher, 'PAYLOAD_SHA', 'b'*40)
    with pytest.raises(launcher.Refusal): launcher.verify_payload(*checkout)
    monkeypatch.setattr(launcher, 'PAYLOAD_SHA', launcher.git(checkout[2], 'rev-parse', 'HEAD').decode().strip())
    monkeypatch.setattr(launcher, 'PAYLOAD_TREE', 'b'*40)
    with pytest.raises(launcher.Refusal): launcher.verify_payload(*checkout)


@pytest.mark.parametrize('raw', [
    b'120000 blob '+b'a'*40+b'\tlink\0', b'160000 commit '+b'a'*40+b'\tmodule\0',
    b'100644 blob '+b'a'*40+b'\t../escape\0', b'100644 blob '+b'a'*40+b'\t.git/config\0',
    b'100644 blob '+b'a'*40+b'\t/absolute\0', b'100644 blob '+b'a'*40+b'\ta//b\0',
])
def test_manifest_rejects_unsafe_types_and_paths(launcher, raw):
    with pytest.raises(launcher.Refusal): launcher.manifest(raw)


def test_manifest_preserves_spaces_and_newlines_in_safe_file_names(launcher, monkeypatch):
    monkeypatch.setattr(launcher, 'FILE_COUNTS', {'100644': 1, '100755': 0}, raising=False)
    assert launcher.manifest(b'100644 blob '+b'a'*40+b'\tsafe name\nfile\0') == {'safe name\nfile': ('100644', 'a'*40)}


def test_file_changed_while_hashing_or_between_enumerations_refuses(launcher, checkout, monkeypatch):
    original = launcher.hash_file
    def mutate(path, mode, oid):
        original(path, mode, oid)
        if path.name == 'source.py': (path.parent / 'new.py').write_text('late input')
    monkeypatch.setattr(launcher, 'hash_file', mutate)
    with pytest.raises(launcher.Refusal): launcher.verify_payload(*checkout)


def test_raw_read_checks_stat_identity_after_read(launcher, checkout, monkeypatch):
    original = launcher.os.read
    changed = [False]
    def mutate(fd, size):
        value = original(fd, size)
        if not changed[0]:
            changed[0] = True
            (checkout[2] / 'src/source.py').write_bytes(b'changed\n')
        return value
    monkeypatch.setattr(launcher.os, 'read', mutate)
    with pytest.raises(launcher.Refusal): launcher.verify_payload(*checkout)


def test_external_paths_must_be_outside_both_checkouts(launcher, checkout, tmp_path):
    workspace, controller, payload = checkout
    assert launcher.outside_checkouts(tmp_path / 'external', controller, payload) is None
    for path in (controller, controller / 'venv', payload / 'wheels'):
        with pytest.raises(launcher.Refusal): launcher.outside_checkouts(path, controller, payload)
    alias = tmp_path / 'alias'; alias.symlink_to(controller, target_is_directory=True)
    with pytest.raises(launcher.Refusal): launcher.outside_checkouts(alias / 'venv', controller, payload)



def test_historical_mutable_nested_metadata_is_not_run_identity(launcher):
    reads = Reads()
    def change(route, data, count):
        if '/actions/runs?' in route and count == 2:
            record = data['workflow_runs'][1]
            record['pull_requests'] = [{'head': {'sha': 'b'*40}}]
            record['repository']['description'] = 'updated description'
            record['head_repository']['pushed_at'] = '2026-10-20T00:00:00Z'
            record['actor']['avatar_url'] = 'https://example.invalid/changed'
            record['triggering_actor']['login'] = 'renamed-display'
        return data
    reads.change = change
    assert admit(launcher, reads) == admit(launcher)


def test_genuine_nested_repository_identity_change_refuses(launcher):
    reads = Reads()
    def change(route, data, count):
        if '/actions/runs?' in route and count == 2:
            data['workflow_runs'][1]['repository']['owner']['id'] = 42
        return data
    reads.change = change
    with pytest.raises(launcher.Refusal): admit(launcher, reads)


@pytest.mark.parametrize('pairs', [
    [('Content-Length', '2'), ('Content-Length', '3')],
    [('Transfer-Encoding', 'chunked'), ('Content-Length', '2')],
    [('Transfer-Encoding', 'gzip')],
    [('Content-Encoding', 'identity'), ('Content-Encoding', 'gzip')],
    [('Content-Type', 'application/json'), ('Content-Type', 'text/html')],
    [('Link', ''), ('Link', '<https://evil.invalid>; rel="next"')],
])
def test_real_multi_headers_refuse_ambiguous_framing(launcher, pairs):
    from http.client import HTTPMessage
    headers = HTTPMessage()
    if not any(key == 'Content-Type' for key, _ in pairs): headers.add_header('Content-Type', 'application/json')
    for key, value in pairs: headers.add_header(key, value)
    reader = launcher.PublicReads(open_request=lambda *a, **k: Response(headers=headers))
    with pytest.raises(launcher.Refusal): reader('/repos/mingulov/p11lab')


def test_default_transport_disables_ambient_proxies(launcher, monkeypatch):
    import urllib.request
    captured = []
    real = launcher.build_opener
    def build(*handlers): captured.extend(handlers); return real(*handlers)
    monkeypatch.setattr(launcher, 'build_opener', build)
    launcher.PublicReads()
    assert any(isinstance(handler, urllib.request.ProxyHandler) and handler.proxies == {} for handler in captured)


def test_safe_summary_contract_exists(launcher):
    assert hasattr(launcher, 'safe_summary'), 'allowlisted summary is missing'


@pytest.mark.parametrize('state', [{}, {'classification': 'secret\nPIN=123'},
    {'controller_sha': 'bad\nTOKEN=secret', 'run_id': 'SECRET', 'payload_sha': 'untrusted'},
    {'classification': 'prebuild_admitted', 'controller_sha': SHA, 'run_id': RUN}])
def test_summary_only_exposes_allowlisted_identity_and_never_acceptance_success(launcher, state):
    text = launcher.safe_summary(state)
    assert 'frozen candidate evidence launched from main' in text
    assert 'not main runtime qualification' in text
    assert 'not acceptance success' in text
    assert not any(x in text for x in ('secret', 'SECRET', 'TOKEN', 'PIN', 'untrusted'))
    assert 'complete success' not in text


@pytest.fixture
def command_environment(launcher, checkout, tmp_path, monkeypatch):
    env = context() | {'GITHUB_WORKSPACE': str(checkout[0]), 'RUNNER_TEMP': str(tmp_path / 'temp'),
                       'GITHUB_EVENT_PATH': str(tmp_path / 'event.json'),
                       'GITHUB_STEP_SUMMARY': str(tmp_path / 'summary.md')}
    Path(env['RUNNER_TEMP']).mkdir()
    Path(env['GITHUB_EVENT_PATH']).write_text(json.dumps(event()))
    original = launcher.git
    monkeypatch.setattr(launcher, 'git', lambda root, *args: (SHA+'\n').encode() if root == checkout[1] else original(root, *args))
    monkeypatch.setattr(launcher, 'PublicReads', Reads)
    return env


def test_admission_and_payload_gate_record_before_any_frozen_execution(launcher, command_environment):
    env = command_environment
    assert launcher.execute('admit', env) == 0
    record = json.loads((Path(env['RUNNER_TEMP']) / 'haskoki-controller.json').read_text())
    assert record['classification'] == 'initial_admitted' and not record['payload_verified']
    assert launcher.execute('verify', env) == 0
    record = json.loads((Path(env['RUNNER_TEMP']) / 'haskoki-controller.json').read_text())
    assert record['payload_verified'] and record['classification'] == 'payload_verified'
    assert (Path(env['RUNNER_TEMP']) / 'haskoki-controller.json').stat().st_mode & 0o777 == 0o600


def test_prebuild_rechecks_payload_and_admission_without_calling_build(launcher, command_environment, checkout, monkeypatch):
    env = command_environment
    assert launcher.execute('admit', env) == launcher.execute('verify', env) == 0
    monkeypatch.setattr(launcher, 'verify_installed', lambda *args: None)
    assert launcher.execute('prebuild', env) == 0
    (checkout[2] / 'driver.py').write_text('changed')
    assert launcher.execute('prebuild', env) == 1
    record = json.loads((Path(env['RUNNER_TEMP']) / 'haskoki-controller.json').read_text())
    assert not record['payload_verified'] and record['classification'] == 'integrity_refused'


def test_later_integrity_failure_never_reuses_initial_verification_for_summary(launcher, command_environment, checkout, monkeypatch):
    env = command_environment
    assert launcher.execute('admit', env) == launcher.execute('verify', env) == 0
    original = (checkout[2] / 'driver.py').read_bytes()
    (checkout[2] / 'driver.py').write_text('changed')
    assert launcher.execute('prebuild', env) == 1
    (checkout[2] / 'driver.py').write_bytes(original)
    invoked = []
    monkeypatch.setattr(launcher, 'frozen_summary', lambda *args: invoked.append(args))
    assert launcher.execute('summary', env) == 0
    assert invoked == []


def test_always_summary_reverifies_current_bytes_before_payload_execution(launcher, command_environment, checkout, monkeypatch):
    env = command_environment
    assert launcher.execute('admit', env) == launcher.execute('verify', env) == 0
    invoked = []
    monkeypatch.setattr(launcher, 'frozen_summary', lambda *args: invoked.append(args))
    assert launcher.execute('summary', env) == 0
    assert len(invoked) == 1
    (checkout[2] / 'driver.py').write_text('changed')
    assert launcher.execute('summary', env) == 1
    assert len(invoked) == 1


def test_refusal_has_no_raw_exception_or_api_output(launcher, command_environment, monkeypatch, capsys):
    def bad(*args): raise RuntimeError('SECRET\nPIN=123 https://private.invalid')
    monkeypatch.setattr(launcher, 'admit', bad)
    assert launcher.execute('admit', command_environment) == 1
    assert launcher.execute('summary', command_environment) == 0
    assert not capsys.readouterr().out and not capsys.readouterr().err
    text = Path(command_environment['GITHUB_STEP_SUMMARY']).read_text()
    assert 'SECRET' not in text and 'private.invalid' not in text and 'PIN' not in text


def test_initial_or_prebuild_missing_state_never_proceeds(launcher, command_environment):
    assert launcher.execute('verify', command_environment) == 1
    assert launcher.execute('prebuild', command_environment) == 1


def test_installed_package_cannot_resolve_into_either_checkout(launcher, checkout, tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace
    for root in checkout[1:]:
        monkeypatch.setitem(sys.modules, 'p11lab', SimpleNamespace(__file__=str(root / 'src/p11lab/__init__.py')))
        with pytest.raises(launcher.Refusal): launcher.verify_installed(*checkout[1:])
    monkeypatch.setitem(sys.modules, 'p11lab', SimpleNamespace(__file__=str(tmp_path / 'venv/lib/p11lab/__init__.py')))
    assert launcher.verify_installed(*checkout[1:]) is None


def test_workflow_is_manual_main_only_and_single_inclusive_runtime():
    path = ROOT / '.github/workflows/haskoki-release-validation.yml'
    assert path.is_file(), 'manual launcher workflow is missing'
    text = path.read_text()
    assert '\non:\n  workflow_dispatch:\n' in text
    assert all(x not in text for x in ('pull_request:', 'push:', 'schedule:', 'workflow_call:', 'workflow_run:', 'repository_dispatch:', 'matrix:', 'continue-on-error:', 'cancel-in-progress: true', 'upload-artifact', 'cache-to', 'secrets.'))
    assert '\n  runtime:\n' in text and text.count('runs-on:') == 1
    assert "if: github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'" in text
    assert 'runs-on: ubuntu-24.04' in text and 'timeout-minutes: 240' in text
    assert 'contents: read' in text and 'packages: none' in text
    assert 'group: haskoki-release-validation-frozen-opportunity' in text
    assert text.count('persist-credentials: false') == 2
    assert 'ref: ${{ github.workflow_sha }}' in text
    assert 'ref: fca1b148f074bc0f3fd527bc02fe7920f33fa4cd' in text
    assert 'default:' not in text
    assert 'reviewed_controller_sha:' in text and 'required: true' in text


def test_workflow_admits_before_payload_init_and_renews_immediately_before_single_build():
    path = ROOT / '.github/workflows/haskoki-release-validation.yml'
    assert path.is_file(), 'manual launcher workflow is missing'
    text = path.read_text()
    positions = [text.index(token) for token in ('haskoki_launcher.py" admit', 'path: payload',
        'haskoki_launcher.py" verify', 'haskoki_validation.py" init', "python-version: '3.12.14'",
        '-m pip wheel', 'haskoki_validation.py" preflight', 'haskoki_launcher.py" prebuild',
        'haskoki_validation.py" build', 'haskoki_validation.py" tests', 'haskoki_launcher.py" summary')]
    assert positions == sorted(positions)
    assert text.count('haskoki_validation.py" build') == 1
    assert '--repository "$PAYLOAD_ROOT"' in text
    assert '-r "$PAYLOAD_ROOT/.github/requirements/haskoki-validation.txt"' in text
    assert '--wheel-dir "$RUNNER_TEMP/haskoki-wheels" "$PAYLOAD_ROOT"' in text
    assert 'if: always()' in text
    assert 'timeout-minutes: 220' in text and 'timeout-minutes: 16' in text
    assert '${{ inputs.' not in text[text.index('steps:'):]
    assert 'GITHUB_EVENT_NAME:' not in text and 'GITHUB_RUN_ATTEMPT:' not in text
    assert text.count('uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262') == 2
    assert 'uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065' in text


def test_whole_admission_deadline_includes_validation_not_only_gets(launcher, monkeypatch):
    import time
    original = launcher.identity
    def slow(record): time.sleep(.2); return original(record)
    monkeypatch.setattr(launcher, 'identity', slow)
    monkeypatch.setattr(launcher, 'ADMISSION_SECONDS', .03)
    start = time.monotonic()
    with pytest.raises(launcher.Refusal): admit(launcher)
    assert time.monotonic() - start < .15


def test_safe_summary_handles_malformed_non_string_classification(launcher):
    assert 'Classification: refused' in launcher.safe_summary({'classification': ['secret']})


def test_documented_fully_qualified_main_dispatch_ref_is_accepted(launcher):
    ev = event(); ev['ref'] = 'refs/heads/main'
    assert admit(launcher, ev=ev) == admit(launcher)


@pytest.mark.parametrize('ref', ['refs/tags/main', None, SHA, ' main', 'main\n', 'refs/heads/main-evil', 'heads/main'])
def test_event_ref_allowset_is_not_a_prefix_or_tag_relaxation(launcher, ref):
    ev = event(); ev['ref'] = ref
    with pytest.raises(launcher.Refusal): admit(launcher, ev=ev)
