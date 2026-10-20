#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Fail-closed admission for one main-launched, frozen Haskoki opportunity.

Public observations are bounded, not atomic. This is not a global exactly-once
lock: historical refs, deletions, stale servers and post-check races remain an
operator/trusted-GitHub boundary. No payload selection or acceptance logic lives
here. Never print API data, input values or exception text.
"""
import hashlib
from contextlib import contextmanager
import json
import os
from pathlib import Path
import stat
import subprocess
import re
import signal
import time
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from datetime import datetime
from urllib.parse import parse_qsl, urlsplit

REPOSITORY = 'mingulov/p11lab'
REPOSITORY_ID = 1394988634
OWNER_ID = 1794540
WORKFLOW_ID = 390791808
WORKFLOW_PATH = '.github/workflows/haskoki-release-validation.yml'
WORKFLOW_NAME = 'haskoki-release-validation'
PAYLOAD_SHA = 'fca1b148f074bc0f3fd527bc02fe7920f33fa4cd'
PAYLOAD_TREE = '08f74d03f9d6acfa2a461c48aa9088b05c317693'
API = 'https://api.github.com'
ROUTE = '/repos/' + REPOSITORY
OLD = {
    1: (39461303417, '100d25a0119ee3612e993bda2ae8d9b5845abbe8', 'failure', 118761165005, 118761167755),
    2: (39463132399, PAYLOAD_SHA, 'success', 118767408221, 118767410829),
}


class Refusal(Exception):
    """A fixed-category refusal; never expose its cause or untrusted data."""


def require(condition):
    if not condition:
        raise Refusal()


def integer(value):
    require(type(value) is int and 0 < value < 2**63)
    return value


def sha(value):
    require(isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value) is not None)
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


def repository(value):
    require(integer(value['id']) == REPOSITORY_ID and value['full_name'] == REPOSITORY)
    require(integer(value['owner']['id']) == OWNER_ID)


def validate_context(env, event, checked_out):
    expected = {
        'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_REPOSITORY_ID': str(REPOSITORY_ID),
        'GITHUB_REPOSITORY_OWNER_ID': str(OWNER_ID), 'GITHUB_ACTOR_ID': str(OWNER_ID),
        'GITHUB_SERVER_URL': 'https://github.com', 'GITHUB_API_URL': API,
        'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
        'GITHUB_REF_TYPE': 'branch', 'GITHUB_RUN_NUMBER': '3', 'GITHUB_RUN_ATTEMPT': '1',
        'CONTROLLER_WORKFLOW_REF': REPOSITORY + '/' + WORKFLOW_PATH + '@refs/heads/main',
    }
    require(all(env.get(key) == value for key, value in expected.items()))
    controller = sha(env['REVIEWED_CONTROLLER_SHA'])
    require(controller == sha(checked_out) == env['GITHUB_SHA'] == env['CONTROLLER_SHA'])
    require(re.fullmatch('[1-9][0-9]{0,18}', env['GITHUB_RUN_ID']) is not None)
    run_id = integer(int(env['GITHUB_RUN_ID']))
    repository(event['repository'])
    require(event['ref'] in ('main', 'refs/heads/main') and event['inputs'] == {'reviewed_controller_sha': controller})
    if 'sender' in event:
        require(integer(event['sender']['id']) == OWNER_ID)
    return controller, run_id


def identity(record):
    """Validate basic run shape and retain only immutable comparison fields."""
    for key in ('id', 'workflow_id', 'run_number', 'run_attempt'):
        integer(record[key])
    for key in ('name', 'path', 'event', 'head_branch'):
        require(isinstance(record[key], str) and bool(record[key]))
    sha(record['head_sha'])
    created = record['created_at']
    require(isinstance(created, str) and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', created))
    datetime.strptime(created, '%Y-%m-%dT%H:%M:%SZ')
    for key in ('repository', 'head_repository'):
        value = record[key]
        integer(value['id']); integer(value['owner']['id'])
        require(isinstance(value['full_name'], str) and bool(value['full_name']))
    for key in ('actor', 'triggering_actor'):
        integer(record[key]['id'])
    require(isinstance(record['pull_requests'], list))
    result = {key: record[key] for key in (
        'id', 'workflow_id', 'path', 'name', 'run_number', 'run_attempt', 'event',
        'head_sha', 'head_branch', 'created_at')}
    # Historical PR heads and profile/repository descriptions remain mutable.
    # They are not identities of this already-created workflow execution.
    for key in ('repository', 'head_repository'):
        result[key] = {'id': record[key]['id'], 'full_name': record[key]['full_name'],
                       'owner_id': record[key]['owner']['id']}
    for key in ('actor', 'triggering_actor'):
        result[key] = record[key]['id']
    return result


def relevant(record):
    match = (record['workflow_id'] == WORKFLOW_ID, record['path'] == WORKFLOW_PATH,
             record['name'] == WORKFLOW_NAME)
    require(not any(match) or all(match))
    return all(match)


def validate_haskoki(record, controller, run_id):
    immutable = identity(record)
    require(relevant(record))
    repository(record['repository']); repository(record['head_repository'])
    require(record['actor']['id'] == record['triggering_actor']['id'] == OWNER_ID)
    require(record['run_attempt'] == 1)
    number = record['run_number']
    if number == 3:
        require(record['id'] == run_id and record['head_sha'] == controller)
        require(record['event'] == 'workflow_dispatch' and record['head_branch'] == 'main')
        require(record['pull_requests'] == [])
        require(record['status'] == 'in_progress' and record['conclusion'] is None)
    else:
        require(number in OLD)
        expected = OLD[number]
        require((record['id'], record['head_sha'], record['conclusion']) == expected[:3])
        require(record['event'] == 'pull_request' and record['status'] == 'completed')
    return immutable | {'status': record['status'], 'conclusion': record['conclusion']}


def pagination(link, route, page, total, *, jobs=False):
    terminal = (total + 99) // 100
    relations = {}
    if link:
        for entry in link.split(','):
            match = re.fullmatch(r'\s*<([^<>]+)>;\s*rel="(next|prev|first|last)"\s*', entry)
            require(match is not None and match[2] not in relations)
            url = urlsplit(match[1])
            require(url.scheme == 'https' and url.netloc == 'api.github.com')
            require(url.path == route and not url.fragment)
            pairs = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True)
            query = dict(pairs)
            require(len(pairs) == len(query) and set(query) == ({'filter', 'per_page', 'page'} if jobs else {'per_page', 'page'}))
            require(query['per_page'] == '100' and (not jobs or query['filter'] == 'all'))
            expected = {'next': page + 1, 'prev': page - 1, 'first': 1, 'last': terminal}[match[2]]
            require(1 <= expected <= terminal and query['page'] == str(expected))
            relations[match[2]] = expected
    require(('next' in relations) == (page < terminal))


def historical_jobs(read, number):
    rid, _, conclusion, static_id, runtime_id = OLD[number]
    route = f'{ROUTE}/actions/runs/{rid}/jobs'
    data, link = read(route + '?filter=all&per_page=100&page=1')
    require(integer(data['total_count']) == 2 and len(data['jobs']) == 2)
    pagination(link, route, 1, 2, jobs=True)
    result = []
    for job in data['jobs']:
        require(integer(job['id']) in (static_id, runtime_id))
        require(integer(job['run_id']) == rid and integer(job['run_attempt']) == 1)
        require(job['status'] == 'completed' and isinstance(job['steps'], list))
        if job['id'] == static_id:
            require(job['name'] == 'static' and job['conclusion'] == conclusion)
        else:
            require(job['name'] == 'runtime' and job['conclusion'] == 'skipped' and job['steps'] == [])
        result.append({key: job[key] for key in ('id', 'run_id', 'run_attempt', 'name', 'status', 'conclusion', 'steps')})
    require({job['id'] for job in result} == {static_id, runtime_id})
    return sorted(result, key=lambda job: job['id'])


def _admit(env, event, checked_out, read):
    """Return the relevant-history digest, never raw API/event data."""
    try:
        controller, run_id = validate_context(env, event, checked_out)
        metadata, _ = read(ROUTE)
        repository(metadata)
        require(metadata['default_branch'] == 'main')
        main, _ = read(ROUTE + '/git/ref/heads/main')
        require(main['ref'] == 'refs/heads/main' and main['object']['type'] == 'commit')
        require(main['object']['sha'] == controller)
        current_route = f'{ROUTE}/actions/runs/{run_id}'
        current, _ = read(current_route)
        current_identity = validate_haskoki(current, controller, run_id)
        require(current['run_number'] == 3)
        records, first = [], None
        route = ROUTE + '/actions/runs'
        for page in range(1, 6):
            data, link = read(route + f'?per_page=100&page={page}')
            total = integer(data['total_count'])
            require(total <= 500)
            require(isinstance(data['workflow_runs'], list))
            if first is None:
                first = data
            require(total == first['total_count'])
            require(len(data['workflow_runs']) == min(100, total - (page - 1) * 100))
            pagination(link, route, page, total)
            records.extend(data['workflow_runs'])
            if page * 100 >= total:
                break
        require(len(records) == total)
        signatures = [identity(record) for record in records]
        require(len({record['id'] for record in records}) == total)
        require(all(a['created_at'] >= b['created_at'] for a, b in zip(records, records[1:])))
        selected = [validate_haskoki(r, controller, run_id) for r in records if relevant(r)]
        require(len(selected) == 3 and {r['run_number'] for r in selected} == {1, 2, 3})
        require(next(r for r in selected if r['run_number'] == 3) == current_identity)
        repeated, link = read(route + '?per_page=100&page=1')
        require(type(repeated['total_count']) is int and repeated['total_count'] == total)
        pagination(link, route, 1, total)
        require([identity(r) for r in repeated['workflow_runs']] == signatures[:100])
        require([validate_haskoki(r, controller, run_id) for r in repeated['workflow_runs'] if relevant(r)] ==
                [r for r in selected if r['id'] in {x['id'] for x in records[:100]}])
        old_jobs = [historical_jobs(read, number) for number in (1, 2)]
        final, _ = read(current_route)
        require(validate_haskoki(final, controller, run_id) == current_identity)
        return digest([sorted(selected, key=lambda r: r['run_number']), old_jobs])
    except Exception:
        raise Refusal() from None


REQUEST_SECONDS = 10
ADMISSION_SECONDS = 60
BODY_LIMIT = 4 * 1024 * 1024
TOTAL_LIMIT = 24 * 1024 * 1024


@contextmanager
def alarm(seconds):
    """Nested real-time watchdogs never extend an enclosing deadline."""
    previous = signal.getsignal(signal.SIGALRM)
    timer = signal.getitimer(signal.ITIMER_REAL)
    require(timer[1] == 0)
    started = time.monotonic()
    signal.signal(signal.SIGALRM, lambda *_: invalid_constant(None))
    signal.setitimer(signal.ITIMER_REAL, min(seconds, timer[0]) if timer[0] else seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if timer[0]:
            signal.setitimer(signal.ITIMER_REAL, max(.000001, timer[0] - (time.monotonic() - started)))


def admit(env, event, checked_out, read):
    # This also covers validation, comparisons and digest work between GETs.
    with alarm(ADMISSION_SECONDS):
        return _admit(env, event, checked_out, read)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def invalid_constant(value):
    raise Refusal()


class PublicReads:
    """Only this launcher's eight-to-twelve public GETs, without retries."""
    def __init__(self, open_request=None, clock=time.monotonic):
        self.open_request = open_request or build_opener(ProxyHandler({}), NoRedirect()).open
        self.clock = clock
        self.deadline = clock() + ADMISSION_SECONDS
        self.requests = self.bytes = 0

    def __call__(self, route):
        try:
            allowed = (route in (ROUTE, ROUTE + '/git/ref/heads/main') or
                       re.fullmatch(re.escape(ROUTE) + r'/actions/runs/[1-9][0-9]{0,18}', route) or
                       re.fullmatch(re.escape(ROUTE) + r'/actions/runs\?per_page=100&page=[1-5]', route) or
                       route in [f'{ROUTE}/actions/runs/{row[0]}/jobs?filter=all&per_page=100&page=1' for row in OLD.values()])
            require(allowed and self.requests < 12)
            remaining = self.deadline - self.clock()
            require(remaining > 0)
            seconds = min(REQUEST_SECONDS, remaining)
            self.requests += 1
            # A socket timeout alone does not bound a trickling response. On the
            # sole Ubuntu job, SIGALRM also bounds DNS/open/read/JSON processing.
            with alarm(seconds):
                url = API + route
                request = Request(url, method='GET', headers={
                    'Accept': 'application/vnd.github+json',
                    'Accept-Encoding': 'identity', 'X-GitHub-Api-Version': '2022-11-28',
                    'User-Agent': 'p11lab-frozen-haskoki-admission',
                })
                with self.open_request(request, timeout=seconds) as response:
                    require(response.status == 200 and response.geturl() == url)
                    headers = response.headers
                    for key in ('Content-Type', 'Content-Length', 'Content-Encoding', 'Transfer-Encoding', 'Link'):
                        values = headers.get_all(key, []) if hasattr(headers, 'get_all') else ([headers[key]] if key in headers else [])
                        require(len(values) <= 1)
                    transfer = headers.get('Transfer-Encoding')
                    require(transfer in (None, 'chunked'))
                    require(not (transfer is not None and headers.get('Content-Length') is not None))
                    require(headers.get('Content-Type', '').split(';')[0].strip() in
                            ('application/json', 'application/vnd.github+json'))
                    require(headers.get('Content-Encoding', 'identity') == 'identity')
                    length = headers.get('Content-Length')
                    if length is not None:
                        require(re.fullmatch('[0-9]+', length) and int(length) <= BODY_LIMIT)
                    body = response.read(BODY_LIMIT + 1)
                    require(len(body) <= BODY_LIMIT and (length is None or len(body) == int(length)))
                    self.bytes += len(body)
                    require(self.bytes <= TOTAL_LIMIT)
                    data = json.loads(body.decode('utf-8'), object_pairs_hook=unique_object,
                                      parse_constant=invalid_constant)
                    require(isinstance(data, dict) and self.clock() < self.deadline)
                    return data, headers.get('Link', '')
        except Exception:
            raise Refusal() from None


FILE_COUNTS = {'100644': 433, '100755': 8}


def git(root, *args):
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env['GIT_NO_REPLACE_OBJECTS'] = '1'
    return subprocess.run(['git', '--no-optional-locks', '-c', 'core.fsmonitor=false',
                           '-C', str(root), *args], env=env, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20).stdout


def no_symlinks(path):
    require(path.is_absolute() and path == path.resolve())
    for part in (path, *path.parents):
        if part.exists() or part.is_symlink():
            require(not stat.S_ISLNK(part.lstat().st_mode))


def outside_checkouts(path, controller, payload):
    no_symlinks(path)
    require(not path.is_relative_to(controller) and not path.is_relative_to(payload))
    require(not controller.is_relative_to(path) and not payload.is_relative_to(path))


def manifest(raw):
    try:
        require(raw.endswith(b'\0'))
        result, counts = {}, dict.fromkeys(FILE_COUNTS, 0)
        for entry in raw[:-1].split(b'\0'):
            header, raw_path = entry.split(b'\t', 1)
            mode, kind, oid = header.decode('ascii').split(' ')
            require(mode in FILE_COUNTS and kind == 'blob')
            sha(oid)
            path = raw_path.decode('utf-8')
            require(path and all(part not in ('', '.', '..', '.git') for part in path.split('/')))
            require(path not in result)
            result[path] = (mode, oid)
            counts[mode] += 1
        require(counts == FILE_COUNTS)
        return result
    except Exception:
        raise Refusal() from None


def stat_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def hash_file(path, mode, oid):
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
    require(stat.S_IMODE(before.st_mode) == int(mode[-3:], 8))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        require(stat_identity(before) == stat_identity(os.fstat(fd)))
        hashed = hashlib.sha1(b'blob ' + str(before.st_size).encode('ascii') + b'\0')
        remaining = before.st_size
        while remaining:
            value = os.read(fd, min(1024 * 1024, remaining))
            require(bool(value))
            hashed.update(value)
            remaining -= len(value)
        require(os.read(fd, 1) == b'')
        require(stat_identity(before) == stat_identity(os.fstat(fd)) == stat_identity(path.lstat()))
        require(hashed.hexdigest() == oid)
    finally:
        os.close(fd)


def enumerate_payload(root):
    entries = {}
    def visit(directory):
        for entry in os.scandir(directory):
            relative = Path(entry.path).relative_to(root).as_posix()
            info = entry.stat(follow_symlinks=False)
            if relative == '.git':
                require(stat.S_ISDIR(info.st_mode))
                continue
            require(stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
            entries[relative] = stat_identity(info)
            if stat.S_ISDIR(info.st_mode):
                visit(entry.path)
    visit(root)
    return entries


def verify_payload(workspace, controller, payload):
    try:
        for path in (workspace, controller, payload):
            no_symlinks(path)
            require(path.is_dir())
        require(controller == workspace / 'controller' and payload == workspace / 'payload')
        require((payload / '.git').is_dir() and not (payload / '.git').is_symlink())
        require(git(payload, 'rev-parse', 'HEAD').decode().strip() == PAYLOAD_SHA)
        require(git(payload, 'rev-parse', 'HEAD^{tree}').decode().strip() == PAYLOAD_TREE)
        expected = manifest(git(payload, 'ls-tree', '-r', '-z', '--full-tree', PAYLOAD_TREE))
        directories = {str(parent) for path in expected for parent in Path(path).parents if str(parent) != '.'}
        before = enumerate_payload(payload)
        require(set(before) == set(expected) | directories)
        require(all(stat.S_ISDIR(before[path][2]) for path in directories))
        for path, (mode, oid) in expected.items():
            hash_file(payload / path, mode, oid)
        require(enumerate_payload(payload) == before)
    except Exception:
        raise Refusal() from None


CLASSIFICATIONS = {'initial_admitted', 'payload_verified', 'prebuild_admitted',
                   'refused', 'integrity_refused'}


def safe_record(env, classification):
    controller = env.get('CONTROLLER_SHA', '')
    if not re.fullmatch('[0-9a-f]{40}', controller):
        controller = 'unavailable'
    run_id = env.get('GITHUB_RUN_ID', '')
    run_id = int(run_id) if re.fullmatch('[1-9][0-9]{0,18}', run_id) else 0
    return {'event': 'workflow_dispatch', 'ref': 'refs/heads/main',
            'controller_sha': controller, 'payload_sha': PAYLOAD_SHA, 'payload_tree': PAYLOAD_TREE,
            'workflow_id': WORKFLOW_ID, 'run_id': run_id, 'run_number': 3, 'run_attempt': 1,
            'classification': classification if classification in CLASSIFICATIONS else 'refused',
            'payload_verified': False}


def safe_summary(record):
    controller = record.get('controller_sha', '')
    if not isinstance(controller, str) or not re.fullmatch('[0-9a-f]{40}', controller):
        controller = 'unavailable'
    classification = record.get('classification')
    if not isinstance(classification, str) or classification not in CLASSIFICATIONS:
        classification = 'refused'
    run_id = record.get('run_id')
    run_id = str(run_id) if type(run_id) is int and 0 < run_id < 2**63 else 'unavailable'
    return ('## Haskoki controller\n'
            'Scope: frozen candidate evidence launched from main; not main runtime qualification.\n'
            'Admission is not acceptance success. Missing or interrupted evidence is not a pass.\n'
            f'- Controller: {controller}\n- Payload: {PAYLOAD_SHA}\n- Payload tree: {PAYLOAD_TREE}\n'
            f'- Reserved workflow / run number / attempt: {WORKFLOW_ID} / 3 / 1\n'
            f'- Run ID: {run_id}\n- Classification: {classification}\n')


def write_record(path, record):
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as output:
        os.fchmod(output.fileno(), 0o600)
        output.write(json.dumps(record, sort_keys=True) + '\n')
    temporary.replace(path)


def verify_installed(controller, payload):
    import p11lab
    outside_checkouts(Path(p11lab.__file__), controller, payload)


def frozen_summary(payload, root, env):
    # Only called after a fresh whole-payload proof. No raw output reaches logs.
    import sys
    subprocess.run([sys.executable, '-I', '-B', str(payload / '.github/scripts/haskoki_validation.py'),
                    'summary', '--root', str(root)], cwd=root.parent, env=env,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=30)


def execute(operation, env):
    """Fixed workflow operations; no inputs can choose payloads or commands."""
    record = safe_record(env, 'refused')
    state_path = None
    try:
        require(operation in ('admit', 'verify', 'prebuild', 'summary'))
        workspace = Path(env['GITHUB_WORKSPACE'])
        controller, payload = workspace / 'controller', workspace / 'payload'
        temporary = Path(env['RUNNER_TEMP'])
        no_symlinks(workspace); no_symlinks(controller)
        for path in (temporary, temporary / 'haskoki-validation', temporary / 'haskoki-venv',
                     temporary / 'haskoki-wheels'):
            outside_checkouts(path, controller, payload)
        state_path = temporary / 'haskoki-controller.json'
        previous = {}
        if state_path.exists():
            raw = state_path.read_bytes()
            require(len(raw) <= 8192)
            previous = json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
            require(isinstance(previous, dict))
        identities = set(record) - {'classification', 'payload_verified'}
        same_run = all(previous.get(key) == record[key] for key in identities)
        if operation == 'admit':
            require(not previous)
            event_bytes = Path(env['GITHUB_EVENT_PATH']).read_bytes()
            require(len(event_bytes) <= BODY_LIMIT)
            event = json.loads(event_bytes, object_pairs_hook=unique_object, parse_constant=invalid_constant)
            checked_out = git(controller, 'rev-parse', 'HEAD').decode().strip()
            history = admit(env, event, checked_out, PublicReads())
            record.update(classification='initial_admitted', history_digest=history)
        elif operation in ('verify', 'prebuild'):
            require(same_run and previous.get('classification') in
                    ('initial_admitted', 'payload_verified', 'prebuild_admitted'))
            record.update(history_digest=previous.get('history_digest'))
            # Invalidate earlier proof before verification, including on exceptions.
            record['classification'] = 'integrity_refused'
            verify_payload(workspace, controller, payload)
            record.update(classification='refused', payload_verified=True)
            if operation == 'prebuild':
                require(previous.get('classification') == 'payload_verified')
                verify_installed(controller, payload)
                event_bytes = Path(env['GITHUB_EVENT_PATH']).read_bytes()
                require(len(event_bytes) <= BODY_LIMIT)
                event = json.loads(event_bytes, object_pairs_hook=unique_object, parse_constant=invalid_constant)
                checked_out = git(controller, 'rev-parse', 'HEAD').decode().strip()
                require(admit(env, event, checked_out, PublicReads()) == previous.get('history_digest'))
                record['classification'] = 'prebuild_admitted'
            else:
                require(previous.get('classification') == 'initial_admitted')
                record['classification'] = 'payload_verified'
        else:
            if same_run:
                record = {key: previous[key] for key in record if key in previous}
            if (same_run and previous.get('payload_verified') is True and
                    previous.get('classification') in CLASSIFICATIONS - {'integrity_refused'}):
                record.update(classification='integrity_refused', payload_verified=False)
                verify_payload(workspace, controller, payload)
                record.update(classification=previous['classification'], payload_verified=True)
                frozen_summary(payload, temporary / 'haskoki-validation', env)
            with Path(env['GITHUB_STEP_SUMMARY']).open('a') as output:
                output.write(safe_summary(record))
            return 0
        write_record(state_path, record)
        return 0
    except Exception:
        # Only fixed categories and validated identities are durable or visible.
        if record['classification'] != 'integrity_refused':
            record['classification'] = 'refused'
        if state_path is not None:
            try:
                write_record(state_path, record)
                if operation == 'summary':
                    with Path(env['GITHUB_STEP_SUMMARY']).open('a') as output:
                        output.write(safe_summary(record))
            except Exception:
                pass
        return 1


if __name__ == '__main__':
    import sys
    raise SystemExit(execute(sys.argv[1] if len(sys.argv) == 2 else '', os.environ))
