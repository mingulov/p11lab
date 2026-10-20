"""Installed fixed-roster tool input authority; acquisition is not admission."""
import hashlib
import json
from pathlib import PurePosixPath
import re
from urllib.parse import urlsplit

from .catalog import package_data


class ToolInputError(ValueError):
    """Tool input selection, provenance or retained bytes failed verification."""


_LIMITS = {'file_bytes': 256 * 1024**2, 'total_bytes': 512 * 1024**2,
           'io_seconds': 60, 'payload_seconds': 900, 'attempt_seconds': 3600, 'redirects': 5}
_SHA = re.compile(r'[0-9a-f]{64}\Z')
_IDENTITY = {'name', 'version', 'architecture', 'source_package', 'source_version'}
_PACKAGE = _IDENTITY | {'filename', 'sha256', 'size', 'url', 'index', 'stanza_sha256',
                        'relations', 'license_status', 'copyright_path', 'path'}
_RELATIONS = {'Pre-Depends', 'Depends', 'Provides', 'Breaks', 'Conflicts', 'Replaces',
              'Multi-Arch', 'Built-Using', 'Static-Built-Using', 'Recommends', 'Suggests', 'Essential', 'Protected'}


def _require(ok, message):
    if not ok:
        raise ToolInputError(message)


def _keys(value, keys):
    _require(isinstance(value, dict) and value.keys() == keys, 'unexpected or missing tool-input fields')


def _json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            _require(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda value: (_ for _ in ()).throw(ToolInputError('nonfinite JSON')))
    except (ValueError, UnicodeError) as error:
        raise ToolInputError('invalid tool-input JSON: ' + str(error)) from error


def _digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _path(value):
    _require(isinstance(value, str) and bool(value) and '\\' not in value and ':' not in value
             and not PurePosixPath(value).is_absolute()
             and all(p not in {'', '.', '..'} for p in value.split('/'))
             and all(32 < ord(c) < 127 for c in value), 'unsafe tool input path')
    return value


def _sha(value):
    _require(isinstance(value, str) and _SHA.fullmatch(value), 'invalid tool input checksum')


def _url(value):
    _require(isinstance(value, str), 'invalid tool input URL')
    parsed = urlsplit(value)
    _require(parsed.scheme == 'https' and parsed.netloc == 'snapshot.debian.org'
             and parsed.path.startswith('/archive/') and not parsed.query and not parsed.fragment
             and not any(c.isspace() or ord(c) < 32 for c in value), 'unapproved tool input URL')


def _file(record):
    _path(record['path'])
    _sha(record['sha256'])
    _require(type(record['size']) is int and 0 < record['size'] <= _LIMITS['file_bytes'], 'invalid tool input size')
    if 'url' in record:
        _url(record['url'])


def _unique(records, key):
    _require(isinstance(records, list) and bool(records), 'missing tool input roster')
    values = [p[key] for p in records]
    _require(all(isinstance(x, str) and x for x in values) and len(values) == len(set(values)),
             'duplicate or invalid tool input ' + key)


def _records(lock):
    """Portable handles are derived from the installed authority, never a receipt."""
    result = []
    for p in lock['packages']:
        result.append({k: p[k] for k in ('path', 'url', 'sha256', 'size')} |
                      {'kind': 'binary', 'id': p['name'] + '=' + p['version'],
                       'source': p['source_package'] + '=' + p['source_version'], 'license_status': 'unreviewed'})
    for source in lock['sources']:
        for p in source['files']:
            result.append({k: p[k] for k in ('path', 'url', 'sha256', 'size')} |
                          {'kind': 'source', 'id': p['filename'],
                           'source': source['name'] + '=' + source['version'], 'license_status': 'unreviewed'})
    for p in lock['metadata']:
        result.append({k: p[k] for k in ('path', 'url', 'sha256', 'size')} |
                      {'kind': 'metadata', 'id': p['filename']})
    for p in lock['resources']:
        result.append(dict(p) | {'kind': 'resource', 'id': p['asset']})
    return result



def _text(value, *, limit=16384):
    _require(isinstance(value, str) and 0 < len(value) <= limit, 'invalid provenance text')


def _metadata_chain(lock, provenance):
    metadata = provenance['metadata']
    _keys(metadata, {'trixie', 'trixie-updates', 'trixie-security', 'verifier'})
    verifier = metadata['verifier']
    _keys(verifier, {'command', 'version', 'keyring_sha256', 'keyring_size', 'trust_basis', 'verification_utc'})
    _sha(verifier['keyring_sha256'])
    _require(type(verifier['keyring_size']) is int and 0 < verifier['keyring_size'] < 1024**2, 'invalid keyring size')
    for field in ('command', 'version', 'trust_basis', 'verification_utc'):
        _text(verifier[field])
    expected = []
    for suite in ('trixie', 'trixie-updates', 'trixie-security'):
        entry = metadata[suite]
        _keys(entry, {'url', 'filename', 'sha256', 'size', 'signatures', 'indexes'})
        archive = 'debian-security' if suite == 'trixie-security' else 'debian'
        prefix = f'https://snapshot.debian.org/archive/{archive}/{lock["apt_snapshot"]}/dists/{suite}/'
        _require(entry['url'] == prefix + 'InRelease' and entry['filename'] == suite + '.InRelease', 'invalid signed metadata origin')
        _require(isinstance(entry['signatures'], list) and 1 <= len(entry['signatures']) <= 8, 'missing signature provenance')
        for signature in entry['signatures']:
            _require(isinstance(signature, list) and len(signature) == 10
                     and all(isinstance(x, str) for x in signature)
                     and all(re.fullmatch(r'[A-F0-9]{40}', signature[i]) for i in (0, 9))
                     and re.fullmatch(r'\d{4}-\d{2}-\d{2}', signature[1])
                     and all(re.fullmatch(r'\d{1,12}', signature[i]) for i in range(2, 9)), 'invalid signature provenance')
        _require(isinstance(entry['indexes'], list) and len(entry['indexes']) == 2, 'incomplete published index roster')
        seen = set()
        for index in entry['indexes']:
            _keys(index, {'url', 'filename', 'sha256', 'size', 'uncompressed'})
            name = index['filename']
            _require(name in {suite + '.Packages.xz', suite + '.Sources.xz'} and name not in seen, 'duplicate/unknown index selector')
            seen.add(name)
            suffix = 'main/binary-amd64/Packages.xz' if name.endswith('.Packages.xz') else 'main/source/Sources.xz'
            _require(index['url'] == prefix + suffix, 'invalid published index origin')
            _keys(index['uncompressed'], {'sha256', 'size'})
            _sha(index['uncompressed']['sha256'])
            _require(type(index['uncompressed']['size']) is int and 0 < index['uncompressed']['size'] <= _LIMITS['file_bytes'], 'invalid expanded index size')
        for record in [entry] + entry['indexes']:
            selected = {k: record[k] for k in ('url', 'filename', 'sha256', 'size')}
            selected['path'] = 'metadata/' + record['filename']
            _file(selected)
            expected.append(selected)
    _require(lock['metadata'] == expected, 'metadata acquisition/selector chain mismatch')


def _selector(record, snapshot, suffix):
    _require(isinstance(record['index'], str) and record['index'] in
             {suite + '.' + suffix for suite in ('trixie', 'trixie-updates', 'trixie-security')}, 'unknown signed index selector')
    archive = 'debian-security' if record['index'].startswith('trixie-security.') else 'debian'
    prefix = f'https://snapshot.debian.org/archive/{archive}/{snapshot}/'
    return prefix


def _package_record(record, snapshot):
    for key in _IDENTITY:
        _text(record[key], limit=256)
    for key in ('name', 'source_package'):
        _require(re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', record[key]), 'invalid package name')
    for key in ('version', 'source_version'):
        _require(re.fullmatch(r'[0-9][A-Za-z0-9.+:~\-]*', record[key]), 'invalid package version')
    _require(record['architecture'] in {'amd64', 'all'}, 'unsupported package architecture')
    _sha(record['stanza_sha256'])
    prefix = _selector(record, snapshot, 'Packages')
    _path(record['filename'])
    _require(record['filename'].endswith('.deb') and record['url'] == prefix + record['filename'], 'package origin/index mismatch')
    _file(record | {'path': record.get('path', record['filename'])})
    _require(isinstance(record['relations'], dict) and record['relations'].keys() <= _RELATIONS, 'invalid relation fields')
    for value in record['relations'].values():
        _text(value)
    _require(record['license_status'] == 'unreviewed'
             and record['copyright_path'] == '/usr/share/doc/' + record['name'] + '/copyright', 'invalid copyright binding')

def _validate(lock, provenance):
    _keys(lock, {'schema_version', 'toolset', 'target', 'platform', 'apt_snapshot', 'base_image',
                 'parent_packages', 'stages', 'packages', 'sources', 'metadata', 'resources',
                 'provenance', 'limits', 'license_status'})
    _require(type(lock['schema_version']) is int and lock['schema_version'] == 1, 'unsupported tool input schema')
    _require((lock['toolset'], lock['target'], lock['platform']) == ('consumer', 'debian13-amd64', 'linux/amd64'),
             'unsupported tool input selection')
    _require(lock['apt_snapshot'] == '20260918T000000Z' and lock['license_status'] == 'unreviewed', 'invalid snapshot/admission')
    _require(isinstance(lock['base_image'], str) and re.fullmatch(r'docker.io/library/debian@sha256:[0-9a-f]{64}', lock['base_image']), 'invalid base pin')
    _require(lock['limits'] == _LIMITS and all(type(v) is int for v in lock['limits'].values()), 'invalid acquisition limits')
    _keys(provenance, {'schema_version', 'lock_binding_sha256', 'metadata', 'parent_package_evidence',
                       'relations', 'conflicts', 'source_bindings', 'parent_incorporated_source_ids', 'status', 'limitations'})
    _require(type(provenance['schema_version']) is int and provenance['schema_version'] == 1 and provenance['status'] == 'authenticated-metadata-only', 'invalid provenance status')
    _require(_digest(_canonical({k: v for k, v in lock.items() if k != 'provenance'})) == provenance['lock_binding_sha256'],
             'curated provenance binding mismatch')
    _metadata_chain(lock, provenance)
    _text(provenance['limitations'], limit=4096)
    for key in ('parent_packages', 'packages'):
        _unique(lock[key], 'name')
        for p in lock[key]:
            _keys(p, _IDENTITY if key == 'parent_packages' else _PACKAGE)
            _require(all(isinstance(p[k], str) and p[k] for k in _IDENTITY)
                     and p['architecture'] in {'amd64', 'all'}, 'invalid package identity/architecture')
            if key == 'packages':
                _package_record(p, lock['apt_snapshot'])
                _file(p)
                _sha(p['stanza_sha256'])
                _require(isinstance(p['relations'], dict) and p['relations'].keys() <= _RELATIONS
                         and all(isinstance(v, str) and v for v in p['relations'].values()), 'invalid package relations')
                _require(p['license_status'] == 'unreviewed' and p['copyright_path'] == '/usr/share/doc/' + p['name'] + '/copyright', 'invalid copyright binding')
    parent = {p['name']: p for p in lock['parent_packages']}
    added = {p['name']: p for p in lock['packages']}
    _require(not parent.keys() & added.keys(), 'parent replacement is not supported')
    all_packages = parent | added
    _unique(provenance['parent_package_evidence'], 'name')
    parent_evidence = {}
    for record in provenance['parent_package_evidence']:
        _keys(record, _PACKAGE - {'path'})
        _package_record(record, lock['apt_snapshot'])
        parent_evidence[record['name']] = record
    _require([{k: p[k] for k in _IDENTITY} for p in provenance['parent_package_evidence']] == lock['parent_packages'],
             'parent provenance inventory mismatch')
    relation_records = parent_evidence | added
    incorporated = set()
    for record in relation_records.values():
        for field in ('Built-Using', 'Static-Built-Using'):
            for term in filter(None, record['relations'].get(field, '').split(',')):
                match = re.fullmatch(r'([a-z0-9][a-z0-9+.-]*) \(= ([^ ()]+)\)', term.strip())
                _require(match is not None, 'unsupported incorporated-source identity')
                incorporated.add(match[1] + '=' + match[2])
    _require(isinstance(provenance['parent_incorporated_source_ids'], list)
             and all(isinstance(x, str) for x in provenance['parent_incorporated_source_ids'])
             and len(incorporated) == len(provenance['parent_incorporated_source_ids'])
             and incorporated == set(provenance['parent_incorporated_source_ids']), 'incorporated source roster mismatch')

    _keys(lock['stages'], {'compiler', 'consumer'})
    _keys(provenance['relations'], {'compiler', 'consumer'})
    _keys(provenance['conflicts'], {'compiler', 'consumer'})
    for name, stage in lock['stages'].items():
        _keys(stage, {'roots', 'packages'})
        _require(isinstance(stage['packages'], list) and all(isinstance(x, str) for x in stage['packages'])
                 and len(stage['packages']) == len(set(stage['packages']))
                 and parent.keys() <= set(stage['packages']) <= all_packages.keys(), 'invalid complete stage roster')
        _require(isinstance(stage['roots'], list) and stage['roots'] and all(
            isinstance(x, str) and any(x == p['name'] + '=' + p['version'] for p in all_packages.values()) for x in stage['roots']), 'invalid stage root')
        _require(provenance['conflicts'][name] == [], 'curated closure has conflicts')
        expected = {(n, field, group.strip()) for n in stage['packages']
                    for field in ('Depends', 'Pre-Depends')
                    for group in relation_records[n]['relations'].get(field, '').split(',') if group.strip()}
        seen = set()
        _require(isinstance(provenance['relations'][name], list), 'invalid dependency witnesses')
        for witness in provenance['relations'][name]:
            _keys(witness, {'package', 'field', 'group', 'selected_package', 'selected_version', 'selected_alternative', 'from_parent'})
            key = (witness['package'], witness['field'], witness['group'])
            _require(key in expected and key not in seen, 'missing/duplicate/unknown dependency witness')
            seen.add(key)
            alternatives = [part.strip() for part in witness['group'].split('|')]
            _require(witness['selected_alternative'] in alternatives, 'invalid selected alternative')
            selected = witness['selected_package']
            _require(witness['package'] in stage['packages'] and selected in stage['packages']
                     and witness['selected_version'] == all_packages[selected]['version']
                     and type(witness['from_parent']) is bool and witness['from_parent'] == (selected in parent), 'invalid fixed dependency witness')
            term = re.fullmatch(r'([a-z0-9][a-z0-9+.-]*)(?::(?:any|native|amd64))?(?: \((<<|<=|=|>=|>>) ([^ ()]+)\))?', witness['selected_alternative'])
            _require(term is not None, 'unsupported dependency syntax')
            if selected != term[1]:
                provides = relation_records[selected]['relations'].get('Provides', '').split(',')
                _require(any(re.fullmatch(re.escape(term[1]) + (r' \(= [^ ()]+\)' if term[2] else r'(?: \(= [^ ()]+\))?'), x.strip()) for x in provides),
                         'selected package does not provide required identity/version')
        _require(seen == expected, 'missing dependency witness')
    _require(provenance['source_bindings'] == [{k: s[k] for k in ('name', 'version', 'files', 'index', 'stanza_sha256')} for s in lock['sources']],
             'source provenance binding mismatch')
    _unique(lock['sources'], 'name')
    sources = set()
    for source in lock['sources']:
        _keys(source, {'name', 'version', 'index', 'stanza_sha256', 'license_status', 'files'})
        _text(source['name'], limit=256)
        _text(source['version'], limit=256)
        _sha(source['stanza_sha256'])
        prefix = _selector(source, lock['apt_snapshot'], 'Sources')

        _require(source['license_status'] == 'unreviewed', 'invalid source license status')
        sources.add(source['name'] + '=' + source['version'])
        _unique(source['files'], 'filename')
        _require(sum(p['filename'].endswith('.dsc') for p in source['files']) == 1, 'missing exact source descriptor')
        for p in source['files']:
            _keys(p, {'filename', 'url', 'sha256', 'size', 'path'})
            _path(p['filename'])
            _require('/' not in p['filename'] and p['url'].startswith(prefix + 'pool/')
                     and p['url'].endswith('/' + p['filename']), 'source origin/index mismatch')
            _file(p)
    _require(all(p['source_package'] + '=' + p['source_version'] in sources for p in added.values()), 'missing corresponding source')
    for key, keys in [('metadata', {'filename', 'url', 'sha256', 'size', 'path'}),
                      ('resources', {'asset', 'sha256', 'size', 'path'})]:
        _unique(lock[key], 'path')
        for p in lock[key]:
            _keys(p, keys)
            _file(p)
            if key == 'resources':
                _path(p['asset'])
                _require(p['asset'].startswith('consumer/'), 'invalid owned resource')
    records = _records(lock)
    _unique(records, 'path')
    _unique(records, 'id')
    paths = {p['path'] for p in records}
    _require(not any('/'.join(path.split('/')[:i]) in paths for path in paths for i in range(1, len(path.split('/')))), 'input file/directory collision')
    _require(sum(p['size'] for p in records) <= _LIMITS['total_bytes'], 'tool inputs exceed aggregate size bound')


def _load(toolset, target):
    _require((toolset, target) == ('consumer', 'debian13-amd64'), 'unsupported toolset/target; only consumer debian13-amd64 is implemented')
    raw = package_data('tool-inputs/consumer.debian13-amd64.lock.json').read_bytes()
    lock = _json(raw)
    _require(isinstance(lock, dict) and isinstance(lock.get('provenance'), dict), 'missing tool provenance')
    _keys(lock['provenance'], {'path', 'sha256'})
    _require(lock['provenance']['path'] == 'tool-inputs/consumer.debian13-amd64.provenance.json', 'unsupported provenance asset')
    provenance = package_data(lock['provenance']['path']).read_bytes()
    _require(_digest(provenance) == lock['provenance']['sha256'], 'provenance checksum mismatch')
    _validate(lock, _json(provenance))
    for record in lock['resources']:
        data = package_data(record['asset']).read_bytes()
        _require(len(data) == record['size'] and _digest(data) == record['sha256'], 'owned resource checksum/size mismatch')
    return lock, _digest(raw)


def _checked_load(toolset, target):
    try:
        return _load(toolset, target)
    except (KeyError, TypeError, AttributeError) as error:
        raise ToolInputError('malformed tool input lock') from error


def load_tool_input_lock(toolset: str, *, target: str) -> dict:
    """Load authoritative installed selection; no caller lock or URL override."""
    return _checked_load(toolset, target)[0]


def _read_regular(path, *, maximum):
    """Bounded read from a single no-follow descriptor, including FIFO races."""
    import os
    import stat
    mode = path.lstat().st_mode
    _require(stat.S_ISREG(mode), 'tool input must be a regular non-symlink file')
    descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_size <= maximum, 'tool input type/size mismatch')
        data = stream.read(maximum + 1)
        _require(len(data) <= maximum, 'tool input exceeds size bound')
        return data


def _verify_tree(root, records, *, receipt):
    import os
    import stat
    from .tool_downloads import safe_directory
    safe_directory(root)
    expected = {p['path']: p for p in records}
    files = set(expected) | ({'resolved-inputs.json'} if receipt else set())
    directories = {str(PurePosixPath(name).parents[i]) for name in files
                   for i in range(len(PurePosixPath(name).parents) - 1)}
    seen = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                name = str((directory / entry.name).relative_to(root)).replace(os.sep, '/')
                mode = entry.stat(follow_symlinks=False).st_mode
                if stat.S_ISDIR(mode):
                    _require(name in directories, 'undeclared input directory')
                    pending.append(directory / entry.name)
                else:
                    _require(stat.S_ISREG(mode) and name in files, 'undeclared or special input file')
                    seen.add(name)
    _require(seen == files, 'missing or extra resolved input files')
    for name, record in expected.items():
        data = _read_regular(root / name, maximum=record['size'])
        _require(len(data) == record['size'] and _digest(data) == record['sha256'], 'resolved input checksum/size mismatch')


def _receipt(lock, lock_sha256, records, observations, elapsed):
    return {'schema_version': 1, 'status': 'resolved', 'toolset': lock['toolset'], 'target': lock['target'],
            'lock_sha256': lock_sha256, 'records': records, 'observations': observations,
            'network_bytes': sum(p['size'] for p in records if p['kind'] != 'resource'),
            'resource_bytes': sum(p['size'] for p in records if p['kind'] == 'resource'),
            'elapsed_seconds': elapsed, 'admission': 'unreviewed', 'installation': 'not-executed'}


def resolve_tool_inputs(toolset: str, *, target: str, output_dir) -> dict:
    """Acquire the authoritative opaque roster into a new owned attempt only."""
    from pathlib import Path
    import time
    from . import receipts
    from .tool_downloads import download_locked_file, safe_directory, _remaining
    lock, lock_sha256 = _checked_load(toolset, target)
    records = _records(lock)
    root = Path(output_dir).absolute()
    safe_directory(root.parent)
    root.mkdir(parents=True, exist_ok=False)
    started = time.monotonic()
    deadline = started + _LIMITS['attempt_seconds']
    receipt_path = root / 'resolved-inputs.json'
    try:
        observations = []
        for record in records:
            _remaining(deadline)
            destination = root / record['path']
            if record['kind'] == 'resource':
                data = package_data(record['asset']).read_bytes()
                _require(len(data) == record['size'] and _digest(data) == record['sha256'], 'owned resource changed before copy')
                safe_directory(destination.parent)
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open('xb') as output:
                    output.write(data)
                observation = {'sha256': record['sha256'], 'size': len(data)}
            else:
                observation = download_locked_file(record, destination, deadline=deadline)
            observations.append({'path': record['path']} | observation)
        _verify_tree(root, records, receipt=False)
        _remaining(deadline)
        result = _receipt(lock, lock_sha256, records, observations, time.monotonic() - started)
        receipts.write_receipt(receipt_path, result)
        _remaining(deadline)
        return result
    except BaseException as error:
        # write_receipt can raise after replacing the file (directory fsync).
        # Best-effort invalidation must not obscure the original failure.
        try:
            receipt_path.unlink(missing_ok=True)
        except OSError as cleanup:
            error.add_note('Could not invalidate resolution receipt after failure: ' + str(cleanup))
        raise


def verify_resolved_tool_inputs(toolset: str, *, target: str, receipt_path) -> dict:
    """Re-select installed authority and rehash files; receipt hashes are not pins."""
    import math
    from pathlib import Path
    from .tool_downloads import safe_directory, _target
    lock, lock_sha256 = _checked_load(toolset, target)
    records = _records(lock)
    path = Path(receipt_path).absolute()
    _require(path.name == 'resolved-inputs.json', 'unexpected resolution receipt filename')
    safe_directory(path.parent)
    result = _json(_read_regular(path, maximum=4 * 1024**2))
    expected = _receipt(lock, lock_sha256, records, [], 0)
    _keys(result, expected.keys())
    _require(type(result['schema_version']) is int, 'invalid receipt schema')
    _require(type(result['elapsed_seconds']) in {int, float} and math.isfinite(result['elapsed_seconds'])
             and 0 <= result['elapsed_seconds'] <= _LIMITS['attempt_seconds'], 'invalid acquisition duration')
    _require(all(_canonical(result[key]) == _canonical(value) for key, value in expected.items()
                 if key not in {'elapsed_seconds', 'observations'}),
             'resolved receipt differs from authoritative installed inputs')
    observations = result['observations']
    _require(isinstance(observations, list) and len(observations) == len(records), 'incomplete acquisition observations')
    for record, observation in zip(records, observations):
        fields = {'path', 'sha256', 'size'} | ({'final_url'} if record['kind'] != 'resource' else set())
        _keys(observation, fields)
        _require(type(observation['size']) is int and all(observation[k] == record[k] for k in ('path', 'sha256', 'size')),
                 'acquisition observation mismatch')
        if 'final_url' in observation:
            _require(isinstance(observation['final_url'], str), 'invalid observed origin')
            _target(observation['final_url'])
    _verify_tree(path.parent, records, receipt=True)
    return result
