"""Actual-content inventory and explicit, digest-bound redistribution evidence.

Reviewed records are assertions supplied by a reviewer, never license inference.
Eligibility does not authorize publication or satisfy anonymous source delivery.
"""
from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess
import tarfile
import tempfile

from .models import ArtifactRef
from .sources import SourceError, checksum


def relative_path(name: str) -> str:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or '..' in path.parts or '\\' in name or path.as_posix() != name:
        raise SourceError('unsafe or noncanonical evidence path: ' + name)
    return name


def parse_dpkg_status(text: str) -> list[dict]:
    packages = []
    for paragraph in re.split(r'\n[ \t]*\n', text.strip('\n')):
        fields = {}
        key = None
        for line in paragraph.splitlines():
            if line.startswith((' ', '\t')) and key:
                fields[key] += ' ' + line.strip()
            elif ':' in line:
                key, value = line.split(':', 1)
                if not re.fullmatch('[A-Za-z0-9][-A-Za-z0-9]*', key):
                    raise SourceError('malformed dpkg field name')
                key = key.title()
                if key in fields:
                    raise SourceError('duplicate dpkg field: ' + key)
                fields[key] = value.lstrip()
            else:
                raise SourceError('malformed dpkg paragraph/continuation')
        if fields.get('Status') != 'install ok installed':
            continue
        if any(not fields.get(field) for field in ('Package', 'Version', 'Architecture')):
            raise SourceError('missing installed dpkg identity field')
        source = fields.get('Source', fields['Package'])
        match = re.fullmatch(r'([^ ()]+)(?: \(([^()]+)\))?', source)
        if not match:
            raise SourceError('invalid installed Source field')
        incorporated = set()
        for field in ('Built-Using', 'Static-Built-Using'):
            for entry in fields.get(field, '').split(','):
                if not entry.strip():
                    continue
                identity = re.fullmatch(r'\s*([^ ()]+)\s*\(=\s*([^()]+)\)\s*', entry)
                if not identity:
                    raise SourceError('invalid installed ' + field)
                incorporated.add(identity[1] + '=' + identity[2].strip())
        packages.append({'name': fields['Package'], 'version': fields['Version'], 'architecture': fields['Architecture'],
            'source_package': match[1], 'source_version': match[2] or fields['Version'],
            'built_using': fields.get('Built-Using', ''), 'static_built_using': fields.get('Static-Built-Using', ''),
            'incorporated_sources': sorted(incorporated)})
    return sorted(packages, key=lambda p: p['name'])


def _needed(binary: bytes) -> list[str]:
    # The loader uses program headers; section names are only consistency evidence.
    try:
        if binary[:6] != b'\x7fELF\x02\x01':
            raise ValueError('expected ELF64 little-endian')
        phoff, shoff = struct.unpack_from('<QQ', binary, 32)
        phsize, phcount, shsize, shcount, shnames = struct.unpack_from('<HHHHH', binary, 54)
        if (phcount and phsize != 56) or phoff + phsize * phcount > len(binary):
            raise ValueError('invalid program headers')
        programs = [struct.unpack_from('<IIQQQQQQ', binary, phoff + i * phsize) for i in range(phcount)]
        sections = []
        if shcount:
            if shsize != 64 or shoff + shsize * shcount > len(binary) or shnames >= shcount:
                raise ValueError('invalid section headers')
            sections = [struct.unpack_from('<IIQQQQIIQQ', binary, shoff + i * shsize) for i in range(shcount)]
        labels = b''
        if shnames:
            header = sections[shnames]
            labels = binary[header[4]:header[4] + header[5]]
        def label(header):
            return labels[header[0]:].split(b'\0', 1)[0]
        dynamics = [h for h in programs if h[0] == 2]
        dynamic_sections = [h for h in sections if h[1] == 6 or label(h) == b'.dynamic']
        if not dynamics:
            if dynamic_sections:
                raise ValueError('inconsistent section/program dynamic metadata')
            return []
        if len(dynamics) != 1:
            raise ValueError('multiple dynamic segments')
        dynamic = dynamics[0]
        start, size = dynamic[2], dynamic[5]
        # objcopy's separate debug files retain headers but no dynamic payload.
        if (size == 0 and any(h[1] == 8 and label(h) == b'.dynamic' for h in sections)
                and not any(h[0] == 1 and h[3] <= dynamic[3] < h[3] + h[5] for h in programs)):
            return []
        if not size or size % 16 or start + size > len(binary):
            raise ValueError('invalid dynamic segment bounds')
        loads = [h for h in programs if h[0] == 1 and h[3] <= dynamic[3]
                 and dynamic[3] + size <= h[3] + h[5]]
        if len(loads) != 1 or loads[0][2] + dynamic[3] - loads[0][3] != start:
            raise ValueError('dynamic segment file offset/address mapping disagreement')
        if sections and (len(dynamic_sections) != 1 or dynamic_sections[0][4:6] != (start, size)
                or dynamic_sections[0][1] != 6 or (labels and label(dynamic_sections[0]) != b'.dynamic')):
            raise ValueError('inconsistent section/program dynamic metadata')
        entries = []
        for offset in range(start, start + size, 16):
            tag, value = struct.unpack_from('<QQ', binary, offset)
            if tag == 0:
                break
            entries.append((tag, value))
        else:
            raise ValueError('unterminated dynamic segment')
        needed_offsets = [value for tag, value in entries if tag == 1]
        if not needed_offsets:
            return []
        pointers = [value for tag, value in entries if tag == 5]
        lengths = [value for tag, value in entries if tag == 10]
        if len(pointers) != 1 or len(lengths) != 1:
            raise ValueError('missing/duplicate dynamic string table')
        address, length = pointers[0], lengths[0]
        loads = [h for h in programs if h[0] == 1 and h[3] <= address and address + length <= h[3] + h[5]]
        if len(loads) != 1:
            raise ValueError('unmapped dynamic string table')
        string_start = loads[0][2] + address - loads[0][3]
        if string_start + length > len(binary):
            raise ValueError('invalid dynamic string bounds')
        string_sections = [h for h in sections if label(h) == b'.dynstr']
        if string_sections and (len(string_sections) != 1 or string_sections[0][4:6] != (string_start, length)):
            raise ValueError('inconsistent section/program string metadata')
        strings = binary[string_start:string_start + length]
        needed = []
        for offset in needed_offsets:
            if offset >= length or b'\0' not in strings[offset:]:
                raise ValueError('invalid dependency string offset')
            name = strings[offset:].split(b'\0', 1)[0].decode('utf-8')
            if not name or '/' in name:
                raise ValueError('unsupported dependency name')
            needed.append(name)
        return sorted(set(needed))
    except (ValueError, struct.error, UnicodeError, IndexError) as error:
        raise SourceError('ELF dependency inspection: ' + str(error)) from error


def inspect_distribution_archive(archive: Path, final_files: list[dict]) -> dict:
    """Inventory distributed layers, including overwritten or deleted bytes."""
    import io
    final = {f['path']: f.get('sha256') for f in final_files}
    hidden, layers, whiteouts, descriptors = [], [], [], []
    runtime_mount_files = {}
    with tarfile.open(archive) as saved:
        roster = saved.getmembers()
        if sum(m.size for m in roster) > 2 * 1024**3:
            raise SourceError('distribution archive exceeds inspection bound')
        names = [m.name for m in roster if m.isfile()]
        if len(names) != len(set(names)):
            raise SourceError('duplicate distribution archive members')
        manifest = json.loads(saved.extractfile('manifest.json').read())
        if len(manifest) != 1:
            raise SourceError('distribution archive must select exactly one image')
        config_data = saved.extractfile(relative_path(manifest[0]['Config'])).read()
        config = json.loads(config_data)
        diff_ids = config.get('rootfs', {}).get('diff_ids', [])
        if config.get('rootfs', {}).get('type') != 'layers' or len(diff_ids) != len(manifest[0]['Layers']):
            raise SourceError('config/manifest layer roster mismatch')
        blobs = {}
        for path in names:
            if path.startswith('blobs/sha256/'):
                data = saved.extractfile(path).read()
                if hashlib.sha256(data).hexdigest() != PurePosixPath(path).name:
                    raise SourceError('OCI blob checksum mismatch')
                blobs['sha256:' + PurePosixPath(path).name] = (len(data), data)
                if data.startswith(b'{'):
                    blob = json.loads(data)
                    if 'schemaVersion' in blob:
                        descriptors.append({'sha256': hashlib.sha256(data).hexdigest(), 'size_bytes': len(data), 'document': blob})
        documents = { 'sha256:' + d['sha256']: d['document'] for d in descriptors }
        if 'index.json' in names:
            documents['index.json'] = json.loads(saved.extractfile('index.json').read())
        expected_config = 'sha256:' + hashlib.sha256(config_data).hexdigest()
        expected_layers = ['sha256:' + hashlib.sha256(saved.extractfile(relative_path(n)).read()).hexdigest() for n in manifest[0]['Layers']]
        for document in documents.values():
            refs = document.get('manifests', []) if 'manifests' in document else [document['config']] + document.get('layers', [])
            for ref in refs:
                if ref.get('digest') not in blobs or ref.get('size') != blobs[ref['digest']][0]:
                    raise SourceError('OCI descriptor digest/size graph mismatch')
            if 'config' in document and (document['config']['digest'] != expected_config
                    or [ref['digest'] for ref in document.get('layers', [])] != expected_layers):
                raise SourceError('OCI descriptor config/layer graph mismatch')
        for index, name in enumerate(manifest[0]['Layers']):
            blob = saved.extractfile(relative_path(name)).read()
            layer = {'index': index, 'sha256': hashlib.sha256(blob).hexdigest(), 'compressed_blob_bytes': len(blob), 'regular_file_bytes': 0}
            with tarfile.open(fileobj=io.BytesIO(blob), mode='r:*') as contents:
                diff_hash, unpacked_bytes = hashlib.sha256(), 0
                contents.fileobj.seek(0)
                while chunk := contents.fileobj.read(1024 * 1024):
                    unpacked_bytes += len(chunk)
                    if unpacked_bytes > 2 * 1024**3:
                        raise SourceError('uncompressed layer exceeds inspection bound')
                    diff_hash.update(chunk)
                if diff_ids[index] != 'sha256:' + diff_hash.hexdigest():
                    raise SourceError('config layer diff_id checksum mismatch')
                contents.fileobj.seek(0)
                layer['diff_id'] = diff_ids[index]
                seen = set()
                for member in contents:
                    path = member.name.removeprefix('./').rstrip('/')
                    if not path:
                        continue
                    relative_path(path)
                    if path in seen:
                        raise SourceError('duplicate layer member')
                    seen.add(path)
                    if PurePosixPath(path).name.startswith('.wh.'):
                        whiteouts.append('/' + str(PurePosixPath(path).with_name(PurePosixPath(path).name[4:])))
                    elif member.isfile():
                        if member.size > 512 * 1024**2:
                            raise SourceError('oversized distribution layer member')
                        data = contents.extractfile(member).read()
                        layer['regular_file_bytes'] += len(data)
                        digest = hashlib.sha256(data).hexdigest()
                        if '/' + path in {'/etc/hosts', '/etc/hostname', '/etc/resolv.conf'}:
                            runtime_mount_files['/' + path] = {'path': '/' + path, 'sha256': digest, 'size': len(data), 'mode': member.mode}
                        if final.get('/' + path) != digest:
                            hidden.append({'layer': index, 'path': '/' + path, 'sha256': digest, 'size': len(data)})
            layers.append(layer)
        hidden = [f for f in hidden if f['path'] not in runtime_mount_files or f['sha256'] != runtime_mount_files[f['path']]['sha256']]
        return {'archive_size_bytes': archive.stat().st_size, 'runtime_mount_files': sorted(runtime_mount_files.values(), key=lambda f: f['path']), 'config_sha256': hashlib.sha256(config_data).hexdigest(),
            'platform': config['os'] + '/' + config['architecture'], 'layers': layers,
            'hidden_layer_files': hidden, 'whiteouts': sorted(set(whiteouts)), 'raw_descriptors': sorted(descriptors, key=lambda d: d['sha256']),
            'measurement': 'distribution archive bytes, compressed OCI blob bytes and summed regular-file payload bytes per layer; directories/symlinks excluded'}


def inspect_artifact(artifact: ArtifactRef) -> dict:
    """Export an exact stopped container; inspect inert rootfs bytes, never its code.

    Retain a complete filesystem hash roster and installed source/static fields.
    ELF DT_NEEDED lookup records candidates, not a runtime loader-order claim.
    Container creation/export do not run entrypoints. Only the owned ID is removed.
    """
    if artifact.kind != 'docker-local':
        if artifact.kind != 'bundle' or checksum(artifact.reference) != artifact.sha256:
            raise SourceError('binary artifact checksum mismatch or unsupported kind')
        files, binaries = [], []
        retained, provenance = {}, {}
        total, seen = 0, set()
        try:
            with tarfile.open(artifact.reference) as contents:
                for member in contents:
                    name = relative_path(member.name)
                    if not member.isfile() or name in seen or member.size > 512 * 1024**2:
                        raise SourceError('unsupported/duplicate binary bundle member')
                    total += member.size
                    if total > 2 * 1024**3:
                        raise SourceError('binary bundle exceeds inspection bounds')
                    seen.add(name)
                    data = contents.extractfile(member).read()
                    record = {'path': '/' + name, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'mode': member.mode, 'package': None}
                    files.append(record)
                    retained[name] = data
                    if name == 'provenance.json':
                        provenance = json.loads(data)
                    if data.startswith(b'\x7fELF'):
                        binaries.append(record | {'needed': _needed(data)})
        except tarfile.TarError as error:
            raise SourceError('invalid binary bundle') from error
        result = {'artifact': asdict(artifact), 'packages': [], 'binaries': binaries, 'linked_libraries': [], 'files': sorted(files, key=lambda f: f['path'])}
        if provenance.get('role') == 'debug-companion':
            from .debug import verify_debug_files
            parent = ArtifactRef(**provenance['matched_runtime'])
            parent_observation = inspect_artifact(parent)
            with tempfile.TemporaryDirectory(prefix='p11lab-debug-admission-') as temporary:
                directory = Path(temporary)
                parent_archive = Path(parent.reference)
                if parent.kind == 'docker-local':
                    parent_archive = directory / 'parent.tar'
                    container = subprocess.check_output(['docker', 'create', '--network', 'none', parent.reference, '/p11lab-inspection-not-executed'], text=True).strip()
                    try:
                        subprocess.run(['docker', 'export', '--output', str(parent_archive), container], check=True, capture_output=True)
                    finally:
                        subprocess.run(['docker', 'rm', container], check=True, capture_output=True)
                if parent_archive.stat().st_size > 2 * 1024**3:
                    raise SourceError('debug parent exceeds inspection bound')
                parent_files = {f['path']: f for f in parent_observation['files']}
                runtime = {}
                with tarfile.open(parent_archive) as contents:
                    members = {m.name.removeprefix('./'): m for m in contents}
                    for name, path in [('libsofthsm2.so', '/usr/local/lib/p11lab/libsofthsm2.so'), ('softhsm2-util', '/usr/local/bin/softhsm2-util')]:
                        member = members.get(path.removeprefix('/'))
                        if member is None or not member.isfile() or member.size > 512 * 1024**2:
                            raise SourceError('missing/invalid inert debug parent file: ' + path)
                        data = contents.extractfile(member).read()
                        expected = parent_files.get(path, {})
                        if hashlib.sha256(data).hexdigest() != expected.get('sha256') or len(data) != expected.get('size'):
                            raise SourceError('inert debug parent byte identity mismatch: ' + path)
                        runtime[name] = data
                for name, data in retained.items():
                    path = directory / relative_path(name)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
                records = verify_debug_files(directory, runtime)
            if records != provenance['binaries']:
                raise SourceError('debug companion provenance/binary relationship mismatch')
            result['debug_relationship'] = {'matched_runtime': asdict(parent), 'binaries': records,
                'parent_observation_sha256': hashlib.sha256(json.dumps(parent_observation, sort_keys=True).encode()).hexdigest()}
        return result
    if artifact.reference != 'sha256:' + artifact.sha256:
        raise SourceError('local engine identity mismatch')
    try:
        inspect = json.loads(subprocess.check_output(['docker', 'image', 'inspect', artifact.reference], text=True))[0]
        if inspect['Id'] != artifact.reference or inspect['Os'] + '/' + inspect['Architecture'] != artifact.platform:
            raise SourceError('binary artifact identity/platform mismatch')
        with tempfile.TemporaryDirectory(prefix='p11lab-inventory-') as temporary:
            archive = Path(temporary) / 'rootfs.tar'
            container = subprocess.check_output(['docker', 'create', '--network', 'none', artifact.reference, '/p11lab-inspection-not-executed'], text=True).strip()
            try:
                subprocess.run(['docker', 'export', '--output', str(archive), container], check=True, capture_output=True)
            finally:
                subprocess.run(['docker', 'rm', container], check=True, capture_output=True)
            if archive.stat().st_size > 2 * 1024**3:
                raise SourceError('rootfs inspection exceeds 2 GiB bound')
            with tarfile.open(archive) as contents:
                files, elf, aliases, owners = [], {}, {}, {}
                packages, md5sums, actual_md5 = [], {}, {}
                for member in contents:
                    name = member.name.removeprefix('./').rstrip('/')
                    if not name:
                        continue
                    relative_path(name)
                    path = '/' + name
                    if member.isfile():
                        if member.size > 512 * 1024**2:
                            raise SourceError('rootfs member exceeds inspection bound')
                        data = contents.extractfile(member).read()
                        actual_md5[path] = hashlib.md5(data).hexdigest()
                        files.append({'path': path, 'sha256': hashlib.sha256(data).hexdigest(), 'size': len(data), 'mode': member.mode})
                        if data.startswith(b'\x7fELF'):
                            elf[path] = {'path': path, 'sha256': files[-1]['sha256'], 'size': len(data), 'needed': _needed(data)}
                        if name == 'var/lib/dpkg/status':
                            packages = parse_dpkg_status(data.decode())
                        if name.startswith('var/lib/dpkg/info/') and name.endswith('.list'):
                            package = PurePosixPath(name).name[:-5].split(':')[0]
                            for entry in data.decode().splitlines():
                                owners[entry] = package
                        if name.startswith('var/lib/dpkg/info/') and name.endswith('.md5sums'):
                            package = PurePosixPath(name).name[:-8].split(':')[0]
                            sums = {}
                            for line in data.decode().splitlines():
                                match = re.fullmatch(r'([0-9a-f]{32})  (.+)', line)
                                if not match:
                                    raise SourceError('malformed installed dpkg md5sums')
                                entry = '/' + relative_path(match[2])
                                if entry in sums:
                                    raise SourceError('duplicate installed dpkg checksum path')
                                sums[entry] = match[1]
                            if package in md5sums:
                                raise SourceError('duplicate installed package checksum manifest')
                            md5sums[package] = (path, files[-1]['sha256'], sums)
                    elif member.issym() or member.islnk():
                        files.append({'path': path, 'link': member.linkname, 'mode': member.mode})
                        aliases[path] = member.linkname if member.issym() else '/' + member.linkname
                def resolve(path):
                    seen = set()
                    while path in aliases:
                        if path in seen:
                            raise SourceError('cyclic rootfs link')
                        seen.add(path)
                        target = aliases[path]
                        import posixpath
                        path = posixpath.normpath(target if target.startswith('/') else posixpath.join(posixpath.dirname(path), target))
                    return path
                candidates = {}
                for path in list(elf) + list(aliases):
                    resolved = resolve(path)
                    if resolved in elf:
                        candidates.setdefault(PurePosixPath(path).name, set()).add(resolved)
                links = []
                for path, record in sorted(elf.items()):
                    record['package'] = owners.get(path)
                    for needed in record['needed']:
                        links.append({'binary': path, 'needed': needed, 'resolved': sorted(candidates.get(needed, []))})
                distribution_archive = Path(temporary) / 'distribution.tar'
                subprocess.run(['docker', 'image', 'save', '--output', str(distribution_archive), artifact.reference], check=True, capture_output=True)
                distribution = inspect_distribution_archive(distribution_archive, files)
                descriptor = inspect.get('Descriptor')
                if descriptor:
                    records = { 'sha256:' + d['sha256']: d for d in distribution['raw_descriptors'] }
                    if (descriptor.get('digest') != artifact.reference or descriptor['digest'] not in records
                            or descriptor.get('size') != records[descriptor['digest']]['size_bytes']):
                        raise SourceError('local engine descriptor/export graph mismatch')
                    pending, visited, reached = [descriptor['digest']], set(), False
                    while pending:
                        digest = pending.pop()
                        if digest in visited:
                            continue
                        visited.add(digest)
                        document = records.get(digest, {}).get('document', {})
                        if (document.get('config', {}).get('digest') == 'sha256:' + distribution['config_sha256']
                                and [r['digest'] for r in document.get('layers', [])]
                                == ['sha256:' + layer['sha256'] for layer in distribution['layers']]):
                            reached = True
                        pending.extend(r['digest'] for r in document.get('manifests', []))
                    if not reached:
                        raise SourceError('local engine root does not reach selected config/layers')
                elif artifact.reference != 'sha256:' + distribution['config_sha256']:
                    raise SourceError('local engine config/export graph mismatch')
                # Docker creates these virtual mount files per container; inventory
                # the actual underlying distributed bytes, not injected host state.
                mount_paths = {'/etc/hosts', '/etc/hostname', '/etc/resolv.conf'}
                files = [f for f in files if f['path'] not in mount_paths] + distribution['runtime_mount_files']
                for record in files:
                    record['package'] = owners.get(record['path'])
                    if record['package'] and 'sha256' in record:
                        manifest = md5sums.get(record['package'])
                        verification = {'status': 'unverifiable', 'actual_md5': actual_md5.get(record['path'])}
                        if manifest and record['path'] in manifest[2] and record['path'] not in mount_paths:
                            expected = manifest[2][record['path']]
                            verification.update(manifest_path=manifest[0], manifest_sha256=manifest[1], expected_md5=expected,
                                status='verified' if expected == verification['actual_md5'] else 'modified')
                        record['package_verification'] = verification
                if distribution['platform'] != artifact.platform:
                    raise SourceError('exported distribution platform mismatch')
                return {'artifact': asdict(artifact), 'distribution': distribution, 'packages': packages, 'binaries': list(elf.values()),
                    'linked_libraries': links, 'files': sorted(files, key=lambda f: f['path']),
                    'descriptor': inspect.get('Descriptor'), 'link_method': 'ELF DT_NEEDED and rootfs candidates; not runtime search-order attestation'}
    except (subprocess.SubprocessError, OSError, KeyError, ValueError) as error:
        raise SourceError('actual artifact inspection failed: ' + str(error)) from error


def _same_artifact(record: dict, artifact: ArtifactRef) -> bool:
    expected = asdict(artifact)
    if artifact.kind == 'bundle':
        expected.pop('reference')
        record = {k: v for k, v in record.items() if k != 'reference'}
    return record == expected


def _same_observation(actual: dict, recorded: dict, artifact: ArtifactRef) -> bool:
    return _same_artifact(recorded.get('artifact', {}), artifact) and \
        {k: v for k, v in actual.items() if k != 'artifact'} == {k: v for k, v in recorded.items() if k != 'artifact'}


def validate_inventory(artifact: ArtifactRef, inventory: dict) -> list[str]:
    reasons = []
    if inventory.get('schema_version') != 1 or not _same_artifact(inventory.get('artifact', {}), artifact):
        reasons.append('inventory binary identity mismatch')
    observation = inventory.get('observation', {})
    if not _same_artifact(observation.get('artifact', {}), artifact):
        reasons.append('actual-content observation binary identity mismatch')
    source_records = inventory.get('sources', [])
    sources = {s['id']: s for s in source_records}
    if len(sources) != len(source_records) or not sources:
        reasons.append('missing or duplicate source identities')
    payloads = {p['path']: p for p in inventory.get('payloads', [])}
    if len(payloads) != len(inventory.get('payloads', [])):
        reasons.append('duplicate payload destinations')
    for path, p in payloads.items():
        try:
            relative_path(path)
            if p['role'] not in {'source', 'notice', 'license', 'build', 'metadata'}:
                reasons.append('source-only companion contains disallowed role: ' + path)
            if not re.fullmatch('[0-9a-f]{64}', p['sha256']) or not isinstance(p['size'], int) or p['size'] < 0:
                reasons.append('invalid payload identity: ' + path)
        except (SourceError, KeyError):
            reasons.append('invalid payload declaration: ' + path)
    reviews = {r['source']: r for r in inventory.get('reviews', [])}
    if len(reviews) != len(inventory.get('reviews', [])):
        reasons.append('duplicate reviewed identities')
    for identity, source in sources.items():
        if not source.get('name') or not source.get('version') or identity != source['name'] + '=' + source['version']:
            reasons.append('source identity mismatch: ' + identity)
        for path in source.get('payloads', []):
            if path not in payloads or payloads[path]['role'] != 'source':
                reasons.append('absent required source payload: ' + identity + ':' + path)
        if not source.get('payloads'):
            reasons.append('source identity has no payload: ' + identity)
        review = reviews.get(identity, {})
        if review.get('status') != 'reviewed' or review.get('grant_known') is not True or review.get('source_redistribution') is not True:
            reasons.append('unreviewed or unknown redistribution grant: ' + identity)
        for field in ('license_declared', 'license_concluded', 'chosen_route', 'modifications'):
            if not review.get(field):
                reasons.append('missing rights evidence ' + field + ': ' + identity)
        for path in review.get('grant_evidence', []):
            if path not in payloads:
                reasons.append('absent grant evidence: ' + identity + ':' + path)
        if not review.get('grant_evidence'):
            reasons.append('missing original grant evidence: ' + identity)
        notices = review.get('notices', [])
        if not notices:
            reasons.append('absent required notice: ' + identity)
        for path in notices:
            if path not in payloads or payloads[path]['role'] not in {'notice', 'license', 'source'}:
                reasons.append('absent required notice: ' + path)
        if 'agpl-remote-source' in review.get('obligations', []):
            offer = review.get('agpl_remote_source_offer', {})
            if offer.get('status') != 'reviewed' or offer.get('evidence_path') not in payloads:
                reasons.append('missing AGPL remote-source-offer evidence: ' + identity)
    for package in observation.get('packages', []):
        required = [package['source_package'] + '=' + package['source_version']] + package['incorporated_sources']
        for identity in required:
            if identity not in sources:
                reasons.append('missing installed/incorporated runtime source: ' + identity)
    for component in inventory.get('components', []):
        if component.get('source') not in sources:
            reasons.append('missing component source: ' + component['id'])
    components = {c['id']: c for c in inventory.get('components', [])}
    for binary in observation.get('binaries', []):
        if not binary.get('package') and binary['path'] not in components:
            reasons.append('unmapped shipped binary: ' + binary['path'])
    for link in observation.get('linked_libraries', []):
        if not link.get('resolved'):
            reasons.append('missing runtime dependency: ' + link['needed'])
    if inventory.get('role') == 'debug-companion':
        relationship = observation.get('debug_relationship', {})
        if not relationship.get('matched_runtime') or relationship['matched_runtime'] != inventory.get('parent_artifact'):
            reasons.append('debug companion lacks exact verified parent relationship')
    packages = {p['name']: p for p in observation.get('packages', [])}
    archives = {}
    for archive in inventory.get('package_archives', []):
        digest = archive.get('sha256', '')
        package = packages.get(archive.get('package'), {})
        authentication = archive.get('authentication', {})
        if (not re.fullmatch('[0-9a-f]{64}', digest) or digest in archives
                or type(archive.get('size')) is not int or not 0 < archive['size'] <= 1024**3
                or not package or archive.get('version') != package.get('version')
                or archive.get('architecture') != package.get('architecture')
                or archive.get('source') != package.get('source_package', '') + '=' + package.get('source_version', '')
                or authentication.get('status') != 'reviewed'
                or payloads.get(authentication.get('evidence_path'), {}).get('role') != 'metadata'):
            reasons.append('invalid authenticated package archive: ' + digest)
        archives[digest] = archive
    package_files = {}
    observed_files = {f['path']: f for f in observation.get('files', [])}
    for record in inventory.get('package_files', []):
        path = record.get('path', '')
        file = observed_files.get(path, {})
        archive = archives.get(record.get('archive_sha256'), {})
        try:
            relative_path(record.get('member', ''))
            if (path in package_files or not file.get('package') or 'sha256' not in file
                    or record.get('package') != file['package'] or archive.get('package') != file['package']
                    or not re.fullmatch('[0-9a-f]{64}', record.get('sha256', ''))):
                raise SourceError('invalid package file binding')
        except SourceError:
            reasons.append('invalid authenticated package file: ' + path)
        package_files[path] = record
    content_reviews = {(r.get('path'), r.get('sha256')): r for r in inventory.get('content_reviews', [])}
    for file in observation.get('files', []):
        if 'sha256' not in file:
            continue
        # MD5 is only a package comparison. Admission needs a SHA256-bound
        # archive member (re-read by collection/assessment) or explicit review.
        binding = package_files.get(file['path'], {})
        if file.get('package') and binding.get('sha256') == file['sha256']:
            continue
        review = content_reviews.get((file['path'], file['sha256']), {})
        if review.get('status') != 'reviewed' or review.get('source') not in sources:
            reasons.append('unreviewed copied/generated content: ' + file['path'])
    layer_reviews = {(r.get('path'), r.get('sha256')): r for r in inventory.get('layer_reviews', [])}
    for hidden in observation.get('distribution', {}).get('hidden_layer_files', []):
        review = layer_reviews.get((hidden['path'], hidden['sha256']), {})
        if review.get('status') != 'reviewed' or review.get('source') not in sources:
            reasons.append('unreviewed distributed lower-layer bytes: ' + hidden['path'])
    for patch in inventory.get('patches', []):
        if (patch.get('status') != 'reviewed' or not patch.get('license') or patch.get('path') not in payloads
                or not re.fullmatch('[0-9a-f]{64}', patch.get('sha256', ''))
                or patch.get('sha256') != payloads.get(patch.get('path'), {}).get('sha256')
                or not patch.get('provenance') or not patch.get('changed_behavior')):
            reasons.append('unreviewed or missing patch evidence')
    if payloads.get(inventory.get('build_instructions'), {}).get('role') != 'build':
        reasons.append('absent required build instructions')
    return sorted(set(reasons))


def spdx_inventory(artifact: ArtifactRef, inventory: dict) -> dict:
    digest = hashlib.sha256(json.dumps(inventory, sort_keys=True).encode()).hexdigest()
    reviews = {r['source']: r for r in inventory['reviews']}
    packages, relationships = [], []
    source_ids = {}
    for index, source in enumerate(inventory['sources']):
        sid = 'SPDXRef-Source-' + str(index)
        source_ids[source['id']] = sid
        review = reviews.get(source['id'], {})
        packages.append({'SPDXID': sid, 'name': source['name'], 'versionInfo': source['version'],
            'downloadLocation': source.get('url', 'NOASSERTION'), 'filesAnalyzed': False,
            'licenseDeclared': review.get('license_declared', 'NOASSERTION'),
            'licenseConcluded': review.get('license_concluded', 'NOASSERTION'), 'copyrightText': 'NOASSERTION',
            'sourceInfo': 'Exact retained source identity ' + source['id'], 'comment': review.get('chosen_route', '')})
        relationships.append({'spdxElementId': 'SPDXRef-DOCUMENT', 'relationshipType': 'DESCRIBES', 'relatedSpdxElement': sid})
    for index, package in enumerate(inventory['observation'].get('packages', [])):
        sid = 'SPDXRef-Binary-' + str(index)
        source_identity = package['source_package'] + '=' + package['source_version']
        review = reviews.get(source_identity, {})
        packages.append({'SPDXID': sid, 'name': package['name'], 'versionInfo': package['version'],
            'downloadLocation': 'NOASSERTION', 'filesAnalyzed': False, 'licenseDeclared': review.get('license_declared', 'NOASSERTION'),
            'licenseConcluded': 'NOASSERTION', 'copyrightText': 'NOASSERTION',
            'sourceInfo': 'Installed ' + package['architecture'] + ' package; source ' + source_identity})
        if source_identity in source_ids:
            relationships.append({'spdxElementId': sid, 'relationshipType': 'GENERATED_FROM', 'relatedSpdxElement': source_ids[source_identity]})
        for identity in package.get('incorporated_sources', []):
            if identity in source_ids:
                relationships.append({'spdxElementId': sid, 'relationshipType': 'STATIC_LINK', 'relatedSpdxElement': source_ids[identity]})
    files = []
    file_ids = {}
    for index, record in enumerate(inventory['observation'].get('files', [])):
        if 'sha256' not in record:
            continue
        file_ids[record['path']] = 'SPDXRef-File-' + str(index)
        files.append({'SPDXID': 'SPDXRef-File-' + str(index), 'fileName': record['path'],
            'checksums': [{'algorithm': 'SHA256', 'checksumValue': record['sha256']}],
            'licenseConcluded': 'NOASSERTION', 'licenseInfoInFiles': ['NOASSERTION'], 'copyrightText': 'NOASSERTION'})
    for link in inventory['observation'].get('linked_libraries', []):
        for path in link.get('resolved', []):
            if link['binary'] in file_ids and path in file_ids:
                relationships.append({'spdxElementId': file_ids[link['binary']], 'relationshipType': 'DYNAMIC_LINK', 'relatedSpdxElement': file_ids[path]})
    for component in inventory.get('components', []):
        if component['id'] in file_ids and component['source'] in source_ids:
            relationships.append({'spdxElementId': file_ids[component['id']], 'relationshipType': 'GENERATED_FROM', 'relatedSpdxElement': source_ids[component['source']]})
    return {'spdxVersion': 'SPDX-2.3', 'dataLicense': 'CC0-1.0', 'SPDXID': 'SPDXRef-DOCUMENT',
        'name': 'P11Lab ' + inventory['role'] + ' actual-content inventory',
        'documentNamespace': 'https://p11lab.invalid/spdx/' + artifact.sha256 + '/' + digest,
        'creationInfo': {'creators': ['Tool: p11lab'], 'created': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')},
        'documentComment': 'Artifact sha256:' + artifact.sha256 + '; NOASSERTION does not replace preserved grants. ' + '; '.join(inventory.get('limitations', [])),
        'packages': packages, 'relationships': relationships, 'files': files, 'hasExtractedLicensingInfos': inventory.get('extracted_licenses', [])}


def assess_distribution(artifact: ArtifactRef, evidence_dir: Path) -> dict:
    from .sources import verify_source_bundle, _verify_package_files
    evidence_dir = Path(evidence_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    blockers = []
    companion = None
    inventory = {}
    try:
        receipt = json.loads((evidence_dir / 'source-companion.json').read_text())
        companion = receipt['artifact']
        archive = evidence_dir / relative_path(receipt['archive'])
        if checksum(archive) != companion['sha256']:
            raise SourceError('source companion checksum mismatch')
        with tempfile.TemporaryDirectory(prefix='p11lab-admission-') as temporary:
            extracted = Path(temporary) / 'extract'
            inventory = verify_source_bundle(archive, extracted)
            _verify_package_files(inventory, extracted, evidence_dir / 'package-cache')
            expected_receipt = {'schema_version': 1, 'role': 'source-companion', 'archive': archive.name,
                'artifact': {'kind': 'bundle', 'reference': 'sha256:' + checksum(archive),
                    'sha256': checksum(archive), 'platform': artifact.platform},
                'matched_artifact': inventory['artifact'], 'size_bytes': archive.stat().st_size,
                'sbom_sha256': checksum(extracted / 'sbom.spdx.json'), 'inventory_sha256': checksum(extracted / 'inventory.json'),
                'payload_count': len(inventory['payloads']), 'source_count': len(inventory['sources']),
                'publication_status': 'not-published', 'source_rights': 'explicit reviewed records; no automatic grant inference'}
            if json.dumps(receipt, sort_keys=True) != json.dumps(expected_receipt, sort_keys=True):
                blockers.append('source companion receipt metadata mismatch')
            if (evidence_dir / 'sbom.spdx.json').read_bytes() != (extracted / 'sbom.spdx.json').read_bytes():
                blockers.append('outer/embedded SPDX inventory mismatch')
        blockers.extend(validate_inventory(artifact, inventory))
        actual = inspect_artifact(artifact)
        if not _same_observation(actual, inventory['observation'], artifact):
            blockers.append('actual binary content inventory mismatch')
        if not _same_artifact(receipt['matched_artifact'], artifact):
            blockers.append('source companion binary identity mismatch')
        sbom = json.loads((evidence_dir / 'sbom.spdx.json').read_text())
        if checksum(evidence_dir / 'sbom.spdx.json') != receipt['sbom_sha256']:
            blockers.append('SPDX inventory checksum mismatch')
        if sbom['documentComment'].split(';')[0] != 'Artifact sha256:' + artifact.sha256:
            blockers.append('SPDX binary identity mismatch')
    except (OSError, ValueError, KeyError, tarfile.TarError) as error:
        blockers.append(str(error))
    public_reference = asdict(artifact)
    if artifact.kind == 'bundle':
        public_reference['reference'] = 'sha256:' + artifact.sha256
    result = {'schema_version': 1, 'artifact': public_reference, 'source_companion': companion,
        'status': 'blocked' if blockers else 'eligible', 'blockers': sorted(set(blockers)),
        'publication_status': 'blocked', 'publication_blockers': ['anonymous-source-first delivery not verified'],
        'source_companion_status': 'blocked' if blockers else 'eligible', 'role': inventory.get('role', 'unknown'), 'limitations': inventory.get('limitations', [])}
    (evidence_dir / 'admission.json').write_text(json.dumps(result, sort_keys=True, indent=2) + '\n')
    return result


def main():
    import argparse
    from .sources import collect_source_bundle
    parser = argparse.ArgumentParser(description='Collect source-only companions or assess exact artifacts; never publish')
    parser.add_argument('operation', choices=('inspect', 'collect', 'assess', 'verify'))
    parser.add_argument('--artifact', type=Path, help='JSON ArtifactRef (or build receipt with artifact)')
    parser.add_argument('--inventory', type=Path)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args()
    try:
        if args.operation == 'verify':
            from .sources import verify_source_bundle
            result = verify_source_bundle(args.archive, args.output_dir)
        else:
            data = json.loads(args.artifact.read_text())
            artifact = ArtifactRef(**data.get('artifact', data))
            if args.operation == 'inspect':
                args.output_dir.mkdir(parents=True, exist_ok=False)
                result = inspect_artifact(artifact)
                (args.output_dir / 'observation.json').write_text(json.dumps(result, indent=2) + '\n')
            elif args.operation == 'collect':
                result = {'archive': str(collect_source_bundle(artifact, json.loads(args.inventory.read_text()), args.output_dir))}
            else:
                result = assess_distribution(artifact, args.output_dir)
        print(json.dumps(result, indent=2))
        return 2 if result.get('status') == 'blocked' else 0
    except (ValueError, OSError, TypeError) as error:
        parser.exit(2, str(error) + '\n')


if __name__ == '__main__':
    raise SystemExit(main())
