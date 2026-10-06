"""Separate unreviewed binary debug exports bound to inspected runtime bytes."""
from pathlib import Path
import hashlib
import json
import re
import struct
import zlib

from .build import BuildError, _checked, runtime_inputs, validate_context
from .identity import artifact_key


def _sections(binary: bytes) -> dict[str, bytes]:
    """Read the selected runtime's ELF64 little-endian section data without tools."""
    try:
        if binary[:6] != b'\x7fELF\x02\x01':
            raise ValueError('expected ELF64 little-endian')
        offset = struct.unpack_from('<Q', binary, 40)[0]
        size, count, names = struct.unpack_from('<HHH', binary, 58)
        if size != 64 or not 0 < names < count or offset + size * count > len(binary):
            raise ValueError('invalid ELF section table')
        headers = [struct.unpack_from('<IIQQQQIIQQ', binary, offset + size * i) for i in range(count)]
        strings = headers[names]
        labels = binary[strings[4]:strings[4] + strings[5]]
        result = {}
        for header in headers:
            label = labels[header[0]:].split(b'\0', 1)[0].decode('ascii')
            if header[1] == 8:  # SHT_NOBITS has no file payload, including debug copies.
                continue
            start, length = header[4:6]
            if start + length > len(binary) or label in result:
                raise ValueError('invalid ELF section bounds/name')
            result[label] = binary[start:start + length]
        return result
    except (ValueError, UnicodeError, struct.error, IndexError) as error:
        raise BuildError('invalid debug/runtime ELF: ' + str(error)) from error


def _build_id(sections):
    note = sections.get('.note.gnu.build-id', b'')
    try:
        names, length, kind = struct.unpack_from('<III', note)
        start = 12 + ((names + 3) & ~3)
        if kind != 3 or note[12:12 + names] != b'GNU\0' or not length or start + length > len(note):
            raise ValueError('missing GNU build ID')
        return note[start:start + length].hex()
    except (struct.error, ValueError) as error:
        raise BuildError('missing/invalid GNU build ID') from error


def verify_debug_files(directory: Path, runtime_binaries: dict[str, bytes]) -> list[dict]:
    """Reject incomplete/wrong debug exports; runtime bytes come from the exact image."""
    records = []
    seen = set()
    try:
        for row in (directory / 'binaries.tsv').read_text().splitlines():
            name, original_sha, original_size, shipped_sha, shipped_size, debug_sha, debug_size, build_id = row.split('\t')
            if name not in runtime_binaries or name in seen or not re.fullmatch(r'[a-zA-Z0-9._-]+', name) or name in {'.', '..'}:
                raise ValueError('unexpected/duplicate binary')
            seen.add(name)
            if not all(re.fullmatch(r'[0-9a-f]{64}', value) for value in (original_sha, shipped_sha, debug_sha)):
                raise ValueError('invalid binary hash')
            if not re.fullmatch(r'[0-9a-f]+', build_id):
                raise ValueError('invalid build ID')
            runtime = runtime_binaries[name]
            debug = (directory / (name + '.debug')).read_bytes()
            if hashlib.sha256(runtime).hexdigest() != shipped_sha or len(runtime) != int(shipped_size):
                raise ValueError('shipped binary hash/size mismatch')
            if hashlib.sha256(debug).hexdigest() != debug_sha or len(debug) != int(debug_size):
                raise ValueError('debug binary hash/size mismatch')
            shipped_sections, debug_sections = _sections(runtime), _sections(debug)
            if any(n.startswith(('.debug_', '.zdebug_')) for n in shipped_sections) or '.symtab' not in shipped_sections:
                raise ValueError('runtime still contains debug sections or lost static symbols')
            if '.debug_info' not in debug_sections:
                raise ValueError('companion lacks debug information')
            if _build_id(shipped_sections) != build_id or _build_id(debug_sections) != build_id:
                raise ValueError('build ID mismatch')
            link = shipped_sections['.gnu_debuglink']
            link_name = link.split(b'\0', 1)[0].decode('ascii')
            crc_offset = (len(link_name) + 4) & ~3
            crc = struct.unpack_from('<I', link, crc_offset)[0]
            if link_name != name + '.debug' or crc != zlib.crc32(debug):
                raise ValueError('GNU debuglink filename/CRC mismatch')
            if int(original_size) <= 0:
                raise ValueError('invalid original size')
            records.append({'name': name, 'original_sha256': original_sha, 'original_size_bytes': int(original_size),
                'shipped_sha256': shipped_sha, 'shipped_size_bytes': int(shipped_size), 'debug_sha256': debug_sha,
                'debug_size_bytes': int(debug_size), 'build_id': build_id, 'debuglink': link_name,
                'debuglink_crc32': f'{crc:08x}'})
        if seen != set(runtime_binaries):
            raise ValueError('incomplete binary roster')
    except (OSError, ValueError, KeyError, UnicodeError, struct.error) as error:
        raise BuildError('debug companion is not matched: ' + str(error)) from error
    return records


def export_debug_companion(spec: dict, artifact, build_dir: Path, output_dir: Path) -> dict:
    """Export a cached scratch target; emit admission evidence only after exact readback."""
    from dataclasses import asdict
    import os
    import subprocess
    import tarfile
    build_dir, output_dir = Path(build_dir).resolve(), Path(output_dir).resolve()
    receipt = json.loads((build_dir / 'artifact.json').read_text())
    if receipt['artifact'] != asdict(artifact) or receipt['build_key'] != artifact_key('runtime', runtime_inputs(spec)):
        raise BuildError('debug export does not match the runtime build inputs')
    declared = receipt['context_manifest']
    context = build_dir / 'context'
    validate_context(context, declared)
    output_dir.mkdir(parents=True, exist_ok=False)
    command = ['docker', 'build', '--provenance=false', '--progress=plain', '--platform', artifact.platform,
        '--build-arg', 'BASE_IMAGE=' + spec['lock']['base_images'][0], '--target', 'debug-companion',
        '--output', 'type=local,dest=' + str(output_dir / 'files'), str(context)]
    with (output_dir / 'build.log').open('w') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
            env=os.environ | {'BUILDX_GIT_INFO': 'false', 'BUILDX_METADATA_PROVENANCE': 'disabled'})
    if result.returncode:
        raise BuildError('debug export failed; no matched companion receipt emitted')
    inspected = json.loads(_checked(['docker', 'image', 'inspect', artifact.reference], output_dir).stdout)[0]
    if inspected['Id'] != artifact.reference:
        raise BuildError('runtime image readback identity mismatch')
    binaries = {}
    for name, path in [('libsofthsm2.so', '/usr/local/lib/p11lab/libsofthsm2.so'), ('softhsm2-util', '/usr/local/bin/softhsm2-util')]:
        try:
            binaries[name] = subprocess.check_output(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat', artifact.reference, path])
        except subprocess.CalledProcessError as error:
            raise BuildError('runtime binary readback failed; no matched companion receipt emitted') from error
    records = verify_debug_files(output_dir / 'files', binaries)
    upstream_license = output_dir / 'files/LICENSE.softhsm2'
    expected_license = spec['lock']['sources'][0]['license_evidence'][0]['sha256']
    if hashlib.sha256(upstream_license.read_bytes()).hexdigest() != expected_license:
        raise BuildError('debug export license differs from locked source evidence')
    from .catalog import package_data
    (output_dir / 'files/LICENSE.p11lab').write_bytes(package_data('runtime/LICENSE').read_bytes())
    (output_dir / 'files/provenance.json').write_text(json.dumps({'role': 'debug-companion', 'admission': 'unreviewed',
        'matched_runtime': asdict(artifact), 'build_key': receipt['build_key'], 'sources': spec['lock']['sources'],
        'patches': spec['lock']['patches'], 'toolchain': spec['lock']['toolchain'], 'binaries': records,
        'source_reference': 'Requires the exact runtime source/license companion; this binary artifact is not a source-only archive.'}, indent=2) + '\n')
    archive = output_dir / 'debug-companion.tar.gz'
    with tarfile.open(archive, 'w:gz') as out:
        for path in sorted((output_dir / 'files').iterdir()):
            out.add(path, arcname=path.name)
    result = {'schema_version': 1, 'role': 'debug-companion', 'admission': 'unreviewed', 'matched_runtime': asdict(artifact),
        'build_key': receipt['build_key'], 'binaries': records,
        'artifact': {'kind': 'bundle', 'reference': str(archive), 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'platform': artifact.platform},
        'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
        'archive_size_bytes': archive.stat().st_size, 'command': command,
        'files': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((output_dir / 'files').iterdir())}}
    (output_dir / 'artifact.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
