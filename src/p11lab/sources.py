"""Hash-checked acquisition with retained original archives and ordered patches."""
from contextlib import ExitStack
import hashlib
from importlib.resources import as_file
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
from urllib.request import urlopen

from .catalog import locked_asset, validate_build_inputs


class SourceError(ValueError):
    """Source resolution did not satisfy the declared immutable inputs."""


def checksum(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def _command(argv, *, cwd=None):
    result = subprocess.run(argv, cwd=cwd, capture_output=True, text=True)
    if result.returncode:
        raise SourceError(f'source checkout/revision or patch operation failed: {result.stderr.strip()}')
    return result.stdout.strip()


def acquire_source(source: dict, output_dir: Path) -> dict:
    """Acquire one source. Callers validate public URL/pin schemas beforehand.

    file URLs are supported by this low-level primitive for offline acquisitions;
    catalogue-driven resolve_sources requires the validated public HTTPS URL.
    Each attempt uses a fresh directory; no failed or stale checkout is reused.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=False)
    checkout = output_dir / 'checkout'
    archive = output_dir / 'source.tar'
    if source['kind'] == 'git':
        repo = output_dir / 'git'
        _command(['git', 'init', '-q', str(repo)])
        _command(['git', '-C', str(repo), 'fetch', '--depth=1', '--no-tags', source['url'], source['revision']])
        actual = _command(['git', '-C', str(repo), 'rev-parse', 'FETCH_HEAD^{commit}'])
        if actual != source['revision']:
            raise SourceError('source checkout revision mismatch')
        _command(['git', '-C', str(repo), 'archive', '--format=tar', '--output=' + str(archive.resolve()), actual])
    else:
        with urlopen(source['url'], timeout=60) as response, archive.open('wb') as stream:
            while chunk := response.read(1024 * 1024):
                stream.write(chunk)
        if checksum(archive) != source['sha256']:
            raise SourceError('source archive checksum mismatch')
    if source.get('archive_sha256') and checksum(archive) != source['archive_sha256']:
        raise SourceError('git source archive checksum mismatch')
    checkout.mkdir()
    try:
        with tarfile.open(archive) as contents:
            contents.extractall(checkout, filter='data')
    except (tarfile.TarError, OSError) as error:
        raise SourceError('unsafe or invalid source archive') from error
    return {'source': source, 'archive': str(archive), 'sha256': checksum(archive), 'checkout': str(checkout)}


def apply_patches(checkout: Path, patches: list[Path]) -> None:
    """A failed declared patch is fatal; never silently skip or reorder it."""
    for patch in patches:
        _command(['patch', '--batch', '--forward', '-p1', '-i', str(Path(patch).resolve())], cwd=checkout)


def resolve_sources(spec: dict, *, output_dir: Path | None = None) -> dict:
    """Resolve a packaged locked spec; retain inputs for source distribution.

    Returned paths are acquisition evidence, not portable runtime dependencies.
    No source is qualified after a checksum, revision or patch failure.
    """
    validate_build_inputs(spec)
    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix='p11lab-sources-'))
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    lock = spec['lock']
    acquired = [acquire_source(source, output_dir / f'source-{index}')
                for index, source in enumerate(lock['sources'] + lock['dependencies'])]
    with ExitStack() as stack:
        patches = [stack.enter_context(as_file(locked_asset(spec['id'], patch))) for patch in lock['patches']]
        if patches:
            apply_patches(Path(acquired[0]['checkout']), patches)
    result = {'schema_version': 1, 'sources': acquired[:len(lock['sources'])],
              'dependencies': acquired[len(lock['sources']):], 'patches': lock['patches']}
    (output_dir / 'resolved-sources.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
