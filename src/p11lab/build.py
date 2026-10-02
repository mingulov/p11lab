"""Build from closed package-resource contexts; local references bind inspected engine image IDs."""
from pathlib import Path

from .sources import checksum


class BuildError(ValueError):
    """A build or its inspected artifact does not match declared inputs."""


def _checked(argv: list[str], output_dir: Path):
    """Translate inspected-artifact readback failures into the handled CLI path."""
    import shlex
    import subprocess
    try:
        return subprocess.run(argv, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as error:
        raise BuildError(f"post-build command failed ({error.returncode}): {shlex.join(argv)}; "
                         f"{error.stderr.strip()}; attempt retained at {output_dir}") from error


def validate_context(context: Path, declared: dict[str, str]) -> None:
    actual = set()
    for path in Path(context).rglob('*'):
        if path.is_symlink():
            raise BuildError('undeclared symlink in build context')
        if path.is_file():
            actual.add(path.relative_to(context).as_posix())
    if actual != set(declared):
        raise BuildError('undeclared or missing build context files: ' + str(actual ^ set(declared)))
    for name, expected in declared.items():
        if checksum(Path(context) / name) != expected:
            raise BuildError('build context checksum mismatch: ' + name)


def inventory_text(packages: list[dict]) -> str:
    return ''.join(sorted('\t'.join(str(p[k]) for k in ('name', 'version', 'architecture', 'source_package', 'source_version')) + '\n' for p in packages))


def verify_inventory(actual: str, expected: list[dict]) -> None:
    if actual != inventory_text(expected):
        raise BuildError('actual package/source inventory differs from locked inputs')


def runtime_inputs(spec: dict) -> dict:
    import hashlib
    import json
    from .catalog import packaged_asset
    lock = spec['lock']
    adapters = [{'scope': a.get('scope', 'provider'), 'path': a['path'], 'sha256': a['sha256']}
                for a in lock['assets'] if a['role'] in {'adapter', 'adapter-common', 'notice'}]
    adapter = hashlib.sha256(json.dumps(adapters, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {key: lock[key] for key in ('sources', 'dependencies', 'patches', 'base_images', 'packages', 'toolchain', 'features')} | {
        'recipe': hashlib.sha256(json.dumps([a for a in lock['assets'] if a['role'] in {'recipe', 'build-helper'}], sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
        'adapter': adapter, 'metadata': hashlib.sha256(packaged_asset(spec['id'], 'provider.json').read_bytes()).hexdigest(),
        'platform': spec['runtime_platforms'][0],
        'features': lock['features'] | {'apt_snapshot': lock['apt_snapshot'], 'signed_index_inputs': lock['signed_index_inputs']},
    }


def prepare_context(spec: dict, resolved: dict, context: Path) -> dict[str, str]:
    """Generate only a closed list of sealed assets and explicit build inputs."""
    import io
    import json
    import tarfile
    from .catalog import locked_asset, packaged_asset, validate_build_inputs, _relative
    from .identity import artifact_key, public_identity
    validate_build_inputs(spec)
    lock = spec['lock']
    if len(resolved['sources']) != 1 or resolved['dependencies']:
        raise BuildError('this runtime recipe requires exactly one primary source and no source dependencies')
    context.mkdir(parents=True, exist_ok=False)
    declared = {}
    for asset in lock['assets']:
        name = asset.get('context_path', asset['path'])
        _relative(name)
        if name in declared:
            raise BuildError('duplicate declared context destination')
        path = context / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(locked_asset(spec['id'], asset).read_bytes())
        declared[name] = asset['sha256']
    acquired = resolved['sources'][0]
    if checksum(acquired['archive']) != acquired['sha256']:
        raise BuildError('acquired source archive checksum mismatch')
    # Keep the original upstream archive; the build tar contains the patch result.
    # Sources are freshly acquired and patched by resolve_sources for each build.
    source_tar = context / 'source.tar'
    with tarfile.open(source_tar, 'w') as out:
        for path in sorted(Path(acquired['checkout']).iterdir()):
            out.add(path, arcname=path.name)
    inputs = runtime_inputs(spec)
    identity = public_identity('runtime', inputs)
    key = artifact_key('runtime', inputs)
    snapshot = lock['apt_snapshot']
    generated = {
        'signed-index-inputs.sha256': ''.join(r['sha256'] + '  ' + r['filename'] + '\n' for r in lock['signed_index_inputs']).encode(),
        'provider.json': packaged_asset(spec['id'], 'provider.json').read_bytes(),
        'runtime-id': (key + '\n').encode(),
        'build-inputs.json': (json.dumps(identity, sort_keys=True, indent=2) + '\n').encode(),
        'source.sha256': (checksum(source_tar) + '  source.tar\n').encode(),
        'builder-requested.txt': ('\n'.join(lock['builder_requested']) + '\n').encode(),
        'base-packages.tsv': inventory_text([p for p in lock['packages'] if p['phase'] == 'runtime']).encode(),
        'builder-packages.tsv': inventory_text(lock['packages']).encode(),
        'snapshot.sources': (f'Types: deb deb-src\nURIs: http://snapshot.debian.org/archive/debian/{snapshot}/\nSuites: trixie trixie-updates\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\nCheck-Valid-Until: no\n\nTypes: deb deb-src\nURIs: http://snapshot.debian.org/archive/debian-security/{snapshot}/\nSuites: trixie-security\nComponents: main\nSigned-By: /usr/share/keyrings/debian-archive-keyring.pgp\nCheck-Valid-Until: no\n').encode(),
    }
    for name, content in generated.items():
        if name in declared:
            raise BuildError('generated context input conflicts with package asset')
        (context / name).write_bytes(content)
        declared[name] = checksum(context / name)
    declared['source.tar'] = checksum(source_tar)
    validate_context(context, declared)
    return declared


def build_artifact(spec: dict, role: str, output_dir: Path):
    """Build a local runtime and retain exact inspected inventory and input receipts.

    The reference binds Docker inspect Id; engine storage may use a config or
    index digest. It is never advertised as a published registry reference.
    Registry publication and digest-bound source/license admission are separate.
    """
    from dataclasses import asdict
    import json
    import subprocess
    import os
    import re
    from .catalog import validate_build_inputs
    from .identity import artifact_key
    from .models import ArtifactRef
    from .sources import resolve_sources
    if role != 'runtime':
        raise BuildError('this recipe supports only the runtime role')
    validate_build_inputs(spec)
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    # Never leave an earlier successful receipt looking like this attempt's result.
    if (output_dir / 'artifact.json').exists() or (output_dir / 'context').exists():
        raise BuildError('build output must be a fresh attempt directory')
    resolved = resolve_sources(spec, output_dir=output_dir / 'sources')
    declared = prepare_context(spec, resolved, output_dir / 'context')
    (output_dir / 'context-manifest.json').write_text(json.dumps(declared, indent=2) + '\n')
    key = artifact_key('runtime', runtime_inputs(spec))
    command = ['docker', 'build', '--provenance=false', '--progress=plain', '--platform', spec['runtime_platforms'][0], '--network', 'default',
               '--build-arg', 'BASE_IMAGE=' + spec['lock']['base_images'][0],
               '--label', 'org.p11lab.build-key=' + key,
               '--label', 'org.p11lab.source-revision=' + spec['lock']['sources'][0]['revision'],
               '--metadata-file', str(output_dir / 'build-metadata.json'),
               '--iidfile', str(output_dir / 'image-id'), str(output_dir / 'context')]
    validate_context(output_dir / 'context', declared)
    with (output_dir / 'build.log').open('w') as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT,
                                env=os.environ | {'BUILDX_GIT_INFO': 'false', 'BUILDX_METADATA_PROVENANCE': 'disabled'})
    if result.returncode:
        raise BuildError('runtime build failed; see build.log (no artifact receipt emitted)')
    image_id = (output_dir / 'image-id').read_text().strip()
    inspected = json.loads(_checked(['docker', 'image', 'inspect', image_id], output_dir).stdout)[0]
    if inspected['Id'] != image_id or inspected['Os'] + '/' + inspected['Architecture'] != spec['runtime_platforms'][0]:
        raise BuildError('built image identity/platform mismatch')
    build_metadata = json.loads((output_dir / 'build-metadata.json').read_text())
    reported_config_digests = sorted(set(re.findall(r'exporting config (sha256:[0-9a-f]{64})', (output_dir / 'build.log').read_text())))
    verify_build_metadata(build_metadata, image_id, spec['runtime_platforms'][0])
    inventories = {}
    for phase in ('base', 'builder', 'runtime'):
        result = _checked(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat', image_id,
                           f'/usr/share/p11lab/build/actual-{phase}.tsv'], output_dir)
        expected = spec['lock']['packages'] if phase == 'builder' else [p for p in spec['lock']['packages'] if p['phase'] == 'runtime']
        verify_inventory(result.stdout, expected)
        inventories[phase] = result.stdout
        (output_dir / f'actual-{phase}.tsv').write_text(result.stdout)
    index_receipt = _checked(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat', image_id, '/usr/share/p11lab/build/actual-signed-indexes.sha256'], output_dir).stdout
    verify_index_inventory(index_receipt, spec['lock']['signed_index_inputs'])
    (output_dir / 'actual-signed-indexes.sha256').write_text(index_receipt)
    artifact = ArtifactRef('docker-local', image_id, image_id.removeprefix('sha256:'), spec['runtime_platforms'][0])
    receipt = {'schema_version': 1, 'artifact': asdict(artifact), 'build_key': key,
               'docker_reported_size_bytes': inspected['Size'],
               'local_engine_descriptor': inspected.get('Descriptor'),
               'actual_config_digest': build_metadata.get('containerimage.config.digest'),
               'reported_config_digests': reported_config_digests,
               'config_digest_observation_status': 'Log observations are unverified; not used for admission or content equality.',
               'build_output_descriptor': build_metadata.get('containerimage.descriptor'),
               'build_output_digest': build_metadata['containerimage.digest'], 'base_images': spec['lock']['base_images'],
               'resolved_sources': resolved, 'context_manifest': declared,
               'command': command, 'admission': 'unreviewed', 'bit_for_bit_reproducibility': 'not asserted'}
    (output_dir / 'image-inspect.json').write_text(json.dumps(inspected, indent=2) + '\n')
    (output_dir / 'artifact.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return artifact


def verify_index_inventory(actual: str, expected: list[dict]) -> None:
    try:
        resolved = {row.split()[1]: row.split()[0] for row in actual.splitlines()}
    except IndexError as error:
        raise BuildError('invalid signed index receipt') from error
    if resolved != {row['filename']: row['sha256'] for row in expected}:
        raise BuildError('actual signed index fingerprints differ from locked inputs')


def verify_build_metadata(metadata: dict, engine_id: str, platform: str | None = None) -> None:
    import re
    config = metadata.get('containerimage.config.digest')
    if config is not None and (not isinstance(config, str) or not re.fullmatch(r'sha256:[0-9a-f]{64}', config)):
        raise BuildError('build metadata lacks the actual config digest')
    # Classic engines report the config digest; current containerd engines may
    # report BuildKit's output index. Both are local IDs, with metadata retained.
    if engine_id not in {metadata.get('containerimage.digest'), config}:
        raise BuildError('build metadata conflicts with the local engine image identity')
    descriptor = metadata.get('containerimage.descriptor')
    if descriptor is not None:
        if descriptor.get('digest') != metadata.get('containerimage.digest'):
            raise BuildError('build output descriptor digest mismatch')
        selected = descriptor.get('platform')
        if selected and platform and selected.get('os', '') + '/' + selected.get('architecture', '') != platform:
            raise BuildError('build metadata platform differs from selected runtime')
