"""External debug companions must bind exact shipped bytes, not just a source pin."""
import json
from pathlib import Path
import subprocess

import pytest

from p11lab.catalog import packaged_asset


@pytest.fixture
def split_fixture(tmp_path):
    original = tmp_path / 'original'
    original.mkdir()
    source = tmp_path / 'example.c'
    source.write_text('int preserved_symbol(int x) { return x + 7; }\nint main(void) { return preserved_symbol(2); }\n')
    subprocess.run(['gcc', '-g', '-Wl,--build-id', str(source), '-o', str(original / 'example')], check=True)
    shipped = tmp_path / 'shipped'
    debug = tmp_path / 'debug'
    subprocess.run(['sh', str(packaged_asset('softhsm2', 'split-debug.sh')), str(original), str(shipped), str(debug), 'example'], check=True)
    return original, shipped, debug


def test_split_preserves_symbols_and_exports_matched_debug(split_fixture):
    from p11lab.debug import verify_debug_files
    original, shipped, debug = split_fixture
    record = verify_debug_files(debug, {'example': (shipped / 'example').read_bytes()})
    assert record[0]['original_sha256'] != record[0]['shipped_sha256']
    assert record[0]['debuglink'] == 'example.debug'
    assert record[0]['original_size_bytes'] > record[0]['shipped_size_bytes']
    for option in ('--defined-only', '-D'):
        def symbols(path):
            return subprocess.check_output(['nm', option, str(path)])
        assert symbols(original / 'example') == symbols(shipped / 'example')
    assert '.debug_info' not in subprocess.check_output(['readelf', '-SW', str(shipped / 'example')], text=True)
    assert '.debug_info' in subprocess.check_output(['readelf', '-SW', str(debug / 'example.debug')], text=True)


@pytest.mark.parametrize('mutation', ['debug-bytes', 'runtime-bytes', 'missing-debug', 'build-id', 'original-hash'])
def test_wrong_companion_cannot_be_matched(split_fixture, mutation):
    from p11lab.build import BuildError
    from p11lab.debug import verify_debug_files
    _, shipped, debug = split_fixture
    payload = (shipped / 'example').read_bytes()
    if mutation == 'debug-bytes':
        with (debug / 'example.debug').open('ab') as out:
            out.write(b'wrong')
    elif mutation == 'runtime-bytes':
        payload += b'wrong'
    elif mutation == 'missing-debug':
        (debug / 'example.debug').unlink()
    else:
        manifest = (debug / 'binaries.tsv').read_text().split('\t')
        manifest[7 if mutation == 'build-id' else 1] = 'a' * 40 if mutation == 'build-id' else 'not-a-digest'
        (debug / 'binaries.tsv').write_text('\t'.join(manifest))
    with pytest.raises(BuildError):
        verify_debug_files(debug, {'example': payload})


def test_build_helper_changes_runtime_identity():
    from copy import deepcopy
    from p11lab.build import runtime_inputs
    from p11lab.catalog import load_environment
    from p11lab.identity import artifact_key
    first = load_environment('softhsm2', 'release')
    second = deepcopy(first)
    helper = next(asset for asset in second['lock']['assets'] if asset['role'] == 'build-helper')
    helper['sha256'] = 'b' * 64
    assert artifact_key('runtime', runtime_inputs(first)) != artifact_key('runtime', runtime_inputs(second))


def test_forged_manifest_cannot_hide_debuglink_crc_mismatch(split_fixture):
    import hashlib
    from p11lab.build import BuildError
    from p11lab.debug import verify_debug_files
    _, shipped, debug = split_fixture
    # Appending bytes leaves the ELF/build ID valid, but changes GNU's debug CRC.
    altered = (debug / 'example.debug').read_bytes() + b'wrong'
    (debug / 'example.debug').write_bytes(altered)
    manifest = (debug / 'binaries.tsv').read_text().rstrip('\n').split('\t')
    manifest[5], manifest[6] = hashlib.sha256(altered).hexdigest(), str(len(altered))
    (debug / 'binaries.tsv').write_text('\t'.join(manifest) + '\n')
    with pytest.raises(BuildError, match='debuglink.*CRC'):
        verify_debug_files(debug, {'example': (shipped / 'example').read_bytes()})


def test_incomplete_expected_binary_roster_is_rejected(split_fixture):
    from p11lab.build import BuildError
    from p11lab.debug import verify_debug_files
    _, shipped, debug = split_fixture
    binary = (shipped / 'example').read_bytes()
    with pytest.raises(BuildError, match='incomplete binary roster'):
        verify_debug_files(debug, {'example': binary, 'omitted': binary})
