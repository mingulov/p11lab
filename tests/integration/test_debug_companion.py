"""Opt-in exact runtime/export acceptance; host binutils are test tools only."""
import json
import os
from pathlib import Path
import subprocess

import pytest

IMAGES = json.loads(os.environ.get('P11LAB_TEST_DEBUG_BUILDS', '{}'))
pytestmark = pytest.mark.skipif(not IMAGES, reason='explicit runtime/debug build outputs required')


@pytest.mark.parametrize('image,build', IMAGES.items())
def test_runtime_debug_sections_are_external(image, build, tmp_path):
    for path in ('/usr/local/lib/p11lab/libsofthsm2.so', '/usr/local/bin/softhsm2-util'):
        binary = subprocess.check_output(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat', image, path])
        elf = tmp_path / Path(path).name
        elf.write_bytes(binary)
        sections = subprocess.check_output(['readelf', '-SW', str(elf)], text=True)
        assert '.debug_info' not in sections
        assert '.symtab' in sections
        assert '.gnu_debuglink' in sections
    absent = subprocess.run(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'sh', image, '-c', 'find / -name "*.debug" 2>/dev/null'], capture_output=True, text=True, check=True)
    assert absent.stdout == ''


@pytest.mark.parametrize('image,build', IMAGES.items())
def test_external_companion_is_exactly_matched(image, build):
    from p11lab.debug import verify_debug_files
    output = Path(build)
    receipt = json.loads((output / 'artifact.json').read_text())
    assert receipt['role'] == 'debug-companion'
    assert receipt['matched_runtime']['reference'] == image
    runtime = {name: subprocess.check_output(['docker', 'run', '--rm', '--network', 'none', '--entrypoint', 'cat', image, path])
               for name, path in [('libsofthsm2.so', '/usr/local/lib/p11lab/libsofthsm2.so'), ('softhsm2-util', '/usr/local/bin/softhsm2-util')]}
    assert verify_debug_files(output / 'files', runtime) == receipt['binaries']
