"""NSS must load all six NSPR inputs as inert, validated data."""
import re
import shlex
import subprocess

import pytest

from p11lab.catalog import package_data


def load_manifest(directory, content):
    manifest = directory / 'manifest.txt'
    manifest.write_text(content)
    helper = package_data('providers/nss/Dockerfile').parent / 'nspr-manifest.sh'
    if helper.is_file():
        command = f'. {shlex.quote(str(helper))}; p11lab_nspr_manifest {shlex.quote(str(manifest))}'
    else:
        # Exercise the BASE recipe verbatim for red evidence, before its helper exists.
        recipe = package_data('providers/nss/Dockerfile').read_text()
        command = re.search(r'RUN (grep.*?) \\\n && curl', recipe, re.S)[1]
        command = command.replace('/tmp/nspr-manifest.txt', shlex.quote(str(manifest)))
    command += ' || exit $?\nprintf "%s\\n" "${NSPR_TAG-}" "${NSPR_REVISION-}" "${NSPR_VERSION-}" "${NSPR_URL-}" "${NSPR_SHA256-}" "${NSPR_SIZE-}"\n'
    return subprocess.run(['sh', '-ec', command], capture_output=True, text=True, timeout=30)


@pytest.mark.parametrize('channel,version', [('release', '4.40'), ('rolling', '4.41 Beta')])
def test_exact_nspr_versions_survive_manifest_loading(tmp_path, channel, version):
    result = load_manifest(tmp_path, package_data(f'providers/nss/nspr-{channel}.txt').read_text())
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines()[2] == version
    assert result.stderr == ''


@pytest.mark.parametrize('change', ['duplicate', 'unknown', 'unquoted-version', 'blank', 'empty', 'command'])
def test_nspr_manifest_rejects_invalid_or_executable_data(tmp_path, change):
    content = package_data('providers/nss/nspr-release.txt').read_text()
    if change == 'duplicate':
        content = content.replace('NSPR_SIZE=1009773', 'NSPR_TAG=duplicate')
    elif change == 'unknown':
        content = content.replace('NSPR_SIZE=1009773', 'OTHER_SIZE=1009773')
    elif change == 'unquoted-version':
        content = content.replace('NSPR_VERSION=4.40', 'NSPR_VERSION=4.41 Beta')
    elif change == 'blank':
        content += '\n'
    elif change == 'empty':
        content = content.replace('NSPR_VERSION=4.40', 'NSPR_VERSION=')
    else:
        content = content.replace('NSPR_VERSION=4.40', f'NSPR_VERSION=$(touch {tmp_path}/EXECUTED)')
    result = load_manifest(tmp_path, content)
    assert result.returncode != 0, result.stdout + result.stderr
    assert not (tmp_path / 'EXECUTED').exists()
