"""Proxy daemon branch: provider delegation contracts without Docker.

The daemon must carry full provider configuration by delegating to the
provider adapter instead of hardcoding one provider. These tests execute
a mechanical path-redirected copy of the real script against stub
binaries, and pin the exact delegation line plus the absence of
provider-specific configuration in the shared script.
"""
import os
from pathlib import Path
import subprocess

import pytest

from p11lab.catalog import package_data


DELEGATION_LINE = 'exec /usr/local/bin/p11lab-provider exec -- /usr/local/bin/pkcs11-proxy-ng "$2"'


def entrypoint_text():
    return package_data('runtime/proxy-entrypoint.sh').read_text()


def redirected_script(directory):
    """Copy the real script with only its absolute paths aimed at stubs."""
    text = entrypoint_text()
    text = text.replace('. /usr/share/p11lab/common.sh',
                        package_data('runtime/common.sh').read_text())
    for original, redirect in (
            ('/usr/local/bin/p11lab-provider', str(directory / 'stub-provider')),
            ('/usr/local/bin/pkcs11-proxy-ng', str(directory / 'stub-proxy')),
            ('/run/p11lab-tls', str(directory / 'tls')),
            # Legacy provider control path; absent once no provider config is hardcoded.
            ('/run/p11lab', str(directory / 'control'))):
        if original == '/run/p11lab' and original not in text:
            continue
        assert original in text, original
        text = text.replace(original, redirect)
    script = directory / 'p11lab-proxy'
    script.write_text(text)
    script.chmod(0o755)
    return script


def write_tls(directory):
    tls = directory / 'tls'
    tls.mkdir()
    for name in ('ca.crt', 'server.crt'):
        (tls / name).write_text('certificate')
        (tls / name).chmod(0o644)
    (tls / 'server.key').write_text('key')
    (tls / 'server.key').chmod(0o600)
    config = directory / 'proxy.toml'
    config.write_text('[backend]\n')
    return config


def run_daemon(script, config, extra_env=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('SOFTHSM', 'FHSM_'))}
    env.update(extra_env or {})
    return subprocess.run(['sh', str(script), 'daemon', str(config)],
                          capture_output=True, text=True, timeout=60, env=env)


def test_daemon_delegates_to_provider_adapter(tmp_path):
    """A non-SoftHSM provider's adapter exports must reach the proxy."""
    script = redirected_script(tmp_path)
    config = write_tls(tmp_path)
    (tmp_path / 'stub-provider').write_text(
        '#!/bin/sh\nset -eu\n'
        '[ "$1" = exec ] && [ "$2" = -- ] || { echo "expected exec --" >&2; exit 1; }\n'
        'shift 2\n'
        'export STUB_PROVIDER_ENV=from-adapter\n'
        'exec "$@"\n')
    (tmp_path / 'stub-provider').chmod(0o755)
    (tmp_path / 'stub-proxy').write_text(
        '#!/bin/sh\nset -eu\n'
        f'printf "%s\\n" "$@" > "{tmp_path}/proxy-argv"\n'
        'printf "%s\\n" "${STUB_PROVIDER_ENV-unset}" "${SOFTHSM2_CONF-unset}" > '
        f'"{tmp_path}/proxy-env"\n')
    (tmp_path / 'stub-proxy').chmod(0o755)
    result = run_daemon(script, config)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'proxy-argv').read_text().splitlines() == [str(config)]
    assert (tmp_path / 'proxy-env').read_text().splitlines() == ['from-adapter', 'unset']
    control = tmp_path / 'control'
    assert not control.exists() or list(control.iterdir()) == []


def test_daemon_relays_adapter_configuration_byte_identically(tmp_path):
    """SoftHSM behavior: the proxy sees exactly the adapter-written conf."""
    script = redirected_script(tmp_path)
    config = write_tls(tmp_path)
    (tmp_path / 'stub-provider').write_text(
        '#!/bin/sh\nset -eu\n'
        '[ "$1" = exec ] && [ "$2" = -- ] || { echo "expected exec --" >&2; exit 1; }\n'
        'shift 2\n'
        f'mkdir -p "{tmp_path}/control"\n'
        f'printf "%s\\n" "directories.tokendir = /tokens" "objectstore.backend = file" > "{tmp_path}/control/softhsm2.conf"\n'
        f'export SOFTHSM2_CONF="{tmp_path}/control/softhsm2.conf"\n'
        'exec "$@"\n')
    (tmp_path / 'stub-provider').chmod(0o755)
    (tmp_path / 'stub-proxy').write_text(
        '#!/bin/sh\nset -eu\n'
        f'cat "$SOFTHSM2_CONF" > "{tmp_path}/proxy-observed-conf"\n'
        f'printf "%s\\n" "$SOFTHSM2_CONF" > "{tmp_path}/proxy-observed-var"\n')
    (tmp_path / 'stub-proxy').chmod(0o755)
    result = run_daemon(script, config)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / 'proxy-observed-conf').read_text().splitlines() == [
        'directories.tokendir = /tokens', 'objectstore.backend = file']
    assert (tmp_path / 'proxy-observed-var').read_text().splitlines() == [
        str(tmp_path / 'control' / 'softhsm2.conf')]


def test_daemon_delegation_line_is_pinned():
    assert DELEGATION_LINE in [line.strip() for line in entrypoint_text().splitlines()]


def test_daemon_carries_no_provider_specific_configuration():
    code = '\n'.join(line for line in entrypoint_text().splitlines()
                     if not line.strip().startswith('#'))
    for fragment in ('SOFTHSM', 'softhsm', 'FHSM_', 'NSS_', 'daemon-config', 'control'):
        assert fragment not in code, fragment


def test_daemon_rejects_non_absolute_config(tmp_path):
    script = redirected_script(tmp_path)
    result = run_daemon(script, Path('relative/proxy.toml'))
    assert result.returncode != 0
    assert 'absolute path' in result.stderr


def test_daemon_rejects_missing_config(tmp_path):
    script = redirected_script(tmp_path)
    write_tls(tmp_path)
    result = run_daemon(script, tmp_path / 'absent.toml')
    assert result.returncode != 0
    assert 'readable regular file' in result.stderr


def marker_stubs(directory, status=0):
    for name in ('provider', 'proxy'):
        script = directory / ('stub-' + name)
        script.write_text('#!/bin/sh\n'
                          f'touch "{directory}/{name}-called"\n'
                          f'echo {name}-diagnostic >&2\n'
                          f'exit {status}\n')
        script.chmod(0o755)


@pytest.mark.parametrize('invalid', ['missing-ca', 'linked-certificate', 'writable-certificate',
                                   'readable-key', 'linked-key'])
def test_invalid_tls_fails_before_provider_adapter(tmp_path, invalid):
    script = redirected_script(tmp_path)
    config = write_tls(tmp_path)
    marker_stubs(tmp_path)
    tls = tmp_path / 'tls'
    if invalid == 'missing-ca':
        (tls / 'ca.crt').unlink()
    elif invalid == 'linked-certificate':
        (tls / 'server.crt').unlink()
        (tls / 'server.crt').symlink_to(tls / 'ca.crt')
    elif invalid == 'writable-certificate':
        (tls / 'server.crt').chmod(0o666)
    elif invalid == 'readable-key':
        (tls / 'server.key').chmod(0o644)
    else:
        (tls / 'server.key').unlink()
        (tls / 'server.key').symlink_to(tls / 'ca.crt')
    result = run_daemon(script, config)
    assert result.returncode != 0
    assert 'TLS' in result.stderr
    assert not (tmp_path / 'provider-called').exists()
    assert not (tmp_path / 'proxy-called').exists()


@pytest.mark.parametrize('status', [37, 73])
def test_daemon_preserves_adapter_exit_status(tmp_path, status):
    script = redirected_script(tmp_path)
    config = write_tls(tmp_path)
    marker_stubs(tmp_path, status)
    result = run_daemon(script, config)
    assert result.returncode == status
    assert result.stderr == 'provider-diagnostic\n'
    assert (tmp_path / 'provider-called').exists()
    assert not (tmp_path / 'proxy-called').exists()


@pytest.mark.parametrize('failure_at', [1, 2, 3])
def test_tls_find_failure_fails_before_provider_adapter(tmp_path, failure_at):
    script = redirected_script(tmp_path)
    config = write_tls(tmp_path)
    marker_stubs(tmp_path)
    tools = tmp_path / 'tools'
    tools.mkdir()
    find = tools / 'find'
    find.write_text('#!/bin/sh\n'
                    f'count=$(cat "{tmp_path}/find-count" 2>/dev/null || echo 0)\n'
                    'count=$((count + 1))\n'
                    f'echo "$count" > "{tmp_path}/find-count"\n'
                    f'if [ "$count" = {failure_at} ]; then echo "injected TLS find failure" >&2; exit 71; fi\n'
                    'exec /usr/bin/find "$@"\n')
    find.chmod(0o755)
    result = run_daemon(script, config, {'PATH': str(tools) + ':' + os.environ['PATH']})
    assert result.returncode != 0, result.stdout + result.stderr
    assert 'cannot enumerate' in result.stderr
    assert 'injected TLS find failure' in result.stderr
    assert not (tmp_path / 'provider-called').exists()
    assert not (tmp_path / 'proxy-called').exists()
