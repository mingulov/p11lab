"""Daemon config permission gate in the proxy entrypoint (review D4).

proxy.md documents that the daemon refuses a group/world-writable config;
these tests execute the real script (path-redirected, stub binaries) and
prove the refusal plus the unaffected 0644/0600 paths.
"""
import os
import subprocess

import pytest

from p11lab.catalog import package_data


def redirected_script(directory):
    text = package_data("runtime/proxy-entrypoint.sh").read_text()
    text = text.replace(
        ". /usr/share/p11lab/common.sh",
        package_data("runtime/common.sh").read_text(),
    )
    for original, redirect in (
        ("/usr/local/bin/p11lab-provider", str(directory / "stub-provider")),
        ("/usr/local/bin/pkcs11-proxy-ng", str(directory / "stub-proxy")),
        ("/run/p11lab-tls", str(directory / "tls")),
    ):
        assert original in text, original
        text = text.replace(original, redirect)
    script = directory / "p11lab-proxy"
    script.write_text(text)
    script.chmod(0o755)
    return script


def stage(directory):
    tls = directory / "tls"
    tls.mkdir()
    for name in ("ca.crt", "server.crt"):
        (tls / name).write_text("certificate")
        (tls / name).chmod(0o644)
    (tls / "server.key").write_text("key")
    (tls / "server.key").chmod(0o600)
    (directory / "stub-provider").write_text(
        "#!/bin/sh\nset -eu\ntouch \"" + str(directory / "delegated") + "\"\n"
    )
    (directory / "stub-provider").chmod(0o755)
    config = directory / "proxy.toml"
    config.write_text("[backend]\n")
    return config


def run_daemon(script, config):
    env = {k: v for k, v in os.environ.items() if not k.startswith(("SOFTHSM", "FHSM_"))}
    return subprocess.run(
        ["sh", str(script), "daemon", str(config)],
        capture_output=True, text=True, timeout=60, env=env,
    )


@pytest.mark.parametrize("mode", [0o644, 0o600, 0o400])
def test_daemon_accepts_private_config_modes(tmp_path, mode):
    script = redirected_script(tmp_path)
    config = stage(tmp_path)
    config.chmod(mode)
    result = run_daemon(script, config)
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "delegated").exists()


@pytest.mark.parametrize("mode", [0o664, 0o666, 0o646, 0o606])
def test_daemon_refuses_group_or_world_writable_config(tmp_path, mode):
    script = redirected_script(tmp_path)
    config = stage(tmp_path)
    config.chmod(mode)
    result = run_daemon(script, config)
    assert result.returncode != 0
    assert "group/world-writable" in result.stderr
    assert not (tmp_path / "delegated").exists()
