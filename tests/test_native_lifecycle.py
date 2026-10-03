"""Native routing must fail before writable state or application side effects."""

from dataclasses import replace
from pathlib import Path
import pytest
from p11lab.models import ArtifactRef, RunSpec
from p11lab.bundle import InstalledBundle
from p11lab.native import run_native_softhsm


def spec(tmp_path):
    return RunSpec(
        "softhsm2",
        "release",
        "native",
        ArtifactRef("bundle", "/candidate", "a" * 64, "linux/amd64"),
        "host",
        None,
        None,
        ("touch", str(tmp_path / "executed")),
        {},
        tmp_path / "output",
        tmp_path,
        5,
    )


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": "direct"},
        {"execution_location": "container"},
        {
            "consumer_artifact": ArtifactRef(
                "docker-local", "x", "b" * 64, "linux/amd64"
            )
        },
        {"client_artifact": ArtifactRef("bundle", "x", "b" * 64, "linux/amd64")},
    ],
)
def test_reject_container_combinations(tmp_path, changes):
    run = replace(spec(tmp_path), **changes)
    with pytest.raises(ValueError):
        run_native_softhsm(
            run,
            InstalledBundle(
                run.artifact,
                tmp_path / "prefix",
                {},
                "a" * 64,
                tmp_path / "receipt",
                "b" * 64,
            ),
        )
    assert not run.output_dir.exists() and not (tmp_path / "executed").exists()


def test_direct_api_rejects_artifact_mismatch_before_readback(tmp_path):
    run = spec(tmp_path)
    other = replace(run.artifact, sha256="b" * 64)
    with pytest.raises(ValueError, match="artifact"):
        run_native_softhsm(
            run,
            InstalledBundle(
                other, tmp_path / "prefix", {}, "a" * 64, tmp_path / "receipt", "b" * 64
            ),
        )
    assert not run.output_dir.exists() and not (tmp_path / "executed").exists()


@pytest.fixture
def installed(tmp_path, monkeypatch):
    import io
    import json
    import hashlib
    import tarfile
    from p11lab.bundle import install_bundle
    from p11lab.catalog import load_native_target
    from p11lab import native

    target = load_native_target("softhsm2", "release", "debian13-amd64")
    # Real N1 verification with a tiny adapter; no pretend provider acceptance.
    files = {
        "lib/libsofthsm2.so": b"fixture module",
        "bin/softhsm2-util": b"fixture utility",
        "bin/p11lab-provider": b'#!/bin/sh\nshift 6\ncase "$1" in exec) shift 2; exec "$@";; *) exit 0;; esac\n',
    }
    manifest = {
        "schema_version": 1,
        "environment": "softhsm2",
        "channel": "release",
        "platform": "linux/amd64",
        "target": "debian13-amd64",
        "role": "native-runtime",
        "module": native.MODULE,
        "lifecycle": {"adapter": native.ADAPTER},
        "source": {"revision": "fixture"},
        "build": {"key": "fixture"},
        "host_requirements": target["native_lock"]["host_requirements"],
        "licenses": [],
        "source_references": [],
        "tested_prerequisites": [],
        "files": [
            {
                "path": p,
                "sha256": hashlib.sha256(d).hexdigest(),
                "size": len(d),
                "mode": 0o755 if p.startswith("bin/") else 0o644,
                "role": "fixture",
            }
            for p, d in files.items()
        ],
    }
    archive = tmp_path / "bundle.tar.gz"
    with tarfile.open(archive, "w:gz") as out:
        for name, data, mode in [
            ("manifest.json", json.dumps(manifest).encode(), 0o644),
            *[
                ("payload/" + r["path"], files[r["path"]], r["mode"])
                for r in manifest["files"]
            ],
        ]:
            m = tarfile.TarInfo(name)
            m.size = len(data)
            m.mode = mode
            out.addfile(m, io.BytesIO(data))
    artifact = ArtifactRef(
        "bundle",
        str(archive),
        hashlib.sha256(archive.read_bytes()).hexdigest(),
        "linux/amd64",
    )
    result = install_bundle(
        artifact,
        tmp_path / "prefix with spaces",
        environment="softhsm2",
        channel="release",
        platform="linux/amd64",
    )
    monkeypatch.setattr(
        native, "preflight_native", lambda *args: {"scope": "unit fixture"}
    )
    return result


@pytest.mark.parametrize("damage", ["modified", "missing", "extra", "receipt-tuple"])
def test_reject_installed_damage_before_application(tmp_path, installed, damage):
    import json

    if damage == "modified":
        (installed.prefix / "payload" / "lib/libsofthsm2.so").write_bytes(b"damage")
    elif damage == "missing":
        (installed.prefix / "payload" / "lib/libsofthsm2.so").unlink()
    elif damage == "extra":
        (installed.prefix / "payload" / "extra").touch()
    else:
        data = json.loads(installed.receipt_path.read_text())
        data["platform"] = "windows/amd64"
        installed.receipt_path.write_text(json.dumps(data))
    run = replace(
        spec(tmp_path), artifact=installed.artifact, installed_prefix=installed.prefix
    )
    with pytest.raises(ValueError):
        run_native_softhsm(run, installed)
    assert not run.output_dir.exists() and not (tmp_path / "executed").exists()


@pytest.mark.parametrize("kind", ["state", "control", "output"])
@pytest.mark.parametrize("direction", ["child", "parent", "alias"])
def test_reject_both_nestings_and_aliases(tmp_path, installed, kind, direction):
    run = replace(spec(tmp_path), artifact=installed.artifact)
    if direction == "child":
        path = installed.prefix / "child"
    elif direction == "parent":
        path = installed.prefix.parent
    else:
        path = tmp_path / "alias"
        path.symlink_to(installed.prefix, target_is_directory=True)
    if kind == "output":
        run = replace(run, output_dir=path / "out" if direction == "alias" else path)
    else:
        run = replace(run, inputs={"P11LAB_" + kind.upper() + "_DIR": str(path)})
    with pytest.raises(ValueError):
        run_native_softhsm(run, installed)
    assert not (tmp_path / "executed").exists()


def test_dependency_preflight_prevents_application_and_state(
    tmp_path, installed, monkeypatch
):
    from p11lab import native

    def fail(*args):
        raise ValueError("missing prerequisite")

    monkeypatch.setattr(native, "preflight_native", fail)
    run = replace(spec(tmp_path), artifact=installed.artifact)
    with pytest.raises(ValueError, match="prerequisite"):
        run_native_softhsm(run, installed)
    assert not run.output_dir.exists() and not (tmp_path / "executed").exists()


def test_actual_application_status_literal_argv_and_archive_cache_independence(
    tmp_path, installed
):
    Path(installed.artifact.reference).unlink()
    run = replace(
        spec(tmp_path),
        artifact=installed.artifact,
        argv=(
            "sh",
            "-c",
            'printf "%s\\n" "$1"; exit 7',
            "app",
            "literal $(touch forbidden); spaces",
        ),
    )
    result = run_native_softhsm(run, installed)
    assert result.app_returncode == result.exit_code == 7
    assert (run.output_dir / "application.stdout.log").read_text().strip() == run.argv[
        -1
    ]
    assert not (tmp_path / "forbidden").exists()


def test_completed_failure_keeps_status_after_later_health_failure(
    tmp_path, installed, monkeypatch
):
    from p11lab import native

    real = native.subprocess.Popen

    def launch(argv, **kwargs):
        if (
            argv[-1] == "health"
            and (tmp_path / "output/application.stdout.log").exists()
        ):
            return real(["sh", "-c", "exit 3"], **kwargs)
        return real(argv, **kwargs)

    monkeypatch.setattr(native.subprocess, "Popen", launch)
    run = replace(
        spec(tmp_path), artifact=installed.artifact, argv=("sh", "-c", "exit 9")
    )
    result = run_native_softhsm(run, installed)
    assert result.exit_code == 9 and result.lifecycle_errors == ("post-health failed",)


def test_native_deadline_bounds_application(tmp_path, installed):
    import json

    run = replace(
        spec(tmp_path),
        artifact=installed.artifact,
        argv=("sleep", "20"),
        timeout_seconds=1,
    )
    result = run_native_softhsm(run, installed)
    assert (
        result.exit_code == 124
        and json.loads(result.receipt_path.read_text())["timeout"]
    )


def test_native_target_contract_and_missing_targets():
    from p11lab.catalog import load_native_target

    release = load_native_target("softhsm2", "release", "debian13-amd64")
    rolling = load_native_target("softhsm2", "rolling", "debian13-amd64")
    assert (
        release["native_lock"]["sources"][0]["revision"]
        != rolling["native_lock"]["sources"][0]["revision"]
    )
    assert release["native_lock"] != release["lock"]
    with pytest.raises(ValueError, match="not-packaged"):
        load_native_target("softhsm2", "release", "windows-amd64")
    with pytest.raises(ValueError, match="not-packaged"):
        load_native_target("softhsm2", "release", "linux-arm64")


@pytest.mark.parametrize(
    "field,value",
    [
        ("target", "ubuntu-amd64"),
        ("host_requirements", {}),
        ("module", "system/module"),
    ],
)
def test_manifest_target_and_prerequisites_must_match_selection(
    installed, field, value
):
    from p11lab.native import _validate_manifest

    with pytest.raises(ValueError, match="target"):
        _validate_manifest(installed.manifest | {field: value}, "softhsm2", "release")


def test_actual_unsupported_host_rejected_before_loader(tmp_path, monkeypatch):
    from p11lab import native

    monkeypatch.setattr(
        native.platform,
        "freedesktop_os_release",
        lambda: {"ID": "ubuntu", "VERSION_ID": "26.04"},
    )
    with pytest.raises(ValueError, match="Debian 13"):
        native.preflight_native(tmp_path, {})


def test_loader_rejects_symbol_version_mismatch_without_binutils(tmp_path, monkeypatch):
    from p11lab import native
    from subprocess import CompletedProcess

    monkeypatch.setattr(
        native.platform,
        "freedesktop_os_release",
        lambda: {"ID": "debian", "VERSION_ID": "13"},
    )
    monkeypatch.setattr(native.platform, "system", lambda: "Linux")
    monkeypatch.setattr(native.platform, "machine", lambda: "x86_64")
    calls = []

    def loader(argv, **kwargs):
        calls.append(argv)
        return CompletedProcess(argv, 1, "", "version `OPENSSL_3.4.0' not found")

    monkeypatch.setattr(native.subprocess, "run", loader)
    with pytest.raises(ValueError, match="incompatible"):
        native.preflight_native(tmp_path, {})
    assert len(calls) == 1 and calls[0][:2] == ["/lib64/ld-linux-x86-64.so.2", "--list"]


def test_cli_excludes_archive_and_installed_prefix_before_routing(tmp_path):
    from p11lab.cli import main

    with pytest.raises(SystemExit) as error:
        main(
            [
                "run",
                "softhsm2",
                "--channel",
                "release",
                "--mode",
                "native",
                "--installed-prefix",
                str(tmp_path),
                "--artifact",
                "other",
                "--output-dir",
                str(tmp_path / "output"),
                "--",
                "true",
            ]
        )
    assert error.value.code == 2 and not (tmp_path / "output").exists()


@pytest.mark.parametrize('termination_race', [False, True])
def test_host_checker_kills_hung_process_and_records_timeout(tmp_path, monkeypatch, termination_race):
    import sys
    import types
    import subprocess
    from p11lab import checker

    # Keep the checker/provider boundary controlled while exercising real host
    # child termination and log drainage; selection itself remains Task5-owned.
    tests = types.ModuleType("pkcs11_check.testcases")
    tests.__file__ = str(tmp_path / "__init__.py")
    parent = types.ModuleType("pkcs11_check")
    parent.testcases = tests
    monkeypatch.setitem(sys.modules, "pkcs11_check", parent)
    monkeypatch.setitem(sys.modules, "pkcs11_check.testcases", tests)
    node = "test_fixture.py::test_one"
    monkeypatch.setattr(checker, "source_inventory", lambda *args: [])
    monkeypatch.setattr(
        checker,
        "validate_results",
        lambda *args: {"complete": False, "observations_complete": False},
    )
    monkeypatch.setattr(checker, "canonical_node", lambda value, root: value)
    monkeypatch.setattr(
        checker.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args[0], 0, str(tmp_path / node) + "\n", ""
        ),
    )
    real = checker.subprocess.Popen
    launched = []

    def launch(*args, **kwargs):
        process = real(["sh", "-c", "printf started; sleep 30"], **kwargs)
        if not hasattr(checker, 'supervised_exec'):
            wait = process.wait
            process.wait = lambda timeout=None: wait(timeout=.05 if timeout == 900 else timeout)
        launched.append(process)
        return process

    monkeypatch.setattr(checker.subprocess, "Popen", launch)
    if hasattr(checker, 'supervised_exec'):
        original_execute = checker.supervised_exec
        monkeypatch.setattr(checker, "supervised_exec", lambda *a, **k: original_execute(*a, **(k | {'timeout': 0.05})))
    if termination_race:
        import os
        killpg = os.killpg
        def concurrent_exit(pid, number):
            try:
                killpg(pid, number)
            except ProcessLookupError:
                pass
            raise ProcessLookupError('checker exited concurrently')
        monkeypatch.setattr(os, 'killpg', concurrent_exit)
    identity = {
        "source_revision": checker.SOURCE,
        "wheel_sha256": checker.WHEEL,
        "runtime_lock_sha256": checker.LOCK,
    }
    record = checker.execute_checker(
        installed_root=tmp_path,
        module=tmp_path / "module",
        slot=0,
        nodes=[node],
        output_dir=tmp_path / "checker",
        pin="1234",
        so_pin="12345678",
        identity=identity,
    )
    assert (
        record["returncode"] == 124
        and record["timeout"]
        and launched[0].poll() is not None
    )


def test_oversized_credential_file_fails_before_state_and_app(tmp_path, installed):
    pin = tmp_path / "pin"
    pin.write_bytes(b"x" * 5000)
    run = replace(
        spec(tmp_path),
        artifact=installed.artifact,
        inputs={"P11LAB_PIN_FILE": str(pin)},
    )
    with pytest.raises(ValueError, match="4096-byte bound"):
        run_native_softhsm(run, installed)
    assert not run.output_dir.exists() and not (tmp_path / "executed").exists()


def test_install_host_preflight_failure_does_not_place_prefix_or_ancestors(
    tmp_path, installed, monkeypatch
):
    from p11lab import native

    def fail(*args):
        raise ValueError("missing dependency")

    monkeypatch.setattr(native, "preflight_native", fail)
    destination = tmp_path / "new parent" / "new prefix"
    with pytest.raises(ValueError, match="dependency"):
        native.install_native_bundle(
            installed.artifact, destination, environment="softhsm2", channel="release"
        )
    assert not destination.parent.exists()
    assert not list(tmp_path.glob(".p11lab-native-preflight-*"))


# ---------------------------------------------------------------------------
# BouncyHSM native lifecycle (M5). SoftHSM tests above are unchanged.
# ---------------------------------------------------------------------------


def bouncy_spec(tmp_path):
    import sys

    return RunSpec(
        "bouncyhsm",
        "release",
        "native",
        ArtifactRef("bundle", "/candidate", "a" * 64, "linux/amd64"),
        "host",
        None,
        None,
        (sys.executable, "-c", "pass"),
        {},
        tmp_path / "output",
        tmp_path,
        30,
    )


@pytest.fixture
def bouncy_installed(tmp_path, monkeypatch):
    import io
    import json
    import hashlib
    import tarfile
    from p11lab.bundle import install_bundle
    from p11lab.native import load_bouncyhsm_target
    from p11lab import native

    lock = load_bouncyhsm_target("bouncyhsm", "release", "debian13-amd64")[
        "native_lock"
    ]
    # Real N1 verification with a tiny payload; the manifest mirrors the
    # locked contract fields so validation runs against real locks.
    files = {
        lock["module"]: b"fixture module",
        lock["lifecycle"]["probe"]: b"fixture probe",
        lock["lifecycle"]["server"]: b"fixture server",
    }
    manifest = {
        "schema_version": 1,
        "environment": "bouncyhsm",
        "channel": "release",
        "platform": "linux/amd64",
        "target": "debian13-amd64",
        "role": "native-runtime",
        "module": lock["module"],
        "lifecycle": lock["lifecycle"],
        "source": {"revision": lock["source"]["revision"]},
        "toolchain": lock["toolchain"],
        "build": {"key": "fixture"},
        "host_requirements": lock["host_requirements"],
        "tested_prerequisites": lock["tested_prerequisites"],
        "licenses": [],
        "source_references": [],
        "files": [
            {
                "path": p,
                "sha256": hashlib.sha256(d).hexdigest(),
                "size": len(d),
                "mode": 0o755 if p.startswith("bin/") else 0o644,
                "role": "fixture",
            }
            for p, d in files.items()
        ],
    }
    archive = tmp_path / "bundle.tar.gz"
    with tarfile.open(archive, "w:gz") as out:
        for name, data, mode in [
            ("manifest.json", json.dumps(manifest).encode(), 0o644),
            *[
                ("payload/" + r["path"], files[r["path"]], r["mode"])
                for r in manifest["files"]
            ],
        ]:
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mode = mode
            out.addfile(member, io.BytesIO(data))
    artifact = ArtifactRef(
        "bundle",
        str(archive),
        hashlib.sha256(archive.read_bytes()).hexdigest(),
        "linux/amd64",
    )
    result = install_bundle(
        artifact,
        tmp_path / "prefix with spaces",
        environment="bouncyhsm",
        channel="release",
        platform="linux/amd64",
    )
    monkeypatch.setattr(
        native, "preflight_bouncyhsm", lambda *args: {"dotnet": "dotnet-fixture"}
    )
    return result


@pytest.mark.parametrize(
    "changes",
    [
        {"mode": "direct"},
        {"execution_location": "container"},
        {
            "consumer_artifact": ArtifactRef(
                "docker-local", "x", "b" * 64, "linux/amd64"
            )
        },
        {"client_artifact": ArtifactRef("bundle", "x", "b" * 64, "linux/amd64")},
        {"argv": ()},
        {"timeout_seconds": 0},
    ],
)
def test_bouncy_reject_routing_before_side_effects(tmp_path, changes):
    from p11lab.native import run_native_bouncyhsm

    run = replace(bouncy_spec(tmp_path), **changes)
    with pytest.raises(ValueError):
        run_native_bouncyhsm(
            run,
            InstalledBundle(
                run.artifact,
                tmp_path / "prefix",
                {},
                "a" * 64,
                tmp_path / "receipt",
                "b" * 64,
            ),
        )
    assert not run.output_dir.exists()


def test_bouncy_reject_artifact_mismatch_before_readback(tmp_path):
    from p11lab.native import run_native_bouncyhsm

    run = bouncy_spec(tmp_path)
    other = replace(run.artifact, sha256="b" * 64)
    with pytest.raises(ValueError, match="artifact"):
        run_native_bouncyhsm(
            run,
            InstalledBundle(
                other, tmp_path / "prefix", {}, "a" * 64, tmp_path / "receipt", "b" * 64
            ),
        )
    assert not run.output_dir.exists()


@pytest.mark.parametrize(
    "inputs",
    [
        {"UNKNOWN": "x"},
        {"P11LAB_LABEL": "has\nnewline"},
        {"P11LAB_PIN": "1", "P11LAB_PIN_FILE": "/pin"},
        {"P11LAB_HTTP_PORT": "http"},
        {"P11LAB_HTTP_PORT": "0"},
        {"P11LAB_TCP_PORT": "65536"},
        {"P11LAB_HTTP_PORT": "8080", "P11LAB_TCP_PORT": "8080"},
        {"P11LAB_LABEL": ""},
        {"P11LAB_LABEL": "x" * 33},
        {"P11LAB_LABEL": "bad;label"},
    ],
)
def test_bouncy_reject_inputs_ports_labels(tmp_path, bouncy_installed, inputs):
    from p11lab.native import run_native_bouncyhsm

    run = replace(
        bouncy_spec(tmp_path), artifact=bouncy_installed.artifact, inputs=inputs
    )
    with pytest.raises(ValueError):
        run_native_bouncyhsm(run, bouncy_installed)
    assert not run.output_dir.exists()


def test_bouncy_occupied_port_refuses_before_output(tmp_path, bouncy_installed):
    import socket
    from p11lab.native import run_native_bouncyhsm

    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    holder.bind(("127.0.0.1", 0))
    holder.listen(1)
    try:
        run = replace(
            bouncy_spec(tmp_path),
            artifact=bouncy_installed.artifact,
            inputs={"P11LAB_TCP_PORT": str(holder.getsockname()[1])},
        )
        with pytest.raises(ValueError, match="occupied"):
            run_native_bouncyhsm(run, bouncy_installed)
    finally:
        holder.close()
    assert not run.output_dir.exists()


@pytest.mark.parametrize("damage", ["modified", "missing", "extra", "receipt-tuple"])
def test_bouncy_reject_installed_damage_before_provisioning(
    tmp_path, bouncy_installed, damage
):
    import json
    from p11lab.native import run_native_bouncyhsm

    if damage == "modified":
        (
            bouncy_installed.prefix / "payload" / "lib/libBouncyHsm.Pkcs11.so"
        ).write_bytes(b"damage")
    elif damage == "missing":
        (bouncy_installed.prefix / "payload" / "lib/libBouncyHsm.Pkcs11.so").unlink()
    elif damage == "extra":
        (bouncy_installed.prefix / "payload" / "extra").touch()
    else:
        data = json.loads(bouncy_installed.receipt_path.read_text())
        data["platform"] = "windows/amd64"
        bouncy_installed.receipt_path.write_text(json.dumps(data))
    run = replace(
        bouncy_spec(tmp_path),
        artifact=bouncy_installed.artifact,
        inputs={"P11LAB_PIN": "1234", "P11LAB_SO_PIN": "12345678"},
    )
    with pytest.raises(ValueError):
        run_native_bouncyhsm(run, bouncy_installed)
    assert not run.output_dir.exists()


def _bouncy_fakes(monkeypatch, tmp_path, slots=(), probe=None):
    from p11lab import native

    calls = {"posts": []}
    state = {"slots": list(slots)}

    def fake_http(method, url, payload, timeout, **kwargs):
        if url.endswith("/health"):
            assert kwargs.get("expect_json", True) is False
            return "Healthy"
        if method == "GET" and url.endswith("/Slot"):
            return [
                {"SlotId": slot, "Token": {"Label": "P11Lab"}}
                for slot in state["slots"]
            ]
        if method == "POST" and url.endswith("/Slot"):
            calls["posts"].append(payload)
            state["slots"] = [1]
            return {"SlotId": 1}
        raise AssertionError(url)

    monkeypatch.setattr(native, "_bouncy_http", fake_http)
    monkeypatch.setattr(native, "_bouncy_probe_slots", lambda *a, **k: probe if probe is not None else (len(state['slots']), len(state['slots'])))

    servers = []
    real_popen = native.subprocess.Popen

    def launch(argv, **kwargs):
        if argv and argv[0] == "dotnet-fixture":
            # The fixture server has the real pipe/process interface and creates
            # a regular DB, matching LiteDB's accepted fresh-state side effect.
            import sys
            Path(kwargs['env']['BouncyHsm_LiteDbPersistentRepositorySetup__DbFilePath']).touch(exist_ok=True)
            proc = real_popen([sys.executable, '-c', 'import time; time.sleep(30)'], **kwargs)
            servers.append(proc)
            return proc
        return real_popen(argv, **kwargs)

    monkeypatch.setattr(native.subprocess, "Popen", launch)
    monkeypatch.setattr(native, "_bouncy_port_occupied", lambda port: False)
    return calls, servers, state


def test_bouncy_provision_then_reuse_without_credentials(
    tmp_path, bouncy_installed, monkeypatch
):
    import json
    import sys
    from p11lab.native import run_native_bouncyhsm

    calls, servers, _ = _bouncy_fakes(monkeypatch, tmp_path)
    state = tmp_path / "token state"
    state.mkdir()
    common = {
        "P11LAB_STATE_DIR": str(state),
        "P11LAB_PIN": "1234",
        "P11LAB_SO_PIN": "12345678",
    }
    first = replace(
        bouncy_spec(tmp_path),
        artifact=bouncy_installed.artifact,
        argv=(sys.executable, "-c", "pass"),
        output_dir=tmp_path / "out 1",
        inputs=dict(common),
    )
    result = run_native_bouncyhsm(first, bouncy_installed)
    assert result.exit_code == 0, (result.lifecycle_errors, result.cleanup_errors)
    assert len(calls["posts"]) == 1
    assert calls["posts"][0]["Token"]["Label"] == "P11Lab"
    receipt = json.loads(Path(result.receipt_path).read_text())
    assert [s["phase"] for s in receipt["stages"]] == [
        "server-start",
        "init-probe",
        "init",
        "ready-probe",
        "ready",
        "application",
        "post-health-probe",
        "post-health",
        "server-stop",
    ]
    assert receipt["state"]["slot"] == 1
    assert (state / "bouncyhsm" / "complete").exists()
    assert servers and all(s.poll() is not None for s in servers)
    # Second run reuses the provisioned token with no credentials at all.
    calls2, servers2, _ = _bouncy_fakes(monkeypatch, tmp_path, slots=(1,), probe=(1, 1))
    second = replace(
        bouncy_spec(tmp_path),
        artifact=bouncy_installed.artifact,
        argv=(sys.executable, "-c", "pass"),
        output_dir=tmp_path / "out 2",
        inputs={"P11LAB_STATE_DIR": str(state)},
    )
    result = run_native_bouncyhsm(second, bouncy_installed)
    assert result.exit_code == 0, (result.lifecycle_errors, result.cleanup_errors)
    assert calls2["posts"] == []


def test_bouncy_completed_failure_keeps_status_after_post_health_failure(
    tmp_path, bouncy_installed, monkeypatch
):
    import sys
    from p11lab import native
    from p11lab.native import run_native_bouncyhsm

    _bouncy_fakes(monkeypatch, tmp_path, slots=(1,), probe=(1, 1))
    real_probe = native._bouncy_probe_slots
    seen = []

    def flapping(*args, **kwargs):
        seen.append(1)
        if len(seen) > 2:
            raise ValueError("native slot probe failed: gone")
        return real_probe(*args, **kwargs)

    monkeypatch.setattr(native, "_bouncy_probe_slots", flapping)
    state = tmp_path / "state"
    state.mkdir()
    run = replace(
        bouncy_spec(tmp_path),
        artifact=bouncy_installed.artifact,
        argv=(sys.executable, "-c", "import sys; sys.exit(9)"),
        inputs={"P11LAB_STATE_DIR": str(state)},
    )
    (state / "bouncyhsm").mkdir()
    marker = (
        "schema=1\nprovider=bouncyhsm\nartifact="
        + bouncy_installed.manifest_sha256
        + "\nlabel=P11Lab\nslot=1\nbackend=litedb\n"
    )
    (state / "bouncyhsm" / "complete").write_text(marker)
    (state / "bouncyhsm" / "BouncyHsm.db").write_bytes(b"db")
    result = run_native_bouncyhsm(run, bouncy_installed)
    assert result.exit_code == 9
    assert len(result.lifecycle_errors) == 1


def test_bouncy_preflight_dispatch_rejects_platform_and_shape(tmp_path):
    import sys
    from p11lab import native

    other = "windows/amd64" if sys.platform != "win32" else "linux/amd64"
    with pytest.raises(ValueError, match="requires"):
        native.preflight_bouncyhsm(
            tmp_path,
            {
                "platform": other,
                "module": "x",
                "lifecycle": {"server": "y", "probe": "z"},
            },
        )
    mine = "windows/amd64" if sys.platform == "win32" else "linux/amd64"
    with pytest.raises(ValueError, match="regular file"):
        native.preflight_bouncyhsm(
            tmp_path,
            {
                "platform": mine,
                "module": "missing-module",
                "lifecycle": {"server": "missing-server", "probe": "missing-probe"},
            },
        )


def test_bouncy_manifest_must_match_locked_contract(tmp_path, bouncy_installed):
    import copy
    import json
    from p11lab.native import _validate_bouncyhsm_manifest

    manifest = json.loads((bouncy_installed.prefix / "manifest.json").read_text())
    _validate_bouncyhsm_manifest(manifest, "bouncyhsm", "release")
    for mutate in (
        lambda m: m.update(module="bin/other.dll"),
        lambda m: m.update(toolchain=[{"name": "other"}]),
        lambda m: m.update(target="windows-amd64"),
    ):
        broken = copy.deepcopy(manifest)
        mutate(broken)
        with pytest.raises(ValueError):
            _validate_bouncyhsm_manifest(broken, "bouncyhsm", "release")


def test_bouncy_dotnet_floor_parsing():
    from p11lab.native import _dotnet_runtime_versions

    versions = _dotnet_runtime_versions(
        "Microsoft.NETCore.App 10.0.12 [/x]\n"
        "Microsoft.AspNetCore.App 10.0.13 [/x]\n"
        "Microsoft.NETCore.App 9.0.0 [/x]\n"
        "garbage line\n"
    )
    assert versions["Microsoft.NETCore.App"] == [(9, 0, 0), (10, 0, 12)]
    assert versions["Microsoft.AspNetCore.App"] == [(10, 0, 13)]


def _state_snapshot(root):
    import stat
    return {
        str(p.relative_to(root)): (stat.S_IFMT(p.lstat().st_mode),
                                  p.readlink().as_posix() if p.is_symlink()
                                  else p.read_bytes() if p.is_file() else None)
        for p in root.rglob('*')
    }


@pytest.mark.parametrize('damage', ['empty-owned', 'missing-db', 'db-link',
                                   'log-link', 'marker-bytes', 'owned-link', 'foreign-top'])
def test_bouncy_static_refusal_precedes_server_open(tmp_path, bouncy_installed, monkeypatch, damage):
    from p11lab.native import _bouncy_marker, run_native_bouncyhsm
    calls, servers, _ = _bouncy_fakes(monkeypatch, tmp_path, slots=(1,), probe=(1, 1))
    state = tmp_path / 'state'
    owned = state / 'bouncyhsm'
    owned.mkdir(parents=True)
    (owned / 'complete').write_text(_bouncy_marker(bouncy_installed.manifest_sha256, 'P11Lab', 1))
    (owned / 'BouncyHsm.db').write_bytes(b'original-db')
    outside = tmp_path / 'outside'
    outside.write_bytes(b'untouched')
    if damage == 'empty-owned':
        for p in owned.iterdir():
            p.unlink()
    elif damage == 'missing-db':
        (owned / 'BouncyHsm.db').unlink()
    elif damage in ('db-link', 'log-link'):
        path = owned / ('BouncyHsm.db' if damage == 'db-link' else 'BouncyHsm-log.db')
        path.unlink(missing_ok=True)
        path.symlink_to(outside)
    elif damage == 'marker-bytes':
        with (owned / 'complete').open('ab') as stream:
            stream.write(b'\n')
    elif damage == 'owned-link':
        owned.rename(state / 'target')
        owned.symlink_to(state / 'target', target_is_directory=True)
    else:
        (state / 'foreign').write_bytes(b'foreign')
    before = _state_snapshot(state)
    spec = replace(bouncy_spec(tmp_path), artifact=bouncy_installed.artifact,
                   inputs={'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN': '1234', 'P11LAB_SO_PIN': '12345678'})
    try:
        result = run_native_bouncyhsm(spec, bouncy_installed)
        assert result.exit_code != 0
    except ValueError:
        pass
    assert servers == [], 'rejected state was opened by the server'
    assert calls['posts'] == []
    assert _state_snapshot(state) == before
    assert outside.read_bytes() == b'untouched'


@pytest.mark.parametrize('data,accepted', [(b'1234\n', True), (b'1234\n\n', False),
                                         (b'123\xff', False)])
def test_bouncy_pin_file_round_trip_before_init(tmp_path, bouncy_installed, monkeypatch, data, accepted):
    import sys
    from p11lab.native import run_native_bouncyhsm
    calls, servers, _ = _bouncy_fakes(monkeypatch, tmp_path)
    pin = tmp_path / 'pin'
    pin.write_bytes(data)
    spec = replace(bouncy_spec(tmp_path), artifact=bouncy_installed.artifact,
                   argv=(sys.executable, '-c', 'pass'),
                   inputs={'P11LAB_PIN_FILE': str(pin), 'P11LAB_SO_PIN': '12345678'})
    if accepted:
        result = run_native_bouncyhsm(spec, bouncy_installed)
        assert result.exit_code == 0, result
        assert calls['posts'][0]['Token']['UserPin'] == '1234'
    else:
        with pytest.raises(ValueError, match='credential'):
            run_native_bouncyhsm(spec, bouncy_installed)
        assert not spec.output_dir.exists()
        assert servers == [] and calls['posts'] == []


@pytest.mark.parametrize('probe', [(0, 0), (1, 0), (2, 1), (2, 2), (0, 1)])
def test_bouncy_probe_counts_must_match_live_token(tmp_path, bouncy_installed, monkeypatch, probe):
    import sys
    from p11lab.native import _bouncy_marker, run_native_bouncyhsm
    _bouncy_fakes(monkeypatch, tmp_path, slots=(1,), probe=probe)
    state = tmp_path / 'state'
    owned = state / 'bouncyhsm'
    owned.mkdir(parents=True)
    (owned / 'complete').write_text(_bouncy_marker(bouncy_installed.manifest_sha256, 'P11Lab', 1))
    (owned / 'BouncyHsm.db').write_bytes(b'db')
    spec = replace(bouncy_spec(tmp_path), artifact=bouncy_installed.artifact,
                   argv=(sys.executable, '-c', 'pass'), inputs={'P11LAB_STATE_DIR': str(state)})
    result = run_native_bouncyhsm(spec, bouncy_installed)
    assert result.exit_code != 0
    import json
    receipt = json.loads(result.receipt_path.read_text())
    assert receipt['app_returncode'] is None
    evidence = [stage for stage in receipt['stages'] if stage.get('native_probe')]
    assert evidence and evidence[-1]['native_probe'] == {'slots': probe[0], 'present': probe[1]}


def test_bouncy_probe_timeout_is_124(tmp_path, monkeypatch):
    import subprocess
    from p11lab.native import _bouncy_probe_slots
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired('probe', 1)
    monkeypatch.setattr(subprocess, 'run', timeout)
    with pytest.raises(TimeoutError):
        _bouncy_probe_slots(tmp_path / 'probe', tmp_path / 'module', 8765, timeout=1)


@pytest.mark.skipif(not hasattr(__import__('os'), 'mkfifo'), reason='requires FIFO')
@pytest.mark.parametrize('provider', ['softhsm2', 'bouncyhsm'])
def test_native_fifo_pin_refuses_without_output(tmp_path, request, provider):
    import multiprocessing
    import os
    from p11lab.native import run_native_bouncyhsm
    fifo = tmp_path / 'fifo'
    os.mkfifo(fifo)
    chosen = request.getfixturevalue('installed' if provider == 'softhsm2' else 'bouncy_installed')
    base = spec(tmp_path) if provider == 'softhsm2' else bouncy_spec(tmp_path)
    run = replace(base, artifact=chosen.artifact, inputs={'P11LAB_PIN_FILE': str(fifo)})
    def attempt():
        try:
            (run_native_softhsm if provider == 'softhsm2' else run_native_bouncyhsm)(run, chosen)
        except ValueError as error:
            assert 'regular' in str(error)
            return
        raise AssertionError('FIFO accepted')
    child = multiprocessing.get_context('fork').Process(target=attempt)
    child.start()
    child.join(1)
    blocked = child.is_alive()
    if blocked:
        child.terminate()
        child.join(2)
        if child.is_alive():
            child.kill()
            child.join(2)
    assert not blocked, 'credential open blocked on a FIFO'
    assert child.exitcode == 0
    assert not run.output_dir.exists()


def test_bouncy_server_log_is_bounded_redacted_and_sealed(tmp_path, bouncy_installed, monkeypatch):
    import json
    import sys
    from p11lab import native
    real = native.subprocess.Popen
    _bouncy_fakes(monkeypatch, tmp_path, slots=(1,))
    wrapper = native.subprocess.Popen
    def launch(argv, **kwargs):
        if argv[0] == 'dotnet-fixture':
            Path(kwargs['env']['BouncyHsm_LiteDbPersistentRepositorySetup__DbFilePath']).touch()
            return real([sys.executable, '-c',
                         'import os,time; print((os.environ["P11LAB_PIN"]+"\\n")*100000,flush=True); time.sleep(30)'], **kwargs)
        return wrapper(argv, **kwargs)
    monkeypatch.setattr(native.subprocess, 'Popen', launch)
    state = tmp_path / 'state'
    owned = state / 'bouncyhsm'
    owned.mkdir(parents=True)
    (owned / 'BouncyHsm.db').write_bytes(b'db')
    (owned / 'complete').write_bytes(native._bouncy_marker(bouncy_installed.manifest_sha256, 'P11Lab', 1).encode())
    selected = replace(bouncy_spec(tmp_path), artifact=bouncy_installed.artifact,
                       argv=(sys.executable, '-c', 'import time; time.sleep(.3)'),
                       inputs={'P11LAB_STATE_DIR': str(state), 'P11LAB_PIN': 'credential-log-test', 'P11LAB_SO_PIN': 'so-log-test'})
    result = native.run_native_bouncyhsm(selected, bouncy_installed)
    assert result.exit_code == 0, result
    content = (selected.output_dir / 'control/server.log').read_bytes()
    assert 0 < len(content) <= 1024 * 1024
    assert b'credential-log-test' not in content and b'[REDACTED]' in content
    receipt = json.loads(result.receipt_path.read_text())
    assert any(stage.get('server_log_truncated') for stage in receipt['stages'])


def test_bouncy_server_log_symlink_refused(tmp_path, bouncy_installed, monkeypatch):
    from p11lab.native import run_native_bouncyhsm
    calls, servers, _ = _bouncy_fakes(monkeypatch, tmp_path)
    control = tmp_path / 'control'
    outside = tmp_path / 'outside-log'
    outside.write_bytes(b'unchanged')
    original_mkdir = Path.mkdir
    def race_log_creation(path, *args, **kwargs):
        result = original_mkdir(path, *args, **kwargs)
        if path == control:
            (control / 'server.log').symlink_to(outside)
        return result
    # Existing control already refused on BASE. Exercise insertion between
    # creation of a fresh control directory and the opened log descriptor.
    monkeypatch.setattr(Path, 'mkdir', race_log_creation)
    selected = replace(bouncy_spec(tmp_path), artifact=bouncy_installed.artifact,
                       inputs={'P11LAB_CONTROL_DIR': str(control), 'P11LAB_PIN': '1234', 'P11LAB_SO_PIN': '12345678'})
    result = run_native_bouncyhsm(selected, bouncy_installed)
    assert result.exit_code != 0 and not servers and not calls['posts']
    assert outside.read_bytes() == b'unchanged'


@pytest.mark.parametrize('timeout_stage', ['http', 'probe'])
def test_bouncy_timeout_stage_is_retained(tmp_path, bouncy_installed, monkeypatch, timeout_stage):
    import json
    from p11lab import native
    _bouncy_fakes(monkeypatch, tmp_path, slots=(1,))
    state = tmp_path / 'state'
    owned = state / 'bouncyhsm'
    owned.mkdir(parents=True)
    (owned / 'BouncyHsm.db').write_bytes(b'db')
    (owned / 'complete').write_bytes(native._bouncy_marker(bouncy_installed.manifest_sha256, 'P11Lab', 1).encode())
    if timeout_stage == 'http':
        original = native._bouncy_http
        def http(method, url, *args, **kwargs):
            if url.endswith('/health'):
                raise ValueError('not ready')
            return original(method, url, *args, **kwargs)
        monkeypatch.setattr(native, '_bouncy_http', http)
    else:
        def probe(*args, **kwargs):
            raise native.NativeStageTimeout('native slot probe timed out')
        monkeypatch.setattr(native, '_bouncy_probe_slots', probe)
    selected = replace(bouncy_spec(tmp_path), artifact=bouncy_installed.artifact, timeout_seconds=.1,
                       inputs={'P11LAB_STATE_DIR': str(state)})
    result = native.run_native_bouncyhsm(selected, bouncy_installed)
    assert result.exit_code == 124
    record = json.loads(result.receipt_path.read_text())
    assert record['timeout'] and any(stage.get('timed_out') for stage in record['stages'])


@pytest.mark.skipif(__import__('os').name != 'posix', reason='POSIX native application tree')
@pytest.mark.parametrize('provider', ['softhsm2', 'bouncyhsm'])
@pytest.mark.parametrize('hang', [False, True])
def test_native_application_reaps_escaped_descendants(tmp_path, request, monkeypatch, provider, hang):
    import json
    import os
    import signal
    import sys
    from test_process_supervision import alive
    from p11lab.native import run_native_bouncyhsm
    chosen = request.getfixturevalue('installed' if provider == 'softhsm2' else 'bouncy_installed')
    if provider == 'bouncyhsm':
        _bouncy_fakes(monkeypatch, tmp_path)
    base = spec(tmp_path) if provider == 'softhsm2' else bouncy_spec(tmp_path)
    child_code = 'import time; print("child",flush=True); time.sleep(30)'
    pidfile = tmp_path / 'descendant'
    app = ('import subprocess,sys,time; from pathlib import Path; '
           f'p=subprocess.Popen([sys.executable,"-c",{child_code!r}],start_new_session=True); '
           f'Path({str(pidfile)!r}).write_text(str(p.pid)); time.sleep(.1); '
           + ('time.sleep(30)' if hang else 'sys.exit(0)'))
    selected = replace(base, artifact=chosen.artifact, argv=(sys.executable, '-c', app),
                       timeout_seconds=.5 if hang else 5,
                       inputs={'P11LAB_PIN': '1234', 'P11LAB_SO_PIN': '12345678'})
    try:
        result = (run_native_softhsm if provider == 'softhsm2' else run_native_bouncyhsm)(selected, chosen)
        pid = int(pidfile.read_text())
        assert not alive(pid)
        assert result.exit_code == (124 if hang else 0), result
        receipt = json.loads(result.receipt_path.read_text())
        app_stage = next(stage for stage in receipt['stages'] if stage['phase'] == 'application')
        assert app_stage['drain_complete'] and app_stage['stragglers_detected']
        assert not app_stage['stragglers_remaining']
    finally:
        if pidfile.exists() and alive(int(pidfile.read_text())):
            os.kill(int(pidfile.read_text()), signal.SIGKILL)
