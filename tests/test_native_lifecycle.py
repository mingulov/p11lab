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


def test_host_checker_kills_hung_process_and_records_timeout(tmp_path, monkeypatch):
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
        wait = process.wait

        def bounded_wait(timeout=None):
            assert timeout is not None, (
                "host execution must never wait without a deadline"
            )
            return wait(timeout=0.05 if timeout == 900 else timeout)

        process.wait = bounded_wait
        launched.append(process)
        return process

    monkeypatch.setattr(checker.subprocess, "Popen", launch)
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
