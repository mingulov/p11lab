"""Selected Debian SoftHSM bundles, system-runtime preflight and native lifecycle."""

from dataclasses import asdict
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import tarfile
import tempfile
import threading
import time
from uuid import uuid4

from .bundle import (
    InstalledBundle,
    inspect_bundle,
    install_bundle,
    read_installation,
    validate_writable_paths,
)
from .catalog import load_native_target, packaged_asset, package_data
from .identity import artifact_key, public_identity
from .models import ArtifactRef, RunSpec, RunResult
from .receipts import write_receipt
from .sources import checksum

TARGET = "debian13-amd64"
MODULE = "lib/libsofthsm2.so"
UTILITY = "bin/softhsm2-util"
ADAPTER = "bin/p11lab-provider"

# Native-client role (proxy shim/CLI bundle). Provider N2 behavior above is
# unchanged. Client bundles are proxy-versioned, not provider-versioned; the
# environment/channel select and namespace the bundle for run verification.
CLIENT_TARGET = "debian13-amd64"
CLIENT_MODULE = "lib/libpkcs11_proxy_ng_shim.so"
CLIENT_CLI = "bin/pkcs11-proxy-ng-cli"
CLIENT_HOST_REQUIREMENTS = {
    "os": "debian",
    "major_version": "13",
    "architecture": "x86_64",
    "platform": "linux/amd64",
    "loader": "/lib64/ld-linux-x86-64.so.2",
    "packages": ["libc6", "libgcc-s1"],
    "symbol_floors": {"GLIBC": "2.34"},
}


def _selection(environment, channel, platform):
    return dict(environment=environment, channel=channel, platform=platform)


def build_native_bundle(spec: dict, output_dir: Path) -> ArtifactRef:
    """Export only sealed shipped bytes from the frozen notice-only parent.

    Docker is a build-time byte acquisition tool, never a native consumer runtime.
    No source selector resolution, stripping, linking or SoftHSM rebuild occurs.
    """
    spec = load_native_target(
        spec["id"], spec["channel"], spec.get("native_target", TARGET)
    )
    lock = spec["native_lock"]
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    parent = lock["parent"]
    observation = json.loads(
        subprocess.run(
            ["docker", "image", "inspect", parent["reference"]],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        ).stdout
    )[0]
    if (
        observation["Id"] != parent["reference"]
        or observation["Os"] + "/" + observation["Architecture"] != lock["platform"]
    ):
        raise ValueError("frozen native parent identity/platform mismatch")
    recipe = json.loads(packaged_asset(spec["id"], "native.recipe.json").read_text())
    expected = recipe["export"]
    exported = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--read-only",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--entrypoint",
            "tar",
            parent["reference"],
            "-C",
            "/",
            "-cf",
            "-",
            *expected.values(),
        ],
        capture_output=True,
        check=True,
        timeout=60,
    ).stdout
    (output_dir / "selected-files.tar").write_bytes(exported)
    contents = {}
    with tarfile.open(fileobj=io.BytesIO(exported)) as archive:
        members = archive.getmembers()
        if (
            {m.name for m in members} != set(expected.values())
            or len(members) != len(expected)
            or any(not m.isfile() for m in members)
        ):
            raise ValueError("native export roster/type mismatch")
        for destination, source in expected.items():
            contents[destination] = archive.extractfile(source).read()
    for binary in lock["binaries"]:
        if hashlib.sha256(contents[binary["path"]]).hexdigest() != binary["sha256"]:
            raise ValueError("native provider bytes differ from sealed staging")
    evidence = lock["sources"][0]["license_evidence"][0]
    if (
        hashlib.sha256(contents["share/licenses/softhsm2/LICENSE"]).hexdigest()
        != evidence["sha256"]
    ):
        raise ValueError("upstream license bytes mismatch")
    inputs = {
        "sources": lock["sources"],
        "binaries": lock["binaries"],
        "dependencies": [],
        "toolchain": lock["toolchain"],
        "recipe": hashlib.sha256(
            json.dumps(
                {
                    "mapping": checksum(
                        packaged_asset(spec["id"], "native.recipe.json")
                    ),
                    "implementation": checksum(Path(__file__)),
                },
                sort_keys=True,
            ).encode()
        ).hexdigest(),
        "platform": lock["platform"],
        "features": {
            "target": TARGET,
            "patches": lock["patches"],
            "compilation": lock["compilation"],
            "assets": lock["assets"],
            "target_lock_sha256": hashlib.sha256(
                packaged_asset(
                    spec["id"],
                    spec["native_target_spec"]["channels"][spec["channel"]]["lock"],
                ).read_bytes()
            ).hexdigest(),
            "host_requirements": lock["host_requirements"],
            "payload_assets": {
                name: hashlib.sha256(data).hexdigest()
                for name, data in {
                    "common.sh": package_data("runtime/common.sh").read_bytes(),
                    "provider.json": packaged_asset(
                        spec["id"], "provider.json"
                    ).read_bytes(),
                    "LICENSE": package_data("runtime/LICENSE").read_bytes(),
                }.items()
            },
        },
    }
    key = artifact_key("native", inputs)
    contents.update(
        {
            ADAPTER: packaged_asset(spec["id"], "native.sh").read_bytes(),
            "share/licenses/softhsm2/FILE-NOTICES.txt": packaged_asset(
                spec["id"], spec["channel"] + ".native-notices.txt"
            ).read_bytes(),
            "share/p11lab/common.sh": package_data("runtime/common.sh").read_bytes(),
            "share/p11lab/native-id": (key + "\n").encode(),
            "share/p11lab/provider.json": packaged_asset(
                spec["id"], "provider.json"
            ).read_bytes(),
            "share/licenses/p11lab/LICENSE": package_data(
                "runtime/LICENSE"
            ).read_bytes(),
            "share/p11lab/THIRD-PARTY-NOTICES.txt": b"P11Lab native adapter: Apache-2.0. SoftHSMv2: BSD-2-Clause; see share/licenses/softhsm2/LICENSE. Host runtime packages are prerequisites, not redistributed. Source and patch identities are recorded in manifest.json. Public admission is a separate artifact-bound gate.\n",
        }
    )
    roster = [
        {
            "path": name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "mode": 0o755 if name.startswith("bin/") else 0o644,
            "role": "module"
            if name == MODULE
            else "utility"
            if name == UTILITY
            else "adapter"
            if name == ADAPTER
            else "notice",
        }
        for name, data in sorted(contents.items())
    ]
    manifest = {
        "schema_version": 1,
        "role": "native-runtime",
        "environment": spec["id"],
        "channel": spec["channel"],
        "platform": lock["platform"],
        "target": TARGET,
        "module": MODULE,
        "lifecycle": {"adapter": ADAPTER},
        "source": {
            "sources": lock["sources"],
            "patches": lock["patches"],
            "notice_provenance": lock["notice_provenance"],
        },
        "build": {"key": key, "identity": public_identity("native", inputs)},
        "host_requirements": lock["host_requirements"],
        "tested_prerequisites": lock["tested_prerequisites"],
        "licenses": [
            "share/licenses/softhsm2/LICENSE",
            "share/licenses/p11lab/LICENSE",
            "share/licenses/softhsm2/FILE-NOTICES.txt",
        ],
        "source_references": [
            {"parent": parent, "source_companion": lock["source_companion"]}
        ],
        "files": roster,
        "admission": "unreviewed; native actual-content admission is separate from container admission",
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    archive_path = output_dir / "softhsm2-native.tar.gz"
    # Fixed tar headers and gzip timestamp; native identity includes all packaged bytes.
    import gzip

    with (
        archive_path.open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as zipped,
        tarfile.open(fileobj=zipped, mode="w") as archive,
    ):
        for name, data, mode in [
            ("manifest.json", manifest_bytes, 0o644),
            *[("payload/" + r["path"], contents[r["path"]], r["mode"]) for r in roster],
        ]:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = mode
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(data))
    artifact = ArtifactRef(
        "bundle", str(archive_path), checksum(archive_path), lock["platform"]
    )
    inspect_bundle(
        artifact, **_selection(spec["id"], spec["channel"], lock["platform"])
    )
    write_receipt(
        output_dir / "artifact.json",
        {
            "schema_version": 1,
            "artifact": asdict(artifact),
            "build_key": key,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "parent": parent,
            "source_companion": lock["source_companion"],
            "payload_bytes": sum(r["size"] for r in roster),
            "archive_bytes": archive_path.stat().st_size,
            "files": roster,
            "admission": "unreviewed",
        },
    )
    (output_dir / "manifest.json").write_bytes(manifest_bytes)
    (output_dir / "parent-inspect.json").write_text(
        json.dumps(observation, indent=2) + "\n"
    )
    return artifact


def _validate_manifest(manifest, environment, channel):
    target = load_native_target(environment, channel, TARGET)
    lock = target["native_lock"]
    if (
        manifest.get("target") != TARGET
        or manifest.get("role") != "native-runtime"
        or manifest.get("host_requirements") != lock["host_requirements"]
        or manifest.get("module") != MODULE
        or manifest.get("lifecycle") != {"adapter": ADAPTER}
    ):
        raise ValueError(
            "native manifest does not match selected target/host requirements"
        )
    return target


def preflight_native(prefix: Path, manifest: dict) -> dict:
    """Use the Debian system loader to verify both ELFs, including symbol versions."""
    release = platform.freedesktop_os_release()
    if (
        platform.system() != "Linux"
        or platform.machine() != "x86_64"
        or release.get("ID") != "debian"
        or release.get("VERSION_ID", "").split(".")[0] != "13"
    ):
        raise ValueError("native SoftHSM requires Debian 13 amd64 (debian13-amd64)")
    closure = {}
    for relative in (MODULE, UTILITY):
        binary = prefix / "payload" / relative
        result = subprocess.run(
            ["/lib64/ld-linux-x86-64.so.2", "--list", str(binary)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if result.returncode or "not found" in result.stdout + result.stderr:
            raise ValueError(
                "missing or incompatible native runtime prerequisite: "
                + relative
                + "; "
                + result.stderr.strip()
            )
        resolved = []
        for line in result.stdout.splitlines():
            fields = line.split()
            name = (
                fields[2]
                if len(fields) > 2 and fields[1] == "=>"
                else fields[0]
                if fields
                else ""
            )
            if name.startswith("/"):
                path = Path(name).resolve()
                resolved.append({"path": str(path), "sha256": checksum(path)})
        closure[relative] = {"loader_output": result.stdout, "resolved": resolved}
    version = subprocess.run(
        [str(prefix / "payload" / UTILITY), "--version"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if version.returncode:
        raise ValueError("native utility launch failed")
    packages = subprocess.run(
        [
            "dpkg-query",
            "-W",
            "-f=${Package}\t${Version}\t${Architecture}\n",
            *manifest["host_requirements"]["packages"],
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if packages.returncode:
        raise ValueError("declared Debian runtime package prerequisites absent")
    return {
        "os_release": release,
        "architecture": platform.machine(),
        "closure": closure,
        "packages": packages.stdout,
        "utility_version": version.stdout.strip(),
    }


def staging_parent(path: Path) -> Path:
    """Use the destination filesystem for executable preflight, including noexec /tmp hosts."""
    parent = Path(path).resolve().parent
    while not parent.exists():
        parent = parent.parent
    return parent


def install_native_bundle(
    artifact: ArtifactRef, prefix: Path, *, environment: str, channel: str
) -> InstalledBundle:
    selection = _selection(environment, channel, artifact.platform)
    manifest = inspect_bundle(artifact, **selection)
    _validate_manifest(manifest, environment, channel)
    # Inert N1 extraction into private temporary placement; no manifest-chosen script.
    # Host preflight precedes creation of the user's requested prefix or ancestors.
    with tempfile.TemporaryDirectory(
        prefix=".p11lab-native-preflight-", dir=staging_parent(prefix)
    ) as temporary:
        staged = install_bundle(artifact, Path(temporary) / "prefix", **selection)
        preflight_native(staged.prefix, manifest)
    return install_bundle(artifact, prefix, **selection)


def run_native_softhsm(spec: RunSpec, installed: InstalledBundle) -> RunResult:
    """Reverify original provenance and installed payload before any native action."""
    if (
        spec.mode != "native"
        or spec.execution_location != "host"
        or spec.consumer_artifact
        or spec.client_artifact
    ):
        raise ValueError(
            "native requires host execution without consumer/client container options"
        )
    if spec.artifact != installed.artifact:
        raise ValueError("run artifact differs from installed artifact")
    if (
        spec.installed_prefix is not None
        and spec.installed_prefix.resolve() != installed.prefix.resolve()
    ):
        raise ValueError("run installed prefix differs from selected installation")
    if (
        spec.artifact.platform != "linux/amd64"
        or not spec.argv
        or any(not isinstance(a, str) or "\0" in a for a in spec.argv)
    ):
        raise ValueError("native requires linux/amd64 and literal application argv")
    if spec.timeout_seconds <= 0 or not spec.cwd.is_dir() or spec.output_dir.exists():
        raise ValueError(
            "positive timeout, caller cwd and fresh output directory required"
        )
    installed = read_installation(
        installed.prefix,
        **_selection(spec.environment, spec.channel, spec.artifact.platform),
    )
    if installed.artifact != spec.artifact:
        raise ValueError("verified receipt artifact differs from run artifact")
    descriptor = _validate_manifest(installed.manifest, spec.environment, spec.channel)
    unknown = (
        set(spec.inputs)
        - set(descriptor["inputs"])
        - {"P11LAB_STATE_DIR", "P11LAB_CONTROL_DIR"}
    )
    if unknown or any(
        not isinstance(v, str) or any(c in v for c in "\n\r\0")
        for v in spec.inputs.values()
    ):
        raise ValueError("native inputs must be allowlisted single-line strings")
    for name in ("P11LAB_PIN", "P11LAB_SO_PIN"):
        if name in spec.inputs and name + "_FILE" in spec.inputs:
            raise ValueError("conflicting scalar/file credential inputs")
    output = spec.output_dir.resolve()
    cwd = spec.cwd.resolve()
    state = Path(spec.inputs.get("P11LAB_STATE_DIR", str(output / "state"))).resolve()
    control = Path(
        spec.inputs.get("P11LAB_CONTROL_DIR", str(output / "control"))
    ).resolve()
    validate_writable_paths(installed.prefix, (state, control, output))
    if (
        state == control
        or state.is_relative_to(control)
        or control.is_relative_to(state)
    ):
        raise ValueError("state and control paths overlap")
    if any(
        "#" in str(p) or any(c in str(p) for c in "\n\r\0")
        for p in (installed.prefix, state, control)
    ):
        raise ValueError("path cannot be represented in SoftHSM configuration")
    if "P11LAB_STATE_DIR" in spec.inputs and not state.is_dir():
        raise ValueError("explicit persistent state directory must already exist")
    # Validate credentials before resource creation; snapshot private file inputs.
    credentials = {}
    secrets = []
    for key, value in spec.inputs.items():
        if descriptor["inputs"].get(key, {}).get("secret"):
            if key.endswith("_FILE"):
                with Path(value).open("rb") as stream:
                    data = stream.read(4097)
            else:
                data = value.encode()
            if len(data) > 4096:
                raise ValueError("credential input exceeds 4096-byte bound")
            credentials[key] = data
            if data:
                secrets.append(data.decode("utf-8", "replace"))
    runtime = preflight_native(installed.prefix, installed.manifest)
    output.mkdir(parents=True, mode=0o700)
    lifecycle = []
    cleanup = []
    stages = []
    app = None
    completed = False
    timed_out = False
    interrupted = 0
    deadline = time.monotonic() + spec.timeout_seconds
    handlers = {}

    def on_signal(number, frame):
        nonlocal interrupted
        interrupted = number

    if threading.current_thread() is threading.main_thread():
        for number in (signal.SIGINT, signal.SIGTERM):
            handlers[number] = signal.signal(number, on_signal)
    try:
        with tempfile.TemporaryDirectory(prefix="p11lab-native-input-") as private:
            # Ambient provider, credential and loader controls cannot override inputs.
            env = {
                k: v
                for k, v in os.environ.items()
                if not k.startswith(("P11LAB_", "SOFTHSM", "LD_"))
            }
            env.update(
                {k: v for k, v in spec.inputs.items() if k in descriptor["inputs"]}
            )
            for key, data in credentials.items():
                if key.endswith("_FILE"):
                    snapshot = Path(private) / key
                    snapshot.write_bytes(data)
                    snapshot.chmod(0o600)
                    env[key] = str(snapshot)
            env.update(
                P11LAB_OUTPUT_DIR=str(output),
                P11LAB_MODULE=str(installed.prefix / "payload" / MODULE),
                SOFTHSM2_CONF=str(control / "softhsm2.conf"),
            )
            adapter = [
                str(installed.prefix / "payload" / ADAPTER),
                "--prefix",
                str(installed.prefix),
                "--state",
                str(state),
                "--control",
                str(control),
            ]
            for phase, args in [
                ("init", ["init"]),
                ("ready", ["health"]),
                ("application", ["exec", "--", *spec.argv]),
                ("post-health", ["health"]),
            ]:
                if interrupted or time.monotonic() >= deadline:
                    timed_out = not bool(interrupted)
                    lifecycle.append("interrupted" if interrupted else "timeout")
                    break
                process = subprocess.Popen(
                    [*adapter, *args],
                    cwd=cwd,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    start_new_session=True,
                )
                logs = {}

                def drain(stream, name):
                    retained = bytearray()
                    truncated = False
                    while chunk := stream.read(65536):
                        room = max(0, 1024 * 1024 - len(retained))
                        retained.extend(chunk[:room])
                        truncated |= len(chunk) > room
                    stream.close()
                    if truncated and secrets:
                        trim = max(len(s.encode()) for s in secrets) - 1
                        if trim:
                            del retained[-trim:]
                    text = retained.decode("utf-8", "replace")
                    for secret in sorted(secrets, key=len, reverse=True):
                        text = text.replace(secret, "[REDACTED]")
                    (output / (phase + "." + name + ".log")).write_text(text)
                    logs[name + "_truncated"] = truncated

                readers = [
                    threading.Thread(target=drain, args=(stream, name))
                    for stream, name in [
                        (process.stdout, "stdout"),
                        (process.stderr, "stderr"),
                    ]
                ]
                for reader in readers:
                    reader.start()
                while (
                    process.poll() is None
                    and not interrupted
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.02)
                stage_timeout = process.poll() is None and not interrupted
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=2)
                # Bound pipe drainage if an application leaves descendants holding pipes.
                for reader in readers:
                    reader.join(timeout=1)
                if any(reader.is_alive() for reader in readers):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    for reader in readers:
                        reader.join(timeout=2)
                status = (
                    124
                    if stage_timeout
                    else process.returncode
                    if process.returncode >= 0
                    else 128 - process.returncode
                )
                timed_out |= stage_timeout
                stages.append(
                    {
                        "phase": phase,
                        "pid": process.pid,
                        "returncode": status,
                        "timed_out": stage_timeout,
                        **logs,
                    }
                )
                if phase == "application":
                    app = status
                    completed = not stage_timeout and not interrupted
                elif status:
                    lifecycle.append(phase + " failed")
                    break
                if stage_timeout or interrupted:
                    break
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        lifecycle.append(
            "native runner operation failed (" + type(error).__name__ + ")"
        )
    finally:
        for number, handler in handlers.items():
            signal.signal(number, handler)
    code = (
        app
        if completed and app
        else 128 + interrupted
        if interrupted
        else 124
        if timed_out
        else app
        if app
        else 1
        if lifecycle or cleanup
        else 0
    )
    receipt = output / "receipt.json"
    write_receipt(
        receipt,
        {
            "schema_version": 1,
            "attempt_id": uuid4().hex,
            "environment": spec.environment,
            "channel": spec.channel,
            "mode": "native",
            "execution_location": "host",
            "artifacts": {
                "provider": asdict(spec.artifact),
                "consumer": None,
                "client": None,
            },
            "installation": {
                "prefix": str(installed.prefix),
                "manifest_sha256": installed.manifest_sha256,
                "receipt_path": str(installed.receipt_path),
                "receipt_sha256": installed.receipt_sha256,
            },
            "runtime": runtime,
            "execution": {
                "module": str(installed.prefix / "payload" / MODULE),
                "configuration": str(control / "softhsm2.conf"),
                "cwd": str(cwd),
                "argv_count": len(spec.argv),
            },
            "state": {
                "path": str(state),
                "control": str(control),
                "persistent_caller_directory": "P11LAB_STATE_DIR" in spec.inputs,
            },
            "stages": stages,
            "app_returncode": app,
            "app_completed": completed,
            "timeout": timed_out,
            "interrupted_signal": interrupted,
            "lifecycle_errors": lifecycle,
            "cleanup_errors": cleanup,
            "exit_code": code,
        },
    )
    return RunResult(app, tuple(lifecycle), tuple(cleanup), code, receipt)


def _validate_client_manifest(manifest, environment, channel):
    """Client bundles carry proxy component identities; no catalog target lock."""
    from .tls import PROXY_CARGO_LOCK_SHA256, PROXY_SOURCE_REVISION

    if (
        manifest.get("role") != "native-client"
        or manifest.get("target") != CLIENT_TARGET
        or manifest.get("module") != CLIENT_MODULE
        or manifest.get("host_requirements") != CLIENT_HOST_REQUIREMENTS
    ):
        raise ValueError(
            "native manifest does not match the client target/host requirements"
        )
    proxy = manifest.get("source", {}).get("proxy", {})
    if (
        proxy.get("source_revision") != PROXY_SOURCE_REVISION
        or proxy.get("cargo_lock_sha256") != PROXY_CARGO_LOCK_SHA256
    ):
        raise ValueError("native client proxy component identity mismatch")
    roster = {entry["path"]: entry for entry in manifest.get("files", [])}
    if (
        roster.get(CLIENT_MODULE, {}).get("sha256") != proxy.get("shim_sha256")
        or roster.get(CLIENT_CLI, {}).get("sha256") != proxy.get("cli_sha256")
    ):
        raise ValueError("native client component bytes differ from declared proxy")
    return manifest


def build_native_client_bundle(
    *,
    proxy: dict,
    shim: Path,
    cli: Path,
    licenses: dict,
    output_dir: Path,
    environment: str,
    channel: str,
) -> ArtifactRef:
    """Package verified pinned-proxy client bytes as a native-client bundle.

    No compilation occurs here. The shim/CLI bytes were built from the pinned
    proxy source and are hash-verified against the declared component
    identities, which enter the build key: a proxy component change
    invalidates the client identity.
    """
    from .tls import PROXY_CARGO_LOCK_SHA256, PROXY_SOURCE_REVISION

    for key in (
        "source_revision",
        "cargo_lock_sha256",
        "source_archive_sha256",
        "shim_sha256",
        "cli_sha256",
        "toolchain",
    ):
        if not proxy.get(key):
            raise ValueError("client build requires proxy " + key)
    if (
        proxy["source_revision"] != PROXY_SOURCE_REVISION
        or proxy["cargo_lock_sha256"] != PROXY_CARGO_LOCK_SHA256
    ):
        raise ValueError("client build proxy component identity mismatch")
    shim_bytes = Path(shim).read_bytes()
    cli_bytes = Path(cli).read_bytes()
    if hashlib.sha256(shim_bytes).hexdigest() != proxy["shim_sha256"]:
        raise ValueError("client shim bytes differ from declared proxy component")
    if hashlib.sha256(cli_bytes).hexdigest() != proxy["cli_sha256"]:
        raise ValueError("client CLI bytes differ from declared proxy component")
    if set(licenses) != {
        "share/licenses/proxy-ng/LICENSE-APACHE",
        "share/licenses/proxy-ng/LICENSE-MIT",
    }:
        raise ValueError("client build requires pinned proxy license texts")
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=False)
    inputs = {
        "sources": [{"revision": proxy["source_revision"]}],
        "binaries": [
            {"path": CLIENT_MODULE, "sha256": proxy["shim_sha256"]},
            {"path": CLIENT_CLI, "sha256": proxy["cli_sha256"]},
        ],
        "dependencies": [],
        "toolchain": [],
        "recipe": hashlib.sha256(
            json.dumps(
                {"implementation": checksum(Path(__file__))}, sort_keys=True
            ).encode()
        ).hexdigest(),
        "platform": "linux/amd64",
        "features": {
            "target": CLIENT_TARGET,
            "host_requirements": CLIENT_HOST_REQUIREMENTS,
            "proxy": {
                key: proxy[key]
                for key in (
                    "source_revision",
                    "cargo_lock_sha256",
                    "source_archive_sha256",
                    "shim_sha256",
                    "cli_sha256",
                )
            },
            "toolchain": proxy["toolchain"],
            "licenses": {
                name: hashlib.sha256(Path(path).read_bytes()).hexdigest()
                for name, path in sorted(licenses.items())
            },
        },
    }
    key = artifact_key("client", inputs)
    contents = {
        CLIENT_MODULE: shim_bytes,
        CLIENT_CLI: cli_bytes,
        "share/p11lab/native-id": (key + "\n").encode(),
        "share/licenses/p11lab/LICENSE": package_data("runtime/LICENSE").read_bytes(),
        "share/p11lab/THIRD-PARTY-NOTICES.txt": (
            "P11Lab native client packaging: Apache-2.0. "
            "pkcs11-proxy-ng shim/CLI: Apache-2.0 OR MIT; see "
            "share/licenses/proxy-ng/. Host runtime packages are "
            "prerequisites, not redistributed. Proxy source and component "
            "identities are recorded in manifest.json. Public admission is a "
            "separate artifact-bound gate.\n"
        ).encode(),
    }
    for name, path in licenses.items():
        contents[name] = Path(path).read_bytes()
    roster = [
        {
            "path": name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "mode": 0o755 if name.startswith("bin/") else 0o644,
            "role": "module"
            if name == CLIENT_MODULE
            else "cli"
            if name == CLIENT_CLI
            else "notice",
        }
        for name, data in sorted(contents.items())
    ]
    manifest = {
        "schema_version": 1,
        "role": "native-client",
        "environment": environment,
        "channel": channel,
        "platform": "linux/amd64",
        "target": CLIENT_TARGET,
        "module": CLIENT_MODULE,
        "source": {
            "proxy": {
                "repository": "https://github.com/mingulov/pkcs11-proxy-ng",
                "source_revision": proxy["source_revision"],
                "source_archive_sha256": proxy["source_archive_sha256"],
                "cargo_lock_sha256": proxy["cargo_lock_sha256"],
                "shim_sha256": proxy["shim_sha256"],
                "cli_sha256": proxy["cli_sha256"],
            }
        },
        "build": {"key": key, "identity": public_identity("client", inputs)},
        "host_requirements": CLIENT_HOST_REQUIREMENTS,
        "tested_prerequisites": ["debian13-amd64 system loader resolution"],
        "licenses": [
            "share/licenses/proxy-ng/LICENSE-APACHE",
            "share/licenses/proxy-ng/LICENSE-MIT",
            "share/licenses/p11lab/LICENSE",
        ],
        "source_references": [
            {
                "repository": "https://github.com/mingulov/pkcs11-proxy-ng",
                "revision": proxy["source_revision"],
            }
        ],
        "files": roster,
        "admission": "unreviewed; native actual-content admission is separate from container admission",
    }
    manifest_bytes = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    archive_path = output_dir / "proxy-client-native.tar.gz"
    import gzip

    with (
        archive_path.open("wb") as raw,
        gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as zipped,
        tarfile.open(fileobj=zipped, mode="w") as archive,
    ):
        for name, data, mode in [
            ("manifest.json", manifest_bytes, 0o644),
            *[("payload/" + r["path"], contents[r["path"]], r["mode"]) for r in roster],
        ]:
            entry = tarfile.TarInfo(name)
            entry.size = len(data)
            entry.mode = mode
            entry.mtime = 0
            archive.addfile(entry, io.BytesIO(data))
    artifact = ArtifactRef(
        "bundle", str(archive_path), checksum(archive_path), "linux/amd64"
    )
    inspect_bundle(
        artifact, **_selection(environment, channel, "linux/amd64")
    )
    write_receipt(
        output_dir / "artifact.json",
        {
            "schema_version": 1,
            "artifact": asdict(artifact),
            "build_key": key,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "proxy": manifest["source"]["proxy"],
            "payload_bytes": sum(r["size"] for r in roster),
            "archive_bytes": archive_path.stat().st_size,
            "files": roster,
            "admission": "unreviewed",
        },
    )
    (output_dir / "manifest.json").write_bytes(manifest_bytes)
    return artifact


def preflight_native_client(prefix: Path, manifest: dict) -> dict:
    """Resolve the shim closure with the host system loader; no provider needed."""
    _validate_client_manifest(
        manifest, manifest.get("environment"), manifest.get("channel")
    )
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("native proxy client requires Linux x86_64")
    loader = manifest["host_requirements"]["loader"]
    shim = prefix / "payload" / CLIENT_MODULE
    result = subprocess.run(
        [loader, "--list", str(shim)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if result.returncode or "not found" in result.stdout + result.stderr:
        raise ValueError(
            "missing or incompatible native client runtime prerequisite: "
            + CLIENT_MODULE
            + "; "
            + result.stderr.strip()
        )
    resolved = []
    for line in result.stdout.splitlines():
        fields = line.split()
        name = (
            fields[2]
            if len(fields) > 2 and fields[1] == "=>"
            else fields[0]
            if fields
            else ""
        )
        if name.startswith("/"):
            path = Path(name).resolve()
            resolved.append({"path": str(path), "sha256": checksum(path)})
    launch = subprocess.run(
        [str(prefix / "payload" / CLIENT_CLI), "--version"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if launch.returncode:
        raise ValueError("native client CLI launch failed")
    return {
        "loader": loader,
        "architecture": platform.machine(),
        "closure": {CLIENT_MODULE: {"loader_output": result.stdout, "resolved": resolved}},
        "cli_version": launch.stdout.strip(),
    }


def install_native_client_bundle(
    artifact: ArtifactRef, prefix: Path, *, environment: str, channel: str
) -> InstalledBundle:
    selection = _selection(environment, channel, artifact.platform)
    manifest = inspect_bundle(artifact, **selection)
    _validate_client_manifest(manifest, environment, channel)
    # Inert N1 extraction into private temporary placement. Host preflight
    # precedes creation of the requested prefix or ancestors.
    with tempfile.TemporaryDirectory(
        prefix=".p11lab-client-preflight-", dir=staging_parent(prefix)
    ) as temporary:
        staged = install_bundle(artifact, Path(temporary) / "prefix", **selection)
        preflight_native_client(staged.prefix, manifest)
    return install_bundle(artifact, prefix, **selection)


def load_client_installation(
    prefix: Path, *, environment: str, channel: str, platform: str = "linux/amd64"
) -> InstalledBundle:
    """Reverify an installed client bundle and its host/ABI preflight."""
    installed = read_installation(
        prefix, environment=environment, channel=channel, platform=platform
    )
    _validate_client_manifest(installed.manifest, environment, channel)
    preflight_native_client(installed.prefix, installed.manifest)
    return installed
