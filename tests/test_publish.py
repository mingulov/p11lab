"""Source-first delivery gates: pins, seals, readback, admission, handoff.

No network, no registry, no Docker: the heavy end-to-end proof runs against
a local registry with evidence, not in this suite.
"""
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path

import pytest

from p11lab import publish
from p11lab.catalog import load_environment

ROOT = Path(__file__).resolve().parent.parent


def tiny_tar(path: Path, name="payload.txt", data=b"sealed bytes"):
    with tarfile.open(path, "w") as contents:
        item = tarfile.TarInfo(name)
        item.size = len(data)
        contents.addfile(item, io.BytesIO(data))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_tag_scheme_binds_digest_short_and_parses():
    digest = "ab" * 32
    tag = publish.artifact_tag("rt", "softhsm2", "release", digest)
    assert tag == "rt-softhsm2-release-" + "ab" * 6
    assert publish.parse_tag(tag) == {"role": "rt", "environment": "softhsm2",
        "channel": "release", "target": None, "short": "ab" * 6}
    native = publish.artifact_tag("native", "softhsm2", "rolling", digest, "debian13-amd64")
    assert publish.parse_tag(native)["target"] == "debian13-amd64"
    with pytest.raises(ValueError):
        publish.artifact_tag("native", "softhsm2", "release", digest)
    with pytest.raises(ValueError):
        publish.artifact_tag("rt", "softhsm2", "release", digest, "debian13-amd64")
    with pytest.raises(ValueError):
        publish.artifact_tag("rt", "softhsm2", "release", "xyz")
    with pytest.raises(ValueError):
        publish.parse_tag("latest")


def test_acquisition_requires_digest_references():
    parsed = publish.require_digest_reference("ghcr.io/mingulov/p11lab@sha256:" + "cd" * 32)
    assert parsed["repository"] == "ghcr.io/mingulov/p11lab"
    local = publish.require_digest_reference("127.0.0.1:5050/p11lab@sha256:" + "cd" * 32)
    assert local["repository"] == "127.0.0.1:5050/p11lab"
    for alias in ("ghcr.io/mingulov/p11lab:latest",
                  "ghcr.io/mingulov/p11lab:rt-softhsm2-release-aabbccddee12",
                  "ghcr.io/mingulov/p11lab@sha256:xyz",
                  "not a reference"):
        with pytest.raises(ValueError):
            publish.require_digest_reference(alias)


def test_validate_action_inputs_defaults_and_failures():
    base = {"environment": "softhsm2", "channel": "release",
            "handoff-digest": "sha256:" + "ef" * 32, "command": '["app", "--x"]'}
    normalized = publish.validate_action_inputs(base)
    assert normalized["mode"] == "direct" and normalized["timeout_seconds"] == 300
    assert normalized["command_argv"] == ["app", "--x"] and normalized["input_entries"] == []
    assert normalized["registry"] == publish.REGISTRY_PACKAGE
    full = publish.validate_action_inputs(base | {"mode": "native", "inputs": "A=1\nB=2",
        "state-dir": "/tmp/state", "timeout": "45", "working-directory": "caller"})
    assert full["input_entries"] == ["A=1", "B=2"] and full["timeout_seconds"] == 45
    bad = [base | {"channel": "stable"}, base | {"mode": "proxy"}, base | {"command": "app"},
           base | {"command": '[""]'}, base | {"command": '["a", 1]'},
           base | {"inputs": "NOEQUALS"}, base | {"timeout": "0"}, base | {"timeout": "soon"},
           base | {"handoff-digest": "latest"}, base | {"environment": "Soft HSM"},
           base | {"unknown": "x"}, {"channel": "release"}]
    for values in bad:
        with pytest.raises(ValueError):
            publish.validate_action_inputs(values)


def test_action_yml_matches_canonical_inputs():
    parsed = publish.action_inputs_from_yml((ROOT / "action.yml").read_text())
    assert set(parsed) == set(publish.ACTION_INPUTS)
    for name, spec in publish.ACTION_INPUTS.items():
        assert parsed[name].get("required", False) == spec.get("required", False), name
        assert parsed[name].get("default", "") == spec.get("default", ""), name
        assert parsed[name]["description"].strip(), name


def test_t13_workflows_and_action_pin_every_used_action():
    checked = []
    for name in (*publish.PUBLISH_WORKFLOWS,):
        text = (ROOT / ".github" / "workflows" / name).read_text()
        uses = re.findall(r"^\s*uses:\s*(\S+)", text, re.M)
        assert uses, name
        for entry in uses:
            if entry in {"./"} or entry.startswith("./"):
                continue
            repo, _, sha = entry.partition("@")
            assert repo in publish.ACTION_PINS, (name, entry)
            assert sha == publish.ACTION_PINS[repo]["sha"], (name, entry)
            checked.append((name, entry))
    action_uses = re.findall(r"^\s*uses:\s*(\S+)", (ROOT / "action.yml").read_text(), re.M)
    assert action_uses
    for entry in action_uses:
        repo, _, sha = entry.partition("@")
        assert sha == publish.ACTION_PINS[repo]["sha"], entry
        checked.append(("action.yml", entry))
    assert ("provider-release.yml", "actions/checkout@" + publish.ACTION_PINS["actions/checkout"]["sha"]) in checked
    assert any(repo == "ilammy/msvc-dev-cmd" for _, entry in checked for repo in [entry.partition("@")[0]])


def test_installers_embed_oras_pins():
    pin = publish.ORAS_PIN
    shell = (ROOT / "src" / "p11lab" / "data" / "delivery" / "install-oras.sh").read_text()
    assert f"ORAS_VERSION={pin['version']}" in shell
    assert f"ORAS_REVISION={pin['source']['revision']}" in shell
    linux = pin["artifacts"]["linux/amd64"]
    assert f"ORAS_URL={linux['url']}" in shell and f"ORAS_SHA256={linux['sha256']}" in shell
    assert f"ORAS_SIZE={linux['size']}" in shell
    pwsh = (ROOT / "src" / "p11lab" / "data" / "delivery" / "install-oras.ps1").read_text()
    windows = pin["artifacts"]["windows/amd64"]
    assert f"$OrasVersion = '{pin['version']}'" in pwsh
    assert f"$OrasRevision = '{pin['source']['revision']}'" in pwsh
    assert f"$OrasUrl = '{windows['url']}'" in pwsh and f"$OrasSha256 = '{windows['sha256']}'" in pwsh
    assert f"$OrasSize = {windows['size']}" in pwsh


def seal_fixture(tmp_path):
    spec = load_environment("softhsm2", "release")
    archive = tmp_path / "source.tar"
    digest = tiny_tar(archive)
    resolved = {"sources": [{"source": spec["lock"]["sources"][0], "archive": str(archive),
                             "sha256": digest, "checkout": str(tmp_path)}],
                "dependencies": [], "patches": []}
    receipt = publish.seal_sources(spec, resolved, tmp_path / "seal")
    manifest = publish.verify_sealed_archive(tmp_path / "seal" / "sealed-source.tar.gz", tmp_path / "extract")
    return spec, receipt, manifest


def build_receipt_for(tmp_path, spec, receipt, manifest, *, name="artifact.json"):
    from p11lab.build import runtime_inputs
    from p11lab.identity import artifact_key
    lock = spec["lock"]
    resolved_sources = {"sources": [{"source": lock["sources"][0], "sha256": manifest["sources"][0]["sha256"]}],
                        "dependencies": []}
    assert artifact_key("runtime", runtime_inputs(spec)) == manifest["build_key"]
    record = {"schema_version": 1, "build_key": manifest["build_key"], "resolved_sources": resolved_sources}
    path = tmp_path / name
    path.write_text(json.dumps(record))
    return path


def readback_proof_for(tmp_path, spec, receipt, manifest, *, name="proof"):
    pulled = tmp_path / f"{name}-pulled"
    pulled.mkdir()
    (pulled / "sealed-source.tar.gz").write_bytes((tmp_path / "seal" / "sealed-source.tar.gz").read_bytes())
    (pulled / "sealed-source.json").write_text((tmp_path / "seal" / "sealed-source.json").read_text())
    transcript = tmp_path / f"{name}-transcript.log"
    transcript.write_text("empty credential state\nanonymous pull ok\n")
    return publish.verify_readback(tmp_path / "seal" / "sealed-source.json", pulled,
                                   transcript_path=transcript, extract_dir=tmp_path / f"{name}-extract")


def pushed_manifest_for(tmp_path, *, name="pushed"):
    import hashlib as _hashlib
    receipt_path = tmp_path / "seal" / "sealed-source.json"
    archive_sha = json.loads(receipt_path.read_text())["archive_sha256"]
    document = {"schemaVersion": 2, "layers": [
        {"digest": "sha256:" + archive_sha, "size": 10},
        {"digest": "sha256:" + _hashlib.sha256(receipt_path.read_bytes()).hexdigest(), "size": 20}]}
    path = tmp_path / f"{name}-manifest.json"
    path.write_text(json.dumps(document))
    return _hashlib.sha256(path.read_bytes()).hexdigest(), path


def test_seal_and_verify_roundtrip(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    assert receipt["role"] == "sealed-source" and receipt["runtime_role"] == "runtime"
    assert receipt["environment"] == "softhsm2" and receipt["channel"] == "release"
    assert manifest["build_key"] == receipt["build_key"] and manifest["sources"][0]["size"] > 0
    assert manifest["provider_sha256"] and manifest["lock_sha256"]
    assert str(tmp_path) not in (tmp_path / "extract" / "sealed.json").read_text()


def test_seal_refuses_to_overwrite(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    archive = tmp_path / "source.tar"
    resolved = {"sources": [{"source": spec["lock"]["sources"][0], "archive": str(archive),
                             "sha256": manifest["sources"][0]["sha256"], "checkout": str(tmp_path)}],
                "dependencies": [], "patches": []}
    with pytest.raises(ValueError, match="fresh attempt"):
        publish.seal_sources(spec, resolved, tmp_path / "seal")


def test_seal_rejects_roster_drift(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    archive = tmp_path / "other.tar"
    digest = tiny_tar(archive, data=b"other")
    resolved = {"sources": [{"source": spec["lock"]["sources"][0] | {"revision": "f" * 40},
                             "archive": str(archive), "sha256": digest, "checkout": str(tmp_path)}],
                "dependencies": [], "patches": []}
    with pytest.raises(ValueError):
        publish.seal_sources(spec, resolved, tmp_path / "seal-drift")


def test_readback_detects_altered_or_missing_bytes(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    pulled = tmp_path / "evil-pulled"
    pulled.mkdir()
    (pulled / "sealed-source.tar.gz").write_bytes((tmp_path / "seal" / "sealed-source.tar.gz").read_bytes() + b"x")
    (pulled / "sealed-source.json").write_text((tmp_path / "seal" / "sealed-source.json").read_text())
    transcript = tmp_path / "transcript.log"
    transcript.write_text("anonymous pull ok\n")
    with pytest.raises(ValueError, match="mismatch"):
        publish.verify_readback(tmp_path / "seal" / "sealed-source.json", pulled,
                                transcript_path=transcript, extract_dir=tmp_path / "evil-extract")
    (pulled / "sealed-source.tar.gz").unlink()
    with pytest.raises(ValueError, match="missing"):
        publish.verify_readback(tmp_path / "seal" / "sealed-source.json", pulled,
                                transcript_path=transcript, extract_dir=tmp_path / "missing-extract")


def test_readback_requires_transcript(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    pulled = tmp_path / "no-transcript-pulled"
    pulled.mkdir()
    (pulled / "sealed-source.tar.gz").write_bytes((tmp_path / "seal" / "sealed-source.tar.gz").read_bytes())
    (pulled / "sealed-source.json").write_text((tmp_path / "seal" / "sealed-source.json").read_text())
    with pytest.raises(ValueError, match="transcript"):
        publish.verify_readback(tmp_path / "seal" / "sealed-source.json", pulled,
                                transcript_path=tmp_path / "absent.log", extract_dir=tmp_path / "extract-2")


def test_input_match_accepts_exact_build(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    match = publish.check_input_match(manifest, build, spec)
    assert match["matched_inputs"] == 1 and match["build_key"] == manifest["build_key"]


def test_input_mismatch_and_new_input_stop_upload(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    tampered = json.loads(build.read_text())
    tampered["resolved_sources"]["sources"][0]["sha256"] = "0" * 64
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(json.dumps(tampered))
    with pytest.raises(ValueError, match="input mismatch"):
        publish.check_input_match(manifest, tampered_path, spec)
    added = json.loads(build.read_text())
    added["resolved_sources"]["dependencies"] = [{"source": {"id": "sneaky", "kind": "git",
        "url": "https://example.invalid/x.git", "revision": "e" * 40, "license_status": "unreviewed"},
        "sha256": "1" * 64}]
    added_path = tmp_path / "added.json"
    added_path.write_text(json.dumps(added))
    with pytest.raises(ValueError, match="newly discovered"):
        publish.check_input_match(manifest, added_path, spec)
    rekeyed = json.loads(build.read_text())
    rekeyed["build_key"] = "2" * 64
    rekeyed_path = tmp_path / "rekeyed.json"
    rekeyed_path.write_text(json.dumps(rekeyed))
    with pytest.raises(ValueError, match="build key"):
        publish.check_input_match(manifest, rekeyed_path, spec)


def test_native_input_match_compares_manifest_and_parent(tmp_path):
    sealed = {"runtime_role": "native", "environment": "softhsm2", "channel": "release",
              "sources": [{"sha256": "aa" * 32, "source": {"archive_sha256": "aa" * 32}}],
              "patches": [], "binaries": [{"path": "lib/libsofthsm2.so", "sha256": "bb" * 32}],
              "parent": {"reference": "sha256:" + "cc" * 32}, "target_lock_sha256": "dd" * 32}
    manifest = {"source": {"sources": [{"archive_sha256": "aa" * 32}], "patches": []},
                "build": {"identity": {"inputs": {"features": {"target_lock_sha256": "dd" * 32}}}}}
    receipt = {"build_key": "ee" * 32, "parent": {"reference": "sha256:" + "cc" * 32},
               "files": [{"path": "lib/libsofthsm2.so", "sha256": "bb" * 32}]}
    receipt_path = tmp_path / "native-artifact.json"
    receipt_path.write_text(json.dumps(receipt))
    spec = {"id": "softhsm2", "channel": "release"}
    assert publish.check_input_match(sealed, receipt_path, spec, manifest=manifest)["role"] == "native"
    changed = dict(receipt, files=[{"path": "lib/libsofthsm2.so", "sha256": "ff" * 32}])
    changed_path = tmp_path / "native-changed.json"
    changed_path.write_text(json.dumps(changed))
    with pytest.raises(ValueError, match="input mismatch"):
        publish.check_input_match(sealed, changed_path, spec, manifest=manifest)
    with pytest.raises(ValueError, match="manifest"):
        publish.check_input_match(sealed, receipt_path, spec)


def test_admit_blocks_without_evidence_and_stamps_verdict(tmp_path):
    from p11lab.catalog import packaged_asset
    spec, receipt, manifest = seal_fixture(tmp_path)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    proof = readback_proof_for(tmp_path, spec, receipt, manifest)
    binary = tmp_path / "binary.tar"
    tiny_tar(binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    result = publish.admit(artifact_kind="bundle", artifact_reference=str(binary), artifact_digest=digest,
        platform="linux/amd64", sealed_receipt_path=tmp_path / "seal" / "sealed-source.json",
        sealed_manifest=manifest, readback_proof=proof, build_receipt_path=build, spec=spec,
        registry="127.0.0.1:5050/p11lab", evidence_dir=None, out_dir=tmp_path / "admission",
        producer={"p11lab_wheel_sha256": "ab" * 32},
        source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)
    assert result["status"] == "blocked"
    assert any("unreviewed" in blocker for blocker in result["blockers"])
    admission = json.loads(Path(result["admission"]).read_text())
    assert admission["catalogue"]["environment"] == "softhsm2"
    assert admission["catalogue"]["provider_sha256"] == hashlib.sha256(
        packaged_asset("softhsm2", "provider.json").read_bytes()).hexdigest()
    assert admission["verdict"]["status"] == "blocked"
    verdict = json.loads(Path(result["verdict"]).read_text())
    assert verdict["status"] == "blocked" and verdict["blockers"]


def test_admit_refuses_readback_mismatch(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    proof = readback_proof_for(tmp_path, spec, receipt, manifest)
    proof["pulled_archive_sha256"] = "9" * 64
    binary = tmp_path / "binary.tar"
    tiny_tar(binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    with pytest.raises(ValueError, match="readback"):
        publish.admit(artifact_kind="bundle", artifact_reference=str(binary), artifact_digest=digest,
            platform="linux/amd64", sealed_receipt_path=tmp_path / "seal" / "sealed-source.json",
            sealed_manifest=manifest, readback_proof=proof, build_receipt_path=build, spec=spec,
            registry="127.0.0.1:5050/p11lab", evidence_dir=None, out_dir=tmp_path / "admission-bad",
            producer={"p11lab_wheel_sha256": "ab" * 32},
        source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)


def admission_inventory(tmp_path):
    import dataclasses
    from p11lab.models import ArtifactRef
    binary = tmp_path / "binary.tar"
    with tarfile.open(binary, "w") as tar:
        item = tarfile.TarInfo("demo.txt")
        item.size = 4
        tar.addfile(item, io.BytesIO(b"demo"))
    artifact = ArtifactRef("bundle", str(binary), hashlib.sha256(binary.read_bytes()).hexdigest(), "linux/amd64")
    payloads = []
    for path, role, text in [("sources/demo.tar", "source", "complete source"),
                             ("notices/demo.txt", "notice", "original grant"),
                             ("BUILD.md", "build", "portable build instructions")]:
        local = tmp_path / Path(path).name
        local.write_text(text)
        payloads.append({"path": path, "role": role, "local_path": str(local),
                         "sha256": hashlib.sha256(local.read_bytes()).hexdigest(), "size": local.stat().st_size})
    inventory = {"schema_version": 1, "artifact": dataclasses.asdict(artifact), "role": "runtime",
        "observation": {"artifact": dataclasses.asdict(artifact), "packages": [], "binaries": [],
                        "linked_libraries": [], "files": [{"path": "/demo.txt",
                        "sha256": hashlib.sha256(b"demo").hexdigest(), "size": 4, "mode": 420, "package": None}]},
        "content_reviews": [{"path": "/demo.txt", "sha256": hashlib.sha256(b"demo").hexdigest(),
                             "source": "demo=1", "status": "reviewed"}],
        "sources": [{"id": "demo=1", "name": "demo", "version": "1", "payloads": ["sources/demo.tar"]}],
        "components": [{"id": "demo=1", "source": "demo=1", "scope": "runtime"}],
        "reviews": [{"source": "demo=1", "status": "reviewed", "grant_known": True, "source_redistribution": True,
                     "license_declared": "MIT", "license_concluded": "MIT",
                     "chosen_route": "retain grant and complete source",
                     "notices": ["notices/demo.txt"], "grant_evidence": ["notices/demo.txt"],
                     "obligations": ["source", "notice"], "modifications": "unmodified"}],
        "patches": [], "payloads": payloads, "build_instructions": "BUILD.md", "limitations": []}
    return artifact, inventory


def test_admit_eligible_with_complete_evidence(tmp_path):
    from p11lab import sources
    spec, receipt, manifest = seal_fixture(tmp_path)
    artifact, inventory = admission_inventory(tmp_path)
    evidence = tmp_path / "evidence"
    sources.collect_source_bundle(artifact, inventory, evidence)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    proof = readback_proof_for(tmp_path, spec, receipt, manifest, name="ok")
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    result = publish.admit(artifact_kind="bundle", artifact_reference=str(artifact.reference),
        artifact_digest=artifact.sha256, platform="linux/amd64",
        sealed_receipt_path=tmp_path / "seal" / "sealed-source.json", sealed_manifest=manifest,
        readback_proof=proof, build_receipt_path=build, spec=spec,
        registry="127.0.0.1:5050/p11lab", evidence_dir=evidence, out_dir=tmp_path / "admission-ok",
        producer={"p11lab_wheel_sha256": "ab" * 32},
        source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)
    assert result["status"] == "eligible", result["blockers"]
    assert json.loads(Path(result["verdict"]).read_text())["status"] == "eligible"


def test_expose_binds_pushed_bundle_after_readback(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    binary = tmp_path / "binary.tar"
    tiny_tar(binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    native_manifest = dict(manifest, runtime_role="native", target="debian13-amd64",
                           binaries=[], parent={"reference": "sha256:" + "cc" * 32})
    native_sealed = dict(native_manifest, sources=[{"sha256": manifest["sources"][0]["sha256"],
        "source": {"archive_sha256": manifest["sources"][0]["sha256"], "id": "demo"}}])
    native_build = {"build_key": manifest["build_key"], "parent": {"reference": "sha256:" + "cc" * 32},
                    "files": []}
    native_build_path = tmp_path / "native-build.json"
    native_build_path.write_text(json.dumps(native_build))
    bundle_manifest = {"source": {"sources": [dict(native_sealed["sources"][0]["source"])],
        "patches": []}, "build": {"identity": {"inputs": {"features": {"target_lock_sha256": "dd" * 32}}}}}
    native_sealed["target_lock_sha256"] = "dd" * 32
    native_spec = {"id": "softhsm2", "channel": "release", "native_target": "debian13-amd64"}
    proof = readback_proof_for(tmp_path, spec, receipt, manifest, name="native")
    proof["runtime_role"] = "native"
    (tmp_path / "seal" / "sealed-source.json").write_text(json.dumps(
        json.loads((tmp_path / "seal" / "sealed-source.json").read_text()) | {"runtime_role": "native"}))
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    result = publish.admit(artifact_kind="bundle", artifact_reference=str(binary), artifact_digest=digest,
        platform="linux/amd64", sealed_receipt_path=tmp_path / "seal" / "sealed-source.json",
        sealed_manifest=native_sealed, readback_proof=proof, build_receipt_path=native_build_path,
        spec=native_spec, registry="127.0.0.1:5050/p11lab", evidence_dir=None,
        out_dir=tmp_path / "admission-native", producer={"p11lab_wheel_sha256": "ab" * 32},
        manifest=bundle_manifest,
        source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)
    assert result["status"] == "blocked"
    pushed = "9f" * 32
    tag = publish.artifact_tag("native", "softhsm2", "release", digest, "debian13-amd64")
    exposed = publish.expose(admission_path=Path(result["admission"]), pushed_digest=pushed,
        pushed_tag=tag, pushed_size=binary.stat().st_size, local_inspect_path=None,
        pulled_inspect_path=None, pulled_bundle_path=binary,
        registry="127.0.0.1:5050/p11lab", out_dir=tmp_path / "handoff")
    handoff = publish.show_handoff(Path(exposed["handoff"]))
    assert handoff["binary"]["reference"] == "127.0.0.1:5050/p11lab@sha256:" + pushed
    assert handoff["binary"]["manifest_sha256"] == pushed
    assert handoff["binary"]["file_sha256"] == digest
    assert handoff["admission"]["status"] == "blocked"
    assert "digest" not in handoff and "handoff_sha256" not in handoff and "self_digest" not in handoff
    assert exposed["reference"].endswith(pushed)


def test_expose_refuses_mismatched_bytes_or_tag(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    binary = tmp_path / "binary.tar"
    tiny_tar(binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    native_sealed = dict(manifest, runtime_role="native", target="debian13-amd64", binaries=[],
                         parent={"reference": "sha256:" + "cc" * 32}, target_lock_sha256="dd" * 32,
                         sources=[{"sha256": manifest["sources"][0]["sha256"],
                                   "source": {"archive_sha256": manifest["sources"][0]["sha256"], "id": "demo"}}])
    native_build_path = tmp_path / "native-build.json"
    native_build_path.write_text(json.dumps({"build_key": manifest["build_key"],
        "parent": {"reference": "sha256:" + "cc" * 32}, "files": []}))
    bundle_manifest = {"source": {"sources": [dict(native_sealed["sources"][0]["source"])],
        "patches": []}, "build": {"identity": {"inputs": {"features": {"target_lock_sha256": "dd" * 32}}}}}
    proof = readback_proof_for(tmp_path, spec, receipt, manifest, name="refuse")
    proof["runtime_role"] = "native"
    (tmp_path / "seal" / "sealed-source.json").write_text(json.dumps(
        json.loads((tmp_path / "seal" / "sealed-source.json").read_text()) | {"runtime_role": "native"}))
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    result = publish.admit(artifact_kind="bundle", artifact_reference=str(binary), artifact_digest=digest,
        platform="linux/amd64", sealed_receipt_path=tmp_path / "seal" / "sealed-source.json",
        sealed_manifest=native_sealed, readback_proof=proof, build_receipt_path=native_build_path,
        spec={"id": "softhsm2", "channel": "release", "native_target": "debian13-amd64"},
        registry="127.0.0.1:5050/p11lab", evidence_dir=None, out_dir=tmp_path / "admission-refuse",
        producer={"p11lab_wheel_sha256": "ab" * 32}, manifest=bundle_manifest,
        source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)
    tag = publish.artifact_tag("native", "softhsm2", "release", digest, "debian13-amd64")
    other = tmp_path / "other.tar"
    tiny_tar(other, data=b"different")
    with pytest.raises(ValueError, match="differ"):
        publish.expose(admission_path=Path(result["admission"]), pushed_digest=digest, pushed_tag=tag,
            pushed_size=10, local_inspect_path=None, pulled_inspect_path=None,
            pulled_bundle_path=other, registry="127.0.0.1:5050/p11lab",
            out_dir=tmp_path / "handoff-bad-bytes")
    with pytest.raises(ValueError, match="alias"):
        publish.expose(admission_path=Path(result["admission"]), pushed_digest=digest, pushed_tag="latest",
            pushed_size=binary.stat().st_size, local_inspect_path=None, pulled_inspect_path=None,
            pulled_bundle_path=binary, registry="127.0.0.1:5050/p11lab",
            out_dir=tmp_path / "handoff-bad-tag")


def test_expose_compares_engine_inspects_for_runtimes(tmp_path):
    spec, receipt, manifest = seal_fixture(tmp_path)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    proof = readback_proof_for(tmp_path, spec, receipt, manifest, name="rt")
    engine = "aa" * 32
    manifest_digest, manifest_path = pushed_manifest_for(tmp_path)
    result = publish.admit(artifact_kind="docker-local", artifact_reference="sha256:" + engine,
        artifact_digest=engine, platform="linux/amd64",
        sealed_receipt_path=tmp_path / "seal" / "sealed-source.json", sealed_manifest=manifest,
        readback_proof=proof, build_receipt_path=build, spec=spec,
        registry="127.0.0.1:5050/p11lab", evidence_dir=None, out_dir=tmp_path / "admission-rt",
        producer={"p11lab_wheel_sha256": "ab" * 32},
        source_manifest_digest=manifest_digest, source_manifest_path=manifest_path)
    pushed = "bb" * 32
    tag = publish.artifact_tag("rt", "softhsm2", "release", pushed)
    before = {"Id": "sha256:" + engine, "Os": "linux", "Architecture": "amd64",
              "RootFS": {"Layers": ["sha256:" + "cc" * 32]}}
    after = dict(before, RepoDigests=["127.0.0.1:5050/p11lab@sha256:" + pushed])
    before_path, after_path = tmp_path / "before.json", tmp_path / "after.json"
    before_path.write_text(json.dumps([before]))
    after_path.write_text(json.dumps([after]))
    exposed = publish.expose(admission_path=Path(result["admission"]), pushed_digest=pushed,
        pushed_tag=tag, pushed_size=1234, local_inspect_path=before_path,
        pulled_inspect_path=after_path, pulled_bundle_path=None,
        registry="127.0.0.1:5050/p11lab", out_dir=tmp_path / "handoff-rt")
    handoff = publish.show_handoff(Path(exposed["handoff"]))
    assert handoff["binary"]["engine_id"] == "sha256:" + engine
    assert handoff["binary"]["manifest_sha256"] == pushed
    drifted = dict(after, RootFS={"Layers": ["sha256:" + "dd" * 32]})
    drifted_path = tmp_path / "drifted.json"
    drifted_path.write_text(json.dumps([drifted]))
    with pytest.raises(ValueError, match="layers differ"):
        publish.expose(admission_path=Path(result["admission"]), pushed_digest=pushed, pushed_tag=tag,
            pushed_size=1234, local_inspect_path=before_path, pulled_inspect_path=drifted_path,
            pulled_bundle_path=None, registry="127.0.0.1:5050/p11lab",
            out_dir=tmp_path / "handoff-rt-drift")


def test_show_handoff_rejects_self_digest(tmp_path):
    document = {"schema_version": 1, "registry": "127.0.0.1:5050/p11lab",
        "catalogue": {"environment": "softhsm2"},
        "source": {"manifest_sha256": "aa" * 32, "file_sha256": "aa" * 32, "tag": "t",
                   "reference": "127.0.0.1:5050/p11lab@sha256:" + "aa" * 32},
        "binary": {"kind": "bundle", "manifest_sha256": "bb" * 32, "file_sha256": "bb" * 32,
                   "tag": "t", "reference": "127.0.0.1:5050/p11lab@sha256:" + "bb" * 32},
        "admission": {"status": "blocked", "blockers": ["x"]}, "readback": {}, "producer": {},
        "exposure": {}, "self_digest": "cc" * 32}
    path = tmp_path / "handoff.json"
    path.write_text(json.dumps(document))
    with pytest.raises(ValueError, match="self-digest"):
        publish.show_handoff(path)


def test_publish_cli_wiring(tmp_path, capsys):
    from p11lab.cli import main
    spec, receipt, manifest = seal_fixture(tmp_path)
    build = build_receipt_for(tmp_path, spec, receipt, manifest)
    manifest_path = tmp_path / "sealed.json"
    manifest_path.write_text(json.dumps(manifest))
    assert main(["publish", "check-inputs", "softhsm2", "--channel", "release",
                 "--sealed-manifest", str(manifest_path), "--build-receipt", str(build)]) == 0
    proof = readback_proof_for(tmp_path, spec, receipt, manifest, name="cli")
    proof_path = tmp_path / "proof.json"
    proof_path.write_text(json.dumps(proof))
    binary = tmp_path / "binary.tar"
    tiny_tar(binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    assert main(["publish", "admit", "softhsm2", "--channel", "release",
                 "--sealed-receipt", str(tmp_path / "seal" / "sealed-source.json"),
                 "--sealed-manifest", str(manifest_path), "--readback-proof", str(proof_path),
                 "--build-receipt", str(build), "--artifact-kind", "bundle",
                 "--artifact-reference", str(binary), "--artifact-digest", digest,
                 "--registry", "127.0.0.1:5050/p11lab", "--output-dir", str(tmp_path / "cli-admission"),
                 "--producer-wheel-sha256", "ab" * 32,
                 "--source-manifest-digest", pushed_manifest_for(tmp_path, name="cli")[0],
                 "--source-manifest", str(pushed_manifest_for(tmp_path, name="cli")[1])]) == 3
    assert main(["publish", "show-handoff"]) == 2
    capsys.readouterr()


def test_action_run_echo_redacts_input_values():
    import importlib.util
    path = ROOT / "src/p11lab/data/delivery/action-run.py"
    spec = importlib.util.spec_from_file_location("action_run", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    shown = module._display(["p11lab", "run", "softhsm2", "--input", "P11LAB_PIN=1234",
                             "--input=P11LAB_SO_PIN_FILE=/run/so", "--", "my-app"])
    assert shown == ["p11lab", "run", "softhsm2", "--input", "P11LAB_PIN=***",
                     "--input=P11LAB_SO_PIN_FILE=***", "--", "my-app"]
    assert "1234" not in " ".join(shown) and "/run/so" not in " ".join(shown)
