"""Real archive and filesystem checks for native bundle integrity."""

import hashlib
import io
import json
from pathlib import Path
import tarfile
import zipfile

import pytest

from p11lab import bundle
from p11lab.models import ArtifactRef


DATA = b"module bytes\n"


def manifest(platform="linux/amd64"):
    return {
        "schema_version": 1, "environment": "softhsm2", "channel": "release",
        "role": "native-runtime", "platform": platform,
        "source": {"revision": "frozen"}, "build": {"recipe_sha256": "a" * 64},
        "host_requirements": {"os": "debian13"}, "module": "lib/module.so",
        "lifecycle": {"initialize": "bin/init"},
        "files": [
            {"path": "lib/module.so", "sha256": hashlib.sha256(DATA).hexdigest(),
             "size": len(DATA), "mode": 0o644, "role": "module"},
            {"path": "bin/init", "sha256": hashlib.sha256(b"init\n").hexdigest(),
             "size": 5, "mode": 0o755, "role": "initialize"},
        ],
        "licenses": [{"id": "Apache-2.0"}], "source_references": ["source:frozen"],
        "tested_prerequisites": [{"name": "glibc", "version": "fixture"}],
    }


def archive(tmp_path, *, spec=None, extra=(), zip_archive=False):
    spec = manifest() if spec is None else spec
    path = tmp_path / ("bundle.zip" if zip_archive else "bundle.tar.gz")
    entries = [("manifest.json", json.dumps(spec).encode(), 0o644),
               ("payload/lib/module.so", DATA, 0o644), ("payload/bin/init", b"init\n", 0o755)]
    entries += list(extra)
    if zip_archive:
        with zipfile.ZipFile(path, "w") as output:
            for name, data, mode in entries:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (0o100000 | mode) << 16
                output.writestr(info, data)
    else:
        with tarfile.open(path, "w:gz") as output:
            for name, data, mode in entries:
                info = tarfile.TarInfo(name)
                info.size, info.mode = len(data), mode
                output.addfile(info, io.BytesIO(data))
    return ArtifactRef("native-bundle", str(path), hashlib.sha256(path.read_bytes()).hexdigest(), spec["platform"])


def install(artifact, prefix, **selection):
    return bundle.install_bundle(artifact, prefix, **({"environment": "softhsm2", "channel": "release", "platform": artifact.platform} | selection))


def read(prefix, **selection):
    return bundle.read_installation(prefix, **({"environment": "softhsm2", "channel": "release", "platform": "linux/amd64"} | selection))


@pytest.mark.parametrize("zip_archive", [False, True])
def test_installs_exact_verified_files_and_reads_without_source_archive(tmp_path, zip_archive):
    artifact = archive(tmp_path, zip_archive=zip_archive)
    prefix = tmp_path / "prefix with spaces"
    installed = install(artifact, prefix)
    assert installed.artifact == artifact
    assert installed.prefix == prefix.resolve()
    assert installed.manifest == manifest()
    assert (prefix / "payload/lib/module.so").read_bytes() == DATA
    assert (prefix / "payload/bin/init").stat().st_mode & 0o777 == 0o755
    assert installed.manifest_sha256 == hashlib.sha256((prefix / "manifest.json").read_bytes()).hexdigest()
    assert installed.receipt_sha256 == hashlib.sha256(installed.receipt_path.read_bytes()).hexdigest()
    Path(artifact.reference).unlink()
    assert read(prefix) == installed
    # A verified installed tree is sufficient for idempotence after acquisition cache cleanup.
    assert install(artifact, prefix) == installed


def test_inspection_verifies_identity_without_creating_prefix(tmp_path):
    artifact = archive(tmp_path)
    assert bundle.inspect_bundle(artifact, environment="softhsm2", channel="release", platform="linux/amd64") == manifest()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["bundle.tar.gz"]
    bad = ArtifactRef(artifact.kind, artifact.reference, "0" * 64, artifact.platform)
    with pytest.raises(bundle.BundleError, match="digest"):
        install(bad, tmp_path / "prefix")
    assert not (tmp_path / "prefix").exists()


@pytest.mark.parametrize("selection", [{"environment": "other"}, {"channel": "rolling"}, {"platform": "windows/amd64"}])
def test_wrong_selection_fails_before_installation(tmp_path, selection):
    with pytest.raises(bundle.BundleError):
        install(archive(tmp_path), tmp_path / "prefix", **selection)
    assert not (tmp_path / "prefix").exists()


@pytest.mark.parametrize("damage", ["changed", "missing", "extra", "mode", "link", "extra-root", "extra-directory"])
def test_readback_rejects_changed_missing_or_extra_installed_content(tmp_path, damage):
    prefix = tmp_path / "prefix"
    install(archive(tmp_path), prefix)
    module = prefix / "payload/lib/module.so"
    if damage == "changed":
        module.write_bytes(b"tampered")
    elif damage == "missing":
        module.unlink()
    elif damage == "extra":
        (prefix / "payload/extra").write_text("extra")
    elif damage == "mode":
        module.chmod(0o755)
    elif damage == "link":
        module.unlink()
        module.symlink_to(tmp_path / "outside")
    elif damage == "extra-root":
        (prefix / "extra").write_text("extra")
    else:
        (prefix / "payload/extra-directory").mkdir()
    with pytest.raises(bundle.BundleError):
        read(prefix)


@pytest.mark.parametrize("damage", ["manifest", "receipt-manifest", "receipt-prefix", "receipt-roster", "receipt-platform", "receipt-artifact"])
def test_readback_binds_manifest_receipt_and_placement(tmp_path, damage):
    prefix = tmp_path / "prefix"
    installed = install(archive(tmp_path), prefix)
    if damage == "manifest":
        path = prefix / "manifest.json"
        data = json.loads(path.read_text())
        data["source"]["revision"] = "other"
    else:
        path = installed.receipt_path
        data = json.loads(path.read_text())
        if damage == "receipt-manifest":
            data["manifest_sha256"] = "0" * 64
        elif damage == "receipt-prefix":
            data["prefix"] = str(tmp_path / "other")
        elif damage == "receipt-roster":
            data["manifest"]["files"] = []
        elif damage == "receipt-platform":
            data["platform"] = "windows/amd64"
        else:
            data["artifact"]["sha256"] = "not-a-digest"
    path.write_text(json.dumps(data))
    with pytest.raises(bundle.BundleError):
        read(prefix)


@pytest.mark.parametrize("existing", ["empty", "nonempty", "file", "symlink"])
def test_existing_unowned_destinations_are_preserved(tmp_path, existing):
    artifact = archive(tmp_path)
    prefix = tmp_path / "prefix"
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("keep")
    if existing == "file":
        prefix.write_text("keep")
    elif existing == "symlink":
        prefix.symlink_to(sentinel)
    else:
        prefix.mkdir()
        if existing == "nonempty":
            (prefix / "user-file").write_text("keep")
    before = prefix.lstat()
    with pytest.raises(bundle.BundleError):
        install(artifact, prefix)
    assert prefix.lstat().st_ino == before.st_ino
    assert sentinel.read_text() == "keep"
    if existing == "nonempty":
        assert (prefix / "user-file").read_text() == "keep"


def test_wrong_artifact_does_not_replace_verified_installation(tmp_path):
    artifact = archive(tmp_path)
    prefix = tmp_path / "prefix"
    installed = install(artifact, prefix)
    other = ArtifactRef(artifact.kind, artifact.reference, "0" * 64, artifact.platform)
    with pytest.raises(bundle.BundleError):
        install(other, prefix)
    assert read(prefix) == installed


@pytest.mark.parametrize("name", ["../sentinel", "/sentinel", "payload/../../sentinel", "payload/lib/module.so", "manifest.json", "payload\\escape", ".p11lab-install.json"])
def test_unsafe_or_duplicate_members_never_write_outside_prefix(tmp_path, name):
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("keep")
    artifact = archive(tmp_path, extra=[(name, b"replace", 0o644)])
    with pytest.raises(bundle.BundleError):
        install(artifact, tmp_path / "prefix")
    assert sentinel.read_text() == "keep"
    assert not (tmp_path / "prefix").exists()
    assert not list(tmp_path.glob(".p11lab-stage-*"))


@pytest.mark.parametrize("entry_type", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE])
def test_tar_links_and_special_entries_are_rejected(tmp_path, entry_type):
    artifact = archive(tmp_path)
    path = Path(artifact.reference)
    # Rewrite uncompressed to append an actual malicious member.
    with tarfile.open(path, "r:gz") as source:
        members = [(entry, source.extractfile(entry).read()) for entry in source.getmembers()]
    with tarfile.open(path, "w") as output:
        for entry, data in members:
            output.addfile(entry, io.BytesIO(data))
        info = tarfile.TarInfo("payload/unsafe")
        info.type, info.linkname = entry_type, "../../sentinel"
        output.addfile(info)
    artifact = ArtifactRef(artifact.kind, str(path), hashlib.sha256(path.read_bytes()).hexdigest(), artifact.platform)
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("keep")
    with pytest.raises(bundle.BundleError):
        install(artifact, tmp_path / "prefix")
    assert sentinel.read_text() == "keep"
    assert not (tmp_path / "prefix").exists()


def test_zip_symlink_is_rejected(tmp_path):
    artifact = archive(tmp_path, zip_archive=True)
    with zipfile.ZipFile(artifact.reference, "a") as output:
        info = zipfile.ZipInfo("payload/unsafe")
        info.create_system, info.external_attr = 3, 0o120777 << 16
        output.writestr(info, "../../sentinel")
    path = Path(artifact.reference)
    artifact = ArtifactRef(artifact.kind, str(path), hashlib.sha256(path.read_bytes()).hexdigest(), artifact.platform)
    with pytest.raises(bundle.BundleError):
        install(artifact, tmp_path / "prefix")
    assert not (tmp_path / "prefix").exists()


@pytest.mark.parametrize("name", ["CON", "con.txt", "aux", "COM1.log", "LPT9", "folder./file", "folder /file", "lib/module.so ", "C:/file", "file:stream", "folder\\file", "bad?name", "lib/MODULE.so"])
def test_windows_reserved_paths_aliases_and_case_collisions_are_rejected(tmp_path, name):
    spec = manifest("windows/amd64")
    spec["files"].append({"path": name, "sha256": hashlib.sha256(b"x").hexdigest(), "size": 1, "mode": 0o644, "role": "data"})
    artifact = archive(tmp_path, spec=spec, extra=[("payload/" + name, b"x", 0o644)], zip_archive=True)
    with pytest.raises(bundle.BundleError):
        install(artifact, tmp_path / "prefix")
    assert not (tmp_path / "prefix").exists()


@pytest.mark.parametrize("damage", ["digest", "size", "duplicate", "conflict", "module", "lifecycle", "schema", "role", "metadata", "mode"])
def test_invalid_manifest_or_payload_fails_before_placement(tmp_path, damage):
    spec = manifest()
    if damage == "digest":
        spec["files"][0]["sha256"] = "0" * 64
    elif damage == "size":
        spec["files"][0]["size"] += 1
    elif damage == "duplicate":
        spec["files"].append(spec["files"][0].copy())
    elif damage == "conflict":
        spec["files"][1]["path"] = "lib/module.so/child"
    elif damage == "module":
        spec["module"] = "not-shipped.so"
    elif damage == "lifecycle":
        spec["lifecycle"]["initialize"] = "../../outside"
    elif damage == "schema":
        spec["schema_version"] = 2
    elif damage == "role":
        spec["role"] = "script-installer"
    elif damage == "metadata":
        del spec["source"]
    else:
        spec["files"][0]["mode"] = 0o4755
    with pytest.raises(bundle.BundleError):
        install(archive(tmp_path, spec=spec), tmp_path / "prefix")
    assert not (tmp_path / "prefix").exists()
    assert not list(tmp_path.glob(".p11lab-stage-*"))


def test_client_bundle_can_declare_no_lifecycle(tmp_path):
    spec = manifest()
    spec["role"], spec["lifecycle"] = "native-client", {}
    assert install(archive(tmp_path, spec=spec), tmp_path / "prefix").manifest["lifecycle"] == {}


@pytest.mark.parametrize("relationship", ["same", "child", "parent", "symlink-child", "symlink-parent", "nonexistent-child"])
def test_writable_paths_cannot_alias_or_contain_immutable_prefix(tmp_path, relationship):
    prefix = tmp_path / "install"
    prefix.mkdir()
    alias = tmp_path / "alias"
    if relationship == "same":
        candidate = prefix
    elif relationship == "child":
        candidate = prefix / "state"
        candidate.mkdir()
    elif relationship == "parent":
        candidate = tmp_path
    elif relationship == "symlink-child":
        alias.symlink_to(prefix, target_is_directory=True)
        candidate = alias / "state"
    elif relationship == "symlink-parent":
        alias.symlink_to(tmp_path, target_is_directory=True)
        candidate = alias
    else:
        candidate = prefix / "nonexistent/child"
    with pytest.raises(bundle.BundleError):
        bundle.validate_writable_paths(prefix, (candidate,))
    assert not (prefix / "nonexistent").exists()


def test_sibling_writable_paths_are_allowed_and_survive_payload_removal(tmp_path):
    import shutil

    prefix = tmp_path / "install"
    install(archive(tmp_path), prefix)
    state = tmp_path / "install-state"
    state.mkdir()
    (state / "token").write_text("preserve")
    bundle.validate_writable_paths(prefix, (state, tmp_path / "control", tmp_path / "output"))
    shutil.rmtree(prefix)
    assert (state / "token").read_text() == "preserve"


def test_failure_during_receipt_flush_removes_only_owned_stage(tmp_path, monkeypatch):
    import os

    artifact = archive(tmp_path)
    keep = tmp_path / ".p11lab-stage-unowned"
    keep.mkdir()
    (keep / "sentinel").write_text("keep")
    actual_fsync = os.fsync

    def fail_receipt_fsync(fd):
        # Actual Linux file descriptors identify the real durable metadata write.
        if Path(f"/proc/self/fd/{fd}").resolve().name == ".p11lab-install.json":
            raise OSError("injected receipt disk failure")
        actual_fsync(fd)

    monkeypatch.setattr(os, "fsync", fail_receipt_fsync)
    with pytest.raises(bundle.BundleError):
        install(artifact, tmp_path / "prefix")
    assert not (tmp_path / "prefix").exists()
    assert list(tmp_path.glob(".p11lab-stage-*")) == [keep]
    assert (keep / "sentinel").read_text() == "keep"


def _contending_installer(artifact, prefix, barrier, result):
    # Synchronize independent processes immediately before the real no-replace
    # syscall so this checks contention rather than sequential idempotence.
    original = bundle._place_no_replace

    def synchronized_place(stage, destination):
        barrier.wait(timeout=15)
        original(stage, destination)

    bundle._place_no_replace = synchronized_place
    try:
        installed = install(artifact, Path(prefix))
        result.put(("ok", installed.artifact.sha256))
    except bundle.BundleError:
        result.put(("conflict", artifact.sha256))


def test_independent_concurrent_installers_never_replace_successful_result(tmp_path):
    import multiprocessing

    context = multiprocessing.get_context("spawn")
    barrier, result = context.Barrier(2), context.Queue()
    one, two = tmp_path / "one", tmp_path / "two"
    one.mkdir()
    two.mkdir()
    first = archive(one)
    spec = manifest()
    spec["source"]["revision"] = "different-frozen-source"
    second = archive(two, spec=spec)
    prefix = tmp_path / "prefix"
    processes = [context.Process(target=_contending_installer, args=(artifact, str(prefix), barrier, result)) for artifact in (first, second)]
    for process in processes:
        process.start()
    try:
        outcomes = [result.get(timeout=20) for _ in processes]
    finally:
        for process in processes:
            process.join(timeout=20)
            if process.is_alive():
                process.kill()
                process.join()
    assert all(process.exitcode == 0 for process in processes)
    assert sorted(status for status, _ in outcomes) == ["conflict", "ok"]
    winner = next(digest for status, digest in outcomes if status == "ok")
    assert read(prefix).artifact.sha256 == winner
    assert not list(tmp_path.glob(".p11lab-stage-*"))


def test_destination_appearing_at_commit_is_preserved_even_if_empty(tmp_path, monkeypatch):
    artifact = archive(tmp_path)
    prefix = tmp_path / "prefix"
    original = bundle._place_no_replace
    identities = []

    def competing_create(stage, destination):
        destination.mkdir()
        identities.append(destination.stat().st_ino)
        original(stage, destination)

    monkeypatch.setattr(bundle, "_place_no_replace", competing_create)
    with pytest.raises(bundle.BundleError):
        install(artifact, prefix)
    assert prefix.stat().st_ino == identities[0]
    assert list(prefix.iterdir()) == []
    assert not list(tmp_path.glob(".p11lab-stage-*"))


def test_post_placement_failure_removes_only_its_owned_prefix(tmp_path, monkeypatch):
    artifact = archive(tmp_path)
    original = bundle._sync_directory
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("keep")

    def fail_parent_flush(directory):
        if directory == tmp_path and (tmp_path / "prefix").exists():
            raise OSError("injected placement durability failure")
        original(directory)

    monkeypatch.setattr(bundle, "_sync_directory", fail_parent_flush)
    with pytest.raises(bundle.BundleError):
        install(artifact, tmp_path / "prefix")
    assert not (tmp_path / "prefix").exists()
    assert not list(tmp_path.glob(".p11lab-stage-*"))
    assert sentinel.read_text() == "keep"


def test_modified_placement_identity_is_not_cleaned_on_failure(tmp_path, monkeypatch):
    import os

    artifact = archive(tmp_path)
    original = bundle._sync_directory
    prefix = tmp_path / "prefix"
    moved = tmp_path / "moved-owned-install"

    def replace_after_placement(directory):
        if directory == tmp_path and prefix.exists():
            os.rename(prefix, moved)
            prefix.mkdir()
            (prefix / "sentinel").write_text("keep")
            raise OSError("injected replacement during durability flush")
        original(directory)

    monkeypatch.setattr(bundle, "_sync_directory", replace_after_placement)
    with pytest.raises(bundle.BundleError):
        install(artifact, prefix)
    assert (prefix / "sentinel").read_text() == "keep"
    assert moved.exists()


def test_installed_file_with_external_hardlink_is_rejected(tmp_path):
    import os

    prefix = tmp_path / "prefix"
    install(archive(tmp_path), prefix)
    os.link(prefix / "payload/lib/module.so", tmp_path / "external-alias")
    with pytest.raises(bundle.BundleError):
        read(prefix)


def test_relocating_files_requires_an_explicit_reinstall_receipt(tmp_path):
    import shutil

    artifact = archive(tmp_path)
    first = tmp_path / "first"
    installed = install(artifact, first)
    relocated = tmp_path / "relocated"
    shutil.copytree(first, relocated)
    with pytest.raises(bundle.BundleError, match="placement"):
        read(relocated)
    second = install(artifact, tmp_path / "second")
    assert second.artifact == installed.artifact
    assert second.manifest_sha256 == installed.manifest_sha256
    assert second.receipt_sha256 != installed.receipt_sha256


def test_native_client_may_omit_lifecycle_mapping(tmp_path):
    spec = manifest()
    spec["role"] = "native-client"
    del spec["lifecycle"]
    installed = install(archive(tmp_path, spec=spec), tmp_path / "prefix")
    assert "lifecycle" not in installed.manifest


@pytest.mark.parametrize("damage", ["invalid-json", "duplicate-key", "linked-receipt", "linked-manifest", "missing-receipt", "missing-manifest", "payload-link"])
def test_untrusted_or_missing_metadata_is_rejected(tmp_path, damage):
    prefix = tmp_path / "prefix"
    installed = install(archive(tmp_path), prefix)
    if damage == "invalid-json":
        installed.receipt_path.write_bytes(b"not json")
    elif damage == "duplicate-key":
        (prefix / "manifest.json").write_bytes(b'{"schema_version":1,"schema_version":1}')
    elif damage.startswith("missing"):
        (installed.receipt_path if damage == "missing-receipt" else prefix / "manifest.json").unlink()
    elif damage == "payload-link":
        (prefix / "payload").rename(tmp_path / "external")
        (prefix / "payload").symlink_to(tmp_path / "external", target_is_directory=True)
    else:
        path = installed.receipt_path if damage == "linked-receipt" else prefix / "manifest.json"
        path.rename(tmp_path / "external")
        path.symlink_to(tmp_path / "external")
    with pytest.raises(bundle.BundleError):
        read(prefix)


def test_interrupted_extraction_cleans_stage_without_writing_outside(tmp_path, monkeypatch):
    artifact = archive(tmp_path)
    sentinel = tmp_path / "sentinel"
    sentinel.write_text("keep")
    original = bundle._copy_verified

    def interrupt(source, entry, destination=None):
        if destination is not None:
            destination.write(source.read(2))
            destination.flush()
            raise OSError("injected interruption after a real partial write")
        original(source, entry, destination)

    monkeypatch.setattr(bundle, "_copy_verified", interrupt)
    with pytest.raises(bundle.BundleError):
        install(artifact, tmp_path / "prefix")
    assert not (tmp_path / "prefix").exists()
    assert not list(tmp_path.glob(".p11lab-stage-*"))
    assert sentinel.read_text() == "keep"


@pytest.mark.parametrize("selection", [{"environment": "other"}, {"channel": "rolling"}, {"platform": "windows/amd64"}])
def test_readback_rejects_wrong_requested_selection(tmp_path, selection):
    prefix = tmp_path / "prefix"
    install(archive(tmp_path), prefix)
    with pytest.raises(bundle.BundleError):
        read(prefix, **selection)


def test_prefix_parent_alias_records_the_actual_resolved_placement(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(actual, target_is_directory=True)
    installed = install(archive(tmp_path), alias / "prefix")
    assert installed.prefix == actual / "prefix"
    assert read(alias / "prefix") == installed


def test_same_artifact_concurrent_installers_share_only_a_fully_verified_result(tmp_path):
    import multiprocessing

    artifact = archive(tmp_path)
    context = multiprocessing.get_context("spawn")
    barrier, result = context.Barrier(2), context.Queue()
    prefix = tmp_path / "prefix"
    processes = [context.Process(target=_contending_installer, args=(artifact, str(prefix), barrier, result)) for _ in range(2)]
    for process in processes:
        process.start()
    try:
        outcomes = [result.get(timeout=20) for _ in processes]
    finally:
        for process in processes:
            process.join(timeout=20)
            if process.is_alive():
                process.kill()
                process.join()
    assert all(process.exitcode == 0 for process in processes)
    assert outcomes == [("ok", artifact.sha256), ("ok", artifact.sha256)]
    assert read(prefix).artifact == artifact
    assert not list(tmp_path.glob(".p11lab-stage-*"))
