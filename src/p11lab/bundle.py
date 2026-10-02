"""Verify native archives and install them into an owned private prefix.

The receipt records original archive provenance; readback verifies the installed
manifest and payload without opening that archive. Host ABI and provider runtime
preconditions belong to the provider lifecycle, outside this module.
"""

from contextlib import contextmanager
import ctypes
from dataclasses import asdict, dataclass
import errno
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tarfile
import tempfile
import unicodedata
import zipfile

from .models import ArtifactRef


class BundleError(ValueError):
    """An archive or installed tree does not satisfy the native bundle contract."""


@dataclass(frozen=True)
class InstalledBundle:
    artifact: ArtifactRef
    prefix: Path
    manifest: dict
    manifest_sha256: str
    receipt_path: Path
    receipt_sha256: str


_RECEIPT = ".p11lab-install.json"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PLATFORMS = {"linux/amd64", "windows/amd64"}


def _require(condition, message):
    if not condition:
        raise BundleError(message)


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _check_digest(value):
    _require(isinstance(value, str) and _SHA256.fullmatch(value), "invalid SHA256 digest")


def _artifact(value):
    _require(isinstance(value, dict) and set(value) == {"kind", "reference", "sha256", "platform"}, "invalid ArtifactRef fields")
    _require(all(isinstance(item, str) and item for item in value.values()), "invalid ArtifactRef values")
    _require(value["kind"] == "bundle", "native archive ArtifactRef kind must be bundle")
    _check_digest(value["sha256"])
    _require(value["platform"] in _PLATFORMS, "unsupported artifact platform")
    return ArtifactRef(**value)


def _json(data):
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            _require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    def invalid_constant(value):
        raise BundleError(f"invalid JSON constant: {value}")

    try:
        result = json.loads(data, object_pairs_hook=unique_pairs, parse_constant=invalid_constant)
    except (ValueError, UnicodeError) as error:
        raise BundleError(f"invalid bundle JSON: {error}") from error
    _require(isinstance(result, dict), "bundle metadata must be an object")
    return result


def _path(name, platform):
    _require(isinstance(name, str) and name, "empty or invalid relative path")
    _require("\\" not in name and not any(ord(c) < 32 or ord(c) == 127 for c in name), "unsafe relative path")
    parts = name.split("/")
    _require(all(part and part not in {".", ".."} for part in parts), "path must be normalized and relative")
    _require(not PurePosixPath(name).is_absolute(), "absolute archive path")
    if platform == "windows/amd64":
        _require(unicodedata.normalize("NFC", name) == name, "Windows path normalization alias")
        for part in parts:
            _require(not any(c in '<>:"|?*' for c in part), "invalid Windows path")
            _require(not part.endswith((".", " ")), "Windows trailing dot or space alias")
            stem = part.split(".", 1)[0].upper()
            _require(stem not in {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
                     and not re.fullmatch(r"(?:COM|LPT)[1-9¹²³]", stem), "Windows reserved path")
    return name


def _parents(names):
    return {str(parent) for name in names for parent in PurePosixPath(name).parents if str(parent) != "."}


def _manifest(value, *, environment, channel, platform):
    _require(type(value.get("schema_version")) is int and value["schema_version"] == 1, "unsupported manifest schema_version")
    _require(platform in _PLATFORMS, "unsupported requested platform")
    for field, requested in (("environment", environment), ("channel", channel), ("platform", platform)):
        _require(isinstance(requested, str) and requested and value.get(field) == requested, f"manifest {field} does not match selection")
    _require(value.get("role") in {"native-runtime", "native-client"}, "unsupported bundle role")
    for field in ("source", "build", "host_requirements"):
        _require(isinstance(value.get(field), dict), f"manifest requires {field} object")
    _require(value["source"] and value["build"], "source and build identities cannot be empty")
    for field in ("licenses", "source_references", "tested_prerequisites"):
        _require(isinstance(value.get(field), list), f"manifest requires {field} list")
    roster = value.get("files")
    _require(isinstance(roster, list) and roster, "manifest requires nonempty file roster")
    files, folded = {}, set()
    for entry in roster:
        _require(isinstance(entry, dict) and set(entry) == {"path", "sha256", "size", "mode", "role"}, "invalid file roster entry")
        name = _path(entry["path"], platform)
        _require(name not in files, "duplicate file roster path")
        if platform == "windows/amd64":
            _require(name.casefold() not in folded, "Windows case collision")
            folded.add(name.casefold())
        _check_digest(entry["sha256"])
        _require(type(entry["size"]) is int and entry["size"] >= 0, "invalid file size")
        _require(type(entry["mode"]) is int and 0 <= entry["mode"] <= 0o777, "invalid file mode")
        _require(isinstance(entry["role"], str) and entry["role"], "invalid file role")
        files[name] = entry
    dirs = _parents(files)
    _require(not set(files) & dirs, "conflicting file and directory paths")
    if platform == "windows/amd64":
        targets = set(files) | dirs
        _require(len({p.casefold() for p in targets}) == len(targets), "Windows directory case collision")
    _require(_path(value.get("module"), platform) in files, "module is not a shipped file")
    lifecycle = value.get("lifecycle", {})
    _require(isinstance(lifecycle, dict), "invalid lifecycle path mapping")
    _require("lifecycle" in value or value["role"] == "native-client", "runtime manifest requires lifecycle mapping")
    for name, path in lifecycle.items():
        _require(isinstance(name, str) and name and _path(path, platform) in files, "lifecycle path is not a shipped file")
    return files


@dataclass
class _Member:
    name: str
    directory: bool
    size: int
    mode: int
    entry: object


@contextmanager
def _archive(artifact):
    _artifact(asdict(artifact))
    # Parse precisely the bytes that were hashed, even if the source pathname is
    # replaced or edited concurrently. Large inputs spill to an owned temp file.
    with tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024) as snapshot:
        digest = hashlib.sha256()
        with Path(artifact.reference).open("rb") as source:
            while data := source.read(1024 * 1024):
                digest.update(data)
                snapshot.write(data)
        _require(digest.hexdigest() == artifact.sha256, "archive digest mismatch")
        snapshot.seek(0)
        if zipfile.is_zipfile(snapshot):
            snapshot.seek(0)
            with zipfile.ZipFile(snapshot) as archive:
                members = []
                for info in archive.infolist():
                    mode = info.external_attr >> 16
                    kind = stat.S_IFMT(mode) if info.create_system == 3 else 0
                    directory = info.is_dir()
                    _require(kind in ({0, stat.S_IFDIR} if directory else {0, stat.S_IFREG}), "ZIP links or special entries are forbidden")
                    # Unix type/permission metadata makes zero permissions
                    # explicit. With no Unix mode (non-Unix producer or zero
                    # upper attribute word), use 0755 dirs / 0644 files and
                    # still require the manifest to match that default.
                    has_unix_mode = info.create_system == 3 and mode != 0
                    permissions = stat.S_IMODE(mode) if has_unix_mode else (0o755 if directory else 0o644)
                    members.append(_Member(info.filename, directory, info.file_size, permissions, info))
                yield members, lambda entry: archive.open(entry)
        else:
            snapshot.seek(0)
            with tarfile.open(fileobj=snapshot, mode="r:*") as archive:
                members = []
                for info in archive.getmembers():
                    _require(info.type in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}, "tar links or special entries are forbidden")
                    members.append(_Member(info.name, info.isdir(), info.size, info.mode, info))
                yield members, archive.extractfile


def _archive_layout(members, opener, artifact, selection):
    names = {}
    for member in members:
        name = member.name[:-1] if member.directory and member.name.endswith("/") else member.name
        _path(name, selection["platform"])
        _require(name not in names, "duplicate archive member")
        _require(member.mode & ~0o777 == 0, "special permission bits are forbidden")
        names[name] = member
    _require("manifest.json" in names and not names["manifest.json"].directory, "missing regular manifest.json")
    with opener(names["manifest.json"].entry) as source:
        manifest_bytes = source.read()
    manifest = _json(manifest_bytes)
    files = _manifest(manifest, **selection)
    _require(artifact.platform == selection["platform"], "artifact platform does not match selection")
    expected_files = {"manifest.json"} | {"payload/" + name for name in files}
    expected_dirs = {"payload"} | {"payload/" + name for name in _parents(files)}
    _require({name for name, member in names.items() if not member.directory} == expected_files, "archive file roster mismatch")
    _require({name for name, member in names.items() if member.directory} <= expected_dirs, "archive directory roster mismatch")
    for name, entry in files.items():
        member = names["payload/" + name]
        _require(member.size == entry["size"] and member.mode == entry["mode"], "archive file size or mode mismatch")
    return manifest, manifest_bytes, files, names


def _copy_verified(source, entry, destination=None):
    digest, size = hashlib.sha256(), 0
    while data := source.read(1024 * 1024):
        size += len(data)
        _require(size <= entry["size"], "payload exceeds declared size")
        digest.update(data)
        if destination is not None:
            destination.write(data)
    _require(size == entry["size"] and digest.hexdigest() == entry["sha256"], "payload file digest or size mismatch")


def inspect_bundle(artifact: ArtifactRef, *, environment: str, channel: str, platform: str) -> dict:
    """Verify archive identity, selection, complete layout and every payload file."""
    selection = dict(environment=environment, channel=channel, platform=platform)
    try:
        with _archive(artifact) as (members, opener):
            manifest, _, files, names = _archive_layout(members, opener, artifact, selection)
            for name, entry in files.items():
                with opener(names["payload/" + name].entry) as source:
                    _copy_verified(source, entry)
            return manifest
    except (OSError, tarfile.TarError, zipfile.BadZipFile, RuntimeError) as error:
        raise BundleError(f"cannot inspect bundle: {error}") from error


def _prefix(path):
    path = Path(path).absolute()
    _require(path.name not in {"", ".", ".."}, "invalid installation prefix")
    _require(not path.is_symlink(), "installation prefix cannot be a symlink")
    return path.parent.resolve() / path.name


def _write(path, data, mode):
    with path.open("xb") as output:
        output.write(data)
        output.flush()
        os.fchmod(output.fileno(), mode) if os.name != "nt" else os.chmod(path, mode)
        os.fsync(output.fileno())


def _sync_directory(path):
    if sys.platform == "linux":
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _create_parents(parent):
    """Return a bottom-up durability roster through the first existing ancestor.

    Keep observed missing entries in the roster even if another installer wins
    their mkdir race, so our success does not depend on that process flushing
    them. Ancestors are not cleanup-owned and are never removed on failure.
    """
    missing = []
    ancestor = parent
    while not ancestor.exists():
        missing.append(ancestor)
        ancestor = ancestor.parent
    for directory in reversed(missing):
        try:
            directory.mkdir()
        except FileExistsError:
            _require(directory.is_dir(), "destination ancestor is not a directory")
    return (parent, *(directory.parent for directory in missing))


def _place_no_replace(stage, destination):
    if sys.platform == "linux":
        library = ctypes.CDLL(None, use_errno=True)
        try:
            rename = library.renameat2
        except AttributeError as error:
            raise BundleError("Linux no-replace rename is unavailable") from error
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(stage), -100, os.fsencode(destination), 1):
            number = ctypes.get_errno()
            raise OSError(number, os.strerror(number), str(destination))
    elif sys.platform == "win32":
        # Windows rename fails if the destination exists, including empty dirs.
        os.rename(stage, destination)
    else:
        raise BundleError("native installation supports Linux and Windows only")


def _identity(path):
    info = path.lstat()
    return info.st_dev, info.st_ino


def _cleanup_owned(path, identity):
    try:
        if not path.is_symlink() and _identity(path) == identity:
            shutil.rmtree(path)
    except FileNotFoundError:
        pass


def install_bundle(artifact: ArtifactRef, prefix: Path, *, environment: str, channel: str, platform: str) -> InstalledBundle:
    """Stage verified bytes and commit without replacing any existing object."""
    _require(sys.platform in {"linux", "win32"}, "native installation supports Linux and Windows only")
    selection = dict(environment=environment, channel=channel, platform=platform)
    _artifact(asdict(artifact))
    prefix = _prefix(prefix)
    stage, owned, placed, completed = None, None, False, False
    try:
        if prefix.exists():
            installed = read_installation(prefix, **selection)
            _require(installed.artifact == artifact, "existing installation belongs to a different artifact")
            return installed
        parent_sync_paths = _create_parents(prefix.parent)
        with _archive(artifact) as (members, opener):
            manifest, manifest_bytes, files, names = _archive_layout(members, opener, artifact, selection)
            stage = Path(tempfile.mkdtemp(prefix=".p11lab-stage-", dir=prefix.parent))
            owned = _identity(stage)
            (stage / "payload").mkdir()
            for name, entry in files.items():
                target = stage / "payload" / name
                target.parent.mkdir(parents=True, exist_ok=True)
                with opener(names["payload/" + name].entry) as source, target.open("xb") as output:
                    _copy_verified(source, entry, output)
                    output.flush()
                    os.fchmod(output.fileno(), entry["mode"]) if os.name != "nt" else os.chmod(target, entry["mode"])
                    os.fsync(output.fileno())
            _write(stage / "manifest.json", manifest_bytes, 0o644)
            receipt = {"schema_version": 1, "artifact": asdict(artifact), "acquisition_source": artifact.reference,
                       "manifest_sha256": _digest(manifest_bytes), "prefix": str(prefix),
                       "platform": platform, "manifest": manifest}
            _write(stage / _RECEIPT, json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode() + b"\n", 0o600)
            for directory in sorted((p for p in stage.rglob("*") if p.is_dir()), key=lambda p: len(p.parts), reverse=True):
                _sync_directory(directory)
            _sync_directory(stage)
            try:
                _place_no_replace(stage, prefix)
            except OSError as error:
                if error.errno in {errno.EEXIST, errno.ENOTEMPTY} or isinstance(error, FileExistsError):
                    installed = read_installation(prefix, **selection)
                    _require(installed.artifact == artifact, "concurrent installation conflict")
                    for directory in parent_sync_paths:
                        _sync_directory(directory)
                    return installed
                raise
            placed = True
            for directory in parent_sync_paths:
                _sync_directory(directory)
        installed = read_installation(prefix, **selection)
        completed = True
        return installed
    except (OSError, tarfile.TarError, zipfile.BadZipFile, RuntimeError) as error:
        raise BundleError(f"cannot install bundle: {error}") from error
    finally:
        if stage is not None:
            if placed and not completed:
                _cleanup_owned(prefix, owned)
            elif not placed:
                _cleanup_owned(stage, owned)


def _regular(path):
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode), "installed metadata or payload is not a regular file")
    _require(info.st_nlink == 1, "installed hardlink aliases are forbidden")
    return info


def read_installation(prefix: Path, *, environment: str, channel: str, platform: str) -> InstalledBundle:
    """Reverify placement, receipt, manifest and the exact installed file roster."""
    selection = dict(environment=environment, channel=channel, platform=platform)
    try:
        prefix = _prefix(prefix)
        _require(prefix.is_dir(), "installation prefix is not a directory")
        _require({p.name for p in prefix.iterdir()} == {"manifest.json", "payload", _RECEIPT}, "installed root roster mismatch")
        receipt_path, manifest_path = prefix / _RECEIPT, prefix / "manifest.json"
        _regular(receipt_path)
        _regular(manifest_path)
        receipt_bytes, manifest_bytes = receipt_path.read_bytes(), manifest_path.read_bytes()
        receipt, manifest = _json(receipt_bytes), _json(manifest_bytes)
        _require(type(receipt.get("schema_version")) is int and receipt["schema_version"] == 1, "unsupported receipt schema_version")
        _require(set(receipt) == {"schema_version", "artifact", "acquisition_source", "manifest_sha256", "prefix", "platform", "manifest"}, "invalid receipt fields")
        artifact = _artifact(receipt["artifact"])
        _require(receipt["acquisition_source"] == artifact.reference, "receipt acquisition source mismatch")
        _require(receipt["prefix"] == str(prefix), "receipt placement mismatch; reinstall at the new prefix")
        _require(receipt["platform"] == platform == artifact.platform, "receipt platform mismatch")
        _require(receipt["manifest_sha256"] == _digest(manifest_bytes) and receipt["manifest"] == manifest, "receipt manifest identity mismatch")
        files = _manifest(manifest, **selection)
        payload = prefix / "payload"
        _require(stat.S_ISDIR(payload.lstat().st_mode), "payload is not a regular directory")
        actual_files, actual_dirs = set(), set()
        for directory, dirs, names in os.walk(payload, followlinks=False):
            for name in dirs:
                path = Path(directory) / name
                _require(stat.S_ISDIR(path.lstat().st_mode), "payload directory link or special entry")
                actual_dirs.add(path.relative_to(payload).as_posix())
            for name in names:
                path = Path(directory) / name
                _regular(path)
                actual_files.add(path.relative_to(payload).as_posix())
        _require(actual_files == set(files) and actual_dirs == _parents(files), "installed payload roster mismatch")
        for name, entry in files.items():
            path = payload / name
            info = _regular(path)
            _require(info.st_size == entry["size"], "installed file size mismatch")
            if os.name != "nt":
                _require(stat.S_IMODE(info.st_mode) == entry["mode"], "installed file mode mismatch")
            with path.open("rb") as source:
                _copy_verified(source, entry)
        return InstalledBundle(artifact, prefix, manifest, _digest(manifest_bytes), receipt_path, _digest(receipt_bytes))
    except OSError as error:
        raise BundleError(f"cannot read installation: {error}") from error


def validate_writable_paths(prefix: Path, paths: tuple[Path, ...]) -> None:
    """Reject state/control/output paths overlapping the resolved payload tree."""
    try:
        prefix = Path(prefix).resolve()
        for path in paths:
            resolved = Path(path).resolve()
            _require(not (resolved == prefix or resolved.is_relative_to(prefix) or prefix.is_relative_to(resolved)), "writable path overlaps installation prefix")
    except (OSError, RuntimeError) as error:
        raise BundleError(f"cannot resolve writable paths: {error}") from error
