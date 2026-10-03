"""Installed catalogue and provider-relative assets.

load_environment adds channel/channel_spec, and lock only for locked channels.
asset_root is an explicit provider directory, never a caller-cwd fallback.
"""

import hashlib
from importlib.resources import files
import json
from pathlib import Path, PurePosixPath
import re
from urllib.parse import urlsplit


class CatalogError(ValueError):
    """Invalid catalogue or incomplete build inputs."""


_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*\Z")
_SHA = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_LICENSE_STATUSES = {"unreviewed", "reviewed", "restricted", "missing"}
_RUNTIME_ENV_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}\Z")
_RUNTIME_ENV_DENIED_SUBSTRINGS = ("PIN", "SECRET", "PASSWORD", "PRIVATE", "KEY", "PASSWD", "AUTH", "CRED")
# Whole-word credential terms: bounded by underscores or name ends, so the
# reviewed PKCS#11-token directory name FHSM_TOKENS_DIR keeps validating
# while API_TOKEN-style aliases are rejected.
_RUNTIME_ENV_DENIED_WORDS = tuple(re.compile(r"(^|_)%s(_|$)" % word) for word in ("TOKEN",))
_RUNTIME_ENV_RESERVED_NAMES = {"PATH", "LD_LIBRARY_PATH", "SYSTEMROOT", "WINDIR", "HOME", "XDG_CONFIG_HOME",
                               "ENV", "SHELLOPTS", "USERPROFILE", "SHELL", "COMSPEC",
                               "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA"}
_RUNTIME_ENV_RESERVED_PREFIXES = ("P11LAB_", "P11TEST_", "PYTEST_", "PKCS11_", "LD_", "PYTHON",
                                  "TMP", "TEMP", "BASH_", "PERL", "NODE_", "RUBY", "GCONV", "XDG_")


def _require(condition, message):
    if not condition:
        raise CatalogError(message)


def _text(value):
    return isinstance(value, str) and bool(value.strip())


def _enum(value, choices):
    return isinstance(value, str) and value in choices


def _relative(path):
    _require(_text(path), "asset path must be a nonempty relative path")
    parts = path.split("/")
    _require(not PurePosixPath(path).is_absolute() and "\\" not in path
             and ":" not in path and all(p not in {"", ".", ".."} for p in parts),
             "asset path must be relative and cannot escape its provider")
    return parts


def _asset(root, path):
    target = root.joinpath(*_relative(path))
    if isinstance(root, Path):
        _require(target.resolve().is_relative_to(root.resolve()), "asset symlink escape from provider directory")
    _require(target.is_file(), f"required asset is absent: {path}")
    return target


def package_data(path: str):
    """Return an existing package data file independently of caller cwd."""
    return _asset(files("p11lab").joinpath("data"), path)


def _provider_root(environment):
    _require(isinstance(environment, str) and _ID.fullmatch(environment), "unknown environment ID")
    root = files("p11lab").joinpath("data", "providers", environment)
    _require(root.is_dir(), f"unknown environment: {environment}")
    return root


def packaged_asset(environment: str, path: str):
    """Return a provider-relative file; reject traversal and escaping symlinks."""
    return _asset(_provider_root(environment), path)



def locked_asset(environment: str, asset: dict, *, asset_root=None):
    """Resolve a declared provider asset or a shared runtime package asset."""
    scope = asset.get("scope", "provider")
    _require(_enum(scope, {"provider", "runtime"}), "unknown asset scope")
    root = (asset_root if asset_root is not None else _provider_root(environment)) if scope == "provider" else files("p11lab").joinpath("data", "runtime")
    return _asset(root, asset.get("path"))

def _json(asset):
    try:
        result = json.loads(asset.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise CatalogError(f"invalid JSON asset: {asset.name}") from error
    _require(isinstance(result, dict), "JSON asset must be an object")
    return result


def _source(source):
    _require(isinstance(source, dict), "source must be an object")
    _require(_enum(source.get("license_status"), _LICENSE_STATUSES), "source requires explicit license_status")
    url = source.get("url")
    _require(_text(url) and urlsplit(url).scheme == "https" and bool(urlsplit(url).hostname)
             and urlsplit(url).username is None and urlsplit(url).password is None,
             "source requires a public HTTPS URL without credentials")
    _require(_enum(source.get("kind"), {"git", "archive"}), "source kind must be git or archive")
    if "revision" in source:
        _require(isinstance(source["revision"], str) and _SHA.fullmatch(source["revision"]),
                 "git source revision must be a full lowercase commit SHA")
    if "sha256" in source:
        _require(isinstance(source["sha256"], str) and _SHA256.fullmatch(source["sha256"]),
                 "archive source sha256 must be full lowercase SHA-256")
    if "selector" in source:
        selector = source["selector"]
        _require(isinstance(selector, dict) and _enum(selector.get("kind"), {"branch", "tag", "default-branch", "latest-stable-tag"})
                 and _text(selector.get("value")), "source selector must declare kind and value")


def _lock(lock, root, environment):
    _require(lock.get("schema_version") == 1, "unsupported lock schema_version")
    for key in ("sources", "dependencies", "patches", "base_images", "packages", "toolchain", "assets"):
        _require(isinstance(lock.get(key), list), f"lock requires {key} list")
    _require(lock["sources"], "lock requires a primary source")
    for source in lock["sources"] + lock["dependencies"]:
        _source(source)
        _require("revision" in source if source["kind"] == "git" else "sha256" in source,
                 "locked source requires immutable revision or sha256")
    _require(lock["base_images"], "lock requires immutable base_images")
    for base in lock["base_images"]:
        _require(isinstance(base, str) and re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", base),
                 "base image must use an immutable sha256 digest")
    _require(isinstance(lock.get("features"), dict), "lock requires features object")
    roles, paths = set(), set()
    for asset in lock["assets"]:
        _require(isinstance(asset, dict), "lock asset must be an object")
        _require(_text(asset.get("role")), "lock asset requires role")
        _require(isinstance(asset.get("sha256"), str) and _SHA256.fullmatch(asset["sha256"]), "asset requires sha256")
        path = asset.get("path")
        target = locked_asset(environment, asset, asset_root=root)
        scoped_path = (asset.get("scope", "provider"), path)
        _require(scoped_path not in paths, "duplicate asset path")
        paths.add(scoped_path)
        roles.add(asset["role"])
        _require(hashlib.sha256(target.read_bytes()).hexdigest() == asset["sha256"], f"asset sha256 mismatch: {path}")
    _require({"recipe", "adapter"} <= roles, "locked entry requires recipe and adapter assets")
    for patch in lock["patches"]:
        _require(isinstance(patch, dict) and _enum(patch.get("license_status"), _LICENSE_STATUSES), "patch requires license_status")
        _require(_text(patch.get("origin")) and _text(patch.get("license")), "patch requires provenance and license")
        target = _asset(root, patch.get("path"))
        _require(hashlib.sha256(target.read_bytes()).hexdigest() == patch.get("sha256"), "patch sha256 mismatch")


def validate_runtime_env(entries) -> None:
    """Validate the provider-declared non-secret env channel (fixed values only).

    Consumers extend their environment from these entries alone; undeclared
    names stay scrubbed. Fail closed: credential-like and reserved names are
    rejected, values are single-line printable ASCII and never enter receipts.
    """
    _require(isinstance(entries, list) and 1 <= len(entries) <= 32,
             "runtime_env must be a non-empty list of fixed entries")
    seen = set()
    for entry in entries:
        _require(isinstance(entry, dict) and set(entry) == {"name", "value"},
                 "runtime_env entry must declare exactly name and value")
        name = entry["name"]
        _require(isinstance(name, str) and _RUNTIME_ENV_NAME.fullmatch(name),
                 "runtime_env name must match [A-Z][A-Z0-9_]{0,63}")
        _require(not any(part in name for part in _RUNTIME_ENV_DENIED_SUBSTRINGS),
                 "runtime_env name resembles a credential and cannot be declared")
        _require(not any(pattern.search(name) for pattern in _RUNTIME_ENV_DENIED_WORDS),
                 "runtime_env name resembles a credential and cannot be declared")
        _require(name not in _RUNTIME_ENV_RESERVED_NAMES
                 and not name.startswith(_RUNTIME_ENV_RESERVED_PREFIXES),
                 "runtime_env name is reserved for the runner or OS essentials")
        _require(name not in seen, "duplicate runtime_env name")
        seen.add(name)
        value = entry["value"]
        _require(isinstance(value, str) and 1 <= len(value) <= 4096
                 and all(0x20 <= ord(c) <= 0x7E for c in value),
                 "runtime_env value must be non-empty single-line printable ASCII")


def validate_descriptor(spec: dict, *, asset_root=None) -> None:
    """Validate a candidate without pretending planned inputs are buildable."""
    _require(isinstance(spec, dict), "descriptor must be an object")
    _require(spec.get("schema_version") == 1, "unsupported descriptor schema_version")
    _require(isinstance(spec.get("id"), str) and _ID.fullmatch(spec["id"]), "invalid environment id")
    for key in ("module_implementation", "backend"):
        value = spec.get(key)
        _require(isinstance(value, dict) and _text(value.get("name")), f"descriptor requires {key} identity")
    for key in ("runtime_platforms", "client_platforms"):
        value = spec.get(key)
        _require(isinstance(value, list) and value and all(isinstance(p, str) and re.fullmatch(r"[a-z0-9]+/[a-z0-9]+", p) for p in value), f"descriptor requires {key}")
    _require(_enum(spec.get("state_mode"), {"persistent", "ephemeral", "process-local"}), "invalid state_mode")
    _require(_text(spec.get("module_path")), "descriptor requires module_path")
    if "runtime_env" in spec:
        validate_runtime_env(spec["runtime_env"])
    _require(isinstance(spec.get("inputs"), dict), "descriptor requires inputs object")
    _require(isinstance(spec.get("services"), list), "descriptor requires services list")
    _require(_text(spec.get("application_profile")), "descriptor requires application_profile")
    distribution = spec.get("distribution")
    _require(isinstance(distribution, dict) and _enum(distribution.get("status"), {"unreviewed", "blocked"})
             and set(distribution) <= {"status", "reason"}, "distribution admission requires digest-bound evidence, not descriptor permission")
    _require(_text(distribution.get("reason")), "distribution requires explicit reason")
    targets = spec.get('native_targets', {})
    _require(isinstance(targets, dict), 'native_targets must be an object')
    for target, native in targets.items():
        _require(target in {'debian13-amd64', 'windows-amd64'} and isinstance(native, dict), 'invalid native target')
        if native.get('status') == 'not-packaged':
            _require(_text(native.get('reason')), 'not-packaged native target requires a reason')
        else:
            _require(native.get('status') == 'packaged' and native.get('platform') in {'linux/amd64', 'windows/amd64'}
                     and isinstance(native.get('host_requirements'), dict) and native['host_requirements'], 'invalid packaged native target')
            _relative(native.get('module_path'))
            _require(isinstance(native.get('channels'), dict) and set(native['channels']) == {'release', 'rolling'}, 'native target requires channel dispositions')
            for value in native['channels'].values():
                _require(isinstance(value, dict) and value.get('status') in {'locked', 'not-packaged'}, 'invalid native channel')
                if value['status'] == 'locked':
                    _asset(asset_root if asset_root is not None else _provider_root(spec['id']), value.get('lock'))
                else:
                    _require(_text(value.get('reason')), 'native source channel requires not-packaged reason')
    channels = spec.get("channels")
    _require(isinstance(channels, dict) and set(channels) == {"release", "rolling"}, "descriptor requires release and rolling channels")
    for name, channel in channels.items():
        _require(isinstance(channel, dict), f"invalid channel: {name}")
        status = channel.get("status")
        if status == "planned":
            _require(set(channel) == {"status", "source", "pending"}, "planned channel requires source/pending and cannot declare lock or recipe assets")
            _require(_text(channel["pending"]), "planned channel requires pending disposition")
            _source(channel["source"])
            _require("selector" in channel["source"], "planned source requires selector")
        elif status == "unavailable":
            _require(set(channel) == {"status", "reason"} and _text(channel.get("reason")), "unavailable channel requires factual reason")
        elif status == "locked":
            _require(set(channel) == {"status", "lock"}, "locked channel requires lock path")
            root = asset_root if asset_root is not None else _provider_root(spec["id"])
            _lock(_json(_asset(root, channel["lock"])), root, spec["id"])
        else:
            raise CatalogError(f"unknown channel status: {name}")


def load_environment(id: str, channel: str) -> dict:
    spec = _json(packaged_asset(id, "provider.json"))
    _require(spec.get("id") == id, "environment ID does not match packaged descriptor")
    validate_descriptor(spec)
    _require(channel in spec["channels"], f"unknown channel: {channel}")
    spec["channel"] = channel
    spec["channel_spec"] = spec["channels"][channel]
    if spec["channel_spec"]["status"] == "locked":
        spec["lock"] = _json(packaged_asset(id, spec["channel_spec"]["lock"]))
    return spec


def validate_build_inputs(spec: dict, *, asset_root=None) -> None:
    """Require selected locked inputs and hash-verified packaged build assets."""
    validate_descriptor(spec, asset_root=asset_root)
    selected = spec["channels"].get(spec.get("channel"))
    _require(selected is not None, "build requires a selected channel")
    _require(selected.get("status") == "locked", "build requires locked inputs; channel is planned or unavailable")
    _require(spec.get("channel_spec") == selected, "selected channel_spec conflicts with descriptor")
    root = asset_root if asset_root is not None else _provider_root(spec["id"])
    actual = _json(_asset(root, selected["lock"]))
    _require(spec.get("lock") == actual, "selected lock conflicts with packaged lock")


def list_environments() -> list[dict]:
    root = files("p11lab").joinpath("data", "providers")
    result = []
    for entry in sorted(root.iterdir(), key=lambda p: p.name):
        if entry.is_dir():
            spec = _json(_asset(entry, "provider.json"))
            _require(spec.get("id") == entry.name, "environment ID does not match packaged directory")
            validate_descriptor(spec)
            result.append(spec)
    return result


def validate_tools(spec: dict) -> None:
    """Validate tool source pins without treating them as built artifacts."""
    _require(isinstance(spec, dict) and spec.get("schema_version") == 1, "unsupported tools schema_version")
    tools = spec.get("tools")
    _require(isinstance(tools, dict) and {"checker", "proxy", "p11scope", "oras", "consumer"} <= tools.keys(), "tools catalogue requires declared integrations")
    for name, tool in tools.items():
        _require(isinstance(tool, dict) and tool.get("status") == "planned", f"tool requires explicit planned status: {name}")
        _require(_text(tool.get("pending")) and tool.get("artifacts") == [], "planned tool cannot claim acquired artifacts")
        if name == "consumer":
            _require(_enum(tool.get("license_status"), _LICENSE_STATUSES), "consumer requires license_status")
        else:
            _source(tool.get("source"))
            _require("revision" in tool["source"] or "selector" in tool["source"], "tool source requires a revision or pending selector")


def load_native_target(id: str, channel: str, target: str) -> dict:
    """Load a separately locked native target; container locks are never substitutes."""
    spec = load_environment(id, channel)
    selected = spec.get('native_targets', {}).get(target)
    _require(selected is not None, f'native target {target}: not-packaged (no packaging recipe)')
    _require(selected.get('status') == 'packaged', f'native target {target}: not-packaged ({selected.get("reason", "unsupported")})')
    choice = selected.get('channels', {}).get(channel, {})
    _require(choice.get('status') == 'locked', 'native source channel is not packaged')
    lock = _json(packaged_asset(id, choice['lock']))
    _require(lock.get('schema_version') == 1 and lock.get('target') == target and lock.get('channel') == channel
             and lock.get('platform') == selected.get('platform'), 'native target lock tuple mismatch')
    _require(isinstance(lock.get('host_requirements'), dict) and lock['host_requirements']
             and selected.get('module_path') == 'lib/libsofthsm2.so', 'invalid native target contract')
    for source in lock.get('sources', []):
        _source(source)
    _require(lock.get('sources') and isinstance(lock.get('binaries'), list) and lock['binaries'], 'native lock requires source and binary identities')
    for asset in lock.get('assets', []):
        _require(hashlib.sha256(packaged_asset(id, asset['path']).read_bytes()).hexdigest() == asset.get('sha256'),
                 'native asset sha256 mismatch')
    return spec | {'native_target': target, 'native_target_spec': selected, 'native_lock': lock}
