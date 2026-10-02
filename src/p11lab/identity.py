"""Canonical artifact dependency identities without credential hashes.

Runtime: sources, dependencies, patches, base_images, packages, toolchain, recipe,
adapter, metadata, platform, features. Derivatives (checker/proxy/derivative):
parent ArtifactRef, artifacts, dependency_locks, recipe, platform, features.
Client/native: sources, binaries, dependencies, toolchain, recipe, platform,
features. Run: artifacts (ArtifactRefs), profile, configuration, initialization,
selection, datasets, limits, attempt_id. Optional run-only secrets are excluded.
Allocate a fresh opaque UUID attempt_id for every invocation, including secret
changes. Substitute newly resolved parent ArtifactRefs after runtime rebuilds.
"""

import hashlib
import json
import re
from uuid import UUID


class IdentityError(ValueError):
    """An identity lacks a required field or has ambiguous inputs."""


_RUNTIME = {"sources", "dependencies", "patches", "base_images", "packages", "toolchain", "recipe", "adapter", "metadata", "platform", "features"}
_DERIVATIVE = {"parent", "artifacts", "dependency_locks", "recipe", "platform", "features"}
_BUNDLE = {"sources", "binaries", "dependencies", "toolchain", "recipe", "platform", "features"}
_RUN = {"artifacts", "profile", "configuration", "initialization", "selection", "datasets", "limits", "attempt_id"}
_FIELDS = {"runtime": _RUNTIME, "checker": _DERIVATIVE, "proxy": _DERIVATIVE, "derivative": _DERIVATIVE,
           "client": _BUNDLE, "native": _BUNDLE, "run": _RUN}
_SECRET = re.compile(r"(?:^|_)(?:pin|password|secret|credential|private_key|api_key|access_token)(?:$|_)", re.I)


def _require(condition, message):
    if not condition:
        raise IdentityError(message)


def _credentials(value):
    if isinstance(value, dict):
        for key, item in value.items():
            _require(isinstance(key, str), "identity object keys must be strings")
            _require(not _SECRET.search(key), "secret input must be supplied only in the excluded secrets map")
            _credentials(item)
    elif isinstance(value, list):
        for item in value:
            _credentials(item)


def _ref(value):
    _require(isinstance(value, dict) and set(value) == {"kind", "reference", "sha256", "platform"}, "artifact requires exact ArtifactRef fields")
    sha = value["sha256"]
    _require(isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha), "artifact requires full sha256")
    kind, reference = value["kind"], value["reference"]
    _require(isinstance(reference, str) and bool(reference), "artifact reference is required")
    if kind == "oci":
        _require(reference.endswith("@sha256:" + sha) and len(reference) > len("@sha256:" + sha), "OCI artifact must bind matching immutable digest")
    elif kind == "docker-local":
        _require(reference == "sha256:" + sha, "local image must bind exact config digest")
    else:
        _require(kind == "bundle", "unsupported artifact reference kind")
    _require(isinstance(value["platform"], str) and re.fullmatch(r"[a-z0-9]+/[a-z0-9]+", value["platform"]), "artifact platform is required")


def _pin(value, field):
    """Component pins are a SHA-256 string or a record with SHA/revision."""
    if isinstance(value, str):
        digest = value.rsplit("@sha256:", 1)[-1].removeprefix("sha256:")
        _require(re.fullmatch(r"[0-9a-f]{64}", digest), f"{field} requires full sha256")
    else:
        _require(isinstance(value, dict), f"{field} requires a pinned component")
        if "revision" in value:
            _require(isinstance(value["revision"], str) and re.fullmatch(r"[0-9a-f]{40}", value["revision"]), f"{field} requires full source revision")
        else:
            _require(isinstance(value.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]), f"{field} requires full sha256")


def public_identity(kind: str, inputs: dict) -> dict:
    """Validate and return a detached public identity; never include secrets."""
    _require(kind in _FIELDS, "unknown artifact identity kind")
    _require(isinstance(inputs, dict), "identity inputs must be an object")
    allowed = _FIELDS[kind] | ({"secrets"} if kind == "run" else set())
    missing, extra = _FIELDS[kind] - inputs.keys(), inputs.keys() - allowed
    _require(not missing, "identity missing required fields: " + ", ".join(sorted(missing)))
    _require(not extra, "identity has unknown fields: " + ", ".join(sorted(extra)))
    public = {k: v for k, v in inputs.items() if k != "secrets"}
    _credentials(public)
    list_fields = {"sources", "dependencies", "patches", "base_images", "packages", "toolchain", "artifacts", "dependency_locks", "binaries", "selection", "datasets"}
    map_fields = {"features", "configuration", "initialization", "limits"}
    for key, value in public.items():
        if key in list_fields:
            _require(isinstance(value, list), f"identity {key} must be a list")
        elif key in map_fields:
            _require(isinstance(value, dict), f"identity {key} must be an object")
        elif key not in {"parent", "profile"}:
            _require(isinstance(value, str) and bool(value), f"identity {key} must be a nonempty string")
    for key in ("recipe", "adapter", "metadata"):
        if key in public:
            _pin(public[key], key)
    for key in ("sources", "dependencies", "patches", "base_images", "packages", "toolchain", "dependency_locks", "binaries", "datasets"):
        for item in public.get(key, []):
            _pin(item, key)
    if "platform" in public:
        _require(re.fullmatch(r"[a-z0-9]+/[a-z0-9]+", public["platform"]), "identity platform is required")
    if kind in {"checker", "proxy", "derivative"}:
        _ref(public["parent"])
        _require(public["artifacts"], "derivative requires added artifacts")
        for artifact in public["artifacts"]:
            _pin(artifact, "artifacts")
    if kind == "runtime":
        _require(public["sources"] and public["base_images"], "runtime requires sources and base_images")
    if kind in {"client", "native"}:
        _require(public["sources"] or public["binaries"], "bundle requires sources or acquired binaries")
    if kind == "run":
        _require(public["artifacts"], "run requires participating artifacts")
        for artifact in public["artifacts"]:
            _ref(artifact)
        profile = public["profile"]
        _require(isinstance(profile, dict) and isinstance(profile.get("id"), str) and bool(profile["id"]), "profile requires id and sha256")
        _pin(profile, "profile")
        try:
            UUID(public["attempt_id"])
        except ValueError as error:
            raise IdentityError("attempt_id must be an opaque UUID") from error
        _require("secrets" not in inputs or isinstance(inputs["secrets"], dict), "secrets must be an excluded map")
    try:
        canonical = json.dumps({"schema_version": 1, "kind": kind, "inputs": public},
                               sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise IdentityError("identity requires finite JSON inputs") from error
    return json.loads(canonical)


def artifact_key(kind: str, inputs: dict) -> str:
    canonical = json.dumps(public_identity(kind, inputs), sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
