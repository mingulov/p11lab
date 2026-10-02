"""Shared lifecycle contracts for subsequent build and run integrations."""

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ArtifactRef:
    kind: str
    reference: str
    sha256: str
    platform: str


@dataclass(frozen=True)
class RunSpec:
    environment: str
    channel: str
    mode: str
    artifact: ArtifactRef
    execution_location: str
    consumer_artifact: ArtifactRef | None
    client_artifact: ArtifactRef | None
    argv: tuple[str, ...]
    inputs: dict[str, str]
    output_dir: Path
    cwd: Path
    timeout_seconds: int


@dataclass(frozen=True)
class RunResult:
    app_returncode: int | None
    lifecycle_errors: tuple[str, ...]
    cleanup_errors: tuple[str, ...]
    exit_code: int
    receipt_path: Path
