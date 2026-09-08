"""Version and run-provenance scaffolding for C1 synchronized development.

This module deliberately does not alter any dataset schema or generator path.
It provides an implementation-level provenance record that later C1 tasks can
attach to generated artifacts.  The identifiers describe the current
development and historical schemas; they do not claim a canonical dataset
release or completed Behavioral-model-v1 synchronization.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import uuid
from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Optional


BEHAVIOR_MODEL_VERSION = "behavioral-model-v1"
GENERATOR_SOFTWARE_VERSION = "c1-sync-development"
EVENT_SCHEMA_VERSION = "historical-event-schema-27135bf"
FEATURE_SCHEMA_VERSION = "historical-feature-schema-27135bf"
CONFIGURATION_VERSION = "historical-defaults-27135bf"


def _json_compatible(value: Any) -> Any:
    """Convert configuration values into deterministic JSON-compatible data."""
    if is_dataclass(value) and not isinstance(value, type):
        return _json_compatible(asdict(value))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Mapping):
        return {
            str(key): _json_compatible(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    return value


def configuration_snapshot(config: Any) -> dict[str, Any]:
    """Return a serializable configuration snapshot without mutating ``config``."""
    snapshot = _json_compatible(config)
    if not isinstance(snapshot, dict):
        raise TypeError("generation configuration must serialize to a mapping")
    return snapshot


def configuration_snapshot_reference(snapshot: Mapping[str, Any]) -> str:
    """Return a stable content reference for a serializable config snapshot."""
    encoded = json.dumps(
        _json_compatible(snapshot), sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def discover_generator_git_commit(repo_root: Optional[Path] = None) -> Optional[str]:
    """Resolve the generator commit from the environment or local Git checkout.

    ``GENERATOR_GIT_COMMIT`` supports packaged/CI execution where ``.git`` is
    unavailable.  Failure to inspect Git is represented explicitly as ``None``.
    """
    supplied = os.environ.get("GENERATOR_GIT_COMMIT")
    if supplied:
        return supplied

    root = repo_root or Path(__file__).resolve().parents[2]
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    commit = result.stdout.strip()
    return commit or None


@dataclass(frozen=True)
class GenerationProvenance:
    """Traceability metadata for one generation run.

    The structure is available now as C1.1 scaffolding.  It is not yet written
    into historical output schemas, because output/schema changes are outside
    this task.
    """

    behavior_model_version: str
    generator_software_version: str
    generator_git_commit: Optional[str]
    event_schema_version: str
    feature_schema_version: str
    run_id: str
    configuration_version: str
    configuration_snapshot_reference: str
    configuration_snapshot: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def build_generation_provenance(
    config: Any,
    *,
    run_id: Optional[str] = None,
    generator_git_commit: Optional[str] = None,
) -> GenerationProvenance:
    """Build a run record without starting or changing simulation execution."""
    snapshot = configuration_snapshot(config)
    return GenerationProvenance(
        behavior_model_version=BEHAVIOR_MODEL_VERSION,
        generator_software_version=GENERATOR_SOFTWARE_VERSION,
        generator_git_commit=(
            generator_git_commit
            if generator_git_commit is not None
            else discover_generator_git_commit()
        ),
        event_schema_version=EVENT_SCHEMA_VERSION,
        feature_schema_version=FEATURE_SCHEMA_VERSION,
        run_id=run_id or str(uuid.uuid4()),
        configuration_version=CONFIGURATION_VERSION,
        configuration_snapshot_reference=configuration_snapshot_reference(snapshot),
        configuration_snapshot=snapshot,
    )
