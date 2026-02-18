"""Artifact persistence — JSONL logs and run manifests.

Provides functions for logging results in JSONL format and
creating reproducible run manifests.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class RunManifest:
    """Manifest for a reproducible experiment run.

    Contains everything needed to recreate a run exactly.
    """
    run_id: str
    experiment_name: str
    config: Dict[str, Any]
    seed: Optional[int]
    timestamp: str
    hostname: str
    python_version: str
    kryptos_version: str

    @classmethod
    def create(
        cls,
        experiment_name: str,
        config: Dict[str, Any],
        seed: Optional[int] = None,
    ) -> "RunManifest":
        """Create a new manifest with current system info."""
        import platform
        import sys
        from kryptos import __version__

        config_str = json.dumps(config, sort_keys=True, separators=(",", ":"))
        run_id = hashlib.sha256(
            f"{experiment_name}:{config_str}:{seed}:{time.time()}".encode()
        ).hexdigest()[:16]

        return cls(
            run_id=run_id,
            experiment_name=experiment_name,
            config=config,
            seed=seed,
            timestamp=datetime.now(timezone.utc).isoformat(),
            hostname=platform.node(),
            python_version=sys.version,
            kryptos_version=__version__,
        )

    def save(self, path: str | Path) -> None:
        """Save manifest to JSON file."""
        with open(path, "w") as f:
            json.dump(asdict(self), f, indent=2)

    @classmethod
    def load(cls, path: str | Path) -> "RunManifest":
        """Load manifest from JSON file."""
        with open(path) as f:
            data = json.load(f)
        return cls(**data)


class JsonlWriter:
    """Append-only JSONL log writer."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.path, "a")

    def write(self, record: Dict[str, Any]) -> None:
        """Write a single JSON record as one line."""
        self._file.write(json.dumps(record, default=str) + "\n")

    def flush(self) -> None:
        self._file.flush()

    def close(self) -> None:
        self._file.close()

    def __enter__(self) -> "JsonlWriter":
        return self

    def __exit__(self, *args) -> None:
        self.close()
