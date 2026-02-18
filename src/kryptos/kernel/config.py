"""Configuration dataclasses for experiments and sweeps.

All configs are explicit, serializable, and hashable for reproducibility.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class SweepConfig:
    """Configuration for a sweep campaign."""
    name: str
    transposition_family: str = "identity"
    cipher_variants: Tuple[str, ...] = ("vigenere", "beaufort", "var_beaufort")
    periods: Tuple[int, ...] = (4, 5, 6, 7)
    mask_keywords: Tuple[str, ...] = ("NONE",)
    alphabet_source: str = "thematic"
    wordlist_path: str = ""
    db_path: str = "db/sweep.sqlite"
    log_dir: str = "logs"
    workers: int = 8
    store_threshold: int = 10
    breakthrough_threshold: int = 24

    @property
    def run_id(self) -> str:
        """Deterministic run ID from config content."""
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SweepConfig":
        # Convert lists to tuples for frozen dataclass
        for key in ("cipher_variants", "periods", "mask_keywords"):
            if key in data and isinstance(data[key], list):
                data[key] = tuple(data[key])
        return cls(**data)

    @classmethod
    def from_toml(cls, path: str | Path) -> "SweepConfig":
        """Load config from TOML file."""
        import tomllib
        with open(path, "rb") as f:
            data = tomllib.load(f)
        if "campaign" in data:
            data = data["campaign"]
        return cls.from_dict(data)


@dataclass(frozen=True)
class ExperimentConfig:
    """Configuration for a single experiment."""
    name: str
    hypothesis: str = ""
    transform_stack: Tuple[Dict[str, Any], ...] = ()
    seed: Optional[int] = None
    max_iterations: int = 0
    params: Dict[str, Any] = field(default_factory=dict)

    @property
    def config_hash(self) -> str:
        payload = json.dumps(
            {"name": self.name, "transforms": list(self.transform_stack),
             "seed": self.seed, "params": dict(self.params)},
            sort_keys=True, separators=(",", ":"),
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:12]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "hypothesis": self.hypothesis,
            "transform_stack": list(self.transform_stack),
            "seed": self.seed,
            "max_iterations": self.max_iterations,
            "params": dict(self.params),
            "hash": self.config_hash,
        }
