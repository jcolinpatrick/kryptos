"""Resumable campaign checkpointing for the two-layer campaign.

A checkpoint records which indices into the SamplingPlan.pairs list
have already been evaluated, plus their serialized results. On resume,
the campaign reconstructs the same plan from the same seed and mode
and skips the already-evaluated indices.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List


@dataclass
class Checkpoint:
    campaign_id: str
    sampling_mode: str
    sampling_seed: int
    target_evals: int
    completed_pair_indices: List[int] = field(default_factory=list)
    results: List[dict] = field(default_factory=list)
    started_at: str = ""
    last_updated_at: str = ""
    filters: dict = field(default_factory=dict)

    def save(self, path) -> None:
        self.last_updated_at = datetime.now(timezone.utc).isoformat()
        path = Path(path)
        os.makedirs(path.parent, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "w") as f:
            json.dump(asdict(self), f, indent=2, default=str)
        os.replace(tmp, path)

    @classmethod
    def load(cls, path) -> "Checkpoint":
        with open(path, "r") as f:
            d = json.load(f)
        return cls(
            campaign_id=d["campaign_id"],
            sampling_mode=d["sampling_mode"],
            sampling_seed=d["sampling_seed"],
            target_evals=d["target_evals"],
            completed_pair_indices=list(d.get("completed_pair_indices", [])),
            results=list(d.get("results", [])),
            started_at=d.get("started_at", ""),
            last_updated_at=d.get("last_updated_at", ""),
            filters=d.get("filters", {}),
        )

    @classmethod
    def new(cls, campaign_id: str, sampling_mode: str, sampling_seed: int,
            target_evals: int, filters: dict = None) -> "Checkpoint":
        now = datetime.now(timezone.utc).isoformat()
        return cls(
            campaign_id=campaign_id,
            sampling_mode=sampling_mode,
            sampling_seed=sampling_seed,
            target_evals=target_evals,
            completed_pair_indices=[],
            results=[],
            started_at=now,
            last_updated_at=now,
            filters=filters or {},
        )
