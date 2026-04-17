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

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if not isinstance(self.campaign_id, str) or not self.campaign_id:
            raise ValueError("campaign_id must be a non-empty string")
        if not isinstance(self.sampling_mode, str) or not self.sampling_mode:
            raise ValueError("sampling_mode must be a non-empty string")
        if not isinstance(self.sampling_seed, int):
            raise ValueError("sampling_seed must be an int")
        if not isinstance(self.target_evals, int) or self.target_evals < 0:
            raise ValueError("target_evals must be a non-negative int")
        if not isinstance(self.completed_pair_indices, list):
            raise ValueError("completed_pair_indices must be a list")
        if not all(isinstance(i, int) for i in self.completed_pair_indices):
            raise ValueError("completed_pair_indices must contain only ints")
        if any(i < 0 or i >= self.target_evals for i in self.completed_pair_indices):
            raise ValueError("completed_pair_indices must lie within [0, target_evals)")
        if len(set(self.completed_pair_indices)) != len(self.completed_pair_indices):
            raise ValueError("completed_pair_indices must be unique")
        if self.completed_pair_indices != sorted(self.completed_pair_indices):
            raise ValueError("completed_pair_indices must be sorted")
        if not isinstance(self.results, list):
            raise ValueError("results must be a list")
        if len(self.results) > len(self.completed_pair_indices):
            raise ValueError("results cannot outnumber completed_pair_indices")
        if not isinstance(self.filters, dict):
            raise ValueError("filters must be a dict")
        if not all(isinstance(r, dict) for r in self.results):
            raise ValueError("results must contain only dict rows")
        seen: set[int] = set()
        completed = set(self.completed_pair_indices)
        for row in self.results:
            if "idx" not in row:
                raise ValueError("every result row must include idx")
            idx = row["idx"]
            if not isinstance(idx, int):
                raise ValueError("result idx values must be ints")
            if idx not in completed:
                raise ValueError("result idx must be present in completed_pair_indices")
            if idx in seen:
                raise ValueError("result idx values must be unique")
            seen.add(idx)

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
