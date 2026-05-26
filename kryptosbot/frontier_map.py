"""Open-frontier map over family x alignment_model cells (advisory).

Hybrid construction: the grid skeleton is families (KNOWN_FAMILIES union the
historical ledger universe) x the 6 canonical alignment models; per-cell
status is derived from theory-ledger evidence. Surfaces UNEXPLORED cells to
the theorist (prompt block) and the human (session briefing). Advisory only:
nothing here gates dispatch or rejects a theory.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from kryptos.alignment_models import (
    ALIGNMENT_MODELS,
    DIRECT_CARVING_MODELS,
    NON_DIRECT_MODELS,
)

# crib_score >= this is SIGNAL; a cell that never reached it despite heavy
# testing is "explored_deep".
_SIGNAL = 18
# n_tested at/above which a no-signal cell is treated as explored_deep.
_DEEP_THRESHOLD = 50

_NULL_MASK_HINTS = ("null_mask", "null mask", "nullmask", "null insertion", "null-insert")
_NON_DIRECT_HINTS = ("non_direct", "non-direct", "reorder", "transposition-first",
                     "pre-transposition", "outer transposition")
_CT73_HINTS = ("ct73", "ct-73", "73-char", "null-extracted", "null extracted")
_JOINT_HINTS = ("joint_mask", "joint mask", "mask x mechanism", "joint inference")


@dataclass(frozen=True)
class FrontierCell:
    family: str
    alignment_model: str
    status: str  # open | explored_shallow | explored_deep | eliminated(reserved)
    n_tested: int
    best_crib: int


@dataclass(frozen=True)
class FrontierMap:
    cells: tuple[FrontierCell, ...]
    built_at: str


def alignment_models_for_row(family: str, mechanism: str, tags: list[str]) -> frozenset[str]:
    """Classify a ledger row into the alignment-model set it assumes.

    Default is the direct-carving pair (the framework's implicit operating
    assumption). Explicit null-mask / non-direct / ct73 / joint hints route
    the row to the matching non-direct model(s). Coarse by design; improvable.
    """
    blob = " ".join([family or "", mechanism or "", " ".join(tags or [])]).lower()
    models: set[str] = set()
    if any(h in blob for h in _CT73_HINTS):
        models.add("ct73_null_extracted")
    if any(h in blob for h in _JOINT_HINTS):
        models.add("joint_mask_mechanism")
    if any(h in blob for h in _NULL_MASK_HINTS):
        models.add("arbitrary_null_mask")
    if any(h in blob for h in _NON_DIRECT_HINTS):
        models.add("non_direct_alignment")
    if not models:
        return DIRECT_CARVING_MODELS
    return frozenset(models)
