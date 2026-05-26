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


def _family_universe() -> list[str]:
    from kryptosbot.kb_family_map import valid_ledger_family_universe
    return sorted(valid_ledger_family_universe())


def build_frontier_map(*, ledger_db_path, family_universe=None, now=None) -> FrontierMap:
    """Build the family x alignment_model frontier map from ledger evidence.

    Status per cell: open (no tested theories), explored_shallow (1.._DEEP_THRESHOLD-1
    tested, no signal), explored_deep (>=_DEEP_THRESHOLD tested, best_crib < SIGNAL).
    """
    families = list(family_universe) if family_universe is not None else _family_universe()
    fam_set = set(families)

    agg: dict[tuple[str, str], dict] = {}
    conn = sqlite3.connect(f"file:{Path(ledger_db_path)}?mode=ro", uri=True)
    try:
        cur = conn.execute(
            "SELECT family, mechanism, tags, best_score, status FROM theories "
            "WHERE status IN ('eliminated', 'completed')")
        rows = cur.fetchall()
    finally:
        conn.close()

    for family, mechanism, tags_json, best_score, _status in rows:
        if family not in fam_set:
            continue
        try:
            tags = json.loads(tags_json) if tags_json else []
        except (ValueError, TypeError):
            tags = []
        for model in alignment_models_for_row(family, mechanism or "", tags):
            entry = agg.setdefault((family, model), {"n": 0, "best": 0})
            entry["n"] += 1
            entry["best"] = max(entry["best"], int(best_score or 0))

    cells: list[FrontierCell] = []
    for family in families:
        for model, _desc in ALIGNMENT_MODELS:
            entry = agg.get((family, model))
            if not entry or entry["n"] == 0:
                cells.append(FrontierCell(family, model, "open", 0, 0))
                continue
            n, best = entry["n"], entry["best"]
            if best >= _SIGNAL:
                status = "explored_shallow"
            elif n >= _DEEP_THRESHOLD:
                status = "explored_deep"
            else:
                status = "explored_shallow"
            cells.append(FrontierCell(family, model, status, n, best))

    ts = (now or datetime.now(timezone.utc)).isoformat()
    return FrontierMap(cells=tuple(cells), built_at=ts)


def open_cells(fm: FrontierMap) -> list[FrontierCell]:
    """Open cells, non-direct-alignment columns first (the priority frontier)."""
    opens = [c for c in fm.cells if c.status == "open"]
    opens.sort(key=lambda c: (c.alignment_model in DIRECT_CARVING_MODELS,
                              c.alignment_model, c.family))
    return opens


_MODEL_DESC = {k: d for k, d in ALIGNMENT_MODELS}


def render_open_frontier(fm: FrontierMap, *, limit: int = 12) -> str:
    """Theorist prompt block listing top open cells. Empty string if none."""
    opens = open_cells(fm)
    if not opens:
        return ""
    lines = ["OPEN FRONTIER (unexplored family x alignment-model cells — "
             "candidates for novel mechanisms; non-direct alignment first):"]
    for c in opens[:limit]:
        lines.append(f"- {c.family} x {c.alignment_model}: "
                     f"{_MODEL_DESC[c.alignment_model]} UNEXPLORED.")
    return "\n".join(lines)


def frontier_cell_for_theory(theory: dict, fm: FrontierMap) -> FrontierCell | None:
    """Resolve a proposed theory (dict with family/mechanism/tags) to its cell.

    Picks the highest-information alignment the theory assumes (non-direct over
    direct when the classifier returns a non-direct model), then the matching
    cell in the map. Returns None if the family is not in the grid.
    """
    family = theory.get("family") or ""
    models = alignment_models_for_row(
        family, theory.get("mechanism") or "", theory.get("tags") or [])
    # prefer a non-direct model if present (more specific signal)
    preferred = sorted(models, key=lambda m: m in DIRECT_CARVING_MODELS)[0]
    for c in fm.cells:
        if c.family == family and c.alignment_model == preferred:
            return c
    return None
