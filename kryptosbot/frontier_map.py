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
    status: str  # open | explored_shallow | explored_deep | has_signal | eliminated(reserved)
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
    from kryptosbot.registries import KNOWN_FAMILIES
    return sorted(f["family_id"] for f in KNOWN_FAMILIES)


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
                status = "has_signal"
            elif n >= _DEEP_THRESHOLD:
                status = "explored_deep"
            else:
                status = "explored_shallow"
            cells.append(FrontierCell(family, model, status, n, best))

    ts = (now or datetime.now(timezone.utc)).isoformat()
    return FrontierMap(cells=tuple(cells), built_at=ts)


def open_cells(fm: FrontierMap) -> list[FrontierCell]:
    """Open cells, round-robin across alignment models (non-direct first).

    Round-robin so a capped render surfaces ALL unexplored alignment
    directions rather than many cells of one alphabetically-first model.
    """
    from collections import defaultdict
    by_model: dict[str, list[FrontierCell]] = defaultdict(list)
    for c in fm.cells:
        if c.status == "open":
            by_model[c.alignment_model].append(c)
    for cells in by_model.values():
        cells.sort(key=lambda c: c.family)
    non_direct = [k for k, _ in ALIGNMENT_MODELS if k in NON_DIRECT_MODELS]
    direct = [k for k, _ in ALIGNMENT_MODELS if k in DIRECT_CARVING_MODELS]
    model_order = non_direct + direct
    idx = {m: 0 for m in model_order}
    result: list[FrontierCell] = []
    progress = True
    while progress:
        progress = False
        for m in model_order:
            lst = by_model.get(m, [])
            if idx[m] < len(lst):
                result.append(lst[idx[m]])
                idx[m] += 1
                progress = True
    return result


_MODEL_DESC = {k: d for k, d in ALIGNMENT_MODELS}
_MODEL_RANK = {k: i for i, (k, _) in enumerate(ALIGNMENT_MODELS)}


def render_open_frontier(fm: FrontierMap, *, limit: int = 12) -> str:
    """Theorist prompt block summarizing the unexplored non-direct alignment
    frontier. Empty string if no open non-direct cells.

    Surfaces ONLY non-direct alignment models. The map's status is derived
    from the kryptosbot ledger alone, so a direct-carving cell reading "open"
    is unreliable: project-wide eliminations recorded in exhaustion_log /
    elimination_tiers are not visible here, and most direct-carving cells are
    in fact eliminated. The non-direct columns, by contrast, are genuinely
    unexplored everywhere — that is the real, trustworthy frontier signal. One
    summary line per open non-direct model, with example families.
    """
    from collections import defaultdict
    fams_by_model: dict[str, set[str]] = defaultdict(set)
    for c in fm.cells:
        if c.status == "open" and c.alignment_model in NON_DIRECT_MODELS:
            fams_by_model[c.alignment_model].add(c.family)
    if not fams_by_model:
        return ""
    lines = ["OPEN FRONTIER (unexplored non-direct alignment models — the "
             "highest-value untested directions; pair a cipher family with a "
             "non-direct crib alignment):"]
    for model, _desc in ALIGNMENT_MODELS:
        if model not in NON_DIRECT_MODELS:
            continue
        fams = sorted(fams_by_model.get(model, set()))
        if not fams:
            continue
        examples = ", ".join(fams[:4])
        lines.append(f"- {model}: UNEXPLORED across {len(fams)} cipher "
                     f"families (e.g. {examples}). {_MODEL_DESC[model]}")
    return "\n".join(lines[:1 + limit])


def frontier_cell_for_theory(theory: dict, fm: FrontierMap) -> FrontierCell | None:
    """Resolve a proposed theory (dict with family/mechanism/tags) to its cell.

    Picks the highest-information alignment the theory assumes (non-direct over
    direct when the classifier returns a non-direct model), then the matching
    cell in the map. Returns None if the family is not in the grid.
    """
    family = theory.get("family") or ""
    models = alignment_models_for_row(
        family, theory.get("mechanism") or "", theory.get("tags") or [])
    # prefer a non-direct model if present (more specific signal); break ties
    # by canonical ALIGNMENT_MODELS order for determinism across frozenset iters.
    preferred = sorted(models, key=lambda m: (m in DIRECT_CARVING_MODELS, _MODEL_RANK[m]))[0]
    for c in fm.cells:
        if c.family == family and c.alignment_model == preferred:
            return c
    return None
