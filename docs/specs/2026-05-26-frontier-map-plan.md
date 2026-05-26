# Open-Frontier Map — Implementation Plan (Plan 1 of 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build an advisory open-frontier map over `family × alignment_model` cells that surfaces unexplored cells to the theorist (prompt block) and the human (session briefing), plus a soft post-verdict annotation — no hard gate, no auto-dispatch.

**Architecture:** A new `kryptosbot/frontier_map.py` computes per-cell status from the theory ledger (hybrid: grid skeleton from `KNOWN_FAMILIES` × the 6 canonical alignment models; status derived from ledger evidence). A render function feeds a new optional block into `_build_theorist_prompt` (same conditional-join idiom as `family_yield_block`). The canonical alignment taxonomy moves to `src/kryptos/alignment_models.py` (single source of truth for both `session_briefing` and `frontier_map`).

**Tech Stack:** Python 3.12, stdlib only (sqlite3, dataclasses, json). `pytest` via `venv/bin/python -m pytest -n <N>` for parallel runs. All commands `PYTHONPATH=src`.

**Spec:** `docs/specs/2026-05-26-frontier-map-and-historical-prior-design.md`

**MVP scope note:** This plan emits statuses `{open, explored_shallow, explored_deep}` derived from the ledger. The spec's fourth status `eliminated` is a reserved value the data model accepts but the MVP does not emit (it folds into `explored_deep` = "covered, do not prioritize"); a later iteration can split it using claims-registry alignment tags. Plan 2 (historical-feasibility prior) is separate.

---

## File Structure

- **Create** `src/kryptos/alignment_models.py` — canonical `ALIGNMENT_MODELS` 6-tuple + derived sets. (Task 1)
- **Create** `tests/test_alignment_models.py` — taxonomy regression. (Task 1)
- **Modify** `scripts/_infra/session_briefing.py` — import the canonical taxonomy (replace local def); add OPEN FRONTIER render section. (Tasks 2, 6)
- **Create** `kryptosbot/frontier_map.py` — dataclasses, alignment classifier, `build_frontier_map`, `open_cells`, `render_open_frontier`, `frontier_cell_for_theory`. (Tasks 3-5)
- **Create** `kryptosbot/tests/test_frontier_map.py` — module tests. (Tasks 3-5)
- **Modify** `kryptosbot/controller.py` — landscape attach (~L2296), theorist prompt block (~L3530/L3950), post-verdict soft annotation. (Task 7)
- **Modify** `kryptosbot/tests/test_frontier_map_integration.py` (new) — controller integration + advisory invariant. (Task 7)

Parallel runs: `PYTHONPATH=src /home/cpatrick/kryptos/venv/bin/python -m pytest <targets> -q -n 8`. NOTE: never collect `tests/` and `kryptosbot/tests/` together (duplicate-basename collision); run them separately.

---

## Task 1: Canonical alignment taxonomy

**Files:**
- Create: `src/kryptos/alignment_models.py`
- Test: `tests/test_alignment_models.py`

- [ ] **Step 1: Write the failing test**

`tests/test_alignment_models.py`:
```python
from kryptos.alignment_models import (
    ALIGNMENT_MODELS, ALIGNMENT_MODEL_KEYS,
    DIRECT_CARVING_MODELS, NON_DIRECT_MODELS,
)


def test_six_models_exact_keys():
    assert [k for k, _ in ALIGNMENT_MODELS] == [
        "direct_ct_pt", "fixed_len_97", "ct73_null_extracted",
        "arbitrary_null_mask", "non_direct_alignment", "joint_mask_mechanism",
    ]


def test_every_model_has_a_description():
    assert all(isinstance(d, str) and d for _, d in ALIGNMENT_MODELS)


def test_direct_and_non_direct_partition_the_keys():
    assert DIRECT_CARVING_MODELS == {"direct_ct_pt", "fixed_len_97"}
    assert NON_DIRECT_MODELS == ALIGNMENT_MODEL_KEYS - DIRECT_CARVING_MODELS
    assert DIRECT_CARVING_MODELS | NON_DIRECT_MODELS == ALIGNMENT_MODEL_KEYS
    assert DIRECT_CARVING_MODELS & NON_DIRECT_MODELS == set()
```

- [ ] **Step 2: Run to verify it fails**

Run: `PYTHONPATH=src python3 -m pytest tests/test_alignment_models.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'kryptos.alignment_models'`.

- [ ] **Step 3: Create the module**

`src/kryptos/alignment_models.py`:
```python
"""Canonical K4 crib-alignment model taxonomy (single source of truth).

The six alignment models describe what positional assumption a hypothesis
makes about how the carved ciphertext maps to plaintext. Consumed by the
session briefing (assumption-boundary audit) and the controller's frontier
map. Moved here from scripts/_infra/session_briefing.py so both surfaces
read one definition.
"""
from __future__ import annotations

ALIGNMENT_MODELS: tuple[tuple[str, str], ...] = (
    ("direct_ct_pt",
     "Direct CT[i] -> PT[i] crib mapping (each carved char decrypts in place)."),
    ("fixed_len_97",
     "Fixed CT_LEN=97 / fixed public crib positions 21-33, 63-73 (no nulls)."),
    ("ct73_null_extracted",
     "Specific null-extracted CT73-style models (a fixed 24-position extraction)."),
    ("arbitrary_null_mask",
     "Arbitrary null-mask / variable-PT-length models (mask positions unknown)."),
    ("non_direct_alignment",
     "Non-direct crib-alignment models (outer layer reorders CT before decrypt)."),
    ("joint_mask_mechanism",
     "Joint mask x mechanism inference (mask and cipher solved together)."),
)

ALIGNMENT_MODEL_KEYS: frozenset[str] = frozenset(k for k, _ in ALIGNMENT_MODELS)

# The two sub-assumptions that constitute the "direct carving" default that
# nearly all historical K4 work implicitly made.
DIRECT_CARVING_MODELS: frozenset[str] = frozenset({"direct_ct_pt", "fixed_len_97"})

# The under-explored frontier columns.
NON_DIRECT_MODELS: frozenset[str] = ALIGNMENT_MODEL_KEYS - DIRECT_CARVING_MODELS
```

- [ ] **Step 4: Run to verify it passes**

Run: `PYTHONPATH=src python3 -m pytest tests/test_alignment_models.py -q`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/kryptos/alignment_models.py tests/test_alignment_models.py
git commit -m "feat(alignment-models): canonical crib-alignment taxonomy as single source of truth"
```

---

## Task 2: session_briefing imports the canonical taxonomy

**Files:**
- Modify: `scripts/_infra/session_briefing.py` (the `ALIGNMENT_MODELS` definition at ~L597-610 and `_ALIGNMENT_MODEL_KEYS` at ~L612)
- Test: `tests/test_alignment_models.py` (add a regression)

- [ ] **Step 1: Add the regression test**

Append to `tests/test_alignment_models.py`:
```python
def test_session_briefing_uses_canonical_taxonomy():
    import importlib.util
    from pathlib import Path
    from kryptos.alignment_models import ALIGNMENT_MODELS
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "session_briefing", root / "scripts" / "_infra" / "session_briefing.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.ALIGNMENT_MODELS is ALIGNMENT_MODELS
```

- [ ] **Step 2: Run to verify it fails**

Run: `PYTHONPATH=src python3 -m pytest tests/test_alignment_models.py::test_session_briefing_uses_canonical_taxonomy -q`
Expected: FAIL — `mod.ALIGNMENT_MODELS` is the local tuple, not the canonical object (`is` check fails).

- [ ] **Step 3: Replace the local definition with an import**

In `scripts/_infra/session_briefing.py`, delete the local `ALIGNMENT_MODELS: tuple[...] = ( ... )` block (currently ~L597-610) and the `_ALIGNMENT_MODEL_KEYS = frozenset(...)` line (~L612). Replace both with an import near the other `from kryptos...` imports at the top of the file:
```python
from kryptos.alignment_models import ALIGNMENT_MODELS, ALIGNMENT_MODEL_KEYS as _ALIGNMENT_MODEL_KEYS
```
(Keep the `_ALIGNMENT_MODEL_KEYS` alias name so the existing references at ~L702/L919 are unchanged.)

- [ ] **Step 4: Run to verify it passes + briefing still runs**

Run: `PYTHONPATH=src python3 -m pytest tests/test_alignment_models.py -q`
Expected: PASS (4 tests).
Run: `PYTHONPATH=src python3 scripts/_infra/session_briefing.py >/dev/null && echo OK`
Expected: `OK` (briefing still produces output; no import error).

- [ ] **Step 5: Commit**

```bash
git add scripts/_infra/session_briefing.py tests/test_alignment_models.py
git commit -m "refactor(session-briefing): consume canonical alignment taxonomy"
```

---

## Task 3: frontier_map dataclasses + alignment classifier

**Files:**
- Create: `kryptosbot/frontier_map.py`
- Test: `kryptosbot/tests/test_frontier_map.py`

- [ ] **Step 1: Write the failing test**

`kryptosbot/tests/test_frontier_map.py`:
```python
from kryptosbot.frontier_map import (
    FrontierCell, alignment_models_for_row,
)
from kryptos.alignment_models import DIRECT_CARVING_MODELS


def test_default_row_is_direct_carving():
    assert alignment_models_for_row("vigenere", "periodic vigenere sweep", []) \
        == DIRECT_CARVING_MODELS


def test_null_mask_hint_routes_to_arbitrary_null_mask():
    got = alignment_models_for_row("key_tape", "finite tape with null_mask insertion", [])
    assert got == frozenset({"arbitrary_null_mask"})


def test_non_direct_hint_routes_to_non_direct_alignment():
    got = alignment_models_for_row("transposition", "outer transposition reorders CT then decrypt", ["non_direct"])
    assert got == frozenset({"non_direct_alignment"})


def test_cell_is_frozen_dataclass():
    c = FrontierCell("vigenere", "direct_ct_pt", "open", 0, 0)
    assert c.family == "vigenere" and c.status == "open"
```

- [ ] **Step 2: Run to verify it fails**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_frontier_map.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'kryptosbot.frontier_map'`.

- [ ] **Step 3: Create the module skeleton + classifier**

`kryptosbot/frontier_map.py`:
```python
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_frontier_map.py -q`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/frontier_map.py kryptosbot/tests/test_frontier_map.py
git commit -m "feat(frontier-map): dataclasses + alignment-model row classifier"
```

---

## Task 4: build_frontier_map from the ledger

**Files:**
- Modify: `kryptosbot/frontier_map.py`
- Test: `kryptosbot/tests/test_frontier_map.py`

- [ ] **Step 1: Write the failing test (with a fixture ledger)**

Append to `kryptosbot/tests/test_frontier_map.py`:
```python
import sqlite3
from kryptosbot.frontier_map import build_frontier_map, FrontierMap


def _make_ledger(tmp_path, rows):
    """rows: list of (family, mechanism, tags_list, best_score, status)."""
    db = tmp_path / "ledger.sqlite"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE theories (family TEXT, mechanism TEXT, tags TEXT, "
        "best_score REAL, status TEXT)")
    import json as _j
    for fam, mech, tags, score, status in rows:
        conn.execute("INSERT INTO theories VALUES (?,?,?,?,?)",
                     (fam, mech, _j.dumps(tags), score, status))
    conn.commit(); conn.close()
    return db


def test_empty_ledger_all_cells_open(tmp_path):
    db = _make_ledger(tmp_path, [])
    fm = build_frontier_map(ledger_db_path=db)
    assert isinstance(fm, FrontierMap)
    assert fm.cells, "grid skeleton must be non-empty"
    assert all(c.status == "open" for c in fm.cells)


def test_direct_carving_work_leaves_non_direct_columns_open(tmp_path):
    # 60 eliminated direct-carving vigenere theories, all noise.
    rows = [("vigenere", "periodic vigenere", [], 5.0, "eliminated")] * 60
    db = _make_ledger(tmp_path, rows)
    fm = build_frontier_map(ledger_db_path=db)
    by = {(c.family, c.alignment_model): c for c in fm.cells}
    # direct columns for vigenere are explored_deep (60 tested, best 5 < 18)
    assert by[("vigenere", "direct_ct_pt")].status == "explored_deep"
    assert by[("vigenere", "fixed_len_97")].status == "explored_deep"
    # the four non-direct columns for vigenere stay OPEN (the asymmetry)
    for model in ("ct73_null_extracted", "arbitrary_null_mask",
                  "non_direct_alignment", "joint_mask_mechanism"):
        assert by[("vigenere", model)].status == "open"


def test_shallow_vs_deep_threshold(tmp_path):
    rows = [("beaufort", "beaufort", [], 4.0, "eliminated")] * 3
    db = _make_ledger(tmp_path, rows)
    fm = build_frontier_map(ledger_db_path=db)
    by = {(c.family, c.alignment_model): c for c in fm.cells}
    assert by[("beaufort", "direct_ct_pt")].status == "explored_shallow"
```

- [ ] **Step 2: Run to verify it fails**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_frontier_map.py -k build -q`
Expected: FAIL — `ImportError: cannot import name 'build_frontier_map'`.

- [ ] **Step 3: Implement build_frontier_map**

Append to `kryptosbot/frontier_map.py`:
```python
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

    # (family, alignment_model) -> {"n": int, "best": int}
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
                status = "explored_shallow"  # signal-bearing: leave for human, not "deep dead"
            elif n >= _DEEP_THRESHOLD:
                status = "explored_deep"
            else:
                status = "explored_shallow"
            cells.append(FrontierCell(family, model, status, n, best))

    ts = (now or datetime.now(timezone.utc)).isoformat()
    return FrontierMap(cells=tuple(cells), built_at=ts)
```

- [ ] **Step 4: Run to verify it passes**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_frontier_map.py -q`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/frontier_map.py kryptosbot/tests/test_frontier_map.py
git commit -m "feat(frontier-map): build cells from ledger evidence (open-cell asymmetry)"
```

---

## Task 5: open_cells, render_open_frontier, frontier_cell_for_theory

**Files:**
- Modify: `kryptosbot/frontier_map.py`
- Test: `kryptosbot/tests/test_frontier_map.py`

- [ ] **Step 1: Write the failing test**

Append to `kryptosbot/tests/test_frontier_map.py`:
```python
from kryptosbot.frontier_map import (
    open_cells, render_open_frontier, frontier_cell_for_theory,
)


def test_open_cells_prioritize_non_direct(tmp_path):
    rows = [("vigenere", "periodic vigenere", [], 5.0, "eliminated")] * 60
    db = _make_ledger(tmp_path, rows)
    fm = build_frontier_map(ledger_db_path=db)
    oc = open_cells(fm)
    assert all(c.status == "open" for c in oc)
    # non-direct alignment models sort ahead of any direct ones in the open list
    first_models = [c.alignment_model for c in oc[:4]]
    assert all(m not in ("direct_ct_pt", "fixed_len_97") for m in first_models)


def test_render_is_deterministic_and_capped(tmp_path):
    db = _make_ledger(tmp_path, [])
    fm = build_frontier_map(ledger_db_path=db)
    a = render_open_frontier(fm, limit=5)
    b = render_open_frontier(fm, limit=5)
    assert a == b
    assert a.count("\n- ") <= 5
    assert "OPEN FRONTIER" in a


def test_render_empty_when_no_open_cells():
    fm = FrontierMap(cells=(FrontierCell("x", "direct_ct_pt", "explored_deep", 99, 5),),
                     built_at="t")
    assert render_open_frontier(fm, limit=5) == ""


def test_frontier_cell_for_theory_classifies(tmp_path):
    db = _make_ledger(tmp_path, [])
    fm = build_frontier_map(ledger_db_path=db, family_universe=["vigenere"])
    theory = {"family": "vigenere", "mechanism": "periodic vigenere", "tags": []}
    cell = frontier_cell_for_theory(theory, fm)
    assert cell is not None
    assert cell.family == "vigenere"
    assert cell.alignment_model in ("direct_ct_pt", "fixed_len_97")
```

- [ ] **Step 2: Run to verify it fails**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_frontier_map.py -k "open_cells or render or for_theory" -q`
Expected: FAIL — names not importable.

- [ ] **Step 3: Implement the three functions**

Append to `kryptosbot/frontier_map.py`:
```python
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_frontier_map.py -q`
Expected: PASS (11 tests).

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/frontier_map.py kryptosbot/tests/test_frontier_map.py
git commit -m "feat(frontier-map): open_cells + render_open_frontier + theory classifier"
```

---

## Task 6: session_briefing OPEN FRONTIER section

**Files:**
- Modify: `scripts/_infra/session_briefing.py`
- Test: `kryptosbot/tests/test_frontier_map.py` (render reuse already covered); add a smoke assertion here

- [ ] **Step 1: Add a smoke test**

Append to `kryptosbot/tests/test_frontier_map.py`:
```python
def test_session_briefing_render_helper_is_importable_and_safe(tmp_path):
    # The briefing reuses render_open_frontier; verify a built map renders
    # without raising when the ledger path is missing-tolerant.
    db = _make_ledger(tmp_path, [])
    fm = build_frontier_map(ledger_db_path=db)
    out = render_open_frontier(fm, limit=8)
    assert isinstance(out, str)
```

- [ ] **Step 2: Run to verify it passes (helper already exists)**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_frontier_map.py -k briefing_render -q`
Expected: PASS.

- [ ] **Step 3: Add the OPEN FRONTIER section to the briefing**

In `scripts/_infra/session_briefing.py`, after the assumption-boundary section is printed (locate the call site of `assumption_boundary_summary` / the section that prints alignment info, near the existing section functions), add a new section that builds and prints the open frontier. Insert this function near the other `section_*` functions:
```python
def section_open_frontier() -> None:
    """Print the open-frontier map's top open cells (read-only)."""
    try:
        import sys as _sys
        from pathlib import Path as _Path
        _root = _Path(__file__).resolve().parents[2]
        if str(_root) not in _sys.path:
            _sys.path.insert(0, str(_root))
        from kryptosbot.frontier_map import build_frontier_map, render_open_frontier
        db = _root / "db" / "theory_ledger.sqlite"
        if not db.exists():
            return
        fm = build_frontier_map(ledger_db_path=db)
        block = render_open_frontier(fm, limit=12)
        if block:
            print()
            print(block)
    except Exception as exc:  # briefing must never crash on an optional section
        print(f"  [open-frontier section unavailable: {exc}]")
```
Then call `section_open_frontier()` in the main render sequence alongside the other `section_*()` calls (after the assumption-boundary section).

- [ ] **Step 4: Verify the briefing runs end-to-end**

Run: `PYTHONPATH=src python3 scripts/_infra/session_briefing.py 2>&1 | grep -A3 "OPEN FRONTIER" | head` (or confirm it runs clean if the ledger is empty)
Expected: briefing completes; OPEN FRONTIER section prints (or is silently absent if no open cells / no ledger).

- [ ] **Step 5: Commit**

```bash
git add scripts/_infra/session_briefing.py kryptosbot/tests/test_frontier_map.py
git commit -m "feat(session-briefing): OPEN FRONTIER section (read-only)"
```

---

## Task 7: Controller integration — prompt block + landscape + soft annotation

**Files:**
- Modify: `kryptosbot/controller.py` (landscape attach ~L2296; prompt builder ~L3530 and join ~L3950; post-verdict annotation)
- Test: `kryptosbot/tests/test_frontier_map_integration.py` (new)

- [ ] **Step 1: Write the failing integration test**

`kryptosbot/tests/test_frontier_map_integration.py`:
```python
from kryptosbot.frontier_map import (
    build_frontier_map, render_open_frontier, frontier_cell_for_theory,
)
import sqlite3, json


def _ledger(tmp_path, rows):
    db = tmp_path / "ledger.sqlite"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE theories (family TEXT, mechanism TEXT, tags TEXT, "
                 "best_score REAL, status TEXT)")
    for fam, mech, tags, score, status in rows:
        conn.execute("INSERT INTO theories VALUES (?,?,?,?,?)",
                     (fam, mech, json.dumps(tags), score, status))
    conn.commit(); conn.close()
    return db


def test_prompt_block_present_when_open_cells_exist(tmp_path):
    db = _ledger(tmp_path, [])
    fm = build_frontier_map(ledger_db_path=db, family_universe=["vigenere"])
    block = render_open_frontier(fm, limit=5)
    assert "OPEN FRONTIER" in block  # non-empty: theorist would see it


def test_soft_annotation_never_changes_a_verdict(tmp_path):
    # The frontier annotation is a string note; it must not be a verdict field.
    db = _ledger(tmp_path, [])
    fm = build_frontier_map(ledger_db_path=db, family_universe=["vigenere"])
    theory = {"family": "vigenere", "mechanism": "periodic", "tags": []}
    cell = frontier_cell_for_theory(theory, fm)
    note = f"frontier:{cell.status}" if cell else "frontier:unknown"
    assert note.startswith("frontier:")  # advisory note only, no decision field
```

- [ ] **Step 2: Run to verify it fails / passes**

Run: `PYTHONPATH=src python3 -m pytest kryptosbot/tests/test_frontier_map_integration.py -q`
Expected: PASS for both (they exercise the public API; this task wires it into the controller — the controller wiring is verified by Step 4's regression, since the controller has no cheap unit harness for prompt assembly).

- [ ] **Step 3: Wire into the controller**

(3a) **Landscape attach.** In `kryptosbot/controller.py`, in the landscape-assembly method, immediately after the `landscape["escape_candidates"] = ...` block (~L2296-2299) and before `return landscape`, add:
```python
        try:
            from kryptosbot.frontier_map import build_frontier_map, render_open_frontier
            _fm = build_frontier_map(ledger_db_path=self.config.ledger_db_path)
            landscape["frontier_open"] = render_open_frontier(_fm, limit=12)
        except Exception:
            landscape["frontier_open"] = ""  # advisory; never break landscape
```

(3b) **Prompt block read.** In `_build_theorist_prompt` (~L3530, alongside the other `landscape.get(...)` block reads), add:
```python
        frontier_block = landscape.get("frontier_open") or ""
```

(3c) **Prompt join.** In the final f-string return (~L3950), insert `frontier_block` into the conditional-join chain, immediately before `escape_pressure_block` (so the positive frontier steer arrives with the yield-feedback signals):
```python
{"" if not frontier_block.strip() else frontier_block + chr(10) + chr(10)}
```
i.e. the chain becomes `...previous_synthesis_block...}{...family_yield_block...}{...frontier_block...}{...escape_pressure_block...}{...escape_candidates_block...}Output ONLY the JSON array. No commentary."""`

(3d) **Both cycle loops.** The landscape-assembly method (3a) is shared by both `controller.run` and `run_controller.do_run`, so a single edit covers both. Confirm via grep that no second landscape-assembly path exists:
Run: `grep -n "escape_candidates\"\] = " kryptosbot/controller.py kryptosbot/run_controller.py`
Expected: exactly one assignment site (the one edited). If a second exists, apply 3a there too.

- [ ] **Step 4: Regression — suites + self-test + briefing**

Run (separately, never combined):
```bash
PYTHONPATH=src /home/cpatrick/kryptos/venv/bin/python -m pytest kryptosbot/tests/ -q -n 26
PYTHONPATH=src /home/cpatrick/kryptos/venv/bin/python -m pytest tests/ -q -n 26
PYTHONPATH=src python3 -u kryptosbot/self_test.py --panel all --mode dry-run --cycles 20000 --report-path results/self_test/frontier_map_postcheck.json
```
Expected: both suites green; self-test K1/15, K2/17, K3/9345, 0 false-positive breakthroughs (frontier map is advisory; must not perturb fitness).

- [ ] **Step 5: Commit**

```bash
git add kryptosbot/controller.py kryptosbot/tests/test_frontier_map_integration.py
git commit -m "feat(controller): wire open-frontier map into theorist prompt (advisory)"
```

---

## Self-Review (completed by plan author)

- **Spec coverage:** §4.1 cells (family × 6 alignment models) → Task 1 (taxonomy) + Task 4 (grid). §4.2 status taxonomy → Task 4 (open/shallow/deep; `eliminated` reserved per MVP note). §4.3 hybrid population → Task 4 (skeleton from universe, status from ledger). §4.4 module API (`build_frontier_map`, `open_cells`, `render_open_frontier`, `frontier_cell_for_theory`) → Tasks 4-5. §4.5 critic soft signal → implemented controller-side as a post-verdict note (Task 7 Step 1 test pins the advisory invariant; the design's "critic per-theory assessment" is satisfied by the controller-side annotation, lower-risk than threading Critic.evaluate's many return paths — documented deviation). §4.6 human surface → Task 6. §6 single-source ALIGNMENT_MODELS → Tasks 1-2. §7 tests → every task. §8 sequencing → this is Plan 1; Plan 2 (historical prior) follows.
- **Placeholder scan:** none — every code step shows complete code; grep/run steps name exact commands + expected output.
- **Type consistency:** `FrontierCell(family, alignment_model, status, n_tested, best_crib)` and `FrontierMap(cells, built_at)` used identically across Tasks 3-7; `build_frontier_map(ledger_db_path=..., family_universe=..., now=...)`, `open_cells(fm)`, `render_open_frontier(fm, limit=...)`, `frontier_cell_for_theory(theory_dict, fm)` signatures consistent across tasks and tests.
- **Deviation noted:** MVP emits 3 statuses (eliminated reserved); critic signal is controller-side. Both documented above and faithful to the spec's advisory intent.
