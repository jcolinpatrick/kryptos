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


def test_session_briefing_render_helper_is_importable_and_safe(tmp_path):
    # The briefing reuses render_open_frontier; verify a built map renders
    # without raising when the ledger path is missing-tolerant.
    db = _make_ledger(tmp_path, [])
    fm = build_frontier_map(ledger_db_path=db)
    out = render_open_frontier(fm, limit=8)
    assert isinstance(out, str)


def test_open_cells_round_robin_across_non_direct_models(tmp_path):
    # All cells open; the first 4 must span the 4 DISTINCT non-direct models
    # (round-robin), not 4 cells of the same alphabetically-first model.
    db = _make_ledger(tmp_path, [])
    fm = build_frontier_map(
        ledger_db_path=db,
        family_universe=["vigenere", "beaufort", "columnar_single"])
    first4 = [c.alignment_model for c in open_cells(fm)[:4]]
    assert set(first4) == {
        "ct73_null_extracted", "arbitrary_null_mask",
        "non_direct_alignment", "joint_mask_mechanism",
    }


def test_family_universe_excludes_non_cipher_junk():
    from kryptosbot.frontier_map import _family_universe
    fams = _family_universe()
    assert "vigenere" in fams and "beaufort" in fams
    assert "admissibility" not in fams
    assert "campaigns_final_checklist" not in fams


def test_signal_bearing_cell_gets_has_signal_status(tmp_path):
    rows = [("vigenere", "periodic vigenere", [], 20.0, "completed")]
    db = _make_ledger(tmp_path, rows)
    fm = build_frontier_map(ledger_db_path=db, family_universe=["vigenere"])
    by = {(c.family, c.alignment_model): c for c in fm.cells}
    assert by[("vigenere", "direct_ct_pt")].status == "has_signal"


def test_frontier_cell_for_theory_is_deterministic_on_multi_model(tmp_path):
    db = _make_ledger(tmp_path, [])
    fm = build_frontier_map(ledger_db_path=db, family_universe=["key_tape"])
    # a mechanism hitting BOTH ct73 and null_mask hints -> two non-direct models;
    # the chosen cell must be stable across calls and pick canonical-first (ct73).
    theory = {"family": "key_tape",
              "mechanism": "ct73 null-extracted with null_mask insertion", "tags": []}
    c1 = frontier_cell_for_theory(theory, fm)
    c2 = frontier_cell_for_theory(theory, fm)
    assert c1 == c2
    assert c1.alignment_model == "ct73_null_extracted"  # canonical order before arbitrary_null_mask


def test_render_summarizes_only_non_direct_models(tmp_path):
    # All cells open. Render must advertise the four non-direct alignment
    # models as a per-model summary and must NOT advertise direct-carving
    # cells (their "open" status is unreliable under the ledger-only view).
    db = _make_ledger(tmp_path, [])
    fm = build_frontier_map(ledger_db_path=db,
                            family_universe=["vigenere", "beaufort"])
    out = render_open_frontier(fm, limit=12)
    assert "direct_ct_pt" not in out
    assert "fixed_len_97" not in out
    for m in ("ct73_null_extracted", "arbitrary_null_mask",
              "non_direct_alignment", "joint_mask_mechanism"):
        assert m in out
    assert "UNEXPLORED across" in out
