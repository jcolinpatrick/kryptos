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
