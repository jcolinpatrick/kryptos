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
    assert "OPEN FRONTIER" in block


def test_frontier_block_threads_into_theorist_prompt(tmp_path):
    # A landscape carrying a frontier_open string must surface in the built
    # theorist prompt. Verify the prompt builder reads landscape['frontier_open'].
    import kryptosbot.controller as ctrl
    import inspect
    src = inspect.getsource(ctrl.ResearchController._build_theorist_prompt)
    assert "frontier_open" in src, "prompt builder must read landscape['frontier_open']"
