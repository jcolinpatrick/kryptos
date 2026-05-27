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
    # Behavioral: build a real controller, pass a landscape carrying a
    # sentinel frontier_open value, and assert the built prompt contains
    # the sentinel. This replaces the inspect.getsource() approach.
    from kryptosbot.controller import ControllerConfig, ResearchController

    config = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "ledger.sqlite",
        alert_threshold="signal",
    )
    ctrl = ResearchController(config)

    # Sparse landscape: _build_theorist_prompt uses .get() for all keys;
    # supply only frontier_open plus empty defaults for the two list keys
    # that _render_pursuit_leads_for_prompt receives as positional args.
    landscape = {
        "frontier_open": "OPEN FRONTIER __MARKER_TOKEN__",
        "pursuit_leads": [],
        "soft_pursuit_leads": [],
    }
    prompt = ctrl._build_theorist_prompt(landscape)
    assert "__MARKER_TOKEN__" in prompt, (
        "frontier_open block must appear verbatim in the built theorist prompt"
    )
