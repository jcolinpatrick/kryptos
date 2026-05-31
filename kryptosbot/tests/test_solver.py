"""Deterministic clue-bounded solver.

The controller's failure mode was relying on the LLM theorist to GUESS an exact
composition. The solver instead: (1) extracts clue INGREDIENTS deterministically
(keywords, candidate families, number hints, alphabets), (2) builds a small set
of bounded SWEEP HypothesisSpecs covering the clue-bounded composition space,
(3) dispatches each through the fast kernel path (job_dispatcher.execute, no
LLM), and (4) selects the best crib_score. No hardcoded answers — it discovers
the solution by sweeping ingredients derived from the public clue pack.

The headline test proves it on the bronze litmus challenge K4B-001.
"""

import json
import pathlib

from kryptosbot.solver import extract_ingredients, build_sweep_specs, solve

_CHDIR = pathlib.Path(__file__).resolve().parents[2] / "bench/k4bench/challenges"


def _payload(bench_id):
    return json.loads((_CHDIR / f"{bench_id}.json").read_text())


def _challenge_kwargs(bench_id):
    p = _payload(bench_id)
    return dict(
        ciphertext=p["ciphertext"],
        crib_dict={int(k): v for k, v in p["known_plaintext_positions"].items()},
        clue_text=p["public_clue_pack"]["clue_text"],
        title=p["title"],
        constraint_summary=tuple(p["public_clue_pack"]["constraint_summary"]),
    )


def test_extract_ingredients_k4b001():
    p = _payload("K4B-001")
    ing = extract_ingredients(
        clue_text=p["public_clue_pack"]["clue_text"],
        title=p["title"],
        constraint_summary=tuple(p["public_clue_pack"]["constraint_summary"]),
    )
    # The two anchor keywords must be mined from the clue.
    assert "CEDAR" in ing.keywords
    assert "LANTERN" in ing.keywords
    # "Seven post marks" -> a number hint.
    assert 7 in ing.number_hints
    # Candidate families must include the dominant transposition + substitution
    # primitives (clue doesn't name the cipher, so a candidate set is required).
    assert "columnar" in ing.families
    assert "vigenere" in ing.families
    # Layer count window from the constraint summary ("two and three").
    assert ing.layer_count_range[0] <= 2 <= ing.layer_count_range[1]


def test_build_sweep_specs_are_valid_and_bounded():
    p = _payload("K4B-001")
    ing = extract_ingredients(
        clue_text=p["public_clue_pack"]["clue_text"],
        title=p["title"],
        constraint_summary=tuple(p["public_clue_pack"]["constraint_summary"]),
    )
    specs = build_sweep_specs(ing, text_length=97)
    assert specs, "solver produced no specs"
    for s in specs:
        assert s.validate() == [], (s.hypothesis_id, s.validate())
        # Each spec must be a bounded sweep, kept small enough to dispatch fast.
        assert 1 <= s.expected_cardinality() <= 2000, (s.hypothesis_id, s.expected_cardinality())


def test_solver_solves_k4b001_bronze():
    result = solve(**_challenge_kwargs("K4B-001"))
    assert result.best_score == 24, (result.best_score, result.best_config)
    assert result.solved is True
    # It found a real composition, not a degenerate single layer.
    assert result.best_config is not None


def test_run_clue_sweep_focused_hypothesis_solves():
    # The in-loop tool engine: the LLM proposes a focused hypothesis (which
    # families + keywords), and this sweeps widths/orders/alphabets serially
    # (no process pool — safe to call from the controller's async MCP handler).
    from kryptosbot.solver import run_clue_sweep

    p = _payload("K4B-001")
    cribs = {int(k): v for k, v in p["known_plaintext_positions"].items()}
    res = run_clue_sweep(
        p["ciphertext"], cribs,
        families=["columnar", "vigenere"],
        keywords=["CEDAR", "LANTERN", "RIVET"],
    )
    assert res["best_score"] == 24, res
    assert res["best_config"] is not None


def test_parallel_dispatch_finds_best_across_specs():
    # _dispatch_best runs specs across a process pool and reduces to the best
    # crib_score. Building the K4B-001 sweep and dispatching it must surface the
    # 24/24 winner regardless of which worker found it.
    from kryptosbot.solver import build_sweep_specs, extract_ingredients, _dispatch_best

    p = _payload("K4B-001")
    ing = extract_ingredients(
        clue_text=p["public_clue_pack"]["clue_text"], title=p["title"],
        constraint_summary=tuple(p["public_clue_pack"]["constraint_summary"]),
    )
    specs = build_sweep_specs(ing, round_idx=0)
    cribs = {int(k): v for k, v in p["known_plaintext_positions"].items()}
    best_score, best_config, best_spec_id, configs = _dispatch_best(
        specs, p["ciphertext"], cribs, workers=4,
    )
    assert best_score == 24
    assert best_config is not None and best_spec_id
    assert configs > 0


def test_k4_ingredients_respects_keyword_override_and_cap():
    from kryptosbot.solver import _k4_ingredients

    ing = _k4_ingredients(
        keywords=["alpha", "bravo", "charlie", "delta", "echo"], max_keywords=3
    )
    assert ing.keywords == ["ALPHA", "BRAVO", "CHARLIE"]  # upper + capped
    assert "columnar" in ing.families and "vigenere" in ing.families
    assert ing.alphabets == ["AZ", "KA"]


def test_k4_default_seed_is_substantial():
    from kryptosbot.solver import _K4_KEYWORD_SEED

    assert len(_K4_KEYWORD_SEED) >= 10


def test_solve_challenge_object_solves_k4b001():
    # solve_challenge accepts a duck-typed challenge object (as the controller
    # passes a K4BenchChallenge) and autonomously solves it.
    from types import SimpleNamespace
    from kryptosbot.solver import solve_challenge

    p = _payload("K4B-001")
    ch = SimpleNamespace(
        ciphertext=p["ciphertext"],
        crib_dict={int(k): v for k, v in p["known_plaintext_positions"].items()},
        clue_text=p["public_clue_pack"]["clue_text"],
        title=p["title"],
        constraint_summary=tuple(p["public_clue_pack"]["constraint_summary"]),
    )
    result = solve_challenge(ch)
    assert result.solved is True
    assert result.best_score == 24
