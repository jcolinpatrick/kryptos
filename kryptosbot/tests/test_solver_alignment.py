"""Solver crib_alignment extension (2026-06-11).

The clue-bounded solver historically hardcoded crib_alignment="direct_positional"
in every spec it authored, so it could only search the (exhausted) direct-aligned
composition space. These tests pin the extension that threads a declared
crib_alignment through spec construction and routes free-alignment dispatch onto
the real-K4 scoring path (the only path with a free matcher — challenge mode
scores anchored regardless of the spec's crib_alignment field).

Free crib scores are presence point-values ({0,11,13,24}); they are never
compared to anchored scores or anchored nulls (alignment-model skill / G-1).
"""

import pytest

from kryptosbot.solver import _k4_ingredients, build_sweep_specs


def _ing():
    # Tiny ingredient set keeps spec construction fast; spec COUNT is
    # family-driven, cardinality is keyword-driven.
    return _k4_ingredients(keywords=["BERLIN", "KRYPTOS"], max_keywords=2)


def test_build_sweep_specs_default_is_direct_positional():
    # Backward compat: no argument -> every spec is the historical direct shape.
    specs = build_sweep_specs(_ing(), round_idx=0)
    assert specs
    for s in specs:
        assert s.crib_alignment == "direct_positional", s.hypothesis_id
        assert "ct97_direct_positional" in s.assumption_bundle, s.hypothesis_id


def test_build_sweep_specs_free_sets_alignment_and_bundle():
    specs = build_sweep_specs(_ing(), round_idx=0, crib_alignment="free")
    assert specs
    for s in specs:
        assert s.crib_alignment == "free", s.hypothesis_id
        # Convention bundle matches f_free_alignment_classical_2026_06_10:
        # non-direct, detection-level, fixed-97 stream; NOT the direct bundle.
        assert "non_direct_alignment" in s.assumption_bundle, s.hypothesis_id
        assert "crib_alignment_free_detection_level" in s.assumption_bundle
        assert "ct97_direct_positional" not in s.assumption_bundle
        # Spec id carries the alignment marker so artifacts are distinguishable.
        assert "-free" in s.hypothesis_id, s.hypothesis_id
        assert s.validate() == [], (s.hypothesis_id, s.validate())


def test_build_sweep_specs_free_three_layer_round():
    specs = build_sweep_specs(_ing(), round_idx=1, crib_alignment="free")
    assert specs
    assert all(s.crib_alignment == "free" for s in specs)
    assert all(len(s.pipeline) == 3 for s in specs)


def test_spec_hash_distinct_across_alignments():
    # Alignment-scoped dedup/exhaustion (B-3) relies on the alignment being
    # part of the spec identity: same pipeline, different alignment must never
    # collide.
    direct = {s.spec_hash for s in build_sweep_specs(_ing(), round_idx=0)}
    free = {s.spec_hash for s in build_sweep_specs(_ing(), round_idx=0, crib_alignment="free")}
    assert direct and free
    assert direct.isdisjoint(free)


def test_build_sweep_specs_rejects_bogus_alignment():
    with pytest.raises(ValueError):
        build_sweep_specs(_ing(), round_idx=0, crib_alignment="sideways")


def test_build_sweep_specs_rejects_post_transposition():
    # post_transposition is deliberately NOT a solver alignment: the decrypt
    # pipeline already physically undoes the outer layer, so anchored scoring
    # of the final PT gives the identical crib_score as direct_positional —
    # a re-run would add no crib information (only a Bean frame relabel).
    with pytest.raises(ValueError):
        build_sweep_specs(_ing(), round_idx=0, crib_alignment="post_transposition")


def test_dispatch_one_spec_routes_free_to_real_k4_path(monkeypatch):
    # The challenge scoring branch has NO free matcher (it scores anchored
    # regardless of crib_alignment), so a free spec must dispatch through the
    # real-K4 path: no challenge args, bench_mode False.
    import kryptosbot.solver as solver_mod
    from kryptos.kernel import constants as C

    calls = {}

    class _FakeResult:
        best_candidate = {"crib_score": 11, "candidate_pt": "X" * 97}
        total_tested = 5

    def fake_execute(spec, **kwargs):
        calls["kwargs"] = kwargs
        return _FakeResult()

    monkeypatch.setattr(solver_mod, "execute", fake_execute)
    specs = build_sweep_specs(_ing(), round_idx=0, crib_alignment="free")
    score, cand, spec_id, tested = solver_mod._dispatch_one_spec(
        specs[0], C.CT, dict(C.CRIB_DICT)
    )
    assert score == 11 and tested == 5
    kw = calls["kwargs"]
    assert kw.get("challenge_ciphertext") is None
    assert kw.get("challenge_crib_dict") is None
    assert not kw.get("bench_mode", False)


def test_dispatch_one_spec_free_rejects_non_kernel_ciphertext():
    # Free dispatch is real-K4 only: a synthetic/challenge CT under a free
    # spec would silently score anchored, so it must fail loudly instead.
    import kryptosbot.solver as solver_mod

    specs = build_sweep_specs(_ing(), round_idx=0, crib_alignment="free")
    with pytest.raises(ValueError, match="free"):
        solver_mod._dispatch_one_spec(specs[0], "Q" * 97, {0: "A"})


def test_dispatch_one_spec_direct_keeps_challenge_path(monkeypatch):
    # Regression pin: the historical direct path (challenge args + bench_mode)
    # is unchanged by the extension.
    import kryptosbot.solver as solver_mod

    calls = {}

    class _FakeResult:
        best_candidate = {"crib_score": 3}
        total_tested = 2

    def fake_execute(spec, **kwargs):
        calls["kwargs"] = kwargs
        return _FakeResult()

    monkeypatch.setattr(solver_mod, "execute", fake_execute)
    specs = build_sweep_specs(_ing(), round_idx=0)
    solver_mod._dispatch_one_spec(specs[0], "Q" * 97, {0: "A"})
    kw = calls["kwargs"]
    assert kw.get("challenge_ciphertext") == "Q" * 97
    assert kw.get("bench_mode") is True


def test_solve_real_k4_rejects_bogus_alignment():
    from kryptosbot.solver import solve_real_k4

    with pytest.raises(ValueError):
        solve_real_k4(crib_alignment="post_transposition", max_rounds=1)
