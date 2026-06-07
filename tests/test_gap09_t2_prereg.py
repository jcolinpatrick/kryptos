"""Regression guard for the GAP-09 T2 pre-registered candidate mask family.

Pins the frozen contract (docs/campaigns/gap09_t2_prereg_mask_family_2026_06_07.md)
so it cannot silently drift before the O1 observable is acquired:
  - the family is hash-identical to pathway-2 (score-free, anti-circularity-vetted);
  - the per-rule null model is correct (matched for periodic/grid R3; uniform for
    letter-class R2/R5);
  - the matched null defeats shared-period inflation (the misspecification fix);
  - the uniform null retains sensitivity;
  - the side-effect gate blocks anchoring while the predicate is unmet (pathway-2 T3=0);
  - no candidate mask intersects a crib position (cribs cannot be nulls).
"""
import importlib.util
import os

from kryptos.kernel.constants import CRIB_POSITIONS

_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts", "campaigns", "gap09_t2_prereg_mask_family_2026_06_07.py")


def _load():
    spec = importlib.util.spec_from_file_location("_gap09_prereg", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_M = _load()
_RECORDS, _HASH = _M.build_family()


def test_family_hash_matches_pathway2():
    assert _HASH == _M.PATHWAY2_RULE_SET_SHA256
    assert len(_RECORDS) == 15


def test_null_model_assignment():
    for r in _RECORDS:
        if r["rule"] == "R3":
            assert r["null_model"] == "matched" and r["matched_null_family"]
        else:  # R2, R5 letter-class
            assert r["null_model"] == "uniform_hypergeometric"
            assert r["matched_null_family"] is None


def test_only_letter_class_masks_are_live():
    # MAJOR-3: the 13 R3 grid-rows have a matched-null floor >> 1e-6 and can NEVER
    # clear the gate; only the 2 uniform-hypergeometric letter-class masks (R2,R5).
    live = [r for r in _RECORDS if r["can_clear_gate"]]
    assert len(live) == 2
    assert {r["rule"] for r in live} == {"R2", "R5"}
    for r in _RECORDS:
        if r["rule"] == "R3":
            assert r["can_clear_gate"] is False
            assert r["best_case_p_raw"] > 1e-6


def test_matched_null_family_uses_whole_crib_free_rows():
    # consistency fix: family members are whole rows (no crib-truncated fragments);
    # every member is crib-free.
    cribs = set(CRIB_POSITIONS)
    for r in _RECORDS:
        if r["rule"] == "R3":
            for member in r["matched_null_family"]:
                assert not (set(member) & cribs)


def test_refreeze_is_deterministic():
    # tamper-evidence: re-freezing reproduces the same prereg hash (date excluded).
    f1, _ = _M.build_frozen()
    f2, _ = _M.build_frozen()
    assert f1["prereg_sha256"] == f2["prereg_sha256"]
    assert f1["mask_universe_hash"] == f2["mask_universe_hash"]
    assert f1["n_live_masks"] == 2


def test_no_candidate_intersects_cribs():
    cribs = set(CRIB_POSITIONS)
    for r in _RECORDS:
        assert not (set(r["mask"]) & cribs), r


def test_matched_null_defeats_period_sharing():
    r3 = next(r for r in _RECORDS if r["rule"] == "R3" and "W=7" in r["params"])
    res = _M.run_closure(list(range(0, _M.N, 7)), [r3])
    assert not res["per_mask"][0]["colocation_significant"]


def test_uniform_null_retains_sensitivity():
    rlet = next(r for r in _RECORDS if r["null_model"] == "uniform_hypergeometric")
    res = _M.run_closure(sorted(rlet["mask"]), [rlet])
    assert res["per_mask"][0]["p_raw"] < 1e-6


def test_side_effect_gate_blocks_anchoring():
    rlet = next(r for r in _RECORDS if r["null_model"] == "uniform_hypergeometric")
    res = _M.run_closure(sorted(rlet["mask"]), [rlet])
    assert res["any_colocation_significant"] is True
    assert res["any_mask_anchors_gap09"] is False
    assert res["verdict"] == "COLOCATION_BUT_SIDE_EFFECT_UNMET"


def test_empty_observable_is_null():
    assert not _M.run_closure([], _RECORDS)["any_colocation_significant"]
