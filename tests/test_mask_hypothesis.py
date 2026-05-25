import pytest
from kryptos.admissibility.mask_hypothesis import (
    MaskUniverse, MaskHypothesis, validate_mask_hypothesis, ALIGNMENT_MODEL_KEYS,
)

def _universe():
    return MaskUniverse(masks=(frozenset(), frozenset({0})), description="demo")

def test_primary_requires_provenance():
    h = MaskHypothesis(
        mask_universe=_universe(), alignment_model="arbitrary_null_mask",
        provenance="", assumption_bundle=("cribs_not_null",),
        tier="primary_evidentiary", stop_rule="enumerate all",
    )
    errs = validate_mask_hypothesis(h)
    assert any("provenance" in e for e in errs)

def test_secondary_allowed_without_provenance():
    h = MaskHypothesis(
        mask_universe=_universe(), alignment_model="arbitrary_null_mask",
        provenance="", assumption_bundle=("cribs_not_null",),
        tier="secondary_exploratory", stop_rule="enumerate all",
    )
    assert validate_mask_hypothesis(h) == []

def test_unknown_alignment_model_rejected():
    h = MaskHypothesis(
        mask_universe=_universe(), alignment_model="made_up",
        provenance="GAP-09 note", assumption_bundle=(),
        tier="secondary_exploratory", stop_rule="x",
    )
    errs = validate_mask_hypothesis(h)
    assert any("alignment_model" in e for e in errs)

def test_empty_universe_rejected():
    h = MaskHypothesis(
        mask_universe=MaskUniverse(masks=(), description="empty"),
        alignment_model="arbitrary_null_mask", provenance="x",
        assumption_bundle=(), tier="secondary_exploratory", stop_rule="x",
    )
    assert any("universe" in e for e in validate_mask_hypothesis(h))

def test_universe_hash_is_deterministic_and_present():
    u = _universe()
    assert u.universe_hash == _universe().universe_hash
    assert len(u.universe_hash) == 64  # sha256 hex

def test_universe_hash_is_order_independent():
    a = MaskUniverse(masks=(frozenset({0}), frozenset({1, 2})), description="x")
    b = MaskUniverse(masks=(frozenset({1, 2}), frozenset({0})), description="x")
    assert a.universe_hash == b.universe_hash

def test_whitespace_stop_rule_rejected():
    h = MaskHypothesis(
        mask_universe=MaskUniverse(masks=(frozenset(),), description="d"),
        alignment_model="arbitrary_null_mask", provenance="p",
        assumption_bundle=(), tier="secondary_exploratory", stop_rule="   ",
    )
    assert any("stop_rule" in e for e in validate_mask_hypothesis(h))
