"""Known-answer gate wiring for real-K4 mask search.

The gate consumes a ReadinessFact produced by the canonical readiness command
(kryptosbot/self_test.py --panel all --cycles 20000) and refuses to launch a
real-K4 mask search unless the gate is GREEN and doctor passed.  Known-answer
readiness is necessary, not sufficient; the guard reads only the boolean
outcome, never the K1/K2/K3 panel contents.
"""
from __future__ import annotations

import pytest

from kryptos.admissibility.mask_campaign_gate import (
    K4MaskSearchBlocked,
    ReadinessFact,
    require_known_answer_ready,
    run_guarded_mask_search,
)
from kryptos.admissibility.mask_hypothesis import MaskHypothesis, MaskUniverse
from kryptos.kernel.transforms.vigenere import CipherVariant, encrypt_text

_GREEN = ReadinessFact(
    readiness_gate="GREEN",
    block_k4_campaign=False,
    doctor_passed=True,
    summary_line="solved: 3/3",
)
_RED = ReadinessFact(
    readiness_gate="RED",
    block_k4_campaign=True,
    doctor_passed=True,
    summary_line="solved: 2/3",
)
_GREEN_BUT_DOCTOR_FAILED = ReadinessFact(
    readiness_gate="GREEN",
    block_k4_campaign=False,
    doctor_passed=False,
    summary_line="solved: 3/3",
)


def _synthetic_challenge():
    pt_prime = "ATTACKATDAWNXKRYPTOSCLOCK"
    key = [3, 17, 8, 22]
    variant = CipherVariant.VIGENERE
    ct_prime = encrypt_text(pt_prime, key, variant)
    mask = frozenset({5, 11, 19})
    carved_len = len(ct_prime) + len(mask)
    src = iter(ct_prime)
    carved = "".join("Q" if p in mask else next(src) for p in range(carved_len))
    nonmask = [p for p in range(carved_len) if p not in mask]
    crib_dict = {nonmask[j]: pt_prime[j] for j in range(8)}
    hyp = MaskHypothesis(
        mask_universe=MaskUniverse(masks=(mask,), description="synthetic"),
        alignment_model="arbitrary_null_mask",
        provenance="synthetic-test-fixture",
        assumption_bundle=("cribs_not_null",),
        tier="secondary_exploratory",
        stop_rule="exhaustive over the declared universe",
    )
    return carved, crib_dict, hyp, pt_prime


def test_require_ready_blocks_on_red():
    with pytest.raises(K4MaskSearchBlocked):
        require_known_answer_ready(_RED)


def test_require_ready_blocks_when_doctor_failed_even_if_green():
    with pytest.raises(K4MaskSearchBlocked):
        require_known_answer_ready(_GREEN_BUT_DOCTOR_FAILED)


def test_require_ready_passes_on_green():
    require_known_answer_ready(_GREEN)  # must not raise


def test_guarded_search_refuses_on_red():
    carved, crib_dict, hyp, _ = _synthetic_challenge()
    with pytest.raises(K4MaskSearchBlocked):
        run_guarded_mask_search(
            carved, hyp, readiness=_RED, crib_dict=crib_dict, periods=[4],
        )


def test_guarded_search_runs_when_green():
    carved, crib_dict, hyp, pt_prime = _synthetic_challenge()
    candidates = run_guarded_mask_search(
        carved, hyp, readiness=_GREEN, crib_dict=crib_dict, periods=[4],
    )
    assert any(c.plaintext == pt_prime for c in candidates)


def test_guarded_search_rejects_inadmissible_hypothesis_even_when_green():
    carved, crib_dict, _, _ = _synthetic_challenge()
    bad = MaskHypothesis(
        mask_universe=MaskUniverse(masks=(), description="empty"),  # no universe
        alignment_model="arbitrary_null_mask",
        provenance="",
        assumption_bundle=(),
        tier="secondary_exploratory",
        stop_rule="",  # missing stop rule too
    )
    with pytest.raises(ValueError):
        run_guarded_mask_search(
            carved, bad, readiness=_GREEN, crib_dict=crib_dict, periods=[4],
        )
