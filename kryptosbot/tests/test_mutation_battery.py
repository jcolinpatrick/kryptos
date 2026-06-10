"""Suite-assurance Task D — mutation / differential battery.

Each test applies a DELIBERATE MUTANT (wrong convention, corrupted state,
fabricated input) and asserts the suite's detector fires: the known-answer
recovery collapses, the guard raises, or the kernel overrule zeroes the
claim. Differential form: the correct configuration is asserted to solve
(pass) and the mutant configuration is asserted to be caught (fail) in the
same test, so the test fails if EITHER the real code breaks or the mutant
goes undetected.

Mutants (goal Task D): off-by-one crib positions; Vigenere/Beaufort sign
swap; AZ/KA alphabet swap; route inverse error; column order reversal;
dropped final char; stale/corrupted real CT; stale null cache; worker
fabricated score.
"""
from __future__ import annotations

import pytest

import kryptos.kernel.constants as KC
from kryptos.kernel.constants import CRIB_DICT, CT_LEN
from kryptos.kernel.constraints.bean import verify_bean_simple
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.transforms.transposition import (
    apply_perm, columnar_perm, invert_perm, serpentine_perm,
)

from kryptosbot.contracts import _verify_against_kernel
from kryptosbot.models import WorkerContract, WorkerStatus
from kryptosbot.null_baselines import NullDistribution, calibration_stale
from kryptosbot.tests.zoo_fixtures import english_pt, kw_key, vig_encrypt


def _vig_decrypt(ct: str, key: list[int]) -> str:
    return "".join(
        chr(65 + ((ord(c) - 65) - key[i % len(key)]) % 26)
        for i, c in enumerate(ct)
    )


def _beaufort_decrypt(ct: str, key: list[int]) -> str:
    return "".join(
        chr(65 + (key[i % len(key)] - (ord(c) - 65)) % 26)
        for i, c in enumerate(ct)
    )


def _crib(pt: str) -> int:
    return score_candidate(pt).crib_score


# ── M1: off-by-one crib positions ────────────────────────────────────────────

def test_m1_off_by_one_crib_positions_detected():
    pt = english_pt()
    assert _crib(pt) == 24                       # real code solves
    shifted = {pos + 1: ch for pos, ch in CRIB_DICT.items()}
    mutant_score = score_candidate(pt, crib_dict=shifted).crib_score
    assert mutant_score < 24, (
        f"off-by-one crib frame went undetected (score {mutant_score})"
    )


# ── M2: Vigenere/Beaufort sign swap ──────────────────────────────────────────

def test_m2_vigenere_beaufort_sign_swap_detected():
    pt = english_pt()
    key = kw_key("AZIMUTH")
    ct = vig_encrypt(pt, key)
    assert _vig_decrypt(ct, key) == pt and _crib(pt) == 24
    mutant_pt = _beaufort_decrypt(ct, key)       # K=(CT+PT) convention swap
    assert mutant_pt != pt
    assert _crib(mutant_pt) < 24, "sign-swap mutant went undetected"


# ── M3: AZ/KA alphabet swap ──────────────────────────────────────────────────

def test_m3_az_ka_alphabet_swap_detected():
    from kryptos.kernel.alphabet import KA

    pt = english_pt()
    keyword = "AZIMUTH"
    ct = vig_encrypt(pt, kw_key(keyword))        # AZ-indexed key
    ka_key = [KA.index_table[ord(c) - 65] for c in keyword]  # KA-indexed mutant
    assert ka_key != kw_key(keyword)
    mutant_pt = _vig_decrypt(ct, ka_key)
    assert mutant_pt != pt
    assert _crib(mutant_pt) < 24, "AZ/KA key-indexing swap went undetected"


# ── M4: route inverse error ──────────────────────────────────────────────────

def test_m4_route_inverse_error_detected():
    pt = english_pt()
    # Horizontal serpentine is an involution (per-row reversal); spiral is
    # not — required so forward-apply != undo.
    from kryptos.kernel.transforms.transposition import spiral_perm
    perm = spiral_perm(7, 14, CT_LEN, True)
    assert list(perm) != list(invert_perm(perm)), "fixture needs non-involution"
    carved = apply_perm(pt, perm)
    assert apply_perm(carved, invert_perm(perm)) == pt   # correct undo
    mutant = apply_perm(carved, perm)                    # forward-applied "undo"
    assert mutant != pt
    assert _crib(mutant) < 24, "route inverse error went undetected"


# ── M5: column order reversal ────────────────────────────────────────────────

def test_m5_column_order_reversal_detected():
    pt = english_pt()
    order = [2, 0, 3, 1, 4, 6, 5]                # non-palindromic
    perm = columnar_perm(7, order, CT_LEN)
    carved = apply_perm(pt, perm)
    assert apply_perm(carved, invert_perm(perm)) == pt
    mutant_perm = columnar_perm(7, list(reversed(order)), CT_LEN)
    mutant = apply_perm(carved, invert_perm(mutant_perm))
    assert mutant != pt
    assert _crib(mutant) < 24, "column-order reversal went undetected"


# ── M6: dropped final char ───────────────────────────────────────────────────

def test_m6_dropped_final_char_zeroed_at_boundary():
    pt96 = english_pt()[:-1]
    c = WorkerContract(
        hypothesis_id="m6", worker_role="w", status=WorkerStatus.SUCCESS,
        score=24.0, crib_score=24, bean_passed=True, best_plaintext=pt96,
    )
    _verify_against_kernel(c)
    assert c.crib_score == 0 and c.bean_passed is False
    assert c.fields_overwritten is True
    assert "96 != 97" in (c.verification_error or ""), c.verification_error


def test_m6_dropped_final_char_kernel_bean_raises():
    with pytest.raises(ValueError):
        verify_bean_simple([0] * (CT_LEN - 1))


# ── M7: stale / corrupted real CT ────────────────────────────────────────────

def test_m7_corrupted_ct_constant_fails_verify():
    original = KC.CT
    try:
        KC.CT = "X" + original[1:]               # boundary char corrupted
        with pytest.raises(AssertionError):
            KC._verify()
    finally:
        KC.CT = original
    KC._verify()                                  # restored state is clean


def test_m7_truncated_ct_constant_fails_verify():
    original = KC.CT
    try:
        KC.CT = original[:-1]
        with pytest.raises(AssertionError):
            KC._verify()
    finally:
        KC.CT = original
    KC._verify()


# ── M8: stale null cache ─────────────────────────────────────────────────────

def test_m8_stale_null_cache_detected():
    dist = NullDistribution(
        scorer_name="crib_score", method="random_text", n_chars=97,
        alphabet="AZ", n_samples=1000, seed=1,
        kernel_commit="deadbeefdeadbeef",
        sorted_scores=[0.0, 1.0, 2.0], mean=0.92, stdev=0.95,
    )
    assert calibration_stale(dist, current_commit="cafebabecafebabe") is True
    assert calibration_stale(dist, current_commit="deadbeefdeadbeef") is False
    # 'unknown' build commit is deliberately permissive (documented).
    dist_unknown = NullDistribution(
        scorer_name="crib_score", method="random_text", n_chars=97,
        alphabet="AZ", n_samples=1000, seed=1,
        kernel_commit="unknown",
        sorted_scores=[0.0, 1.0, 2.0], mean=0.92, stdev=0.95,
    )
    assert calibration_stale(dist_unknown, current_commit="cafebabe") is False


# ── M9: worker fabricated score ──────────────────────────────────────────────

def test_m9_fabricated_worker_score_overruled():
    garbage = ("Q" * 97)
    c = WorkerContract(
        hypothesis_id="m9", worker_role="w", status=WorkerStatus.SUCCESS,
        score=24.0, crib_score=24, bean_passed=True, best_plaintext=garbage,
    )
    _verify_against_kernel(c)
    assert c.crib_score == 0
    assert c.bean_passed is False
    assert c.fields_overwritten is True
    assert c.worker_self_report == {
        "crib_score": 24, "bean_passed": True, "score": 24.0,
    }


def test_m9_fabricated_crib_paste_demoted_inconclusive():
    paste = "".join(
        CRIB_DICT.get(i, "Q") for i in range(CT_LEN)
    )
    c = WorkerContract(
        hypothesis_id="m9b", worker_role="w", status=WorkerStatus.SUCCESS,
        score=24.0, crib_score=24, bean_passed=True, best_plaintext=paste,
    )
    _verify_against_kernel(c)
    assert c.status == WorkerStatus.INCONCLUSIVE
    assert c.crib_score == 0
    assert (c.raw_artifacts or {}).get("artifact_class") == "crib_paste"
