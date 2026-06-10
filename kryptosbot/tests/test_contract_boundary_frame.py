"""Suite-assurance Task A/B — contract-boundary scoring-frame correctness.

The dispatcher's per-candidate scoring is frame-aware (Lever B1 free scoring +
the AUDIT-5 post_transposition Bean-frame fix). But every JobResult is then
converted to a WorkerContract via ``job_result_to_worker_contract``, which
re-verifies through ``contracts._verify_against_kernel`` — and that boundary
verifier was frame-UNAWARE:

* it re-scored cribs ANCHORED via ``score_cribs(pt)``, zeroing any genuine
  ``free``-alignment find whose cribs sit off-anchor (silent kill of a
  non-direct solve at the ledger/alert surface), and
* it re-derived Bean against the CARVED CT, overwriting the dispatcher's
  route-frame Bean verdict for ``post_transposition`` candidates (the exact
  frame error AUDIT-5 fixed inside the dispatcher, reintroduced one layer up).

These tests pin the frame-aware boundary behavior. Conventions (Step 0):
ALPHABET AZ A=0; VARIANT vigenere K=(CT-PT) mod 26 (boundary tries all 3);
POSITIONS 0-indexed, cribs 21-33 / 63-73; SCOPE LOCAL (24 crib positions);
Bean applies only via an explicit frame argument under post_transposition.
"""
from __future__ import annotations

import pytest

from kryptos.kernel.constants import CT, CT_LEN
from kryptos.kernel.text import text_to_nums
from kryptos.kernel.constraints.bean import verify_bean_simple
from kryptos.kernel.transforms.transposition import apply_perm

from kryptosbot.models import WorkerContract, WorkerStatus
from kryptosbot.contracts import _verify_against_kernel
from kryptosbot.job_dispatcher import (
    JobResult,
    _evaluate_one,
    job_result_to_worker_contract,
)

_ENE = "EASTNORTHEAST"
_BC = "BERLINCLOCK"

# English filler so the crib-paste detector (non-crib ngram floor -6.2)
# does NOT fire on the legitimate off-anchor candidate.
_ENGLISH = (
    "THETIMEHASCOMETHEWALRUSSAIDTOTALKOFMANYTHINGSOFSHOESANDSHIPS"
    "ANDSEALINGWAXOFCABBAGESANDKINGS"
)


def _pt_offanchor() -> str:
    """97-char PT, ENE at 0 and BC at 40 (neither at canonical positions)."""
    body = _ENE + _ENGLISH[:27] + _BC + _ENGLISH[27:]
    pt = body[:CT_LEN]
    assert len(pt) == CT_LEN
    assert pt.index(_ENE) == 0 and pt.index(_BC) == 40
    # Must NOT score anchored — that's the point of the fixture.
    assert pt[21:34] != _ENE and pt[63:74] != _BC
    return pt


def _pt_anchored() -> str:
    """97-char PT with both cribs at the canonical anchored positions."""
    chars = list((_ENGLISH * 2)[:CT_LEN])
    for start, word in ((21, _ENE), (63, _BC)):
        for j, ch in enumerate(word):
            chars[start + j] = ch
    return "".join(chars)


def _contract(pt: str, crib: int, bean: bool = False) -> WorkerContract:
    return WorkerContract(
        hypothesis_id="suite-assurance",
        worker_role="dsl_dispatcher",
        status=WorkerStatus.SUCCESS,
        score=float(crib),
        crib_score=crib,
        bean_passed=bean,
        best_plaintext=pt,
    )


def _bean_verdict_any_variant(frame_ct: str, pt: str) -> bool:
    """Independent recompute: Bean PASS under any of the 3 variants."""
    c = text_to_nums(frame_ct)
    p = text_to_nums(pt)
    for derive in (
        lambda a, b: (a - b) % 26,   # vigenere
        lambda a, b: (a + b) % 26,   # beaufort
        lambda a, b: (b - a) % 26,   # variant beaufort
    ):
        if verify_bean_simple([derive(x, y) for x, y in zip(c, p)]):
            return True
    return False


# ── free alignment at the boundary ───────────────────────────────────────────

def test_free_boundary_preserves_offanchor_cribs():
    """A genuine free-alignment find (both cribs off-anchor, English body)
    must NOT be zeroed by the boundary verifier."""
    pt = _pt_offanchor()
    c = _contract(pt, crib=24)
    _verify_against_kernel(c, scoring_mode="free")
    assert c.crib_score == 24, (
        f"off-anchor free find zeroed at contract boundary: {c.crib_score} "
        f"(verification_error={c.verification_error!r})"
    )
    assert c.status == WorkerStatus.SUCCESS
    # Bean is N/A under free — never asserted.
    assert c.bean_passed is False
    assert c.bean_variant is None


def test_free_boundary_overrules_fabricated_score():
    """Kernel overrule must still hold under free: a worker claiming 24
    on a crib-less PT is overruled from the kernel recompute."""
    pt = (_ENGLISH * 2)[:CT_LEN]
    assert _ENE not in pt and _BC not in pt
    c = _contract(pt, crib=24)
    _verify_against_kernel(c, scoring_mode="free")
    assert c.crib_score == 0
    assert c.fields_overwritten is True
    assert c.worker_self_report == {
        "crib_score": 24, "bean_passed": False, "score": 24.0,
    }


def test_free_boundary_partial_crib_recomputed():
    """ENE-only off-anchor PT recomputes to the free point value 13."""
    body = _ENE + (_ENGLISH * 2)
    pt = body[:CT_LEN]
    assert _BC not in pt
    c = _contract(pt, crib=24)  # worker over-claims
    _verify_against_kernel(c, scoring_mode="free")
    assert c.crib_score == 13
    assert c.fields_overwritten is True


def test_free_boundary_paste_artifact_zeroed():
    """Crib-paste discipline survives under free: off-anchor cribs with a
    garbage body are an artifact, zeroed and demoted INCONCLUSIVE."""
    body = _ENE + "Q" * 27 + _BC + "Q" * 46
    pt = body[:CT_LEN]
    c = _contract(pt, crib=24)
    _verify_against_kernel(c, scoring_mode="free")
    assert c.crib_score == 0
    assert c.status == WorkerStatus.INCONCLUSIVE
    assert c.raw_artifacts and c.raw_artifacts.get("artifact_class") == "crib_paste"


# ── post_transposition Bean frame at the boundary ────────────────────────────

def test_post_transposition_boundary_uses_frame_not_carved_ct():
    """The boundary Bean verdict must follow the supplied route-undone frame,
    not the carved CT. Fixture: anchored-crib PT; frame = reversed carved CT.
    The carved-CT verdict and the frame verdict provably differ."""
    pt = _pt_anchored()
    frame = apply_perm(CT, [CT_LEN - 1 - i for i in range(CT_LEN)])
    carved_verdict = _bean_verdict_any_variant(CT, pt)
    frame_verdict = _bean_verdict_any_variant(frame, pt)
    assert carved_verdict != frame_verdict, (
        "fixture degenerate: frame and carved verdicts agree; pick another frame"
    )
    c = _contract(pt, crib=24, bean=frame_verdict)
    _verify_against_kernel(
        c, scoring_mode="post_transposition", bean_frame_ct=frame,
    )
    assert c.crib_score == 24
    assert c.bean_passed == frame_verdict, (
        "boundary Bean verdict followed the carved CT, not the supplied frame"
    )


def test_post_transposition_boundary_frame_equal_to_carved_matches_direct():
    """Sanity: when the frame IS the carved CT, the verdict equals direct."""
    pt = _pt_anchored()
    expected = _bean_verdict_any_variant(CT, pt)
    c = _contract(pt, crib=24, bean=expected)
    _verify_against_kernel(
        c, scoring_mode="post_transposition", bean_frame_ct=CT,
    )
    assert c.bean_passed == expected


def test_post_transposition_boundary_no_frame_is_bean_na():
    """Frame undefined => Bean N/A (False/None), never a carved-CT verdict."""
    pt = _pt_anchored()
    assert _bean_verdict_any_variant(CT, pt) is True  # carved would say PASS
    c = _contract(pt, crib=24, bean=False)
    _verify_against_kernel(
        c, scoring_mode="post_transposition_bean_unavailable", bean_frame_ct=None,
    )
    assert c.crib_score == 24
    assert c.bean_passed is False
    assert c.bean_variant is None


def test_default_direct_behavior_unchanged_regression():
    """No kwargs => existing carved-CT anchored behavior (regression pin)."""
    pt = _pt_anchored()
    c = _contract(pt, crib=24, bean=True)
    _verify_against_kernel(c)
    assert c.crib_score == 24
    # Anchored 24/24 against the carved CT implies the real implied keystream
    # at the crib positions, which is Bean-valid by construction.
    assert c.bean_passed is True
    assert c.bean_variant == "vigenere"


# ── integration: JobResult -> WorkerContract ─────────────────────────────────

def _job_result(best: dict) -> JobResult:
    return JobResult(
        hypothesis_id="suite-assurance-int",
        spec_hash="deadbeefdeadbeef",
        universe_hash="cafebabecafebabe",
        total_tested=1,
        total_stored=1,
        best_candidate=best,
        best_score=float(best.get("crib_score", 0)),
    )


def test_job_result_conversion_free_preserves_offanchor_crib():
    pt = _pt_offanchor()
    best = {
        "config_id": "cfg-free",
        "candidate_pt": pt,
        "crib_score": 24,
        "bean_passed": False,
        "bean_variant": None,
        "ngram_score": -3.0,
        "classification": "breakthrough",
        "scoring_mode": "free",
        "canonical_positions": False,
    }
    contract = job_result_to_worker_contract(_job_result(best))
    assert contract.crib_score == 24, (
        f"free JobResult zeroed at conversion (got {contract.crib_score}, "
        f"error={contract.verification_error!r})"
    )


def test_evaluate_one_emits_bean_frame_ct_for_post_transposition():
    """_evaluate_one must surface the Bean frame so the boundary can re-derive
    Bean in the correct frame. Known-answer fixture mirrors AUDIT-5's."""
    crib_positions = list(range(21, 34)) + list(range(63, 74))
    # English body so the (correct) crib-paste detector does not fire.
    PT = _pt_anchored()
    ct_nums = text_to_nums(CT)
    pt_nums = text_to_nums(PT)
    K = [0] * CT_LEN
    for i in crib_positions:
        K[i] = (ct_nums[i] - pt_nums[i]) % 26
    assert verify_bean_simple(K)
    inter = "".join(
        chr(ord("A") + (pt_nums[i] + K[i]) % 26) for i in range(CT_LEN)
    )
    perm = [CT_LEN - 1 - i for i in range(CT_LEN)]
    carved = apply_perm(inter, perm)
    result = _evaluate_one({
        "config_id": "frame-emit",
        "pipeline_dict": {
            "name": "frame_emit",
            "direction": "decrypt",
            "steps": [
                {"type": "transposition_full",
                 "params": {"perm": perm, "direction": "undo"}},
                {"type": "vigenere",
                 "params": {"key": K, "direction": "decrypt"}},
            ],
        },
        "challenge_ciphertext": carved,
        "challenge_crib_dict": None,
        "crib_alignment": "post_transposition",
    })
    assert "error" not in result, result
    assert result["scoring_mode"] == "post_transposition"
    assert result.get("bean_frame_ct") == inter, (
        "bean_frame_ct missing from _evaluate_one result — boundary cannot "
        "re-derive Bean in the route-undone frame"
    )
    # And the conversion must carry the dispatcher's frame verdict through.
    contract = job_result_to_worker_contract(_job_result(result))
    assert contract.crib_score == 24
    assert contract.bean_passed is True, (
        "route-frame Bean verdict lost at the contract boundary"
    )
    assert contract.bean_variant == "vigenere"
