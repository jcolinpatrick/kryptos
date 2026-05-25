"""Adversarial battery against kryptosbot.contracts._verify_against_kernel.

Framework maturation Phase 3 (2026-04-21). These tests are organized by
attack category. Each case feeds an adversarial input to the verifier
and asserts on both the return value (mutated contract fields) AND the
side-effect state (fields_overwritten, worker_self_report,
verification_error, bean_variant).

The verifier is the chokepoint that prevents fake breakthroughs.
Happy-path coverage already lives in kryptosbot/tests/test_contracts.py;
this file exercises the surface those tests don't — malformed input,
unicode smuggling, numeric type confusion, conflicting self-reports,
empty-plaintext edge cases, and correctness of the Bean-variant loop.

See docs/maturation/phase_03_report.md for the per-category rationale
and the branch-coverage argument.
"""

from __future__ import annotations

import random
from typing import Any, Optional

import pytest

from kryptosbot.contracts import (
    _BEAN_VARIANTS,
    _safe_float,
    _safe_int,
    _verify_against_kernel,
    extract_json_block,
    validate_worker_contract,
)
from kryptosbot.models import WorkerContract, WorkerStatus


# ─── Helpers ─────────────────────────────────────────────────────────────────

# Crib positions and contents (from kryptos.kernel.constants; mirrored here as
# test constants so a change in constants.py would cause an explicit
# failure here — the verifier's correctness is anchored to these values).
_CRIB_ENE_POS = 21   # "EASTNORTHEAST" spans [21, 33]
_CRIB_ENE_STR = "EASTNORTHEAST"
_CRIB_BC_POS = 63    # "BERLINCLOCK" spans [63, 73]
_CRIB_BC_STR = "BERLINCLOCK"


def _build_contract(
    pt: str,
    *,
    crib_score: Any = 0,
    bean_passed: Any = False,
    score: Any = 0.0,
    status: WorkerStatus = WorkerStatus.SUCCESS,
) -> WorkerContract:
    """Construct a WorkerContract for testing, bypassing validate_worker_contract.

    Tests that go through the full validator should use the `raw` helper in
    test_contracts.py; this helper is for testing the verifier in isolation.
    """
    return WorkerContract(
        hypothesis_id="TEST",
        status=status,
        score=score,
        crib_score=crib_score,
        bean_passed=bean_passed,
        best_plaintext=pt,
    )


def _correct_cribs_pt(filler: str = "X") -> str:
    """Build a 97-char PT whose 24 crib positions match the cribs exactly.

    Under all three additive variants, this PT produces a keystream that
    satisfies Bean at the 24 crib positions (variant-independence — see
    kryptos.kernel.constraints.derive.derive_bean_constraints, which
    superseded the deleted kryptos.kernel.constants._derive_bean_ineq). The filler at non-crib
    positions does not affect Bean (Bean constraints live only at crib
    positions); it only affects crib_score at those positions, which is
    zero since "X" is not a crib letter.

    Phase 2 note: a single-character filler (default "X") produces a PT
    that the crib-paste artifact detector in ``_verify_against_kernel``
    will classify as ``crib_paste`` and zero out — the non-crib ngram
    score falls below -6.2. Tests that need the 24/24 verification path
    to *pass through* the detector must use ``_correct_cribs_english_pt``
    below; tests that explicitly assert the artifact-rejection path
    continue to use this helper.
    """
    assert len(filler) == 1
    return (
        filler * _CRIB_ENE_POS                          # 0..20  (21 chars)
        + _CRIB_ENE_STR                                 # 21..33 (13 chars)
        + filler * (_CRIB_BC_POS - (_CRIB_ENE_POS + len(_CRIB_ENE_STR)))
                                                        # 34..62 (29 chars)
        + _CRIB_BC_STR                                  # 63..73 (11 chars)
        + filler * (97 - (_CRIB_BC_POS + len(_CRIB_BC_STR)))
                                                        # 74..96 (23 chars)
    )


# Plausible English filler used by tests that need a 24/24 result to
# pass through the Phase 2 crib-paste artifact detector. Pattern mirrors
# the canonical English-filler PT in tests/test_crib_paste_detector.py
# (THEQUICKBROWNFOXJUMPSOVERLAZYDOG); the non-crib positions of the
# resulting PT score well above the -6.2 ngram floor.
_ENGLISH_FILLER_SOURCE = "THEQUICKBROWNFOXJUMPSOVERLAZYDOG"


def _correct_cribs_english_pt() -> str:
    """Build a 97-char PT with canonical cribs at 21-33 / 63-73 and
    plausible-English filler everywhere else.

    This is the Phase 2-safe analogue of ``_correct_cribs_pt("X")`` — same
    24/24 crib match, same Bean validity under all three variants, but the
    non-crib positions look like English so the crib-paste detector does
    not fire. Use this whenever a test asserts the 24/24 verifier path
    succeeds (Categories 2/3/4/7/9 happy-path branches).
    """
    src = (_ENGLISH_FILLER_SOURCE * 4)[:97]
    pt = list(src)
    for i, ch in enumerate(_CRIB_ENE_STR):
        pt[_CRIB_ENE_POS + i] = ch
    for i, ch in enumerate(_CRIB_BC_STR):
        pt[_CRIB_BC_POS + i] = ch
    return "".join(pt)


def _random_noncrib_pt(seed: int) -> str:
    """97-char PT that (overwhelmingly likely) fails Bean under all three variants."""
    rng = random.Random(seed)
    return "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(97))


def _assert_zero_score_fields(c: WorkerContract) -> None:
    assert c.crib_score == 0, f"crib_score not zeroed: {c.crib_score}"
    assert c.bean_passed is False, f"bean_passed not zeroed: {c.bean_passed}"
    assert c.score == 0.0, f"score not zeroed: {c.score}"
    assert c.bean_variant is None, f"bean_variant not None: {c.bean_variant}"


# ─── Category 1: length mismatches ───────────────────────────────────────────

class TestCategory1_LengthMismatches:
    """Any best_plaintext whose length (after .strip().upper()) is neither 0
    nor 97 must zero every worker-claim field and record a length-based
    verification_error."""

    @pytest.mark.parametrize("length,label", [
        (1, "len_1"),
        (73, "len_73_CT73_space"),
        (96, "len_96_off_by_one_under"),
        (98, "len_98_off_by_one_over"),
        (194, "len_194_double_CT"),
    ])
    def test_nonempty_wrong_length_zeros_worker_claim(self, length, label):
        pt = "A" * length
        c = _build_contract(pt, crib_score=24, bean_passed=True, score=42.0)

        _verify_against_kernel(c)

        _assert_zero_score_fields(c)
        assert c.fields_overwritten is True
        assert c.verification_error.startswith(
            f"best_plaintext length {length} != 97"
        ), f"{label}: unexpected error: {c.verification_error}"
        assert c.worker_self_report == {
            "crib_score": 24, "bean_passed": True, "score": 42.0,
        }, f"{label}: worker_self_report lost"


# ─── Category 2: case / whitespace smuggling ─────────────────────────────────

class TestCategory2_CaseAndWhitespaceSmuggling:
    """The verifier normalizes with .strip().upper() — leading/trailing
    whitespace and case do not defeat verification. Internal whitespace and
    embedded newlines shift the length and fall through to length / kernel
    branches."""

    def test_lowercase_97_chars_verifies_after_upper(self):
        """A lowercase 97-char PT uppercases to a valid verifiable PT.

        Uses English filler so the 24/24 result passes through the Phase 2
        crib-paste artifact detector (X-filler would be classified as
        crib_paste and zeroed). The case-normalization branch under test
        is independent of the filler choice.
        """
        pt = _correct_cribs_english_pt().lower()
        assert len(pt) == 97
        c = _build_contract(pt, crib_score=24, bean_passed=True, score=24.0)

        _verify_against_kernel(c)

        assert c.crib_score == 24, "lowercase correct-cribs PT failed to verify"
        assert c.bean_passed is True
        assert c.bean_variant == "vigenere"
        assert c.fields_overwritten is False, "agreement should leave fields untouched"
        assert c.verification_error == ""

    def test_mixed_case_97_chars_verifies_after_upper(self):
        """Mixed casing normalizes identically; worker disagreement still caught.

        Uses English filler (see test_lowercase_… for rationale).
        """
        pt = _correct_cribs_english_pt()
        # Deliberately toggle cases on the English-filler PT.
        pt_mixed = "".join(
            (ch.upper() if i % 2 == 0 else ch.lower())
            for i, ch in enumerate(pt)
        )
        assert len(pt_mixed) == 97
        c = _build_contract(pt_mixed, crib_score=0, bean_passed=False, score=0.0)

        _verify_against_kernel(c)

        assert c.crib_score == 24, "mixed-case correct-cribs PT failed to verify"
        assert c.bean_passed is True
        assert c.bean_variant == "vigenere"
        # Worker pessimistically reported 0/False; verifier overwrites.
        assert c.fields_overwritten is True
        assert c.worker_self_report == {"crib_score": 0, "bean_passed": False, "score": 0.0}

    def test_surrounding_whitespace_is_stripped(self):
        """Leading/trailing spaces and newlines are stripped without penalty.

        Uses English filler so the 24/24 result passes through the Phase 2
        crib-paste artifact detector.
        """
        pt = "   \n\t" + _correct_cribs_english_pt().lower() + "\n   "
        c = _build_contract(pt, crib_score=24, bean_passed=True, score=24.0)

        _verify_against_kernel(c)

        assert c.crib_score == 24
        assert c.bean_passed is True
        assert c.verification_error == ""

    def test_internal_space_shifts_length(self):
        """An internal space survives strip() and makes length != 97 OR
        causes kernel verification to raise. Either way, verifier zeroes
        worker claim."""
        pt_base = _correct_cribs_pt("X")
        # Insert a space at position 5, keeping total length 97 by trimming one X.
        pt = pt_base[:5] + " " + pt_base[5 + 1:]
        assert len(pt) == 97
        c = _build_contract(pt, crib_score=24, bean_passed=True, score=24.0)

        _verify_against_kernel(c)

        # Either length check or kernel exception branch zeros the claim.
        _assert_zero_score_fields(c)
        assert c.fields_overwritten is True
        assert c.worker_self_report == {
            "crib_score": 24, "bean_passed": True, "score": 24.0,
        }
        assert c.verification_error  # non-empty

    def test_internal_newline_shifts_length(self):
        """An internal newline is not stripped by .strip() (only edges are)."""
        pt_base = _correct_cribs_pt("X")
        pt = pt_base[:10] + "\n" + pt_base[10 + 1:]
        assert len(pt) == 97
        c = _build_contract(pt, crib_score=24, bean_passed=True, score=24.0)

        _verify_against_kernel(c)

        _assert_zero_score_fields(c)
        assert c.fields_overwritten is True
        assert c.verification_error


# ─── Category 3: crib-position-only fakes ────────────────────────────────────

class TestCategory3_CribPositionOnlyFakes:
    """A PT that *only* matches cribs at the 24 anchored positions and is
    garbage elsewhere still registers crib_score=24 and Bean PASS —
    that's by construction, not hallucination. The verifier must accept
    the high score while still overwriting any *other* mis-matching
    worker claim."""

    def test_cribs_inserted_into_filler_is_rejected_as_crib_paste(self):
        """X-filler with cribs at the right spots: kernel agrees 24/True
        BEFORE the Phase 2 paste filter. The filter then rejects the PT as
        a crib-paste artifact and zeroes the score fields.

        Retargeted under Phase 2 yield-feedback (Task 14): the prior
        Phase 1 behavior (24/24 X-paste flowed through the verifier
        untouched) is exactly what the detector now suppresses. The kernel
        still sees 24/True, but the snapshot lives in
        raw_artifacts.kernel_verified_before_artifact_filter while the
        contract is forced to INCONCLUSIVE.
        """
        pt = _correct_cribs_pt("X")
        c = _build_contract(pt, crib_score=24, bean_passed=True, score=24.0)

        _verify_against_kernel(c)

        # Score fields zeroed by the paste filter.
        assert c.crib_score == 0
        assert c.bean_passed is False
        assert c.score == 0.0
        assert c.bean_variant is None
        assert c.status == WorkerStatus.INCONCLUSIVE

        # Audit trail records what the kernel saw before the filter ran.
        assert c.fields_overwritten is True
        assert c.raw_artifacts.get("artifact_class") == "crib_paste"
        snapshot = c.raw_artifacts.get("kernel_verified_before_artifact_filter")
        assert isinstance(snapshot, dict)
        assert snapshot.get("crib_score") == 24
        assert snapshot.get("bean_passed") is True
        assert snapshot.get("bean_variant") == "vigenere"
        assert "crib_paste_artifact:v1" in c.verification_error
        # Worker's claim is preserved even though it agreed with the
        # pre-filter kernel verdict — Phase 2 still snapshots because the
        # final mutated fields no longer match the worker self-report.
        assert c.worker_self_report == {
            "crib_score": 24, "bean_passed": True, "score": 24.0,
        }

    def test_cribs_inserted_but_worker_underreports(self):
        """English-filler PT; worker claimed 0/False (pessimistic). Verifier
        correctly upgrades to 24/True AND flags the disagreement.

        Uses English filler so the 24/24 result passes through the Phase 2
        crib-paste detector — the test's purpose is to verify the worker-
        underreport upgrade branch, not the artifact-rejection branch.
        """
        pt = _correct_cribs_english_pt()
        c = _build_contract(pt, crib_score=0, bean_passed=False, score=0.0)

        _verify_against_kernel(c)

        assert c.crib_score == 24
        assert c.bean_passed is True
        assert c.bean_variant == "vigenere"
        assert c.fields_overwritten is True
        assert c.worker_self_report == {
            "crib_score": 0, "bean_passed": False, "score": 0.0,
        }

    def test_fake_cribs_at_correct_positions_fail(self):
        """PT that puts wrong letters at crib positions — use 'X' throughout
        (X is not in any crib letter). All 24 crib positions mis-match;
        crib_score == 0. Worker's 24/True claim collapses.

        (Note: using the reversed crib strings would coincidentally match
        some palindromic positions — the reversed 'EASTNORTHEAST' has an R
        at position 27 matching the real 'R' there, and reversed
        'BERLINCLOCK' matches at L/N/L positions. Those coincidences are
        interesting on their own but not what this test is asserting.)"""
        pt = "X" * 97
        c = _build_contract(pt, crib_score=24, bean_passed=True, score=24.0)

        _verify_against_kernel(c)

        assert c.crib_score == 0
        assert c.bean_passed is False
        assert c.bean_variant is None
        assert c.fields_overwritten is True
        assert c.worker_self_report == {
            "crib_score": 24, "bean_passed": True, "score": 24.0,
        }


# ─── Category 4: Bean-variant selection ──────────────────────────────────────

class TestCategory4_BeanVariantSelection:
    """The verifier loops over _BEAN_VARIANTS in declared order and stops
    at the first PASS. The Bean variant names are recorded on
    contract.bean_variant so downstream can audit which variant was accepted.

    Variant-independent Bean semantics mean a correct-crib PT passes under
    all three variants — so natural "only variant X passes" PTs are
    astronomically unlikely. We use monkeypatch on verify_bean_simple
    to deterministically force each single-variant scenario."""

    def test_correct_cribs_picks_first_variant_vigenere(self):
        """Correct cribs ⇒ all three variants pass ⇒ first in loop wins.

        Uses English filler so the 24/24 result passes through the Phase 2
        crib-paste detector — the test's purpose is to verify the Bean-
        variant loop's order/short-circuit, not the artifact-rejection
        branch. (X-filler trips the paste filter and bean_variant is
        cleared to None before this assertion runs.)
        """
        pt = _correct_cribs_english_pt()
        c = _build_contract(pt)

        _verify_against_kernel(c)

        assert c.bean_passed is True
        assert c.bean_variant == "vigenere"

    def test_only_beaufort_variant_passes(self, monkeypatch):
        """Monkeypatch so Bean returns True only on the 2nd call (Beaufort)."""
        calls = {"n": 0}

        def fake_verify(keystream):
            calls["n"] += 1
            return calls["n"] == 2  # only the 2nd attempt passes

        monkeypatch.setattr(
            "kryptos.kernel.constraints.bean.verify_bean_simple", fake_verify
        )
        c = _build_contract(_random_noncrib_pt(42))

        _verify_against_kernel(c)

        assert c.bean_passed is True
        assert c.bean_variant == "beaufort"
        assert calls["n"] == 2, (
            "Verifier should short-circuit after 2nd (beaufort) PASS; "
            f"called verify_bean_simple {calls['n']} times"
        )

    def test_only_variant_beaufort_passes(self, monkeypatch):
        """Monkeypatch so Bean returns True only on the 3rd call."""
        calls = {"n": 0}

        def fake_verify(keystream):
            calls["n"] += 1
            return calls["n"] == 3

        monkeypatch.setattr(
            "kryptos.kernel.constraints.bean.verify_bean_simple", fake_verify
        )
        c = _build_contract(_random_noncrib_pt(7))

        _verify_against_kernel(c)

        assert c.bean_passed is True
        assert c.bean_variant == "variant_beaufort"
        assert calls["n"] == 3

    def test_no_variant_passes_bean_variant_is_none(self):
        """Random garbage PT: none of the three variants produce a
        Bean-valid 24-vector. bean_passed=False, bean_variant=None."""
        pt = _random_noncrib_pt(2026_04_21)
        c = _build_contract(pt, crib_score=0, bean_passed=False)

        _verify_against_kernel(c)

        assert c.bean_passed is False
        assert c.bean_variant is None

    def test_bean_variant_declared_order_is_vig_beau_varbeau(self):
        """The loop order is the contract — audit logs and correctness
        assertions elsewhere depend on it."""
        assert [name for name, _ in _BEAN_VARIANTS] == [
            "vigenere", "beaufort", "variant_beaufort",
        ]


# ─── Category 5: empty plaintext + non-zero claim ────────────────────────────

class TestCategory5_EmptyPlaintextWithNonZeroClaim:
    """best_plaintext="" is a legitimate "no candidate" signal — the
    verifier only complains if the worker attaches non-zero score claims
    to it."""

    def test_empty_with_nonzero_crib_claim_is_overwritten(self):
        c = _build_contract("", crib_score=24, bean_passed=True, score=100.0)

        _verify_against_kernel(c)

        _assert_zero_score_fields(c)
        assert c.fields_overwritten is True
        assert c.verification_error == (
            "Worker reported non-zero score fields with empty best_plaintext"
        )
        assert c.worker_self_report == {
            "crib_score": 24, "bean_passed": True, "score": 100.0,
        }

    def test_whitespace_only_plaintext_is_treated_as_empty(self):
        """After .strip().upper() a whitespace-only PT is empty."""
        c = _build_contract("   \n\t ", crib_score=10, bean_passed=False, score=15.0)

        _verify_against_kernel(c)

        _assert_zero_score_fields(c)
        assert c.fields_overwritten is True
        assert c.verification_error.startswith("Worker reported non-zero score fields")
        assert c.worker_self_report == {
            "crib_score": 10, "bean_passed": False, "score": 15.0,
        }


# ─── Category 6: unicode / non-A-Z smuggling ─────────────────────────────────

class TestCategory6_UnicodeSmuggling:
    """Non-A-Z characters slip past strip/upper. As of 2026-05-16 these are
    rejected explicitly at the pt.isalpha() guard, BEFORE the kernel call —
    previously they fell through and produced a misleading "Kernel verification
    raised: verify_bean_simple requires a length-97 keystream, got N" error
    when text_to_nums silently dropped the non-A-Z chars."""

    def test_accented_char_rejected_at_alphabet_guard(self):
        """A single accented char in an otherwise 97-char PT is rejected at
        the alphabet guard with a clear error message."""
        pt = _correct_cribs_pt("X")[:50] + "é" + _correct_cribs_pt("X")[51:]
        assert len(pt) == 97
        c = _build_contract(pt, crib_score=24, bean_passed=True, score=24.0)

        _verify_against_kernel(c)

        _assert_zero_score_fields(c)
        assert c.fields_overwritten is True
        assert c.verification_error.startswith(
            "best_plaintext contains non-A-Z characters"
        )
        assert c.worker_self_report == {
            "crib_score": 24, "bean_passed": True, "score": 24.0,
        }

    def test_zero_width_joiner_shifts_length(self):
        """ZWJ is one char; appending to a 97-char PT makes len == 98."""
        pt = _correct_cribs_pt("X") + "‍"
        assert len(pt) == 98
        c = _build_contract(pt, crib_score=24, bean_passed=True, score=24.0)

        _verify_against_kernel(c)

        _assert_zero_score_fields(c)
        assert c.fields_overwritten is True
        # Falls through the length branch, not the alphabet branch.
        assert c.verification_error.startswith("best_plaintext length 98 != 97")

    def test_cyrillic_homoglyph_rejected_at_alphabet_guard(self):
        """Cyrillic 'А' (U+0410) looks like Latin 'A' but is a different
        codepoint. Rejected explicitly at the alphabet guard."""
        # Replace the first crib letter E at position 21 with Cyrillic А (U+0410).
        pt_base = _correct_cribs_pt("X")
        pt = pt_base[:21] + "А" + pt_base[22:]
        assert len(pt) == 97
        c = _build_contract(pt, crib_score=24, bean_passed=True)

        _verify_against_kernel(c)

        _assert_zero_score_fields(c)
        assert c.fields_overwritten is True
        assert c.verification_error.startswith(
            "best_plaintext contains non-A-Z characters"
        )

    def test_question_mark_placeholder_rejected_cleanly(self):
        """Workers sometimes emit '?' for unknown positions. With len==97 these
        used to leak the kernel's "got N != 97" error; now caught at the
        alphabet guard with a clear message. Regression for the 2026-05-08
        audit finding (controller_maturity_audit_2026_05_16.md)."""
        pt = "?NTM??X?LJ?VDH?D?APVUUCYFNFWFDSAXQ?WUKNVHQZO?BABV?AMTR?C??D?ERFAEZBDRJLZLMERPBQXVYDT?SK?W????EI?A"
        assert len(pt) == 97
        c = _build_contract(pt, crib_score=4, bean_passed=False, score=4.0)

        _verify_against_kernel(c)

        _assert_zero_score_fields(c)
        assert c.fields_overwritten is True
        assert c.verification_error.startswith(
            "best_plaintext contains non-A-Z characters"
        )
        # Sanity check: the count in the message matches reality.
        assert "got 21 non-alphabetic char(s)" in c.verification_error


# ─── Category 7: numeric field type confusion ────────────────────────────────

class TestCategory7_NumericTypeConfusion:
    """Direct WorkerContract construction can bypass validate_worker_contract's
    type checks. The verifier must not crash on bad types — it should
    coerce via _safe_int / _safe_float, zeroing on ValueError."""

    def test_crib_score_as_float_truncates_via_int(self):
        """A 24.7 float crib_score snapshots as int(24.7) == 24."""
        c = _build_contract("", crib_score=24.7, bean_passed=False, score=0.0)

        _verify_against_kernel(c)

        # Empty-with-nonzero branch fired because 24 != 0.
        assert c.fields_overwritten is True
        assert c.worker_self_report["crib_score"] == 24  # truncated float
        _assert_zero_score_fields(c)

    def test_bean_passed_as_int_one_is_treated_as_true(self):
        """bool(1) is True; non-zero claim triggers the overwrite branch."""
        c = _build_contract("", crib_score=0, bean_passed=1, score=0.0)

        _verify_against_kernel(c)

        assert c.fields_overwritten is True
        assert c.worker_self_report["bean_passed"] is True

    def test_score_as_nonnumeric_string_is_coerced_to_zero(self):
        """_safe_float("not a number") returns 0.0 instead of crashing.

        Uses English filler so the 24/24 result passes through the Phase 2
        crib-paste detector — the test's purpose is to verify the
        _safe_float coercion path on a pathological non-numeric score,
        not the artifact-rejection branch.
        """
        # This test would raise ValueError in the pre-Phase-3 verifier.
        c = _build_contract(
            _correct_cribs_english_pt(), crib_score=24, bean_passed=True,
            score="not a number",
        )

        _verify_against_kernel(c)

        # Verifier did not crash; score gets mirrored from verified_crib.
        assert c.score == 24.0
        assert c.crib_score == 24
        assert c.bean_passed is True
        # worker_claim.score was coerced to 0.0 (not "not a number")
        # so disagreement on bean_passed/crib_score determines overwrite.
        # Both verify as correct; no disagreement → not overwritten.
        assert c.fields_overwritten is False

    def test_safe_int_helpers_handle_pathological_inputs(self):
        """Contract between the _safe_* helpers and caller: never raise."""
        assert _safe_int(None) == 0
        assert _safe_int("abc") == 0
        assert _safe_int(42) == 42
        assert _safe_int(42.9) == 42
        assert _safe_int("") == 0
        assert _safe_int(object()) == 0
        assert _safe_float(None) == 0.0
        assert _safe_float("not a float") == 0.0
        assert _safe_float("") == 0.0
        assert _safe_float(1.5) == 1.5
        assert _safe_float("1.5") == 1.5
        assert _safe_float(object()) == 0.0


# ─── Category 8: deeply nested / malformed JSON payload ──────────────────────

class TestCategory8_NestedPayload:
    """extract_json_block + validate_worker_contract are the upstream parser;
    the verifier only sees the contract that emerges from them. These
    tests exercise the extract-and-validate path with nested payloads."""

    def test_extract_picks_last_fenced_block(self):
        """When multiple fenced blocks are present, the last one is picked."""
        raw = (
            '```json\n{"status": "inconclusive", "score": 0}\n```\n'
            'more text\n'
            '```json\n{"status": "success", "score": 42}\n```\n'
        )
        block = extract_json_block(raw)
        assert block is not None
        assert '"score": 42' in block
        assert '"score": 0' not in block

    def test_validate_through_nested_fence_returns_last(self):
        """Full pipeline: two fenced blocks, only the last one is trusted."""
        raw = (
            '```json\n{"status": "success", "crib_score": 99, "best_plaintext": ""}\n```\n'
            'decoy narrative\n'
            '```json\n{"status": "success", "crib_score": 0, "best_plaintext": ""}\n```\n'
        )
        result = validate_worker_contract(raw, hypothesis_id="H-NESTED")
        assert result.is_valid, f"expected valid contract; errors: {result.errors}"
        # Empty PT + crib_score=0 = clean; no overwrite. crib_score=99 from the
        # decoy is not present on the contract.
        assert result.value.crib_score == 0
        assert result.value.fields_overwritten is False


# ─── Category 9: conflicting self-reports ────────────────────────────────────

class TestCategory9_ConflictingSelfReports:
    """The most common hallucination failure mode: a worker emits an
    internally inconsistent result (high crib_score with empty PT,
    high score with crib_score=0, bean_passed=False with crib_score=24,
    etc.). The verifier must overwrite to kernel truth regardless."""

    def test_crib24_but_bean_false_worker_on_correct_cribs(self):
        """Worker says 24/False, kernel says 24/True — bean disagreement
        triggers overwrite.

        Uses English filler so the 24/24 result passes through the Phase 2
        crib-paste detector — the test's purpose is to verify the bean-
        disagreement overwrite branch, not the artifact-rejection branch.
        """
        pt = _correct_cribs_english_pt()
        c = _build_contract(pt, crib_score=24, bean_passed=False, score=24.0)

        _verify_against_kernel(c)

        assert c.crib_score == 24  # agreement
        assert c.bean_passed is True  # overwrite
        assert c.bean_variant == "vigenere"
        assert c.fields_overwritten is True
        assert c.worker_self_report == {
            "crib_score": 24, "bean_passed": False, "score": 24.0,
        }

    def test_crib24_bean_true_but_kernel_says_zero(self):
        """Worker's 24/True is a pure lie on random PT."""
        pt = _random_noncrib_pt(31415)
        c = _build_contract(pt, crib_score=24, bean_passed=True, score=24.0)

        _verify_against_kernel(c)

        assert c.crib_score < 24, f"random PT scored {c.crib_score}"
        assert c.bean_passed is False
        assert c.bean_variant is None
        assert c.fields_overwritten is True
        assert c.worker_self_report == {
            "crib_score": 24, "bean_passed": True, "score": 24.0,
        }

    def test_score_100_but_crib_score_0_mirrors_from_kernel(self):
        """Contract.score is mirrored from verified_crib, not from worker."""
        pt = _random_noncrib_pt(9999)
        c = _build_contract(pt, crib_score=0, bean_passed=False, score=100.0)

        _verify_against_kernel(c)

        # score field always mirrors verified crib_score as float.
        assert c.score == float(c.crib_score)
        assert c.score != 100.0
        # Worker claimed score=100 but crib_score=0; disagreement depends on
        # whether verified_crib matches worker's crib_score claim.
        # Random PT is extremely unlikely to have crib_score=0 AND the worker
        # claim of 0 — so agreement is plausible. Check the invariant
        # regardless of overwrite flag.

    def test_worker_reports_crib_score_as_none(self):
        """None is a legitimate 'field absent' — _safe_int coerces to 0."""
        c = WorkerContract(
            hypothesis_id="H-NONE",
            status=WorkerStatus.SUCCESS,
            best_plaintext="",
        )
        # crib_score/bean_passed/score stay at defaults (0 / False / 0.0)

        _verify_against_kernel(c)

        assert c.fields_overwritten is False  # truthful null report
        assert c.verification_error == ""
        _assert_zero_score_fields(c)


# ─── Property: kernel always overrules worker on crib_score ──────────────────

class TestProperty_KernelOverrulesWorker:
    """For any random 97-char PT, regardless of worker-reported
    (crib_score, bean_passed, score), the final contract.crib_score must
    equal kernel's score_cribs(pt). The verifier's promise is that
    workers cannot inject false breakthroughs.

    Implemented as deterministic Monte Carlo (hypothesis library not in
    venv and not installed by this brief to avoid network). Seeded for
    reproducibility; sample size chosen to exercise all crib_score
    values 0..1 that random PTs can produce.
    """

    _N_TRIALS = 200
    _SEED_BASE = 20260421  # phase date

    def test_worker_cannot_inflate_crib_score(self):
        """For every random PT, no worker claim can set contract.crib_score
        to a value greater than what score_cribs(pt) returned."""
        from kryptos.kernel.scoring.crib_score import score_cribs

        rng = random.Random(self._SEED_BASE)
        violations = []
        for trial in range(self._N_TRIALS):
            pt_bytes = [
                rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(97)
            ]
            pt = "".join(pt_bytes)
            truth = int(score_cribs(pt))

            # Worker claims a wildly inflated crib_score + bean_passed.
            claimed = rng.randint(truth + 1, 24) if truth < 24 else 24
            c = _build_contract(
                pt, crib_score=claimed, bean_passed=True, score=float(claimed),
            )
            _verify_against_kernel(c)

            if c.crib_score != truth:
                violations.append((trial, truth, claimed, c.crib_score))

        assert not violations, (
            f"Kernel failed to overrule worker in {len(violations)} trials: "
            f"{violations[:5]}"
        )

    def test_worker_cannot_force_bean_pass_with_random_pt(self):
        """For any random PT where all three variants fail Bean, no worker
        claim can end with contract.bean_passed=True."""
        from kryptos.kernel.constraints.bean import verify_bean_simple
        from kryptos.kernel.constants import CT
        from kryptos.kernel.text import text_to_nums

        rng = random.Random(self._SEED_BASE + 1)
        ct_nums = text_to_nums(CT)

        for trial in range(self._N_TRIALS):
            pt = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ") for _ in range(97))
            pt_nums = text_to_nums(pt)
            # Precompute ground-truth bean_passed for this PT.
            truth = False
            for _, derive in _BEAN_VARIANTS:
                ks = [derive(c, p) for c, p in zip(ct_nums, pt_nums)]
                if verify_bean_simple(ks):
                    truth = True
                    break

            c = _build_contract(pt, crib_score=0, bean_passed=True, score=0.0)
            _verify_against_kernel(c)

            assert c.bean_passed is truth, (
                f"trial {trial}: kernel truth={truth} but contract says "
                f"{c.bean_passed}"
            )
