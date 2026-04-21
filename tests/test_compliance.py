"""Tests for mechanism compliance scoring (Tier 0-3 constraint evaluation).

Verifies that the compliance framework correctly evaluates candidate
mechanisms against the full constraint hierarchy: hard constraints (HC),
coupling constraints (CxS), Bean structural constraints (SC), and
extra-cryptographic constraints (XC).

QUARANTINE 2026-04-14: `check_coupling_constraints` and
`score_mechanism_compliance` now take an explicit `palette` parameter
instead of silently importing NULL_PALETTE from the kernel. Tests that
want to exercise the historical palette-specific CxS-1 / CxS-3 math
must import NULL_PALETTE directly and pass it in. This is intentional:
the compliance scorer has zero live callers outside this test file, so
the math continues to be exercised as a regression fixture without the
live pipeline inheriting any implicit anchor to the retired palette.
Tests that do NOT pass `palette=` will get CxS-1=0.0 / CxS-3=0.0, which
drops the coupling score below COMPLIANT and flips the verdict to
PARTIAL. See memory/project_consensus_nulls_epistemic_status_2026_04_14.md.
"""
from __future__ import annotations

import warnings

import pytest

from kryptos.kernel.constants import ALPH, N_CRIBS
# Retired imports (moved from constants to retired/ in Phase 2, 2026-04-20).
# Used ONLY as test fixtures here — see module docstring for why. On allow-list
# in tests/test_retired_usage.py.
from kryptos.kernel.retired import BEAUFORT_KEYSTREAM_AT_CRIBS, NULL_PALETTE
from kryptos.kernel.scoring.compliance import (
    MechanismDescription,
    ComplianceScore,
    check_hard_constraints,
    check_coupling_constraints,
    check_bean_constraints,
    check_structural_constraints,
    score_mechanism_compliance,
)

# Real K4 Beaufort keystream at 24 crib positions, as integer values (A=0)
REAL_KS = [ALPH.index(c) for c in BEAUFORT_KEYSTREAM_AT_CRIBS]


def _full_mechanism() -> MechanismDescription:
    """A mechanism that matches all known K4 structural properties."""
    return MechanismDescription(
        name="Beaufort-5wide-dual",
        uses_ka=True,
        uses_az=True,
        grid_width=5,
        hand_executable=True,
        periodic=False,
        key_source="5-wide grid",
    )


def _bare_mechanism() -> MechanismDescription:
    """A mechanism with no structural claims (all fields minimal/None)."""
    return MechanismDescription(
        name="unknown",
        uses_ka=False,
        uses_az=False,
        grid_width=None,
        hand_executable=None,
        periodic=None,
        key_source=None,
    )


class TestMechanismDescription:
    """MechanismDescription dataclass creation and field access."""

    def test_create_basic(self):
        m = MechanismDescription(
            name="test",
            uses_ka=True,
            uses_az=False,
            grid_width=5,
            hand_executable=True,
            periodic=False,
            key_source="tableau",
        )
        assert m.name == "test"
        assert m.uses_ka is True
        assert m.uses_az is False
        assert m.grid_width == 5
        assert m.hand_executable is True
        assert m.periodic is False
        assert m.key_source == "tableau"
        assert m.notes == ""

    def test_notes_default(self):
        m = MechanismDescription(
            name="x", uses_ka=False, uses_az=False,
            grid_width=None, hand_executable=None,
            periodic=None, key_source=None,
        )
        assert m.notes == ""

    def test_notes_custom(self):
        m = MechanismDescription(
            name="x", uses_ka=False, uses_az=False,
            grid_width=None, hand_executable=None,
            periodic=None, key_source=None,
            notes="custom note",
        )
        assert m.notes == "custom note"


class TestHardConstraints:
    """HC-1 through HC-4: hard pass/fail/unknown constraints."""

    def test_real_keystream_passes_hc1(self):
        """Real keystream must match reference exactly."""
        result = check_hard_constraints(REAL_KS, _full_mechanism())
        assert result["HC-1"] == "PASS"

    def test_real_keystream_passes_hc2(self):
        """Bean equality k[27]=k[65] holds for real keystream."""
        result = check_hard_constraints(REAL_KS, _full_mechanism())
        assert result["HC-2"] == "PASS"

    def test_real_keystream_passes_hc3(self):
        """Bean inequalities all satisfied for real keystream."""
        result = check_hard_constraints(REAL_KS, _full_mechanism())
        assert result["HC-3"] == "PASS"

    def test_non_periodic_passes_hc4(self):
        """periodic=False should pass HC-4."""
        result = check_hard_constraints(REAL_KS, _full_mechanism())
        assert result["HC-4"] == "PASS"

    def test_wrong_keystream_fails_hc1(self):
        """All-zero keystream must fail HC-1."""
        wrong_ks = [0] * N_CRIBS
        result = check_hard_constraints(wrong_ks, _full_mechanism())
        assert result["HC-1"] == "FAIL"

    def test_periodic_true_fails_hc4(self):
        """periodic=True should fail HC-4 (periodic proven impossible)."""
        m = _full_mechanism()
        m.periodic = True
        result = check_hard_constraints(REAL_KS, m)
        assert result["HC-4"] == "FAIL"

    def test_periodic_none_gives_unknown(self):
        """periodic=None should give UNKNOWN for HC-4."""
        m = _full_mechanism()
        m.periodic = None
        result = check_hard_constraints(REAL_KS, m)
        assert result["HC-4"] == "UNKNOWN"

    def test_hc2_with_wrong_keystream(self):
        """All-zero keystream: k[27]=k[65] trivially holds (both 0)."""
        wrong_ks = [0] * N_CRIBS
        result = check_hard_constraints(wrong_ks, _full_mechanism())
        # Both are index 6 and 15 → both are 0 → equality holds
        assert result["HC-2"] == "PASS"

    def test_hc2_fails_with_inequality(self):
        """Keystream where k[idx6] != k[idx15] should fail HC-2."""
        ks = list(REAL_KS)
        ks[6] = (ks[15] + 1) % 26  # Make them differ
        result = check_hard_constraints(ks, _full_mechanism())
        assert result["HC-2"] == "FAIL"

    def test_all_hc_keys_present(self):
        """Result dict should contain exactly HC-1 through HC-4."""
        result = check_hard_constraints(REAL_KS, _full_mechanism())
        assert set(result.keys()) == {"HC-1", "HC-2", "HC-3", "HC-4"}

    def test_short_keystream_rejected(self):
        with pytest.raises(ValueError, match="exactly 24 values"):
            check_hard_constraints(REAL_KS[:-1], _full_mechanism())

    def test_out_of_range_keystream_rejected(self):
        bad = list(REAL_KS)
        bad[0] = 26
        with pytest.raises(ValueError, match=r"\[0, 26\)"):
            check_hard_constraints(bad, _full_mechanism())


class TestCouplingConstraints:
    """CxS-1 through CxS-4: coupling score components."""

    def test_real_keystream_high_cxs1(self):
        """Real keystream has 13/13 palette enrichment → normalized 1.0.

        Passes the retired NULL_PALETTE as an explicit test fixture.
        The math is still correct; the retirement is about not letting
        the live pipeline inherit this palette implicitly.
        """
        m = _full_mechanism()
        result = check_coupling_constraints(REAL_KS, m, palette=NULL_PALETTE)
        assert result["CxS-1"] == 1.0

    def test_palette_none_gives_zero_cxs1_cxs3_with_warning(self):
        """Quarantine regression: palette=None must zero the palette-dependent
        terms and emit a DeprecationWarning. This is the gate that prevents
        the live pipeline from silently anchoring to the retired palette."""
        m = _full_mechanism()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            result = check_coupling_constraints(REAL_KS, m)  # no palette arg
        assert result["CxS-1"] == 0.0
        assert result["CxS-3"] == 0.0
        # CxS-2 and CxS-4 are palette-independent and should be unchanged
        assert result["CxS-4"] == 1.0
        assert any(
            issubclass(w.category, DeprecationWarning)
            and "null_palette_retired" in str(w.message)
            for w in caught
        ), "Expected DeprecationWarning mentioning null_palette_retired"

    def test_cxs4_dual_alphabet(self):
        """Mechanism with both KA and AZ should score 1.0 on CxS-4."""
        m = _full_mechanism()
        result = check_coupling_constraints(REAL_KS, m)
        assert result["CxS-4"] == 1.0

    def test_cxs4_single_alphabet(self):
        """Mechanism with only KA (not AZ) should score 0.0 on CxS-4."""
        m = MechanismDescription(
            name="ka-only", uses_ka=True, uses_az=False,
            grid_width=5, hand_executable=True,
            periodic=False, key_source="grid",
        )
        result = check_coupling_constraints(REAL_KS, m)
        assert result["CxS-4"] == 0.0

    def test_all_cxs_keys_present(self):
        """Result dict should contain CxS-1 through CxS-4."""
        result = check_coupling_constraints(REAL_KS, _full_mechanism())
        assert set(result.keys()) == {"CxS-1", "CxS-2", "CxS-3", "CxS-4"}

    def test_all_values_in_range(self):
        """All coupling scores should be in [0.0, 1.0]."""
        result = check_coupling_constraints(REAL_KS, _full_mechanism())
        for key, val in result.items():
            assert 0.0 <= val <= 1.0, f"{key} = {val} out of range"

    def test_short_keystream_rejected_before_scoring(self):
        with pytest.raises(ValueError, match="exactly 24 values"):
            check_coupling_constraints(REAL_KS[:-1], _full_mechanism())


class TestBeanConstraints:
    """SC-4 and SC-5: Bean structural metrics."""

    def test_sc4_computed(self):
        """SC-4 should be a numeric value (minor difference sum)."""
        result = check_bean_constraints(REAL_KS)
        assert "SC-4" in result
        assert isinstance(result["SC-4"], (int, float))

    def test_sc5_computed(self):
        """SC-5 should be a numeric value (mean clustering distance)."""
        result = check_bean_constraints(REAL_KS)
        assert "SC-5" in result
        assert isinstance(result["SC-5"], float)

    def test_sc4_value(self):
        """SC-4 for K4 should be around 20 (sum of KRYPTOS-letter CT distances)."""
        result = check_bean_constraints(REAL_KS)
        # Computed from CT at crib positions: O=11, R=0, S=1, T=4+3+1=8 → 20
        assert result["SC-4"] == 20

    def test_sc5_value(self):
        """SC-5 for K4 should be approximately 3.6 (mean of all repeated-PT distances)."""
        result = check_bean_constraints(REAL_KS)
        assert abs(result["SC-5"] - 3.6154) < 0.01

    def test_all_sc_keys_present(self):
        """Result dict should contain SC-4 and SC-5."""
        result = check_bean_constraints(REAL_KS)
        assert set(result.keys()) == {"SC-4", "SC-5"}

    def test_malformed_keystream_rejected(self):
        with pytest.raises(ValueError, match="exactly 24 values"):
            check_bean_constraints(REAL_KS[:-1])


class TestStructuralConstraints:
    """XC-1 through XC-4: extra-cryptographic structural constraints."""

    def test_full_match_all_true(self):
        """Mechanism matching all K4 properties should get all True."""
        m = MechanismDescription(
            name="full", uses_ka=True, uses_az=True,
            grid_width=5, hand_executable=True,
            periodic=False, key_source="5-wide grid",
        )
        result = check_structural_constraints(m)
        assert result["XC-1"] is True
        assert result["XC-2"] is True
        assert result["XC-3"] is True
        assert result["XC-4"] is True

    def test_no_match_all_false(self):
        """Mechanism with no matching properties should get all False."""
        m = MechanismDescription(
            name="none", uses_ka=False, uses_az=False,
            grid_width=None, hand_executable=None,
            periodic=None, key_source=None,
        )
        result = check_structural_constraints(m)
        assert result["XC-1"] is False
        assert result["XC-2"] is False
        assert result["XC-3"] is False
        assert result["XC-4"] is False

    def test_grid_width_10_passes_xc2(self):
        """grid_width=10 (divisible by 5) should pass XC-2."""
        m = MechanismDescription(
            name="wide", uses_ka=False, uses_az=False,
            grid_width=10, hand_executable=None,
            periodic=None, key_source=None,
        )
        result = check_structural_constraints(m)
        assert result["XC-2"] is True

    def test_grid_width_7_fails_xc2(self):
        """grid_width=7 (not divisible by 5) should fail XC-2."""
        m = MechanismDescription(
            name="odd", uses_ka=False, uses_az=False,
            grid_width=7, hand_executable=None,
            periodic=None, key_source=None,
        )
        result = check_structural_constraints(m)
        assert result["XC-2"] is False

    def test_xc4_requires_grid5_and_key_source(self):
        """XC-4 requires BOTH grid_width==5 AND key_source not None."""
        m = MechanismDescription(
            name="partial", uses_ka=False, uses_az=False,
            grid_width=5, hand_executable=None,
            periodic=None, key_source=None,
        )
        result = check_structural_constraints(m)
        assert result["XC-4"] is False

    def test_all_xc_keys_present(self):
        """Result dict should contain XC-1 through XC-4."""
        result = check_structural_constraints(_full_mechanism())
        assert set(result.keys()) == {"XC-1", "XC-2", "XC-3", "XC-4"}


class TestFullCompliance:
    """End-to-end: score_mechanism_compliance() integration tests."""

    def test_real_keystream_proper_mechanism_compliant(self):
        """Real keystream + full mechanism → COMPLIANT (with explicit palette).

        Must pass palette=NULL_PALETTE explicitly so the CxS-1 and CxS-3
        terms fire; palette=None would yield PARTIAL under quarantine.
        """
        score = score_mechanism_compliance(
            REAL_KS, _full_mechanism(), palette=NULL_PALETTE
        )
        assert score.verdict == "COMPLIANT"

    def test_real_keystream_no_palette_is_partial_not_compliant(self):
        """Quarantine regression: without an explicit palette, the real
        keystream + full mechanism is PARTIAL, not COMPLIANT. This pins
        the gate — a future regression that re-introduces the implicit
        NULL_PALETTE default would make this test fail."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            score = score_mechanism_compliance(REAL_KS, _full_mechanism())
        assert score.verdict != "COMPLIANT"
        assert score.verdict in ("PARTIAL", "ELIMINATED")

    def test_random_keystream_bare_mechanism_not_compliant(self):
        """Random-ish keystream + bare mechanism → PARTIAL or ELIMINATED."""
        random_ks = list(range(24))  # 0..23, definitely wrong keystream
        score = score_mechanism_compliance(random_ks, _bare_mechanism())
        assert score.verdict in ("PARTIAL", "ELIMINATED")

    def test_periodic_true_eliminated(self):
        """Any mechanism with periodic=True → ELIMINATED (HC fail overrides palette)."""
        m = _full_mechanism()
        m.periodic = True
        # HC failure eliminates regardless of palette gating
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            score = score_mechanism_compliance(REAL_KS, m)
        assert score.verdict == "ELIMINATED"

    def test_compliance_score_fields(self):
        """ComplianceScore should have all expected fields."""
        score = score_mechanism_compliance(
            REAL_KS, _full_mechanism(), palette=NULL_PALETTE
        )
        assert isinstance(score.hard_pass, int)
        assert isinstance(score.hard_fail, int)
        assert isinstance(score.hard_unknown, int)
        assert isinstance(score.coupling_score, float)
        assert isinstance(score.bean_score, float)
        assert isinstance(score.structural_score, float)
        assert isinstance(score.total, float)
        assert isinstance(score.details, dict)
        assert isinstance(score.verdict, str)

    def test_compliant_has_positive_scores(self):
        """COMPLIANT mechanism should have positive coupling and structural scores.

        Requires explicit palette; see module docstring.
        """
        score = score_mechanism_compliance(
            REAL_KS, _full_mechanism(), palette=NULL_PALETTE
        )
        assert score.coupling_score >= 2.5
        assert score.structural_score > 0.0
        assert score.hard_fail == 0

    def test_details_contains_all_sections(self):
        """Details dict should contain results from all four checkers."""
        score = score_mechanism_compliance(
            REAL_KS, _full_mechanism(), palette=NULL_PALETTE
        )
        assert "hard" in score.details
        assert "coupling" in score.details
        assert "bean" in score.details
        assert "structural" in score.details

    def test_wrong_keystream_fails_hc1(self):
        """Wrong keystream should cause HC-1 fail → ELIMINATED."""
        wrong_ks = [0] * N_CRIBS
        # HC failure overrides palette gating
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            score = score_mechanism_compliance(wrong_ks, _full_mechanism())
        assert score.verdict == "ELIMINATED"
        assert score.hard_fail >= 1

    def test_malformed_keystream_rejected(self):
        with pytest.raises(ValueError, match="exactly 24 values"):
            score_mechanism_compliance(REAL_KS[:-1], _full_mechanism())
