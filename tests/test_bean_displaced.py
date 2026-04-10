"""Tests for Bean constraint re-derivation under transposition-first ciphers.

These tests validate the TABP (Transposition-Aware Bean Pre-Filter) math
before any campaign compute is committed. The identity + reverse tests are
mandated by the red-team-disprover adversarial review that killed the
initial "just permute the indices" implementation — they would have caught
the original error immediately.

The core claim being tested:
    rederive_bean_for_transposition(identity) == (BEAN_EQ, BEAN_INEQ)

If this fails, the derivation is broken and no TABP campaign may run.
"""
from __future__ import annotations

import pytest

from kryptos.kernel.constants import (
    ALPH_IDX,
    BEAN_EQ,
    BEAN_INEQ,
    CRIB_DICT,
    CT,
    CT_LEN,
    KRYPTOS_ALPHABET,
)
from kryptos.kernel.constraints.bean import (
    rederive_bean_for_transposition,
    verify_bean_simple,
)


# ── Red-team mandatory tests ───────────────────────────────────────────

class TestBeanRederivationRedTeamMandatory:
    """Tests explicitly required by the red-team-disprover review.

    Rationale: the original TABP proposal claimed the 242 inequalities were
    T-invariant and could be re-indexed through T. The red-team showed this
    was false — inequalities encode letter pairings, not just positions.
    These tests would have killed that implementation instantly.
    """

    def test_identity_reproduces_canonical_eq(self) -> None:
        """T=identity must reproduce the canonical BEAN_EQ exactly.

        If this fails, the re-derivation has diverged from the authoritative
        constants._derive_bean_ineq derivation and is not safe to use.
        """
        identity = list(range(CT_LEN))
        eq, _ineq = rederive_bean_for_transposition(identity)

        assert len(eq) == len(BEAN_EQ), (
            f"Identity T produced {len(eq)} equalities, canonical has "
            f"{len(BEAN_EQ)}. Re-derivation diverges from constants."
        )
        assert set(eq) == set(BEAN_EQ), (
            f"Identity T equality set differs from canonical.\n"
            f"  Derived: {sorted(eq)}\n"
            f"  Canonical: {sorted(BEAN_EQ)}"
        )

    def test_identity_reproduces_canonical_ineq(self) -> None:
        """T=identity must reproduce the canonical BEAN_INEQ (242 pairs) exactly.

        This is the most load-bearing test in the suite. If it passes, we
        know the re-derivation matches the authoritative direct-positional
        math at the one input where they must agree.
        """
        identity = list(range(CT_LEN))
        _eq, ineq = rederive_bean_for_transposition(identity)

        assert len(ineq) == 242, (
            f"Identity T produced {len(ineq)} inequalities, canonical has 242."
        )
        assert set(ineq) == set(BEAN_INEQ), (
            f"Identity T inequality set differs from canonical.\n"
            f"  Missing from derived: "
            f"{set(BEAN_INEQ) - set(ineq)}\n"
            f"  Extra in derived: "
            f"{set(ineq) - set(BEAN_INEQ)}"
        )

    def test_reverse_T_differs_from_identity(self) -> None:
        """T=reverse must produce a DIFFERENT constraint set from identity.

        If reversing the CT produced the same inequality set, the derivation
        would be T-invariant — which would contradict the letter-pairing
        semantics and mean the function is broken. This test proves the
        derivation is correctly sensitive to T.
        """
        reverse_T = [CT_LEN - 1 - i for i in range(CT_LEN)]
        eq_rev, ineq_rev = rederive_bean_for_transposition(reverse_T)

        assert set(ineq_rev) != set(BEAN_INEQ), (
            "Reverse T produced the same inequality set as identity — "
            "derivation is T-invariant, which contradicts letter-pairing "
            "semantics. The re-derivation is broken."
        )

        # Sanity: reverse T should still produce SOME derivable constraints,
        # otherwise the crib-letter-to-CT-letter mapping is so scrambled that
        # no variant-independent structure survives.
        assert len(eq_rev) + len(ineq_rev) > 0, (
            "Reverse T produced no derivable constraints — "
            "possible edge case, verify manually"
        )


# ── Structural invariants ──────────────────────────────────────────────

class TestBeanRederivationStructural:
    """Structural properties that must hold for any valid T."""

    def test_rejects_wrong_length(self) -> None:
        with pytest.raises(ValueError, match="length"):
            rederive_bean_for_transposition([0, 1, 2])

    def test_rejects_non_permutation(self) -> None:
        """Input must be a valid permutation of 0..96."""
        not_a_perm = [0] * CT_LEN  # all zeros
        with pytest.raises(ValueError, match="permutation"):
            rederive_bean_for_transposition(not_a_perm)

    def test_rejects_out_of_range(self) -> None:
        """Input with values outside 0..96 must be rejected."""
        bad = list(range(CT_LEN))
        bad[0] = 100
        with pytest.raises(ValueError, match="permutation"):
            rederive_bean_for_transposition(bad)

    def test_output_pairs_are_sorted_within(self) -> None:
        """Each returned pair (a, b) must satisfy a < b for stable set ops."""
        # Use reverse T to exercise the normalization path
        reverse_T = [CT_LEN - 1 - i for i in range(CT_LEN)]
        eq, ineq = rederive_bean_for_transposition(reverse_T)
        for a, b in eq:
            assert a < b, f"EQ pair not sorted: ({a}, {b})"
        for a, b in ineq:
            assert a < b, f"INEQ pair not sorted: ({a}, {b})"

    def test_output_positions_in_ct_coordinates(self) -> None:
        """All returned positions must be valid CT indices 0..96."""
        reverse_T = [CT_LEN - 1 - i for i in range(CT_LEN)]
        eq, ineq = rederive_bean_for_transposition(reverse_T)
        for a, b in eq + ineq:
            assert 0 <= a < CT_LEN, f"EQ/INEQ position {a} out of range"
            assert 0 <= b < CT_LEN, f"EQ/INEQ position {b} out of range"

    def test_eq_and_ineq_disjoint(self) -> None:
        """A pair cannot appear in both EQ and INEQ for the same T."""
        for T in [
            list(range(CT_LEN)),
            [CT_LEN - 1 - i for i in range(CT_LEN)],
        ]:
            eq, ineq = rederive_bean_for_transposition(T)
            assert not (set(eq) & set(ineq)), (
                f"EQ and INEQ overlap for T: "
                f"{set(eq) & set(ineq)}"
            )

    def test_total_pairs_bounded_by_276(self) -> None:
        """C(24,2) = 276 is the hard upper bound on derivable pairs."""
        reverse_T = [CT_LEN - 1 - i for i in range(CT_LEN)]
        eq, ineq = rederive_bean_for_transposition(reverse_T)
        assert len(eq) + len(ineq) <= 276, (
            f"Total pairs {len(eq) + len(ineq)} exceeds C(24,2)=276"
        )


# ── Semantic correctness ───────────────────────────────────────────────

class TestBeanRederivationSemantics:
    """Tests that the derivation produces correct constraints under TABP semantics."""

    def test_identity_eq_is_27_65(self) -> None:
        """The single canonical equality is the (27, 65) pair — both PT=R, both CT=P."""
        identity = list(range(CT_LEN))
        eq, _ = rederive_bean_for_transposition(identity)
        assert (27, 65) in eq

    def test_rederivation_roundtrip_with_known_keystream(self) -> None:
        """Under identity T, a keystream satisfying the original BEAN constraints
        must also satisfy the re-derived constraints (they're the same set)."""
        # Construct a minimal keystream that satisfies direct-positional Bean:
        # use the Vigenère-derived keys at crib positions.
        from kryptos.kernel.constants import (
            VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
        )
        keystream = [0] * CT_LEN
        for i, v in enumerate(VIGENERE_KEY_ENE):
            keystream[21 + i] = v
        for i, v in enumerate(VIGENERE_KEY_BC):
            keystream[63 + i] = v

        # This keystream satisfies the canonical Bean constraints.
        assert verify_bean_simple(keystream), (
            "Canonical Vigenère keys fail verify_bean_simple — "
            "constants are broken"
        )

        # And the re-derived constraints under identity T must agree.
        eq, ineq = rederive_bean_for_transposition(list(range(CT_LEN)))
        for a, b in eq:
            assert keystream[a] == keystream[b], (
                f"Re-derived EQ ({a}, {b}) violated by canonical keystream"
            )
        for a, b in ineq:
            assert keystream[a] != keystream[b], (
                f"Re-derived INEQ ({a}, {b}) violated by canonical keystream"
            )

    def test_reverse_T_constraint_count_plausible(self) -> None:
        """Sanity: reverse T should produce O(100s) of constraints, not 0 or 10000.

        The exact count depends on the specific CT letter distribution at
        reversed positions. This is a sanity check, not a precise assertion.
        """
        reverse_T = [CT_LEN - 1 - i for i in range(CT_LEN)]
        eq, ineq = rederive_bean_for_transposition(reverse_T)
        total = len(eq) + len(ineq)
        # Lower bound: random pairings should produce ~80% variant-independent
        # pairs on average. C(24,2)=276, so expect >= 100 derivable pairs.
        assert total >= 100, (
            f"Reverse T produced only {total} constraints — "
            f"unusually low, possible edge case"
        )
        assert total <= 276

    def test_cyclic_shift_T_differs_from_identity(self) -> None:
        """Another independent T must also produce a different constraint set.

        Uses a cyclic shift by 1 to exercise a permutation distinct from both
        identity and reverse. If the derivation were accidentally invariant
        under some permutation class, this catches it.
        """
        cyclic_shift = [(i + 1) % CT_LEN for i in range(CT_LEN)]
        _eq_shift, ineq_shift = rederive_bean_for_transposition(cyclic_shift)
        assert set(ineq_shift) != set(BEAN_INEQ), (
            "Cyclic-shift T produced same inequalities as identity"
        )


# ── Consistency with C-BEAN-01 ─────────────────────────────────────────

class TestBeanRederivationAlphabetParameterization:
    """Tests for the alph_idx parameter added to support KA (KRYPTOS)
    alphabet work under TABP v2a.
    """

    def test_default_alph_idx_matches_explicit_az(self) -> None:
        """Passing ALPH_IDX explicitly must produce identical results to
        the default (no alph_idx argument)."""
        identity = list(range(CT_LEN))
        eq_default, ineq_default = rederive_bean_for_transposition(identity)
        eq_explicit, ineq_explicit = rederive_bean_for_transposition(
            identity, alph_idx=ALPH_IDX
        )
        assert set(eq_default) == set(eq_explicit)
        assert set(ineq_default) == set(ineq_explicit)

    def test_ka_alphabet_produces_different_identity_constraints(self) -> None:
        """Identity T with KA alphabet should produce a DIFFERENT constraint
        set than with AZ. Under KA, the arithmetic for each variant uses
        different indices, so the variant-independence predicate may hold
        for different pairs.

        If this test produces the SAME set as AZ, that would indicate the
        alph_idx parameter is not being used, or that KA happens to
        coincide with AZ on variant-independence (mathematically possible
        for structural reasons, but would warrant a manual check).
        """
        identity = list(range(CT_LEN))
        ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
        eq_az, ineq_az = rederive_bean_for_transposition(identity)
        eq_ka, ineq_ka = rederive_bean_for_transposition(identity, alph_idx=ka_idx)
        # At least one of the two sets must differ
        assert (set(eq_az) != set(eq_ka)) or (set(ineq_az) != set(ineq_ka)), (
            "KA alphabet produced identical constraints to AZ — "
            "alph_idx parameter not being used, or unexpected coincidence"
        )

    def test_ka_alphabet_identity_has_nontrivial_constraints(self) -> None:
        """Under KA, identity T should still produce a reasonable number
        of constraints (order of magnitude ~200-250, similar to AZ).
        Near-zero or near-276 would indicate a bug."""
        identity = list(range(CT_LEN))
        ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
        eq, ineq = rederive_bean_for_transposition(identity, alph_idx=ka_idx)
        total = len(eq) + len(ineq)
        assert 150 < total < 276, (
            f"KA identity produced {total} total constraints "
            f"(eq={len(eq)}, ineq={len(ineq)}) — unexpectedly skewed"
        )

    def test_ka_reverse_T_differs_from_ka_identity(self) -> None:
        """Sanity check: KA with reverse T should differ from KA with
        identity T, just as AZ does. Confirms T-sensitivity is preserved
        under the alphabet parameterization."""
        identity = list(range(CT_LEN))
        reverse_T = [CT_LEN - 1 - i for i in range(CT_LEN)]
        ka_idx = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
        _, ineq_id = rederive_bean_for_transposition(identity, alph_idx=ka_idx)
        _, ineq_rv = rederive_bean_for_transposition(reverse_T, alph_idx=ka_idx)
        assert set(ineq_id) != set(ineq_rv)


class TestBeanRederivationConsistencyWithCBean01:
    """Cross-check against the authoritative C-BEAN-01 elimination.

    C-BEAN-01 states that columnar widths {4, 6, 8, 9} × Vig/Beau/VarBeau
    are all rejected under direct-positional mapping. Our re-derivation at
    identity T must be consistent with this — the underlying math is the
    same, and we've already verified identity reproduces BEAN_EQ/BEAN_INEQ
    exactly. This test is a redundancy check that confirms we haven't
    accidentally changed the semantics of the (eq, ineq) sets.
    """

    def test_identity_rederivation_has_242_ineq(self) -> None:
        """C-BEAN-01's arithmetic relies on the 242-count being exactly right."""
        _eq, ineq = rederive_bean_for_transposition(list(range(CT_LEN)))
        assert len(ineq) == 242

    def test_identity_rederivation_eq_singleton(self) -> None:
        eq, _ineq = rederive_bean_for_transposition(list(range(CT_LEN)))
        assert len(eq) == 1
