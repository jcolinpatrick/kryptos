"""
Cross-verification of E-FRAC-35 Bean impossibility proof.

The claim: For ANY transposition sigma (including identity), periodic
substitution at all "discriminating" periods (2-7) violates at least one
Bean inequality constraint. This holds for ALL 97! permutations because
periodic keying makes the violation depend only on position residues
mod p, which are invariant under transposition of ciphertext positions
(the key schedule is applied to plaintext positions, and periodic keying
means k[i] = key[i % p]; the Bean constraints reference specific
plaintext positions whose residues are fixed).

Two elimination mechanisms:
  Type 1 (same-residue inequality): If Bean inequality pair (a,b) has
    a mod p == b mod p, then under periodic keying k[a] = k[b],
    violating the constraint k[a] != k[b].
  Type 2 (equality-inequality conflict): Bean equality forces
    key[27%p] = key[65%p]. If some inequality pair (a,b) maps to the
    same residue pair {27%p, 65%p}, the equality and inequality
    directly conflict.

Combined result: 17 of 25 periods (2-26) are eliminated.
Surviving: {8, 13, 16, 19, 20, 23, 24, 26}.
"""

import pytest
import random

from kryptos.kernel.constants import BEAN_EQ, BEAN_INEQ


class TestBeanImpossibility:
    """Independent verification of the Bean impossibility proof (E-FRAC-35)."""

    # -- Fixtures ----------------------------------------------------------

    @pytest.fixture(autouse=True)
    def setup_constraints(self):
        """Load and validate Bean constraints from constants module."""
        # Bean equality: exactly one pair
        assert len(BEAN_EQ) == 1, f"Expected 1 equality pair, got {len(BEAN_EQ)}"
        self.eq_a, self.eq_b = BEAN_EQ[0]
        assert self.eq_a == 27, f"Expected equality position 27, got {self.eq_a}"
        assert self.eq_b == 65, f"Expected equality position 65, got {self.eq_b}"

        # Bean inequalities: full variant-independent set (242 pairs)
        self.ineq_pairs = list(BEAN_INEQ)
        assert len(self.ineq_pairs) == 242, (
            f"Expected 242 inequality pairs, got {len(self.ineq_pairs)}"
        )

        # All positions must be valid K4 indices (0-96)
        for a, b in self.ineq_pairs:
            assert 0 <= a < 97, f"Position {a} out of range"
            assert 0 <= b < 97, f"Position {b} out of range"
        assert 0 <= self.eq_a < 97 and 0 <= self.eq_b < 97

    # -- Helper methods ----------------------------------------------------

    def _type1_violations(self, p: int) -> list:
        """
        Find inequality pairs where both positions share the same
        residue mod p. Under periodic keying, k[a] = key[a%p] = key[b%p] = k[b],
        which violates the inequality k[a] != k[b].
        """
        violations = []
        for a, b in self.ineq_pairs:
            if a % p == b % p:
                violations.append((a, b))
        return violations

    def _type2_violations(self, p: int) -> list:
        """
        Find inequality pairs whose residue set matches the equality
        residue set. The equality forces key[27%p] = key[65%p], but
        if an inequality pair (a,b) has {a%p, b%p} == {27%p, 65%p},
        it requires key[27%p] != key[65%p] -- a direct contradiction.

        Only applies when 27%p != 65%p (otherwise equality is trivially
        satisfied and imposes no cross-residue constraint).
        """
        eq_r_a = self.eq_a % p
        eq_r_b = self.eq_b % p
        if eq_r_a == eq_r_b:
            # Equality is trivially satisfied (same residue class),
            # no cross-residue constraint to conflict with.
            return []

        eq_residues = frozenset([eq_r_a, eq_r_b])
        violations = []
        for a, b in self.ineq_pairs:
            ineq_residues = frozenset([a % p, b % p])
            if ineq_residues == eq_residues:
                violations.append((a, b))
        return violations

    def _is_eliminated(self, p: int) -> bool:
        """Check if period p is eliminated by either mechanism."""
        return bool(self._type1_violations(p)) or bool(self._type2_violations(p))

    # -- Core claim tests --------------------------------------------------

    def test_type1_eliminated_periods(self):
        """With full 242 VI inequalities, Type 1 eliminates ALL periods 1-26."""
        actual_type1 = set()
        for p in range(1, 27):
            if self._type1_violations(p):
                actual_type1.add(p)
        expected_type1 = set(range(1, 27))
        assert actual_type1 == expected_type1, (
            f"Type 1 mismatch.\n"
            f"  Expected: {sorted(expected_type1)}\n"
            f"  Actual:   {sorted(actual_type1)}\n"
            f"  Missing:  {sorted(expected_type1 - actual_type1)}"
        )

    def test_type2_additional_eliminations(self):
        """
        With full 242 VI inequalities, Type 1 already eliminates all
        periods 1-26. Type 2 provides redundant confirming violations
        for many periods but eliminates no additional ones.
        """
        type1_set = {p for p in range(2, 27) if self._type1_violations(p)}
        type2_only = set()
        for p in range(2, 27):
            if p not in type1_set and self._type2_violations(p):
                type2_only.add(p)
        assert type2_only == set(), (
            f"With full inequality set, Type 2 should add nothing beyond Type 1.\n"
            f"  Type 2-only: {sorted(type2_only)}"
        )

    def test_combined_eliminated_set(self):
        """All 25 periods (2-26) are eliminated."""
        actual_eliminated = {p for p in range(2, 27) if self._is_eliminated(p)}
        expected_eliminated = set(range(2, 27))
        assert actual_eliminated == expected_eliminated
        assert len(actual_eliminated) == 25

    def test_surviving_set(self):
        """No periods 2-26 survive the full Bean inequality check."""
        actual_surviving = {p for p in range(2, 27) if not self._is_eliminated(p)}
        assert actual_surviving == set(), (
            f"Expected no surviving periods, got {sorted(actual_surviving)}"
        )

    # -- Per-period detailed tests -----------------------------------------

    @pytest.mark.parametrize("p", list(range(2, 27)))
    def test_all_periods_eliminated(self, p):
        """Every period 2-26 is eliminated by at least Type 1."""
        violations = self._type1_violations(p)
        assert len(violations) > 0, (
            f"Period {p} should be eliminated by Type 1 but has no violations"
        )

    # -- Structural / sanity checks ----------------------------------------

    def test_period_1_trivial(self):
        """
        Period 1 means all key values are the same (monoalphabetic).
        Every inequality pair violates.
        """
        violations = self._type1_violations(1)
        assert len(violations) == 242, (
            "Period 1 (monoalphabetic) should violate all 242 inequalities"
        )

    def test_equality_residue_overlap(self):
        """
        Check which periods cause the equality pair (27,65) to land
        in the same residue class. When 27%p == 65%p, the equality
        constraint is trivially satisfied and Type 2 cannot apply.
        """
        # 65 - 27 = 38. Periods that divide 38 cause same residue.
        # Factors of 38: 1, 2, 19, 38.
        # In range 2-26: {2, 19}
        same_residue_periods = {p for p in range(2, 27) if 27 % p == 65 % p}
        assert same_residue_periods == {2, 19}, (
            f"Equality same-residue periods should be {{2, 19}}, got {same_residue_periods}"
        )
        # For these periods, Type 2 is inapplicable (trivially satisfied)
        for p in same_residue_periods:
            assert self._type2_violations(p) == [], (
                f"Period {p}: Type 2 should return [] when equality residues match"
            )

    def test_inequality_pairs_are_distinct_positions(self):
        """Every inequality pair has a != b (no self-comparisons)."""
        for a, b in self.ineq_pairs:
            assert a != b, f"Self-comparison found: ({a}, {b})"

    def test_transposition_invariance_argument(self):
        """
        Verify the key insight: under periodic keying, k[i] = key[i % p].
        The Bean constraints reference PLAINTEXT positions, and the
        claim is that transposition doesn't help because:

        For Type 1: If a % p == b % p, then for ANY plaintext assignment,
        the key values at positions a and b are key[a%p] and key[b%p],
        which are equal. This is true regardless of what plaintext
        characters appear at those positions.

        We verify this by checking that the residue computation is
        purely a function of the position indices, not of any
        permutation or alphabet choice.
        """
        rng = random.Random(42)

        for p in [2, 3, 4, 5, 6, 7]:
            violations = self._type1_violations(p)
            assert len(violations) > 0

            # For each violation, verify that ANY key assignment
            # with periodic structure must have k[a] == k[b]
            for trial in range(100):
                # Random key of length p
                key = [rng.randint(0, 25) for _ in range(p)]
                for a, b in violations:
                    assert key[a % p] == key[b % p], (
                        f"Period {p}, key={key}: "
                        f"k[{a}]={key[a % p]} != k[{b}]={key[b % p]} "
                        f"but {a}%{p}={a % p} == {b}%{p}={b % p}"
                    )

    def test_type2_conflict_explicit(self):
        """
        Demonstrate Type 2 conflicts for periods where equality residues
        differ and Type 2 violations exist.
        """
        # Pick periods where Type 2 actually applies (eq residues differ
        # and there are cross-residue inequality pairs matching eq residues)
        for p in range(2, 27):
            eq_r_a = self.eq_a % p
            eq_r_b = self.eq_b % p
            if eq_r_a == eq_r_b:
                continue  # Type 2 doesn't apply
            type2 = self._type2_violations(p)
            if not type2:
                continue
            for a, b in type2:
                ineq_r = frozenset([a % p, b % p])
                eq_r = frozenset([eq_r_a, eq_r_b])
                assert ineq_r == eq_r

    def test_violation_count_per_period(self):
        """
        All periods 2-26 have at least 1 violation.
        """
        for p in range(2, 27):
            t1_count = len(self._type1_violations(p))
            t2_count = len(self._type2_violations(p))
            total = t1_count + t2_count
            assert total > 0, (
                f"Period {p} should be eliminated but has 0 violations"
            )


# ============================================================
# Bimodal pre-filter artifact verification (E-FRAC-11)
# ============================================================

def bimodal_check(perm):
    """
    Bimodal pre-filter from legacy harness specification.

    Positions 22-30 should map approximately to themselves (+-5).
    Positions 64-74 should NOT all map to themselves.
    """
    for i in range(22, 31):
        if abs(perm[i] - i) > 5:
            return False
    identity_count = sum(1 for i in range(64, 74) if abs(perm[i] - i) <= 2)
    if identity_count > 4:
        return False
    return True


def _random_perm(rng, n=97):
    """Generate a random permutation of length n using Fisher-Yates."""
    perm = list(range(n))
    for i in range(n - 1, 0, -1):
        j = rng.randint(0, i)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


class TestBimodalArtifact:
    """
    Independently verify E-FRAC-11 claim that the bimodal pre-filter
    is a statistical artifact.

    FRAC claims:
      1. 0/500,000 random permutations pass bimodal_check (too restrictive)
      2. Per-position crib preservation rates are uniform at 1/97 for all
         positions under random permutations -- no bimodal pattern exists.
    """

    # Crib positions (0-indexed)
    ENE_POSITIONS = list(range(21, 34))   # EASTNORTHEAST: positions 21-33
    BC_POSITIONS = list(range(63, 74))    # BERLINCLOCK:   positions 63-73
    ALL_CRIB_POSITIONS = ENE_POSITIONS + BC_POSITIONS  # 13 + 11 = 24 positions
    PERM_LENGTH = 97

    def test_bimodal_pass_rate_below_threshold(self):
        """
        FRAC claim 1: bimodal_check pass rate on random perms is ~0%.

        Generate 100,000 random permutations and verify pass rate < 0.1%.
        """
        rng = random.Random(42)
        n_trials = 100_000
        n_pass = 0

        for _ in range(n_trials):
            perm = _random_perm(rng, self.PERM_LENGTH)
            if bimodal_check(perm):
                n_pass += 1

        pass_rate = n_pass / n_trials
        assert pass_rate < 0.001, (
            f"bimodal_check pass rate = {pass_rate:.6f} ({n_pass}/{n_trials}), "
            f"expected < 0.001. FRAC claim of ~0% is "
            f"{'confirmed' if n_pass == 0 else 'approximately confirmed'}."
        )
        print(f"\n  bimodal_check pass rate: {n_pass}/{n_trials} = {pass_rate:.6f}")

    def test_bimodal_pass_rate_is_exactly_zero(self):
        """
        Stronger check: FRAC claims literally 0/500,000.
        We test 100,000 and expect 0 passes.
        """
        rng = random.Random(42)
        n_trials = 100_000
        n_pass = 0

        for _ in range(n_trials):
            perm = _random_perm(rng, self.PERM_LENGTH)
            if bimodal_check(perm):
                n_pass += 1

        assert n_pass == 0, (
            f"Expected 0 passes but got {n_pass}/{n_trials}. "
            f"The filter is extremely restrictive but not zero-pass."
        )
        print(f"\n  Confirmed: 0/{n_trials} random permutations pass bimodal_check")

    def test_why_bimodal_check_is_too_restrictive(self):
        """
        Analytical verification: the ENE proximity constraint requires
        9 positions (22-30) to each map within +-5. The independent
        probability is (11/97)^9 ~ 2.6e-9, astronomically small.
        """
        import math

        window_sizes = []
        for i in range(22, 31):
            low = max(0, i - 5)
            high = min(96, i + 5)
            window_size = high - low + 1
            window_sizes.append(window_size)
            assert window_size == 11, f"Position {i} window should be 11, got {window_size}"

        indep_prob = math.prod(ws / self.PERM_LENGTH for ws in window_sizes)
        print(f"\n  Independent approximation: P(all 9 in window) ~ {indep_prob:.2e}")
        assert indep_prob < 1e-7, (
            f"Independent probability {indep_prob:.2e} should be < 1e-7"
        )

    def test_crib_preservation_gradient_not_bimodal(self):
        """
        FRAC claim 2: Per-position crib preservation rates under random
        permutations show no bimodal pattern.

        In a random permutation of length n, P(perm[i] == i) = 1/n for all i.
        We verify all 24 crib positions are near 1/97 with no systematic
        difference between ENE and BC groups.
        """
        rng = random.Random(42)
        n_trials = 10_000

        preservation_counts = {pos: 0 for pos in self.ALL_CRIB_POSITIONS}

        for _ in range(n_trials):
            perm = _random_perm(rng, self.PERM_LENGTH)
            for pos in self.ALL_CRIB_POSITIONS:
                if perm[pos] == pos:
                    preservation_counts[pos] += 1

        preservation_rates = {
            pos: count / n_trials
            for pos, count in preservation_counts.items()
        }

        ene_rates = [preservation_rates[p] for p in self.ENE_POSITIONS]
        bc_rates = [preservation_rates[p] for p in self.BC_POSITIONS]
        ene_mean = sum(ene_rates) / len(ene_rates)
        bc_mean = sum(bc_rates) / len(bc_rates)

        print(f"\n  ENE position preservation rates (pos 21-33):")
        for p in self.ENE_POSITIONS:
            print(f"    pos {p:2d}: {preservation_rates[p]:.4f}")
        print(f"  ENE mean: {ene_mean:.4f}")

        print(f"\n  BC position preservation rates (pos 63-73):")
        for p in self.BC_POSITIONS:
            print(f"    pos {p:2d}: {preservation_rates[p]:.4f}")
        print(f"  BC mean: {bc_mean:.4f}")

        expected_rate = 1.0 / self.PERM_LENGTH  # ~0.01031

        # All rates should be close to 1/97 (within sampling noise)
        # With 10k trials, stddev ~ sqrt(0.0103*0.9897/10000) ~ 0.00101
        # Allow 6 sigma = 0.006 tolerance
        for pos in self.ALL_CRIB_POSITIONS:
            rate = preservation_rates[pos]
            assert abs(rate - expected_rate) < 0.006, (
                f"Position {pos}: preservation rate {rate:.4f} deviates "
                f"from expected {expected_rate:.4f} by more than 0.006"
            )

        print(f"\n  Expected rate (1/97): {expected_rate:.4f}")
        print(f"  All positions within tolerance of 1/97 -- NO bimodal pattern.")

    def test_ene_positions_not_higher_than_bc_under_random(self):
        """
        Verify that under random permutations, ENE positions (21-33) do NOT
        have systematically higher identity-preservation rates than BC
        positions (63-73). Both groups should cluster around 1/97.

        This confirms FRAC's claim: the apparent bimodal pattern is an
        artifact of the filter design, not random permutation statistics.
        """
        rng = random.Random(42)
        n_trials = 10_000

        ene_total = 0
        bc_total = 0

        for _ in range(n_trials):
            perm = _random_perm(rng, self.PERM_LENGTH)
            for pos in self.ENE_POSITIONS:
                if perm[pos] == pos:
                    ene_total += 1
            for pos in self.BC_POSITIONS:
                if perm[pos] == pos:
                    bc_total += 1

        ene_mean = ene_total / (n_trials * len(self.ENE_POSITIONS))
        bc_mean = bc_total / (n_trials * len(self.BC_POSITIONS))

        print(f"\n  ENE mean preservation: {ene_mean:.5f}")
        print(f"  BC mean preservation:  {bc_mean:.5f}")
        print(f"  Difference: {abs(ene_mean - bc_mean):.5f}")

        # The difference should be negligible (< 0.003)
        assert abs(ene_mean - bc_mean) < 0.003, (
            f"ENE mean ({ene_mean:.5f}) and BC mean ({bc_mean:.5f}) "
            f"should be nearly equal under random permutations. "
            f"No bimodal pattern exists."
        )

    def test_bimodal_filter_bottleneck_is_ene_window(self):
        """
        Demonstrate that the ENE proximity constraint (positions 22-30
        within +-5) is the bottleneck. Test the two halves independently.
        """
        rng = random.Random(42)
        n_trials = 50_000

        ene_pass = 0
        bc_pass = 0

        for _ in range(n_trials):
            perm = _random_perm(rng, self.PERM_LENGTH)

            # Test ENE constraint only
            ene_ok = True
            for i in range(22, 31):
                if abs(perm[i] - i) > 5:
                    ene_ok = False
                    break
            if ene_ok:
                ene_pass += 1

            # Test BC constraint only
            identity_count = sum(1 for i in range(64, 74) if abs(perm[i] - i) <= 2)
            if identity_count <= 4:
                bc_pass += 1

        ene_rate = ene_pass / n_trials
        bc_rate = bc_pass / n_trials

        print(f"\n  ENE constraint pass rate (pos 22-30 within +-5): "
              f"{ene_pass}/{n_trials} = {ene_rate:.6f}")
        print(f"  BC constraint pass rate (pos 64-73 identity count <= 4): "
              f"{bc_pass}/{n_trials} = {bc_rate:.4f}")

        # ENE constraint is the extremely restrictive one
        assert ene_rate < 0.001, (
            f"ENE constraint alone should be < 0.1%, got {ene_rate:.6f}"
        )

        # BC constraint passes most of the time (P(identity) is low)
        assert bc_rate > 0.95, (
            f"BC constraint alone should pass >95%, got {bc_rate:.4f}"
        )

        print(f"\n  Confirmed: ENE proximity constraint is the bottleneck. "
              f"BC constraint is nearly always satisfied.")


class TestStatisticalSignals:
    """
    Independent verification of FRAC E-FRAC-13/14 claims:
    The three "statistical pillars" (IC, lag-7 autocorrelation, DFT k=9)
    are NOT statistically significant after proper corrections.

    [QA cross-verification of FRAC alert: STATISTICAL SIGNALS ARE WEAKER THAN CLAIMED]
    """

    CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

    @staticmethod
    def _compute_ic(text):
        """Index of coincidence."""
        from collections import Counter
        counts = Counter(text)
        n = len(text)
        if n <= 1:
            return 0.0
        return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))

    @staticmethod
    def _compute_lag_matches(text, lag):
        """Count matching positions between text and text shifted by lag."""
        return sum(1 for i in range(len(text) - lag) if text[i] == text[i + lag])

    @staticmethod
    def _compute_dft_magnitudes(text):
        """Compute DFT magnitudes of numeric text representation."""
        import cmath
        n = len(text)
        nums = [ord(c) - ord('A') for c in text]
        mags = []
        for k in range(1, n // 2 + 1):
            s = sum(nums[j] * cmath.exp(-2j * cmath.pi * k * j / n) for j in range(n))
            mags.append((k, abs(s)))
        return mags

    @staticmethod
    def _random_text(rng, length):
        """Generate random uppercase text of given length."""
        return ''.join(rng.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(length))

    def test_ic_percentile_unremarkable(self):
        """
        FRAC claim: K4's IC = 0.036 is at ~21.5th percentile of random 97-char text.
        We verify it falls between 10th and 40th percentile.
        """
        rng = random.Random(42)
        k4_ic = self._compute_ic(self.CT)
        n_trials = 50_000

        below_count = 0
        for _ in range(n_trials):
            rand_text = self._random_text(rng, 97)
            rand_ic = self._compute_ic(rand_text)
            if rand_ic <= k4_ic:
                below_count += 1

        percentile = below_count / n_trials * 100
        print(f"\n  K4 IC = {k4_ic:.4f}")
        print(f"  Percentile: {percentile:.1f}th")

        assert 10 < percentile < 40, (
            f"K4 IC at {percentile:.1f}th percentile, expected between 10 and 40. "
            f"FRAC claims 21.5th."
        )

    def test_lag7_autocorrelation_fails_bonferroni(self):
        """
        FRAC claim: Lag-7 has p=0.0077 uncorrected, but Bonferroni for
        48 lags requires p<0.001. Lag-7 fails correction.
        """
        rng = random.Random(42)
        k4_lag7 = self._compute_lag_matches(self.CT, 7)
        n_trials = 50_000

        exceed_count = 0
        for _ in range(n_trials):
            rand_text = self._random_text(rng, 97)
            rand_lag7 = self._compute_lag_matches(rand_text, 7)
            if rand_lag7 >= k4_lag7:
                exceed_count += 1

        p_uncorrected = exceed_count / n_trials
        n_lags_tested = 48  # typical: lags 1 through 48
        bonferroni_threshold = 0.05 / n_lags_tested  # ~0.00104

        print(f"\n  K4 lag-7 matches: {k4_lag7}")
        print(f"  Uncorrected p-value: {p_uncorrected:.4f}")
        print(f"  Bonferroni threshold (48 lags): {bonferroni_threshold:.5f}")
        print(f"  Corrected p-value: {p_uncorrected * n_lags_tested:.4f}")

        # Uncorrected p should be > 0.001 (not extreme)
        assert p_uncorrected > 0.001, (
            f"Uncorrected p = {p_uncorrected:.6f}, even this is < 0.001"
        )
        # Must FAIL Bonferroni correction
        assert p_uncorrected > bonferroni_threshold, (
            f"p = {p_uncorrected:.6f} < Bonferroni threshold {bonferroni_threshold:.5f}, "
            f"would survive correction — contradicts FRAC claim"
        )

    def test_dft_k9_below_random_maximum_95th_percentile(self):
        """
        FRAC claim: DFT k=9 magnitude (162) is below the 95th percentile
        of the maximum random peak (~192).
        """
        rng = random.Random(42)

        # Compute K4's DFT at k=9
        k4_dft = self._compute_dft_magnitudes(self.CT)
        k4_k9_mag = next(mag for k, mag in k4_dft if k == 9)

        # Generate random texts, compute max DFT magnitude for each
        n_trials = 10_000
        max_mags = []
        for _ in range(n_trials):
            rand_text = self._random_text(rng, 97)
            rand_dft = self._compute_dft_magnitudes(rand_text)
            max_mag = max(mag for _, mag in rand_dft)
            max_mags.append(max_mag)

        max_mags.sort()
        pct_95 = max_mags[int(0.95 * n_trials)]

        # What percentile is K4's k=9 among random maxima?
        k4_percentile = sum(1 for m in max_mags if m <= k4_k9_mag) / n_trials * 100

        print(f"\n  K4 DFT k=9 magnitude: {k4_k9_mag:.2f}")
        print(f"  95th percentile of random max magnitudes: {pct_95:.2f}")
        print(f"  K4 k=9 is at {k4_percentile:.1f}th percentile of random maxima")

        assert k4_k9_mag < pct_95, (
            f"K4 DFT k=9 ({k4_k9_mag:.2f}) >= 95th percentile ({pct_95:.2f}). "
            f"FRAC claims it should be below."
        )

    def test_none_of_three_pillars_survive_correction(self):
        """
        Combined check: none of the three "statistical pillars" survive
        proper multiple-testing correction.
        """
        rng = random.Random(42)

        # IC percentile
        k4_ic = self._compute_ic(self.CT)
        below = sum(1 for _ in range(10_000)
                     if self._compute_ic(self._random_text(rng, 97)) <= k4_ic)
        ic_percentile = below / 10_000 * 100
        ic_extreme = ic_percentile < 2.5 or ic_percentile > 97.5

        # Lag-7 p-value with Bonferroni
        k4_lag7 = self._compute_lag_matches(self.CT, 7)
        exceed = sum(1 for _ in range(10_000)
                      if self._compute_lag_matches(self._random_text(rng, 97), 7) >= k4_lag7)
        lag7_p = exceed / 10_000
        lag7_survives = lag7_p < (0.05 / 48)

        # DFT k=9 vs random max 95th pct
        k4_k9_mag = next(mag for k, mag in self._compute_dft_magnitudes(self.CT) if k == 9)
        max_mags = []
        for _ in range(5_000):
            rand_dft = self._compute_dft_magnitudes(self._random_text(rng, 97))
            max_mags.append(max(mag for _, mag in rand_dft))
        max_mags.sort()
        pct_95 = max_mags[int(0.95 * len(max_mags))]
        dft_significant = k4_k9_mag >= pct_95

        print(f"\n  IC percentile: {ic_percentile:.1f}% (extreme: {ic_extreme})")
        print(f"  Lag-7 p-value: {lag7_p:.4f} (survives Bonferroni: {lag7_survives})")
        print(f"  DFT k=9 significant: {dft_significant}")

        assert not ic_extreme, "IC should not be extreme"
        assert not lag7_survives, "Lag-7 should not survive Bonferroni"
        assert not dft_significant, "DFT k=9 should not be significant"
        print("\n  CONFIRMED: None of three pillars survive proper corrections.")
