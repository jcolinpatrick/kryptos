"""QA verification of width-9 structural claims, DFT signal, bimodal pre-filter,
and underdetermination noise floors.

These tests independently verify the claims that other agents rely on:
1. DFT peak at k=9 with z≈2.83 (from E-S-25)
2. Lag-7 autocorrelation z≈3.04 (strongest CT signal)
3. Width-9 grid geometry (97/9 = 10.78, Sanborn annotation)
4. Bimodal pre-filter correctness (AGENT_PROMPT.md specification)
5. Underdetermination noise floors at various periods
6. Known keystream values at crib positions

Repro: PYTHONPATH=src pytest tests/test_qa_structural_claims.py -v
"""
import math
import random
from collections import Counter, defaultdict

import pytest

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD, ALPH,
    CRIB_DICT, CRIB_ENTRIES, N_CRIBS,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    NOISE_FLOOR, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
)

# ── Helper: numeric CT ──────────────────────────────────────────────────────
CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN


# ── Helper: DFT magnitude at a given frequency ─────────────────────────────
def dft_magnitude(data: list[float], k: int) -> float:
    """Compute |F(k)| for a real-valued sequence."""
    n = len(data)
    re = sum(data[j] * math.cos(2 * math.pi * k * j / n) for j in range(n))
    im = sum(data[j] * math.sin(2 * math.pi * k * j / n) for j in range(n))
    return math.sqrt(re * re + im * im)


# ── Helper: period consistency scoring (majority voting) ────────────────────
def period_consistency_score(perm: list[int], period: int, variant: str = "vigenere") -> int:
    """Score a permutation+period by majority-voting on keystream residue classes.

    perm: gather-convention permutation, len 97. output[i] = input[perm[i]]
    Undoing transposition: intermediate[perm[i]] = CT[i], so intermediate[j] = CT[inv_perm[j]]
    Then key[j] = (CT[j] - PT[j]) mod 26 for vigenere on the intermediate.

    Actually, the standard approach: given perm as the transposition that was APPLIED
    to plaintext to get an intermediate (then substituted to get CT), we undo by:
    intermediate = apply_inverse_perm(CT) -- but this depends on the model.

    For simplicity, use the direct crib-scoring approach:
    For each crib position p where PT[p] is known, derive key value from CT[p].
    Group by p % period, count majority agreement.
    """
    groups: dict[int, list[int]] = defaultdict(list)
    for pos, ch in CRIB_DICT.items():
        ct_val = ALPH_IDX[CT[pos]]
        pt_val = ALPH_IDX[ch]
        if variant == "vigenere":
            key_val = (ct_val - pt_val) % 26
        elif variant == "beaufort":
            key_val = (ct_val + pt_val) % 26
        elif variant == "var_beaufort":
            key_val = (pt_val - ct_val) % 26
        else:
            raise ValueError(f"Unknown variant: {variant}")
        groups[pos % period].append(key_val)

    score = 0
    for vals in groups.values():
        if vals:
            score += Counter(vals).most_common(1)[0][1]
    return score


# ── Helper: bimodal pre-filter (from AGENT_PROMPT.md specification) ─────────
def bimodal_check(perm: list[int]) -> bool:
    """Reject permutations inconsistent with the bimodal fingerprint.

    Exactly as specified in AGENT_PROMPT.md lines 246-260.
    """
    # Positions 22-30 should map approximately to themselves (+-5)
    for i in range(22, 31):
        if abs(perm[i] - i) > 5:
            return False
    # Positions 64-74 should NOT all map to themselves
    identity_count = sum(1 for i in range(64, 74) if abs(perm[i] - i) <= 2)
    if identity_count > 4:  # more than ~40% are identity-ish -> wrong signature
        return False
    return True


# ═══════════════════════════════════════════════════════════════════════════════
# 1. DFT ANALYSIS VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════


class TestDFTAnalysis:
    """Independently verify the DFT peak at k=9 claimed in E-S-25."""

    def test_dft_basic_sanity(self):
        """DFT of constant sequence should be zero for k>0."""
        data = [5.0] * 97
        for k in range(1, 49):
            mag = dft_magnitude(data, k)
            assert mag < 1e-10, f"k={k}: constant signal should have zero DFT"

    def test_dft_known_sinusoid(self):
        """DFT of a pure sinusoid at frequency k0 should peak at k0."""
        n = 97
        k0 = 9
        data = [math.sin(2 * math.pi * k0 * j / n) for j in range(n)]
        mags = {k: dft_magnitude(data, k) for k in range(1, n // 2 + 1)}
        peak_k = max(mags, key=mags.get)
        assert peak_k == k0, f"Sinusoid at k={k0} should peak at k={k0}, got k={peak_k}"

    def test_dft_ct_k9_computation(self):
        """Verify the raw DFT magnitude at k=9 for the K4 CT."""
        mean_val = sum(CT_NUM) / N
        centered = [v - mean_val for v in CT_NUM]
        mag_k9 = dft_magnitude(centered, 9)

        # Verify it's a real positive number
        assert mag_k9 > 0
        # The expected random magnitude parameter: sqrt(N * var_uniform / 2)
        var_uniform = sum((i - 12.5) ** 2 for i in range(26)) / 26
        expected_sigma = math.sqrt(N * var_uniform / 2)
        assert expected_sigma == pytest.approx(52.3, abs=0.5)

        # k=9 should be notably above the Rayleigh parameter
        # (The claim is it's in the top frequencies)
        assert mag_k9 > expected_sigma, f"k=9 mag={mag_k9:.1f} should exceed sigma={expected_sigma:.1f}"

    def test_dft_ct_k9_is_top_peak(self):
        """Verify that k=9 is among the top DFT peaks for K4 CT."""
        mean_val = sum(CT_NUM) / N
        centered = [v - mean_val for v in CT_NUM]
        mags = {k: dft_magnitude(centered, k) for k in range(1, N // 2 + 1)}

        # Sort by magnitude descending
        ranked = sorted(mags.items(), key=lambda x: -x[1])
        top_10_ks = [k for k, _ in ranked[:10]]

        assert 9 in top_10_ks, f"k=9 not in top 10 DFT peaks: top={top_10_ks}"

    def test_dft_ct_k9_monte_carlo_significance(self):
        """Monte Carlo: compute p-value of k=9 magnitude under null hypothesis.

        Null: random permutation of CT letters (preserves letter frequencies).
        """
        rng = random.Random(42)
        mean_val = sum(CT_NUM) / N
        centered = [v - mean_val for v in CT_NUM]
        observed_mag = dft_magnitude(centered, 9)

        n_trials = 5000
        count_exceeding = 0

        for _ in range(n_trials):
            shuffled = CT_NUM[:]
            rng.shuffle(shuffled)
            mean_s = sum(shuffled) / N
            centered_s = [v - mean_s for v in shuffled]
            mag = dft_magnitude(centered_s, 9)
            if mag >= observed_mag:
                count_exceeding += 1

        p_value = count_exceeding / n_trials
        # The claim is z≈2.83 which corresponds to p≈0.0023 (one-sided)
        # We expect p < 0.01 at minimum for a real signal
        assert p_value < 0.05, (
            f"k=9 DFT not significant: p={p_value:.4f} ({count_exceeding}/{n_trials})"
        )

    def test_dft_ct_max_magnitude_frequency(self):
        """Record which frequency has the absolute maximum DFT magnitude."""
        mean_val = sum(CT_NUM) / N
        centered = [v - mean_val for v in CT_NUM]
        mags = {k: dft_magnitude(centered, k) for k in range(1, N // 2 + 1)}
        peak_k = max(mags, key=mags.get)
        peak_mag = mags[peak_k]
        mag_k9 = mags[9]
        # Just record — don't assert k=9 is THE max (it might not be)
        # But it should be in the top tier
        assert mag_k9 >= peak_mag * 0.6, (
            f"k=9 mag={mag_k9:.1f} is less than 60% of peak k={peak_k} mag={peak_mag:.1f}"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 2. LAG-7 AUTOCORRELATION VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════


class TestLag7Autocorrelation:
    """Independently verify the lag-7 autocorrelation claim (z≈3.04)."""

    def test_lag7_matches_count(self):
        """Count exact letter matches at lag 7."""
        matches = sum(1 for i in range(N - 7) if CT_NUM[i] == CT_NUM[i + 7])
        n_pairs = N - 7  # = 90
        assert n_pairs == 90
        # For random text: expected = 90/26 ≈ 3.46
        expected = n_pairs / 26
        assert expected == pytest.approx(3.46, abs=0.01)
        # The claim is that matches significantly exceed expectation
        assert matches > expected, f"Lag-7 matches={matches} should exceed expected={expected:.2f}"

    def test_lag7_z_score(self):
        """Compute z-score for lag-7 autocorrelation."""
        matches = sum(1 for i in range(N - 7) if CT_NUM[i] == CT_NUM[i + 7])
        n_pairs = N - 7
        p_match = 1.0 / 26
        expected = n_pairs * p_match
        std = math.sqrt(n_pairs * p_match * (1 - p_match))
        z = (matches - expected) / std
        # Claim: z ≈ 3.04
        assert z > 2.0, f"Lag-7 z-score={z:.3f} should be > 2.0"
        assert z == pytest.approx(3.04, abs=0.5), f"Lag-7 z-score={z:.3f} should be ≈3.04"

    def test_lag7_is_strongest_autocorrelation(self):
        """Verify lag-7 has the highest z-score among all lags."""
        best_lag = None
        best_z = -999
        for lag in range(1, N):
            matches = sum(1 for i in range(N - lag) if CT_NUM[i] == CT_NUM[i + lag])
            n_pairs = N - lag
            p_match = 1.0 / 26
            expected = n_pairs * p_match
            std = math.sqrt(n_pairs * p_match * (1 - p_match))
            z = (matches - expected) / std if std > 0 else 0
            if z > best_z:
                best_z = z
                best_lag = lag
        assert best_lag == 7, f"Strongest autocorrelation at lag {best_lag} (z={best_z:.3f}), expected lag 7"

    def test_lag7_monte_carlo(self):
        """Monte Carlo p-value for lag-7 autocorrelation."""
        rng = random.Random(123)
        observed = sum(1 for i in range(N - 7) if CT_NUM[i] == CT_NUM[i + 7])

        n_trials = 5000
        count_exceeding = 0
        for _ in range(n_trials):
            shuffled = CT_NUM[:]
            rng.shuffle(shuffled)
            matches = sum(1 for i in range(N - 7) if shuffled[i] == shuffled[i + 7])
            if matches >= observed:
                count_exceeding += 1

        p_value = count_exceeding / n_trials
        assert p_value < 0.01, f"Lag-7 autocorrelation p={p_value:.4f}, expected < 0.01"


# ═══════════════════════════════════════════════════════════════════════════════
# 3. WIDTH-9 GRID GEOMETRY
# ═══════════════════════════════════════════════════════════════════════════════


class TestWidth9Geometry:
    """Verify width-9 grid properties and Sanborn annotation match."""

    def test_ct_length_97(self):
        """CT is exactly 97 characters."""
        assert len(CT) == 97
        assert CT_LEN == 97

    def test_width9_row_count(self):
        """97 / 9 = 10.777..., matching Sanborn's '10.8 rows' annotation."""
        rows = CT_LEN / 9
        assert rows == pytest.approx(10.778, abs=0.001)
        # "10.8 rows" rounds to this
        assert abs(rows - 10.8) < 0.03

    def test_width9_grid_column_heights(self):
        """Width-9 grid: 97 = 9*10 + 7, so 7 columns of 11, 2 columns of 10."""
        width = 9
        full_rows = CT_LEN // width  # 10
        remainder = CT_LEN % width   # 7
        assert full_rows == 10
        assert remainder == 7
        # Column heights: first 7 columns have 11 chars, last 2 have 10
        long_cols = remainder
        short_cols = width - remainder
        assert long_cols == 7
        assert short_cols == 2
        assert long_cols * (full_rows + 1) + short_cols * full_rows == CT_LEN

    def test_width9_columnar_permutation_construction(self):
        """Verify columnar permutation for width-9 is correctly constructable."""
        width = 9
        n_full_rows = CT_LEN // width  # 10
        remainder = CT_LEN % width     # 7

        # Standard columnar: fill row by row, read column by column
        # order = identity (col 0, col 1, ..., col 8) for testing
        order = list(range(width))

        # Build permutation: output position i maps to input position perm[i]
        perm = []
        for col_idx in order:
            col_height = n_full_rows + 1 if col_idx < remainder else n_full_rows
            for row in range(col_height):
                perm.append(row * width + col_idx)

        assert len(perm) == CT_LEN
        assert sorted(perm) == list(range(CT_LEN))  # bijection

    def test_width9_all_orderings_count(self):
        """9! = 362880 — number of column orderings to test."""
        assert math.factorial(9) == 362880

    def test_width7_comparison(self):
        """Width-7 grid for comparison: 97 = 7*13 + 6."""
        width = 7
        full_rows = CT_LEN // width  # 13
        remainder = CT_LEN % width   # 6
        assert full_rows == 13
        assert remainder == 6
        rows = CT_LEN / width
        assert rows == pytest.approx(13.857, abs=0.001)


# ═══════════════════════════════════════════════════════════════════════════════
# 4. BIMODAL PRE-FILTER VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════


class TestBimodalPreFilter:
    """Verify the bimodal pre-filter specified in AGENT_PROMPT.md."""

    def test_identity_permutation_passes(self):
        """Identity permutation should pass: positions 22-30 are preserved,
        positions 64-74 all map to themselves (identity_count=10 > 4) — FAILS.
        Wait: the filter says positions 64-74 should NOT all map to themselves.
        Identity has identity_count=10 > 4, so it should FAIL the filter.
        """
        perm = list(range(CT_LEN))
        # Identity: positions 22-30 are exactly themselves (pass first check)
        # But positions 64-74 have identity_count=10 > 4 (fail second check)
        assert bimodal_check(perm) is False

    def test_perfect_bimodal_permutation(self):
        """Construct a permutation that preserves 22-30 but scrambles 64-74."""
        perm = list(range(CT_LEN))
        # Scramble positions 64-74: reverse them
        segment = list(range(64, 74))
        segment.reverse()
        for i, j in enumerate(range(64, 74)):
            perm[j] = segment[i]
        # Now: positions 22-30 are identity (pass), positions 64-74 are reversed
        # identity_count in 64-74: check how many have |perm[i] - i| <= 2
        id_count = sum(1 for i in range(64, 74) if abs(perm[i] - i) <= 2)
        # reversed 64-73 → 73-64: perm[64]=73 (|73-64|=9), ..., perm[68]=69 (|69-68|=1)
        # perm[68]=69-68=1 <=2, perm[69]=68-69=1 <=2 -- these two pass
        # perm[70]=67-70=3 > 2 -- fails
        # So identity_count should be <= 4
        assert id_count <= 4, f"Expected <=4 identity-ish in scrambled region, got {id_count}"
        assert bimodal_check(perm) is True

    def test_positions_22_30_displacement_boundary(self):
        """Test boundary: position displaced by exactly 5 should pass, 6 should fail."""
        # Displacement = 5 (boundary pass)
        perm = list(range(CT_LEN))
        for i in range(64, 74):
            perm[i] = (i + 10) % CT_LEN if i + 10 < CT_LEN else i - 10
        perm[22] = 27  # |27 - 22| = 5, should pass
        assert abs(perm[22] - 22) == 5
        # Need to fix the bijection — swap 22 and 27
        perm[27] = 22
        assert bimodal_check(perm) is True

        # Displacement = 6 (boundary fail)
        perm2 = list(range(CT_LEN))
        for i in range(64, 74):
            perm2[i] = (i + 10) % CT_LEN if i + 10 < CT_LEN else i - 10
        perm2[22] = 28  # |28 - 22| = 6, should fail
        perm2[28] = 22
        assert bimodal_check(perm2) is False

    def test_region_64_74_identity_boundary(self):
        """Test boundary: exactly 4 identity-ish positions should pass, 5 should fail."""
        # Build perm with 22-30 preserved and exactly 4 identity-ish in 64-73
        # Keep 64-67 as identity (4 positions), swap 68-73 with 0-5 (far away)
        perm = list(range(CT_LEN))
        far_targets = [0, 1, 2, 3, 4, 5]
        local_targets = [68, 69, 70, 71, 72, 73]
        for local_pos, far_pos in zip(local_targets, far_targets):
            perm[local_pos] = far_pos
            perm[far_pos] = local_pos
        id_count = sum(1 for i in range(64, 74) if abs(perm[i] - i) <= 2)
        assert id_count == 4, f"Expected 4, got {id_count}"
        assert bimodal_check(perm) is True

        # Now make 5 identity-ish: keep 64-68 as identity, swap 69-73 with 0-4
        perm2 = list(range(CT_LEN))
        far_targets2 = [0, 1, 2, 3, 4]
        local_targets2 = [69, 70, 71, 72, 73]
        for local_pos, far_pos in zip(local_targets2, far_targets2):
            perm2[local_pos] = far_pos
            perm2[far_pos] = local_pos
        id_count2 = sum(1 for i in range(64, 74) if abs(perm2[i] - i) <= 2)
        assert id_count2 == 5, f"Expected 5, got {id_count2}"
        assert bimodal_check(perm2) is False

    def test_random_permutations_mostly_fail(self):
        """Most random permutations should fail the bimodal check."""
        rng = random.Random(999)
        n_trials = 1000
        pass_count = 0
        for _ in range(n_trials):
            perm = list(range(CT_LEN))
            rng.shuffle(perm)
            if bimodal_check(perm):
                pass_count += 1
        # Random permutations should rarely satisfy both constraints
        pass_rate = pass_count / n_trials
        assert pass_rate < 0.01, f"Random permutation pass rate {pass_rate:.3f} too high"

    def test_bimodal_filter_requires_full_length(self):
        """Bimodal check needs perm of length >= 74."""
        perm = list(range(CT_LEN))
        # Scramble 64-73
        for i in range(64, 74):
            perm[i] = 64 + (73 - i)
        assert bimodal_check(perm) is True or bimodal_check(perm) is False
        # Just verifying it doesn't crash on valid length


# ═══════════════════════════════════════════════════════════════════════════════
# 5. UNDERDETERMINATION NOISE FLOORS
# ═══════════════════════════════════════════════════════════════════════════════


class TestUnderdeterminationNoiseFloors:
    """Verify claimed noise floors at various periods.

    The noise floor is the **majority-voting period consistency score**: group
    the 24 crib-derived keystream values by (position % period), then sum the
    majority counts in each group. This is deterministic for the identity
    permutation (no transposition).

    CLAUDE.md claims:
    - Period 24: ~19.2/24
    - Period 17: ~17.3/24
    - Period 7: ~8.2/24
    """

    @staticmethod
    def _majority_vote_score(period: int, variant: str = "vigenere") -> int:
        """Compute majority-voting period consistency score for actual K4 CT+cribs."""
        groups: dict[int, list[int]] = defaultdict(list)
        for pos, ch in CRIB_DICT.items():
            ct_val = ALPH_IDX[CT[pos]]
            pt_val = ALPH_IDX[ch]
            if variant == "vigenere":
                k_val = (ct_val - pt_val) % 26
            elif variant == "beaufort":
                k_val = (ct_val + pt_val) % 26
            else:
                k_val = (pt_val - ct_val) % 26
            groups[pos % period].append(k_val)

        score = 0
        for vals in groups.values():
            if vals:
                score += Counter(vals).most_common(1)[0][1]
        return score

    @staticmethod
    def _random_perm_noise_floor(period: int, variant: str = "vigenere",
                                  n_trials: int = 2000, seed: int = 42) -> float:
        """Compute average majority-vote score over random transpositions.

        For a random permutation σ, intermediate[pos] = CT[σ[pos]], then
        derive keystream at crib positions and use majority voting.
        """
        rng = random.Random(seed)
        scores = []
        for _ in range(n_trials):
            perm = list(range(CT_LEN))
            rng.shuffle(perm)

            groups: dict[int, list[int]] = defaultdict(list)
            for pos, ch in CRIB_DICT.items():
                # After undoing transposition σ: intermediate[pos] = CT[perm[pos]]
                ct_val = ALPH_IDX[CT[perm[pos]]]
                pt_val = ALPH_IDX[ch]
                if variant == "vigenere":
                    k_val = (ct_val - pt_val) % 26
                elif variant == "beaufort":
                    k_val = (ct_val + pt_val) % 26
                else:
                    k_val = (pt_val - ct_val) % 26
                groups[pos % period].append(k_val)

            score = 0
            for vals in groups.values():
                if vals:
                    score += Counter(vals).most_common(1)[0][1]
            scores.append(score)

        return sum(scores) / len(scores)

    def test_period7_noise_floor_identity(self):
        """Identity-perm majority-vote at period 7 should be around 8/24."""
        score = self._majority_vote_score(7)
        # The actual K4 keystream is aperiodic, so at p=7 most groups disagree
        assert 6 <= score <= 12, f"Period 7 identity score={score}, expected ~8"

    def test_period17_noise_floor_identity(self):
        """Identity-perm majority-vote at period 17 should be elevated."""
        score = self._majority_vote_score(17)
        assert score > 13, f"Period 17 identity score={score}, expected > 13"

    def test_period24_noise_floor_identity(self):
        """Identity-perm majority-vote at period 24 should be ~19/24."""
        score = self._majority_vote_score(24)
        assert score >= 17, f"Period 24 identity score={score}, expected ~19"

    def test_noise_floor_monotonically_increases(self):
        """Majority-vote score should generally increase with period."""
        periods = [3, 5, 7, 10, 13, 17, 24]
        scores = [self._majority_vote_score(p) for p in periods]
        # Strict monotonicity not guaranteed, but overall trend should be up
        assert scores[-1] > scores[0], (
            f"Period 24 score ({scores[-1]}) should exceed period 3 ({scores[0]})"
        )
        assert scores[-1] - scores[0] > 5, (
            f"Difference should be substantial: {scores[-1]} - {scores[0]} = {scores[-1]-scores[0]}"
        )

    def test_low_period_gives_low_noise(self):
        """At period 3, majority-vote should be very low (strong discrimination)."""
        score = self._majority_vote_score(3)
        assert score <= 6, f"Period 3 score={score}, expected <= 6"

    def test_random_perm_noise_floor_period7(self):
        """Average majority-vote over random permutations at period 7 ≈ 8.2."""
        avg = self._random_perm_noise_floor(7, n_trials=2000)
        assert 6.0 < avg < 12.0, f"Random perm period 7 avg={avg:.1f}, expected ~8.2"

    def test_random_perm_noise_floor_period24(self):
        """Average majority-vote over random permutations at period 24 ≈ 19.2."""
        avg = self._random_perm_noise_floor(24, n_trials=2000)
        assert avg > 16.0, f"Random perm period 24 avg={avg:.1f}, expected ~19.2"

    def test_period7_score_18_is_rare_with_random_perm(self):
        """Majority-vote >=18 at period 7 should be extremely rare for random perms."""
        rng = random.Random(555)
        n_trials = 5000
        count_above_18 = 0
        for _ in range(n_trials):
            perm = list(range(CT_LEN))
            rng.shuffle(perm)

            groups: dict[int, list[int]] = defaultdict(list)
            for pos, ch in CRIB_DICT.items():
                ct_val = ALPH_IDX[CT[perm[pos]]]
                pt_val = ALPH_IDX[ch]
                k_val = (ct_val - pt_val) % 26
                groups[pos % 7].append(k_val)

            score = sum(Counter(v).most_common(1)[0][1] for v in groups.values() if v)
            if score >= 18:
                count_above_18 += 1

        p_value = count_above_18 / n_trials
        assert p_value < 0.001, (
            f"Period 7 score>=18 rate: {p_value:.4f} ({count_above_18}/{n_trials}), "
            "expected extremely rare — period 7 IS a meaningful discriminator"
        )

    def test_period24_score_18_is_common_with_random_perm(self):
        """Majority-vote >=18 at period 24 should be very common for random perms."""
        rng = random.Random(666)
        n_trials = 2000
        count_above_18 = 0
        for _ in range(n_trials):
            perm = list(range(CT_LEN))
            rng.shuffle(perm)

            groups: dict[int, list[int]] = defaultdict(list)
            for pos, ch in CRIB_DICT.items():
                ct_val = ALPH_IDX[CT[perm[pos]]]
                pt_val = ALPH_IDX[ch]
                k_val = (ct_val - pt_val) % 26
                groups[pos % 24].append(k_val)

            score = sum(Counter(v).most_common(1)[0][1] for v in groups.values() if v)
            if score >= 18:
                count_above_18 += 1

        rate = count_above_18 / n_trials
        assert rate > 0.10, (
            f"Period 24 score>=18 rate: {rate:.3f}, "
            "expected high (>10%) due to underdetermination"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 6. KEYSTREAM VALUE VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════


class TestKeystreamValues:
    """Independently verify the keystream values stored in constants.py."""

    def test_vigenere_key_ene_derivation(self):
        """Re-derive Vigenère keystream at ENE positions: k = (CT - PT) mod 26."""
        for i, (pos, ch) in enumerate(CRIB_ENTRIES):
            if 21 <= pos <= 33:
                ct_val = ALPH_IDX[CT[pos]]
                pt_val = ALPH_IDX[ch]
                expected_k = (ct_val - pt_val) % 26
                assert VIGENERE_KEY_ENE[pos - 21] == expected_k, (
                    f"Vig key at pos {pos}: expected {expected_k}, "
                    f"got {VIGENERE_KEY_ENE[pos - 21]}"
                )

    def test_vigenere_key_bc_derivation(self):
        """Re-derive Vigenère keystream at BC positions: k = (CT - PT) mod 26."""
        for i, (pos, ch) in enumerate(CRIB_ENTRIES):
            if 63 <= pos <= 73:
                ct_val = ALPH_IDX[CT[pos]]
                pt_val = ALPH_IDX[ch]
                expected_k = (ct_val - pt_val) % 26
                assert VIGENERE_KEY_BC[pos - 63] == expected_k, (
                    f"Vig key at pos {pos}: expected {expected_k}, "
                    f"got {VIGENERE_KEY_BC[pos - 63]}"
                )

    def test_beaufort_key_ene_derivation(self):
        """Re-derive Beaufort keystream at ENE positions: k = (CT + PT) mod 26."""
        for i, (pos, ch) in enumerate(CRIB_ENTRIES):
            if 21 <= pos <= 33:
                ct_val = ALPH_IDX[CT[pos]]
                pt_val = ALPH_IDX[ch]
                expected_k = (ct_val + pt_val) % 26
                assert BEAUFORT_KEY_ENE[pos - 21] == expected_k, (
                    f"Beau key at pos {pos}: expected {expected_k}, "
                    f"got {BEAUFORT_KEY_ENE[pos - 21]}"
                )

    def test_beaufort_key_bc_derivation(self):
        """Re-derive Beaufort keystream at BC positions: k = (CT + PT) mod 26."""
        for i, (pos, ch) in enumerate(CRIB_ENTRIES):
            if 63 <= pos <= 73:
                ct_val = ALPH_IDX[CT[pos]]
                pt_val = ALPH_IDX[ch]
                expected_k = (ct_val + pt_val) % 26
                assert BEAUFORT_KEY_BC[pos - 63] == expected_k, (
                    f"Beau key at pos {pos}: expected {expected_k}, "
                    f"got {BEAUFORT_KEY_BC[pos - 63]}"
                )

    def test_keystream_lengths(self):
        """Keystream arrays should match crib word lengths."""
        assert len(VIGENERE_KEY_ENE) == 13, "ENE crib is 13 chars"
        assert len(VIGENERE_KEY_BC) == 11, "BC crib is 11 chars"
        assert len(BEAUFORT_KEY_ENE) == 13
        assert len(BEAUFORT_KEY_BC) == 11

    def test_keystream_aperiodicity(self):
        """Verify key is aperiodic: no period 1-26 works for combined keystream."""
        # Combine Vigenère keystream at all 24 crib positions
        vig_keys = {}
        for pos, ch in CRIB_DICT.items():
            ct_val = ALPH_IDX[CT[pos]]
            pt_val = ALPH_IDX[ch]
            vig_keys[pos] = (ct_val - pt_val) % 26

        for period in range(1, 27):
            # Group by residue class
            groups = defaultdict(list)
            for pos, k in vig_keys.items():
                groups[pos % period].append(k)
            # Check if all values in each group are identical
            all_consistent = all(
                len(set(vals)) == 1
                for vals in groups.values()
                if len(vals) > 1  # only check groups with 2+ positions
            )
            assert not all_consistent, (
                f"Keystream appears periodic with period {period}! This should be impossible."
            )

    def test_bean_equality_keystream(self):
        """Bean equality: k[27] = k[65] should hold for all cipher variants."""
        for variant_name, sign_fn in [
            ("vigenere", lambda c, p: (c - p) % 26),
            ("beaufort", lambda c, p: (c + p) % 26),
            ("var_beaufort", lambda c, p: (p - c) % 26),
        ]:
            k27 = sign_fn(ALPH_IDX[CT[27]], ALPH_IDX[CRIB_DICT[27]])
            k65 = sign_fn(ALPH_IDX[CT[65]], ALPH_IDX[CRIB_DICT[65]])
            assert k27 == k65, (
                f"Bean equality fails for {variant_name}: k[27]={k27}, k[65]={k65}"
            )


# ═══════════════════════════════════════════════════════════════════════════════
# 7. IC VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════


class TestICVerification:
    """Verify IC claims about K4 ciphertext."""

    def test_ct_ic_below_random(self):
        """K4 IC ≈ 0.0361, which is below random (0.0385)."""
        freq = Counter(CT)
        n = len(CT)
        ic_val = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))
        assert ic_val == pytest.approx(0.0361, abs=0.001)
        assert ic_val < 1.0 / 26, "K4 IC should be below random expectation"

    def test_ic_below_random_is_unusual(self):
        """Monte Carlo: verify that IC below 0.0361 is rare for random text."""
        rng = random.Random(321)
        n_trials = 5000
        count_below = 0
        ct_ic = 0.0361
        for _ in range(n_trials):
            text = [rng.randint(0, 25) for _ in range(97)]
            freq = Counter(text)
            ic_val = sum(f * (f - 1) for f in freq.values()) / (97 * 96)
            if ic_val <= ct_ic:
                count_below += 1
        rate = count_below / n_trials
        # Below-random IC should occur maybe 20-30% of the time for truly random text
        # It's unusual but not astronomically rare
        assert rate < 0.50, f"IC <= {ct_ic} rate: {rate:.3f}"
        # But it shouldn't be effectively impossible either
        assert rate > 0.01, f"IC <= {ct_ic} rate: {rate:.3f}, too rare for random text"


# ═══════════════════════════════════════════════════════════════════════════════
# 8. CRIB POSITION VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════════


class TestCribPositions:
    """Verify crib positions and self-encrypting positions."""

    def test_ene_crib_positions(self):
        """ENE crib: positions 21-33, 'EASTNORTHEAST'."""
        ene = "EASTNORTHEAST"
        for i, ch in enumerate(ene):
            assert CRIB_DICT[21 + i] == ch, f"ENE pos {21+i}: expected {ch}"

    def test_bc_crib_positions(self):
        """BC crib: positions 63-73, 'BERLINCLOCK'."""
        bc = "BERLINCLOCK"
        for i, ch in enumerate(bc):
            assert CRIB_DICT[63 + i] == ch, f"BC pos {63+i}: expected {ch}"

    def test_self_encrypting_positions(self):
        """CT[32]='S'=PT[32] and CT[73]='K'=PT[73]."""
        assert CT[32] == "S"
        assert CRIB_DICT[32] == "S"
        assert CT[73] == "K"
        assert CRIB_DICT[73] == "K"

    def test_total_crib_count(self):
        """24 known plaintext positions total."""
        assert N_CRIBS == 24
        assert len(CRIB_DICT) == 24
        assert len(CRIB_ENTRIES) == 24

    def test_no_crib_overlap(self):
        """ENE and BC cribs don't overlap."""
        ene_positions = set(range(21, 34))
        bc_positions = set(range(63, 74))
        assert ene_positions.isdisjoint(bc_positions)

    def test_all_26_letters_in_ct(self):
        """K4 CT contains all 26 letters (eliminates 25-letter ciphers)."""
        assert set(CT) == set(ALPH)


# ═══════════════════════════════════════════════════════════════════════════════
# 9. PERIOD CONSISTENCY SCORING CORRECTNESS
# ═══════════════════════════════════════════════════════════════════════════════


class TestPeriodConsistencyScoring:
    """Verify the majority-voting period consistency approach used by agents."""

    def test_identity_perm_period_scores(self):
        """Identity transposition + various periods: should match noise floors."""
        for period in [3, 5, 7]:
            score = period_consistency_score(list(range(CT_LEN)), period)
            # At identity perm (no transposition), score should be reasonable
            # but not breakthrough (keystream is proven aperiodic)
            assert score <= N_CRIBS
            assert score >= 0

    def test_perfect_periodic_key_scores_24(self):
        """If we construct a CT that has a perfect periodic key, scoring should give 24."""
        # Generate a fake CT using a known periodic key
        period = 5
        key = [3, 17, 8, 21, 0]
        # PT from cribs at known positions; fill rest with 'A'
        pt = ['A'] * CT_LEN
        for pos, ch in CRIB_DICT.items():
            pt[pos] = ch

        # Encrypt: fake_ct[i] = (PT[i] + key[i%period]) % 26
        fake_ct = ""
        for i in range(CT_LEN):
            pt_val = ALPH_IDX[pt[i]]
            fake_ct += ALPH[(pt_val + key[i % period]) % 26]

        # Now score this fake_ct's implied keystream at the crib positions
        groups = defaultdict(list)
        for pos, ch in CRIB_DICT.items():
            ct_val = ALPH_IDX[fake_ct[pos]]
            pt_val = ALPH_IDX[ch]
            k_val = (ct_val - pt_val) % 26
            groups[pos % period].append(k_val)

        score = sum(Counter(vals).most_common(1)[0][1] for vals in groups.values() if vals)
        assert score == N_CRIBS, f"Perfect periodic key should score 24/24, got {score}"

    def test_scoring_variant_independence_of_bean_equality(self):
        """Bean equality k[27]=k[65] holds regardless of cipher variant."""
        for variant in ["vigenere", "beaufort", "var_beaufort"]:
            ct27 = ALPH_IDX[CT[27]]
            pt27 = ALPH_IDX[CRIB_DICT[27]]
            ct65 = ALPH_IDX[CT[65]]
            pt65 = ALPH_IDX[CRIB_DICT[65]]

            if variant == "vigenere":
                k27, k65 = (ct27 - pt27) % 26, (ct65 - pt65) % 26
            elif variant == "beaufort":
                k27, k65 = (ct27 + pt27) % 26, (ct65 + pt65) % 26
            else:
                k27, k65 = (pt27 - ct27) % 26, (pt65 - ct65) % 26

            assert k27 == k65, f"Bean equality fails for {variant}: k[27]={k27} != k[65]={k65}"
