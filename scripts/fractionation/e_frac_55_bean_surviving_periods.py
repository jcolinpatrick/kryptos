#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: fractionation
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-55: Columnar Transposition at Bean-Surviving Periods

GAP IDENTIFIED:
  Prior experiments (E-FRAC-12/29/30) tested columnar widths 5-15 at periods 2-7.
  E-FRAC-35 originally proved periods 2-7 are Bean-impossible. With the full
  242 variant-independent inequality set, ALL periods 1-26 are now eliminated.
  This script tests a subset (8, 13, 16) for historical completeness.

  However, structured columnar transpositions have NEVER been tested at these
  surviving periods. This experiment closes that gap.

METHOD:
  For each Bean-eq-passing columnar ordering at widths 6, 8, 9 (17,124 configs
  from prior experiments):
    1. Compute columnar transposition permutation
    2. Derive key values at 24 crib positions
    3. Check period-p consistency for p in {8, 13, 16}
    4. Check Bean inequality on the derived key values
    5. If consistent: score plaintext with quadgrams

  Additional tests:
    A. COUPLED-KEY MODEL (width 8, period 8):
       The same keyword determines BOTH the columnar order AND the Vigenère key.
       This means the derived key values (8 residue values) must be alphabetically
       ordered according to the column order. Tests the "one keyword for everything"
       hypothesis.

    B. RANDOM BASELINE:
       50K random permutations scored at periods 8, 13, 16 to establish noise floor.

EXPECTED:
  From E-FRAC-44 information theory: structured families have ~2^18 options.
  At period 8: P(consistent) ≈ (1/26)^16 ≈ 4×10^-23
  Expected FP = 2^18 × 4×10^-23 ≈ 10^-17 → ZERO false positives.
  Any match would be significant.
"""

import json
import os
import sys
import time
import random
from itertools import permutations
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, ALPH, MOD,
    CRIB_ENTRIES, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

# Crib data
CRIB_POS = [pos for pos, _ in CRIB_ENTRIES]
CRIB_PT = [ALPH_IDX[ch] for _, ch in CRIB_ENTRIES]
CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN  # 97

QUADGRAM_FILE = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')

# Originally "Bean-surviving" periods — now all periods are eliminated with
# the full 242 VI inequality set. Kept for historical completeness.
SURVIVING_PERIODS = [8, 13, 16]


class QuadgramScorer:
    def __init__(self, filepath):
        with open(filepath) as f:
            data = json.load(f)
        self.logp = data['logp'] if isinstance(data, dict) and 'logp' in data else data
        self.floor = min(self.logp.values()) - 1.0

    def score_per_char(self, text):
        text = text.upper()
        if len(text) < 4:
            return self.floor
        total = sum(self.logp.get(text[i:i+4], self.floor) for i in range(len(text) - 3))
        return total / len(text)


def generate_columnar_perm(width, col_order):
    """Generate the 97-char permutation for columnar transposition."""
    nrows = (N + width - 1) // width
    full_cols = N - (nrows - 1) * width
    perm = []
    for col in col_order:
        rows = nrows if col < full_cols else nrows - 1
        for row in range(rows):
            pos = row * width + col
            if pos < N:
                perm.append(pos)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def check_bean_eq(inv_perm):
    for eq_a, eq_b in BEAN_EQ:
        if CT[inv_perm[eq_a]] != CT[inv_perm[eq_b]]:
            return False
    return True


def check_period_consistency(key_vals, period):
    """Check if 24 derived key values are consistent with a periodic key.

    Returns (score, key_residues) where score = number of matching positions
    and key_residues = derived key value per residue (using majority vote).
    """
    # Group key values by residue class
    residue_groups = defaultdict(list)
    for i in range(N_CRIBS):
        r = CRIB_POS[i] % period
        residue_groups[r].append(key_vals[i])

    # For each residue: find the majority key value
    total_matches = 0
    key_residues = {}
    for r, vals in residue_groups.items():
        # Find most common value
        counts = defaultdict(int)
        for v in vals:
            counts[v] += 1
        best_val = max(counts, key=lambda v: counts[v])
        key_residues[r] = best_val
        total_matches += counts[best_val]

    return total_matches, key_residues


def check_period_exact(key_vals, period):
    """Check if ALL 24 derived key values are exactly consistent (24/24).

    Returns True only if all cribs at the same residue give the same key value.
    """
    residue_seen = {}
    for i in range(N_CRIBS):
        r = CRIB_POS[i] % period
        if r in residue_seen:
            if residue_seen[r] != key_vals[i]:
                return False
        else:
            residue_seen[r] = key_vals[i]
    return True


def check_bean_ineq_on_key(key_vals):
    """Check Bean inequalities on derived key values."""
    kv_dict = {CRIB_POS[i]: key_vals[i] for i in range(N_CRIBS)}
    for a, b in BEAN_INEQ:
        if a in kv_dict and b in kv_dict and kv_dict[a] == kv_dict[b]:
            return False
    return True


def derive_plaintext(inv_perm, key_residues, period, variant):
    """Derive 97-char plaintext from transposition + periodic key.

    variant: 'vig' (K = CT - PT), 'beau' (K = CT + PT), 'vb' (K = PT - CT)
    """
    pt = []
    for j in range(N):
        ct_pos = inv_perm[j]
        ct_val = CT_NUM[ct_pos]
        r = j % period
        k = key_residues.get(r, 0)
        if variant == 'vig':
            pt_val = (ct_val - k) % MOD
        elif variant == 'beau':
            pt_val = (k - ct_val) % MOD
        else:  # vb
            pt_val = (ct_val + k) % MOD  # K = PT - CT → PT = CT + K
        pt.append(ALPH[pt_val])
    return ''.join(pt)


def check_coupled_key(col_order, key_residues, width):
    """Check if key values are alphabetically ordered according to column order.

    For the coupled-key model: the keyword's alphabetical ranking produces
    the column order. So key_residues[col_order[0]] <= key_residues[col_order[1]]
    <= ... (with strict inequality for standard columnar, but repeated letters
    are possible in real keywords).

    Returns True if the key values respect the ordering (non-strict).
    """
    if len(key_residues) < width:
        return False  # not all residues populated

    ordered_keys = [key_residues[col_order[i]] for i in range(width)]
    # Standard alphabetical ranking: key values should be non-decreasing
    # when read in column order
    for i in range(width - 1):
        if ordered_keys[i] > ordered_keys[i + 1]:
            return False
    return True


def main():
    print("=" * 70)
    print("E-FRAC-55: Columnar Transposition at Bean-Surviving Periods")
    print("=" * 70)
    t0 = time.time()

    scorer = QuadgramScorer(QUADGRAM_FILE)
    print("Quadgram scorer loaded")

    # ── Phase 1: Generate Bean-eq-passing transpositions ──────────────
    print("\n--- Phase 1: Generate Bean-eq-passing columnar transpositions ---")
    configs = []  # (label, width, col_order_tuple, inv_perm)
    for width in [6, 8, 9]:
        count = 0
        bean_pass = 0
        for col_order in permutations(range(width)):
            count += 1
            perm = generate_columnar_perm(width, col_order)
            inv = invert_perm(perm)
            if check_bean_eq(inv):
                bean_pass += 1
                configs.append((f"col-{width}", width, col_order, inv))
        print(f"  Width {width}: {count} orderings, {bean_pass} Bean-eq passes")
    print(f"  Total Bean-eq configs: {len(configs)}")

    # ── Phase 2: Score at Bean-surviving periods ──────────────────────
    print(f"\n--- Phase 2: Score at Bean-surviving periods {SURVIVING_PERIODS} ---")

    variants = ['vig', 'beau', 'vb']
    results_by_period = {p: [] for p in SURVIVING_PERIODS}
    exact_matches = []  # 24/24 matches
    coupled_key_matches = []

    # Tracking
    total_checks = 0
    period_max_score = {p: 0 for p in SURVIVING_PERIODS}
    period_score_dist = {p: defaultdict(int) for p in SURVIVING_PERIODS}
    period_bean_pass_count = {p: 0 for p in SURVIVING_PERIODS}

    for config_idx, (label, width, col_order, inv_perm) in enumerate(configs):
        if config_idx % 3000 == 0:
            elapsed = time.time() - t0
            print(f"  ... {config_idx}/{len(configs)} configs ({elapsed:.1f}s)")

        for var in variants:
            # Derive key values at 24 crib positions
            key_vals = []
            for i in range(N_CRIBS):
                ct_pos = inv_perm[CRIB_POS[i]]
                ct_val = CT_NUM[ct_pos]
                pt_val = CRIB_PT[i]
                if var == 'vig':
                    k = (ct_val - pt_val) % MOD
                elif var == 'beau':
                    k = (ct_val + pt_val) % MOD
                else:  # vb
                    k = (pt_val - ct_val) % MOD
                key_vals.append(k)

            for period in SURVIVING_PERIODS:
                total_checks += 1
                score, key_residues = check_period_consistency(key_vals, period)
                period_score_dist[period][score] += 1

                if score > period_max_score[period]:
                    period_max_score[period] = score

                # Track Bean inequality pass on derived key
                bean_ineq_ok = False
                if score >= 20:  # Only check Bean-ineq for promising scores
                    bean_ineq_ok = check_bean_ineq_on_key(key_vals)
                    if bean_ineq_ok:
                        period_bean_pass_count[period] += 1

                if score == N_CRIBS:  # 24/24 exact match
                    bean_ineq_ok = check_bean_ineq_on_key(key_vals)
                    pt = derive_plaintext(inv_perm, key_residues, period, var)
                    qscore = scorer.score_per_char(pt)
                    entry = {
                        'label': label,
                        'width': width,
                        'col_order': list(col_order),
                        'variant': var,
                        'period': period,
                        'score': score,
                        'bean_ineq': bean_ineq_ok,
                        'quadgram': qscore,
                        'plaintext': pt,
                        'key_residues': {str(k): v for k, v in key_residues.items()},
                    }
                    exact_matches.append(entry)

                    # Check coupled-key constraint (only for width == period)
                    if width == period:
                        coupled = check_coupled_key(col_order, key_residues, width)
                        entry['coupled_key'] = coupled
                        if coupled:
                            coupled_key_matches.append(entry)

                # Track top results per period
                if score >= 18:
                    bean_ineq_ok = check_bean_ineq_on_key(key_vals) if not bean_ineq_ok else bean_ineq_ok
                    pt = derive_plaintext(inv_perm, key_residues, period, var)
                    qscore = scorer.score_per_char(pt)
                    results_by_period[period].append({
                        'label': label, 'width': width,
                        'col_order': list(col_order),
                        'variant': var, 'period': period,
                        'score': score, 'bean_ineq': bean_ineq_ok,
                        'quadgram': qscore, 'plaintext': pt[:40],
                    })

    elapsed = time.time() - t0
    print(f"\n  Total checks: {total_checks}")
    print(f"  Elapsed: {elapsed:.1f}s")

    # ── Phase 3: Random baseline ──────────────────────────────────────
    print("\n--- Phase 3: Random baseline (50K permutations) ---")
    N_RANDOM = 50000
    random.seed(42)
    random_max = {p: 0 for p in SURVIVING_PERIODS}
    random_scores = {p: [] for p in SURVIVING_PERIODS}

    for trial in range(N_RANDOM):
        perm = list(range(N))
        random.shuffle(perm)
        inv = invert_perm(perm)

        # Only test Vigenère (results are symmetric across variants for random)
        key_vals = []
        for i in range(N_CRIBS):
            ct_pos = inv[CRIB_POS[i]]
            ct_val = CT_NUM[ct_pos]
            pt_val = CRIB_PT[i]
            k = (ct_val - pt_val) % MOD
            key_vals.append(k)

        for period in SURVIVING_PERIODS:
            score, _ = check_period_consistency(key_vals, period)
            random_scores[period].append(score)
            if score > random_max[period]:
                random_max[period] = score

    for p in SURVIVING_PERIODS:
        scores = random_scores[p]
        mean = sum(scores) / len(scores)
        print(f"  Period {p}: mean={mean:.2f}, max={random_max[p]}/24")

    # ── Phase 4: Expected random scores at each period ────────────────
    print("\n--- Phase 4: Analytical expectations ---")
    for p in SURVIVING_PERIODS:
        # Number of crib positions per residue
        residue_counts = defaultdict(int)
        for pos, _ in CRIB_ENTRIES:
            residue_counts[pos % p] += 1
        occupied = len(residue_counts)
        # Expected score: sum of (1 + (n_r - 1)/26) for each occupied residue
        # + 0 for unoccupied
        expected = sum(1 + (n - 1) / MOD for n in residue_counts.values())
        # Constraints = sum of (n_r - 1) = 24 - occupied
        constraints = N_CRIBS - occupied
        print(f"  Period {p}: {occupied}/{p} residues occupied, "
              f"{constraints} constraints, expected score={expected:.2f}/24, "
              f"residue counts={dict(residue_counts)}")

    # ── Phase 5: Summary ──────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)

    print("\n  Per-period max scores (columnar):")
    for p in SURVIVING_PERIODS:
        print(f"    Period {p}: max={period_max_score[p]}/24 "
              f"(random max={random_max[p]}/24)")

    print("\n  Score distributions (columnar):")
    for p in SURVIVING_PERIODS:
        dist = period_score_dist[p]
        high_scores = {s: c for s, c in sorted(dist.items()) if s >= 14}
        print(f"    Period {p}: high scores (>=14): {high_scores}")

    print(f"\n  Exact 24/24 matches: {len(exact_matches)}")
    if exact_matches:
        for m in exact_matches[:10]:
            print(f"    {m['label']} order={m['col_order']} var={m['variant']} "
                  f"p={m['period']} Bean-ineq={m['bean_ineq']} "
                  f"Q={m['quadgram']:.3f} PT={m['plaintext'][:30]}...")

    print(f"\n  Coupled-key matches (width=period, alphabetical order): "
          f"{len(coupled_key_matches)}")
    if coupled_key_matches:
        for m in coupled_key_matches[:10]:
            print(f"    {m['label']} order={m['col_order']} var={m['variant']} "
                  f"Q={m['quadgram']:.3f} key={m['key_residues']} "
                  f"PT={m['plaintext'][:30]}...")

    print(f"\n  >=18/24 results per period:")
    for p in SURVIVING_PERIODS:
        results = results_by_period[p]
        print(f"    Period {p}: {len(results)} results >=18")
        bean_pass = sum(1 for r in results if r['bean_ineq'])
        if results:
            best_q = max(r['quadgram'] for r in results)
            print(f"      Bean-ineq pass: {bean_pass}, best quadgram: {best_q:.3f}/char")
            # Show top 3
            top = sorted(results, key=lambda r: -r['score'])[:3]
            for r in top:
                print(f"      score={r['score']} w={r['width']} order={r['col_order']} "
                      f"var={r['variant']} Bean={r['bean_ineq']} "
                      f"Q={r['quadgram']:.3f} PT={r['plaintext']}")

    # ── Phase 6: Statistical significance ─────────────────────────────
    print("\n--- Statistical significance ---")
    for p in SURVIVING_PERIODS:
        max_col = period_max_score[p]
        # How many random trials scored >= max_col?
        n_above = sum(1 for s in random_scores[p] if s >= max_col)
        p_val = n_above / N_RANDOM
        n_configs = len(configs) * 3  # × 3 variants
        corrected_p = 1 - (1 - p_val) ** n_configs if p_val > 0 else 0
        print(f"  Period {p}: max_col={max_col}, "
              f"P(random >= {max_col}) = {p_val:.6f}, "
              f"corrected p (N={n_configs}) = {corrected_p:.6f}")
        # Check underperformance
        n_random_above_col = sum(1 for s in random_scores[p] if s > max_col)
        pct_random_above = n_random_above_col / N_RANDOM * 100
        print(f"    Random > {max_col}: {pct_random_above:.1f}% → "
              f"{'UNDERPERFORMS random' if pct_random_above > 5 else 'at or above random'}")

    # ── Verdict ───────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    any_signal = False
    for p in SURVIVING_PERIODS:
        if period_max_score[p] > random_max[p]:
            any_signal = True
    if exact_matches:
        any_signal = True

    if any_signal:
        print("VERDICT: SIGNAL DETECTED — investigate further")
    else:
        print("VERDICT: NOISE — columnar transposition at Bean-surviving periods")
        print("  All structured columnar orderings produce noise-level scores at")
        print("  Bean-surviving periods {8, 13, 16}, consistent with E-FRAC-12/29/30")
        print("  results at periods 2-7. The Bean impossibility gap is now fully closed.")
    print("=" * 70)

    # ── Save results ──────────────────────────────────────────────────
    results_dir = os.path.join(os.path.dirname(__file__), '..', 'results', 'frac')
    os.makedirs(results_dir, exist_ok=True)
    results_file = os.path.join(results_dir, 'e_frac_55_bean_surviving_periods.json')

    output = {
        'experiment': 'E-FRAC-55',
        'description': 'Columnar transposition at Bean-surviving periods (8, 13, 16)',
        'n_configs': len(configs),
        'total_checks': total_checks,
        'surviving_periods': SURVIVING_PERIODS,
        'period_max_scores': period_max_score,
        'random_max_scores': random_max,
        'random_means': {p: sum(random_scores[p]) / len(random_scores[p])
                        for p in SURVIVING_PERIODS},
        'score_distributions': {str(p): {str(s): c for s, c in dist.items()}
                               for p, dist in period_score_dist.items()},
        'exact_24_matches': exact_matches,
        'coupled_key_matches': coupled_key_matches,
        'high_score_results': {str(p): [r for r in results_by_period[p]]
                              for p in SURVIVING_PERIODS},
        'runtime_seconds': time.time() - t0,
    }

    with open(results_file, 'w') as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {results_file}")


if __name__ == '__main__':
    main()
