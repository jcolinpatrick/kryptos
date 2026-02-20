#!/usr/bin/env python3
"""E-FRAC-36: Period-8 Hill-Climbing with Bean Constraint

E-FRAC-35 proved that ALL discriminating periods (2-7) are Bean-impossible for
transposition + periodic key. Period 8 is the FIRST surviving period (3 cribs/var).

This experiment tests whether hill-climbing at period 8 with Bean as a HARD
constraint can reach 24/24, and if so, characterizes the false positives:
- Can 24/24 + Bean PASS be achieved at period 8?
- What quadgram scores do these solutions produce?
- Does the E-FRAC-34 multi-objective oracle discriminate them?
- How does period 8 compare to the eliminated periods (5, 7)?

Also tests period 13 (next surviving period, 1.8 cribs/var) for comparison.
"""

import json
import os
import random
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import BEAN_EQ, BEAN_INEQ, CRIB_DICT, CT

START_TIME = time.time()

# Setup
CT_VALS = [ord(c) - ord('A') for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())
PT_VALS = {pos: ord(CRIB_DICT[pos]) - ord('A') for pos in CRIB_POS}
N = len(CT)  # 97

# Load quadgram data
QUADGRAM_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'english_quadgrams.json')
QUADGRAMS = {}
if os.path.exists(QUADGRAM_PATH):
    with open(QUADGRAM_PATH) as f:
        QUADGRAMS = json.load(f)
    QUAD_FLOOR = min(QUADGRAMS.values()) - 1.0
else:
    print("WARNING: quadgram file not found, using dummy scores")
    QUAD_FLOOR = -10.0


def quadgram_score(text):
    """Compute quadgram log-probability per character."""
    if not QUADGRAMS:
        return -6.0
    total = 0.0
    n = 0
    for i in range(len(text) - 3):
        q = text[i:i+4]
        total += QUADGRAMS.get(q, QUAD_FLOOR)
        n += 1
    return total / n if n > 0 else QUAD_FLOOR


def ic(text):
    """Index of coincidence."""
    freq = defaultdict(int)
    for c in text:
        freq[c] += 1
    n = len(text)
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1)) if n > 1 else 0


def derive_plaintext(perm, key_tuple, period, variant='vigenere'):
    """Given permutation and periodic key, derive full 97-char plaintext."""
    pt = []
    for i in range(N):
        ct_val = CT_VALS[perm[i]]
        k = key_tuple[i % period]
        if variant == 'vigenere':
            pt_val = (ct_val - k) % 26
        else:  # beaufort
            pt_val = (k - ct_val) % 26
        pt.append(chr(pt_val + ord('A')))
    return ''.join(pt)


def check_bean_key(key_tuple, period):
    """Check if a periodic key tuple satisfies Bean constraints."""
    # Equality
    for a, b in BEAN_EQ:
        if key_tuple[a % period] != key_tuple[b % period]:
            return False
    # Inequality
    for a, b in BEAN_INEQ:
        if key_tuple[a % period] == key_tuple[b % period]:
            return False
    return True


def crib_score_periodic(perm, period, variant='vigenere'):
    """Score a permutation at a specific period.
    Returns (score, key_tuple) where key_tuple is the majority-vote key.
    """
    # Group crib positions by residue
    residue_groups = defaultdict(list)
    for pos in CRIB_POS:
        residue_groups[pos % period].append(pos)

    # For each residue, find the key value that matches the most cribs
    key_tuple = [0] * period
    total_matches = 0

    for r in range(period):
        if r not in residue_groups:
            key_tuple[r] = 0
            continue

        best_k = 0
        best_count = 0
        for k in range(26):
            count = 0
            for pos in residue_groups[r]:
                ct_val = CT_VALS[perm[pos]]
                if variant == 'vigenere':
                    implied_pt = (ct_val - k) % 26
                else:
                    implied_pt = (k - ct_val) % 26
                if implied_pt == PT_VALS[pos]:
                    count += 1
            if count > best_count:
                best_count = count
                best_k = k
        key_tuple[r] = best_k
        total_matches += best_count

    return total_matches, tuple(key_tuple)


def crib_score_with_bean(perm, period, variant='vigenere'):
    """Score a permutation, but return 0 if Bean fails."""
    score, key_tuple = crib_score_periodic(perm, period, variant)
    if not check_bean_key(key_tuple, period):
        return 0, key_tuple
    return score, key_tuple


def hill_climb(period, max_steps=10000, bean_hard=True, variant='vigenere'):
    """Hill-climb over permutation space at a fixed period.
    If bean_hard=True, only accept moves that satisfy Bean.
    """
    perm = list(range(N))
    random.shuffle(perm)

    if bean_hard:
        score, key = crib_score_with_bean(perm, period, variant)
    else:
        score, key = crib_score_periodic(perm, period, variant)

    best_score = score
    best_perm = perm[:]
    best_key = key

    stale = 0
    for step in range(max_steps):
        # Random swap
        i, j = random.sample(range(N), 2)
        perm[i], perm[j] = perm[j], perm[i]

        if bean_hard:
            new_score, new_key = crib_score_with_bean(perm, period, variant)
        else:
            new_score, new_key = crib_score_periodic(perm, period, variant)

        if new_score >= score:
            score = new_score
            if score > best_score:
                best_score = score
                best_perm = perm[:]
                best_key = new_key
                stale = 0
        else:
            perm[i], perm[j] = perm[j], perm[i]  # undo
            stale += 1

        if stale > 2000:
            break  # stuck

    return best_score, best_perm, best_key


print("=" * 70)
print("E-FRAC-36: Period-8 Hill-Climbing with Bean Constraint")
print("=" * 70)

results = {}

for period in [8, 13]:
    print(f"\n{'='*70}")
    print(f"PERIOD {period} (cribs/var = {24/period:.1f})")
    print("=" * 70)

    for variant in ['vigenere', 'beaufort']:
        print(f"\n--- {variant.capitalize()}, period {period} ---")

        # Hill-climbing WITH Bean constraint
        n_climbs = 50
        max_steps = 10000
        scores_bean = []
        solutions_24 = []

        random.seed(42 + period * 100 + (0 if variant == 'vigenere' else 1))

        for c in range(n_climbs):
            score, perm, key = hill_climb(period, max_steps=max_steps,
                                          bean_hard=True, variant=variant)
            scores_bean.append(score)

            if score >= 20:
                pt = derive_plaintext(perm, key, period, variant)
                qg = quadgram_score(pt)
                ic_val = ic(pt)
                solutions_24.append({
                    'score': score,
                    'key': list(key),
                    'quadgram': round(qg, 4),
                    'ic': round(ic_val, 4),
                    'plaintext': pt[:40] + '...',
                    'bean_pass': check_bean_key(key, period),
                })
                if c < 5 or score == 24:
                    print(f"  Climb {c}: {score}/24 Bean=PASS qg={qg:.3f}/char IC={ic_val:.4f}")
                    print(f"    Key: {list(key)}")
                    print(f"    PT:  {pt[:50]}...")

        max_s = max(scores_bean)
        mean_s = sum(scores_bean) / len(scores_bean)
        n_24 = sum(1 for s in scores_bean if s >= 24)
        n_20_plus = sum(1 for s in scores_bean if s >= 20)

        print(f"\n  Summary ({variant} p={period}, Bean=HARD, {n_climbs} climbs × {max_steps} steps):")
        print(f"    Max: {max_s}/24, Mean: {mean_s:.1f}")
        print(f"    ≥24: {n_24}/{n_climbs} ({100*n_24/n_climbs:.0f}%)")
        print(f"    ≥20: {n_20_plus}/{n_climbs} ({100*n_20_plus/n_climbs:.0f}%)")

        if solutions_24:
            qgs = [s['quadgram'] for s in solutions_24]
            print(f"    Quadgram range for ≥20: [{min(qgs):.3f}, {max(qgs):.3f}]/char")
            print(f"    (English ≈ -4.84, FP threshold from E-FRAC-34: -5.0)")

        # Hill-climbing WITHOUT Bean for comparison
        scores_nobean = []
        random.seed(142 + period * 100 + (0 if variant == 'vigenere' else 1))

        for c in range(n_climbs):
            score, perm, key = hill_climb(period, max_steps=max_steps,
                                          bean_hard=False, variant=variant)
            scores_nobean.append(score)

        max_nb = max(scores_nobean)
        mean_nb = sum(scores_nobean) / len(scores_nobean)
        n_24_nb = sum(1 for s in scores_nobean if s >= 24)

        print(f"\n  Comparison (NO Bean constraint):")
        print(f"    Max: {max_nb}/24, Mean: {mean_nb:.1f}")
        print(f"    ≥24: {n_24_nb}/{n_climbs} ({100*n_24_nb/n_climbs:.0f}%)")
        print(f"    Bean DROP: max {max_s}→{max_nb}, mean {mean_s:.1f}→{mean_nb:.1f}")

        results[f'{variant}_p{period}'] = {
            'period': period,
            'variant': variant,
            'n_climbs': n_climbs,
            'max_steps': max_steps,
            'bean_hard': {
                'max': max_s,
                'mean': round(mean_s, 2),
                'n_24': n_24,
                'n_20_plus': n_20_plus,
                'scores': scores_bean,
            },
            'no_bean': {
                'max': max_nb,
                'mean': round(mean_nb, 2),
                'n_24': n_24_nb,
            },
            'solutions_20_plus': solutions_24,
        }

    elapsed = time.time() - START_TIME
    print(f"\n  [elapsed: {elapsed:.0f}s]")


# Random baseline
print(f"\n{'='*70}")
print("RANDOM BASELINE (period 8)")
print("=" * 70)

random.seed(999)
baseline_scores = []
for _ in range(10000):
    perm = list(range(N))
    random.shuffle(perm)
    score, key = crib_score_periodic(perm, 8, 'vigenere')
    baseline_scores.append(score)

max_rand = max(baseline_scores)
mean_rand = sum(baseline_scores) / len(baseline_scores)
print(f"Random baseline (10K perms, period 8): max={max_rand}, mean={mean_rand:.2f}")

# With Bean filter
baseline_bean_scores = []
random.seed(999)
for _ in range(10000):
    perm = list(range(N))
    random.shuffle(perm)
    score, key = crib_score_with_bean(perm, 8, 'vigenere')
    baseline_bean_scores.append(score)

nonzero_bean = [s for s in baseline_bean_scores if s > 0]
print(f"Random + Bean filter: {len(nonzero_bean)}/10K pass Bean ({100*len(nonzero_bean)/10000:.1f}%)")
if nonzero_bean:
    print(f"  Bean-passing: max={max(nonzero_bean)}, mean={sum(nonzero_bean)/len(nonzero_bean):.2f}")


# Summary
print(f"\n{'='*70}")
print("SUMMARY")
print("=" * 70)

summary = {
    'experiment': 'E-FRAC-36',
    'title': 'Period-8 Hill-Climbing with Bean Constraint',
    'runtime_seconds': round(time.time() - START_TIME, 1),
    'results': results,
    'random_baseline': {
        'period': 8,
        'n_samples': 10000,
        'max': max_rand,
        'mean': round(mean_rand, 2),
        'bean_pass_rate': len(nonzero_bean) / 10000,
    },
}

for config, data in results.items():
    bh = data['bean_hard']
    nb = data['no_bean']
    print(f"\n  {config}:")
    print(f"    Bean=HARD: max={bh['max']}, ≥24={bh['n_24']}/{data['n_climbs']}, ≥20={bh['n_20_plus']}/{data['n_climbs']}")
    print(f"    No Bean:   max={nb['max']}, ≥24={nb['n_24']}/{data['n_climbs']}")

# Determine verdict
all_max_bean = max(data['bean_hard']['max'] for data in results.values())
any_24_bean = any(data['bean_hard']['n_24'] > 0 for data in results.values())

if any_24_bean:
    # Check if any pass quadgram threshold
    all_sols = []
    for data in results.values():
        all_sols.extend(data.get('solutions_20_plus', []))
    sols_24 = [s for s in all_sols if s['score'] >= 24]
    if sols_24:
        best_qg = max(s['quadgram'] for s in sols_24)
        print(f"\n  24/24 + Bean: YES ({sum(data['bean_hard']['n_24'] for data in results.values())} solutions)")
        print(f"  Best quadgram at 24/24: {best_qg:.3f}/char (threshold: -5.0)")
        if best_qg > -5.0:
            print(f"  WARNING: quadgram above threshold! Investigate!")
        else:
            print(f"  All 24/24 solutions are FALSE POSITIVES (quadgram < -5.0)")
        verdict = "FALSE_POSITIVES_AT_P8" if best_qg < -5.0 else "INVESTIGATE"
    else:
        verdict = "NO_24_SOLUTIONS"
else:
    print(f"\n  24/24 + Bean: NO (max achieved: {all_max_bean}/24)")
    print(f"  Period 8 may be TOO constrained for hill-climbing to reach 24/24")
    verdict = f"MAX_{all_max_bean}_OF_24"

summary['verdict'] = verdict
print(f"\n  Verdict: {verdict}")
print(f"  Runtime: {summary['runtime_seconds']}s")

os.makedirs('results/frac', exist_ok=True)
outpath = 'results/frac/e_frac_36_period8_bean_hillclimb.json'
with open(outpath, 'w') as f:
    json.dump(summary, f, indent=2, default=str)
print(f"\n  Results: {outpath}")
print(f"\nRESULT: {verdict}")
