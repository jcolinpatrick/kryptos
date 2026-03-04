#!/usr/bin/env python3
"""
Cipher: autokey
Family: fractionation
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-37: Autokey + Arbitrary Transposition — Oracle Generalization Test

E-FRAC-35 proved periodic keying is Bean-impossible at ALL discriminating periods
for ANY transposition. But autokey bypasses periodicity — key values depend on
previous plaintext, not position mod p. This experiment tests:

1. Can hill-climbing + autokey + arbitrary transposition reach 24/24 + Bean?
2. If so, do the false positives beat the multi-objective oracle (quadgram > -5.0)?
3. Does autokey's self-consistency produce more English-like plaintext than periodic?
4. Is the multi-objective oracle from E-FRAC-34 robust to non-periodic key models?

Models tested:
- PT-autokey (Vigenère): K[0]=seed, K[i]=PT[i-1] for i>0. PT[i]=(CT[σ(i)]-K[i])%26
- PT-autokey (Beaufort): K[0]=seed, K[i]=PT[i-1] for i>0. PT[i]=(K[i]-CT[σ(i)])%26
- CT-autokey (Vigenère): K[0]=seed, K[i]=CT[σ(i-1)] for i>0. PT[i]=(CT[σ(i)]-K[i])%26
- CT-autokey (Beaufort): K[0]=seed, K[i]=CT[σ(i-1)] for i>0. PT[i]=(K[i]-CT[σ(i)])%26
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


def decrypt_pt_autokey_vig(perm, seed):
    """Decrypt with PT-autokey Vigenère. K[0]=seed, K[i]=PT[i-1] for i>0."""
    pt = [0] * N
    pt[0] = (CT_VALS[perm[0]] - seed) % 26
    for i in range(1, N):
        pt[i] = (CT_VALS[perm[i]] - pt[i - 1]) % 26
    return pt


def decrypt_pt_autokey_beau(perm, seed):
    """Decrypt with PT-autokey Beaufort. K[0]=seed, K[i]=PT[i-1] for i>0."""
    pt = [0] * N
    pt[0] = (seed - CT_VALS[perm[0]]) % 26
    for i in range(1, N):
        pt[i] = (pt[i - 1] - CT_VALS[perm[i]]) % 26
    return pt


def decrypt_ct_autokey_vig(perm, seed):
    """Decrypt with CT-autokey Vigenère. K[0]=seed, K[i]=CT[σ(i-1)] for i>0."""
    pt = [0] * N
    pt[0] = (CT_VALS[perm[0]] - seed) % 26
    for i in range(1, N):
        k = CT_VALS[perm[i - 1]]
        pt[i] = (CT_VALS[perm[i]] - k) % 26
    return pt


def decrypt_ct_autokey_beau(perm, seed):
    """Decrypt with CT-autokey Beaufort. K[0]=seed, K[i]=CT[σ(i-1)] for i>0."""
    pt = [0] * N
    pt[0] = (seed - CT_VALS[perm[0]]) % 26
    for i in range(1, N):
        k = CT_VALS[perm[i - 1]]
        pt[i] = (k - CT_VALS[perm[i]]) % 26
    return pt


DECRYPT_FUNCS = {
    'pt_autokey_vig': decrypt_pt_autokey_vig,
    'pt_autokey_beau': decrypt_pt_autokey_beau,
    'ct_autokey_vig': decrypt_ct_autokey_vig,
    'ct_autokey_beau': decrypt_ct_autokey_beau,
}


def check_bean(pt_vals_list):
    """Check Bean constraints on plaintext-derived key values.
    For autokey with primer length 1: K[i] = PT[i-1] for i > 0, K[0] = seed.
    Bean constrains K[a] vs K[b] for specific position pairs.
    For PT-autokey: K[i] = PT[i-1], so Bean on K[a] == K[b] means PT[a-1] == PT[b-1].

    But the key schedule differs by model. Instead, we derive the key values and check directly.
    """
    # For autokey, Bean constraints apply to the key values K[i].
    # K[0] = seed (known), K[i] = PT[i-1] (PT-autokey) or CT[σ(i-1)] (CT-autokey).
    # We pass the full key array and check.
    # Actually, we need to know the key values. Let's compute them from PT.
    # This function receives pt_vals_list = the plaintext as list of ints.
    # For PT-autokey: K[i] = seed if i=0, else PT[i-1]
    # For CT-autokey: K[i] = seed if i=0, else CT[σ(i-1)]
    # Since we don't have the key here, we'll compute Bean differently.
    # The caller should pass key_vals instead.
    pass


def score_autokey(perm, model, return_details=False):
    """Score a permutation under autokey model. Try all 26 seeds.
    Returns (best_score, best_seed, best_key_vals) or
    (best_score, best_seed, best_key_vals, best_pt) if return_details.
    """
    decrypt_func = DECRYPT_FUNCS[model]
    best_score = -1
    best_seed = -1
    best_key_vals = None
    best_pt_vals = None

    for seed in range(26):
        pt = decrypt_func(perm, seed)

        # Count crib matches
        matches = 0
        for pos in CRIB_POS:
            if pt[pos] == PT_VALS[pos]:
                matches += 1

        if matches > best_score:
            best_score = matches
            best_seed = seed
            best_pt_vals = pt[:]

            # Derive key values for Bean checking
            if 'pt_autokey' in model:
                key_vals = [seed] + pt[:-1]  # K[0]=seed, K[i]=PT[i-1]
            else:  # ct_autokey
                key_vals = [seed] + [CT_VALS[perm[i]] for i in range(N - 1)]
            best_key_vals = key_vals

    # Check Bean on best key
    bean_pass = True
    if best_key_vals:
        for a, b in BEAN_EQ:
            if best_key_vals[a] != best_key_vals[b]:
                bean_pass = False
                break
        if bean_pass:
            for a, b in BEAN_INEQ:
                if best_key_vals[a] == best_key_vals[b]:
                    bean_pass = False
                    break

    if return_details:
        pt_str = ''.join(chr(v + ord('A')) for v in best_pt_vals) if best_pt_vals else ''
        return best_score, best_seed, bean_pass, pt_str
    return best_score, best_seed, bean_pass


def score_autokey_bean_hard(perm, model):
    """Score but require Bean to pass. Return 0 if Bean fails."""
    decrypt_func = DECRYPT_FUNCS[model]
    best_score = -1
    best_seed = -1

    for seed in range(26):
        pt = decrypt_func(perm, seed)

        # Derive key values
        if 'pt_autokey' in model:
            key_vals = [seed] + list(pt[:-1])
        else:
            key_vals = [seed] + [CT_VALS[perm[i]] for i in range(N - 1)]

        # Check Bean
        bean_pass = True
        for a, b in BEAN_EQ:
            if key_vals[a] != key_vals[b]:
                bean_pass = False
                break
        if bean_pass:
            for a, b in BEAN_INEQ:
                if key_vals[a] == key_vals[b]:
                    bean_pass = False
                    break

        if not bean_pass:
            continue

        # Count crib matches
        matches = 0
        for pos in CRIB_POS:
            if pt[pos] == PT_VALS[pos]:
                matches += 1

        if matches > best_score:
            best_score = matches
            best_seed = seed

    return max(best_score, 0), best_seed


def hill_climb_autokey(model, max_steps=5000, bean_hard=False):
    """Hill-climb over permutation space with autokey scoring."""
    perm = list(range(N))
    random.shuffle(perm)

    if bean_hard:
        score, seed = score_autokey_bean_hard(perm, model)
    else:
        score, seed, _ = score_autokey(perm, model)

    best_score = score
    best_perm = perm[:]
    best_seed = seed

    stale = 0
    for step in range(max_steps):
        i, j = random.sample(range(N), 2)
        perm[i], perm[j] = perm[j], perm[i]

        if bean_hard:
            new_score, new_seed = score_autokey_bean_hard(perm, model)
        else:
            new_score, new_seed, _ = score_autokey(perm, model)

        if new_score >= score:
            score = new_score
            if score > best_score:
                best_score = score
                best_perm = perm[:]
                best_seed = new_seed
                stale = 0
        else:
            perm[i], perm[j] = perm[j], perm[i]
            stale += 1

        if stale > 2000:
            break

    return best_score, best_perm, best_seed


print("=" * 70)
print("E-FRAC-37: Autokey + Arbitrary Transposition — Oracle Generalization")
print("=" * 70)

results = {}

# Phase 1: Random baseline
print(f"\n{'='*70}")
print("PHASE 1: Random Baseline (10K perms × 4 models × 26 seeds)")
print("=" * 70)

random.seed(42)
for model in DECRYPT_FUNCS:
    scores = []
    bean_scores = []
    for _ in range(10000):
        perm = list(range(N))
        random.shuffle(perm)
        score, seed, bean = score_autokey(perm, model)
        scores.append(score)
        if bean:
            bean_scores.append(score)

    max_s = max(scores)
    mean_s = sum(scores) / len(scores)
    print(f"\n  {model}: max={max_s}/24, mean={mean_s:.2f}")
    print(f"    Bean pass: {len(bean_scores)}/10000 ({100*len(bean_scores)/10000:.1f}%)")
    if bean_scores:
        print(f"    Bean max: {max(bean_scores)}/24, Bean mean: {sum(bean_scores)/len(bean_scores):.2f}")

    results[f'baseline_{model}'] = {
        'n_samples': 10000,
        'max': max_s,
        'mean': round(mean_s, 2),
        'bean_pass_count': len(bean_scores),
        'bean_max': max(bean_scores) if bean_scores else 0,
    }

elapsed = time.time() - START_TIME
print(f"\n  [Phase 1 elapsed: {elapsed:.0f}s]")


# Phase 2: Hill-climbing (NO Bean constraint)
print(f"\n{'='*70}")
print("PHASE 2: Hill-Climbing WITHOUT Bean (50 climbs × 5K steps × 4 models)")
print("=" * 70)

n_climbs = 50
max_steps = 5000

for model in DECRYPT_FUNCS:
    print(f"\n--- {model} ---")
    random.seed(100 + hash(model) % 10000)

    scores = []
    solutions_high = []

    for c in range(n_climbs):
        score, perm, seed = hill_climb_autokey(model, max_steps=max_steps, bean_hard=False)
        scores.append(score)

        if score >= 18:
            # Get full details
            _, _, bean_pass, pt_str = score_autokey(perm, model, return_details=True)
            qg = quadgram_score(pt_str)
            ic_val = ic(pt_str)
            solutions_high.append({
                'score': score,
                'seed': seed,
                'quadgram': round(qg, 4),
                'ic': round(ic_val, 4),
                'bean_pass': bean_pass,
                'plaintext': pt_str[:40] + '...',
            })
            if c < 5 or score >= 22:
                print(f"  Climb {c}: {score}/24 seed={seed} Bean={'PASS' if bean_pass else 'FAIL'}"
                      f" qg={qg:.3f}/char IC={ic_val:.4f}")
                print(f"    PT: {pt_str[:50]}...")

    max_s = max(scores)
    mean_s = sum(scores) / len(scores)
    n_24 = sum(1 for s in scores if s >= 24)
    n_20 = sum(1 for s in scores if s >= 20)

    print(f"\n  Summary ({model}, no Bean, {n_climbs} climbs × {max_steps} steps):")
    print(f"    Max: {max_s}/24, Mean: {mean_s:.1f}")
    print(f"    ≥24: {n_24}/{n_climbs} ({100*n_24/n_climbs:.0f}%)")
    print(f"    ≥20: {n_20}/{n_climbs} ({100*n_20/n_climbs:.0f}%)")

    if solutions_high:
        qgs = [s['quadgram'] for s in solutions_high]
        print(f"    Quadgram range for ≥18: [{min(qgs):.3f}, {max(qgs):.3f}]/char")
        print(f"    (English ≈ -4.84, threshold: -5.0)")
        bean_pass_high = [s for s in solutions_high if s['bean_pass']]
        print(f"    Bean pass in ≥18: {len(bean_pass_high)}/{len(solutions_high)}")

    results[f'climb_{model}'] = {
        'n_climbs': n_climbs,
        'max_steps': max_steps,
        'bean_hard': False,
        'max': max_s,
        'mean': round(mean_s, 2),
        'n_24': n_24,
        'n_20': n_20,
        'solutions_high': solutions_high,
    }

elapsed = time.time() - START_TIME
print(f"\n  [Phase 2 elapsed: {elapsed:.0f}s]")


# Phase 3: Hill-climbing WITH Bean constraint
print(f"\n{'='*70}")
print("PHASE 3: Hill-Climbing WITH Bean HARD (50 climbs × 5K steps × 4 models)")
print("=" * 70)

for model in DECRYPT_FUNCS:
    print(f"\n--- {model} (Bean=HARD) ---")
    random.seed(200 + hash(model) % 10000)

    scores = []
    solutions_high = []

    for c in range(n_climbs):
        score, perm, seed = hill_climb_autokey(model, max_steps=max_steps, bean_hard=True)
        scores.append(score)

        if score >= 15:
            _, _, bean_pass, pt_str = score_autokey(perm, model, return_details=True)
            qg = quadgram_score(pt_str)
            ic_val = ic(pt_str)
            solutions_high.append({
                'score': score,
                'seed': seed,
                'quadgram': round(qg, 4),
                'ic': round(ic_val, 4),
                'bean_pass': bean_pass,
                'plaintext': pt_str[:40] + '...',
            })
            if c < 5 or score >= 20:
                print(f"  Climb {c}: {score}/24 seed={seed} Bean={'PASS' if bean_pass else 'FAIL'}"
                      f" qg={qg:.3f}/char IC={ic_val:.4f}")
                print(f"    PT: {pt_str[:50]}...")

    max_s = max(scores) if scores else 0
    mean_s = sum(scores) / len(scores) if scores else 0
    n_24 = sum(1 for s in scores if s >= 24)
    n_20 = sum(1 for s in scores if s >= 20)

    print(f"\n  Summary ({model}, Bean=HARD, {n_climbs} climbs × {max_steps} steps):")
    print(f"    Max: {max_s}/24, Mean: {mean_s:.1f}")
    print(f"    ≥24: {n_24}/{n_climbs} ({100*n_24/n_climbs:.0f}%)")
    print(f"    ≥20: {n_20}/{n_climbs} ({100*n_20/n_climbs:.0f}%)")

    if solutions_high:
        qgs = [s['quadgram'] for s in solutions_high]
        print(f"    Quadgram range for ≥15: [{min(qgs):.3f}, {max(qgs):.3f}]/char")

    results[f'climb_bean_{model}'] = {
        'n_climbs': n_climbs,
        'max_steps': max_steps,
        'bean_hard': True,
        'max': max_s,
        'mean': round(mean_s, 2),
        'n_24': n_24,
        'n_20': n_20,
        'solutions_high': solutions_high,
    }

elapsed = time.time() - START_TIME
print(f"\n  [Phase 3 elapsed: {elapsed:.0f}s]")


# Summary
print(f"\n{'='*70}")
print("SUMMARY — Autokey vs Periodic False Positives")
print("=" * 70)

# Collect all solutions ≥20 for comparison
all_solutions = []
for key, data in results.items():
    if 'solutions_high' in data:
        for sol in data['solutions_high']:
            sol['config'] = key
            all_solutions.append(sol)

sols_24 = [s for s in all_solutions if s['score'] >= 24]
sols_24_bean = [s for s in sols_24 if s['bean_pass']]
sols_20 = [s for s in all_solutions if s['score'] >= 20]

print(f"\n  Total solutions ≥20: {len(sols_20)}")
print(f"  Total solutions ≥24: {len(sols_24)}")
print(f"  Total solutions ≥24 + Bean: {len(sols_24_bean)}")

if sols_24:
    qgs_24 = [s['quadgram'] for s in sols_24]
    ics_24 = [s['ic'] for s in sols_24]
    print(f"\n  24/24 solutions:")
    print(f"    Quadgram range: [{min(qgs_24):.3f}, {max(qgs_24):.3f}]/char")
    print(f"    IC range: [{min(ics_24):.4f}, {max(ics_24):.4f}]")
    print(f"    (English: qg=-4.84, IC=0.067; Oracle threshold: qg>-5.0, IC>0.055)")

    any_beat_oracle = any(s['quadgram'] > -5.0 for s in sols_24)
    print(f"\n    Any beat quadgram threshold (-5.0)? {'YES — INVESTIGATE!' if any_beat_oracle else 'NO'}")
    any_beat_ic = any(s['ic'] > 0.055 for s in sols_24)
    print(f"    Any beat IC threshold (0.055)? {'YES — INVESTIGATE!' if any_beat_ic else 'NO'}")

if sols_24_bean:
    qgs_bean = [s['quadgram'] for s in sols_24_bean]
    ics_bean = [s['ic'] for s in sols_24_bean]
    print(f"\n  24/24 + Bean solutions:")
    print(f"    Count: {len(sols_24_bean)}")
    print(f"    Quadgram range: [{min(qgs_bean):.3f}, {max(qgs_bean):.3f}]/char")
    print(f"    IC range: [{min(ics_bean):.4f}, {max(ics_bean):.4f}]")

# Comparison with E-FRAC-34/36 periodic false positives
print(f"\n  COMPARISON WITH PERIODIC FALSE POSITIVES (E-FRAC-34/36):")
print(f"    Periodic best quadgram: -5.77/char (90 solutions, E-FRAC-34)")
print(f"    Periodic bean best: -6.171/char (175 solutions, E-FRAC-36)")
if sols_24:
    best_ak_qg = max(s['quadgram'] for s in sols_24)
    print(f"    Autokey best quadgram: {best_ak_qg:.3f}/char ({len(sols_24)} solutions)")
    if best_ak_qg > -5.77:
        print(f"    *** AUTOKEY CLOSER TO ENGLISH THAN PERIODIC! ***")
    else:
        print(f"    Autokey same or worse than periodic")

# Determine verdict
if sols_24_bean:
    best_qg_bean = max(s['quadgram'] for s in sols_24_bean)
    if best_qg_bean > -5.0:
        verdict = "ORACLE_BROKEN"
    else:
        verdict = "ORACLE_ROBUST"
elif sols_24:
    best_qg = max(s['quadgram'] for s in sols_24)
    if best_qg > -5.0:
        verdict = "ORACLE_BROKEN_NO_BEAN"
    else:
        verdict = "AUTOKEY_FP_DISCRIMINATED"
else:
    verdict = "AUTOKEY_CANNOT_REACH_24"

print(f"\n  Verdict: {verdict}")

summary = {
    'experiment': 'E-FRAC-37',
    'title': 'Autokey + Arbitrary Transposition — Oracle Generalization',
    'runtime_seconds': round(time.time() - START_TIME, 1),
    'models': list(DECRYPT_FUNCS.keys()),
    'n_climbs': n_climbs,
    'max_steps': max_steps,
    'total_solutions_20_plus': len(sols_20),
    'total_solutions_24': len(sols_24),
    'total_solutions_24_bean': len(sols_24_bean),
    'verdict': verdict,
    'results': results,
}

os.makedirs('results/frac', exist_ok=True)
outpath = 'results/frac/e_frac_37_autokey_arbitrary_transposition.json'
with open(outpath, 'w') as f:
    json.dump(summary, f, indent=2, default=str)
print(f"\n  Results: {outpath}")
print(f"  Runtime: {summary['runtime_seconds']}s")
print(f"\nRESULT: {verdict}")
