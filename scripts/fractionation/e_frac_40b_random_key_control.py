#!/usr/bin/env python3
"""
Cipher: fractionation analysis
Family: fractionation
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-FRAC-40b: Random Key Control for Quadgram Screening

Critical control for E-FRAC-40: does SA-optimized transposition produce
good quadgrams even with RANDOM (non-Carter) running key? If yes, then
E-FRAC-40's "signal" is an SA optimization artifact, NOT evidence that
Carter is the running key source.

The key question: is Carter text SPECIAL, or does ANY running key + SA
produce good quadgrams when optimizing the 73 non-crib positions?
"""
import json
import math
import os
import random
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD,
    CRIB_ENTRIES, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CT_LETTER_POSITIONS = {}
for j, v in enumerate(CT_NUM):
    CT_LETTER_POSITIONS.setdefault(v, []).append(j)

CRIB_POS = [pos for pos, _ in CRIB_ENTRIES]
CRIB_PT_NUM = [ALPH_IDX[ch] for _, ch in CRIB_ENTRIES]
CRIB_SET = set(CRIB_POS)
NON_CRIB_POS = sorted(set(range(CT_LEN)) - CRIB_SET)

BASE = os.path.dirname(os.path.dirname(__file__))
with open(os.path.join(BASE, 'data', 'english_quadgrams.json')) as f:
    QUADGRAMS = json.load(f)
QG_FLOOR = -7.0


def quadgram_score(text_nums):
    total = 0.0
    n_quads = 0
    for i in range(len(text_nums) - 3):
        qg = chr(text_nums[i] + 65) + chr(text_nums[i+1] + 65) + \
             chr(text_nums[i+2] + 65) + chr(text_nums[i+3] + 65)
        total += QUADGRAMS.get(qg, QG_FLOOR)
        n_quads += 1
    return total / n_quads if n_quads > 0 else QG_FLOOR


def check_bean(key_nums):
    for eq_a, eq_b in BEAN_EQ:
        if key_nums[eq_a] != key_nums[eq_b]:
            return False, False
    for ineq_a, ineq_b in BEAN_INEQ:
        if key_nums[ineq_a] == key_nums[ineq_b]:
            return True, False
    return True, True


def max_bipartite_matching_with_assignment(adj, n_left, n_right):
    match_right = [-1] * n_right
    match_left = [-1] * n_left

    def augment(u, visited):
        for v in adj[u]:
            if not visited[v]:
                visited[v] = True
                if match_right[v] == -1 or augment(match_right[v], visited):
                    match_right[v] = u
                    match_left[u] = v
                    return True
        return False

    matching = 0
    for u in range(n_left):
        visited = [False] * n_right
        if augment(u, visited):
            matching += 1
    return matching, match_left


def find_matching(key_nums, variant):
    adj = []
    for i in range(N_CRIBS):
        pt_val = CRIB_PT_NUM[i]
        key_val = key_nums[CRIB_POS[i]]
        if variant == 'vigenere':
            required = (pt_val + key_val) % MOD
        else:
            required = (key_val - pt_val) % MOD
        adj.append(CT_LETTER_POSITIONS.get(required, []))
    size, assignment = max_bipartite_matching_with_assignment(adj, N_CRIBS, CT_LEN)
    return size, assignment


def sa_optimize(key_nums, variant, crib_ct_assignments,
                n_restarts=3, n_steps=5000, t_start=2.0, t_end=0.01):
    used_ct = set(crib_ct_assignments.values())
    available_ct = sorted(set(range(CT_LEN)) - used_ct)

    best_score = -999
    best_pt_str = ""

    for restart in range(n_restarts):
        assignment = list(available_ct)
        random.shuffle(assignment)

        inv_perm = [0] * CT_LEN
        for pos, ct_pos in crib_ct_assignments.items():
            inv_perm[pos] = ct_pos
        for idx, pos in enumerate(NON_CRIB_POS):
            inv_perm[pos] = assignment[idx]

        # Derive plaintext
        pt = [0] * CT_LEN
        for i in range(CT_LEN):
            if variant == 'vigenere':
                pt[i] = (CT_NUM[inv_perm[i]] - key_nums[i]) % MOD
            else:
                pt[i] = (key_nums[i] - CT_NUM[inv_perm[i]]) % MOD

        score = quadgram_score(pt)

        for step in range(n_steps):
            t = t_start * (t_end / t_start) ** (step / n_steps)
            i = random.randint(0, len(NON_CRIB_POS) - 1)
            j = random.randint(0, len(NON_CRIB_POS) - 2)
            if j >= i:
                j += 1

            pos_i = NON_CRIB_POS[i]
            pos_j = NON_CRIB_POS[j]

            inv_perm[pos_i], inv_perm[pos_j] = inv_perm[pos_j], inv_perm[pos_i]

            old_pt_i = pt[pos_i]
            old_pt_j = pt[pos_j]

            if variant == 'vigenere':
                pt[pos_i] = (CT_NUM[inv_perm[pos_i]] - key_nums[pos_i]) % MOD
                pt[pos_j] = (CT_NUM[inv_perm[pos_j]] - key_nums[pos_j]) % MOD
            else:
                pt[pos_i] = (key_nums[pos_i] - CT_NUM[inv_perm[pos_i]]) % MOD
                pt[pos_j] = (key_nums[pos_j] - CT_NUM[inv_perm[pos_j]]) % MOD

            new_score = quadgram_score(pt)
            delta = new_score - score

            if delta > 0 or random.random() < math.exp(delta / t):
                score = new_score
                if score > best_score:
                    best_score = score
                    best_pt_str = ''.join(chr(c + 65) for c in pt)
            else:
                inv_perm[pos_i], inv_perm[pos_j] = inv_perm[pos_j], inv_perm[pos_i]
                pt[pos_i] = old_pt_i
                pt[pos_j] = old_pt_j

    return best_score, best_pt_str


def generate_random_key_with_bean():
    """Generate random key (uniform 0-25) that passes Bean constraints."""
    while True:
        key = [random.randint(0, 25) for _ in range(CT_LEN)]
        _, bean_full = check_bean(key)
        if bean_full:
            return key


def generate_english_freq_key_with_bean():
    """Generate random key with English letter frequencies that passes Bean."""
    freqs = [0.0817, 0.0149, 0.0278, 0.0425, 0.1270, 0.0223, 0.0202, 0.0609,
             0.0697, 0.0015, 0.0077, 0.0403, 0.0241, 0.0675, 0.0751, 0.0193,
             0.0010, 0.0599, 0.0633, 0.0906, 0.0276, 0.0098, 0.0236, 0.0015,
             0.0197, 0.0007]
    cumulative = []
    total = 0
    for f in freqs:
        total += f
        cumulative.append(total)

    while True:
        key = []
        for _ in range(CT_LEN):
            r = random.random()
            for i, c in enumerate(cumulative):
                if r <= c:
                    key.append(i)
                    break
            else:
                key.append(25)
        _, bean_full = check_bean(key)
        if bean_full:
            return key


def main():
    t0 = time.time()
    random.seed(42)

    print("=" * 70)
    print("E-FRAC-40b: Random Key Control — Is Carter Special?")
    print("=" * 70)

    n_trials = 100
    variant = 'vigenere'  # Test primary variant

    print(f"\nPhase 1: Uniform Random Key ({n_trials} trials)")
    print("  (key values uniform 0-25, Bean-passing)")
    uniform_scores = []
    uniform_pts = []
    t1 = time.time()

    for trial in range(n_trials):
        key = generate_random_key_with_bean()
        size, assignment = find_matching(key, variant)
        if size < 24:
            continue  # Skip (unlikely)

        crib_ct = {}
        for i in range(N_CRIBS):
            crib_ct[CRIB_POS[i]] = assignment[i]

        score, pt = sa_optimize(key, variant, crib_ct, n_restarts=3, n_steps=5000)
        uniform_scores.append(score)
        uniform_pts.append(pt)

        if (trial + 1) % 25 == 0:
            elapsed = time.time() - t1
            print(f"  {trial+1}/{n_trials}: best={max(uniform_scores):.4f}, "
                  f"mean={sum(uniform_scores)/len(uniform_scores):.4f} ({elapsed:.1f}s)")

    print(f"\n  Uniform random key results ({len(uniform_scores)} trials):")
    print(f"    Best: {max(uniform_scores):.4f}/char")
    print(f"    Mean: {sum(uniform_scores)/len(uniform_scores):.4f}/char")
    print(f"    Worst: {min(uniform_scores):.4f}/char")
    above = sum(1 for s in uniform_scores if s > -5.0)
    print(f"    Above -5.0: {above}/{len(uniform_scores)}")

    # Top-3 plaintexts
    sorted_uniform = sorted(zip(uniform_scores, uniform_pts), reverse=True)
    print(f"    Top-3 plaintexts:")
    for score, pt in sorted_uniform[:3]:
        print(f"      qg={score:.4f}: {pt[:40]}...")

    print(f"\nPhase 2: English-Frequency Random Key ({n_trials} trials)")
    print("  (key values follow English letter frequencies, Bean-passing)")
    english_scores = []
    english_pts = []
    t2 = time.time()

    for trial in range(n_trials):
        key = generate_english_freq_key_with_bean()
        size, assignment = find_matching(key, variant)
        if size < 24:
            continue

        crib_ct = {}
        for i in range(N_CRIBS):
            crib_ct[CRIB_POS[i]] = assignment[i]

        score, pt = sa_optimize(key, variant, crib_ct, n_restarts=3, n_steps=5000)
        english_scores.append(score)
        english_pts.append(pt)

        if (trial + 1) % 25 == 0:
            elapsed = time.time() - t2
            print(f"  {trial+1}/{n_trials}: best={max(english_scores):.4f}, "
                  f"mean={sum(english_scores)/len(english_scores):.4f} ({elapsed:.1f}s)")

    print(f"\n  English-freq random key results ({len(english_scores)} trials):")
    print(f"    Best: {max(english_scores):.4f}/char")
    print(f"    Mean: {sum(english_scores)/len(english_scores):.4f}/char")
    print(f"    Worst: {min(english_scores):.4f}/char")
    above_eng = sum(1 for s in english_scores if s > -5.0)
    print(f"    Above -5.0: {above_eng}/{len(english_scores)}")

    sorted_english = sorted(zip(english_scores, english_pts), reverse=True)
    print(f"    Top-3 plaintexts:")
    for score, pt in sorted_english[:3]:
        print(f"      qg={score:.4f}: {pt[:40]}...")

    # Summary
    total_time = time.time() - t0
    print("\n" + "=" * 70)
    print("COMPARISON")
    print("=" * 70)
    print(f"  Carter Gutenberg (E-FRAC-40): best=-4.27, mean=-4.55")
    print(f"  Uniform random key:           best={max(uniform_scores):.4f}, "
          f"mean={sum(uniform_scores)/len(uniform_scores):.4f}")
    print(f"  English-freq random key:      best={max(english_scores):.4f}, "
          f"mean={sum(english_scores)/len(english_scores):.4f}")
    print(f"  English text (E-FRAC-34):     -4.84")
    print(f"  E-FRAC-34 false positives:    -5.77 best (crib-optimized, NOT quadgram-optimized)")

    # Is Carter special?
    carter_best = -4.2685
    carter_mean = -4.5466
    uniform_best = max(uniform_scores)
    uniform_mean = sum(uniform_scores) / len(uniform_scores)
    english_best = max(english_scores)
    english_mean = sum(english_scores) / len(english_scores)

    carter_vs_uniform = abs(carter_best - uniform_best)
    carter_vs_english = abs(carter_best - english_best)

    if carter_vs_uniform < 0.15 and carter_vs_english < 0.15:
        verdict = (f"CARTER_NOT_SPECIAL — Carter achieves similar quadgrams "
                   f"({carter_best:.3f}) as random key ({uniform_best:.3f}) and "
                   f"English-freq key ({english_best:.3f}). The 'signal' in E-FRAC-40 "
                   f"is an SA optimization artifact, NOT evidence for Carter as source.")
    elif carter_best > uniform_best + 0.3 and carter_best > english_best + 0.3:
        verdict = (f"CARTER_POTENTIALLY_SPECIAL — Carter ({carter_best:.3f}) "
                   f"significantly outperforms random ({uniform_best:.3f}) and "
                   f"English-freq ({english_best:.3f}). Investigate further.")
    else:
        verdict = (f"INCONCLUSIVE — Carter ({carter_best:.3f}) vs random "
                   f"({uniform_best:.3f}) vs English-freq ({english_best:.3f}). "
                   f"Difference is small.")

    print(f"\n  VERDICT: {verdict}")
    print(f"  Total runtime: {total_time:.1f}s")

    # Save
    summary = {
        'experiment': 'E-FRAC-40b',
        'description': 'Random key control for quadgram screening',
        'total_time_seconds': round(total_time, 1),
        'carter_reference': {'best': carter_best, 'mean': carter_mean},
        'uniform_random': {
            'n_trials': len(uniform_scores),
            'best': round(max(uniform_scores), 4),
            'mean': round(sum(uniform_scores)/len(uniform_scores), 4),
            'worst': round(min(uniform_scores), 4),
            'above_threshold': above,
        },
        'english_freq_random': {
            'n_trials': len(english_scores),
            'best': round(max(english_scores), 4),
            'mean': round(sum(english_scores)/len(english_scores), 4),
            'worst': round(min(english_scores), 4),
            'above_threshold': above_eng,
        },
        'verdict': verdict,
    }

    results_dir = os.path.join(BASE, 'results', 'frac')
    os.makedirs(results_dir, exist_ok=True)
    outpath = os.path.join(results_dir, 'e_frac_40b_random_key_control.json')
    with open(outpath, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"  Results saved to: {outpath}")

    print("\n" + "=" * 70)
    print("RESULT: " + verdict)
    print("=" * 70)


if __name__ == '__main__':
    main()
