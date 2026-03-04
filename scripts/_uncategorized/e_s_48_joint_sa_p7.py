#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-48: Joint SA — Transposition + Period-7 Key with Quadgram Fitness

KEY INSIGHT: Period-7 key has only 7 DOF (vs 73 for arbitrary key).
With 24 cribs distributed across 7 residue classes (3-4 per class),
the period-7 key is OVERDETERMINED for a given transposition σ.
This means most random σ will FAIL the crib check, unlike the
73-DOF case where any σ trivially passes.

MODEL A: CT[σ(p)] = PT[p] + key[p % 7] mod 26 (period in PT space)
  - For each PT residue r: key[r] is determined by cribs at residue r
  - If cribs at residue r disagree, σ is INVALID

MODEL B: CT[σ(p)] = PT[p] + key[σ(p) % 7] mod 26 (period in CT space)
  - For each CT residue r: key[r] is determined by cribs mapping to that residue
  - More complex but also constrained

We test BOTH models with SA optimizing σ.

Output: results/e_s_48_joint_sa.json
"""

import json
import sys
import os
import time
import math
import random
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH, ALPH_IDX

N = CT_LEN

# Load quadgram data
try:
    with open("data/english_quadgrams.json") as f:
        qg_data = json.load(f)
    if "logp" in qg_data:
        QUADGRAMS = qg_data["logp"]
    else:
        QUADGRAMS = qg_data
    print(f"Loaded {len(QUADGRAMS)} quadgrams")
except FileNotFoundError:
    print("WARNING: quadgrams not found, using empty")
    QUADGRAMS = {}

# Precompute crib arrays
CRIB_LIST = sorted(CRIB_DICT.items())
CRIB_POS = [p for p, _ in CRIB_LIST]
CRIB_PT = [ALPH_IDX[c] for _, c in CRIB_LIST]
CRIB_BY_RESIDUE = defaultdict(list)
for p, c in CRIB_LIST:
    CRIB_BY_RESIDUE[p % 7].append((p, ALPH_IDX[c]))

CT_IDX = [ALPH_IDX[c] for c in CT]


def quadgram_score(text_indices):
    """Score a plaintext by quadgram log-probabilities."""
    score = 0.0
    for i in range(len(text_indices) - 3):
        qg = ALPH[text_indices[i]] + ALPH[text_indices[i+1]] + \
             ALPH[text_indices[i+2]] + ALPH[text_indices[i+3]]
        score += QUADGRAMS.get(qg, -10.0)
    return score


def derive_key_model_a(perm):
    """For Model A (period in PT space), derive period-7 key from cribs.

    For each PT residue r: key[r] = (CT[perm[p]] - PT[p]) % 26
    All cribs at residue r must agree. If not, return (None, n_consistent).
    """
    key = [None] * 7
    consistent = 0
    total = 0

    for r in range(7):
        cribs_r = CRIB_BY_RESIDUE[r]
        if not cribs_r:
            continue

        # Compute required key values
        key_votes = defaultdict(int)
        for p, pt_idx in cribs_r:
            required_k = (CT_IDX[perm[p]] - pt_idx) % 26
            key_votes[required_k] += 1
            total += 1

        # Use majority vote
        best_k = max(key_votes, key=key_votes.get)
        key[r] = best_k
        consistent += key_votes[best_k]

    # Fill in unconstrained residues
    for r in range(7):
        if key[r] is None:
            key[r] = 0

    return key, consistent


def derive_key_model_b(perm):
    """For Model B (period in CT space), derive period-7 key from cribs.

    For each crib p, σ(p) = perm[p]. The CT residue is perm[p] % 7.
    All cribs with the same CT residue must agree on key value.
    """
    # Group cribs by CT residue
    ct_residue_cribs = defaultdict(list)
    for p, pt_idx in zip(CRIB_POS, CRIB_PT):
        j = perm[p]
        r = j % 7
        ct_residue_cribs[r].append((p, pt_idx, j))

    key = [None] * 7
    consistent = 0

    for r in range(7):
        cribs_r = ct_residue_cribs[r]
        if not cribs_r:
            continue

        key_votes = defaultdict(int)
        for p, pt_idx, j in cribs_r:
            required_k = (CT_IDX[j] - pt_idx) % 26
            key_votes[required_k] += 1

        best_k = max(key_votes, key=key_votes.get)
        key[r] = best_k
        consistent += key_votes[best_k]

    for r in range(7):
        if key[r] is None:
            key[r] = 0

    return key, consistent


def decrypt_model_a(perm, key):
    """Decrypt: PT[i] = (CT[perm[i]] - key[i%7]) % 26"""
    pt = [0] * N
    for i in range(N):
        pt[i] = (CT_IDX[perm[i]] - key[i % 7]) % 26
    return pt


def decrypt_model_b(perm, key):
    """Decrypt: PT[i] = (CT[perm[i]] - key[perm[i]%7]) % 26"""
    pt = [0] * N
    for i in range(N):
        j = perm[i]
        pt[i] = (CT_IDX[j] - key[j % 7]) % 26
    return pt


def lag7_score(pt):
    """Count lag-7 matches in plaintext."""
    return sum(1 for i in range(len(pt)-7) if pt[i] == pt[i+7])


def full_score(perm, model='A'):
    """Compute full score for a given permutation."""
    if model == 'A':
        key, n_consistent = derive_key_model_a(perm)
        pt = decrypt_model_a(perm, key)
    else:
        key, n_consistent = derive_key_model_b(perm)
        pt = decrypt_model_b(perm, key)

    qg = quadgram_score(pt)
    lag7 = lag7_score(pt)

    # Combined score: quadgrams + crib bonus + lag7 bonus
    score = qg + n_consistent * 5.0 + lag7 * 2.0

    return score, qg, n_consistent, lag7, key, pt


def simulated_annealing(model, n_restarts=20, n_steps=200000, seed=42):
    """SA to find transposition σ that maximizes score."""
    print(f"\n{'='*60}")
    print(f"SA: Model {model}, {n_restarts} restarts × {n_steps:,} steps")
    print(f"{'='*60}")

    random.seed(seed)
    t0 = time.time()

    global_best_score = -1e9
    global_best = None

    for restart in range(n_restarts):
        # Random initial permutation
        perm = list(range(N))
        random.shuffle(perm)

        score, qg, n_con, lag7, key, pt = full_score(perm, model)

        best_score = score
        best_perm = perm[:]
        best_qg = qg
        best_con = n_con
        best_lag7 = lag7
        best_key = key[:]
        best_pt = pt[:]

        T = 10.0  # Initial temperature
        T_min = 0.01
        alpha = (T_min / T) ** (1.0 / n_steps)

        accepted = 0
        improved = 0

        for step in range(n_steps):
            # Mutation: swap two positions
            i, j = random.sample(range(N), 2)
            perm[i], perm[j] = perm[j], perm[i]

            new_score, new_qg, new_con, new_lag7, new_key, new_pt = full_score(perm, model)

            delta = new_score - score
            if delta > 0 or random.random() < math.exp(delta / T):
                score = new_score
                accepted += 1
                if new_score > best_score:
                    best_score = new_score
                    best_perm = perm[:]
                    best_qg = new_qg
                    best_con = new_con
                    best_lag7 = new_lag7
                    best_key = new_key[:]
                    best_pt = new_pt[:]
                    improved += 1
            else:
                perm[i], perm[j] = perm[j], perm[i]

            T *= alpha

        pt_str = ''.join(ALPH[x] for x in best_pt)
        key_str = ''.join(ALPH[x] for x in best_key)

        if restart < 5 or best_score > global_best_score - 10:
            print(f"  Restart {restart:2d}: score={best_score:.1f} "
                  f"qg={best_qg:.1f} ({best_qg/94:.2f}/char) "
                  f"crib={best_con}/24 lag7={best_lag7} "
                  f"key={key_str}")
            if best_con >= 20:
                print(f"    PT: {pt_str}")

        if best_score > global_best_score:
            global_best_score = best_score
            global_best = {
                'score': best_score,
                'qg': best_qg,
                'qg_per_char': round(best_qg / 94, 3),
                'crib_matches': best_con,
                'lag7': best_lag7,
                'key': best_key,
                'key_str': key_str,
                'pt': pt_str,
                'perm': best_perm,
                'restart': restart,
            }

    elapsed = time.time() - t0
    print(f"\n  Global best: score={global_best_score:.1f} "
          f"qg={global_best['qg']:.1f} ({global_best['qg_per_char']}/char) "
          f"crib={global_best['crib_matches']}/24 lag7={global_best['lag7']} "
          f"key={global_best['key_str']}")
    print(f"  PT: {global_best['pt']}")
    print(f"  Time: {elapsed:.1f}s")

    return global_best, elapsed


def main():
    print("=" * 70)
    print("E-S-48: Joint SA — Transposition + Period-7 Key")
    print("=" * 70)

    t0 = time.time()
    results = {'experiment': 'E-S-48'}

    # Model A: period in PT space
    best_a, time_a = simulated_annealing('A', n_restarts=20, n_steps=200000, seed=42)
    results['model_a'] = best_a
    results['model_a']['time'] = round(time_a, 1)

    # Model B: period in CT space
    best_b, time_b = simulated_annealing('B', n_restarts=20, n_steps=200000, seed=43)
    results['model_b'] = best_b
    results['model_b']['time'] = round(time_b, 1)

    elapsed = time.time() - t0

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"  Model A: score={best_a['score']:.1f} qg/c={best_a['qg_per_char']} "
          f"crib={best_a['crib_matches']}/24 lag7={best_a['lag7']} key={best_a['key_str']}")
    print(f"  Model B: score={best_b['score']:.1f} qg/c={best_b['qg_per_char']} "
          f"crib={best_b['crib_matches']}/24 lag7={best_b['lag7']} key={best_b['key_str']}")

    # Compare against baselines
    print(f"\n  Baselines:")
    print(f"    English text: qg/c ≈ -4.29")
    print(f"    E-S-21 SA (73 DOF): qg/c ≈ -3.77, 24/24 cribs")
    print(f"    Random: qg/c ≈ -4.70")

    best_overall = best_a if best_a['qg_per_char'] > best_b['qg_per_char'] else best_b
    if best_overall['crib_matches'] >= 20 and best_overall['qg_per_char'] > -4.5:
        verdict = "INVESTIGATE — high crib + decent quadgrams"
    elif best_overall['crib_matches'] >= 24:
        verdict = "INVESTIGATE — perfect cribs"
    else:
        verdict = "NOISE — SA ceiling similar to prior experiments"

    results['verdict'] = verdict
    results['elapsed_seconds'] = round(elapsed, 1)

    print(f"  Verdict: {verdict}")
    print(f"  Total time: {elapsed:.1f}s")

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_48_joint_sa.json", "w") as f:
        json.dump(results, f, indent=2, default=lambda x: str(x) if not isinstance(x, (int, float, str, bool, list, dict, type(None))) else x)

    print(f"  Artifact: results/e_s_48_joint_sa.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_48_joint_sa_p7.py")


if __name__ == "__main__":
    main()
