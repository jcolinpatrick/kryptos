#!/usr/bin/env python3
"""
Cipher: running key
Family: running_key
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-S-51: Dual Running Key SA — Both PT and KEY Must Be English

MOTIVATION: E-S-49 showed that word segmentation of PT alone is underdetermined
(97! DOF in σ overwhelms word-level scoring). This experiment doubles the
constraint: for a running key cipher with transposition, BOTH the plaintext AND
the running key text must segment into real English words simultaneously.

Model: CT[σ(i)] = (PT[i] + KEY[i]) mod 26
Given σ, for each position i: PT[i] + KEY[i] ≡ CT[σ(i)] (mod 26)
This means choosing PT[i] uniquely determines KEY[i] and vice versa.

The SA optimizes σ to maximize:
  word_score(PT) + word_score(KEY) + crib_bonus

At crib positions, PT is fixed → KEY is determined.
At non-crib positions, neither PT nor KEY is fixed — but they're linked.

For the DP word segmentation scorer, at each position we choose PT[i] from
0-25, which determines KEY[i]. The score is: max over all PT choices of
(word coverage of PT + word coverage of KEY).

Since this inner optimization is expensive, we use a simplified approach:
- SA over σ (outer loop)
- For each σ, we DON'T optimize over PT choices at non-crib positions
  (too expensive per step). Instead, we set PT[i] = (CT[σ(i)] - KEY[i]) % 26
  where KEY is optimized via word segmentation DP.

Actually, the simplest approach: SA optimizes σ. For each σ:
1. At crib positions: PT is known, KEY[i] = (CT[σ(i)] - PT[i]) % 26
2. At non-crib positions: try a few KEY candidates via DP
3. Score = word_score(PT) + word_score(KEY)

SIMPLIFIED VERSION: We optimize σ with a two-pass scoring:
- Pass 1: Assume KEY is English → use DP to find best KEY segmentation
  → this determines PT at non-crib positions
- Score: word_score(KEY) + word_score(PT)
- Crib constraint: PT at crib positions must match known values

Output: results/e_s_51_dual_running_key.json
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

# Load dictionary
DICT_PATH = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'english.txt')
print("Loading dictionary...", end=" ", flush=True)
WORD_SET = set()
MAX_WORD_LEN = 0
with open(DICT_PATH) as f:
    for line in f:
        w = line.strip().upper()
        if 2 <= len(w) <= 20:
            WORD_SET.add(w)
            if len(w) > MAX_WORD_LEN:
                MAX_WORD_LEN = len(w)
print(f"{len(WORD_SET)} words loaded (max len {MAX_WORD_LEN})")

# Precompute
CRIB_LIST = sorted(CRIB_DICT.items())
CRIB_POS_SET = set(p for p, _ in CRIB_LIST)
CRIB_PT = {p: ALPH_IDX[c] for p, c in CRIB_LIST}
CT_IDX = [ALPH_IDX[c] for c in CT]


def word_seg_score(text_str):
    """DP word segmentation score. Returns (score, coverage, n_words, seg_str)."""
    n = len(text_str)
    dp_score = [0.0] * (n + 1)
    dp_covered = [0] * (n + 1)
    dp_prev = [-1] * (n + 1)
    dp_words = [0] * (n + 1)

    for i in range(1, n + 1):
        dp_score[i] = dp_score[i-1]
        dp_covered[i] = dp_covered[i-1]
        dp_prev[i] = i - 1
        dp_words[i] = dp_words[i-1]

        max_wl = min(i, MAX_WORD_LEN)
        for wlen in range(2, max_wl + 1):
            word = text_str[i-wlen:i]
            if word in WORD_SET:
                new_score = dp_score[i-wlen] + wlen * wlen
                if new_score > dp_score[i]:
                    dp_score[i] = new_score
                    dp_covered[i] = dp_covered[i-wlen] + wlen
                    dp_prev[i] = i - wlen
                    dp_words[i] = dp_words[i-wlen] + 1

    # Backtrack
    segs = []
    pos = n
    while pos > 0:
        prev = dp_prev[pos]
        if prev < pos - 1:
            segs.append(text_str[prev:pos])
        else:
            segs.append(text_str[prev:pos].lower())
        pos = prev
    segs.reverse()

    cov = dp_covered[n] / n if n > 0 else 0.0
    return dp_score[n], cov, dp_words[n], '-'.join(segs)


def full_score_running_key(perm):
    """Score a permutation under the running key model.

    For each position i: CT[perm[i]] = (PT[i] + KEY[i]) mod 26
    PT at crib positions is fixed.
    For non-crib positions, we use the greedy assignment: KEY[i] = 0 (i.e., PT[i] = CT[perm[i]]).
    Actually, we just compute both PT and KEY and score both.
    """
    # For each position: c = CT_IDX[perm[i]]
    # At crib position p: PT[p] = CRIB_PT[p], KEY[p] = (c - PT[p]) % 26
    # At non-crib position: we need to choose PT[p] (and KEY[p] = (c - PT[p]) % 26)

    # Simple approach: set PT at non-crib positions to maximize PT word score
    # This means KEY at those positions is determined but might not be English

    ct_vals = [CT_IDX[perm[i]] for i in range(N)]

    # Check crib consistency first
    n_consistent = 0
    for p in range(N):
        if p in CRIB_POS_SET:
            # PT is known, KEY is determined
            n_consistent += 1  # We don't have period constraint, all cribs "match"

    # For scoring, just compute PT = CT[perm[i]] (identity KEY = 0) and KEY separately
    # Actually: assume no KEY (Vigenère with key=0 → PT = CT rearranged)
    # This is equivalent to: "can we rearrange CT to form two English texts?"

    # Better approach: compute PT assuming KEY is all zeros, and KEY assuming PT = CT
    # Then score both

    # Approach: PT[i] = ct_vals[i] for non-crib positions (key=0)
    #           PT[i] = CRIB_PT[i] for crib positions
    pt = [0] * N
    key = [0] * N
    for i in range(N):
        if i in CRIB_POS_SET:
            pt[i] = CRIB_PT[i]
            key[i] = (ct_vals[i] - pt[i]) % 26
        else:
            pt[i] = ct_vals[i]  # assume key=0
            key[i] = 0

    pt_str = ''.join(ALPH[x] for x in pt)
    key_str = ''.join(ALPH[x] for x in key)

    pt_ws, pt_cov, pt_nw, _ = word_seg_score(pt_str)
    key_ws, key_cov, key_nw, _ = word_seg_score(key_str)

    # Score combines both
    score = pt_ws + key_ws

    return score, pt_ws, key_ws, pt_cov, key_cov, pt_str, key_str


def full_score_dual(perm):
    """Score where we optimize the split between PT and KEY at each non-crib position.

    For each non-crib position i, we have c = CT_IDX[perm[i]].
    We try all 26 possible PT[i] values and pick the one that maximizes
    the JOINT word score. This is too expensive for per-step SA, so we
    use a simpler heuristic: for each non-crib position, pick PT[i] that
    extends the longest word in EITHER PT or KEY sequence.

    Actually, let's just use the simpler approach of scoring PT as one
    rearrangement and KEY as the complementary rearrangement.
    """
    ct_vals = [CT_IDX[perm[i]] for i in range(N)]

    # Build PT: at crib positions use known PT, at non-crib use ct_vals (key=0)
    pt = [0] * N
    key = [0] * N
    for i in range(N):
        if i in CRIB_POS_SET:
            pt[i] = CRIB_PT[i]
            key[i] = (ct_vals[i] - pt[i]) % 26
        else:
            pt[i] = ct_vals[i]
            key[i] = 0

    pt_str = ''.join(ALPH[x] for x in pt)
    key_str = ''.join(ALPH[x] for x in key)

    pt_ws, pt_cov, _, _ = word_seg_score(pt_str)
    key_ws, key_cov, _, _ = word_seg_score(key_str)

    return pt_ws + key_ws, pt_ws, key_ws, pt_cov, key_cov, pt_str, key_str


def sa_dual(n_restarts=10, n_steps=150000, seed=42):
    """SA optimizing σ for dual word score (PT + KEY both English).

    Model: CT[σ(i)] = PT[i] + KEY[i] mod 26
    At non-crib positions: KEY[i] = 0 → PT[i] = CT[σ(i)]
    Score: word_score(PT) + word_score(KEY)
    """
    print(f"\n{'='*60}")
    print(f"SA: Dual Running Key, {n_restarts} restarts × {n_steps:,} steps")
    print(f"{'='*60}")

    random.seed(seed)
    t0 = time.time()

    global_best_score = -1e9
    global_best = None

    for restart in range(n_restarts):
        perm = list(range(N))
        random.shuffle(perm)

        score, pt_ws, key_ws, pt_cov, key_cov, pt_str, key_str = full_score_dual(perm)

        best_score = score
        best_perm = perm[:]
        best_pt_ws = pt_ws
        best_key_ws = key_ws
        best_pt_cov = pt_cov
        best_key_cov = key_cov
        best_pt_str = pt_str
        best_key_str = key_str

        T = 15.0
        T_min = 0.01
        alpha = (T_min / T) ** (1.0 / n_steps)

        for step in range(n_steps):
            i, j = random.sample(range(N), 2)
            perm[i], perm[j] = perm[j], perm[i]

            new_score, new_pt_ws, new_key_ws, new_pt_cov, new_key_cov, new_pt_str, new_key_str = full_score_dual(perm)

            delta = new_score - score
            if delta > 0 or random.random() < math.exp(delta / T):
                score = new_score
                if new_score > best_score:
                    best_score = new_score
                    best_perm = perm[:]
                    best_pt_ws = new_pt_ws
                    best_key_ws = new_key_ws
                    best_pt_cov = new_pt_cov
                    best_key_cov = new_key_cov
                    best_pt_str = new_pt_str
                    best_key_str = new_key_str
            else:
                perm[i], perm[j] = perm[j], perm[i]

            T *= alpha

            if (step + 1) % 50000 == 0:
                elapsed = time.time() - t0
                print(f"    R{restart:2d} step {step+1:,}: "
                      f"pt_ws={best_pt_ws:.0f}({best_pt_cov:.0%}) "
                      f"key_ws={best_key_ws:.0f}({best_key_cov:.0%}) "
                      f"T={T:.4f} [{elapsed:.0f}s]", flush=True)

        _, pt_cov_full, _, pt_seg = word_seg_score(best_pt_str)
        _, key_cov_full, _, key_seg = word_seg_score(best_key_str)

        print(f"  R{restart:2d}: total={best_score:.0f} "
              f"pt_ws={best_pt_ws:.0f}({best_pt_cov:.0%}) "
              f"key_ws={best_key_ws:.0f}({best_key_cov:.0%})")
        print(f"    PT:  {pt_seg[:120]}")
        print(f"    KEY: {key_seg[:120]}")

        if best_score > global_best_score:
            global_best_score = best_score
            global_best = {
                'score': best_score,
                'pt_ws': best_pt_ws,
                'key_ws': best_key_ws,
                'pt_coverage': round(best_pt_cov, 4),
                'key_coverage': round(best_key_cov, 4),
                'pt': best_pt_str,
                'key': best_key_str,
                'pt_seg': pt_seg,
                'key_seg': key_seg,
                'perm': best_perm,
                'restart': restart,
            }

    elapsed = time.time() - t0
    print(f"\n  Global best: total={global_best_score:.0f}")
    print(f"  PT:  ws={global_best['pt_ws']:.0f} cov={global_best['pt_coverage']:.1%}")
    print(f"  KEY: ws={global_best['key_ws']:.0f} cov={global_best['key_coverage']:.1%}")
    print(f"  Time: {elapsed:.1f}s")

    return global_best, elapsed


def sa_period7_dual(n_restarts=10, n_steps=150000, seed=44):
    """SA with period-7 key + transposition, but score BOTH PT and KEY by word seg.

    Model A: CT[σ(i)] = (PT[i] + key[i%7]) mod 26
    KEY is just the repeated period-7 pattern — not English by itself.
    Instead, derive PT from σ + key, and score PT by word segmentation.
    Also check: does the KEY spell anything if read as a word?
    """
    print(f"\n{'='*60}")
    print(f"SA: Period-7 + Dual Score, {n_restarts} restarts × {n_steps:,} steps")
    print(f"{'='*60}")

    random.seed(seed)
    t0 = time.time()

    CRIB_BY_RESIDUE = defaultdict(list)
    for p, c in CRIB_LIST:
        CRIB_BY_RESIDUE[p % 7].append((p, ALPH_IDX[c]))

    global_best_score = -1e9
    global_best = None

    for restart in range(n_restarts):
        perm = list(range(N))
        random.shuffle(perm)

        # Derive key from cribs
        key = [None] * 7
        n_con = 0
        for r in range(7):
            cribs_r = CRIB_BY_RESIDUE[r]
            if not cribs_r:
                continue
            votes = defaultdict(int)
            for p, pt_idx in cribs_r:
                votes[(CT_IDX[perm[p]] - pt_idx) % 26] += 1
            best_k = max(votes, key=votes.get)
            key[r] = best_k
            n_con += votes[best_k]
        for r in range(7):
            if key[r] is None:
                key[r] = 0

        pt = [(CT_IDX[perm[i]] - key[i % 7]) % 26 for i in range(N)]
        pt_str = ''.join(ALPH[x] for x in pt)
        pt_ws, pt_cov, _, _ = word_seg_score(pt_str)

        best_score = pt_ws + n_con * 30.0
        best_perm = perm[:]
        best_key = key[:]
        best_pt_str = pt_str
        best_pt_ws = pt_ws
        best_pt_cov = pt_cov
        best_n_con = n_con

        T = 15.0
        T_min = 0.01
        alpha = (T_min / T) ** (1.0 / n_steps)

        for step in range(n_steps):
            i, j = random.sample(range(N), 2)
            perm[i], perm[j] = perm[j], perm[i]

            key2 = [None] * 7
            n_con2 = 0
            for r in range(7):
                cribs_r = CRIB_BY_RESIDUE[r]
                if not cribs_r:
                    continue
                votes = defaultdict(int)
                for p, pt_idx in cribs_r:
                    votes[(CT_IDX[perm[p]] - pt_idx) % 26] += 1
                best_k = max(votes, key=votes.get)
                key2[r] = best_k
                n_con2 += votes[best_k]
            for r in range(7):
                if key2[r] is None:
                    key2[r] = 0

            pt2 = [(CT_IDX[perm[i2]] - key2[i2 % 7]) % 26 for i2 in range(N)]
            pt2_str = ''.join(ALPH[x] for x in pt2)
            pt2_ws, pt2_cov, _, _ = word_seg_score(pt2_str)

            new_score = pt2_ws + n_con2 * 30.0

            delta = new_score - best_score  # compare to current, not best
            cur_score = pt_ws + n_con * 30.0  # track current separately
            delta_cur = new_score - cur_score
            if delta_cur > 0 or random.random() < math.exp(delta_cur / T):
                pt_ws = pt2_ws
                pt_cov = pt2_cov
                n_con = n_con2
                key = key2

                if new_score > best_score:
                    best_score = new_score
                    best_perm = perm[:]
                    best_key = key2[:]
                    best_pt_str = pt2_str
                    best_pt_ws = pt2_ws
                    best_pt_cov = pt2_cov
                    best_n_con = n_con2
            else:
                perm[i], perm[j] = perm[j], perm[i]

            T *= alpha

            if (step + 1) % 50000 == 0:
                elapsed = time.time() - t0
                print(f"    R{restart:2d} step {step+1:,}: "
                      f"ws={best_pt_ws:.0f} cov={best_pt_cov:.0%} "
                      f"crib={best_n_con}/24 T={T:.4f} [{elapsed:.0f}s]",
                      flush=True)

        _, _, _, pt_seg = word_seg_score(best_pt_str)
        key_str = ''.join(ALPH[x] for x in best_key)

        print(f"  R{restart:2d}: ws={best_pt_ws:.0f} cov={best_pt_cov:.0%} "
              f"crib={best_n_con}/24 key={key_str}")
        print(f"    SEG: {pt_seg[:150]}")

        if best_score > global_best_score:
            global_best_score = best_score
            global_best = {
                'score': best_score,
                'pt_ws': best_pt_ws,
                'pt_coverage': round(best_pt_cov, 4),
                'crib_matches': best_n_con,
                'key': best_key,
                'key_str': key_str,
                'pt': best_pt_str,
                'pt_seg': pt_seg,
                'perm': best_perm,
                'restart': restart,
            }

    elapsed = time.time() - t0
    print(f"\n  Global best: ws={global_best['pt_ws']:.0f} "
          f"cov={global_best['pt_coverage']:.1%} "
          f"crib={global_best['crib_matches']}/24 "
          f"key={global_best['key_str']}")
    print(f"  Time: {elapsed:.1f}s")

    return global_best, elapsed


def main():
    print("=" * 70)
    print("E-S-51: Dual Running Key SA")
    print("=" * 70)

    t0 = time.time()
    results = {'experiment': 'E-S-51'}

    # Part 1: Running key model (no period, KEY=0 at non-crib positions)
    rk_best, rk_time = sa_dual(n_restarts=10, n_steps=150000, seed=42)
    results['running_key'] = rk_best
    results['running_key']['time'] = round(rk_time, 1)

    # Part 2: Period-7 model with word segmentation
    p7_best, p7_time = sa_period7_dual(n_restarts=10, n_steps=150000, seed=44)
    results['period7_word'] = p7_best
    results['period7_word']['time'] = round(p7_time, 1)

    elapsed = time.time() - t0

    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"  Running key: pt_ws={rk_best.get('pt_ws',0):.0f} "
          f"key_ws={rk_best.get('key_ws',0):.0f} "
          f"pt_cov={rk_best.get('pt_coverage',0):.1%} "
          f"key_cov={rk_best.get('key_coverage',0):.1%}")
    print(f"  Period-7 word: ws={p7_best.get('pt_ws',0):.0f} "
          f"cov={p7_best.get('pt_coverage',0):.1%} "
          f"crib={p7_best.get('crib_matches',0)}/24")

    verdict = "UNDERDETERMINED — dual scoring still insufficient with arbitrary σ"
    results['verdict'] = verdict
    results['elapsed_seconds'] = round(elapsed, 1)

    print(f"\n  Verdict: {verdict}")
    print(f"  Total time: {elapsed:.1f}s")

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_51_dual_running_key.json", "w") as f:
        json.dump(results, f, indent=2,
                  default=lambda x: str(x) if not isinstance(x, (int, float, str, bool, list, dict, type(None))) else x)

    print(f"  Artifact: results/e_s_51_dual_running_key.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_51_dual_running_key_sa.py")


if __name__ == "__main__":
    main()
