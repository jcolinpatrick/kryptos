#!/usr/bin/env python3
"""
E-S-49: Word-Segmentation SA — Period-7 Key + Transposition

KEY INSIGHT: E-S-48 showed quadgram SA produces gibberish artifacts that score
24/24 cribs + better-than-English quadgrams. This is because quadgrams measure
local character patterns, not actual words.

This experiment replaces quadgrams with dictionary-based word segmentation:
- DP finds optimal segmentation into real English words
- Longer words are weighted quadratically (wlen²) to penalize short-word cheating
- SA must now produce REAL ENGLISH WORDS, not just plausible character sequences

If the SA still finds coherent English with period-7 key + transposition, we
may have the real solution. If it produces high-scoring nonsense (like
"RATE OVER ATED"), the model needs more constraints.

Output: results/e_s_49_word_sa.json
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
        if 2 <= len(w) <= 20:  # skip single letters, cap at 20
            WORD_SET.add(w)
            if len(w) > MAX_WORD_LEN:
                MAX_WORD_LEN = len(w)
print(f"{len(WORD_SET)} words loaded (max len {MAX_WORD_LEN})")

# Precompute crib arrays
CRIB_LIST = sorted(CRIB_DICT.items())
CRIB_POS = [p for p, _ in CRIB_LIST]
CRIB_PT = [ALPH_IDX[c] for _, c in CRIB_LIST]
CRIB_BY_RESIDUE = defaultdict(list)
for p, c in CRIB_LIST:
    CRIB_BY_RESIDUE[p % 7].append((p, ALPH_IDX[c]))

CT_IDX = [ALPH_IDX[c] for c in CT]


def word_segmentation_score(pt_indices):
    """Score plaintext by dictionary word segmentation.

    Uses DP to find optimal segmentation. Longer words score quadratically more
    (wlen² per word found) to prevent gaming with short words.

    Returns (total_score, n_words, longest_word, coverage_frac, segmentation_str).
    """
    pt_str = ''.join(ALPH[x] for x in pt_indices)
    n = len(pt_str)

    # dp[i] = (best_score, n_words, longest_word, prev_index)
    dp_score = [0.0] * (n + 1)
    dp_words = [0] * (n + 1)
    dp_longest = [0] * (n + 1)
    dp_covered = [0] * (n + 1)  # characters covered by words
    dp_prev = [-1] * (n + 1)   # for backtracking

    for i in range(1, n + 1):
        # Default: skip this character (carry forward previous score)
        dp_score[i] = dp_score[i-1]
        dp_words[i] = dp_words[i-1]
        dp_longest[i] = dp_longest[i-1]
        dp_covered[i] = dp_covered[i-1]
        dp_prev[i] = i - 1

        # Try ending a word at position i
        max_wl = min(i, MAX_WORD_LEN)
        for wlen in range(2, max_wl + 1):
            word = pt_str[i-wlen:i]
            if word in WORD_SET:
                new_score = dp_score[i-wlen] + wlen * wlen
                if new_score > dp_score[i]:
                    dp_score[i] = new_score
                    dp_words[i] = dp_words[i-wlen] + 1
                    dp_longest[i] = max(dp_longest[i-wlen], wlen)
                    dp_covered[i] = dp_covered[i-wlen] + wlen
                    dp_prev[i] = i - wlen

    # Backtrack to find segmentation
    segments = []
    pos = n
    while pos > 0:
        prev = dp_prev[pos]
        if prev < pos - 1:  # a word was found
            segments.append(pt_str[prev:pos])
        elif prev == pos - 1:  # single char skipped
            segments.append(pt_str[prev:pos].lower())  # lowercase = not a word
        pos = prev
    segments.reverse()
    seg_str = '-'.join(segments)

    coverage = dp_covered[n] / n if n > 0 else 0.0

    return dp_score[n], dp_words[n], dp_longest[n], coverage, seg_str


def derive_key_model_a(perm):
    """Model A: period in PT space. key[r] = (CT[perm[p]] - PT[p]) % 26"""
    key = [None] * 7
    consistent = 0

    for r in range(7):
        cribs_r = CRIB_BY_RESIDUE[r]
        if not cribs_r:
            continue
        key_votes = defaultdict(int)
        for p, pt_idx in cribs_r:
            required_k = (CT_IDX[perm[p]] - pt_idx) % 26
            key_votes[required_k] += 1
        best_k = max(key_votes, key=key_votes.get)
        key[r] = best_k
        consistent += key_votes[best_k]

    for r in range(7):
        if key[r] is None:
            key[r] = 0

    return key, consistent


def derive_key_model_b(perm):
    """Model B: period in CT space. key[perm[p]%7] = (CT[perm[p]] - PT[p]) % 26"""
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
    pt = [0] * N
    for i in range(N):
        pt[i] = (CT_IDX[perm[i]] - key[i % 7]) % 26
    return pt


def decrypt_model_b(perm, key):
    pt = [0] * N
    for i in range(N):
        j = perm[i]
        pt[i] = (CT_IDX[j] - key[j % 7]) % 26
    return pt


def full_score(perm, model='A'):
    """Compute score using word segmentation + crib consistency."""
    if model == 'A':
        key, n_consistent = derive_key_model_a(perm)
        pt = decrypt_model_a(perm, key)
    else:
        key, n_consistent = derive_key_model_b(perm)
        pt = decrypt_model_b(perm, key)

    ws_score, n_words, longest, coverage, _ = word_segmentation_score(pt)

    # Combined: word segmentation + crib bonus
    # Scale: perfect English ~2500-4000 ws_score, 24 cribs × 30 = 720
    score = ws_score + n_consistent * 30.0

    return score, ws_score, n_consistent, n_words, longest, coverage, key, pt


def simulated_annealing(model, n_restarts=20, n_steps=200000, seed=42):
    """SA to find transposition σ that maximizes word segmentation score."""
    print(f"\n{'='*60}")
    print(f"SA: Model {model}, {n_restarts} restarts × {n_steps:,} steps")
    print(f"{'='*60}")

    random.seed(seed)
    t0 = time.time()

    global_best_score = -1e9
    global_best = None

    for restart in range(n_restarts):
        perm = list(range(N))
        random.shuffle(perm)

        score, ws, n_con, n_w, longest, cov, key, pt = full_score(perm, model)

        best_score = score
        best_perm = perm[:]
        best_ws = ws
        best_con = n_con
        best_nw = n_w
        best_longest = longest
        best_cov = cov
        best_key = key[:]
        best_pt = pt[:]

        T = 15.0
        T_min = 0.01
        alpha = (T_min / T) ** (1.0 / n_steps)

        for step in range(n_steps):
            # Mutation: swap two positions
            i, j = random.sample(range(N), 2)
            perm[i], perm[j] = perm[j], perm[i]

            new_score, new_ws, new_con, new_nw, new_longest, new_cov, new_key, new_pt = full_score(perm, model)

            delta = new_score - score
            if delta > 0 or random.random() < math.exp(delta / T):
                score = new_score
                if new_score > best_score:
                    best_score = new_score
                    best_perm = perm[:]
                    best_ws = new_ws
                    best_con = new_con
                    best_nw = new_nw
                    best_longest = new_longest
                    best_cov = new_cov
                    best_key = new_key[:]
                    best_pt = new_pt[:]
            else:
                perm[i], perm[j] = perm[j], perm[i]

            T *= alpha

            # Progress every 50K steps
            if (step + 1) % 50000 == 0:
                elapsed = time.time() - t0
                print(f"    R{restart:2d} step {step+1:,}: best_ws={best_ws:.0f} "
                      f"crib={best_con}/24 cov={best_cov:.1%} T={T:.4f} "
                      f"[{elapsed:.0f}s]", flush=True)

        pt_str = ''.join(ALPH[x] for x in best_pt)
        key_str = ''.join(ALPH[x] for x in best_key)

        # Get segmentation for display
        _, _, _, _, seg_str = word_segmentation_score(best_pt)

        print(f"  Restart {restart:2d}: ws={best_ws:.0f} crib={best_con}/24 "
              f"words={best_nw} longest={best_longest} cov={best_cov:.1%} "
              f"key={key_str}")
        if best_con >= 18:
            print(f"    SEG: {seg_str}")

        if best_score > global_best_score:
            global_best_score = best_score
            global_best = {
                'score': best_score,
                'ws_score': best_ws,
                'crib_matches': best_con,
                'n_words': best_nw,
                'longest_word': best_longest,
                'coverage': round(best_cov, 4),
                'key': best_key,
                'key_str': key_str,
                'pt': pt_str,
                'segmentation': seg_str,
                'perm': best_perm,
                'restart': restart,
            }

    elapsed = time.time() - t0
    print(f"\n  Global best: ws={global_best['ws_score']:.0f} "
          f"crib={global_best['crib_matches']}/24 "
          f"words={global_best['n_words']} longest={global_best['longest_word']} "
          f"cov={global_best['coverage']:.1%} key={global_best['key_str']}")
    print(f"  SEG: {global_best['segmentation']}")
    print(f"  Time: {elapsed:.1f}s")

    return global_best, elapsed


def baseline_word_scores():
    """Compute word segmentation scores for baselines."""
    print("\n" + "="*60)
    print("BASELINES: Word segmentation scores")
    print("="*60)

    import random as rng
    rng.seed(999)

    # Random text
    random_scores = []
    for _ in range(100):
        pt = [rng.randint(0, 25) for _ in range(N)]
        ws, nw, longest, cov, _ = word_segmentation_score(pt)
        random_scores.append((ws, cov))
    mean_ws = sum(s[0] for s in random_scores) / len(random_scores)
    mean_cov = sum(s[1] for s in random_scores) / len(random_scores)
    print(f"  Random text: ws={mean_ws:.1f} cov={mean_cov:.1%}")

    # English-like (from quadgram SA artifact)
    artifact = "RATEOVERATEDIERATENTREASTNORTHEASTATTHESTANTHRONATELLINETELLINEBERLINCLOCKINLANEMORIACEFORMACEFUL"
    art_idx = [ALPH_IDX[c] for c in artifact]
    ws, nw, longest, cov, seg = word_segmentation_score(art_idx)
    print(f"  E-S-48 artifact: ws={ws:.0f} cov={cov:.1%} words={nw} longest={longest}")
    print(f"    SEG: {seg}")

    # Actual English sample (from K1-K3 plaintexts)
    k1_pt = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABOREALANTHENYSIDIMENSION"
    k1_idx = [ALPH_IDX[c] for c in k1_pt[:N]]
    ws, nw, longest, cov, seg = word_segmentation_score(k1_idx)
    print(f"  K1 plaintext (truncated): ws={ws:.0f} cov={cov:.1%} words={nw} longest={longest}")
    print(f"    SEG: {seg}")

    # K2 plaintext
    k2_pt = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHERED"
    k2_idx = [ALPH_IDX[c] for c in k2_pt[:N]]
    ws, nw, longest, cov, seg = word_segmentation_score(k2_idx)
    print(f"  K2 plaintext (truncated): ws={ws:.0f} cov={cov:.1%} words={nw} longest={longest}")
    print(f"    SEG: {seg}")


def main():
    print("=" * 70)
    print("E-S-49: Word-Segmentation SA — Period-7 Key + Transposition")
    print("=" * 70)

    t0 = time.time()
    results = {'experiment': 'E-S-49'}

    # Baselines
    baseline_word_scores()

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
    print(f"  Model A: ws={best_a['ws_score']:.0f} crib={best_a['crib_matches']}/24 "
          f"cov={best_a['coverage']:.1%} words={best_a['n_words']} "
          f"longest={best_a['longest_word']} key={best_a['key_str']}")
    print(f"    SEG: {best_a['segmentation']}")
    print(f"  Model B: ws={best_b['ws_score']:.0f} crib={best_b['crib_matches']}/24 "
          f"cov={best_b['coverage']:.1%} words={best_b['n_words']} "
          f"longest={best_b['longest_word']} key={best_b['key_str']}")
    print(f"    SEG: {best_b['segmentation']}")

    # Verdict
    best = best_a if best_a['coverage'] > best_b['coverage'] else best_b
    if best['coverage'] > 0.85 and best['crib_matches'] >= 22:
        verdict = "INVESTIGATE — high word coverage + cribs"
    elif best['coverage'] > 0.70:
        verdict = "MARGINAL — decent coverage but check coherence"
    else:
        verdict = "NOISE — word segmentation can't overcome underdetermination"

    results['verdict'] = verdict
    results['elapsed_seconds'] = round(elapsed, 1)

    print(f"\n  Verdict: {verdict}")
    print(f"  Total time: {elapsed:.1f}s")

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_49_word_sa.json", "w") as f:
        json.dump(results, f, indent=2,
                  default=lambda x: str(x) if not isinstance(x, (int, float, str, bool, list, dict, type(None))) else x)

    print(f"  Artifact: results/e_s_49_word_sa.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_49_word_segmentation_sa.py")


if __name__ == "__main__":
    main()
