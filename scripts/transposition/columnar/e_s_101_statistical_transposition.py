#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-101: Statistical Transposition Detection

Key insight: Even after polyalphabetic substitution, the intermediate text
(before substitution, after transposition) preserves some statistical
properties. Specifically:

1. If the CORRECT transposition is applied, adjacent positions in the
   intermediate should show SOME English-like adjacency patterns
   (though weakened by substitution).

2. The IC of the intermediate = IC of the CT (transposition preserves IC).
   But BIGRAM frequencies differ — correct transposition should show
   higher bigram IC or better pattern matching.

Actually, a more robust approach: the PLAINTEXT (after full decryption)
should have higher-than-random English statistics. Without knowing the
substitution, we can use the following trick:

For each candidate transposition σ, compute I = σ(CT).
Check the IC of I — it should equal CT's IC (0.0361). ✓ by construction.

Better approach: ASSUME the substitution is simple (e.g., additive shift)
and check if the differential statistics of I reveal structure.

Most powerful approach: Given I = σ(CT) and knowing PT at 24 positions:
  The keystream k[j] = I[j] - PT[j] (mod 26) at crib positions.
  The IC of the keystream at non-crib positions can be estimated
  from the positions where we have data.

For a GOOD transposition with a low-entropy key:
  - Keystream should have lower entropy
  - Keystream values should cluster
  - IC of keystream should be higher

This is essentially what E-S-94 checked. Let me try something different:

APPROACH: Use the POSITIONAL pattern of the keystream.
For each transposition, the 24 keystream values come from 24 specific
positions in the 7-column grid. A "good" transposition should produce
keystream values that show column-level or row-level consistency.

This has been tested. Let me try yet another angle:

APPROACH: Use the DIFFERENTIAL IC.
For each σ, compute the difference sequence: d[j] = I[j] - I[j+1] mod 26.
For English text encrypted with a periodic key, the difference sequence
has different statistics than random. Specifically, the IC of the
difference sequence is related to the period.
"""

import json, os, time, math
from itertools import permutations
from collections import Counter

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
CT_N = [I2N[c] for c in CT]

CRIBS = {
    21:'E',22:'A',23:'S',24:'T',25:'N',26:'O',27:'R',28:'T',29:'H',30:'E',31:'A',32:'S',33:'T',
    63:'B',64:'E',65:'R',66:'L',67:'I',68:'N',69:'C',70:'L',71:'O',72:'C',73:'K'}
PT_FULL = {p: I2N[c] for p, c in CRIBS.items()}
CPOS = sorted(CRIBS.keys())

W = 7

# English letter frequencies (for log-likelihood)
ENGLISH_FREQ = [0.0817,0.0149,0.0278,0.0425,0.127,0.0223,0.0202,0.0609,0.0697,0.0015,0.0077,
                0.0403,0.0241,0.0675,0.0751,0.0193,0.001,0.0599,0.0633,0.0906,0.0276,0.0098,
                0.0236,0.0015,0.0197,0.0007]

# English bigram frequencies (approximate, top 20)
COMMON_BIGRAMS = {
    (19,7):0.035, (7,4):0.030, (8,13):0.023, (4,17):0.021, (0,13):0.020,
    (17,4):0.019, (14,13):0.018, (0,19):0.017, (4,13):0.017, (13,3):0.016,
    (18,19):0.016, (4,18):0.016, (14,17):0.015, (19,4):0.015, (14,5):0.014,
    (4,3):0.014, (8,18):0.013, (8,19):0.013, (0,11):0.013, (0,17):0.012,
}


def build_perm(order, w=W):
    nr = (N + w - 1) // w
    ns = nr * w - N
    p = []
    for k in range(w):
        c = order[k]
        sz = nr - 1 if c >= w - ns else nr
        for r in range(sz):
            p.append(r * w + c)
    return p


def bigram_score(text_nums):
    """Score based on English-like bigram frequencies."""
    score = 0.0
    for i in range(len(text_nums) - 1):
        bg = (text_nums[i], text_nums[i+1])
        if bg in COMMON_BIGRAMS:
            score += COMMON_BIGRAMS[bg]
    return score


def differential_ic(text_nums):
    """IC of the first-difference sequence."""
    diffs = [(text_nums[i+1] - text_nums[i]) % 26 for i in range(len(text_nums)-1)]
    freq = Counter(diffs)
    n = len(diffs)
    if n <= 1:
        return 0
    return sum(f*(f-1) for f in freq.values()) / (n*(n-1))


def log_likelihood(text_nums):
    """Log-likelihood under English unigram model."""
    return sum(math.log(ENGLISH_FREQ[c] + 1e-10) for c in text_nums)


print("=" * 70)
print("E-S-101: Statistical Transposition Detection")
print(f"  N={N}, W={W}")
print("=" * 70)

t0 = time.time()

# ── Phase 1: Bigram score for w7 columnar orderings ──────────────────
print("\n--- P1: Bigram score of intermediate text (w7 columnar) ---")

ORDERS = [list(o) for o in permutations(range(W))]
PERMS = [build_perm(o) for o in ORDERS]

bg_scores = []
for oi in range(len(ORDERS)):
    perm = PERMS[oi]
    intermed = [CT_N[perm[j]] for j in range(N)]
    bg = bigram_score(intermed)
    bg_scores.append((bg, oi))

# Also compute for CT itself (identity permutation)
ct_bg = bigram_score(CT_N)
ct_dic = differential_ic(CT_N)
ct_ll = log_likelihood(CT_N)

bg_scores.sort(reverse=True)
print(f"  CT (no transposition): bigram={ct_bg:.4f}, diff_IC={ct_dic:.4f}, loglik={ct_ll:.1f}")

print(f"\n  Top 10 orderings by bigram score:")
for bg, oi in bg_scores[:10]:
    perm = PERMS[oi]
    intermed = [CT_N[perm[j]] for j in range(N)]
    dic = differential_ic(intermed)
    ll = log_likelihood(intermed)
    print(f"    order={ORDERS[oi]} bg={bg:.4f} dic={dic:.4f} ll={ll:.1f}")

print(f"\n  Bottom 3:")
for bg, oi in bg_scores[-3:]:
    print(f"    order={ORDERS[oi]} bg={bg:.4f}")

# Statistics
all_bg = [s for s, _ in bg_scores]
mean_bg = sum(all_bg) / len(all_bg)
std_bg = (sum((s - mean_bg)**2 for s in all_bg) / len(all_bg)) ** 0.5
print(f"\n  Bigram stats: mean={mean_bg:.4f}, std={std_bg:.4f}")
print(f"  CT score: z={(ct_bg - mean_bg) / std_bg:.2f}")
print(f"  Top score: z={(bg_scores[0][0] - mean_bg) / std_bg:.2f}")

# Expected: if a correct transposition exists, its bigram score should
# be significantly above mean. If all scores are similar, the intermediate
# text is too well-mixed for bigram detection.


# ── Phase 2: Differential IC for w7 orderings ────────────────────────
print("\n--- P2: Differential IC (w7 columnar) ---")

dic_scores = []
for oi in range(len(ORDERS)):
    perm = PERMS[oi]
    intermed = [CT_N[perm[j]] for j in range(N)]
    dic = differential_ic(intermed)
    dic_scores.append((dic, oi))

dic_scores.sort(reverse=True)
print(f"  Top 10 by differential IC:")
for dic, oi in dic_scores[:10]:
    print(f"    order={ORDERS[oi]} dic={dic:.4f}")

all_dic = [s for s, _ in dic_scores]
mean_dic = sum(all_dic) / len(all_dic)
std_dic = (sum((s - mean_dic)**2 for s in all_dic) / len(all_dic)) ** 0.5
print(f"\n  Diff IC stats: mean={mean_dic:.4f}, std={std_dic:.4f}")
print(f"  Top: z={(dic_scores[0][0] - mean_dic) / std_dic:.2f}")

# For English first-differences, expected IC ≈ 0.045 (higher than random 0.038)
# For random text, diff IC ≈ 0.038
# For polyalphabetic cipher output, diff IC depends on cipher type
print(f"  Expected: English diff IC ≈ 0.045, random ≈ 0.038")


# ── Phase 3: Cross-validate top candidates ────────────────────────────
print("\n--- P3: Cross-validation of top orderings ---")

# Get orderings that appear in top 50 for both bigram and diff IC
top_bg_set = set(oi for _, oi in bg_scores[:50])
top_dic_set = set(oi for _, oi in dic_scores[:50])
overlap = top_bg_set & top_dic_set

print(f"  Top-50 bigram ∩ top-50 diff_IC: {len(overlap)} orderings")

# Also get top 50 for log-likelihood
ll_scores = []
for oi in range(len(ORDERS)):
    perm = PERMS[oi]
    intermed = [CT_N[perm[j]] for j in range(N)]
    ll = log_likelihood(intermed)
    ll_scores.append((ll, oi))
ll_scores.sort(reverse=True)

top_ll_set = set(oi for _, oi in ll_scores[:50])
triple_overlap = top_bg_set & top_dic_set & top_ll_set

print(f"  Triple overlap (bg ∩ dic ∩ ll): {len(triple_overlap)} orderings")

if triple_overlap:
    print(f"\n  Triple-overlap orderings:")
    for oi in sorted(triple_overlap):
        bg = next(s for s, i in bg_scores if i == oi)
        dic = next(s for s, i in dic_scores if i == oi)
        ll = next(s for s, i in ll_scores if i == oi)
        print(f"    order={ORDERS[oi]} bg={bg:.4f} dic={dic:.4f} ll={ll:.1f}")


# ── Phase 4: Test other transposition widths ──────────────────────────
print("\n--- P4: Bigram/DIC for other widths ---")

for w in [5, 6, 8, 9, 10]:
    all_orders_w = list(permutations(range(w)))
    if len(all_orders_w) > 10000:
        import random
        random.seed(42)
        all_orders_w = random.sample(all_orders_w, 10000)

    bg_list = []
    for order in all_orders_w:
        perm = build_perm(list(order), w)
        intermed = [CT_N[perm[j]] for j in range(N)]
        bg = bigram_score(intermed)
        bg_list.append(bg)

    mean_w = sum(bg_list) / len(bg_list)
    std_w = (sum((s - mean_w)**2 for s in bg_list) / len(bg_list)) ** 0.5
    max_w = max(bg_list)
    print(f"  Width {w}: mean bg={mean_w:.4f}, std={std_w:.4f}, max={max_w:.4f}, "
          f"max z={(max_w - mean_w) / std_w if std_w > 0 else 0:.2f}")


# ── Phase 5: Decimation ──────────────────────────────────────────────
print("\n--- P5: Bigram/DIC for decimation ---")

dec_scores = []
for d in range(1, N):
    perm = [(j * d) % N for j in range(N)]
    intermed = [CT_N[perm[j]] for j in range(N)]
    bg = bigram_score(intermed)
    dic = differential_ic(intermed)
    dec_scores.append((bg, dic, d))

dec_scores.sort(key=lambda x: x[0], reverse=True)
print(f"  Top 5 decimation steps by bigram:")
for bg, dic, d in dec_scores[:5]:
    print(f"    d={d}: bg={bg:.4f}, dic={dic:.4f}")


# ── Summary ───────────────────────────────────────────────────────────
total_elapsed = time.time() - t0

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print(f"  Width-7 bigram: top z={(bg_scores[0][0] - mean_bg) / std_bg:.2f}")
print(f"  Width-7 diff IC: top z={(dic_scores[0][0] - mean_dic) / std_dic:.2f}")
print(f"  Triple overlap (top-50): {len(triple_overlap)}")
print(f"  Total: {total_elapsed:.1f}s")

# If the top z-scores are < 3, the statistical signal is too weak
# to identify the correct transposition from statistics alone.
top_z = max((bg_scores[0][0] - mean_bg) / std_bg,
            (dic_scores[0][0] - mean_dic) / std_dic)
if top_z >= 3:
    print(f"\n  Verdict: POSSIBLE SIGNAL (z={top_z:.2f})")
else:
    print(f"\n  Verdict: NO CLEAR SIGNAL (top z={top_z:.2f})")

os.makedirs("results", exist_ok=True)
out = {
    'experiment': 'E-S-101',
    'description': 'Statistical transposition detection',
    'top_bigram_z': (bg_scores[0][0] - mean_bg) / std_bg,
    'top_dic_z': (dic_scores[0][0] - mean_dic) / std_dic,
    'triple_overlap': len(triple_overlap),
    'elapsed_seconds': total_elapsed,
}
with open("results/e_s_101_statistical_transposition.json", "w") as f:
    json.dump(out, f, indent=2, default=str)
print(f"\n  Artifact: results/e_s_101_statistical_transposition.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_101_statistical_transposition.py")
