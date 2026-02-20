#!/usr/bin/env python3
"""E-S-109: Deep Analysis of Top Statistically-Ranked Orderings.

E-S-108 found differential IC z=5.54 for ordering [6,1,2,0,4,5,3] — the
strongest statistical signal for ordering identification across all experiments.

This experiment:
1. For each top-10 diff_ic ordering, compute the full crib-derived keystream
   under Vig/Beau/VBeau and analyze for patterns
2. Check if any ordering produces a keystream with structure:
   - Periodic sub-patterns within each column
   - Arithmetic progressions
   - Readability as text
   - Known keyword alignment
3. For the most promising orderings, attempt SA to fill in the 73 unknown
   key positions using quadgram scoring
4. Test width-14 orderings (since 14=2×7 could explain lag-7)
5. Cross-check: does the top diff_ic ordering also produce sensible
   plaintext when combined with known-keyword substitution?

Output: results/e_s_109_top_ordering_analysis.json
"""
import json
import math
import time
import sys
import os
import random
from collections import Counter
from itertools import permutations

sys.path.insert(0, "src")
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
)

CT_IDX = [ALPH_IDX[c] for c in CT]
PT_AT_CRIB = {p: ALPH_IDX[ch] for p, ch in CRIB_DICT.items()}
CRIB_POS = sorted(CRIB_POSITIONS)
N = CT_LEN
WIDTH = 7
NROWS = N // WIDTH  # 13
EXTRA = N % WIDTH   # 6

# Load quadgrams
QG_FLOOR = -10.0
QG_TABLE = [QG_FLOOR] * (26 ** 4)
with open("data/english_quadgrams.json") as f:
    qg_data = json.load(f)
for gram, logp in qg_data.items():
    if len(gram) == 4 and all(c in ALPH_IDX for c in gram):
        a, b, c, d = ALPH_IDX[gram[0]], ALPH_IDX[gram[1]], ALPH_IDX[gram[2]], ALPH_IDX[gram[3]]
        QG_TABLE[a * 17576 + b * 676 + c * 26 + d] = logp


def qg_score(text_idx):
    """Quadgram log-probability per character."""
    total = 0.0
    for i in range(len(text_idx) - 3):
        total += QG_TABLE[text_idx[i]*17576 + text_idx[i+1]*676 + text_idx[i+2]*26 + text_idx[i+3]]
    return total / max(1, len(text_idx) - 3)


def build_columnar_perm(order, width=WIDTH, n=N):
    w = width
    nf = n // w
    extra = n % w
    heights = [nf + (1 if c < extra else 0) for c in range(w)]
    perm = []
    for rank in range(w):
        col = order[rank]
        for row in range(heights[col]):
            perm.append(row * w + col)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def derive_keystream(order, variant="vig"):
    """Derive keystream at crib positions under Model B.

    Model B: CT[i] = Sub(intermediate[i], key[i])
    intermediate = columnar_trans(PT)

    perm[ct_pos] = pt_pos (gather)
    inv_perm[pt_pos] = ct_pos

    At crib pt_pos: key[ct_pos] = f(CT[ct_pos], PT[pt_pos])
    """
    perm = build_columnar_perm(order)
    inv = invert_perm(perm)

    keystream = {}  # ct_pos → key_value
    for pt_pos in CRIB_POS:
        ct_pos = inv[pt_pos]
        pt_val = PT_AT_CRIB[pt_pos]
        ct_val = CT_IDX[ct_pos]
        if variant == "vig":
            k = (ct_val - pt_val) % MOD
        elif variant == "beau":
            k = (ct_val + pt_val) % MOD
        else:  # vbeau
            k = (pt_val - ct_val) % MOD
        keystream[ct_pos] = k
    return keystream


def analyze_keystream(keystream, label=""):
    """Analyze a sparse keystream for patterns."""
    positions = sorted(keystream.keys())
    values = [keystream[p] for p in positions]
    text = ''.join(ALPH[v] for v in values)

    # Check if values are readable
    analysis = {"text": text, "values": values, "positions": positions}

    # Check periodicity within columns
    # Under width-7 columnar, CT positions within a column are contiguous
    # Column heights: cols 0-5 have 14, col 6 has 13
    # With ordering, column c occupies positions starting at some offset

    # Check for simple arithmetic patterns in the values
    diffs = [(values[i+1] - values[i]) % MOD for i in range(len(values)-1)]
    analysis["diffs"] = diffs
    diff_counter = Counter(diffs)
    analysis["most_common_diff"] = diff_counter.most_common(3)

    # Check for periodicity in values
    for p in range(2, 13):
        consistent = 0
        total = 0
        for i in range(len(values)):
            for j in range(i+1, len(values)):
                if (positions[j] - positions[i]) % p == 0:
                    total += 1
                    if values[i] == values[j]:
                        consistent += 1
        if total > 0:
            analysis[f"period_{p}_consistency"] = f"{consistent}/{total}"

    # Check Bean equality: key[27] = key[65] (in PT space) under this ordering
    # Under Model B with transposition, CT positions of PT[27] and PT[65] differ

    return analysis


def sa_fill_key(order, variant="vig", n_restarts=5, steps=100000, seed=42):
    """SA to fill in the 73 unknown key positions, maximizing quadgram score.

    Fixed: 24 known key values at crib-derived positions.
    Free: 73 unknown key values.
    """
    rng = random.Random(seed)
    perm = build_columnar_perm(order)
    inv = invert_perm(perm)

    # Derive fixed key values from cribs
    fixed_keys = {}
    for pt_pos in CRIB_POS:
        ct_pos = inv[pt_pos]
        pt_val = PT_AT_CRIB[pt_pos]
        ct_val = CT_IDX[ct_pos]
        if variant == "vig":
            k = (ct_val - pt_val) % MOD
        elif variant == "beau":
            k = (ct_val + pt_val) % MOD
        else:
            k = (pt_val - ct_val) % MOD
        fixed_keys[ct_pos] = k

    free_positions = [i for i in range(N) if i not in fixed_keys]

    def decrypt_with_key(key):
        if variant == "vig":
            intermediate = [(CT_IDX[i] - key[i]) % MOD for i in range(N)]
        elif variant == "beau":
            intermediate = [(key[i] - CT_IDX[i]) % MOD for i in range(N)]
        else:
            intermediate = [(CT_IDX[i] + key[i]) % MOD for i in range(N)]
        # Un-transpose
        pt = [0] * N
        for ct_pos in range(N):
            pt[perm[ct_pos]] = intermediate[ct_pos]
        return pt

    best_score = -999
    best_pt = None
    best_key = None

    for restart in range(n_restarts):
        # Random initial key
        key = [0] * N
        for pos in range(N):
            if pos in fixed_keys:
                key[pos] = fixed_keys[pos]
            else:
                key[pos] = rng.randint(0, 25)

        pt = decrypt_with_key(key)
        current_score = qg_score(pt)

        temp = 2.0
        for step in range(steps):
            # Mutate a random free position
            pos = free_positions[rng.randint(0, len(free_positions)-1)]
            old_val = key[pos]
            new_val = rng.randint(0, 25)
            if new_val == old_val:
                new_val = (old_val + rng.randint(1, 25)) % MOD

            key[pos] = new_val
            pt = decrypt_with_key(key)
            new_score = qg_score(pt)

            if new_score > current_score or rng.random() < math.exp((new_score - current_score) / temp):
                current_score = new_score
            else:
                key[pos] = old_val

            temp *= 0.999995

            if current_score > best_score:
                best_score = current_score
                best_pt = decrypt_with_key(key)
                best_key = list(key)

    return best_score, best_pt, best_key


print("=" * 70)
print("E-S-109: Deep Analysis of Top Statistically-Ranked Orderings")
print("=" * 70)
t0 = time.time()

results = {}

# Top diff_ic orderings from E-S-108
TOP_ORDERINGS = [
    ([6, 1, 2, 0, 4, 5, 3], 5.537),
    ([4, 6, 0, 5, 2, 3, 1], 5.216),
    ([3, 5, 6, 4, 1, 2, 0], 5.136),
    ([6, 3, 1, 0, 5, 2, 4], 4.976),
    ([1, 6, 5, 0, 3, 2, 4], 4.816),
    # Add E-S-101 top ordering for comparison
    ([5, 3, 0, 4, 1, 2, 6], 3.970),
    # Add KRYPTOS and ABSCISSA orderings
    ([0, 5, 3, 1, 6, 4, 2], 0.0),  # KRYPTOS
    ([0, 1, 3, 4, 2, 5, 6], 0.0),  # ABSCISSA
]

# ==========================================================================
# Phase 1: Keystream analysis for top orderings
# ==========================================================================
print("\n--- Phase 1: Keystream analysis for top diff_ic orderings ---")

for order, z_score in TOP_ORDERINGS:
    print(f"\n  Order {order} (diff_ic z={z_score:.3f}):")

    for variant in ["vig", "beau", "vbeau"]:
        ks = derive_keystream(order, variant)
        analysis = analyze_keystream(ks, f"{order}_{variant}")

        # Print key results
        print(f"    {variant}: key text = {analysis['text']}")
        print(f"      values = {analysis['values']}")
        print(f"      diffs  = {analysis['diffs']}")

        # Check if key text contains any known words (len >= 3)
        text = analysis['text']
        # Simple check for common 3-letter sequences
        for wlen in range(7, 2, -1):
            for i in range(len(text) - wlen + 1):
                substr = text[i:i+wlen]
                if substr in {"THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU",
                              "ALL", "CAN", "HAD", "HER", "WAS", "ONE", "OUR",
                              "KEY", "CIA", "NSA", "MAP", "GOD", "ART", "SPY",
                              "CODE", "EAST", "WEST", "BERLI", "CLOCK", "NORTH",
                              "KRYPT", "PALIM", "ABSCIS", "SHADOW", "SECRET",
                              "HIDDEN", "CIPHER"}:
                    print(f"      WORD FOUND: '{substr}' at position {i}")

    results[f"order_{order}"] = {
        "z_score": z_score,
        "vig_key": analysis['text'] if variant == "vig" else "",
    }

# ==========================================================================
# Phase 2: SA optimization for top orderings
# ==========================================================================
print("\n--- Phase 2: SA optimization for top-5 diff_ic orderings ---")

sa_results = {}
for order, z_score in TOP_ORDERINGS[:5]:
    print(f"\n  Order {order} (z={z_score:.3f}):", flush=True)
    for variant in ["vig", "beau"]:
        score, pt, key = sa_fill_key(order, variant, n_restarts=3, steps=200000, seed=42)
        pt_text = ''.join(ALPH[v] for v in pt)
        key_text = ''.join(ALPH[v] for v in key)

        # Check crib matches
        crib_matches = sum(1 for p in CRIB_POS if pt[p] == PT_AT_CRIB[p])

        print(f"    {variant}: qg/c={score:.3f}, cribs={crib_matches}/24")
        print(f"      PT: ...{pt_text[18:37]}...{pt_text[60:77]}...")

        sa_results[f"{order}_{variant}"] = {
            "qg_per_char": round(score, 4),
            "crib_matches": crib_matches,
            "pt_prefix": pt_text[:40],
            "pt_crib1": pt_text[18:37],
            "pt_crib2": pt_text[60:77],
        }

results["sa_results"] = sa_results

# ==========================================================================
# Phase 3: Width-14 orderings (14 = 2×7, could explain lag-7)
# ==========================================================================
print("\n--- Phase 3: Width-14 differential IC analysis ---")

# Width 14: 97 = 6×14 + 13. 13 columns have 7 rows, 1 column has 6 rows.
WIDTH14 = 14
NROWS14 = N // WIDTH14  # 6
EXTRA14 = N % WIDTH14   # 13

# Too many orderings (14! = 87 billion). Sample keywords instead.
KEYWORDS_14 = [
    "KRYPTOSPALIMPS",  # 14 chars
    "PALIMPSESTABSC",
    "ABSCISSAKRYPTO",
    "EASTNORTHEAST!",  # pad to 14
    "BERLINCLOCKEYE",
    "SHADOWKRYPTOS!",
]

# Also try all 14! is too big. Instead, test specific patterns:
# width-14 means 14 columns with 6 or 7 rows
# Check diff_ic for sampled orderings
print("  Sampling width-14 orderings for diff_ic...", flush=True)

rng = random.Random(42)
w14_scores = []
for _ in range(100000):
    order = list(range(WIDTH14))
    rng.shuffle(order)
    perm = build_columnar_perm(order, width=WIDTH14, n=N)

    # Compute diff_ic
    inv = invert_perm(perm)
    diffs = []
    for i in range(N - 1):
        ct_a = inv[i]
        ct_b = inv[i + 1]
        if ct_a < N and ct_b < N:
            diff = (CT_IDX[ct_a] - CT_IDX[ct_b]) % MOD
            diffs.append(diff)
    if len(diffs) >= 2:
        freq = Counter(diffs)
        n_d = len(diffs)
        ic = sum(f*(f-1) for f in freq.values()) / (n_d * (n_d - 1)) if n_d > 1 else 0
        w14_scores.append((ic, order))

w14_scores.sort(reverse=True)
print(f"  Width-14 diff_ic: top={w14_scores[0][0]:.6f}, mean={sum(s for s,_ in w14_scores)/len(w14_scores):.6f}")
print(f"  Top-5 orderings:")
for ic, order in w14_scores[:5]:
    print(f"    IC={ic:.6f}, order={order[:7]}...{order[7:]}")

results["width14_diff_ic"] = {
    "top_ic": round(w14_scores[0][0], 6),
    "mean_ic": round(sum(s for s,_ in w14_scores)/len(w14_scores), 6),
    "top5": [{"ic": round(ic, 6), "order": order} for ic, order in w14_scores[:5]]
}

# ==========================================================================
# Phase 4: For top orderings, test known-keyword Vig at period != width
# ==========================================================================
print("\n--- Phase 4: Top orderings + known-keyword Vig (all periods 2-14) ---")

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
            "SANBORN", "MEDUSA", "ENIGMA", "INVISIBLE"]

best_p4, best_p4_config = 0, ""
for order, z_score in TOP_ORDERINGS[:5]:
    perm = build_columnar_perm(order)
    inv = invert_perm(perm)

    for kw in KEYWORDS:
        kw_idx = [ALPH_IDX[c] for c in kw]
        period = len(kw_idx)

        for variant in ["vig", "beau", "vbeau"]:
            # Check if this keyword is consistent with all cribs
            consistent = True
            key_at_residue = {}
            for pt_pos in CRIB_POS:
                ct_pos = inv[pt_pos]
                pt_val = PT_AT_CRIB[pt_pos]
                ct_val = CT_IDX[ct_pos]

                # Key at ct_pos is kw_idx[ct_pos % period]
                expected_key = kw_idx[ct_pos % period]

                if variant == "vig":
                    derived_key = (ct_val - pt_val) % MOD
                elif variant == "beau":
                    derived_key = (ct_val + pt_val) % MOD
                else:
                    derived_key = (pt_val - ct_val) % MOD

                if derived_key != expected_key:
                    consistent = False
                    break

            if consistent:
                print(f"  *** MATCH: order={order}, kw={kw}, variant={variant}")
                best_p4 = 24
                best_p4_config = f"order={order},kw={kw},variant={variant}"

    # Also test keyword at PT position (not CT position)
    for kw in KEYWORDS:
        kw_idx = [ALPH_IDX[c] for c in kw]
        period = len(kw_idx)

        for variant in ["vig", "beau", "vbeau"]:
            consistent = True
            for pt_pos in CRIB_POS:
                ct_pos = inv[pt_pos]
                pt_val = PT_AT_CRIB[pt_pos]
                ct_val = CT_IDX[ct_pos]

                # Key at PT position: kw_idx[pt_pos % period]
                expected_key = kw_idx[pt_pos % period]

                if variant == "vig":
                    derived_key = (ct_val - pt_val) % MOD
                elif variant == "beau":
                    derived_key = (ct_val + pt_val) % MOD
                else:
                    derived_key = (pt_val - ct_val) % MOD

                if derived_key != expected_key:
                    consistent = False
                    break

            if consistent:
                print(f"  *** MATCH (PT-indexed): order={order}, kw={kw}, variant={variant}")
                best_p4 = 24
                best_p4_config = f"order={order},kw={kw},variant={variant},pt_indexed"

if best_p4 == 0:
    print("  No keyword matches found for any top ordering")
results["P4_keyword_match"] = {"best": best_p4, "config": best_p4_config}

# ==========================================================================
# Phase 5: Test if the diff_ic signal is specific to width-7
# ==========================================================================
print("\n--- Phase 5: diff_ic significance across widths ---")

for width in [5, 6, 7, 8, 9, 10]:
    if width > N:
        continue

    # Sample orderings
    rng = random.Random(42)
    n_perms = min(5040, math.factorial(width))
    scores = []

    if n_perms <= 5040:
        for order in permutations(range(width)):
            order = list(order)
            perm = build_columnar_perm(order, width=width, n=N)
            inv = invert_perm(perm)
            diffs = []
            for i in range(N - 1):
                ct_a = inv[i]
                ct_b = inv[i + 1]
                if ct_a < N and ct_b < N:
                    diff = (CT_IDX[ct_a] - CT_IDX[ct_b]) % MOD
                    diffs.append(diff)
            if len(diffs) >= 2:
                freq = Counter(diffs)
                n_d = len(diffs)
                ic = sum(f*(f-1) for f in freq.values()) / (n_d * (n_d - 1)) if n_d > 1 else 0
                scores.append(ic)
    else:
        for _ in range(10000):
            order = list(range(width))
            rng.shuffle(order)
            perm = build_columnar_perm(order, width=width, n=N)
            inv = invert_perm(perm)
            diffs = []
            for i in range(N - 1):
                ct_a = inv[i]
                ct_b = inv[i + 1]
                diff = (CT_IDX[ct_a] - CT_IDX[ct_b]) % MOD
                diffs.append(diff)
            freq = Counter(diffs)
            n_d = len(diffs)
            ic = sum(f*(f-1) for f in freq.values()) / (n_d * (n_d - 1)) if n_d > 1 else 0
            scores.append(ic)

    if scores:
        mean_s = sum(scores) / len(scores)
        std_s = (sum((s - mean_s)**2 for s in scores) / len(scores)) ** 0.5
        max_s = max(scores)
        max_z = (max_s - mean_s) / std_s if std_s > 0 else 0
        print(f"  Width {width}: max_diff_ic={max_s:.6f}, mean={mean_s:.6f}, "
              f"std={std_s:.6f}, max_z={max_z:.2f} (n={len(scores)})")
        results[f"width{width}_diff_ic"] = {
            "max": round(max_s, 6), "mean": round(mean_s, 6),
            "std": round(std_s, 6), "max_z": round(max_z, 2)
        }

# ==========================================================================
# Summary
# ==========================================================================
elapsed = time.time() - t0

print(f"\n{'='*70}")
print(f"E-S-109 COMPLETE — elapsed: {elapsed:.1f}s")
print(f"Top diff_ic ordering: [6,1,2,0,4,5,3] (z=5.54)")
print(f"Keyword matches: {best_p4_config if best_p4 > 0 else 'NONE'}")
print(f"{'='*70}")

results["elapsed_seconds"] = elapsed

os.makedirs("results", exist_ok=True)
with open("results/e_s_109_top_ordering_analysis.json", "w") as f:
    json.dump({"experiment": "E-S-109",
               "description": "Deep analysis of top statistically-ranked orderings",
               "results": results}, f, indent=2, default=str)

print(f"\nResults saved to results/e_s_109_top_ordering_analysis.json")
