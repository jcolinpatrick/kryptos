#!/usr/bin/env python3
"""
Cipher: constructive-key-management
Family: two_system
Status: active
Keyspace: ~167M
Last run:
Best score:

E-CKM-02: Constructive Key Management Exhaustive Sweep

Hypothesis: K4's cipher key is CONSTRUCTED by combining two keyword sources
through a simple mod-26 operation: key[i] = f(A[i%La], B[(i+d)%Lb]) mod 26.

This produces a non-periodic key (period = lcm(La,Lb)) from periodic components.
On CT73, periods >23 are NOT covered by the Bean proof — this is the open gap.

Ed Scheidt co-founded TecSec Inc. and holds 36 patents in "Constructive Key
Management" (CKM). Gillogly: K4 uses "an invention by Scheidt that has never
appeared in cryptographic literature." The key DERIVATION may be the invention.

Prior: E-SPLIT-00 tested 51K configs with 23 keywords (CT97 only, best 6/24).
This test: ~167M configs, 372 thematic + English words, CT97 + CT73, phase offsets.
"""

import json
import os
import sys
import time
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT

# ── Ciphertext variants ──────────────────────────────────────────────────

CT_NUM = [ALPH_IDX[c] for c in CT]

# Consensus null positions (17 fixed + 7 varying from specific clusters)
CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}

# Three null mask layouts that produce distinct crib scoring
# (from Gutenberg sweep: 55 masks collapse to 3 crib-scoring layouts)
# Layout A: varying nulls from {38,39,40} + {55} + {87} + {93,94}
MASK_A = sorted(CONSENSUS_NULLS | {38, 39, 40, 55, 87, 93, 94})
# Layout B: varying nulls shifted
MASK_B = sorted(CONSENSUS_NULLS | {38, 39, 40, 56, 88, 93, 94})
# Layout C: alternative
MASK_C = sorted(CONSENSUS_NULLS | {41, 42, 43, 55, 87, 95, 96})


def extract_ct(mask):
    """Remove null positions from CT, return (ct73_nums, crib_map)."""
    mask_set = set(mask)
    ct73 = []
    pos_map = {}  # CT97 pos -> CT73 pos
    j = 0
    for i in range(CT_LEN):
        if i not in mask_set:
            ct73.append(CT_NUM[i])
            pos_map[i] = j
            j += 1
    # Remap cribs to CT73 positions
    crib73 = {}
    for pos, ch in CRIB_DICT.items():
        if pos in pos_map:
            crib73[pos_map[pos]] = ALPH_IDX[ch]
    return ct73, crib73


# Pre-compute CT73 variants
CT73_VARIANTS = {}
for name, mask in [("mask_a", MASK_A), ("mask_b", MASK_B), ("mask_c", MASK_C)]:
    ct73, crib73 = extract_ct(mask)
    CT73_VARIANTS[name] = (ct73, crib73, len(ct73))

# CT97 cribs as numeric
CRIB97 = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# ── KA alphabet ──────────────────────────────────────────────────────────

KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}


def word_to_nums_az(word):
    return [ALPH_IDX[c] for c in word if c in ALPH_IDX]


def word_to_nums_ka(word):
    return [KA_IDX[c] for c in word if c in KA_IDX]


# ── Load keywords ────────────────────────────────────────────────────────

def load_thematic():
    """Load thematic keywords."""
    path = os.path.join(_ROOT, "wordlists", "thematic_keywords.txt")
    words = set()
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                w = "".join(c for c in line.upper() if c.isalpha())
                if 2 <= len(w) <= 20:
                    words.add(w)
    return sorted(words)


def load_tier1():
    """Priority keywords — must test."""
    return sorted(set([
        "KRYPTOS", "SEVEN", "PALIMPSEST", "ABSCISSA", "DEFECTOR",
        "BERLIN", "CLOCK", "KOMPASS", "SHADOW", "LANGLEY",
        "SCHEIDT", "SANBORN", "CARTER", "LAYERTWO", "IDBYROWS",
        "IQLUSION", "CIPHER", "SECRET", "BURIED", "NORTH",
        "EAST", "WEST", "POINT", "COMPASS", "DEGREES",
        "MINUTES", "SECONDS", "INVISIBLE", "MAGNETIC", "FIELD",
        "LODGE", "TOWER", "CHART", "FILTER", "MEDUSA",
        "FIVE", "ROSETTA", "COLOPHON", "PARALLAX", "WEBSTER",
    ]))


def load_english_top(n=1000):
    """Load top N English words by length variety, 3-13 chars."""
    path = os.path.join(_ROOT, "wordlists", "english.txt")
    words = set()
    with open(path) as f:
        for line in f:
            w = line.strip().upper()
            if w.isalpha() and 3 <= len(w) <= 13:
                words.add(w)
            if len(words) >= n * 10:  # read enough to sample
                break
    # Prioritize: shorter words + diverse lengths
    by_len = {}
    for w in words:
        by_len.setdefault(len(w), []).append(w)
    result = set()
    for length in range(3, 14):
        bucket = by_len.get(length, [])
        # Take up to n/11 from each length bucket
        for w in sorted(bucket)[:n // 11 + 50]:
            result.add(w)
            if len(result) >= n:
                break
        if len(result) >= n:
            break
    return sorted(result)


# ── Core test function ───────────────────────────────────────────────────

def score_key_on_ct(key_nums, ct_nums, crib_map, ct_len):
    """Score a key against a ciphertext using all 3 cipher variants.

    Returns (best_score, best_variant, best_pt_snippet).
    Variants:
      Vig:    PT = (CT - KEY) mod 26
      Beau:   PT = (KEY - CT) mod 26
      VBeau:  PT = (CT + KEY) mod 26  [= decrypt of C=(P-K)]
    """
    best = 0
    best_var = ""

    for var_name, sign_a, sign_b in [("vig", 1, -1), ("beau", -1, 1), ("vbeau", 1, 1)]:
        score = 0
        for pos, expected in crib_map.items():
            if pos < ct_len:
                ki = pos % len(key_nums)
                pt_val = (sign_a * ct_nums[pos] + sign_b * key_nums[ki]) % MOD
                if pt_val == expected:
                    score += 1
        if score > best:
            best = score
            best_var = var_name

    return best, best_var


# ── Combination functions ────────────────────────────────────────────────

def combine_add(a, b, d, length):
    la, lb = len(a), len(b)
    return [(a[i % la] + b[(i + d) % lb]) % MOD for i in range(length)]


def combine_sub_ab(a, b, d, length):
    la, lb = len(a), len(b)
    return [(a[i % la] - b[(i + d) % lb]) % MOD for i in range(length)]


def combine_sub_ba(a, b, d, length):
    la, lb = len(a), len(b)
    return [(b[(i + d) % lb] - a[i % la]) % MOD for i in range(length)]


def combine_mul(a, b, d, length):
    la, lb = len(a), len(b)
    return [(a[i % la] * b[(i + d) % lb]) % MOD for i in range(length)]


def combine_min(a, b, d, length):
    la, lb = len(a), len(b)
    return [min(a[i % la], b[(i + d) % lb]) for i in range(length)]


def combine_max(a, b, d, length):
    la, lb = len(a), len(b)
    return [max(a[i % la], b[(i + d) % lb]) for i in range(length)]


COMBINERS = [
    ("add", combine_add),
    ("sub_AB", combine_sub_ab),
    ("sub_BA", combine_sub_ba),
    ("mul", combine_mul),
    ("min", combine_min),
    ("max", combine_max),
]


# ── Worker for multiprocessing ───────────────────────────────────────────

def test_word_pair(args):
    """Test one (word_a, word_b) pair across all combinations, offsets, variants, CTs."""
    word_a, word_b, alpha_name = args
    if alpha_name == "AZ":
        nums_a = word_to_nums_az(word_a)
        nums_b = word_to_nums_az(word_b)
    else:
        nums_a = word_to_nums_ka(word_a)
        nums_b = word_to_nums_ka(word_b)

    if not nums_a or not nums_b:
        return []

    la, lb = len(nums_a), len(nums_b)
    max_offset = min(lb, 8)  # test offsets 0..min(lb-1, 7)

    hits = []  # [(score, variant, word_a, word_b, comb, offset, alpha, ct_name)]
    tested = 0

    for comb_name, comb_fn in COMBINERS:
        for d in range(max_offset):
            # Generate key for max length needed (97)
            key = comb_fn(nums_a, nums_b, d, CT_LEN)

            # Test on CT97
            score, var = score_key_on_ct(key, CT_NUM, CRIB97, CT_LEN)
            tested += 1
            if score >= 8:
                hits.append((score, var, word_a, word_b, comb_name, d, alpha_name, "ct97"))

            # Test on CT73 variants
            for ct_name, (ct73, crib73, ct73_len) in CT73_VARIANTS.items():
                key73 = key[:ct73_len]  # truncate key to CT73 length
                score, var = score_key_on_ct(key73, ct73, crib73, ct73_len)
                tested += 1
                if score >= 8:
                    hits.append((score, var, word_a, word_b, comb_name, d, alpha_name, ct_name))

    return hits, tested


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 70)
    print("E-CKM-02: Constructive Key Management Exhaustive Sweep")
    print("=" * 70)

    # Load keywords
    tier1 = load_tier1()
    thematic = load_thematic()
    english_top = load_english_top(1000)

    # Word A: tier1 + thematic (primary sources)
    words_a = sorted(set(tier1) | set(thematic))
    # Word B: all sources
    words_b = sorted(set(tier1) | set(thematic) | set(english_top))

    print(f"Word A pool: {len(words_a)} words (tier1 + thematic)")
    print(f"Word B pool: {len(words_b)} words (tier1 + thematic + english)")
    print(f"Alphabets: AZ, KA")
    print(f"Combiners: {len(COMBINERS)}")
    print(f"CT variants: CT97 + 3 CT73 masks = 4")

    # Build work items
    work = []
    for alpha in ["AZ", "KA"]:
        for wa in words_a:
            for wb in words_b:
                work.append((wa, wb, alpha))

    total_pairs = len(work)
    est_configs = total_pairs * len(COMBINERS) * 4 * 4  # ~4 offsets avg, 4 CT variants
    print(f"Word pairs to test: {total_pairs:,}")
    print(f"Estimated total configs: {est_configs:,}")
    print()

    # Run with multiprocessing
    n_workers = min(cpu_count(), 28)
    print(f"Running with {n_workers} workers...")

    all_hits = []
    total_tested = 0
    batch_size = 10000

    with Pool(n_workers) as pool:
        for i in range(0, len(work), batch_size):
            batch = work[i:i + batch_size]
            results = pool.map(test_word_pair, batch)
            for res in results:
                if res:
                    hits, tested = res
                    total_tested += tested
                    for h in hits:
                        all_hits.append(h)

            elapsed = time.time() - t0
            progress = min(i + batch_size, len(work)) / len(work) * 100
            print(f"  {progress:5.1f}% | {total_tested:>12,} configs | "
                  f"{len(all_hits)} hits ≥8 | {elapsed:.0f}s", flush=True)

    elapsed = time.time() - t0

    # Sort by score descending
    all_hits.sort(key=lambda x: -x[0])

    # Summary
    print()
    print("=" * 70)
    print(f"COMPLETE: {total_tested:,} configs in {elapsed:.1f}s "
          f"({total_tested / elapsed:,.0f} configs/sec)")
    print(f"Hits ≥ 8: {len(all_hits)}")

    if all_hits:
        print(f"BEST SCORE: {all_hits[0][0]}/24")
        print()
        print("TOP 20 RESULTS:")
        print("-" * 70)
        for h in all_hits[:20]:
            score, var, wa, wb, comb, d, alpha, ct_name = h
            print(f"  {score:2d}/24 | {var:6s} | {alpha} | {ct_name:6s} | "
                  f"{wa}+{wb}({comb},d={d})")

        # For the best hit, show the actual plaintext
        if all_hits[0][0] >= 10:
            print()
            print("*** ABOVE NOISE — INVESTIGATING BEST HIT ***")
            h = all_hits[0]
            score, var, wa, wb, comb, d, alpha, ct_name = h
            if alpha == "AZ":
                nums_a, nums_b = word_to_nums_az(wa), word_to_nums_az(wb)
            else:
                nums_a, nums_b = word_to_nums_ka(wa), word_to_nums_ka(wb)

            comb_fn = dict(COMBINERS)[comb]

            if ct_name == "ct97":
                ct_nums, crib_map, ct_len = CT_NUM, CRIB97, CT_LEN
            else:
                ct_nums, crib_map, ct_len = CT73_VARIANTS[ct_name]

            key = comb_fn(nums_a, nums_b, d, ct_len)

            signs = {"vig": (1, -1), "beau": (-1, 1), "vbeau": (1, 1)}
            sa, sb = signs[var]
            pt = "".join(ALPH[(sa * ct_nums[i] + sb * key[i % len(key)]) % MOD]
                         for i in range(ct_len))
            print(f"  Key: {''.join(ALPH[k] for k in key[:40])}...")
            print(f"  PT:  {pt[:50]}...")
    else:
        print("ZERO hits ≥ 8. Two-keyword CKM combination = NOISE for this search space.")

    print("=" * 70)

    # Score distribution
    score_dist = {}
    for h in all_hits:
        s = h[0]
        score_dist[s] = score_dist.get(s, 0) + 1
    print(f"\nScore distribution (≥8): {dict(sorted(score_dist.items()))}")

    # Save results
    output = {
        "experiment": "E-CKM-02",
        "description": "Constructive Key Management Exhaustive Sweep",
        "total_configs": total_tested,
        "elapsed_seconds": round(elapsed, 1),
        "configs_per_second": round(total_tested / elapsed),
        "words_a_count": len(words_a),
        "words_b_count": len(words_b),
        "combiners": [c[0] for c in COMBINERS],
        "alphabets": ["AZ", "KA"],
        "ct_variants": ["ct97", "mask_a", "mask_b", "mask_c"],
        "best_score": all_hits[0][0] if all_hits else 0,
        "hits_above_8": len(all_hits),
        "score_distribution": score_dist,
        "top_20": [
            {
                "score": h[0], "variant": h[1], "word_a": h[2], "word_b": h[3],
                "combiner": h[4], "offset": h[5], "alphabet": h[6], "ct_name": h[7],
            }
            for h in all_hits[:20]
        ],
    }

    out_path = os.path.join(_ROOT, "results", "e_ckm_exhaustive_02.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
