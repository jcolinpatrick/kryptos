#!/usr/bin/env python3
# Cipher:     Two-system Model A (structured null masks + periodic sub)
# Family:     two_system
# Status:     active
# Keyspace:   ~50K structured masks x 340 keywords x 6 variants = ~102M decryptions
# Last run:
# Best score:
#
# E-TWO-SYS-06: Structured null masks.
#
# The 24 null positions may follow a geometric/structural rule visible in the
# 28×31 grid or some other mathematical pattern. Instead of SA-searching the
# full C(73,24) space, generate masks from:
#
#   1. Grid patterns: every-Nth row/column in 28×31 grid, diagonals, spirals
#   2. Modular: positions where p % d == r for various d, r
#   3. W-constrained: 5 W positions fixed, 19 more from patterns
#   4. Frequency-based: remove positions with most/least common CT letters
#   5. Reverse-engineered: for each keyword, compute which positions MUST be
#      null for cribs to work at shifted positions
#   6. Arithmetic sequences and other structured patterns
from __future__ import annotations

import os
import sys
import time
import multiprocessing as mp
from collections import Counter
from itertools import combinations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, KRYPTOS_ALPHABET,
)

# ── Constants ─────────────────────────────────────────────────────────────

REDUCED_LEN = 73
N_NULLS = 24

CRIB_ENE = "EASTNORTHEAST"
CRIB_BC = "BERLINCLOCK"
CRIB_LIST = sorted(CRIB_DICT.items())

W_POSITIONS = [20, 36, 48, 58, 74]

# Non-crib positions (where nulls can be placed)
NON_CRIB = sorted(set(range(CT_LEN)) - CRIB_POSITIONS)

N_WORKERS = min(28, os.cpu_count() or 4)
REPORT_THRESHOLD = 8

# Alphabets and ciphers
ALPH_TABLE = {
    "AZ": (ALPH, {c: i for i, c in enumerate(ALPH)}),
    "KA": (KRYPTOS_ALPHABET, {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}),
}

def vig_dec(c, k): return (c - k) % MOD
def beau_dec(c, k): return (k - c) % MOD
def vbeau_dec(c, k): return (c + k) % MOD

CIPHER_TABLE = {
    "Vig": vig_dec,
    "Beau": beau_dec,
    "VBeau": vbeau_dec,
}

# Thematic keywords
THEMATIC_KEYWORDS_FILE = os.path.join(
    os.path.dirname(__file__), '..', '..', 'wordlists', 'thematic_keywords.txt'
)

PRIORITY_KEYWORDS = [
    "KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
    "SHADOW", "CIPHER", "SECRET", "BERLIN", "CLOCK",
    "PALIMPSEST", "QUAGMIRE", "COMPASS", "LODESTONE",
    "MAGNETIC", "BURIED", "HIDDEN", "LANGLEY", "SCULPTURE",
    "ENIGMA", "SANBORN", "SCHEIDT",
]


def load_keywords() -> list:
    """Load thematic keywords."""
    keywords = set(PRIORITY_KEYWORDS)
    if os.path.exists(THEMATIC_KEYWORDS_FILE):
        with open(THEMATIC_KEYWORDS_FILE) as f:
            for line in f:
                w = line.strip().upper()
                if 3 <= len(w) <= 20 and w.isalpha():
                    keywords.add(w)
    return sorted(keywords)


# ── Mask generators ───────────────────────────────────────────────────────

def generate_modular_masks() -> list:
    """Masks based on position % d == r."""
    masks = []
    for d in range(2, 49):
        for r in range(d):
            nulls = [p for p in NON_CRIB if p % d == r]
            if len(nulls) == N_NULLS:
                masks.append((f"mod_{d}_{r}", frozenset(nulls)))
            # Also try combinations of residues
            if len(nulls) < N_NULLS:
                # Add more positions from next residue
                for r2 in range(r + 1, d):
                    nulls2 = nulls + [p for p in NON_CRIB if p % d == r2 and p not in nulls]
                    if len(nulls2) == N_NULLS:
                        masks.append((f"mod_{d}_{r}+{r2}", frozenset(nulls2)))
                    elif len(nulls2) > N_NULLS:
                        # Take first 24
                        masks.append((f"mod_{d}_{r}+{r2}_trunc", frozenset(sorted(nulls2)[:N_NULLS])))
    return masks


def generate_grid_masks() -> list:
    """Masks based on 28×31 grid patterns."""
    masks = []
    WIDTH = 31

    # K4 starts at row 24, col 27 in the 28×31 grid (0-indexed)
    # So position p in K4 maps to grid position (row, col) where:
    # linear = 24*31 + 27 + p = 771 + p
    # row = linear // 31, col = linear % 31

    def k4_to_grid(p):
        linear = 771 + p
        return linear // WIDTH, linear % WIDTH

    # Every-Nth column patterns
    for skip in range(2, 8):
        for offset in range(skip):
            nulls = []
            for p in NON_CRIB:
                _, col = k4_to_grid(p)
                if col % skip == offset:
                    nulls.append(p)
            if len(nulls) >= N_NULLS:
                masks.append((f"grid_col_{skip}_{offset}", frozenset(sorted(nulls)[:N_NULLS])))
            elif len(nulls) > 0:
                masks.append((f"grid_col_{skip}_{offset}_partial", frozenset(nulls)))

    # Every-Nth position patterns (simple arithmetic)
    for skip in range(2, 10):
        for offset in range(skip):
            nulls = [p for p in NON_CRIB if p % skip == offset]
            if len(nulls) >= N_NULLS:
                masks.append((f"every_{skip}_off{offset}", frozenset(sorted(nulls)[:N_NULLS])))

    # Diagonal patterns in grid
    for diag_offset in range(-30, 30):
        nulls = []
        for p in NON_CRIB:
            r, c = k4_to_grid(p)
            if (r - c) % 31 == diag_offset % 31:
                nulls.append(p)
        if len(nulls) == N_NULLS:
            masks.append((f"grid_diag_{diag_offset}", frozenset(nulls)))
        elif len(nulls) > N_NULLS:
            masks.append((f"grid_diag_{diag_offset}_trunc", frozenset(sorted(nulls)[:N_NULLS])))

    return masks


def generate_w_constrained_masks() -> list:
    """Masks with 5 W positions fixed, 19 more from patterns."""
    masks = []
    w_set = set(W_POSITIONS)
    remaining_non_crib = [p for p in NON_CRIB if p not in w_set]
    n_needed = N_NULLS - len(W_POSITIONS)  # 19

    # Modular patterns for the remaining 19
    for d in range(2, 25):
        for r in range(d):
            extra = [p for p in remaining_non_crib if p % d == r]
            if len(extra) >= n_needed:
                nulls = sorted(list(w_set) + extra[:n_needed])
                masks.append((f"W+mod_{d}_{r}", frozenset(nulls)))

    # Evenly spaced from remaining
    for skip in range(2, 8):
        for offset in range(skip):
            extra = [p for p in remaining_non_crib if p % skip == offset]
            if len(extra) >= n_needed:
                masks.append((f"W+every_{skip}_off{offset}",
                             frozenset(sorted(list(w_set) + extra[:n_needed]))))

    return masks


def generate_frequency_masks() -> list:
    """Masks based on CT letter frequency — remove rare or common letters."""
    masks = []

    # CT letter frequencies at non-crib positions
    non_crib_freq = Counter(CT[p] for p in NON_CRIB)

    # Sort non-crib positions by their CT letter frequency
    pos_by_freq = sorted(NON_CRIB, key=lambda p: non_crib_freq[CT[p]])

    # Remove rarest letters' positions
    masks.append(("freq_rarest", frozenset(pos_by_freq[:N_NULLS])))

    # Remove most common letters' positions
    masks.append(("freq_commonest", frozenset(pos_by_freq[-N_NULLS:])))

    # Remove positions with specific letters (low-freq in English)
    for letter in "JXZQVWK":
        positions = [p for p in NON_CRIB if CT[p] == letter]
        if 0 < len(positions) <= N_NULLS:
            # Pad with next rarest
            remaining = [p for p in pos_by_freq if p not in positions]
            combo = positions + remaining[:N_NULLS - len(positions)]
            if len(combo) == N_NULLS:
                masks.append((f"freq_remove_{letter}", frozenset(combo)))

    return masks


def generate_arithmetic_masks() -> list:
    """Arithmetic sequences and fibonacci-like patterns."""
    masks = []

    # Arithmetic sequences: start + i*step for i=0..23
    for start in range(max(NON_CRIB[0], 0), min(10, len(NON_CRIB))):
        for step in range(1, 5):
            nulls = []
            for i in range(N_NULLS):
                p = NON_CRIB[0] + start + i * step
                if p in set(NON_CRIB) and p < CT_LEN:
                    nulls.append(p)
            if len(nulls) == N_NULLS:
                masks.append((f"arith_s{start}_d{step}", frozenset(nulls)))

    # First N, last N, middle N
    masks.append(("first_24", frozenset(NON_CRIB[:N_NULLS])))
    masks.append(("last_24", frozenset(NON_CRIB[-N_NULLS:])))
    mid = len(NON_CRIB) // 2
    masks.append(("middle_24", frozenset(NON_CRIB[mid - 12:mid + 12])))

    # Interleaved: every other non-crib position
    masks.append(("even_noncrib", frozenset(NON_CRIB[::3][:N_NULLS])))
    masks.append(("odd_noncrib", frozenset(NON_CRIB[1::3][:N_NULLS])))

    # Zones: all from zone A, fill from B
    zone_a = [p for p in NON_CRIB if p <= 20]
    zone_b = [p for p in NON_CRIB if 34 <= p <= 62]
    zone_c = [p for p in NON_CRIB if p >= 74]

    # All from zone A (21 positions) + 3 from zone B
    if len(zone_a) + 3 <= N_NULLS:
        for combo_b in combinations(zone_b, N_NULLS - len(zone_a)):
            masks.append(("zoneA+3B", frozenset(zone_a + list(combo_b))))
            break  # just first combo
    if len(zone_a) >= N_NULLS:
        masks.append(("zoneA_only", frozenset(zone_a[:N_NULLS])))

    # Split evenly across zones
    za = min(8, len(zone_a))
    zb = min(8, len(zone_b))
    zc = min(8, len(zone_c))
    if za + zb + zc >= N_NULLS:
        masks.append(("zones_even",
                      frozenset(zone_a[:za] + zone_b[:zb] + zone_c[:N_NULLS - za - zb])))

    return masks


def generate_reverse_engineered_masks(keywords: list) -> list:
    """For each keyword, compute which positions MUST be null for cribs to align."""
    masks = []

    for keyword in keywords[:50]:  # limit to top 50
        kw_len = len(keyword)
        for alph_name, (alph_str, alph_idx) in ALPH_TABLE.items():
            try:
                kw_nums = [alph_idx[c] for c in keyword]
            except KeyError:
                continue

            for cipher_name, dec_fn in CIPHER_TABLE.items():
                # For cribs at ORIGINAL positions (21-33, 63-73) in the
                # REDUCED text, we need the CT chars at those reduced positions
                # to decrypt correctly. The reduced position depends on how
                # many nulls precede it.
                #
                # Strategy: for each possible shift `a` (nulls before pos 21),
                # compute which original positions map to the reduced crib positions.
                # Then check if the CT chars at those positions decrypt correctly.
                for a in range(0, 22):  # nulls before ENE
                    for b in range(0, min(30, N_NULLS - a + 1)):
                        c = N_NULLS - a - b
                        if c < 0 or c > 23:
                            continue

                        # Build a candidate mask: a nulls from zone A, b from B, c from C
                        zone_a = [p for p in NON_CRIB if p <= 20]
                        zone_b = [p for p in NON_CRIB if 34 <= p <= 62]
                        zone_c = [p for p in NON_CRIB if p >= 74]

                        if a > len(zone_a) or b > len(zone_b) or c > len(zone_c):
                            continue

                        # Use first `a` from zone A, first `b` from zone B, first `c` from zone C
                        nulls = zone_a[:a] + zone_b[:b] + zone_c[:c]
                        if len(nulls) != N_NULLS:
                            continue

                        null_set = set(nulls)

                        # Build reduced CT and check cribs
                        reduced_ct = []
                        orig_to_reduced = {}
                        ridx = 0
                        for pos in range(CT_LEN):
                            if pos not in null_set:
                                reduced_ct.append(CT[pos])
                                orig_to_reduced[pos] = ridx
                                ridx += 1

                        # Count crib hits
                        hits = 0
                        for orig_pos, expected in CRIB_LIST:
                            if orig_pos in orig_to_reduced:
                                rpos = orig_to_reduced[orig_pos]
                                # Decrypt
                                c_num = alph_idx[reduced_ct[rpos]]
                                k_num = kw_nums[rpos % kw_len]
                                p_num = dec_fn(c_num, k_num)
                                if alph_str[p_num] == expected:
                                    hits += 1

                        if hits >= REPORT_THRESHOLD:
                            masks.append((
                                f"rev_{keyword}_{cipher_name}_{alph_name}_a{a}b{b}",
                                frozenset(nulls),
                                {"keyword": keyword, "cipher": cipher_name,
                                 "alphabet": alph_name, "hits": hits,
                                 "a": a, "b": b, "c": c},
                            ))

    return masks


# ── Scoring worker ────────────────────────────────────────────────────────

def score_mask_batch(args: tuple) -> list:
    """Score a batch of masks against all keyword/cipher/alphabet combos."""
    mask_batch, keywords = args
    results = []

    for mask_name, null_set in mask_batch:
        if len(null_set) != N_NULLS:
            continue

        # Verify no crib positions are nulled
        if null_set & CRIB_POSITIONS:
            continue

        # Build reduced CT once per mask
        null_list = sorted(null_set)
        reduced_ct = []
        orig_to_reduced = {}
        ridx = 0
        for i in range(CT_LEN):
            if i not in null_set:
                reduced_ct.append(CT[i])
                orig_to_reduced[i] = ridx
                ridx += 1
        reduced_ct_str = "".join(reduced_ct)

        for keyword in keywords:
            for alph_name, (alph_str, alph_idx) in ALPH_TABLE.items():
                try:
                    kw_nums = [alph_idx[c] for c in keyword]
                except KeyError:
                    continue
                kw_len = len(kw_nums)

                for cipher_name, dec_fn in CIPHER_TABLE.items():
                    # Decrypt reduced CT
                    pt_chars = []
                    for i, ch in enumerate(reduced_ct_str):
                        c_num = alph_idx[ch]
                        k_num = kw_nums[i % kw_len]
                        p_num = dec_fn(c_num, k_num)
                        pt_chars.append(alph_str[p_num])
                    pt = "".join(pt_chars)

                    # Score: mapped crib hits
                    mapped = 0
                    for orig_pos, expected in CRIB_LIST:
                        if orig_pos in orig_to_reduced:
                            rpos = orig_to_reduced[orig_pos]
                            if pt[rpos] == expected:
                                mapped += 1

                    # Free crib search
                    free = 0
                    if CRIB_ENE in pt:
                        free += 13
                    if CRIB_BC in pt:
                        free += 11

                    best = max(mapped, free)
                    if best >= REPORT_THRESHOLD:
                        results.append({
                            "mask_name": mask_name,
                            "keyword": keyword,
                            "cipher": cipher_name,
                            "alphabet": alph_name,
                            "mapped_score": mapped,
                            "free_score": free,
                            "plaintext": pt,
                            "null_positions": null_list,
                        })

    return results


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    keywords = load_keywords()

    print("=" * 78)
    print("E-TWO-SYS-06: Structured null masks")
    print("=" * 78)
    print(f"\nCT ({CT_LEN} chars): {CT}")
    print(f"Keywords: {len(keywords)}")
    print(f"Workers: {N_WORKERS}")
    print()
    sys.stdout.flush()

    # ── Generate all structured masks ─────────────────────────────────────
    print("Generating structured masks...")
    all_masks = []

    mod_masks = generate_modular_masks()
    print(f"  Modular masks: {len(mod_masks)}")
    all_masks.extend(mod_masks)

    grid_masks = generate_grid_masks()
    print(f"  Grid masks: {len(grid_masks)}")
    all_masks.extend(grid_masks)

    w_masks = generate_w_constrained_masks()
    print(f"  W-constrained masks: {len(w_masks)}")
    all_masks.extend(w_masks)

    freq_masks = generate_frequency_masks()
    print(f"  Frequency masks: {len(freq_masks)}")
    all_masks.extend(freq_masks)

    arith_masks = generate_arithmetic_masks()
    print(f"  Arithmetic masks: {len(arith_masks)}")
    all_masks.extend(arith_masks)

    # Deduplicate by null set
    seen = set()
    unique_masks = []
    for item in all_masks:
        name, nulls = item[0], item[1]
        if nulls not in seen and len(nulls) == N_NULLS:
            # Verify no crib positions
            if not (nulls & CRIB_POSITIONS):
                seen.add(nulls)
                unique_masks.append((name, nulls))

    print(f"\nTotal unique masks (24 nulls, no crib overlap): {len(unique_masks)}")
    total_configs = len(unique_masks) * len(keywords) * len(CIPHER_TABLE) * len(ALPH_TABLE)
    print(f"Total decryption configs: {total_configs:,}")
    print()
    sys.stdout.flush()

    # ── Score all masks ───────────────────────────────────────────────────
    print("Scoring masks...")

    # Split masks into batches for parallel processing
    batch_size = max(1, len(unique_masks) // (N_WORKERS * 4))
    batches = []
    for i in range(0, len(unique_masks), batch_size):
        batches.append((unique_masks[i:i + batch_size], keywords))

    all_results = []
    completed = 0

    with mp.Pool(N_WORKERS) as pool:
        for result_list in pool.imap_unordered(score_mask_batch, batches):
            all_results.extend(result_list)
            completed += 1
            if completed % 10 == 0 or completed == len(batches):
                elapsed = time.time() - t0
                print(f"  Batch {completed}/{len(batches)}, "
                      f"{elapsed:.1f}s, hits: {len(all_results)}")
                sys.stdout.flush()

    # ── Reverse-engineered masks (separate pass) ──────────────────────────
    print(f"\nGenerating reverse-engineered masks...")
    rev_masks = generate_reverse_engineered_masks(keywords)
    print(f"  Reverse-engineered hits: {len(rev_masks)}")
    for item in rev_masks:
        name, nulls, info = item
        print(f"    {name}: hits={info['hits']} a={info['a']} b={info['b']} c={info['c']}")
        all_results.append({
            "mask_name": name,
            "keyword": info["keyword"],
            "cipher": info["cipher"],
            "alphabet": info["alphabet"],
            "mapped_score": info["hits"],
            "free_score": 0,
            "plaintext": "",
            "null_positions": sorted(nulls),
        })

    elapsed = time.time() - t0

    # ── Results ───────────────────────────────────────────────────────────
    print(f"\n{'=' * 78}")
    print(f"RESULTS")
    print(f"{'=' * 78}")
    print(f"Masks tested: {len(unique_masks)}")
    print(f"Total configs: {total_configs:,}")
    print(f"Results >= {REPORT_THRESHOLD}: {len(all_results)}")
    print(f"Elapsed: {elapsed:.1f}s")

    if all_results:
        all_results.sort(key=lambda r: -(max(r["mapped_score"], r["free_score"])))

        # Group by mask pattern type
        pattern_counts = Counter(r["mask_name"].split("_")[0] for r in all_results)
        print(f"\nResults by pattern type:")
        for ptype, count in pattern_counts.most_common():
            print(f"  {ptype}: {count}")

        print(f"\nTop 50 results:")
        for i, r in enumerate(all_results[:50]):
            print(f"  #{i+1}: mapped={r['mapped_score']} free={r['free_score']} "
                  f"| {r['mask_name']} {r['keyword']}/{r['cipher']}/{r['alphabet']}")
            if r["plaintext"]:
                print(f"       PT: {r['plaintext'][:60]}...")
    else:
        print("  NO results above threshold.")

    best = max(
        (max(r["mapped_score"], r["free_score"]) for r in all_results),
        default=0,
    )
    print(f"\n{'=' * 78}")
    if best >= 18:
        print(f"*** SIGNAL (best={best}) — investigate ***")
    elif best >= REPORT_THRESHOLD:
        print(f"Above noise (best={best}) — review")
    else:
        print(f"NOISE — Structured masks: no signal (best={best})")
    print(f"{'=' * 78}")


if __name__ == "__main__":
    main()
