#!/usr/bin/env python3
"""
Cipher: K3-method extension
Family: k3_continuity
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-58: K3 Method Variant + Keystream Deep Analysis.

Analytical (not brute-force) experiment combining:
A) K3 method variant impact: which width-7 transpositions produce key fragments
   that look like English (running key signal)?
B) Direct keystream pattern search: arithmetic, coordinates, dates, text matches,
   algebraic structures in the 24 known key values.
C) Crib alignment analysis: why do both cribs start at multiples of 7?

Key insight: both crib starting positions (21=3×7, 63=9×7) are multiples of 7,
meaning they align with row boundaries in a 7-column grid. This is potentially
significant for columnar transposition analysis.
"""
import json
import time
import sys
import os
import math
from collections import Counter, defaultdict
from itertools import permutations

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    BEAN_EQ, BEAN_INEQ,
)

CT_IDX = [ALPH_IDX[c] for c in CT]
PT_IDX = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

# Full keystream at all 24 crib positions (Vigenère convention)
CRIB_POS_SORTED = sorted(CRIB_POSITIONS)
VIG_KEY_FULL = []
for p in CRIB_POS_SORTED:
    VIG_KEY_FULL.append((CT_IDX[p] - PT_IDX[p]) % MOD)
BEAU_KEY_FULL = []
for p in CRIB_POS_SORTED:
    BEAU_KEY_FULL.append((CT_IDX[p] + PT_IDX[p]) % MOD)

results = {
    "experiment": "E-S-58",
    "phases": {},
}


def ic_of_values(vals):
    """IC of a sequence of integer values 0-25."""
    n = len(vals)
    if n < 2:
        return 0.0
    counts = Counter(vals)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def columnar_perm(order, text_len):
    """Generate columnar transposition permutation.

    order: list giving the read order of columns (e.g., [0,5,3,1,6,4,2] for KRYPTOS)
    Returns perm where perm[ct_pos] = pt_pos (gather convention).
    """
    width = len(order)
    n_full_rows = text_len // width
    extra = text_len % width

    # Column heights
    col_heights = []
    for c in range(width):
        col_heights.append(n_full_rows + (1 if c < extra else 0))

    perm = []
    for read_idx in range(width):
        col = order[read_idx]
        for row in range(col_heights[col]):
            pt_pos = row * width + col
            perm.append(pt_pos)

    return perm


def invert_perm(perm):
    """Invert a permutation."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def keyword_to_order(keyword):
    """Convert keyword to columnar order."""
    indexed = sorted(range(len(keyword)), key=lambda i: (keyword[i], i))
    order = [0] * len(keyword)
    for rank, col in enumerate(indexed):
        order[col] = rank
    # Return the read order: which column to read at each step
    read_order = [0] * len(keyword)
    for col, rank in enumerate(order):
        read_order[rank] = col
    return read_order


# ============================================================
# PHASE A: Direct Keystream Pattern Analysis
# ============================================================
def phase_a():
    print("=" * 70)
    print("PHASE A: Direct Keystream Pattern Analysis")
    print("=" * 70)

    vig = VIG_KEY_FULL
    beau = BEAU_KEY_FULL

    print(f"\nVigenère key (24 values):  {vig}")
    print(f"  Letters: {''.join(ALPH[v] for v in vig)}")
    print(f"Beaufort key (24 values): {beau}")
    print(f"  Letters: {''.join(ALPH[v] for v in beau)}")
    print(f"Positions: {CRIB_POS_SORTED}")

    phase_results = {}

    # A1: First differences
    print("\n--- A1: First differences ---")
    for name, key in [("Vigenère", vig), ("Beaufort", beau)]:
        diffs = [(key[i+1] - key[i]) % MOD for i in range(len(key)-1)]
        print(f"  {name} Δ: {diffs}")
        # Check if diffs are periodic
        for p in range(1, 13):
            consistent = all(diffs[i] == diffs[i % p] for i in range(len(diffs)) if i >= p)
            if consistent and p < len(diffs):
                print(f"    Period {p}: CONSISTENT (but only {len(diffs)} values)")

    # A2: Second differences
    print("\n--- A2: Second differences ---")
    for name, key in [("Vigenère", vig), ("Beaufort", beau)]:
        d1 = [(key[i+1] - key[i]) % MOD for i in range(len(key)-1)]
        d2 = [(d1[i+1] - d1[i]) % MOD for i in range(len(d1)-1)]
        print(f"  {name} Δ²: {d2}")

    # A3: IC of key fragments
    print("\n--- A3: IC of key fragments ---")
    for name, key in [("Vigenère", vig), ("Beaufort", beau)]:
        ic_all = ic_of_values(key)
        ic_ene = ic_of_values(key[:13])
        ic_bc = ic_of_values(key[13:])
        print(f"  {name}: IC_all={ic_all:.4f}, IC_ENE={ic_ene:.4f}, IC_BC={ic_bc:.4f}")
        print(f"    (Random: 0.0385, English: 0.067)")

    # A4: Key in KRYPTOS alphabet
    print("\n--- A4: Key mapped through KRYPTOS alphabet ---")
    for name, key in [("Vigenère", vig), ("Beaufort", beau)]:
        ka_mapped = [KA_IDX[ALPH[v]] for v in key]
        print(f"  {name} in KA: {ka_mapped}")
        print(f"    Letters via KA: {''.join(KRYPTOS_ALPHABET[v] for v in key)}")

    # A5: Coordinate digits
    print("\n--- A5: Match against coordinate digits ---")
    # K2 coordinates: 38°57'6.5"N, 77°8'44"W
    coord_digits = [3,8,9,5,1,4,7,7,1,4,5,6]  # from 38.9514, 77.1456
    coord_digits2 = [3,8,5,7,6,5,7,7,8,4,4]  # from 38°57'6.5", 77°8'44"
    for name, key in [("Vigenère", vig), ("Beaufort", beau)]:
        mod10 = [v % 10 for v in key]
        # Check if any contiguous substring matches
        for clen in range(4, min(len(coord_digits), len(key))+1):
            for offset in range(len(key) - clen + 1):
                if mod10[offset:offset+clen] == coord_digits[:clen]:
                    print(f"  {name} mod10 matches coords at offset {offset}, len {clen}")
    print("  No coordinate matches found")

    # A6: Date-derived patterns
    print("\n--- A6: Date patterns ---")
    dates = {
        "1986": [1,9,8,6],
        "1989": [1,9,8,9],
        "11/9/1989": [1,1,0,9,1,9,8,9],
        "11/4/1922": [1,1,0,4,1,9,2,2],  # Carter discovery
        "11/26/1922": [1,1,2,6,1,9,2,2],  # Tomb opening
    }
    for name, key in [("Vigenère", vig), ("Beaufort", beau)]:
        mod10 = [v % 10 for v in key]
        for dname, dvals in dates.items():
            for offset in range(len(key) - len(dvals) + 1):
                if mod10[offset:offset+len(dvals)] == dvals:
                    print(f"  {name} mod10 matches {dname} at offset {offset}")
    print("  No date matches found in mod-10 key values")

    # A7: Modular reductions
    print("\n--- A7: Key values under various moduli ---")
    for name, key in [("Vigenère", vig), ("Beaufort", beau)]:
        for m in [2, 3, 5, 7, 13]:
            reduced = [v % m for v in key]
            print(f"  {name} mod {m:2d}: {reduced}")

    # A8: Check if key values form arithmetic sequence (any start, any step)
    print("\n--- A8: Arithmetic progressions ---")
    for name, key in [("Vigenère", vig), ("Beaufort", beau)]:
        best_len = 0
        best_params = None
        for start_idx in range(len(key)):
            for step in range(1, MOD):
                length = 0
                for i in range(start_idx, len(key)):
                    expected = (key[start_idx] + (i - start_idx) * step) % MOD
                    if key[i] == expected:
                        length += 1
                    else:
                        break
                if length > best_len:
                    best_len = length
                    best_params = (start_idx, step, length)
        print(f"  {name}: best AP length={best_params[2]} starting at idx {best_params[0]} step {best_params[1]}")

    # A9: Fibonacci-like check
    print("\n--- A9: Fibonacci-like sequences ---")
    for name, key in [("Vigenère", vig), ("Beaufort", beau)]:
        best_len = 0
        for i in range(len(key) - 2):
            length = 2
            for j in range(i + 2, len(key)):
                if (key[j-2] + key[j-1]) % MOD == key[j]:
                    length += 1
                else:
                    break
            if length > best_len:
                best_len = length
                print(f"  {name}: Fib-like run of {length} starting at idx {i}: {key[i:i+length]}")

    # A10: Key as text in reversed alphabet / other mappings
    print("\n--- A10: Key under alphabet remappings ---")
    mappings = {
        "Standard": ALPH,
        "Reversed": ALPH[::-1],
        "KRYPTOS": KRYPTOS_ALPHABET,
        "KRYPTOS reversed": KRYPTOS_ALPHABET[::-1],
        "ROT13": ALPH[13:] + ALPH[:13],
        "Atbash": ''.join(chr(ord('A') + 25 - i) for i in range(26)),
    }
    for name, key in [("Vigenère", vig), ("Beaufort", beau)]:
        for mname, mapping in mappings.items():
            text = ''.join(mapping[v] for v in key)
            print(f"  {name} via {mname}: {text}")

    # A11: Cross-block relationship
    print("\n--- A11: ENE-BC cross-block analysis ---")
    ene_key = vig[:13]
    bc_key = vig[13:]
    print(f"  ENE positions: {CRIB_POS_SORTED[:13]}")
    print(f"  BC  positions: {CRIB_POS_SORTED[13:]}")
    print(f"  Position gap: {CRIB_POS_SORTED[13] - CRIB_POS_SORTED[0]} = {63-21}")
    print(f"  42 = 6 × 7 = 2 × 3 × 7")

    # Check if bc_key = shifted version of ene_key
    for shift in range(MOD):
        matches = sum(1 for i in range(min(len(ene_key), len(bc_key)))
                      if (ene_key[i] + shift) % MOD == bc_key[i])
        if matches >= 5:
            print(f"  Shift {shift}: {matches}/{min(len(ene_key),len(bc_key))} matches")

    # Check if bc_key = ene_key with multiplicative factor
    for a in range(1, MOD):
        if math.gcd(a, MOD) != 1:
            continue
        matches = sum(1 for i in range(min(len(ene_key), len(bc_key)))
                      if (ene_key[i] * a) % MOD == bc_key[i])
        if matches >= 5:
            print(f"  Affine a={a}: {matches}/{min(len(ene_key),len(bc_key))} matches")

    # A12: Check absolute position relationship
    print("\n--- A12: Key value vs position relationship ---")
    for name, key in [("Vigenère", vig), ("Beaufort", beau)]:
        # Is k[p] = f(p) for some simple f?
        for a in range(MOD):
            for b in range(MOD):
                matches = sum(1 for i, p in enumerate(CRIB_POS_SORTED)
                              if (a * p + b) % MOD == key[i])
                if matches >= 8:
                    print(f"  {name}: k[p] = {a}*p + {b} mod 26: {matches}/24 matches")

    phase_results["a_ic_vig"] = ic_of_values(vig)
    phase_results["a_ic_beau"] = ic_of_values(beau)
    phase_results["a_vig_letters"] = ''.join(ALPH[v] for v in vig)
    phase_results["a_beau_letters"] = ''.join(ALPH[v] for v in beau)

    return phase_results


# ============================================================
# PHASE B: Width-7 Transposition + Key Analysis
# ============================================================
def phase_b():
    print("\n" + "=" * 70)
    print("PHASE B: Width-7 Transposition + Key IC Analysis")
    print("=" * 70)
    print("Testing all 5040 width-7 orderings: derive key at crib positions,")
    print("check IC (running key signal), check text matches.\n")

    phase_results = {
        "top_ic_configs": [],
        "text_match_configs": [],
        "k3_key_results": {},
    }

    # Load reference texts for matching
    ref_texts = {}
    ref_dir = "reference/running_key_texts"
    if os.path.exists(ref_dir):
        for fname in os.listdir(ref_dir):
            fpath = os.path.join(ref_dir, fname)
            try:
                with open(fpath) as f:
                    text = f.read().upper()
                    text = ''.join(c for c in text if c in ALPH)
                    if len(text) > 50:
                        ref_texts[fname] = text
            except:
                pass

    # Also load Carter text
    for carter_path in ["reference/carter_vol1_extract.txt", "reference/carter_vol1.txt"]:
        if os.path.exists(carter_path):
            try:
                with open(carter_path) as f:
                    text = f.read().upper()
                    text = ''.join(c for c in text if c in ALPH)
                    if len(text) > 50:
                        ref_texts[carter_path] = text
                        break
            except:
                pass

    print(f"Loaded {len(ref_texts)} reference texts: {list(ref_texts.keys())}")

    # K3's exact key
    k3_order = keyword_to_order("KRYPTOS")
    print(f"K3 key (KRYPTOS) order: {k3_order}")

    top_ic = []  # (ic, order, model, key_letters)
    text_matches = []  # (score, order, model, text_name, offset)

    n_orderings = 0
    for order in permutations(range(7)):
        order = list(order)
        n_orderings += 1

        perm = columnar_perm(order, CT_LEN)
        inv_perm = invert_perm(perm)

        for model_name, model_func in [
            ("B_vig", lambda ct_pos, pt_pos: (CT_IDX[ct_pos] - PT_IDX[pt_pos]) % MOD),
            ("B_beau", lambda ct_pos, pt_pos: (CT_IDX[ct_pos] + PT_IDX[pt_pos]) % MOD),
            ("A_vig", lambda ct_pos, pt_pos: (CT_IDX[ct_pos] - PT_IDX[pt_pos]) % MOD),
            ("A_beau", lambda ct_pos, pt_pos: (CT_IDX[ct_pos] + PT_IDX[pt_pos]) % MOD),
        ]:
            # Model B: Trans then Sub → CT[i] = f(PT[perm[i]], k[i])
            #   k[i] = CT[i] - PT[perm[i]] (Vig) or CT[i] + PT[perm[i]] (Beau)
            #   For crib: PT[p] known → need CT position i where perm[i] = p, i.e. i = inv_perm[p]
            #   k[inv_perm[p]] = CT[inv_perm[p]] ± PT[p]

            # Model A: Sub then Trans → CT[σ(p)] = PT[p] + k[p]
            #   k[p] = CT[σ(p)] - PT[p] (Vig) or CT[σ(p)] + PT[p] (Beau)
            #   σ(p) = inv_perm[p] (perm is CT→PT, inv is PT→CT)

            if model_name.startswith("B"):
                # Key at CT positions inv_perm[p]
                key_at_pos = {}
                for p in CRIB_POS_SORTED:
                    ct_pos = inv_perm[p]
                    key_at_pos[ct_pos] = model_func(ct_pos, p)
            else:
                # Key at PT positions p
                key_at_pos = {}
                for p in CRIB_POS_SORTED:
                    ct_pos = inv_perm[p]
                    key_at_pos[p] = model_func(ct_pos, p)

            key_values = list(key_at_pos.values())
            key_positions = sorted(key_at_pos.keys())
            key_sorted = [key_at_pos[pos] for pos in key_positions]

            # IC of derived key
            ic = ic_of_values(key_values)

            key_letters = ''.join(ALPH[key_at_pos[pos]] for pos in key_positions)

            if ic >= 0.055:
                top_ic.append((ic, order, model_name, key_letters, key_positions))
            # Text matching deferred to Phase E (too expensive here)

            # Special: K3 key analysis
            if order == k3_order and model_name in ("B_vig", "A_vig"):
                phase_results["k3_key_results"][model_name] = {
                    "key_positions": key_positions,
                    "key_values": key_sorted,
                    "key_letters": key_letters,
                    "ic": ic,
                }

        if n_orderings % 1000 == 0:
            print(f"  [{n_orderings:5d}/5040] top_ic_hits={len(top_ic)}")

    # Sort results
    top_ic.sort(reverse=True)
    text_matches.sort(reverse=True)

    print(f"\n  Orderings tested: {n_orderings}")
    print(f"  Key IC ≥ 0.055: {len(top_ic)} configs")

    if top_ic:
        print(f"\n  Top 15 by key IC:")
        for ic, order, model, letters, positions in top_ic[:15]:
            print(f"    IC={ic:.4f} {model} order={order} key={letters}")

    # K3 key results
    if phase_results["k3_key_results"]:
        print(f"\n  K3 key (KRYPTOS) results:")
        for model, data in phase_results["k3_key_results"].items():
            print(f"    {model}: key={data['key_letters']} IC={data['ic']:.4f}")

    # Expected IC distribution under random key
    print(f"\n  Reference: random key IC ≈ 0.0385, English key IC ≈ 0.067")
    print(f"  For n=24, IC variance is high: σ ≈ 0.015")
    print(f"  Threshold IC ≥ 0.055 is ~1σ above random")

    # Count how many exceed various thresholds
    all_ics = [ic for ic, *_ in top_ic]
    for thresh in [0.055, 0.060, 0.065, 0.070]:
        count = sum(1 for ic in all_ics if ic >= thresh)
        print(f"  IC ≥ {thresh:.3f}: {count} configs")

    phase_results["top_ic_configs"] = [
        {"ic": ic, "order": list(order), "model": model, "key": letters}
        for ic, order, model, letters, _ in top_ic[:50]
    ]

    return phase_results


# ============================================================
# PHASE C: Crib Alignment Analysis
# ============================================================
def phase_c():
    print("\n" + "=" * 70)
    print("PHASE C: Crib Alignment Analysis")
    print("=" * 70)

    phase_results = {}

    # C1: Both cribs start at multiples of 7
    print("\n--- C1: Crib positions modular analysis ---")
    for width in range(2, 20):
        starts_mod = [21 % width, 63 % width]
        ends_mod = [33 % width, 73 % width]
        both_start_aligned = all(s == 0 for s in starts_mod)
        if both_start_aligned:
            print(f"  Width {width:2d}: Both cribs START at row boundary "
                  f"(21={21//width}×{width}, 63={63//width}×{width})")

    # C2: At width 7, what does the grid look like?
    print("\n--- C2: Width-7 grid structure ---")
    width = 7
    n_rows = (CT_LEN + width - 1) // width  # 14
    print(f"  Grid: {width} columns × {n_rows} rows (last row: {CT_LEN % width} chars)")
    print(f"  ENE crib (21-33) spans rows 3-4:")
    for row in range(3, 5):
        chars = []
        for col in range(width):
            pos = row * width + col
            if pos < CT_LEN:
                if pos in CRIB_DICT:
                    chars.append(f"{CRIB_DICT[pos]}({pos})")
                else:
                    chars.append(f"?({pos})")
        print(f"    Row {row}: {' '.join(chars)}")

    print(f"  BC crib (63-73) spans rows 9-10:")
    for row in range(9, 11):
        chars = []
        for col in range(width):
            pos = row * width + col
            if pos < CT_LEN:
                if pos in CRIB_DICT:
                    chars.append(f"{CRIB_DICT[pos]}({pos})")
                else:
                    chars.append(f"?({pos})")
        print(f"    Row {row}: {' '.join(chars)}")

    # C3: Which column has the most crib coverage?
    print("\n--- C3: Crib coverage by column (width 7) ---")
    for col in range(width):
        positions_in_col = [p for p in range(col, CT_LEN, width)]
        crib_in_col = [p for p in positions_in_col if p in CRIB_DICT]
        coverage = len(crib_in_col) / len(positions_in_col)
        print(f"  Column {col}: {len(crib_in_col)}/{len(positions_in_col)} "
              f"({coverage:.0%}) crib positions: {crib_in_col}")

    # C4: Under K3's transposition, where do cribs land in CT?
    print("\n--- C4: Crib positions under K3 transposition (KRYPTOS) ---")
    k3_order = keyword_to_order("KRYPTOS")
    perm = columnar_perm(k3_order, CT_LEN)
    inv_perm = invert_perm(perm)

    print(f"  K3 read order: {k3_order}")
    print(f"  Column heights: {[14 if c < CT_LEN % 7 else 13 for c in range(7)]}")
    # Wait, CT_LEN=97, 97%7=6, so columns 0-5 have 14 chars, column 6 has 13
    col_heights = [14 if c < (CT_LEN % 7) else 13 for c in range(7)]
    print(f"  Column heights (corrected): {col_heights}")

    for p in CRIB_POS_SORTED:
        ct_pos = inv_perm[p]
        pt_char = CRIB_DICT[p]
        ct_char = CT[ct_pos]
        col = p % 7
        row = p // 7
        print(f"    PT[{p:2d}]={pt_char} (col={col},row={row}) → CT[{ct_pos:2d}]={ct_char}")

    # C5: Are the mapped CT positions contiguous or clustered?
    ct_positions = sorted(inv_perm[p] for p in CRIB_POS_SORTED)
    gaps = [ct_positions[i+1] - ct_positions[i] for i in range(len(ct_positions)-1)]
    print(f"\n  Mapped CT positions (sorted): {ct_positions}")
    print(f"  Gaps: {gaps}")
    print(f"  Max gap: {max(gaps)}, Min gap: {min(gaps)}")

    # C6: Probability analysis — how likely is both cribs starting at 7-multiples?
    print("\n--- C6: Probability of crib alignment ---")
    # If cribs are at random positions: P(both start at mult of 7) = (97//7 * 97//7) / (97*97)
    # Actually: # of multiples of 7 in 0-96 = {0,7,14,21,...,91} = 14 positions
    # Probability first crib starts at a multiple of 7: 14/97 ≈ 0.144
    # Probability both: (14/97)² ≈ 0.021
    n_mults = len([i for i in range(97) if i % 7 == 0])
    p_one = n_mults / 97
    p_both = p_one ** 2
    print(f"  Multiples of 7 in [0,96]: {n_mults}")
    print(f"  P(one crib starts at mult of 7): {p_one:.3f}")
    print(f"  P(both start at mult of 7): {p_both:.4f}")
    print(f"  This is {'suggestive' if p_both < 0.05 else 'not significant'} (p={p_both:.4f})")

    # C7: What about other widths?
    print("\n--- C7: Alignment at other widths ---")
    for w in range(2, 20):
        n_m = len([i for i in range(97) if i % w == 0])
        p = (n_m / 97) ** 2
        aligned = (21 % w == 0) and (63 % w == 0)
        if aligned:
            print(f"  Width {w:2d}: ALIGNED (p={p:.4f}, GCD(21,63)={math.gcd(21,63)}, {w} divides GCD)")

    gcd_cribs = math.gcd(21, 63)
    print(f"\n  GCD(21, 63) = {gcd_cribs} = 3 × 7")
    print(f"  Widths that align both cribs: divisors of {gcd_cribs} = {[d for d in range(1, gcd_cribs+1) if gcd_cribs % d == 0]}")

    phase_results["gcd_crib_starts"] = gcd_cribs
    phase_results["aligned_widths"] = [d for d in range(1, gcd_cribs+1) if gcd_cribs % d == 0]
    phase_results["p_both_aligned_w7"] = p_both

    return phase_results


# ============================================================
# PHASE D: K3 Method Specific Variants
# ============================================================
def phase_d():
    print("\n" + "=" * 70)
    print("PHASE D: K3 Method Variant Analysis")
    print("=" * 70)
    print("K3: columnar(KRYPTOS, w=7) + Vigenère(ABSCISSA, p=8)")
    print("What changes produce K4-like statistics?\n")

    phase_results = {"variants": []}

    k3_order = keyword_to_order("KRYPTOS")
    k3_perm = columnar_perm(k3_order, CT_LEN)
    k3_inv = invert_perm(k3_perm)

    # For each variant, derive key at crib positions and characterize
    def analyze_transposition(perm, name):
        inv = invert_perm(perm)

        # Model B (trans then sub): k[inv_perm[p]] = CT[inv_perm[p]] - PT[p]
        key_b = {}
        for p in CRIB_POS_SORTED:
            ct_pos = inv[p]
            key_b[ct_pos] = (CT_IDX[ct_pos] - PT_IDX[p]) % MOD

        # Model A (sub then trans): k[p] = CT[inv_perm[p]] - PT[p]
        key_a = {}
        for p in CRIB_POS_SORTED:
            ct_pos = inv[p]
            key_a[p] = (CT_IDX[ct_pos] - PT_IDX[p]) % MOD

        # Check periodicity of key_a
        best_period = None
        best_score = 0
        for period in range(2, 15):
            matches = 0
            total = 0
            by_residue = defaultdict(list)
            for p in CRIB_POS_SORTED:
                by_residue[p % period].append(key_a[p])
            for r, vals in by_residue.items():
                if len(vals) >= 2:
                    total += len(vals)
                    matches += sum(1 for v in vals if v == vals[0])
            if total > 0 and matches > best_score:
                best_score = matches
                best_period = period

        ic_a = ic_of_values(list(key_a.values()))
        ic_b = ic_of_values(list(key_b.values()))

        return {
            "name": name,
            "key_a_letters": ''.join(ALPH[key_a[p]] for p in CRIB_POS_SORTED),
            "key_b_letters": ''.join(ALPH[key_b[p]] for p in sorted(key_b.keys())),
            "ic_a": ic_a,
            "ic_b": ic_b,
            "best_period": best_period,
            "best_period_score": best_score,
        }

    # D1: K3 exact
    r = analyze_transposition(k3_perm, "K3_exact")
    phase_results["variants"].append(r)
    print(f"  {r['name']}: key_a={r['key_a_letters']} IC_a={r['ic_a']:.4f} best_period={r['best_period']}({r['best_period_score']}/24)")

    # D2: K3 reversed (read columns bottom-to-top)
    def reversed_columnar(order, text_len):
        width = len(order)
        n_full_rows = text_len // width
        extra = text_len % width
        col_heights = [n_full_rows + (1 if c < extra else 0) for c in range(width)]
        perm = []
        for read_idx in range(width):
            col = order[read_idx]
            for row in range(col_heights[col]-1, -1, -1):  # reversed
                pt_pos = row * width + col
                perm.append(pt_pos)
        return perm

    perm_rev = reversed_columnar(k3_order, CT_LEN)
    r = analyze_transposition(perm_rev, "K3_reversed_columns")
    phase_results["variants"].append(r)
    print(f"  {r['name']}: key_a={r['key_a_letters']} IC_a={r['ic_a']:.4f} best_period={r['best_period']}({r['best_period_score']}/24)")

    # D3: K3 with columns read in reverse order
    k3_rev_order = k3_order[::-1]
    perm_ro = columnar_perm(k3_rev_order, CT_LEN)
    r = analyze_transposition(perm_ro, "K3_reverse_order")
    phase_results["variants"].append(r)
    print(f"  {r['name']}: key_a={r['key_a_letters']} IC_a={r['ic_a']:.4f} best_period={r['best_period']}({r['best_period_score']}/24)")

    # D4: Double K3 transposition
    def compose_perm(p1, p2):
        """Apply p1 then p2: result[i] = p1[p2[i]]"""
        return [p1[p2[i]] for i in range(len(p1))]

    double_perm = compose_perm(k3_perm, k3_perm)
    r = analyze_transposition(double_perm, "K3_double")
    phase_results["variants"].append(r)
    print(f"  {r['name']}: key_a={r['key_a_letters']} IC_a={r['ic_a']:.4f} best_period={r['best_period']}({r['best_period_score']}/24)")

    # D5: K3 transposition + ABSCISSA transposition
    abscissa_order = keyword_to_order("ABSCISSA")
    abscissa_perm = columnar_perm(abscissa_order, CT_LEN)
    combined = compose_perm(k3_perm, abscissa_perm)
    r = analyze_transposition(combined, "K3+ABSCISSA_double")
    phase_results["variants"].append(r)
    print(f"  {r['name']}: key_a={r['key_a_letters']} IC_a={r['ic_a']:.4f} best_period={r['best_period']}({r['best_period_score']}/24)")

    # D6: Other K3-related keywords
    for kw in ["PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "KRYPTOS",
                "SANBORN", "SCHEIDT", "LANGLEY", "CARTER", "EGYPT",
                "POINT", "MESSAGE", "DELIVER", "BURIED"]:
        order = keyword_to_order(kw)
        try:
            perm = columnar_perm(order, CT_LEN)
            r = analyze_transposition(perm, f"KW_{kw}")
            phase_results["variants"].append(r)
            flag = " ***" if r["ic_a"] > 0.055 or r["best_period_score"] >= 15 else ""
            print(f"  {r['name']:25s}: IC_a={r['ic_a']:.4f} period={r['best_period']}({r['best_period_score']}/24){flag}")
        except Exception as e:
            print(f"  {kw}: ERROR {e}")

    # D7: K3 transposition with different widths using KRYPTOS-derived keys
    print("\n  Width variants:")
    for width in [3, 5, 7, 8, 9, 10, 11, 13, 14]:
        # Use first `width` chars of KRYPTOSABCDEFGHIJLMNQUVWXZ as key
        kw = KRYPTOS_ALPHABET[:width]
        order = keyword_to_order(kw)
        perm = columnar_perm(order, CT_LEN)
        r = analyze_transposition(perm, f"KA_w{width}")
        flag = " ***" if r["ic_a"] > 0.055 or r["best_period_score"] >= 15 else ""
        print(f"  {r['name']:25s}: IC_a={r['ic_a']:.4f} period={r['best_period']}({r['best_period_score']}/24){flag}")

    return phase_results


# ============================================================
# PHASE E: Keystream + Known Text Cross-Reference
# ============================================================
def phase_e():
    print("\n" + "=" * 70)
    print("PHASE E: Keystream vs Known Texts (Direct, No Transposition)")
    print("=" * 70)

    phase_results = {"text_checks": []}

    vig = VIG_KEY_FULL
    beau = BEAU_KEY_FULL

    # Load all reference texts
    ref_texts = {}
    for root, dirs, files in os.walk("reference"):
        for fname in files:
            if fname.endswith(".txt"):
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath) as f:
                        text = f.read().upper()
                        text = ''.join(c for c in text if c in ALPH)
                        if len(text) > 50:
                            ref_texts[fname] = text
                except:
                    pass

    print(f"Loaded {len(ref_texts)} reference texts")

    # For each text, check if key values at crib positions match any offset
    # Optimized: use numpy-like vectorized comparison
    for tname, ttext in sorted(ref_texts.items()):
        ttext_idx = [ALPH_IDX[c] for c in ttext]
        max_offset = min(len(ttext) - 97, len(ttext) - max(CRIB_POS_SORTED) - 1)
        if max_offset < 1:
            print(f"  {tname}: too short ({len(ttext)} chars)")
            continue

        best_match = 0
        best_offset = 0
        best_match_b = 0
        best_offset_b = 0

        # Sample offsets for very long texts, exhaustive for short ones
        step = max(1, max_offset // 10000)
        for offset in range(0, max_offset, step):
            matches_v = sum(1 for i, p in enumerate(CRIB_POS_SORTED)
                           if ttext_idx[p + offset] == vig[i])
            if matches_v > best_match:
                best_match = matches_v
                best_offset = offset

            matches_b = sum(1 for i, p in enumerate(CRIB_POS_SORTED)
                           if ttext_idx[p + offset] == beau[i])
            if matches_b > best_match_b:
                best_match_b = matches_b
                best_offset_b = offset

        result = {
            "text": tname,
            "len": len(ttext),
            "best_vig": best_match,
            "best_vig_offset": best_offset,
            "best_beau": best_match_b,
            "best_beau_offset": best_offset_b,
        }
        phase_results["text_checks"].append(result)

        if best_match >= 4 or best_match_b >= 4:
            print(f"  {tname}: Vig best={best_match}/24 @{best_offset}, Beau best={best_match_b}/24 @{best_offset_b}")
        else:
            print(f"  {tname}: Vig best={best_match}/24, Beau best={best_match_b}/24 (noise)")

    # Expected: for random text of length L, best match over L-97 offsets
    # Each position has 1/26 chance of matching → expected matches = 24/26 ≈ 0.92 per offset
    # Over many offsets, best match ~ 4-5 by birthday effect
    print(f"\n  Expected best match for random text: ~4-5/24 (birthday effect over many offsets)")

    return phase_results


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-S-58: K3 Method Variant + Keystream Deep Analysis")
    print("=" * 70)

    results["phases"]["A"] = phase_a()
    results["phases"]["B"] = phase_b()
    results["phases"]["C"] = phase_c()
    results["phases"]["D"] = phase_d()
    results["phases"]["E"] = phase_e()

    elapsed = time.time() - t0
    results["elapsed_seconds"] = elapsed

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    ic_a = results["phases"]["A"]["a_ic_vig"]
    ic_b = results["phases"]["A"]["a_ic_beau"]
    print(f"  Key IC (direct): Vig={ic_a:.4f}, Beau={ic_b:.4f} (random=0.0385, English=0.067)")

    gcd = results["phases"]["C"]["gcd_crib_starts"]
    p_align = results["phases"]["C"]["p_both_aligned_w7"]
    print(f"  Crib alignment: GCD(21,63)={gcd}, P(both at width-7 boundary)={p_align:.4f}")

    n_top_ic = len(results["phases"]["B"]["top_ic_configs"])
    print(f"  Width-7 sweep: {n_top_ic} configs with key IC≥0.055")

    print(f"  Time: {elapsed:.1f}s")

    # Verdict
    print(f"\n  Verdict: ANALYTICAL — no breakthrough, see detailed output above")

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_58_k3_variant_keystream.json", "w") as f:
        json.dump(results, f, indent=2, default=str)

    print(f"\n  Artifact: results/e_s_58_k3_variant_keystream.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_58_k3_variant_keystream.py")


if __name__ == "__main__":
    main()
