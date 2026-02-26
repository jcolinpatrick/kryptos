#!/usr/bin/env python3
"""E-CHART-05: Antipodes-Corrected Misspelling Tableau Modifications

The Antipodes sculpture (Sanborn's companion piece at Hirshhorn Museum) CORRECTS
the UNDERGRUUND misspelling to UNDERGROUND. This means the O->U substitution was
likely a genuine error, not a cipher instruction.

Deliberate misspellings (reduced set of 4):
  1. S->C  (PALIMPCEST in K1)
  2. L->Q  (IQLUSION in K1)
  3. E->A  (DESPARATLY in K3)
  4. I->E  (DIGETAL in K0 Morse)

Tests:
  1. 4-pair ROW swaps in KA tableau
  2. 4-pair COLUMN swaps in KA tableau
  3. 4-pair BOTH row+column swaps
  4. Keywords from 4-pair letters (CQAE, ISLE, LIES, etc.)
  5. "One clue" hypothesis: HILL keyword + L-shift + 4-pair modified tableau
  6. Combined: HILL keyword + 4-pair modified tableau + K3 running key
  7. LIES/ISLE as keyword through modified tableau
  Top-5 configs also tested with width-8 columnar transposition (all 40,320 orderings).
"""

import json
import os
import sys
import time
from itertools import permutations

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS,
    ALPH, ALPH_IDX, KRYPTOS_ALPHABET,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean

# ── Constants ─────────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET  # KRYPTOSABCDEFGHIJLMNQUVWXZ
KA_IDX = {c: i for i, c in enumerate(KA)}
MOD = 26
N = CT_LEN

# The 4 deliberate misspelling pairs (wrong_letter, right_letter)
# S->C means Sanborn wrote C where S was correct
MISSPELLING_PAIRS = [
    ('S', 'C'),  # PALIMPCEST (C instead of S)
    ('L', 'Q'),  # IQLUSION   (Q instead of L)
    ('E', 'A'),  # DESPARATLY (A instead of E)
    ('I', 'E'),  # DIGETAL    (E instead of I)
]

# Keywords to test
THEMATIC_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "LAYERTWO",
    "YAR", "STOPWATCH", "GOLD",
]

# Keywords from misspelling letters
WRONG_LETTERS = "CQAE"  # The wrong letters
RIGHT_LETTERS = "SLEI"  # The right letters

MISSPELLING_KEYWORDS = [
    "CQAE", "EAQC", "ACQE", "AQCE",  # wrong letters
    "SLEI", "IELS", "SILE", "LEIS",   # right letters
    "ISLE", "LIES", "LISE",            # English words from right letters
]

ALL_KEYWORDS = THEMATIC_KEYWORDS + MISSPELLING_KEYWORDS + ["HILL"]

VARIANT_NAMES = ["vig", "beau", "var_beau"]


# ── Tableau building ──────────────────────────────────────────────────────

def build_standard_tableau(alphabet):
    """Build standard Vigenere tableau: row r, col c -> alphabet[(r+c) % 26]."""
    n = len(alphabet)
    return [[alphabet[(r + c) % n] for c in range(n)] for r in range(n)]


def swap_rows(tableau, a_char, b_char, alphabet):
    """Swap two rows in the tableau (rows indexed by alphabet position of char)."""
    idx = {c: i for i, c in enumerate(alphabet)}
    ra, rb = idx[a_char], idx[b_char]
    t = [row[:] for row in tableau]
    t[ra], t[rb] = t[rb], t[ra]
    return t


def swap_cols(tableau, a_char, b_char, alphabet):
    """Swap two columns in the tableau."""
    idx = {c: i for i, c in enumerate(alphabet)}
    ca, cb = idx[a_char], idx[b_char]
    t = [row[:] for row in tableau]
    for row in t:
        row[ca], row[cb] = row[cb], row[ca]
    return t


def apply_misspelling_swaps(tableau, alphabet, mode):
    """Apply misspelling-derived swaps.
    mode: 'rows', 'cols', 'both'
    """
    t = [row[:] for row in tableau]
    for wrong, right in MISSPELLING_PAIRS:
        if mode in ('rows', 'both'):
            t = swap_rows(t, wrong, right, alphabet)
        if mode in ('cols', 'both'):
            t = swap_cols(t, wrong, right, alphabet)
    return t


def shift_tableau_rows(tableau, shift):
    """Cyclically shift all rows of the tableau by `shift` positions."""
    n = len(tableau)
    return [tableau[(r + shift) % n] for r in range(n)]


# ── Decrypt via modified tableau ──────────────────────────────────────────

def decrypt_via_tableau(ct_str, keyword, tableau, alphabet, variant):
    """Decrypt CT using a keyword through a (possibly modified) tableau.

    Standard Vigenere tableau usage:
      - Vig:  Find CT char in row indexed by KEY char; column index = PT
      - Beau: Find CT char in column indexed by KEY char; row index = PT
      - VB:   Find CT char in row indexed by KEY char; but PT = col
              (VB is just Vig with reversed key, we handle it explicitly)

    For modified tableaux, the lookup remains the same but the tableau content differs.
    """
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    kw_nums = [alph_idx[c] for c in keyword]
    klen = len(kw_nums)
    n = len(alphabet)
    pt_chars = []

    for i, ct_ch in enumerate(ct_str):
        k_idx = kw_nums[i % klen]
        ct_idx = alph_idx[ct_ch]

        if variant == "vig":
            # Row = key, find ct_ch in that row, column = PT index
            row = tableau[k_idx]
            # Build reverse lookup for this row
            found = False
            for col in range(n):
                if row[col] == ct_ch:
                    pt_chars.append(alphabet[col])
                    found = True
                    break
            if not found:
                pt_chars.append('?')

        elif variant == "beau":
            # Column = key, find ct_ch in that column, row = PT index
            found = False
            for row_idx in range(n):
                if tableau[row_idx][k_idx] == ct_ch:
                    pt_chars.append(alphabet[row_idx])
                    found = True
                    break
            if not found:
                pt_chars.append('?')

        elif variant == "var_beau":
            # VB: C = (P - K) mod 26, so P = (C + K) mod 26
            # Through tableau: row = key, column = result of (ct + key) lookup
            # For standard tableau this gives P = alphabet[(ct_idx + k_idx) % n]
            # For modified tableau, use direct position math on alphabet indices
            row = tableau[k_idx]
            # In VB, if C = P - K, then P = C + K. Through tableau:
            # We need the character at position (ct_idx + k_idx) mod n in the UNMODIFIED sense
            # But with modified tableau, interpret: row[ct_idx] gives the output
            pt_chars.append(row[ct_idx])

    return "".join(pt_chars)


def decrypt_numeric(ct_str, key_nums, variant, alphabet):
    """Standard numeric decrypt (no tableau modification)."""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    n = len(alphabet)
    pt = []
    klen = len(key_nums)
    for i, c in enumerate(ct_str):
        ci = alph_idx[c]
        ki = key_nums[i % klen]
        if variant == "vig":
            pi = (ci - ki) % n
        elif variant == "beau":
            pi = (ki - ci) % n
        else:  # var_beau
            pi = (ci + ki) % n
        pt.append(alphabet[pi])
    return "".join(pt)


def count_crib_matches(pt_str):
    """Count matching crib positions."""
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(pt_str) and pt_str[pos] == ch)


def derive_keystream_numeric(ct_str, pt_str, variant, alphabet):
    """Derive keystream from CT and PT."""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    n = len(alphabet)
    ks = []
    for i in range(len(ct_str)):
        ci = alph_idx[ct_str[i]]
        pi = alph_idx[pt_str[i]]
        if variant == "vig":
            ks.append((ci - pi) % n)
        elif variant == "beau":
            ks.append((ci + pi) % n)
        else:  # var_beau
            ks.append((pi - ci) % n)
    return ks


# ── Columnar transposition ───────────────────────────────────────────────

def build_columnar_perm(order, width, n):
    """Build gather permutation for columnar transposition."""
    nrows = n // width
    nextra = n % width
    col_lengths = [nrows + 1 if c < nextra else nrows for c in range(width)]
    perm = []
    for rank in range(width):
        col = order[rank]
        clen = col_lengths[col]
        for row in range(clen):
            pt_pos = row * width + col
            perm.append(pt_pos)
    return perm


def apply_inv_transposition(text, perm):
    """Apply inverse columnar transposition (scatter)."""
    n = len(text)
    pt = ['?'] * n
    for j in range(n):
        pt[perm[j]] = text[j]
    return "".join(pt)


# ── K3 plaintext for running key tests ───────────────────────────────────

K3_PLAINTEXT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFW"
    "HATIWASONCETHELIFEOFUSALLBEGINTOLOS"
    "EITNOWSEEMINGLYTHEIMPLICATIONSOFPA"
)
# Trim/pad to 97 chars
K3_KEY = K3_PLAINTEXT[:97] if len(K3_PLAINTEXT) >= 97 else (K3_PLAINTEXT * 2)[:97]


# ══════════════════════════════════════════════════════════════════════════
# MAIN EXECUTION
# ══════════════════════════════════════════════════════════════════════════

print("=" * 72)
print("E-CHART-05: Antipodes-Corrected Misspelling Tableau Modifications")
print("=" * 72)
print(f"  CT: {CT[:50]}...")
print(f"  KA: {KA}")
print(f"  Misspelling pairs (4): {MISSPELLING_PAIRS}")
print(f"  Keywords: {len(ALL_KEYWORDS)}")
print()

t0 = time.time()
all_results = []
best_overall = {"score": 0, "config": None, "pt": ""}


def record(config_dict, pt_str):
    """Record a result and update global best."""
    global best_overall
    cribs = count_crib_matches(pt_str)
    config_dict["crib_score"] = cribs
    config_dict["pt_preview"] = pt_str[:50]
    all_results.append(config_dict)

    if cribs > best_overall["score"]:
        best_overall = {"score": cribs, "config": config_dict.copy(), "pt": pt_str}

    if cribs > NOISE_FLOOR:
        sb = score_candidate(pt_str)
        config_dict["ic"] = sb.ic_value
        config_dict["full_pt"] = pt_str
        print(f"  ABOVE NOISE: cribs={cribs}/24 | {config_dict.get('test','')} "
              f"| {config_dict.get('variant','')} kw={config_dict.get('keyword','')}"
              f" | IC={sb.ic_value:.4f}")
        print(f"    PT: {pt_str[:60]}...")

    return cribs


# ── Test 1: 4-pair ROW swaps ─────────────────────────────────────────────
print("-" * 72)
print("Test 1: 4-pair ROW swaps in KA tableau")
print("-" * 72)

for alph_name, alphabet in [("KA", KA), ("AZ", ALPH)]:
    base_tableau = build_standard_tableau(alphabet)
    mod_tableau = apply_misspelling_swaps(base_tableau, alphabet, 'rows')

    for variant in VARIANT_NAMES:
        for keyword in ALL_KEYWORDS:
            pt = decrypt_via_tableau(CT, keyword, mod_tableau, alphabet, variant)
            record({
                "test": "row_swap",
                "alphabet": alph_name,
                "variant": variant,
                "keyword": keyword,
                "swap_mode": "rows",
            }, pt)

t1 = time.time()
print(f"  Test 1 done: {t1 - t0:.1f}s, best so far: {best_overall['score']}/24")

# ── Test 2: 4-pair COLUMN swaps ──────────────────────────────────────────
print("-" * 72)
print("Test 2: 4-pair COLUMN swaps in KA tableau")
print("-" * 72)

for alph_name, alphabet in [("KA", KA), ("AZ", ALPH)]:
    base_tableau = build_standard_tableau(alphabet)
    mod_tableau = apply_misspelling_swaps(base_tableau, alphabet, 'cols')

    for variant in VARIANT_NAMES:
        for keyword in ALL_KEYWORDS:
            pt = decrypt_via_tableau(CT, keyword, mod_tableau, alphabet, variant)
            record({
                "test": "col_swap",
                "alphabet": alph_name,
                "variant": variant,
                "keyword": keyword,
                "swap_mode": "cols",
            }, pt)

t2 = time.time()
print(f"  Test 2 done: {t2 - t1:.1f}s, best so far: {best_overall['score']}/24")

# ── Test 3: 4-pair BOTH row+column swaps ─────────────────────────────────
print("-" * 72)
print("Test 3: 4-pair BOTH row+column swaps in KA tableau")
print("-" * 72)

for alph_name, alphabet in [("KA", KA), ("AZ", ALPH)]:
    base_tableau = build_standard_tableau(alphabet)
    mod_tableau = apply_misspelling_swaps(base_tableau, alphabet, 'both')

    for variant in VARIANT_NAMES:
        for keyword in ALL_KEYWORDS:
            pt = decrypt_via_tableau(CT, keyword, mod_tableau, alphabet, variant)
            record({
                "test": "both_swap",
                "alphabet": alph_name,
                "variant": variant,
                "keyword": keyword,
                "swap_mode": "both",
            }, pt)

t3 = time.time()
print(f"  Test 3 done: {t3 - t2:.1f}s, best so far: {best_overall['score']}/24")

# ── Test 4: Keywords from misspelling letters ────────────────────────────
print("-" * 72)
print("Test 4: Keywords from misspelling letters (unmodified tableau)")
print("-" * 72)

for alph_name, alphabet in [("KA", KA), ("AZ", ALPH)]:
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    base_tableau = build_standard_tableau(alphabet)

    for variant in VARIANT_NAMES:
        for keyword in MISSPELLING_KEYWORDS:
            # Through unmodified tableau
            pt = decrypt_via_tableau(CT, keyword, base_tableau, alphabet, variant)
            record({
                "test": "misspelling_kw_plain",
                "alphabet": alph_name,
                "variant": variant,
                "keyword": keyword,
            }, pt)

            # Through modified tableau (all 3 modes)
            for mode in ['rows', 'cols', 'both']:
                mod_tab = apply_misspelling_swaps(base_tableau, alphabet, mode)
                pt2 = decrypt_via_tableau(CT, keyword, mod_tab, alphabet, variant)
                record({
                    "test": f"misspelling_kw_{mode}",
                    "alphabet": alph_name,
                    "variant": variant,
                    "keyword": keyword,
                    "swap_mode": mode,
                }, pt2)

t4 = time.time()
print(f"  Test 4 done: {t4 - t3:.1f}s, best so far: {best_overall['score']}/24")

# ── Test 5: "One clue" hypothesis — HILL + L-shift + modified tableau ────
print("-" * 72)
print("Test 5: HILL keyword + L-shift + modified tableau")
print("-" * 72)

for alph_name, alphabet in [("KA", KA), ("AZ", ALPH)]:
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    base_tableau = build_standard_tableau(alphabet)
    l_pos = alph_idx['L']

    for variant in VARIANT_NAMES:
        # Test 5a: HILL with standard tableau
        pt = decrypt_via_tableau(CT, "HILL", base_tableau, alphabet, variant)
        record({
            "test": "hill_plain",
            "alphabet": alph_name,
            "variant": variant,
            "keyword": "HILL",
        }, pt)

        # Test 5b: HILL with L-shifted tableau (all rows shifted by L's position)
        shifted_tab = shift_tableau_rows(base_tableau, l_pos)
        pt = decrypt_via_tableau(CT, "HILL", shifted_tab, alphabet, variant)
        record({
            "test": "hill_l_shift",
            "alphabet": alph_name,
            "variant": variant,
            "keyword": "HILL",
            "l_shift": l_pos,
        }, pt)

        # Test 5c: HILL with 4-pair modified + L-shift
        for mode in ['rows', 'cols', 'both']:
            mod_tab = apply_misspelling_swaps(base_tableau, alphabet, mode)
            shifted_mod = shift_tableau_rows(mod_tab, l_pos)
            pt = decrypt_via_tableau(CT, "HILL", shifted_mod, alphabet, variant)
            record({
                "test": f"hill_l_shift_{mode}",
                "alphabet": alph_name,
                "variant": variant,
                "keyword": "HILL",
                "l_shift": l_pos,
                "swap_mode": mode,
            }, pt)

        # Test 5d: HILL with 4-pair modified (no L-shift)
        for mode in ['rows', 'cols', 'both']:
            mod_tab = apply_misspelling_swaps(base_tableau, alphabet, mode)
            pt = decrypt_via_tableau(CT, "HILL", mod_tab, alphabet, variant)
            record({
                "test": f"hill_{mode}",
                "alphabet": alph_name,
                "variant": variant,
                "keyword": "HILL",
                "swap_mode": mode,
            }, pt)

t5 = time.time()
print(f"  Test 5 done: {t5 - t4:.1f}s, best so far: {best_overall['score']}/24")

# ── Test 6: HILL keyword + 4-pair modified tableau + K3 running key ──────
print("-" * 72)
print("Test 6: HILL keyword + modified tableau + K3 running key")
print("-" * 72)

for alph_name, alphabet in [("KA", KA), ("AZ", ALPH)]:
    alph_idx_map = {c: i for i, c in enumerate(alphabet)}
    base_tableau = build_standard_tableau(alphabet)

    for variant in VARIANT_NAMES:
        for mode in ['rows', 'cols', 'both', 'none']:
            if mode == 'none':
                tab = base_tableau
            else:
                tab = apply_misspelling_swaps(base_tableau, alphabet, mode)

            # Step 1: Decrypt with HILL keyword through modified tableau
            intermediate = decrypt_via_tableau(CT, "HILL", tab, alphabet, variant)

            # Step 2: Remove K3 running key (Vigenere subtraction)
            k3_key_nums = [alph_idx_map[c] for c in K3_KEY]
            for variant2 in VARIANT_NAMES:
                pt = decrypt_numeric(intermediate, k3_key_nums, variant2, alphabet)
                record({
                    "test": "hill_k3_running",
                    "alphabet": alph_name,
                    "variant": f"{variant}+{variant2}",
                    "keyword": "HILL",
                    "swap_mode": mode,
                    "running_key": "K3_PT",
                }, pt)

            # Also try: K3 running key first, then HILL
            k3_intermediate = decrypt_numeric(CT, k3_key_nums, variant, alphabet)
            for variant2 in VARIANT_NAMES:
                pt = decrypt_via_tableau(k3_intermediate, "HILL", tab, alphabet, variant2)
                record({
                    "test": "k3_then_hill",
                    "alphabet": alph_name,
                    "variant": f"{variant}+{variant2}",
                    "keyword": "HILL",
                    "swap_mode": mode,
                    "running_key": "K3_PT",
                }, pt)

t6 = time.time()
print(f"  Test 6 done: {t6 - t5:.1f}s, best so far: {best_overall['score']}/24")

# ── Test 7: LIES/ISLE as keyword through modified tableau ────────────────
print("-" * 72)
print("Test 7: LIES/ISLE keywords through modified tableau")
print("-" * 72)

english_word_keywords = ["LIES", "ISLE", "LEIS", "LISE"]

for alph_name, alphabet in [("KA", KA), ("AZ", ALPH)]:
    base_tableau = build_standard_tableau(alphabet)

    for variant in VARIANT_NAMES:
        for keyword in english_word_keywords:
            # Standard tableau
            pt = decrypt_via_tableau(CT, keyword, base_tableau, alphabet, variant)
            record({
                "test": "english_kw_plain",
                "alphabet": alph_name,
                "variant": variant,
                "keyword": keyword,
            }, pt)

            # Modified tableau (all modes)
            for mode in ['rows', 'cols', 'both']:
                mod_tab = apply_misspelling_swaps(base_tableau, alphabet, mode)
                pt2 = decrypt_via_tableau(CT, keyword, mod_tab, alphabet, variant)
                record({
                    "test": f"english_kw_{mode}",
                    "alphabet": alph_name,
                    "variant": variant,
                    "keyword": keyword,
                    "swap_mode": mode,
                }, pt2)

t7 = time.time()
print(f"  Test 7 done: {t7 - t6:.1f}s, best so far: {best_overall['score']}/24")

# ── Phase 2: Top-5 configs + width-8 columnar transposition ──────────────
print()
print("=" * 72)
print("Phase 2: Top-5 configs + width-8 columnar transposition")
print("  (40,320 orderings per config)")
print("=" * 72)

# Sort all results by crib score descending
all_results.sort(key=lambda x: -x["crib_score"])

# Deduplicate top configs by their resulting plaintext
seen_pts = set()
top5_configs = []
for r in all_results:
    pt_key = r.get("pt_preview", "")[:40]
    if pt_key not in seen_pts:
        seen_pts.add(pt_key)
        top5_configs.append(r)
    if len(top5_configs) >= 5:
        break

print(f"\nTop 5 configs for Phase 2 transposition testing:")
for i, cfg in enumerate(top5_configs):
    print(f"  {i+1}. cribs={cfg['crib_score']}/24 | {cfg.get('test','')} "
          f"| {cfg.get('alphabet','')} {cfg.get('variant','')} "
          f"kw={cfg.get('keyword','')} mode={cfg.get('swap_mode','')}")

WIDTH = 8
all_orders = list(permutations(range(WIDTH)))
print(f"\n  Width-8 orderings: {len(all_orders)}")

t8 = time.time()
phase2_best = {"score": 0, "config": None, "pt": ""}
phase2_above_noise = []

for cfg_idx, cfg in enumerate(top5_configs):
    # Reconstruct the plaintext for this config
    alph_name = cfg.get("alphabet", "KA")
    alphabet = KA if alph_name == "KA" else ALPH
    variant = cfg.get("variant", "vig")
    keyword = cfg.get("keyword", "KRYPTOS")
    swap_mode = cfg.get("swap_mode", "")
    test_name = cfg.get("test", "")

    base_tableau = build_standard_tableau(alphabet)
    if swap_mode and swap_mode != "none":
        tab = apply_misspelling_swaps(base_tableau, alphabet, swap_mode)
    else:
        tab = base_tableau

    # Check if this was a combined test (running key etc.)
    if "k3" in test_name or "running" in test_name:
        # Skip complex multi-step configs for transposition (too many combinations)
        print(f"  Config {cfg_idx+1}/5: SKIPPED (multi-step config)")
        continue

    # Check if L-shift was involved
    if "l_shift" in cfg:
        alph_idx_map = {c: i for i, c in enumerate(alphabet)}
        l_pos = alph_idx_map['L']
        tab = shift_tableau_rows(tab, l_pos)

    # Decrypt to get the intermediate text
    intermediate = decrypt_via_tableau(CT, keyword, tab, alphabet, variant)

    cfg_best = 0
    for order in all_orders:
        order_list = list(order)
        perm = build_columnar_perm(order_list, WIDTH, N)

        # Model B: substitution then transpose
        pt_b = apply_inv_transposition(intermediate, perm)
        cribs_b = count_crib_matches(pt_b)

        if cribs_b > cfg_best:
            cfg_best = cribs_b

        if cribs_b > phase2_best["score"]:
            phase2_best = {
                "score": cribs_b,
                "config": {
                    "test": test_name, "alphabet": alph_name,
                    "variant": variant, "keyword": keyword,
                    "swap_mode": swap_mode, "order": order_list,
                    "width": WIDTH, "model": "B_sub_then_transpose",
                },
                "pt": pt_b,
            }

        if cribs_b > NOISE_FLOOR:
            sb = score_candidate(pt_b)
            phase2_above_noise.append({
                "test": test_name, "alphabet": alph_name,
                "variant": variant, "keyword": keyword,
                "swap_mode": swap_mode, "order": order_list,
                "model": "B", "crib_score": cribs_b,
                "ic": sb.ic_value,
                "pt_preview": pt_b[:50],
            })

        # Model A: transpose CT then substitution
        ct_transposed = apply_inv_transposition(CT, perm)
        pt_a = decrypt_via_tableau(ct_transposed, keyword, tab, alphabet, variant)
        cribs_a = count_crib_matches(pt_a)

        if cribs_a > cfg_best:
            cfg_best = cribs_a

        if cribs_a > phase2_best["score"]:
            phase2_best = {
                "score": cribs_a,
                "config": {
                    "test": test_name, "alphabet": alph_name,
                    "variant": variant, "keyword": keyword,
                    "swap_mode": swap_mode, "order": order_list,
                    "width": WIDTH, "model": "A_transpose_then_sub",
                },
                "pt": pt_a,
            }

        if cribs_a > NOISE_FLOOR:
            sb = score_candidate(pt_a)
            phase2_above_noise.append({
                "test": test_name, "alphabet": alph_name,
                "variant": variant, "keyword": keyword,
                "swap_mode": swap_mode, "order": order_list,
                "model": "A", "crib_score": cribs_a,
                "ic": sb.ic_value,
                "pt_preview": pt_a[:50],
            })

    elapsed_cfg = time.time() - t8
    print(f"  Config {cfg_idx+1}/5: {test_name} {alph_name} {variant} "
          f"kw={keyword} mode={swap_mode} => best w8={cfg_best} [{elapsed_cfg:.1f}s]")

elapsed_p2 = time.time() - t8
print(f"\nPhase 2 complete in {elapsed_p2:.1f}s")
print(f"Phase 2 best: cribs={phase2_best['score']}/24")
if phase2_best["config"]:
    print(f"  Config: {phase2_best['config']}")
if phase2_best["pt"]:
    print(f"  PT: {phase2_best['pt'][:70]}...")

if phase2_above_noise:
    phase2_above_noise.sort(key=lambda x: -x["crib_score"])
    print(f"\nPhase 2 above-noise results ({len(phase2_above_noise)}):")
    for i, r in enumerate(phase2_above_noise[:15]):
        print(f"  {i+1:2d}. cribs={r['crib_score']:2d}/24 | {r['test']} "
              f"{r['alphabet']} {r['variant']} kw={r['keyword']} "
              f"order={r['order']} model={r['model']}")


# ── Summary ──────────────────────────────────────────────────────────────

total_elapsed = time.time() - t0

print()
print("=" * 72)
print("SUMMARY — E-CHART-05: Antipodes-Corrected Misspelling Tableau")
print("=" * 72)
print(f"  Total configs tested (Phase 1): {len(all_results)}")
print(f"  Phase 1 best: cribs={best_overall['score']}/24")
print(f"  Phase 2 best (w8 columnar): cribs={phase2_best['score']}/24")

overall_best = max(best_overall['score'], phase2_best['score'])
print(f"  Overall best: {overall_best}/24")

# Top 20 results
print(f"\nTop 20 Phase 1 results:")
for i, r in enumerate(all_results[:20]):
    print(f"  {i+1:2d}. cribs={r['crib_score']:2d}/24 | {r.get('test','')} "
          f"| {r.get('alphabet','')} {r.get('variant','')} "
          f"kw={r.get('keyword','')} mode={r.get('swap_mode','')}")

if overall_best >= 18:
    verdict = f"SIGNAL — {overall_best}/24 cribs, investigate further"
elif overall_best >= 10:
    verdict = f"INTERESTING — {overall_best}/24 cribs, check false positive rate"
elif overall_best > NOISE_FLOOR:
    verdict = f"MARGINAL — {overall_best}/24 cribs, above noise but not significant"
else:
    verdict = (f"NO SIGNAL — best {overall_best}/24 cribs. "
               "Antipodes-corrected 4-pair misspelling tableau ELIMINATED.")

print(f"\n  VERDICT: {verdict}")
print(f"  Total time: {total_elapsed:.1f}s")

# ── Save artifact ────────────────────────────────────────────────────────

os.makedirs("results", exist_ok=True)
output = {
    "experiment": "E-CHART-05",
    "description": "Antipodes-corrected misspelling tableau modifications (4 pairs, O->U removed)",
    "misspelling_pairs": [f"{w}->{r}" for w, r in MISSPELLING_PAIRS],
    "total_configs_phase1": len(all_results),
    "phase1_best": {
        "crib_score": best_overall["score"],
        "config": best_overall["config"],
        "pt": best_overall["pt"][:80] if best_overall["pt"] else None,
    },
    "phase2_best": {
        "crib_score": phase2_best["score"],
        "config": phase2_best["config"],
        "pt": phase2_best["pt"][:80] if phase2_best["pt"] else None,
    },
    "phase2_above_noise": phase2_above_noise[:20] if phase2_above_noise else [],
    "phase1_top20": [
        {k: v for k, v in r.items() if k != "full_pt"}
        for r in all_results[:20]
    ],
    "overall_best": overall_best,
    "verdict": verdict,
    "total_elapsed_seconds": total_elapsed,
    "keywords_tested": ALL_KEYWORDS,
    "repro": "PYTHONPATH=src python3 -u scripts/e_chart_05_antipodes_misspelling.py",
}

with open("results/e_chart_05_antipodes.json", "w") as f:
    json.dump(output, f, indent=2, default=str)

print(f"\n  Artifact: results/e_chart_05_antipodes.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_chart_05_antipodes_misspelling.py")
