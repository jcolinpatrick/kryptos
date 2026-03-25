#!/usr/bin/env python3
"""
Cipher: constructive-key-management
Family: two_system
Status: active
Keyspace: ~85M
Last run:
Best score:

E-CKM-03: CKM Credential-Based Key Construction from K1-K3

Hypothesis: K4's cipher key is CONSTRUCTED by combining K1/K2/K3 PLAINTEXT
(as "credentials") with a keyword through mod-26 operations, following Ed
Scheidt's CKM philosophy: protect the data, construct keys only when needed
from credential-linked values, destroy keys after use.

This fills the gap between:
  - E-CKM-02 (keyword × keyword, 170M configs, best 10/24)
  - K123 running key exhaustive (raw K-section PT as direct key, 247K, best 0/24)

Neither test combined K-section plaintext WITH a keyword. CKM says keys are
assembled from independent sources — one source is the "credential" (having
solved K1-K3), the other is a keyword seed.

Models:
  M1: key[i] = f(K_section_PT[i+d], keyword[i % Lk]) mod 26
      The section plaintext is one input, a cycling keyword is the other.
  M2: key[i] = f(K_section_PT[(i*step+d) % Ls], keyword[i % Lk]) mod 26
      Decimated/strided access into section plaintext.
  M3: key[i] = f(K_section_PT[perm(i)+d], keyword[i % Lk]) mod 26
      Columnar-transposed section PT combined with keyword.
  M4: key[i] = f(concat_sections[i+d], keyword[i % Lk]) mod 26
      Concatenated K1+K2+K3 (all 6 orderings) as credential source.
  M5: key[i] = f(section_PT[i+d], coords[i % 7]) mod 26
      Section PT combined with K2 coordinate values (heterogeneous).
  M6: Progressive credential — K1_method(K2_keyword) → K3_key → K4_key
      Each section's solution reveals the next section's key component.

Combination functions: add, sub_AB, sub_BA, xor_like (bitwise-sim mod 26)
Cipher variants: Vigenere, Beaufort, Variant Beaufort
Alphabets: AZ, KA
CT variants: CT97, CT73 (3 null mask layouts)
"""

import json
import os
import sys
import time
import math
from multiprocessing import Pool, cpu_count
from itertools import permutations

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT

# ── K1/K2/K3 Plaintext ("credentials") ──────────────────────────────────

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELD"
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
    "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEA"
    "TINYBREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLE"
    "ALITTLEINSERTEDACANDLEANDPEEREDIN"
)

# Concatenation orders (all 6 permutations of K1,K2,K3)
SECTIONS = [K1_PT, K2_PT, K3_PT]
CONCAT_ORDERS = list(permutations(range(3)))

# K2 coordinate numeric values
K2_COORDS_DMS = [38, 57, 6, 5, 77, 8, 44]  # DMS components
K2_COORDS_DIGITS = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]  # individual digits
K2_COORDS_MOD26 = [v % 26 for v in K2_COORDS_DMS]  # [12, 5, 6, 5, 25, 8, 18]

# ── Keywords (Tier 1 — Kryptos-relevant) ─────────────────────────────────

KEYWORDS = [
    "KRYPTOS", "SEVEN", "PALIMPSEST", "ABSCISSA", "DEFECTOR",
    "BERLIN", "CLOCK", "BERLINCLOCK", "SHADOW", "LANGLEY",
    "SCHEIDT", "SANBORN", "CARTER", "IQLUSION", "CIPHER",
    "SECRET", "INVISIBLE", "MAGNETIC", "FIELD", "COMPASS",
    "MEDUSA", "ROSETTA", "LODGE", "TOWER", "CHART",
    "FILTER", "COLOPHON", "PARALLAX", "BURIED", "POINT",
    "NORTHEAST", "LAYERTWO", "IDBYROWS",
]

# ── Ciphertext setup ─────────────────────────────────────────────────────

CT_NUM = [ALPH_IDX[c] for c in CT]

# Consensus null masks (from E-CKM-02)
CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
MASK_A = sorted(CONSENSUS_NULLS | {38, 39, 40, 55, 87, 93, 94})
MASK_B = sorted(CONSENSUS_NULLS | {38, 39, 40, 56, 88, 93, 94})
MASK_C = sorted(CONSENSUS_NULLS | {41, 42, 43, 55, 87, 95, 96})


def extract_ct(mask):
    """Remove null positions from CT, return (ct73_nums, crib_map, length)."""
    mask_set = set(mask)
    ct73 = []
    pos_map = {}
    j = 0
    for i in range(CT_LEN):
        if i not in mask_set:
            ct73.append(CT_NUM[i])
            pos_map[i] = j
            j += 1
    crib73 = {}
    for pos, ch in CRIB_DICT.items():
        if pos in pos_map:
            crib73[pos_map[pos]] = ALPH_IDX[ch]
    return ct73, crib73, len(ct73)


CT73_VARIANTS = {}
for name, mask in [("mask_a", MASK_A), ("mask_b", MASK_B), ("mask_c", MASK_C)]:
    CT73_VARIANTS[name] = extract_ct(mask)

CRIB97 = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# ── KA alphabet ──────────────────────────────────────────────────────────

KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}


def to_nums(text, alpha):
    """Convert text to numeric list using given alphabet index."""
    idx = ALPH_IDX if alpha == "AZ" else KA_IDX
    return [idx[c] for c in text if c in idx]


# ── Combination functions ────────────────────────────────────────────────

def combine_add(a_val, b_val):
    return (a_val + b_val) % MOD

def combine_sub_ab(a_val, b_val):
    return (a_val - b_val) % MOD

def combine_sub_ba(a_val, b_val):
    return (b_val - a_val) % MOD

def combine_xor_like(a_val, b_val):
    """Bitwise XOR mapped to mod-26: treat as 5-bit values, XOR, mod 26."""
    return (a_val ^ b_val) % MOD

COMBINERS = [
    ("add", combine_add),
    ("sub_AB", combine_sub_ab),
    ("sub_BA", combine_sub_ba),
    ("xor", combine_xor_like),
]


# ── Core scoring ─────────────────────────────────────────────────────────

def score_key(key_nums, ct_nums, crib_map, ct_len):
    """Score a key against CT using all 3 cipher variants.
    Returns (best_score, best_variant).
    """
    best = 0
    best_var = ""
    key_len = len(key_nums)

    for var_name, sign_a, sign_b in [("vig", 1, -1), ("beau", -1, 1), ("vbeau", 1, 1)]:
        score = 0
        for pos, expected in crib_map.items():
            if pos < ct_len and pos < key_len:
                pt_val = (sign_a * ct_nums[pos] + sign_b * key_nums[pos]) % MOD
                if pt_val == expected:
                    score += 1
        if score > best:
            best = score
            best_var = var_name

    return best, best_var


# ── Columnar transposition utility ───────────────────────────────────────

def columnar_read(text, width):
    """Read text in ascending columnar order."""
    n = len(text)
    n_rows = math.ceil(n / width)
    padded = text + 'X' * (n_rows * width - n)
    result = []
    for col in range(width):
        for row in range(n_rows):
            idx = row * width + col
            if idx < n:
                result.append(text[idx])
    return ''.join(result)


# ── Model M1: Section PT + keyword combination ──────────────────────────

def build_m1_key(section_nums, kw_nums, offset, comb_fn, length):
    """key[i] = f(section[i+offset], keyword[i % Lk])"""
    Ls = len(section_nums)
    Lk = len(kw_nums)
    key = []
    for i in range(length):
        si = (i + offset) % Ls
        ki = i % Lk
        key.append(comb_fn(section_nums[si], kw_nums[ki]))
    return key


# ── Model M2: Decimated section PT + keyword ─────────────────────────────

def build_m2_key(section_nums, kw_nums, offset, step, comb_fn, length):
    """key[i] = f(section[(i*step+offset) % Ls], keyword[i % Lk])"""
    Ls = len(section_nums)
    Lk = len(kw_nums)
    key = []
    for i in range(length):
        si = (i * step + offset) % Ls
        ki = i % Lk
        key.append(comb_fn(section_nums[si], kw_nums[ki]))
    return key


# ── Model M5: Section PT + coordinate values ────────────────────────────

def build_m5_key(section_nums, coord_nums, offset, comb_fn, length):
    """key[i] = f(section[i+offset], coords[i % Lc])"""
    Ls = len(section_nums)
    Lc = len(coord_nums)
    key = []
    for i in range(length):
        si = (i + offset) % Ls
        ci = i % Lc
        key.append(comb_fn(section_nums[si], coord_nums[ci]))
    return key


# ── Model M6: Progressive credential unwrapping ─────────────────────────

def build_m6_progressive_keys(alpha):
    """
    Progressive credential chain:
    - K1 used keyword PALIMPSEST → K1 PT reveals something
    - K2 used keyword ABSCISSA → K2 PT reveals coordinates
    - K3 used keyword KRYPTOS → K3 PT reveals next layer

    Chains:
    a) K1_PT encrypted with ABSCISSA → intermediate → combine with KRYPTOS
    b) K2_PT encrypted with KRYPTOS → intermediate → key for K4
    c) K3_PT[0:97] encrypted with PALIMPSEST → key for K4
    d) K3_PT encrypted with ABSCISSA → key for K4
    e) Chain: encrypt K1_PT with K2_PT, use result as key
    f) Chain: encrypt K2_PT with K3_PT, use result as key
    """
    idx = ALPH_IDX if alpha == "AZ" else KA_IDX
    alph = ALPH if alpha == "AZ" else KA_STR

    results = []

    # Progressive encryption chains
    chains = [
        ("K1pt_enc_ABSCISSA", K1_PT, "ABSCISSA"),
        ("K1pt_enc_KRYPTOS", K1_PT, "KRYPTOS"),
        ("K2pt_enc_KRYPTOS", K2_PT, "KRYPTOS"),
        ("K2pt_enc_PALIMPSEST", K2_PT, "PALIMPSEST"),
        ("K3pt_enc_PALIMPSEST", K3_PT, "PALIMPSEST"),
        ("K3pt_enc_ABSCISSA", K3_PT, "ABSCISSA"),
        ("K3pt_enc_KRYPTOS", K3_PT, "KRYPTOS"),
        ("K3pt_enc_DEFECTOR", K3_PT, "DEFECTOR"),
    ]

    for label, plaintext, keyword in chains:
        pt_nums = [idx.get(c, 0) for c in plaintext]
        kw_nums = [idx.get(c, 0) for c in keyword]
        Lk = len(kw_nums)

        # Vigenere encryption: intermediate = (PT + KW) mod 26
        enc_vig = [(pt_nums[i] + kw_nums[i % Lk]) % MOD for i in range(len(pt_nums))]
        results.append((f"M6_{label}_vig_{alpha}", enc_vig))

        # Beaufort encryption: intermediate = (KW - PT) mod 26
        enc_beau = [(kw_nums[i % Lk] - pt_nums[i]) % MOD for i in range(len(pt_nums))]
        results.append((f"M6_{label}_beau_{alpha}", enc_beau))

    # Cross-section encryption chains
    cross = [
        ("K1pt_enc_K2pt", K1_PT, K2_PT),
        ("K2pt_enc_K1pt", K2_PT, K1_PT),
        ("K2pt_enc_K3pt", K2_PT, K3_PT),
        ("K3pt_enc_K2pt", K3_PT, K2_PT),
        ("K1pt_enc_K3pt", K1_PT, K3_PT),
        ("K3pt_enc_K1pt", K3_PT, K1_PT),
    ]

    for label, text_a, text_b in cross:
        a_nums = [idx.get(c, 0) for c in text_a]
        b_nums = [idx.get(c, 0) for c in text_b]
        Lb = len(b_nums)

        enc_vig = [(a_nums[i] + b_nums[i % Lb]) % MOD for i in range(len(a_nums))]
        results.append((f"M6_{label}_vig_{alpha}", enc_vig))

        enc_beau = [(b_nums[i % Lb] - a_nums[i]) % MOD for i in range(len(a_nums))]
        results.append((f"M6_{label}_beau_{alpha}", enc_beau))

    # Double encryption: encrypt section with KW1, then encrypt result with KW2
    double_chains = [
        ("K3_KRYPTOS_then_ABSCISSA", K3_PT, "KRYPTOS", "ABSCISSA"),
        ("K3_ABSCISSA_then_KRYPTOS", K3_PT, "ABSCISSA", "KRYPTOS"),
        ("K3_PALIMPSEST_then_KRYPTOS", K3_PT, "PALIMPSEST", "KRYPTOS"),
        ("K1K2K3_KRYPTOS_then_SEVEN", K1_PT + K2_PT + K3_PT, "KRYPTOS", "SEVEN"),
        ("K1K2K3_SEVEN_then_KRYPTOS", K1_PT + K2_PT + K3_PT, "SEVEN", "KRYPTOS"),
    ]

    for label, plaintext, kw1, kw2 in double_chains:
        pt_nums = [idx.get(c, 0) for c in plaintext]
        kw1_nums = [idx.get(c, 0) for c in kw1]
        kw2_nums = [idx.get(c, 0) for c in kw2]
        L1, L2 = len(kw1_nums), len(kw2_nums)

        # Vig then Vig
        step1 = [(pt_nums[i] + kw1_nums[i % L1]) % MOD for i in range(len(pt_nums))]
        step2 = [(step1[i] + kw2_nums[i % L2]) % MOD for i in range(len(step1))]
        results.append((f"M6_double_{label}_vv_{alpha}", step2))

        # Beau then Beau
        step1 = [(kw1_nums[i % L1] - pt_nums[i]) % MOD for i in range(len(pt_nums))]
        step2 = [(kw2_nums[i % L2] - step1[i]) % MOD for i in range(len(step1))]
        results.append((f"M6_double_{label}_bb_{alpha}", step2))

    return results


# ── Worker: test one (section, keyword, alpha) tuple ─────────────────────

def worker_m1_m2(args):
    """Test M1 and M2 for one (section_name, section_text, keyword, alpha)."""
    section_name, section_text, kw_text, alpha_name = args

    section_nums = to_nums(section_text, alpha_name)
    kw_nums = to_nums(kw_text, alpha_name)

    if not section_nums or not kw_nums:
        return [], 0

    Ls = len(section_nums)
    hits = []
    tested = 0

    # M1: section PT + keyword, various offsets
    max_offset = min(Ls, 20)
    for comb_name, comb_fn in COMBINERS:
        for d in range(max_offset):
            # Build key of length 97 (covers both CT97 and CT73)
            key = build_m1_key(section_nums, kw_nums, d, comb_fn, CT_LEN)

            # Test CT97
            score, var = score_key(key, CT_NUM, CRIB97, CT_LEN)
            tested += 1
            if score >= 8:
                hits.append((score, var, f"M1_{section_name}+{kw_text}", comb_name, d, alpha_name, "ct97", ""))

            # Test CT73
            for ct_name, (ct73, crib73, ct73_len) in CT73_VARIANTS.items():
                key73 = build_m1_key(section_nums, kw_nums, d, comb_fn, ct73_len)
                score, var = score_key(key73, ct73, crib73, ct73_len)
                tested += 1
                if score >= 8:
                    hits.append((score, var, f"M1_{section_name}+{kw_text}", comb_name, d, alpha_name, ct_name, ""))

    # M2: decimated section PT + keyword (steps 2,3,5,7,11,13)
    for step in [2, 3, 5, 7, 11, 13]:
        for comb_name, comb_fn in COMBINERS:
            for d in range(min(Ls, 10)):
                key = build_m2_key(section_nums, kw_nums, d, step, comb_fn, CT_LEN)

                score, var = score_key(key, CT_NUM, CRIB97, CT_LEN)
                tested += 1
                if score >= 8:
                    hits.append((score, var, f"M2_{section_name}+{kw_text}", comb_name, d, alpha_name, "ct97", f"step={step}"))

                for ct_name, (ct73, crib73, ct73_len) in CT73_VARIANTS.items():
                    key73 = build_m2_key(section_nums, kw_nums, d, step, comb_fn, ct73_len)
                    score, var = score_key(key73, ct73, crib73, ct73_len)
                    tested += 1
                    if score >= 8:
                        hits.append((score, var, f"M2_{section_name}+{kw_text}", comb_name, d, alpha_name, ct_name, f"step={step}"))

    return hits, tested


def worker_m5(args):
    """Test M5: section PT + coordinate values."""
    section_name, section_text, alpha_name = args

    section_nums = to_nums(section_text, alpha_name)
    if not section_nums:
        return [], 0

    Ls = len(section_nums)
    hits = []
    tested = 0

    coord_sets = [
        ("DMS7", K2_COORDS_MOD26),
        ("digits11", K2_COORDS_DIGITS),
    ]

    for coord_name, coord_vals in coord_sets:
        for comb_name, comb_fn in COMBINERS:
            for d in range(min(Ls, 20)):
                key = build_m5_key(section_nums, coord_vals, d, comb_fn, CT_LEN)

                score, var = score_key(key, CT_NUM, CRIB97, CT_LEN)
                tested += 1
                if score >= 8:
                    hits.append((score, var, f"M5_{section_name}+{coord_name}", comb_name, d, alpha_name, "ct97", ""))

                for ct_name, (ct73, crib73, ct73_len) in CT73_VARIANTS.items():
                    key73 = build_m5_key(section_nums, coord_vals, d, comb_fn, ct73_len)
                    score, var = score_key(key73, ct73, crib73, ct73_len)
                    tested += 1
                    if score >= 8:
                        hits.append((score, var, f"M5_{section_name}+{coord_name}", comb_name, d, alpha_name, ct_name, ""))

    return hits, tested


def worker_m3(args):
    """Test M3: columnar-transposed section PT + keyword."""
    section_name, section_text, kw_text, width, alpha_name = args

    transposed = columnar_read(section_text, width)
    section_nums = to_nums(transposed, alpha_name)
    kw_nums = to_nums(kw_text, alpha_name)

    if not section_nums or not kw_nums:
        return [], 0

    Ls = len(section_nums)
    hits = []
    tested = 0

    for comb_name, comb_fn in COMBINERS:
        for d in range(min(Ls, 10)):
            key = build_m1_key(section_nums, kw_nums, d, comb_fn, CT_LEN)

            score, var = score_key(key, CT_NUM, CRIB97, CT_LEN)
            tested += 1
            if score >= 8:
                hits.append((score, var, f"M3_{section_name}_col{width}+{kw_text}", comb_name, d, alpha_name, "ct97", ""))

            for ct_name, (ct73, crib73, ct73_len) in CT73_VARIANTS.items():
                key73 = build_m1_key(section_nums, kw_nums, d, comb_fn, ct73_len)
                score, var = score_key(key73, ct73, crib73, ct73_len)
                tested += 1
                if score >= 8:
                    hits.append((score, var, f"M3_{section_name}_col{width}+{kw_text}", comb_name, d, alpha_name, ct_name, ""))

    return hits, tested


def worker_m4(args):
    """Test M4: concatenated sections + keyword."""
    order_idx, kw_text, alpha_name = args
    perm = CONCAT_ORDERS[order_idx]
    concat_text = ''.join(SECTIONS[i] for i in perm)

    section_nums = to_nums(concat_text, alpha_name)
    kw_nums = to_nums(kw_text, alpha_name)

    if not section_nums or not kw_nums:
        return [], 0

    Ls = len(section_nums)
    hits = []
    tested = 0
    order_label = ''.join(str(i+1) for i in perm)

    for comb_name, comb_fn in COMBINERS:
        for d in range(min(Ls, 30)):
            key = build_m1_key(section_nums, kw_nums, d, comb_fn, CT_LEN)

            score, var = score_key(key, CT_NUM, CRIB97, CT_LEN)
            tested += 1
            if score >= 8:
                hits.append((score, var, f"M4_concat{order_label}+{kw_text}", comb_name, d, alpha_name, "ct97", ""))

            for ct_name, (ct73, crib73, ct73_len) in CT73_VARIANTS.items():
                key73 = build_m1_key(section_nums, kw_nums, d, comb_fn, ct73_len)
                score, var = score_key(key73, ct73, crib73, ct73_len)
                tested += 1
                if score >= 8:
                    hits.append((score, var, f"M4_concat{order_label}+{kw_text}", comb_name, d, alpha_name, ct_name, ""))

    return hits, tested


def worker_m6(args):
    """Test M6: progressive credential chain (pre-built keys)."""
    label, key_nums = args

    if len(key_nums) < 73:
        return [], 0

    hits = []
    tested = 0

    # Crib drag: slide key over CT at various offsets
    max_offset = min(len(key_nums) - CT_LEN, 300)
    for d in range(max(1, max_offset + 1)):
        key_slice = key_nums[d:d + CT_LEN]
        if len(key_slice) < CT_LEN:
            break

        score, var = score_key(key_slice, CT_NUM, CRIB97, CT_LEN)
        tested += 1
        if score >= 8:
            hits.append((score, var, label, "chain", d, "", "ct97", ""))

        for ct_name, (ct73, crib73, ct73_len) in CT73_VARIANTS.items():
            key73_slice = key_nums[d:d + ct73_len]
            if len(key73_slice) < ct73_len:
                continue
            score, var = score_key(key73_slice, ct73, crib73, ct73_len)
            tested += 1
            if score >= 8:
                hits.append((score, var, label, "chain", d, "", ct_name, ""))

    return hits, tested


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 72)
    print("E-CKM-03: CKM Credential-Based Key Construction from K1-K3")
    print("=" * 72)

    n_workers = min(cpu_count(), 28)
    all_hits = []
    total_tested = 0

    section_sources = [
        ("K1", K1_PT),
        ("K2", K2_PT),
        ("K3", K3_PT),
    ]

    # ── Phase 1: M1 + M2 (section PT + keyword) ─────────────────────────
    print(f"\n--- Phase 1: M1 (direct) + M2 (decimated) section PT × keyword ---")
    print(f"  Sections: {len(section_sources)}, Keywords: {len(KEYWORDS)}, Alphabets: 2")

    work_m1m2 = []
    for sname, stext in section_sources:
        for kw in KEYWORDS:
            for alpha in ["AZ", "KA"]:
                work_m1m2.append((sname, stext, kw, alpha))

    print(f"  Work items: {len(work_m1m2):,}")

    with Pool(n_workers) as pool:
        results = pool.map(worker_m1_m2, work_m1m2)

    for hits, tested in results:
        total_tested += tested
        all_hits.extend(hits)

    best_so_far = max((h[0] for h in all_hits), default=0)
    print(f"  Configs: {total_tested:,} | Hits ≥8: {len(all_hits)} | Best: {best_so_far}")

    # ── Phase 2: M3 (columnar-transposed section PT + keyword) ───────────
    print(f"\n--- Phase 2: M3 columnar-transposed section PT × keyword ---")

    work_m3 = []
    widths = [7, 8, 9, 10, 14, 24, 31]
    for sname, stext in section_sources:
        for kw in KEYWORDS:
            for w in widths:
                for alpha in ["AZ", "KA"]:
                    work_m3.append((sname, stext, kw, w, alpha))

    print(f"  Work items: {len(work_m3):,}")

    with Pool(n_workers) as pool:
        results = pool.map(worker_m3, work_m3)

    phase2_tested = 0
    for hits, tested in results:
        phase2_tested += tested
        total_tested += tested
        all_hits.extend(hits)

    best_so_far = max((h[0] for h in all_hits), default=0)
    print(f"  Configs: {phase2_tested:,} | Hits ≥8: {len(all_hits)} | Best: {best_so_far}")

    # ── Phase 3: M4 (concatenated sections + keyword) ────────────────────
    print(f"\n--- Phase 3: M4 concatenated K1+K2+K3 (6 orders) × keyword ---")

    work_m4 = []
    for oi in range(len(CONCAT_ORDERS)):
        for kw in KEYWORDS:
            for alpha in ["AZ", "KA"]:
                work_m4.append((oi, kw, alpha))

    print(f"  Work items: {len(work_m4):,}")

    with Pool(n_workers) as pool:
        results = pool.map(worker_m4, work_m4)

    phase3_tested = 0
    for hits, tested in results:
        phase3_tested += tested
        total_tested += tested
        all_hits.extend(hits)

    best_so_far = max((h[0] for h in all_hits), default=0)
    print(f"  Configs: {phase3_tested:,} | Hits ≥8: {len(all_hits)} | Best: {best_so_far}")

    # ── Phase 4: M5 (section PT + coordinate values) ─────────────────────
    print(f"\n--- Phase 4: M5 section PT × K2 coordinate values ---")

    work_m5 = []
    for sname, stext in section_sources:
        for alpha in ["AZ", "KA"]:
            work_m5.append((sname, stext, alpha))

    print(f"  Work items: {len(work_m5):,}")

    with Pool(n_workers) as pool:
        results = pool.map(worker_m5, work_m5)

    phase4_tested = 0
    for hits, tested in results:
        phase4_tested += tested
        total_tested += tested
        all_hits.extend(hits)

    best_so_far = max((h[0] for h in all_hits), default=0)
    print(f"  Configs: {phase4_tested:,} | Hits ≥8: {len(all_hits)} | Best: {best_so_far}")

    # ── Phase 5: M6 (progressive credential chains) ──────────────────────
    print(f"\n--- Phase 5: M6 progressive credential chains ---")

    m6_keys = []
    for alpha in ["AZ", "KA"]:
        m6_keys.extend(build_m6_progressive_keys(alpha))

    print(f"  Pre-built credential chains: {len(m6_keys)}")

    with Pool(n_workers) as pool:
        results = pool.map(worker_m6, m6_keys)

    phase5_tested = 0
    for hits, tested in results:
        phase5_tested += tested
        total_tested += tested
        all_hits.extend(hits)

    best_so_far = max((h[0] for h in all_hits), default=0)
    print(f"  Configs: {phase5_tested:,} | Hits ≥8: {len(all_hits)} | Best: {best_so_far}")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    all_hits.sort(key=lambda x: -x[0])

    print()
    print("=" * 72)
    print(f"COMPLETE: {total_tested:,} configs in {elapsed:.1f}s "
          f"({total_tested / max(elapsed, 0.01):,.0f} configs/sec)")
    print(f"Hits ≥ 8: {len(all_hits)}")

    if all_hits:
        print(f"BEST SCORE: {all_hits[0][0]}/24")
        print()
        print("TOP 20 RESULTS:")
        print("-" * 72)
        for h in all_hits[:20]:
            score, var, model_label, comb, d, alpha, ct_name, extra = h
            extra_str = f" [{extra}]" if extra else ""
            print(f"  {score:2d}/24 | {var:6s} | {alpha:2s} | {ct_name:6s} | "
                  f"d={d} {comb:6s} | {model_label}{extra_str}")
    else:
        print("ZERO hits ≥ 8. CKM credential-based construction = NOISE.")

    print("=" * 72)

    # Score distribution
    score_dist = {}
    for h in all_hits:
        s = h[0]
        score_dist[s] = score_dist.get(s, 0) + 1
    print(f"\nScore distribution (≥8): {dict(sorted(score_dist.items()))}")

    # Model breakdown
    model_best = {}
    for h in all_hits:
        model = h[2].split("_")[0] + "_" + h[2].split("_")[1] if "_" in h[2] else h[2]
        if model not in model_best or h[0] > model_best[model]:
            model_best[model] = h[0]
    if model_best:
        print(f"\nBest by model family:")
        for m, s in sorted(model_best.items(), key=lambda x: -x[1]):
            print(f"  {m}: {s}/24")

    # Save results
    output = {
        "experiment": "E-CKM-03",
        "description": "CKM Credential-Based Key Construction from K1-K3",
        "hypothesis": "K4 key CONSTRUCTED from K1/K2/K3 plaintext + keyword via mod-26 ops",
        "total_configs": total_tested,
        "elapsed_seconds": round(elapsed, 1),
        "configs_per_second": round(total_tested / max(elapsed, 0.01)),
        "models": ["M1_direct", "M2_decimated", "M3_columnar", "M4_concat", "M5_coords", "M6_progressive"],
        "sections": ["K1", "K2", "K3"],
        "keywords": KEYWORDS,
        "combiners": [c[0] for c in COMBINERS],
        "alphabets": ["AZ", "KA"],
        "ct_variants": ["ct97", "mask_a", "mask_b", "mask_c"],
        "best_score": all_hits[0][0] if all_hits else 0,
        "hits_above_8": len(all_hits),
        "score_distribution": score_dist,
        "model_best": model_best,
        "top_20": [
            {
                "score": h[0], "variant": h[1], "model": h[2],
                "combiner": h[3], "offset": h[4], "alphabet": h[5],
                "ct_name": h[6], "extra": h[7],
            }
            for h in all_hits[:20]
        ],
    }

    out_path = os.path.join(_ROOT, "results", "e_ckm_credential_03.json")
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to {out_path}")


if __name__ == "__main__":
    main()
