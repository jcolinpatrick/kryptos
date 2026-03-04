#!/usr/bin/env python3
"""
Cipher: non-columnar transposition
Family: transposition/other
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-AUDIT-05: Scytale Cipher — The Antipodes IS a Cylinder.

[HYPOTHESIS] The Antipodes sculpture (a physical cylinder) is literally a scytale.
K4's ciphertext was produced by writing plaintext on a strip, wrapping it around
a rod of a specific diameter, and reading across rows. Or: the Antipodes 2D grid
layout itself IS the decryption tool — reading vertically reveals plaintext.

This is NOT covered by existing eliminations because:
- Standard columnar tests on K4 use column PERMUTATIONS; scytale uses identity order
  (but identity IS one of the permutations tested at w5-12; untested at other widths)
- The Antipodes 2D grid (47 rows × 32-36 chars) as a scytale has never been tested
- The physical column positions of K4 chars across Antipodes rows are untested
- Two-pass K4 comparison (same text at different column offsets) is untested

Test plan:
- Phase 1: Standard scytale on K4 alone — write in rows of width W, read columns
           (all widths 2-48). This is identity-column columnar transposition.
- Phase 2: Scytale + substitution (widths × Vig/Beau/VBeau with keyword alphabets)
- Phase 3: Antipodes grid — read K4 chars by their column positions on the cylinder
- Phase 4: Two-pass extraction — use column offset DIFFERENCE between K4 pass 1
           and pass 2 as a key or permutation
- Phase 5: Physical rod diameters — Antipodes row widths (32-36) as scytale params

Uses BOTH position-free AND anchored crib scoring.
"""
import json
import math
import os
import sys
import time
from collections import defaultdict
from itertools import product
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_WORDS, CRIB_DICT, N_CRIBS,
    KRYPTOS_ALPHABET,
)
from kryptos.kernel.scoring.free_crib import score_free, score_free_fast
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.transforms.transposition import columnar_perm, invert_perm, apply_perm


# ── Antipodes row data (from verified reconstruction) ────────────────────
# Each tuple: (row_number, width, text, section)
# Source: memory/antipodes_reconstruction.md — 1,584 letters, ZERO mismatches

ANTIPODES_ROWS = [
    (1,  34, "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACH", "K3"),
    (2,  33, "TNREYULDSLLSLLNOHSNOSMRWXMNETPRNG", "K3"),
    (3,  35, "ATIHNRARPESLNNELEBLPIIACAEWMTWNDITE", "K3"),
    (4,  34, "ENRAHCTENEUDRETNHAEOETFOLSEDTIWENH", "K3"),
    (5,  34, "AEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWE", "K3"),
    (6,  34, "NATAMATEGYEERLBTEEFOASFIOTUETUAEOT", "K3"),
    (7,  34, "OARMAEERTNRTIBSEDDNIAAHTTMSTEWPIER", "K3"),
    (8,  35, "OAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDD", "K3"),
    (9,  33, "RYDLORITRKLMLEHAGTDHARDPNEOHMGFMF", "K3"),
    (10, 33, "EUHEECDMRIPFEIMEHNLSSTTRTVDOHWOBK", "K3/K4"),
    (11, 34, "RUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTW", "K4"),
    (12, 35, "TQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZF", "K4"),
    (13, 33, "PKWGDKZXTJCDIGKUHUAUEKCAREMUFPHZL", "K4/K1"),  # SPACE removed (not a letter)
    (14, 34, "RFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQV", "K1/K2"),
    (15, 33, "YUVLLTREVJYQTMKYRDMFDVFPJUDEEHZWE", "K1/K2"),
    (16, 32, "TZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQ", "K2"),  # ? removed
    (17, 33, "ZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDA", "K2"),
    (18, 34, "GDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJL", "K2"),
    (19, 34, "BQCETBJDFHRRYIZETKZEMVDUFKSJHKFWHK", "K2"),  # UNDERGROUND corrected
    (20, 33, "UWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYC", "K2"),  # ? removed
    (21, 34, "UQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLA", "K2"),
    (22, 34, "VIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF", "K2"),  # ? and dots removed
    (23, 33, "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZ", "K2"),
    (24, 33, "ZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFM", "K2"),
    (25, 33, "PNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBE", "K2"),
    (26, 33, "DMHDAFMJGZNUPLGEWJLLAETGENDYAHROH", "K2/K3"),
    (27, 35, "NLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSL", "K3"),
    (28, 33, "LSLLNOHSNOSMRWXMNETPRNGATIHNRARPE", "K3"),
    (29, 34, "SLNNELEBLPIIACAEWMTWNDITEENRAHCTEN", "K3"),
    (30, 34, "EUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQ", "K3"),
    (31, 34, "HEENCTAYCREIFTBRSPAMHHEWENATAMATEG", "K3"),
    (32, 34, "YEERLBTEEFOASFIOTUETUAEOTOARMAEERT", "K3"),
    (33, 35, "NRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB", "K3"),
    (34, 36, "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKL", "K3"),
    (35, 33, "MLEHAGTDHARDPNEOHMGFMFEUHEECDMRIP", "K3"),
    (36, 33, "FEIMEHNLSSTTRTVDOHWOBKRUOXOGHULBS", "K3/K4"),
    (37, 34, "OLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZ", "K4"),
    (38, 34, "WATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJ", "K4"),
    (39, 34, "CDIGKUHUAUEKCAREMUFPHZLRFAXYUSDJKZ", "K4/K1"),  # NO space
    (40, 34, "LDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJY", "K1/K2"),
    (41, 32, "QTMKYRDMFDVFPJUDEEHZWETZYVGWHKKQ", "K2"),
    (42, 32, "ETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPF", "K2"),  # ? removed
    (43, 33, "XHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNG", "K2"),
    (44, 34, "EUNAQZGZLECGYUXUEENJTBJLBQCETBJDFH", "K2"),  # UNDERGROUND corrected
    (45, 34, "RRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIH", "K2"),
    (46, 33, "HDDDUVHDWKBFUFPWNTDFIYCUQZEREEVLD", "K2"),  # ? removed
    (47, 35, "KFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ", "K2"),
]

# Build full Antipodes stream (letters only, no punctuation)
ANTIPODES_STREAM = "".join(row[2] for row in ANTIPODES_ROWS)
ANTIPODES_LEN = len(ANTIPODES_STREAM)

# Build the 2D grid: (row_idx, col_idx) → char, plus (row_idx, col_idx) → stream_pos
GRID = {}           # (row, col) → char
GRID_POS = {}       # (row, col) → stream position
STREAM_TO_GRID = {} # stream position → (row, col)
pos = 0
for row_idx, (_, width, text, _) in enumerate(ANTIPODES_ROWS):
    for col_idx, ch in enumerate(text):
        GRID[(row_idx, col_idx)] = ch
        GRID_POS[(row_idx, col_idx)] = pos
        STREAM_TO_GRID[pos] = (row_idx, col_idx)
        pos += 1

# Identify K4 character positions in the Antipodes stream
# K4 appears twice: pass 1 and pass 2
# From reconstruction: K3 (336) + K4 (97) + K1 (63) + K2 (369) = 865 per pass
K3_LEN = 336
K4_LEN = 97
K1_LEN = 63
K2_LEN = 369
PASS_LEN = K3_LEN + K4_LEN + K1_LEN + K2_LEN  # 865

K4_PASS1_START = K3_LEN           # 336
K4_PASS1_END = K3_LEN + K4_LEN    # 433
K4_PASS2_START = PASS_LEN + K3_LEN  # 1201
K4_PASS2_END = PASS_LEN + K3_LEN + K4_LEN  # 1298


def verify_antipodes():
    """Verify our Antipodes reconstruction matches K4."""
    k4_pass1 = ANTIPODES_STREAM[K4_PASS1_START:K4_PASS1_END]
    k4_pass2 = ANTIPODES_STREAM[K4_PASS2_START:K4_PASS2_END]
    assert k4_pass1 == CT, f"Pass 1 K4 mismatch: {k4_pass1[:20]}... vs {CT[:20]}..."
    assert k4_pass2 == CT, f"Pass 2 K4 mismatch: {k4_pass2[:20]}... vs {CT[:20]}..."
    assert ANTIPODES_LEN == 1584, f"Antipodes length {ANTIPODES_LEN} != 1584"
    print(f"  Antipodes stream: {ANTIPODES_LEN} chars, K4 verified at positions "
          f"{K4_PASS1_START}-{K4_PASS1_END} and {K4_PASS2_START}-{K4_PASS2_END}")


# ── Scoring helpers ──────────────────────────────────────────────────────

def anchored_crib_score(text: str) -> int:
    """Score using anchored crib positions (standard method)."""
    if len(text) < 74:
        return 0
    score = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(text) and text[pos] == ch:
            score += 1
    return score


def combined_score(text: str) -> dict:
    """Score using both anchored and free crib methods."""
    anch = anchored_crib_score(text)
    free = score_free_fast(text)
    ic_val = ic(text) if len(text) >= 20 else 0.0
    return {"anchored": anch, "free": free, "ic": ic_val}


# ── Scytale primitives ──────────────────────────────────────────────────

def scytale_encrypt(plaintext: str, width: int) -> str:
    """Scytale encryption: write in rows of `width`, read down columns in order.

    This is equivalent to columnar transposition with identity column order.
    """
    n = len(plaintext)
    nrows = math.ceil(n / width)
    # Pad if needed (shouldn't be for analysis, but handle gracefully)
    padded = plaintext.ljust(nrows * width, 'X')

    result = []
    for col in range(width):
        for row in range(nrows):
            idx = row * width + col
            if idx < n:
                result.append(plaintext[idx])
    return ''.join(result)


def scytale_decrypt(ciphertext: str, width: int) -> str:
    """Scytale decryption: undo columnar-by-column reading.

    The CT was produced by reading columns of a width-wide grid.
    To decrypt: figure out the grid dimensions, fill columns, read rows.
    """
    n = len(ciphertext)
    nrows = math.ceil(n / width)
    # Number of full columns: how many columns have nrows chars?
    full_cols = n - width * (nrows - 1)  # cols with nrows chars
    # Remaining cols have (nrows-1) chars

    # Build column lengths
    col_lengths = []
    for c in range(width):
        if c < full_cols:
            col_lengths.append(nrows)
        else:
            col_lengths.append(nrows - 1)

    # Fill columns from CT
    cols = []
    pos = 0
    for c in range(width):
        cols.append(ciphertext[pos:pos + col_lengths[c]])
        pos += col_lengths[c]

    # Read rows
    result = []
    for row in range(nrows):
        for c in range(width):
            if row < len(cols[c]):
                result.append(cols[c][row])
    return ''.join(result)


def vigenere_decrypt(ct: str, key_shifts: List[int]) -> str:
    """Vigenère decryption with repeating key shifts."""
    result = []
    klen = len(key_shifts)
    for i, ch in enumerate(ct):
        if ch in ALPH_IDX:
            pt_idx = (ALPH_IDX[ch] - key_shifts[i % klen]) % MOD
            result.append(ALPH[pt_idx])
        else:
            result.append(ch)
    return ''.join(result)


def beaufort_decrypt(ct: str, key_shifts: List[int]) -> str:
    """Beaufort decryption: PT = (K - CT) mod 26."""
    result = []
    klen = len(key_shifts)
    for i, ch in enumerate(ct):
        if ch in ALPH_IDX:
            pt_idx = (key_shifts[i % klen] - ALPH_IDX[ch]) % MOD
            result.append(ALPH[pt_idx])
        else:
            result.append(ch)
    return ''.join(result)


def keyword_to_shifts(keyword: str) -> List[int]:
    """Convert keyword string to shift values (A=0, B=1, ...)."""
    return [ALPH_IDX[ch] for ch in keyword.upper() if ch in ALPH_IDX]


# ── Phase 1: Standard scytale on K4 (all widths) ────────────────────────

def phase1_scytale_k4():
    """Test scytale decryption of K4 at all widths 2-48."""
    print()
    print("Phase 1: Standard scytale on K4 (all widths 2-48)")
    print("-" * 60)

    best_anch = 0
    best_free = 0
    results = []

    for width in range(2, 49):
        # Decrypt: if CT was produced by scytale_encrypt(PT, width),
        # then PT = scytale_decrypt(CT, width)
        pt = scytale_decrypt(CT, width)
        sc = combined_score(pt)

        # Also try the inverse: what if the PT was read off by columns
        # (i.e., CT = read_rows after write_cols)?
        pt_inv = scytale_encrypt(CT, width)  # "encrypt" undoes the inverse
        sc_inv = combined_score(pt_inv)

        if sc["anchored"] > best_anch or sc["free"] > best_free:
            best_anch = max(best_anch, sc["anchored"])
            best_free = max(best_free, sc["free"])
            print(f"  w={width}: anchored={sc['anchored']}/24, free={sc['free']}/24, "
                  f"IC={sc['ic']:.4f}, text={pt[:30]}...")

        if sc_inv["anchored"] > best_anch or sc_inv["free"] > best_free:
            best_anch = max(best_anch, sc_inv["anchored"])
            best_free = max(best_free, sc_inv["free"])
            print(f"  w={width} (inv): anchored={sc_inv['anchored']}/24, free={sc_inv['free']}/24, "
                  f"IC={sc_inv['ic']:.4f}, text={pt_inv[:30]}...")

        results.append({
            "width": width,
            "decrypt_anchored": sc["anchored"],
            "decrypt_free": sc["free"],
            "decrypt_ic": sc["ic"],
            "inverse_anchored": sc_inv["anchored"],
            "inverse_free": sc_inv["free"],
            "inverse_ic": sc_inv["ic"],
        })

    print(f"  Best anchored: {best_anch}/24")
    print(f"  Best free: {best_free}/24")
    print(f"  Widths tested: 2-48 (47 widths × 2 directions = 94 configs)")
    return results, best_anch, best_free


# ── Phase 2: Scytale + substitution ──────────────────────────────────────

def phase2_scytale_plus_sub():
    """Test scytale + Vigenère/Beaufort decryption with keywords."""
    print()
    print("Phase 2: Scytale + substitution (Vig/Beau × keywords × widths)")
    print("-" * 60)

    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
        "CLOCK", "EAST", "NORTH", "IQLUSION", "SANBORN",
        "SCHEIDT", "LANGLEY", "DESPARATLY", "UNDERGROUND",
        "BERLINCLOCK", "EASTNORTHEAST", "WELTZEITUHR",
    ]

    best_anch = 0
    best_free = 0
    configs_tested = 0
    results = []

    for width in range(2, 49):
        for direction in ["decrypt", "encrypt"]:
            # Apply scytale first, then try substitution
            if direction == "decrypt":
                transposed = scytale_decrypt(CT, width)
            else:
                transposed = scytale_encrypt(CT, width)

            for kw in keywords:
                shifts = keyword_to_shifts(kw)
                for cipher_fn, cipher_name in [(vigenere_decrypt, "vig"),
                                                (beaufort_decrypt, "beau")]:
                    pt = cipher_fn(transposed, shifts)
                    configs_tested += 1
                    sc = combined_score(pt)

                    if sc["anchored"] > best_anch or sc["free"] > best_free:
                        best_anch = max(best_anch, sc["anchored"])
                        best_free = max(best_free, sc["free"])
                        print(f"  w={width} {direction} + {cipher_name}({kw}): "
                              f"anch={sc['anchored']}/24, free={sc['free']}/24, "
                              f"IC={sc['ic']:.4f}")
                        results.append({
                            "width": width, "direction": direction,
                            "cipher": cipher_name, "keyword": kw,
                            **sc
                        })

                    # Also try sub FIRST, then scytale
                    pt2 = cipher_fn(CT, shifts)
                    if direction == "decrypt":
                        pt2 = scytale_decrypt(pt2, width)
                    else:
                        pt2 = scytale_encrypt(pt2, width)
                    configs_tested += 1
                    sc2 = combined_score(pt2)

                    if sc2["anchored"] > best_anch or sc2["free"] > best_free:
                        best_anch = max(best_anch, sc2["anchored"])
                        best_free = max(best_free, sc2["free"])
                        print(f"  {cipher_name}({kw}) + w={width} {direction}: "
                              f"anch={sc2['anchored']}/24, free={sc2['free']}/24, "
                              f"IC={sc2['ic']:.4f}")
                        results.append({
                            "width": width, "direction": direction,
                            "cipher": cipher_name + "_first", "keyword": kw,
                            **sc2
                        })

    print(f"  Configs tested: {configs_tested:,}")
    print(f"  Best anchored: {best_anch}/24")
    print(f"  Best free: {best_free}/24")
    return results, best_anch, best_free, configs_tested


# ── Phase 3: Antipodes grid vertical readings ───────────────────────────

def phase3_antipodes_vertical():
    """Read the Antipodes grid vertically and extract K4 characters."""
    print()
    print("Phase 3: Antipodes grid — vertical/column readings")
    print("-" * 60)

    max_width = max(row[1] for row in ANTIPODES_ROWS)
    nrows = len(ANTIPODES_ROWS)
    print(f"  Grid: {nrows} rows × {max_width} max cols (variable 32-36)")

    results = []
    best_free = 0
    configs_tested = 0

    # 3a: Read entire grid column by column (left to right, top to bottom per column)
    print()
    print("  3a: Full vertical reading (all chars, column by column)")
    vertical_text = []
    for col in range(max_width):
        for row_idx in range(nrows):
            if (row_idx, col) in GRID:
                vertical_text.append(GRID[(row_idx, col)])
    vertical_str = ''.join(vertical_text)
    print(f"    Vertical reading: {len(vertical_str)} chars")
    print(f"    First 50: {vertical_str[:50]}")
    sc = combined_score(vertical_str)
    print(f"    Anchored: {sc['anchored']}/24, Free: {sc['free']}/24, IC: {sc['ic']:.4f}")

    # Check if K4 crib appears anywhere in vertical reading
    fr = score_free(vertical_str)
    if fr.ene_found:
        print(f"    *** ENE found at offsets: {fr.ene_offsets}")
    if fr.bc_found:
        print(f"    *** BC found at offsets: {fr.bc_offsets}")
    if fr.ene_fragments:
        print(f"    ENE fragments: {fr.ene_fragments[:5]}")
    if fr.bc_fragments:
        print(f"    BC fragments: {fr.bc_fragments[:5]}")
    results.append({"method": "full_vertical", **sc})
    configs_tested += 1

    # 3b: Read column by column, right to left
    vertical_rl = []
    for col in range(max_width - 1, -1, -1):
        for row_idx in range(nrows):
            if (row_idx, col) in GRID:
                vertical_rl.append(GRID[(row_idx, col)])
    vertical_rl_str = ''.join(vertical_rl)
    sc_rl = combined_score(vertical_rl_str)
    fr_rl = score_free(vertical_rl_str)
    print(f"  3b: Right-to-left vertical: anch={sc_rl['anchored']}/24, "
          f"free={sc_rl['free']}/24, IC={sc_rl['ic']:.4f}")
    if fr_rl.ene_found or fr_rl.bc_found:
        print(f"    *** CRIBS FOUND: ENE={fr_rl.ene_found}, BC={fr_rl.bc_found}")
    results.append({"method": "full_vertical_rl", **sc_rl})
    configs_tested += 1

    # 3c: Read column by column, bottom to top
    vertical_bt = []
    for col in range(max_width):
        for row_idx in range(nrows - 1, -1, -1):
            if (row_idx, col) in GRID:
                vertical_bt.append(GRID[(row_idx, col)])
    vertical_bt_str = ''.join(vertical_bt)
    sc_bt = combined_score(vertical_bt_str)
    fr_bt = score_free(vertical_bt_str)
    print(f"  3c: Bottom-to-top vertical: anch={sc_bt['anchored']}/24, "
          f"free={sc_bt['free']}/24, IC={sc_bt['ic']:.4f}")
    results.append({"method": "full_vertical_bt", **sc_bt})
    configs_tested += 1

    # 3d: Serpentine (boustrophedon) vertical — alternating top-down, bottom-up
    vertical_serp = []
    for col in range(max_width):
        if col % 2 == 0:
            for row_idx in range(nrows):
                if (row_idx, col) in GRID:
                    vertical_serp.append(GRID[(row_idx, col)])
        else:
            for row_idx in range(nrows - 1, -1, -1):
                if (row_idx, col) in GRID:
                    vertical_serp.append(GRID[(row_idx, col)])
    vertical_serp_str = ''.join(vertical_serp)
    sc_serp = combined_score(vertical_serp_str)
    fr_serp = score_free(vertical_serp_str)
    print(f"  3d: Serpentine vertical: anch={sc_serp['anchored']}/24, "
          f"free={sc_serp['free']}/24, IC={sc_serp['ic']:.4f}")
    results.append({"method": "full_vertical_serpentine", **sc_serp})
    configs_tested += 1

    # 3e: Extract ONLY K4 chars from vertical reading
    # K4 positions in the stream: pass 1 at 336-432, pass 2 at 1201-1297
    # Find where these characters land in the vertical reading
    print()
    print("  3e: K4 chars extracted from vertical reading order")

    # Build vertical reading order as stream positions
    vert_order = []
    for col in range(max_width):
        for row_idx in range(nrows):
            if (row_idx, col) in GRID_POS:
                vert_order.append(GRID_POS[(row_idx, col)])

    # K4 pass 1: which positions in vert_order correspond to K4?
    k4_p1_set = set(range(K4_PASS1_START, K4_PASS1_END))
    k4_p2_set = set(range(K4_PASS2_START, K4_PASS2_END))

    k4_p1_vert_positions = [(i, ANTIPODES_STREAM[sp])
                             for i, sp in enumerate(vert_order)
                             if sp in k4_p1_set]
    k4_p2_vert_positions = [(i, ANTIPODES_STREAM[sp])
                             for i, sp in enumerate(vert_order)
                             if sp in k4_p2_set]

    k4_p1_extracted = ''.join(ch for _, ch in k4_p1_vert_positions)
    k4_p2_extracted = ''.join(ch for _, ch in k4_p2_vert_positions)

    print(f"    K4 pass 1 from vertical: {k4_p1_extracted[:40]}...")
    print(f"    K4 pass 2 from vertical: {k4_p2_extracted[:40]}...")

    # These should be permutations of K4's CT
    assert sorted(k4_p1_extracted) == sorted(CT), "K4 pass 1 extraction mismatch"
    assert sorted(k4_p2_extracted) == sorted(CT), "K4 pass 2 extraction mismatch"

    # Score these extracted orderings
    for label, extracted in [("K4_p1_vert", k4_p1_extracted),
                              ("K4_p2_vert", k4_p2_extracted)]:
        sc_k = combined_score(extracted)
        fr_k = score_free(extracted)
        print(f"    {label}: anch={sc_k['anchored']}/24, free={sc_k['free']}/24, "
              f"IC={sc_k['ic']:.4f}")
        if fr_k.ene_found or fr_k.bc_found:
            print(f"      *** CRIBS FOUND: ENE={fr_k.ene_found}, BC={fr_k.bc_found}")
        if fr_k.ene_fragments:
            print(f"      ENE fragments: {fr_k.ene_fragments[:3]}")
        if fr_k.bc_fragments:
            print(f"      BC fragments: {fr_k.bc_fragments[:3]}")
        results.append({"method": label, **sc_k})
        best_free = max(best_free, sc_k["free"])
        configs_tested += 1

    # 3f: Diagonal readings across the grid
    print()
    print("  3f: Diagonal readings across Antipodes grid")
    for diag_name, diag_fn in [
        ("NW-SE", lambda r, c: r + c),
        ("NE-SW", lambda r, c: r - c + max_width),
    ]:
        diag_text = []
        diag_groups = defaultdict(list)
        for row_idx in range(nrows):
            for col in range(ANTIPODES_ROWS[row_idx][1]):
                key = diag_fn(row_idx, col)
                diag_groups[key].append(GRID[(row_idx, col)])
        for key in sorted(diag_groups):
            diag_text.extend(diag_groups[key])
        diag_str = ''.join(diag_text)
        sc_d = combined_score(diag_str)
        fr_d = score_free(diag_str)
        print(f"    {diag_name} diagonal: anch={sc_d['anchored']}/24, "
              f"free={sc_d['free']}/24, IC={sc_d['ic']:.4f}")
        if fr_d.ene_found or fr_d.bc_found:
            print(f"      *** CRIBS FOUND")
        results.append({"method": f"diagonal_{diag_name}", **sc_d})
        best_free = max(best_free, sc_d["free"])
        configs_tested += 1

    print(f"  Phase 3 configs: {configs_tested}")
    print(f"  Best free score: {best_free}/24")
    return results, best_free, configs_tested


# ── Phase 4: Two-pass column offset as key ──────────────────────────────

def phase4_two_pass_offset():
    """Use the column position difference between K4 pass 1 and pass 2."""
    print()
    print("Phase 4: Two-pass K4 column offset analysis")
    print("-" * 60)

    results = []
    configs_tested = 0

    # Get grid positions for each K4 character in both passes
    k4_p1_grid = []  # list of (row, col) for each K4 char, pass 1
    k4_p2_grid = []  # list of (row, col) for each K4 char, pass 2

    for i in range(K4_LEN):
        sp1 = K4_PASS1_START + i
        sp2 = K4_PASS2_START + i
        k4_p1_grid.append(STREAM_TO_GRID[sp1])
        k4_p2_grid.append(STREAM_TO_GRID[sp2])

    # Show the grid positions
    print("  K4 char grid positions (first 10 chars):")
    for i in range(10):
        r1, c1 = k4_p1_grid[i]
        r2, c2 = k4_p2_grid[i]
        print(f"    K4[{i}]='{CT[i]}': pass1=({r1},{c1}), pass2=({r2},{c2}), "
              f"col_diff={c2-c1}, row_diff={r2-r1}")

    # Extract column differences
    col_diffs = [k4_p2_grid[i][1] - k4_p1_grid[i][1] for i in range(K4_LEN)]
    row_diffs = [k4_p2_grid[i][0] - k4_p1_grid[i][0] for i in range(K4_LEN)]

    print(f"\n  Column diffs (unique): {sorted(set(col_diffs))}")
    print(f"  Row diffs (unique): {sorted(set(row_diffs))}")

    # 4a: Use column differences as shift values for Vigenère decryption
    print()
    print("  4a: Column diffs as Vigenère key")
    col_shifts_mod26 = [(d % MOD) for d in col_diffs]
    pt_vig = vigenere_decrypt(CT, col_shifts_mod26)
    sc = combined_score(pt_vig)
    print(f"    Vig decrypt with col_diff key: {pt_vig[:40]}...")
    print(f"    anch={sc['anchored']}/24, free={sc['free']}/24, IC={sc['ic']:.4f}")
    results.append({"method": "col_diff_vig", **sc})
    configs_tested += 1

    # 4b: Use row differences as key
    row_shifts_mod26 = [(d % MOD) for d in row_diffs]
    pt_row = vigenere_decrypt(CT, row_shifts_mod26)
    sc2 = combined_score(pt_row)
    print(f"  4b: Row diffs as Vigenère key: {pt_row[:40]}...")
    print(f"    anch={sc2['anchored']}/24, free={sc2['free']}/24, IC={sc2['ic']:.4f}")
    results.append({"method": "row_diff_vig", **sc2})
    configs_tested += 1

    # 4c: Use absolute column positions (pass 1) as key
    col_p1 = [k4_p1_grid[i][1] for i in range(K4_LEN)]
    pt_colp1 = vigenere_decrypt(CT, [(c % MOD) for c in col_p1])
    sc3 = combined_score(pt_colp1)
    print(f"  4c: Pass 1 column positions as key: {pt_colp1[:40]}...")
    print(f"    anch={sc3['anchored']}/24, free={sc3['free']}/24, IC={sc3['ic']:.4f}")
    results.append({"method": "col_pos_p1_vig", **sc3})
    configs_tested += 1

    # 4d: Use absolute column positions (pass 2) as key
    col_p2 = [k4_p2_grid[i][1] for i in range(K4_LEN)]
    pt_colp2 = vigenere_decrypt(CT, [(c % MOD) for c in col_p2])
    sc4 = combined_score(pt_colp2)
    print(f"  4d: Pass 2 column positions as key: {pt_colp2[:40]}...")
    print(f"    anch={sc4['anchored']}/24, free={sc4['free']}/24, IC={sc4['ic']:.4f}")
    results.append({"method": "col_pos_p2_vig", **sc4})
    configs_tested += 1

    # 4e: Column positions as permutation (reorder K4 chars by column position)
    print()
    print("  4e: Reorder K4 by column position on Antipodes")
    for pass_num, grid_positions in [("pass1", k4_p1_grid), ("pass2", k4_p2_grid)]:
        # Sort K4 chars by their column position, then row
        indexed = [(grid_positions[i][1], grid_positions[i][0], i, CT[i])
                    for i in range(K4_LEN)]
        # Sort by column first, then row
        indexed.sort(key=lambda x: (x[0], x[1]))
        reordered = ''.join(ch for _, _, _, ch in indexed)
        sc_r = combined_score(reordered)
        fr_r = score_free(reordered)
        print(f"    {pass_num} (col,row order): {reordered[:40]}...")
        print(f"      anch={sc_r['anchored']}/24, free={sc_r['free']}/24, IC={sc_r['ic']:.4f}")
        if fr_r.ene_found or fr_r.bc_found:
            print(f"      *** CRIBS FOUND: ENE={fr_r.ene_found}, BC={fr_r.bc_found}")
        results.append({"method": f"reorder_{pass_num}_col_row", **sc_r})
        configs_tested += 1

        # Also sort by row first, then column (standard reading of rotated text)
        indexed.sort(key=lambda x: (x[1], x[0]))
        reordered2 = ''.join(ch for _, _, _, ch in indexed)
        sc_r2 = combined_score(reordered2)
        fr_r2 = score_free(reordered2)
        print(f"    {pass_num} (row,col order): {reordered2[:40]}...")
        print(f"      anch={sc_r2['anchored']}/24, free={sc_r2['free']}/24, IC={sc_r2['ic']:.4f}")
        if fr_r2.ene_found or fr_r2.bc_found:
            print(f"      *** CRIBS FOUND")
        results.append({"method": f"reorder_{pass_num}_row_col", **sc_r2})
        configs_tested += 1

    # 4f: XOR-like combination of two passes
    print()
    print("  4f: Two-pass difference as substitution")
    # Take the two K4 streams at their vertical-reading positions
    # and compute position-wise differences
    for label, grid_pos_list in [("pass1", k4_p1_grid), ("pass2", k4_p2_grid)]:
        # Use the OTHER pass's column as key to decrypt THIS pass's text
        other = k4_p2_grid if label == "pass1" else k4_p1_grid
        shifts = [(other[i][1] % MOD) for i in range(K4_LEN)]
        pt = vigenere_decrypt(CT, shifts)
        sc_x = combined_score(pt)
        print(f"    Vig(CT, other_col): anch={sc_x['anchored']}/24, "
              f"free={sc_x['free']}/24")
        results.append({"method": f"cross_pass_{label}", **sc_x})
        configs_tested += 1

    best_anch = max(r.get("anchored", 0) for r in results)
    best_free = max(r.get("free", 0) for r in results)
    print(f"\n  Phase 4 configs: {configs_tested}")
    print(f"  Best anchored: {best_anch}/24, Best free: {best_free}/24")
    return results, best_anch, best_free, configs_tested


# ── Phase 5: Antipodes row widths as scytale parameters ─────────────────

def phase5_rod_diameters():
    """Use actual Antipodes row widths (32-36) as scytale widths for K4."""
    print()
    print("Phase 5: Antipodes row widths as scytale parameters")
    print("-" * 60)

    results = []
    best_free = 0
    configs_tested = 0

    # The actual widths on Antipodes
    widths = sorted(set(row[1] for row in ANTIPODES_ROWS))
    print(f"  Antipodes row widths: {widths}")

    # Also test the mode (34), mean (~33.7), and related values
    test_widths = list(range(30, 40)) + [47]  # Include nrows as width too
    test_widths = sorted(set(test_widths))

    for width in test_widths:
        for direction in ["decrypt", "encrypt"]:
            if direction == "decrypt":
                pt = scytale_decrypt(CT, width)
            else:
                pt = scytale_encrypt(CT, width)

            sc = combined_score(pt)
            fr = score_free(pt)
            configs_tested += 1

            if sc["free"] > 0 or sc["anchored"] > 0:
                print(f"  w={width} {direction}: anch={sc['anchored']}/24, "
                      f"free={sc['free']}/24, IC={sc['ic']:.4f}")
                if fr.ene_found or fr.bc_found:
                    print(f"    *** CRIBS FOUND")

            results.append({"width": width, "direction": direction, **sc})
            best_free = max(best_free, sc["free"])

            # With substitution using Kryptos keywords
            for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLINCLOCK",
                        "EASTNORTHEAST", "WELTZEITUHR"]:
                shifts = keyword_to_shifts(kw)
                for cipher_fn, cn in [(vigenere_decrypt, "vig"),
                                       (beaufort_decrypt, "beau")]:
                    # Scytale then sub
                    pt_ss = cipher_fn(pt, shifts)
                    sc_ss = combined_score(pt_ss)
                    configs_tested += 1
                    if sc_ss["free"] > 0 or sc_ss["anchored"] > 2:
                        print(f"    w={width} {direction}+{cn}({kw}): "
                              f"anch={sc_ss['anchored']}/24, free={sc_ss['free']}/24")
                    results.append({"width": width, "direction": direction,
                                    "cipher": cn, "keyword": kw, **sc_ss})
                    best_free = max(best_free, sc_ss["free"])

                    # Sub then scytale
                    ct_sub = cipher_fn(CT, shifts)
                    if direction == "decrypt":
                        pt_sub = scytale_decrypt(ct_sub, width)
                    else:
                        pt_sub = scytale_encrypt(ct_sub, width)
                    sc_sub = combined_score(pt_sub)
                    configs_tested += 1
                    if sc_sub["free"] > 0 or sc_sub["anchored"] > 2:
                        print(f"    {cn}({kw})+w={width} {direction}: "
                              f"anch={sc_sub['anchored']}/24, free={sc_sub['free']}/24")
                    results.append({"width": width, "direction": direction,
                                    "cipher": cn + "_first", "keyword": kw, **sc_sub})
                    best_free = max(best_free, sc_sub["free"])

    print(f"\n  Phase 5 configs: {configs_tested}")
    print(f"  Best free: {best_free}/24")
    return results, best_free, configs_tested


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 72)
    print("E-AUDIT-05: Scytale Cipher — The Antipodes IS a Cylinder")
    print("=" * 72)

    t0 = time.time()

    # Verify Antipodes data
    print("\nVerifying Antipodes reconstruction...")
    verify_antipodes()

    # Phase 1
    r1, best1_anch, best1_free = phase1_scytale_k4()

    # Phase 2
    r2, best2_anch, best2_free, n2 = phase2_scytale_plus_sub()

    # Phase 3
    r3, best3_free, n3 = phase3_antipodes_vertical()

    # Phase 4
    r4, best4_anch, best4_free, n4 = phase4_two_pass_offset()

    # Phase 5
    r5, best5_free, n5 = phase5_rod_diameters()

    elapsed = time.time() - t0
    total_configs = 94 + n2 + n3 + n4 + n5

    # Summary
    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    overall_best_free = max(best1_free, best2_free, best3_free, best4_free, best5_free)
    overall_best_anch = max(best1_anch, best2_anch, best4_anch)
    print(f"Total configurations tested: {total_configs:,}")
    print(f"Time: {elapsed:.1f}s")
    print(f"Best anchored score: {overall_best_anch}/24")
    print(f"Best free score: {overall_best_free}/24")
    print()
    print(f"Phase 1 (scytale K4 alone):     anch={best1_anch}/24, free={best1_free}/24 (94 configs)")
    print(f"Phase 2 (scytale + sub):         anch={best2_anch}/24, free={best2_free}/24 ({n2:,} configs)")
    print(f"Phase 3 (Antipodes vertical):    free={best3_free}/24 ({n3} configs)")
    print(f"Phase 4 (two-pass offset):       anch={best4_anch}/24, free={best4_free}/24 ({n4} configs)")
    print(f"Phase 5 (rod diameter widths):   free={best5_free}/24 ({n5:,} configs)")
    print()

    if overall_best_free >= 24 or overall_best_anch >= 24:
        print("*** BREAKTHROUGH: Full crib match! Investigate immediately. ***")
    elif overall_best_free >= 13 or overall_best_anch >= 13:
        print("*** SIGNAL: One full crib found. Worth deeper investigation. ***")
    else:
        print("NOISE: No crib content found through any scytale approach.")
        print("The Antipodes cylinder form does not directly yield K4 plaintext")
        print("via scytale-type readings (vertical, diagonal, reordered, or shifted).")

    # Save results
    os.makedirs("results/audit", exist_ok=True)
    output = {
        "experiment": "E-AUDIT-05",
        "description": "Scytale cipher — Antipodes as physical cylinder tool",
        "total_configs": total_configs,
        "elapsed_seconds": elapsed,
        "best_anchored": overall_best_anch,
        "best_free": overall_best_free,
        "phase1": {"best_anch": best1_anch, "best_free": best1_free, "configs": 94},
        "phase2": {"best_anch": best2_anch, "best_free": best2_free, "configs": n2},
        "phase3": {"best_free": best3_free, "configs": n3},
        "phase4": {"best_anch": best4_anch, "best_free": best4_free, "configs": n4},
        "phase5": {"best_free": best5_free, "configs": n5},
    }
    outpath = "results/audit/e_audit_05_scytale_cylinder.json"
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to {outpath}")


if __name__ == "__main__":
    main()
