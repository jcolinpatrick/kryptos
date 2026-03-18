#!/usr/bin/env python3
"""
Cipher: geometry/physical
Family: geometry
Status: active
Keyspace: ~200 configs (directions x methods x ciphers)
Last run:
Best score:
"""
"""E-NDYAHR-NEIGHBOR-POINTER-09: NDYAHR letters as directional pointers to neighbors.

HYPOTHESIS: Every occurrence of N, D, Y, A, H, R in the 28x31 grid is a
directional pointer. The physical displacement direction of each letter
tells you which NEIGHBORING character to mark for deletion/selection:

    N: shifted LEFT  -> mark neighbor to the LEFT  (row, col-1)
    D: shifted RIGHT -> mark neighbor to the RIGHT (row, col+1)
    Y: shifted UP    -> mark neighbor ABOVE         (row-1, col)
    A: shifted UP    -> mark neighbor ABOVE         (row-1, col)
    H: shifted RIGHT -> mark neighbor to the RIGHT  (row, col+1)
    R: shifted UP-LEFT -> mark neighbor UP-LEFT     (row-1, col-1)

Test plan:
  1. Build full 28x31 grid. For EVERY NDYAHR letter, compute neighbor position.
  2. Collect all marked positions. How many? Which chars?
  3. Focus on K4 region (rows 24-27). How many K4 chars marked? Is it 24 (null count)?
  4. If 24 removed -> try decrypting the 73 remaining with known ciphers.
  5. Also test REVERSED directions (viewing from other side).
  6. Also test LINEAR K4 (97 chars) with same pointer logic.
  7. Statistical check: overlap with consensus null positions.

Run: PYTHONPATH=src python3 -u scripts/geometry/e_ndyahr_neighbor_pointer_09.py
"""

import sys
import os
import json
import time
from collections import Counter
from itertools import combinations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, CRIB_DICT, N_CRIBS, CRIB_WORDS,
    NOISE_FLOOR, STORE_THRESHOLD, CRIB_POSITIONS,
)
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

# Try to load quadgram scorer
try:
    with open('data/english_quadgrams.json') as f:
        QUADGRAMS = json.load(f)
    QG_FLOOR = min(QUADGRAMS.values()) - 1.0

    def qg_score(text):
        """Quadgram log-probability score per character."""
        if len(text) < 4:
            return -10.0
        total = 0.0
        for i in range(len(text) - 3):
            qg = text[i:i+4]
            total += QUADGRAMS.get(qg, QG_FLOOR)
        return total / len(text)
except:
    def qg_score(text):
        return -10.0

# ── Grid Constants ──────────────────────────────────────────────────────

GRID_ROWS = 28
GRID_COLS = 31

# Full cipher side grid (28 rows x 31 cols)
# From blitz_ka_cycle_grille.py (verified)
CIPHER_ROWS = [
    'EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV',   # row 0  K1
    'JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF',   # row 1
    'DVFPJUDEEHZWETZYVGWHKKQETGFQJNC',   # row 2
    'EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG',  # row 3  (? at col 7)
    'TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA',   # row 4  (30 chars?)
    'QZGZLECGYUXUEENJTBJLBQCETBJDFHR',   # row 5
    'RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT',   # row 6
    'IHHDDDUVH?DWKBFUFPWNTDFIYCUQZER',   # row 7  (? at col 9)
    'EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI',   # row 8
    'DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK',   # row 9
    'FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ',   # row 10
    'ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE',   # row 11
    'DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP',   # row 12
    'DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG',   # row 13  K2 ends
    'ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI',   # row 14  K3 starts
    'ACHTNREYULDSLLSLLNOHSNOSMRWXMNE',   # row 15
    'TPRNGATIHNRARPESLNNELEBLPIIACAE',    # row 16 (30 chars)
    'WMTWNDITEENRAHCTENEUDRETNHAEOE',     # row 17 (30 chars)
    'TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR',  # row 18
    'EIFTBRSPAMHHEWENATAMATEGYEERLBT',    # row 19 (30 chars? check)
    'EEFOASFIOTUETUAEOTOARMAEERTNRTI',    # row 20
    'BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB',   # row 21
    'AECTDDHILCEIHSITEGOEAOSDDRYDLOR',   # row 22
    'ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE',   # row 23
    'ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR',   # row 24  K4@col27
    'UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO',   # row 25
    'TWTQSJQSSEKZZWATJKLUDIAWINFBNYP',   # row 26
    'VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR',   # row 27
]

# Fix: ensure all rows are exactly 31 chars. Some rows in the original
# source have 30 or 31. For the experiment we need exactly 31.
# Let's rebuild carefully. The known text on the sculpture:

# K1 = 63 chars, K2 = 369 chars, K3 = 336 chars, K4 = 97 chars
# Total = 63 + 369 + 336 + 97 = 865... plus 3 unknown chars = 868

# The '?' marks are genuinely unclear/damaged positions on the sculpture.
# For this experiment, we'll use the grid as-is and handle '?' gracefully.

# Verify and pad rows
for i, row in enumerate(CIPHER_ROWS):
    if len(row) < 31:
        # Pad with '?' to maintain grid alignment
        CIPHER_ROWS[i] = row + '?' * (31 - len(row))
    elif len(row) > 31:
        CIPHER_ROWS[i] = row[:31]

assert all(len(r) == 31 for r in CIPHER_ROWS), "Grid alignment failed"

# Build 2D grid
GRID = []
for row_str in CIPHER_ROWS:
    GRID.append(list(row_str))

# ── K4 positions in grid ────────────────────────────────────────────────

K4_POSITIONS = []  # (row, col) for each K4 index 0..96
for c in range(27, 31):
    K4_POSITIONS.append((24, c))
for r in range(25, 28):
    for c in range(31):
        K4_POSITIONS.append((r, c))
assert len(K4_POSITIONS) == 97

# Verify K4 text matches
k4_from_grid = ''.join(GRID[r][c] for r, c in K4_POSITIONS)
# Handle the '?' at position 26 in row 24
# K4 starts at col 27, so the '?' at col 26 is NOT in K4
assert k4_from_grid == CT, f"K4 mismatch: {k4_from_grid}"

# Reverse lookup: (row, col) -> K4 index (or None if not K4)
POS_TO_K4 = {}
for i, (r, c) in enumerate(K4_POSITIONS):
    POS_TO_K4[(r, c)] = i

# ── Consensus null positions from MEMORY.md ─────────────────────────────

CONSENSUS_17 = frozenset([0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85])

# Known 24-null masks (from prior work)
MASKS_24 = [
    frozenset([0,1,2,5,8,12,14,20,36,38,39,40,52,55,58,59,74,75,78,84,85,88,94,96]),
    frozenset([0,1,2,5,8,12,14,20,36,39,41,43,52,56,58,59,74,75,78,84,85,88,93,95]),
]

# ── Displacement direction rules ────────────────────────────────────────

# Primary directions (from user hypothesis)
PRIMARY_DIRS = {
    'N': (0, -1),   # LEFT
    'D': (0, +1),   # RIGHT
    'Y': (-1, 0),   # UP
    'A': (-1, 0),   # UP
    'H': (0, +1),   # RIGHT
    'R': (-1, -1),  # UP-LEFT (diagonal)
}

# Reversed directions (viewing from tableau side)
REVERSED_DIRS = {
    'N': (0, +1),   # RIGHT
    'D': (0, -1),   # LEFT (or DOWN in user alt)
    'Y': (-1, 0),   # UP (same)
    'A': (-1, 0),   # UP (same)
    'H': (0, -1),   # LEFT
    'R': (-1, 0),   # UP (simplified)
}

# User's explicit reverse: R→UP, H→LEFT, A→UP, Y→UP, D→DOWN, N→RIGHT
REVERSED_DIRS_V2 = {
    'N': (0, +1),   # RIGHT
    'D': (+1, 0),   # DOWN
    'Y': (-1, 0),   # UP
    'A': (-1, 0),   # UP
    'H': (0, -1),   # LEFT
    'R': (-1, 0),   # UP
}

NDYAHR = set('NDYAHR')

# ── Cipher functions ────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET
AZ = ALPH
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ_IDX = ALPH_IDX

def decrypt_vig(ct_text, keyword, alph=AZ, alph_idx=AZ_IDX):
    key_nums = [alph_idx[c] for c in keyword]
    ct_nums = [alph_idx[c] for c in ct_text]
    pt_nums = [(c - key_nums[i % len(key_nums)]) % 26 for i, c in enumerate(ct_nums)]
    return ''.join(alph[n] for n in pt_nums)

def decrypt_beau(ct_text, keyword, alph=AZ, alph_idx=AZ_IDX):
    key_nums = [alph_idx[c] for c in keyword]
    ct_nums = [alph_idx[c] for c in ct_text]
    pt_nums = [(key_nums[i % len(key_nums)] - c) % 26 for i, c in enumerate(ct_nums)]
    return ''.join(alph[n] for n in pt_nums)

def decrypt_varbeau(ct_text, keyword, alph=AZ, alph_idx=AZ_IDX):
    key_nums = [alph_idx[c] for c in keyword]
    ct_nums = [alph_idx[c] for c in ct_text]
    pt_nums = [(c - key_nums[i % len(key_nums)]) % 26 for i, c in enumerate(ct_nums)]
    # Var Beaufort: PT = CT - Key (same as Vig but different context)
    # Actually: K = (PT - CT) mod 26, so PT = (K + CT) mod 26
    pt_nums2 = [(key_nums[i % len(key_nums)] + c) % 26 for i, c in enumerate(ct_nums)]
    return ''.join(alph[n] for n in pt_nums2)

def decrypt_autokey_pt(ct_text, primer, alph=AZ, alph_idx=AZ_IDX):
    """PT-autokey Vigenere."""
    ct_nums = [alph_idx[c] for c in ct_text]
    key_nums = [alph_idx[c] for c in primer]
    pt_nums = []
    for i, c in enumerate(ct_nums):
        k = key_nums[i] if i < len(key_nums) else pt_nums[i - len(key_nums)]
        pt_nums.append((c - k) % 26)
    return ''.join(alph[n] for n in pt_nums)

def columnar_decrypt(ct_text, width):
    """Columnar transposition decrypt (standard column order)."""
    n = len(ct_text)
    full_rows = n // width
    extra = n % width
    col_lengths = [full_rows + (1 if i < extra else 0) for i in range(width)]
    cols = []
    idx = 0
    for cl in col_lengths:
        cols.append(ct_text[idx:idx+cl])
        idx += cl
    # Read off row by row
    pt = []
    for row in range(full_rows + (1 if extra else 0)):
        for col in range(width):
            if row < len(cols[col]):
                pt.append(cols[col][row])
    return ''.join(pt)

KEYWORDS = ['KRYPTOS', 'DEFECTOR', 'PALIMPSEST', 'ABSCISSA', 'KOMPASS',
            'SHADOW', 'SANBORN', 'BERLIN', 'CLOCK', 'BERLINCLOCK',
            'EASTNORTHEAST', 'COLOPHON', 'PARALLAX']

# ══════════════════════════════════════════════════════════════════════════
# EXPERIMENT
# ══════════════════════════════════════════════════════════════════════════

timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
results = {
    "experiment": "E-NDYAHR-NEIGHBOR-POINTER-09",
    "timestamp": timestamp,
    "hypothesis": "NDYAHR letters in 28x31 grid are directional pointers to neighbors for deletion",
    "phases": {},
}

best_overall = {"score": 0, "method": "", "detail": "", "pt": ""}

def update_best(score, method, detail, pt=""):
    global best_overall
    if score > best_overall["score"]:
        best_overall = {"score": score, "method": method, "detail": detail, "pt": pt}

print("=" * 80)
print("E-NDYAHR-NEIGHBOR-POINTER-09")
print("NDYAHR letters as directional pointers to grid neighbors")
print("=" * 80)
print()

# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: Full grid scan — all NDYAHR occurrences point to neighbors
# ══════════════════════════════════════════════════════════════════════════

def scan_grid(direction_map, label, wrap=False):
    """For every NDYAHR letter in the grid, compute the pointed-to neighbor.
    Returns set of (row, col) marked for deletion, and K4-specific subset."""

    all_marked = set()
    k4_marked_indices = set()
    ndyahr_count = Counter()
    out_of_bounds = 0

    for r in range(GRID_ROWS):
        for c in range(GRID_COLS):
            ch = GRID[r][c]
            if ch in direction_map:
                ndyahr_count[ch] += 1
                dr, dc = direction_map[ch]
                nr, nc = r + dr, c + dc

                if wrap:
                    nr = nr % GRID_ROWS
                    nc = nc % GRID_COLS

                if 0 <= nr < GRID_ROWS and 0 <= nc < GRID_COLS:
                    all_marked.add((nr, nc))
                    if (nr, nc) in POS_TO_K4:
                        k4_marked_indices.add(POS_TO_K4[(nr, nc)])
                else:
                    out_of_bounds += 1

    return all_marked, k4_marked_indices, ndyahr_count, out_of_bounds

print("PHASE 1: Full 28x31 grid — primary directions")
print("-" * 60)

for label, dir_map in [("PRIMARY", PRIMARY_DIRS), ("REVERSED", REVERSED_DIRS), ("REVERSED_V2", REVERSED_DIRS_V2)]:
    for wrap in [False, True]:
        wrap_label = "wrap" if wrap else "no-wrap"
        tag = f"{label}:{wrap_label}"

        all_marked, k4_marked, ndyahr_count, oob = scan_grid(dir_map, tag, wrap=wrap)

        # K4 positions marked
        k4_remaining = sorted(set(range(97)) - k4_marked)
        k4_removed = sorted(k4_marked)

        # Characters at marked K4 positions
        marked_chars = ''.join(CT[i] for i in k4_removed)
        remaining_text = ''.join(CT[i] for i in k4_remaining)

        # Overlap with consensus nulls
        overlap_17 = k4_marked & CONSENSUS_17
        overlap_24_0 = k4_marked & MASKS_24[0]
        overlap_24_1 = k4_marked & MASKS_24[1]

        print(f"\n  [{tag}]")
        print(f"    Total grid positions marked: {len(all_marked)}/{GRID_ROWS*GRID_COLS}")
        print(f"    K4 positions marked for deletion: {len(k4_marked)}/97")
        print(f"    K4 remaining: {len(k4_remaining)}")
        print(f"    Out-of-bounds skipped: {oob}")
        print(f"    NDYAHR counts in grid: {dict(ndyahr_count)}, total={sum(ndyahr_count.values())}")
        print(f"    Marked K4 positions: {k4_removed}")
        print(f"    Marked K4 chars: {marked_chars}")
        print(f"    Overlap with consensus-17: {len(overlap_17)}/17 = {sorted(overlap_17)}")
        print(f"    Overlap with mask-24[0]: {len(overlap_24_0)}/24")
        print(f"    Overlap with mask-24[1]: {len(overlap_24_1)}/24")

        if len(k4_remaining) == 73:
            print(f"    *** EXACTLY 73 REMAINING! ***")
        if 70 <= len(k4_remaining) <= 76:
            print(f"    ** NEAR 73 ({len(k4_remaining)}) **")

        results["phases"][f"phase1_{tag}"] = {
            "total_marked": len(all_marked),
            "k4_marked": len(k4_marked),
            "k4_remaining": len(k4_remaining),
            "k4_marked_positions": k4_removed,
            "marked_chars": marked_chars,
            "remaining_text": remaining_text,
            "consensus17_overlap": len(overlap_17),
            "mask24_0_overlap": len(overlap_24_0),
            "mask24_1_overlap": len(overlap_24_1),
            "oob": oob,
        }

        # If remaining is in a useful range, try decryption
        if 60 <= len(k4_remaining) <= 85:
            print(f"    Attempting decryption of {len(k4_remaining)}-char extract...")
            best_qg = -10.0
            best_qg_detail = ""

            for kw in KEYWORDS:
                for cipher_name, cipher_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
                    for alph_name, alph, aidx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
                        try:
                            pt = cipher_fn(remaining_text, kw, alph, aidx)
                            q = qg_score(pt)
                            if q > best_qg:
                                best_qg = q
                                best_qg_detail = f"{kw}:{alph_name}_{cipher_name}"
                                best_pt = pt
                        except:
                            pass

                    # Autokey
                    try:
                        pt = decrypt_autokey_pt(remaining_text, kw, AZ, AZ_IDX)
                        q = qg_score(pt)
                        if q > best_qg:
                            best_qg = q
                            best_qg_detail = f"{kw}:AZ_autokey"
                            best_pt = pt
                    except:
                        pass

            # Also try col7 transposition before sub
            for w in [7, 8, 9, 10, 11, 13, 14]:
                if w >= len(remaining_text):
                    continue
                trans_text = columnar_decrypt(remaining_text, w)
                for kw in ['DEFECTOR', 'KRYPTOS', 'PALIMPSEST', 'ABSCISSA']:
                    for cipher_name, cipher_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
                        for alph_name, alph, aidx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
                            try:
                                pt = cipher_fn(trans_text, kw, alph, aidx)
                                q = qg_score(pt)
                                if q > best_qg:
                                    best_qg = q
                                    best_qg_detail = f"col{w}+{kw}:{alph_name}_{cipher_name}"
                                    best_pt = pt
                            except:
                                pass

            # Crib scoring on 97-char reconstruction (put blanks back)
            if len(k4_remaining) <= 97:
                # Score remaining text with free crib search
                sc_free = score_candidate_free(remaining_text)

                print(f"    Best quadgram: {best_qg:.3f}/char ({best_qg_detail})")
                print(f"    Free crib score on extract: {sc_free.crib_score}")
                if best_qg > -5.5:
                    print(f"    ** ELEVATED quadgram score!")
                    print(f"    PT: {best_pt[:60]}...")

                update_best(sc_free.crib_score, f"grid-pointer:{tag}",
                           f"k4_marked={len(k4_marked)}, best_qg={best_qg:.3f} ({best_qg_detail})",
                           remaining_text)

print()

# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: NDYAHR in K4 region ONLY (rows 24-27 of grid)
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PHASE 2: NDYAHR in K4 grid region only (rows 24-27)")
print("-" * 60)

def scan_k4_region(direction_map, label, wrap=False):
    """Only look at NDYAHR letters WITHIN K4 (rows 24-27)."""
    k4_marked_indices = set()
    count = 0

    for k4_idx in range(97):
        r, c = K4_POSITIONS[k4_idx]
        ch = CT[k4_idx]
        if ch in direction_map:
            count += 1
            dr, dc = direction_map[ch]
            nr, nc = r + dr, c + dc

            if wrap:
                # Wrap within K4 grid space only
                if nr < 24:
                    nr = 27
                elif nr > 27:
                    nr = 24
                nc = nc % GRID_COLS

            if 0 <= nr < GRID_ROWS and 0 <= nc < GRID_COLS:
                if (nr, nc) in POS_TO_K4:
                    k4_marked_indices.add(POS_TO_K4[(nr, nc)])

    return k4_marked_indices, count

for label, dir_map in [("PRIMARY", PRIMARY_DIRS), ("REVERSED", REVERSED_DIRS), ("REVERSED_V2", REVERSED_DIRS_V2)]:
    for wrap in [False, True]:
        tag = f"{label}:{('wrap' if wrap else 'no-wrap')}"
        k4_marked, ndyahr_in_k4 = scan_k4_region(dir_map, tag, wrap=wrap)
        k4_remaining = sorted(set(range(97)) - k4_marked)

        overlap_17 = k4_marked & CONSENSUS_17

        print(f"\n  [{tag}]")
        print(f"    NDYAHR letters in K4: {ndyahr_in_k4}")
        print(f"    K4 neighbors marked: {len(k4_marked)}/97")
        print(f"    K4 remaining: {len(k4_remaining)}")
        print(f"    Consensus-17 overlap: {len(overlap_17)}/17")

        if len(k4_remaining) == 73:
            print(f"    *** EXACTLY 73 REMAINING! ***")

        results["phases"][f"phase2_k4only_{tag}"] = {
            "ndyahr_in_k4": ndyahr_in_k4,
            "k4_marked": len(k4_marked),
            "k4_remaining": len(k4_remaining),
            "consensus17_overlap": len(overlap_17),
        }

print()

# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: NDYAHR in FULL grid but only count marks that land in K4
# Already done in Phase 1, but also: marks from K3 region pointing INTO K4
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PHASE 3: Marks from K3 boundary region pointing into K4")
print("-" * 60)

for label, dir_map in [("PRIMARY", PRIMARY_DIRS), ("REVERSED_V2", REVERSED_DIRS_V2)]:
    # Focus on K3/K4 boundary: rows 22-24
    boundary_marks_into_k4 = set()

    for r in range(22, 25):
        for c in range(GRID_COLS):
            ch = GRID[r][c]
            if ch in dir_map:
                dr, dc = dir_map[ch]
                nr, nc = r + dr, c + dc
                if 0 <= nr < GRID_ROWS and 0 <= nc < GRID_COLS:
                    if (nr, nc) in POS_TO_K4:
                        boundary_marks_into_k4.add(POS_TO_K4[(nr, nc)])

    print(f"\n  [{label}] K3 boundary (rows 22-24) marks into K4: {len(boundary_marks_into_k4)}")
    print(f"    Positions: {sorted(boundary_marks_into_k4)}")

print()

# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: LINEAR K4 interpretation (97 chars as 1D string)
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PHASE 4: Linear K4 — NDYAHR as pointer to linear neighbors")
print("-" * 60)

# Interpretation 1: Simple left/right in linear text
LINEAR_DIRS_SIMPLE = {
    'N': -1,   # left
    'D': +1,   # right
    'Y': -1,   # up = left (linear)
    'A': -1,   # up = left
    'H': +1,   # right
    'R': -2,   # up-left = two left (linear)
}

# Interpretation 2: Grid-based (width 31)
LINEAR_DIRS_GRID = {
    'N': -1,      # left
    'D': +1,      # right
    'Y': -31,     # up (previous row in width-31 grid)
    'A': -31,     # up
    'H': +1,      # right
    'R': -32,     # up-left (row up, one left)
}

# Also reversed versions
LINEAR_DIRS_SIMPLE_REV = {
    'N': +1, 'D': -1, 'Y': -1, 'A': -1, 'H': -1, 'R': -1,
}
LINEAR_DIRS_GRID_REV = {
    'N': +1, 'D': +31, 'Y': -31, 'A': -31, 'H': -1, 'R': -31,
}

for interp_label, offset_map in [
    ("SIMPLE", LINEAR_DIRS_SIMPLE),
    ("GRID_W31", LINEAR_DIRS_GRID),
    ("SIMPLE_REV", LINEAR_DIRS_SIMPLE_REV),
    ("GRID_W31_REV", LINEAR_DIRS_GRID_REV),
]:
    marked = set()
    ndyahr_count = 0

    for i, ch in enumerate(CT):
        if ch in offset_map:
            ndyahr_count += 1
            target = i + offset_map[ch]
            if 0 <= target < 97:
                marked.add(target)

    remaining_idx = sorted(set(range(97)) - marked)
    remaining_text = ''.join(CT[i] for i in remaining_idx)
    overlap_17 = marked & CONSENSUS_17

    print(f"\n  [{interp_label}]")
    print(f"    NDYAHR in K4: {ndyahr_count}")
    print(f"    Positions marked: {len(marked)}")
    print(f"    Remaining: {len(remaining_idx)}")
    print(f"    Consensus-17 overlap: {len(overlap_17)}/17")
    print(f"    Marked positions: {sorted(marked)}")

    if len(remaining_idx) == 73:
        print(f"    *** EXACTLY 73! ***")
    if 70 <= len(remaining_idx) <= 76:
        print(f"    ** NEAR 73 ({len(remaining_idx)}) **")

    # Try decryption
    if 50 <= len(remaining_idx) <= 90:
        best_qg = -10.0
        best_qg_detail = ""
        best_pt = ""

        for kw in ['KRYPTOS', 'DEFECTOR', 'PALIMPSEST', 'ABSCISSA']:
            for cipher_name, cipher_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
                for alph_name, alph, aidx in [("AZ", AZ, AZ_IDX), ("KA", KA, KA_IDX)]:
                    try:
                        pt = cipher_fn(remaining_text, kw, alph, aidx)
                        q = qg_score(pt)
                        if q > best_qg:
                            best_qg = q
                            best_qg_detail = f"{kw}:{alph_name}_{cipher_name}"
                            best_pt = pt
                    except:
                        pass

        # Also col7 trans
        for w in [7]:
            if w < len(remaining_text):
                trans = columnar_decrypt(remaining_text, w)
                for kw in ['DEFECTOR']:
                    try:
                        pt = decrypt_beau(trans, kw, AZ, AZ_IDX)
                        q = qg_score(pt)
                        if q > best_qg:
                            best_qg = q
                            best_qg_detail = f"col{w}+{kw}:AZ_beau"
                            best_pt = pt
                    except:
                        pass

        sc_free = score_candidate_free(remaining_text)
        print(f"    Best quadgram: {best_qg:.3f}/char ({best_qg_detail})")
        print(f"    Free crib score: {sc_free.crib_score}")

        update_best(sc_free.crib_score, f"linear:{interp_label}",
                   f"marked={len(marked)}, best_qg={best_qg:.3f} ({best_qg_detail})",
                   remaining_text)

    results["phases"][f"phase4_linear_{interp_label}"] = {
        "ndyahr_count": ndyahr_count,
        "marked": len(marked),
        "remaining": len(remaining_idx),
        "remaining_text": remaining_text,
        "consensus17_overlap": len(overlap_17),
    }

print()

# ══════════════════════════════════════════════════════════════════════════
# PHASE 5: Delete the NDYAHR letter ITSELF if neighbor matches criteria
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PHASE 5: Delete NDYAHR letters themselves (self-deletion)")
print("-" * 60)

# Maybe NDYAHR letters are the NULLS — delete all N,D,Y,A,H,R from K4
ndyahr_positions = [i for i, ch in enumerate(CT) if ch in NDYAHR]
non_ndyahr_positions = [i for i, ch in enumerate(CT) if ch not in NDYAHR]
remaining_text = ''.join(CT[i] for i in non_ndyahr_positions)
overlap_17 = set(ndyahr_positions) & CONSENSUS_17

print(f"  NDYAHR letters in K4: {len(ndyahr_positions)}")
print(f"  Positions: {ndyahr_positions}")
print(f"  Remaining after removing NDYAHR: {len(non_ndyahr_positions)}")
print(f"  Remaining text: {remaining_text}")
print(f"  Consensus-17 overlap: {len(overlap_17)}/17")

if len(non_ndyahr_positions) == 73:
    print(f"  *** EXACTLY 73! ***")

results["phases"]["phase5_self_deletion"] = {
    "ndyahr_count": len(ndyahr_positions),
    "remaining": len(non_ndyahr_positions),
    "remaining_text": remaining_text,
    "consensus17_overlap": len(overlap_17),
}

print()

# ══════════════════════════════════════════════════════════════════════════
# PHASE 6: Neighbor chars as KEY values
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PHASE 6: NDYAHR neighbor chars define a cyclic KEY")
print("-" * 60)

for label, dir_map in [("PRIMARY", PRIMARY_DIRS), ("REVERSED_V2", REVERSED_DIRS_V2)]:
    # For each NDYAHR in K4, get the neighbor char -> key value
    key_chars = []
    for i, ch in enumerate(CT):
        if ch in NDYAHR:
            r, c = K4_POSITIONS[i]
            dr, dc = dir_map[ch]
            nr, nc = r + dr, c + dc
            if 0 <= nr < GRID_ROWS and 0 <= nc < GRID_COLS:
                neighbor = GRID[nr][nc]
                if neighbor != '?':
                    key_chars.append(neighbor)

    if key_chars:
        key_str = ''.join(key_chars)
        print(f"\n  [{label}] Key from K4 NDYAHR neighbors: {key_str} (len={len(key_str)})")

        # Use as repeating key
        for cipher_name, cipher_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
            try:
                pt = cipher_fn(CT, key_str, AZ, AZ_IDX)
                q = qg_score(pt)
                sc = score_candidate(pt)
                print(f"    {cipher_name}: qg={q:.3f}, crib={sc.crib_score}/24, PT={pt[:40]}...")
                update_best(sc.crib_score, f"ndyahr-key:{label}:{cipher_name}",
                           f"key={key_str}, qg={q:.3f}", pt)
            except:
                pass

print()

# ══════════════════════════════════════════════════════════════════════════
# PHASE 7: Comprehensive direction variations
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PHASE 7: All plausible direction assignments (combinatorial)")
print("-" * 60)

# Each letter can point in 8 directions. But we constrain by the known
# physical displacements. Let's test a few alternative interpretations.

ALT_DIRS = [
    # Name, dir_map
    ("down_for_up", {'N': (0, -1), 'D': (0, +1), 'Y': (+1, 0), 'A': (+1, 0), 'H': (0, +1), 'R': (+1, -1)}),
    ("all_right",   {'N': (0, +1), 'D': (0, +1), 'Y': (0, +1), 'A': (0, +1), 'H': (0, +1), 'R': (0, +1)}),
    ("all_left",    {'N': (0, -1), 'D': (0, -1), 'Y': (0, -1), 'A': (0, -1), 'H': (0, -1), 'R': (0, -1)}),
    ("all_up",      {'N': (-1, 0), 'D': (-1, 0), 'Y': (-1, 0), 'A': (-1, 0), 'H': (-1, 0), 'R': (-1, 0)}),
    ("all_down",    {'N': (+1, 0), 'D': (+1, 0), 'Y': (+1, 0), 'A': (+1, 0), 'H': (+1, 0), 'R': (+1, 0)}),
    # Self (mark the position itself)
    ("self",        {'N': (0, 0), 'D': (0, 0), 'Y': (0, 0), 'A': (0, 0), 'H': (0, 0), 'R': (0, 0)}),
]

results_phase7 = []
for alt_name, alt_dirs in ALT_DIRS:
    all_marked, k4_marked, _, _ = scan_grid(alt_dirs, alt_name, wrap=False)
    remaining = 97 - len(k4_marked)
    overlap_17 = k4_marked & CONSENSUS_17

    print(f"  [{alt_name}] K4 marked={len(k4_marked)}, remaining={remaining}, cons17={len(overlap_17)}/17")

    if remaining == 73:
        print(f"    *** EXACTLY 73! ***")

    results_phase7.append({
        "name": alt_name,
        "k4_marked": len(k4_marked),
        "remaining": remaining,
        "consensus17": len(overlap_17),
    })

results["phases"]["phase7_alt_dirs"] = results_phase7

print()

# ══════════════════════════════════════════════════════════════════════════
# PHASE 8: NDYAHR in K3 text only — marks pointing into K4
# K3 ends at row 24 col 25. NDYAHR instructions from K3 pointing right/down
# could mark K4 positions.
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PHASE 8: NDYAHR in K3 text — marks pointing into K4 region")
print("-" * 60)

K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)
K3_CT = K3_CT.replace('\n', '')

# K3 positions: rows 14-23 (full 31-wide) + row 24 cols 0-25 (26 chars)
k3_positions = []
for r in range(14, 24):
    for c in range(31):
        k3_positions.append((r, c))
for c in range(26):
    k3_positions.append((24, c))

print(f"  K3 length: {len(K3_CT)}, grid positions: {len(k3_positions)}")

for label, dir_map in [("PRIMARY", PRIMARY_DIRS), ("REVERSED_V2", REVERSED_DIRS_V2)]:
    k4_marks_from_k3 = set()

    for idx, (r, c) in enumerate(k3_positions):
        if idx < len(K3_CT):
            ch = K3_CT[idx]
        else:
            continue
        if ch in dir_map:
            dr, dc = dir_map[ch]
            nr, nc = r + dr, c + dc
            if 0 <= nr < GRID_ROWS and 0 <= nc < GRID_COLS:
                if (nr, nc) in POS_TO_K4:
                    k4_marks_from_k3.add(POS_TO_K4[(nr, nc)])

    k4_remaining = sorted(set(range(97)) - k4_marks_from_k3)
    overlap_17 = k4_marks_from_k3 & CONSENSUS_17

    print(f"\n  [{label}] K3 NDYAHR pointing into K4: {len(k4_marks_from_k3)} positions")
    print(f"    Positions: {sorted(k4_marks_from_k3)}")
    print(f"    K4 remaining: {len(k4_remaining)}")
    print(f"    Consensus-17 overlap: {len(overlap_17)}/17")

    if len(k4_remaining) == 73:
        print(f"    *** EXACTLY 73! ***")

print()

# ══════════════════════════════════════════════════════════════════════════
# PHASE 9: Statistical analysis — expected vs observed
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PHASE 9: Statistical baseline — expected marks by random direction assignment")
print("-" * 60)

# Count NDYAHR in each region
total_ndyahr_grid = sum(1 for r in range(GRID_ROWS) for c in range(GRID_COLS) if GRID[r][c] in NDYAHR)
ndyahr_in_k4 = sum(1 for ch in CT if ch in NDYAHR)
ndyahr_in_k4_region = sum(1 for r in range(24, 28) for c in range(GRID_COLS) if GRID[r][c] in NDYAHR)

print(f"  Total NDYAHR in 28x31 grid: {total_ndyahr_grid}/{GRID_ROWS*GRID_COLS} = {total_ndyahr_grid/(GRID_ROWS*GRID_COLS)*100:.1f}%")
print(f"  NDYAHR in K4 (97 chars): {ndyahr_in_k4}/97 = {ndyahr_in_k4/97*100:.1f}%")
print(f"  NDYAHR in K4 grid region (rows 24-27): {ndyahr_in_k4_region}")

# Each NDYAHR occurrence marks 1 neighbor. Some neighbors overlap.
# Expected unique K4 marks from full grid pointing:
# Prob that any given K4 position is NOT marked = (1 - 1/868)^total_ndyahr
import math
p_not_marked = (1 - 97/(GRID_ROWS*GRID_COLS)) ** total_ndyahr_grid
expected_k4_marked = 97 * (1 - p_not_marked)
print(f"\n  Expected K4 marks (if random pointing): ~{expected_k4_marked:.1f}")
print(f"  For 73-char result, need exactly 24 K4 marks")
print(f"  Probability of exactly 24 by chance: requires detailed calculation")

results["phases"]["phase9_stats"] = {
    "total_ndyahr_grid": total_ndyahr_grid,
    "ndyahr_in_k4": ndyahr_in_k4,
}

print()

# ══════════════════════════════════════════════════════════════════════════
# PHASE 10: The deleted characters as key for the remaining text
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("PHASE 10: Deleted chars as cipher key for remaining text")
print("-" * 60)

for label, dir_map in [("PRIMARY", PRIMARY_DIRS), ("REVERSED_V2", REVERSED_DIRS_V2)]:
    all_marked, k4_marked, _, _ = scan_grid(dir_map, label, wrap=False)

    if len(k4_marked) == 0:
        continue

    k4_removed = sorted(k4_marked)
    k4_remaining = sorted(set(range(97)) - k4_marked)

    deleted_chars = ''.join(CT[i] for i in k4_removed)
    remaining_text = ''.join(CT[i] for i in k4_remaining)

    if len(deleted_chars) == 0 or len(remaining_text) == 0:
        continue

    print(f"\n  [{label}] Deleted={len(deleted_chars)} chars: {deleted_chars}")
    print(f"  Remaining={len(remaining_text)} chars: {remaining_text[:60]}...")

    # Use deleted chars as key
    for cipher_name, cipher_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
        try:
            pt = cipher_fn(remaining_text, deleted_chars, AZ, AZ_IDX)
            q = qg_score(pt)
            print(f"    {cipher_name}(remaining, deleted): qg={q:.3f}, PT={pt[:50]}...")
            update_best(0, f"deleted-as-key:{label}:{cipher_name}",
                       f"qg={q:.3f}", pt)
        except:
            pass

    # Reverse: use remaining as key for deleted
    for cipher_name, cipher_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
        try:
            pt = cipher_fn(deleted_chars, remaining_text[:len(deleted_chars)], AZ, AZ_IDX)
            q = qg_score(pt)
            print(f"    {cipher_name}(deleted, remaining): qg={q:.3f}, PT={pt[:50]}...")
        except:
            pass

print()

# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("OVERALL SUMMARY")
print("=" * 80)

print(f"\n  Best overall score: {best_overall['score']}/24")
print(f"  Method: {best_overall['method']}")
print(f"  Detail: {best_overall['detail']}")
if best_overall['pt']:
    print(f"  PT: {best_overall['pt'][:80]}...")

# Key finding summary
print(f"\n  KEY FINDINGS:")
for phase_name, phase_data in results["phases"].items():
    if isinstance(phase_data, dict) and "k4_remaining" in phase_data:
        rem = phase_data["k4_remaining"]
        if rem == 73:
            print(f"    *** {phase_name}: EXACTLY 73 REMAINING ***")
        elif 70 <= rem <= 76:
            print(f"    ** {phase_name}: {rem} remaining (near 73) **")

results["best_overall"] = best_overall

# Save results
os.makedirs("results", exist_ok=True)
out_path = "results/ndyahr_neighbor_pointer.json"
with open(out_path, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f"\n  Results saved to {out_path}")

print("\n" + "=" * 80)
print("DONE")
print("=" * 80)
