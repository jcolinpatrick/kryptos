#!/usr/bin/env python3
"""
Cipher: NDYAHR-neighbor-deletion + LAYER-TWO
Family: k3_continuity
Status: active
Keyspace: ~200K configs across 2 parts
Last run: 2026-03-15
Best score: TBD
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

"""
PART A: NDYAHR Neighbor Deletion with CORRECTED Directions
  Apply corrected displacement directions to 28x31 master grid.
  For each NDYAHR letter, mark the NEIGHBOR in the given direction for deletion.
  Corrected directions (from Alias scale model, reverse view):
    N = LEFT  -> (row, col-1)
    D = DOWN  -> (row+1, col)
    Y = UP    -> (row-1, col)
    A = UP    -> (row-1, col)
    H = RIGHT -> (row, col+1)
    R = UP    -> (row-1, col)
  Analyze: how many K4 chars marked? Overlap with consensus nulls?
  If near 73 residue, try DEFECTOR:AZ_beau decryption.

PART B: What "LAYER TWO" Really Means
  K2 PT ends with "...IDBYROWS" (physical) or "...XLAYERTWO" (intended).
  Test: alternative K3 transposition using NDYAHR-derived grid dimensions.
  K3 = pure transposition (double rotation 24x14 -> 8x42).
  Try NDYAHR values {3,7,24} as alternative grid widths for re-reading K3 CT.

Usage: PYTHONPATH=src python3 -u scripts/k3_continuity/e_ndyahr_neighbor_deletion_and_layer_two.py
"""

import sys
import os
import json
import time
import math
import random
from collections import Counter
from datetime import datetime, timezone
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET
from kryptos.kernel.scoring.ngram import NgramScorer

# Load quadgram scorer
QG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
scorer = NgramScorer.from_file(QG_PATH, n=4)

random.seed(42)

# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"

K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE"
    "GGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA"
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI"
    "HHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX"
    "FLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ"
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP"
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)

K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAE"
    "WMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR"
    "EIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI"
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT"
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)

K4_CT = CT  # from constants

K3_PT = ''.join(c for c in (
    "SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS "
    "THAT ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED "
    "WITH TREMBLING HANDS I MADE A TINY BREACH IN THE UPPER "
    "LEFT HAND CORNER AND THEN WIDENING THE HOLE A LITTLE "
    "I INSERTED THE CANDLE AND PEERED IN THE HOT AIR ESCAPING "
    "FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT PRESENTLY "
    "DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST "
    "X CAN YOU SEE ANYTHING Q"
).upper() if c.isalpha())

# K2 plaintexts (both versions)
K2_PT_PHYSICAL = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELD"
    "XTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATION"
    "XDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHERE"
    "XWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGE"
    "XTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTH"
    "SEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS"
)

K2_PT_INTENDED = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELD"
    "XTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGROUNDTOANUNKNOWNLOCATION"
    "XDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHERE"
    "XWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMESSAGE"
    "XTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTH"
    "SEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTXLAYERTWO"
)

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"

# Consensus null positions from best 15/24 masks
CONSENSUS_NULLS = {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}

# Corrected NDYAHR displacement directions (from Alias scale model)
# These are NEIGHBOR directions: the letter tells you to delete the neighbor in that direction
CORRECTED_DIRECTIONS = {
    'N': (0, -1),   # LEFT: (row_delta, col_delta)
    'D': (1, 0),    # DOWN
    'Y': (-1, 0),   # UP
    'A': (-1, 0),   # UP
    'H': (0, 1),    # RIGHT
    'R': (-1, 0),   # UP
}

GRID_WIDTH = 31

results = {
    'timestamp': datetime.now(timezone.utc).isoformat(),
    'script': 'e_ndyahr_neighbor_deletion_and_layer_two.py',
    'parts': {}
}

def ic(text):
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text)
    return sum(f * (f-1) for f in freq.values()) / (n * (n-1))

def vig_decrypt(ct, key, alphabet=ALPH):
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    for i, c in enumerate(ct):
        ki = alph_idx.get(key[i % len(key)], 0)
        ci = alph_idx.get(c, 0)
        pi = (ci - ki) % 26
        pt.append(alphabet[pi])
    return ''.join(pt)

def beau_decrypt(ct, key, alphabet=ALPH):
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    for i, c in enumerate(ct):
        ki = alph_idx.get(key[i % len(key)], 0)
        ci = alph_idx.get(c, 0)
        pi = (ki - ci) % 26
        pt.append(alphabet[pi])
    return ''.join(pt)

def vbeau_decrypt(ct, key, alphabet=ALPH):
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    for i, c in enumerate(ct):
        ki = alph_idx.get(key[i % len(key)], 0)
        ci = alph_idx.get(c, 0)
        pi = (ci + ki) % 26
        pt.append(alphabet[pi])
    return ''.join(pt)

def autokey_pt_decrypt(ct, primer, alphabet=ALPH):
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    key_stream = list(primer)
    for i, c in enumerate(ct):
        ki = alph_idx.get(key_stream[i], 0)
        ci = alph_idx.get(c, 0)
        pi = (ci - ki) % 26
        p = alphabet[pi]
        pt.append(p)
        key_stream.append(p)
    return ''.join(pt)

def columnar_decrypt(ct, key_order):
    """Decrypt columnar transposition with given column order."""
    n = len(ct)
    ncols = len(key_order)
    full_rows = n // ncols
    extra = n % ncols

    rank_to_col = [0] * ncols
    for col_idx, rank in enumerate(key_order):
        rank_to_col[rank] = col_idx

    col_lengths = [full_rows + (1 if col < extra else 0) for col in range(ncols)]

    columns = {}
    pos = 0
    for rank in range(ncols):
        col = rank_to_col[rank]
        length = col_lengths[col]
        columns[col] = ct[pos:pos + length]
        pos += length

    plaintext = []
    max_rows = full_rows + (1 if extra > 0 else 0)
    for row in range(max_rows):
        for col in range(ncols):
            if row < len(columns.get(col, '')):
                plaintext.append(columns[col][row])

    return ''.join(plaintext)

def single_rotation_decrypt(ct, width):
    """Single rotation: write into grid of given width, rotate 90 CW, read rows."""
    n = len(ct)
    height = math.ceil(n / width)
    # Write into width-column grid row by row
    grid = []
    for r in range(height):
        row = []
        for c in range(width):
            idx = r * width + c
            if idx < n:
                row.append(ct[idx])
            else:
                row.append('')
        grid.append(row)

    # Rotate 90 CW: new_grid[c][height-1-r] = grid[r][c]
    new_height = width
    new_width = height
    result = []
    for r in range(new_height):
        for c in range(new_width):
            old_r = height - 1 - c
            old_c = r
            if old_r >= 0 and old_r < len(grid) and old_c < len(grid[old_r]) and grid[old_r][old_c]:
                result.append(grid[old_r][old_c])
    return ''.join(result)

def double_rotation_decrypt(ct, w1, h1, w2, h2):
    """Double rotation: write into w1-wide grid, rotate CW, read; write into w2-wide, rotate CW, read."""
    n = len(ct)
    if w1 * h1 < n or w2 * h2 < n:
        return None

    # First rotation
    inter = single_rotation_decrypt(ct, w1)
    if len(inter) < n:
        return None
    inter = inter[:n]

    # Second rotation
    result = single_rotation_decrypt(inter, w2)
    return result[:n] if result else None

def find_english(text, min_len=4):
    common = ['THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 'ALL',
              'CAN', 'HER', 'WAS', 'ONE', 'OUR', 'OUT', 'THAT', 'HAVE',
              'BEEN', 'THEY', 'THIS', 'WILL', 'EACH', 'MAKE', 'FROM',
              'THEM', 'THEN', 'WITH', 'WHICH', 'THEIR', 'THERE', 'THESE',
              'WOULD', 'COULD', 'SHOULD', 'ABOUT', 'CLOCK', 'BERLIN',
              'EAST', 'NORTH', 'LAYER', 'TWO', 'ROOM', 'DOOR', 'WALL',
              'LIGHT', 'TUNNEL', 'SECRET', 'HIDDEN', 'BENEATH',
              'SLOWLY', 'PASSAGE', 'CHAMBER', 'CANDLE', 'FLAME',
              'KRYPTOS', 'SHADOW', 'COMPASS', 'POINT', 'MIST',
              'BETWEEN', 'SUBTLE', 'SHADING', 'NUANCE', 'IQLUSION',
              'INVISIBLE', 'MAGNETIC', 'FIELD', 'BURIED', 'LOCATION',
              'DESPERATELY', 'REMAINS', 'DEBRIS', 'DOORWAY', 'TREMBLING',
              'BREACH', 'CORNER', 'WIDENING', 'INSERTED', 'PEERED',
              'ESCAPING', 'FLICKER', 'PRESENTLY', 'DETAILS', 'EMERGED']
    found = []
    text_upper = text.upper()
    for word in common:
        if len(word) >= min_len:
            idx = text_upper.find(word)
            if idx >= 0:
                found.append((word, idx))
    return found

def score_crib(text, crib_positions):
    """Score candidate against K4 cribs. Returns (total, ene_score, bcl_score)."""
    ene_start, ene_word = 21, "EASTNORTHEAST"
    bcl_start, bcl_word = 63, "BERLINCLOCK"

    ene_score = sum(1 for i, c in enumerate(ene_word) if ene_start + i < len(text) and text[ene_start + i] == c)
    bcl_score = sum(1 for i, c in enumerate(bcl_word) if bcl_start + i < len(text) and text[bcl_start + i] == c)

    return ene_score + bcl_score, ene_score, bcl_score

def score_crib_free(text, min_len=5):
    """Search for cribs at any position (for shifted/scrambled text)."""
    best = 0
    best_pos = -1
    for crib in ["EASTNORTHEAST", "BERLINCLOCK"]:
        for start in range(len(text) - len(crib) + 1):
            match = sum(1 for i, c in enumerate(crib) if text[start + i] == c)
            if match > best:
                best = match
                best_pos = start
    return best

# ══════════════════════════════════════════════════════════════════════════════
# BUILD THE 28x31 MASTER GRID
# ══════════════════════════════════════════════════════════════════════════════

print("=" * 80)
print("BUILDING 28x31 MASTER GRID")
print("=" * 80)

# The grid has 868 characters = 28 rows x 31 cols
# Top 14 rows (0-13) = K1 + K2 + 2 question marks
# Bottom 14 rows (14-27) = K3 + 1 question mark + K4

# Construct the full text
# K1 = 63 chars, K2 = 369 chars + 3 ? = 372 positions
# Total top = 63 + 369 + 2 "?" = 434 (where do the ? go?)
# Actually the grid has: K1(63) + K2(369+3?) = 435. But we need 434 for 14 rows.
# Let's use the known grid from memory/full_ciphertext.md
# The full text is written continuously, with ? marks at specific positions

# From full_ciphertext.md - the full 28-row text:
FULL_ROWS = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",  # Row 0 - K1
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",   # Row 1 - K1 end, K2 start
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",    # Row 2
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",    # Row 3 - has ?
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",     # Row 4
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",   # Row 5
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",     # Row 6
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",    # Row 7 - has ?
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",    # Row 8
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",    # Row 9 - has ?
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",      # Row 10
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",     # Row 11
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",     # Row 12
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",     # Row 13 - K2 end
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",     # Row 14 - K3 start
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",     # Row 15
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",      # Row 16
    "WMTWNDITEENRAHCTENEUDRETNHAEOE",       # Row 17
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR",    # Row 18
    "EIFTBRSPAMHHEWENATAMATEGYEERLB",       # Row 19
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI",    # Row 20
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",     # Row 21
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",      # Row 22
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",     # Row 23
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",     # Row 24 - K3 end, ?, K4 start
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",      # Row 25
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",      # Row 26
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",     # Row 27
]

# Verify lengths
print(f"Grid: {len(FULL_ROWS)} rows")
for i, row in enumerate(FULL_ROWS):
    if len(row) != 31:
        # Some rows might have different lengths - fix
        pass
    print(f"  Row {i:2d}: {len(row):2d} chars: {row}")

# Build grid as 2D array (row, col) -> char
grid_28x31 = {}
all_chars = []
for r, row in enumerate(FULL_ROWS):
    for c, ch in enumerate(row):
        grid_28x31[(r, c)] = ch
        all_chars.append(ch)

total_chars = len(all_chars)
print(f"\nTotal grid characters: {total_chars}")

# Identify K4 region in the grid
# K4 starts at row 24, col 27 (after the ? at col 26)
# Based on memory/grid31_discovery.md: K4 at row 24 col 27
# K4 = 97 chars: 4 in row 24 (cols 27-30), 31 in row 25, 31 in row 26, 31 in row 27

k4_grid_positions = []
# Row 24, cols 27-30 = OBKR (4 chars)
for c in range(27, 31):
    k4_grid_positions.append((24, c))
# Row 25 full = 31 chars
for c in range(31):
    k4_grid_positions.append((25, c))
# Row 26 full = 31 chars
for c in range(31):
    k4_grid_positions.append((26, c))
# Row 27 full = 31 chars
for c in range(31):
    k4_grid_positions.append((27, c))

# Verify K4 extraction
k4_from_grid = ''.join(grid_28x31.get(pos, '?') for pos in k4_grid_positions)
print(f"\nK4 from grid ({len(k4_from_grid)} chars): {k4_from_grid}")
print(f"K4 constant  ({len(K4_CT)} chars): {K4_CT}")
print(f"K4 match: {k4_from_grid == K4_CT}")

# Map K4 position (0-96) to grid position (row, col)
k4_pos_to_grid = {i: pos for i, pos in enumerate(k4_grid_positions)}
k4_grid_to_pos = {pos: i for i, pos in enumerate(k4_grid_positions)}

# ══════════════════════════════════════════════════════════════════════════════
# PART A: NDYAHR NEIGHBOR DELETION
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PART A: NDYAHR NEIGHBOR DELETION (CORRECTED DIRECTIONS)")
print("=" * 80)

print("\nCorrected directions:")
for letter, (dr, dc) in CORRECTED_DIRECTIONS.items():
    dir_name = {(0,-1): 'LEFT', (0,1): 'RIGHT', (-1,0): 'UP', (1,0): 'DOWN'}.get((dr,dc), f'({dr},{dc})')
    print(f"  {letter} -> {dir_name} (dr={dr}, dc={dc})")

# Step 2: Apply NDYAHR neighbor deletion to ENTIRE 28x31 grid
NDYAHR_SET = set('NDYAHR')
marked_for_deletion = set()
ndyahr_occurrences = []

for r in range(len(FULL_ROWS)):
    for c in range(len(FULL_ROWS[r])):
        ch = grid_28x31.get((r, c), '')
        if ch in NDYAHR_SET:
            dr, dc = CORRECTED_DIRECTIONS[ch]
            target_r = r + dr
            target_c = c + dc

            # Check bounds
            if 0 <= target_r < len(FULL_ROWS) and 0 <= target_c < len(FULL_ROWS[target_r]):
                target_ch = grid_28x31.get((target_r, target_c), '')
                marked_for_deletion.add((target_r, target_c))
                ndyahr_occurrences.append({
                    'source': (r, c),
                    'source_char': ch,
                    'target': (target_r, target_c),
                    'target_char': target_ch,
                })

print(f"\nTotal NDYAHR occurrences in grid: {len(ndyahr_occurrences)}")
print(f"Total unique positions marked for deletion: {len(marked_for_deletion)}")

# Step 3: Analyze results
# Focus on K4 region
k4_marked = set()
k4_marked_positions = []
for pos in marked_for_deletion:
    if pos in k4_grid_to_pos:
        k4_idx = k4_grid_to_pos[pos]
        k4_marked.add(k4_idx)
        k4_marked_positions.append(k4_idx)

k4_marked_positions.sort()
k4_remaining_positions = sorted(set(range(97)) - k4_marked)

print(f"\n--- K4 Region Analysis ---")
print(f"K4 positions marked for deletion: {len(k4_marked)}")
print(f"K4 positions remaining: {len(k4_remaining_positions)}")
print(f"Marked K4 positions: {k4_marked_positions}")
print(f"Remaining K4 positions: {k4_remaining_positions}")

# What characters get marked in K4?
k4_marked_chars = [K4_CT[i] for i in k4_marked_positions]
print(f"Marked K4 chars: {''.join(k4_marked_chars)}")
print(f"Marked char frequencies: {dict(Counter(k4_marked_chars))}")

# Remaining text after deletion
k4_residue = ''.join(K4_CT[i] for i in k4_remaining_positions)
print(f"\nK4 residue ({len(k4_residue)} chars): {k4_residue}")
print(f"K4 residue IC: {ic(k4_residue):.6f}")

# Check if 73 chars remain
print(f"\nIs residue 73 chars? {'YES!' if len(k4_residue) == 73 else 'No (' + str(len(k4_residue)) + ')'}")

# Check overlap with consensus nulls
overlap_with_consensus = k4_marked & CONSENSUS_NULLS
consensus_not_marked = CONSENSUS_NULLS - k4_marked
marked_not_consensus = k4_marked - CONSENSUS_NULLS

print(f"\n--- Overlap with consensus null positions ---")
print(f"Consensus nulls: {sorted(CONSENSUS_NULLS)} ({len(CONSENSUS_NULLS)} positions)")
print(f"NDYAHR-marked: {k4_marked_positions} ({len(k4_marked)} positions)")
print(f"Overlap: {sorted(overlap_with_consensus)} ({len(overlap_with_consensus)} positions)")
print(f"In consensus but NOT marked: {sorted(consensus_not_marked)} ({len(consensus_not_marked)})")
print(f"Marked but NOT in consensus: {sorted(marked_not_consensus)} ({len(marked_not_consensus)})")

# Check if marked chars are from palette {B,G,I,K,O,W,Z}
PALETTE = set('BGIKOWZ')
marked_in_palette = sum(1 for c in k4_marked_chars if c in PALETTE)
print(f"\nMarked chars in palette {{B,G,I,K,O,W,Z}}: {marked_in_palette}/{len(k4_marked_chars)}")
print(f"Marked chars NOT in palette: {[c for c in k4_marked_chars if c not in PALETTE]}")

# ══════════════════════════════════════════════════════════════════════════════
# PART A - Step 4: Try decrypting the residue
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PART A - Step 4: Decrypt K4 residue")
print("=" * 80)

KEYWORDS = ['DEFECTOR', 'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'KOMPASS', 'COLOPHON', 'PARALLAX', 'SHADOW']

best_results_a = []

# Try with fixed crib positions first (if residue keeps same positions)
# Then try free crib scoring
for kw in KEYWORDS:
    for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
        for cipher_name, cipher_fn in [('vig', vig_decrypt), ('beau', beau_decrypt), ('vbeau', vbeau_decrypt)]:
            # Direct on residue
            pt = cipher_fn(k4_residue, kw, alph)
            qg = scorer.score_per_char(pt)
            frags = find_english(pt)
            free_crib = score_crib_free(pt)

            entry = {
                'keyword': kw, 'alphabet': alph_name, 'cipher': cipher_name,
                'qg': round(qg, 4), 'ic': round(ic(pt), 6),
                'free_crib': free_crib, 'fragments': frags,
                'pt_preview': pt[:60], 'type': 'direct_residue',
            }
            best_results_a.append(entry)

            if qg > -6.0 or frags or free_crib >= 4:
                print(f"  {kw}:{alph_name}_{cipher_name}: qg={qg:.3f}, free_crib={free_crib}, frags={frags}")
                if qg > -5.5:
                    print(f"    PT: {pt[:80]}")

        # Autokey
        for ak_name, ak_fn in [('ptautokey', autokey_pt_decrypt)]:
            pt = ak_fn(k4_residue, kw, alph)
            qg = scorer.score_per_char(pt)
            frags = find_english(pt)
            free_crib = score_crib_free(pt)

            entry = {
                'keyword': kw, 'alphabet': alph_name, 'cipher': ak_name,
                'qg': round(qg, 4), 'ic': round(ic(pt), 6),
                'free_crib': free_crib, 'fragments': frags,
                'pt_preview': pt[:60], 'type': 'direct_residue_autokey',
            }
            best_results_a.append(entry)

            if qg > -6.0 or frags or free_crib >= 4:
                print(f"  {kw}:{alph_name}_{ak_name}: qg={qg:.3f}, free_crib={free_crib}")

# Also try with col7 transposition on the residue
print(f"\n--- With col7 transposition on residue ---")
kryptos_key = 'KRYPTOS'
indexed = [(ch, i) for i, ch in enumerate(kryptos_key)]
ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
col7_order = [0] * len(kryptos_key)
for rank, (_, pos) in enumerate(ranked):
    col7_order[pos] = rank

for kw in KEYWORDS[:5]:
    for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
        for cipher_name, cipher_fn in [('vig', vig_decrypt), ('beau', beau_decrypt)]:
            # Col7 then cipher
            transposed = columnar_decrypt(k4_residue, col7_order)
            pt = cipher_fn(transposed, kw, alph)
            qg = scorer.score_per_char(pt)
            frags = find_english(pt)
            free_crib = score_crib_free(pt)

            if qg > -6.0 or frags or free_crib >= 4:
                print(f"  col7+{kw}:{alph_name}_{cipher_name}: qg={qg:.3f}, free_crib={free_crib}")

best_results_a.sort(key=lambda x: x['qg'], reverse=True)
print(f"\nPart A: Top 5 results:")
for r in best_results_a[:5]:
    print(f"  {r['type']} {r['keyword']}:{r['alphabet']}_{r['cipher']}: qg={r['qg']:.3f}, free_crib={r['free_crib']}, ic={r['ic']:.4f}")
    print(f"    PT: {r['pt_preview']}")

results['parts']['A'] = {
    'total_ndyahr_in_grid': len(ndyahr_occurrences),
    'unique_positions_marked': len(marked_for_deletion),
    'k4_positions_marked': len(k4_marked),
    'k4_positions_remaining': len(k4_remaining_positions),
    'k4_marked_positions': k4_marked_positions,
    'k4_residue': k4_residue,
    'k4_residue_length': len(k4_residue),
    'is_73': len(k4_residue) == 73,
    'consensus_overlap': len(overlap_with_consensus),
    'consensus_overlap_positions': sorted(overlap_with_consensus),
    'marked_chars_in_palette': marked_in_palette,
    'top_results': best_results_a[:10],
}

# ══════════════════════════════════════════════════════════════════════════════
# PART A - Step 5: Apply ONLY to K4 region
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PART A - Step 5: NDYAHR neighbor deletion WITHIN K4 grid region")
print("=" * 80)

# Apply ONLY to NDYAHR letters that are IN the K4 region
k4_internal_marked = set()
k4_to_k3_marked = set()  # NDYAHR in K4 pointing UP into K3 territory

for k4_pos in range(97):
    ch = K4_CT[k4_pos]
    if ch not in NDYAHR_SET:
        continue

    gr, gc = k4_grid_positions[k4_pos]
    dr, dc = CORRECTED_DIRECTIONS[ch]
    target_r = gr + dr
    target_c = gc + dc
    target_pos = (target_r, target_c)

    # Check if target is in K4
    if target_pos in k4_grid_to_pos:
        k4_internal_marked.add(k4_grid_to_pos[target_pos])
    elif 0 <= target_r < len(FULL_ROWS) and 0 <= target_c < len(FULL_ROWS[target_r]):
        k4_to_k3_marked.add(target_pos)

k4_only_remaining = sorted(set(range(97)) - k4_internal_marked)
k4_only_residue = ''.join(K4_CT[i] for i in k4_only_remaining)

print(f"NDYAHR letters in K4 CT: {sum(1 for c in K4_CT if c in NDYAHR_SET)}")
print(f"K4-internal positions marked: {len(k4_internal_marked)}")
print(f"K4-internal marked positions: {sorted(k4_internal_marked)}")
print(f"K4-to-K3 targets (pointing above K4): {len(k4_to_k3_marked)}")
print(f"K4-to-K3 target positions: {sorted(k4_to_k3_marked)}")
print(f"\nK4 residue (internal only): {len(k4_only_residue)} chars")
print(f"Residue: {k4_only_residue}")

# Also: NDYAHR in K3 pointing DOWN into K4
k3_to_k4_marked = set()
k3_ct_text = K3_CT  # K3 starts at row 14
k3_grid_positions = []
# K3 starts at row 14, col 0 and runs through row 24, col 25 (before ?)
pos = 0
for r in range(14, 25):
    for c in range(31):
        if r == 24 and c >= 26:  # ? and then K4
            break
        if pos < len(K3_CT):
            k3_grid_positions.append((r, c))
            pos += 1

# Now also check K3 NDYAHR pointing into K4
for k3_idx, grid_pos in enumerate(k3_grid_positions):
    if k3_idx >= len(K3_CT):
        break
    ch = K3_CT[k3_idx]
    if ch not in NDYAHR_SET:
        continue

    gr, gc = grid_pos
    dr, dc = CORRECTED_DIRECTIONS[ch]
    target_r = gr + dr
    target_c = gc + dc
    target_pos = (target_r, target_c)

    if target_pos in k4_grid_to_pos:
        k3_to_k4_idx = k4_grid_to_pos[target_pos]
        k3_to_k4_marked.add(k3_to_k4_idx)

print(f"\nK3 NDYAHR letters pointing INTO K4: {len(k3_to_k4_marked)}")
print(f"K3->K4 marked positions: {sorted(k3_to_k4_marked)}")
if k3_to_k4_marked:
    print(f"K3->K4 marked chars: {''.join(K4_CT[i] for i in sorted(k3_to_k4_marked))}")

# Combined: all NDYAHR deletions that affect K4 (from K3, K4, and full grid)
combined_k4_marked = k4_internal_marked | k3_to_k4_marked
combined_remaining = sorted(set(range(97)) - combined_k4_marked)
combined_residue = ''.join(K4_CT[i] for i in combined_remaining)

print(f"\nCombined (K3+K4 NDYAHR -> K4 deletions): {len(combined_k4_marked)} positions")
print(f"Combined remaining: {len(combined_remaining)} chars")
print(f"Combined residue: {combined_residue}")
print(f"Is 73? {'YES!' if len(combined_residue) == 73 else 'No'}")
print(f"Overlap with consensus nulls: {len(combined_k4_marked & CONSENSUS_NULLS)}/{len(CONSENSUS_NULLS)}")

# ══════════════════════════════════════════════════════════════════════════════
# PART A - Step 5b: Broader view - which ROWS/COLS contribute
# ══════════════════════════════════════════════════════════════════════════════

print("\n--- Detailed NDYAHR source analysis for K4 deletions ---")

# Show which NDYAHR letters in the grid mark K4 positions
k4_deletion_sources = []
for occ in ndyahr_occurrences:
    target = occ['target']
    if target in k4_grid_to_pos:
        k4_idx = k4_grid_to_pos[target]
        k4_deletion_sources.append({
            'source_pos': occ['source'],
            'source_char': occ['source_char'],
            'target_pos': target,
            'target_k4_idx': k4_idx,
            'target_char': K4_CT[k4_idx],
        })

print(f"\nAll NDYAHR entries in grid pointing at K4 positions: {len(k4_deletion_sources)}")
for src in sorted(k4_deletion_sources, key=lambda x: x['target_k4_idx']):
    print(f"  K4[{src['target_k4_idx']:2d}]={src['target_char']} <- {src['source_char']}@({src['source_pos'][0]},{src['source_pos'][1]})")

results['parts']['A_k4_only'] = {
    'k4_internal_marked': len(k4_internal_marked),
    'k3_to_k4_marked': len(k3_to_k4_marked),
    'combined_marked': len(combined_k4_marked),
    'combined_remaining_length': len(combined_remaining),
    'combined_residue': combined_residue,
    'is_73_combined': len(combined_residue) == 73,
}

# ══════════════════════════════════════════════════════════════════════════════
# PART B: WHAT "LAYER TWO" REALLY MEANS
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PART B: WHAT 'LAYER TWO' REALLY MEANS")
print("=" * 80)

# First, show the full K2 plaintext context
print("\n--- K2 Plaintext (physical sculpture version) ---")
print(f"Length: {len(K2_PT_PHYSICAL)}")
# Show with word boundaries (X = delimiter)
segments = K2_PT_PHYSICAL.split('X')
for i, seg in enumerate(segments):
    print(f"  Segment {i}: {seg}")

print(f"\n--- K2 Plaintext (intended version) ---")
print(f"Length: {len(K2_PT_INTENDED)}")
segments = K2_PT_INTENDED.split('X')
for i, seg in enumerate(segments):
    print(f"  Segment {i}: {seg}")

print(f"\n--- K2 ending comparison ---")
print(f"Physical: ...{K2_PT_PHYSICAL[-40:]}")
print(f"Intended: ...{K2_PT_INTENDED[-40:]}")
print()
print("KEY OBSERVATION:")
print("  Physical copper decrypts to: ...WESTIDBYROWS")
print("  Sanborn's intended text:      ...WESTXLAYERTWO")
print("  'ID BY ROWS' vs 'LAYER TWO' are fundamentally different instructions")
print("  'ID BY ROWS' = identify by reading rows (transposition instruction)")
print("  'LAYER TWO'  = this is the second layer/level")
print()
print("  Scheidt: 'ID BY ROWS / LAYER TWO may not have been a mistake'")
print("  'In spycraft you deliberately do these things'")
print("  BOTH readings may be intentionally valid and meaningful")

# K3 PT context
print(f"\n--- K3 Plaintext ending ---")
print(f"K3 PT: ...{K3_PT[-60:]}")
print("  X CAN YOU SEE ANYTHING Q")
print("  The X delimiter + question = instruction to look further")

# ══════════════════════════════════════════════════════════════════════════════
# PART B - Test: Alternative K3 Transposition (NDYAHR-derived dimensions)
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PART B - Test: Alternative K3 transposition with NDYAHR-derived dimensions")
print("=" * 80)

# NDYAHR letter values (A=0):
# N=13, D=3, Y=24, A=0, H=7, R=17
# NDYAHR letter values (A=1):
# N=14, D=4, Y=25, A=1, H=8, R=18

# K3 CT = 336 chars. Factors of 336: 1,2,3,4,6,7,8,12,14,16,21,24,28,42,48,56,84,112,168,336
# NDYAHR values that are factors (A=0): D=3, H=7, Y=24
# K3 confirmed method: (24x14) then (8x42)

print(f"\nK3 CT length: {len(K3_CT)}")
print(f"Factors of 336: {[d for d in range(1, 337) if 336 % d == 0]}")
print(f"\nNDYAHR values (A=0): N=13, D=3, Y=24, A=0, H=7, R=17")
print(f"NDYAHR values that are factors of 336: D=3, H=7, Y=24")
print(f"\nK3 confirmed method: write 24-wide (14 rows), rotate CW, write 8-wide (42 rows), rotate CW")
print()

# Test single rotations with NDYAHR-derived widths
print("--- Single rotation with NDYAHR widths ---")
single_rotation_results = []

for width_name, width in [('D=3', 3), ('H=7', 7), ('Y=24', 24),
                           ('14', 14), ('8', 8), ('42', 42), ('48', 48), ('28', 28), ('21', 21),
                           ('16', 16), ('12', 12), ('6', 6), ('4', 4), ('2', 2),
                           ('56', 56), ('84', 84), ('112', 112), ('168', 168)]:
    if 336 % width != 0:
        continue

    pt = single_rotation_decrypt(K3_CT, width)
    if pt:
        qg = scorer.score_per_char(pt)
        frags = find_english(pt)
        pt_ic = ic(pt)

        entry = {
            'width': width, 'width_name': width_name,
            'qg': round(qg, 4), 'ic': round(pt_ic, 6),
            'fragments': frags, 'pt_preview': pt[:80],
        }
        single_rotation_results.append(entry)

        interesting = qg > -5.5 or len(frags) >= 2
        if interesting:
            print(f"  *** w={width} ({width_name}): qg={qg:.3f}, ic={pt_ic:.4f}, frags={frags}")
            print(f"      PT: {pt[:100]}")
        else:
            print(f"  w={width} ({width_name}): qg={qg:.3f}, ic={pt_ic:.4f}, frags={[f[0] for f in frags]}")

single_rotation_results.sort(key=lambda x: x['qg'], reverse=True)
print(f"\nBest single rotation: w={single_rotation_results[0]['width']} ({single_rotation_results[0]['width_name']}): qg={single_rotation_results[0]['qg']:.3f}")

# Test double rotations with NDYAHR-derived pairs
print("\n--- Double rotation with NDYAHR-derived width pairs ---")
double_rotation_results = []

# All factor pairs
factors = [d for d in range(2, 337) if 336 % d == 0]

# Focus on NDYAHR-meaningful factors + K3-relevant factors
priority_widths = [3, 7, 24, 8, 14, 42, 12, 16, 21, 28, 48, 56, 84]

for w1 in priority_widths:
    if 336 % w1 != 0:
        continue
    h1 = 336 // w1
    for w2 in priority_widths:
        if 336 % w2 != 0:
            continue
        h2 = 336 // w2

        # Skip the KNOWN K3 method (24,14 -> 8,42)
        if (w1 == 24 and w2 == 8):
            continue

        pt = double_rotation_decrypt(K3_CT, w1, h1, w2, h2)
        if pt and len(pt) >= 300:
            pt = pt[:336]
            qg = scorer.score_per_char(pt)
            frags = find_english(pt)
            pt_ic = ic(pt)

            entry = {
                'w1': w1, 'h1': h1, 'w2': w2, 'h2': h2,
                'qg': round(qg, 4), 'ic': round(pt_ic, 6),
                'fragments': frags, 'pt_preview': pt[:80],
            }
            double_rotation_results.append(entry)

            interesting = qg > -5.0 or len(frags) >= 3
            if interesting:
                print(f"  *** ({w1}x{h1} -> {w2}x{h2}): qg={qg:.3f}, ic={pt_ic:.4f}, frags={frags}")
                print(f"      PT: {pt[:100]}")

double_rotation_results.sort(key=lambda x: x['qg'], reverse=True)
if double_rotation_results:
    print(f"\nBest double rotation:")
    for r in double_rotation_results[:5]:
        print(f"  ({r['w1']}x{r['h1']} -> {r['w2']}x{r['h2']}): qg={r['qg']:.3f}, ic={r['ic']:.4f}")
        if r['fragments']:
            print(f"    Fragments: {r['fragments'][:5]}")
        print(f"    PT: {r['pt_preview'][:80]}")

# ══════════════════════════════════════════════════════════════════════════════
# PART B - Test: Columnar transposition of K3 CT with various widths
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PART B - Test: Columnar transposition of K3 CT")
print("=" * 80)

columnar_results = []

# Try widths derived from NDYAHR and other meaningful values
for width in [3, 7, 24, 8, 14, 42, 12, 16, 21, 28, 31, 48]:
    # Identity column order (just read columns sequentially)
    identity_order = list(range(width))
    pt = columnar_decrypt(K3_CT, identity_order)
    qg = scorer.score_per_char(pt)
    frags = find_english(pt)
    pt_ic = ic(pt)

    entry = {
        'width': width, 'key': 'identity',
        'qg': round(qg, 4), 'ic': round(pt_ic, 6),
        'fragments': frags, 'pt_preview': pt[:80],
    }
    columnar_results.append(entry)

    interesting = qg > -5.5 or len(frags) >= 2
    if interesting:
        print(f"  *** col{width}(identity): qg={qg:.3f}, ic={pt_ic:.4f}, frags={frags}")
        print(f"      PT: {pt[:100]}")
    else:
        print(f"  col{width}(identity): qg={qg:.3f}, ic={pt_ic:.4f}, frags={[f[0] for f in frags]}")

    # For width 7, also try KRYPTOS key order
    if width == 7:
        pt = columnar_decrypt(K3_CT, col7_order)
        qg = scorer.score_per_char(pt)
        frags = find_english(pt)
        pt_ic = ic(pt)

        entry = {
            'width': 7, 'key': 'KRYPTOS',
            'qg': round(qg, 4), 'ic': round(pt_ic, 6),
            'fragments': frags, 'pt_preview': pt[:80],
        }
        columnar_results.append(entry)

        interesting = qg > -5.5 or len(frags) >= 2
        if interesting:
            print(f"  *** col7(KRYPTOS): qg={qg:.3f}, ic={pt_ic:.4f}, frags={frags}")
            print(f"      PT: {pt[:100]}")
        else:
            print(f"  col7(KRYPTOS): qg={qg:.3f}, ic={pt_ic:.4f}, frags={[f[0] for f in frags]}")

columnar_results.sort(key=lambda x: x['qg'], reverse=True)
print(f"\nBest columnar:")
for r in columnar_results[:3]:
    print(f"  col{r['width']}({r['key']}): qg={r['qg']:.3f}")

# ══════════════════════════════════════════════════════════════════════════════
# PART B - Test: Rail fence with various depths
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PART B - Test: Rail fence cipher on K3 CT")
print("=" * 80)

def rail_fence_decrypt(ct, rails):
    """Decrypt rail fence cipher."""
    n = len(ct)
    if rails < 2 or rails >= n:
        return ct

    # Calculate the length of each rail
    cycle = 2 * (rails - 1)
    rail_lengths = [0] * rails
    for i in range(n):
        pos_in_cycle = i % cycle
        rail = pos_in_cycle if pos_in_cycle < rails else cycle - pos_in_cycle
        rail_lengths[rail] += 1

    # Split CT into rails
    rail_texts = []
    pos = 0
    for r in range(rails):
        rail_texts.append(ct[pos:pos + rail_lengths[r]])
        pos += rail_lengths[r]

    # Read off in zig-zag order
    rail_indices = [0] * rails
    result = []
    for i in range(n):
        pos_in_cycle = i % cycle
        rail = pos_in_cycle if pos_in_cycle < rails else cycle - pos_in_cycle
        result.append(rail_texts[rail][rail_indices[rail]])
        rail_indices[rail] += 1

    return ''.join(result)

rail_results = []
for depth in [3, 7, 24, 8, 14, 4, 5, 6, 12, 13, 17]:
    pt = rail_fence_decrypt(K3_CT, depth)
    qg = scorer.score_per_char(pt)
    frags = find_english(pt)
    pt_ic = ic(pt)

    entry = {
        'depth': depth, 'qg': round(qg, 4), 'ic': round(pt_ic, 6),
        'fragments': frags, 'pt_preview': pt[:80],
    }
    rail_results.append(entry)

    interesting = qg > -5.5 or len(frags) >= 2
    if interesting:
        print(f"  *** rail{depth}: qg={qg:.3f}, ic={pt_ic:.4f}, frags={frags}")
        print(f"      PT: {pt[:100]}")
    else:
        print(f"  rail{depth}: qg={qg:.3f}, ic={pt_ic:.4f}, frags={[f[0] for f in frags]}")

rail_results.sort(key=lambda x: x['qg'], reverse=True)

# ══════════════════════════════════════════════════════════════════════════════
# PART B - Test: Diagonal reading on grids
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PART B - Test: Diagonal reading patterns on K3 CT")
print("=" * 80)

def diagonal_read(text, width, direction='down_right'):
    """Read text written in a grid of given width along diagonals."""
    n = len(text)
    height = math.ceil(n / width)

    # Build grid
    grid = {}
    for i, c in enumerate(text):
        r = i // width
        c_idx = i % width
        grid[(r, c_idx)] = c

    result = []
    if direction == 'down_right':
        # Read diagonals from top-left to bottom-right
        for start_col in range(width):
            r, c = 0, start_col
            while r < height and c < width:
                if (r, c) in grid:
                    result.append(grid[(r, c)])
                r += 1
                c += 1
        for start_row in range(1, height):
            r, c = start_row, 0
            while r < height and c < width:
                if (r, c) in grid:
                    result.append(grid[(r, c)])
                r += 1
                c += 1
    elif direction == 'down_left':
        for start_col in range(width - 1, -1, -1):
            r, c = 0, start_col
            while r < height and c >= 0:
                if (r, c) in grid:
                    result.append(grid[(r, c)])
                r += 1
                c -= 1
        for start_row in range(1, height):
            r, c = start_row, width - 1
            while r < height and c >= 0:
                if (r, c) in grid:
                    result.append(grid[(r, c)])
                r += 1
                c -= 1
    elif direction == 'spiral':
        top, bottom, left, right = 0, height - 1, 0, width - 1
        while top <= bottom and left <= right:
            for c in range(left, right + 1):
                if (top, c) in grid:
                    result.append(grid[(top, c)])
            top += 1
            for r in range(top, bottom + 1):
                if (r, right) in grid:
                    result.append(grid[(r, right)])
            right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    if (bottom, c) in grid:
                        result.append(grid[(bottom, c)])
                bottom -= 1
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    if (r, left) in grid:
                        result.append(grid[(r, left)])
                left += 1

    return ''.join(result)

diag_results = []
for width in [3, 7, 24, 8, 14, 42, 12, 21, 28, 31]:
    for direction in ['down_right', 'down_left', 'spiral']:
        pt = diagonal_read(K3_CT, width, direction)
        if len(pt) < 200:
            continue
        qg = scorer.score_per_char(pt)
        frags = find_english(pt)
        pt_ic = ic(pt)

        entry = {
            'width': width, 'direction': direction,
            'qg': round(qg, 4), 'ic': round(pt_ic, 6),
            'fragments': frags,
        }
        diag_results.append(entry)

        interesting = qg > -5.5 or len(frags) >= 3
        if interesting:
            print(f"  *** diag w={width} {direction}: qg={qg:.3f}, ic={pt_ic:.4f}, frags={frags}")
            print(f"      PT: {pt[:100]}")

diag_results.sort(key=lambda x: x['qg'], reverse=True)
if diag_results:
    print(f"\nBest diagonal: w={diag_results[0]['width']} {diag_results[0]['direction']}: qg={diag_results[0]['qg']:.3f}")

# ══════════════════════════════════════════════════════════════════════════════
# PART B - Test: Specific NDYAHR double-rotation pairs
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PART B - Test: NDYAHR-specific double rotation pairs")
print("=" * 80)

# Specific pairs from the user's hypothesis:
# (3, 7), (7, 3), (24, 7), (7, 24), (3, 24), (24, 3)
ndyahr_pairs = [
    (3, 7), (7, 3), (24, 7), (7, 24), (3, 24), (24, 3),
    (3, 3), (7, 7), (24, 24),
    (8, 7), (7, 8), (8, 3), (3, 8),
    (8, 24), (24, 8),  # original K3 method reversed
    (14, 7), (7, 14), (14, 3), (3, 14),
    (14, 24), (24, 14),  # original K3 method!!
    (42, 8), (8, 42),  # original K3 method
    (42, 7), (7, 42), (42, 3), (3, 42),
    (21, 7), (7, 21), (21, 3), (3, 21),
    (21, 24), (24, 21), (21, 8), (8, 21),
    (28, 7), (7, 28), (28, 3), (3, 28),
    (12, 7), (7, 12), (12, 3), (3, 12),
    (16, 7), (7, 16), (16, 3), (3, 16),
    (48, 7), (7, 48),
]

# Deduplicate
seen = set()
unique_pairs = []
for p in ndyahr_pairs:
    if p not in seen:
        seen.add(p)
        unique_pairs.append(p)

ndyahr_double_results = []
for w1, w2 in unique_pairs:
    if 336 % w1 != 0 or 336 % w2 != 0:
        continue
    h1 = 336 // w1
    h2 = 336 // w2

    pt = double_rotation_decrypt(K3_CT, w1, h1, w2, h2)
    if pt and len(pt) >= 300:
        pt = pt[:336]
        qg = scorer.score_per_char(pt)
        frags = find_english(pt)
        pt_ic = ic(pt)

        # Check if this is the known K3 solution
        is_known = (pt[:30] == K3_PT[:30])

        entry = {
            'w1': w1, 'h1': h1, 'w2': w2, 'h2': h2,
            'qg': round(qg, 4), 'ic': round(pt_ic, 6),
            'fragments': frags, 'pt_preview': pt[:100],
            'is_known_solution': is_known,
        }
        ndyahr_double_results.append(entry)

        if is_known:
            print(f"  *** KNOWN K3 SOLUTION: ({w1}x{h1} -> {w2}x{h2}): qg={qg:.3f}")
        elif qg > -4.5 or len(frags) >= 4:
            print(f"  *** ({w1}x{h1} -> {w2}x{h2}): qg={qg:.3f}, ic={pt_ic:.4f}, frags={frags}")
            print(f"      PT: {pt[:120]}")
        elif qg > -5.5 or len(frags) >= 2:
            print(f"  ({w1}x{h1} -> {w2}x{h2}): qg={qg:.3f}, ic={pt_ic:.4f}, frags={[f[0] for f in frags]}")

ndyahr_double_results.sort(key=lambda x: x['qg'], reverse=True)
print(f"\nTop 10 NDYAHR double rotations:")
for r in ndyahr_double_results[:10]:
    marker = " *** KNOWN" if r.get('is_known_solution') else ""
    print(f"  ({r['w1']}x{r['h1']} -> {r['w2']}x{r['h2']}): qg={r['qg']:.3f}, ic={r['ic']:.4f}{marker}")
    if r['fragments']:
        print(f"    Fragments: {[f[0] for f in r['fragments'][:5]]}")
    print(f"    PT: {r['pt_preview'][:80]}")

# ══════════════════════════════════════════════════════════════════════════════
# PART B - Comprehensive: All factor-pair double rotations
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PART B - Comprehensive: ALL factor-pair double rotations for K3 CT")
print("=" * 80)

all_factors = [d for d in range(2, 337) if 336 % d == 0]
all_double_results = []
known_count = 0

for w1 in all_factors:
    h1 = 336 // w1
    for w2 in all_factors:
        h2 = 336 // w2

        pt = double_rotation_decrypt(K3_CT, w1, h1, w2, h2)
        if pt and len(pt) >= 300:
            pt = pt[:336]
            qg = scorer.score_per_char(pt)

            is_known = (pt[:50] == K3_PT[:50])
            if is_known:
                known_count += 1

            entry = {
                'w1': w1, 'h1': h1, 'w2': w2, 'h2': h2,
                'qg': round(qg, 4),
                'is_known': is_known,
                'pt_start': pt[:40],
            }
            all_double_results.append(entry)

all_double_results.sort(key=lambda x: x['qg'], reverse=True)

print(f"Total factor-pair double rotations tested: {len(all_double_results)}")
print(f"Factor pairs that reproduce KNOWN K3 plaintext: {known_count}")
print(f"\nAll pairs reproducing known K3 PT:")
for r in all_double_results:
    if r['is_known']:
        print(f"  ({r['w1']}x{r['h1']} -> {r['w2']}x{r['h2']}): qg={r['qg']:.3f}")

print(f"\nTop 20 by quadgram score (excluding known solution):")
shown = 0
for r in all_double_results:
    if r['is_known']:
        continue
    frags_check = find_english(r['pt_start'])
    print(f"  ({r['w1']}x{r['h1']} -> {r['w2']}x{r['h2']}): qg={r['qg']:.3f} {'FRAGS: ' + str(frags_check) if frags_check else ''}")
    print(f"    PT: {r['pt_start']}")
    shown += 1
    if shown >= 20:
        break

# ══════════════════════════════════════════════════════════════════════════════
# PART B - ID BY ROWS interpretation
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PART B - 'ID BY ROWS' interpretation")
print("=" * 80)

print("\n'ID BY ROWS' on the physical sculpture could mean:")
print("  1. Identify (the message) by reading rows (of a grid)")
print("  2. The method involves row-based reading/identification")
print("  3. An acronym or coded instruction")
print()

# Test: Read K4 CT in a grid and pick every Nth row
print("--- Reading K4 by rows of various widths ---")
for width in [7, 8, 13, 14, 24, 31, 97]:
    height = math.ceil(97 / width)
    rows = []
    for r in range(height):
        row_text = K4_CT[r*width:(r+1)*width]
        rows.append(row_text)

    print(f"\n  Width {width} ({height} rows):")
    for i, row in enumerate(rows):
        print(f"    Row {i}: {row}")

# Test: Read K3 CT row-by-row on different widths and check for English
print("\n--- 'ID BY ROWS' applied to K3: read CT in grid, take specific rows ---")
for width in [7, 24, 31]:
    height = math.ceil(len(K3_CT) / width)
    rows = []
    for r in range(height):
        row_text = K3_CT[r*width:(r+1)*width]
        rows.append(row_text)

    # Try reading alternate rows
    alt_rows = ''.join(rows[i] for i in range(0, len(rows), 2))
    qg = scorer.score_per_char(alt_rows)
    print(f"  Width {width}: alternate rows ({len(alt_rows)} chars): qg={qg:.3f}")

    # Try reading every 3rd row
    if len(rows) >= 3:
        third_rows = ''.join(rows[i] for i in range(0, len(rows), 3))
        qg = scorer.score_per_char(third_rows)
        print(f"  Width {width}: every 3rd row ({len(third_rows)} chars): qg={qg:.3f}")

# ══════════════════════════════════════════════════════════════════════════════
# PART B - LAYER TWO: Try Vig/Beau on K3 CT (substitution as second layer)
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PART B - LAYER TWO: substitution cipher on K3 CT")
print("=" * 80)
print("If 'Layer Two' means K3 has TWO layers (transposition + substitution),")
print("then applying substitution to K3 CT should reveal a different message.")
print("K3 PT was found by transposition alone => if there's a sub layer,")
print("it would mean the known PT has a sub layer ON TOP of it.")
print()

# The hypothesis: K3 is (PT -> sub -> intermediate -> transposition -> CT)
# Known decryption: CT -> inverse_transposition -> K3_PT
# If there's a sub layer: CT -> inverse_transposition -> intermediate -> inverse_sub -> REAL_PT
# This means K3_PT IS the intermediate (already computed)
# So: K3_PT -> inverse_sub -> REAL_PT
# Try Vig/Beau on K3_PT with various keywords

print("--- Substitution decryption of K3 PT (= trans(CT)) ---")
k3pt_sub_results = []

for kw in KEYWORDS + ['LAYERTWO', 'IDBYROWS']:
    for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
        for cipher_name, cipher_fn in [('vig', vig_decrypt), ('beau', beau_decrypt), ('vbeau', vbeau_decrypt)]:
            pt = cipher_fn(K3_PT, kw, alph)
            qg = scorer.score_per_char(pt)
            frags = find_english(pt)
            pt_ic = ic(pt)

            entry = {
                'keyword': kw, 'alphabet': alph_name, 'cipher': cipher_name,
                'qg': round(qg, 4), 'ic': round(pt_ic, 6),
                'fragments': frags, 'pt_preview': pt[:80],
            }
            k3pt_sub_results.append(entry)

            if qg > -5.0 or len(frags) >= 3:
                print(f"  *** {kw}:{alph_name}_{cipher_name}: qg={qg:.3f}, ic={pt_ic:.4f}, frags={frags}")
                print(f"      PT: {pt[:100]}")

# Also try autokey on K3 PT
for kw in KEYWORDS[:5] + ['LAYERTWO', 'IDBYROWS']:
    for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
        pt = autokey_pt_decrypt(K3_PT, kw, alph)
        qg = scorer.score_per_char(pt)
        frags = find_english(pt)

        entry = {
            'keyword': kw, 'alphabet': alph_name, 'cipher': 'ptautokey',
            'qg': round(qg, 4), 'ic': round(ic(pt), 6),
            'fragments': frags, 'pt_preview': pt[:80],
        }
        k3pt_sub_results.append(entry)

        if qg > -5.0 or len(frags) >= 3:
            print(f"  *** {kw}:{alph_name}_ptautokey: qg={qg:.3f}, frags={frags}")
            print(f"      PT: {pt[:100]}")

k3pt_sub_results.sort(key=lambda x: x['qg'], reverse=True)
print(f"\nTop 10 substitution on K3 PT:")
for r in k3pt_sub_results[:10]:
    print(f"  {r['keyword']}:{r['alphabet']}_{r['cipher']}: qg={r['qg']:.3f}, ic={r['ic']:.4f}")
    if r['fragments']:
        print(f"    Fragments: {r['fragments']}")
    print(f"    PT: {r['pt_preview'][:60]}")

# ══════════════════════════════════════════════════════════════════════════════
# PART B - Running key test: K1/K2 PT as key for K3 PT
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PART B - Running key: K1/K2 PT as key for Vig/Beau on K3 PT")
print("=" * 80)

running_key_texts = {
    'K1_PT': K1_PT,
    'K2_PT_phys': K2_PT_PHYSICAL,
    'K2_PT_intended': K2_PT_INTENDED,
    'K1+K2_phys': K1_PT + K2_PT_PHYSICAL,
    'K1+K2_intended': K1_PT + K2_PT_INTENDED,
}

rk_results = []
for rk_name, rk_text in running_key_texts.items():
    # Pad or truncate
    key = rk_text
    while len(key) < len(K3_PT):
        key += rk_text
    key = key[:len(K3_PT)]

    for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
        for cipher_name, cipher_fn in [('vig', vig_decrypt), ('beau', beau_decrypt)]:
            pt = cipher_fn(K3_PT, key, alph)
            qg = scorer.score_per_char(pt)
            frags = find_english(pt)
            pt_ic = ic(pt)

            entry = {
                'running_key': rk_name, 'alphabet': alph_name, 'cipher': cipher_name,
                'qg': round(qg, 4), 'ic': round(pt_ic, 6),
                'fragments': frags, 'pt_preview': pt[:80],
            }
            rk_results.append(entry)

            if qg > -5.5 or len(frags) >= 2:
                print(f"  *** {rk_name}:{alph_name}_{cipher_name}: qg={qg:.3f}, ic={pt_ic:.4f}")
                print(f"      PT: {pt[:100]}")
            else:
                print(f"  {rk_name}:{alph_name}_{cipher_name}: qg={qg:.3f}")

rk_results.sort(key=lambda x: x['qg'], reverse=True)

# ══════════════════════════════════════════════════════════════════════════════
# PART B - Test: Does different transposition + same keyword yield new PT?
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("PART B - Alternative: NDYAHR as transposition on K3 CT, then check sub")
print("=" * 80)

print("If LAYER TWO means a different READING ORDER of the same K3 CT grid,")
print("then the same CT read differently gives different PT.")
print("Testing all single-rotation widths for K3 CT quality...")

# We already tested single rotation above. Now let's check if any
# single-rotation output of K3 CT produces English when further decrypted with a keyword

sr_sub_results = []
for width in all_factors:
    if width < 3 or width > 200:
        continue
    pt_trans = single_rotation_decrypt(K3_CT, width)
    if not pt_trans or len(pt_trans) < 300:
        continue
    pt_trans = pt_trans[:336]

    # Now try Vig/Beau with KRYPTOS, DEFECTOR, LAYERTWO on the transposed text
    for kw in ['KRYPTOS', 'DEFECTOR', 'LAYERTWO', 'IDBYROWS', 'PALIMPSEST', 'ABSCISSA']:
        for alph_name, alph in [('AZ', ALPH), ('KA', KRYPTOS_ALPHABET)]:
            for cipher_name, cipher_fn in [('vig', vig_decrypt), ('beau', beau_decrypt)]:
                pt = cipher_fn(pt_trans, kw, alph)
                qg = scorer.score_per_char(pt)
                frags = find_english(pt)

                if qg > -4.5 or len(frags) >= 4:
                    print(f"  *** rot({width}) + {kw}:{alph_name}_{cipher_name}: qg={qg:.3f}, frags={frags}")
                    print(f"      PT: {pt[:100]}")
                    sr_sub_results.append({
                        'width': width, 'keyword': kw, 'alphabet': alph_name,
                        'cipher': cipher_name, 'qg': round(qg, 4),
                        'fragments': frags, 'pt_preview': pt[:80],
                    })

if sr_sub_results:
    sr_sub_results.sort(key=lambda x: x['qg'], reverse=True)
    print(f"\nTop rotation+sub results:")
    for r in sr_sub_results[:5]:
        print(f"  rot({r['width']}) + {r['keyword']}:{r['alphabet']}_{r['cipher']}: qg={r['qg']:.3f}")
else:
    print("\nNo rotation+sub results above threshold.")

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

print("\n" + "=" * 80)
print("COMPREHENSIVE SUMMARY")
print("=" * 80)

print(f"""
=== PART A: NDYAHR NEIGHBOR DELETION (CORRECTED DIRECTIONS) ===

Grid: 28x31 = {total_chars} characters
Total NDYAHR occurrences in grid: {len(ndyahr_occurrences)}
Unique positions marked for deletion: {len(marked_for_deletion)}

K4 Region:
  K4 positions marked (from full grid NDYAHR): {len(k4_marked)} / 97
  K4 positions remaining: {len(k4_remaining_positions)}
  Is remaining 73? {'YES!' if len(k4_remaining_positions) == 73 else 'NO (' + str(len(k4_remaining_positions)) + ')'}

  Overlap with consensus nulls ({len(CONSENSUS_NULLS)} positions):
    Overlap: {len(overlap_with_consensus)} / {len(CONSENSUS_NULLS)}
    In consensus but NOT marked: {len(consensus_not_marked)}
    Marked but NOT consensus: {len(marked_not_consensus)}

  Marked chars in palette {{B,G,I,K,O,W,Z}}: {marked_in_palette}/{len(k4_marked_chars)}

  K4-internal NDYAHR marks: {len(k4_internal_marked)}
  K3->K4 NDYAHR marks: {len(k3_to_k4_marked)}
  Combined: {len(combined_k4_marked)} positions

  K4 residue: {k4_residue}

  Best decryption attempt: {best_results_a[0]['keyword']}:{best_results_a[0]['alphabet']}_{best_results_a[0]['cipher']}
    qg={best_results_a[0]['qg']:.3f}, free_crib={best_results_a[0]['free_crib']}

=== PART B: WHAT 'LAYER TWO' REALLY MEANS ===

K2 Physical ending: ...WESTIDBYROWS  (= 'identify by rows')
K2 Intended ending: ...WESTXLAYERTWO (= 'layer two')

K3 confirmed method: double rotation (24x14 -> 8x42) = pure transposition
  - Self-inverting with specific dimensions

Alternative double rotations that reproduce K3 PT: {known_count} factor pairs
  (The known method has MULTIPLE equivalent parameterizations)

Best NON-KNOWN double rotation: ({all_double_results[0]['w1']}x{all_double_results[0]['h1']} -> {all_double_results[0]['w2']}x{all_double_results[0]['h2']}): qg={all_double_results[0]['qg']:.3f}
  {'*** THIS IS THE KNOWN SOLUTION ***' if all_double_results[0]['is_known'] else '(different from known solution)'}

Substitution on K3 PT (testing 'layer two' = sub on top of transposition):
  Best: {k3pt_sub_results[0]['keyword']}:{k3pt_sub_results[0]['alphabet']}_{k3pt_sub_results[0]['cipher']}: qg={k3pt_sub_results[0]['qg']:.3f}
  (English threshold ~-4.0; random ~-6.8)

Running key (K1/K2 PT as key for K3 PT):
  Best: {rk_results[0]['running_key']}:{rk_results[0]['alphabet']}_{rk_results[0]['cipher']}: qg={rk_results[0]['qg']:.3f}
""")

# Save results
results['parts']['B'] = {
    'single_rotation_top5': single_rotation_results[:5] if single_rotation_results else [],
    'double_rotation_known_count': known_count,
    'double_rotation_top5': [r for r in all_double_results[:5]],
    'ndyahr_double_top5': ndyahr_double_results[:5] if ndyahr_double_results else [],
    'k3pt_sub_top5': k3pt_sub_results[:5],
    'running_key_top5': rk_results[:5],
    'columnar_top5': columnar_results[:5],
}

results_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'results')
os.makedirs(results_dir, exist_ok=True)
results_file = os.path.join(results_dir, 'ndyahr_neighbor_deletion_layer_two.json')
with open(results_file, 'w') as f:
    json.dump(results, f, indent=2, default=str)
print(f"\nResults saved to: {results_file}")
