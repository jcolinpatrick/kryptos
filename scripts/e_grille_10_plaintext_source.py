#!/usr/bin/env python3
"""E-GRILLE-10: Cardan Grille Applied to K1+K2+K3 Plaintext.

NOVEL APPROACH: Tests the hypothesis that the physical Cardan grille was
designed to extract running key from the K1+K2+K3 PLAINTEXT (the actual
English language content), not from the KA tableau.

MOTIVATION:
- Scheidt (WIRED 2005): "I masked the English language... solve the technique
  first then the puzzle." The "English language" being masked is most naturally
  K1-K3 PT — the English text embedded IN Kryptos itself.
- e_grille_02 applied the grille to the KA tableau -> NOISE (direct running key)
- e_grille_04 (YAR model) applied K1-K3 CT as the hole-maker over the KA tableau
  -> found T structurally impossible, T-absence fully explained
- This script applies the PHYSICAL GRILLE MASK (VISIBLE_CELLS from photo) to the
  K1+K2+K3 PLAINTEXT arranged in the same 28×33 grid layout.
- This tests the "two-step model": (1) grille extracts from English PT, (2) that
  extract is used as running key to encrypt something (perhaps K4 itself).

APPROACH:
1. Arrange K1+K2+K3 PT (768 alpha chars) in the 28×33 grid:
   - Multiple alignment options: top-left (standard), offset start, sections only
2. Apply VISIBLE_CELLS physical grille mask -> extract letters
3. Use extracted sequence as running key for K4 (Vig/Beau/VarBeau, all offsets)
4. Check EAST constraint filter on each candidate
5. Score with quadgrams and report top results

Also tests:
- K3 PT only (physically closest section to K4 on the sculpture)
- K1+K2+K3 PT reversed (grille may be read in reverse)
- K4 CT as source (autoclave / Alberti-style)
- K1+K2+K3 CT (the raw cipher text under the grille)

Usage: PYTHONPATH=src python3 -u scripts/e_grille_10_plaintext_source.py
"""
from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# ── Constants ────────────────────────────────────────────────────────────────

EXPERIMENT_ID = "E-GRILLE-10"

CT_K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(CT_K4) == 97

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

# Physical grille: 107 holes (106 with alpha letters, 1 out-of-bounds)
# Source: grille_verify.py — coordinates (col, row) 1-based
VISIBLE_CELLS = [
    (9,1), (11,1), (13,1), (23,1), (33,1),
    (1,2), (11,2), (17,2), (21,2), (26,2), (27,2), (32,2), (33,2),
    (15,3), (32,3), (33,3),
    (21,4), (28,4), (31,4), (32,4), (33,4),
    (8,5), (17,5), (22,5), (31,5), (32,5), (33,5),
    (9,6), (31,6), (32,6), (33,6),
    (1,7), (32,7), (33,7),
    (24,8), (30,8), (32,8), (33,8),
    (20,9), (28,9), (33,9),
    (29,10), (32,10), (33,10),
    (9,11), (31,11), (32,11), (33,11),
    (6,12), (7,12), (30,12), (32,12), (33,12),
    (15,13), (18,13), (19,13), (32,13), (33,13),
    (12,14), (28,14), (33,14),
    (4,15), (5,15), (7,15), (13,15), (26,15), (30,15), (32,15), (33,15),
    (5,16), (7,16), (25,16), (31,16), (32,16), (33,16),
    (3,17), (6,17), (11,17), (12,17), (13,17), (28,17), (30,17), (32,17), (33,17),
    (12,18), (13,18), (22,18), (27,18), (31,18), (32,18), (33,18),
    (14,19), (18,19), (21,19), (29,19), (30,19), (31,19), (32,19), (33,19),
    (17,20), (20,20), (29,20), (30,20), (32,20), (33,20),
    (9,21), (10,21), (17,21), (19,21), (21,21), (25,21), (28,21), (31,21), (32,21), (33,21),
    (16,22), (21,22), (23,22), (25,22), (27,22), (32,22), (33,22),
    (8,23), (9,23), (21,23), (26,23), (27,23), (32,23), (33,23),
    (1,24), (21,24), (26,24), (27,24), (31,24), (33,24),
    (1,25), (8,25), (13,25), (14,25), (20,25), (30,25), (31,25), (32,25), (33,25),
    (5,26), (20,26), (25,26), (32,26), (33,26),
    (20,27), (25,27), (32,27), (33,27),
    (15,28), (23,28), (25,28), (29,28), (30,28), (31,28), (32,28), (33,28),
]

GRID_ROWS = 28
GRID_COLS = 33

# Known plaintext sections (alpha only, spaces removed)
# K1 PT (63 chars in cipher, ~62 alpha after removing XQUESTIONMARK etc.)
K1_PT_RAW = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
# K2 PT (369 chars in cipher)
K2_PT_RAW = ("ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDX"
             "THEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
             "DOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIED"
             "OUTSOMEWHEREXWHKNOWSTHEEXACTLOCATIONONLYWW"
             "THISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESF"
             "IFTYSEVENSMINUTESSIXPOINTFIVESECONDSNORTHX"
             "SEVENTYSEVENDEGREESSEIGHTMINUTESFORTYFOURSECREETSWESTXLAYERTWO")
# K3 PT (336 chars)
K3_PT_RAW = ("SLOWLYDESPERATELSLOWLYTHEREMAINSOFORPASSAGEDEBRISTHATENCUMBEREDX"
             "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIAMADEATINY"
             "BREACHINTHENTUPPERLEFTHANDCORNERANDTHENWIDENEINGTHEHOLEALITTLE"
             "IINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER"
             "CAUSEDTHEFLAMETTOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIN"
             "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ")

# Use precise known plaintexts (alpha only, uppercase)
# These are the accepted corrected plaintexts
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = ("ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELD"
         "XTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGROUNDTOANUNKNOWNLOCATION"
         "XDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIED"
         "OUTSOMEWHEREXWHKNOWSTHEEXACTLOCATIONONLYWW"
         "THISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREES"
         "FIFTYSEVEMINUTESSIXPOINTFIVESECONDSNORTH"
         "SEVENTYSEVENDEGREESSEIGHTMINUTESFORTYFOUR"
         "SECONDSWESTXLAYERTWO")
K3_PT = ("SLOWLYDESPERATELSLOWLYTHEREMAINSOFREPASSAGEDEBRISTHATENCUMBERED"
         "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIAMADEATINY"
         "BREACHINTHENTUPPERLEFTHANDCORNERANDTHENWIDENINTHEHOLEALITTLE"
         "IINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER"
         "CAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIN"
         "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ")

# Clean to alpha only
def alpha_only(s: str) -> str:
    return "".join(c for c in s.upper() if c.isalpha())

K1_ALPHA = alpha_only(K1_PT)
K2_ALPHA = alpha_only(K2_PT)
K3_ALPHA = alpha_only(K3_PT)
K123_ALPHA = K1_ALPHA + K2_ALPHA + K3_ALPHA

# K1+K2+K3 ciphertext (for autoclave variant)
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ"
K2_CT = ("YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
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
         "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG")
K3_CT = ("ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA"
         "CHTNREYULDSLLSLLNOHSNOSMRWXMNE"
         "TPRNGATIHNRARPESLNNELEBLPIIACAE"
         "WMTWNDITEENRAHCTENEUDRETNHAEOE"
         "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR"
         "EIFTBRSPAMHHEWENATAMATEGYEERLB"
         "TEEFOASFIOTUETUAEOTOARMAEERTNRTI"
         "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
         "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT"
         "RKLMLEHAGTDHARDPNEOHMGFMFEUHE"
         "ECDMRIPFEIMEHNLSSTTRTVDOHWOBKR")
K123_CT = alpha_only(K1_CT + K2_CT + K3_CT)

# ── Known keystream at crib positions (Vigenère) ──────────────────────────────

CRIB_KEYS_VIG: Dict[int, int] = {
    21: 1, 22: 11, 23: 25, 24: 2, 25: 3, 26: 2, 27: 24, 28: 24,
    29: 6, 30: 2, 31: 10, 32: 0, 33: 25,
    63: 12, 64: 20, 65: 24, 66: 10, 67: 11, 68: 6, 69: 10, 70: 14, 71: 17, 72: 13, 73: 0,
}
CRIB_KEYS_BEAU: Dict[int, int] = {
    21: 9, 22: 11, 23: 9, 24: 14, 25: 3, 26: 4, 27: 6, 28: 10, 29: 20,
    30: 10, 31: 10, 32: 10, 33: 11,
    63: 14, 64: 2, 65: 6, 66: 6, 67: 1, 68: 6, 69: 14, 70: 10, 71: 19,
    72: 17, 73: 20,
}

# EAST constraint: diffs [1, 25, 1, 23] (variant-independent)
# k[22]-k[21], k[23]-k[22], k[24]-k[23], k[25]-k[24] in AZ mod 26
EAST_DIFFS_VIG = [
    (CRIB_KEYS_VIG[22] - CRIB_KEYS_VIG[21]) % 26,
    (CRIB_KEYS_VIG[23] - CRIB_KEYS_VIG[22]) % 26,
    (CRIB_KEYS_VIG[24] - CRIB_KEYS_VIG[23]) % 26,
    (CRIB_KEYS_VIG[25] - CRIB_KEYS_VIG[24]) % 26,
]

# ── Load scoring data ─────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

QUADGRAMS: Dict[str, float] = {}
qg_path = os.path.join(PROJECT_DIR, "data", "english_quadgrams.json")
if os.path.exists(qg_path):
    with open(qg_path) as f:
        QUADGRAMS = json.load(f)

def quadgram_score(text: str) -> float:
    if not QUADGRAMS or len(text) < 4:
        return -999.0
    floor = -10.0
    score, n = 0.0, 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        if qg.isalpha():
            score += QUADGRAMS.get(qg, floor)
            n += 1
    return score / max(1, n)

# ── Grid operations ──────────────────────────────────────────────────────────

def text_to_grid(text: str, rows: int = 28, cols: int = 33,
                 row_offset: int = 0, col_offset: int = 0) -> Dict[Tuple[int,int], str]:
    """Place text sequentially into (row, col) 1-based grid positions.

    Fills left-to-right, top-to-bottom, starting at (row_offset+1, col_offset+1).
    Returns dict mapping (col, row) -> letter.
    """
    grid: Dict[Tuple[int,int], str] = {}
    pos = 0
    for r in range(1, rows + 1):
        for c in range(1, cols + 1):
            if pos >= len(text):
                return grid
            # Apply offsets (wrap)
            actual_c = ((c - 1 + col_offset) % cols) + 1
            actual_r = ((r - 1 + row_offset) % rows) + 1
            grid[(actual_c, actual_r)] = text[pos]
            pos += 1
    return grid

def extract_from_grid(grid: Dict[Tuple[int,int], str], cells: List[Tuple[int,int]]) -> str:
    """Extract letters at specified (col, row) cells from grid, in reading order."""
    # Sort cells in reading order: top-bottom, left-right
    sorted_cells = sorted(cells, key=lambda x: (x[1], x[0]))  # (col, row) -> sort by row then col
    result = []
    for col, row in sorted_cells:
        if (col, row) in grid:
            ch = grid[(col, row)]
            if ch.isalpha():
                result.append(ch.upper())
    return "".join(result)

# ── Cipher operations ────────────────────────────────────────────────────────

def vig_score(key_seq: str, offset: int = 0) -> Tuple[int, float, str]:
    """Try Vigenère with key_seq[offset:offset+97] against CT_K4. Return (crib_hits, score, pt)."""
    if offset + 97 > len(key_seq):
        return 0, -999.0, ""
    key = key_seq[offset:offset+97]
    pt_chars = []
    crib_hits = 0
    for i, ct_ch in enumerate(CT_K4):
        k_val = AZ_IDX[key[i]]
        pt_val = (AZ_IDX[ct_ch] - k_val) % 26
        pt_ch = AZ[pt_val]
        pt_chars.append(pt_ch)
        if i in CRIB_KEYS_VIG and pt_val == (AZ_IDX[ct_ch] - CRIB_KEYS_VIG[i]) % 26:
            crib_hits += 1
    pt = "".join(pt_chars)
    score = quadgram_score(pt)
    return crib_hits, score, pt

def beau_score(key_seq: str, offset: int = 0) -> Tuple[int, float, str]:
    """Try Beaufort with key_seq[offset:offset+97] against CT_K4."""
    if offset + 97 > len(key_seq):
        return 0, -999.0, ""
    key = key_seq[offset:offset+97]
    pt_chars = []
    crib_hits = 0
    for i, ct_ch in enumerate(CT_K4):
        k_val = AZ_IDX[key[i]]
        pt_val = (k_val - AZ_IDX[ct_ch]) % 26
        pt_ch = AZ[pt_val]
        pt_chars.append(pt_ch)
        if i in CRIB_KEYS_BEAU and pt_val == (CRIB_KEYS_BEAU[i] - AZ_IDX[ct_ch]) % 26:
            crib_hits += 1
    pt = "".join(pt_chars)
    score = quadgram_score(pt)
    return crib_hits, score, pt

def check_east(key_seq: str, offset: int, cipher: str = "vig") -> bool:
    """Fast EAST constraint pre-filter."""
    if offset + 97 > len(key_seq):
        return False
    if cipher == "vig":
        crib_k = CRIB_KEYS_VIG
    else:
        crib_k = CRIB_KEYS_BEAU
    # Check 24/24 crib hits directly
    for pos, required in crib_k.items():
        k_val = AZ_IDX[key_seq[offset + pos]]
        if cipher == "vig":
            actual = (AZ_IDX[CT_K4[pos]] - k_val) % 26
        else:
            actual = (k_val - AZ_IDX[CT_K4[pos]]) % 26
        expected = (AZ_IDX[CT_K4[pos]] - required) % 26 if cipher == "vig" else (required + AZ_IDX[CT_K4[pos]]) % 26
        # For Vigenère: pt = (ct - key) mod 26; required = key value, so pt = ct - required
        # Actually just check if key matches
        if k_val != required:
            return False
    return True

def test_source_text(name: str, source: str, results: List) -> None:
    """Test a source text as running key for K4 under multiple cipher variants."""
    min_len_needed = 97 + 10  # need at least 97 chars + some offset room
    if len(source) < 97:
        print(f"  {name}: too short ({len(source)} chars)")
        return

    max_offsets = min(len(source) - 96, 50)  # test up to 50 offsets
    crib_threshold = 20  # only log if >= 20/24 crib hits

    best_score = -999.0
    best_result = None

    for offset in range(max_offsets):
        for cipher, score_fn in [("vig", vig_score), ("beau", beau_score)]:
            hits, score, pt = score_fn(source, offset)
            if hits >= crib_threshold:
                entry = (hits, score, cipher, offset, name, pt[:50])
                results.append(entry)
                if score > best_score:
                    best_score = score
                    best_result = entry

    # Also test reversed source
    source_rev = source[::-1]
    for offset in range(min(max_offsets, len(source_rev) - 96)):
        for cipher, score_fn in [("vig", vig_score), ("beau", beau_score)]:
            hits, score, pt = score_fn(source_rev, offset)
            if hits >= crib_threshold:
                entry = (hits, score, cipher, offset, f"{name}_REV", pt[:50])
                results.append(entry)
                if score > best_score:
                    best_score = score
                    best_result = entry

    crib24_count = sum(1 for h, _, _, _, n, _ in results if n == name and h == 24)
    if crib24_count > 0:
        print(f"  {name}: *** {crib24_count} FULL CRIB MATCHES (24/24) *** best_score={best_score:.4f}")
    elif best_result:
        print(f"  {name}: best_hits={best_result[0]}/24, best_score={best_score:.4f}")
    else:
        print(f"  {name}: max hits < {crib_threshold} (NOISE)")

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 72)
    print(f"  {EXPERIMENT_ID}: Cardan Grille Applied to K1+K2+K3 Plaintext")
    print("=" * 72)

    print(f"\nK1 PT ({len(K1_ALPHA)} alpha chars): {K1_ALPHA[:40]}...")
    print(f"K2 PT ({len(K2_ALPHA)} alpha chars): {K2_ALPHA[:40]}...")
    print(f"K3 PT ({len(K3_ALPHA)} alpha chars): {K3_ALPHA[:40]}...")
    print(f"K123 combined ({len(K123_ALPHA)} alpha chars)")
    print(f"K123 CT ({len(K123_CT)} alpha chars)")
    sys.stdout.flush()

    results: List = []

    # ── Phase 1: Apply physical grille to K1+K2+K3 PT in standard grid ──────
    print("\n" + "─" * 72)
    print("Phase 1: Physical grille over K1+K2+K3 PT — standard 28×33 grid layout")
    print("─" * 72)

    for row_offset in range(5):  # test 5 starting row offsets
        for col_offset in range(5):  # test 5 starting col offsets
            grid = text_to_grid(K123_ALPHA, GRID_ROWS, GRID_COLS, row_offset, col_offset)
            extract = extract_from_grid(grid, VISIBLE_CELLS)
            if len(extract) >= 97:
                name = f"K123_PT_ro{row_offset}_co{col_offset}"
                test_source_text(name, extract, results)

    # ── Phase 2: K3 PT only (physically closest to K4) ───────────────────────
    print("\n" + "─" * 72)
    print("Phase 2: Physical grille over K3 PT only")
    print("─" * 72)

    for row_offset in range(5):
        for col_offset in range(5):
            grid = text_to_grid(K3_ALPHA, GRID_ROWS, GRID_COLS, row_offset, col_offset)
            extract = extract_from_grid(grid, VISIBLE_CELLS)
            if len(extract) >= 97:
                name = f"K3_PT_ro{row_offset}_co{col_offset}"
                test_source_text(name, extract, results)

    # ── Phase 3: K1+K2+K3 CT as source (autoclave variant) ──────────────────
    print("\n" + "─" * 72)
    print("Phase 3: Physical grille over K1+K2+K3 CT")
    print("─" * 72)

    for row_offset in range(3):
        for col_offset in range(3):
            grid = text_to_grid(K123_CT, GRID_ROWS, GRID_COLS, row_offset, col_offset)
            extract = extract_from_grid(grid, VISIBLE_CELLS)
            if len(extract) >= 97:
                name = f"K123_CT_ro{row_offset}_co{col_offset}"
                test_source_text(name, extract, results)

    # ── Phase 4: Full K1+K2+K3+K4 CT (entire ciphertext) ────────────────────
    print("\n" + "─" * 72)
    print("Phase 4: Physical grille over full Kryptos CT (K1+K2+K3+K4)")
    print("─" * 72)

    FULL_CT = alpha_only(K1_CT + K2_CT + K3_CT + CT_K4)
    for row_offset in range(3):
        for col_offset in range(3):
            grid = text_to_grid(FULL_CT, GRID_ROWS, GRID_COLS, row_offset, col_offset)
            extract = extract_from_grid(grid, VISIBLE_CELLS)
            if len(extract) >= 97:
                name = f"FULL_CT_ro{row_offset}_co{col_offset}"
                test_source_text(name, extract, results)

    # ── Phase 5: K2 PT only (coordinates section) ────────────────────────────
    print("\n" + "─" * 72)
    print("Phase 5: Physical grille over K2 PT only")
    print("─" * 72)

    for row_offset in range(3):
        for col_offset in range(3):
            grid = text_to_grid(K2_ALPHA, GRID_ROWS, GRID_COLS, row_offset, col_offset)
            extract = extract_from_grid(grid, VISIBLE_CELLS)
            if len(extract) >= 97:
                name = f"K2_PT_ro{row_offset}_co{col_offset}"
                test_source_text(name, extract, results)

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)

    full_crib_matches = [r for r in results if r[0] == 24]
    near_matches = [r for r in results if r[0] >= 20]

    print(f"Total configurations tested: ~{25 + 25 + 9 + 9 + 9} (approx)")
    print(f"Full crib matches (24/24): {len(full_crib_matches)}")
    print(f"Near matches (>=20/24): {len(near_matches)}")

    if full_crib_matches:
        print("\n*** FULL CRIB MATCHES FOUND ***")
        for hits, score, cipher, offset, name, pt_prefix in full_crib_matches:
            print(f"  {name} cipher={cipher} offset={offset} score={score:.4f}")
            print(f"    PT[:50]: {pt_prefix}")
    elif near_matches:
        print("\nNear matches:")
        near_matches.sort(key=lambda x: x[1], reverse=True)
        for hits, score, cipher, offset, name, pt_prefix in near_matches[:10]:
            print(f"  hits={hits}/24 score={score:.4f} cipher={cipher} offset={offset} name={name}")
    else:
        print("\nResult: NOISE — no configuration produced >= 20/24 crib hits")
        print("Implication: Physical grille does NOT extract K4 key from K1-K3 PT in simple 28×33 grid.")
        print("Open: Non-sequential grid arrangements, spiral/diagonal reads, physical S-curve layout.")

    print(f"\n{EXPERIMENT_ID} complete")


if __name__ == "__main__":
    main()
