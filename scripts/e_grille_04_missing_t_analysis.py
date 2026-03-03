#!/usr/bin/env python3
"""E-GRILLE-04: Investigate why T is completely absent from YAR grille CT.

The analyst found that T has ZERO occurrences in the 106-char YAR grille CT.
For a 106-char text from a 26-letter alphabet, P(zero T) ~ 0.016 — unlikely
but not impossible. This script determines whether the absence is FULLY
explained by the KA tableau structure (i.e., no Y/A/R positions in the
ciphertext grid happen to align with T positions in the tableau), or if
it reveals something deeper.

Also checks whether the UNDERGRUUND correction (R->E) matters.

Usage: PYTHONPATH=src python3 -u scripts/e_grille_04_missing_t_analysis.py
"""
from __future__ import annotations

import math
import sys
from collections import Counter
from typing import List, Tuple, Dict, Optional

from kryptos.kernel.constants import CT, KRYPTOS_ALPHABET

# ── Constants ────────────────────────────────────────────────────────────────

EXPERIMENT_ID = "E-GRILLE-04"
KA = KRYPTOS_ALPHABET  # "KRYPTOSABCDEFGHIJLMNQUVWXZ"

GRILLE_CT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

# Cipher rows from the physical sculpture (28 rows)
CIPHER_ROWS = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ",   # 0  (32)
    "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD",     # 1  (31)
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCE",      # 2  (31)
    "GGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",       # 3  (30)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",       # 4  (31)
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHRR",     # 5  (32)
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTI",       # 6  (31)
    "HHDDDUVH?DWKBFUFPWNTDFIYCUQZERE",       # 7  (31)
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDX",      # 8  (32)
    "FLGGTEZ?FKZBSFDQVGOGIPUFXHHDRKF",       # 9  (31)
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",        # 10 (30)
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",       # 11 (31)
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",       # 12 (31)
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",       # 13 (31)
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIA",      # 14 (32)
    "CHTNREYULDSLLSLLNOHSNOSMRWXMNE",        # 15 (30)
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",        # 16 (31)
    "WMTWNDITEENRAHCTENEUDRETNHAEOE",         # 17 (30)
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCR",      # 18 (32)
    "EIFTBRSPAMHHEWENATAMATEGYEERLB",         # 19 (30)
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTI",      # 20 (32)
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",       # 21 (31)
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORIT",     # 22 (33)
    "RKLMLEHAGTDHARDPNEOHMGFMFEUHE",         # 23 (29)
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",       # 24 (31)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",       # 25 (31)
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",       # 26 (31)
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",      # 27 (31)
]

# Build corrected cipher rows (UNDERGRUUND -> UNDERGROUND: row 5 col 23 R->E)
CORRECTED_ROWS = list(CIPHER_ROWS)
CORRECTED_ROWS[5] = CIPHER_ROWS[5][:23] + "E" + CIPHER_ROWS[5][24:]


def build_tableau() -> List[str]:
    """Build the 28 tableau rows: header, 26 body (A-Z), footer."""
    rows = []
    rows.append(" ABCDEFGHIJKLMNOPQRSTUVWXYZABCD")  # header
    for i in range(26):
        label = chr(ord("A") + i)
        body = "".join(KA[(j + i) % 26] for j in range(30))
        row = label + body
        if label == "N":
            row += "L"  # Stray L anomaly
        rows.append(row)
    rows.append(" ABCDEFGHIJKLMNOPQRSTUVWXYZABCD")  # footer
    return rows


def find_yar_positions(cipher_rows: List[str]) -> List[Tuple[int, int, str]]:
    """Find all Y/A/R positions in cipher rows. Returns (row, col, letter)."""
    positions = []
    for r_idx, row in enumerate(cipher_rows):
        for c_idx, ch in enumerate(row):
            if ch in "YAR":
                positions.append((r_idx, c_idx, ch))
    return positions


def extract_grille(cipher_rows: List[str], tableau_rows: List[str],
                   removal_set: str = "YAR") -> List[Tuple[int, int, str, str, str]]:
    """Extract grille CT by reading tableau chars through Y/A/R holes.

    Returns list of (cipher_row, cipher_col, hole_letter, tableau_char, tableau_row_label).
    Uses baseline alignment: h_offset=0, v_offset=0, no label col, normal direction.
    """
    rm_set = set(removal_set)
    results = []

    for r_idx, row in enumerate(cipher_rows):
        for c_idx, ch in enumerate(row):
            if ch in rm_set:
                # Baseline alignment: tab_row = cipher_row, tab_col = cipher_col
                tab_row_idx = r_idx
                tab_col = c_idx
                if 0 <= tab_row_idx < len(tableau_rows) and 0 <= tab_col < len(tableau_rows[tab_row_idx]):
                    t_ch = tableau_rows[tab_row_idx][tab_col]
                    # Get tableau row label
                    tab_row_str = tableau_rows[tab_row_idx]
                    tab_label = tab_row_str[0] if tab_row_str[0].isalpha() else "HDR/FTR"
                    if t_ch.isalpha():
                        results.append((r_idx, c_idx, ch, t_ch, tab_label))

    return results


def main():
    print("=" * 80)
    print(f"  {EXPERIMENT_ID}: Missing T Investigation — KA Tableau Structural Analysis")
    print("=" * 80)
    sys.stdout.flush()

    tableau_rows = build_tableau()

    # ══════════════════════════════════════════════════════════════════════════
    # Part 1: Verify the grille CT and confirm T is missing
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 80}")
    print("Part 1: Verify grille CT and frequency analysis")
    print(f"{'─' * 80}")

    print(f"Grille CT: {GRILLE_CT}")
    print(f"Length: {len(GRILLE_CT)}")

    freq = Counter(GRILLE_CT)
    print(f"\nLetter frequencies in grille CT:")
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        count = freq.get(letter, 0)
        pct = count / len(GRILLE_CT) * 100
        bar = "#" * count
        missing_tag = " *** MISSING ***" if count == 0 else ""
        print(f"  {letter}: {count:3d} ({pct:5.2f}%) {bar}{missing_tag}")

    missing_letters = [c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if freq.get(c, 0) == 0]
    print(f"\nMissing letters: {missing_letters}")

    # Statistical test: P(letter appears 0 times in 106 chars from uniform 26-letter alphabet)
    # P(miss one specific letter) = (25/26)^106
    p_miss_one = (25.0 / 26.0) ** 106
    # Expected number of missing letters = 26 * p_miss_one
    expected_missing = 26 * p_miss_one
    print(f"\nP(specific letter missing | n=106, uniform) = (25/26)^106 = {p_miss_one:.6f}")
    print(f"Expected missing letters from 26 = {expected_missing:.3f}")
    print(f"Actual missing: {len(missing_letters)}")

    if len(missing_letters) == 1:
        # P(exactly 1 letter missing from 26) = C(26,1) * (25/26)^106 * adjustment
        # More precisely using inclusion-exclusion, but approximate:
        print(f"P(exactly 1 missing from 26) ~ 26 * (25/26)^106 = {26 * p_miss_one:.4f}")
        print("  -> This is ~42% likely, so missing T alone is NOT unusual by chance")
        print("  -> BUT: the question is whether the KA tableau structure FORCES this")

    # ══════════════════════════════════════════════════════════════════════════
    # Part 2: Map T positions in the KA tableau
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 80}")
    print("Part 2: Where does T appear in the KA tableau?")
    print(f"{'─' * 80}")

    # KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    # T is at KA index 4
    t_ka_idx = KA.index("T")
    print(f"T is at position {t_ka_idx} in KA alphabet: {KA}")

    print(f"\nT positions in each tableau body row:")
    t_positions_by_row = {}  # row_label -> column index where T appears
    for i in range(26):
        label = chr(ord("A") + i)
        tab_row_idx = i + 1  # +1 for header
        row = tableau_rows[tab_row_idx]
        # Find all T positions in this row (including the label)
        t_cols = [c for c in range(len(row)) if row[c] == "T"]
        t_positions_by_row[label] = t_cols
        row_display = row[:35]
        t_markers = ""
        for c in range(len(row_display)):
            t_markers += "^" if row_display[c] == "T" else " "
        print(f"  Row {label} (idx {tab_row_idx:2d}): {row_display}")
        print(f"          {'  ':17s}{t_markers}")
        print(f"          T at columns: {t_cols}")

    # ══════════════════════════════════════════════════════════════════════════
    # Part 3: Which Y/A/R positions align with T in the tableau?
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 80}")
    print("Part 3: Do ANY Y/A/R cipher positions align with T in the tableau?")
    print(f"{'─' * 80}")

    # Extract with original cipher rows
    extractions_orig = extract_grille(CIPHER_ROWS, tableau_rows)
    extractions_corr = extract_grille(CORRECTED_ROWS, tableau_rows)

    print(f"\nOriginal cipher: {len(extractions_orig)} grille chars extracted")
    print(f"Corrected cipher: {len(extractions_corr)} grille chars extracted")

    # Check which extracted chars are T
    t_extractions_orig = [(r, c, h, t, tl) for r, c, h, t, tl in extractions_orig if t == "T"]
    t_extractions_corr = [(r, c, h, t, tl) for r, c, h, t, tl in extractions_corr if t == "T"]

    print(f"\nOriginal: T extracted {len(t_extractions_orig)} times")
    for r, c, h, t, tl in t_extractions_orig:
        print(f"  cipher_row={r}, cipher_col={c}, hole={h}, tableau_label={tl}")

    print(f"Corrected: T extracted {len(t_extractions_corr)} times")
    for r, c, h, t, tl in t_extractions_corr:
        print(f"  cipher_row={r}, cipher_col={c}, hole={h}, tableau_label={tl}")

    # Reconstruct grille CT from extractions to verify
    orig_grille_text = "".join(t for _, _, _, t, _ in extractions_orig)
    corr_grille_text = "".join(t for _, _, _, t, _ in extractions_corr)

    print(f"\nReconstructed grille CT (original):  {orig_grille_text}")
    print(f"Reconstructed grille CT (corrected): {corr_grille_text}")
    print(f"Given grille CT:                     {GRILLE_CT}")

    if orig_grille_text == GRILLE_CT:
        print("  -> Original matches given CT exactly")
    elif corr_grille_text == GRILLE_CT:
        print("  -> Corrected matches given CT exactly")
    else:
        # Check which one is closer
        orig_match = sum(1 for a, b in zip(orig_grille_text, GRILLE_CT) if a == b)
        corr_match = sum(1 for a, b in zip(corr_grille_text, GRILLE_CT) if a == b)
        print(f"  -> Neither matches exactly. Original: {orig_match}/{len(GRILLE_CT)}, Corrected: {corr_match}/{len(GRILLE_CT)}")
        # Show diffs
        for i, (a, b) in enumerate(zip(corr_grille_text, GRILLE_CT)):
            if a != b:
                print(f"     pos {i}: reconstructed={a}, given={b}")

    # ══════════════════════════════════════════════════════════════════════════
    # Part 4: Detailed structural analysis — which tableau letters CAN appear?
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 80}")
    print("Part 4: Expected frequency of grille output from KA tableau structure")
    print(f"{'─' * 80}")

    # For each Y/A/R hole, what tableau character appears?
    # This gives us the STRUCTURAL frequency of the grille output
    extracted_freq_orig = Counter(t for _, _, _, t, _ in extractions_orig)
    extracted_freq_corr = Counter(t for _, _, _, t, _ in extractions_corr)

    print(f"\nStructural letter frequencies (original cipher):")
    print(f"  {'Letter':>6s} {'Count':>5s} {'Pct':>6s}  {'Bar'}")
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        count = extracted_freq_orig.get(letter, 0)
        pct = count / len(extractions_orig) * 100 if extractions_orig else 0
        bar = "#" * count
        tag = " *** ZERO ***" if count == 0 else ""
        print(f"  {letter:>6s} {count:5d} {pct:6.2f}%  {bar}{tag}")

    print(f"\nStructural letter frequencies (corrected cipher):")
    print(f"  {'Letter':>6s} {'Count':>5s} {'Pct':>6s}  {'Bar'}")
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        count = extracted_freq_corr.get(letter, 0)
        pct = count / len(extractions_corr) * 100 if extractions_corr else 0
        bar = "#" * count
        tag = " *** ZERO ***" if count == 0 else ""
        print(f"  {letter:>6s} {count:5d} {pct:6.2f}%  {bar}{tag}")

    # ══════════════════════════════════════════════════════════════════════════
    # Part 5: Analyze T near-misses
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 80}")
    print("Part 5: T near-misses — Y/A/R positions adjacent to T in the tableau")
    print(f"{'─' * 80}")

    # For each Y/A/R position, check what the neighboring tableau cells contain
    yar_positions = find_yar_positions(CIPHER_ROWS)
    print(f"\nTotal Y/A/R positions in cipher: {len(yar_positions)}")
    y_count = sum(1 for _, _, c in yar_positions if c == "Y")
    a_count = sum(1 for _, _, c in yar_positions if c == "A")
    r_count = sum(1 for _, _, c in yar_positions if c == "R")
    print(f"  Y: {y_count}, A: {a_count}, R: {r_count}")

    near_misses = []
    for r_idx, c_idx, hole_ch in yar_positions:
        tab_row_idx = r_idx  # baseline alignment
        if 0 <= tab_row_idx < len(tableau_rows):
            tab_row = tableau_rows[tab_row_idx]
            # Check if T is in an adjacent column (c_idx-1 or c_idx+1)
            for offset in [-1, 1]:
                adj_col = c_idx + offset
                if 0 <= adj_col < len(tab_row) and tab_row[adj_col] == "T":
                    # What letter is actually at the hole position?
                    actual = tab_row[c_idx] if c_idx < len(tab_row) else "OOB"
                    near_misses.append((r_idx, c_idx, hole_ch, actual, adj_col, offset))

    print(f"\nT near-misses (T one column away from a Y/A/R hole):")
    if near_misses:
        for r, c, h, actual, adj_c, offset in near_misses:
            direction = "right" if offset == 1 else "left"
            print(f"  Row {r:2d} col {c:2d} (hole={h}): reads '{actual}', T is one col {direction} at col {adj_c}")
    else:
        print("  None found")

    # ══════════════════════════════════════════════════════════════════════════
    # Part 6: UNDERGRUUND correction impact
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 80}")
    print("Part 6: UNDERGRUUND correction impact on T")
    print(f"{'─' * 80}")

    # The correction changes row 5 col 23 from R to E
    # This REMOVES one R hole. What did that R hole extract?
    # Row 5 col 23 in original is R -> hole -> tableau char
    tab_row_5 = tableau_rows[5]  # Row F (0=header, 1=A, ..., 6=F)
    if 23 < len(tab_row_5):
        lost_char = tab_row_5[23]
        print(f"Original row 5 col 23 = R (hole) -> tableau[5][23] = '{lost_char}'")
        print(f"Corrected row 5 col 23 = E (not a hole) -> this character is LOST from grille CT")
        if lost_char == "T":
            print("  *** The lost character IS T! The correction removes T from the output! ***")
        else:
            print(f"  The lost character is '{lost_char}', not T")
    else:
        print(f"  Row 5 col 23 is out of bounds for tableau row (len={len(tab_row_5)})")

    # Check: does the uncorrected grille CT contain T?
    uncorr_grille_text = "".join(t for _, _, _, t, _ in extractions_orig)
    t_in_uncorr = "T" in uncorr_grille_text
    t_in_corr = "T" in corr_grille_text
    print(f"\nT in uncorrected grille CT: {t_in_uncorr} (count={uncorr_grille_text.count('T')})")
    print(f"T in corrected grille CT:   {t_in_corr} (count={corr_grille_text.count('T')})")

    # Show the diff between original and corrected extractions
    if len(extractions_orig) != len(extractions_corr):
        print(f"\nExtraction count differs: orig={len(extractions_orig)}, corr={len(extractions_corr)}")
        # Find what changed
        orig_set = set((r, c) for r, c, _, _, _ in extractions_orig)
        corr_set = set((r, c) for r, c, _, _, _ in extractions_corr)
        lost = orig_set - corr_set
        gained = corr_set - orig_set
        print(f"  Lost positions: {lost}")
        print(f"  Gained positions: {gained}")
        for r, c in lost:
            matching = [(r2, c2, h, t, tl) for r2, c2, h, t, tl in extractions_orig if r2 == r and c2 == c]
            for _, _, h, t, tl in matching:
                print(f"    Lost: row={r} col={c} hole={h} -> extracted '{t}' (tableau row {tl})")

    # ══════════════════════════════════════════════════════════════════════════
    # Part 7: Deep structural analysis — WHY does T never appear?
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 80}")
    print("Part 7: Deep structural analysis — WHY is T absent?")
    print(f"{'─' * 80}")

    # For each tableau body row, show where T appears and where Y/A/R holes are
    print("\nRow-by-row: Y/A/R holes vs T positions in tableau")
    print(f"  {'Row':>3s} {'TabLabel':>8s} {'#Holes':>6s} {'T_cols':>20s} {'Hole_cols':>40s} {'Overlap':>7s}")

    total_t_positions = 0
    total_hole_positions = 0
    t_accessible = 0

    for r_idx, row in enumerate(CIPHER_ROWS):
        tab_row_idx = r_idx
        if tab_row_idx >= len(tableau_rows):
            continue
        tab_row = tableau_rows[tab_row_idx]
        tab_label = tab_row[0] if tab_row[0].isalpha() else "H/F"

        # Y/A/R hole columns in this cipher row
        hole_cols = [c for c, ch in enumerate(row) if ch in "YAR"]
        # T positions in corresponding tableau row
        t_cols = [c for c in range(len(tab_row)) if tab_row[c] == "T"]

        # Overlap: holes that land on T
        overlap = set(hole_cols) & set(t_cols)

        total_t_positions += len(t_cols)
        total_hole_positions += len(hole_cols)
        t_accessible += len(overlap)

        overlap_str = str(sorted(overlap)) if overlap else "NONE"
        print(f"  {r_idx:3d} {tab_label:>8s} {len(hole_cols):6d} {str(t_cols):>20s} "
              f"{str(hole_cols):>40s} {overlap_str:>7s}")

    print(f"\n  Total T positions across all tableau rows: {total_t_positions}")
    print(f"  Total Y/A/R hole positions: {total_hole_positions}")
    print(f"  T positions accessible through holes: {t_accessible}")

    if t_accessible == 0:
        print(f"\n  *** STRUCTURAL EXPLANATION CONFIRMED ***")
        print(f"  No Y/A/R hole in the cipher grid aligns with any T position in the tableau.")
        print(f"  The absence of T is ENTIRELY explained by the KA tableau geometry.")
        print(f"  This is not a statistical anomaly — it's a deterministic consequence.")
    else:
        print(f"\n  T IS accessible through {t_accessible} holes — so its absence would be anomalous")

    # ══════════════════════════════════════════════════════════════════════════
    # Part 8: Which OTHER letters are structurally impossible?
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 80}")
    print("Part 8: Structurally impossible/rare letters in grille output")
    print(f"{'─' * 80}")

    # For each letter, count how many Y/A/R holes could produce it
    letter_accessibility = Counter()
    for r_idx, row in enumerate(CIPHER_ROWS):
        tab_row_idx = r_idx
        if tab_row_idx >= len(tableau_rows):
            continue
        tab_row = tableau_rows[tab_row_idx]
        for c_idx, ch in enumerate(row):
            if ch in "YAR" and c_idx < len(tab_row) and tab_row[c_idx].isalpha():
                letter_accessibility[tab_row[c_idx]] += 1

    print(f"\nLetter accessibility (how many Y/A/R holes can produce each letter):")
    print(f"  {'Letter':>6s} {'Accessible':>10s} {'Actual':>6s} {'Status'}")
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        accessible = letter_accessibility.get(letter, 0)
        actual = freq.get(letter, 0)
        if accessible == 0:
            status = "IMPOSSIBLE (structural)"
        elif actual == 0 and accessible > 0:
            status = f"ABSENT but accessible ({accessible} holes)"
        elif actual > accessible:
            status = "ERROR: more actual than accessible!"
        else:
            status = ""
        print(f"  {letter:>6s} {accessible:10d} {actual:6d}  {status}")

    impossible_letters = [c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if letter_accessibility.get(c, 0) == 0]
    print(f"\nStructurally impossible letters: {impossible_letters}")

    # Compare actual vs structural expectation
    # If output were uniform over accessible positions, expected freq per letter =
    # (accessibility[letter] / total_accessible) * total_output_chars
    total_accessible = sum(letter_accessibility.values())
    print(f"\nExpected vs Actual (under uniform random selection of accessible positions):")
    print(f"  Total accessible positions: {total_accessible}")
    print(f"  {'Letter':>6s} {'Access':>6s} {'ExpFrac':>8s} {'Expected':>8s} {'Actual':>6s} {'Deviation':>9s}")

    max_dev = 0
    max_dev_letter = ""
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        accessible = letter_accessibility.get(letter, 0)
        expected_frac = accessible / total_accessible if total_accessible > 0 else 0
        expected_count = expected_frac * len(GRILLE_CT)
        actual_count = freq.get(letter, 0)
        dev = actual_count - expected_count
        if abs(dev) > abs(max_dev):
            max_dev = dev
            max_dev_letter = letter
        print(f"  {letter:>6s} {accessible:6d} {expected_frac:8.4f} {expected_count:8.2f} {actual_count:6d} {dev:+9.2f}")

    print(f"\n  Largest deviation: {max_dev_letter} ({max_dev:+.2f})")

    # ══════════════════════════════════════════════════════════════════════════
    # Part 9: What does the KA structure predict about letter distribution?
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 80}")
    print("Part 9: KA cyclic structure — why T is special")
    print(f"{'─' * 80}")

    # In KA, T is at index 4. In each row i, T appears at column (4 - i) mod 26 + 1
    # (the +1 is for the label column)
    print(f"\nKA alphabet: {KA}")
    print(f"T is at KA index: {t_ka_idx}")
    print(f"\nFor each tableau body row i (0-25), T appears at body column (4-i) mod 26")
    print(f"With the label, that's actual column (4-i) mod 26 + 1")
    print(f"\n  {'Row':>3s} {'Label':>5s} {'T_body_col':>10s} {'T_actual_col':>12s} {'Cipher_char':>11s} {'Is_YAR':>6s}")

    for i in range(26):
        label = chr(ord("A") + i)
        t_body_col = (t_ka_idx - i) % 26
        t_actual_col = t_body_col + 1  # +1 for label column
        tab_row_idx = i + 1  # +1 for header

        # What cipher character is at this position?
        cipher_row = CIPHER_ROWS[tab_row_idx] if tab_row_idx < len(CIPHER_ROWS) else None
        if cipher_row and t_actual_col < len(cipher_row):
            cipher_ch = cipher_row[t_actual_col]
            is_yar = cipher_ch in "YAR"
        elif cipher_row:
            cipher_ch = "OOB"
            is_yar = False
        else:
            cipher_ch = "N/A"
            is_yar = False

        print(f"  {i:3d} {label:>5s} {t_body_col:10d} {t_actual_col:12d} "
              f"{cipher_ch:>11s} {'YES' if is_yar else 'no':>6s}")

    # Also check header/footer rows
    print(f"\n  Header (row 0): T at column {tableau_rows[0].index('T') if 'T' in tableau_rows[0] else 'N/A'}")
    print(f"  Footer (row 27): T at column {tableau_rows[27].index('T') if 'T' in tableau_rows[27] else 'N/A'}")

    for row_idx in [0, 27]:
        tab_row = tableau_rows[row_idx]
        t_cols = [c for c in range(len(tab_row)) if tab_row[c] == "T"]
        for tc in t_cols:
            cipher_row = CIPHER_ROWS[row_idx] if row_idx < len(CIPHER_ROWS) else None
            if cipher_row and tc < len(cipher_row):
                cipher_ch = cipher_row[tc]
                is_yar = cipher_ch in "YAR"
                print(f"    Row {row_idx} col {tc}: cipher='{cipher_ch}' is_YAR={'YES' if is_yar else 'no'}")

    # ══════════════════════════════════════════════════════════════════════════
    # Part 10: Corrected vs uncorrected — does the correction matter for T?
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'─' * 80}")
    print("Part 10: Does the UNDERGRUUND correction affect T accessibility?")
    print(f"{'─' * 80}")

    # Corrected accessibility
    corr_letter_accessibility = Counter()
    for r_idx, row in enumerate(CORRECTED_ROWS):
        tab_row_idx = r_idx
        if tab_row_idx >= len(tableau_rows):
            continue
        tab_row = tableau_rows[tab_row_idx]
        for c_idx, ch in enumerate(row):
            if ch in "YAR" and c_idx < len(tab_row) and tab_row[c_idx].isalpha():
                corr_letter_accessibility[tab_row[c_idx]] += 1

    corr_t = corr_letter_accessibility.get("T", 0)
    orig_t = letter_accessibility.get("T", 0)
    print(f"T accessibility — Original: {orig_t}, Corrected: {corr_t}")

    if orig_t != corr_t:
        print(f"  Correction CHANGES T accessibility by {corr_t - orig_t}")
        # Which specific hole was lost/gained?
        print(f"  Correction site: row 5 col 23, R->E")
        tab_5_23 = tableau_rows[5][23] if 23 < len(tableau_rows[5]) else "OOB"
        print(f"  Tableau at [5][23] = '{tab_5_23}'")
        if tab_5_23 == "T":
            print(f"  *** The R->E correction REMOVES the only T access point! ***")
            print(f"  In the uncorrected cipher, row 5 col 23 is R (a hole) reading T from the tableau.")
            print(f"  In the corrected cipher, row 5 col 23 is E (not a hole), so T becomes inaccessible.")
    else:
        print(f"  Correction does NOT affect T accessibility")

    corr_impossible = [c for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if corr_letter_accessibility.get(c, 0) == 0]
    orig_impossible = impossible_letters
    print(f"\n  Structurally impossible (original):  {orig_impossible}")
    print(f"  Structurally impossible (corrected): {corr_impossible}")

    new_impossible = set(corr_impossible) - set(orig_impossible)
    if new_impossible:
        print(f"  Letters that BECOME impossible after correction: {sorted(new_impossible)}")

    # ══════════════════════════════════════════════════════════════════════════
    # VERDICT
    # ══════════════════════════════════════════════════════════════════════════
    print(f"\n{'=' * 80}")
    print("VERDICT")
    print(f"{'=' * 80}")

    if t_accessible == 0 and corr_t == 0:
        print(f"""
  T is STRUCTURALLY IMPOSSIBLE in BOTH the original and corrected grille CT.
  No Y/A/R hole in the cipher grid aligns with any T position in the KA tableau.
  This is a deterministic geometric consequence, not a statistical anomaly.

  The UNDERGRUUND correction (R->E) does NOT affect this — T was already
  inaccessible before the correction.

  Other structurally impossible letters (corrected): {corr_impossible}
  Other structurally impossible letters (original):  {orig_impossible}

  The apparent anomaly of missing T is FULLY EXPLAINED by tableau geometry.
""")
    elif t_accessible == 0 and corr_t > 0:
        print(f"""
  T is structurally IMPOSSIBLE in the corrected grille CT, but WAS accessible
  in the original (uncorrected) version through {orig_t} hole(s).

  The UNDERGRUUND correction (R->E at row 5 col 23) REMOVED the T access point.
  This means the corrected grille structurally excludes T.

  Implication: The absence of T is a CONSEQUENCE of applying the UNDERGRUUND
  correction. If the researcher used the corrected cipher, this fully explains it.
""")
    elif t_accessible > 0 and corr_t == 0:
        print(f"""
  T WAS accessible ({t_accessible} holes) in the original cipher but becomes
  IMPOSSIBLE after the UNDERGRUUND correction removes the access point.

  The UNDERGRUUND correction (R->E at row 5 col 23) is THE reason T is missing.
  Tableau cell [5][23] = '{tableau_rows[5][23]}' was the ONLY T access point.

  *** SIGNIFICANT FINDING: The correction CREATES the T absence. ***
  If the grille CT was extracted from the corrected cipher, the missing T is
  a direct and necessary consequence of the correction.
""")
    else:
        print(f"""
  T is accessible through {corr_t} hole(s) in the corrected cipher
  and {orig_t} hole(s) in the original — yet it appears 0 times in the output.

  This is a GENUINE STATISTICAL ANOMALY, not explained by tableau structure.
  Probability of 0 occurrences given {corr_t} accessible positions is very low.
  This warrants further investigation.
""")

    print(f"{'=' * 80}")
    print(f"  {EXPERIMENT_ID} complete")
    print(f"{'=' * 80}")


if __name__ == "__main__":
    main()
