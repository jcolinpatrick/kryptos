#!/usr/bin/env python3
"""E-AUDIT-04: Cardan-Style Aperture Extraction over Antipodes Field.

[HYPOTHESIS] K4 is not the result of transforming 97 plaintext letters directly,
but of SELECTING 97 letters from a larger text field (the Antipodes layout) via
a movable aperture mask.

Historical anchor: Cardan grille (Girolamo Cardano, 1550). The key is not a word
or number but a geometric pattern that selects letters from a field.

This is fundamentally different from all prior elimination work because:
- It's a SELECTION cipher, not a TRANSFORMATION cipher
- The "ciphertext" is the Antipodes text field
- K4 is either the selected letters or the residue after selection
- Position correspondence between CT and PT does not follow standard indexing

Test plan:
1. Use K4 CT characters as a SELECTION from the full Antipodes text
2. Check if K4 chars can be extracted from Antipodes via low-complexity masks
3. Test if REMAINING (non-selected) chars contain English/cribs
4. Test row-by-row extraction patterns
5. Test systematic aperture patterns (every-Nth, diagonal, etc.)

Uses position-FREE crib scoring.
"""
import json
import os
import sys
import time
from collections import Counter
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, ALPH
from kryptos.kernel.scoring.free_crib import score_free, score_free_fast, CRIB_ENE, CRIB_BC
from kryptos.kernel.scoring.ic import ic


# ── Antipodes text field ─────────────────────────────────────────────────

# Full Antipodes ciphertext (1,584 letters), reconstructed and verified.
# Sequence: K3 → K4 → K1 → K2 → K3 → K4 → K1 → K2 (truncated)
ANTIPODES_ROWS = [
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACH",          # Row 1, K3
    "TNREYULDSLLSLLNOHSNOSMRWXMNETPRNG",            # Row 2
    "ATIHNRARPESLNNELEBLPIIACAEWMTWNDITE",           # Row 3
    "ENRAHCTENEUDRETNHAEOETFOLSEDTIWENH",            # Row 4
    "AEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWE",            # Row 5
    "NATAMATEGYEERLBTEEFOASFIOTUETUAEOT",            # Row 6
    "OARMAEERTNRTIBSEDDNIAAHTTMSTEWPIER",            # Row 7
    "OAGRIEWFEBAECTDDHILCEIHSITEGOEAOSDD",           # Row 8
    "RYDLORITRKLMLEHAGTDHARDPNEOHMGFMF",             # Row 9
    "EUHEECDMRIPFEIMEHNLSSTTRTVDOHWOBK",              # Row 10, K3→K4
    "RUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTW",             # Row 11, K4
    "TQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZF",           # Row 12
    "PKWGDKZXTJCDIGKUHUAUEKCAREMUFPHZL",              # Row 13, K4→K1 (space removed)
    "RFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQV",            # Row 14
    "YUVLLTREVJYQTMKYRDMFDVFPJUDEEHZWE",             # Row 15
    "TZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQ",              # Row 16
    "ZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDA",             # Row 17
    "GDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJL",            # Row 18
    "BQCETBJDFHRRYIZETKZEMVDUFKSJHKFWHK",            # Row 19
    "UWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYC",              # Row 20
    "UQZEREEVLDKFEZMOQQJLTTUGSYQPFEUNLA",            # Row 21
    "VIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF",            # Row 22 (dots removed)
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZ",             # Row 23
    "ZVRRGKFFVOEEXBDMVPNFQXEZLGREDNQFM",             # Row 24
    "PNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBE",             # Row 25
    "DMHDAFMJGZNUPLGEWJLLAETGENDYAHROH",             # Row 26, K2→K3
    "NLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSL",           # Row 27
    "LSLLNOHSNOSMRWXMNETPRNGATIHNRARPE",             # Row 28
    "SLNNELEBLPIIACAEWMTWNDITEENRAHCTEN",             # Row 29
    "EUDRETNHAEOETFOLSEDTIWENHAEIOYTEYQ",             # Row 30
    "HEENCTAYCREIFTBRSPAMHHEWENATAMATEG",             # Row 31
    "YEERLBTEEFOASFIOTUETUAEOTOARMAEERT",             # Row 32
    "NRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",           # Row 33
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKL",          # Row 34 (longest)
    "MLEHAGTDHARDPNEOHMGFMFEUHEECDMRIP",             # Row 35
    "FEIMEHNLSSTTRTVDOHWOBKRUOXOGHULBS",              # Row 36, K3→K4
    "OLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZ",            # Row 37, K4
    "WATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJ",            # Row 38
    "CDIGKUHUAUEKCAREMUFPHZLRFAXYUSDJKZ",            # Row 39, K4→K1
    "LDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJY",            # Row 40
    "QTMKYRDMFDVFPJUDEEHZWETZYVGWHKKQ",               # Row 41
    "ETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPF",               # Row 42
    "XHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNG",             # Row 43
    "EUNAQZGZLECGYUXUEENJTBJLBQCETBJDFH",            # Row 44
    "RRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIH",            # Row 45
    "HDDDUVHDWKBFUFPWNTDFIYCUQZEREEVLD",              # Row 46
    "KFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZ",           # Row 47
]

ANTIPODES_FLAT = ''.join(ANTIPODES_ROWS)
ANTIPODES_LEN = len(ANTIPODES_FLAT)


# ── K4 within Antipodes ─────────────────────────────────────────────────

def find_k4_in_antipodes():
    """Find where K4 appears in the Antipodes flat text."""
    positions = []
    start = 0
    while True:
        idx = ANTIPODES_FLAT.find(CT, start)
        if idx == -1:
            break
        positions.append(idx)
        start = idx + 1
    return positions


# ── Aperture extraction ──────────────────────────────────────────────────

def extract_by_mask(text: str, mask_positions: List[int]) -> str:
    """Extract characters at mask positions from text."""
    return ''.join(text[p] for p in mask_positions if p < len(text))


def residue_after_mask(text: str, mask_positions: Set[int]) -> str:
    """Get characters NOT at mask positions."""
    return ''.join(text[i] for i in range(len(text)) if i not in mask_positions)


def every_nth_mask(text_len: int, n: int, offset: int = 0) -> List[int]:
    """Positions at every Nth character starting from offset."""
    return list(range(offset, text_len, n))


def diagonal_mask(rows: List[str], direction: int = 1, start_col: int = 0) -> List[int]:
    """Diagonal extraction from the 2D grid."""
    positions = []
    flat_offset = 0
    col = start_col

    for row in rows:
        if 0 <= col < len(row):
            positions.append(flat_offset + col)
        col = (col + direction) % max(len(row), 1)
        flat_offset += len(row)

    return positions


def column_extraction(rows: List[str], col: int) -> Tuple[str, List[int]]:
    """Extract a single column from the 2D grid."""
    chars = []
    positions = []
    offset = 0
    for row in rows:
        if col < len(row):
            chars.append(row[col])
            positions.append(offset + col)
        offset += len(row)
    return ''.join(chars), positions


# ── K4 as selection from Antipodes ───────────────────────────────────────

def check_k4_chars_in_field(field: str, k4: str = CT) -> Dict:
    """Check if K4's character frequencies can be drawn from the field."""
    k4_counts = Counter(k4)
    field_counts = Counter(field)

    possible = True
    deficits = {}
    for ch, count in k4_counts.items():
        if field_counts[ch] < count:
            possible = False
            deficits[ch] = count - field_counts[ch]

    return {
        "possible": possible,
        "deficits": deficits,
        "k4_unique_chars": len(k4_counts),
        "field_unique_chars": len(field_counts),
    }


# ── Main search ──────────────────────────────────────────────────────────

def run_cardan_aperture():
    print("=" * 72)
    print("E-AUDIT-04: Cardan-Style Aperture Extraction")
    print("=" * 72)
    print()

    # Step 0: Verify Antipodes data
    print(f"Antipodes flat text length: {ANTIPODES_LEN}")
    print(f"Rows: {len(ANTIPODES_ROWS)}")
    print(f"Row lengths: {[len(r) for r in ANTIPODES_ROWS]}")

    k4_positions = find_k4_in_antipodes()
    print(f"K4 appears in Antipodes at positions: {k4_positions}")
    print()

    # Step 1: Can K4 characters be drawn from various Antipodes subfields?
    print("Step 1: Character frequency compatibility")
    print("-" * 48)

    subfields = {
        "full_antipodes": ANTIPODES_FLAT,
        "pass1_only": ''.join(ANTIPODES_ROWS[:26]),
        "pass2_only": ''.join(ANTIPODES_ROWS[26:]),
        "k3_only_p1": ''.join(ANTIPODES_ROWS[:10]),
        "k2_only_p1": ''.join(ANTIPODES_ROWS[15:26]),
        "non_k4": ''.join(r for i, r in enumerate(ANTIPODES_ROWS)
                         if i not in [10, 11, 12, 36, 37, 38]),
    }

    for name, field in subfields.items():
        result = check_k4_chars_in_field(field)
        status = "OK" if result["possible"] else f"DEFICIT: {result['deficits']}"
        print(f"  {name} ({len(field)} chars): {status}")
    print()

    # Step 2: Every-Nth extraction from Antipodes
    print("Step 2: Every-Nth character extraction")
    print("-" * 48)

    best_score_step2 = 0
    configs_step2 = 0

    for n in range(2, 50):
        for offset in range(n):
            mask = every_nth_mask(ANTIPODES_LEN, n, offset)
            if len(mask) < 50:
                continue

            extracted = extract_by_mask(ANTIPODES_FLAT, mask)
            configs_step2 += 1

            # Check if extracted matches K4
            if extracted[:CT_LEN] == CT:
                print(f"  *** K4 IS every-{n}th from offset {offset}! ***")

            # Check extracted text for cribs
            fscore = score_free_fast(extracted)
            if fscore > best_score_step2:
                best_score_step2 = fscore
                print(f"  HIT: every-{n}th offset={offset}, score={fscore}/24, "
                      f"len={len(extracted)}")

            # Check residue for cribs
            mask_set = set(mask)
            residue = residue_after_mask(ANTIPODES_FLAT, mask_set)
            rscore = score_free_fast(residue)
            if rscore > best_score_step2:
                best_score_step2 = rscore
                print(f"  HIT (residue): every-{n}th offset={offset}, "
                      f"score={rscore}/24, len={len(residue)}")

    print(f"  Configs: {configs_step2}, Best: {best_score_step2}/24")
    print()

    # Step 3: Column extraction from 2D grid
    print("Step 3: Single column extraction from Antipodes grid")
    print("-" * 48)

    max_col = max(len(r) for r in ANTIPODES_ROWS)
    best_score_step3 = 0

    for col in range(max_col):
        col_text, col_positions = column_extraction(ANTIPODES_ROWS, col)
        if len(col_text) < 20:
            continue

        fscore = score_free_fast(col_text)
        if fscore > 0:
            print(f"  HIT: col={col}, score={fscore}/24, text={col_text[:40]}...")
            if fscore > best_score_step3:
                best_score_step3 = fscore

    # Multi-column extraction
    print()
    print("  Multi-column extraction (2-5 adjacent columns):")
    for width in range(2, 6):
        for start_col in range(max_col - width + 1):
            text = ''
            for col in range(start_col, start_col + width):
                ct, _ = column_extraction(ANTIPODES_ROWS, col)
                text += ct
            fscore = score_free_fast(text)
            if fscore > 0:
                print(f"    HIT: cols={start_col}-{start_col+width-1}, "
                      f"score={fscore}/24, len={len(text)}")
                if fscore > best_score_step3:
                    best_score_step3 = fscore

    print(f"  Best column score: {best_score_step3}/24")
    print()

    # Step 4: Diagonal extraction
    print("Step 4: Diagonal extraction patterns")
    print("-" * 48)

    best_score_step4 = 0
    configs_step4 = 0

    for direction in range(-5, 6):
        if direction == 0:
            continue
        for start_col in range(0, max_col, 2):
            mask = diagonal_mask(ANTIPODES_ROWS, direction, start_col)
            if len(mask) < 20:
                continue
            configs_step4 += 1

            extracted = extract_by_mask(ANTIPODES_FLAT, mask)
            fscore = score_free_fast(extracted)
            if fscore > 0:
                print(f"  HIT: dir={direction}, start_col={start_col}, "
                      f"score={fscore}/24")
                if fscore > best_score_step4:
                    best_score_step4 = fscore

    print(f"  Configs: {configs_step4}, Best: {best_score_step4}/24")
    print()

    # Step 5: K4 position-based mask analysis
    # Where does each K4 letter appear in Antipodes (excluding K4 sections)?
    print("Step 5: K4 letter positions in non-K4 Antipodes regions")
    print("-" * 48)

    # Build non-K4 text (exclude K4 rows: 10-12, 36-38)
    k4_row_indices = {10, 11, 12, 36, 37, 38}  # 0-indexed
    non_k4_flat = ''
    non_k4_row_map = []  # track which positions belong to which row
    for i, row in enumerate(ANTIPODES_ROWS):
        if i not in k4_row_indices:
            non_k4_row_map.extend([(i, j) for j in range(len(row))])
            non_k4_flat += row

    print(f"  Non-K4 Antipodes length: {len(non_k4_flat)}")

    # For each K4 char, find its possible positions in non-K4 text
    # Then check if any low-complexity selection pattern matches
    char_positions = {}
    for i, ch in enumerate(CT):
        if ch not in char_positions:
            char_positions[ch] = []
        # Find all positions of this char in non-K4 text
        for j, c in enumerate(non_k4_flat):
            if c == ch:
                char_positions[ch].append(j)

    total_positions = sum(len(v) for v in char_positions.values())
    avg_per_char = total_positions / len(char_positions)
    print(f"  Avg positions per unique char: {avg_per_char:.1f}")

    # Step 6: Wrap-around aperture on K4-length windows
    print()
    print("Step 6: Sliding window aperture (97-char windows from Antipodes)")
    print("-" * 48)

    best_score_step6 = 0
    configs_step6 = 0

    # Slide a 97-char window across Antipodes and check for cribs
    for start in range(ANTIPODES_LEN - CT_LEN + 1):
        window = ANTIPODES_FLAT[start:start + CT_LEN]
        configs_step6 += 1

        # Direct window
        fscore = score_free_fast(window)
        if fscore > 0:
            if fscore > best_score_step6:
                best_score_step6 = fscore
                print(f"  HIT: start={start}, score={fscore}/24, "
                      f"text={window[:40]}...")

        # XOR-like: for each position, subtract K4 char to get a "key"
        # and check if the key pattern has structure

    # Also try: take chars NOT in any 97-char window
    for start in range(0, ANTIPODES_LEN - CT_LEN + 1, 50):
        window_set = set(range(start, start + CT_LEN))
        residue = ''.join(ANTIPODES_FLAT[i] for i in range(ANTIPODES_LEN)
                         if i not in window_set)
        rscore = score_free_fast(residue)
        if rscore > 0:
            print(f"  HIT (residue): window_start={start}, score={rscore}/24")
            if rscore > best_score_step6:
                best_score_step6 = rscore

    print(f"  Window configs: {configs_step6}, Best: {best_score_step6}/24")
    print()

    # Step 7: Check if K4 XOR with any Antipodes window gives English
    print("Step 7: K4 XOR with Antipodes windows (running key model)")
    print("-" * 48)

    best_score_step7 = 0

    for start in range(ANTIPODES_LEN - CT_LEN + 1):
        window = ANTIPODES_FLAT[start:start + CT_LEN]

        # Vigenere decrypt: PT = (CT - KEY) mod 26
        pt_vig = ''
        for c, k in zip(CT, window):
            pt_vig += ALPH[(ord(c) - ord(k)) % 26]

        fscore = score_free_fast(pt_vig)
        if fscore > 0:
            result = score_free(pt_vig)
            if fscore > best_score_step7:
                best_score_step7 = fscore
                print(f"  HIT (Vig): start={start}, score={fscore}/24")
                if result.ene_found:
                    print(f"    ENE at: {result.ene_offsets}")
                if result.bc_found:
                    print(f"    BC at: {result.bc_offsets}")

        # Beaufort: PT = (KEY - CT) mod 26
        pt_beau = ''
        for c, k in zip(CT, window):
            pt_beau += ALPH[(ord(k) - ord(c)) % 26]

        fscore_b = score_free_fast(pt_beau)
        if fscore_b > 0:
            result_b = score_free(pt_beau)
            if fscore_b > best_score_step7:
                best_score_step7 = fscore_b
                print(f"  HIT (Beau): start={start}, score={fscore_b}/24")
                if result_b.ene_found:
                    print(f"    ENE at: {result_b.ene_offsets}")
                if result_b.bc_found:
                    print(f"    BC at: {result_b.bc_offsets}")

    print(f"  Best running-key score: {best_score_step7}/24")
    print()

    # Summary
    all_bests = [best_score_step2, best_score_step3, best_score_step4,
                 best_score_step6, best_score_step7]
    overall_best = max(all_bests)

    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Step 2 (every-Nth): {best_score_step2}/24")
    print(f"Step 3 (columns): {best_score_step3}/24")
    print(f"Step 4 (diagonals): {best_score_step4}/24")
    print(f"Step 6 (sliding window): {best_score_step6}/24")
    print(f"Step 7 (running key): {best_score_step7}/24")
    print(f"Overall best: {overall_best}/24")
    print()

    if overall_best >= 24:
        print("*** BREAKTHROUGH: Both cribs found! ***")
    elif overall_best >= 13:
        print("*** SIGNAL: One full crib found. ***")
    elif overall_best >= 11:
        print("INTERESTING: Partial crib match.")
    else:
        print("NOISE: No crib content found under Cardan aperture model.")
        print("Remaining open: non-linear mask patterns, multi-layer masks,")
        print("masks derived from physical sculpture features.")

    # Save
    os.makedirs("results/audit", exist_ok=True)
    output = {
        "experiment": "E-AUDIT-04",
        "description": "Cardan-style aperture extraction from Antipodes",
        "antipodes_length": ANTIPODES_LEN,
        "overall_best": overall_best,
        "step2_best": best_score_step2,
        "step3_best": best_score_step3,
        "step4_best": best_score_step4,
        "step6_best": best_score_step6,
        "step7_best": best_score_step7,
    }
    with open("results/audit/e_audit_04_cardan_aperture.json", "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to results/audit/e_audit_04_cardan_aperture.json")


if __name__ == "__main__":
    run_cardan_aperture()
