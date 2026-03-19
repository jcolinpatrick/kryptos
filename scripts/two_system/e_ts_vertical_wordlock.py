#!/usr/bin/env python3
"""
Cipher: vertical word lock (cylindrical rotation, vertical alignment)
Family: two_system
Status: active
Keyspace: ~50M configs
Last run:
Best score:

Giant Word Lock hypothesis: the 28x31 master cipher grid is a cylinder
where each row rotates independently. The correct 28 rotation offsets
produce a meaningful 28-character string reading vertically down one of
the 31 columns, AND the K4 crib characters land at their correct positions.

Three stages:
  C - Crib-Anchored: use K4 cribs to constrain K4-row rotations, sweep
      non-K4 rows, score vertical columns.
  A - Dictionary/Phrase: try known 28-char verticals and check feasibility.
  B - Beam Search: build verticals character-by-character with ngram scoring.
"""
import sys
import os
import json
import time
import math
from collections import defaultdict

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH, ALPH_IDX

# ── Panel data (28 rows, from cylinder_viewer.js) ────────────────────────
PANEL_ROWS = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",   # 0   K1
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",   # 1   K1
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNC",    # 2   K1 ends col 0, K2 starts col 1
    "EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",   # 3   K2 (has ?)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",    # 4   K2
    "QZGZLECGYUXUEENJTBJLBQCRTBJDFHR",    # 5   K2
    "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT",    # 6   K2
    "IHHDDDUVH?DWKBFUFPWNTDFIYCUQZER",    # 7   K2 (has ?)
    "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI",    # 8   K2
    "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK",    # 9   K2
    "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",    # 10  K2
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",    # 11  K2
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",    # 12  K2
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",    # 13  K2 ends
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",    # 14  K3
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",    # 15  K3
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",     # 16  K3
    "WMTWNDITEENRAHCTENEUDRETNHAEOET",     # 17  K3
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",    # 18  K3
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT",     # 19  K3
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI",     # 20  K3
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",    # 21  K3
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",    # 22  K3
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",    # 23  K3
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",    # 24  K3 ends, K4 starts col 27 (has ?)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",    # 25  K4
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",    # 26  K4
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",   # 27  K4 ends
]

NUM_ROWS = 28
WINDOW = 31

K4_GLOBAL_START = 24 * WINDOW + 27  # = 771
K4_ROWS = [24, 25, 26, 27]

# ── Precompute row lengths and char-position indices ─────────────────────
ROW_LENS = [len(r) for r in PANEL_ROWS]

# For each row, map char -> list of positions where it appears
ROW_CHAR_POS = []
for ri in range(NUM_ROWS):
    d = defaultdict(list)
    for ci, ch in enumerate(PANEL_ROWS[ri]):
        d[ch].append(ci)
    ROW_CHAR_POS.append(dict(d))

# ── Map crib positions to grid coordinates ───────────────────────────────
# CRIB_DICT maps K4 position -> expected plaintext char
# We need to know: for each crib position, which (row, col) in the grid
CRIB_GRID = {}  # {k4_pos: (row, col, expected_char)}
CRIB_BY_ROW = defaultdict(list)  # {row: [(col, expected_char, k4_pos), ...]}
for k4_pos, expected_char in CRIB_DICT.items():
    g = K4_GLOBAL_START + k4_pos
    r = g // WINDOW
    c = g % WINDOW
    CRIB_GRID[k4_pos] = (r, c, expected_char)
    CRIB_BY_ROW[r].append((c, expected_char, k4_pos))

N_CRIB_CHARS = len(CRIB_DICT)  # 24

# ── Load quadgrams ──────────────────────────────────────────────────────
QUADGRAMS = None
QUADGRAM_FLOOR = -10.0

def load_quadgrams():
    global QUADGRAMS, QUADGRAM_FLOOR
    qpath = os.path.join(_ROOT, "data", "english_quadgrams.json")
    if os.path.exists(qpath):
        print(f"[INFO] Loading quadgrams from {qpath} ...", flush=True)
        with open(qpath) as f:
            QUADGRAMS = json.load(f)
        # Floor = worst observed value - 1
        if QUADGRAMS:
            QUADGRAM_FLOOR = min(QUADGRAMS.values()) - 1.0
        print(f"[INFO] Loaded {len(QUADGRAMS)} quadgrams, floor={QUADGRAM_FLOOR:.2f}", flush=True)
        return True
    else:
        print("[WARN] Quadgram file not found, using letter frequency fallback", flush=True)
        return False

# English letter frequencies (log-prob)
ENGLISH_FREQ = {
    'A': -1.129, 'B': -2.818, 'C': -2.200, 'D': -1.942, 'E': -0.828,
    'F': -1.962, 'G': -2.470, 'H': -1.471, 'I': -1.183, 'J': -3.745,
    'K': -3.117, 'L': -1.624, 'M': -2.017, 'N': -1.172, 'O': -1.118,
    'P': -2.305, 'Q': -4.036, 'R': -1.201, 'S': -1.104, 'T': -1.020,
    'U': -2.102, 'V': -2.927, 'W': -2.016, 'X': -3.509, 'Y': -2.032,
    'Z': -3.879
}

def score_quadgrams(text):
    """Score a text string using quadgram log-probabilities. Higher = more English-like."""
    if not text or len(text) < 4:
        return -999.0
    # Only score alphabetic characters
    clean = ''.join(c for c in text.upper() if c in ALPH)
    if len(clean) < 4:
        return -999.0
    if QUADGRAMS:
        total = 0.0
        for i in range(len(clean) - 3):
            qg = clean[i:i+4]
            total += QUADGRAMS.get(qg, QUADGRAM_FLOOR)
        return total / (len(clean) - 3)  # Normalize by number of quadgrams
    else:
        # Fallback: letter frequency score
        total = sum(ENGLISH_FREQ.get(c, -5.0) for c in clean)
        return total / len(clean)

def score_bigrams_partial(text):
    """Simple bigram-quality heuristic for partial strings during beam search."""
    if not text or len(text) < 2:
        return 0.0
    clean = ''.join(c for c in text.upper() if c in ALPH)
    if len(clean) < 2:
        return 0.0
    if QUADGRAMS and len(clean) >= 4:
        total = 0.0
        for i in range(len(clean) - 3):
            qg = clean[i:i+4]
            total += QUADGRAMS.get(qg, QUADGRAM_FLOOR)
        return total / (len(clean) - 3)
    else:
        # Letter frequency fallback
        total = sum(ENGLISH_FREQ.get(c, -5.0) for c in clean)
        return total / len(clean)


# ── Core helpers ────────────────────────────────────────────────────────
def visible_char(row_idx, col, rotation):
    """Return the character visible at column `col` when row is rotated by `rotation`.

    Rotation convention: positive rotation shifts the row to the RIGHT,
    meaning the character that was at position p now appears at position (p + rotation) % row_len.
    To find what's visible at column col: look at source index (col - rotation) % row_len.
    """
    row = PANEL_ROWS[row_idx]
    n = ROW_LENS[row_idx]
    src = (col - rotation) % n
    return row[src]


def rotations_for_char(row_idx, col, target_char):
    """Return list of rotation amounts that place `target_char` at column `col`.

    If target_char is at original position p in the row, then to place it at column col,
    we need rotation = (col - p) % row_len.
    """
    positions = ROW_CHAR_POS[row_idx].get(target_char, [])
    n = ROW_LENS[row_idx]
    return [(col - p) % n for p in positions]


def read_vertical(col, rotations):
    """Return the 28-char string reading down column `col` with given rotations."""
    chars = []
    for ri in range(NUM_ROWS):
        chars.append(visible_char(ri, col, rotations[ri]))
    return ''.join(chars)


def score_k4_cribs(rotations):
    """Score how many K4 crib characters match after applying rotations to K4 rows.

    For each crib position p (0-indexed in K4), compute the grid (row, col),
    then check if visible_char(row, col, rotations[row]) matches the expected crib char.

    Returns (matched_count, total_crib_chars).
    """
    matched = 0
    for k4_pos, (r, c, expected) in CRIB_GRID.items():
        actual = visible_char(r, c, rotations[r])
        if actual == expected:
            matched += 1
    return matched


def find_consistent_rotation(row_idx, crib_entries):
    """Given a list of (col, expected_char) for a row, find rotation(s) consistent with ALL.

    Returns list of rotations that satisfy all constraints simultaneously.
    If empty, no single rotation can satisfy all crib chars on this row.
    """
    if not crib_entries:
        return list(range(ROW_LENS[row_idx]))  # Any rotation works

    # Start with rotations valid for the first constraint
    col0, char0 = crib_entries[0][:2]
    candidates = set(rotations_for_char(row_idx, col0, char0))

    # Intersect with rotations for each subsequent constraint
    for col_i, char_i in [(e[0], e[1]) for e in crib_entries[1:]]:
        rots_i = set(rotations_for_char(row_idx, col_i, char_i))
        candidates &= rots_i
        if not candidates:
            return []

    return sorted(candidates)


# ══════════════════════════════════════════════════════════════════════════
# STAGE C: Crib-Anchored
# ══════════════════════════════════════════════════════════════════════════
def stage_c():
    """Use K4 cribs to constrain K4-row rotations, then sweep non-K4 rows.

    For rows with crib constraints (25, 26, 27), find the rotation(s) that
    make all crib characters land correctly. Row 24 has no cribs.

    For each valid K4-row rotation set, for each column c (0-30):
      - For each non-K4 row (0-23), try all 31 rotations
      - But that's 31^24 which is too many.
      - Instead: just report the vertical at each column for the crib-consistent rotations,
        using rotation=0 for non-K4 rows, and also try all 31 rotations for row 24.
      - Score verticals by quadgram quality.
    """
    print("=" * 72, flush=True)
    print("STAGE C: Crib-Anchored Search", flush=True)
    print("=" * 72, flush=True)

    results = []
    configs_tested = 0
    best_crib = 0

    # Find crib-consistent rotations for K4 rows
    # Row 24: no cribs -> any rotation
    # Row 25: 13 ENE crib chars (cols 17-29)
    # Row 26: 3 BCL crib chars (cols 28-30)
    # Row 27: 8 BCL crib chars (cols 0-7)

    row25_consistent = find_consistent_rotation(25, CRIB_BY_ROW[25])
    row26_consistent = find_consistent_rotation(26, CRIB_BY_ROW[26])
    row27_consistent = find_consistent_rotation(27, CRIB_BY_ROW[27])

    print(f"  Row 25 consistent rotations ({len(CRIB_BY_ROW[25])} crib chars): {row25_consistent}", flush=True)
    print(f"  Row 26 consistent rotations ({len(CRIB_BY_ROW[26])} crib chars): {row26_consistent}", flush=True)
    print(f"  Row 27 consistent rotations ({len(CRIB_BY_ROW[27])} crib chars): {row27_consistent}", flush=True)

    if not row25_consistent or not row26_consistent or not row27_consistent:
        print("  [WARN] No consistent rotation found for one or more crib rows!", flush=True)
        print("  This means the crib characters cannot all land correctly with any single rotation.", flush=True)
        # Still continue with partial constraints

    # For each combination of valid K4-row rotations
    r24_options = list(range(ROW_LENS[24]))  # 31 options (no crib constraint)
    r25_options = row25_consistent if row25_consistent else [0]
    r26_options = row26_consistent if row26_consistent else [0]
    r27_options = row27_consistent if row27_consistent else [0]

    total_k4_combos = len(r24_options) * len(r25_options) * len(r26_options) * len(r27_options)
    print(f"  Total K4-row rotation combos: {total_k4_combos}", flush=True)
    print(f"  x 31 columns = {total_k4_combos * WINDOW} vertical checks", flush=True)
    print(flush=True)

    # We'll check ALL columns for each K4-row rotation combo
    # Non-K4 rows are fixed at rotation=0 for this stage
    # (we can't search 31^24 combos for the non-K4 rows)

    for rot25 in r25_options:
        for rot26 in r26_options:
            for rot27 in r27_options:
                for rot24 in r24_options:
                    # Build rotation array: 0 for non-K4 rows, specific for K4 rows
                    rotations = [0] * NUM_ROWS
                    rotations[24] = rot24
                    rotations[25] = rot25
                    rotations[26] = rot26
                    rotations[27] = rot27

                    crib_score = score_k4_cribs(rotations)

                    for col in range(WINDOW):
                        configs_tested += 1
                        vertical = read_vertical(col, rotations)
                        ngram = score_quadgrams(vertical)

                        if crib_score > best_crib:
                            best_crib = crib_score

                        if crib_score > 5 or ngram > -6.0:
                            entry = {
                                "vertical": vertical,
                                "column": col,
                                "rotations": rotations[:],
                                "crib_score": crib_score,
                                "ngram_score": round(ngram, 3),
                                "method": "stage_c",
                                "detail": f"rot24={rot24},rot25={rot25},rot26={rot26},rot27={rot27}"
                            }
                            results.append(entry)
                            if crib_score > 5:
                                print(f"  [HIT] col={col} crib={crib_score}/{N_CRIB_CHARS} "
                                      f"ngram={ngram:.3f} V={vertical} "
                                      f"rots=24:{rot24},25:{rot25},26:{rot26},27:{rot27}", flush=True)

                    if configs_tested % 10000 == 0:
                        print(f"  Stage C progress: {configs_tested} configs, best_crib={best_crib}", flush=True)

    # Also try: for each column, find the BEST non-K4 row rotation by trying
    # to maximize quadgram quality of the vertical (greedy per-row)
    print(f"\n  Stage C greedy: optimizing non-K4 rows per column...", flush=True)

    for rot25 in r25_options:
        for rot26 in r26_options:
            for rot27 in r27_options:
                for col in range(WINDOW):
                    # Greedy: for each non-K4 row, pick the rotation that
                    # yields the best-scoring character given what we have so far
                    best_rot24 = 0
                    best_rot24_score = -999

                    # Try all rot24 values, pick best vertical quality
                    for rot24 in r24_options:
                        rotations = [0] * NUM_ROWS
                        rotations[24] = rot24
                        rotations[25] = rot25
                        rotations[26] = rot26
                        rotations[27] = rot27

                        # Greedy: for non-K4 rows, pick best char by frequency
                        for ri in range(24):
                            best_freq = -999
                            best_ri_rot = 0
                            for rot_try in range(ROW_LENS[ri]):
                                ch = visible_char(ri, col, rot_try)
                                freq = ENGLISH_FREQ.get(ch, -5.0)
                                if freq > best_freq:
                                    best_freq = freq
                                    best_ri_rot = rot_try
                            rotations[ri] = best_ri_rot

                        vertical = read_vertical(col, rotations)
                        ngram = score_quadgrams(vertical)
                        crib_score = score_k4_cribs(rotations)
                        configs_tested += 1

                        if ngram > best_rot24_score:
                            best_rot24_score = ngram
                            best_entry = {
                                "vertical": vertical,
                                "column": col,
                                "rotations": rotations[:],
                                "crib_score": crib_score,
                                "ngram_score": round(ngram, 3),
                                "method": "stage_c_greedy",
                                "detail": f"rot25={rot25},rot26={rot26},rot27={rot27}"
                            }

                    if best_rot24_score > -7.0:
                        results.append(best_entry)
                        if best_entry["crib_score"] > best_crib:
                            best_crib = best_entry["crib_score"]

    # Sort results by crib score desc, then ngram desc
    results.sort(key=lambda x: (-x["crib_score"], -x["ngram_score"]))
    top_results = results[:50]

    print(f"\n  Stage C complete: {configs_tested} configs tested", flush=True)
    print(f"  Best crib score: {best_crib}/{N_CRIB_CHARS}", flush=True)
    print(f"  Total results collected: {len(results)}", flush=True)
    if top_results:
        print(f"  Top 5 results:", flush=True)
        for r in top_results[:5]:
            print(f"    crib={r['crib_score']} ngram={r['ngram_score']:.3f} "
                  f"col={r['column']} V={r['vertical']} [{r['method']}]", flush=True)

    return {
        "configs": configs_tested,
        "best_crib": best_crib,
        "best_results": top_results
    }


# ══════════════════════════════════════════════════════════════════════════
# STAGE A: Dictionary + Phrase Search
# ══════════════════════════════════════════════════════════════════════════
def stage_a():
    """Try known words/phrases as 28-char vertical targets."""
    print("\n" + "=" * 72, flush=True)
    print("STAGE A: Dictionary + Phrase Search", flush=True)
    print("=" * 72, flush=True)

    results = []
    configs_tested = 0
    best_crib = 0

    # Build candidate 28-char vertical strings
    candidates = set()

    # 1. Repeated thematic keywords
    thematic_path = os.path.join(_ROOT, "wordlists", "thematic_keywords.txt")
    thematic_words = []
    if os.path.exists(thematic_path):
        with open(thematic_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    w = line.upper()
                    if w.isalpha():
                        thematic_words.append(w)
        print(f"  Loaded {len(thematic_words)} thematic keywords", flush=True)

    # Generate repeated/padded versions to 28 chars
    all_keywords = list(set(thematic_words + [
        "KRYPTOS", "SEVEN", "PALIMPSEST", "ABSCISSA", "DEFECTOR",
        "BERLINCLOCK", "EASTNORTHEAST", "IQLUSION", "SANBORN",
        "SCHEIDT", "LANGLEY", "CIA", "COMPASS", "ENIGMA",
        "HOROLOGE", "KOMPASS", "COLOPHON", "WELTZEITUHR",
    ]))

    for w in all_keywords:
        if len(w) == 0:
            continue
        # Repeat to fill 28 chars
        repeated = (w * (28 // len(w) + 1))[:28]
        candidates.add(repeated)
        # Also try single word padded with A's or X's (less likely but cheap)
        if len(w) <= 28:
            candidates.add(w.ljust(28, 'A'))
            candidates.add(w.ljust(28, 'X'))

    # Some specific 28-char candidates
    candidates.add("KRYPTOSKRYPTOSKRYPTOSKRYPTOS")  # 7*4 = 28
    candidates.add("SEVENSEVENSEVENSEVENSEVENSEV")   # 5*5+3 = 28
    candidates.add("ABCDEFGHIJKLMNOPQRSTUVWXYZAB")   # Alphabet + 2
    candidates.add("KRYPTOSABCDEFGHIJLMNQUVWXZAB")   # KA + 2

    # 2. 28-letter words from english.txt
    english_path = os.path.join(_ROOT, "wordlists", "english.txt")
    long_words_count = 0
    if os.path.exists(english_path):
        print(f"  Scanning english.txt for 28-letter words...", flush=True)
        with open(english_path) as f:
            for line in f:
                w = line.strip().upper()
                if len(w) == 28 and w.isalpha():
                    candidates.add(w)
                    long_words_count += 1
                # Also collect words of length 14 (repeat x2 = 28)
                elif len(w) == 14 and w.isalpha():
                    candidates.add(w * 2)
                # Length 7 (repeat x4 = 28)
                elif len(w) == 7 and w.isalpha():
                    candidates.add(w * 4)
                # Length 4 (repeat x7 = 28)
                elif len(w) == 4 and w.isalpha():
                    candidates.add(w * 7)
        print(f"  Found {long_words_count} exact 28-letter words", flush=True)

    # 3. Thematic keyword combinations
    # Pairs that sum to 28
    for i, w1 in enumerate(all_keywords):
        for w2 in all_keywords[i:]:
            if len(w1) + len(w2) == 28:
                candidates.add(w1 + w2)
                candidates.add(w2 + w1)

    print(f"  Total candidates: {len(candidates)}", flush=True)
    print(f"  Testing each against 31 columns...", flush=True)

    checked = 0
    for cand in candidates:
        if len(cand) != 28:
            continue

        cand_upper = cand.upper()

        for col in range(WINDOW):
            configs_tested += 1

            # Check feasibility: does each char appear in the corresponding row?
            feasible = True
            rotations = [0] * NUM_ROWS

            for ri in range(NUM_ROWS):
                target_ch = cand_upper[ri]
                rots = rotations_for_char(ri, col, target_ch)
                if not rots:
                    feasible = False
                    break
                # Pick the first valid rotation (we'll check crib consistency below)
                rotations[ri] = rots[0]

            if not feasible:
                continue

            # Feasible! Check crib score.
            # But wait — there may be multiple rotation choices per row.
            # For K4 rows with cribs, we need to check if ANY rotation choice
            # for the target vertical char is also crib-consistent.

            # First, get crib-consistent rotations for K4 rows
            best_crib_for_this = 0
            best_rots_for_this = None

            # For each K4 row, find rotations that place the target char at col
            # AND satisfy crib constraints
            k4_row_options = {}
            for ri in K4_ROWS:
                target_ch = cand_upper[ri]
                char_rots = set(rotations_for_char(ri, col, target_ch))
                crib_rots = set(find_consistent_rotation(ri, CRIB_BY_ROW.get(ri, [])))
                compatible = char_rots & crib_rots
                if compatible:
                    k4_row_options[ri] = sorted(compatible)
                else:
                    # Can't satisfy both vertical target and cribs for this row
                    k4_row_options[ri] = sorted(char_rots)  # Use vertical target only

            # Build rotations: use crib-compatible for K4 rows when possible
            for ri in K4_ROWS:
                target_ch = cand_upper[ri]
                rots = rotations_for_char(ri, col, target_ch)
                if ri in k4_row_options and k4_row_options[ri]:
                    rotations[ri] = k4_row_options[ri][0]
                elif rots:
                    rotations[ri] = rots[0]

            crib_score = score_k4_cribs(rotations)
            ngram = score_quadgrams(cand_upper)

            if crib_score > best_crib:
                best_crib = crib_score

            if crib_score > 3 or ngram > -5.5:
                entry = {
                    "vertical": cand_upper,
                    "column": col,
                    "rotations": rotations[:],
                    "crib_score": crib_score,
                    "ngram_score": round(ngram, 3),
                    "method": "stage_a"
                }
                results.append(entry)
                if crib_score > 3:
                    print(f"  [HIT] col={col} crib={crib_score}/{N_CRIB_CHARS} "
                          f"ngram={ngram:.3f} V={cand_upper}", flush=True)

        checked += 1
        if checked % 5000 == 0:
            print(f"  Stage A progress: {checked}/{len(candidates)} candidates, "
                  f"{configs_tested} configs, best_crib={best_crib}", flush=True)

    results.sort(key=lambda x: (-x["crib_score"], -x["ngram_score"]))
    top_results = results[:50]

    print(f"\n  Stage A complete: {configs_tested} configs tested", flush=True)
    print(f"  Best crib score: {best_crib}/{N_CRIB_CHARS}", flush=True)
    print(f"  Total results collected: {len(results)}", flush=True)
    if top_results:
        print(f"  Top 5 results:", flush=True)
        for r in top_results[:5]:
            print(f"    crib={r['crib_score']} ngram={r['ngram_score']:.3f} "
                  f"col={r['column']} V={r['vertical']} [{r['method']}]", flush=True)

    return {
        "configs": configs_tested,
        "best_crib": best_crib,
        "best_results": top_results
    }


# ══════════════════════════════════════════════════════════════════════════
# STAGE B: Beam Search
# ══════════════════════════════════════════════════════════════════════════
def stage_b():
    """Beam search building 28-char vertical strings character-by-character."""
    print("\n" + "=" * 72, flush=True)
    print("STAGE B: Beam Search (per-column)", flush=True)
    print("=" * 72, flush=True)

    BEAM_WIDTH = 500
    results = []
    configs_tested = 0
    best_crib = 0

    # Precompute: for each row and column, what characters are available?
    # Each rotation gives a different char at that column.
    # row_col_chars[ri][col] = list of (char, rotation) pairs
    row_col_chars = []
    for ri in range(NUM_ROWS):
        col_map = {}
        n = ROW_LENS[ri]
        for col in range(WINDOW):
            chars = []
            seen = set()
            for rot in range(n):
                ch = visible_char(ri, col, rot)
                if ch not in seen:  # Deduplicate (same char from different rotations)
                    chars.append((ch, rot))
                    seen.add(ch)
                else:
                    # Keep all rotations even for duplicate chars (needed for crib checking)
                    chars.append((ch, rot))
            col_map[col] = chars
        row_col_chars.append(col_map)

    # Precompute unique chars per row/col (for beam expansion, we only need unique chars)
    row_col_unique = []
    for ri in range(NUM_ROWS):
        col_map = {}
        n = ROW_LENS[ri]
        for col in range(WINDOW):
            unique = {}
            for rot in range(n):
                ch = visible_char(ri, col, rot)
                if ch not in unique:
                    unique[ch] = rot  # Store first rotation that gives this char
            col_map[col] = unique  # {char: rotation}
        row_col_unique.append(col_map)

    for col in range(WINDOW):
        # Beam: each element is (score, partial_string, rotations_list)
        # Start with empty
        beam = [(0.0, "", [])]

        for ri in range(NUM_ROWS):
            new_beam = []
            unique_chars = row_col_unique[ri][col]  # {char: rotation}

            for score, partial, rots in beam:
                for ch, rot in unique_chars.items():
                    new_partial = partial + ch
                    new_rots = rots + [rot]

                    # Score the partial string
                    if len(new_partial) >= 4:
                        new_score = score_bigrams_partial(new_partial)
                    else:
                        # For < 4 chars, use letter frequency
                        new_score = sum(ENGLISH_FREQ.get(c, -5.0) for c in new_partial if c in ENGLISH_FREQ)
                        if new_partial:
                            new_score /= len(new_partial)

                    new_beam.append((new_score, new_partial, new_rots))
                    configs_tested += 1

            # Prune to beam width
            new_beam.sort(key=lambda x: -x[0])
            beam = new_beam[:BEAM_WIDTH]

        # Score completed verticals
        col_results = []
        for score, vertical, rots in beam:
            crib_score = score_k4_cribs(rots)
            ngram = score_quadgrams(vertical)

            if crib_score > best_crib:
                best_crib = crib_score

            entry = {
                "vertical": vertical,
                "column": col,
                "rotations": rots[:],
                "crib_score": crib_score,
                "ngram_score": round(ngram, 3),
                "method": "stage_b"
            }
            col_results.append(entry)

            if crib_score > 5:
                print(f"  [HIT] col={col} crib={crib_score}/{N_CRIB_CHARS} "
                      f"ngram={ngram:.3f} V={vertical}", flush=True)

        # Keep top 20 per column
        col_results.sort(key=lambda x: (-x["crib_score"], -x["ngram_score"]))
        results.extend(col_results[:20])

        if (col + 1) % 5 == 0 or col == 0:
            print(f"  Stage B progress: col {col}/{WINDOW-1}, "
                  f"{configs_tested} configs, best_crib={best_crib}", flush=True)

    # Now do a crib-focused beam search: for K4 rows (24-27), constrain rotations
    # to be crib-consistent, then beam-search the non-K4 rows
    print(f"\n  Stage B crib-focused: constraining K4 rows to crib-consistent rotations...", flush=True)

    row25_consistent = find_consistent_rotation(25, CRIB_BY_ROW[25])
    row26_consistent = find_consistent_rotation(26, CRIB_BY_ROW[26])
    row27_consistent = find_consistent_rotation(27, CRIB_BY_ROW[27])

    for col in range(WINDOW):
        for rot25 in row25_consistent:
            for rot26 in row26_consistent:
                for rot27 in row27_consistent:
                    for rot24 in range(ROW_LENS[24]):
                        # Fixed K4 rotations
                        fixed_k4 = {24: rot24, 25: rot25, 26: rot26, 27: rot27}

                        # Beam search over non-K4 rows (0-23)
                        beam = [(0.0, "", [])]

                        for ri in range(NUM_ROWS):
                            if ri in fixed_k4:
                                # Use fixed rotation
                                rot = fixed_k4[ri]
                                ch = visible_char(ri, col, rot)
                                new_beam = []
                                for score, partial, rots in beam:
                                    new_partial = partial + ch
                                    new_rots = rots + [rot]
                                    if len(new_partial) >= 4:
                                        new_score = score_bigrams_partial(new_partial)
                                    else:
                                        new_score = sum(ENGLISH_FREQ.get(c, -5.0)
                                                        for c in new_partial if c in ENGLISH_FREQ)
                                        if new_partial:
                                            new_score /= len(new_partial)
                                    new_beam.append((new_score, new_partial, new_rots))
                                    configs_tested += 1
                                beam = new_beam
                            else:
                                unique_chars = row_col_unique[ri][col]
                                new_beam = []
                                for score, partial, rots in beam:
                                    for ch, rot in unique_chars.items():
                                        new_partial = partial + ch
                                        new_rots = rots + [rot]
                                        if len(new_partial) >= 4:
                                            new_score = score_bigrams_partial(new_partial)
                                        else:
                                            new_score = sum(ENGLISH_FREQ.get(c, -5.0)
                                                            for c in new_partial if c in ENGLISH_FREQ)
                                            if new_partial:
                                                new_score /= len(new_partial)
                                        new_beam.append((new_score, new_partial, new_rots))
                                        configs_tested += 1
                                new_beam.sort(key=lambda x: -x[0])
                                beam = new_beam[:BEAM_WIDTH]

                        # Score completed verticals
                        for score, vertical, rots in beam[:5]:  # Top 5 per combo
                            crib_score = score_k4_cribs(rots)
                            ngram = score_quadgrams(vertical)

                            if crib_score > best_crib:
                                best_crib = crib_score

                            if crib_score > 5 or ngram > -6.0:
                                entry = {
                                    "vertical": vertical,
                                    "column": col,
                                    "rotations": rots[:],
                                    "crib_score": crib_score,
                                    "ngram_score": round(ngram, 3),
                                    "method": "stage_b_crib_focused"
                                }
                                results.append(entry)

                                if crib_score > 5:
                                    print(f"  [HIT] col={col} crib={crib_score}/{N_CRIB_CHARS} "
                                          f"ngram={ngram:.3f} V={vertical}", flush=True)

        if (col + 1) % 5 == 0 or col == 0:
            print(f"  Stage B crib-focused progress: col {col}/{WINDOW-1}, "
                  f"{configs_tested} configs, best_crib={best_crib}", flush=True)

    results.sort(key=lambda x: (-x["crib_score"], -x["ngram_score"]))
    top_results = results[:50]

    print(f"\n  Stage B complete: {configs_tested} configs tested", flush=True)
    print(f"  Best crib score: {best_crib}/{N_CRIB_CHARS}", flush=True)
    print(f"  Total results collected: {len(results)}", flush=True)
    if top_results:
        print(f"  Top 5 results:", flush=True)
        for r in top_results[:5]:
            print(f"    crib={r['crib_score']} ngram={r['ngram_score']:.3f} "
                  f"col={r['column']} V={r['vertical']} [{r['method']}]", flush=True)

    return {
        "configs": configs_tested,
        "best_crib": best_crib,
        "best_results": top_results
    }


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════
def main():
    t0 = time.time()

    print("=" * 72, flush=True)
    print("VERTICAL WORD LOCK — Giant Cylinder Hypothesis", flush=True)
    print("=" * 72, flush=True)
    print(f"  Panel: {NUM_ROWS} rows, window={WINDOW}", flush=True)
    print(f"  Row lengths: {ROW_LENS}", flush=True)
    print(f"  K4 starts at global pos {K4_GLOBAL_START} (row 24, col 27)", flush=True)
    print(f"  K4 length: {CT_LEN}", flush=True)
    print(f"  Crib positions: {sorted(CRIB_DICT.keys())}", flush=True)
    print(f"  Crib chars by row: " + ", ".join(
        f"row {r}: {len(v)} chars" for r, v in sorted(CRIB_BY_ROW.items())
    ), flush=True)
    print(f"  Rows with '?': {[i for i, r in enumerate(PANEL_ROWS) if '?' in r]}", flush=True)
    print(flush=True)

    # Verify K4 readback
    k4_readback = ""
    for p in range(CT_LEN):
        g = K4_GLOBAL_START + p
        r, c = g // WINDOW, g % WINDOW
        k4_readback += PANEL_ROWS[r][c]
    assert k4_readback == CT, f"K4 readback mismatch!\n  Got:    {k4_readback}\n  Expect: {CT}"
    print("  [OK] K4 readback from grid matches CT", flush=True)
    print(flush=True)

    has_quadgrams = load_quadgrams()
    print(flush=True)

    # Run stages
    stage_c_results = stage_c()
    stage_a_results = stage_a()
    stage_b_results = stage_b()

    elapsed = time.time() - t0

    overall_best_crib = max(
        stage_c_results["best_crib"],
        stage_a_results["best_crib"],
        stage_b_results["best_crib"]
    )

    # Compile output
    output = {
        "stage_c": stage_c_results,
        "stage_a": stage_a_results,
        "stage_b": stage_b_results,
        "overall_best_crib": overall_best_crib,
        "elapsed_seconds": round(elapsed, 2)
    }

    # Write results
    results_dir = os.path.join(_ROOT, "results")
    os.makedirs(results_dir, exist_ok=True)
    out_path = os.path.join(results_dir, "e_ts_vertical_wordlock.json")
    with open(out_path, "w") as f:
        json.dump(output, f, indent=2)

    print("\n" + "=" * 72, flush=True)
    print("FINAL SUMMARY", flush=True)
    print("=" * 72, flush=True)
    print(f"  Stage C: {stage_c_results['configs']} configs, best crib = {stage_c_results['best_crib']}/{N_CRIB_CHARS}", flush=True)
    print(f"  Stage A: {stage_a_results['configs']} configs, best crib = {stage_a_results['best_crib']}/{N_CRIB_CHARS}", flush=True)
    print(f"  Stage B: {stage_b_results['configs']} configs, best crib = {stage_b_results['best_crib']}/{N_CRIB_CHARS}", flush=True)
    print(f"  Overall best crib: {overall_best_crib}/{N_CRIB_CHARS}", flush=True)
    print(f"  Elapsed: {elapsed:.1f}s", flush=True)
    print(f"  Results written to: {out_path}", flush=True)
    print(flush=True)


if __name__ == "__main__":
    main()
