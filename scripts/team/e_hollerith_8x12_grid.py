#!/usr/bin/env python3
"""
Experiment: Hollerith 8x12 Punch Card Model for K4
===================================================
Cipher:    Two-system (null insertion + substitution)
Family:    team
Status:    active
Keyspace:  Phase 1: 220×8×2=3,520 | Phase 2: ~24×8×2=384 | Phase 3: ~40×8×2=640 | Phase 4: constrained
Last run:  never
Best score: n/a

MODEL:
  Legal pad says "8 lines 73" for K4. 97-73=24 nulls.
  Arrange first 96 chars as 8 rows x 12 columns (pos 96='R' always kept).
  Punch 3 columns per row (3x8=24 nulls). Remove punched positions -> 73-char real CT.
  Then Vigenere/Beaufort decrypt with candidate keywords.

PHASES:
  1. Same 3 columns in every row: C(12,3)=220 uniform masks
  2. Keyword-driven column selection (mod 12 arithmetic)
  3. Diagonal/systematic patterns (shifts, checkerboard, evenly spaced)
  4. W-position constraint: 5 W's forced as nulls, systematic remainder
"""

import json
import math
import sys
import os
from itertools import combinations
from collections import defaultdict

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX

# ── Constants ────────────────────────────────────────────────────────────────

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR",
    "PARALLAX", "COLOPHON", "HOROLOGE", "SHADOW",
    "BERLINCLOCK", "EASTNORTHEAST", "SANBORN", "SCHEIDT",
]

CRIBS = ["EASTNORTHEAST", "BERLINCLOCK"]

ROWS = 8
COLS = 12
GRID_SIZE = ROWS * COLS  # 96
NULLS_PER_ROW = 3
KEPT_PER_ROW = COLS - NULLS_PER_ROW  # 9
TOTAL_NULLS = NULLS_PER_ROW * ROWS  # 24
REAL_CT_LEN = 73  # 96 - 24 + 1 (pos 96 always kept)

assert len(CT) == 97
assert GRID_SIZE == 96

# ── Quadgram Scoring ─────────────────────────────────────────────────────────

print("Loading quadgrams...", flush=True)
QUAD_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
with open(QUAD_PATH) as f:
    QUADGRAMS = json.load(f)

# Floor value for unknown quadgrams
_quad_values = list(QUADGRAMS.values())
QUAD_FLOOR = min(_quad_values) - 2.0  # well below the worst known quadgram
print(f"  Loaded {len(QUADGRAMS)} quadgrams. Floor={QUAD_FLOOR:.3f}", flush=True)


def quadgram_score(text: str) -> float:
    """Sum of log-prob for all 4-grams in text."""
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += QUADGRAMS.get(qg, QUAD_FLOOR)
    return score


def quadgram_per_char(text: str) -> float:
    n = len(text) - 3
    if n <= 0:
        return QUAD_FLOOR
    return quadgram_score(text) / n


def ic(text: str) -> float:
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    counts = [0] * 26
    for c in text:
        counts[ALPH_IDX[c]] += 1
    total = sum(f * (f - 1) for f in counts)
    return total / (n * (n - 1))


def check_cribs(text: str) -> list:
    """Check for crib substrings anywhere in text."""
    found = []
    for crib in CRIBS:
        idx = text.find(crib)
        if idx >= 0:
            found.append((crib, idx))
    return found


# ── Cipher Decryption ────────────────────────────────────────────────────────

def vig_decrypt(ct: str, key: str) -> str:
    """Vigenere: PT[i] = (CT[i] - KEY[i]) mod 26"""
    klen = len(key)
    result = []
    for i, c in enumerate(ct):
        k = ALPH_IDX[key[i % klen]]
        p = (ALPH_IDX[c] - k) % 26
        result.append(ALPH[p])
    return ''.join(result)


def beau_decrypt(ct: str, key: str) -> str:
    """Beaufort: PT[i] = (KEY[i] - CT[i]) mod 26"""
    klen = len(key)
    result = []
    for i, c in enumerate(ct):
        k = ALPH_IDX[key[i % klen]]
        p = (k - ALPH_IDX[c]) % 26
        result.append(ALPH[p])
    return ''.join(result)


# ── Grid Operations ──────────────────────────────────────────────────────────

def extract_real_ct(null_positions: set) -> str:
    """Remove null positions from CT[0:96], append CT[96], return 73-char real CT."""
    chars = []
    for i in range(96):
        if i not in null_positions:
            chars.append(CT[i])
    chars.append(CT[96])  # pos 96 = 'R' always kept
    return ''.join(chars)


def null_mask_from_columns_per_row(cols_per_row: list) -> set:
    """
    cols_per_row: list of 8 lists, each containing 3 column indices (0-11).
    Returns set of positions (0-95) to remove.
    """
    nulls = set()
    for row in range(ROWS):
        for col in cols_per_row[row]:
            pos = row * COLS + col
            nulls.add(pos)
    return nulls


def format_mask(null_positions: set) -> str:
    """Format a human-readable mask showing which positions are null."""
    rows = []
    for r in range(ROWS):
        row_str = ""
        for c in range(COLS):
            pos = r * COLS + c
            if pos in null_positions:
                row_str += "."
            else:
                row_str += CT[pos]
            row_str += " "
        rows.append(row_str.strip())
    return "\n".join(rows)


# ── Results Collection ───────────────────────────────────────────────────────

class ResultCollector:
    def __init__(self, top_n=20):
        self.top_n = top_n
        self.results = []  # (qg_score, ic_val, plaintext, method, mask_desc, cribs_found, null_positions)
        self.worst_score = float('-inf')
        self.total_tested = 0
        self.crib_hits = 0

    def add(self, qg_score, ic_val, plaintext, method, mask_desc, null_positions):
        self.total_tested += 1
        cribs_found = check_cribs(plaintext)
        if cribs_found:
            self.crib_hits += 1
            # Always store crib hits
            self.results.append((qg_score, ic_val, plaintext, method, mask_desc, cribs_found, null_positions))
            self.results.sort(key=lambda x: x[0], reverse=True)
            return

        if len(self.results) < self.top_n or qg_score > self.worst_score:
            self.results.append((qg_score, ic_val, plaintext, method, mask_desc, cribs_found, null_positions))
            self.results.sort(key=lambda x: x[0], reverse=True)
            if len(self.results) > self.top_n:
                self.results = self.results[:self.top_n]
            self.worst_score = self.results[-1][0] if len(self.results) >= self.top_n else float('-inf')

    def report(self, phase_name):
        print(f"\n{'='*80}", flush=True)
        print(f"  {phase_name} — Top {min(len(self.results), self.top_n)} Results", flush=True)
        print(f"  Total configs tested: {self.total_tested:,} | Crib hits: {self.crib_hits}", flush=True)
        print(f"{'='*80}", flush=True)
        for rank, (qg, ic_val, pt, method, mask_desc, cribs, nulls) in enumerate(self.results[:self.top_n], 1):
            crib_str = f" *** CRIB: {cribs} ***" if cribs else ""
            print(f"\n  #{rank}  QG/char={qg/(len(pt)-3) if len(pt)>3 else 0:.4f}  QG={qg:.2f}  IC={ic_val:.4f}{crib_str}", flush=True)
            print(f"  Method: {method}", flush=True)
            print(f"  PT: {pt}", flush=True)
            print(f"  Mask: {mask_desc}", flush=True)


collector = ResultCollector(top_n=20)


def evaluate_mask(null_positions: set, mask_desc: str):
    """Extract real CT, try all keywords with Vig/Beau, collect results."""
    real_ct = extract_real_ct(null_positions)
    assert len(real_ct) == 73, f"Expected 73 chars, got {len(real_ct)}"

    for kw in KEYWORDS:
        for cipher_name, decrypt_fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt)]:
            pt = decrypt_fn(real_ct, kw)
            qg = quadgram_score(pt)
            ic_val = ic(pt)
            method = f"{cipher_name}({kw}) on 73-char CT"
            collector.add(qg, ic_val, pt, method, mask_desc, null_positions)


# ── Phase 1: Uniform column selection ────────────────────────────────────────

def phase1():
    print("\n" + "="*80, flush=True)
    print("  PHASE 1: Uniform column selection — C(12,3)=220 masks × 12 keywords × 2 ciphers", flush=True)
    print("="*80, flush=True)

    count = 0
    for cols in combinations(range(COLS), NULLS_PER_ROW):
        cols_per_row = [list(cols)] * ROWS
        null_positions = null_mask_from_columns_per_row(cols_per_row)
        mask_desc = f"Uniform cols {cols}"
        evaluate_mask(null_positions, mask_desc)
        count += 1

    print(f"  Phase 1 complete: {count} column selections tested.", flush=True)


# ── Phase 2: Keyword-driven column selection ─────────────────────────────────

def phase2():
    print("\n" + "="*80, flush=True)
    print("  PHASE 2: Keyword-driven column selection", flush=True)
    print("="*80, flush=True)

    kw_list = KEYWORDS + [
        "KRYPTOSABCDE", "INTELLIGENCE", "CRYPTOGRAPHY",
        "CLANDESTINE", "LANGLEY", "VIRGINIAV",
    ]

    count = 0
    seen_masks = set()

    for kw in kw_list:
        # Convert keyword to numbers mod 12
        nums = [ALPH_IDX[c] % 12 for c in kw]

        # Method A: Take consecutive groups of 3
        if len(nums) >= 24:
            nums_24 = nums[:24]
        else:
            # Repeat keyword to fill 24 positions
            nums_24 = (nums * (24 // len(nums) + 1))[:24]

        cols_per_row = []
        for row in range(ROWS):
            row_cols = list(set(nums_24[row*3:(row+1)*3]))
            # If duplicates collapsed, need to pick additional columns
            while len(row_cols) < 3:
                for c in range(COLS):
                    if c not in row_cols:
                        row_cols.append(c)
                        break
            cols_per_row.append(sorted(row_cols[:3]))

        null_positions = null_mask_from_columns_per_row(cols_per_row)
        mask_key = frozenset(null_positions)
        if mask_key not in seen_masks:
            seen_masks.add(mask_key)
            mask_desc = f"KW-driven({kw}) groups-of-3"
            evaluate_mask(null_positions, mask_desc)
            count += 1

        # Method B: Use running offset: row r gets cols [nums[r], nums[r]+nums[r+8], nums[r]+nums[r+16]] mod 12
        if len(nums) >= 3:
            cols_per_row_b = []
            for row in range(ROWS):
                base = nums[row % len(nums)]
                step1 = nums[(row + 8) % len(nums)]
                step2 = nums[(row + 16) % len(nums)]
                row_cols = list(set([base % 12, (base + step1) % 12, (base + step1 + step2) % 12]))
                while len(row_cols) < 3:
                    for c in range(COLS):
                        if c not in row_cols:
                            row_cols.append(c)
                            break
                cols_per_row_b.append(sorted(row_cols[:3]))

            null_positions_b = null_mask_from_columns_per_row(cols_per_row_b)
            mask_key_b = frozenset(null_positions_b)
            if mask_key_b not in seen_masks:
                seen_masks.add(mask_key_b)
                mask_desc = f"KW-driven({kw}) running-offset"
                evaluate_mask(null_positions_b, mask_desc)
                count += 1

        # Method C: Keyword specifies 3 columns sequentially cycling
        if len(nums) >= 3:
            cols_per_row_c = []
            for row in range(ROWS):
                c0 = nums[(row * 3) % len(nums)] % 12
                c1 = nums[(row * 3 + 1) % len(nums)] % 12
                c2 = nums[(row * 3 + 2) % len(nums)] % 12
                row_cols = list(set([c0, c1, c2]))
                while len(row_cols) < 3:
                    for c in range(COLS):
                        if c not in row_cols:
                            row_cols.append(c)
                            break
                cols_per_row_c.append(sorted(row_cols[:3]))

            null_positions_c = null_mask_from_columns_per_row(cols_per_row_c)
            mask_key_c = frozenset(null_positions_c)
            if mask_key_c not in seen_masks:
                seen_masks.add(mask_key_c)
                mask_desc = f"KW-driven({kw}) cycling-3"
                evaluate_mask(null_positions_c, mask_desc)
                count += 1

    print(f"  Phase 2 complete: {count} unique masks tested.", flush=True)


# ── Phase 3: Diagonal/systematic patterns ────────────────────────────────────

def phase3():
    print("\n" + "="*80, flush=True)
    print("  PHASE 3: Diagonal/systematic patterns", flush=True)
    print("="*80, flush=True)

    count = 0
    seen_masks = set()

    def try_pattern(cols_per_row, desc):
        nonlocal count
        null_positions = null_mask_from_columns_per_row(cols_per_row)
        mask_key = frozenset(null_positions)
        if mask_key not in seen_masks:
            seen_masks.add(mask_key)
            evaluate_mask(null_positions, desc)
            count += 1

    # Evenly spaced: {0,4,8}, {1,5,9}, {2,6,10}, {3,7,11}
    for base in range(4):
        cols = [base, base + 4, base + 8]
        try_pattern([cols] * ROWS, f"Even-spaced base={base} cols={cols}")

    # Shift by k each row
    for shift in range(1, 12):
        cols_per_row = []
        for row in range(ROWS):
            base = (row * shift) % 12
            row_cols = sorted(set([(base + 0) % 12, (base + 4) % 12, (base + 8) % 12]))
            while len(row_cols) < 3:
                for c in range(COLS):
                    if c not in row_cols:
                        row_cols.append(c)
                        break
            cols_per_row.append(sorted(row_cols[:3]))
        try_pattern(cols_per_row, f"Shift-{shift} evenly-spaced")

    # Diagonal: row r gets cols {r%12, (r+1)%12, (r+2)%12}
    for start in range(12):
        cols_per_row = []
        for row in range(ROWS):
            c0 = (start + row) % 12
            c1 = (start + row + 1) % 12
            c2 = (start + row + 2) % 12
            cols_per_row.append(sorted([c0, c1, c2]))
        try_pattern(cols_per_row, f"Diagonal start={start} consecutive-3")

    # Diagonal with wider spacing
    for start in range(12):
        for spacing in [3, 4, 5, 6]:
            cols_per_row = []
            for row in range(ROWS):
                c0 = (start + row * spacing) % 12
                c1 = (c0 + 4) % 12
                c2 = (c0 + 8) % 12
                cols_per_row.append(sorted([c0, c1, c2]))
            try_pattern(cols_per_row, f"Diagonal start={start} spacing={spacing} even-3")

    # Reverse diagonal
    for start in range(12):
        cols_per_row = []
        for row in range(ROWS):
            c0 = (start - row) % 12
            c1 = (start - row - 1) % 12
            c2 = (start - row - 2) % 12
            cols_per_row.append(sorted([c0, c1, c2]))
        try_pattern(cols_per_row, f"RevDiag start={start}")

    # Checkerboard: even rows get {0,2,4}, odd rows get {1,3,5} etc.
    for offset in range(6):
        even_cols = [(offset * 2) % 12, (offset * 2 + 2) % 12, (offset * 2 + 4) % 12]
        odd_cols = [(offset * 2 + 1) % 12, (offset * 2 + 3) % 12, (offset * 2 + 5) % 12]
        cols_per_row = [even_cols if r % 2 == 0 else odd_cols for r in range(ROWS)]
        try_pattern(cols_per_row, f"Checkerboard offset={offset}")

    # Fibonacci-like: cols derived from Fibonacci sequence mod 12
    fib = [1, 1]
    for _ in range(30):
        fib.append(fib[-1] + fib[-2])
    for start_idx in range(len(fib) - 24):
        cols_per_row = []
        for row in range(ROWS):
            row_cols = list(set([fib[start_idx + row*3 + j] % 12 for j in range(3)]))
            while len(row_cols) < 3:
                for c in range(COLS):
                    if c not in row_cols:
                        row_cols.append(c)
                        break
            cols_per_row.append(sorted(row_cols[:3]))
        try_pattern(cols_per_row, f"Fibonacci start_idx={start_idx}")

    # Prime-based: column = prime[i] mod 12
    primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89]
    for offset in range(len(primes) - 24 + 1):
        cols_per_row = []
        for row in range(ROWS):
            row_cols = list(set([primes[offset + row*3 + j] % 12 for j in range(3)]))
            while len(row_cols) < 3:
                for c in range(COLS):
                    if c not in row_cols:
                        row_cols.append(c)
                        break
            cols_per_row.append(sorted(row_cols[:3]))
        try_pattern(cols_per_row, f"Primes offset={offset}")

    # Row-number-based: row r gets cols {r, r+3, r+6} mod 12, {r, r+4, r+8} mod 12, etc.
    for gap in range(1, 12):
        cols_per_row = []
        for row in range(ROWS):
            row_cols = sorted(set([(row + gap * j) % 12 for j in range(3)]))
            while len(row_cols) < 3:
                for c in range(COLS):
                    if c not in row_cols:
                        row_cols.append(c)
                        break
            cols_per_row.append(sorted(row_cols[:3]))
        try_pattern(cols_per_row, f"RowBased gap={gap}")

    print(f"  Phase 3 complete: {count} unique patterns tested.", flush=True)


# ── Phase 4: W-position constraint ──────────────────────────────────────────

def phase4():
    print("\n" + "="*80, flush=True)
    print("  PHASE 4: W-position constraint (W's forced as nulls)", flush=True)
    print("="*80, flush=True)

    # W positions in CT: find all
    w_positions = [i for i, c in enumerate(CT[:96]) if c == 'W']
    print(f"  W positions in CT[0:96]: {w_positions}", flush=True)

    # The 5 W positions from the hypothesis: 20, 36, 48, 58, 74
    # But 74 is beyond the 8x12 grid (which only covers 0-95)
    # W at pos 74 is in row 6 col 2
    w_hyp = [20, 36, 48, 58, 74]
    w_in_grid = [p for p in w_hyp if p < 96]
    print(f"  Hypothesis W positions (in grid): {w_in_grid}", flush=True)

    # Map to row, col
    w_grid = [(p // COLS, p % COLS) for p in w_in_grid]
    print(f"  W grid positions (row, col): {w_grid}", flush=True)

    # Count forced nulls per row from W positions
    w_by_row = defaultdict(list)
    for r, c in w_grid:
        w_by_row[r].append(c)

    print(f"  W nulls per row: {dict(w_by_row)}", flush=True)

    # Each row needs exactly 3 nulls. Some rows already have W-forced nulls.
    # Row 1 (pos 20 = col 8): needs 2 more
    # Row 3 (pos 36 = col 0): needs 2 more
    # Row 4 (pos 48 = col 0, pos 58 = col 10): needs 1 more
    # Row 6 (pos 74 = col 2): needs 2 more
    # Rows 0, 2, 5, 7: need 3 each

    count = 0
    seen_masks = set()

    # This is still tractable: for each row, enumerate possible additional columns
    # Total combos = product over rows of C(available_cols, needed_cols)
    # Rows with 0 forced: C(12,3) = 220
    # Rows with 1 forced: C(11,2) = 55
    # Rows with 2 forced: C(10,1) = 10
    # Total = 220^4 * 55^2 * 10 = too large (220^4 ≈ 2.3B)

    # So we use systematic patterns for the unfixed rows, not exhaustive.
    # Strategy: for each row, use a fixed base pattern, adjusted by W constraints.

    # Strategy 4a: Try uniform columns plus W constraints
    print("  Phase 4a: Uniform base + W override...", flush=True)
    for cols in combinations(range(COLS), NULLS_PER_ROW):
        cols_set = set(cols)
        cols_per_row = []
        valid = True
        for row in range(ROWS):
            forced = set(w_by_row.get(row, []))
            row_cols = forced | cols_set
            # Take the first 3 that include all forced
            if len(forced) > 3:
                valid = False
                break
            # Must have exactly 3
            row_cols_list = sorted(forced)
            for c in sorted(cols_set):
                if c not in forced and len(row_cols_list) < 3:
                    row_cols_list.append(c)
            # If still not 3 (forced cols overlapped with uniform), fill
            for c in range(COLS):
                if c not in row_cols_list and len(row_cols_list) < 3:
                    row_cols_list.append(c)
                if len(row_cols_list) >= 3:
                    break
            cols_per_row.append(sorted(row_cols_list[:3]))
        if not valid:
            continue

        null_positions = null_mask_from_columns_per_row(cols_per_row)
        # Verify W positions are included
        if not all(p in null_positions for p in w_in_grid):
            continue
        mask_key = frozenset(null_positions)
        if mask_key not in seen_masks:
            seen_masks.add(mask_key)
            evaluate_mask(null_positions, f"W-constrained uniform-base {cols}")
            count += 1

    # Strategy 4b: Row-shifting patterns with W constraint
    print("  Phase 4b: Systematic shifts + W override...", flush=True)
    for base in range(12):
        for gap in range(1, 12):
            cols_per_row = []
            for row in range(ROWS):
                forced = set(w_by_row.get(row, []))
                # Base pattern for this row
                base_cols = set([(base + row + gap * j) % 12 for j in range(3)])
                # Merge forced with base, keep exactly 3
                row_cols_list = sorted(forced)
                for c in sorted(base_cols):
                    if c not in forced and len(row_cols_list) < 3:
                        row_cols_list.append(c)
                for c in range(COLS):
                    if c not in row_cols_list and len(row_cols_list) < 3:
                        row_cols_list.append(c)
                    if len(row_cols_list) >= 3:
                        break
                cols_per_row.append(sorted(row_cols_list[:3]))

            null_positions = null_mask_from_columns_per_row(cols_per_row)
            if not all(p in null_positions for p in w_in_grid):
                continue
            mask_key = frozenset(null_positions)
            if mask_key not in seen_masks:
                seen_masks.add(mask_key)
                evaluate_mask(null_positions, f"W-constrained shift base={base} gap={gap}")
                count += 1

    # Strategy 4c: For rows with less constraint room, try all combos for those rows
    # with a fixed pattern for the rest.
    # Row 4 only needs 1 more null (has 2 W-forced). Try all 10 options for that 1.
    # For the other constrained rows, try a smaller set.
    print("  Phase 4c: Row-4 exhaustive + systematic others...", flush=True)
    row4_forced = set(w_by_row.get(4, []))  # {0, 10}
    row4_available = [c for c in range(COLS) if c not in row4_forced]

    for r4_extra in row4_available:
        row4_cols = sorted(list(row4_forced) + [r4_extra])
        # For other rows, try evenly-spaced patterns
        for base in range(4):
            base_cols = [base, base + 4, base + 8]
            cols_per_row = []
            for row in range(ROWS):
                if row == 4:
                    cols_per_row.append(row4_cols)
                    continue
                forced = set(w_by_row.get(row, []))
                row_cols_list = sorted(forced)
                for c in base_cols:
                    if c not in forced and len(row_cols_list) < 3:
                        row_cols_list.append(c)
                for c in range(COLS):
                    if c not in row_cols_list and len(row_cols_list) < 3:
                        row_cols_list.append(c)
                    if len(row_cols_list) >= 3:
                        break
                cols_per_row.append(sorted(row_cols_list[:3]))

            null_positions = null_mask_from_columns_per_row(cols_per_row)
            if not all(p in null_positions for p in w_in_grid):
                continue
            mask_key = frozenset(null_positions)
            if mask_key not in seen_masks:
                seen_masks.add(mask_key)
                evaluate_mask(null_positions, f"W-row4-extra={r4_extra} base={base}")
                count += 1

    print(f"  Phase 4 complete: {count} unique W-constrained masks tested.", flush=True)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print(f"Kryptos K4 — Hollerith 8×12 Punch Card Model", flush=True)
    print(f"CT: {CT}", flush=True)
    print(f"CT length: {CT_LEN}", flush=True)
    print(f"Grid: {ROWS}×{COLS} = {GRID_SIZE}, +1 extra = 97", flush=True)
    print(f"Nulls per row: {NULLS_PER_ROW}, Total nulls: {TOTAL_NULLS}", flush=True)
    print(f"Real CT length: {REAL_CT_LEN}", flush=True)
    print(f"Keywords: {KEYWORDS}", flush=True)

    # Display the grid
    print(f"\n8×12 Grid Layout:", flush=True)
    for r in range(ROWS):
        row_chars = CT[r*COLS:(r+1)*COLS]
        positions = f"[{r*COLS:2d}-{(r+1)*COLS-1:2d}]"
        print(f"  Row {r} {positions}: {' '.join(row_chars)}", flush=True)
    print(f"  Extra pos 96: {CT[96]}", flush=True)

    # Run all phases
    phase1()
    phase2()
    phase3()
    phase4()

    # Final report
    collector.report("COMBINED RESULTS — All Phases")

    # Also show the grid for the best result
    if collector.results:
        best = collector.results[0]
        _, _, _, _, _, _, null_pos = best
        if null_pos:
            print(f"\n{'='*80}", flush=True)
            print(f"  Best Result Grid Visualization (. = null/punched):", flush=True)
            print(f"{'='*80}", flush=True)
            print(format_mask(null_pos), flush=True)
            print(f"  + pos 96: {CT[96]} (always kept)", flush=True)

    print(f"\nTotal configurations evaluated: {collector.total_tested:,}", flush=True)
    print(f"Crib matches found: {collector.crib_hits}", flush=True)
    print("Done.", flush=True)


if __name__ == "__main__":
    main()
