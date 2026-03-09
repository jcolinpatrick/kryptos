#!/usr/bin/env python3
"""
Cipher: 4x24 punch card null removal + substitution
Family: team
Status: active
Keyspace: ~6M (keyword masks * decrypt keys * cipher types)
Last run:
Best score:
"""
"""E-HOLLERITH-4x24-GRID: 4-row x 24-column punch card model for K4.

Hypothesis: Arrange first 96 chars of K4 as 4 rows x 24 cols.
For each column, one row is "punched" (null). Removing 24 nulls yields
73-char real CT. Then decrypt with Vigenere/Beaufort + keyword.

Phase 1: Keyword-driven row selection (keyword letters mod 4).
Phase 2: Brute-force periodic row patterns (periods 1-8).
Phase 3: Sculpture-number-driven row selection (misspelling positions, K2 coords).
"""
import sys
import os
import json
import math
import time
from collections import Counter
from itertools import product

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD

# ── Constants ──────────────────────────────────────────────────────────────

GRID_ROWS = 4
GRID_COLS = 24
assert GRID_ROWS * GRID_COLS == 96  # first 96 chars
TAIL = CT[96]  # final char 'R', always kept

# Build the 4x24 grid
GRID = []
for r in range(GRID_ROWS):
    row_start = r * GRID_COLS
    GRID.append(CT[row_start : row_start + GRID_COLS])

# Decrypt keywords
DECRYPT_KEYS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR",
    "PARALLAX", "COLOPHON", "HOROLOGE", "SHADOW",
]

# Null-mask keywords
MASK_KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "HOROLOGE", "DEFECTOR",
    "PARALLAX", "COLOPHON", "SHADOW", "ENIGMA", "BERLINCLOCK",
    "EASTNORTHEAST", "CLOCK", "BERLIN", "FIVE", "SANBORN",
    "SCHEIDT", "WEBSTER", "CIA", "LANGLEY", "INFERNO",
    "LUCID", "MATRIX", "LAYER", "TWO",
]

CRIBS = ["EASTNORTHEAST", "BERLINCLOCK"]

# ── Load quadgrams ────────────────────────────────────────────────────────

QUADGRAMS_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "data", "english_quadgrams.json"
)

print("Loading quadgrams...", flush=True)
with open(QUADGRAMS_PATH) as f:
    QUADGRAMS = json.load(f)

# Floor value for unknown quadgrams (worst observed - 1)
QG_FLOOR = min(QUADGRAMS.values()) - 1.0
print(f"  Loaded {len(QUADGRAMS)} quadgrams, floor={QG_FLOOR:.2f}", flush=True)


# ── Helpers ────────────────────────────────────────────────────────────────

def keyword_to_mask(keyword: str, length: int = GRID_COLS) -> list:
    """Convert keyword letters to row indices (mod 4), repeated to length."""
    nums = [ALPH_IDX[c] % GRID_ROWS for c in keyword.upper() if c in ALPH_IDX]
    if not nums:
        return [0] * length
    mask = []
    while len(mask) < length:
        mask.extend(nums)
    return mask[:length]


def apply_mask(mask: list) -> str:
    """Given a 24-element mask (which row to punch per column), return 73-char CT."""
    chars = []
    for col in range(GRID_COLS):
        punch_row = mask[col]
        for row in range(GRID_ROWS):
            if row != punch_row:
                chars.append(GRID[row][col])
    chars.append(TAIL)
    assert len(chars) == 73, f"Expected 73 chars, got {len(chars)}"
    return "".join(chars)


def vigenere_decrypt(ct_text: str, key: str) -> str:
    """Vigenere decrypt: PT[i] = (CT[i] - KEY[i]) mod 26."""
    key_nums = [ALPH_IDX[c] for c in key.upper()]
    klen = len(key_nums)
    result = []
    for i, c in enumerate(ct_text):
        ct_val = ALPH_IDX[c]
        k_val = key_nums[i % klen]
        pt_val = (ct_val - k_val) % MOD
        result.append(ALPH[pt_val])
    return "".join(result)


def beaufort_decrypt(ct_text: str, key: str) -> str:
    """Beaufort decrypt: PT[i] = (KEY[i] - CT[i]) mod 26."""
    key_nums = [ALPH_IDX[c] for c in key.upper()]
    klen = len(key_nums)
    result = []
    for i, c in enumerate(ct_text):
        ct_val = ALPH_IDX[c]
        k_val = key_nums[i % klen]
        pt_val = (k_val - ct_val) % MOD
        result.append(ALPH[pt_val])
    return "".join(result)


def quadgram_score(text: str) -> float:
    """Sum of log-probabilities for all 4-grams in text."""
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += QUADGRAMS.get(qg, QG_FLOOR)
    return score


def ic_value(text: str) -> float:
    """Index of coincidence."""
    n = len(text)
    if n < 2:
        return 0.0
    freq = Counter(text)
    num = sum(f * (f - 1) for f in freq.values())
    return num / (n * (n - 1))


def check_cribs(text: str) -> list:
    """Check if any crib appears as substring."""
    found = []
    for crib in CRIBS:
        pos = text.find(crib)
        if pos >= 0:
            found.append((crib, pos))
    return found


# ── Result tracking ───────────────────────────────────────────────────────

class Result:
    __slots__ = [
        "mask_label", "mask", "cipher", "decrypt_key",
        "plaintext", "qg_score", "qg_per_char", "ic", "cribs_found",
    ]

    def __init__(self, mask_label, mask, cipher, decrypt_key,
                 plaintext, qg_score, ic, cribs_found):
        self.mask_label = mask_label
        self.mask = mask
        self.cipher = cipher
        self.decrypt_key = decrypt_key
        self.plaintext = plaintext
        self.qg_score = qg_score
        self.qg_per_char = qg_score / max(len(plaintext) - 3, 1)
        self.ic = ic
        self.cribs_found = cribs_found


def evaluate_mask(mask: list, mask_label: str, results: list):
    """Apply mask, try all decryptions, score, append to results."""
    ct73 = apply_mask(mask)

    for key in DECRYPT_KEYS:
        for cipher_name, decrypt_fn in [("Vig", vigenere_decrypt), ("Beau", beaufort_decrypt)]:
            pt = decrypt_fn(ct73, key)
            qg = quadgram_score(pt)
            ic = ic_value(pt)
            cribs = check_cribs(pt)

            r = Result(mask_label, mask[:], cipher_name, key, pt, qg, ic, cribs)
            results.append(r)

            if cribs:
                print(f"\n*** CRIB FOUND! mask={mask_label} {cipher_name}/{key} ***", flush=True)
                print(f"    PT: {pt}", flush=True)
                print(f"    Cribs: {cribs}", flush=True)


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    t0 = time.time()
    all_results: list = []

    # Display grid
    print("\n=== 4x24 GRID ===")
    for r in range(GRID_ROWS):
        print(f"  Row {r} (pos {r*24:2d}-{r*24+23:2d}): {GRID[r]}")
    print(f"  Tail (pos 96):       {TAIL}")
    print()

    # ── Phase 1: Keyword-driven row selection ──────────────────────────────
    print("=" * 70)
    print("PHASE 1: Keyword-driven row selection")
    print("=" * 70)

    phase1_count = 0
    for mkw in MASK_KEYWORDS:
        mask = keyword_to_mask(mkw)
        label = f"KW:{mkw}"
        evaluate_mask(mask, label, all_results)
        phase1_count += 1

    print(f"  Tested {phase1_count} mask keywords x {len(DECRYPT_KEYS)} decrypt keys x 2 ciphers "
          f"= {phase1_count * len(DECRYPT_KEYS) * 2} configs")

    # ── Phase 2: Brute-force periodic patterns ─────────────────────────────
    print("\n" + "=" * 70)
    print("PHASE 2: Brute-force periodic row patterns (periods 1-8)")
    print("=" * 70)

    phase2_count = 0
    for period in [1, 2, 3, 4, 5, 6, 7, 8]:
        n_patterns = GRID_ROWS ** period
        print(f"  Period {period}: {n_patterns} patterns...", end="", flush=True)

        for combo in product(range(GRID_ROWS), repeat=period):
            # Repeat the pattern to length 24
            mask = list(combo) * ((GRID_COLS // period) + 1)
            mask = mask[:GRID_COLS]
            label = f"P{period}:{''.join(str(x) for x in combo)}"
            evaluate_mask(mask, label, all_results)
            phase2_count += 1

        print(f" done ({phase2_count} total so far)", flush=True)

    print(f"  Total phase 2: {phase2_count} masks x {len(DECRYPT_KEYS)} keys x 2 = "
          f"{phase2_count * len(DECRYPT_KEYS) * 2} configs")

    # ── Phase 3: Sculpture-number driven ───────────────────────────────────
    print("\n" + "=" * 70)
    print("PHASE 3: Sculpture-number driven masks")
    print("=" * 70)

    phase3_count = 0

    # Misspelling positions: K1 pos 7 (IQLUSION), K3 pos 2, 5, 8, 4, 14
    misspell_digits = [7 % 4, 2 % 4, 5 % 4, 8 % 4, 4 % 4, 14 % 4]  # [3, 2, 1, 0, 0, 2]
    mask = (misspell_digits * 4)[:GRID_COLS]
    evaluate_mask(mask, "MISSPELL:[3,2,1,0,0,2]", all_results)
    phase3_count += 1

    # K2 coordinate digits: 38°57'6.5"N, 77°8'44"W → 3,8,5,7,6,5,7,7,8,4,4
    k2_digits = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]
    k2_mod4 = [d % 4 for d in k2_digits]  # [3, 0, 1, 3, 2, 1, 3, 3, 0, 0, 0]
    mask = (k2_mod4 * 3)[:GRID_COLS]
    evaluate_mask(mask, "K2COORDS:" + str(k2_mod4), all_results)
    phase3_count += 1

    # Also try the raw coordinate sequences: 38576577844
    # and the individual coords: 389576.5 and 77844
    lat_digits = [3, 8, 9, 5, 7, 6, 5]
    lon_digits = [7, 7, 0, 8, 4, 4]
    for name, digits in [("LAT", lat_digits), ("LON", lon_digits)]:
        mod4 = [d % 4 for d in digits]
        mask = (mod4 * 4)[:GRID_COLS]
        evaluate_mask(mask, f"{name}:{mod4}", all_results)
        phase3_count += 1

    # W positions in K4: 20, 36, 48, 58, 74 → mod 4 = 0, 0, 0, 2, 2
    w_positions = [20, 36, 48, 58, 74]
    w_mod4 = [p % 4 for p in w_positions]
    mask = (w_mod4 * 5)[:GRID_COLS]
    evaluate_mask(mask, f"WPOS:{w_mod4}", all_results)
    phase3_count += 1

    # 4-8-20-24 from maintenance instructions (pump/light times)
    maint_digits = [4, 8, 20, 24]
    maint_mod4 = [d % 4 for d in maint_digits]  # [0, 0, 0, 0] — all row 0
    mask = maint_mod4 * 6  # already 24
    evaluate_mask(mask, f"MAINT:{maint_mod4}", all_results)
    phase3_count += 1

    # Row 0-3 cycling in different orders
    for perm in [[0,1,2,3], [0,2,1,3], [0,3,2,1], [1,0,3,2],
                 [1,2,3,0], [2,0,1,3], [2,3,0,1], [3,2,1,0], [3,0,1,2]]:
        mask = (perm * 6)[:GRID_COLS]
        label = f"CYCLE:{''.join(str(x) for x in perm)}"
        evaluate_mask(mask, label, all_results)
        phase3_count += 1

    print(f"  Phase 3: {phase3_count} masks tested")

    # ── Collect and report ─────────────────────────────────────────────────
    elapsed = time.time() - t0
    total_configs = len(all_results)
    print(f"\n{'=' * 70}")
    print(f"TOTAL CONFIGS TESTED: {total_configs}")
    print(f"ELAPSED: {elapsed:.1f}s")
    print(f"{'=' * 70}")

    # Check for any crib hits
    crib_hits = [r for r in all_results if r.cribs_found]
    if crib_hits:
        print(f"\n*** {len(crib_hits)} CRIB HIT(S) FOUND! ***")
        for r in crib_hits:
            print(f"  Mask: {r.mask_label}")
            print(f"  Cipher: {r.cipher}/{r.decrypt_key}")
            print(f"  PT: {r.plaintext}")
            print(f"  Cribs: {r.cribs_found}")
            print(f"  QG/char: {r.qg_per_char:.4f}, IC: {r.ic:.4f}")
            print()
    else:
        print("\nNo crib hits found.")

    # Top 20 by quadgram score per character
    all_results.sort(key=lambda r: r.qg_per_char, reverse=True)

    print(f"\n{'=' * 70}")
    print("TOP 20 BY QUADGRAM SCORE (per character)")
    print(f"{'=' * 70}")
    print(f"{'Rank':>4}  {'QG/char':>8}  {'IC':>6}  {'Cipher':>5}  {'Key':<12}  {'Mask':<28}  {'Plaintext'}")
    print("-" * 140)

    for i, r in enumerate(all_results[:20]):
        crib_flag = " ***CRIB***" if r.cribs_found else ""
        print(f"{i+1:>4}  {r.qg_per_char:>8.4f}  {r.ic:>6.4f}  {r.cipher:>5}  {r.decrypt_key:<12}  "
              f"{r.mask_label:<28}  {r.plaintext}{crib_flag}")

    # Also show top 20 by IC
    all_results.sort(key=lambda r: r.ic, reverse=True)
    print(f"\n{'=' * 70}")
    print("TOP 20 BY INDEX OF COINCIDENCE")
    print(f"{'=' * 70}")
    print(f"{'Rank':>4}  {'IC':>6}  {'QG/char':>8}  {'Cipher':>5}  {'Key':<12}  {'Mask':<28}  {'Plaintext'}")
    print("-" * 140)

    for i, r in enumerate(all_results[:20]):
        crib_flag = " ***CRIB***" if r.cribs_found else ""
        print(f"{i+1:>4}  {r.ic:>6.4f}  {r.qg_per_char:>8.4f}  {r.cipher:>5}  {r.decrypt_key:<12}  "
              f"{r.mask_label:<28}  {r.plaintext}{crib_flag}")

    # Summary statistics
    all_qg = [r.qg_per_char for r in all_results]
    all_ic = [r.ic for r in all_results]
    print(f"\n{'=' * 70}")
    print("SUMMARY STATISTICS")
    print(f"{'=' * 70}")
    print(f"  QG/char — min: {min(all_qg):.4f}, max: {max(all_qg):.4f}, "
          f"mean: {sum(all_qg)/len(all_qg):.4f}")
    print(f"  IC      — min: {min(all_ic):.4f}, max: {max(all_ic):.4f}, "
          f"mean: {sum(all_ic)/len(all_ic):.4f}")
    print(f"  English IC ≈ 0.0667, Random IC ≈ 0.0385")
    print(f"  Crib hits: {len(crib_hits)}")
    print(f"  Total time: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
