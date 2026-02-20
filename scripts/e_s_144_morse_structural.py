#!/usr/bin/env python3
"""E-S-144: Morse code K0 data as SECOND-ORDER structural parameters for K4.

Previous experiments (E-01, E-S-112, E-S-143) tested K0 data as DIRECT key
material (first-order). All produced NOISE. This experiment tests K0 data as
STRUCTURAL PARAMETERS: null indicators, transposition block widths, reading
order selectors, and procedural operation sequences.

Phases:
  A: QTH prosign [16,19,7] as period-3 key (quick baseline)
  B: E-positions as null indicators (remove chars from K4 CT)
  C: E-group sizes as variable-width transposition blocks
  D: T=19 rotation + width-7 columnar (all 5040 orderings)
  E: 9x9 and 11x9 grid reading orders on K4 CT
  F: Combined: T=19 rotation + null removal + substitution

Output: results/e_s_144_morse_structural.json
"""

import json
import os
import sys
import time as time_mod
import itertools
import random

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, NOISE_FLOOR,
    KRYPTOS_ALPHABET, CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]

# Standard alphabet
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}

# Kryptos Alphabet
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# ═══════════════════════════════════════════════════════════════════════════════
# MORSE CODE DATA (from E-01, community consensus)
# ═══════════════════════════════════════════════════════════════════════════════

MORSE_TOKENS = [
    'e', 'e',  # 2 E's before VIRTUALLY
    'V', 'I', 'R', 'T', 'U', 'A', 'L', 'L', 'Y',
    'e',  # 1 E after VIRTUALLY
    'e', 'e', 'e', 'e', 'e',  # 5 E's before INVISIBLE
    'I', 'N', 'V', 'I', 'S', 'I', 'B', 'L', 'E',  # INVISIBLE
    'e',  # 1 E
    'D', 'I', 'G', 'E', 'T', 'A', 'L',  # DIGETAL
    'e', 'e', 'e',  # 3 E's
    'I', 'N', 'T', 'E', 'R', 'P', 'R', 'E', 'T', 'A', 'T', 'I', 'U',  # INTERPRETATIU
    'e', 'e',  # 2 E's
    'S', 'H', 'A', 'D', 'O', 'W',
    'e', 'e',  # 2 E's
    'F', 'O', 'R', 'C', 'E', 'S',  # FORCES
    'e', 'e', 'e', 'e', 'e',  # 5 E's
    'L', 'U', 'C', 'I', 'D',
    'e', 'e', 'e',  # 3 E's
    'M', 'E', 'M', 'O', 'R', 'Y',  # MEMORY
    'e',  # 1 E
    'T', 'I', 'S', 'Y', 'O', 'U', 'R',
    'P', 'O', 'S', 'I', 'T', 'I', 'O', 'N',
    'e',  # 1 E
    'S', 'O', 'S',
    'R', 'Q',
]

E_GROUP_SIZES = [2, 1, 5, 1, 3, 2, 2, 5, 3, 1, 1]  # 11 groups, sum=26

# ═══════════════════════════════════════════════════════════════════════════════
# CIPHER PRIMITIVES
# ═══════════════════════════════════════════════════════════════════════════════

def vig_dec(ct_nums, key_nums):
    p = len(key_nums)
    return [(ct_nums[i] - key_nums[i % p]) % MOD for i in range(len(ct_nums))]

def beau_dec(ct_nums, key_nums):
    p = len(key_nums)
    return [(key_nums[i % p] - ct_nums[i]) % MOD for i in range(len(ct_nums))]

def varbeau_dec(ct_nums, key_nums):
    p = len(key_nums)
    return [(ct_nums[i] + key_nums[i % p]) % MOD for i in range(len(ct_nums))]

def nums_to_text(nums):
    return ''.join(chr(ord('A') + n) for n in nums)

def score_cribs_from_nums(pt_nums):
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt_nums) and pt_nums[pos] == ALPH_IDX[ch]:
            matches += 1
    return matches

def score_cribs_text(text):
    """Score plaintext string against cribs."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(text) and text[pos] == ch:
            matches += 1
    return matches

def check_bean(pt_nums):
    if len(pt_nums) < CT_LEN:
        return False
    key = [(CT_NUM[i] - pt_nums[i]) % MOD for i in range(CT_LEN)]
    for a, b in BEAN_EQ:
        if a < len(key) and b < len(key) and key[a] != key[b]:
            return False
    for a, b in BEAN_INEQ:
        if a < len(key) and b < len(key) and key[a] == key[b]:
            return False
    return True

def apply_columnar_trans(text, width, col_order):
    """Undo columnar transposition: given CT written in columns per col_order, recover PT."""
    n = len(text)
    nrows = (n + width - 1) // width
    long_cols = n % width if n % width != 0 else width

    # Figure out how many chars in each column
    col_lens = []
    for c in range(width):
        if long_cols == width:
            col_lens.append(nrows)
        elif c < long_cols:
            col_lens.append(nrows)
        else:
            col_lens.append(nrows - 1)

    # Read columns in col_order
    cols = {}
    pos = 0
    for rank in range(width):
        col_idx = col_order.index(rank)
        clen = col_lens[col_idx]
        cols[col_idx] = text[pos:pos + clen]
        pos += clen

    # Read off row by row
    result = []
    for r in range(nrows):
        for c in range(width):
            if r < len(cols[c]):
                result.append(cols[c][r])
    return ''.join(result)

# ═══════════════════════════════════════════════════════════════════════════════
# TRACKING
# ═══════════════════════════════════════════════════════════════════════════════

best_score = 0
best_tag = ""
best_pt = ""
total_configs = 0
results_log = []

def test_and_log(tag, pt_text):
    global best_score, best_tag, best_pt, total_configs
    total_configs += 1
    score = score_cribs_text(pt_text[:CT_LEN])
    if score > best_score:
        best_score = score
        best_tag = tag
        best_pt = pt_text[:50]
        print(f"  NEW BEST: {score}/{N_CRIBS} — {tag}")
        print(f"    PT: {pt_text[:60]}...")
    if score >= NOISE_FLOOR:
        results_log.append({"tag": tag, "score": score, "pt_prefix": pt_text[:40]})
    return score

def test_sub_variants(tag_prefix, ct_text, keys_dict):
    """Test Vig/Beaufort/VarBeau for each key in keys_dict against ct_text."""
    ct_n = [ALPH_IDX[c] for c in ct_text]
    for kname, knums in keys_dict.items():
        for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec), ("VB", varbeau_dec)]:
            pt_n = vfn(ct_n, knums)
            pt_t = nums_to_text(pt_n)
            test_and_log(f"{tag_prefix}_{kname}_{vname}", pt_t)

# ═══════════════════════════════════════════════════════════════════════════════

# Key material from K1-K3
PAL_AZ = [ord(c) - ord('A') for c in "PALIMPSEST"]
ABS_AZ = [ord(c) - ord('A') for c in "ABSCISSA"]
KRY_AZ = [ord(c) - ord('A') for c in "KRYPTOS"]
PAL_KA = [KA_IDX[c] for c in "PALIMPSEST"]
ABS_KA = [KA_IDX[c] for c in "ABSCISSA"]
KRY_KA = [KA_IDX[c] for c in "KRYPTOS"]

KNOWN_KEYS = {
    "PAL_AZ": PAL_AZ, "PAL_KA": PAL_KA,
    "ABS_AZ": ABS_AZ, "ABS_KA": ABS_KA,
    "KRY_AZ": KRY_AZ, "KRY_KA": KRY_KA,
}


def main():
    global best_score, best_tag, total_configs
    random.seed(42)
    t0 = time_mod.time()

    print("=" * 72)
    print("E-S-144: Morse K0 as Second-Order Structural Parameters for K4")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"E-group sizes: {E_GROUP_SIZES}")
    print()

    # ── Compute E-positions ──────────────────────────────────────────────
    e_token_positions = [i for i, t in enumerate(MORSE_TOKENS) if t == 'e']
    msg_letters = [t for t in MORSE_TOKENS if t != 'e']
    print(f"Total tokens: {len(MORSE_TOKENS)}, E's: {len(e_token_positions)}, msg letters: {len(msg_letters)}")

    # E positions within message-letter stream (how many msg letters seen before each E)
    e_msg_positions = []
    msg_idx = 0
    for t in MORSE_TOKENS:
        if t == 'e':
            e_msg_positions.append(msg_idx)
        else:
            msg_idx += 1
    print(f"E positions in msg stream: {e_msg_positions}")

    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE A: QTH prosign [16,19,7] as period-3 key")
    print("─" * 72)

    qth_key = [16, 19, 7]  # Q=16, T=19, H=7 (A=0)
    for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec), ("VB", varbeau_dec)]:
        for rot in range(3):
            rkey = qth_key[rot:] + qth_key[:rot]
            pt_n = vfn(CT_NUM, rkey)
            pt_t = nums_to_text(pt_n)
            test_and_log(f"A_QTH_rot{rot}_{vname}", pt_t)

    # Also test QTH reversed: HTQ = [7,19,16]
    htq_key = [7, 19, 16]
    for vname, vfn in [("Vig", vig_dec), ("Beau", beau_dec), ("VB", varbeau_dec)]:
        pt_n = vfn(CT_NUM, htq_key)
        pt_t = nums_to_text(pt_n)
        test_and_log(f"A_HTQ_{vname}", pt_t)

    print(f"  Phase A: {total_configs} tests, best={best_score}")

    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE B: E-positions as null indicators")
    print("─" * 72)
    phase_b_start = total_configs

    # Strategy: map E-positions to K4 positions, remove those, test remainder
    # Mapping 1: Direct — first 26 E message-positions mod 97
    null_sets = {}

    # B1: E cumulative index → K4 position (i.e., positions 0-25)
    null_sets["B1_first26"] = set(range(26))

    # B2: E msg-stream positions mod 97
    null_sets["B2_epos_mod97"] = set(p % 97 for p in e_msg_positions)

    # B3: E token positions mod 97
    null_sets["B3_etok_mod97"] = set(p % 97 for p in e_token_positions)

    # B4: E-group cumulative sums as positions
    cum = []
    s = 0
    for g in E_GROUP_SIZES:
        s += g
        cum.append(s - 1)  # 0-indexed end of each group
    null_sets["B4_group_cumsum"] = set(c % 97 for c in cum)

    # B5: E-group sizes as positions directly
    null_sets["B5_group_sizes_as_pos"] = set(E_GROUP_SIZES)

    # B6: Last 26 positions (mirror of B1)
    null_sets["B6_last26"] = set(range(71, 97))

    for nname, null_pos in null_sets.items():
        # Remove null positions from CT
        reduced_ct = ''.join(CT[i] for i in range(CT_LEN) if i not in null_pos)
        n_removed = CT_LEN - len(reduced_ct)
        print(f"  {nname}: removed {n_removed} chars, reduced CT len={len(reduced_ct)}")

        # Test with known keys
        test_sub_variants(f"B_{nname}", reduced_ct, KNOWN_KEYS)

        # Also test identity (no substitution — just check if removal reveals cribs)
        # This only makes sense if cribs are at adjusted positions, which is complex
        # Skip for now — the sub variants cover the key space

    print(f"  Phase B: {total_configs - phase_b_start} tests, best={best_score}")

    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE C: E-group sizes as variable-width transposition blocks")
    print("─" * 72)
    phase_c_start = total_configs

    # Divide K4 CT into blocks using E-group sizes [2,1,5,1,3,2,2,5,3,1,1]
    # Pattern repeats: 26 chars per cycle, 97 chars = 3 full cycles + 19 leftover
    def make_blocks(text, block_sizes):
        blocks = []
        pos = 0
        size_idx = 0
        while pos < len(text):
            bsize = block_sizes[size_idx % len(block_sizes)]
            block = text[pos:pos + bsize]
            if block:
                blocks.append(block)
            pos += bsize
            size_idx += 1
        return blocks

    blocks = make_blocks(CT, E_GROUP_SIZES)
    print(f"  Blocks ({len(blocks)} total): {[len(b) for b in blocks]}")
    print(f"  Block contents: {blocks[:15]}...")

    # Test all permutations of blocks (for small block count)
    n_blocks = len(blocks)
    if n_blocks <= 10:
        # All permutations feasible
        count = 0
        for perm in itertools.permutations(range(n_blocks)):
            reordered = ''.join(blocks[p] for p in perm)
            test_and_log(f"C_blockperm_{perm[:4]}", reordered)
            count += 1
            if count >= 100000:
                break
    else:
        # Sample random permutations
        # Identity and reverse first
        identity_text = ''.join(blocks)
        test_and_log("C_blocks_identity", identity_text)
        reverse_text = ''.join(reversed(blocks))
        test_and_log("C_blocks_reverse", reverse_text)

        # Sample 50,000 random
        indices = list(range(n_blocks))
        for trial in range(50000):
            perm = indices[:]
            random.shuffle(perm)
            reordered = ''.join(blocks[p] for p in perm)
            test_and_log(f"C_blockperm_r{trial}", reordered)

    # Also try: blocks read in REVERSE within each block
    blocks_rev = [b[::-1] for b in blocks]
    rev_text = ''.join(blocks_rev)
    test_and_log("C_blocks_internal_rev", rev_text)

    # Blocks reversed internally + block order reversed
    test_and_log("C_blocks_all_rev", ''.join(reversed(blocks_rev)))

    # Now test block permutations + substitution on the best few
    # Try the reordered text through Vig/Beau with known keys
    # Use identity block order + sub as baseline
    test_sub_variants("C_identity", CT, KNOWN_KEYS)

    print(f"  Phase C: {total_configs - phase_c_start} tests, best={best_score}")

    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE D: T=19 rotation + width-7 columnar (all 5040 orderings)")
    print("─" * 72)
    phase_d_start = total_configs

    # Circularly shift CT by 19 positions
    for shift in [19, 20, 78, 77]:  # T=19 (A=0), T=20 (A=1), and complements
        shifted_ct = CT[shift:] + CT[:shift]

        # Test shifted CT through all w7 columnar orderings
        for perm in itertools.permutations(range(7)):
            pt = apply_columnar_trans(shifted_ct, 7, list(perm))
            test_and_log(f"D_shift{shift}_w7_{perm}", pt)

    print(f"  Phase D: {total_configs - phase_d_start} tests, best={best_score}")

    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE E: Grid reading orders (9x11, 11x9, 10x10)")
    print("─" * 72)
    phase_e_start = total_configs

    def read_grid_columns(text, width):
        """Read text written row-by-row, then read column-by-column."""
        nrows = (len(text) + width - 1) // width
        # Pad with X if needed
        padded = text + 'X' * (nrows * width - len(text))
        result = []
        for c in range(width):
            for r in range(nrows):
                idx = r * width + c
                if idx < len(text):
                    result.append(text[idx])
        return ''.join(result)

    def read_grid_diagonal(text, width):
        """Read text in diagonal order."""
        nrows = (len(text) + width - 1) // width
        result = []
        for d in range(nrows + width - 1):
            for r in range(nrows):
                c = d - r
                if 0 <= c < width:
                    idx = r * width + c
                    if idx < len(text):
                        result.append(text[idx])
        return ''.join(result)

    def read_grid_spiral(text, width):
        """Read text in spiral order (clockwise from top-left)."""
        nrows = (len(text) + width - 1) // width
        padded = text + 'X' * (nrows * width - len(text))
        grid = []
        for r in range(nrows):
            grid.append(list(padded[r * width:(r + 1) * width]))

        result = []
        top, bottom, left, right = 0, nrows - 1, 0, width - 1
        while top <= bottom and left <= right:
            for c in range(left, right + 1):
                result.append(grid[top][c])
            top += 1
            for r in range(top, bottom + 1):
                result.append(grid[r][right])
            right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    result.append(grid[bottom][c])
                bottom -= 1
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    result.append(grid[r][left])
                left += 1
        return ''.join(result[:len(text)])

    def read_grid_snake(text, width):
        """Read in boustrophedon order (even rows L→R, odd rows R→L)."""
        nrows = (len(text) + width - 1) // width
        result = []
        for r in range(nrows):
            row = text[r * width:(r + 1) * width]
            if r % 2 == 1:
                row = row[::-1]
            result.append(row)
        return ''.join(result)[:len(text)]

    # Test various grid widths
    for width in [7, 8, 9, 10, 11, 13, 14]:
        for reader_name, reader_fn in [
            ("cols", read_grid_columns),
            ("diag", read_grid_diagonal),
            ("spiral", read_grid_spiral),
            ("snake", read_grid_snake),
        ]:
            # Read CT in this grid order
            reordered = reader_fn(CT, width)
            test_and_log(f"E_w{width}_{reader_name}", reordered)

            # Also test with substitution
            for kname in ["PAL_AZ", "ABS_AZ", "KRY_AZ"]:
                ct_n = [ALPH_IDX[c] for c in reordered]
                for vn, vfn in [("Vig", vig_dec), ("Beau", beau_dec)]:
                    pt_n = vfn(ct_n, KNOWN_KEYS[kname])
                    pt_t = nums_to_text(pt_n)
                    test_and_log(f"E_w{width}_{reader_name}_{kname}_{vn}", pt_t)

    print(f"  Phase E: {total_configs - phase_e_start} tests, best={best_score}")

    # ─────────────────────────────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("PHASE F: Combined — T=19 shift + null removal + substitution")
    print("─" * 72)
    phase_f_start = total_configs

    # Combine T=19 shift with E-position null removal then substitution
    for shift in [0, 19, 20]:
        shifted = CT[shift:] + CT[:shift]
        for nname, null_pos in null_sets.items():
            reduced = ''.join(shifted[i] for i in range(len(shifted)) if i not in null_pos)
            test_sub_variants(f"F_s{shift}_{nname}", reduced, KNOWN_KEYS)

    # T=19 shift + grid reading + substitution
    for shift in [19, 20]:
        shifted = CT[shift:] + CT[:shift]
        for width in [7, 9, 11]:
            reordered = read_grid_columns(shifted, width)
            test_sub_variants(f"F_s{shift}_w{width}_cols", reordered, KNOWN_KEYS)
            reordered = read_grid_snake(shifted, width)
            test_sub_variants(f"F_s{shift}_w{width}_snake", reordered, KNOWN_KEYS)

    print(f"  Phase F: {total_configs - phase_f_start} tests, best={best_score}")

    # ═══════════════════════════════════════════════════════════════════════
    elapsed = time_mod.time() - t0

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total configurations tested: {total_configs}")
    print(f"Above NOISE ({NOISE_FLOOR}): {len(results_log)}")
    print(f"Best score: {best_score} ({best_tag})")
    print(f"Elapsed: {elapsed:.1f}s")

    if results_log:
        print("\nResults above noise floor:")
        for r in sorted(results_log, key=lambda x: -x["score"])[:20]:
            print(f"  score={r['score']} | {r['tag']}")

    print(f"\nConclusion: {'SIGNAL DETECTED' if best_score >= 10 else 'No signal from K0 structural parameters.'}")

    # Save results
    os.makedirs("results", exist_ok=True)
    with open("results/e_s_144_morse_structural.json", "w") as f:
        json.dump({
            "experiment": "E-S-144",
            "total_configs": total_configs,
            "best_score": best_score,
            "best_tag": best_tag,
            "elapsed": elapsed,
            "results_above_noise": results_log,
        }, f, indent=2)

    print(f"\nResults saved to results/e_s_144_morse_structural.json")


if __name__ == "__main__":
    main()
