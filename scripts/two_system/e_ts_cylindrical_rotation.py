#!/usr/bin/env python3
"""
Cipher: cylindrical rotation (Jefferson-style + alternating direction)
Family: two_system
Status: active
Keyspace: ~500K configs
Last run:
Best score:
"""
"""Cylindrical Grid Rotation Model for K4

Motivated by:
- Coding chart arrows (→ row 1, ← row 2) = alternating rotation direction
- Escape-room cylindrical padlocks = each row is a rotating ring
- Jefferson cipher turned on its end
- Column 0 overflow on chart = wrap-around from rotation
- Sanborn: "two systems of enciphering" = substitution + rotation

Models tested:
A) Pure cylindrical rotation (transposition only)
B) Rotation + Vigenère/Beaufort (product cipher)
C) Rotation with alternating Vig/Beau per row
D) All above on CT97 and CT73 (consensus null extraction)
"""

import sys
import os
import json
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
MOD = 26

AZ_INV = {c: i for i, c in enumerate(AZ)}
KA_INV = {c: i for i, c in enumerate(KA)}

CT_NUMS = [AZ_INV[c] for c in CT]

CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_NUMS = [AZ_INV[CRIB_DICT[p]] for p in CRIB_POS]

# Consensus null positions (17 fixed + 7 from varying ranges)
CONSENSUS_NULLS_17 = frozenset({0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85})

# Candidate full null sets (17 consensus + 7 from varying ranges)
# Varying: {38-45} pick 3, {55-56} pick 1, {87-88} pick 1, {93-96} pick 2
# We'll test several plausible combinations
CANDIDATE_NULL_SETS = [
    CONSENSUS_NULLS_17 | {38, 40, 42, 55, 87, 93, 95},
    CONSENSUS_NULLS_17 | {39, 41, 43, 56, 88, 94, 96},
    CONSENSUS_NULLS_17 | {38, 41, 44, 55, 88, 93, 96},
    CONSENSUS_NULLS_17 | {39, 42, 45, 56, 87, 94, 95},
    CONSENSUS_NULLS_17 | {38, 39, 40, 55, 87, 93, 94},
    CONSENSUS_NULLS_17 | {43, 44, 45, 56, 88, 95, 96},
]

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "BERLIN",
    "CLOCK", "ENIGMA", "SEVEN", "SHADOW", "KOMPASS",
    "COLOPHON", "MAGNETIC", "INVISIBLE", "BURIED",
]

RESULTS_DIR = os.path.join(_ROOT, "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


def keyword_mixed(keyword, base=AZ):
    seen = set()
    result = []
    for c in keyword.upper() + base:
        if c.isalpha() and c not in seen:
            seen.add(c)
            result.append(c)
    return "".join(result)


def extract_ct73(ct_str, null_positions):
    """Remove null positions from CT97 to get CT73."""
    return "".join(c for i, c in enumerate(ct_str) if i not in null_positions)


def map_crib_positions(null_positions):
    """Map CT97 crib positions to CT73 positions after null extraction."""
    # Build mapping: CT97 pos -> CT73 pos (for non-null positions)
    ct73_idx = 0
    mapping = {}
    for i in range(97):
        if i not in null_positions:
            mapping[i] = ct73_idx
            ct73_idx += 1
    # Map crib positions
    mapped = {}
    for pos in CRIB_POS:
        if pos in mapping:
            mapped[mapping[pos]] = CRIB_DICT[pos]
    return mapped


def score_cribs_mapped(pt_nums, crib_map):
    """Score against a mapped crib dictionary {ct73_pos: expected_char}."""
    s = 0
    for pos, ch in crib_map.items():
        exp = AZ_INV[ch]
        if pos < len(pt_nums) and pt_nums[pos] == exp:
            s += 1
    return s


def score_cribs_97(pt_nums):
    s = 0
    for pos, exp in zip(CRIB_POS, CRIB_NUMS):
        if pos < len(pt_nums) and pt_nums[pos] == exp:
            s += 1
    return s


# ============================================================
# CYLINDRICAL ROTATION
# ============================================================

def rotate_row(row, amount):
    """Rotate a list cyclically. Positive = right, negative = left."""
    if not row:
        return row
    n = len(row)
    amount = amount % n
    if amount == 0:
        return list(row)
    return row[-amount:] + row[:-amount]


def grid_to_rows(ct_nums, width):
    """Split ciphertext into grid rows of given width."""
    rows = []
    for i in range(0, len(ct_nums), width):
        rows.append(list(ct_nums[i:i + width]))
    return rows


def rows_to_flat(rows):
    """Flatten grid rows back to a single list."""
    result = []
    for r in rows:
        result.extend(r)
    return result


def decrypt_cylindrical(ct_nums, width, rot_amounts, directions):
    """Decrypt by un-rotating each row.

    rot_amounts: list of rotation amounts per row
    directions: list of +1 (right) or -1 (left) per row
    Un-rotation = rotate in opposite direction by same amount.
    """
    rows = grid_to_rows(ct_nums, width)
    for i, row in enumerate(rows):
        if i < len(rot_amounts):
            # Un-rotate: if encryption rotated right, decryption rotates left
            amt = rot_amounts[i] * directions[i]
            rows[i] = rotate_row(row, -amt)
    return rows_to_flat(rows)


def decrypt_cylindrical_plus_sub(ct_nums, width, rot_amounts, directions,
                                  keyword_nums, cipher_modes, alpha_inv):
    """Decrypt: first un-rotate rows, then apply inverse substitution.

    cipher_modes: list of 'vig' or 'beau' per row
    alpha_inv: inverse alphabet lookup (letter -> position)
    """
    # Step 1: Un-rotate rows
    rows = grid_to_rows(ct_nums, width)
    for i, row in enumerate(rows):
        if i < len(rot_amounts):
            amt = rot_amounts[i] * directions[i]
            rows[i] = rotate_row(row, -amt)
    unrotated = rows_to_flat(rows)

    # Step 2: Inverse substitution
    key_len = len(keyword_nums)
    pt = []
    for i, cv in enumerate(unrotated):
        row = i // width
        col = i % width
        ki = keyword_nums[col % key_len]

        mode = cipher_modes[row % len(cipher_modes)]
        if mode == 'vig':
            pv = (cv - ki) % MOD  # inverse Vigenere
        else:  # 'beau'
            pv = (ki - cv) % MOD  # Beaufort is self-reciprocal
        pt.append(pv)
    return pt


def decrypt_sub_plus_cylindrical(ct_nums, width, rot_amounts, directions,
                                  keyword_nums, cipher_modes, alpha_inv):
    """Decrypt: first inverse substitution, then un-rotate rows.

    (Opposite order from above — tests both orderings)
    """
    # Step 1: Inverse substitution
    key_len = len(keyword_nums)
    intermediate = []
    for i, cv in enumerate(ct_nums):
        row = i // width
        col = i % width
        ki = keyword_nums[col % key_len]

        mode = cipher_modes[row % len(cipher_modes)]
        if mode == 'vig':
            pv = (cv - ki) % MOD
        else:
            pv = (ki - cv) % MOD
        intermediate.append(pv)

    # Step 2: Un-rotate rows
    rows = grid_to_rows(intermediate, width)
    for i, row in enumerate(rows):
        if i < len(rot_amounts):
            amt = rot_amounts[i] * directions[i]
            rows[i] = rotate_row(row, -amt)
    return rows_to_flat(rows)


# ============================================================
# SEARCH
# ============================================================

def run_test(ct_nums, ct_len, score_fn, label, widths=None):
    """Run cylindrical rotation test on a ciphertext."""
    print(f"\n{'='*60}")
    print(f"  {label} (len={ct_len})")
    print(f"{'='*60}")

    if widths is None:
        widths = [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 19, 21, 23, 31]

    # Direction patterns
    dir_patterns = {
        "RL": [1, -1],    # → ← → ← (right then left)
        "LR": [-1, 1],    # ← → ← → (left then right)
    }

    # Cipher mode patterns
    mode_patterns = {
        "vig_beau": ['vig', 'beau'],
        "beau_vig": ['beau', 'vig'],
        "vig_only": ['vig'],
        "beau_only": ['beau'],
    }

    # Key alphabets
    key_alphas = {"AZ": AZ_INV, "KA": KA_INV}

    best = 0
    best_cfgs = []
    total = 0

    # ── Model A: Pure rotation (transposition only) ──
    print("\n  --- Model A: Pure cylindrical rotation ---")
    a_best = 0
    for w in widths:
        n_rows = (ct_len + w - 1) // w
        for dn, dp in dir_patterns.items():
            dirs = [dp[i % len(dp)] for i in range(n_rows)]
            # Try all rotation amounts for each row (keyword-derived)
            for kw in KEYWORDS:
                # Rotation from keyword letter values (AZ)
                kw_rots_az = [AZ_INV[c] % w for c in kw]
                # Rotation from keyword letter values (KA)
                kw_rots_ka = [KA_INV[c] % w for c in kw]
                for rot_name, kw_rots in [("AZ", kw_rots_az), ("KA", kw_rots_ka)]:
                    rot_amounts = [kw_rots[i % len(kw_rots)] for i in range(n_rows)]
                    pt = decrypt_cylindrical(ct_nums, w, rot_amounts, dirs)
                    sc = score_fn(pt)
                    total += 1
                    if sc > a_best:
                        a_best = sc
                        if sc > best:
                            best = sc
                        txt = "".join(AZ[v] for v in pt[:60])
                        cfg = f"A w={w} dir={dn} kw={kw}_{rot_name}"
                        best_cfgs.append((sc, cfg, txt))
                        if sc >= 5:
                            print(f"    {sc}/24 — {cfg}")

            # Also try uniform rotation amounts 0..w-1
            for rot_amt in range(w):
                rot_amounts = [rot_amt] * n_rows
                pt = decrypt_cylindrical(ct_nums, w, rot_amounts, dirs)
                sc = score_fn(pt)
                total += 1
                if sc > a_best:
                    a_best = sc
                    if sc > best:
                        best = sc
                    txt = "".join(AZ[v] for v in pt[:60])
                    cfg = f"A w={w} dir={dn} uniform_rot={rot_amt}"
                    best_cfgs.append((sc, cfg, txt))
                    if sc >= 5:
                        print(f"    {sc}/24 — {cfg}")

    print(f"    Model A best: {a_best}/24")

    # ── Model B: Rotation + substitution (both orderings) ──
    print("\n  --- Model B: Rotation + Vig/Beau substitution ---")
    b_best = 0
    for w in widths:
        n_rows = (ct_len + w - 1) // w
        for dn, dp in dir_patterns.items():
            dirs = [dp[i % len(dp)] for i in range(n_rows)]
            for mn, mp in mode_patterns.items():
                modes = mp
                for ka_name, ka_inv in key_alphas.items():
                    for kw in KEYWORDS:
                        kw_nums = [ka_inv[c] for c in kw]
                        kw_rots = [ka_inv[c] % w for c in kw]
                        rot_amounts = [kw_rots[i % len(kw_rots)] for i in range(n_rows)]

                        # Order 1: un-rotate then un-sub
                        pt = decrypt_cylindrical_plus_sub(
                            ct_nums, w, rot_amounts, dirs,
                            kw_nums, modes, ka_inv)
                        sc = score_fn(pt)
                        total += 1
                        if sc > b_best:
                            b_best = sc
                            if sc > best:
                                best = sc
                            txt = "".join(AZ[v] for v in pt[:60])
                            cfg = f"B1 w={w} dir={dn} mode={mn} kw={kw}_{ka_name}"
                            best_cfgs.append((sc, cfg, txt))
                            if sc >= 5:
                                print(f"    {sc}/24 — {cfg}")

                        # Order 2: un-sub then un-rotate
                        pt = decrypt_sub_plus_cylindrical(
                            ct_nums, w, rot_amounts, dirs,
                            kw_nums, modes, ka_inv)
                        sc = score_fn(pt)
                        total += 1
                        if sc > b_best:
                            b_best = sc
                            if sc > best:
                                best = sc
                            txt = "".join(AZ[v] for v in pt[:60])
                            cfg = f"B2 w={w} dir={dn} mode={mn} kw={kw}_{ka_name}"
                            best_cfgs.append((sc, cfg, txt))
                            if sc >= 5:
                                print(f"    {sc}/24 — {cfg}")

    print(f"    Model B best: {b_best}/24")

    # ── Model C: Exhaustive rotation per row (small widths only) ──
    # For small widths, try ALL rotation amounts independently per row
    print("\n  --- Model C: Exhaustive rotation (small widths) ---")
    c_best = 0
    small_widths = [w for w in widths if w <= 13]
    for w in small_widths:
        n_rows = (ct_len + w - 1) // w
        if n_rows > 12:
            continue  # too many rows for exhaustive
        for dn, dp in dir_patterns.items():
            dirs = [dp[i % len(dp)] for i in range(n_rows)]
            for mn, mp in mode_patterns.items():
                modes = mp
                for ka_name, ka_inv in key_alphas.items():
                    for kw in KEYWORDS[:5]:  # top 5 keywords only
                        kw_nums = [ka_inv[c] for c in kw]
                        # Try all rotation amounts for EACH ROW independently
                        # But this is w^n_rows which is huge. Instead:
                        # Try row-0 rotation exhaustively, others from keyword
                        kw_rots = [ka_inv[c] % w for c in kw]
                        base_rots = [kw_rots[i % len(kw_rots)] for i in range(n_rows)]
                        for r0_offset in range(w):
                            rot_amounts = list(base_rots)
                            rot_amounts[0] = (rot_amounts[0] + r0_offset) % w
                            pt = decrypt_cylindrical_plus_sub(
                                ct_nums, w, rot_amounts, dirs,
                                kw_nums, modes, ka_inv)
                            sc = score_fn(pt)
                            total += 1
                            if sc > c_best:
                                c_best = sc
                                if sc > best:
                                    best = sc
                                txt = "".join(AZ[v] for v in pt[:60])
                                cfg = f"C w={w} dir={dn} mode={mn} kw={kw}_{ka_name} r0off={r0_offset}"
                                best_cfgs.append((sc, cfg, txt))
                                if sc >= 5:
                                    print(f"    {sc}/24 — {cfg}")

    print(f"    Model C best: {c_best}/24")

    print(f"\n  Total: {total} configs, overall best: {best}/24")

    # Keep only top results
    best_cfgs.sort(key=lambda x: -x[0])
    return best, best_cfgs[:20], total


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    print("Cylindrical Grid Rotation Model for K4")
    print("Hypothesis: rows are rings that rotate (→/←), like a Jefferson cipher")
    print(f"CT97: {CT}")
    print()

    t0 = time.time()
    all_results = {}

    # Test on CT97
    best97, cfgs97, n97 = run_test(
        CT_NUMS, CT_LEN,
        score_cribs_97,
        "CT97 (raw carved text)")
    all_results["ct97"] = {
        "configs": n97, "best_score": best97,
        "best": [(s, c, t) for s, c, t in cfgs97[:10]],
    }

    # Test on CT73 with candidate null sets
    best73_overall = 0
    for ni, null_set in enumerate(CANDIDATE_NULL_SETS):
        ct73_str = extract_ct73(CT, null_set)
        ct73_nums = [AZ_INV[c] for c in ct73_str]
        crib_map = map_crib_positions(null_set)

        def score_fn(pt, cm=crib_map):
            return score_cribs_mapped(pt, cm)

        b, cfgs, n = run_test(
            ct73_nums, len(ct73_nums),
            score_fn,
            f"CT73 null set #{ni+1} (len={len(ct73_str)})")

        if b > best73_overall:
            best73_overall = b

        all_results[f"ct73_nullset_{ni+1}"] = {
            "null_set": sorted(null_set),
            "ct73_len": len(ct73_str),
            "configs": n, "best_score": b,
            "best": [(s, c, t) for s, c, t in cfgs[:10]],
        }

    elapsed = time.time() - t0

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  CT97 best:     {best97}/24")
    print(f"  CT73 best:     {best73_overall}/24")
    overall = max(best97, best73_overall)
    print(f"  Overall:       {overall}/24")
    print(f"  Time:          {elapsed:.1f}s")

    if overall >= 8:
        print("\n  *** SIGNIFICANT — investigate further ***")
    elif overall >= 6:
        print("\n  Above noise but not significant.")
    else:
        print("\n  All at noise level.")

    all_results["overall_best"] = overall
    all_results["conclusion"] = (
        "SIGNAL" if overall >= 18 else
        "INTERESTING" if overall >= 10 else
        "NOISE"
    )

    outfile = os.path.join(RESULTS_DIR, "e_ts_cylindrical_rotation.json")
    with open(outfile, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nResults → {outfile}")
