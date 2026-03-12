#!/usr/bin/env python3
"""
Meet-in-the-Middle: Find transpositions that maximize keystream R²
===================================================================

The regression analysis proved: keystream at carved positions {21-33, 63-73}
has NO exploitable structure (adj R² < 0.3). This means the carved positions
don't correspond to cipher positions — a transposition scrambles them.

This script inverts the problem:
  For each candidate transposition σ:
    1. Remap 24 crib positions: new_pos[j] = σ⁻¹(crib_pos[j])
    2. Compute key values: k = f(CT[new_pos[j]], PT[j]) for each cipher mode
    3. Check: does k show periodic structure at the new positions?
       - Count conflicts: same residue mod P should have same key value
       - 0 conflicts = BREAKTHROUGH (exact periodic key)
       - Also compute R² for progressive models

Transposition families tested:
  - Columnar w=4-9 (exhaustive column orderings: up to 362,880)
  - Columnar w=10-14 (keyword-derived orderings from thematic list)
  - Rail fence (depths 2-20)
  - Reversed segments, reversed rows, serpentine
"""

import sys
sys.path.insert(0, 'src')

import time
import itertools
import numpy as np
from kryptos.kernel.constants import CT
from kryptos.kernel.alphabet import AZ, KA

# ── Precompute constants ─────────────────────────────────────────────────────
N = 97

# Crib positions and PT characters
ENE_POS, ENE_PT = 21, 'EASTNORTHEAST'
BC_POS, BC_PT = 63, 'BERLINCLOCK'

CRIB_POS = []
CRIB_PT = []
for j, ch in enumerate(ENE_PT):
    CRIB_POS.append(ENE_POS + j)
    CRIB_PT.append(ch)
for j, ch in enumerate(BC_PT):
    CRIB_POS.append(BC_POS + j)
    CRIB_PT.append(ch)

CRIB_POS = np.array(CRIB_POS)  # (24,)
N_CRIB = len(CRIB_POS)

# Precompute numerical values
CT_AZ = np.array([ord(c) - 65 for c in CT])  # (97,) AZ alphabet
CT_KA_MAP = {c: i for i, c in enumerate('KRYPTOSABCDEFGHIJLMNQUVWXZ')}
CT_KA = np.array([CT_KA_MAP[c] for c in CT])  # (97,) KA alphabet

PT_AZ = np.array([ord(c) - 65 for c in CRIB_PT])  # (24,)
KA_STR = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
PT_KA = np.array([CT_KA_MAP[c] for c in CRIB_PT])  # (24,)


def count_conflicts(positions, key_vals, period):
    """Count conflicts: pairs in the same residue class with different key values."""
    residues = positions % period
    conflicts = 0
    # Group by residue
    for r in range(period):
        mask = residues == r
        vals = key_vals[mask]
        if len(vals) <= 1:
            continue
        # Conflicts = number of values that differ from the first
        conflicts += np.sum(vals != vals[0])
    return conflicts


def compute_keys_and_check(new_positions, ct_nums, pt_nums, periods):
    """Compute keystream and check periodicity for all modes.

    Returns dict: mode -> {period -> conflict_count}
    """
    results = {}

    # 3 modes: vig (CT-PT), beau (CT+PT), vbeau (PT-CT)
    ct_at_new = ct_nums[new_positions]  # (24,)

    keys_vig = (ct_at_new - pt_nums) % 26
    keys_beau = (ct_at_new + pt_nums) % 26
    keys_vbeau = (pt_nums - ct_at_new) % 26

    for mode_name, keys in [('vig', keys_vig), ('beau', keys_beau), ('vbeau', keys_vbeau)]:
        mode_results = {}
        for p in periods:
            c = count_conflicts(new_positions, keys, p)
            mode_results[p] = c
        results[mode_name] = mode_results

    return results


def ols_r2_periodic(positions, key_vals, period):
    """R² for periodic model (indicator variables for residue classes)."""
    n = len(positions)
    if period >= n:
        return 1.0  # saturated

    X = np.zeros((n, period))
    for j in range(period):
        X[:, j] = (positions % period == j).astype(float)

    try:
        coeffs = np.linalg.lstsq(X, key_vals.astype(float), rcond=None)[0]
        y_pred = X @ coeffs
        ss_res = np.sum((key_vals.astype(float) - y_pred) ** 2)
        ss_tot = np.sum((key_vals.astype(float) - np.mean(key_vals)) ** 2)
        if ss_tot < 1e-10:
            return 1.0
        return max(0, 1 - ss_res / ss_tot)
    except:
        return 0.0


def ols_r2_progressive(positions, key_vals, period):
    """R² for progressive model (periodic indicators + linear row term)."""
    n = len(positions)
    if period + 1 >= n:
        return 1.0

    X = np.zeros((n, period + 1))
    for j in range(period):
        X[:, j] = (positions % period == j).astype(float)
    X[:, period] = positions // period  # row number

    try:
        coeffs = np.linalg.lstsq(X, key_vals.astype(float), rcond=None)[0]
        y_pred = X @ coeffs
        ss_res = np.sum((key_vals.astype(float) - y_pred) ** 2)
        ss_tot = np.sum((key_vals.astype(float) - np.mean(key_vals)) ** 2)
        if ss_tot < 1e-10:
            return 1.0
        r2 = max(0, 1 - ss_res / ss_tot)
        adj_r2 = 1 - (1 - r2) * (n - 1) / (n - period - 2) if n > period + 2 else float('nan')
        return adj_r2
    except:
        return 0.0


# ── Transposition generators ─────────────────────────────────────────────────

def columnar_inv_perm(width, col_order):
    """Build inverse permutation for columnar transposition.

    Forward: write PT row-by-row into grid of width w, read columns in col_order.
    inv_perm[pt_pos] = ct_pos (where PT character ends up in intermediate/CT).
    """
    n_rows = (N + width - 1) // width
    n_long = N % width  # columns with n_rows entries
    if n_long == 0:
        n_long = width

    # Column lengths
    col_len = np.array([n_rows if c < n_long else n_rows - 1 for c in range(width)])

    # Build forward perm: perm[ct_pos] = pt_pos
    # Reading column col_order[c_idx], rows 0..col_len[col]-1
    perm = np.empty(N, dtype=np.int32)
    offset = 0
    for c_idx in range(width):
        c = col_order[c_idx]
        for r in range(col_len[c]):
            perm[offset] = r * width + c
            offset += 1

    # Inverse: inv_perm[pt_pos] = ct_pos
    inv_perm = np.empty(N, dtype=np.int32)
    inv_perm[perm] = np.arange(N, dtype=np.int32)

    return inv_perm


def rail_fence_inv_perm(depth):
    """Inverse permutation for rail fence cipher."""
    # Build the zigzag pattern
    rails = [[] for _ in range(depth)]
    rail = 0
    direction = 1
    for i in range(N):
        rails[rail].append(i)
        if rail == 0:
            direction = 1
        elif rail == depth - 1:
            direction = -1
        rail += direction

    # Forward perm: read rails top to bottom
    perm = []
    for rail_list in rails:
        perm.extend(rail_list)
    perm = np.array(perm, dtype=np.int32)

    inv_perm = np.empty(N, dtype=np.int32)
    inv_perm[perm] = np.arange(N, dtype=np.int32)
    return inv_perm


def reverse_segments_inv_perm(segment_len):
    """Reverse each segment of given length."""
    perm = np.arange(N, dtype=np.int32)
    for start in range(0, N, segment_len):
        end = min(start + segment_len, N)
        perm[start:end] = perm[start:end][::-1]
    # This is its own inverse (reversing twice = identity), but the perm
    # maps input position to output position in scatter convention.
    # Actually: output[i] = input[perm[i]] where perm swaps within segments.
    inv_perm = np.empty(N, dtype=np.int32)
    inv_perm[perm] = np.arange(N, dtype=np.int32)
    return inv_perm


def serpentine_inv_perm(width):
    """Boustrophedon: reverse every other row in a grid of given width."""
    perm = np.arange(N, dtype=np.int32)
    n_rows = (N + width - 1) // width
    for r in range(n_rows):
        if r % 2 == 1:  # reverse odd rows
            start = r * width
            end = min(start + width, N)
            perm[start:end] = perm[start:end][::-1]

    inv_perm = np.empty(N, dtype=np.int32)
    inv_perm[perm] = np.arange(N, dtype=np.int32)
    return inv_perm


def keyword_to_col_order(keyword, width):
    """Derive column order from keyword for columnar transposition."""
    if len(keyword) < width:
        # Pad with remaining letters
        used = set(keyword.upper())
        extra = [c for c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if c not in used]
        keyword = keyword.upper() + ''.join(extra[:width - len(keyword)])
    keyword = keyword.upper()[:width]

    # Rank by alphabetical order (stable sort for ties)
    indexed = sorted(range(width), key=lambda i: keyword[i])
    col_order = [0] * width
    for rank, idx in enumerate(indexed):
        col_order[rank] = idx
    return col_order


# ── Main search ──────────────────────────────────────────────────────────────

def search_columnar_exhaustive(width, periods):
    """Exhaustive search over all column orderings for given width."""
    n_perms = 1
    for i in range(1, width + 1):
        n_perms *= i

    print(f"\n  Width {width}: {n_perms} orderings")

    best_by_mode = {}  # mode -> (min_conflicts, period, col_order)
    best_r2_by_mode = {}  # mode -> (max_adj_r2, period, col_order)

    t0 = time.time()

    for perm_idx, col_order in enumerate(itertools.permutations(range(width))):
        inv_perm = columnar_inv_perm(width, col_order)
        new_pos = inv_perm[CRIB_POS]  # (24,) remapped positions

        for alph_name, ct_nums, pt_nums in [('AZ', CT_AZ, PT_AZ), ('KA', CT_KA, PT_KA)]:
            results = compute_keys_and_check(new_pos, ct_nums, pt_nums, periods)

            for mode_name, mode_results in results.items():
                key = f"{alph_name}/{mode_name}"
                for p, conflicts in mode_results.items():
                    if key not in best_by_mode or conflicts < best_by_mode[key][0]:
                        best_by_mode[key] = (conflicts, p, list(col_order))
                    elif conflicts == best_by_mode[key][0] and p < best_by_mode[key][1]:
                        best_by_mode[key] = (conflicts, p, list(col_order))

        if perm_idx > 0 and perm_idx % 50000 == 0:
            elapsed = time.time() - t0
            rate = perm_idx / elapsed
            remaining = (n_perms - perm_idx) / rate
            print(f"    {perm_idx}/{n_perms} ({elapsed:.1f}s, {remaining:.1f}s remaining)")

    elapsed = time.time() - t0
    print(f"    Done in {elapsed:.1f}s")

    return best_by_mode


def search_columnar_keywords(width, periods, keywords):
    """Search keyword-derived column orderings for given width."""
    best_by_mode = {}
    tested = set()

    for kw in keywords:
        if len(kw) < width:
            continue
        col_order = keyword_to_col_order(kw, width)
        col_key = tuple(col_order)
        if col_key in tested:
            continue
        tested.add(col_key)

        inv_perm = columnar_inv_perm(width, col_order)
        new_pos = inv_perm[CRIB_POS]

        for alph_name, ct_nums, pt_nums in [('AZ', CT_AZ, PT_AZ), ('KA', CT_KA, PT_KA)]:
            results = compute_keys_and_check(new_pos, ct_nums, pt_nums, periods)

            for mode_name, mode_results in results.items():
                key = f"{alph_name}/{mode_name}"
                for p, conflicts in mode_results.items():
                    if key not in best_by_mode or conflicts < best_by_mode[key][0]:
                        best_by_mode[key] = (conflicts, p, col_order, kw)

    print(f"  Width {width}: {len(tested)} unique orderings from {len(keywords)} keywords")
    return best_by_mode


def search_non_columnar(periods):
    """Search non-columnar transposition families."""
    best_by_mode = {}

    configs = []

    # Rail fence
    for depth in range(2, 21):
        inv_perm = rail_fence_inv_perm(depth)
        configs.append((f"rail_fence_d{depth}", inv_perm))

    # Reverse segments
    for seg_len in range(2, 50):
        inv_perm = reverse_segments_inv_perm(seg_len)
        configs.append((f"reverse_seg_{seg_len}", inv_perm))

    # Serpentine
    for width in range(4, 25):
        inv_perm = serpentine_inv_perm(width)
        configs.append((f"serpentine_w{width}", inv_perm))

    # Simple reverse
    perm = np.arange(N - 1, -1, -1, dtype=np.int32)
    inv_perm = np.empty(N, dtype=np.int32)
    inv_perm[perm] = np.arange(N, dtype=np.int32)
    configs.append(("full_reverse", inv_perm))

    print(f"\n  Non-columnar: {len(configs)} configurations")

    for label, inv_perm in configs:
        new_pos = inv_perm[CRIB_POS]

        for alph_name, ct_nums, pt_nums in [('AZ', CT_AZ, PT_AZ), ('KA', CT_KA, PT_KA)]:
            results = compute_keys_and_check(new_pos, ct_nums, pt_nums, periods)

            for mode_name, mode_results in results.items():
                key = f"{alph_name}/{mode_name}"
                for p, conflicts in mode_results.items():
                    if key not in best_by_mode or conflicts < best_by_mode[key][0]:
                        best_by_mode[key] = (conflicts, p, label)

    return best_by_mode


def deep_analysis(inv_perm, label, periods_to_check):
    """Full regression analysis for a specific transposition."""
    new_pos = inv_perm[CRIB_POS]

    print(f"\n  Deep analysis: {label}")
    print(f"  Remapped positions: {sorted(new_pos)}")
    print(f"  Position spread: {np.min(new_pos)}-{np.max(new_pos)}")
    print(f"  Unique positions: {len(np.unique(new_pos))}/24")

    if len(np.unique(new_pos)) < 24:
        print(f"  WARNING: Position collision! Transposition maps 2+ crib chars to same position.")
        return

    for alph_name, ct_nums, pt_nums in [('AZ', CT_AZ, PT_AZ), ('KA', CT_KA, PT_KA)]:
        ct_at_new = ct_nums[new_pos]

        for mode_name, keys in [
            ('vig', (ct_at_new - pt_nums) % 26),
            ('beau', (ct_at_new + pt_nums) % 26),
            ('vbeau', (pt_nums - ct_at_new) % 26),
        ]:
            label_full = f"{alph_name}/{mode_name}"

            # Conflict check
            for p in periods_to_check:
                conflicts = count_conflicts(new_pos, keys, p)
                if conflicts <= 3:
                    r2 = ols_r2_periodic(new_pos, keys, p)
                    adj_r2 = ols_r2_progressive(new_pos, keys, p)
                    print(f"    {label_full} period {p:2d}: conflicts={conflicts}, "
                          f"R²={r2:.4f}, prog_adj_R²={adj_r2:.4f}")


def main():
    print("=" * 90)
    print("MEET-IN-THE-MIDDLE: Transposition Search via Keystream R²")
    print("=" * 90)
    print(f"\nSearching for transpositions that make the keystream periodic.")
    print(f"For each transposition σ, we remap 24 crib positions and check")
    print(f"if key values at remapped positions show periodic structure.")
    print(f"0 conflicts at period P ≤ 12 = BREAKTHROUGH.\n")

    periods = list(range(1, 16))  # periods 1-15

    # ── Phase 1: Columnar exhaustive (w=4-9) ─────────────────────────────────
    print("=" * 90)
    print("PHASE 1: Columnar transposition, exhaustive column orderings")
    print("=" * 90)

    all_columnar_best = {}
    overall_best = {}

    for width in range(4, 10):
        best = search_columnar_exhaustive(width, periods)

        for key, (conflicts, p, col_order) in best.items():
            label = f"col_w{width}"
            if key not in overall_best or conflicts < overall_best[key][0]:
                overall_best[key] = (conflicts, p, f"{label}/{col_order}")

    # Print summary
    print(f"\n  {'Mode':<12s} {'Min conflicts':>14s} {'Period':>7s} {'Config':<30s}")
    print(f"  {'-'*65}")
    for key in sorted(overall_best.keys()):
        conflicts, p, config = overall_best[key]
        flag = ' *** ZERO ***' if conflicts == 0 else ''
        print(f"  {key:<12s} {conflicts:>14d} {p:>7d} {config:<30s}{flag}")

    # ── Phase 2: Columnar with keywords (w=10-14) ────────────────────────────
    print(f"\n{'='*90}")
    print("PHASE 2: Columnar transposition, keyword-derived orderings (w=10-14)")
    print("=" * 90)

    # Load thematic keywords
    try:
        with open('wordlists/thematic_keywords.txt') as f:
            keywords = [line.strip().upper() for line in f if line.strip()]
    except FileNotFoundError:
        keywords = []

    # Add priority keywords
    keywords.extend([
        'KRYPTOS', 'KOMPASS', 'DEFECTOR', 'COLOPHON', 'ABSCISSA',
        'PALIMPSEST', 'BERLINCLOCK', 'EASTNORTHEAST', 'SANBORN',
        'SCHEIDT', 'CIPHER', 'ENIGMA', 'INTELLIGENCE', 'SHADOW',
    ])
    keywords = list(set(keywords))

    for width in range(10, 15):
        best = search_columnar_keywords(width, periods, keywords)
        for key, (conflicts, p, col_order, kw) in best.items():
            label = f"col_w{width}/kw={kw}"
            if key not in overall_best or conflicts < overall_best[key][0]:
                overall_best[key] = (conflicts, p, label)

    # ── Phase 3: Non-columnar transpositions ──────────────────────────────────
    print(f"\n{'='*90}")
    print("PHASE 3: Non-columnar transpositions (rail fence, serpentine, etc.)")
    print("=" * 90)

    nc_best = search_non_columnar(periods)
    for key, (conflicts, p, config) in nc_best.items():
        if key not in overall_best or conflicts < overall_best[key][0]:
            overall_best[key] = (conflicts, p, config)

    # ── Overall summary ──────────────────────────────────────────────────────
    print(f"\n{'='*90}")
    print("OVERALL BEST (minimum conflicts per cipher mode)")
    print("=" * 90)
    print(f"\n  {'Mode':<12s} {'Min conflicts':>14s} {'Period':>7s} {'Config':<40s}")
    print(f"  {'-'*75}")
    for key in sorted(overall_best.keys()):
        conflicts, p, config = overall_best[key]
        flag = ' *** BREAKTHROUGH ***' if conflicts == 0 else ''
        if conflicts <= 2:
            flag = flag or ' ◀ VERY LOW'
        print(f"  {key:<12s} {conflicts:>14d} {p:>7d} {config:<40s}{flag}")

    # ── Deep analysis on best configs ─────────────────────────────────────────
    print(f"\n{'='*90}")
    print("DEEP ANALYSIS: Best configurations")
    print("=" * 90)

    # Reconstruct the best transpositions for deep analysis
    seen = set()
    for key in sorted(overall_best.keys()):
        conflicts, p, config = overall_best[key]
        if conflicts > 4:
            continue
        if config in seen:
            continue
        seen.add(config)

        # Parse config to reconstruct inv_perm
        if config.startswith('col_w'):
            parts = config.split('/')
            w = int(parts[0].replace('col_w', ''))
            col_order = eval(parts[1]) if '[' in parts[1] else None
            if col_order is not None:
                inv_perm = columnar_inv_perm(w, col_order)
                deep_analysis(inv_perm, config, list(range(1, 16)))
        elif config.startswith('rail_fence'):
            depth = int(config.split('_d')[1])
            inv_perm = rail_fence_inv_perm(depth)
            deep_analysis(inv_perm, config, list(range(1, 16)))
        elif config.startswith('serpentine'):
            w = int(config.split('_w')[1])
            inv_perm = serpentine_inv_perm(w)
            deep_analysis(inv_perm, config, list(range(1, 16)))

    # ── Comparison with baseline (no transposition) ──────────────────────────
    print(f"\n{'='*90}")
    print("BASELINE: No transposition (identity permutation)")
    print("=" * 90)

    identity = np.arange(N, dtype=np.int32)
    deep_analysis(identity, "identity (no transposition)", list(range(1, 16)))

    # ── Verdict ──────────────────────────────────────────────────────────────
    print(f"\n{'='*90}")
    print("VERDICT")
    print("=" * 90)

    any_zero = any(v[0] == 0 for v in overall_best.values())
    min_conflicts = min(v[0] for v in overall_best.values())

    if any_zero:
        print("\n  *** ZERO CONFLICTS FOUND — potential BREAKTHROUGH! ***")
        print("  Verify by full decryption and plaintext quality check.")
    elif min_conflicts <= 2:
        print(f"\n  Minimum conflicts = {min_conflicts}. Close to periodic consistency.")
        print("  Worth investigating with expanded transposition search.")
    else:
        print(f"\n  Minimum conflicts = {min_conflicts}.")
        print("  No columnar/rail/serpentine transposition makes the keystream periodic.")
        print("  Either:")
        print("  • The transposition is non-standard (bespoke)")
        print("  • The substitution is non-periodic (autokey, running key)")
        print("  • Both systems are more complex than tested")
        print("  • The two-system model involves null removal before transposition")


if __name__ == '__main__':
    main()
