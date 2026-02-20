#!/usr/bin/env python3
"""E-FRAC-09: Structural Characterization of Bimodal-Compatible Permutations.

E-FRAC-08 proved that NO columnar transposition (any width 2-20) satisfies
the bimodal fingerprint. This experiment asks: what kinds of permutations
DO satisfy bimodal? This characterizes the viable search space for TRANS/BESPOKE.

Analyses:
1. Random permutation bimodal compatibility rate
2. Structural properties of bimodal-compatible permutations:
   - Average displacement
   - Displacement distribution (how "local" vs "global" are the swaps)
   - Number of fixed points (positions that don't move)
   - Block structure (are displacements clustered?)
   - Cycle structure
3. Bimodal compatibility under structured transposition families:
   - Rail fence
   - Route cipher (various routes on various grid sizes)
   - Strip manipulation (Sanborn's stated method)
   - Partial identity + block swap
   - "Nearly identity" permutations (small number of swaps)
4. Bimodal-compatible permutations that also pass Bean constraints

Output: Structural profile that tells TRANS/BESPOKE what to search for.
"""
import itertools
import json
import math
import os
import random
import time
from collections import Counter, defaultdict

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_SET = set(CRIB_DICT.keys())
CRIB_PT_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
random.seed(42)


def bimodal_check(perm, ene_tolerance=5, bc_max_identity=4):
    """Standard bimodal check: positions 22-30 near-identity, 64-74 scattered."""
    for i in range(22, 31):
        if i < CT_LEN:
            if abs(perm[i] - i) > ene_tolerance:
                return False
    bc_identity = 0
    for i in range(64, min(75, CT_LEN)):
        if abs(perm[i] - i) <= 2:
            bc_identity += 1
    return bc_identity <= bc_max_identity


def perm_stats(perm):
    """Compute structural properties of a permutation."""
    n = len(perm)
    displacements = [abs(perm[i] - i) for i in range(n)]
    avg_disp = sum(displacements) / n
    max_disp = max(displacements)
    fixed_points = sum(1 for i in range(n) if perm[i] == i)
    near_fixed = sum(1 for i in range(n) if abs(perm[i] - i) <= 2)

    # Displacement by region
    region1 = displacements[:22]  # before ENE
    region2 = displacements[22:31]  # ENE region
    region3 = displacements[31:64]  # middle
    region4 = displacements[64:75]  # BC region
    region5 = displacements[75:]  # after BC

    # Cycle structure
    visited = [False] * n
    cycle_lengths = []
    for start in range(n):
        if visited[start]:
            continue
        cycle_len = 0
        pos = start
        while not visited[pos]:
            visited[pos] = True
            pos = perm[pos]
            cycle_len += 1
        cycle_lengths.append(cycle_len)

    return {
        "avg_disp": avg_disp,
        "max_disp": max_disp,
        "fixed_points": fixed_points,
        "near_fixed": near_fixed,
        "disp_region_before_ene": sum(region1) / max(len(region1), 1),
        "disp_region_ene": sum(region2) / max(len(region2), 1),
        "disp_region_middle": sum(region3) / max(len(region3), 1),
        "disp_region_bc": sum(region4) / max(len(region4), 1),
        "disp_region_after_bc": sum(region5) / max(len(region5), 1),
        "n_cycles": len(cycle_lengths),
        "max_cycle": max(cycle_lengths),
        "n_fixed_or_2cycles": sum(1 for c in cycle_lengths if c <= 2),
    }


def check_bean_equality(perm):
    """Check Bean equality constraint k[27] == k[65] under perm."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    ct_pos_27 = inv[27]
    ct_pos_65 = inv[65]
    k27 = (CT_NUM[ct_pos_27] - CRIB_PT_NUM[27]) % MOD
    k65 = (CT_NUM[ct_pos_65] - CRIB_PT_NUM[65]) % MOD
    return k27 == k65


# ── Structured transposition generators ──────────────────────────────

def rail_fence_perm(n, rails):
    """Generate a rail fence cipher permutation."""
    fence = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for i in range(n):
        fence[rail].append(i)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction

    perm = [0] * n
    pos = 0
    for rail_positions in fence:
        for orig_pos in rail_positions:
            perm[pos] = orig_pos
            pos += 1
    return perm


def route_cipher_perm(n, width, route_type="row_alt"):
    """Generate route cipher permutations on a grid.

    route_type:
        "row_alt" - boustrophedon (alternating row direction)
        "col_down" - read columns top to bottom
        "col_alt" - serpentine columns
        "spiral_in" - clockwise spiral inward
    """
    n_rows = math.ceil(n / width)
    grid = []
    idx = 0
    for r in range(n_rows):
        row = []
        for c in range(width):
            if idx < n:
                row.append(idx)
            else:
                row.append(None)
            idx += 1
        grid.append(row)

    reading = []
    if route_type == "row_alt":
        for r in range(n_rows):
            row = grid[r]
            if r % 2 == 1:
                row = list(reversed(row))
            for val in row:
                if val is not None:
                    reading.append(val)

    elif route_type == "col_down":
        for c in range(width):
            for r in range(n_rows):
                if c < len(grid[r]) and grid[r][c] is not None:
                    reading.append(grid[r][c])

    elif route_type == "col_alt":
        for c in range(width):
            col_vals = []
            for r in range(n_rows):
                if c < len(grid[r]) and grid[r][c] is not None:
                    col_vals.append(grid[r][c])
            if c % 2 == 1:
                col_vals.reverse()
            reading.extend(col_vals)

    elif route_type == "spiral_in":
        top, bottom, left, right = 0, n_rows - 1, 0, width - 1
        while top <= bottom and left <= right:
            for c in range(left, right + 1):
                if top < n_rows and c < len(grid[top]) and grid[top][c] is not None:
                    reading.append(grid[top][c])
            top += 1
            for r in range(top, bottom + 1):
                if r < n_rows and right < len(grid[r]) and grid[r][right] is not None:
                    reading.append(grid[r][right])
            right -= 1
            if top <= bottom:
                for c in range(right, left - 1, -1):
                    if bottom < n_rows and c < len(grid[bottom]) and grid[bottom][c] is not None:
                        reading.append(grid[bottom][c])
                bottom -= 1
            if left <= right:
                for r in range(bottom, top - 1, -1):
                    if r < n_rows and left < len(grid[r]) and grid[r][left] is not None:
                        reading.append(grid[r][left])
                left += 1

    # reading[i] = which original position goes to output position i
    # We need perm[i] = source position for output position i
    if len(reading) == n:
        return reading
    return None


def strip_manipulation_perm(n, strip_width, operations):
    """Generate strip manipulation permutations.

    Write plaintext on strips of strip_width characters, then rearrange/flip strips.
    operations: list of (strip_index, flip) tuples defining the output order.
    """
    n_strips = math.ceil(n / strip_width)
    strips = []
    for s in range(n_strips):
        start = s * strip_width
        end = min(start + strip_width, n)
        strips.append(list(range(start, end)))

    perm = []
    for strip_idx, flip in operations:
        if strip_idx < n_strips:
            strip = strips[strip_idx]
            if flip:
                strip = list(reversed(strip))
            perm.extend(strip)

    if len(perm) == n:
        return perm
    return None


def local_swap_perm(n, n_swaps, max_distance):
    """Generate permutation by applying n_swaps random swaps within max_distance."""
    perm = list(range(n))
    for _ in range(n_swaps):
        i = random.randint(0, n - 1)
        # Pick j within max_distance of i
        j_min = max(0, i - max_distance)
        j_max = min(n - 1, i + max_distance)
        j = random.randint(j_min, j_max)
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def block_swap_perm(n, block_a_start, block_a_end, block_b_start, block_b_end):
    """Swap two blocks, keep everything else in place."""
    perm = list(range(n))
    block_a = list(range(block_a_start, block_a_end))
    block_b = list(range(block_b_start, block_b_end))

    if len(block_a) != len(block_b):
        return None

    for i, j in zip(block_a, block_b):
        perm[i], perm[j] = perm[j], perm[i]
    return perm


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-FRAC-09: Structural Characterization of Bimodal-Compatible Permutations")
    print("=" * 70)
    print()

    # ── Part 1: Random permutation bimodal rate ──────────────────────
    print("Part 1: Random Permutation Bimodal Compatibility")
    print("-" * 50)

    N_RANDOM = 1_000_000
    bimodal_pass = 0
    bimodal_and_bean = 0
    passing_stats = []
    failing_stats_sample = []

    for trial in range(N_RANDOM):
        perm = list(range(CT_LEN))
        random.shuffle(perm)

        if bimodal_check(perm):
            bimodal_pass += 1
            stats = perm_stats(perm)
            bean = check_bean_equality(perm)
            if bean:
                bimodal_and_bean += 1
            if len(passing_stats) < 10000:
                stats["bean"] = bean
                passing_stats.append(stats)
        elif len(failing_stats_sample) < 5000:
            failing_stats_sample.append(perm_stats(perm))

        if (trial + 1) % 200000 == 0:
            pct = 100 * bimodal_pass / (trial + 1)
            print(f"  [{trial+1:,}] bimodal_pass={bimodal_pass:,} ({pct:.4f}%)")

    bimodal_rate = bimodal_pass / N_RANDOM
    print(f"\n  Total: {bimodal_pass:,} / {N_RANDOM:,} pass bimodal ({100*bimodal_rate:.4f}%)")
    print(f"  Bimodal + Bean: {bimodal_and_bean:,} / {N_RANDOM:,}")
    if bimodal_pass > 0:
        print(f"  Bean rate among bimodal: {100*bimodal_and_bean/bimodal_pass:.2f}%")

    # ── Part 2: Structural profile of passing vs failing ─────────────
    print()
    print("Part 2: Structural Profile (Passing vs Failing)")
    print("-" * 50)

    def summarize_stats(stats_list, label):
        if not stats_list:
            print(f"  {label}: no data")
            return {}
        fields = ["avg_disp", "max_disp", "fixed_points", "near_fixed",
                   "disp_region_before_ene", "disp_region_ene",
                   "disp_region_middle", "disp_region_bc", "disp_region_after_bc",
                   "n_cycles", "max_cycle"]
        summary = {}
        for field in fields:
            vals = [s[field] for s in stats_list]
            mean = sum(vals) / len(vals)
            vals_sorted = sorted(vals)
            median = vals_sorted[len(vals_sorted) // 2]
            summary[field] = {"mean": round(mean, 2), "median": round(median, 2),
                              "min": round(min(vals), 2), "max": round(max(vals), 2)}
        print(f"\n  {label} (N={len(stats_list):,}):")
        for field in fields:
            s = summary[field]
            print(f"    {field:30s}: mean={s['mean']:8.2f}  median={s['median']:8.2f}  "
                  f"min={s['min']:8.2f}  max={s['max']:8.2f}")
        return summary

    pass_summary = summarize_stats(passing_stats, "BIMODAL-PASSING")
    fail_summary = summarize_stats(failing_stats_sample, "BIMODAL-FAILING (sample)")

    # Key comparison
    if pass_summary and fail_summary:
        print("\n  KEY DIFFERENCES (passing vs failing):")
        for field in ["disp_region_ene", "disp_region_bc", "avg_disp",
                       "fixed_points", "near_fixed"]:
            p = pass_summary[field]["mean"]
            f = fail_summary[field]["mean"]
            print(f"    {field:30s}: pass={p:8.2f}  fail={f:8.2f}  "
                  f"ratio={p/f:.2f}" if f > 0 else
                  f"    {field:30s}: pass={p:8.2f}  fail={f:8.2f}")

    # ── Part 3: Displacement distribution of passing perms ───────────
    print()
    print("Part 3: Displacement Distribution (Bimodal-Passing)")
    print("-" * 50)

    if passing_stats:
        # What fraction of positions in passing perms have displacement <= k?
        # We need the actual perms for this, so re-generate a sample
        random.seed(123)
        disp_counts = Counter()
        n_sample = 0
        for _ in range(500_000):
            perm = list(range(CT_LEN))
            random.shuffle(perm)
            if bimodal_check(perm):
                for i in range(CT_LEN):
                    disp = abs(perm[i] - i)
                    disp_counts[disp] += 1
                n_sample += 1
                if n_sample >= 5000:
                    break

        if n_sample > 0:
            total_positions = n_sample * CT_LEN
            cumulative = 0
            print(f"  Based on {n_sample:,} bimodal-passing permutations:")
            print(f"  {'Displacement':>12s}  {'Count':>10s}  {'Fraction':>10s}  {'Cumulative':>10s}")
            for d in range(CT_LEN):
                c = disp_counts.get(d, 0)
                cumulative += c
                if c > 0:
                    frac = c / total_positions
                    cum_frac = cumulative / total_positions
                    if d <= 20 or d % 10 == 0 or d == CT_LEN - 1:
                        print(f"  {d:12d}  {c:10,}  {frac:10.4f}  {cum_frac:10.4f}")

    # ── Part 4: Structured transposition families ────────────────────
    print()
    print("Part 4: Structured Transposition Families")
    print("-" * 50)

    structured_results = {}

    # Rail fence
    print("\n  4a. Rail Fence:")
    for rails in range(2, 16):
        perm = rail_fence_perm(CT_LEN, rails)
        passed = bimodal_check(perm)
        bean = check_bean_equality(perm) if passed else False
        disp = sum(abs(perm[i] - i) for i in range(CT_LEN)) / CT_LEN
        indicator = "PASS" if passed else "fail"
        bean_str = " +Bean" if bean else ""
        print(f"    rails={rails:2d}: {indicator}{bean_str}  avg_disp={disp:.1f}")
        structured_results[f"rail_fence_{rails}"] = {
            "bimodal": passed, "bean": bean, "avg_disp": round(disp, 1)}

    # Route ciphers on various grids
    print("\n  4b. Route Ciphers:")
    route_types = ["row_alt", "col_down", "col_alt", "spiral_in"]
    for width in [5, 7, 8, 9, 10, 11, 13, 14, 16, 20]:
        for route in route_types:
            perm = route_cipher_perm(CT_LEN, width, route)
            if perm is None:
                continue
            passed = bimodal_check(perm)
            bean = check_bean_equality(perm) if passed else False
            if passed:
                disp = sum(abs(perm[i] - i) for i in range(CT_LEN)) / CT_LEN
                bean_str = " +Bean" if bean else ""
                print(f"    w={width:2d}, route={route:10s}: PASS{bean_str}  avg_disp={disp:.1f}")
                structured_results[f"route_{width}_{route}"] = {
                    "bimodal": True, "bean": bean, "avg_disp": round(disp, 1)}

    # Also test inverse of each route
    print("\n  4c. Inverse Route Ciphers (undo the route):")
    for width in [5, 7, 8, 9, 10, 11, 13, 14, 16, 20]:
        for route in route_types:
            perm = route_cipher_perm(CT_LEN, width, route)
            if perm is None:
                continue
            # Invert
            inv = [0] * CT_LEN
            for i, p in enumerate(perm):
                inv[p] = i
            passed = bimodal_check(inv)
            bean = check_bean_equality(inv) if passed else False
            if passed:
                disp = sum(abs(inv[i] - i) for i in range(CT_LEN)) / CT_LEN
                bean_str = " +Bean" if bean else ""
                print(f"    w={width:2d}, route={route:10s} (inv): PASS{bean_str}  avg_disp={disp:.1f}")
                structured_results[f"inv_route_{width}_{route}"] = {
                    "bimodal": True, "bean": bean, "avg_disp": round(disp, 1)}

    # Strip manipulation
    print("\n  4d. Strip Manipulation (Sanborn's method):")
    strip_pass_count = 0
    strip_bean_count = 0
    strip_tested = 0

    for strip_width in [5, 7, 8, 9, 10, 11, 13, 14, 16, 20]:
        n_strips = math.ceil(CT_LEN / strip_width)
        # Test random strip rearrangements + flips
        n_samples = min(10000, math.factorial(n_strips) * 2**n_strips)
        local_pass = 0
        local_bean = 0

        for _ in range(int(n_samples)):
            strip_order = list(range(n_strips))
            random.shuffle(strip_order)
            flips = [random.choice([True, False]) for _ in range(n_strips)]
            operations = list(zip(strip_order, flips))

            perm = strip_manipulation_perm(CT_LEN, strip_width, operations)
            if perm is None:
                continue
            strip_tested += 1
            if bimodal_check(perm):
                local_pass += 1
                strip_pass_count += 1
                bean = check_bean_equality(perm)
                if bean:
                    local_bean += 1
                    strip_bean_count += 1

        if local_pass > 0:
            print(f"    strip_width={strip_width:2d}: {local_pass:,}/{int(n_samples):,} pass bimodal "
                  f"({local_bean} +Bean)")
        else:
            print(f"    strip_width={strip_width:2d}: 0/{int(n_samples):,} pass bimodal")

    print(f"\n    TOTAL strip: {strip_pass_count:,}/{strip_tested:,} pass, "
          f"{strip_bean_count} +Bean")

    # Local swaps (nearly-identity permutations)
    print("\n  4e. Local Swap Permutations:")
    for n_swaps in [1, 2, 3, 5, 10, 15, 20, 30, 50]:
        for max_dist in [3, 5, 10, 20, 50]:
            local_pass = 0
            local_bean = 0
            n_trials = 10000
            for _ in range(n_trials):
                perm = local_swap_perm(CT_LEN, n_swaps, max_dist)
                if bimodal_check(perm):
                    local_pass += 1
                    if check_bean_equality(perm):
                        local_bean += 1

            if local_pass > 0:
                pct = 100 * local_pass / n_trials
                print(f"    swaps={n_swaps:2d}, dist={max_dist:2d}: "
                      f"{local_pass:,}/{n_trials:,} pass ({pct:.1f}%), {local_bean} +Bean")

    # Block swaps
    print("\n  4f. Block Swaps:")
    block_swap_pass = 0
    block_swap_bean = 0
    block_swap_tested = 0
    block_swap_examples = []

    # Try all pairs of same-size blocks
    for block_size in range(3, 30):
        for a_start in range(0, CT_LEN - block_size):
            a_end = a_start + block_size
            for b_start in range(a_end, CT_LEN - block_size + 1):
                b_end = b_start + block_size
                perm = block_swap_perm(CT_LEN, a_start, a_end, b_start, b_end)
                if perm is None:
                    continue
                block_swap_tested += 1
                if bimodal_check(perm):
                    block_swap_pass += 1
                    bean = check_bean_equality(perm)
                    if bean:
                        block_swap_bean += 1
                    if len(block_swap_examples) < 20:
                        block_swap_examples.append({
                            "block_size": block_size,
                            "a": [a_start, a_end],
                            "b": [b_start, b_end],
                            "bean": bean,
                        })

    print(f"    Tested: {block_swap_tested:,} block swaps")
    print(f"    Bimodal pass: {block_swap_pass:,} ({100*block_swap_pass/max(block_swap_tested,1):.2f}%)")
    print(f"    Bimodal + Bean: {block_swap_bean:,}")
    if block_swap_examples:
        print(f"    Examples (first {len(block_swap_examples)}):")
        for ex in block_swap_examples[:10]:
            bean_str = "+Bean" if ex["bean"] else ""
            print(f"      size={ex['block_size']}, blocks={ex['a']}-{ex['b']} {bean_str}")

    # ── Part 5: Minimum perturbation analysis ────────────────────────
    print()
    print("Part 5: Minimum Perturbation for Bimodal Compatibility")
    print("-" * 50)
    print("  How many positions must move from identity to be bimodal-compatible?")
    print("  (Bimodal requires BC region 64-74 to be scattered)")
    print()

    # The BC constraint requires at most 4 of 11 positions to be near-identity
    # So at minimum, 7 of 11 positions in 64-74 must move by >2
    # The ENE constraint requires 9 positions (22-30) to be within ±5

    # Try: identity with increasing perturbations in the BC region only
    for n_perturb in range(1, 12):
        n_pass = 0
        n_trials = 100000
        for _ in range(n_trials):
            perm = list(range(CT_LEN))
            # Perturb n_perturb positions in 64-74
            positions = random.sample(range(64, 75), min(n_perturb, 11))
            # Move each to a random non-local position
            for pos in positions:
                # Swap with a distant position
                targets = [t for t in range(CT_LEN)
                           if abs(t - pos) > 2 and t not in range(22, 31)]
                if targets:
                    target = random.choice(targets)
                    perm[pos], perm[target] = perm[target], perm[pos]
            if bimodal_check(perm):
                n_pass += 1
        pct = 100 * n_pass / n_trials
        print(f"    Perturb {n_perturb:2d} BC positions: {n_pass:,}/{n_trials:,} pass ({pct:.1f}%)")

    # ── Summary ──────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Random bimodal rate: {bimodal_pass:,}/{N_RANDOM:,} ({100*bimodal_rate:.4f}%)")
    print(f"Random bimodal + Bean: {bimodal_and_bean:,}/{N_RANDOM:,}")
    print(f"Strip manipulation passes: {strip_pass_count:,}")
    print(f"Block swap passes: {block_swap_pass:,} (Bean: {block_swap_bean:,})")
    print()

    if passing_stats:
        bean_passing = [s for s in passing_stats if s.get("bean")]
        print(f"Among bimodal-passing random perms (N={len(passing_stats):,}):")
        print(f"  Bean rate: {len(bean_passing)}/{len(passing_stats)} "
              f"({100*len(bean_passing)/len(passing_stats):.1f}%)")

    # Key insights
    print()
    print("KEY INSIGHTS:")
    print("  1. Bimodal compatibility requires positions 22-30 to be near-identity")
    print("     AND positions 64-74 to be scrambled.")
    print("  2. Columnar transposition (any width) fails because it moves ALL")
    print("     positions by structured offsets — it cannot preserve one region")
    print("     while scrambling another.")
    print("  3. The bimodal-compatible search space consists of permutations that")
    print("     are 'locally identity' near positions 22-30 but 'globally scrambled'")
    print("     near positions 64-74.")

    print(f"\nTotal time: {elapsed:.1f}s")

    # Save
    os.makedirs("results/frac", exist_ok=True)
    artifact = {
        "experiment": "E-FRAC-09",
        "description": "Structural characterization of bimodal-compatible permutations",
        "random_bimodal_rate": round(bimodal_rate, 6),
        "random_bimodal_count": bimodal_pass,
        "random_bimodal_and_bean": bimodal_and_bean,
        "n_random_tested": N_RANDOM,
        "pass_summary": pass_summary,
        "fail_summary": fail_summary,
        "structured_results": structured_results,
        "strip_results": {
            "total_pass": strip_pass_count,
            "total_bean": strip_bean_count,
            "total_tested": strip_tested,
        },
        "block_swap_results": {
            "total_pass": block_swap_pass,
            "total_bean": block_swap_bean,
            "total_tested": block_swap_tested,
            "examples": block_swap_examples,
        },
        "elapsed_seconds": round(elapsed, 1),
    }
    path = "results/frac/e_frac_09_bimodal_structure.json"
    with open(path, "w") as f:
        json.dump(artifact, f, indent=2)
    print(f"\nSaved to {path}")


if __name__ == "__main__":
    main()
