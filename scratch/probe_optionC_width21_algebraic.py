"""Option C diagnostic: algebraic constraints at width 21.

Tests whether period-21 polyalphabetic substitution is consistent with
the EAST and BERLIN cribs under direct positional crib mapping. If
inconsistent (which Tier 1 says it should be — period 21 is in the
"all periods 1-26" eliminated set), we want to see HOW it fails:

  - Which cosets [0..10] (where EAST and BERLIN both have a crib) are
    inconsistent under each variant?
  - What's the magnitude of the inconsistency (k_EAST - k_BERLIN per
    coset)?
  - Does the pattern of inconsistencies have any structure that points
    at a non-trivial mechanism (e.g., additive offset = monoalphabetic
    shift, periodic difference = compound period)?

Also checks phase-shifted period-21 hypotheses: maybe the cipher is
period 21 but with a non-zero phase, so position i is encrypted with
key_((i + phi) mod 21) for some phi in [0..20].

If ALL phase shifts of all 3 variants fail at all cosets, period-21
substitution is ruled out and Probe 2's row-major width-21 structure
must come from a transposition / route at width 21 (combined with
something).
"""
from __future__ import annotations

from kryptos.kernel.constants import CT, CRIB_DICT


ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
A2I = {c: i for i, c in enumerate(ALPH)}


def crib_pairs_at_period(period: int):
    """Return all crib position pairs (i, j) with i < j and i ≡ j (mod period)."""
    crib_positions = sorted(CRIB_DICT.keys())
    pairs = []
    for i_idx in range(len(crib_positions)):
        for j_idx in range(i_idx + 1, len(crib_positions)):
            i, j = crib_positions[i_idx], crib_positions[j_idx]
            if i % period == j % period:
                pairs.append((i, j))
    return pairs


def recover_key(ct_char: str, pt_char: str, variant: str) -> int:
    """Recover the keystream value at this position under the variant."""
    c, p = A2I[ct_char], A2I[pt_char]
    if variant == "vig":
        return (c - p) % 26
    elif variant == "beau":
        return (c + p) % 26
    elif variant == "varbeau":
        return (p - c) % 26
    else:
        raise ValueError(f"unknown variant {variant}")


def consistency_per_period(period: int, variant: str, phase: int = 0):
    """For each pair of crib positions in the same coset, compute the
    implied keystream values under (variant, period, phase) and check
    consistency. Returns:
        consistent: bool (True if all pairs agree)
        n_pairs: int (number of crib pairs at this period)
        n_consistent: int (number where k_i == k_j)
        per_coset: dict {coset_id: (k_first_value, [(pos, k), ...])}
        max_diff: int (largest |k_i - k_j| mod 26)
    """
    pairs = crib_pairs_at_period(period)
    per_coset = {}
    for i in CRIB_DICT:
        coset = (i + phase) % period
        k_i = recover_key(CT[i], CRIB_DICT[i], variant)
        per_coset.setdefault(coset, []).append((i, k_i))

    n_pairs = 0
    n_consistent = 0
    max_diff = 0
    inconsistent_cosets = []
    for coset, positions in per_coset.items():
        if len(positions) < 2:
            continue
        # All pairs within this coset
        for a in range(len(positions)):
            for b in range(a + 1, len(positions)):
                n_pairs += 1
                k_a, k_b = positions[a][1], positions[b][1]
                if k_a == k_b:
                    n_consistent += 1
                else:
                    diff = abs((k_a - k_b) % 26)
                    diff = min(diff, 26 - diff)  # circular distance
                    max_diff = max(max_diff, diff)
                    inconsistent_cosets.append({
                        "coset": coset,
                        "pos_a": positions[a][0],
                        "pos_b": positions[b][0],
                        "k_a": k_a,
                        "k_b": k_b,
                        "diff": diff,
                    })
    return {
        "period": period,
        "variant": variant,
        "phase": phase,
        "n_pairs": n_pairs,
        "n_consistent": n_consistent,
        "consistent": n_pairs > 0 and n_consistent == n_pairs,
        "max_diff": max_diff,
        "inconsistent_cosets": inconsistent_cosets,
    }


def all_phases_summary(period: int):
    """For each (variant, phase) at the given period, report consistency."""
    variants = ["vig", "beau", "varbeau"]
    print(f"\n{'='*80}")
    print(f"PERIOD {period}: ALL VARIANTS × ALL PHASES")
    print(f"{'='*80}")
    print(f"{'variant':10s} {'phase':6s} {'n_pairs':8s} {'consistent':12s} {'max_diff':10s}")
    any_consistent = False
    best_per_variant = {}
    for variant in variants:
        for phase in range(period):
            r = consistency_per_period(period, variant, phase)
            mark = " ← CONSISTENT" if r["consistent"] else ""
            if r["consistent"]:
                any_consistent = True
            # Track best (highest n_consistent / n_pairs ratio) per variant
            ratio = r["n_consistent"] / r["n_pairs"] if r["n_pairs"] else 0
            best = best_per_variant.get(variant)
            if best is None or ratio > best["ratio"]:
                best_per_variant[variant] = {"phase": phase, "ratio": ratio, "result": r}
            if r["consistent"] or ratio > 0.5:
                print(
                    f"{variant:10s} {phase:6d} {r['n_pairs']:8d} "
                    f"{r['n_consistent']}/{r['n_pairs']:<8d} "
                    f"{r['max_diff']:10d}{mark}"
                )

    print()
    print(f"BEST per variant (any phase):")
    for variant, info in best_per_variant.items():
        r = info["result"]
        print(
            f"  {variant:10s} phase={info['phase']:2d}  "
            f"{r['n_consistent']}/{r['n_pairs']} consistent  "
            f"max_diff={r['max_diff']}  ratio={info['ratio']:.3f}"
        )
    return any_consistent, best_per_variant


def difference_pattern_check(period: int, variant: str, phase: int):
    """If the per-coset key values are inconsistent BUT the differences
    follow a pattern (e.g., constant offset), that suggests a compound
    cipher: period-21 sub PLUS another layer (e.g., monoalphabetic shift).
    """
    print(f"\n--- Difference pattern check: period={period} variant={variant} phase={phase} ---")
    per_coset = {}
    for i in CRIB_DICT:
        coset = (i + phase) % period
        k_i = recover_key(CT[i], CRIB_DICT[i], variant)
        per_coset.setdefault(coset, []).append((i, k_i))

    cosets_with_pairs = []
    for coset, positions in sorted(per_coset.items()):
        if len(positions) >= 2:
            # For coset r, list (i, k_i) for each crib position in that coset.
            # Compute differences between consecutive entries.
            positions.sort()
            diffs = []
            for a in range(len(positions) - 1):
                k_a, k_b = positions[a][1], positions[a + 1][1]
                diff = (k_b - k_a) % 26
                diffs.append(diff)
            cosets_with_pairs.append({
                "coset": coset,
                "positions": positions,
                "diffs": diffs,
            })
            pos_str = ", ".join(f"pos{p}->k={k}" for p, k in positions)
            diffs_str = ", ".join(str(d) for d in diffs)
            print(f"  coset {coset:2d}: [{pos_str}]  diffs={diffs_str}")

    # If all cosets have the same diff[0], that's a constant-offset
    # additive layer — compound cipher hypothesis viable.
    first_diffs = [c["diffs"][0] for c in cosets_with_pairs if c["diffs"]]
    if first_diffs:
        unique_diffs = set(first_diffs)
        print(f"  → Set of first-position differences across cosets: {sorted(unique_diffs)}")
        if len(unique_diffs) == 1:
            print(f"  ★ CONSTANT difference {first_diffs[0]} across all cosets:")
            print(f"    suggests compound cipher = period-{period} substitution")
            print(f"    + an additive offset of {first_diffs[0]}")
        else:
            # Are the diffs themselves periodic? E.g., does the set form
            # a pattern modular some N?
            print(f"  No constant difference; pattern is mixed across cosets.")


if __name__ == "__main__":
    print("=" * 80)
    print("WIDTH-21 ALGEBRAIC DIAGNOSTIC (Option C)")
    print("=" * 80)
    print(f"CT = {CT}")
    print(f"Crib positions: {sorted(CRIB_DICT.keys())} ({len(CRIB_DICT)} total)")

    # Show the period-21 coset structure of the cribs
    print("\n--- Crib positions by mod-21 coset ---")
    cosets = {}
    for p in sorted(CRIB_DICT):
        coset = p % 21
        cosets.setdefault(coset, []).append((p, CRIB_DICT[p]))
    for coset in sorted(cosets):
        positions = cosets[coset]
        pos_str = ", ".join(f"pos{p}={ch}" for p, ch in positions)
        print(f"  coset {coset:2d} ({'EAST+BERLIN' if len(positions)==2 else ('EAST only' if positions[0][0] < 60 else 'BERLIN only')}): [{pos_str}]")
    print(f"\nCosets with 2 crib positions (EAST+BERLIN): {sum(1 for c in cosets.values() if len(c)==2)}")
    print("These are the constraint pairs for period-21 consistency checks.")

    # Period 21
    consistent_21, best_21 = all_phases_summary(21)

    # Difference patterns at the best phase per variant
    print("\n" + "=" * 80)
    print("DIFFERENCE PATTERNS (period=21, best phase per variant)")
    print("=" * 80)
    for variant in ["vig", "beau", "varbeau"]:
        info = best_21[variant]
        difference_pattern_check(21, variant, info["phase"])

    # Test a few related periods for context
    print("\n" + "=" * 80)
    print("CONTEXT: same diagnostic at related periods")
    print("=" * 80)
    for related_period in [7, 14, 42, 3]:
        print(f"\n--- Period {related_period} ---")
        consistent, _ = all_phases_summary(related_period)
        if consistent:
            print(f"  ★ Period {related_period} is CONSISTENT under some variant/phase!")
        else:
            print(f"  Period {related_period}: ELIMINATED at all variant/phase combinations")

    # Final summary
    print("\n" + "=" * 80)
    print("DIAGNOSTIC SUMMARY")
    print("=" * 80)
    if consistent_21:
        print("★★ Period-21 substitution IS consistent under some (variant, phase).")
        print("   This would be a major finding — Tier 1 says period 1-26 is eliminated.")
        print("   Verify against kernel.constants.BEAN_INEQ to rule out instrumentation bug.")
    else:
        print("Period-21 substitution is INCONSISTENT under all (variant, phase) combinations.")
        print("Confirms Tier 1's elimination of period 21 under direct positional crib mapping.")
        print()
        print("Implication for Probe 2's row-major width-21 finding:")
        print("  - The width-21 row-major bigram anomaly is NOT explained by pure period-21")
        print("    substitution (which would mathematically have to satisfy Bean equality at")
        print("    crib positions, and doesn't).")
        print("  - The anomaly must come from a non-substitution mechanism at width 21:")
        print("    transposition / route / grille / cyclic-Wheatstone-like cipher.")
        print("  - The TABP model (outer-trans + inner-period-substitution) at width 21 has")
        print("    NOT been tested (TABP only covered widths 5,7,10-13).")
        print("  - Recommended next: launch focused width-21 TABP campaign.")
