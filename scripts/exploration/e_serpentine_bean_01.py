#!/usr/bin/env python3
"""
Serpentine (boustrophedon) reading + periodic substitution: Bean constraint check.

Hypothesis: The arrows on the K1-K2 encoding chart (→ line 1, ← line 2)
indicate boustrophedon writing. Reading K4 CT in serpentine order at various
widths produces a rearranged CT. The Bean periodicity constraints (which
eliminate ALL periods on raw CT) may NOT eliminate all periods on the
rearranged CT, because the crib positions change.

Tests:
1. For each width W (2-48, covering chart widths 7, 8, 14, 31):
   - Compute serpentine permutation
   - Map crib positions through the permutation inverse
   - Derive keystream values at new (chart) positions
   - Check Bean equality and all 242 inequalities for each period 1-48
   - Report ANY surviving period

2. For any surviving period, attempt full key recovery.

Cipher: Beaufort, Vigenere, Variant Beaufort (all 3)
Family: exploration
Status: active
Keyspace: 47 widths × 48 periods × 3 variants = 6,768 configs
Last run: never
Best score: n/a
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os
_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, BEAN_EQ, BEAN_INEQ, ALPH_IDX, MOD
from kryptos.kernel.transforms.transposition import serpentine_perm
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

import math


def build_serpentine_inv(width: int, length: int = 97) -> list[int]:
    """Build the inverse serpentine mapping: carved_pos → chart_pos.

    serpentine_perm gives the reading order (chart positions in carved order).
    We need the inverse: given a carved position, what chart position does it map to?
    """
    rows = math.ceil(length / width)
    perm = serpentine_perm(rows, width, length, vertical=False)
    # perm[i] = chart position that is read as carved position i
    # So carved position i has chart_CT[perm[i]] = carved_CT[i]
    # We want: carved_pos → chart_pos, which is just perm itself
    # But wait: serpentine_perm gives the READING ORDER.
    # perm[0] = first chart position read = carved position 0
    # So perm[carved_pos] = chart_pos? No...
    #
    # serpentine_perm generates positions in reading order:
    #   perm = [0, 1, 2, ..., W-1, 2W-1, 2W-2, ..., W, 2W, 2W+1, ...]
    # perm[i] is the grid position that is read at step i
    #
    # For our model:
    # - Chart is filled sequentially: chart_CT[0], chart_CT[1], ...
    # - Sculpture reads the chart in serpentine order
    # - carved_CT[i] = chart_CT[perm[i]]
    #
    # So to go from carved to chart: chart_pos = perm[carved_pos]
    # And to go from chart to carved: we need the inverse

    # carved_to_chart[i] = perm[i]  (carved position i reads chart position perm[i])
    carved_to_chart = perm

    # chart_to_carved = inverse of perm
    chart_to_carved = [0] * length
    for carved_pos, chart_pos in enumerate(perm):
        chart_to_carved[chart_pos] = carved_pos

    return carved_to_chart, chart_to_carved


def derive_chart_keystream(carved_to_chart: list[int], variant: str = "beaufort") -> dict[int, int]:
    """Derive keystream values at CHART positions from known cribs.

    The cipher operates on chart-ordered text. Crib positions in the carved text
    map to chart positions. The keystream at chart positions is:
      Beaufort:  K = (CT_chart + PT) mod 26
      Vigenere:  K = (CT_chart - PT) mod 26
      Var Beau:  K = (PT - CT_chart) mod 26

    Where CT_chart[chart_pos] = CT_carved[carved_pos] (same character, just at
    a different position in the chart ordering).
    """
    keystream = {}
    for carved_pos, pt_char in CRIB_DICT.items():
        chart_pos = carved_to_chart[carved_pos]
        ct_val = ALPH_IDX[CT[carved_pos]]
        pt_val = ALPH_IDX[pt_char]

        if variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        elif variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "var_beaufort":
            k = (pt_val - ct_val) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")

        keystream[chart_pos] = k

    return keystream


def check_bean_periodic(keystream: dict[int, int], period: int,
                        carved_to_chart: list[int]) -> tuple[bool, int, int]:
    """Check if a periodic key with given period is consistent with Bean constraints.

    For a periodic key: k[i] depends only on (i mod p) where i is the CHART position.

    Bean equality: k[chart_pos(27)] must equal k[chart_pos(65)]
    This is satisfied iff chart_pos(27) mod p == chart_pos(65) mod p
    OR the key values happen to be equal.

    Bean inequalities: k[chart_pos(a)] must NOT equal k[chart_pos(b)]
    Violated iff chart_pos(a) mod p == chart_pos(b) mod p AND the derived keys differ.

    Returns: (passes, n_eq_violations, n_ineq_violations)
    """
    # Check equality constraint
    eq_violations = 0
    for a, b in BEAN_EQ:
        ca = carved_to_chart[a]
        cb = carved_to_chart[b]
        ka = keystream[ca]
        kb = keystream[cb]
        if ca % period == cb % period:
            # Same residue class — key values MUST be equal
            if ka != kb:
                eq_violations += 1
        else:
            # Different residue classes — equality is not forced by periodicity
            # but MUST still hold (Bean says k[27]=k[65])
            # For periodic key, different residues means different key slots
            # So we can SET them equal if free, but if other constraints force different values, it fails
            # Actually: Bean says these MUST be equal. If they're in different residue classes,
            # we need to check if the values CAN be equal given other constraints.
            # For now, just note it — we'll check consistency below.
            pass

    # Check inequality constraints
    ineq_violations = 0
    for a, b in BEAN_INEQ:
        ca = carved_to_chart[a]
        cb = carved_to_chart[b]
        if ca % period == cb % period:
            # Same residue class → periodic key forces k[ca] = k[cb]
            # But Bean says they must be DIFFERENT → VIOLATION
            ka = keystream[ca]
            kb = keystream[cb]
            if ka != kb:
                # The derived keys are indeed different, confirming the inequality holds
                # But periodic key forces them equal → CONFLICT → period is impossible
                ineq_violations += 1

    return (eq_violations == 0 and ineq_violations == 0), eq_violations, ineq_violations


def check_full_periodic_consistency(keystream: dict[int, int], period: int) -> tuple[bool, int]:
    """Check if the keystream values are consistent with a periodic key.

    Group chart positions by (chart_pos mod period). All positions in the same
    group must have the same keystream value.
    """
    groups: dict[int, set[int]] = {}
    for chart_pos, k_val in keystream.items():
        residue = chart_pos % period
        if residue not in groups:
            groups[residue] = set()
        groups[residue].add(k_val)

    conflicts = sum(1 for vals in groups.values() if len(vals) > 1)
    return conflicts == 0, conflicts


def score_with_serpentine(width: int, period: int, variant: str) -> tuple[float, str]:
    """For a surviving (width, period, variant), attempt full decryption and score."""
    rows = math.ceil(CT_LEN / width)
    carved_to_chart, chart_to_carved = build_serpentine_inv(width)

    # Derive the periodic key from chart-position keystream
    keystream = derive_chart_keystream(carved_to_chart, variant)

    # Build the period-p key from the known values
    key_slots: dict[int, list[int]] = {}
    for chart_pos, k_val in keystream.items():
        residue = chart_pos % period
        if residue not in key_slots:
            key_slots[residue] = []
        key_slots[residue].append(k_val)

    # Check consistency and get consensus key
    key = [None] * period
    for residue, vals in key_slots.items():
        if len(set(vals)) != 1:
            return -1.0, f"Conflict at residue {residue}: {set(vals)}"
        key[residue] = vals[0]

    # Decrypt: first un-serpentine the CT, then apply periodic decryption
    chart_ct = [''] * CT_LEN
    for carved_pos in range(CT_LEN):
        chart_pos = carved_to_chart[carved_pos]
        chart_ct[chart_pos] = CT[carved_pos]

    pt_chars = []
    for chart_pos in range(CT_LEN):
        ct_val = ALPH_IDX[chart_ct[chart_pos]]
        residue = chart_pos % period

        if key[residue] is not None:
            k_val = key[residue]
        else:
            # Unknown key slot — can't decrypt this position
            pt_chars.append('?')
            continue

        if variant == "beaufort":
            pt_val = (k_val - ct_val) % MOD
        elif variant == "vigenere":
            pt_val = (ct_val - k_val) % MOD
        elif variant == "var_beaufort":
            pt_val = (ct_val + k_val) % MOD

        pt_chars.append(chr(pt_val + ord('A')))

    pt_chart_order = ''.join(pt_chars)

    # Re-serpentine the PT to get carved-order PT for scoring
    pt_carved = [''] * CT_LEN
    for chart_pos in range(CT_LEN):
        carved_pos = chart_to_carved[chart_pos]
        pt_carved[carved_pos] = pt_chart_order[chart_pos]

    pt_carved_str = ''.join(pt_carved)

    # Score against cribs at ORIGINAL carved positions
    score = 0
    for pos, expected in CRIB_DICT.items():
        if pt_carved_str[pos] == expected:
            score += 1

    return score, pt_carved_str


def main():
    print("=" * 70)
    print("SERPENTINE BOUSTROPHEDON + PERIODIC SUBSTITUTION")
    print("Bean constraint re-derivation under position rearrangement")
    print("=" * 70)

    variants = ["beaufort", "vigenere", "var_beaufort"]
    widths = list(range(2, 49))  # 2 through 48
    max_period = 48

    survivors = []

    for width in widths:
        rows = math.ceil(CT_LEN / width)
        carved_to_chart, chart_to_carved = build_serpentine_inv(width)

        # Also test "reverse start" (odd rows first, even reversed)
        for start_forward in [True, False]:
            if not start_forward:
                # Swap: reverse even rows instead of odd
                # This is equivalent to starting with ← instead of →
                new_c2c = list(carved_to_chart)
                for r in range(rows):
                    row_start = r * width
                    row_end = min(row_start + width, CT_LEN)
                    row_len = row_end - row_start
                    if r % 2 == 0:  # Reverse even rows (opposite of default)
                        for c in range(row_len):
                            new_c2c[row_start + c] = row_start + (row_len - 1 - c)
                    else:  # Keep odd rows normal
                        for c in range(row_len):
                            new_c2c[row_start + c] = row_start + c
                carved_to_chart_v = new_c2c
                chart_to_carved_v = [0] * CT_LEN
                for cp, chp in enumerate(carved_to_chart_v):
                    chart_to_carved_v[chp] = cp
            else:
                carved_to_chart_v = carved_to_chart
                chart_to_carved_v = chart_to_carved

            for variant in variants:
                keystream = derive_chart_keystream(carved_to_chart_v, variant)

                for period in range(1, max_period + 1):
                    # Quick check: are keystream values consistent with this period?
                    consistent, conflicts = check_full_periodic_consistency(keystream, period)

                    if consistent:
                        # Also verify Bean constraints
                        bean_ok, eq_v, ineq_v = check_bean_periodic(
                            keystream, period, carved_to_chart_v
                        )

                        direction = "fwd" if start_forward else "rev"

                        if bean_ok:
                            # SURVIVOR! Try decryption
                            score, pt = score_with_serpentine(width, period, variant)
                            survivors.append({
                                'width': width,
                                'period': period,
                                'variant': variant,
                                'direction': direction,
                                'score': score,
                                'pt_snippet': pt[:40] + '...',
                            })
                            print(f"  *** SURVIVOR: w={width} p={period} {variant} {direction} "
                                  f"score={score}/24")
                            if score >= 10:
                                print(f"      PT: {pt}")

    print()
    print("=" * 70)
    print(f"RESULTS: {len(survivors)} surviving (width, period, variant) combinations")
    print("=" * 70)

    if not survivors:
        print("NO survivors. Serpentine rearrangement does NOT open any periodic")
        print("substitution that was closed on the raw CT.")
    else:
        # Sort by score descending
        survivors.sort(key=lambda x: x['score'], reverse=True)
        print(f"\nTop results (showing top 20):")
        print(f"{'Width':>5} {'Dir':>3} {'Period':>6} {'Variant':>12} {'Score':>5}")
        print("-" * 40)
        for s in survivors[:20]:
            print(f"{s['width']:>5} {s['direction']:>3} {s['period']:>6} "
                  f"{s['variant']:>12} {s['score']:>5}/24")

        # Histogram of scores
        from collections import Counter
        score_counts = Counter(s['score'] for s in survivors)
        print(f"\nScore distribution:")
        for score in sorted(score_counts.keys(), reverse=True):
            print(f"  {score}/24: {score_counts[score]} configs")

        # Flag key widths
        key_widths = {7, 8, 14, 31}
        key_results = [s for s in survivors if s['width'] in key_widths]
        if key_results:
            print(f"\nChart-relevant widths (7, 8, 14, 31):")
            for s in key_results:
                print(f"  w={s['width']} p={s['period']} {s['variant']} {s['direction']} "
                      f"→ {s['score']}/24")

    # Always report Bean equality transfer
    print("\n--- Bean Equality k[27]=k[65] position transfer ---")
    for width in [7, 8, 14, 31]:
        rows = math.ceil(CT_LEN / width)
        carved_to_chart, _ = build_serpentine_inv(width)
        new_27 = carved_to_chart[27]
        new_65 = carved_to_chart[65]
        print(f"  w={width}: k[{new_27}] = k[{new_65}]  "
              f"(original: k[27]=k[65])  "
              f"gap={abs(new_65-new_27)}  "
              f"divisors of gap: {[d for d in range(1, abs(new_65-new_27)+1) if abs(new_65-new_27) % d == 0]}")


if __name__ == "__main__":
    main()
