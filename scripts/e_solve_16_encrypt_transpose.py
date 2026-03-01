#!/usr/bin/env python3
"""
E-SOLVE-16: Encrypt-Then-Transpose Pigeonhole Analysis

Model: PT → Vigenère/Beaufort(period p) → Transposition T → CT

Under this model:
  - Enc[i] = cipher(PT[i], key[i mod p])
  - CT[T(i)] = Enc[i]

For crib positions i (where PT[i] is known):
  CT[T(i)] = cipher(crib[i], key[i mod p])

This constrains which CT positions T(i) can map to.
For each key value key_r at residue class r:
  The required CT characters form a multiset.
  If the CT doesn't have enough of any required character, that key_r is impossible.
  If ALL 26 key_r values are impossible for some residue class r,
  then that period p is IMPOSSIBLE under ANY transposition.

This is a pure pigeonhole argument — no need to enumerate transpositions.
"""

import sys
from collections import Counter
from math import gcd

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
)

CT_INT = [ALPH_IDX[c] for c in CT]
CT_COUNTS = Counter(CT_INT)

CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[CRIB_DICT[pos]] for pos in CRIB_POS}

print("E-SOLVE-16: Encrypt-Then-Transpose Pigeonhole Analysis")
print("=" * 70)
print()
print("Model: PT → Periodic Cipher → Transposition → CT")
print("The transposition is UNKNOWN and ARBITRARY.")
print("We use pigeonhole counting to determine if ANY transposition")
print("is compatible with the known cribs.")
print()

# CT character counts
print("CT character frequencies:")
for v in range(26):
    c = CT_COUNTS.get(v, 0)
    if c > 0:
        print(f"  {ALPH[v]}({v:2d}): {c}", end="")
        if c >= 5:
            print(" ***", end="")
        print()
print()

# ── Analysis for each period ──────────────────────────────────────────

for variant_name, cipher_func in [
    ("Vigenère",   lambda pt, k: (pt + k) % MOD),
    ("Beaufort",   lambda pt, k: (k - pt) % MOD),
    ("VarBeaufort", lambda pt, k: (pt - k) % MOD),
]:
    print(f"{'='*70}")
    print(f"Cipher variant: {variant_name}")
    print(f"{'='*70}")
    print()

    for p in range(2, 27):
        # Group crib positions by residue class
        classes = {}
        for pos in CRIB_POS:
            r = pos % p
            if r not in classes:
                classes[r] = []
            classes[r].append(pos)

        # For each residue class, find which key values are feasible
        class_feasible = {}  # r -> set of feasible key values

        for r, positions in classes.items():
            feasible_keys = set()

            for key_r in range(26):
                # What CT characters are required for this key_r?
                required = Counter()
                for pos in positions:
                    enc_val = cipher_func(CRIB_PT[pos], key_r)
                    required[enc_val] += 1

                # Check if CT has enough of each required character
                # Note: the T(i) must be DISTINCT positions, and each required
                # character must come from a distinct CT position with that character
                possible = True
                for char_val, needed in required.items():
                    available = CT_COUNTS.get(char_val, 0)
                    if needed > available:
                        possible = False
                        break

                if possible:
                    feasible_keys.add(key_r)

            class_feasible[r] = feasible_keys

        # For the period to work, ALL residue classes that contain
        # crib positions must have at least one feasible key
        all_classes_feasible = True
        blocking_classes = []
        for r, feasible in class_feasible.items():
            if not feasible:
                all_classes_feasible = False
                blocking_classes.append(r)

        # Also check Bean EQ constraint: key[27 mod p] == key[65 mod p]
        r27 = 27 % p
        r65 = 65 % p
        bean_eq_constraint = (r27 == r65)  # If same class, automatically satisfied
        if not bean_eq_constraint:
            # Different classes: need compatible key values
            # But this doesn't further restrict feasibility
            # (it constrains which specific key values pair up, not whether any exist)
            pass

        # Cross-class constraint: positions from DIFFERENT crib blocks
        # that fall in the same residue class must be compatible.
        # This is already handled by the within-class counting above.

        # But we can add a STRONGER constraint: the transposition must be
        # a BIJECTION. So the total number of CT positions used by ALL
        # classes combined must not exceed 97.
        # For a given assignment of key values to classes, compute
        # the total number of distinct CT positions needed.

        # For now, just report per-class feasibility
        n_feasible_classes = sum(1 for f in class_feasible.values() if f)
        n_total_classes = len(class_feasible)

        if not all_classes_feasible:
            print(f"  Period {p:2d}: IMPOSSIBLE — {len(blocking_classes)} class(es) "
                  f"have ZERO feasible keys: {blocking_classes}")
        else:
            # Count average feasible keys per class
            avg_feasible = sum(len(f) for f in class_feasible.values()) / n_total_classes
            min_feasible = min(len(f) for f in class_feasible.values())
            max_feasible = max(len(f) for f in class_feasible.values())

            # Try to further constrain using the bipartite matching requirement
            # For each valid combination of key values across classes,
            # check if the required CT positions are mutually non-overlapping

            # For small periods, try all key combinations
            if p <= 7:
                from itertools import product

                classes_list = sorted(class_feasible.keys())
                feasible_list = [sorted(class_feasible[r]) for r in classes_list]

                valid_combos = 0
                total_combos = 1
                for f in feasible_list:
                    total_combos *= len(f)

                if total_combos <= 1000000:
                    for combo in product(*feasible_list):
                        # For this key assignment, compute required CT positions
                        required_total = Counter()
                        for r_idx, r in enumerate(classes_list):
                            key_r = combo[r_idx]
                            for pos in classes[r]:
                                enc_val = cipher_func(CRIB_PT[pos], key_r)
                                required_total[enc_val] += 1

                        # Check if CT has enough of each character
                        possible = True
                        for char_val, needed in required_total.items():
                            if needed > CT_COUNTS.get(char_val, 0):
                                possible = False
                                break

                        # Also check Bean EQ
                        if possible and r27 != r65:
                            r27_idx = classes_list.index(r27) if r27 in classes_list else -1
                            r65_idx = classes_list.index(r65) if r65 in classes_list else -1
                            if r27_idx >= 0 and r65_idx >= 0:
                                if combo[r27_idx] != combo[r65_idx]:
                                    possible = False

                        # Check Bean INEQ
                        if possible:
                            for a, b in BEAN_INEQ:
                                if a in CRIB_PT and b in CRIB_PT:
                                    ra = a % p
                                    rb = b % p
                                    if ra in classes_list and rb in classes_list:
                                        ra_idx = classes_list.index(ra)
                                        rb_idx = classes_list.index(rb)
                                        if combo[ra_idx] == combo[rb_idx]:
                                            # key values equal at these classes
                                            # But wait, Bean INEQ is about key values
                                            # being DIFFERENT. Under transposition,
                                            # the key applies at the original position,
                                            # so key[a] != key[b] means key[a%p] != key[b%p]
                                            # when a and b are in different classes.
                                            # If same class, then key[a]=key[b] by definition,
                                            # violating Bean INEQ.
                                            if ra == rb:
                                                possible = False
                                                break

                        if possible:
                            valid_combos += 1

                    print(f"  Period {p:2d}: {valid_combos}/{total_combos} valid key combos "
                          f"(per-class: min={min_feasible}, max={max_feasible}, avg={avg_feasible:.1f})")
                    if valid_combos == 0:
                        print(f"            → IMPOSSIBLE (all combos violate CT counting or Bean)")
                else:
                    print(f"  Period {p:2d}: FEASIBLE per-class "
                          f"(min={min_feasible}, max={max_feasible}, avg={avg_feasible:.1f}, "
                          f"combos={total_combos:,})")
            else:
                # Large period — just report class-level feasibility
                print(f"  Period {p:2d}: FEASIBLE per-class "
                      f"(min={min_feasible}, max={max_feasible}, avg={avg_feasible:.1f})")

                # Check Bean INEQ within same class
                bean_ineq_within = False
                for a, b in BEAN_INEQ:
                    if a in CRIB_PT and b in CRIB_PT:
                        if a % p == b % p:
                            # Same class → key[a] = key[b], violates INEQ
                            bean_ineq_within = True
                            break
                if bean_ineq_within:
                    print(f"            → IMPOSSIBLE (Bean INEQ pair in same residue class)")

        print()

# ── Summary ───────────────────────────────────────────────────────────

print("=" * 70)
print("SUMMARY")
print("=" * 70)
print()
print("This analysis determines whether ANY transposition (not just columnar)")
print("is compatible with periodic Vigenère/Beaufort at each period.")
print("The pigeonhole constraint checks character availability in CT,")
print("and Bean constraints further restrict valid key assignments.")
print()
print("An IMPOSSIBLE result means: at the given period, no permutation of")
print("the 97 CT characters can simultaneously satisfy all crib constraints")
print("under periodic Vigenère/Beaufort. This is a STRONGER result than")
print("testing specific transposition families (columnar, grid, etc.).")
