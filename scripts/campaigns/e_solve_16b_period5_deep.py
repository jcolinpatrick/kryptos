#!/usr/bin/env python3
"""
Cipher: multi-vector campaign
Family: campaigns
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-SOLVE-16B: Deep analysis of encrypt-then-transpose at period 5.

Period 5 survived the pigeonhole analysis with ~10M possible key combos.
This script enumerates ALL combos and applies Bean + counting constraints
to determine if any survive.
"""

import sys
from collections import Counter
from itertools import product

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
)

CT_INT = [ALPH_IDX[c] for c in CT]
CT_COUNTS = Counter(CT_INT)

CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[CRIB_DICT[pos]] for pos in CRIB_POS}

print("E-SOLVE-16B: Encrypt-Then-Transpose Period 5 Deep Analysis")
print("=" * 70)

for variant_name, cipher_func in [
    ("Vigenère",   lambda pt, k: (pt + k) % MOD),
    ("Beaufort",   lambda pt, k: (k - pt) % MOD),
    ("VarBeaufort", lambda pt, k: (pt - k) % MOD),
]:
    print(f"\nCipher: {variant_name}")
    print("-" * 50)

    for p in [5, 6, 7, 8]:
        # Group crib positions by residue class
        classes = {}
        for pos in CRIB_POS:
            r = pos % p
            if r not in classes:
                classes[r] = []
            classes[r].append(pos)

        # Find feasible keys per class
        class_feasible = {}
        for r, positions in classes.items():
            feasible = []
            for key_r in range(26):
                required = Counter()
                for pos in positions:
                    enc_val = cipher_func(CRIB_PT[pos], key_r)
                    required[enc_val] += 1
                ok = all(CT_COUNTS.get(cv, 0) >= n for cv, n in required.items())
                if ok:
                    feasible.append(key_r)
            class_feasible[r] = feasible

        classes_list = sorted(class_feasible.keys())
        feasible_list = [class_feasible[r] for r in classes_list]

        total = 1
        for f in feasible_list:
            total *= len(f)

        if total == 0:
            print(f"  Period {p}: IMPOSSIBLE (zero feasible combos)")
            continue

        if total > 50_000_000:
            print(f"  Period {p}: {total:,} combos (too many to enumerate)")
            # But check Bean INEQ within same class
            bean_ineq_fail = False
            for a, b in BEAN_INEQ:
                if a in CRIB_PT and b in CRIB_PT:
                    if a % p == b % p:
                        bean_ineq_fail = True
                        break
            if bean_ineq_fail:
                print(f"            → IMPOSSIBLE (Bean INEQ)")
            continue

        print(f"  Period {p}: Enumerating {total:,} combos...", end=" ", flush=True)

        # Bean EQ: key[27%p] == key[65%p]
        r27 = 27 % p
        r65 = 65 % p
        r27_idx = classes_list.index(r27) if r27 in classes_list else -1
        r65_idx = classes_list.index(r65) if r65 in classes_list else -1

        # Bean INEQ within same class
        bean_same_class = set()
        for a, b in BEAN_INEQ:
            if a in CRIB_PT and b in CRIB_PT:
                if a % p == b % p:
                    bean_same_class.add(a % p)

        if bean_same_class:
            print(f"IMPOSSIBLE (Bean INEQ within class {bean_same_class})")
            continue

        # Bean INEQ across classes
        bean_cross = []
        for a, b in BEAN_INEQ:
            if a in CRIB_PT and b in CRIB_PT:
                ra, rb = a % p, b % p
                if ra != rb and ra in classes_list and rb in classes_list:
                    ra_idx = classes_list.index(ra)
                    rb_idx = classes_list.index(rb)
                    bean_cross.append((ra_idx, rb_idx))

        valid = 0
        for combo in product(*feasible_list):
            # Bean EQ
            if r27_idx >= 0 and r65_idx >= 0 and r27_idx != r65_idx:
                if combo[r27_idx] != combo[r65_idx]:
                    continue

            # Bean INEQ across classes
            fail = False
            for ra_idx, rb_idx in bean_cross:
                if combo[ra_idx] == combo[rb_idx]:
                    fail = True
                    break
            if fail:
                continue

            # CT counting (aggregate across all classes)
            required = Counter()
            for r_idx, r in enumerate(classes_list):
                key_r = combo[r_idx]
                for pos in classes[r]:
                    enc_val = cipher_func(CRIB_PT[pos], key_r)
                    required[enc_val] += 1

            ok = all(CT_COUNTS.get(cv, 0) >= n for cv, n in required.items())
            if ok:
                valid += 1
                if valid <= 5:
                    key_word = "".join(ALPH[combo[classes_list.index(r)]] for r in range(p))
                    print(f"\n    Valid combo: key={key_word} ({list(combo)})")

        print(f"\n    Result: {valid}/{total:,} valid combos", end="")
        if valid == 0:
            print(" → IMPOSSIBLE")
        else:
            print(f" → {valid} FEASIBLE (but underdetermined — need to test actual transpositions)")
        print()

print()
print("=" * 70)
print("Note: FEASIBLE means the pigeonhole + Bean constraints allow this period,")
print("but actual feasibility requires finding a specific transposition that works.")
print("With 97! possible transpositions, this remains underdetermined without")
print("additional structural constraints (like the transposition being columnar).")
