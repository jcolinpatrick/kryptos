#!/usr/bin/env python3
"""
Misspelling substitutions only (no deletion, no UNDERGRUUND).

The 4 confirmed deliberate letter CHANGES:
  DESPARATLY:  E→A  (deletion was for grid-fitting, not a cipher clue)
  IQLUSION:    L→Q
  DIGETAL:     I→E
  PALIMPCEST:  S→C

4! = 24 orderings, 2^4 = 16 subsets. Exhaustive.

Cipher: Substitution transform + Vigenere/Beaufort
Family: grille
Status: active
"""
import sys, os, json
from itertools import permutations
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT

QG_PATH = os.path.join(os.path.dirname(__file__), '..', '..', 'data', 'english_quadgrams.json')
with open(QG_PATH) as f:
    QG = json.load(f)
QG_FLOOR = min(QG.values()) - 1.0

def qg_score(text):
    if len(text) < 4:
        return QG_FLOOR
    return sum(QG.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3)) / (len(text) - 3)

def vig_decrypt(ct, key):
    kl = len(key)
    return ''.join(ALPH[(ALPH_IDX[c] - ALPH_IDX[key[i % kl]]) % 26] for i, c in enumerate(ct))

def beau_decrypt(ct, key):
    kl = len(key)
    return ''.join(ALPH[(ALPH_IDX[key[i % kl]] - ALPH_IDX[c]) % 26] for i, c in enumerate(ct))

def varbeau_decrypt(ct, key):
    kl = len(key)
    return ''.join(ALPH[(ALPH_IDX[c] + ALPH_IDX[key[i % kl]]) % 26] for i, c in enumerate(ct))

KA = 'KRYPTOSABCDEFGHIJLMNQUVWXZ'
KA_IDX = {c: i for i, c in enumerate(KA)}

def vig_ka(ct, key):
    kl = len(key)
    return ''.join(KA[(KA_IDX[c] - KA_IDX[key[i % kl]]) % 26] for i, c in enumerate(ct))

def beau_ka(ct, key):
    kl = len(key)
    return ''.join(KA[(KA_IDX[key[i % kl]] - KA_IDX[c]) % 26] for i, c in enumerate(ct))

def crib_score(pt):
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(pt) and pt[pos] == ch)

def free_crib_search(pt):
    total = 0
    details = []
    for crib in ('EASTNORTHEAST', 'BERLINCLOCK', 'NORTHEAST', 'BERLIN',
                 'CLOCK', 'EAST', 'NORTH'):
        idx = pt.find(crib)
        if idx >= 0:
            total += len(crib)
            details.append((crib, idx))
    return total, details

KEYWORDS = {
    'KRYPTOS': 'KRYPTOS',
    'PALIMPSEST': 'PALIMPSEST',
    'ABSCISSA': 'ABSCISSA',
    'SHADOW': 'SHADOW',
    'SANBORN': 'SANBORN',
    'VERDIGRIS': 'VERDIGRIS',
    'ALETHEIA': 'ALETHEIA',
    'BERLIN': 'BERLIN',
    'URANIA': 'URANIA',
    'KRYPTE': 'KRYPTE',
}

DECRYPTORS = {
    'Vig/AZ': vig_decrypt,
    'Beau/AZ': beau_decrypt,
    'VBeau/AZ': varbeau_decrypt,
    'Vig/KA': vig_ka,
    'Beau/KA': beau_ka,
}

# The 4 confirmed substitutions
SUBS = [
    ('E→A', 'E', 'A'),   # DESPARATLY
    ('L→Q', 'L', 'Q'),   # IQLUSION
    ('I→E', 'I', 'E'),   # DIGETAL
    ('S→C', 'S', 'C'),   # PALIMPCEST
]

REVERSE_SUBS = [
    ('A→E', 'A', 'E'),
    ('Q→L', 'Q', 'L'),
    ('E→I', 'E', 'I'),
    ('C→S', 'C', 'S'),
]

print("=" * 70)
print("MISSPELLING SUBSTITUTIONS ONLY (4 transforms, no deletion)")
print("  E→A (DESPARATLY), L→Q (IQLUSION), I→E (DIGETAL), S→C (PALIMPCEST)")
print("=" * 70)

print(f"\nK4: {CT}")
ct_counts = Counter(CT)
print(f"Affected letters: E={ct_counts['E']}, A={ct_counts['A']}, "
      f"L={ct_counts['L']}, Q={ct_counts['Q']}, "
      f"I={ct_counts['I']}, S={ct_counts['S']}, C={ct_counts['C']}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 1: All 24 orderings of the 4 forward substitutions
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("Approach 1: Forward substitutions — all 4! = 24 orderings")
print("=" * 70)

best_fwd = (-999, '', '', [])
all_transformed = set()

for perm in permutations(range(4)):
    text = CT
    order_names = []
    for idx in perm:
        name, src, dst = SUBS[idx]
        text = text.replace(src, dst)
        order_names.append(name)

    all_transformed.add(text)
    print(f"\n  Order: {' → '.join(order_names)}")
    print(f"  Result: {text}")
    new_counts = Counter(text)
    print(f"  Counts: {', '.join(f'{c}={new_counts[c]}' for c in sorted(new_counts) if new_counts[c] > 0)}")

    best_for_order = (-999, '', '')
    for kname, key in KEYWORDS.items():
        for dname, decrypt in DECRYPTORS.items():
            pt = decrypt(text, key)
            cs = crib_score(pt)
            fc, fd = free_crib_search(pt)
            qs = qg_score(pt)
            if cs > best_for_order[0]:
                best_for_order = (cs, pt, f"{dname}/{kname}")
            if cs > best_fwd[0]:
                best_fwd = (cs, pt, f"{dname}/{kname}", order_names)
            if cs >= 4 or fc > 0:
                print(f"    ** crib={cs} qg={qs:.3f} free={fd} {dname}/{kname}")
                print(f"       PT: {pt[:70]}")

    print(f"  Best: crib={best_for_order[0]} via {best_for_order[2]}")

print(f"\nUnique transformed texts: {len(all_transformed)} (of 24 orderings)")
print(f"Overall best forward: crib={best_fwd[0]} via {best_fwd[2]} order={best_fwd[3]}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 2: All 24 orderings of the 4 REVERSE substitutions
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("Approach 2: Reverse substitutions — all 4! = 24 orderings")
print("  Undo the misspellings: A→E, Q→L, E→I, C→S")
print("=" * 70)

best_rev = (-999, '', '', [])

for perm in permutations(range(4)):
    text = CT
    order_names = []
    for idx in perm:
        name, src, dst = REVERSE_SUBS[idx]
        text = text.replace(src, dst)
        order_names.append(name)

    best_for_order = (-999, '', '')
    for kname, key in KEYWORDS.items():
        for dname, decrypt in DECRYPTORS.items():
            pt = decrypt(text, key)
            cs = crib_score(pt)
            fc, fd = free_crib_search(pt)
            qs = qg_score(pt)
            if cs > best_for_order[0]:
                best_for_order = (cs, pt, f"{dname}/{kname}")
            if cs > best_rev[0]:
                best_rev = (cs, pt, f"{dname}/{kname}", order_names)
            if cs >= 4 or fc > 0:
                print(f"  ** crib={cs} qg={qs:.3f} free={fd} order={order_names} {dname}/{kname}")
                print(f"     PT: {pt[:70]}")

print(f"\nOverall best reverse: crib={best_rev[0]} via {best_rev[2]} order={best_rev[3]}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 3: All 16 subsets of the 4 forward substitutions
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("Approach 3: All 2^4 = 16 subsets (forward)")
print("=" * 70)

best_sub = (-999, '', '', [])

for mask in range(1, 16):
    text = CT
    applied = []
    for bit in range(4):
        if mask & (1 << bit):
            name, src, dst = SUBS[bit]
            text = text.replace(src, dst)
            applied.append(name)

    best_for_subset = (-999, '', '')
    for kname, key in KEYWORDS.items():
        for dname, decrypt in DECRYPTORS.items():
            pt = decrypt(text, key)
            cs = crib_score(pt)
            fc, fd = free_crib_search(pt)
            if cs > best_for_subset[0]:
                best_for_subset = (cs, pt, f"{dname}/{kname}")
            if cs > best_sub[0]:
                best_sub = (cs, pt, f"{dname}/{kname}", applied)
            if cs >= 4 or fc > 0:
                print(f"  ** crib={cs} free={fd} subset={applied} {dname}/{kname}")

    if best_for_subset[0] >= 3:
        print(f"  Subset {applied}: best crib={best_for_subset[0]} via {best_for_subset[2]}")

print(f"\nOverall best subset: crib={best_sub[0]} via {best_sub[2]} transforms={best_sub[3]}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 4: All 16 subsets of REVERSE substitutions
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("Approach 4: All 2^4 = 16 subsets (reverse)")
print("=" * 70)

best_rsub = (-999, '', '', [])

for mask in range(1, 16):
    text = CT
    applied = []
    for bit in range(4):
        if mask & (1 << bit):
            name, src, dst = REVERSE_SUBS[bit]
            text = text.replace(src, dst)
            applied.append(name)

    best_for_subset = (-999, '', '')
    for kname, key in KEYWORDS.items():
        for dname, decrypt in DECRYPTORS.items():
            pt = decrypt(text, key)
            cs = crib_score(pt)
            fc, fd = free_crib_search(pt)
            if cs > best_for_subset[0]:
                best_for_subset = (cs, pt, f"{dname}/{kname}")
            if cs > best_rsub[0]:
                best_rsub = (cs, pt, f"{dname}/{kname}", applied)
            if cs >= 4 or fc > 0:
                print(f"  ** crib={cs} free={fd} subset={applied} {dname}/{kname}")

    if best_for_subset[0] >= 3:
        print(f"  Subset {applied}: best crib={best_for_subset[0]} via {best_for_subset[2]}")

print(f"\nOverall best reverse subset: crib={best_rsub[0]} via {best_rsub[2]} transforms={best_rsub[3]}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 5: Transform as plaintext operation (decrypt FIRST, then transform)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("Approach 5: Decrypt first, THEN apply transforms to plaintext")
print("  (What if the transforms describe what happened to the PT?)")
print("=" * 70)

best_a5 = (-999, '', '', '')

for kname, key in KEYWORDS.items():
    for dname, decrypt in DECRYPTORS.items():
        raw_pt = decrypt(CT, key)
        # Apply reverse transforms to the plaintext (undo what Sanborn did)
        for perm in permutations(range(4)):
            text = raw_pt
            for idx in perm:
                name, src, dst = REVERSE_SUBS[idx]
                text = text.replace(src, dst)
            cs = crib_score(text)
            fc, fd = free_crib_search(text)
            qs = qg_score(text)
            if cs > best_a5[0]:
                best_a5 = (cs, text, f"{dname}/{kname} then reverse subs", raw_pt)
            if cs >= 4 or fc > 0:
                print(f"  ** crib={cs} qg={qs:.3f} free={fd} {dname}/{kname}")

print(f"\nBest (decrypt then transform): crib={best_a5[0]} via {best_a5[2]}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 6: Check if the substitution pairs define a cipher alphabet
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("Approach 6: Do the 4 pairs define a partial cipher alphabet?")
print("  E↔A, L↔Q, I↔E, S↔C")
print("=" * 70)

# The pairs as a partial monoalphabetic substitution
# E→A, A→E (reciprocal pair 1)
# L→Q, Q→L (reciprocal pair 2)
# I→E... but E→A already. So I→E→A (chain!)
# S→C, C→S (reciprocal pair 3)

print("  Chain analysis:")
print("    E→A (and A→E? or A stays?)")
print("    L→Q (and Q→L? or Q stays?)")
print("    I→E (then E→A? So I→E→A = I→A?)")
print("    S→C (and C→S? or C stays?)")
print()
print("  If chained: I→E→A, L→Q, S→C")
print("  If reciprocal pairs: E↔A, L↔Q, I↔E (conflict!), S↔C")
print("  The I→E + E→A chain suggests ORDER MATTERS")

# Build the full monoalphabetic mapping
# Forward: apply in narrative order K0→K1→K3
# K0: I→E, K1: S→C then L→Q, K3: E→A
# So: I→E (step 1), then E→A (step 4) means I effectively maps to A
print("\n  Narrative chain (K0→K1→K3):")
mapping = {c: c for c in ALPH}  # identity
# K0: I→E
mapping['I'] = 'E'
# K1: S→C
mapping['S'] = 'C'
# K1: L→Q
mapping['L'] = 'Q'
# K3: E→A (this also catches the I→E from step 1!)
for c in ALPH:
    if mapping[c] == 'E':
        mapping[c] = 'A'

print(f"  Changed mappings: ", end='')
for c in ALPH:
    if mapping[c] != c:
        print(f"{c}→{mapping[c]}", end='  ')
print()

# Apply this mapping to K4
transformed = ''.join(mapping[c] for c in CT)
print(f"\n  K4 after mapping: {transformed}")
print(f"  Length: {len(transformed)}")

for kname, key in KEYWORDS.items():
    for dname, decrypt in DECRYPTORS.items():
        pt = decrypt(transformed, key)
        cs = crib_score(pt)
        fc, fd = free_crib_search(pt)
        qs = qg_score(pt)
        if cs >= 3 or fc > 0:
            print(f"    crib={cs} qg={qs:.3f} free={fd} {dname}/{kname}")
            print(f"    PT: {pt[:70]}")

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("SUMMARY — CORRECTED MISSPELLING SUBSTITUTIONS (4 only)")
print("=" * 70)
print(f"  Forward (24 orderings):     best crib = {best_fwd[0]}")
print(f"  Reverse (24 orderings):     best crib = {best_rev[0]}")
print(f"  Forward subsets (16):       best crib = {best_sub[0]}")
print(f"  Reverse subsets (16):       best crib = {best_rsub[0]}")
print(f"  Decrypt then transform:     best crib = {best_a5[0]}")
print(f"  Chained mapping:            see above")

print("\n  KEY INSIGHT: DESPARATLY E-deletion = grid-fitting (336=24x14)")
print("  337 is prime → DESPERATELY doesn't fit any rectangle.")
print("  Scheidt refused to answer because admitting it reveals K3 grid.")
print("=" * 70)
