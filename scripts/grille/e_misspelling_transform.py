#!/usr/bin/env python3
"""
Misspelling-as-instructions: apply the misspelling transformations to K4.

The 5 misspellings across K0-K3 define a transformation procedure:
  DESPARATLY:  Remove E / E→A
  IQLUSION:    L→Q
  UNDERGRUUND: O→U
  DIGETAL:     I→E
  PALIMPCEST:  S→C

Test: apply these as letter transformations to K4 ciphertext, then
attempt decryption with standard keywords.

Cipher: Substitution transform + Vigenere/Beaufort
Family: grille
Status: active
"""
import sys, os, json
from itertools import permutations

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

def crib_score_fixed(pt):
    """Anchored crib score at standard positions."""
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(pt) and pt[pos] == ch)

def free_crib_search(pt):
    total = 0
    details = []
    for crib in ('EASTNORTHEAST', 'BERLINCLOCK', 'NORTHEAST', 'BERLIN',
                 'CLOCK', 'EAST', 'NORTH', 'LAYER', 'POSITION'):
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
}

DECRYPTORS = {'Vig': vig_decrypt, 'Beau': beau_decrypt, 'VBeau': varbeau_decrypt}

print("=" * 70)
print("MISSPELLING-AS-INSTRUCTIONS TRANSFORM")
print("=" * 70)

# ── Define the transformations ───────────────────────────────────────────────
# Each transform is (name, type, params)
# Types: 'sub' = substitute, 'del' = delete
TRANSFORMS = {
    'DESPARATLY_sub': ('sub', 'E', 'A'),    # E→A
    'DESPARATLY_del': ('del', 'E', None),    # Remove E
    'IQLUSION':       ('sub', 'L', 'Q'),     # L→Q
    'UNDERGRUUND':    ('sub', 'O', 'U'),     # O→U
    'DIGETAL':        ('sub', 'I', 'E'),     # I→E
    'PALIMPCEST':     ('sub', 'S', 'C'),     # S→C
}

def apply_transform(text, name, ttype, src, dst):
    if ttype == 'del':
        return text.replace(src, '')
    elif ttype == 'sub':
        return text.replace(src, dst)
    return text

# ── Show K4 letter counts for affected letters ──────────────────────────────
print(f"\nK4 CT: {CT}")
print(f"Length: {len(CT)}")
from collections import Counter
ct_counts = Counter(CT)
affected = ['E', 'A', 'L', 'Q', 'O', 'U', 'I', 'S', 'C']
print(f"Affected letter counts: {', '.join(f'{c}={ct_counts[c]}' for c in affected)}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 1: Apply ALL substitutions (no deletion), then decrypt
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("Approach 1: All substitutions (E→A, L→Q, O→U, I→E, S→C), no deletion")
print("  This preserves length at 97")
print("=" * 70)

# Order matters! Test all orderings of the 5 substitutions
# But 5! = 120 orderings — tractable
subs = [
    ('E→A', 'E', 'A'),
    ('L→Q', 'L', 'Q'),
    ('O→U', 'O', 'U'),
    ('I→E', 'I', 'E'),
    ('S→C', 'S', 'C'),
]

# Also test the "narrative order" (K0→K1→K2→K3)
narrative_order = [
    ('I→E', 'I', 'E'),   # K0 DIGETAL
    ('S→C', 'S', 'C'),   # K1 PALIMPCEST (keyword)
    ('L→Q', 'L', 'Q'),   # K1 IQLUSION (plaintext)
    ('O→U', 'O', 'U'),   # K2 UNDERGRUUND
    ('E→A', 'E', 'A'),   # K3 DESPARATLY
]

best_a1 = (-999, '', '', '')

# First test narrative order
text = CT
order_desc = []
for name, src, dst in narrative_order:
    text = text.replace(src, dst)
    order_desc.append(name)

print(f"\n  Narrative order (K0→K1→K2→K3): {' → '.join(order_desc)}")
print(f"  Transformed: {text}")
print(f"  Length: {len(text)}")
new_counts = Counter(text)
print(f"  New counts: {', '.join(f'{c}={new_counts[c]}' for c in sorted(new_counts))}")

for kname, key in KEYWORDS.items():
    for dname, decrypt in DECRYPTORS.items():
        pt = decrypt(text, key)
        cs = crib_score_fixed(pt)
        fc, fd = free_crib_search(pt)
        qs = qg_score(pt)
        if cs > best_a1[0] or (cs == best_a1[0] and qs > qg_score(best_a1[1])):
            best_a1 = (cs, pt, f"Narrative+{dname}/{kname}", text)
        if cs >= 3 or fc > 0 or qs > -6.0:
            print(f"    {dname}/{kname}: crib={cs} qg={qs:.3f} free={fd}")

# Now test all 120 orderings
print(f"\n  Testing all 5! = 120 orderings...")
best_ordering = (-999, '', '', [])

for perm in permutations(range(5)):
    text = CT
    order_names = []
    for idx in perm:
        name, src, dst = subs[idx]
        text = text.replace(src, dst)
        order_names.append(name)

    for kname, key in KEYWORDS.items():
        for dname, decrypt in DECRYPTORS.items():
            pt = decrypt(text, key)
            cs = crib_score_fixed(pt)
            fc, fd = free_crib_search(pt)
            if cs > best_ordering[0]:
                qs = qg_score(pt)
                best_ordering = (cs, pt, f"{dname}/{kname}", order_names)
            if fc > 0:
                qs = qg_score(pt)
                print(f"  *** FREE CRIB: {fd} order={order_names} {dname}/{kname}")

print(f"  Best across 120 orderings: crib={best_ordering[0]} via {best_ordering[2]}")
print(f"  Order: {best_ordering[3]}")
print(f"  PT: {best_ordering[1][:70]}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 2: Apply ALL substitutions + deletion, then decrypt
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("Approach 2: All substitutions + E deletion (length changes)")
print("=" * 70)

# 6 operations (5 subs + 1 deletion), but deletion position matters
# Test: delete BEFORE subs vs AFTER subs vs at each point in sequence
# Key insight: if I→E runs first, it creates new E's. If delete-E runs after,
# those new E's get deleted too.

ops = [
    ('E→A', 'sub', 'E', 'A'),
    ('L→Q', 'sub', 'L', 'Q'),
    ('O→U', 'sub', 'O', 'U'),
    ('I→E', 'sub', 'I', 'E'),
    ('S→C', 'sub', 'S', 'C'),
    ('del-E', 'del', 'E', None),
]

# Test deletion at each position in the narrative order
positions_to_test = [
    # Delete first, then substitute
    ['del-E', 'I→E', 'S→C', 'L→Q', 'O→U', 'E→A'],
    # Narrative order with delete at end
    ['I→E', 'S→C', 'L→Q', 'O→U', 'E→A', 'del-E'],
    # I→E first (creates new E's), then delete all E's, then rest
    ['I→E', 'del-E', 'S→C', 'L→Q', 'O→U', 'E→A'],
    # Delete E, then I→E (brings E back), then rest
    ['del-E', 'I→E', 'L→Q', 'O→U', 'S→C', 'E→A'],
    # Just the 4 pure substitutions (no E→A, just delete E)
    ['del-E', 'L→Q', 'O→U', 'I→E', 'S→C'],
    # Substitutions only, delete last
    ['L→Q', 'O→U', 'I→E', 'S→C', 'del-E'],
    # E→A only (no deletion) — DESPARATLY has BOTH
    ['E→A', 'L→Q', 'O→U', 'I→E', 'S→C'],
]

best_a2 = (-999, '', '', '')

ops_lookup = {name: (ttype, src, dst) for name, ttype, src, dst in ops}
ops_lookup['E→A'] = ('sub', 'E', 'A')

for order in positions_to_test:
    text = CT
    for op_name in order:
        ttype, src, dst = ops_lookup[op_name]
        if ttype == 'del':
            text = text.replace(src, '')
        else:
            text = text.replace(src, dst)

    print(f"\n  Order: {' → '.join(order)}")
    print(f"  Result: {text[:70]}... (len={len(text)})")

    for kname, key in KEYWORDS.items():
        for dname, decrypt in DECRYPTORS.items():
            # Handle variable length — key alignment changes
            pt = decrypt(text, key)
            cs = crib_score_fixed(pt)
            fc, fd = free_crib_search(pt)
            qs = qg_score(pt)
            if cs > best_a2[0]:
                best_a2 = (cs, pt, f"{dname}/{kname} order={order}", text)
            if cs >= 3 or fc > 0 or qs > -6.0:
                print(f"    {dname}/{kname}: crib={cs} qg={qs:.3f} free={fd}")

print(f"\n  Best: crib={best_a2[0]} via {best_a2[2]}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 3: Reverse the transforms (undo the misspellings)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("Approach 3: REVERSE the misspelling transforms")
print("  If misspellings show what was DONE, undo them: Q→L, U→O, etc.")
print("=" * 70)

reverse_subs = [
    ('A→E', 'A', 'E'),  # undo E→A
    ('Q→L', 'Q', 'L'),  # undo L→Q
    ('U→O', 'U', 'O'),  # undo O→U
    ('E→I', 'E', 'I'),  # undo I→E
    ('C→S', 'C', 'S'),  # undo S→C
]

best_a3 = (-999, '', '', '')

# Narrative order reversed
for perm in permutations(range(5)):
    text = CT
    order_names = []
    for idx in perm:
        name, src, dst = reverse_subs[idx]
        text = text.replace(src, dst)
        order_names.append(name)

    for kname, key in KEYWORDS.items():
        for dname, decrypt in DECRYPTORS.items():
            pt = decrypt(text, key)
            cs = crib_score_fixed(pt)
            fc, fd = free_crib_search(pt)
            if cs > best_a3[0]:
                best_a3 = (cs, pt, f"{dname}/{kname}", order_names)
            if fc > 0:
                print(f"  *** FREE CRIB: {fd} order={order_names} {dname}/{kname}")

print(f"  Best across 120 reverse orderings: crib={best_a3[0]} via {best_a3[2]}")
print(f"  Order: {best_a3[3]}")
print(f"  PT: {best_a3[1][:70]}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 4: Partial transforms (subsets of the 5 substitutions)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("Approach 4: All subsets of transforms (2^5 = 32 combos)")
print("=" * 70)

best_a4 = (-999, '', '', '')

for mask in range(1, 32):  # skip 0 (no transforms)
    text = CT
    applied = []
    for bit in range(5):
        if mask & (1 << bit):
            name, src, dst = subs[bit]
            text = text.replace(src, dst)
            applied.append(name)

    for kname, key in KEYWORDS.items():
        for dname, decrypt in DECRYPTORS.items():
            pt = decrypt(text, key)
            cs = crib_score_fixed(pt)
            fc, fd = free_crib_search(pt)
            if cs > best_a4[0]:
                qs = qg_score(pt)
                best_a4 = (cs, pt, f"{dname}/{kname} transforms={applied}", text)
            if fc > 0:
                print(f"  *** FREE CRIB: {fd} transforms={applied} {dname}/{kname}")
            if cs >= 5:
                qs = qg_score(pt)
                print(f"  crib={cs} qg={qs:.3f} transforms={applied} {dname}/{kname}")

print(f"\n  Best subset: crib={best_a4[0]} via {best_a4[2]}")
print(f"  PT: {best_a4[1][:70]}")

# ══════════════════════════════════════════════════════════════════════════════
# APPROACH 5: Transform then check if result IS English (no decryption)
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("Approach 5: Could the transformed text itself be readable?")
print("  (What if the misspelling transforms ARE the decryption?)")
print("=" * 70)

# Apply forward transforms
for perm in permutations(range(5)):
    text = CT
    order_names = []
    for idx in perm:
        name, src, dst = subs[idx]
        text = text.replace(src, dst)
        order_names.append(name)
    qs = qg_score(text)
    fc, fd = free_crib_search(text)
    if qs > -6.5 or fc > 0:
        print(f"  Forward {order_names}: qg={qs:.3f} free={fd}")
        print(f"    {text}")

# Apply reverse transforms
for perm in permutations(range(5)):
    text = CT
    order_names = []
    for idx in perm:
        name, src, dst = reverse_subs[idx]
        text = text.replace(src, dst)
        order_names.append(name)
    qs = qg_score(text)
    fc, fd = free_crib_search(text)
    if qs > -6.5 or fc > 0:
        print(f"  Reverse {order_names}: qg={qs:.3f} free={fd}")
        print(f"    {text}")

# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("SUMMARY — MISSPELLING TRANSFORM RESULTS")
print("=" * 70)
print(f"  Approach 1 (all subs, 120 orders): best crib = {best_ordering[0]}")
print(f"  Approach 2 (subs + deletion):      best crib = {best_a2[0]}")
print(f"  Approach 3 (reverse transforms):   best crib = {best_a3[0]}")
print(f"  Approach 4 (all 32 subsets):       best crib = {best_a4[0]}")
print(f"  Approach 5 (transform = decrypt):  see above")
print("=" * 70)
