#!/usr/bin/env python3
"""
W-anchor hypothesis: M2d (reverse non-crib inter-W blocks) and M6 (W as phase-reset).

Test both against periodic Vigenere/Beaufort/Variant-Beaufort at periods 1-20.
"""
import os, sys
_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    parent = os.path.dirname(_ROOT)
    if parent == _ROOT: sys.exit("kryptos repo root not found")
    _ROOT = parent
sys.path.insert(0, os.path.join(_ROOT, 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT
from kryptos.kernel.scoring.aggregate import score_candidate

W_POS = [20, 36, 48, 58, 74]
# Inter-W block boundaries (W positions themselves are NOT in any block)
BLOCKS = [
    (0, 20),    # B0
    (21, 36),   # B1: EAST at 21-33
    (37, 48),   # B2
    (49, 58),   # B3
    (59, 74),   # B4: BERLIN at 63-73
    (75, 97),   # B5
]
NONCRIB_BLOCKS = [0, 2, 3, 5]   # B0, B2, B3, B5

def m2d(ct):
    chars = list(ct)
    for idx in NONCRIB_BLOCKS:
        s, e = BLOCKS[idx]
        chars[s:e] = chars[s:e][::-1]
    return ''.join(chars)

def derive_k(c_char, p_char, variant):
    c, p = ord(c_char)-65, ord(p_char)-65
    if variant == 'vig':     return (c - p) % 26
    if variant == 'beau':    return (c + p) % 26
    if variant == 'varbeau': return (p - c) % 26

def apply_k(c_char, k, variant):
    c = ord(c_char)-65
    if variant == 'vig':     p = (c - k) % 26
    if variant == 'beau':    p = (k - c) % 26
    if variant == 'varbeau': p = (c + k) % 26
    return chr(p+65)

def consistency(crib_k_pairs, residue_fn, period):
    """crib_k_pairs: list of (logical_position, k_value). residue_fn(pos) -> int."""
    constraints = {}
    for pos, k in crib_k_pairs:
        r = residue_fn(pos) % period
        if r in constraints and constraints[r] != k:
            return False, len(constraints)
        constraints[r] = k
    return True, len(constraints)

def last_w_before(pos):
    last = -1
    for w in W_POS:
        if w < pos: last = w
        else: break
    return last

# =================================================================
print("="*70)
print(" K4 W-ANCHOR TESTS: M2d + M6")
print("="*70)
m2d_ct = m2d(CT)
print(f"\nRaw CT : {CT}")
print(f"M2d CT : {m2d_ct}")
diff = [i for i in range(97) if CT[i] != m2d_ct[i]]
print(f"M2d touched positions ({len(diff)}): {diff}")
crib_safe = all(m2d_ct[p] == CT[p] for p in CRIB_DICT)
print(f"All 24 crib positions preserved by M2d: {crib_safe}")

# =================================================================
print("\n" + "="*70)
print(" TEST A: M2d + standard periodic ciphers (Vig/Beau/VarBeau, p=1..20)")
print(" Crib positions are unchanged by M2d, so this also reproves raw-K4 result.")
print("="*70)
any_a_consistent = False
for variant in ['vig','beau','varbeau']:
    crib_pairs = [(pos, derive_k(CT[pos], CRIB_DICT[pos], variant)) for pos in sorted(CRIB_DICT)]
    print(f"\n {variant}:")
    for p in range(1, 21):
        ok, n = consistency(crib_pairs, lambda x: x, p)
        if ok:
            print(f"   p={p:2d}: CONSISTENT  ({n}/{p} residues constrained)")
            any_a_consistent = True
print(f"\n  Test A summary: {'AT LEAST ONE consistent period' if any_a_consistent else 'EMPTY across all variants/periods 1..20'}")

# =================================================================
print("\n" + "="*70)
print(" TEST B: M6 same-key phase-reset (Vig/Beau/VarBeau, p=1..20)")
print(" Single key K[0..p-1] reset at each W. Tests block-relative positions.")
print("="*70)
any_b_consistent = False
for variant in ['vig','beau','varbeau']:
    crib_pairs = [(pos, derive_k(CT[pos], CRIB_DICT[pos], variant)) for pos in sorted(CRIB_DICT)]
    print(f"\n {variant}:")
    found = []
    for p in range(1, 21):
        ok, n = consistency(crib_pairs, lambda x: x - last_w_before(x) - 1, p)
        if ok:
            found.append((p, n))
    if found:
        any_b_consistent = True
        for p, n in found:
            print(f"   p={p:2d}: CONSISTENT  ({n}/{p} residues constrained)")
    else:
        print(f"   no consistent period in 1..20")
print(f"\n  Test B summary: {'consistent period FOUND' if any_b_consistent else 'EMPTY across all variants/periods 1..20'}")

# =================================================================
print("\n" + "="*70)
print(" TEST C: M6 different-key per block (smallest consistent period per block)")
print("="*70)
b1_cribs = sorted(p for p in CRIB_DICT if p < 36)
b4_cribs = sorted(p for p in CRIB_DICT if p >= 59)
print(f"\n B1 crib positions (block-rel 0..14, length 15): {b1_cribs} -> block_rel {[p-21 for p in b1_cribs]}")
print(f" B4 crib positions (block-rel 0..14, length 15): {b4_cribs} -> block_rel {[p-59 for p in b4_cribs]}")

for variant in ['vig','beau','varbeau']:
    print(f"\n {variant}:")
    for label, cribs, block_start in [("B1 (EAST)", b1_cribs, 21), ("B4 (BERLIN)", b4_cribs, 59)]:
        pairs = [(pos - block_start, derive_k(CT[pos], CRIB_DICT[pos], variant)) for pos in cribs]
        smallest_p = None
        for p in range(1, 16):
            ok, _ = consistency(pairs, lambda x: x, p)
            if ok:
                smallest_p = p
                break
        print(f"   {label}: smallest consistent period = {smallest_p}")
        # Decrypt block at smallest p
        if smallest_p is not None:
            keystream = {}
            for br, k in pairs:
                keystream[br % smallest_p] = k
            block_len = 15
            pt = []
            for i in range(block_len):
                pos = block_start + i
                r = i % smallest_p
                if r in keystream:
                    pt.append(apply_k(CT[pos], keystream[r], variant))
                else:
                    pt.append('?')
            print(f"        decrypted: {''.join(pt)}")

# =================================================================
print("\n" + "="*70)
print(" SUMMARY")
print("="*70)
print(f" Test A (M2d + periodic): {'HIT' if any_a_consistent else 'EMPTY'}")
print(f" Test B (M6 same-key):    {'HIT' if any_b_consistent else 'EMPTY'}")
print(" Test C: see per-block decryptions above; multiple solutions exist per")
print("         block but uncribbed blocks (B0, B2, B3, B5) are unconstrained.")
