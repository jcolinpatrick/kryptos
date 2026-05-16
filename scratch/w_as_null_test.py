#!/usr/bin/env python3
"""
Test #4: W's are null/filler positions. Remove them and check whether the
92-char remainder has better statistical properties or admits a periodic
substitution cipher consistent with remapped cribs.
"""
import os, sys
_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, 'src')):
    parent = os.path.dirname(_ROOT)
    if parent == _ROOT: sys.exit("repo root not found")
    _ROOT = parent
sys.path.insert(0, os.path.join(_ROOT, 'src'))

from kryptos.kernel.constants import CT, CRIB_DICT
from collections import Counter

W_POS = [20, 36, 48, 58, 74]
ALL_W_SET = set(W_POS)

# === Build 92-char CT with W's removed and remapped cribs ===
remap = {}  # original pos -> new pos
new_ct = []
new_pos = 0
for orig_pos, ch in enumerate(CT):
    if orig_pos in ALL_W_SET:
        continue
    remap[orig_pos] = new_pos
    new_ct.append(ch)
    new_pos += 1
CT92 = ''.join(new_ct)
CRIB92 = {remap[p]: CRIB_DICT[p] for p in CRIB_DICT}

print("="*70)
print(" TEST 4: W-as-null hypothesis")
print("="*70)
print(f"\n CT (97): {CT}")
print(f" CT (92): {CT92}")
print(f" New crib positions: {sorted(CRIB92.keys())}")
print(f" Cribs:")
print(f"   EAST   at new positions {sorted(p for p in CRIB92 if p < 35)} = "
      f"{''.join(CRIB92[p] for p in sorted(p for p in CRIB92 if p < 35))}")
print(f"   BERLIN at new positions {sorted(p for p in CRIB92 if p >= 35)} = "
      f"{''.join(CRIB92[p] for p in sorted(p for p in CRIB92 if p >= 35))}")

# === Statistical comparison ===
def index_of_coincidence(s):
    n = len(s)
    counts = Counter(s)
    return sum(c*(c-1) for c in counts.values()) / (n*(n-1))

def kappa_at_distance(s, d):
    n = len(s)
    if d >= n: return 0
    return sum(1 for i in range(n-d) if s[i] == s[i+d]) / (n-d)

def repeat_ngrams(s, n):
    cnt = Counter(s[i:i+n] for i in range(len(s)-n+1))
    return sum(c-1 for c in cnt.values() if c > 1)

print(f"\n Statistical comparison (raw 97 vs W-removed 92):")
print(f"   IC:      raw={index_of_coincidence(CT):.4f}  92char={index_of_coincidence(CT92):.4f}  (English ~0.067, random ~0.038)")
print(f"   rep3:    raw={repeat_ngrams(CT, 3):d}  92char={repeat_ngrams(CT92, 3):d}")
print(f"   rep4:    raw={repeat_ngrams(CT, 4):d}  92char={repeat_ngrams(CT92, 4):d}")
print(f"   kappa peaks (top 5 by distance, 92char):")
kappas_92 = sorted([(d, kappa_at_distance(CT92, d)) for d in range(1, 30)], key=lambda x: -x[1])[:5]
for d, k in kappas_92:
    print(f"     d={d:2d}: {k:.4f}")
print(f"   kappa peaks (top 5 by distance, raw 97):")
kappas_97 = sorted([(d, kappa_at_distance(CT, d)) for d in range(1, 30)], key=lambda x: -x[1])[:5]
for d, k in kappas_97:
    print(f"     d={d:2d}: {k:.4f}")

# === Periodic consistency on 92-char CT ===
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

def check_period(ct, cribs, variant, p):
    constraints = {}
    for pos, ptch in cribs.items():
        k = derive_k(ct[pos], ptch, variant)
        r = pos % p
        if r in constraints and constraints[r] != k:
            return False, None
        constraints[r] = k
    return True, constraints

print(f"\n Periodic substitution consistency on 92-char CT (cribs at remapped positions):")
hits = []
for variant in ['vig','beau','varbeau']:
    print(f"\n  {variant}:")
    for p in range(1, 31):
        ok, ks = check_period(CT92, CRIB92, variant, p)
        if ok:
            n = len(ks)
            # Decrypt and score
            pt = []
            for i, ch in enumerate(CT92):
                r = i % p
                if r in ks:
                    pt.append(apply_k(ch, ks[r], variant))
                else:
                    pt.append('?')
            pt_str = ''.join(pt)
            print(f"    p={p:2d}: CONSISTENT ({n}/{p} residues constrained)")
            print(f"           PT: {pt_str}")
            hits.append((variant, p, pt_str, n))

if not hits:
    print(f"\n  No consistent period 1..30 across any variant. EMPTY.")
else:
    print(f"\n  {len(hits)} (variant, period) pairs consistent with remapped cribs.")

# === Final summary ===
print(f"\n{'='*70}\n SUMMARY\n{'='*70}")
print(f" W-as-null hypothesis:")
ic_diff = index_of_coincidence(CT92) - index_of_coincidence(CT)
print(f"   IC delta: {ic_diff:+.4f}  ({'increased' if ic_diff > 0 else 'decreased' if ic_diff < 0 else 'unchanged'} after removal)")
print(f"   Periodic substitution: {'HITS — investigate' if hits else 'EMPTY across p=1..30, all variants'}")
print(f"\n Expected behavior under genuine null hypothesis: removal should")
print(f"   (a) raise IC toward 0.067 (English-like) if W's were diluting structure")
print(f"   (b) admit at least one consistent period if cribs constrain a periodic key")
