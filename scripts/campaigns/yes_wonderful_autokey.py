#!/usr/bin/env python3
"""
YESWONDERFULTHINGS + autokey test.

For PT-autokey, given primer of length p:
  key[i] = primer[i]     if i < p
  key[i] = PT[i-p]       if i >= p

Since PT[0:18] = YESWONDERFULTHINGS is known, we DERIVE the primer
from those positions, then propagate the full plaintext and check
if cribs emerge naturally at positions 21-33 and 63-73.

This is deterministic — no search needed.

Also tests CT-autokey and all 6 cipher variants.
"""
import sys
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_DICT, KRYPTOS_ALPHABET as KA

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
OPENING = "YESWONDERFULTHINGS"  # 18 chars, positions 0-17

def to_idx(alpha, ch):
    return alpha.index(ch)

def to_ch(alpha, idx):
    return alpha[idx % 26]

# ── PT autokey Vigenère decrypt ───────────────────────────────────────────
def pt_autokey_vig_decrypt(alpha, primer, ct):
    """PT autokey Vigenère: key = primer then previous PT."""
    pt = []
    for i, c in enumerate(ct):
        if i < len(primer):
            k = primer[i]
        else:
            k = pt[i - len(primer)]
        pt.append(to_ch(alpha, to_idx(alpha, c) - to_idx(alpha, k)))
    return ''.join(pt)

def pt_autokey_beau_decrypt(alpha, primer, ct):
    """PT autokey Beaufort: key = primer then previous PT."""
    pt = []
    for i, c in enumerate(ct):
        if i < len(primer):
            k = primer[i]
        else:
            k = pt[i - len(primer)]
        pt.append(to_ch(alpha, to_idx(alpha, k) - to_idx(alpha, c)))
    return ''.join(pt)

def pt_autokey_vbeau_decrypt(alpha, primer, ct):
    """PT autokey Variant Beaufort: key = primer then previous PT."""
    pt = []
    for i, c in enumerate(ct):
        if i < len(primer):
            k = primer[i]
        else:
            k = pt[i - len(primer)]
        pt.append(to_ch(alpha, to_idx(alpha, c) + to_idx(alpha, k)))
    return ''.join(pt)

# ── CT autokey (key = primer then previous CT) ────────────────────────────
def ct_autokey_vig_decrypt(alpha, primer, ct):
    pt = []
    for i, c in enumerate(ct):
        k = primer[i] if i < len(primer) else ct[i - len(primer)]
        pt.append(to_ch(alpha, to_idx(alpha, c) - to_idx(alpha, k)))
    return ''.join(pt)

def ct_autokey_beau_decrypt(alpha, primer, ct):
    pt = []
    for i, c in enumerate(ct):
        k = primer[i] if i < len(primer) else ct[i - len(primer)]
        pt.append(to_ch(alpha, to_idx(alpha, k) - to_idx(alpha, c)))
    return ''.join(pt)

def ct_autokey_vbeau_decrypt(alpha, primer, ct):
    pt = []
    for i, c in enumerate(ct):
        k = primer[i] if i < len(primer) else ct[i - len(primer)]
        pt.append(to_ch(alpha, to_idx(alpha, c) + to_idx(alpha, k)))
    return ''.join(pt)

# primer derivation: given alpha, variant, known PT[0:p], derive primer
def derive_primer_vig(alpha, known_pt, ct, p):
    """primer[i] s.t. Vig with this primer recovers known_pt[0:p]"""
    primer = []
    for i in range(p):
        # CT[i] = (PT[i] + primer[i]) % 26
        k_idx = (to_idx(alpha, ct[i]) - to_idx(alpha, known_pt[i])) % 26
        primer.append(to_ch(alpha, k_idx))
    return ''.join(primer)

def derive_primer_beau(alpha, known_pt, ct, p):
    primer = []
    for i in range(p):
        # CT[i] = (primer[i] - PT[i]) % 26 → primer[i] = CT[i] + PT[i]
        k_idx = (to_idx(alpha, ct[i]) + to_idx(alpha, known_pt[i])) % 26
        primer.append(to_ch(alpha, k_idx))
    return ''.join(primer)

def derive_primer_vbeau(alpha, known_pt, ct, p):
    primer = []
    for i in range(p):
        # CT[i] = (PT[i] - primer[i]) % 26 → primer[i] = PT[i] - CT[i]
        k_idx = (to_idx(alpha, known_pt[i]) - to_idx(alpha, ct[i])) % 26
        primer.append(to_ch(alpha, k_idx))
    return ''.join(primer)

VARIANTS = [
    ('PT-Vig-AZ',   AZ, derive_primer_vig,   pt_autokey_vig_decrypt),
    ('PT-Beau-AZ',  AZ, derive_primer_beau,  pt_autokey_beau_decrypt),
    ('PT-VBeau-AZ', AZ, derive_primer_vbeau, pt_autokey_vbeau_decrypt),
    ('PT-Vig-KA',   KA, derive_primer_vig,   pt_autokey_vig_decrypt),
    ('PT-Beau-KA',  KA, derive_primer_beau,  pt_autokey_beau_decrypt),
    ('PT-VBeau-KA', KA, derive_primer_vbeau, pt_autokey_vbeau_decrypt),
    ('CT-Vig-AZ',   AZ, derive_primer_vig,   ct_autokey_vig_decrypt),
    ('CT-Beau-AZ',  AZ, derive_primer_beau,  ct_autokey_beau_decrypt),
    ('CT-VBeau-AZ', AZ, derive_primer_vbeau, ct_autokey_vbeau_decrypt),
    ('CT-Vig-KA',   KA, derive_primer_vig,   ct_autokey_vig_decrypt),
    ('CT-Beau-KA',  KA, derive_primer_beau,  ct_autokey_beau_decrypt),
    ('CT-VBeau-KA', KA, derive_primer_vbeau, ct_autokey_vbeau_decrypt),
]

# ── Crib check function ───────────────────────────────────────────────────
ALL_CRIBS = list(CRIB_DICT.items())  # [(pos, ch), ...]
ALL_CRIB_POSITIONS = set(CRIB_DICT.keys())

def count_crib_hits(pt):
    return sum(1 for pos, ch in ALL_CRIBS if pos < len(pt) and pt[pos] == ch)

def check_known_pt(pt, known):
    return sum(1 for pos, ch in known.items() if pos < len(pt) and pt[pos] == ch)

# ── Main test ─────────────────────────────────────────────────────────────
print(f"CT: {CT}")
print(f"Opening (pos 0-17): {OPENING}")
print(f"Cribs: {CRIB_DICT}")
print()

BEST = []

for vname, alpha, derive_fn, decrypt_fn in VARIANTS:
    for p in range(1, 19):  # primer length 1..18
        # Derive primer so that decrypt(CT[0:p]) = OPENING[0:p]
        primer = derive_fn(alpha, OPENING, CT, p)

        # Decrypt full CT with this primer
        pt = decrypt_fn(alpha, primer, CT)

        # Check if OPENING[0:18] is reproduced
        opening_match = (pt[:18] == OPENING)

        # Check cribs
        crib_hits = count_crib_hits(pt)
        full_hit = (crib_hits == 24)

        BEST.append((crib_hits, vname, p, primer, pt, opening_match))

BEST.sort(key=lambda x: -x[0])

print(f"{'Variant':<16} {'P':>3} {'Hits':>5}  {'Opening?':>8}  {'Primer':<20}  {'Plaintext[:40]'}")
print("-" * 95)
for crib_hits, vname, p, primer, pt, opening_match in BEST[:40]:
    flag = " ★ FULL CRIB MATCH!" if crib_hits == 24 else ""
    om = "YES" if opening_match else "no"
    print(f"{vname:<16} {p:>3}  {crib_hits:>3}/24  {om:>8}  {primer:<20}  {pt[:40]}{flag}")

# Show top result in detail
print("\n=== TOP RESULT ===")
top = BEST[0]
crib_hits, vname, p, primer, pt, opening_match = top
print(f"Variant: {vname}, Primer length: {p}, Primer: {primer}")
print(f"Crib hits: {crib_hits}/24")
print(f"Opening match: {opening_match}")
print(f"Full plaintext: {pt}")
print()

# Mark crib positions
pt_marked = list(pt)
for pos, ch in CRIB_DICT.items():
    if pt[pos] == ch:
        pt_marked[pos] = f"[{ch}]"
    else:
        pt_marked[pos] = f"({pt[pos]}≠{ch})"
print("With crib annotations:")
print(''.join(pt_marked[:80]))

# ── Also test: what if OPENING is not at 0 but the opening has a
#    shifted primer (i.e., cipher was keyed before the opening)? ──────────
print("\n\n=== EXTENDED: Best PT per variant summary ===")
by_variant = {}
for crib_hits, vname, p, primer, pt, om in BEST:
    if vname not in by_variant or crib_hits > by_variant[vname][0]:
        by_variant[vname] = (crib_hits, p, primer, pt)

for vname, (hits, p, primer, pt) in sorted(by_variant.items(), key=lambda x: -x[1][0]):
    print(f"  {vname:<16}  best={hits}/24 at p={p}  primer={primer:<20}  {pt[:40]}")
