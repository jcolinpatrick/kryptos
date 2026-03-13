#!/usr/bin/env python3
"""
Test 'YESWONDERFULTHINGS' as K4 opening (positions 0-17).

K3 ends: "...CAN YOU SEE ANYTHING Q"  (Carter's question at Tutankhamun's tomb)
K4 reply: Carter answered "Yes, wonderful things."
→ YESWONDERFULTHINGS at positions 0-17 (18 chars)

Combined with cribs (21-33=EASTNORTHEAST, 63-73=BERLINCLOCK),
this gives 42 known PT positions.

For each cipher variant × period, derive required key letters and check consistency.
If consistent, decrypt full CT and show plaintext.
"""
import sys
sys.path.insert(0, 'src')

from kryptos.kernel.constants import CT, CRIB_DICT, KRYPTOS_ALPHABET as KA

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# ── Build known PT map ──────────────────────────────────────────────────
KNOWN_PT = {}

# Hypothesis: K4 opens with the reply to K3's question
OPENING = "YESWONDERFULTHINGS"
for i, ch in enumerate(OPENING):
    KNOWN_PT[i] = ch

# Established cribs
for pos, ch in CRIB_DICT.items():
    if pos in KNOWN_PT and KNOWN_PT[pos] != ch:
        print(f"CONFLICT in known PT at pos {pos}: {KNOWN_PT[pos]} vs crib {ch}")
    KNOWN_PT[pos] = ch

print(f"Known PT positions: {sorted(KNOWN_PT.keys())}")
print(f"Count: {len(KNOWN_PT)}")
print()

# ── Cipher key derivation functions ──────────────────────────────────────
def derive_vig(alpha, ct_ch, pt_ch):
    """Vig: CT = PT + KEY mod 26 → KEY = CT - PT mod 26"""
    return (alpha.index(ct_ch) - alpha.index(pt_ch)) % 26

def derive_beau(alpha, ct_ch, pt_ch):
    """Beaufort: CT = KEY - PT mod 26 → KEY = CT + PT mod 26"""
    return (alpha.index(ct_ch) + alpha.index(pt_ch)) % 26

def derive_vbeau(alpha, ct_ch, pt_ch):
    """Variant Beaufort: CT = PT - KEY mod 26 → KEY = PT - CT mod 26"""
    return (alpha.index(pt_ch) - alpha.index(ct_ch)) % 26

def decrypt_vig(alpha, key_letters, ct):
    out = []
    for i, c in enumerate(ct):
        k = key_letters[i % len(key_letters)]
        out.append(alpha[(alpha.index(c) - alpha.index(k)) % 26])
    return ''.join(out)

def decrypt_beau(alpha, key_letters, ct):
    out = []
    for i, c in enumerate(ct):
        k = key_letters[i % len(key_letters)]
        out.append(alpha[(alpha.index(k) - alpha.index(c)) % 26])
    return ''.join(out)

def decrypt_vbeau(alpha, key_letters, ct):
    out = []
    for i, c in enumerate(ct):
        k = key_letters[i % len(key_letters)]
        out.append(alpha[(alpha.index(c) + alpha.index(k)) % 26])
    return ''.join(out)

VARIANTS = [
    ('AZ-Vig',   AZ, derive_vig,   decrypt_vig),
    ('AZ-Beau',  AZ, derive_beau,  decrypt_beau),
    ('AZ-VBeau', AZ, derive_vbeau, decrypt_vbeau),
    ('KA-Vig',   KA, derive_vig,   decrypt_vig),
    ('KA-Beau',  KA, derive_beau,  decrypt_beau),
    ('KA-VBeau', KA, derive_vbeau, decrypt_vbeau),
]

# ── Test all periods × variants ───────────────────────────────────────────
print("=== KEY CONSISTENCY ANALYSIS (opening=YESWONDERFULTHINGS) ===")
print(f"{'Variant':<12} {'P':>3} {'Coverage':>10}  {'Key'}")
print("-" * 70)

passing = []

for vname, alpha, derive_fn, decrypt_fn in VARIANTS:
    for period in range(1, 27):
        key_req = {}     # key_pos → required idx
        conflict = False

        for pos, pt_ch in KNOWN_PT.items():
            ct_ch = CT[pos]
            key_pos = pos % period
            try:
                req_idx = derive_fn(alpha, ct_ch, pt_ch)
            except ValueError:
                conflict = True
                break

            if key_pos in key_req:
                if key_req[key_pos] != req_idx:
                    conflict = True
                    break
            else:
                key_req[key_pos] = req_idx

        if conflict:
            continue

        # Build key string
        key = [None] * period
        for kp, ki in key_req.items():
            if kp < period:
                key[kp] = alpha[ki]

        coverage = sum(1 for k in key if k is not None)
        key_str = ''.join(k if k else '?' for k in key)

        # Score: what fraction of key positions are determined?
        frac = coverage / period
        passing.append({
            'variant': vname, 'period': period, 'key': key_str,
            'coverage': coverage, 'frac': frac,
            'alpha': alpha, 'decrypt_fn': decrypt_fn,
        })

        marker = " ◄ FULL KEY!" if coverage == period else ""
        print(f"{vname:<12} {period:>3}  {coverage:>3}/{period:<3}={frac:.2f}  {key_str}{marker}")

# ── Show decryptions for fully-determined keys ────────────────────────────
full_keys = [r for r in passing if r['coverage'] == r['period']]
print(f"\n{len(full_keys)} fully-determined keys found:")

for r in full_keys:
    key_letters = list(r['key'])
    pt = r['decrypt_fn'](r['alpha'], key_letters, CT)
    crib_hits = sum(1 for pos, ch in KNOWN_PT.items() if pos < len(pt) and pt[pos] == ch)
    print(f"\n  {r['variant']} p={r['period']} key={r['key']}")
    print(f"  Plaintext: {pt}")
    print(f"  Crib hits: {crib_hits}/{len(KNOWN_PT)}")

# ── Also try variant: opening at position 1 (if CT[0] is a null) ─────────
print("\n\n=== VARIANT: opening starts at position 1 (CT[0] is null) ===")
KNOWN_PT2 = {}
OPENING2 = "YESWONDERFULTHINGS"
for i, ch in enumerate(OPENING2):
    KNOWN_PT2[i + 1] = ch  # shifted by 1
for pos, ch in CRIB_DICT.items():
    if pos in KNOWN_PT2 and KNOWN_PT2[pos] != ch:
        pass  # silently skip conflicts in this variant
    else:
        KNOWN_PT2[pos] = ch

print(f"Known PT2 positions: {sorted(KNOWN_PT2.keys())}, count={len(KNOWN_PT2)}")

# Count conflicts
conflicts2 = sum(1 for pos, ch in KNOWN_PT2.items()
                  if pos in CRIB_DICT and CRIB_DICT[pos] != ch)
print(f"Conflicts with cribs: {conflicts2}")

# ── Try longer opening: "YESWONDERFULTHINGSW" (with W delimiter) ──────────
print("\n\n=== VARIANT: opening + 'BB' at 18,19 then W delimiter ===")
# What if pos 18,19 encode something, and pos 20 is W (delimiter)?
# We already know CT[20]=W, so if PT[20]=W that's self-encrypting
KNOWN_PT3 = dict(KNOWN_PT)  # copy base
KNOWN_PT3[20] = 'W'  # CT[20]=W, PT[20]=W (self-encrypting like pos 32,73)
print(f"Adding self-encrypting constraint: pos 20 CT=W, PT=W")
print(f"Known PT3 positions: {len(KNOWN_PT3)}")

passing3 = []
for vname, alpha, derive_fn, decrypt_fn in VARIANTS:
    for period in range(1, 27):
        key_req = {}
        conflict = False

        for pos, pt_ch in KNOWN_PT3.items():
            ct_ch = CT[pos]
            key_pos = pos % period
            try:
                req_idx = derive_fn(alpha, ct_ch, pt_ch)
            except ValueError:
                conflict = True
                break

            if key_pos in key_req:
                if key_req[key_pos] != req_idx:
                    conflict = True
                    break
            else:
                key_req[key_pos] = req_idx

        if conflict:
            continue

        key = [None] * period
        for kp, ki in key_req.items():
            if kp < period:
                key[kp] = alpha[ki]

        coverage = sum(1 for k in key if k is not None)
        key_str = ''.join(k if k else '?' for k in key)
        frac = coverage / period
        passing3.append({'variant': vname, 'period': period, 'key': key_str,
                         'coverage': coverage, 'frac': frac,
                         'alpha': alpha, 'decrypt_fn': decrypt_fn})

        if coverage == period:
            print(f"  FULL KEY: {vname} p={period} key={key_str}")
            key_letters = list(key_str)
            pt = decrypt_fn(alpha, key_letters, CT)
            crib_hits = sum(1 for pos, ch in KNOWN_PT3.items() if pos < len(pt) and pt[pos] == ch)
            print(f"  Plaintext: {pt}")
            print(f"  Crib hits: {crib_hits}/{len(KNOWN_PT3)}")

full3 = [r for r in passing3 if r['coverage'] == r['period']]
print(f"\n{len(full3)} fully-determined keys (with W self-enc constraint)")

print("\nDone.")
