#!/usr/bin/env python3
"""Decrypt K4 using the 106-char Cardan grille extract as running key.

Tests all combinations of:
- Cipher variant: Vigenère, Beaufort, Variant Beaufort
- Alphabet: standard AZ, Kryptos KA
- Key offset: 0 through 9 (grille extract is 9 chars longer than K4)
- Direction: grille as key for K4, and K4 as key for grille

Also analyzes the grille extract itself for internal structure.
"""
import sys, json, os
from collections import Counter
from itertools import product

sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT as K4_CT

# ── Constants ────────────────────────────────────────────────────────────
GRILLE = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Known cribs (0-indexed positions in K4 plaintext)
CRIB_ENE = (21, "EASTNORTHEAST")   # positions 21-33
CRIB_BC  = (63, "BERLINCLOCK")     # positions 63-73

# Bean constraint: keystream[27] == keystream[65]
BEAN_EQ_POS = (27, 65)

print("=" * 80)
print("CARDAN GRILLE DECRYPTION ATTACK ON K4")
print("=" * 80)

# ── 1. GRILLE EXTRACT ANALYSIS ──────────────────────────────────────────
print("\n" + "─" * 80)
print("1. GRILLE EXTRACT ANALYSIS")
print("─" * 80)
print(f"Length: {len(GRILLE)}")
print(f"K4 length: {len(K4_CT)}")
print(f"Offset range: 0 to {len(GRILLE) - len(K4_CT)}")

# Frequency
freq = Counter(GRILLE)
print(f"\nFrequency distribution:")
for ch in sorted(freq.keys()):
    bar = '#' * freq[ch]
    print(f"  {ch}: {freq[ch]:3d} {bar}")

# IC
n = len(GRILLE)
ic = sum(f * (f - 1) for f in freq.values()) / (n * (n - 1)) if n > 1 else 0
print(f"\nIC: {ic:.4f} (English ~0.0667, random ~0.0385)")

# Quadgram score (if available)
QGRAM_PATH = "data/english_quadgrams.json"
quadgrams = {}
if os.path.exists(QGRAM_PATH):
    with open(QGRAM_PATH) as f:
        quadgrams = json.load(f)
    total_qg = 0
    count_qg = 0
    for i in range(len(GRILLE) - 3):
        qg = GRILLE[i:i+4]
        total_qg += quadgrams.get(qg, -10.0)
        count_qg += 1
    avg_qg = total_qg / count_qg if count_qg else 0
    print(f"Quadgram score: {avg_qg:.3f}/char (English text ~-4.2, random ~-5.0)")

# ── 2. DECRYPTION FUNCTIONS ─────────────────────────────────────────────

def char_to_idx(ch, alpha):
    return alpha.index(ch)

def idx_to_char(idx, alpha):
    return alpha[idx % len(alpha)]

def decrypt_vigenere(ct, key, alpha):
    """PT = (CT - KEY) mod 26"""
    result = []
    for c, k in zip(ct, key):
        ci = char_to_idx(c, alpha)
        ki = char_to_idx(k, alpha)
        pi = (ci - ki) % 26
        result.append(idx_to_char(pi, alpha))
    return ''.join(result)

def decrypt_beaufort(ct, key, alpha):
    """PT = (KEY - CT) mod 26"""
    result = []
    for c, k in zip(ct, key):
        ci = char_to_idx(c, alpha)
        ki = char_to_idx(k, alpha)
        pi = (ki - ci) % 26
        result.append(idx_to_char(pi, alpha))
    return ''.join(result)

def decrypt_variant_beaufort(ct, key, alpha):
    """PT = (CT + KEY) mod 26"""
    result = []
    for c, k in zip(ct, key):
        ci = char_to_idx(c, alpha)
        ki = char_to_idx(k, alpha)
        pi = (ci + ki) % 26
        result.append(idx_to_char(pi, alpha))
    return ''.join(result)

# ── 3. CRIB SCORING ─────────────────────────────────────────────────────

def score_cribs(pt):
    """Check how many crib characters match at known positions."""
    score = 0
    details = []
    for start, crib_text in [CRIB_ENE, CRIB_BC]:
        for i, ch in enumerate(crib_text):
            pos = start + i
            if pos < len(pt):
                if pt[pos] == ch:
                    score += 1
                    details.append(f"  pos {pos}: '{ch}' ✓")
                # else:
                #     details.append(f"  pos {pos}: expected '{ch}' got '{pt[pos]}'")
    return score, details

def check_bean_eq(ct, pt, alpha):
    """Check Bean equality: keystream[27] == keystream[65]."""
    if len(pt) <= 65:
        return None  # can't check
    # Derive keystream: k = (ct - pt) mod 26 for Vigenère convention
    k27 = (char_to_idx(ct[27], alpha) - char_to_idx(pt[27], alpha)) % 26
    k65 = (char_to_idx(ct[65], alpha) - char_to_idx(pt[65], alpha)) % 26
    return k27 == k65

def quadgram_score(text):
    """Average quadgram log-probability per character."""
    if not quadgrams:
        return 0
    total = sum(quadgrams.get(text[i:i+4], -10.0) for i in range(len(text) - 3))
    return total / (len(text) - 3) if len(text) > 3 else -10.0

# ── 4. SYSTEMATIC DECRYPTION ────────────────────────────────────────────
print("\n" + "─" * 80)
print("2. SYSTEMATIC DECRYPTION: GRILLE AS KEY FOR K4")
print("─" * 80)

variants = [
    ("Vigenere", decrypt_vigenere),
    ("Beaufort", decrypt_beaufort),
    ("VarBeau",  decrypt_variant_beaufort),
]
alphabets = [("AZ", AZ), ("KA", KA)]
offsets = range(len(GRILLE) - len(K4_CT) + 1)  # 0..9

best_results = []

for (vname, vfunc), (aname, alpha), offset in product(variants, alphabets, offsets):
    key_slice = GRILLE[offset:offset + len(K4_CT)]
    pt = vfunc(K4_CT, key_slice, alpha)
    crib_score, _ = score_cribs(pt)
    bean = check_bean_eq(K4_CT, pt, alpha)
    qg = quadgram_score(pt)

    best_results.append((crib_score, bean, qg, vname, aname, offset, pt))

# Sort by crib score descending, then quadgram
best_results.sort(key=lambda x: (-x[0], -x[2]))

print(f"\n{'Rank':>4} {'Crib':>5} {'Bean':>5} {'QG/ch':>7} {'Variant':>10} {'Alpha':>5} {'Off':>4}  Plaintext (first 40)")
print("─" * 100)
for i, (cs, bean, qg, vn, an, off, pt) in enumerate(best_results[:30]):
    bean_str = "PASS" if bean else "FAIL" if bean is not None else "N/A"
    print(f"{i+1:4d} {cs:5d} {bean_str:>5} {qg:7.3f} {vn:>10} {an:>5} {off:4d}  {pt[:40]}")

# ── 5. REVERSE DIRECTION: K4 AS KEY FOR GRILLE ──────────────────────────
print("\n" + "─" * 80)
print("3. REVERSE: K4 AS KEY FOR GRILLE EXTRACT")
print("─" * 80)

reverse_results = []

for (vname, vfunc), (aname, alpha), offset in product(variants, alphabets, offsets):
    grille_slice = GRILLE[offset:offset + len(K4_CT)]
    pt = vfunc(grille_slice, K4_CT, alpha)
    qg = quadgram_score(pt)
    # Check if any known words appear
    reverse_results.append((qg, vname, aname, offset, pt))

reverse_results.sort(key=lambda x: -x[0])

print(f"\n{'Rank':>4} {'QG/ch':>7} {'Variant':>10} {'Alpha':>5} {'Off':>4}  Plaintext (first 40)")
print("─" * 80)
for i, (qg, vn, an, off, pt) in enumerate(reverse_results[:15]):
    print(f"{i+1:4d} {qg:7.3f} {vn:>10} {an:>5} {off:4d}  {pt[:40]}")

# ── 6. DETAILED OUTPUT FOR TOP RESULTS ──────────────────────────────────
print("\n" + "─" * 80)
print("4. DETAILED TOP RESULTS (crib score >= 2)")
print("─" * 80)

for cs, bean, qg, vn, an, off, pt in best_results:
    if cs >= 2:
        bean_str = "PASS" if bean else "FAIL" if bean is not None else "N/A"
        print(f"\n  {vn} / {an} / offset={off}")
        print(f"  Crib: {cs}/24  Bean: {bean_str}  QG: {qg:.3f}/char")
        print(f"  PT: {pt}")
        # Show crib alignment
        ene_match = pt[21:34]
        bc_match = pt[63:74]
        print(f"  pos 21-33: {ene_match} (want: EASTNORTHEAST)")
        print(f"  pos 63-73: {bc_match} (want: BERLINCLOCK)")
        # Highlight matching positions
        ene_marks = ''.join('✓' if ene_match[i] == "EASTNORTHEAST"[i] else '·' for i in range(min(len(ene_match), 13)))
        bc_marks = ''.join('✓' if bc_match[i] == "BERLINCLOCK"[i] else '·' for i in range(min(len(bc_match), 11)))
        print(f"            {ene_marks}")
        print(f"            {bc_marks}")

# ── 7. KEYSTREAM ANALYSIS AT CRIB POSITIONS ─────────────────────────────
print("\n" + "─" * 80)
print("5. KEYSTREAM ANALYSIS: What key would produce known PT from K4 CT?")
print("─" * 80)

# If PT[21:34] = EASTNORTHEAST, what key values are needed?
print("\nRequired keystream (Vigenère: K = CT - PT mod 26) for EASTNORTHEAST crib:")
print(f"{'Pos':>4} {'CT':>4} {'PT':>4} {'K_AZ':>5} {'K_idx':>6}")
for i, pt_ch in enumerate("EASTNORTHEAST"):
    pos = 21 + i
    ct_ch = K4_CT[pos]
    k_idx = (AZ.index(ct_ch) - AZ.index(pt_ch)) % 26
    k_ch = AZ[k_idx]
    print(f"{pos:4d} {ct_ch:>4} {pt_ch:>4} {k_ch:>5} {k_idx:>6}")

print("\nRequired keystream for BERLINCLOCK crib:")
for i, pt_ch in enumerate("BERLINCLOCK"):
    pos = 63 + i
    ct_ch = K4_CT[pos]
    k_idx = (AZ.index(ct_ch) - AZ.index(pt_ch)) % 26
    k_ch = AZ[k_idx]
    print(f"{pos:4d} {ct_ch:>4} {pt_ch:>4} {k_ch:>5} {k_idx:>6}")

# Now check: does the grille extract at any offset provide these key values?
print("\nChecking grille extract at each offset against required keystream:")
required_ene = []
for i, pt_ch in enumerate("EASTNORTHEAST"):
    pos = 21 + i
    ct_ch = K4_CT[pos]
    k_idx = (AZ.index(ct_ch) - AZ.index(pt_ch)) % 26
    required_ene.append((pos, AZ[k_idx]))

required_bc = []
for i, pt_ch in enumerate("BERLINCLOCK"):
    pos = 63 + i
    ct_ch = K4_CT[pos]
    k_idx = (AZ.index(ct_ch) - AZ.index(pt_ch)) % 26
    required_bc.append((pos, AZ[k_idx]))

for offset in range(10):
    key_slice = GRILLE[offset:offset + len(K4_CT)]
    ene_matches = sum(1 for pos, req_k in required_ene if key_slice[pos] == req_k)
    bc_matches = sum(1 for pos, req_k in required_bc if key_slice[pos] == req_k)
    total = ene_matches + bc_matches
    if total > 0:
        print(f"  Offset {offset}: ENE {ene_matches}/13, BC {bc_matches}/11, total {total}/24")

# Same for KA alphabet
print("\nSame check with KA alphabet:")
required_ene_ka = []
for i, pt_ch in enumerate("EASTNORTHEAST"):
    pos = 21 + i
    ct_ch = K4_CT[pos]
    k_idx = (KA.index(ct_ch) - KA.index(pt_ch)) % 26
    required_ene_ka.append((pos, KA[k_idx]))

required_bc_ka = []
for i, pt_ch in enumerate("BERLINCLOCK"):
    pos = 63 + i
    ct_ch = K4_CT[pos]
    k_idx = (KA.index(ct_ch) - KA.index(pt_ch)) % 26
    required_bc_ka.append((pos, KA[k_idx]))

for offset in range(10):
    key_slice = GRILLE[offset:offset + len(K4_CT)]
    ene_matches = sum(1 for pos, req_k in required_ene_ka if key_slice[pos] == req_k)
    bc_matches = sum(1 for pos, req_k in required_bc_ka if key_slice[pos] == req_k)
    total = ene_matches + bc_matches
    if total > 0:
        print(f"  Offset {offset}: ENE {ene_matches}/13, BC {bc_matches}/11, total {total}/24")

# ── 8. XOR / ADDITION ANALYSIS ──────────────────────────────────────────
print("\n" + "─" * 80)
print("6. GRILLE POSITION IN K4 CT CHECK")
print("─" * 80)
# Check if any substring of the grille appears in K4 or vice versa
for window in range(4, 10):
    for i in range(len(GRILLE) - window + 1):
        substr = GRILLE[i:i+window]
        if substr in K4_CT:
            print(f"  MATCH: grille[{i}:{i+window}] = '{substr}' found in K4 CT")

# ── 9. SUMMARY ──────────────────────────────────────────────────────────
print("\n" + "=" * 80)
print("SUMMARY")
print("=" * 80)
top = best_results[0]
print(f"Best crib score: {top[0]}/24 ({top[3]} / {top[4]} / offset={top[5]})")
print(f"Best Bean: {'PASS' if top[1] else 'FAIL'}")
print(f"Best quadgram: {top[2]:.3f}/char")
if top[0] >= 10:
    print("*** SIGNAL DETECTED — investigate further ***")
elif top[0] >= 3:
    print("*** Marginal — above random expectation, worth examining ***")
else:
    print("*** NOISE — no significant crib matches under direct running key ***")
    print("Consider: transposition of grille extract before use as key,")
    print("          partial key extraction, or grille extract as plaintext seed.")
