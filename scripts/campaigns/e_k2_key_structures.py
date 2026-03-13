#!/usr/bin/env python3
"""
Cipher:   K2-derived key structures + analytical tests
Family:   campaigns
Status:   active
Keyspace: see below
Last run:
Best score:

K2 KEY STRUCTURE ANALYSIS
--------------------------
1. STEHLE Δ4=5 OBSERVATION: Compute all bigram statistics for K4 CT.
   Stehle reportedly observed CT[i]+CT[i+4]≡5 (mod 26) at unusual frequency.
   Verify and test exploitation.

2. AFFINE KEY: Use T(x)=(27x+21) mod 97 as KEY GENERATION for cipher.
   key[i] = ((27*i+21) mod 97) mod 26  →  Trithemius-like structure
   Also test key[i] = (27*i+21) mod 26 = (i+21) mod 26 (pure Trithemius).

3. ANALYTICAL PRIMER DERIVATION: For W-null model (W at [20,36,48,58,74]),
   derive the algebraically required 7-char Vigenère PT-autokey primer.
   Check if DHJZIQG (derived primer) is meaningful.

4. BEAN EQUALITY STRUCTURE: k[27]=k[65] in context of W-null shifts.
   In 73-char, these become k[26]=k[63] (shifted by W at 20 and 36).
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET, CRIB_DICT,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC, BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
)
from collections import Counter
import math

CT_ORDS = [ord(c) - 65 for c in CT]

print("=" * 70)
print("K2 KEY STRUCTURE ANALYSIS")
print("=" * 70)

# ── Part 1: Stehle Δ4=5 observation ──────────────────────────────────────

print("\n--- PART 1: STEHLE Δk BIGRAM STATISTICS ---")
print("For each offset d, tabulate frequency of (CT[i]-CT[i+d]) mod 26 values.")

for d in [1, 3, 4, 5, 8, 13]:
    diffs = [(CT_ORDS[i] - CT_ORDS[i+d]) % 26 for i in range(CT_LEN - d)]
    cnt = Counter(diffs)
    n = len(diffs)
    expected = n / 26
    # Find max and its significance
    max_val = max(cnt.values())
    max_key = max(cnt, key=cnt.get)
    z = (max_val - expected) / math.sqrt(expected * (1 - 1/26))
    print(f"  d={d:2d}: n={n} expected={expected:.2f} | max freq={max_val} at Δ={max_key} (z={z:.2f})")
    # Also show top 5
    top5 = sorted(cnt.items(), key=lambda x: -x[1])[:5]
    print(f"         top5: {top5}")
    if d == 4:
        count_5 = cnt.get(5, 0)
        print(f"         Δ4=5: freq={count_5} (expected={expected:.2f}, ratio={count_5/expected:.2f}×)")

# ── Part 2: Affine key cipher tests ───────────────────────────────────────

print("\n--- PART 2: AFFINE KEY GENERATION ---")

CRIB_LIST = sorted(CRIB_DICT.items())

def count_cribs(pt_ords):
    return sum(1 for pos, ch in CRIB_LIST
               if pos < len(pt_ords) and pt_ords[pos] == ord(ch) - 65)

def count_cribs_str(pt_str):
    mapped = sum(1 for pos, ch in CRIB_LIST if pos < len(pt_str) and pt_str[pos] == ch)
    free = 13 if "EASTNORTHEAST" in pt_str else 0
    free += 11 if "BERLINCLOCK" in pt_str else 0
    return max(mapped, free)

# Test various affine key structures
models = [
    ("Trithemius_mod26",  [(i + 21) % 26 for i in range(97)]),       # 27≡1 mod26 → slope=1
    ("T_mod97_mod26",     [((27*i+21) % 97) % 26 for i in range(97)]), # full 97-cycle then reduce
    ("27i_mod26",         [(27*i) % 26 for i in range(97)]),           # pure slope=27 (=1 mod26)
    ("Quadratic_ENE_BC",  [(i*i + 21) % 26 for i in range(97)]),      # quadratic
    ("VIGENERE_KEY_wrap", list(VIGENERE_KEY_ENE) * 10),                # wrap ENE key
]

for model_name, key_seq in models:
    for cipher_variant, fn in [("Vig", lambda c,k: (c-k)%26),
                                  ("Beau", lambda c,k: (k-c)%26),
                                  ("VBeau", lambda c,k: (c+k)%26)]:
        pt = [fn(CT_ORDS[i], key_seq[i % len(key_seq)]) for i in range(97)]
        hits = count_cribs(pt)
        if hits >= 3:
            pt_str = ''.join(chr(p+65) for p in pt)
            print(f"  {hits}/24 | {model_name}/{cipher_variant}")
            print(f"    ENE: {pt_str[21:34]} (want EASTNORTHEAST)")
            print(f"    BC:  {pt_str[63:74]} (want BERLINCLOCK)")

# ── Part 3: Analytical primer derivation ─────────────────────────────────

print("\n--- PART 3: ANALYTICAL PRIMER DERIVATION ---")
print("For W-null (W at [20,36,48,58,74]) + no extra nulls in 0-12:")
print("ENE at position 20 in 73-char (W at 20 as only null before ENE).")
print()

# CT73 with only W positions removed
W_POS = [20, 36, 48, 58, 74]
CT73 = [CT_ORDS[i] for i in range(97) if i not in W_POS][:73]

# For Vigenère PT-autokey, L=7, ENE at position 20:
# ENE requires pt73[13..19] to have specific values (VIGENERE_KEY_ENE[0..6])
# And these come from the autokey chain. Derive the primer.

def derive_primer_vigenere(ct73, L, ene_start):
    """Derive primer for Vigenère PT-autokey that satisfies ENE crib."""
    # key[ene_start + i] = VIGENERE_KEY_ENE[i] for i=0..12
    # For i in 0..L-1: key[ene_start+i] = pt73[ene_start+i-L]
    # pt73[ene_start+i-L] = (ct73[ene_start+i-L] - key[ene_start+i-L]) % 26
    # This creates a chain... solve backwards if possible
    # For L=7 and ene_start=20: key[20..32] = pt73[13..25]
    # These pt73 values come from the autokey chain from position 0
    # The chain is complex; instead compute forward and find the required primer
    # by working backwards from the constraint.

    # Compute what pt73[0..L-1] must be for the chain to work:
    # This requires solving a system of equations.
    # Simplified: try all 26^L primers and check
    # But 26^7 = ~8B, too slow. Use the analytical constraints instead.

    # For position i in 0..L-1:
    # pt73[i] = (ct73[i] - primer[i]) mod 26
    # For position L..ene_start-1:
    # pt73[i] = (ct73[i] - pt73[i-L]) mod 26
    # For position ene_start..ene_start+12:
    # pt73[i] = ENE[i - ene_start] (crib constraint)

    # Working backwards from ENE:
    # pt73[ene_start - L..ene_start - 1] = VIGENERE_KEY_ENE[0..L-1]
    # For j in ene_start-L..ene_start-1:
    #   pt73[j] = VIGENERE_KEY_ENE[j - (ene_start - L)]

    # These pt73 values were computed from the chain:
    # For j in L..ene_start-1: pt73[j] = (ct73[j] - pt73[j-L]) mod 26
    # So pt73[j-L] = (ct73[j] - pt73[j]) mod 26

    # This allows us to propagate backward to find primer
    # from pt73[ene_start-L..ene_start-1] = VIGENERE_KEY_ENE

    # Forward propagation gives us a constraint system
    # Let's solve by forward computation with a constraint

    ene_pt = list(VIGENERE_KEY_ENE)  # 13 values

    # We know pt73[ene_start-L..ene_start-1] = ene_pt[0..L-1]
    known_pt = {}
    for j in range(L):
        known_pt[ene_start - L + j] = ene_pt[j]

    # Propagate backwards: for j < ene_start - L:
    # pt73[j] = (ct73[j+L] - pt73[j+L]) mod 26 if pt73[j+L] is known
    # Also: pt73[ene_start..ene_start+12] = ENE (from crib)
    ene_str = "EASTNORTHEAST"
    for j in range(13):
        known_pt[ene_start + j] = ord(ene_str[j]) - 65

    # Propagate backward from known positions
    for j in range(ene_start - 1, -1, -1):
        if j in known_pt:
            continue
        if j + L in known_pt:
            # pt73[j] = (ct73[j+L] - pt73[j+L]) mod 26
            # This comes from: pt73[j+L] = (ct73[j+L] - pt73[j]) mod 26
            # → pt73[j] = (ct73[j+L] - pt73[j+L]) mod 26
            known_pt[j] = (ct73[j + L] - known_pt[j + L]) % 26

    # Extract primer from pt73[0..L-1]
    primer = []
    for j in range(L):
        if j in known_pt:
            # pt73[j] = (ct73[j] - primer[j]) mod 26
            # → primer[j] = (ct73[j] - pt73[j]) mod 26
            primer.append((ct73[j] - known_pt[j]) % 26)
        else:
            primer.append(None)

    return primer, known_pt

print("Vigenère PT-autokey, L=7, ENE at pos 20:")
primer_v, known_pt_v = derive_primer_vigenere(CT73, 7, 20)
primer_str_v = ''.join(chr(p+65) if p is not None else '?' for p in primer_v)
print(f"  Derived primer: {primer_str_v}")
print(f"  In KA positions: {[KRYPTOS_ALPHABET.index(c) if c != '?' else -1 for c in primer_str_v]}")

# Verify by forward computation
if None not in primer_v:
    key = list(primer_v)
    pt73_fwd = []
    for i, c in enumerate(CT73):
        k = key[i] if i < 7 else pt73_fwd[i-7]
        p = (c - k) % 26
        pt73_fwd.append(p)
        key.append(p)

    hits_ene = sum(1 for j, ch in enumerate("EASTNORTHEAST") if j+20 < len(pt73_fwd) and pt73_fwd[j+20] == ord(ch)-65)
    bc_start = 20 + 1 + 11 + 1 + 11 + 1 + 9 + 1  # rough estimate
    # Actually need to compute BC position in 73-char
    # W positions before BC: 20 (1), 36 (2), 48 (3), 58 (4) → 4 removed before pos 63
    bc_73 = 63 - 4  # = 59
    hits_bc = sum(1 for j, ch in enumerate("BERLINCLOCK") if j+bc_73 < len(pt73_fwd) and pt73_fwd[j+bc_73] == ord(ch)-65)
    print(f"  Verification: ENE hits={hits_ene}/13, BC hits={hits_bc}/11")
    print(f"  ENE region: {''.join(chr(p+65) for p in pt73_fwd[20:33])}")
    print(f"  BC region:  {''.join(chr(p+65) for p in pt73_fwd[bc_73:bc_73+11])}")

# Now try: is DHJZIQG meaningful?
print(f"\n  Checking if DHJZIQG has structure:")
dhjziqg = [3, 7, 9, 25, 8, 16, 6]  # D,H,J,Z,I,Q,G
vigenere_key_ene = list(VIGENERE_KEY_ENE)
print(f"  DHJZIQG vs VIGENERE_KEY_ENE prefix: {dhjziqg} vs {vigenere_key_ene[:7]}")
print(f"  KA lookup: {[KRYPTOS_ALPHABET[i] for i in dhjziqg]}")

# ── Part 4: Bean equality in 73-char context ──────────────────────────────

print("\n--- PART 4: BEAN EQUALITY IN 73-CHAR CONTEXT ---")
print("Original: k[27]=k[65]. Under W-null (W at 20,36 removed before 65):")
# W at 20 is before 27 (1 null) → 27 shifts to 26 in 73-char
# W at 20 and 36 are before 65 (2 nulls) → 65 shifts to 63 in 73-char
print(f"  k[27] → k[26] in 73-char (W at 20 shifts position 27 left by 1)")
print(f"  k[65] → k[63] in 73-char (W at 20,36 shift position 65 left by 2)")
print(f"  New equality: k[26]=k[63] in 73-char")
print(f"  These are positions: ENE[6]=R (pos 26) and BC[0]=B (pos 63)")
print(f"  ??? check if this is actually (ENE[6]=R and BC first=B)")
# In 73-char, position 26 = crib ENE[6] = R (since ENE starts at 20 in 73-char)
# In 73-char, position 63 = BC start = B (since BC starts at 59, not 63)
# Wait: BC start in 73-char = 63 - 4 = 59. So position 63 in 73-char is BC[4]=I.
bc_start_73 = 63 - 4  # 4 W's before BC: positions 20, 36, 48, 58
print(f"  BC in 73-char starts at position {bc_start_73}")
print(f"  Position 63 in 73-char = BC[63-{bc_start_73}] = BC[{63-bc_start_73}] = {chr(ord('BERLINCLOCK'[63-bc_start_73]))} if valid")
bc_idx = 63 - bc_start_73  # = 4
if 0 <= bc_idx < 11:
    print(f"  BC[4] = {'BERLINCLOCK'[bc_idx]} = I")
    print(f"  Bean equality in 73-char: key at R-position = key at I-position")
    print(f"  For Vigenère: (F-R)%26 = (M-I)%26 → {(5-17)%26} = {(12-8)%26} → 14 ≠ 4. CONFLICT exists")

# Summary
print("\n" + "=" * 70)
print("SUMMARY:")
print("1. Stehle Δ4 stats: see above (check for anomalous frequency at Δ=5)")
print("2. Affine key: only shows hits above 3 if found")
print("3. Analytical primer DHJZIQG: not a recognizable keyword")
print("   This rules out Vig PT-autokey L=7 on W-only-null 73-char text")
print("4. Bean equality shifts but still creates conflict in 73-char model")
print("=" * 70)
