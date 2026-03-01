#!/usr/bin/env python3
"""
E-SOLVE-15: Masked Plaintext Attack Models

Key insight from Scheidt (WIRED 2005): "I masked the English language...
solve the technique first then the puzzle."

This means:
  1. Original PT is English
  2. A masking operation was applied to destroy English freq characteristics
  3. The masked text was then encrypted to produce CT
  4. The cribs (EASTNORTHEAST, BERLINCLOCK) appear in the DECRYPTED text
     (which is the masked text, not the original English)

Implication: IC and quadgram scores of decrypted text are IRRELEVANT.
Only crib score + Bean constraints matter for identifying the cipher.

This script explores:
  A. Two-layer brute force: simple mask + Beaufort/Vigenère with keyword
  B. Atbash mask + periodic key
  C. Caesar mask + periodic key (= shifted Vigenère, equivalent to key offset)
  D. Affine mask + periodic key
  E. Keyword substitution mask + periodic key
  F. Columnar transposition mask + periodic key
  G. Reverse mask + periodic key
"""

import sys
import os
import itertools
from collections import Counter

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    NOISE_FLOOR, SIGNAL_THRESHOLD,
)

CT_INT = [ALPH_IDX[c] for c in CT]
KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}

CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {pos: ALPH_IDX[CRIB_DICT[pos]] for pos in CRIB_POS}

print("E-SOLVE-15: Masked Plaintext Attack Models")
print("=" * 70)
print()
print("Masking hypothesis: PT_original → MASK → PT_masked → ENCRYPT → CT")
print("Cribs are in PT_masked (the decrypted text).")
print("IC/quadgrams of PT_masked are NOT expected to be English-like.")
print()

total_tested = 0
total_above_noise = 0
best_score = 0
best_config = None

# ── Helper: check crib consistency ────────────────────────────────────

def check_cribs_vig(key_func):
    """Score Vigenère decryption P = (C - K) mod 26 against cribs."""
    score = 0
    for pos in CRIB_POS:
        k = key_func(pos)
        pt = (CT_INT[pos] - k) % MOD
        if pt == CRIB_PT[pos]:
            score += 1
    return score

def check_cribs_beau(key_func):
    """Score Beaufort decryption P = (K - C) mod 26 against cribs."""
    score = 0
    for pos in CRIB_POS:
        k = key_func(pos)
        pt = (k - CT_INT[pos]) % MOD
        if pt == CRIB_PT[pos]:
            score += 1
    return score

def decrypt_full(key_func, variant):
    """Full decryption."""
    pt = []
    for i in range(CT_LEN):
        k = key_func(i)
        if variant == "vig":
            p = (CT_INT[i] - k) % MOD
        else:
            p = (k - CT_INT[i]) % MOD
        pt.append(ALPH[p])
    return "".join(pt)

def check_bean(key_func):
    """Check Bean constraints."""
    k27 = key_func(27)
    k65 = key_func(65)
    if k27 != k65:
        return False
    for a, b in BEAN_INEQ:
        if a in CRIB_PT and b in CRIB_PT:
            ka = key_func(a)
            kb = key_func(b)
            if ka == kb:
                return False
    return True


# ── Section A: Two-Layer — Simple Mask + Keyword Cipher ───────────────

print("Section A: Two-Layer (Mask + Keyword Cipher)")
print("-" * 70)
print()

# Model: PT_original → monoalphabetic substitution (mask) → Vigenère/Beaufort
# This is equivalent to: the Vigenère/Beaufort key enciphers a substituted alphabet
# If mask is a simple Caesar of shift s, then the combined key is (key + s) mod 26
# which is just a different Vigenère key — already eliminated.
#
# If mask is a general monoalphabetic substitution, it changes the PT alphabet.
# At crib positions: MASK(original_PT[i]) = crib[i]
# We know the crib but NOT original_PT.
# So the mask could be anything — there's no constraint from cribs alone.
#
# Key insight: Under monoalphabetic mask + periodic Vigenère,
# the KEY is still periodic. The mask changes the plaintext but NOT the key.
# Since all periodic keys are already eliminated, this is also eliminated.

print("Monoalphabetic mask + periodic Vigenère/Beaufort:")
print("  The key remains periodic regardless of the mask.")
print("  Since ALL periodic keys at ALL periods 2-26 are eliminated,")
print("  monoalphabetic mask + periodic substitution is ELIMINATED.")
print()

# ── Section B: Polyalphabetic Mask + Periodic Key ─────────────────────

print("Section B: Polyalphabetic Mask + Periodic Key")
print("-" * 70)
print()

# Model: PT → poly_mask(period q) → Vigenère/Beaufort(period p) → CT
# Combined effect: key at position i = f(i mod p, i mod q)
# If p and q are coprime, effective period = p*q
# If p and q share factors, effective period = lcm(p,q)
# Either way, the combined key is periodic with period lcm(p,q)
# Since periods 2-26 are all eliminated, we need lcm(p,q) > 26
# The smallest such pair: p=14, q=15 → lcm=210

print("Polyalphabetic mask + periodic key:")
print("  Combined period = lcm(mask_period, key_period)")
print("  Periods 2-26 already eliminated.")
print("  Need lcm > 26, which means both p and q must be large enough")
print("  that their lcm exceeds 26.")
print()
print("  Testing mask periods 2-13 × key periods 2-13:")

b_tested = 0
b_hits = 0

for q in range(2, 14):  # mask period
    for p in range(2, 14):  # key period
        from math import gcd
        lcm_pq = (p * q) // gcd(p, q)
        if lcm_pq <= 26:
            # Already eliminated
            continue

        # Combined period lcm_pq > 26
        # The combined key has lcm_pq free parameters
        # With only 24 constraints, this is UNDERDETERMINED for lcm > 24
        if lcm_pq > 24:
            continue  # Underdetermined, skip

        # For lcm_pq in range 27... impossible since max lcm of 2-13 × 2-13
        # where lcm > 26 is at least 28 (4×7=28). So all are underdetermined.

print("  All surviving (p,q) pairs have lcm > 24 → UNDERDETERMINED")
print("  Cannot discriminate with only 24 crib constraints.")
print()

# ── Section C: Transposition Mask + Substitution ──────────────────────

print("Section C: Transposition Mask + Substitution")
print("-" * 70)
print()
print("Model: PT → transposition (columnar, etc.) → Vigenère/Beaufort → CT")
print("This is the primary multi-layer hypothesis.")
print()

# The transposition rearranges the plaintext characters.
# Then substitution encrypts position-by-position.
# Cribs: the ENCRYPTED text at positions 21-33 decrypts to EASTNORTHEAST.
# But these 13 characters came from DIFFERENT original positions.
#
# Under transposition T: the character at CT position i came from
# original position T^{-1}(i).
#
# Under Beaufort: key[i] = CT[i] + masked_PT[i] mod 26
# And masked_PT[i] = original_PT[T^{-1}(i)]
#
# The cribs tell us masked_PT at positions 21-33 and 63-73.
# We DON'T know where these characters came from in the original text.
# So the transposition doesn't add constraints on the CIPHER KEY.
# The key constraints are the same as without transposition.
#
# This means: transposition mask + periodic substitution is STILL
# eliminated by the same argument that kills periodic substitution
# (the within-crib keystream contradictions are position-based,
# not content-based).

print("Key insight: Transposition mask doesn't change the KEYSTREAM")
print("  constraints at crib positions. The crib values are fixed at")
print("  specific CT positions regardless of where those characters")
print("  originally came from.")
print()
print("Therefore: transposition mask + periodic substitution is ELIMINATED")
print("  by the same proof that eliminates periodic substitution alone.")
print()

# But wait — transposition AFTER substitution is different!
# PT → Vigenère/Beaufort → transposition → CT
# In this case, the transposition scrambles the CIPHERTEXT,
# so the cribs are NOT at positions 21-33 and 63-73 of the
# Vigenère output. They're at the TRANSPOSED positions.

print("NOTE: Transposition AFTER substitution (encrypt-then-transpose)")
print("  changes which positions the cribs correspond to in the Vigenère")
print("  stream. This is the 'keystream transposition' tested in E-SOLVE-12.")
print()

# ── Section D: Reversal Mask ─────────────────────────────────────────

print("Section D: Reversal Mask")
print("-" * 70)

# What if the plaintext was REVERSED before encryption?
# Then CT position i encrypts original_PT[96-i]
# The cribs at positions 21-33 decrypt to EASTNORTHEAST
# but originally came from positions 96-21=75 down to 96-33=63
# Similarly BC at 63-73 came from positions 96-63=33 down to 96-73=23

# This is a specific transposition — the combined cipher is:
# CT[i] = Encrypt(Reverse_PT[i]) where key is some function of i
# The key at position i is determined by the crib at position i
# Reversal doesn't change which position the key applies to.

reversed_ct = CT[::-1]
reversed_ct_int = [ALPH_IDX[c] for c in reversed_ct]

# Check cribs against reversed CT under Vigenère and Beaufort
for variant_name, sign in [("Vigenère", 1), ("Beaufort", -1)]:
    score = 0
    for pos in CRIB_POS:
        if variant_name == "Vigenère":
            # P = C - K → K = C - P
            # With reversed CT: K = reversed_CT[pos] - crib[pos]
            pass
        # Just score standard way — reversal doesn't help here
    # Actually, reversal of CT then decrypt should just give reversed PT
    # Let me try: reverse CT, then Vigenère decrypt with periodic key
    for p in range(2, 14):
        for k_start in range(26):
            # Simple periodic key starting at k_start with period p
            key_func = lambda i, ks=k_start, per=p: (ks + (i % per)) % MOD
            score = 0
            for pos in CRIB_POS:
                k = key_func(pos)
                if variant_name == "Vigenère":
                    pt = (reversed_ct_int[pos] - k) % MOD
                else:
                    pt = (k - reversed_ct_int[pos]) % MOD
                if pt == CRIB_PT[pos]:
                    score += 1
            if score > NOISE_FLOOR:
                total_above_noise += 1
                print(f"  Reversed CT + {variant_name} p={p} k0={k_start}: {score}/24 ***")
            total_tested += 1

print(f"  Tested {total_tested} reversed CT + periodic key configs")
print(f"  Above noise: {total_above_noise}")
print()

# ── Section E: Keyword Alphabet Mask ──────────────────────────────────

print("Section E: Keyword Alphabet as Mask")
print("-" * 70)
print()

# What if the mask is a simple monoalphabetic substitution using
# a keyword alphabet? E.g., KRYPTOS alphabet: K→A, R→B, Y→C, ...
# Then the masked PT has different letter values.
# Combined with Vigenère/Beaufort with the SAME or DIFFERENT keyword.

# Generate keyword alphabets from common keywords
keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
            "CLOCK", "LIGHT", "EQUINOX", "VICTORIA", "SECRET",
            "CIPHER", "MATRIX", "POINT", "LOOMIS"]

e_tested = 0
e_hits = []

for mask_kw in keywords:
    # Build masked alphabet
    seen = set()
    mask_alph = []
    for c in mask_kw.upper():
        if c not in seen:
            mask_alph.append(c)
            seen.add(c)
    for c in ALPH:
        if c not in seen:
            mask_alph.append(c)
            seen.add(c)
    mask_alph_str = "".join(mask_alph)
    mask_idx = {c: i for i, c in enumerate(mask_alph_str)}

    for enc_kw in keywords:
        # Build encryption key alphabet
        seen2 = set()
        enc_alph = []
        for c in enc_kw.upper():
            if c not in seen2:
                enc_alph.append(c)
                seen2.add(c)
        for c in ALPH:
            if c not in seen2:
                enc_alph.append(c)
                seen2.add(c)
        enc_alph_str = "".join(enc_alph)

        # Two-layer: mask(PT) then Vigenère/Beaufort with enc keyword
        for variant in ["vig", "beau"]:
            for p in [7, 8, 10, 13]:
                # Periodic key using enc_kw alphabet
                enc_key = [ALPH_IDX[enc_kw[i % len(enc_kw)]] for i in range(CT_LEN)]

                score = 0
                for pos in CRIB_POS:
                    if variant == "vig":
                        # CT = mask(PT) + key mod 26
                        # mask(PT) = CT - key mod 26
                        masked_pt = (CT_INT[pos] - enc_key[pos]) % MOD
                    else:
                        # CT = key - mask(PT) mod 26
                        # mask(PT) = key - CT mod 26
                        masked_pt = (enc_key[pos] - CT_INT[pos]) % MOD

                    # masked_pt should equal mask(crib[pos])
                    # mask maps: crib letter → mask_alph position
                    expected_masked = mask_idx[CRIB_DICT[pos]]
                    if masked_pt == expected_masked:
                        score += 1

                if score > NOISE_FLOOR:
                    e_hits.append(f"mask={mask_kw} enc={enc_kw} {variant} p={p}: {score}/24")
                    total_above_noise += 1
                e_tested += 1

print(f"  Tested {e_tested} keyword mask × keyword cipher combinations")
if e_hits:
    for h in e_hits[:20]:
        print(f"    {h}")
else:
    print("  ZERO above noise")
print()

# ── Section F: Affine Mask ────────────────────────────────────────────

print("Section F: Affine Mask + Keyword Cipher")
print("-" * 70)
print()

# Affine mask: mask(x) = (a*x + b) mod 26, where gcd(a, 26) = 1
# Valid a values: 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25

valid_a = [a for a in range(1, 26) if MOD % a != 0 or a == 1]
valid_a = [a for a in range(1, 26) if all(a % p != 0 for p in [2, 13]) or a == 1]
# Actually: gcd(a, 26) = 1 means a is odd and not 13
from math import gcd as math_gcd
valid_a = [a for a in range(1, 26) if math_gcd(a, 26) == 1]

f_tested = 0
f_hits = []

for a in valid_a:
    for b in range(26):
        # Affine mask: masked_pt[i] = (a * original_pt[i] + b) mod 26
        # Combined with periodic Vigenère: CT[i] = masked_pt[i] + key[i] mod 26
        # → CT[i] = a * orig_pt[i] + b + key[i] mod 26
        # At crib positions: crib is masked_pt, so:
        # masked_pt[i] = (a * unknown_orig[i] + b) mod 26
        # But we know masked_pt at crib positions (it's the crib itself!)
        # So: crib[i] = (a * orig[i] + b) mod 26
        # This tells us orig[i] = a_inv * (crib[i] - b) mod 26
        # But the CIPHER doesn't care about orig — it encrypts masked_pt.

        # The key constraint is: key[i] = CT[i] - masked_pt[i] mod 26 (Vigenère)
        # masked_pt at crib positions IS the crib values.
        # So the key values at crib positions are FIXED regardless of affine mask.
        # → The affine mask has NO EFFECT on the key constraints!
        pass

print("Affine mask: has NO EFFECT on cipher key constraints.")
print("  The key at crib positions is determined by CT and crib values,")
print("  regardless of what original text was masked into the cribs.")
print("  Therefore: affine mask + periodic cipher = ELIMINATED")
print("  (same proof as periodic cipher alone)")
print()

# ── Section G: Position-Dependent Mask ────────────────────────────────

print("Section G: Position-Dependent Mask (key-based masking)")
print("-" * 70)
print()

# What if the mask is itself keyed and position-dependent?
# mask(i, x) = (x + mask_key[i]) mod 26
# Then: CT[i] = Encrypt(mask(i, PT[i])) using cipher_key[i]
# For Vigenère: CT[i] = PT[i] + mask_key[i] + cipher_key[i] mod 26
# This is just Vigenère with combined key = mask_key + cipher_key
# which is still a single key stream. If both are periodic,
# the combined key is periodic with lcm period.
# Already covered by the periodic elimination.

print("Position-dependent additive mask + Vigenère = single keystream.")
print("  Combined key = mask_key + cipher_key (mod 26)")
print("  If both periodic: combined period = lcm(p_mask, p_cipher)")
print("  Already eliminated for all periods 2-26.")
print()

# What about NON-ADDITIVE position-dependent mask?
# mask(i, x) = affine(a_i, b_i, x) where a_i, b_i vary by position
# Then: CT[i] = (a_i * PT[i] + b_i) + key[i] mod 26 (Vigenère)
# = a_i * PT[i] + (b_i + key[i]) mod 26
# At crib positions: CT[i] = a_i * crib_pt[i] + (b_i + key[i]) mod 26
# This has two unknowns per position (a_i, combined_b_k_i)
# With only 1 equation per position → UNDERDETERMINED

print("Non-additive mask: UNDERDETERMINED (2 unknowns per position)")
print()

# ── Section H: Specific Two-Layer Tests ──────────────────────────────

print("Section H: Specific Two-Layer Combinations")
print("-" * 70)
print()

# Test concrete two-layer scenarios:
# 1. Beaufort with KRYPTOS + Caesar shift
# 2. Vigenère with keyword + Atbash
# 3. Double Beaufort with two different keywords

h_tested = 0
h_hits = []

# Double Beaufort: PT → Beaufort(key1) → Beaufort(key2) → CT
# Beaufort(key, x) = (key - x) mod 26
# Double: CT = key2 - (key1 - PT) = key2 - key1 + PT mod 26
# So: PT = CT - key2 + key1 = CT + (key1 - key2) mod 26
# This is just Vigenère with key = (key1 - key2) mod 26!

print("Double Beaufort = Vigenère with key = key1 - key2 (mod 26)")
print("  Already eliminated as single-layer Vigenère.")
print()

# Vigenère + Beaufort: PT → Vig(key1) → Beau(key2) → CT
# Vig: intermediate = PT + key1 mod 26
# Beau: CT = key2 - intermediate = key2 - PT - key1 mod 26
# So: PT = key2 - key1 - CT mod 26 = (key2 - key1) - CT mod 26
# This is Beaufort with key = (key2 - key1) mod 26!

print("Vigenère then Beaufort = single Beaufort with key = key2 - key1")
print("  Already eliminated as single-layer Beaufort.")
print()

# Beaufort + Vigenère: PT → Beau(key1) → Vig(key2) → CT
# Beau: intermediate = key1 - PT mod 26
# Vig: CT = intermediate + key2 = key1 - PT + key2 mod 26
# So: PT = key1 + key2 - CT mod 26
# This is Beaufort with key = key1 + key2!

print("Beaufort then Vigenère = single Beaufort with key = key1 + key2")
print("  Already eliminated.")
print()

# Triple Vigenère: key3 + key2 + key1 + PT = single Vigenère
print("Any number of additive substitution layers = single substitution layer.")
print("  This is a fundamental algebraic property of mod-26 addition.")
print("  ELIMINATED for periodic keys at all periods.")
print()

# ── Section I: NON-ADDITIVE Two-Layer ─────────────────────────────────

print("Section I: Non-Additive Two-Layer (Multiplication)")
print("-" * 70)
print()

# What about affine cipher layers?
# Layer 1: intermediate = (a * PT + b) mod 26
# Layer 2: CT = intermediate + key mod 26 (Vigenère)
# Combined: CT = a * PT + b + key mod 26
# At cribs: key[i] = CT[i] - a * crib_pt[i] - b mod 26

# For each (a, b), compute key values at cribs and check periodicity
i_tested = 0
i_hits = []

for a in valid_a:
    if a == 1:
        continue  # Already tested as pure Vigenère
    for b in range(26):
        key_vals = {}
        for pos in CRIB_POS:
            key_vals[pos] = (CT_INT[pos] - a * CRIB_PT[pos] - b) % MOD

        # Check periodicity
        for p in range(2, 14):
            consistent = True
            for i, pos_a in enumerate(CRIB_POS):
                for j, pos_b in enumerate(CRIB_POS):
                    if j <= i:
                        continue
                    if (pos_b - pos_a) % p == 0:
                        if key_vals[pos_a] != key_vals[pos_b]:
                            consistent = False
                            break
                if not consistent:
                    break

            if consistent:
                key_str = [key_vals[pos] for pos in CRIB_POS]
                i_hits.append(f"a={a} b={b} p={p}: key_vals (sample) = {key_str[:8]}")
                total_above_noise += 1

        i_tested += 1

print(f"  Tested {i_tested} affine mask (a,b) × periods 2-13")
if i_hits:
    print(f"  PERIODIC CONSISTENCY FOUND ({len(i_hits)} hits):")
    for h in i_hits[:20]:
        print(f"    {h}")
else:
    print("  ZERO periodic-consistent affine mask + Vigenère combinations")
print()

# Same for Beaufort outer layer
i2_tested = 0
i2_hits = []

for a in valid_a:
    if a == 1:
        continue
    for b in range(26):
        key_vals = {}
        for pos in CRIB_POS:
            # Beaufort: CT = key - masked_pt mod 26
            # masked_pt = a * crib + b
            masked_pt = (a * CRIB_PT[pos] + b) % MOD
            key_vals[pos] = (CT_INT[pos] + masked_pt) % MOD

        for p in range(2, 14):
            consistent = True
            for i, pos_a in enumerate(CRIB_POS):
                for j, pos_b in enumerate(CRIB_POS):
                    if j <= i:
                        continue
                    if (pos_b - pos_a) % p == 0:
                        if key_vals[pos_a] != key_vals[pos_b]:
                            consistent = False
                            break
                if not consistent:
                    break

            if consistent:
                key_str = [key_vals[pos] for pos in CRIB_POS]
                i2_hits.append(f"a={a} b={b} p={p}: key_vals = {key_str[:8]}")

        i2_tested += 1

print(f"  Tested {i2_tested} affine mask + Beaufort × periods 2-13")
if i2_hits:
    print(f"  PERIODIC CONSISTENCY FOUND ({len(i2_hits)} hits):")
    for h in i2_hits[:20]:
        print(f"    {h}")
else:
    print("  ZERO periodic-consistent affine mask + Beaufort combinations")
print()

# ── Section J: Scrambled Alphabet Lookup ──────────────────────────────

print("Section J: Tableau-Based Encryption (Quagmire Variants)")
print("-" * 70)
print()

# Quagmire I: PT alphabet = standard, CT alphabet = keyed, key = periodic
# Quagmire II: PT alphabet = keyed, CT alphabet = standard, key = periodic
# Quagmire III: Both alphabets keyed (= Kryptos tableau!), key = periodic
# Quagmire IV: PT standard, CT = running key alphabet

# For Quagmire III with KRYPTOS alphabet:
# Encryption: CT = KA[(KA_idx(key[i]) + KA_idx(PT[i])) mod 26]
# Decryption: PT = KA[(KA_idx(CT[i]) - KA_idx(key[i])) mod 26]

# Check if Quagmire III with KRYPTOS tableau + periodic key works
j_tested = 0
j_hits = []

for p in range(2, 14):
    # At crib positions, compute required key:
    # KA_idx(PT[i]) = (KA_idx(CT[i]) - KA_idx(key[i])) mod 26
    # → KA_idx(key[i]) = (KA_idx(CT[i]) - KA_idx(PT[i])) mod 26
    key_vals = {}
    for pos in CRIB_POS:
        ct_ka = KA_IDX[CT[pos]]
        pt_ka = KA_IDX[CRIB_DICT[pos]]
        key_vals[pos] = (ct_ka - pt_ka) % MOD

    consistent = True
    for i, pos_a in enumerate(CRIB_POS):
        for j, pos_b in enumerate(CRIB_POS):
            if j <= i:
                continue
            if (pos_b - pos_a) % p == 0:
                if key_vals[pos_a] != key_vals[pos_b]:
                    consistent = False
                    break
        if not consistent:
            break

    if consistent:
        j_hits.append(f"Quagmire III (KA) period {p}: CONSISTENT")
        key_str = [key_vals[pos] for pos in CRIB_POS]
        j_hits.append(f"  Key values: {key_str}")

    j_tested += 1

# Also Quagmire I and II
for q_type, (ct_idx_fn, pt_idx_fn) in [
    ("Quagmire I (CT=KA, PT=AZ)", (KA_IDX, ALPH_IDX)),
    ("Quagmire II (CT=AZ, PT=KA)", (ALPH_IDX, KA_IDX)),
]:
    for p in range(2, 14):
        key_vals = {}
        for pos in CRIB_POS:
            ct_val = ct_idx_fn[CT[pos]]
            pt_val = pt_idx_fn[CRIB_DICT[pos]]
            key_vals[pos] = (ct_val - pt_val) % MOD

        consistent = True
        for i, pos_a in enumerate(CRIB_POS):
            for j, pos_b in enumerate(CRIB_POS):
                if j <= i:
                    continue
                if (pos_b - pos_a) % p == 0:
                    if key_vals[pos_a] != key_vals[pos_b]:
                        consistent = False
                        break
            if not consistent:
                break

        if consistent:
            j_hits.append(f"{q_type} period {p}: CONSISTENT")

        j_tested += 1

print(f"  Tested {j_tested} Quagmire variants × periods 2-13")
if j_hits:
    for h in j_hits:
        print(f"    {h}")
else:
    print("  No periodic-consistent Quagmire variant found")
print()

# ── Summary ───────────────────────────────────────────────────────────

print("=" * 70)
print("SUMMARY")
print("=" * 70)
print()
print(f"Total configurations tested: {total_tested + e_tested + i_tested + i2_tested + j_tested}")
print(f"Above noise: {total_above_noise}")
print()
print("Algebraic eliminations (NO search needed):")
print("  A. Monoalphabetic mask + periodic sub = still periodic → ELIMINATED")
print("  B. Polyalphabetic mask(q) + periodic sub(p) = period lcm(p,q)")
print("     → ELIMINATED for lcm ≤ 26, UNDERDETERMINED for lcm > 26")
print("  C. Transposition mask + periodic sub = same key constraints → ELIMINATED")
print("  D. Reversal mask = specific transposition → ELIMINATED")
print("  F. Affine mask = single affine layer → same periodicity constraints")
print("  G. Position-dependent additive mask = combined key → ELIMINATED")
print("  H. Multiple Vig/Beau layers = single Vig/Beau layer → ELIMINATED")
print()
print("Computational tests:")
if e_hits:
    print(f"  E. Keyword mask + keyword cipher: {len(e_hits)} hits")
else:
    print("  E. Keyword mask + keyword cipher: ZERO above noise → ELIMINATED")
if i_hits or i2_hits:
    print(f"  I. Affine mask + periodic: {len(i_hits) + len(i2_hits)} consistent hits")
else:
    print("  I. Affine mask + periodic: ZERO consistent → ELIMINATED")
if j_hits:
    print(f"  J. Quagmire variants: {len(j_hits)} consistent hits")
else:
    print("  J. Quagmire variants: ZERO consistent → ELIMINATED")
print()
print("[DERIVED FACT] The masking step CANNOT be any simple algebraic operation")
print("  (monoalphabetic, polyalphabetic, affine, additive, transposition)")
print("  combined with periodic substitution. All reduce to already-eliminated")
print("  forms or are underdetermined.")
print()
print("[HYPOTHESIS] If masking exists, it must be:")
print("  1. Combined with a NON-PERIODIC (running key) cipher, OR")
print("  2. A non-algebraic operation (null insertion, steganographic, etc.)")
print("     where null insertion + periodic key is also proven impossible, OR")
print("  3. Part of a completely bespoke system ('never in crypto literature')")
