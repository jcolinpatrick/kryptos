#!/usr/bin/env python3
"""
Morse Reflection Pool Theory — Comprehensive Test

Cipher: substitution + reflection
Family: grille
Status: active
Keyspace: ~300 configs
Last run: 2026-03-08
Best score: TBD

Theory: The Kryptos Morse code (K0), when "reflected" in the pool of water,
produces a letter substitution (each Morse pattern reverses). This reflected
text may serve as key material for K4 decryption.

Reflection mapping:
  A↔N, B↔V, D↔U, F↔L, G↔W, Q↔Y
  Self-mirror (unchanged): E, H, I, K, M, O, P, R, S, T, X
  C, J, Z → invalid (prosigns in reflected Morse)

Tests performed:
  1. Reflected K0 text as repeating Vigenere/Beaufort/VarBeau key (AZ + KA)
  2. Reflected K0 fragments as keywords
  3. Self-mirror letter extraction as key
  4. Reflection applied to K4 CT then standard decryption
  5. C-position analysis in K0
  6. Various truncations and orderings
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, N_CRIBS, NOISE_FLOOR, ALPH, KRYPTOS_ALPHABET
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.scoring.free_crib import score_free

# ── Morse Reflection Substitution ──────────────────────────────────────────

# Forward → Reflected pairs (bidirectional swaps)
REFLECTION_PAIRS = {
    'A': 'N', 'N': 'A',
    'B': 'V', 'V': 'B',
    'D': 'U', 'U': 'D',
    'F': 'L', 'L': 'F',
    'G': 'W', 'W': 'G',
    'Q': 'Y', 'Y': 'Q',
}

# Self-mirror letters (unchanged by reflection)
SELF_MIRROR = set('EHIKMOPRSTX')

# Invalid reflections (C, J, Z produce Morse prosigns)
INVALID_REFLECT = set('CJZ')

def reflect_letter(ch: str) -> str:
    """Apply Morse reflection substitution to a single letter."""
    ch = ch.upper()
    if ch in REFLECTION_PAIRS:
        return REFLECTION_PAIRS[ch]
    elif ch in SELF_MIRROR:
        return ch
    elif ch in INVALID_REFLECT:
        return None  # No valid reflection
    return None

def reflect_text(text: str, skip_invalid=True) -> str:
    """Apply reflection substitution to text. If skip_invalid, drops C/J/Z."""
    result = []
    for ch in text.upper():
        if not ch.isalpha():
            continue
        r = reflect_letter(ch)
        if r is not None:
            result.append(r)
        elif not skip_invalid:
            result.append(ch)  # Keep original if not skipping
    return ''.join(result)

def reflect_and_reverse(text: str, skip_invalid=True) -> str:
    """True water reflection: reverse order + reflect each letter."""
    reflected = reflect_text(text, skip_invalid)
    return reflected[::-1]

# ── K0 Text Variants ──────────────────────────────────────────────────────

# Full K0 decoded text (with E-padding)
K0_FULL_WITH_E = "VIRTUALLYINVISIBLEDIGETALINTERPRETATIUESHADOWFORCESLUCIDMEMORYTISYOURPOSITIONSOSRQE"
# Without trailing E
K0_FULL_NO_E = "VIRTUALLYINVISIBLEDIGETALINTERPRETATIUESHADOWFORCESLUCIDMEMORYTISYOURPOSITIONSOSRQ"
# Stripped spaces version (from user)
K0_STRIPPED = "VIRTUALLYINVISIBLEDIGETALINTERPRETATIUSHADOWFORCESLUCIDMEMORYTISYOURPOSITIONSOSRQ"

# Individual K0 phrases
K0_PHRASES = {
    'VIRTUALLY_INVISIBLE': 'VIRTUALLYINVISIBLE',
    'DIGETAL_INTERPRETATIU': 'DIGETALINTERPRETATIU',
    'SHADOW_FORCES': 'SHADOWFORCES',
    'LUCID_MEMORY': 'LUCIDMEMORY',
    'T_IS_YOUR_POSITION': 'TISYOURPOSITION',
    'SOS': 'SOS',
    'RQ': 'RQ',
}

# Key K0 words for keyword testing
K0_KEYWORDS = [
    'VIRTUALLY', 'INVISIBLE', 'DIGETAL', 'INTERPRETATIU',
    'SHADOW', 'FORCES', 'LUCID', 'MEMORY', 'POSITION',
    'SHADOWFORCES', 'LUCIDMEMORY',
]

# ── Cipher Operations ─────────────────────────────────────────────────────

def make_index_table(alphabet: str) -> dict:
    """Create char->index mapping for an alphabet."""
    return {ch: i for i, ch in enumerate(alphabet)}

def vigenere_decrypt(ct: str, key: str, alphabet: str = ALPH) -> str:
    """Vigenere decryption: PT[i] = (CT[i] - KEY[i]) mod 26 in given alphabet."""
    idx = make_index_table(alphabet)
    mod = len(alphabet)
    result = []
    for i, c in enumerate(ct):
        k = key[i % len(key)]
        if c not in idx or k not in idx:
            result.append(c)
            continue
        pt_idx = (idx[c] - idx[k]) % mod
        result.append(alphabet[pt_idx])
    return ''.join(result)

def beaufort_decrypt(ct: str, key: str, alphabet: str = ALPH) -> str:
    """Beaufort decryption: PT[i] = (KEY[i] - CT[i]) mod 26 in given alphabet."""
    idx = make_index_table(alphabet)
    mod = len(alphabet)
    result = []
    for i, c in enumerate(ct):
        k = key[i % len(key)]
        if c not in idx or k not in idx:
            result.append(c)
            continue
        pt_idx = (idx[k] - idx[c]) % mod
        result.append(alphabet[pt_idx])
    return ''.join(result)

def variant_beaufort_decrypt(ct: str, key: str, alphabet: str = ALPH) -> str:
    """Variant Beaufort: PT[i] = (CT[i] + KEY[i]) mod 26 — same as Vig encrypt."""
    idx = make_index_table(alphabet)
    mod = len(alphabet)
    result = []
    for i, c in enumerate(ct):
        k = key[i % len(key)]
        if c not in idx or k not in idx:
            result.append(c)
            continue
        pt_idx = (idx[c] + idx[k]) % mod
        result.append(alphabet[pt_idx])
    return ''.join(result)

CIPHER_FUNCS = {
    'Vigenere': vigenere_decrypt,
    'Beaufort': beaufort_decrypt,
    'VarBeau': variant_beaufort_decrypt,
}

ALPHABETS = {
    'AZ': ALPH,
    'KA': KRYPTOS_ALPHABET,
}

# ── Scoring ────────────────────────────────────────────────────────────────

def score_pt(pt: str) -> dict:
    """Score a plaintext candidate. Returns dict with score and details."""
    if len(pt) < CT_LEN:
        return {'score': 0, 'ene': 0, 'bc': 0, 'classification': 'noise'}
    detail = score_cribs_detailed(pt)
    return {
        'score': detail['score'],
        'ene': detail['ene_score'],
        'bc': detail['bc_score'],
        'classification': detail['classification'],
    }

def score_pt_free(pt: str) -> dict:
    """Score using position-free crib matching."""
    fcr = score_free(pt.upper())
    return {
        'score': fcr.score,
        'ene_found': fcr.ene_found,
        'bc_found': fcr.bc_found,
    }

# ── Main Test Runner ───────────────────────────────────────────────────────

def main():
    config_count = 0
    above_noise = []
    best_score = 0
    best_config = None
    best_pt = None

    def test_config(desc: str, pt: str, free=False):
        nonlocal config_count, best_score, best_config, best_pt
        config_count += 1

        # Anchored scoring
        s = score_pt(pt)
        score = s['score']

        # Also do free scoring
        fs = score_pt_free(pt)

        effective_score = max(score, fs['score'])

        if effective_score > best_score:
            best_score = effective_score
            best_config = desc
            best_pt = pt

        if score > NOISE_FLOOR:
            above_noise.append((score, desc, pt[:60]))
            print(f"  *** ABOVE NOISE: {desc}")
            print(f"      Anchored: {score}/24 (ENE={s['ene']}/13, BC={s['bc']}/11)")
            print(f"      PT: {pt[:80]}...")

        if fs['score'] > NOISE_FLOOR:
            if score <= NOISE_FLOOR:  # Don't double-print
                above_noise.append((fs['score'], f"{desc} [FREE]", pt[:60]))
                print(f"  *** FREE ABOVE NOISE: {desc}")
                print(f"      Free: {fs['score']}/24 (ENE={'YES' if fs['ene_found'] else 'no'}, BC={'YES' if fs['bc_found'] else 'no'})")
                print(f"      PT: {pt[:80]}...")

    # ═══════════════════════════════════════════════════════════════════════
    # SECTION 1: Display the reflection mapping
    # ═══════════════════════════════════════════════════════════════════════
    print("=" * 80)
    print("MORSE REFLECTION POOL THEORY — COMPREHENSIVE TEST")
    print("=" * 80)

    print("\n── Reflection Substitution Table ──")
    print("Swaps: A↔N, B↔V, D↔U, F↔L, G↔W, Q↔Y")
    print("Self-mirror: E H I K M O P R S T X")
    print("Invalid (prosigns): C J Z")

    print("\n── Full Reflection as Substitution Cipher ──")
    for letter in ALPH:
        r = reflect_letter(letter)
        status = "SELF" if letter in SELF_MIRROR else ("INVALID" if r is None else f"→ {r}")
        print(f"  {letter} : {status}")

    # ═══════════════════════════════════════════════════════════════════════
    # SECTION 2: K0 Text Reflections
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SECTION 1: K0 TEXT REFLECTIONS")
    print("=" * 80)

    k0_variants = {
        'K0_FULL_WITH_E': K0_FULL_WITH_E,
        'K0_FULL_NO_E': K0_FULL_NO_E,
        'K0_STRIPPED': K0_STRIPPED,
    }

    for name, text in k0_variants.items():
        print(f"\n  {name} ({len(text)} chars):")
        print(f"    Original:   {text}")

        # Substitution only (skip invalid)
        refl_sub = reflect_text(text, skip_invalid=True)
        print(f"    Refl(skip):  {refl_sub} ({len(refl_sub)} chars)")

        # Substitution only (keep invalid as-is)
        refl_keep = reflect_text(text, skip_invalid=False)
        print(f"    Refl(keep):  {refl_keep} ({len(refl_keep)} chars)")

        # True reflection (reverse + substitute)
        true_refl = reflect_and_reverse(text, skip_invalid=True)
        print(f"    TrueRefl:    {true_refl} ({len(true_refl)} chars)")

    # Show reflected phrases
    print("\n── Reflected Phrases ──")
    for name, phrase in K0_PHRASES.items():
        refl = reflect_text(phrase, skip_invalid=True)
        rev_refl = reflect_and_reverse(phrase, skip_invalid=True)
        print(f"  {name}: {phrase}")
        print(f"    Sub only:   {refl}")
        print(f"    Rev+Sub:    {rev_refl}")

    # ═══════════════════════════════════════════════════════════════════════
    # SECTION 3: Reflected K0 as repeating key for K4
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SECTION 2: REFLECTED K0 AS REPEATING KEY FOR K4")
    print("=" * 80)

    # Build all key variants
    key_variants = {}
    for name, text in k0_variants.items():
        key_variants[f"{name}_sub_skip"] = reflect_text(text, skip_invalid=True)
        key_variants[f"{name}_sub_keep"] = reflect_text(text, skip_invalid=False)
        key_variants[f"{name}_rev_skip"] = reflect_and_reverse(text, skip_invalid=True)
        key_variants[f"{name}_rev_keep"] = reflect_and_reverse(text, skip_invalid=False)
        # Also original (unreflected) as control
        key_variants[f"{name}_original"] = text

    print(f"\n  Testing {len(key_variants)} key variants x 3 ciphers x 2 alphabets = {len(key_variants)*6} configs")

    for kv_name, key in key_variants.items():
        if len(key) == 0:
            continue
        for cipher_name, cipher_func in CIPHER_FUNCS.items():
            for alph_name, alphabet in ALPHABETS.items():
                pt = cipher_func(CT, key, alphabet)
                desc = f"K0key: {kv_name} | {cipher_name} | {alph_name}"
                test_config(desc, pt)

    # ═══════════════════════════════════════════════════════════════════════
    # SECTION 4: Reflected K0 fragments as keywords
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SECTION 3: REFLECTED K0 FRAGMENTS AS KEYWORDS")
    print("=" * 80)

    fragment_keys = []
    for word in K0_KEYWORDS:
        # Substitution only
        refl = reflect_text(word, skip_invalid=True)
        if refl and len(refl) >= 3:
            fragment_keys.append((f"Refl({word})", refl))
        # Reversed + substitution
        rev_refl = reflect_and_reverse(word, skip_invalid=True)
        if rev_refl and len(rev_refl) >= 3:
            fragment_keys.append((f"RevRefl({word})", rev_refl))
        # Keep invalid
        refl_keep = reflect_text(word, skip_invalid=False)
        if refl_keep and len(refl_keep) >= 3:
            fragment_keys.append((f"ReflKeep({word})", refl_keep))

    # Also test specific reflected words mentioned in task
    fragment_keys.extend([
        ("BIRTDNFFQ", "BIRTDNFFQ"),   # VIRTUALLY reflected (sub)
        ("QFFNDTRIB", "QFFNDTRIB"),   # VIRTUALLY rev+sub  (note: corrected)
        ("SHNUOW", "SHNUOW"),         # SHADOW sub
        ("WOUNHS", "WOUNHS"),         # SHADOW rev+sub
        ("MEMORQ", "MEMORQ"),         # MEMORY sub
        ("POSITIOA", "POSITIOA"),     # POSITION sub
    ])

    # Deduplicate
    seen_keys = set()
    unique_fragment_keys = []
    for name, key in fragment_keys:
        if key not in seen_keys:
            seen_keys.add(key)
            unique_fragment_keys.append((name, key))

    print(f"\n  Testing {len(unique_fragment_keys)} fragment keywords x 3 ciphers x 2 alphabets = {len(unique_fragment_keys)*6} configs")

    for fk_name, key in unique_fragment_keys:
        for cipher_name, cipher_func in CIPHER_FUNCS.items():
            for alph_name, alphabet in ALPHABETS.items():
                pt = cipher_func(CT, key, alphabet)
                desc = f"Fragment: {fk_name}={key} | {cipher_name} | {alph_name}"
                test_config(desc, pt)

    # ═══════════════════════════════════════════════════════════════════════
    # SECTION 5: Self-mirror letters as filter
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SECTION 4: SELF-MIRROR LETTER FILTER")
    print("=" * 80)

    for name, text in k0_variants.items():
        # Extract only self-mirror letters
        mirror_only = ''.join(ch for ch in text if ch in SELF_MIRROR)
        # Extract only swappable letters
        swap_only = ''.join(ch for ch in text if ch in REFLECTION_PAIRS)
        # Extract only invalid letters (C, J, Z)
        invalid_only = ''.join(ch for ch in text if ch in INVALID_REFLECT)

        print(f"\n  {name}:")
        print(f"    Self-mirror extract: {mirror_only} ({len(mirror_only)} chars)")
        print(f"    Swappable extract:   {swap_only} ({len(swap_only)} chars)")
        print(f"    Invalid extract:     {invalid_only} ({len(invalid_only)} chars)")

        # Test mirror-only as key
        if mirror_only:
            for cipher_name, cipher_func in CIPHER_FUNCS.items():
                for alph_name, alphabet in ALPHABETS.items():
                    pt = cipher_func(CT, mirror_only, alphabet)
                    desc = f"MirrorOnly({name}) | {cipher_name} | {alph_name}"
                    test_config(desc, pt)

        # Test swap-only as key
        if swap_only:
            for cipher_name, cipher_func in CIPHER_FUNCS.items():
                for alph_name, alphabet in ALPHABETS.items():
                    pt = cipher_func(CT, swap_only, alphabet)
                    desc = f"SwapOnly({name}) | {cipher_name} | {alph_name}"
                    test_config(desc, pt)

        # Test reflected swap letters as key
        if swap_only:
            refl_swap = reflect_text(swap_only)
            for cipher_name, cipher_func in CIPHER_FUNCS.items():
                for alph_name, alphabet in ALPHABETS.items():
                    pt = cipher_func(CT, refl_swap, alphabet)
                    desc = f"ReflSwap({name}) | {cipher_name} | {alph_name}"
                    test_config(desc, pt)

    # ═══════════════════════════════════════════════════════════════════════
    # SECTION 6: Reflection applied to K4 itself
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SECTION 5: REFLECTION APPLIED TO K4 CIPHERTEXT")
    print("=" * 80)

    # Reflect the K4 CT, then decrypt with known keywords
    ct_reflected = reflect_text(CT, skip_invalid=False)
    ct_reflected_skip = reflect_text(CT, skip_invalid=True)
    ct_reversed_reflected = reflect_and_reverse(CT, skip_invalid=False)

    print(f"\n  K4 CT:                  {CT}")
    print(f"  K4 CT reflected (keep): {ct_reflected} ({len(ct_reflected)} chars)")
    print(f"  K4 CT reflected (skip): {ct_reflected_skip} ({len(ct_reflected_skip)} chars)")
    print(f"  K4 CT rev+reflected:    {ct_reversed_reflected} ({len(ct_reversed_reflected)} chars)")

    standard_keywords = [
        'KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'HOROLOGE',
        'DEFECTOR', 'PARALLAX', 'COLOPHON', 'ENIGMA', 'LODESTONE',
        'COMPASS', 'BERLIN', 'CLOCK', 'SPHINX', 'PHARAOH',
        'FIVE', 'POINT', 'VIRTUALLY', 'INVISIBLE', 'MEMORY',
        'POSITION', 'NORTHEAST', 'EASTNORTHEAST',
    ]

    ct_forms = {
        'CT_refl_keep': ct_reflected,
        'CT_refl_skip': ct_reflected_skip,
        'CT_rev_refl': ct_reversed_reflected,
    }

    for ct_name, ct_form in ct_forms.items():
        if len(ct_form) < 97:
            # Pad to ensure we can score (positions up to 73)
            if len(ct_form) < 74:
                print(f"  SKIPPING {ct_name}: too short ({len(ct_form)} chars) for crib scoring")
                continue
        for kw in standard_keywords:
            for cipher_name, cipher_func in CIPHER_FUNCS.items():
                for alph_name, alphabet in ALPHABETS.items():
                    pt = cipher_func(ct_form, kw, alphabet)
                    desc = f"ReflCT: {ct_name} + {kw} | {cipher_name} | {alph_name}"
                    test_config(desc, pt)

    # Also try: reflect CT, then use reflected keywords
    reflected_keywords = []
    for kw in standard_keywords:
        rkw = reflect_text(kw, skip_invalid=True)
        if rkw and len(rkw) >= 3:
            reflected_keywords.append((f"Refl({kw})", rkw))

    for ct_name, ct_form in ct_forms.items():
        if len(ct_form) < 74:
            continue
        for rkw_name, rkw in reflected_keywords:
            for cipher_name, cipher_func in CIPHER_FUNCS.items():
                for alph_name, alphabet in ALPHABETS.items():
                    pt = cipher_func(ct_form, rkw, alphabet)
                    desc = f"DoubleRefl: {ct_name} + {rkw_name}={rkw} | {cipher_name} | {alph_name}"
                    test_config(desc, pt)

    # ═══════════════════════════════════════════════════════════════════════
    # SECTION 7: C-position analysis
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SECTION 6: C-POSITION ANALYSIS IN K0")
    print("=" * 80)

    for name, text in k0_variants.items():
        c_positions = [i for i, ch in enumerate(text) if ch == 'C']
        print(f"\n  {name}:")
        print(f"    C positions: {c_positions}")
        print(f"    Text at C positions: {[text[i] for i in c_positions]}")

        if c_positions:
            first_c = c_positions[0]
            print(f"    First C at position {first_c}")
            print(f"    Text up to first C: {text[:first_c]}")

            # Use text up to first C as key
            truncated = text[:first_c]
            if len(truncated) >= 3:
                for cipher_name, cipher_func in CIPHER_FUNCS.items():
                    for alph_name, alphabet in ALPHABETS.items():
                        pt = cipher_func(CT, truncated, alphabet)
                        desc = f"TruncAtC({name}): '{truncated}' | {cipher_name} | {alph_name}"
                        test_config(desc, pt)

                # Also reflected truncated
                refl_trunc = reflect_text(truncated, skip_invalid=True)
                if refl_trunc and len(refl_trunc) >= 3:
                    for cipher_name, cipher_func in CIPHER_FUNCS.items():
                        for alph_name, alphabet in ALPHABETS.items():
                            pt = cipher_func(CT, refl_trunc, alphabet)
                            desc = f"ReflTruncAtC({name}): '{refl_trunc}' | {cipher_name} | {alph_name}"
                            test_config(desc, pt)

            # Text between C's
            if len(c_positions) >= 2:
                between_cs = text[c_positions[0]+1:c_positions[1]]
                print(f"    Between first two C's: {between_cs}")
                if len(between_cs) >= 3:
                    for cipher_name, cipher_func in CIPHER_FUNCS.items():
                        for alph_name, alphabet in ALPHABETS.items():
                            pt = cipher_func(CT, between_cs, alphabet)
                            desc = f"BetweenC({name}): '{between_cs}' | {cipher_name} | {alph_name}"
                            test_config(desc, pt)

        # C positions in K4 mapping
        print(f"\n    C positions mapped to K4:")
        for cp in c_positions:
            if cp < CT_LEN:
                print(f"      K0[{cp}] = C → K4[{cp}] = {CT[cp]}")
                if cp in CRIB_DICT:
                    print(f"        (crib position: expected {CRIB_DICT[cp]})")

    # ═══════════════════════════════════════════════════════════════════════
    # SECTION 8: Reflection as alphabet permutation for cipher
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SECTION 7: REFLECTION AS CIPHER ALPHABET")
    print("=" * 80)

    # The reflection defines a partial substitution cipher.
    # Build the reflected alphabet (where C→C, J→J, Z→Z as identity for now)
    reflected_alph = ''
    for ch in ALPH:
        r = reflect_letter(ch)
        if r is None:
            reflected_alph += ch  # Keep as-is for invalid
        else:
            reflected_alph += r
    print(f"  Standard:  {ALPH}")
    print(f"  Reflected: {reflected_alph}")
    print(f"  (Reflection is an involution: applying twice = identity)")

    # Apply reflection substitution to CT, then try standard decryptions
    ct_subst = ''.join(reflected_alph[ALPH.index(c)] for c in CT)
    print(f"\n  K4 CT after reflection substitution: {ct_subst}")

    for kw in standard_keywords:
        for cipher_name, cipher_func in CIPHER_FUNCS.items():
            for alph_name, alphabet in ALPHABETS.items():
                pt = cipher_func(ct_subst, kw, alphabet)
                desc = f"ReflSubst + {kw} | {cipher_name} | {alph_name}"
                test_config(desc, pt)

    # ═══════════════════════════════════════════════════════════════════════
    # SECTION 9: Combining reflection + known K4 approaches
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SECTION 8: COMBINATION APPROACHES")
    print("=" * 80)

    # Test: What if reflection is applied to BOTH key and CT?
    print("\n  Testing reflection on both CT and key...")
    for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA', 'SHADOW', 'HOROLOGE',
               'DEFECTOR', 'PARALLAX', 'COLOPHON']:
        rkw = reflect_text(kw, skip_invalid=False)
        for cipher_name, cipher_func in CIPHER_FUNCS.items():
            for alph_name, alphabet in ALPHABETS.items():
                pt = cipher_func(ct_subst, rkw, alphabet)
                desc = f"BothRefl: CT+{kw}→{rkw} | {cipher_name} | {alph_name}"
                test_config(desc, pt)

    # Test: reflected K0 as a running key
    print("\n  Testing reflected K0 as running key (one-time pad style)...")
    for name, text in k0_variants.items():
        refl = reflect_text(text, skip_invalid=True)
        if len(refl) >= CT_LEN:
            # Running key: use first 97 chars
            running_key = refl[:CT_LEN]
            for cipher_name, cipher_func in CIPHER_FUNCS.items():
                for alph_name, alphabet in ALPHABETS.items():
                    pt = cipher_func(CT, running_key, alphabet)
                    desc = f"RunningKey: Refl({name}) | {cipher_name} | {alph_name}"
                    test_config(desc, pt)

        # Also reversed
        rev_refl = reflect_and_reverse(text, skip_invalid=True)
        if len(rev_refl) >= CT_LEN:
            running_key = rev_refl[:CT_LEN]
            for cipher_name, cipher_func in CIPHER_FUNCS.items():
                for alph_name, alphabet in ALPHABETS.items():
                    pt = cipher_func(CT, running_key, alphabet)
                    desc = f"RunningKey: RevRefl({name}) | {cipher_name} | {alph_name}"
                    test_config(desc, pt)

    # Test: K0 letter positions as transposition indices
    print("\n  Testing K0 reflection as transposition guide...")
    # Which K0 positions are self-mirror vs swappable?
    for name, text in [('K0_STRIPPED', K0_STRIPPED)]:
        mirror_mask = [1 if ch in SELF_MIRROR else 0 for ch in text[:CT_LEN]]
        mirror_positions = [i for i, m in enumerate(mirror_mask) if m == 1]
        swap_positions = [i for i, m in enumerate(mirror_mask) if m == 0]
        print(f"\n  {name} mask (1=self-mirror, 0=swap):")
        print(f"    Mirror positions ({len(mirror_positions)}): {mirror_positions[:30]}...")
        print(f"    Swap positions ({len(swap_positions)}): {swap_positions[:30]}...")

        # Read K4 at mirror positions, then at swap positions
        if len(text) >= CT_LEN:
            mirror_chars = ''.join(CT[i] for i in mirror_positions if i < CT_LEN)
            swap_chars = ''.join(CT[i] for i in swap_positions if i < CT_LEN)
            reordered = mirror_chars + swap_chars
            print(f"    K4 at mirror pos: {mirror_chars}")
            print(f"    K4 at swap pos:   {swap_chars}")
            print(f"    Reordered (mirror first): {reordered}")

            # Try decrypting the reordered text
            for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA']:
                for cipher_name, cipher_func in CIPHER_FUNCS.items():
                    pt = cipher_func(reordered, kw, ALPH)
                    desc = f"Reorder(mirror-first) + {kw} | {cipher_name} | AZ"
                    test_config(desc, pt)

    # ═══════════════════════════════════════════════════════════════════════
    # SECTION 10: Reflection + Grille extract
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SECTION 9: REFLECTION + GRILLE EXTRACT")
    print("=" * 80)

    GRILLE_EXTRACT = "HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD"

    # Reflect the grille extract
    grille_reflected = reflect_text(GRILLE_EXTRACT, skip_invalid=False)
    grille_reflected_skip = reflect_text(GRILLE_EXTRACT, skip_invalid=True)

    print(f"  Grille extract:        {GRILLE_EXTRACT} ({len(GRILLE_EXTRACT)} chars)")
    print(f"  Reflected (keep):      {grille_reflected} ({len(grille_reflected)} chars)")
    print(f"  Reflected (skip):      {grille_reflected_skip} ({len(grille_reflected_skip)} chars)")

    # Use reflected grille as key
    for grille_name, grille_key in [('GrilleRefl', grille_reflected), ('GrilleReflSkip', grille_reflected_skip)]:
        if len(grille_key) >= CT_LEN:
            key97 = grille_key[:CT_LEN]
            for cipher_name, cipher_func in CIPHER_FUNCS.items():
                for alph_name, alphabet in ALPHABETS.items():
                    pt = cipher_func(CT, key97, alphabet)
                    desc = f"{grille_name} as key | {cipher_name} | {alph_name}"
                    test_config(desc, pt)

    # Use grille as permutation on reflected CT
    if len(GRILLE_EXTRACT) >= CT_LEN:
        # Interpret grille letters as permutation indices
        for alph_name, alphabet in ALPHABETS.items():
            idx_table = make_index_table(alphabet)
            perm = [idx_table[ch] % CT_LEN for ch in GRILLE_EXTRACT[:CT_LEN]]

            # Check if this is a valid permutation (may not be)
            if len(set(perm)) == CT_LEN:
                permuted_ct = ''.join(ct_reflected[perm[i]] if perm[i] < len(ct_reflected) else '?' for i in range(CT_LEN))
                for kw in ['KRYPTOS', 'PALIMPSEST', 'ABSCISSA']:
                    for cipher_name, cipher_func in CIPHER_FUNCS.items():
                        pt = cipher_func(permuted_ct, kw, ALPH)
                        desc = f"GrillePerm({alph_name})+ReflCT + {kw} | {cipher_name}"
                        test_config(desc, pt)

    # ═══════════════════════════════════════════════════════════════════════
    # SECTION 11: Reflection as K4 alphabet (substitution cipher itself)
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SECTION 10: REFLECTION SUBSTITUTION ON K4 + STANDARD DECRYPT")
    print("=" * 80)

    # What if the "simple substitution" layer in the paradigm IS the Morse reflection?
    # PT → Morse reflection → real CT → scramble → carved text
    # Then: unscramble(carved) → real CT → inverse of Morse reflection → PT
    # Since reflection is an involution, inverse = reflection itself

    # Apply reflection to CT (already done as ct_subst), try decrypting
    # Already tested in Section 7, but let's also try with reflected alphabets

    # Build a reflected KA alphabet
    ka_reflected = ''.join(reflect_letter(ch) or ch for ch in KRYPTOS_ALPHABET)
    print(f"  KA reflected: {ka_reflected}")

    # Test using reflected alphabet as cipher alphabet
    for kw in standard_keywords[:10]:  # Top 10
        for cipher_name, cipher_func in CIPHER_FUNCS.items():
            # Use reflected KA as the alphabet
            try:
                pt = cipher_func(CT, kw, ka_reflected)
                desc = f"ReflKA + {kw} | {cipher_name}"
                test_config(desc, pt)
            except Exception:
                pass  # May fail if reflected alphabet has issues

    # ═══════════════════════════════════════════════════════════════════════
    # SECTION 12: Additional creative combinations
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SECTION 11: ADDITIONAL CREATIVE COMBINATIONS")
    print("=" * 80)

    # Test: XOR-like combination of K0 reflection with K4
    # (Modular addition/subtraction of reflected K0 positions with K4 positions)
    print("\n  Modular arithmetic: reflected K0 + K4 positions...")
    for name, text in [('K0_STRIPPED', K0_STRIPPED)]:
        refl = reflect_text(text, skip_invalid=False)
        if len(refl) >= CT_LEN:
            # PT[i] = (CT[i] + reflK0[i]) mod 26
            pt_add = ''
            pt_sub = ''
            for i in range(CT_LEN):
                c_idx = ALPH.index(CT[i])
                k_idx = ALPH.index(refl[i % len(refl)])
                pt_add += ALPH[(c_idx + k_idx) % 26]
                pt_sub += ALPH[(c_idx - k_idx) % 26]

            test_config(f"ModAdd: CT + ReflK0 | AZ", pt_add)
            test_config(f"ModSub: CT - ReflK0 | AZ", pt_sub)

    # Test: Reflection as autokey seed
    print("\n  Testing reflected K0 first letters as autokey primers...")
    for primer_len in [1, 3, 5, 7, 10, 13]:
        for name, text in [('K0_STRIPPED', K0_STRIPPED)]:
            refl = reflect_text(text, skip_invalid=False)
            primer = refl[:primer_len]

            # Autokey Vigenere: key = primer + plaintext
            for alph_name, alphabet in ALPHABETS.items():
                idx = make_index_table(alphabet)
                mod = len(alphabet)
                pt_chars = []
                key_stream = list(primer)
                for i in range(CT_LEN):
                    k = key_stream[i] if i < len(key_stream) else pt_chars[i - primer_len]
                    pt_idx = (idx[CT[i]] - idx[k]) % mod
                    pt_ch = alphabet[pt_idx]
                    pt_chars.append(pt_ch)
                    if i >= primer_len - 1 and len(key_stream) <= i + 1:
                        key_stream.append(pt_ch)

                pt = ''.join(pt_chars)
                desc = f"Autokey(primer={primer_len}): ReflK0 | Vig | {alph_name}"
                test_config(desc, pt)

                # Beaufort autokey
                pt_chars2 = []
                key_stream2 = list(primer)
                for i in range(CT_LEN):
                    k = key_stream2[i] if i < len(key_stream2) else pt_chars2[i - primer_len]
                    pt_idx = (idx[k] - idx[CT[i]]) % mod
                    pt_ch = alphabet[pt_idx]
                    pt_chars2.append(pt_ch)
                    if i >= primer_len - 1 and len(key_stream2) <= i + 1:
                        key_stream2.append(pt_ch)

                pt2 = ''.join(pt_chars2)
                desc = f"Autokey(primer={primer_len}): ReflK0 | Beau | {alph_name}"
                test_config(desc, pt2)

    # ═══════════════════════════════════════════════════════════════════════
    # SECTION 13: Mirror letters from K0 as positional markers in K4
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("SECTION 12: MIRROR/SWAP POSITIONAL ANALYSIS")
    print("=" * 80)

    # For each K0 variant, look at which K4 positions correspond to mirror vs swap letters
    for name, text in [('K0_STRIPPED', K0_STRIPPED)]:
        if len(text) < CT_LEN:
            print(f"  {name} too short for full mapping")
            continue

        mirror_pos = [i for i in range(CT_LEN) if text[i] in SELF_MIRROR]
        swap_pos = [i for i in range(CT_LEN) if text[i] in REFLECTION_PAIRS]
        invalid_pos = [i for i in range(CT_LEN) if text[i] in INVALID_REFLECT]

        print(f"\n  {name} K4 position analysis:")
        print(f"    Mirror letter positions ({len(mirror_pos)}): {mirror_pos}")
        print(f"    Swap letter positions ({len(swap_pos)}): {swap_pos}")
        print(f"    Invalid letter positions ({len(invalid_pos)}): {invalid_pos}")

        # Check which crib positions fall on mirror vs swap vs invalid
        for pos in sorted(CRIB_DICT.keys()):
            if pos < len(text):
                k0_ch = text[pos]
                k4_ch = CT[pos]
                crib_ch = CRIB_DICT[pos]
                mirror_status = "MIRROR" if k0_ch in SELF_MIRROR else ("SWAP" if k0_ch in REFLECTION_PAIRS else "INVALID")
                print(f"      Crib pos {pos}: K0='{k0_ch}'({mirror_status}) K4='{k4_ch}' expect='{crib_ch}'")

    # ═══════════════════════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ═══════════════════════════════════════════════════════════════════════
    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)

    print(f"\n  Total configurations tested: {config_count}")
    print(f"  Best score: {best_score}/24")
    if best_config:
        print(f"  Best config: {best_config}")
        if best_pt:
            print(f"  Best PT: {best_pt[:97]}")

    if above_noise:
        print(f"\n  Results above noise floor (>{NOISE_FLOOR}):")
        above_noise.sort(key=lambda x: -x[0])
        for score, desc, pt_preview in above_noise:
            print(f"    Score {score}/24: {desc}")
            print(f"      PT: {pt_preview}")
    else:
        print(f"\n  No results above noise floor (>{NOISE_FLOOR})")

    print(f"\n  REFLECTION SUBSTITUTION TABLE (for reference):")
    print(f"    A↔N  B↔V  D↔U  F↔L  G↔W  Q↔Y")
    print(f"    Self: E H I K M O P R S T X")
    print(f"    Invalid: C J Z")

    return config_count, best_score, above_noise


if __name__ == '__main__':
    main()
