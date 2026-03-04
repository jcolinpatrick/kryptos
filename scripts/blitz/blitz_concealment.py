#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""blitz_concealment.py — Test concealment/stego pre-processing models for K4.

Scheidt: "I masked the English language so it's more of a challenge"
Scheidt: "frequency analysis will NOT help with K4"
Scheidt: "a little bit of concealment/stego"
NOVA narrator: "techniques like removing all the vowels first, or spelling
               the message phonetically"
Sanborn did this BY HAND on a yellow legal pad.

Models tested:
  1. Null cipher — every Nth char is a null (discard before decryption)
  2. Vowel removal/reinsertion — encrypted text with vowels stripped
  3. Phonetic respelling effects on crib matching
  4. Concealment = transposition layer itself (naming the scramble)
  5. Keys hidden in Morse code phrases from the sculpture
  6. Selective letter masking (replace vowels with fixed letter pre-encryption)
  7. Reversal + concealment combos
  8. Double-keyword Vigenère with Morse-derived keys
  9. Interleaved null patterns (structured null insertion)
  10. Consonant-only encryption with vowel reinsertion

Run: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/blitz_concealment.py
"""
from __future__ import annotations

import sys
import os
import time
import itertools
from collections import Counter, defaultdict

sys.path.insert(0, "scripts")
from kbot_harness import (
    test_perm, test_unscramble, score_text, score_text_per_char,
    has_cribs, vig_decrypt, vig_encrypt, beau_decrypt,
    apply_permutation, load_quadgrams,
    K4_CARVED, AZ, KA, KEYWORDS, CRIBS,
)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
N = 97
VOWELS = set("AEIOU")
CONSONANTS = set(AZ) - VOWELS

# Morse code phrases from Kryptos sculpture (between granite slabs)
MORSE_PHRASES = [
    "TISYOURPOSITION",
    "VIRTUALLYINVISIBLE",
    "SHADOWFORCES",
    "LUCIDMEMORY",
    "DIGITALINTERPRETATION",
    "SOS",
    # Substrings and combos
    "SHADOW",
    "FORCES",
    "LUCID",
    "MEMORY",
    "POSITION",
    "INVISIBLE",
    "VIRTUAL",
    "DIGITAL",
    "INTERPRET",
]

# Additional thematic keywords to test as Morse-derived keys
MORSE_KEYWORDS = [
    "TISYOURPOSITION",
    "TYOURPOSITION",
    "TYPOSITION",
    "TPOSITION",
    "SHADOWFORCES",
    "LUCIDMEMORY",
    "VIRTUALLYINVISIBLE",
    "TINVISIBLE",
    "TSHADOW",
    "TLUCID",
    "TDIGITAL",
]

# Known cribs
CRIB_ENE = "EASTNORTHEAST"
CRIB_BC = "BERLINCLOCK"

BEST_SCORE = -999.0
BEST_RESULT = None
ALERT_THRESHOLD = -5.5  # per char — report anything above this

def update_best(label, pt, score_pc, extra=""):
    global BEST_SCORE, BEST_RESULT
    if score_pc > BEST_SCORE:
        BEST_SCORE = score_pc
        BEST_RESULT = (label, pt, score_pc, extra)
    if score_pc > ALERT_THRESHOLD:
        print(f"\n{'='*70}")
        print(f"*** ALERT *** Score {score_pc:.3f}/char from {label}")
        print(f"  PT: {pt}")
        print(f"  {extra}")
        print(f"{'='*70}\n")


def check_cribs_anywhere(pt):
    """Return list of (crib, pos) for any crib found in pt."""
    hits = []
    for crib in [CRIB_ENE, CRIB_BC]:
        idx = pt.find(crib)
        if idx >= 0:
            hits.append((crib, idx))
    return hits


def try_decrypt(ct_str, key, label_prefix):
    """Try Vig and Beaufort with AZ and KA, track best."""
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
            try:
                pt = cipher_fn(ct_str, key, alpha)
            except (ValueError, IndexError):
                continue
            sc = score_text_per_char(pt)
            label = f"{label_prefix}/{cipher_name}/{alpha_name}/{key}"
            cribs = check_cribs_anywhere(pt)
            if cribs:
                print(f"\n{'!'*70}")
                print(f"*** CRIB HIT *** {label}")
                print(f"  PT: {pt}")
                print(f"  Cribs: {cribs}")
                print(f"  Score: {sc:.3f}/char")
                print(f"{'!'*70}\n")
            update_best(label, pt, sc, f"cribs={cribs}" if cribs else "")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL 1: NULL CIPHER — Discard every Nth character
# ═════════════════════════════════════════════════════════════════════════════
def test_null_cipher():
    print("\n" + "="*70)
    print("MODEL 1: NULL CIPHER — Discard every Nth character")
    print("="*70)

    tested = 0
    for skip_n in range(2, 11):  # every 2nd, 3rd, ... 10th char is null
        for offset in range(skip_n):
            # Build CT with nulls removed
            kept = [K4_CARVED[i] for i in range(N) if (i % skip_n) != offset]
            ct_short = "".join(kept)

            for key in KEYWORDS + MORSE_PHRASES[:6]:
                try_decrypt(ct_short, key, f"null/skip{skip_n}/off{offset}")
                tested += 1

            # Also try the DISCARDED chars as a separate message
            discarded = [K4_CARVED[i] for i in range(N) if (i % skip_n) == offset]
            ct_disc = "".join(discarded)
            if len(ct_disc) >= 10:
                for key in KEYWORDS[:5]:
                    try_decrypt(ct_disc, key, f"null_disc/skip{skip_n}/off{offset}")
                    tested += 1

    print(f"  Tested {tested} null cipher configs")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL 2: VOWEL REMOVAL — What if PT vowels were removed before encryption?
# ═════════════════════════════════════════════════════════════════════════════
def test_vowel_removal():
    print("\n" + "="*70)
    print("MODEL 2: VOWEL REMOVAL / MASKING")
    print("="*70)

    tested = 0

    # 2a: Direct decrypt, then check if result looks like vowel-stripped English
    for key in KEYWORDS + MORSE_PHRASES[:6]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cipher_fn(K4_CARVED, key, alpha)
                except (ValueError, IndexError):
                    continue

                # Count vowel ratio — vowel-stripped text has ~0% vowels
                vowel_count = sum(1 for c in pt if c in VOWELS)
                vowel_ratio = vowel_count / len(pt)

                # Normal English: ~38% vowels. Stripped: ~0%.
                # If decrypted text has very few vowels, could be vowel-stripped
                if vowel_ratio < 0.15:
                    # Try reinserting vowels — this is hard to automate,
                    # but we can at least flag low-vowel candidates
                    consonants_only = "".join(c for c in pt if c not in VOWELS)
                    sc = score_text_per_char(pt)
                    label = f"vowel_check/{cipher_name}/{alpha_name}/{key}"
                    if sc > -8.0 or vowel_ratio < 0.08:
                        print(f"  Low-vowel ({vowel_ratio:.1%}): {label} → {pt[:40]}... sc={sc:.3f}")
                tested += 1

    # 2b: What if specific vowels were replaced with a fixed letter (e.g., X)?
    # Decrypt, replace X->each vowel pattern
    for key in KEYWORDS[:8]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cipher_fn(K4_CARVED, key, alpha)
                except (ValueError, IndexError):
                    continue

                # Try replacing each uncommon letter with each vowel
                for mask_letter in "XZQJ":
                    if mask_letter in pt:
                        for vowel in "AEIOU":
                            pt_mod = pt.replace(mask_letter, vowel)
                            sc = score_text_per_char(pt_mod)
                            label = f"vowel_mask/{mask_letter}->{vowel}/{cipher_name}/{alpha_name}/{key}"
                            update_best(label, pt_mod, sc)
                            cribs = check_cribs_anywhere(pt_mod)
                            if cribs:
                                print(f"  CRIB HIT: {label} → cribs={cribs}")
                            tested += 1

    print(f"  Tested {tested} vowel removal configs")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL 3: PHONETIC RESPELLING
# ═════════════════════════════════════════════════════════════════════════════
def test_phonetic():
    print("\n" + "="*70)
    print("MODEL 3: PHONETIC RESPELLING")
    print("="*70)

    # Key insight: if PT was phonetically respelled, cribs may be different
    # EASTNORTHEAST → EESTNORTHEEST, EESTNOORTHHEEST, ESTNOREST, etc.
    # BERLINCLOCK → BURLINCLOK, BERLINCLOC, BRLINCLK, etc.

    # Generate phonetic variants of cribs
    ene_variants = [
        "EASTNORTHEAST",
        "EESTNORTHEEST",     # double vowels
        "ESTNOREST",          # simplified
        "ESTNRTHEST",         # dropped vowels
        "EASTNOERTHEAST",     # extra vowel
        "EASTNORFEEST",       # TH->F
        "EASNOREEAS",         # extreme simplification
        "ISTNORTHIST",        # E->I
        "ASTNORTHAST",        # vowel swap
        "EESTNORTHEEST",      # long vowels
        "STNRTHST",           # consonants only
        "EASTNOTHEAST",       # drop R
    ]

    bc_variants = [
        "BERLINCLOCK",
        "BURLINCLOK",         # phonetic vowel
        "BERLINCLOC",         # drop K
        "BERLINCLCK",         # drop vowel
        "BURLINCLCK",         # phonetic + drop vowel
        "BRLINCLK",           # consonants only
        "BERLINEKLOK",        # German-influenced
        "BEARLINCLOK",        # diphthong
        "BERLINKLOCK",        # K variant
        "BERLINUHR",          # German for clock
    ]

    tested = 0
    for key in KEYWORDS + MORSE_PHRASES[:6]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cipher_fn(K4_CARVED, key, alpha)
                except (ValueError, IndexError):
                    continue

                # Check for phonetic variants of cribs
                for variant in ene_variants + bc_variants:
                    idx = pt.find(variant)
                    if idx >= 0:
                        sc = score_text_per_char(pt)
                        print(f"  PHONETIC HIT: '{variant}' at pos {idx}")
                        print(f"    {cipher_name}/{alpha_name}/{key} → {pt}")
                        print(f"    Score: {sc:.3f}/char")
                        update_best(f"phonetic/{variant}", pt, sc, f"at pos {idx}")
                tested += 1

    print(f"  Tested {tested} phonetic configs")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL 4: CONCEALMENT = THE TRANSPOSITION ITSELF
# ═════════════════════════════════════════════════════════════════════════════
def test_concealment_is_transposition():
    print("\n" + "="*70)
    print("MODEL 4: CONCEALMENT = TRANSPOSITION (test direct Vig/Beau on carved)")
    print("  Testing extended keyword set including Morse phrases")
    print("="*70)

    # If "concealment" just means the scrambling/transposition layer,
    # then the underlying cipher could be standard Vigenère/Beaufort
    # but we need the RIGHT keyword. Test Morse-derived keys.

    tested = 0
    all_keys = KEYWORDS + MORSE_KEYWORDS + [
        # Concealment-themed keywords
        "CONCEALMENT", "STEGANOGRAPHY", "STEGO", "HIDDEN",
        "MASKED", "INVISIBLE", "BURIED", "FOSSIL",
        # Kryptos-related
        "LANGLEY", "WEBSTER", "CIA",
        "PALIMPSEST", "ABSCISSA",
        # Combined
        "KRYPTOSSHADOW", "KRYPTOSLUCID", "SHADOWKRYPTOS",
        "PALIMPSESTSHADOW", "ABSCISSASHADOW",
        # Carter/Tomb themed
        "CARTER", "TUTANKHAMUN", "CARNARVON", "WONDERFUL",
        "CANDLE", "TOMB", "CHAMBER",
        # Period-derived
        "KLUCIDM",  # 7 letters
        "SHADOWFO",  # 8 letters
    ]

    for key in all_keys:
        if not key or not key.isalpha():
            continue
        try_decrypt(K4_CARVED, key, "concealment_trans")
        tested += 1

    print(f"  Tested {tested} concealment-as-transposition configs")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL 5: KEY HIDDEN IN MORSE CODE
# ═════════════════════════════════════════════════════════════════════════════
def test_morse_keys():
    print("\n" + "="*70)
    print("MODEL 5: KEY HIDDEN IN MORSE CODE PHRASES")
    print("="*70)

    # "T IS YOUR POSITION" — T=19 (0-indexed) or T=20 (1-indexed)
    # Could mean: start at position T in some sequence
    # Could define a keyword: extract every Nth letter from Morse phrases

    tested = 0

    # 5a: Use Morse phrases directly as keys
    for phrase in MORSE_PHRASES:
        try_decrypt(K4_CARVED, phrase, "morse_key")
        tested += 1

    # 5b: Extract keys from Morse phrases using various methods
    morse_combined = "TISYOURPOSITIONVIRTUALLYINVISIBLESHADOWFORCESLUCIDMEMORYDIGITALINTERPRETATION"

    # Every Nth letter from combined Morse
    for skip in range(2, 15):
        for start in range(min(skip, 5)):
            key = morse_combined[start::skip]
            if len(key) >= 3:
                key = key[:20]  # truncate
                try_decrypt(K4_CARVED, key, f"morse_skip{skip}_off{start}")
                tested += 1

    # 5c: First letters of Morse words
    morse_words = ["T", "IS", "YOUR", "POSITION", "VIRTUALLY", "INVISIBLE",
                   "SHADOW", "FORCES", "LUCID", "MEMORY", "DIGITAL", "INTERPRETATION", "SOS"]
    acrostic = "".join(w[0] for w in morse_words)  # TIYPVISFLDIS
    try_decrypt(K4_CARVED, acrostic, "morse_acrostic")
    tested += 1

    # Last letters
    telestich = "".join(w[-1] for w in morse_words)
    try_decrypt(K4_CARVED, telestich, "morse_telestich")
    tested += 1

    # 5d: Morse → numeric → key
    # T=20, I=9, S=19, Y=25, O=15, U=21, R=18 (1-indexed A=1)
    # Convert to letters mod 26
    for phrase in MORSE_PHRASES[:6]:
        nums = [(ord(c) - ord('A')) for c in phrase]
        # Sum consecutive pairs
        if len(nums) >= 2:
            pair_key = "".join(AZ[(nums[i] + nums[i+1]) % 26] for i in range(0, len(nums)-1, 2))
            try_decrypt(K4_CARVED, pair_key, f"morse_pairsum/{phrase[:10]}")
            tested += 1
        # XOR consecutive
        if len(nums) >= 2:
            xor_key = "".join(AZ[(nums[i] ^ nums[i+1]) % 26] for i in range(0, len(nums)-1, 2))
            try_decrypt(K4_CARVED, xor_key, f"morse_pairxor/{phrase[:10]}")
            tested += 1

    # 5e: "T IS YOUR POSITION" = T-row of tableau = key
    # T-row of KA tableau: shift by KA.index(T) = 4
    t_idx_ka = KA.index('T')  # =4
    t_row = KA[t_idx_ka:] + KA[:t_idx_ka]  # "OSABCDEFGHIJLMNQUVWXZKRYPT"
    try_decrypt(K4_CARVED, t_row[:7], "morse_T_row_ka7")
    try_decrypt(K4_CARVED, t_row[:8], "morse_T_row_ka8")
    try_decrypt(K4_CARVED, t_row, "morse_T_row_full")
    tested += 3

    # T-row of AZ tableau: shift by 19
    t_idx_az = AZ.index('T')  # =19
    t_row_az = AZ[t_idx_az:] + AZ[:t_idx_az]
    try_decrypt(K4_CARVED, t_row_az[:7], "morse_T_row_az7")
    try_decrypt(K4_CARVED, t_row_az[:8], "morse_T_row_az8")
    tested += 2

    print(f"  Tested {tested} Morse key configs")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL 6: SELECTIVE LETTER MASKING
# ═════════════════════════════════════════════════════════════════════════════
def test_selective_masking():
    print("\n" + "="*70)
    print("MODEL 6: SELECTIVE LETTER MASKING")
    print("  What if vowels in PT were replaced with a single letter before encryption?")
    print("="*70)

    # Idea: PT had all vowels replaced with X (or another letter) before Vig encryption
    # Then the encrypted vowel positions all map to the same shifted letter
    # This would flatten the frequency distribution (freq analysis won't help)

    tested = 0

    for key in KEYWORDS[:8]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cipher_fn(K4_CARVED, key, alpha)
                except (ValueError, IndexError):
                    continue

                # For each letter that appears frequently, assume it's the mask
                freq = Counter(pt)
                for mask_char, count in freq.most_common(8):
                    if count < 5:
                        break

                    # Try each vowel as the original
                    # But we can't know which positions had which vowel
                    # Instead: check if replacing mask_char with most likely vowel
                    # improves score
                    for vowel in "EAIO":  # most common vowels
                        pt_restored = pt.replace(mask_char, vowel)
                        sc = score_text_per_char(pt_restored)
                        label = f"mask/{mask_char}->{vowel}/{cipher_name}/{alpha_name}/{key}"
                        update_best(label, pt_restored, sc)
                        tested += 1

    print(f"  Tested {tested} masking configs")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL 7: REVERSED CT + CONCEALMENT
# ═════════════════════════════════════════════════════════════════════════════
def test_reversed_concealment():
    print("\n" + "="*70)
    print("MODEL 7: REVERSED CT + CONCEALMENT KEYS")
    print("="*70)

    tested = 0
    ct_rev = K4_CARVED[::-1]

    for key in KEYWORDS + MORSE_PHRASES[:8]:
        try_decrypt(ct_rev, key, "reversed")
        tested += 1

    # Also test reversing halves
    mid = N // 2
    ct_swap = K4_CARVED[mid:] + K4_CARVED[:mid]
    for key in KEYWORDS[:8]:
        try_decrypt(ct_swap, key, "half_swap")
        tested += 1

    # Reverse each half
    ct_rev_halves = K4_CARVED[:mid][::-1] + K4_CARVED[mid:][::-1]
    for key in KEYWORDS[:8]:
        try_decrypt(ct_rev_halves, key, "rev_halves")
        tested += 1

    print(f"  Tested {tested} reversed configs")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL 8: DOUBLE-KEYWORD VIGENÈRE
# ═════════════════════════════════════════════════════════════════════════════
def test_double_keyword():
    print("\n" + "="*70)
    print("MODEL 8: DOUBLE-KEYWORD VIGENÈRE (two keywords combined)")
    print("  Scheidt: 'two separate systems' / KryptosFan: 'K4 expected to have TWO keywords'")
    print("="*70)

    tested = 0

    # Two keywords applied sequentially
    key_pool = KEYWORDS[:10] + MORSE_PHRASES[:6]

    for key1 in key_pool:
        for key2 in key_pool:
            if key1 == key2:
                continue

            # Decrypt with key1, then decrypt result with key2
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                for c1_name, c1_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                    for c2_name, c2_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                        try:
                            intermediate = c1_fn(K4_CARVED, key1, alpha)
                            pt = c2_fn(intermediate, key2, alpha)
                        except (ValueError, IndexError):
                            continue

                        sc = score_text_per_char(pt)
                        label = f"double/{c1_name}_{key1[:6]}+{c2_name}_{key2[:6]}/{alpha_name}"

                        cribs = check_cribs_anywhere(pt)
                        if cribs:
                            print(f"\n  CRIB HIT in double-keyword: {label}")
                            print(f"  PT: {pt}")
                            print(f"  Cribs: {cribs}")

                        update_best(label, pt, sc, f"cribs={cribs}" if cribs else "")
                        tested += 1

            # Limit to avoid explosion
            if tested > 50000:
                print(f"  (capped at {tested} double-keyword configs)")
                return

    print(f"  Tested {tested} double-keyword configs")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL 9: INTERLEAVED NULLS (structured null insertion)
# ═════════════════════════════════════════════════════════════════════════════
def test_interleaved_nulls():
    print("\n" + "="*70)
    print("MODEL 9: INTERLEAVED NULL PATTERNS")
    print("  What if specific positions are nulls (padding), not real CT?")
    print("="*70)

    tested = 0

    # 9a: Positions where doubled letters occur — could be null padding
    # K4 has: BB (pos 18-19), QQ (pos 24-25), SS (pos 31-32, 41-42), KK (pos 86-87?),
    # ZZ (pos 44-45), TT (pos 68-69)
    doubles = []
    for i in range(N-1):
        if K4_CARVED[i] == K4_CARVED[i+1]:
            doubles.append(i)

    print(f"  Double positions: {doubles}")

    # Remove one of each double pair
    for which in [0, 1]:  # remove first or second of pair
        kept = list(range(N))
        for d in doubles:
            kept.remove(d + which)
        ct_short = "".join(K4_CARVED[i] for i in kept)
        for key in KEYWORDS[:8]:
            try_decrypt(ct_short, key, f"drop_double_{which}")
            tested += 1

    # 9b: Remove positions matching "8 Lines 73" — if K4 is 8 rows,
    # maybe 97-73=24 positions are nulls (same as crib count!)
    # Try removing various patterns of 24 positions
    # Hypothesis: null positions could be at row boundaries
    for width in [8, 12, 13]:
        null_positions = set()
        # Last position of each row
        for row in range(N // width + 1):
            pos = row * width + (width - 1)
            if pos < N:
                null_positions.add(pos)

        if len(null_positions) > 0:
            kept = [i for i in range(N) if i not in null_positions]
            ct_short = "".join(K4_CARVED[i] for i in kept)
            for key in KEYWORDS[:8]:
                try_decrypt(ct_short, key, f"row_boundary_null/w{width}")
                tested += 1

    # 9c: Self-encrypting positions as clue for null pattern
    # CT[32]=PT[32]=S and CT[73]=PT[73]=K
    # Key value at positions 32 and 73 must be 0 (identity)
    # These could be null insertion points

    print(f"  Tested {tested} interleaved null configs")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL 10: K4 LETTER FREQUENCIES AS CONCEALMENT EVIDENCE
# ═════════════════════════════════════════════════════════════════════════════
def test_frequency_analysis():
    print("\n" + "="*70)
    print("MODEL 10: FREQUENCY ANALYSIS FOR CONCEALMENT EVIDENCE")
    print("  Scheidt: 'frequency analysis will NOT help with K4'")
    print("  WHY? Because concealment flattened the distribution.")
    print("="*70)

    freq = Counter(K4_CARVED)
    total = sum(freq.values())

    print(f"\n  K4 letter frequencies (IC={sum(v*(v-1) for v in freq.values())/(total*(total-1)):.4f}):")
    for letter, count in sorted(freq.items(), key=lambda x: -x[1]):
        bar = "#" * count
        print(f"    {letter}: {count:2d} ({count/total:.3f}) {bar}")

    # Check if any decryption produces UNIFORM distribution (evidence of masking)
    print(f"\n  Checking decryptions for uniform distribution (concealment evidence)...")

    flattest = None
    flattest_score = 999

    for key in KEYWORDS[:8]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name, cipher_fn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cipher_fn(K4_CARVED, key, alpha)
                except (ValueError, IndexError):
                    continue

                pt_freq = Counter(pt)
                # Chi-squared against uniform
                expected = len(pt) / 26.0
                chi2 = sum((pt_freq.get(c, 0) - expected)**2 / expected for c in AZ)

                if chi2 < flattest_score:
                    flattest_score = chi2
                    flattest = (cipher_name, alpha_name, key, pt, chi2)

    if flattest:
        cn, an, k, pt, chi2 = flattest
        print(f"  Flattest distribution: {cn}/{an}/{k}")
        print(f"    Chi-squared vs uniform: {chi2:.1f} (lower=flatter, English~50, random~26)")
        print(f"    PT: {pt[:50]}...")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL 11: CONCEALMENT VIA AUTOKEY / RUNNING KEY
# ═════════════════════════════════════════════════════════════════════════════
def test_autokey():
    print("\n" + "="*70)
    print("MODEL 11: AUTOKEY CIPHER (PT feeds back into key)")
    print("  Autokey = 'concealment' because key changes with each letter")
    print("="*70)

    tested = 0

    for primer in KEYWORDS + MORSE_PHRASES[:6]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            # Autokey Vigenère: K[i] = primer for i < len(primer), else PT[i-len(primer)]
            # Decrypt: PT[0..p-1] = Vig_decrypt(CT[0..p-1], primer)
            # Then PT[p] = (CT[p] - PT[0]) mod 26, etc.

            pt_chars = []
            p = len(primer)

            try:
                # Decrypt primer portion
                for i in range(min(p, N)):
                    ci = alpha.index(K4_CARVED[i])
                    ki = alpha.index(primer[i])
                    pt_chars.append(alpha[(ci - ki) % 26])

                # Autokey portion
                for i in range(p, N):
                    ci = alpha.index(K4_CARVED[i])
                    ki = alpha.index(pt_chars[i - p])
                    pt_chars.append(alpha[(ci - ki) % 26])

                pt = "".join(pt_chars)
                sc = score_text_per_char(pt)
                label = f"autokey_vig/{alpha_name}/{primer[:10]}"
                update_best(label, pt, sc)

                cribs = check_cribs_anywhere(pt)
                if cribs:
                    print(f"  CRIB HIT: {label} → cribs={cribs}")
                    print(f"  PT: {pt}")
                tested += 1
            except (ValueError, IndexError):
                continue

            # Autokey Beaufort: PT[i] = (K[i] - CT[i]) mod 26
            pt_chars2 = []
            try:
                for i in range(min(p, N)):
                    ci = alpha.index(K4_CARVED[i])
                    ki = alpha.index(primer[i])
                    pt_chars2.append(alpha[(ki - ci) % 26])

                for i in range(p, N):
                    ci = alpha.index(K4_CARVED[i])
                    ki = alpha.index(pt_chars2[i - p])
                    pt_chars2.append(alpha[(ki - ci) % 26])

                pt2 = "".join(pt_chars2)
                sc2 = score_text_per_char(pt2)
                label2 = f"autokey_beau/{alpha_name}/{primer[:10]}"
                update_best(label2, pt2, sc2)

                cribs2 = check_cribs_anywhere(pt2)
                if cribs2:
                    print(f"  CRIB HIT: {label2} → cribs={cribs2}")
                    print(f"  PT: {pt2}")
                tested += 1
            except (ValueError, IndexError):
                continue

            # CT autokey: K[i] = primer for i < p, else CT[i-p]
            pt_chars3 = []
            try:
                for i in range(min(p, N)):
                    ci = alpha.index(K4_CARVED[i])
                    ki = alpha.index(primer[i])
                    pt_chars3.append(alpha[(ci - ki) % 26])

                for i in range(p, N):
                    ci = alpha.index(K4_CARVED[i])
                    ki = alpha.index(K4_CARVED[i - p])
                    pt_chars3.append(alpha[(ci - ki) % 26])

                pt3 = "".join(pt_chars3)
                sc3 = score_text_per_char(pt3)
                label3 = f"ct_autokey/{alpha_name}/{primer[:10]}"
                update_best(label3, pt3, sc3)

                cribs3 = check_cribs_anywhere(pt3)
                if cribs3:
                    print(f"  CRIB HIT: {label3} → cribs={cribs3}")
                    print(f"  PT: {pt3}")
                tested += 1
            except (ValueError, IndexError):
                continue

    print(f"  Tested {tested} autokey configs")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL 12: PROGRESSIVE KEY (key changes with each position)
# ═════════════════════════════════════════════════════════════════════════════
def test_progressive_key():
    print("\n" + "="*70)
    print("MODEL 12: PROGRESSIVE KEY (key shifts by constant each position)")
    print("  Medieval guild cipher: fixed keyword + progressive offset")
    print("="*70)

    tested = 0

    for base_key in KEYWORDS[:8]:
        for step in range(1, 26):  # shift increment per position
            # Key[i] = (base_key[i % len(base_key)] + i*step) mod 26
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                pt_chars = []
                try:
                    for i in range(N):
                        ci = alpha.index(K4_CARVED[i])
                        base_ki = alpha.index(base_key[i % len(base_key)])
                        ki = (base_ki + i * step) % 26
                        pt_chars.append(alpha[(ci - ki) % 26])

                    pt = "".join(pt_chars)
                    sc = score_text_per_char(pt)
                    label = f"progressive/{alpha_name}/{base_key[:6]}/step{step}"
                    update_best(label, pt, sc)

                    cribs = check_cribs_anywhere(pt)
                    if cribs:
                        print(f"  CRIB HIT: {label} → cribs={cribs}")
                        print(f"  PT: {pt}")
                    tested += 1
                except (ValueError, IndexError):
                    continue

    print(f"  Tested {tested} progressive key configs")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL 13: STEGO — KEY ENCODED IN K1-K3 PLAINTEXT
# ═════════════════════════════════════════════════════════════════════════════
def test_stego_k1k3():
    print("\n" + "="*70)
    print("MODEL 13: STEGO — Key hidden in K1-K3 plaintext")
    print("  'a little bit of stego' could mean the key IS the stego")
    print("="*70)

    tested = 0

    # K1 PT (known)
    K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
    # K2 PT (known)
    K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOESLANGLOYKNOWABOUTTHISTHEYSABORETIRFSCURRBECOMEDTHECAMERASAHCTADETARETCEHTTAHPREBEIWTBURYETOUSRRAHTSIHTX"
    # K3 PT (known)
    K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEABORISTTDAHTTEREREBMUCNETHOLREDOWTLRETHTFOTRAPRNWOLEHTDECOFNAMELTORIVETTDETHTIWEDAESAIAHNTIELBDNA"

    # Note: K2/K3 PT above may have known misspellings and reversed sections

    # Extract keys from K1-K3 PT using various methods
    sources = [("K1", K1_PT), ("K2", K2_PT[:100]), ("K3", K3_PT)]

    for src_name, src_text in sources:
        # Every Nth letter
        for skip in range(2, 15):
            for offset in range(min(skip, 3)):
                key = src_text[offset::skip]
                if len(key) >= 5:
                    key = key[:20]
                    try_decrypt(K4_CARVED, key, f"stego_{src_name}_skip{skip}_off{offset}")
                    tested += 1

        # First letter of each word (need to split - no spaces, use common words)
        # Try using known word boundaries
        if src_name == "K1":
            words = ["BETWEEN", "SUBTLE", "SHADING", "AND", "THE", "ABSENCE",
                     "OF", "LIGHT", "LIES", "THE", "NUANCE", "OF", "IQLUSION"]
            acrostic = "".join(w[0] for w in words)
            try_decrypt(K4_CARVED, acrostic, f"stego_{src_name}_acrostic")
            tested += 1

    # Misspelling letters as key
    # K1: IQLUSION → Q (should be L), K3: DESPARATLY → A (should be E)
    # These spell K,A in ciphertext space. As a key: "KA" or "QA"
    for key in ["KA", "QA", "KAQEQL", "KRYPTOSQA", "KRYPTOSKA"]:
        try_decrypt(K4_CARVED, key, f"stego_misspell/{key}")
        tested += 1

    print(f"  Tested {tested} stego configs")


# ═════════════════════════════════════════════════════════════════════════════
# MODEL 14: GRONSFELD / NUMERIC KEY VARIANTS
# ═════════════════════════════════════════════════════════════════════════════
def test_numeric_keys():
    print("\n" + "="*70)
    print("MODEL 14: NUMERIC / GRONSFELD KEYS")
    print("  What if the key is numeric (from coordinates, dates, etc.)?")
    print("="*70)

    tested = 0

    # K2 coordinates: 38°57'6.5"N, 77°8'44"W
    numeric_keys = [
        "3857065",      # lat digits
        "770844",       # lon digits
        "38570657708440",  # both
        "3857",
        "7708",
        "38577708",
        "06577084",     # minutes+seconds
        "65440",        # seconds only
        "389577084",    # compressed
        "19901103",     # dedication date Nov 3 1990
        "1103",
        "1990",
        "19221126",     # Carter opens tomb Nov 26 1922
        "1126",
        "1922",
        "8073",         # "8 Lines 73"
        "873",
        "831",          # 8×31 grid
        "2831",         # 28×31 grid
        "1570",         # year of Vigenère (1570)
    ]

    for num_key in numeric_keys:
        # Gronsfeld: shift by digit (0-9)
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            pt_chars = []
            try:
                for i in range(N):
                    ci = alpha.index(K4_CARVED[i])
                    ki = int(num_key[i % len(num_key)])
                    pt_chars.append(alpha[(ci - ki) % 26])
                pt = "".join(pt_chars)
                sc = score_text_per_char(pt)
                label = f"gronsfeld/{alpha_name}/{num_key}"
                update_best(label, pt, sc)
                cribs = check_cribs_anywhere(pt)
                if cribs:
                    print(f"  CRIB HIT: {label} → cribs={cribs}")
                tested += 1
            except (ValueError, IndexError):
                continue

    print(f"  Tested {tested} numeric key configs")


# ═════════════════════════════════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════════════════════════════════
def main():
    t0 = time.time()
    print("="*70)
    print("BLITZ CONCEALMENT — Testing concealment/stego pre-processing models")
    print(f"K4 carved text ({N} chars): {K4_CARVED}")
    print("="*70)

    test_null_cipher()
    test_vowel_removal()
    test_phonetic()
    test_concealment_is_transposition()
    test_morse_keys()
    test_selective_masking()
    test_reversed_concealment()
    test_double_keyword()
    test_interleaved_nulls()
    test_frequency_analysis()
    test_autokey()
    test_progressive_key()
    test_stego_k1k3()
    test_numeric_keys()

    elapsed = time.time() - t0

    print("\n" + "="*70)
    print("FINAL RESULTS")
    print("="*70)
    print(f"Total time: {elapsed:.1f}s")

    if BEST_RESULT:
        label, pt, sc, extra = BEST_RESULT
        print(f"\nBest score: {sc:.4f}/char")
        print(f"  Method: {label}")
        print(f"  PT: {pt}")
        if extra:
            print(f"  Extra: {extra}")
    else:
        print("\nNo results above noise.")

    print(f"\nAlert threshold was {ALERT_THRESHOLD}/char")
    if BEST_SCORE > ALERT_THRESHOLD:
        print("*** ABOVE ALERT THRESHOLD — INVESTIGATE ***")
    else:
        print("All results below alert threshold — concealment models tested negative.")

    # Summary assessment
    print("\n" + "="*70)
    print("ASSESSMENT")
    print("="*70)
    print("""
Key findings:
1. NULL CIPHER: If every Nth char is null, shorter CT tested with all keywords.
2. VOWEL MASKING: Checked if any decryption produces low-vowel text.
3. PHONETIC: Searched for phonetic variants of cribs in all decryptions.
4. CONCEALMENT=TRANSPOSITION: Extended keyword set (Morse phrases) tested.
5. MORSE KEYS: Phrases, acrostics, skip-extractions from Morse text.
6. SELECTIVE MASKING: Replaced high-frequency letters with vowels.
7. REVERSED: CT reversed, halves swapped, halves reversed.
8. DOUBLE KEYWORD: Sequential Vig/Beau with all keyword pairs.
9. INTERLEAVED NULLS: Removed doubled-letter positions, row boundaries.
10. FREQUENCY ANALYSIS: Checked distribution flatness.
11. AUTOKEY: PT-autokey, CT-autokey, Beaufort autokey.
12. PROGRESSIVE KEY: Keyword + linear step per position.
13. STEGO K1-K3: Keys extracted from K1-K3 plaintext via skips/acrostics.
14. NUMERIC KEYS: Gronsfeld with coordinates, dates, "8 Lines 73".

If Scheidt's 'concealment' refers to the scrambling/transposition layer itself
(not a PT pre-processing step), then this entire model class is moot and
the search should focus on finding the correct unscrambling permutation.
""")


if __name__ == "__main__":
    main()
