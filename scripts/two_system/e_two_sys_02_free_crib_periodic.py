#!/usr/bin/env python3
# Cipher:     Two-system (null removal + periodic substitution, free crib placement)
# Family:     two_system
# Status:     active
# Keyspace:   36 periods x 3 variants x 2 alphabets x 61 x 63 = ~830K triples
# Last run:
# Best score:
#
# E-TWO-SYS-02: Free-crib periodic consistency.
#
# Model A + periodic substitution, but cribs appear at ARBITRARY positions in the
# 73-char plaintext (not necessarily at their shifted original positions). Maybe
# the null removal scrambles crib positions, or the cribs apply to a different
# reading order.
#
# For each period T, cipher variant, alphabet, and possible crib placement
# (s1=ENE start, s2=BC start in 73-char text):
#   Derive key values at crib positions. Check periodic consistency.
#   If consistent: record the surviving triple and the required CT chars.
#
# Search space: 36 × 6 × 61 × 63 ≈ 830K checks. Runtime: < 5 minutes.
from __future__ import annotations

import os
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET,
)

# ── Setup ─────────────────────────────────────────────────────────────────

REDUCED_LEN = 73

ENE_WORD = "EASTNORTHEAST"
BC_WORD = "BERLINCLOCK"
ENE_LEN = len(ENE_WORD)  # 13
BC_LEN = len(BC_WORD)    # 11

# Key recovery functions
def vig_key(c, p):
    return (c - p) % MOD

def beau_key(c, p):
    return (c + p) % MOD

def vbeau_key(c, p):
    return (p - c) % MOD

VARIANTS = [
    ("Vigenere", vig_key),
    ("Beaufort", beau_key),
    ("VarBeau", vbeau_key),
]

ALPHABETS = [
    ("AZ", ALPH, [0]*26),
    ("KA", KRYPTOS_ALPHABET, [0]*26),
]

# Build index tables
for i, (name, alph_str, idx) in enumerate(ALPHABETS):
    new_idx = {c: j for j, c in enumerate(alph_str)}
    ALPHABETS[i] = (name, alph_str, new_idx)

MAX_PERIOD = 36

# CT character indices (standard A-Z for lookups against the 97-char CT)
CT_CHARS = list(CT)

# All 97 CT chars as potential sources — the 73-char reduced CT is some
# subset of these. For free-crib search, we need to know which CT chars
# could appear at each position in the reduced text. Since we don't know
# the mask, we test all possible CT chars at crib positions.
#
# Actually: for free-crib periodic consistency, we're testing whether
# ANY 73-char subset of the 97-char CT could produce the cribs at
# positions (s1, s2) under periodic key with period T.
#
# The CT char at reduced position j depends on which nulls are removed.
# We don't know the specific CT chars — so instead, we check:
# for EACH possible CT char (A-Z) at each crib position, does a
# consistent periodic key exist?
#
# BUT: the CT chars aren't arbitrary — they come from the 97-char CT.
# So we need a different approach: enumerate which CT chars COULD appear
# at a given reduced position.
#
# For a given (a, b) null distribution:
#   reduced[j] = CT[orig_pos] where orig_pos is the j-th non-null position.
#
# Since we're doing FREE crib search (cribs at arbitrary positions in the
# 73-char text), and we don't know the null mask, we must consider all
# possible CT characters that could appear at each reduced position.
#
# Simplification: just test all 26 possible CT values at each crib pos.
# This gives an UPPER BOUND on survivors. Then filter against actual CT
# character availability.


def check_consistency_free(
    s1: int, s2: int, period: int,
    key_fn, alph_idx: dict,
) -> list:
    """Check periodic consistency for cribs at positions s1 (ENE) and s2 (BC).

    Since we don't know which CT chars appear at these reduced positions,
    we try ALL 26^24 possible CT char combinations... NO, that's too many.

    Better approach: for each crib position, the key value k = key_fn(c, p)
    depends on the unknown CT char c. For periodic consistency, all positions
    at the same residue must have the same k value. So:

    For residue r = s1+i % T = s2+j % T (if they collide):
      key_fn(c1, ENE[i]) == key_fn(c2, BC[j])
      This constrains which CT chars can appear at those positions.

    For same-crib collisions (s1+i % T == s1+j % T):
      key_fn(c_i, ENE[i]) == key_fn(c_j, ENE[j])
      This constrains CT char pairs.

    Strategy: for each residue, collect the crib chars that map to it.
    Then check if there EXISTS a key value k such that for each crib char p
    at that residue, the required CT char c = encrypt(p, k) is available
    in the CT (with multiplicity).

    Returns list of (key_value_per_residue, ct_requirements) or empty list.
    """
    # Map residue -> list of (crib_char_as_int, position_in_73)
    residue_to_cribs = {}

    for i in range(ENE_LEN):
        pos = s1 + i
        r = pos % period
        p_num = alph_idx[ENE_WORD[i]]
        residue_to_cribs.setdefault(r, []).append(p_num)

    for i in range(BC_LEN):
        pos = s2 + i
        r = pos % period
        p_num = alph_idx[BC_WORD[i]]
        residue_to_cribs.setdefault(r, []).append(p_num)

    # For each residue with crib constraints, find valid key values.
    # For key value k:
    #   Vigenere: c = (p + k) mod 26 → CT char needed is alph[p+k]
    #   Beaufort: c = (k - p) mod 26 → CT char needed is alph[k-p]
    #   VarBeau:  c = (p - k) mod 26 → CT char needed is alph[p-k]
    #
    # But since key_fn recovers k from (c,p), we need encrypt_fn(p,k) → c.
    # Actually we just need consistency: all plaintexts at same residue
    # produce the same key. For Vigenere: k = (c - p) mod 26.
    # If k is fixed for a residue, then c = (p + k) mod 26.
    # The c must be a letter available in CT (with multiplicity across all
    # 73 chosen positions). Since we don't know which CT chars are at
    # which reduced position, we just check: for each possible k (0-25),
    # do the required CT chars exist in CT with sufficient multiplicity?

    # But this is very loose — CT has all 26 letters. The real constraint
    # is that the SAME key value works for all crib chars at the same residue.
    # That's just: key_fn(c_i, p_i) must all equal k for some k.
    # Since c_i is unknown, for Vigenere: c_i = (p_i + k) for each p_i.
    # The question is whether such c_i chars exist in CT.
    # Since CT contains all 26 letters, ANY k is feasible if we only need
    # 1-2 copies of each letter. But some letters appear only once in CT.

    # Actually, the tightest constraint is: if two crib chars at the same
    # residue are DIFFERENT but require the SAME CT char, then that CT char
    # must appear at least twice in the 73-char reduced text at positions
    # with the same residue. This is a mild constraint.

    # The PRIMARY constraint is just: does a consistent k exist?
    # For the same residue r, all crib chars p_i must produce the same k.
    # key_fn(c_i, p_i) = k for all i.
    # Since c_i is a free variable (any of the 97 CT chars could end up there),
    # we can always find c_i = encrypt(p_i, k) for any k.
    # So THE ONLY CONSTRAINT is on positions where BOTH an ENE char and a BC
    # char share the same residue — they must agree on k, and the two
    # plaintext chars (ENE[i] and BC[j]) must produce the same k from their
    # respective (unknown) CT chars. Since CT chars are free, this is
    # always satisfiable! Key: k is arbitrary for each residue.

    # WAIT. I'm overcomplicating this. The real question is:
    # Given 73 specific CT chars (in unknown order due to null mask), can
    # we assign them to positions 0-72 such that a periodic key of period T
    # decrypts to give ENE at s1 and BC at s2?
    #
    # The CT chars ARE fixed (they're from the carved text with 24 removed).
    # So c_i is NOT arbitrary — it's one of the CT chars.
    #
    # For this script, let's just check the STRUCTURAL constraint:
    # all crib chars at the same residue must be consistent with SOME key value.
    # For Vigenere: k = (c - p) mod 26. Two crib chars p_i, p_j at same residue:
    #   (c_i - p_i) ≡ (c_j - p_j) mod 26
    #   c_i - c_j ≡ p_i - p_j mod 26
    # So the CT chars at these positions must differ by the same amount as
    # the plaintext chars. This is a constraint on CT char DIFFERENCES, not
    # values. Since we're choosing from 97 CT chars with known frequencies,
    # this is checkable.

    # SIMPLIFICATION for speed: just check if a consistent key EXISTS
    # assuming CT chars are freely assignable (upper bound on survivors).
    # Then for survivors, verify against actual CT character availability.

    # For Vigenere key_fn: k = (c - p). For fixed k and two cribs p1, p2:
    #   c1 - c2 = p1 - p2 (mod 26). So we need CT chars with this difference.
    # This is ALWAYS possible if CT has ≥2 of each letter (which it doesn't
    # for all letters). But as a first pass, just count structural survivors.

    # The simplest useful check: for each residue with multiple crib chars,
    # all crib chars must be identical (for Vigenere/VarBeau) or have
    # matching sum (for Beaufort). Actually no — different crib chars CAN
    # share a residue as long as different CT chars produce the same key.

    # OK, the correct tight check without knowing CT chars:
    # For Vigenere, k = c - p. If p1 ≠ p2 at same residue, we need c1 ≠ c2
    # with c1 - c2 = p1 - p2. This is always possible if distinct CT chars exist.
    # Similarly for Beaufort (k = c + p): c1 + p1 = c2 + p2, so c1 - c2 = p2 - p1.
    # For VarBeau (k = p - c): p1 - c1 = p2 - c2, so c1 - c2 = p1 - p2.
    #
    # All variants: the constraint is c1 - c2 = ±(p1 - p2) mod 26.
    # This is satisfiable as long as the CT (97 chars) has enough distinct chars
    # — which it does (all 26 letters present). So the STRUCTURAL check is trivially
    # satisfied for all configs! The only real filter is the NULL MASK: which 73
    # of the 97 chars are kept, and whether they can be ARRANGED to satisfy the key.

    # CONCLUSION: For free-crib search without a specific mask, periodic consistency
    # is ALWAYS structurally satisfiable. The real filter comes from:
    # 1. Fixing a specific keyword (not just "some key exists")
    # 2. Checking CT character multiset availability
    # 3. Verifying that the reduced CT positions match

    # So this script should take a different approach: fix a keyword, then
    # for each (s1, s2), compute what CT chars would need to appear at the
    # crib positions, and check if they're available from the CT multiset.

    # For now, return True if constraints don't conflict.
    # Multiple crib chars at same residue: consistent if a valid k exists.
    for r, p_nums in residue_to_cribs.items():
        if len(p_nums) <= 1:
            continue
        # For any variant, we need: key_fn(c_i, p_i) = k for all i.
        # Test all 26 possible k values:
        valid_k = set(range(MOD))
        # No constraint from k itself — any k works since c_i is free.
        # The constraint is on AVAILABLE CT chars.
        # Skip detailed CT check for now (upper bound mode).

    return True  # structural consistency always holds for free CT


def main():
    t0 = time.time()
    print("=" * 78)
    print("E-TWO-SYS-02: Free-crib periodic consistency")
    print("=" * 78)
    print(f"\nCT ({CT_LEN} chars): {CT}")
    print(f"Reduced length: {REDUCED_LEN}")
    print(f"Testing: cribs at arbitrary positions in 73-char text")
    print(f"Periods: 1-{MAX_PERIOD}")
    print(f"ENE positions: 0..{REDUCED_LEN - ENE_LEN}")
    print(f"BC positions:  0..{REDUCED_LEN - BC_LEN}")
    print()

    # CT character frequency (available pool for 73-char subset)
    ct_freq = Counter(CT)
    print(f"CT character frequencies: {dict(sorted(ct_freq.items()))}")
    print()
    sys.stdout.flush()

    # For each period T, variant, alphabet, and keyword candidate,
    # check how many (s1, s2) placements produce consistent keys,
    # AND verify the required CT chars are available.
    #
    # Since structural consistency is always trivially satisfiable,
    # we take the KEYWORD-DRIVEN approach: for each keyword of length T,
    # compute what CT chars are needed at crib positions, and check availability.

    PRIORITY_KEYWORDS = [
        "KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
        "SHADOW", "CIPHER", "SECRET", "ENIGMA", "BERLIN",
        "CLOCK", "PALIMPSEST", "QUAGMIRE",
    ]

    total_checks = 0
    survivors = []

    for kw in PRIORITY_KEYWORDS:
        kw_len = len(kw)
        for alph_name, alph_str, alph_idx in ALPHABETS:
            kw_nums = [alph_idx[c] for c in kw]
            for var_name, key_fn in VARIANTS:
                # For this keyword as the period-T key:
                # At reduced position j, key = kw_nums[j % kw_len]
                # Decrypt: P = decrypt(CT_reduced[j], key_j)
                # We want P at positions s1..s1+12 = ENE, s2..s2+10 = BC

                # For each crib placement (s1, s2):
                for s1 in range(REDUCED_LEN - ENE_LEN + 1):
                    for s2 in range(REDUCED_LEN - BC_LEN + 1):
                        # Non-overlapping check
                        if not (s2 >= s1 + ENE_LEN or s1 >= s2 + BC_LEN):
                            continue

                        total_checks += 1

                        # Compute required CT chars at crib positions
                        # For Vigenere decrypt: P = (C - K) mod 26 → C = (P + K) mod 26
                        # For Beaufort decrypt: P = (K - C) mod 26 → C = (K - P) mod 26
                        # For VarBeau decrypt:  P = (C + K) mod 26 → C = (P - K) mod 26
                        needed_cts = []  # (reduced_pos, required_ct_char_index)

                        valid = True
                        for i in range(ENE_LEN):
                            rpos = s1 + i
                            k = kw_nums[rpos % kw_len]
                            p = alph_idx[ENE_WORD[i]]
                            # Compute required c: encrypt(p, k)
                            if var_name == "Vigenere":
                                c = (p + k) % MOD
                            elif var_name == "Beaufort":
                                c = (k - p) % MOD
                            else:  # VarBeau
                                c = (p - k) % MOD
                            needed_cts.append((rpos, alph_str[c]))

                        for i in range(BC_LEN):
                            rpos = s2 + i
                            k = kw_nums[rpos % kw_len]
                            p = alph_idx[BC_WORD[i]]
                            if var_name == "Vigenere":
                                c = (p + k) % MOD
                            elif var_name == "Beaufort":
                                c = (k - p) % MOD
                            else:
                                c = (p - k) % MOD
                            needed_cts.append((rpos, alph_str[c]))

                        # Check: do the required CT chars exist in the CT
                        # with sufficient multiplicity?
                        # We need 24 specific chars from 97 CT chars for
                        # crib positions (other 49 positions are unconstrained).
                        needed_freq = Counter(c for _, c in needed_cts)
                        for ch, need in needed_freq.items():
                            if ct_freq.get(ch, 0) < need:
                                valid = False
                                break

                        if valid:
                            survivors.append({
                                "keyword": kw,
                                "period": kw_len,
                                "variant": var_name,
                                "alphabet": alph_name,
                                "ene_start": s1,
                                "bc_start": s2,
                                "needed_cts": needed_cts,
                            })

    elapsed = time.time() - t0

    # ── Results ────────────────────────────────────────────────────────────
    print(f"\nTotal checks: {total_checks:,}")
    print(f"Survivors: {len(survivors)}")
    print(f"Elapsed: {elapsed:.2f}s")
    print()

    # Group by keyword
    kw_counts = Counter(s["keyword"] for s in survivors)
    print("Survivors by keyword:")
    for kw, count in kw_counts.most_common():
        print(f"  {kw:15s}: {count:6d}")

    # Group by keyword+variant+alphabet
    print(f"\nSurvivors by keyword/variant/alphabet:")
    combo_counts = Counter(
        (s["keyword"], s["variant"], s["alphabet"]) for s in survivors
    )
    for (kw, var, alph), count in combo_counts.most_common(30):
        # How many (s1,s2) placements survived?
        print(f"  {kw:15s}/{var:8s}/{alph}: {count:5d} placements")

    # Show specific placements for short keywords (most constraining)
    short_kw_survivors = [s for s in survivors if s["period"] <= 7]
    print(f"\nShort-keyword survivors (period <= 7): {len(short_kw_survivors)}")
    for s in short_kw_survivors[:30]:
        needed_str = "".join(c for _, c in s["needed_cts"])
        print(f"  {s['keyword']:10s} T={s['period']} {s['variant']:8s}/{s['alphabet']} "
              f"ENE@{s['ene_start']:2d} BC@{s['bc_start']:2d} | "
              f"needed_CT: {needed_str}")

    # KEY OUTPUT: for each surviving (keyword, s1, s2), we know exactly
    # which CT chars must appear at specific reduced positions. This
    # constrains the null mask heavily.
    print(f"\n{'=' * 78}")
    if not survivors:
        print("NO SURVIVORS — free-crib periodic consistency impossible")
    else:
        print(f"{len(survivors)} survivors found. These constrain the null mask search.")
        print("Next step: for each survivor, find null masks that place the")
        print("required CT chars at the correct reduced positions.")
    print(f"{'=' * 78}")


if __name__ == "__main__":
    main()
