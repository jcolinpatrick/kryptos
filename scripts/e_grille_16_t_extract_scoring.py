#!/usr/bin/env python3
"""
E-GRILLE-16: Score the T-position tableau extract as candidate real CT

The 97-char extract from overlaying T-position grille on the KA tableau
(pass 1 + 180° rotation pass 2) produced exactly 97 characters — K4's length.

This script treats that extract as the "real ciphertext" (unscrambled K4)
and tries every reasonable decryption against it:
  - Vigenère / Beaufort / Variant Beaufort
  - AZ and KA alphabets
  - All keywords: KRYPTOS, PALIMPSEST, ABSCISSA, plus single letters A-Z
  - Score each result with the full kernel scoring pipeline
  - Also try the extract as a permutation index for K4
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from collections import Counter
from itertools import product

# ─── The 97-char T-position tableau extract ───────────────────────────────────
# Pass 1 (original T-holes, row-major on tableau): 52 chars
PASS1 = "RHUFWDNRBAXQUEFHTIPQLVTFRWBLQBFTYODNVPTAWCTGHJZKGBCO"
# Pass 2 (180°-rotated T-holes, row-major on tableau): 45 chars
PASS2 = "SJPGIJZEQSVZKADNXRLUCFUSLZACHZILMBCOVUYDSLBIY"
# Combined
EXTRACT_97 = PASS1 + PASS2

# K4 carved text
K4_CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

# Known cribs (0-indexed in carved K4)
CRIB1_POS, CRIB1_TEXT = 21, "EASTNORTHEAST"
CRIB2_POS, CRIB2_TEXT = 63, "BERLINCLOCK"

# Alphabets
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Keywords to try
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA",
    "BERLINCLOCK", "EASTNORTHEAST",
    "LAYERTWO", "SANBORN", "SCHEIDT",
    "SHADOW", "LIGHT", "POSITION",
    "EQUINOX", "CLOCK", "BERLIN",
]
# Also try single-letter keys (Caesar shifts)
KEYWORDS += [chr(c) for c in range(ord('A'), ord('Z') + 1)]


def vig_decrypt(ct, key, alph=AZ):
    """Vigenère: PT = (CT - KEY) mod N"""
    n = len(alph)
    return ''.join(alph[(alph.index(c) - alph.index(key[i % len(key)])) % n]
                   for i, c in enumerate(ct))


def beaufort_decrypt(ct, key, alph=AZ):
    """Beaufort: PT = (KEY - CT) mod N"""
    n = len(alph)
    return ''.join(alph[(alph.index(key[i % len(key)]) - alph.index(c)) % n]
                   for i, c in enumerate(ct))


def var_beaufort_decrypt(ct, key, alph=AZ):
    """Variant Beaufort: PT = (CT + KEY) mod N"""
    n = len(alph)
    return ''.join(alph[(alph.index(c) + alph.index(key[i % len(key)])) % n]
                   for i, c in enumerate(ct))


def ic(text):
    """Index of coincidence."""
    freq = Counter(text)
    n = len(text)
    if n < 2:
        return 0.0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


def count_english_words(text, min_len=4):
    """Count English word fragments (simple check)."""
    words = [
        "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL", "CAN",
        "HER", "WAS", "ONE", "OUR", "OUT", "DAY", "HAD", "HAS", "HIS",
        "HOW", "ITS", "MAY", "NEW", "NOW", "OLD", "SEE", "WAY", "WHO",
        "DID", "GET", "LET", "SAY", "SHE", "TOO", "USE",
        "THAT", "WITH", "HAVE", "THIS", "WILL", "YOUR", "FROM",
        "THEY", "BEEN", "CALL", "COME", "EACH", "MAKE", "LIKE",
        "LONG", "LOOK", "MANY", "SOME", "THAN", "THEM", "THEN",
        "WHAT", "WHEN", "WERE", "SAID", "EAST", "WEST", "NORTH", "SOUTH",
        "BERLIN", "CLOCK", "COULD", "WOULD", "SHOULD", "SLOWLY",
        "UNDERGROUND", "DESPERATE", "ILLUSION", "SHADOW", "LIGHT",
        "BETWEEN", "SUBTLE", "ABSENCE", "BURIED", "UNKNOWN",
        "POSITION", "LAYER", "PALIMPSEST",
    ]
    hits = []
    for w in words:
        if len(w) >= min_len and w in text:
            hits.append(w)
    return hits


def score_crib_match(pt, crib_pos, crib_text):
    """Check how many crib positions match if we assume cribs apply to THIS text."""
    matches = 0
    for i, expected in enumerate(crib_text):
        pos = crib_pos + i
        if pos < len(pt) and pt[pos] == expected:
            matches += 1
    return matches


def try_as_permutation(extract, k4, method="rank"):
    """Try using the extract letters as a permutation index to reorder K4."""
    if len(extract) != len(k4):
        return None

    if method == "rank":
        # Rank letters: (letter_value, position) → stable sort
        indexed = [(ord(c) - ord('A'), i) for i, c in enumerate(extract)]
        perm = sorted(range(len(extract)), key=lambda i: indexed[i])
        return ''.join(k4[p] for p in perm)
    elif method == "rank_reverse":
        indexed = [(ord(c) - ord('A'), i) for i, c in enumerate(extract)]
        perm = sorted(range(len(extract)), key=lambda i: indexed[i])
        inv_perm = [0] * len(perm)
        for i, p in enumerate(perm):
            inv_perm[p] = i
        return ''.join(k4[inv_perm[i]] for i in range(len(k4)))
    return None


def main():
    print("=" * 70)
    print("  E-GRILLE-16: T-Position Extract — Full Scoring Pipeline")
    print("=" * 70)
    print(f"\n  Extract (97 chars): {EXTRACT_97}")
    print(f"  K4 carved (97 chars): {K4_CT}")
    print(f"  IC of extract: {ic(EXTRACT_97):.4f}")
    print(f"  IC of K4: {ic(K4_CT):.4f}")

    # ─── Part A: Treat extract AS the real CT, decrypt with keys ──────────
    print(f"\n{'='*70}")
    print(f"  PART A: Decrypt extract with Vig/Beaufort × keywords × alphabets")
    print(f"{'='*70}")

    best_results = []

    for key in KEYWORDS:
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            # Skip if key has letters not in alphabet
            if not all(c in alph for c in key):
                continue

            for dec_name, dec_fn in [("Vig", vig_decrypt),
                                      ("Beau", beaufort_decrypt),
                                      ("VBeau", var_beaufort_decrypt)]:
                pt = dec_fn(EXTRACT_97, key, alph)
                pt_ic = ic(pt)
                words = count_english_words(pt)

                # Score cribs at their K4 positions (in case they transfer)
                c1_score = score_crib_match(pt, CRIB1_POS, CRIB1_TEXT)
                c2_score = score_crib_match(pt, CRIB2_POS, CRIB2_TEXT)
                total_crib = c1_score + c2_score

                # Interesting if: IC > 0.05, or crib > 2, or English words found
                interesting = pt_ic > 0.050 or total_crib > 2 or len(words) > 0

                if interesting:
                    best_results.append({
                        'key': key, 'alph': alph_name, 'method': dec_name,
                        'pt': pt, 'ic': pt_ic, 'crib': total_crib,
                        'c1': c1_score, 'c2': c2_score, 'words': words
                    })

    # Sort by IC + crib score
    best_results.sort(key=lambda r: (r['crib'], r['ic']), reverse=True)

    print(f"\n  Tested {len(KEYWORDS)} keywords × 2 alphabets × 3 methods = "
          f"{len(KEYWORDS)*2*3} configs")
    print(f"  Interesting results: {len(best_results)}")

    for i, r in enumerate(best_results[:30]):
        print(f"\n  [{i+1}] {r['method']}/{r['key']}/{r['alph']}  "
              f"IC={r['ic']:.4f}  Crib={r['crib']}/24 ({r['c1']}+{r['c2']})")
        if r['words']:
            print(f"       Words: {r['words']}")
        print(f"       PT: {r['pt']}")

    # ─── Part B: Try extract as unscrambling permutation for K4 ───────────
    print(f"\n{'='*70}")
    print(f"  PART B: Extract as unscrambling permutation for K4")
    print(f"{'='*70}")

    for method in ["rank", "rank_reverse"]:
        unscrambled = try_as_permutation(EXTRACT_97, K4_CT, method)
        if unscrambled:
            print(f"\n  Method: {method}")
            print(f"  Unscrambled: {unscrambled}")
            print(f"  IC: {ic(unscrambled):.4f}")

            # Try decrypting the unscrambled text
            for key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
                    if not all(c in alph for c in key):
                        continue
                    for dec_name, dec_fn in [("Vig", vig_decrypt),
                                              ("Beau", beaufort_decrypt)]:
                        pt = dec_fn(unscrambled, key, alph)
                        pt_ic = ic(pt)
                        c1 = score_crib_match(pt, CRIB1_POS, CRIB1_TEXT)
                        c2 = score_crib_match(pt, CRIB2_POS, CRIB2_TEXT)
                        words = count_english_words(pt)

                        # Also check for cribs ANYWHERE in the text
                        anywhere_hits = []
                        for crib in ["EAST", "NORTH", "BERLIN", "CLOCK"]:
                            if crib in pt:
                                anywhere_hits.append(crib)

                        if pt_ic > 0.045 or (c1 + c2) > 1 or words or anywhere_hits:
                            print(f"    {dec_name}/{key}/{alph_name}: IC={pt_ic:.4f} "
                                  f"Crib={c1+c2}/24 Words={words} Anywhere={anywhere_hits}")
                            print(f"    PT: {pt}")

    # ─── Part C: Free crib search — do cribs appear ANYWHERE? ─────────────
    print(f"\n{'='*70}")
    print(f"  PART C: Free crib search (cribs anywhere in decrypted extract)")
    print(f"{'='*70}")

    free_hits = []
    for key in KEYWORDS:
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            if not all(c in alph for c in key):
                continue
            for dec_name, dec_fn in [("Vig", vig_decrypt),
                                      ("Beau", beaufort_decrypt),
                                      ("VBeau", var_beaufort_decrypt)]:
                pt = dec_fn(EXTRACT_97, key, alph)
                for crib in ["EASTNORTHEAST", "BERLINCLOCK", "NORTHEAST",
                              "BERLIN", "CLOCK", "EAST"]:
                    if crib in pt:
                        free_hits.append((crib, dec_name, key, alph_name,
                                          pt.index(crib), pt))

    if free_hits:
        print(f"\n  *** CRIB HITS FOUND: {len(free_hits)} ***")
        for crib, dec, key, alph, pos, pt in free_hits:
            print(f"    '{crib}' at pos {pos}: {dec}/{key}/{alph}")
            print(f"    PT: {pt}")
    else:
        print(f"\n  No crib fragments found in any decryption.")

    # ─── Part D: Differential analysis — extract vs K4 ────────────────────
    print(f"\n{'='*70}")
    print(f"  PART D: Differential analysis (extract vs K4)")
    print(f"{'='*70}")

    # Letter frequency comparison
    ext_freq = Counter(EXTRACT_97)
    k4_freq = Counter(K4_CT)

    print(f"\n  Letter frequency comparison (Extract vs K4):")
    print(f"  {'Letter':>6} {'Extract':>8} {'K4':>8} {'Diff':>8}")
    for c in AZ:
        ef = ext_freq.get(c, 0)
        kf = k4_freq.get(c, 0)
        diff = ef - kf
        marker = " ***" if abs(diff) >= 3 else ""
        print(f"  {c:>6} {ef:>8} {kf:>8} {diff:>+8}{marker}")

    # Check if extract is an anagram of K4
    if ext_freq == k4_freq:
        print(f"\n  *** EXTRACT IS AN EXACT ANAGRAM OF K4! ***")
    else:
        print(f"\n  Extract is NOT an anagram of K4.")
        diff_letters = {}
        for c in AZ:
            d = ext_freq.get(c, 0) - k4_freq.get(c, 0)
            if d != 0:
                diff_letters[c] = d
        print(f"  Differences: {diff_letters}")

    # ─── Part E: Use kernel scoring if available ──────────────────────────
    print(f"\n{'='*70}")
    print(f"  PART E: Kernel scoring pipeline")
    print(f"{'='*70}")

    try:
        from kryptos.kernel.constants import CT, CRIBS, BEAN_EQ, BEAN_INEQ
        from kryptos.kernel.scoring.aggregate import score_candidate

        print(f"  Kernel loaded successfully.")
        print(f"  CT from kernel: {CT[:20]}... (len={len(CT)})")

        # Score the extract directly as if it were plaintext
        # (score_candidate expects a plaintext candidate)
        try:
            score = score_candidate(EXTRACT_97)
            print(f"  Direct score (extract as PT): {score}")
        except Exception as e:
            print(f"  Direct scoring failed: {e}")

        # Score decrypted versions
        print(f"\n  Scoring top decryptions through kernel:")
        for key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
                if not all(c in alph for c in key):
                    continue
                for dec_name, dec_fn in [("Vig", vig_decrypt),
                                          ("Beau", beaufort_decrypt)]:
                    pt = dec_fn(EXTRACT_97, key, alph)
                    try:
                        score = score_candidate(pt)
                        print(f"    {dec_name}/{key}/{alph_name}: {score}")
                    except Exception as e:
                        print(f"    {dec_name}/{key}/{alph_name}: error: {e}")

    except ImportError as e:
        print(f"  Kernel not available: {e}")
        print(f"  Falling back to manual scoring...")

    print(f"\n{'='*70}")
    print(f"  DONE")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
