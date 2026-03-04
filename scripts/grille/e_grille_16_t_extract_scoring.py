#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: grille
Status: active
Keyspace: see implementation
Last run:
Best score:
"""
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


def attack(ciphertext, **params):
    """Standard attack interface. Returns [(score, plaintext, method_description), ...]"""
    extract = params.get("extract", EXTRACT_97)
    k4_ct = ciphertext

    all_results = []

    # ─── Part A: Treat extract AS the real CT, decrypt with keys ──────────
    for key in KEYWORDS:
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            if not all(c in alph for c in key):
                continue

            for dec_name, dec_fn in [("Vig", vig_decrypt),
                                      ("Beau", beaufort_decrypt),
                                      ("VBeau", var_beaufort_decrypt)]:
                pt = dec_fn(extract, key, alph)
                pt_ic = ic(pt)
                words = count_english_words(pt)

                c1_score = score_crib_match(pt, CRIB1_POS, CRIB1_TEXT)
                c2_score = score_crib_match(pt, CRIB2_POS, CRIB2_TEXT)
                total_crib = c1_score + c2_score

                interesting = pt_ic > 0.050 or total_crib > 2 or len(words) > 0

                if interesting:
                    method = (f"PartA extract_decrypt {dec_name}/{key}/{alph_name} "
                              f"IC={pt_ic:.4f} crib={total_crib}/24")
                    all_results.append((float(total_crib), pt, method))

    # ─── Part B: Try extract as unscrambling permutation for K4 ───────────
    for perm_method in ["rank", "rank_reverse"]:
        unscrambled = try_as_permutation(extract, k4_ct, perm_method)
        if not unscrambled:
            continue

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

                    anywhere_hits = []
                    for crib in ["EAST", "NORTH", "BERLIN", "CLOCK"]:
                        if crib in pt:
                            anywhere_hits.append(crib)

                    total_crib = c1 + c2
                    if pt_ic > 0.045 or total_crib > 1 or anywhere_hits:
                        method = (f"PartB perm_{perm_method} {dec_name}/{key}/{alph_name} "
                                  f"IC={pt_ic:.4f} crib={total_crib}/24 anywhere={anywhere_hits}")
                        all_results.append((float(total_crib), pt, method))

    # ─── Part C: Free crib search — do cribs appear ANYWHERE? ─────────────
    for key in KEYWORDS:
        for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
            if not all(c in alph for c in key):
                continue
            for dec_name, dec_fn in [("Vig", vig_decrypt),
                                      ("Beau", beaufort_decrypt),
                                      ("VBeau", var_beaufort_decrypt)]:
                pt = dec_fn(extract, key, alph)
                for crib in ["EASTNORTHEAST", "BERLINCLOCK", "NORTHEAST",
                              "BERLIN", "CLOCK", "EAST"]:
                    if crib in pt:
                        crib_pos = pt.index(crib)
                        method = (f"PartC free_crib '{crib}' at pos {crib_pos} "
                                  f"{dec_name}/{key}/{alph_name}")
                        # Score by crib length (longer = more significant)
                        all_results.append((float(len(crib)), pt, method))

    # ─── Part E: Kernel scoring if available ──────────────────────────────
    try:
        from kryptos.kernel.scoring.aggregate import score_candidate

        # Score the extract directly as if it were plaintext
        try:
            score = score_candidate(extract)
            crib_score = getattr(score, 'crib_score', 0)
            method = f"PartE kernel_direct extract_as_PT crib={crib_score}"
            all_results.append((float(crib_score), extract, method))
        except Exception:
            pass

        # Score decrypted versions
        for key in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
            for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
                if not all(c in alph for c in key):
                    continue
                for dec_name, dec_fn in [("Vig", vig_decrypt),
                                          ("Beau", beaufort_decrypt)]:
                    pt = dec_fn(extract, key, alph)
                    try:
                        score = score_candidate(pt)
                        crib_score = getattr(score, 'crib_score', 0)
                        method = (f"PartE kernel {dec_name}/{key}/{alph_name} "
                                  f"crib={crib_score}")
                        all_results.append((float(crib_score), pt, method))
                    except Exception:
                        pass
    except ImportError:
        pass

    # Sort by score descending
    all_results.sort(key=lambda r: r[0], reverse=True)
    return all_results


def main():
    print("=" * 70)
    print("  E-GRILLE-16: T-Position Extract — Full Scoring Pipeline")
    print("=" * 70)
    print(f"\n  Extract (97 chars): {EXTRACT_97}")
    print(f"  K4 carved (97 chars): {K4_CT}")
    print(f"  IC of extract: {ic(EXTRACT_97):.4f}")
    print(f"  IC of K4: {ic(K4_CT):.4f}")

    results = attack(K4_CT, extract=EXTRACT_97)

    # ─── Print Part A results ─────────────────────────────────────────────
    part_a = [r for r in results if r[2].startswith("PartA")]
    print(f"\n{'='*70}")
    print(f"  PART A: Decrypt extract with Vig/Beaufort x keywords x alphabets")
    print(f"{'='*70}")
    print(f"\n  Tested {len(KEYWORDS)} keywords x 2 alphabets x 3 methods = "
          f"{len(KEYWORDS)*2*3} configs")
    print(f"  Interesting results: {len(part_a)}")

    for i, (score, pt, method) in enumerate(part_a[:30]):
        print(f"\n  [{i+1}] {method}")
        print(f"       PT: {pt}")

    # ─── Print Part B results ─────────────────────────────────────────────
    part_b = [r for r in results if r[2].startswith("PartB")]
    print(f"\n{'='*70}")
    print(f"  PART B: Extract as unscrambling permutation for K4")
    print(f"{'='*70}")

    for score, pt, method in part_b:
        print(f"    {method}")
        print(f"    PT: {pt}")

    # ─── Print Part C results ─────────────────────────────────────────────
    part_c = [r for r in results if r[2].startswith("PartC")]
    print(f"\n{'='*70}")
    print(f"  PART C: Free crib search (cribs anywhere in decrypted extract)")
    print(f"{'='*70}")

    if part_c:
        print(f"\n  *** CRIB HITS FOUND: {len(part_c)} ***")
        for score, pt, method in part_c:
            print(f"    {method}")
            print(f"    PT: {pt}")
    else:
        print(f"\n  No crib fragments found in any decryption.")

    # ─── Part D: Differential analysis — extract vs K4 (no scoring) ───────
    print(f"\n{'='*70}")
    print(f"  PART D: Differential analysis (extract vs K4)")
    print(f"{'='*70}")

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

    # ─── Print Part E results ─────────────────────────────────────────────
    part_e = [r for r in results if r[2].startswith("PartE")]
    print(f"\n{'='*70}")
    print(f"  PART E: Kernel scoring pipeline")
    print(f"{'='*70}")

    if part_e:
        for score, pt, method in part_e:
            print(f"    {method}")
    else:
        print(f"  Kernel not available or no results.")

    # ─── Overall summary ──────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  SUMMARY: Top 10 results across all parts")
    print(f"{'='*70}")

    for i, (score, pt, method) in enumerate(results[:10]):
        print(f"  [{i+1}] score={score:.1f} | {method}")
        print(f"       PT: {pt[:60]}...")

    print(f"\n{'='*70}")
    print(f"  DONE")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
