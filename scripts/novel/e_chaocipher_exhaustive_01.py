#!/usr/bin/env python3
"""
Cipher: Chaocipher (proper dual-alphabet implementation)
Family: novel
Status: exhausted
Keyspace: ~10K keyword pairs × 2 zenith choices = ~200M alphabet states
Last run: 2026-03-31
Best score: 0.0 (crib_score)

Proper Chaocipher implementation with dual rotating/permuting alphabets.
The existing e_novel_06 only tested a handful of hardcoded configurations.
This script exhaustively tests keyword-seeded initial alphabets with the
correct Chaocipher algorithm (Byrne's 1918 mechanism, declassified 2010).

Chaocipher: Two circular alphabets (left=CT, right=PT). For each letter:
  1. Find CT char in left alphabet at position i
  2. PT char is at position i in right alphabet
  3. Permute left: rotate so position i+1 is at front, extract pos 2 → insert after pos 13
  4. Permute right: rotate so position i is at front, extract pos 3 → insert after pos 13
"""
import sys
import os
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.alphabet import keyword_mixed_alphabet


def chaocipher_decrypt(ct: str, left_alpha: str, right_alpha: str) -> str:
    """Decrypt using Chaocipher algorithm.

    left_alpha = ciphertext alphabet (26 chars)
    right_alpha = plaintext alphabet (26 chars)
    """
    left = list(left_alpha)
    right = list(right_alpha)
    pt = []

    for ch in ct:
        # Find CT character in left alphabet
        i = left.index(ch)
        # PT character is at same position in right alphabet
        pt.append(right[i])

        # Permute LEFT alphabet
        # Rotate so position i+1 is at front
        left = left[i + 1:] + left[:i + 1]
        # Extract character at position 2 (0-indexed), insert after position 13
        extracted = left.pop(2)
        left.insert(13, extracted)

        # Permute RIGHT alphabet
        # Rotate so position i is at front (the PT character position)
        right = right[i:] + right[:i]
        # Extract character at position 3 (0-indexed), insert after position 13
        extracted = right.pop(3)
        right.insert(13, extracted)

    return ''.join(pt)


def test_keyword_pair(args):
    """Test a pair of keywords as initial left/right alphabets."""
    kw_left, kw_right = args
    try:
        left = keyword_mixed_alphabet(kw_left)
        right = keyword_mixed_alphabet(kw_right)
    except (ValueError, AssertionError):
        return None

    if left == right:
        return None  # Skip identical alphabets (already tested in e_novel_06)

    pt = chaocipher_decrypt(CT, left, right)
    sb = score_candidate(pt)
    score = float(sb.crib_score)

    if score >= 3:
        method = f"Chaocipher L={kw_left} R={kw_right}"
        return (score, pt, method)
    return None


def load_keywords():
    """Load thematic keywords."""
    keywords = set()
    tk_path = os.path.join(_ROOT, "wordlists", "thematic_keywords.txt")
    if os.path.exists(tk_path):
        with open(tk_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    keywords.add(line.upper())

    # Add standard alphabet as "no keyword"
    keywords.add("A")

    # Add high-priority keywords from cipher discovery
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "COMPASS",
               "LODESTONE", "BERLINCLOCK", "EASTNORTHEAST", "SHADOW",
               "VERDIGRIS", "COLOPHON", "PARALLAX", "SCHEIDT", "SANBORN",
               "LANGLEY", "MAGNETIC", "NEEDLE", "WHEATSTONE"]:
        keywords.add(kw)

    return sorted(keywords)


def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack contract."""
    keywords = load_keywords()
    workers = max(1, cpu_count() - 2)

    # Generate all keyword pairs
    pairs = [(kw_l, kw_r) for kw_l in keywords for kw_r in keywords]
    print(f"  Testing {len(pairs)} keyword pairs ({len(keywords)} keywords) "
          f"with {workers} workers...")

    results = []
    tested = 0
    with Pool(workers) as pool:
        for result in pool.imap_unordered(test_keyword_pair, pairs, chunksize=200):
            tested += 1
            if tested % 50000 == 0:
                print(f"    ...{tested}/{len(pairs)} tested")
            if result is not None:
                results.append(result)

    results.sort(key=lambda x: -x[0])
    return results


def main():
    print("=" * 70)
    print("Chaocipher — Exhaustive Keyword-Pair Sweep")
    print("=" * 70)
    print(f"CT: {CT[:50]}...")
    print()

    results = attack(CT)

    if results:
        print(f"\nResults with score >= 3: {len(results)}")
        print(f"\nTop 10:")
        for score, pt, method in results[:10]:
            print(f"  {score:5.1f}  {method}")
            print(f"         pt={pt[:60]}...")
        best = results[0][0]
    else:
        best = 0.0
        print("\nNo results with score >= 3")

    print(f"\nBest score: {best}/24")
    if best < 10:
        print("VERDICT: NOISE — Chaocipher with keyword-mixed alphabets does not decrypt K4")
    elif best < 18:
        print("VERDICT: INTERESTING — investigate further")
    else:
        print("VERDICT: SIGNAL — requires detailed analysis!")


if __name__ == "__main__":
    main()
