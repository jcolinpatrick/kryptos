#!/usr/bin/env python3
"""E-S-17: Steganographic / extraction pattern analysis.

Tests whether K4 CT contains hidden structure when read in non-standard ways:
1. Every Nth character (skip cipher)
2. Acrostic patterns (first letter of each group)
3. Specific position extractions (primes, Fibonacci, squares, etc.)
4. Character-conditional extraction (only positions where CT is vowel, etc.)
5. Digram and trigram pattern matching against English
6. Position-based word extraction (try to form words from CT subsequences)
7. Anagram detection on CT segments

Also checks: do the known plaintext fragments appear ELSEWHERE in CT
when different extraction patterns are applied?
"""

import json
import os
import sys
import time
from collections import Counter

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN

# Load dictionary
DICT_PATH = os.path.join(os.path.dirname(__file__), '..', 'wordlists', 'english.txt')
if os.path.exists(DICT_PATH):
    with open(DICT_PATH) as f:
        WORDS = set(w.strip().upper() for w in f if len(w.strip()) >= 4)
    print(f"Dictionary loaded: {len(WORDS)} words (length ≥ 4)")
else:
    WORDS = set()
    print("Dictionary not found!")

# Short words for substring matching
SHORT_WORDS = set(w for w in WORDS if 4 <= len(w) <= 8)
LONG_WORDS = set(w for w in WORDS if len(w) >= 8)


def find_words_in_text(text, min_len=4):
    """Find all English words that appear as substrings."""
    found = []
    for length in range(min_len, min(len(text) + 1, 15)):
        for start in range(len(text) - length + 1):
            substr = text[start:start + length]
            if substr in WORDS:
                found.append((start, substr))
    return found


def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


def main():
    t0 = time.time()

    print("=" * 60)
    print("E-S-17: Extraction Pattern Analysis")
    print("=" * 60)
    print(f"CT: {CT}")
    print(f"Length: {CT_LEN}")
    print()

    all_results = {}

    # ═══ Phase 1: Skip patterns ═══════════════════════════════════════════
    print("Phase 1: Every Nth character (skip patterns)")
    print("-" * 40)

    skip_results = []
    for n in range(2, 25):
        for start in range(n):
            extracted = ''.join(CT[i] for i in range(start, CT_LEN, n))
            words = find_words_in_text(extracted)
            if words:
                # Filter for interesting words (> 5 chars)
                long_words = [w for _, w in words if len(w) >= 5]
                if long_words:
                    entry = {
                        "pattern": f"every_{n}th_start_{start}",
                        "extracted": extracted,
                        "words_found": long_words[:10],
                        "n_words": len(words),
                    }
                    skip_results.append(entry)
                    print(f"  n={n} start={start}: {extracted[:30]}... "
                          f"→ words: {long_words[:5]}")

    all_results["skip_patterns"] = skip_results
    print(f"  Patterns with words ≥5 chars: {len(skip_results)}")

    # ═══ Phase 2: Position-based extraction ════════════════════════════════
    print("\nPhase 2: Position-based extraction (primes, fib, squares, etc.)")
    print("-" * 40)

    position_patterns = {
        "primes": [i for i in range(CT_LEN) if is_prime(i)],
        "composites": [i for i in range(CT_LEN) if i >= 2 and not is_prime(i)],
        "fibonacci": [],
        "squares": [i*i for i in range(10) if i*i < CT_LEN],
        "triangular": [],
        "even": list(range(0, CT_LEN, 2)),
        "odd": list(range(1, CT_LEN, 2)),
        "mod3_0": list(range(0, CT_LEN, 3)),
        "mod3_1": list(range(1, CT_LEN, 3)),
        "mod3_2": list(range(2, CT_LEN, 3)),
        "mod7_0": list(range(0, CT_LEN, 7)),
        "mod7_1": list(range(1, CT_LEN, 7)),
        "mod7_2": list(range(2, CT_LEN, 7)),
        "mod7_3": list(range(3, CT_LEN, 7)),
        "mod7_4": list(range(4, CT_LEN, 7)),
        "mod7_5": list(range(5, CT_LEN, 7)),
        "mod7_6": list(range(6, CT_LEN, 7)),
    }

    # Fibonacci positions
    a, b = 0, 1
    fib_pos = []
    while a < CT_LEN:
        fib_pos.append(a)
        a, b = b, a + b
    position_patterns["fibonacci"] = fib_pos

    # Triangular
    n = 0
    while n * (n + 1) // 2 < CT_LEN:
        position_patterns["triangular"].append(n * (n + 1) // 2)
        n += 1

    pos_results = []
    for name, positions in position_patterns.items():
        if not positions:
            continue
        extracted = ''.join(CT[i] for i in positions if i < CT_LEN)
        words = find_words_in_text(extracted)
        long_words = [w for _, w in words if len(w) >= 5]
        if long_words:
            entry = {
                "pattern": name,
                "positions": positions[:20],
                "extracted": extracted[:50],
                "words_found": long_words[:10],
            }
            pos_results.append(entry)
            print(f"  {name}: {extracted[:30]}... → {long_words[:5]}")

    all_results["position_patterns"] = pos_results

    # ═══ Phase 3: Character-conditional extraction ═════════════════════════
    print("\nPhase 3: Character-conditional extraction")
    print("-" * 40)

    # Positions where CT is a vowel
    vowels = set("AEIOU")
    consonants = set("BCDFGHJKLMNPQRSTVWXYZ")

    cond_patterns = {
        "after_vowel": [i+1 for i in range(CT_LEN-1) if CT[i] in vowels],
        "after_consonant": [i+1 for i in range(CT_LEN-1) if CT[i] in consonants],
        "before_vowel": [i for i in range(CT_LEN-1) if CT[i+1] in vowels],
        "vowel_positions": [i for i in range(CT_LEN) if CT[i] in vowels],
        "consonant_positions": [i for i in range(CT_LEN) if CT[i] in consonants],
        "repeated_char": [i for i in range(CT_LEN-1) if CT[i] == CT[i+1]],
        "between_doubles": [],
    }

    # Positions between doubled characters
    for i in range(CT_LEN - 2):
        if CT[i] == CT[i+2]:
            cond_patterns["between_doubles"].append(i + 1)

    for name, positions in cond_patterns.items():
        if not positions:
            continue
        extracted = ''.join(CT[i] for i in positions if i < CT_LEN)
        words = find_words_in_text(extracted)
        long_words = [w for _, w in words if len(w) >= 5]
        if long_words:
            print(f"  {name}: {extracted[:30]}... → {long_words[:5]}")

    # ═══ Phase 4: Word-finding in raw CT ═══════════════════════════════════
    print("\nPhase 4: English words in raw CT")
    print("-" * 40)

    ct_words = find_words_in_text(CT, min_len=4)
    ct_words.sort(key=lambda x: -len(x[1]))
    print(f"  Words found in CT: {len(ct_words)}")
    for pos, word in ct_words[:15]:
        print(f"    pos {pos:>2}: {word}")

    all_results["ct_raw_words"] = [(p, w) for p, w in ct_words]

    # ═══ Phase 5: Reversed CT ══════════════════════════════════════════════
    print("\nPhase 5: Reversed CT")
    print("-" * 40)

    ct_rev = CT[::-1]
    print(f"  Reversed: {ct_rev}")
    rev_words = find_words_in_text(ct_rev, min_len=4)
    rev_words.sort(key=lambda x: -len(x[1]))
    print(f"  Words found: {len(rev_words)}")
    for pos, word in rev_words[:10]:
        print(f"    pos {pos:>2}: {word}")

    all_results["ct_reversed_words"] = [(p, w) for p, w in rev_words]

    # ═══ Phase 6: Letter frequency analysis ════════════════════════════════
    print("\nPhase 6: Letter frequency and patterns")
    print("-" * 40)

    freq = Counter(CT)
    sorted_freq = freq.most_common()
    print(f"  Frequency: {' '.join(f'{c}:{n}' for c, n in sorted_freq[:10])}")

    # Unique letters
    print(f"  Unique letters: {len(freq)}/26 ({sorted(freq.keys())})")

    # Bigram frequencies
    bigrams = Counter(CT[i:i+2] for i in range(CT_LEN - 1))
    print(f"  Most common bigrams: {bigrams.most_common(10)}")

    # Repeated bigrams with positions
    for bg, count in bigrams.most_common(5):
        positions = [i for i in range(CT_LEN - 1) if CT[i:i+2] == bg]
        print(f"    {bg}: positions {positions}")

    # ═══ Phase 7: "WHATSTHEPOINT" search ═══════════════════════════════════
    print("\nPhase 7: Embedded clue search")
    print("-" * 40)

    # Sanborn said "What's the point?" is embedded. Test:
    # 1. Is "THEPOINT" or "POINT" in CT? (No)
    # 2. Is it in any skip pattern?
    # 3. Is it formed by specific extraction?

    targets = ["POINT", "THEPOINT", "WHATSTHEPOINT", "THATSTHEPOINT",
               "MESSAGE", "DELIVER", "EGYPT", "BERLIN", "CAIRO",
               "TOMB", "CARTER", "CANDLE", "WALL"]

    for target in targets:
        if target in CT:
            print(f"  '{target}' found directly in CT at pos {CT.index(target)}!")

        # Check skip patterns
        for n in range(2, 20):
            for start in range(n):
                extracted = ''.join(CT[i] for i in range(start, CT_LEN, n))
                if target in extracted:
                    pos = extracted.index(target)
                    print(f"  '{target}' found in every-{n}th-from-{start} at pos {pos}")

        # Check reversed CT
        if target in ct_rev:
            print(f"  '{target}' found in reversed CT at pos {ct_rev.index(target)}")

    # ═══ Phase 8: Digram substitution check ═══════════════════════════════
    print("\nPhase 8: CT digram → PT letter mapping")
    print("-" * 40)

    # What if pairs of CT letters encode single PT letters?
    # Test: take CT in pairs, see if they map to English via any consistent rule
    if CT_LEN % 2 == 1:  # 97 is odd
        # Try with overlap and without
        for offset in [0, 1]:
            pairs = [CT[i:i+2] for i in range(offset, CT_LEN - 1, 2)]
            unique_pairs = set(pairs)
            print(f"  Offset {offset}: {len(pairs)} pairs, {len(unique_pairs)} unique")

    # ═══ Summary ═══════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print(f"\n{'=' * 60}")
    print(f"  SUMMARY")
    print(f"{'=' * 60}")
    print(f"  Time: {elapsed:.3f}s")
    print(f"  Skip patterns with words ≥5: {len(skip_results)}")
    print(f"  Position patterns with words ≥5: {len(pos_results)}")
    print(f"  Raw CT words (≥4 chars): {len(ct_words)}")
    print(f"  Reversed CT words: {len(rev_words)}")

    # Check if any extraction produced notably long words
    max_word_len = 0
    max_word = ""
    max_source = ""
    for entry in skip_results + pos_results:
        for w in entry.get("words_found", []):
            if len(w) > max_word_len:
                max_word_len = len(w)
                max_word = w
                max_source = entry.get("pattern", "?")

    for _, w in ct_words:
        if len(w) > max_word_len:
            max_word_len = len(w)
            max_word = w
            max_source = "raw_ct"

    print(f"\n  Longest word found: '{max_word}' ({max_word_len} chars) from {max_source}")

    # Verdict
    if max_word_len >= 8 and max_source != "raw_ct":
        verdict = "INVESTIGATE"
    else:
        verdict = "NO HIDDEN ENGLISH"

    print(f"  VERDICT: {verdict}")

    # Write results
    os.makedirs("results", exist_ok=True)
    outpath = "results/e_s_17_extraction_patterns.json"
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "E-S-17",
            "hypothesis": "CT contains hidden English via extraction patterns",
            "total_time_s": round(elapsed, 3),
            "verdict": verdict,
            "skip_patterns": skip_results,
            "position_patterns": pos_results,
            "ct_words": [(p, w) for p, w in ct_words[:20]],
            "reversed_words": [(p, w) for p, w in rev_words[:20]],
            "max_word": max_word,
            "max_word_source": max_source,
        }, f, indent=2, default=str)

    print(f"\n  Artifacts: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_17_extraction_patterns.py")
    print(f"\nRESULT: max_word='{max_word}' verdict={verdict}")


if __name__ == "__main__":
    main()
