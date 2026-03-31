#!/usr/bin/env python3
"""
Cipher: Fractionated Morse
Family: fractionation
Status: active
Keyspace: ~425 thematic keywords × 2 alphabets + 1M dictionary words (top 10K)
Last run: 2026-03-31
Best score: 0.0 (crib_score)

Fractionated Morse: PT → Morse → group into trigrams of {dot,dash,x} →
substitute each trigram with a keyed alphabet letter → CT.
Distinct from bifid/trifid (no 5×5 grid). Produces all-alpha output with
naturally flat IC — matches K4's IC below random. Sanborn references Morse.
"""
import sys
import os
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from kryptos.kernel.constants import CT, ALPH, ALPH_IDX, MOD, CRIB_DICT
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.alphabet import keyword_mixed_alphabet

# ── Morse code table ────────────────────────────────────────────────────

MORSE_TABLE = {
    'A': '.-',    'B': '-...',  'C': '-.-.',  'D': '-..',   'E': '.',
    'F': '..-.',  'G': '--.',   'H': '....',  'I': '..',    'J': '.---',
    'K': '-.-',   'L': '.-..',  'M': '--',    'N': '-.',    'O': '---',
    'P': '.--.',  'Q': '--.-',  'R': '.-.',   'S': '...',   'T': '-',
    'U': '..-',   'V': '...-',  'W': '.--',   'X': '-..-',  'Y': '-.--',
    'Z': '--..',
}

REVERSE_MORSE = {v: k for k, v in MORSE_TABLE.items()}

# ── Fractionated Morse trigram table ────────────────────────────────────
# 27 trigrams from {., -, x}^3, exclude 'xxx', leaving 26.
# Standard ordering: enumerate with .=0, -=1, x=2

SYMBOLS = '.', '-', 'x'

TRIGRAMS = []
for a in SYMBOLS:
    for b in SYMBOLS:
        for c in SYMBOLS:
            tri = a + b + c
            if tri != 'xxx':
                TRIGRAMS.append(tri)
assert len(TRIGRAMS) == 26


def build_decrypt_table(keyed_alpha: str) -> dict:
    """Map each CT letter → its trigram using the keyed alphabet."""
    return {keyed_alpha[i]: TRIGRAMS[i] for i in range(26)}


def morse_decode_stream(stream: str) -> str | None:
    """Decode a dot-dash-x stream to plaintext.

    'x' = letter separator, 'xx' = word separator (appears as 'x' at
    trigram boundary + 'x' at next trigram start, or as embedded 'xx').
    Returns None if any Morse sequence is invalid.
    """
    # Split on 'x' to get individual Morse letters
    # 'xx' splits into ['', ''] which we treat as word boundary (space)
    parts = stream.split('x')
    result = []
    i = 0
    while i < len(parts):
        part = parts[i]
        if part == '':
            # Skip empty parts (word boundaries) — we only care about letters
            i += 1
            continue
        if part in REVERSE_MORSE:
            result.append(REVERSE_MORSE[part])
        else:
            return None  # Invalid Morse sequence
        i += 1
    if not result:
        return None
    return ''.join(result)


def decrypt_fractionated_morse(ct: str, keyed_alpha: str) -> str | None:
    """Decrypt: CT letter → trigram → Morse stream → plaintext."""
    table = build_decrypt_table(keyed_alpha)
    # Convert each CT letter to its trigram
    trigram_stream = ''.join(table[c] for c in ct)
    # Decode the Morse stream
    return morse_decode_stream(trigram_stream)


def test_keyword(keyword: str) -> tuple[float, str, str] | None:
    """Test a single keyword. Returns (score, pt, method) or None."""
    try:
        alpha = keyword_mixed_alphabet(keyword)
    except (ValueError, AssertionError):
        return None

    pt = decrypt_fractionated_morse(CT, alpha)
    if pt is None:
        return None

    # Fractionated Morse produces variable-length output.
    # If output is too short to cover crib positions, score what we can.
    if len(pt) < 74:
        # Too short to evaluate both cribs — check partial
        if len(pt) < 22:
            return None  # Too short for any crib
        # Score with what we have
        sb = score_candidate(pt.ljust(97, 'X'))  # Pad to score
    else:
        sb = score_candidate(pt[:97] if len(pt) > 97 else pt.ljust(97, 'X'))

    score = float(sb.crib_score)
    method = f"FracMorse kw={keyword} alpha={alpha[:10]}... ptlen={len(pt)}"
    return (score, pt[:97], method)


def test_keyword_wrapper(args):
    """Wrapper for multiprocessing."""
    keyword = args
    return test_keyword(keyword)


def load_keywords():
    """Load thematic keywords + top dictionary words."""
    keywords = set()

    # Thematic keywords
    tk_path = os.path.join(_ROOT, "wordlists", "thematic_keywords.txt")
    if os.path.exists(tk_path):
        with open(tk_path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    keywords.add(line.upper())

    # Top dictionary words (up to 10K)
    dict_path = os.path.join(_ROOT, "wordlists", "english.txt")
    if os.path.exists(dict_path):
        with open(dict_path) as f:
            count = 0
            for line in f:
                word = line.strip().upper()
                if word and word.isalpha() and len(word) >= 3:
                    keywords.add(word)
                    count += 1
                    if count >= 10000:
                        break

    # Also test plain A-Z (no keyword mixing)
    keywords.add("A")  # Will produce standard alphabet

    return sorted(keywords)


def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack contract."""
    keywords = load_keywords()
    results = []
    workers = max(1, cpu_count() - 2)

    print(f"  Testing {len(keywords)} keywords with {workers} workers...")

    with Pool(workers) as pool:
        for result in pool.imap_unordered(test_keyword_wrapper, keywords, chunksize=50):
            if result is not None:
                results.append(result)

    results.sort(key=lambda x: -x[0])
    return results


def main():
    print("=" * 70)
    print("Fractionated Morse — Keyword-Mixed Alphabet Sweep")
    print("=" * 70)
    print(f"CT: {CT[:50]}...")
    print(f"Trigrams: {len(TRIGRAMS)} (excluding 'xxx')")
    print()

    results = attack(CT)

    # Stats
    valid = len(results)
    print(f"\nValid decryptions: {valid}")

    if results:
        print(f"\nTop 10 results:")
        for score, pt, method in results[:10]:
            print(f"  {score:5.1f}  {method}")
            print(f"         pt={pt[:60]}...")

        best = results[0][0]
        # Plaintext length distribution
        lengths = [len(r[1]) for r in results]
        if lengths:
            print(f"\n  PT lengths: min={min(lengths)}, max={max(lengths)}, "
                  f"median={sorted(lengths)[len(lengths)//2]}")
    else:
        best = 0.0

    print(f"\nBest score: {best}/24")
    if best < 10:
        print("VERDICT: NOISE — Fractionated Morse with keyword alphabets does not decrypt K4")
    elif best < 18:
        print("VERDICT: INTERESTING — investigate further")
    else:
        print("VERDICT: SIGNAL — requires detailed analysis!")


if __name__ == "__main__":
    main()
