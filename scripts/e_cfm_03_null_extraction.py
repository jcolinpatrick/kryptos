#!/usr/bin/env python3
"""E-CFM-03: Null cipher / steganographic extraction patterns.

[HYPOTHESIS] K4 CT may be cover text with the real message hidden via a
selection rule — not a mathematical decryption. Tests extraction patterns:
  1. Every Nth letter (N=2..20)
  2. Row-start and row-end acrostics (using known sculpture row widths)
  3. Fibonacci/prime-indexed positions
  4. Self-referential: positions encoded by the letters themselves
  5. Diagonal reads from grids with padding
"""
import sys
import os
import string

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX

# ── English word check (simple) ──────────────────────────────────────────

COMMON_WORDS = set()
WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "wordlists", "english.txt")
if os.path.exists(WORDLIST_PATH):
    with open(WORDLIST_PATH) as f:
        for line in f:
            w = line.strip().upper()
            if 3 <= len(w) <= 15:
                COMMON_WORDS.add(w)
    print(f"Loaded {len(COMMON_WORDS)} words from wordlist")
else:
    # Fallback minimal set
    COMMON_WORDS = {"THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL",
                    "HER", "WAS", "ONE", "OUR", "OUT", "HIS", "HAS", "HIM",
                    "HOW", "MAN", "NEW", "NOW", "OLD", "SEE", "WAY", "WHO",
                    "DID", "GET", "LET", "SAY", "SHE", "TOO", "USE", "DAY",
                    "EAST", "NORTH", "WEST", "SOUTH", "BERLIN", "CLOCK",
                    "BETWEEN", "SHADOW", "LIGHT", "UNDER", "GROUND", "LAYER",
                    "SECRET", "HIDDEN", "BURIED", "LOCATION", "COMPASS"}
    print(f"Using fallback wordlist ({len(COMMON_WORDS)} words)")


def find_words(text: str, min_len: int = 3) -> list:
    """Find English words in a text string (greedy, longest first)."""
    found = []
    for wlen in range(min(len(text), 15), min_len - 1, -1):
        for start in range(len(text) - wlen + 1):
            substr = text[start:start + wlen]
            if substr in COMMON_WORDS:
                found.append((start, substr))
    # Deduplicate overlapping (keep longest)
    used = set()
    result = []
    for start, word in sorted(found, key=lambda x: -len(x[1])):
        positions = set(range(start, start + len(word)))
        if not positions & used:
            result.append((start, word))
            used |= positions
    return sorted(result)


def word_coverage(text: str, min_len: int = 3) -> float:
    """Fraction of text covered by English words."""
    words = find_words(text, min_len)
    covered = sum(len(w) for _, w in words)
    return covered / len(text) if text else 0.0


def main():
    print("=" * 70)
    print("E-CFM-03: Null Cipher / Steganographic Extraction Patterns")
    print("=" * 70)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")

    best_coverage = 0.0
    best_config = ""
    results = []

    # ── Test 1: Every Nth letter ──────────────────────────────────────────
    print("\n── Test 1: Every Nth letter extraction ──")
    for n in range(2, 21):
        for offset in range(n):
            extracted = CT[offset::n]
            if len(extracted) < 3:
                continue
            cov = word_coverage(extracted, 4)
            words = find_words(extracted, 4)
            if cov > 0.2 or words:
                tag = f"every {n}th, offset {offset}"
                print(f"  {tag}: '{extracted}' — words: {words}, coverage: {cov:.1%}")
                results.append((cov, tag, extracted, words))
                if cov > best_coverage:
                    best_coverage = cov
                    best_config = tag

    # ── Test 2: Kryptos sculpture row acrostics ───────────────────────────
    print("\n── Test 2: Sculpture row-start/end acrostics ──")
    # Known Kryptos cipher-side approximate row widths (86 rows)
    # K4 starts at ~row 62 on the sculpture. Typical row width ~10-12 chars
    for width in range(8, 16):
        # Row starts
        starts = [i for i in range(0, CT_LEN, width)]
        text_starts = "".join(CT[i] for i in starts if i < CT_LEN)
        # Row ends
        ends = [min(i + width - 1, CT_LEN - 1) for i in range(0, CT_LEN, width)]
        text_ends = "".join(CT[i] for i in ends if i < CT_LEN)

        for label, text in [("row-starts", text_starts), ("row-ends", text_ends)]:
            words = find_words(text, 3)
            cov = word_coverage(text, 3)
            if words:
                tag = f"width={width} {label}"
                print(f"  {tag}: '{text}' — words: {words}, cov: {cov:.1%}")
                results.append((cov, tag, text, words))

    # ── Test 3: Fibonacci / prime indexed positions ───────────────────────
    print("\n── Test 3: Fibonacci and prime position extraction ──")
    # Fibonacci indices
    fib = [1, 1]
    while fib[-1] < CT_LEN:
        fib.append(fib[-1] + fib[-2])
    fib_indices = sorted(set(f for f in fib if f < CT_LEN))
    fib_text = "".join(CT[i] for i in fib_indices)
    words = find_words(fib_text, 3)
    print(f"  Fibonacci positions: '{fib_text}' — words: {words}")
    results.append((word_coverage(fib_text, 3), "fibonacci", fib_text, words))

    # 0-indexed Fibonacci
    fib0 = [0, 1]
    while fib0[-1] < CT_LEN:
        fib0.append(fib0[-1] + fib0[-2])
    fib0_indices = sorted(set(f for f in fib0 if f < CT_LEN))
    fib0_text = "".join(CT[i] for i in fib0_indices)
    words0 = find_words(fib0_text, 3)
    print(f"  Fibonacci (0-idx): '{fib0_text}' — words: {words0}")

    # Primes
    def is_prime(n):
        if n < 2:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    primes = [i for i in range(CT_LEN) if is_prime(i)]
    prime_text = "".join(CT[i] for i in primes)
    words = find_words(prime_text, 3)
    print(f"  Prime positions: '{prime_text}' — words: {words}")
    results.append((word_coverage(prime_text, 3), "primes", prime_text, words))

    # ── Test 4: Self-referential (letter value as next index) ─────────────
    print("\n── Test 4: Self-referential position chains ──")
    for start in range(CT_LEN):
        chain = [start]
        visited = {start}
        pos = start
        for _ in range(30):  # max chain length
            next_pos = ALPH_IDX[CT[pos]] % CT_LEN
            if next_pos in visited:
                break
            chain.append(next_pos)
            visited.add(next_pos)
            pos = next_pos
        if len(chain) >= 8:
            text = "".join(CT[i] for i in chain)
            words = find_words(text, 4)
            if words:
                print(f"  Chain from {start}: '{text}' — words: {words}")
                results.append((word_coverage(text, 3), f"chain-from-{start}", text, words))

    # ── Test 5: Diagonal reads from grids with padding ────────────────────
    print("\n── Test 5: Grid diagonal reads ──")
    for width in range(7, 15):
        nrows = (CT_LEN + width - 1) // width
        padded = CT + "X" * (nrows * width - CT_LEN)
        # Main diagonal
        diag = "".join(padded[r * width + (r % width)] for r in range(nrows) if r * width + (r % width) < len(padded))
        words = find_words(diag, 3)
        if words:
            print(f"  width={width} diagonal: '{diag}' — words: {words}")
        # Anti-diagonal
        adiag = "".join(padded[r * width + (width - 1 - r % width)] for r in range(nrows) if r * width + (width - 1 - r % width) < len(padded))
        words = find_words(adiag, 3)
        if words:
            print(f"  width={width} anti-diag: '{adiag}' — words: {words}")

    # ── Test 6: Positions where CT matches known PT letters ───────────────
    print("\n── Test 6: Positions of specific high-value letters ──")
    for letter in "EASTNORTHBERLICK":
        positions = [i for i, c in enumerate(CT) if c == letter]
        if len(positions) >= 2:
            # Extract letters at those positions from CT shifted
            print(f"  Positions of '{letter}' in CT: {positions}")

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    results.sort(key=lambda x: -x[0])
    if results:
        print(f"Best word coverage: {results[0][0]:.1%} — {results[0][1]}")
        print(f"Extraction: '{results[0][2]}'")
        print(f"Words found: {results[0][3]}")
        print("\nTop 10 extractions by word coverage:")
        for cov, tag, text, words in results[:10]:
            if words:
                print(f"  {cov:.1%} | {tag} | words: {[w for _, w in words]}")
    else:
        print("No extractions with English words found.")

    has_signal = any(cov > 0.3 for cov, _, _, _ in results)
    print(f"\nVerdict: {'SIGNAL — investigate!' if has_signal else 'NOISE — no steganographic pattern detected'}")


if __name__ == "__main__":
    main()
