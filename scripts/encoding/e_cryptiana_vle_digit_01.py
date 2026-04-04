#!/usr/bin/env python3 -u
"""
Cipher: variable-length encoding (digit intermediary)
Family: encoding
Status: active
Keyspace: ~2M (letter-to-digit maps x prefix pairs x checkerboard fills)
Last run:
Best score:

CRYPTIANA VLE DIGIT MODEL: Letter-to-Digit Straddling Checkerboard

Hypothesis: CT(97 letters) -> letter-to-digit map -> digit stream ->
            straddling checkerboard decode -> PT(~40-73 chars)

This tests the DIGIT-LEVEL path of the VIC cipher model. The existing
e_vic_model.py tested letter-level prefix parsing (CT letters as prefix
markers). This script instead converts CT letters to digits 0-9 first,
then parses the digit stream with a straddling checkerboard.

The "two systems" interpretation:
  System 1: A keyed letter-to-digit substitution (26 letters -> 10 digits)
  System 2: A straddling checkerboard (variable-length digit groups -> PT)

The "invention never in literature" could be the specific letter-to-digit
mapping scheme using the Kryptos alphabet or sculpture properties.

Attack strategy:
  Phase 1: For each letter-to-digit map, convert CT to digits
  Phase 2: For each prefix-digit pair, parse digit stream into tokens
  Phase 3: Check crib repetition patterns (EASTNORTHEAST + BERLINCLOCK)
  Phase 4: Score hits and reconstruct partial checkerboard tables

Key insight: We don't need to know the checkerboard fill to detect cribs.
The crib repetition patterns (same letter = same token) are sufficient
for initial detection. Only after finding a hit do we reconstruct the table.
"""

import sys
import os
import json
import time
from itertools import combinations, permutations
from collections import Counter
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, KRYPTOS_ALPHABET

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CT_FREQ = Counter(CT)

# ---- Crib pattern matching (reused from e_vic_model.py) ----

ENE = "EASTNORTHEAST"
BCL = "BERLINCLOCK"
ENE_LEN = len(ENE)  # 13
BCL_LEN = len(BCL)  # 11


def check_ene(tokens, p):
    """Check EASTNORTHEAST repetition pattern at position p."""
    t = tokens
    if p + 12 >= len(t):
        return False
    if t[p] != t[p+9]: return False      # E=E
    if t[p+1] != t[p+10]: return False    # A=A
    if t[p+2] != t[p+11]: return False    # S=S
    if t[p+3] != t[p+7]: return False     # T=T
    if t[p+3] != t[p+12]: return False    # T=T
    vals = {t[p], t[p+1], t[p+2], t[p+3], t[p+4], t[p+5], t[p+6], t[p+8]}
    return len(vals) == 8


def check_bc(tokens, q):
    """Check BERLINCLOCK repetition pattern at position q."""
    t = tokens
    if q + 10 >= len(t):
        return False
    if t[q+3] != t[q+7]: return False     # L=L
    if t[q+6] != t[q+9]: return False     # C=C
    vals = {t[q], t[q+1], t[q+2], t[q+3], t[q+4], t[q+5], t[q+6], t[q+8], t[q+10]}
    return len(vals) == 9


def check_cross(tokens, p, q):
    """Cross-crib constraints: shared letters E,N,O,R must have same token."""
    t = tokens
    if t[p] != t[q+1]: return False       # E
    if t[p+4] != t[q+5]: return False     # N
    if t[p+5] != t[q+8]: return False     # O
    if t[p+6] != t[q+2]: return False     # R
    all_toks = {
        t[p], t[p+1], t[p+2], t[p+3], t[p+4], t[p+5], t[p+6], t[p+8],
        t[q], t[q+3], t[q+4], t[q+6], t[q+10]
    }
    return len(all_toks) == 13


def find_crib_patterns(tokens):
    """Find all (p, q) positions where both cribs match with cross-constraints."""
    n = len(tokens)
    hits = []
    ene_matches = []
    for p in range(n - ENE_LEN + 1):
        if check_ene(tokens, p):
            ene_matches.append(p)
    if not ene_matches:
        return hits
    for p in ene_matches:
        for q in range(n - BCL_LEN + 1):
            if check_bc(tokens, q) and check_cross(tokens, p, q):
                hits.append((p, q))
    return hits


# ---- Digit-level straddling checkerboard parsing ----

def parse_digits_cb(digits, prefix_digits):
    """Parse a digit string using straddling checkerboard prefix digits.

    prefix_digits: set of 2 digits that signal a 2-digit code.
    Other digits are 1-digit codes. Returns list of token strings.
    """
    tokens = []
    i = 0
    n = len(digits)
    while i < n:
        d = digits[i]
        if d in prefix_digits:
            if i + 1 < n:
                tokens.append(digits[i:i+2])
                i += 2
            else:
                tokens.append(digits[i])
                i += 1
        else:
            tokens.append(digits[i])
            i += 1
    return tokens


# ---- Letter-to-digit mapping generators ----

def generate_frequency_maps():
    """Generate letter-to-digit maps based on CT frequency ranking.

    In a straddling checkerboard, the 8 most frequent plaintext letters
    get single-digit codes, and the rest get 2-digit codes. But we're
    mapping CT letters to digits, not PT letters. Multiple strategies:

    1. Frequency-rank: most frequent CT letters get lowest digits
    2. KRYPTOS-alphabet order: K=0, R=1, Y=2, P=3, T=4, O=5, S=6, A=7, B=8, C=9...
    3. Standard alphabet order: A=0, B=1, ... (mod 10 with offset)
    4. Keyword-derived: KRYPTOS generates the first 7 digits, rest fill in
    """
    maps = []

    # Strategy 1: Frequency-ranked (top 10 CT letters get digits 0-9)
    freq_sorted = sorted(CT_FREQ.keys(), key=lambda c: -CT_FREQ[c])
    for rotation in range(10):  # try 10 rotations of the digit assignment
        m = {}
        for i, letter in enumerate(freq_sorted):
            m[letter] = str((i + rotation) % 10)
        maps.append(("freq_rot" + str(rotation), m))

    # Strategy 2: KRYPTOS alphabet order (mod 10)
    ka = KRYPTOS_ALPHABET
    for offset in range(10):
        m = {}
        for i, letter in enumerate(ka):
            m[letter] = str((i + offset) % 10)
        maps.append(("ka_off" + str(offset), m))

    # Strategy 3: Standard alphabet (mod 10)
    for offset in range(10):
        m = {}
        for i, letter in enumerate(ALPHA):
            m[letter] = str((i + offset) % 10)
        maps.append(("az_off" + str(offset), m))

    # Strategy 4: Reversed KRYPTOS alphabet (mod 10)
    ka_rev = ka[::-1]
    for offset in range(10):
        m = {}
        for i, letter in enumerate(ka_rev):
            m[letter] = str((i + offset) % 10)
        maps.append(("ka_rev_off" + str(offset), m))

    # Strategy 5: Polybius-derived (row*5 + col mapped to digit)
    # KRYPTOS in 5-wide grid: row = i//5, col = i%5
    for row_weight in range(1, 4):
        for col_weight in range(1, 4):
            m = {}
            for i, letter in enumerate(ka):
                row, col = i // 5, i % 5
                digit = (row * row_weight + col * col_weight) % 10
                m[letter] = str(digit)
            label = f"poly_r{row_weight}c{col_weight}"
            maps.append((label, m))

    # Strategy 6: Direct position in alphabet mod 10 (Beaufort-style)
    # Key[i] = (CT[i] + offset) mod 10
    for offset in range(10):
        m = {}
        for letter in ALPHA:
            val = (ord(letter) - ord('A') + offset) % 10
            m[letter] = str(val)
        maps.append(("pos_mod10_off" + str(offset), m))

    return maps


# ---- Worker function ----

def test_config(args):
    """Test one (letter-to-digit map, prefix pair) configuration."""
    map_label, letter_map, prefix_pair = args

    # Convert CT to digit string
    digits = ''.join(letter_map[c] for c in CT)

    # Parse with straddling checkerboard
    prefix_set = set(prefix_pair)
    tokens = parse_digits_cb(digits, prefix_set)
    n_tokens = len(tokens)

    # Skip if token count is implausible (need room for both cribs)
    if n_tokens < 24:  # minimum: ENE(13) + BCL(11) with no overlap
        return None
    if n_tokens > 90:  # too close to 1:1, unlikely VLE
        return None

    # Check crib patterns
    hits = find_crib_patterns(tokens)

    if hits:
        prefix_str = ''.join(sorted(prefix_pair))
        return {
            "map_label": map_label,
            "prefix": prefix_str,
            "n_tokens": n_tokens,
            "hits": [(p, q) for p, q in hits],
            "digits": digits,
            "tokens": tokens,
        }
    return None


def main():
    print("=" * 70)
    print("CRYPTIANA VLE DIGIT MODEL")
    print("CT -> letter-to-digit -> straddling checkerboard -> PT")
    print("=" * 70)
    t0 = time.time()

    # Generate letter-to-digit maps
    print("\nPhase 1: Generating letter-to-digit maps...")
    maps = generate_frequency_maps()
    print(f"  {len(maps)} maps generated")

    # Generate prefix digit pairs (C(10,2) = 45)
    prefix_pairs = list(combinations("0123456789", 2))
    print(f"  {len(prefix_pairs)} prefix digit pairs")

    # Build work items
    work_items = []
    for map_label, letter_map in maps:
        for pp in prefix_pairs:
            work_items.append((map_label, letter_map, pp))

    print(f"  {len(work_items)} total configurations")

    # Phase 2: Scan
    print(f"\nPhase 2: Scanning ({cpu_count()-2} workers)...")
    n_workers = max(1, cpu_count() - 2)
    results = []

    with Pool(n_workers) as pool:
        for result in pool.imap_unordered(test_config, work_items, chunksize=100):
            if result is not None:
                results.append(result)

    elapsed = time.time() - t0
    print(f"\n  Scan complete in {elapsed:.1f}s")

    # Phase 3: Results
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    if not results:
        print("\n  NO HITS. Zero configurations produced both crib patterns.")
        print("  This means under these letter-to-digit maps, the digit stream")
        print("  never contains the EASTNORTHEAST + BERLINCLOCK repetition")
        print("  patterns simultaneously under any prefix pair.")
    else:
        print(f"\n  {len(results)} HITS!")
        for r in results[:20]:
            print(f"\n  Map: {r['map_label']}, Prefix: {r['prefix']}, Tokens: {r['n_tokens']}")
            for p, q in r['hits']:
                print(f"    ENE@{p}, BCL@{q} (gap={q-p})")
                # Show the token values at crib positions
                tokens = r['tokens']
                ene_tokens = tokens[p:p+13]
                bcl_tokens = tokens[q:q+11]
                print(f"    ENE tokens: {ene_tokens}")
                print(f"    BCL tokens: {bcl_tokens}")

    # Also report near-misses: configs where ENE pattern alone matches
    print(f"\n  Checking for ENE-only matches (partial signal)...")
    ene_only_count = 0
    best_ene_only = []
    for map_label, letter_map in maps:
        for pp in prefix_pairs:
            digits = ''.join(letter_map[c] for c in CT)
            tokens = parse_digits_cb(digits, set(pp))
            n_tokens = len(tokens)
            if n_tokens < 13 or n_tokens > 90:
                continue
            for p in range(n_tokens - ENE_LEN + 1):
                if check_ene(tokens, p):
                    ene_only_count += 1
                    if len(best_ene_only) < 10:
                        best_ene_only.append({
                            "map": map_label,
                            "prefix": ''.join(sorted(pp)),
                            "pos": p,
                            "n_tokens": n_tokens,
                        })

    print(f"  ENE-only matches: {ene_only_count}")
    for hit in best_ene_only[:10]:
        print(f"    {hit['map']} prefix={hit['prefix']} ENE@{hit['pos']} ({hit['n_tokens']} tokens)")

    # Save results
    out = {
        "timestamp": time.strftime("%Y%m%d_%H%M%S"),
        "configs_tested": len(work_items),
        "maps_tested": len(maps),
        "prefix_pairs": len(prefix_pairs),
        "full_hits": len(results),
        "ene_only_hits": ene_only_count,
        "runtime_s": round(elapsed, 1),
        "results": results[:50] if results else [],
    }
    out_path = os.path.join(_ROOT, "results", "e_cryptiana_vle_digit_01.json")
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2, default=str)
    print(f"\n  Saved to {out_path}")
    print(f"  Total runtime: {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
