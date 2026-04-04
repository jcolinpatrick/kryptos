#!/usr/bin/env python3 -u
"""
Cipher: VLE + columnar transposition (VIC-style digit-level)
Family: encoding
Status: active
Keyspace: letter-to-digit maps x columnar widths x orderings
Last run:
Best score:

CRYPTIANA VLE + COLUMNAR: Digit-Level Straddling Checkerboard with Transposition

STRUCTURAL PROOF: Standard VLE is impossible under direct correspondence
because 13 unique crib letters need single-digit codes but a checkerboard
has only 8 slots. VLE is ONLY viable with a transposition layer.

Model (encryption direction):
  PT -> straddling checkerboard encode -> digit stream -> columnar transposition
  -> digit-to-letter substitution -> CT(97)

Model (attack direction):
  CT(97) -> letter-to-digit -> digit stream -> undo columnar -> checkerboard decode -> PT

The digit stream after letter-to-digit is 97 digits. After undoing columnar
transposition, the reordered digits are parsed by the checkerboard into
PT tokens. The crib repetition patterns (EASTNORTHEAST, BERLINCLOCK) must
appear in the decoded token sequence.

Key difference from existing VIC tests: existing tests undo columnar on
the LETTER string then parse tokens. This test undoes columnar on the
DIGIT string, which is the correct VIC attack direction.
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
CT_LEN = len(CT)  # 97


# ---- Crib pattern matching (from e_vic_model.py) ----

def check_ene(tokens, p):
    if p + 12 >= len(tokens): return False
    t = tokens
    if t[p] != t[p+9]: return False
    if t[p+1] != t[p+10]: return False
    if t[p+2] != t[p+11]: return False
    if t[p+3] != t[p+7]: return False
    if t[p+3] != t[p+12]: return False
    vals = {t[p], t[p+1], t[p+2], t[p+3], t[p+4], t[p+5], t[p+6], t[p+8]}
    return len(vals) == 8


def check_bc(tokens, q):
    if q + 10 >= len(tokens): return False
    t = tokens
    if t[q+3] != t[q+7]: return False
    if t[q+6] != t[q+9]: return False
    vals = {t[q], t[q+1], t[q+2], t[q+3], t[q+4], t[q+5], t[q+6], t[q+8], t[q+10]}
    return len(vals) == 9


def check_cross(tokens, p, q):
    t = tokens
    if t[p] != t[q+1]: return False
    if t[p+4] != t[q+5]: return False
    if t[p+5] != t[q+8]: return False
    if t[p+6] != t[q+2]: return False
    all_toks = {
        t[p], t[p+1], t[p+2], t[p+3], t[p+4], t[p+5], t[p+6], t[p+8],
        t[q], t[q+3], t[q+4], t[q+6], t[q+10]
    }
    return len(all_toks) == 13


def find_crib_patterns(tokens):
    n = len(tokens)
    hits = []
    ene_matches = []
    for p in range(n - 12):
        if check_ene(tokens, p):
            ene_matches.append(p)
    if not ene_matches:
        return hits
    for p in ene_matches:
        for q in range(n - 10):
            if check_bc(tokens, q) and check_cross(tokens, p, q):
                hits.append((p, q))
    return hits


# ---- Checkerboard parsing ----

def parse_digits_cb(digits, prefix_digits):
    """Parse digit string using straddling checkerboard prefix digits."""
    tokens = []
    i = 0
    n = len(digits)
    while i < n:
        if digits[i] in prefix_digits:
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


# ---- Columnar transposition ----

def columnar_undo(seq, width, perm):
    """Undo columnar transposition on a sequence.
    perm[i] = which column is read i-th in CT.
    Returns the row-reading-order sequence."""
    n = len(seq)
    nrows = (n + width - 1) // width
    rem = n % width
    if rem == 0:
        col_lens = [nrows] * width
    else:
        col_lens = [nrows if c < rem else nrows - 1 for c in range(width)]

    # Distribute seq into columns according to perm
    cols = [None] * width
    pos = 0
    for ci in perm:
        cl = col_lens[ci]
        cols[ci] = seq[pos:pos+cl]
        pos += cl

    # Read row by row
    result = []
    for r in range(nrows):
        for c in range(width):
            if r < len(cols[c]):
                result.append(cols[c][r])
    return ''.join(result) if isinstance(seq, str) else result


# ---- Letter-to-digit maps ----

def generate_maps():
    """Generate letter-to-digit mappings."""
    maps = []

    # KRYPTOS alphabet mod 10
    ka = KRYPTOS_ALPHABET
    for offset in range(10):
        m = {ka[i]: str((i + offset) % 10) for i in range(26)}
        maps.append((f"ka_off{offset}", m))

    # Standard alphabet mod 10
    for offset in range(10):
        m = {ALPHA[i]: str((i + offset) % 10) for i in range(26)}
        maps.append((f"az_off{offset}", m))

    # Reversed KA mod 10
    ka_rev = ka[::-1]
    for offset in range(10):
        m = {ka_rev[i]: str((i + offset) % 10) for i in range(26)}
        maps.append((f"karev_off{offset}", m))

    # Polybius-derived (KA in 5-wide grid)
    for rw in range(1, 4):
        for cw in range(1, 4):
            m = {ka[i]: str((i // 5 * rw + i % 5 * cw) % 10) for i in range(26)}
            maps.append((f"poly_r{rw}c{cw}", m))

    return maps


# ---- Worker function ----

def test_config(args):
    """Test one (map, width, perm, prefix_pair) configuration.

    Steps:
    1. CT -> letter-to-digit -> 97-digit string
    2. Undo columnar transposition on the digit string
    3. Parse with straddling checkerboard
    4. Check crib patterns in token sequence
    """
    map_label, letter_map, width, perm, prefix_pair = args

    # Step 1: CT letters to digits
    digits = ''.join(letter_map[c] for c in CT)

    # Step 2: Undo columnar transposition on digits
    try:
        reordered = columnar_undo(digits, width, perm)
    except Exception:
        return None

    # Step 3: Parse with checkerboard
    tokens = parse_digits_cb(reordered, set(prefix_pair))
    n_tokens = len(tokens)

    if n_tokens < 24 or n_tokens > 85:
        return None

    # Step 4: Check crib patterns
    hits = find_crib_patterns(tokens)

    if hits:
        return {
            "map": map_label,
            "width": width,
            "perm": list(perm),
            "prefix": ''.join(sorted(prefix_pair)),
            "n_tokens": n_tokens,
            "hits": hits,
        }
    return None


def main():
    print("=" * 70)
    print("CRYPTIANA VLE + COLUMNAR (Digit-Level)")
    print("CT -> digits -> undo columnar -> checkerboard decode -> PT")
    print("=" * 70)
    t0 = time.time()

    maps = generate_maps()
    print(f"\n  {len(maps)} letter-to-digit maps")

    # Columnar widths: 5-14 (97/w gives reasonable grid dimensions)
    widths = list(range(5, 15))
    prefix_pairs = list(combinations("0123456789", 2))  # 45 pairs

    # For each width, test all permutations up to width 8,
    # sample for larger widths
    print(f"  Widths: {widths}")
    print(f"  Prefix pairs: {len(prefix_pairs)}")

    work_items = []
    for map_label, letter_map in maps:
        for width in widths:
            if width <= 7:
                # Exhaustive permutations (up to 5040)
                perms = list(permutations(range(width)))
            else:
                # Sample: keyword-derived orderings
                perms = []
                for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KUBARK",
                           "SANBORN", "SCHEIDT", "BERLIN", "SECRET", "SHADOW"]:
                    # Keyword ordering: alphabetical rank of keyword chars
                    kw_trimmed = kw[:width]
                    if len(kw_trimmed) < width:
                        kw_trimmed += ALPHA[:width - len(kw_trimmed)]
                    chars = list(kw_trimmed)
                    order = sorted(range(len(chars)), key=lambda i: (chars[i], i))
                    perms.append(tuple(order))
                # Also add identity and reverse
                perms.append(tuple(range(width)))
                perms.append(tuple(range(width-1, -1, -1)))
                perms = list(set(perms))

            for perm in perms:
                for pp in prefix_pairs:
                    work_items.append((map_label, letter_map, width, perm, pp))

    print(f"  {len(work_items)} total configurations")

    # Scan
    n_workers = max(1, cpu_count() - 2)
    print(f"\n  Scanning with {n_workers} workers...")

    results = []
    done = 0
    batch = max(1, len(work_items) // 20)

    with Pool(n_workers) as pool:
        for result in pool.imap_unordered(test_config, work_items, chunksize=500):
            done += 1
            if result is not None:
                results.append(result)
                print(f"  HIT: {result['map']} w={result['width']} "
                      f"prefix={result['prefix']} tokens={result['n_tokens']} "
                      f"hits={len(result['hits'])}")
            if done % batch == 0:
                print(f"    {done}/{len(work_items)} ({time.time()-t0:.0f}s)")

    elapsed = time.time() - t0

    print(f"\n  Done in {elapsed:.1f}s")
    print(f"  {len(results)} configurations with crib pattern matches")

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    if not results:
        print("\n  NO HITS. Zero configurations produced both crib patterns")
        print("  in the decoded token sequence after digit-level columnar undo.")
    else:
        for r in results[:20]:
            print(f"\n  Map: {r['map']}, Width: {r['width']}, "
                  f"Perm: {r['perm']}, Prefix: {r['prefix']}")
            print(f"  Tokens: {r['n_tokens']}")
            for p, q in r['hits'][:5]:
                print(f"    ENE@{p}, BCL@{q} (gap={q-p})")

    # Save
    out = {
        "timestamp": time.strftime("%Y%m%d_%H%M%S"),
        "configs_tested": len(work_items),
        "maps": len(maps),
        "widths": widths,
        "prefix_pairs": len(prefix_pairs),
        "hits": len(results),
        "runtime_s": round(elapsed, 1),
        "results": results[:50],
    }
    out_path = os.path.join(_ROOT, "results", "e_cryptiana_vle_columnar_01.json")
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"\n  Saved to {out_path}")
    print(f"  Total: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
