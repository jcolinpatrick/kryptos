#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: grille
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-GRILLE-20: Period-8 / "8 Lines 73" — Columnar Transposition Width 8

EVIDENCE CONVERGENCE:
  - Tableau anomalies: extra L (row N=14), extra T (row V=22), spacing = 8
  - N-L = V-T = 2, L+T = 30 (= body columns), V-N = T-L = 8
  - "8 Lines 73" on Sanborn's yellow pad (K4 section)
  - 97 - 24 (known crib chars) = 73 (unknown chars)
  - 97 mod 8 = 1
  - Period 8 is Bean-compatible (FRAC analysis)
  - "11 Lines 342" for K3 → 11 physical rows on cipher panel, ~342 chars incl delimiters

HYPOTHESIS: K4 uses a width-8 columnar transposition. The carved text was produced by
writing the real CT into 8 columns and reading off in a keyed column order.

This script tests:
  1. All 8! = 40,320 column permutations for width-8 columnar transposition
  2. Each unscrambled result × Vig/Beaufort × KRYPTOS/PALIMPSEST/ABSCISSA × AZ/KA
  3. Score by crib matches (positional + free search)
  4. T-diagonal column offsets as candidate column order
  5. Misspelling-position-derived column orders
  6. Also test width 12 (97/8 ≈ 12.1) and width 13 (97/8 rounded up)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from itertools import permutations
from collections import Counter
import time

# ─── Constants ────────────────────────────────────────────────────────────────
try:
    from kryptos.kernel.constants import CT
    K4_CT = CT
except ImportError:
    K4_CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

CRIB1_POS, CRIB1 = 21, "EASTNORTHEAST"
CRIB2_POS, CRIB2 = 63, "BERLINCLOCK"
ALL_CRIB_POSITIONS = {}
for i, ch in enumerate(CRIB1):
    ALL_CRIB_POSITIONS[CRIB1_POS + i] = ch
for i, ch in enumerate(CRIB2):
    ALL_CRIB_POSITIONS[CRIB2_POS + i] = ch

KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]


# ─── Columnar transposition ──────────────────────────────────────────────────

def columnar_decrypt(ct, col_order, num_cols):
    """
    Decrypt columnar transposition.

    Encryption was: write PT into rows of `num_cols`, read columns in `col_order`.
    Decryption: distribute CT back into columns (in col_order), read rows.

    col_order: tuple of column indices (0-based) giving the order columns were read
    """
    n = len(ct)
    num_full_rows = n // num_cols
    remainder = n % num_cols

    # Columns with index < remainder have (num_full_rows + 1) chars
    # Columns with index >= remainder have num_full_rows chars
    col_lengths = []
    for col_idx in range(num_cols):
        if col_idx < remainder:
            col_lengths.append(num_full_rows + 1)
        else:
            col_lengths.append(num_full_rows)

    # Distribute CT into columns according to col_order
    columns = [''] * num_cols
    pos = 0
    for col_idx in col_order:
        length = col_lengths[col_idx]
        columns[col_idx] = ct[pos:pos + length]
        pos += length

    # Read off rows
    pt = []
    for row in range(num_full_rows + (1 if remainder > 0 else 0)):
        for col in range(num_cols):
            if row < len(columns[col]):
                pt.append(columns[col][row])

    return ''.join(pt)


def columnar_encrypt(pt, col_order, num_cols):
    """
    Encrypt with columnar transposition.
    Write PT into rows of num_cols, read columns in col_order.
    """
    n = len(pt)
    num_full_rows = n // num_cols
    remainder = n % num_cols

    # Build grid
    grid = []
    pos = 0
    for row in range(num_full_rows + (1 if remainder > 0 else 0)):
        row_chars = []
        for col in range(num_cols):
            if pos < n:
                row_chars.append(pt[pos])
                pos += 1
            # Don't append padding for incomplete rows
        grid.append(row_chars)

    # Read columns in col_order
    ct = []
    for col_idx in col_order:
        for row in grid:
            if col_idx < len(row):
                ct.append(row[col_idx])

    return ''.join(ct)


# ─── Cipher functions ─────────────────────────────────────────────────────────

def vig_decrypt(ct, key, alph=AZ):
    n = len(alph)
    return ''.join(alph[(alph.index(c) - alph.index(key[i % len(key)])) % n]
                   for i, c in enumerate(ct))


def beaufort_decrypt(ct, key, alph=AZ):
    n = len(alph)
    return ''.join(alph[(alph.index(key[i % len(key)]) - alph.index(c)) % n]
                   for i, c in enumerate(ct))


# ─── Scoring ──────────────────────────────────────────────────────────────────

def score_positional_cribs(pt):
    """Count how many crib positions match."""
    score = 0
    for pos, expected in ALL_CRIB_POSITIONS.items():
        if pos < len(pt) and pt[pos] == expected:
            score += 1
    return score


def find_cribs_anywhere(text):
    """Find crib words anywhere in text."""
    hits = []
    for word in ["EASTNORTHEAST", "BERLINCLOCK", "NORTHEAST", "EAST", "NORTH",
                 "BERLIN", "CLOCK", "SLOWLY", "DESPERATE", "TREMBLING",
                 "CANDLE", "CHAMBER", "FLICKER"]:
        idx = text.find(word)
        if idx >= 0:
            hits.append((word, idx))
    return hits


def ic(text):
    freq = Counter(text)
    n = len(text)
    if n < 2:
        return 0.0
    return sum(f * (f - 1) for f in freq.values()) / (n * (n - 1))


# ─── Main sweep ──────────────────────────────────────────────────────────────

def sweep_width(width, ct, label=""):
    """Sweep all column permutations for a given width."""
    print(f"\n{'='*70}")
    print(f"  WIDTH-{width} COLUMNAR SWEEP {label}")
    print(f"  CT length: {len(ct)}, Grid: {len(ct)//width + (1 if len(ct)%width else 0)} rows × {width} cols")
    print(f"  Remainder: {len(ct) % width} (columns 0..{len(ct)%width - 1} have 1 extra char)")
    print(f"  Total permutations: {1}")

    import math
    total_perms = math.factorial(width)
    total_configs = total_perms * len(KEYWORDS) * 2 * 2  # keywords × alphabets × cipher types
    print(f"  Total permutations: {total_perms:,}")
    print(f"  Total configs (× keys × alphs × ciphers): {total_configs:,}")
    print(f"{'='*70}")

    best_results = []
    tested = 0
    t0 = time.time()

    for col_order in permutations(range(width)):
        unscrambled = columnar_decrypt(ct, col_order, width)

        # Quick check: score unscrambled directly against cribs
        # (if the transposition alone reveals cribs in plaintext)
        raw_score = score_positional_cribs(unscrambled)
        if raw_score >= 5:
            best_results.append({
                'col_order': col_order, 'key': 'NONE', 'alph': 'NONE',
                'method': 'raw', 'pt': unscrambled, 'score': raw_score,
                'ic': ic(unscrambled), 'free_cribs': find_cribs_anywhere(unscrambled)
            })

        for key in KEYWORDS:
            for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
                if not all(c in alph for c in key):
                    continue
                for dec_name, dec_fn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
                    pt = dec_fn(unscrambled, key, alph)
                    score = score_positional_cribs(pt)

                    if score >= 6:  # Above noise floor
                        free = find_cribs_anywhere(pt)
                        best_results.append({
                            'col_order': col_order, 'key': key, 'alph': alph_name,
                            'method': dec_name, 'pt': pt, 'score': score,
                            'ic': ic(pt), 'free_cribs': free
                        })

        tested += 1
        if tested % 5000 == 0:
            elapsed = time.time() - t0
            rate = tested / elapsed
            remaining = (total_perms - tested) / rate
            best_so_far = max((r['score'] for r in best_results), default=0)
            print(f"  ... {tested:,}/{total_perms:,} perms "
                  f"({elapsed:.1f}s, {rate:.0f}/s, ~{remaining:.0f}s left) "
                  f"best={best_so_far}/24")

    elapsed = time.time() - t0
    print(f"\n  Completed {tested:,} permutations in {elapsed:.1f}s")

    # Sort by score descending
    best_results.sort(key=lambda r: (r['score'], r['ic']), reverse=True)

    if best_results:
        print(f"  Results above noise (score >= 6): {len(best_results)}")
        for i, r in enumerate(best_results[:20]):
            print(f"\n  [{i+1}] Score={r['score']}/24  IC={r['ic']:.4f}  "
                  f"{r['method']}/{r['key']}/{r['alph']}  cols={r['col_order']}")
            if r['free_cribs']:
                print(f"       Free cribs: {r['free_cribs']}")
            print(f"       PT: {r['pt']}")
    else:
        print(f"  No results above noise floor (score >= 6)")

    return best_results


def test_specific_orders(width, ct):
    """Test specific column orders derived from clues."""
    print(f"\n{'='*70}")
    print(f"  SPECIFIC COLUMN ORDERS (width {width})")
    print(f"{'='*70}")

    # T-diagonal column positions on KA tableau
    # In row A (KRYPTOSABCDEFGHIJLMNQUVWXZ), T is at index 4 (0-based: K=0,R=1,Y=2,P=3,T=4)
    # Each row shifts by 1, so T is at col (4 + row) mod 26 in the KA body
    # For period-8 rows F(5), N(13), V(21):
    # Row F (shift=5): T at (4+5)%26 = 9
    # Row N (shift=13): T at (4+13)%26 = 17
    # Row V (shift=21): T at (4+21)%26 = 25
    # But in the 30-col tableau body, position wraps at 26 with 4 extra columns
    # T positions mod 8 for all rows:
    t_cols_mod8 = [(4 + shift) % 8 for shift in range(26)]  # T column mod 8 for each row
    # Unique ordering from first 8 rows (A through H, shifts 0-7):
    t_first_8 = tuple((4 + i) % 8 for i in range(8))  # (4,5,6,7,0,1,2,3)

    specific_orders = [
        (t_first_8, "T-diagonal mod 8 (rows A-H)"),
        ((4, 5, 6, 7, 0, 1, 2, 3), "T-diagonal: shift-4 rotation"),
        ((3, 4, 5, 6, 7, 0, 1, 2), "T-diagonal: shift-3 rotation"),
        ((0, 1, 2, 3, 4, 5, 6, 7), "Identity (natural order)"),
        ((7, 6, 5, 4, 3, 2, 1, 0), "Reverse order"),
        ((1, 6, 4, 9 % 8, 7, 3, 0, 2), "Misspelling positions [2,7,5,10%8,8%8,4,1,3]"),
        # KRYPTOS as columnar key (K=0,R=1,Y=2,P=3,T=4,O=5,S=6 → rank order)
        # K=10, R=17, Y=24, P=15, T=19, O=14, S=18 → rank: O=0,K=1,P=2,R=3,S=4,T=5,Y=6
        # But we need 8 columns, KRYPTOS has 7 letters. KRYPTOSA has 8.
        # K=10,R=17,Y=24,P=15,T=19,O=14,S=18,A=0 → rank: A=0,K=1,O=2,P=3,R=4,S=5,T=6,Y=7
        ((1, 4, 7, 3, 6, 2, 5, 0), "KRYPTOSA alphabetic rank"),
        # YAR: Y=24, A=0, R=17 → could give col order starting points
        ((0, 2, 4, 6, 1, 3, 5, 7), "Even-odd interleave"),
        ((0, 4, 1, 5, 2, 6, 3, 7), "Stride-4 interleave"),
        # Period-8 rows on tableau: F(6), N(14), V(22).
        # Letters at these rows in KA tableau vary by column.
        # Use the KEY LETTERS of these rows: F=5, N=13, V=21 (KA indices)
        # mod 8: 5, 5, 5 — not useful
        # Use the EXTRA CHAR info: L=11, T=19.
        # L mod 8 = 3, T mod 8 = 3 — both = 3
        # N mod 8 = 5, V mod 8 = 5 — both = 5
        # N-L=2, V-T=2 → difference = 2
        ((2, 0, 5, 3, 7, 1, 6, 4), "Derived from N=13,V=21,L=11,T=19 mod 8 with offsets"),
    ]

    for col_order, description in specific_orders:
        # Validate
        if sorted(col_order) != list(range(width)):
            print(f"\n  SKIP (invalid perm): {description} = {col_order}")
            continue

        unscrambled = columnar_decrypt(ct, col_order, width)
        print(f"\n  --- {description} ---")
        print(f"  Column order: {col_order}")
        print(f"  Unscrambled: {unscrambled}")
        print(f"  IC: {ic(unscrambled):.4f}")

        # Score raw
        raw_score = score_positional_cribs(unscrambled)
        free = find_cribs_anywhere(unscrambled)
        print(f"  Raw crib score: {raw_score}/24  Free: {free}")

        # Try all decryptions
        for key in KEYWORDS:
            for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
                if not all(c in alph for c in key):
                    continue
                for dec_name, dec_fn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
                    pt = dec_fn(unscrambled, key, alph)
                    score = score_positional_cribs(pt)
                    free_pt = find_cribs_anywhere(pt)
                    if score >= 3 or free_pt:
                        print(f"    {dec_name}/{key}/{alph_name}: score={score}/24 "
                              f"IC={ic(pt):.4f} free={free_pt}")
                        if score >= 6:
                            print(f"    *** SIGNAL: {pt}")


def test_reverse_direction(width, ct):
    """
    Test the reverse: what if the CARVED TEXT was produced by columnar ENCRYPTION?
    Then we need columnar decryption to recover the intermediate CT.
    Also test: what if we need to columnar-encrypt (write to grid, read cols) to unscramble.
    """
    print(f"\n{'='*70}")
    print(f"  REVERSE DIRECTION: Columnar encrypt K4 (width {width})")
    print(f"{'='*70}")

    best_score = 0
    best_result = None
    tested = 0

    for col_order in permutations(range(width)):
        scrambled = columnar_encrypt(ct, col_order, width)

        for key in KEYWORDS:
            for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
                if not all(c in alph for c in key):
                    continue
                for dec_name, dec_fn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
                    pt = dec_fn(scrambled, key, alph)
                    score = score_positional_cribs(pt)

                    if score > best_score:
                        best_score = score
                        best_result = {
                            'col_order': col_order, 'key': key, 'alph': alph_name,
                            'method': dec_name, 'pt': pt, 'score': score,
                            'ic': ic(pt), 'free_cribs': find_cribs_anywhere(pt)
                        }

                    if score >= 6:
                        free = find_cribs_anywhere(pt)
                        print(f"  Score={score}/24 {dec_name}/{key}/{alph_name} "
                              f"cols={col_order}  IC={ic(pt):.4f}  free={free}")
                        print(f"  PT: {pt}")

        tested += 1
        if tested % 5000 == 0:
            print(f"  ... {tested:,}/40320 (best so far: {best_score}/24)")

    if best_result:
        print(f"\n  Best result: score={best_result['score']}/24")
        print(f"  {best_result['method']}/{best_result['key']}/{best_result['alph']} "
              f"cols={best_result['col_order']}")
        print(f"  PT: {best_result['pt']}")
    else:
        print(f"\n  No results above noise.")


def sweep_widths_quick(ct, widths):
    """Quick sweep: only score >= 8 results, for widths other than 8."""
    for w in widths:
        import math
        total = math.factorial(w)
        if total > 1_000_000:
            print(f"\n  Width {w}: {total:,} permutations — TOO LARGE, skipping full sweep")
            print(f"  Testing specific orders only...")
            continue

        print(f"\n{'='*70}")
        print(f"  WIDTH-{w} QUICK SWEEP")
        print(f"{'='*70}")

        best_score = 0
        best_result = None
        tested = 0
        t0 = time.time()

        for col_order in permutations(range(w)):
            unscrambled = columnar_decrypt(ct, col_order, w)

            for key in KEYWORDS:
                for alph_name, alph in [("AZ", AZ), ("KA", KA)]:
                    if not all(c in alph for c in key):
                        continue
                    for dec_name, dec_fn in [("Vig", vig_decrypt), ("Beau", beaufort_decrypt)]:
                        pt = dec_fn(unscrambled, key, alph)
                        score = score_positional_cribs(pt)

                        if score > best_score:
                            best_score = score
                            best_result = {
                                'col_order': col_order, 'key': key, 'alph': alph_name,
                                'method': dec_name, 'pt': pt, 'score': score,
                                'ic': ic(pt)
                            }

            tested += 1
            if tested % 10000 == 0:
                print(f"  ... {tested:,}/{total:,} (best: {best_score}/24)")

        elapsed = time.time() - t0
        print(f"  Width {w}: {tested:,} perms in {elapsed:.1f}s, best score={best_score}/24")
        if best_result and best_score >= 6:
            print(f"  Best: {best_result['method']}/{best_result['key']}/{best_result['alph']} "
                  f"cols={best_result['col_order']}  IC={best_result['ic']:.4f}")
            print(f"  PT: {best_result['pt']}")


def main():
    print("=" * 70)
    print("  E-GRILLE-20: Period-8 / '8 Lines 73' Columnar Transposition")
    print("=" * 70)
    print(f"\n  K4 CT: {K4_CT}")
    print(f"  Length: {len(K4_CT)}")
    print(f"  97 mod 8 = {97 % 8}")
    print(f"  97 / 8 = {97 // 8} remainder {97 % 8}")
    print(f"  Grid: 13 rows × 8 cols (first {97%8} col(s) have 13 chars, rest have 12)")
    print(f"  97 - 24 = 73 (unknown chars)")

    # ─── Phase 1: Specific column orders ──────────────────────────────────
    test_specific_orders(8, K4_CT)

    # ─── Phase 2: Full sweep width 8 (decrypt direction) ─────────────────
    results_8 = sweep_width(8, K4_CT, "(columnar DECRYPT)")

    # ─── Phase 3: Full sweep width 8 (encrypt direction) ─────────────────
    test_reverse_direction(8, K4_CT)

    # ─── Phase 4: Quick sweeps for related widths ─────────────────────────
    print(f"\n{'='*70}")
    print(f"  RELATED WIDTH SWEEPS")
    print(f"{'='*70}")
    # Width 12: 97/8 ≈ 12.1, so 8 rows × 12 cols (+1)
    # Width 13: 97/8 = 12.125, rounds to 13 cols × 7-8 rows
    # Width 9: yellow pad "10.8 rows" → 97/9 ≈ 10.78
    # Width 7: KRYPTOS has 7 letters
    sweep_widths_quick(K4_CT, [7, 9, 12, 13])

    # ─── Phase 5: Context ─────────────────────────────────────────────────
    print(f"\n{'='*70}")
    print(f"  CONTEXT: Expected random scores at width 8")
    print(f"{'='*70}")
    import random
    random.seed(42)
    random_scores = []
    for _ in range(1000):
        perm = list(range(8))
        random.shuffle(perm)
        unscrambled = columnar_decrypt(K4_CT, tuple(perm), 8)
        for key in ["KRYPTOS"]:
            for alph in [AZ]:
                pt = vig_decrypt(unscrambled, key, alph)
                s = score_positional_cribs(pt)
                random_scores.append(s)

    from collections import Counter
    dist = Counter(random_scores)
    print(f"  Score distribution (1000 random width-8 + Vig/KRYPTOS/AZ):")
    for s in sorted(dist):
        bar = '█' * dist[s]
        print(f"    {s:2d}/24: {dist[s]:4d} {bar}")

    avg = sum(random_scores) / len(random_scores)
    print(f"  Mean: {avg:.2f}/24")
    print(f"  Max:  {max(random_scores)}/24")

    print(f"\n{'='*70}")
    print(f"  DONE")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
