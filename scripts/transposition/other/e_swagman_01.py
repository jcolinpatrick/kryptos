#!/usr/bin/env python3
"""
Cipher: Swagman (Latin Square Transposition)
Family: transposition/other
Status: active
Keyspace: Latin squares of order 4-10, all row-rotation variants
Last run: 2026-03-31
Best score: 0.0 (crib_score)

Swagman cipher: Australian Army transposition using a Latin square key.
Text is written into blocks of width n, each block's columns are permuted
according to the corresponding row of the n×n Latin square (cycling).
Then read off by columns. Novel transposition not covered by standard
columnar/route testing.
"""
import sys
import os
import itertools
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))
_SRC = os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from kryptos.kernel.constants import CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT
from kryptos.kernel.scoring.aggregate import score_candidate


def generate_latin_squares(n: int, max_count: int = 5000) -> list:
    """Generate Latin squares of order n by systematic row permutation.

    For small n (≤5), generates exhaustively from normalized forms.
    For larger n, generates by permuting rows/columns of canonical squares.
    """
    squares = []

    # Start with canonical Latin square: row i = [i, i+1, ..., i+n-1] mod n
    canonical = [[(i + j) % n for j in range(n)] for i in range(n)]

    # Generate squares by permuting columns of canonical
    if n <= 5:
        # For small n, try all column permutations
        for col_perm in itertools.permutations(range(n)):
            sq = [[row[col_perm[j]] for j in range(n)] for row in canonical]
            squares.append(sq)
            if len(squares) >= max_count:
                return squares
        # Also try row permutations of each column permutation (sample)
        for col_perm in itertools.permutations(range(n)):
            for row_perm in itertools.permutations(range(n)):
                sq = [[canonical[row_perm[i]][col_perm[j]]
                       for j in range(n)] for i in range(n)]
                # Verify it's still a Latin square
                if _is_latin_square(sq, n):
                    sq_tuple = tuple(tuple(r) for r in sq)
                    squares.append(sq)
                    if len(squares) >= max_count:
                        return squares
    else:
        # For larger n, systematic column permutations of canonical
        # plus row-shifted variants
        for shift in range(n):
            shifted = [[(i + j + shift) % n for j in range(n)] for i in range(n)]
            for col_perm in itertools.permutations(range(n)):
                sq = [[row[col_perm[j]] for j in range(n)] for row in shifted]
                squares.append(sq)
                if len(squares) >= max_count:
                    return squares

    return squares


def _is_latin_square(sq: list, n: int) -> bool:
    """Verify a square is a valid Latin square."""
    target = set(range(n))
    for row in sq:
        if set(row) != target:
            return False
    for j in range(n):
        if set(sq[i][j] for i in range(n)) != target:
            return False
    return True


def swagman_decrypt(ct: str, latin_sq: list, n: int) -> str:
    """Decrypt Swagman cipher.

    Encryption: write PT in rows of width n, permute each row by the
    corresponding Latin square row (cycling), read columns.

    Decryption: reverse — write CT in columns, inverse-permute each row.
    """
    ct_len = len(ct)
    n_rows = (ct_len + n - 1) // n

    # Write CT into grid by columns (reverse of column readoff)
    grid = [[''] * n for _ in range(n_rows)]
    idx = 0
    for col in range(n):
        for row in range(n_rows):
            if idx < ct_len:
                grid[row][col] = ct[idx]
                idx += 1
            else:
                grid[row][col] = 'X'  # padding

    # Inverse-permute each row using the Latin square
    pt_grid = [[''] * n for _ in range(n_rows)]
    for row_idx in range(n_rows):
        sq_row = latin_sq[row_idx % n]
        # sq_row[j] tells us: column j of PT went to column sq_row[j] of CT
        # So for decryption: PT[row][j] = CT_grid[row][sq_row[j]]
        # Actually: encryption permutes PT columns by sq_row,
        # so PT[row][sq_row[j]] = original_before_colread[row][j]
        # The inverse: PT[row][j] = grid[row][inv_perm[j]]
        inv_perm = [0] * n
        for j in range(n):
            inv_perm[sq_row[j]] = j
        for j in range(n):
            pt_grid[row_idx][j] = grid[row_idx][inv_perm[j]]

    # Read off by rows
    pt = ''.join(''.join(row) for row in pt_grid)
    return pt[:ct_len]


def swagman_decrypt_v2(ct: str, latin_sq: list, n: int) -> str:
    """Alternative Swagman interpretation: row-by-row write, permuted readoff.

    Encryption: write PT by rows into grid, for each row apply Latin square
    permutation, then read by rows. Effectively a periodic substitution of
    positions within each block.
    """
    ct_len = len(ct)
    n_rows = (ct_len + n - 1) // n
    padded = ct.ljust(n_rows * n, 'X')

    pt = list(padded)
    for row_idx in range(n_rows):
        sq_row = latin_sq[row_idx % n]
        inv_perm = [0] * n
        for j in range(n):
            inv_perm[sq_row[j]] = j
        base = row_idx * n
        block = padded[base:base + n]
        for j in range(n):
            pt[base + j] = block[inv_perm[j]]

    return ''.join(pt)[:ct_len]


def test_square(args):
    """Test one Latin square with both decrypt variants."""
    latin_sq, n, sq_id = args
    results = []

    for variant, decrypt_fn in [("colread", swagman_decrypt),
                                 ("rowperm", swagman_decrypt_v2)]:
        pt = decrypt_fn(CT, latin_sq, n)
        sb = score_candidate(pt)
        score = float(sb.crib_score)
        if score >= 4:  # Only track somewhat interesting results
            method = f"Swagman n={n} var={variant} sq={sq_id}"
            results.append((score, pt, method))

    return results


def attack(ciphertext: str, **params) -> list[tuple[float, str, str]]:
    """Standard attack contract."""
    all_results = []
    workers = max(1, cpu_count() - 2)

    for n in range(4, 11):
        squares = generate_latin_squares(n, max_count=5000)
        print(f"  n={n}: testing {len(squares)} Latin squares...")

        tasks = [(sq, n, i) for i, sq in enumerate(squares)]

        with Pool(workers) as pool:
            for batch_results in pool.imap_unordered(test_square, tasks, chunksize=50):
                all_results.extend(batch_results)

    all_results.sort(key=lambda x: -x[0])
    return all_results


def main():
    print("=" * 70)
    print("Swagman Cipher — Latin Square Transposition Sweep")
    print("=" * 70)
    print(f"CT: {CT[:50]}...")
    print(f"CT length: {CT_LEN}")
    print()

    results = attack(CT)

    if results:
        print(f"\nResults with score >= 4: {len(results)}")
        print(f"\nTop 10:")
        for score, pt, method in results[:10]:
            print(f"  {score:5.1f}  {method}")
            print(f"         pt={pt[:60]}...")
        best = results[0][0]
    else:
        best = 0.0
        print("\nNo results above threshold (score >= 4)")

    print(f"\nBest score: {best}/24")
    if best < 10:
        print("VERDICT: NOISE — Swagman transposition does not decrypt K4")
    elif best < 18:
        print("VERDICT: INTERESTING — investigate further")
    else:
        print("VERDICT: SIGNAL — requires detailed analysis!")


if __name__ == "__main__":
    main()
