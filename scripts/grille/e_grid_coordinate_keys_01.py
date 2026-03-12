#!/usr/bin/env python3
"""Test grid-coordinate-derived keys on 73-char column mask extracts.

Each character in K4 has a known (row, col) in the 28x31 grid. If the
substitution key at each position is determined by its grid coordinates,
the cipher would be:
  - Non-periodic (irregular grid layout, row 24 starts at col 27)
  - Hand-computable (count row/col from the sculpture)
  - Physically motivated ("who says it is even a math solution?")

This tests ALL reasonable coordinate-to-key functions with Vig/Beau/VBeau.

Cipher: grid-coordinate substitution
Family: grille
Status: active
Keyspace: ~10K configs
Last run: never
Best score: N/A
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from kryptos.kernel.constants import CT, ALPH, MOD, CRIB_WORDS


def get_grid_coordinates(keep_col: int) -> list[tuple[int, int, int]]:
    """Get (orig_pos, row, col) for each non-null position.

    Grid layout:
      Row 24: cols 27-30 → positions 0-3
      Row 25: cols 0-30  → positions 4-34
      Row 26: cols 0-30  → positions 35-65
      Row 27: cols 0-30  → positions 66-96
    """
    # Null positions: cols 8-16 (minus kept col) in rows 25-27
    null_cols = set(range(8, 17)) - {keep_col}

    coords = []  # (orig_pos, row, col)

    # Row 24: cols 27-30
    for c in range(27, 31):
        pos = c - 27  # positions 0-3
        coords.append((pos, 24, c))

    # Rows 25-27
    for r in range(25, 28):
        row_start = 4 + (r - 25) * 31
        for c in range(31):
            pos = row_start + c
            if c not in null_cols:
                coords.append((pos, r, c))

    # Sort by original position
    coords.sort(key=lambda x: x[0])
    return coords


def extract_and_map(ct97: str, keep_col: int) -> tuple[str, list[tuple[int, int]]]:
    """Extract 73 chars and return CT + grid coordinates for each."""
    grid_coords = get_grid_coordinates(keep_col)
    assert len(grid_coords) == 73, f"Expected 73, got {len(grid_coords)}"

    ct73 = ''.join(ct97[pos] for pos, _, _ in grid_coords)
    row_col = [(r, c) for _, r, c in grid_coords]
    return ct73, row_col


def shifted_crib_positions() -> list[tuple[int, str]]:
    """Crib positions in the 73-char extract: ENE at 13-25, BC at 47-57."""
    cribs = []
    for orig_start, word in CRIB_WORDS:
        shift = 8 if orig_start == 21 else 16
        for i, ch in enumerate(word):
            cribs.append((orig_start + i - shift, ch))
    return cribs


def score_cribs(pt: str, crib_pairs: list[tuple[int, str]]) -> int:
    return sum(1 for pos, ch in crib_pairs if 0 <= pos < len(pt) and pt[pos] == ch)


def decrypt_with_keys(ct: str, keys: list[int], variant: str) -> str:
    """Decrypt using position-specific keys."""
    result = []
    for i, c_ch in enumerate(ct):
        c = ord(c_ch) - 65
        k = keys[i] % MOD

        if variant == "vigenere":
            p = (c - k) % MOD
        elif variant == "beaufort":
            p = (k - c) % MOD
        elif variant == "var_beaufort":
            p = (c + k) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant}")

        result.append(chr(p + 65))
    return "".join(result)


def main():
    print("=" * 70)
    print("GRID-COORDINATE-DERIVED KEY TEST")
    print("=" * 70)

    crib_pairs = shifted_crib_positions()
    variants = ["vigenere", "beaufort", "var_beaufort"]

    # Define key derivation functions from (row, col)
    # Each returns a list of integer keys for the 73 positions
    def make_key_funcs(row_col: list[tuple[int, int]]) -> dict[str, list[int]]:
        funcs = {}

        # Basic coordinate keys
        funcs["row"] = [r for r, c in row_col]
        funcs["col"] = [c for r, c in row_col]
        funcs["row+col"] = [(r + c) for r, c in row_col]
        funcs["row-col"] = [(r - c) for r, c in row_col]
        funcs["col-row"] = [(c - r) for r, c in row_col]
        funcs["row*col"] = [(r * c) for r, c in row_col]
        funcs["row^col"] = [(r ^ c) for r, c in row_col]  # XOR

        # Distance-based keys
        funcs["|col-15|"] = [abs(c - 15) for r, c in row_col]  # center distance
        funcs["28-row"] = [(28 - r) for r, c in row_col]  # distance from bottom
        funcs["row-24"] = [(r - 24) for r, c in row_col]  # distance from top of K4
        funcs["30-col"] = [(30 - c) for r, c in row_col]  # distance from right

        # Diagonal keys
        funcs["row+col diag"] = [(r + c) for r, c in row_col]  # same as row+col
        funcs["|row-col|"] = [abs(r - c) for r, c in row_col]

        # Modular keys
        for m in [3, 4, 5, 7, 8, 13, 14, 24, 31]:
            funcs[f"col%{m}"] = [c % m for r, c in row_col]
            funcs[f"(r+c)%{m}"] = [(r + c) % m for r, c in row_col]
            funcs[f"(r*c)%{m}"] = [(r * c) % m for r, c in row_col]

        # Grid-index (position within the 28x31 master grid)
        funcs["grid_idx"] = [r * 31 + c for r, c in row_col]
        funcs["grid_idx%26"] = [(r * 31 + c) % 26 for r, c in row_col]

        # Position within K4 section (row 24 = 0, etc.)
        funcs["k4_row"] = [r - 24 for r, c in row_col]
        funcs["k4_row*col"] = [(r - 24) * c for r, c in row_col]

        # Checkerboard patterns
        funcs["(r+c)%2"] = [(r + c) % 2 for r, c in row_col]
        funcs["(r+c)%2 * col"] = [((r + c) % 2) * c for r, c in row_col]

        # Triangular numbers, Fibonacci-like
        funcs["col*(col+1)/2%26"] = [(c * (c + 1) // 2) % 26 for r, c in row_col]
        funcs["row*(row+1)/2%26"] = [(r * (r + 1) // 2) % 26 for r, c in row_col]

        # Key from column number in different alphabets
        # If columns map to letters of KRYPTOS keyword
        KA_KEY = "KRYPTOS"
        funcs["KRYPTOS[col%7]"] = [ord(KA_KEY[c % 7]) - 65 for r, c in row_col]
        funcs["KRYPTOS[(r+c)%7]"] = [ord(KA_KEY[(r + c) % 7]) - 65 for r, c in row_col]

        # Key from popular keywords applied cyclically to columns
        for kw in ["KRYPTOS", "KOMPASS", "BERLIN", "CLOCK", "PALIMPSEST",
                    "DEFECTOR", "ABSCISSA", "COLOPHON", "GRILLE", "CARDAN",
                    "FIVE", "NORTH", "EAST", "POINT", "SHADOW", "LIGHT",
                    "COMPASS", "LOOMIS", "SANBORN", "SCHEIDT", "CIPHER",
                    "ENIGMA", "SECRET", "HIDDEN", "MASK"]:
            kwlen = len(kw)
            funcs[f"{kw}[col%{kwlen}]"] = [ord(kw[c % kwlen]) - 65 for r, c in row_col]
            funcs[f"{kw}[pos%{kwlen}]"] = [ord(kw[i % kwlen]) - 65 for i in range(73)]
            # Key offset by row
            funcs[f"{kw}[col%{kwlen}]+row"] = [(ord(kw[c % kwlen]) - 65 + r) for r, c in row_col]

        # Bearing-derived keys (from LOOMIS triangle)
        # 24° at LOOMIS, 74° at sculpture, 82° at K2
        for angle in [24, 56, 74, 80, 82, 162]:
            funcs[f"(col*{angle})%26"] = [(c * angle) % 26 for r, c in row_col]
            funcs[f"(pos*{angle})%26"] = [(i * angle) % 26 for i in range(73)]

        # Reversed position key
        funcs["72-pos"] = [72 - i for i in range(73)]

        # 24-hour clock keys
        funcs["col%24"] = [c % 24 for r, c in row_col]
        funcs["(r*31+c)%24"] = [(r * 31 + c) % 24 for r, c in row_col]

        return funcs

    best_overall = 0
    best_configs = []
    total_configs = 0

    for keep_col in range(8, 17):
        ct73, row_col = extract_and_map(CT, keep_col)
        key_funcs = make_key_funcs(row_col)

        for key_name, keys in key_funcs.items():
            for variant in variants:
                pt = decrypt_with_keys(ct73, keys, variant)
                score = score_cribs(pt, crib_pairs)
                total_configs += 1

                if score > best_overall:
                    best_overall = score
                    best_configs = []
                if score >= best_overall and score >= 4:
                    best_configs.append(
                        (score, f"{key_name}/{variant} col={keep_col}", pt[:40]))

    # ── Report ───────────────────────────────────────────────────────────
    print(f"\n{total_configs:,} total configs tested")
    print(f"Best score: {best_overall}/24")

    if best_configs:
        seen = set()
        unique = []
        for score, desc, pt in sorted(best_configs, reverse=True):
            if desc not in seen:
                seen.add(desc)
                unique.append((score, desc, pt))
        for score, desc, pt in unique[:20]:
            print(f"  {score}/24  {desc}")
            print(f"         PT: {pt}...")
    else:
        print("  No configs scored >= 4/24")

    # ── Deep analysis: what key would MAKE the cribs work? ───────────────
    print(f"\n{'='*70}")
    print("REQUIRED KEY VALUES AT CRIB POSITIONS (keep col 8)")
    print(f"{'='*70}")

    ct73, row_col = extract_and_map(CT, 8)

    print("\nFor Vigenère (k = CT - PT mod 26):")
    print(f"{'Pos':>4} {'CT':>3} {'PT':>3} {'Key':>4} {'KeyCh':>5} {'Row':>4} {'Col':>4}")
    vig_keys = []
    for pos, pt_ch in crib_pairs:
        ct_ch = ct73[pos]
        k = (ord(ct_ch) - ord(pt_ch)) % MOD
        r, c = row_col[pos]
        print(f"{pos:4d} {ct_ch:>3} {pt_ch:>3} {k:4d} {chr(k+65):>5} {r:4d} {c:4d}")
        vig_keys.append((pos, k, r, c))

    # Check if any simple function of (r,c) produces the key
    print(f"\n{'='*70}")
    print("SEARCHING FOR f(row,col) = key pattern")
    print(f"{'='*70}")

    # For each pair of crib positions, compute what relationship holds
    # between their grid coords and their key values
    print("\nKey differences at consecutive ENE positions:")
    for i in range(12):
        pos1, k1, r1, c1 = vig_keys[i]
        pos2, k2, r2, c2 = vig_keys[i + 1]
        dk = (k2 - k1) % MOD
        dc = c2 - c1
        print(f"  Δkey={dk:3d} Δcol={dc:2d}  (pos {pos1}→{pos2}, col {c1}→{c2})")

    print("\nKey differences at consecutive BC positions:")
    for i in range(13, 23):
        pos1, k1, r1, c1 = vig_keys[i]
        pos2, k2, r2, c2 = vig_keys[i + 1]
        dk = (k2 - k1) % MOD
        dc = c2 - c1
        print(f"  Δkey={dk:3d} Δcol={dc:2d}  (pos {pos1}→{pos2}, col {c1}→{c2})")

    # Check if key = a*col + b*row + c (affine in coordinates)
    print("\nAffine fit attempt: key = a*col + b*row + c (mod 26)")
    found_affine = False
    for a in range(26):
        for b in range(26):
            for c_const in range(26):
                matches = sum(1 for pos, k, r, c in vig_keys
                             if (a * c + b * r + c_const) % MOD == k)
                if matches >= 20:
                    print(f"  a={a} b={b} c={c_const}: {matches}/24 matches")
                    found_affine = True
    if not found_affine:
        print("  No affine function matches >= 20/24 crib positions")

    # Check Beaufort too
    print("\nFor Beaufort (k = CT + PT mod 26):")
    beau_keys = []
    for pos, pt_ch in crib_pairs:
        ct_ch = ct73[pos]
        k = (ord(ct_ch) - 65 + ord(pt_ch) - 65) % MOD
        r, c = row_col[pos]
        beau_keys.append((pos, k, r, c))

    found_affine_b = False
    for a in range(26):
        for b in range(26):
            for c_const in range(26):
                matches = sum(1 for pos, k, r, c in beau_keys
                             if (a * c + b * r + c_const) % MOD == k)
                if matches >= 20:
                    print(f"  Beaufort affine a={a} b={b} c={c_const}: {matches}/24 matches")
                    found_affine_b = True
    if not found_affine_b:
        print("  No Beaufort affine function matches >= 20/24 crib positions")

    print(f"\n{'='*70}")
    if best_overall <= 6:
        print("RESULT: ALL NOISE. Grid-coordinate keys do not produce signal.")
        print("The cipher key is NOT a simple function of grid position.")
    else:
        print(f"RESULT: Best {best_overall}/24. Investigate further.")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
