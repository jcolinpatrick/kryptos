#!/usr/bin/env python3
"""
Cipher: non-columnar transposition
Family: transposition/other
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-SOLVE-05: Key Transposition Hypothesis.

NOVEL INSIGHT: What if the KEYSTREAM (not the plaintext) is produced by
columnar transposition of a periodic key text?

Model:
  1. A periodic key text T (from repeating a keyword) is written into a grid
  2. The grid is read by columns in keyword order -> this produces the actual keystream
  3. CT[i] = PT[i] + transposed_key[i] mod 26

This produces a NON-PERIODIC effective keystream from a PERIODIC source.
It has never been directly tested because all prior experiments transpose
the CT or PT, not the key itself.

Also tests:
  H22: Non-linear two-keyword combination through the KA tableau
  H23: Key derived from READING the KA tableau in non-standard order
"""

import json
import sys
import time
from pathlib import Path
from itertools import permutations

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET,
    CRIB_DICT, BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)

CT_VALS = [ALPH_IDX[c] for c in CT]
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}


def crib_score(pt_vals):
    score = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt_vals) and pt_vals[pos] == ALPH_IDX[ch]:
            score += 1
    return score


def bean_check(key_vals):
    for a, b in BEAN_EQ:
        if a < len(key_vals) and b < len(key_vals):
            if key_vals[a] != key_vals[b]:
                return False
    for a, b in BEAN_INEQ:
        if a < len(key_vals) and b < len(key_vals):
            if key_vals[a] == key_vals[b]:
                return False
    return True


# Known keystream at crib positions (Vigenère convention)
KNOWN_KEYS = {}
for i, k in enumerate(VIGENERE_KEY_ENE):
    KNOWN_KEYS[21 + i] = k
for i, k in enumerate(VIGENERE_KEY_BC):
    KNOWN_KEYS[63 + i] = k


# ====================================================================
# H21: Key Transposition — Columnar Transposition of Periodic Key
# ====================================================================
def test_key_transposition():
    """
    For each grid width W and column permutation:
    1. Build the inverse columnar transposition mapping (keystream pos → source pos)
    2. Map the 24 known keystream values to their source positions
    3. Check if the values at source positions are periodic (same value at same residue mod P)
    4. If periodic, the source key is a repeated keyword of length P
    5. Decrypt the full CT with the reconstructed key

    This tests: is there a columnar transposition of a periodic key that
    produces the observed non-periodic keystream?
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 21: Key Transposition (Columnar Trans of Periodic Key)")
    print("=" * 70)

    best_score = 0
    above_noise = 0
    total = 0
    candidates = []

    for W in range(5, 16):
        n_full_rows = CT_LEN // W
        n_extra = CT_LEN % W  # first n_extra columns are 1 longer

        # For small widths, enumerate all permutations
        if W <= 8:
            perms = list(permutations(range(W)))
        else:
            # Use keyword-derived permutations
            kw_list = [
                "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
                "CLOCK", "EAST", "NORTH", "SCHEIDT", "SANBORN",
                "CARTER", "PHARAOH", "LANGLEY", "VIRGINIA", "MATRIX",
                "INVISIBLE", "DIGETAL", "INTERPRETATU", "UNDERGRUUND",
                "DESPERATELY", "REMINDER", "IQLUSION", "SUBTLESHADING",
            ]
            perms = set()
            for kw in kw_list:
                kw_upper = kw.upper()
                if len(kw_upper) < W:
                    continue
                kw_trimmed = kw_upper[:W]
                indexed = tuple(sorted(range(W), key=lambda i: (kw_trimmed[i], i)))
                perms.add(indexed)
            perms.add(tuple(range(W)))
            perms.add(tuple(reversed(range(W))))
            perms = list(perms)

        for perm in perms:
            # Build inverse mapping: keystream position → source text position
            # Columnar trans: write source into W columns (by rows),
            # read by columns in perm order
            # source pos (r, c) → keystream pos
            col_heights = []
            for c in range(W):
                if n_extra == 0:
                    col_heights.append(n_full_rows)
                elif c < n_extra:
                    col_heights.append(n_full_rows + 1)
                else:
                    col_heights.append(n_full_rows)

            # Build forward map: source_pos → keystream_pos
            source_to_key = {}
            key_pos = 0
            for col_idx in perm:
                for r in range(col_heights[col_idx]):
                    source_pos = r * W + col_idx
                    if source_pos < CT_LEN:
                        source_to_key[source_pos] = key_pos
                        key_pos += 1

            if key_pos != CT_LEN:
                continue

            # Inverse: keystream_pos → source_pos
            key_to_source = {v: k for k, v in source_to_key.items()}

            # Map known keystream values to source positions
            source_known = {}
            for key_pos_val, key_val in KNOWN_KEYS.items():
                if key_pos_val in key_to_source:
                    src_pos = key_to_source[key_pos_val]
                    source_known[src_pos] = key_val

            # Check if source values are periodic
            for period in range(2, 8):  # Only discriminating periods
                by_residue = {}
                consistent = True
                for src_pos, kval in source_known.items():
                    res = src_pos % period
                    if res in by_residue:
                        if by_residue[res] != kval:
                            consistent = False
                            break
                    else:
                        by_residue[res] = kval

                total += 1

                if not consistent:
                    continue

                # Check how many residues are covered
                n_covered = len(by_residue)
                n_uncovered = period - n_covered

                if n_covered < period:
                    continue  # Need full coverage for discriminating test

                # Fully determined periodic source key!
                # Reconstruct full key
                source_key = [by_residue[i % period] for i in range(CT_LEN)]

                # Apply transposition to source key to get keystream
                keystream = [0] * CT_LEN
                for src_pos, key_pos_val in source_to_key.items():
                    keystream[key_pos_val] = source_key[src_pos]

                # Decrypt (Vigenère)
                pt_vals = [(CT_VALS[i] - keystream[i]) % 26 for i in range(CT_LEN)]
                score = crib_score(pt_vals)

                if score >= 24:
                    # Check Bean
                    bean = bean_check(keystream)
                    # Check quality
                    pt_text = ''.join(ALPH[v] for v in pt_vals)
                    src_key_text = ''.join(ALPH[v] for v in source_key[:period])
                    print(f"  *** W={W}, perm={perm}, period={period}, "
                          f"src_key={src_key_text}, score={score}, Bean={'PASS' if bean else 'FAIL'}")
                    print(f"      PT: {pt_text}")
                    candidates.append({
                        "width": W, "perm": str(perm), "period": period,
                        "source_key": src_key_text, "score": score,
                        "bean": bean, "pt": pt_text,
                    })

                if score > best_score:
                    best_score = score
                if score > NOISE_FLOOR:
                    above_noise += 1

                # Also try Beaufort
                pt_vals_b = [(keystream[i] - CT_VALS[i]) % 26 for i in range(CT_LEN)]
                score_b = crib_score(pt_vals_b)
                total += 1

                if score_b >= 24:
                    bean_b = bean_check(keystream)
                    pt_text_b = ''.join(ALPH[v] for v in pt_vals_b)
                    src_key_text = ''.join(ALPH[v] for v in source_key[:period])
                    print(f"  *** [BEAU] W={W}, perm={perm}, period={period}, "
                          f"src_key={src_key_text}, score={score_b}, Bean={'PASS' if bean_b else 'FAIL'}")
                    print(f"      PT: {pt_text_b}")
                    candidates.append({
                        "width": W, "perm": str(perm), "period": period,
                        "source_key": src_key_text, "score": score_b,
                        "bean": bean_b, "pt": pt_text_b, "variant": "beaufort",
                    })

                if score_b > best_score:
                    best_score = score_b
                if score_b > NOISE_FLOOR:
                    above_noise += 1

        if W <= 8:
            print(f"  Width {W}: tested {len(perms)} permutations × periods 2-7")

    print(f"\n  Total tested: {total}")
    print(f"  Best score: {best_score}/24")
    print(f"  Above-noise: {above_noise}")
    print(f"  Score-24 candidates: {len(candidates)}")
    return {"total": total, "best": best_score, "above_noise": above_noise,
            "candidates": candidates}


# ====================================================================
# H22: Non-Linear Two-Keyword Combination via KA Tableau
# ====================================================================
def test_nonlinear_combination():
    """
    Instead of k = kw1 + kw2 (additive, equivalent to single key, eliminated),
    use the KA tableau as a non-linear combination function:

    k[i] = KA_tableau_lookup(kw1[i%p1], kw2[i%p2])

    where the lookup uses non-standard access patterns:
    - Standard: tableau[r][c] = KA[(r+c) % 26] — this IS addition, eliminated
    - Reverse column: tableau[r][25-c] — this gives KA[(r+26-c)%26] = subtraction
    - Diagonal: tableau[r][(r+c) % 26] — adds a position-dependent offset
    - Square access: tableau[kw1][kw2] where positions are in KA-space

    Test multiplication in KA-space:
    k[i] = KA_idx(kw1[i%p1]) * KA_idx(kw2[i%p2]) mod 26
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 22: Non-Linear Two-Keyword Combination")
    print("=" * 70)

    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
        "CLOCK", "EAST", "NORTH", "SCHEIDT", "SANBORN",
        "LIGHT", "POINT", "MATRIX", "CARTER", "HOWARD",
        "TOMB", "DIGETAL", "REMINDER", "WEBSTER", "LANGLEY",
    ]

    # Combination functions
    def combine_mult(a, b):
        return (a * b) % 26

    def combine_power(a, b):
        return pow(a, b, 26) if b > 0 else 0

    def combine_ka_mult(a, b):
        # Convert to KA positions, multiply, convert back
        ka_a = KA_IDX.get(ALPH[a], a)
        ka_b = KA_IDX.get(ALPH[b], b)
        result = (ka_a * ka_b) % 26
        return ALPH_IDX.get(KA[result], result)

    def combine_xor(a, b):
        return (a ^ b) % 26

    def combine_max(a, b):
        return max(a, b)

    def combine_min_plus(a, b):
        return (min(a, b) + max(a, b)) % 26  # same as a+b

    def combine_abs_diff(a, b):
        return abs(a - b) % 26

    def combine_ka_sub(a, b):
        ka_a = KA_IDX.get(ALPH[a], a)
        ka_b = KA_IDX.get(ALPH[b], b)
        return ALPH_IDX.get(KA[(ka_a - ka_b) % 26], 0)

    combiners = [
        ("mult", combine_mult),
        ("ka_mult", combine_ka_mult),
        ("xor", combine_xor),
        ("abs_diff", combine_abs_diff),
        ("ka_sub", combine_ka_sub),
    ]

    best_score = 0
    above_noise = 0
    total = 0

    for kw1 in keywords:
        k1 = [ALPH_IDX[c] for c in kw1]
        p1 = len(kw1)

        for kw2 in keywords:
            if kw1 >= kw2:
                continue
            k2 = [ALPH_IDX[c] for c in kw2]
            p2 = len(kw2)

            for comb_name, comb_fn in combiners:
                # Generate keystream
                key_vals = [comb_fn(k1[i % p1], k2[i % p2]) for i in range(CT_LEN)]

                # Decrypt Vigenère
                pt_vals = [(CT_VALS[i] - key_vals[i]) % 26 for i in range(CT_LEN)]
                score = crib_score(pt_vals)
                total += 1
                if score > best_score:
                    best_score = score
                if score > NOISE_FLOOR:
                    above_noise += 1

                # Decrypt Beaufort
                pt_vals_b = [(key_vals[i] - CT_VALS[i]) % 26 for i in range(CT_LEN)]
                score_b = crib_score(pt_vals_b)
                total += 1
                if score_b > best_score:
                    best_score = score_b
                if score_b > NOISE_FLOOR:
                    above_noise += 1

    print(f"  Tested {total} non-linear combination configs")
    print(f"  Best score: {best_score}/24")
    print(f"  Above-noise: {above_noise}")
    return {"total": total, "best": best_score, "above_noise": above_noise}


# ====================================================================
# H23: Key from Reading KA Tableau in Non-Standard Order
# ====================================================================
def test_tableau_reading():
    """
    The KA tableau has 26 rows, each a cyclic shift of KA.
    Read the tableau in various non-standard orders to generate a keystream.

    Non-standard orders:
    - Column-major (top to bottom, left to right in columns)
    - Diagonal (main diagonal, then anti-diagonals)
    - Spiral (clockwise from top-left)
    - Knight's move (chess knight L-shape)
    - Keyword-column-order then rows
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 23: Key from Tableau Non-Standard Reading")
    print("=" * 70)

    # Build KA tableau
    tableau = []
    for r in range(26):
        row = [KA_IDX[KA[(c + r) % 26]] for c in range(26)]
        tableau.append(row)

    best_score = 0
    above_noise = 0
    total = 0

    # Column-major readings with different column orders
    kw_list = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
        "CLOCK", "EAST", "NORTH", "SCHEIDT", "SANBORN",
    ]

    for kw in kw_list:
        # Column order from keyword
        kw_vals = [ALPH_IDX[c] for c in kw]
        col_order = sorted(range(len(kw)), key=lambda i: (kw[i], i))

        # Read tableau columns in keyword order, rows top to bottom
        key_stream = []
        for c_idx in col_order:
            col = c_idx % 26
            for r in range(26):
                key_stream.append(tableau[r][col])
                if len(key_stream) >= CT_LEN:
                    break
            if len(key_stream) >= CT_LEN:
                break

        if len(key_stream) < CT_LEN:
            # Extend
            key_stream = (key_stream * 4)[:CT_LEN]

        # Try with different starting offsets
        for offset in range(0, min(26 * 26, len(key_stream) - CT_LEN + 1), 1):
            ks = key_stream[offset:offset + CT_LEN]
            if len(ks) < CT_LEN:
                break

            pt_vals = [(CT_VALS[i] - ks[i]) % 26 for i in range(CT_LEN)]
            score = crib_score(pt_vals)
            total += 1
            if score > best_score:
                best_score = score
            if score > NOISE_FLOOR:
                above_noise += 1

    # Diagonal readings
    for start_r in range(26):
        for start_c in range(26):
            for dr, dc in [(1, 1), (1, 0), (0, 1), (1, -1), (2, 1), (1, 2)]:
                key_stream = []
                r, c = start_r, start_c
                for _ in range(CT_LEN):
                    key_stream.append(tableau[r % 26][c % 26])
                    r += dr
                    c += dc

                pt_vals = [(CT_VALS[i] - key_stream[i]) % 26 for i in range(CT_LEN)]
                score = crib_score(pt_vals)
                total += 1
                if score > best_score:
                    best_score = score
                if score > NOISE_FLOOR:
                    above_noise += 1

    print(f"  Tested {total} tableau reading configs")
    print(f"  Best score: {best_score}/24")
    print(f"  Above-noise: {above_noise}")
    return {"total": total, "best": best_score, "above_noise": above_noise}


# ====================================================================
# MAIN
# ====================================================================
def main():
    print(f"E-SOLVE-05: Key Transposition & Non-Linear Combination Attacks")
    print(f"CT: {CT[:45]}...")
    print()

    t0 = time.time()
    results = {}

    results["h21_key_transposition"] = test_key_transposition()
    results["h22_nonlinear_combo"] = test_nonlinear_combination()
    results["h23_tableau_reading"] = test_tableau_reading()

    elapsed = time.time() - t0

    print("\n" + "=" * 70)
    print(f"E-SOLVE-05 SUMMARY ({elapsed:.1f}s)")
    print("=" * 70)
    for name, res in results.items():
        print(f"  {name}: {res.get('above_noise', 0)} above-noise, "
              f"best={res.get('best', 0)}/24")
        if res.get("candidates"):
            print(f"    Score-24 candidates: {len(res['candidates'])}")

    total_an = sum(r.get("above_noise", 0) for r in results.values())
    print(f"\n  OVERALL: {total_an} above-noise results found!")

    out_path = Path("results/e_solve_05_results.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Remove non-serializable items for JSON output
    json_results = {}
    for k, v in results.items():
        json_results[k] = {kk: vv for kk, vv in v.items()
                          if kk != "candidates" or not vv}
        if v.get("candidates"):
            json_results[k]["candidates"] = v["candidates"][:50]

    out_path.write_text(json.dumps(json_results, indent=2, default=str))
    print(f"  Results saved to {out_path}")


if __name__ == "__main__":
    main()
