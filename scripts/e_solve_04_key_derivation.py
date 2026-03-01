#!/usr/bin/env python3
"""E-SOLVE-04: Novel key derivation attacks.

Key insight: if the KEY itself is produced by a procedure (not just
a repeated word), it could appear non-periodic even though the
generation method is structured.

Targets:
  H16: Key from columnar-transposed phrase (write phrase in grid, read columns)
  H17: Key from tableau walk (follow a path through the KA Vigenère tableau)
  H18: Key = f(CT) — the key depends on the ciphertext in a non-autokey way
  H19: Key from interleaving two short keywords
  H20: Key derived by XOR/addition of position with a keyword-derived value
"""

import json
import sys
import time
from pathlib import Path
from itertools import permutations

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_POSITIONS, BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD,
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


def decrypt_vig(key_vals):
    return [(CT_VALS[i] - key_vals[i]) % 26 for i in range(CT_LEN)]


def decrypt_beau(key_vals):
    return [(key_vals[i] - CT_VALS[i]) % 26 for i in range(CT_LEN)]


# ====================================================================
# H16: Key from Columnar-Transposed Phrase
# ====================================================================
def test_columnar_key():
    """
    Write a key phrase into a grid, read by columns (in keyword order).
    The resulting sequence becomes the encryption keystream.

    This produces a NON-PERIODIC key from a structured source.
    Sheidt mentioned "matrix codes" — this is literally a matrix-derived key.
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 16: Key from Columnar-Transposed Phrase")
    print("=" * 70)

    # Key phrases: things Sanborn/Scheidt might use
    phrases = [
        "KRYPTOSABCDEFGHIJLMNQUVWXZ" * 4,  # KA repeated
        "PALIMPSESTABSCISSAKRYPTOS",
        "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION",
        "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLE",
        "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRIS",
        "WHOISTHEBURIEDPERSONWHATISTHECOORDINATESWHEREARETHEY",
        "EASTNORTHEASTBERLINCLOCK",
        "SHADOWFORCESLANGLEYVIRGINIA",
        "VIRTUALLYINVISIBLEDIGETAL",
        "THEAMERICANCRYPTOGRAPHICASSOCIATION",
        "KRYPTOSSCULPTURECENTRALINTELLIGENCEAGENCY",
        "HOWARDCARTEROPENEDTHETOMBOFTUTANKHAMUN",
        "ONLYWACANKNOWTHIS",
        "TWOWORDSARETHEKEY",
        "LAYERTWOXLAYERTWO",
        "POINTABSCISSA",
        "DIGESTTHISONEWAYTOCOMPREHENDTHEWHOLEISTOSTUDYTHEPARTS",
    ]

    # Column ordering keywords
    col_keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
        "CLOCK", "EAST", "NORTH", "SCHEIDT", "SANBORN",
        "LIGHT", "POINT", "KEY", "CODE", "MATRIX",
    ]

    best_score = 0
    above_noise = 0
    total = 0

    for phrase in phrases:
        phrase_vals = [ALPH_IDX[c] for c in phrase.upper() if c in ALPH_IDX]
        if len(phrase_vals) < CT_LEN:
            # Extend by repeating
            phrase_vals = (phrase_vals * ((CT_LEN // len(phrase_vals)) + 2))[:CT_LEN + 50]

        for col_kw in col_keywords:
            width = len(col_kw)
            if width < 3 or width > 20:
                continue

            # Determine column read order from keyword
            indexed = sorted(range(width), key=lambda i: (col_kw[i], i))

            # Write phrase into grid, read by columns in keyword order
            n_rows = (len(phrase_vals) + width - 1) // width
            grid = []
            for r in range(n_rows):
                row = []
                for c in range(width):
                    idx = r * width + c
                    row.append(phrase_vals[idx] if idx < len(phrase_vals) else 0)
                grid.append(row)

            # Read columns in keyword order
            key_vals = []
            for col in indexed:
                for r in range(n_rows):
                    key_vals.append(grid[r][col])
                    if len(key_vals) >= CT_LEN:
                        break
                if len(key_vals) >= CT_LEN:
                    break

            key_vals = key_vals[:CT_LEN]
            if len(key_vals) < CT_LEN:
                continue

            # Decrypt with Vigenère and Beaufort
            for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
                pt_vals = decrypt_fn(key_vals)
                score = crib_score(pt_vals)
                total += 1
                if score > best_score:
                    best_score = score
                if score > NOISE_FLOOR:
                    above_noise += 1

            # Also: key derived by reading rows (standard order) after column shuffle
            # This is equivalent to transposing the phrase, then using it as key
            key_vals2 = []
            for r in range(n_rows):
                for col in indexed:
                    key_vals2.append(grid[r][col])
                    if len(key_vals2) >= CT_LEN:
                        break
                if len(key_vals2) >= CT_LEN:
                    break

            key_vals2 = key_vals2[:CT_LEN]
            if len(key_vals2) < CT_LEN:
                continue

            for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
                pt_vals = decrypt_fn(key_vals2)
                score = crib_score(pt_vals)
                total += 1
                if score > best_score:
                    best_score = score
                if score > NOISE_FLOOR:
                    above_noise += 1

    print(f"  Tested {total} columnar-key configs")
    print(f"  Best score: {best_score}/24")
    print(f"  Above-noise: {above_noise}")
    return {"total": total, "best": best_score, "above_noise": above_noise}


# ====================================================================
# H17: Key from Tableau Walk
# ====================================================================
def test_tableau_walk():
    """
    The Kryptos tableau is physically present on the sculpture.
    What if the key is generated by walking through the tableau
    following a specific pattern, collecting letters?

    Tableau: row r = cyclic shift of KA by r positions
    tableau[r][c] = KA[(c + r) % 26]
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 17: Key from Tableau Walk")
    print("=" * 70)

    # Build the tableau
    def tableau(r, c):
        return KA[(c + r) % 26]

    def tableau_val(r, c):
        return KA_IDX[tableau(r, c)]

    # Walk patterns: start at (r0, c0), advance by (dr, dc)
    # Each collected letter becomes the key at that position
    walks = []

    # Linear walks with various slopes
    for r0 in range(26):
        for c0 in range(26):
            for dr in range(-5, 6):
                for dc in range(-5, 6):
                    if dr == 0 and dc == 0:
                        continue
                    walks.append((r0, c0, dr, dc))

    # Keyword-directed walks: row = keyword letter index
    keyword_walks = []
    keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
                "CLOCK", "EAST", "NORTH", "SCHEIDT", "SANBORN",
                "MATRIX", "LIGHT", "POINT", "CARTER", "HOWARD"]

    for kw in keywords:
        kw_vals = [ALPH_IDX[c] for c in kw]
        # Walk: row = kw[i % len(kw)], column advances
        for c0 in range(26):
            for dc in range(1, 26):
                walk_key = []
                for i in range(CT_LEN):
                    r = kw_vals[i % len(kw)]
                    c = (c0 + i * dc) % 26
                    walk_key.append(ALPH_IDX[tableau(r, c)])
                keyword_walks.append((kw, c0, dc, walk_key))

    best_score = 0
    above_noise = 0
    total = 0

    # Test linear walks (sampled — too many for exhaustive)
    import random
    random.seed(42)
    sampled_walks = random.sample(walks, min(50000, len(walks)))

    for r0, c0, dr, dc in sampled_walks:
        key_vals = []
        for i in range(CT_LEN):
            r = (r0 + i * dr) % 26
            c = (c0 + i * dc) % 26
            key_vals.append(ALPH_IDX[tableau(r, c)])

        for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
            pt_vals = decrypt_fn(key_vals)
            score = crib_score(pt_vals)
            total += 1
            if score > best_score:
                best_score = score
            if score > NOISE_FLOOR:
                above_noise += 1

    # Test keyword-directed walks
    for kw, c0, dc, walk_key in keyword_walks:
        for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
            pt_vals = decrypt_fn(walk_key)
            score = crib_score(pt_vals)
            total += 1
            if score > best_score:
                best_score = score
            if score > NOISE_FLOOR:
                above_noise += 1

    print(f"  Tested {total} tableau walk configs")
    print(f"  Best score: {best_score}/24")
    print(f"  Above-noise: {above_noise}")
    return {"total": total, "best": best_score, "above_noise": above_noise}


# ====================================================================
# H18: Key = f(CT) — Non-Autokey CT Dependence
# ====================================================================
def test_ct_function_key():
    """
    What if the key at position i depends on the ciphertext, but not
    as standard autokey? For example:

    - key[i] = CT[97-1-i] (reversed CT)
    - key[i] = CT[i*k mod 97] for various k (permuted CT)
    - key[i] = sum(CT[0:i]) mod 26 (running sum)
    - key[i] = CT[i] * a + b mod 26 (affine of CT)
    - key[i] = CT[i] XOR CT[i-1] (differential)
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 18: Key = f(CT) — Non-Autokey CT Dependence")
    print("=" * 70)

    best_score = 0
    above_noise = 0
    total = 0

    # key[i] = CT[i*k mod 97] for k coprime to 97
    # Since 97 is prime, all k=1..96 are coprime
    for k in range(1, 97):
        key_vals = [CT_VALS[(i * k) % 97] for i in range(CT_LEN)]

        for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
            pt_vals = decrypt_fn(key_vals)
            score = crib_score(pt_vals)
            total += 1
            if score > best_score:
                best_score = score
            if score > NOISE_FLOOR:
                above_noise += 1

    # key[i] = CT[(i + offset) mod 97] for various offsets (shifted CT)
    for offset in range(1, 97):
        key_vals = [CT_VALS[(i + offset) % 97] for i in range(CT_LEN)]

        for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
            pt_vals = decrypt_fn(key_vals)
            score = crib_score(pt_vals)
            total += 1
            if score > best_score:
                best_score = score
            if score > NOISE_FLOOR:
                above_noise += 1

    # key[i] = a*CT[i] + b mod 26 (affine transform of CT values)
    valid_a = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
    for a in valid_a:
        for b in range(26):
            key_vals = [(a * CT_VALS[i] + b) % 26 for i in range(CT_LEN)]

            for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
                pt_vals = decrypt_fn(key_vals)
                score = crib_score(pt_vals)
                total += 1
                if score > best_score:
                    best_score = score
                if score > NOISE_FLOOR:
                    above_noise += 1

    # key[i] = running XOR of CT (CT[i] XOR CT[i-1])
    for start in range(26):
        key_vals = [start]
        for i in range(1, CT_LEN):
            key_vals.append((CT_VALS[i] ^ CT_VALS[i-1]) % 26)

        for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
            pt_vals = decrypt_fn(key_vals)
            score = crib_score(pt_vals)
            total += 1
            if score > best_score:
                best_score = score
            if score > NOISE_FLOOR:
                above_noise += 1

    # key[i] = running sum of CT mod 26
    for start_offset in range(26):
        key_vals = []
        running = start_offset
        for i in range(CT_LEN):
            running = (running + CT_VALS[i]) % 26
            key_vals.append(running)

        for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
            pt_vals = decrypt_fn(key_vals)
            score = crib_score(pt_vals)
            total += 1
            if score > best_score:
                best_score = score
            if score > NOISE_FLOOR:
                above_noise += 1

    # key[i] = CT in KA-space permutation (read CT through KA ordering)
    # CT letter → KA position → use as key value
    key_vals = [KA_IDX[CT[i]] for i in range(CT_LEN)]
    for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
        pt_vals = decrypt_fn(key_vals)
        score = crib_score(pt_vals)
        total += 1
        if score > best_score:
            best_score = score
        if score > NOISE_FLOOR:
            above_noise += 1

    # Same but reversed
    key_vals = [KA_IDX[CT[96-i]] for i in range(CT_LEN)]
    for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
        pt_vals = decrypt_fn(key_vals)
        score = crib_score(pt_vals)
        total += 1
        if score > best_score:
            best_score = score
        if score > NOISE_FLOOR:
            above_noise += 1

    print(f"  Tested {total} CT-function key configs")
    print(f"  Best score: {best_score}/24")
    print(f"  Above-noise: {above_noise}")
    return {"total": total, "best": best_score, "above_noise": above_noise}


# ====================================================================
# H19: Key from Interleaving Two Short Keywords
# ====================================================================
def test_interleaved_keys():
    """
    The "two systems" clue could mean two keywords interleaved:
    key = K1[0], K2[0], K1[1], K2[1], ...

    Or more complex: K1 advances every N positions, K2 every M.
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 19: Interleaved Keyword Keys")
    print("=" * 70)

    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
        "CLOCK", "EAST", "NORTH", "SCHEIDT", "SANBORN",
        "LIGHT", "POINT", "MATRIX", "CARTER", "HOWARD",
        "TOMB", "EGYPT", "PHARAOH", "DIGETAL", "REMINDER",
        "WEBSTER", "LANGLEY", "VIRGINIA", "INVISIBLE", "HIDDEN",
    ]

    best_score = 0
    above_noise = 0
    total = 0

    for kw1 in keywords:
        k1_vals = [ALPH_IDX[c] for c in kw1]
        p1 = len(kw1)

        for kw2 in keywords:
            if kw1 >= kw2:  # avoid duplicates
                continue
            k2_vals = [ALPH_IDX[c] for c in kw2]
            p2 = len(kw2)

            # Interleave: alternate between kw1 and kw2
            # Pattern 1: strict alternation
            key_vals = []
            i1, i2 = 0, 0
            for i in range(CT_LEN):
                if i % 2 == 0:
                    key_vals.append(k1_vals[i1 % p1])
                    i1 += 1
                else:
                    key_vals.append(k2_vals[i2 % p2])
                    i2 += 1

            for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
                pt_vals = decrypt_fn(key_vals)
                score = crib_score(pt_vals)
                total += 1
                if score > best_score:
                    best_score = score
                if score > NOISE_FLOOR:
                    above_noise += 1

            # Pattern 2: add the two keywords (key[i] = kw1[i%p1] + kw2[i%p2] mod 26)
            key_vals = [(k1_vals[i % p1] + k2_vals[i % p2]) % 26 for i in range(CT_LEN)]
            for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
                pt_vals = decrypt_fn(key_vals)
                score = crib_score(pt_vals)
                total += 1
                if score > best_score:
                    best_score = score
                if score > NOISE_FLOOR:
                    above_noise += 1

            # Pattern 3: multiply (key[i] = kw1[i%p1] * kw2[i%p2] mod 26)
            key_vals = [(k1_vals[i % p1] * k2_vals[i % p2]) % 26 for i in range(CT_LEN)]
            for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
                pt_vals = decrypt_fn(key_vals)
                score = crib_score(pt_vals)
                total += 1
                if score > best_score:
                    best_score = score
                if score > NOISE_FLOOR:
                    above_noise += 1

            # Pattern 4: XOR (key[i] = kw1[i%p1] XOR kw2[i%p2])
            key_vals = [(k1_vals[i % p1] ^ k2_vals[i % p2]) % 26 for i in range(CT_LEN)]
            for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
                pt_vals = decrypt_fn(key_vals)
                score = crib_score(pt_vals)
                total += 1
                if score > best_score:
                    best_score = score
                if score > NOISE_FLOOR:
                    above_noise += 1

    print(f"  Tested {total} interleaved key configs")
    print(f"  Best score: {best_score}/24")
    print(f"  Above-noise: {above_noise}")
    return {"total": total, "best": best_score, "above_noise": above_noise}


# ====================================================================
# H20: Key = keyword[i%p] + f(position) mod 26
# ====================================================================
def test_position_modified_key():
    """
    Key combines a periodic keyword with a position-dependent modifier.
    This produces a non-periodic key from a structured source.

    key[i] = keyword[i % p] + g(i) mod 26

    where g could be: i, i^2, i mod k, floor(i/k), etc.
    """
    print("\n" + "=" * 70)
    print("HYPOTHESIS 20: Position-Modified Keyword Key")
    print("=" * 70)

    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN",
        "CLOCK", "EAST", "NORTH", "SCHEIDT", "SANBORN",
    ]

    # Position functions
    def pos_fns():
        yield "i", lambda i: i
        yield "i^2", lambda i: i * i
        yield "i*2", lambda i: i * 2
        yield "i*3", lambda i: i * 3
        yield "i*5", lambda i: i * 5
        yield "i*7", lambda i: i * 7
        yield "i*11", lambda i: i * 11
        yield "i*13", lambda i: i * 13
        yield "97-i", lambda i: 97 - i
        yield "i//7", lambda i: i // 7
        yield "i//8", lambda i: i // 8
        yield "i//9", lambda i: i // 9
        yield "i%7", lambda i: i % 7
        yield "i%8", lambda i: i % 8
        yield "i%13", lambda i: i % 13
        yield "fib(i)", lambda i: _fib_memo(i)
        yield "tri(i)", lambda i: (i * (i + 1)) // 2

    _fib_cache = {0: 0, 1: 1}
    def _fib_memo(n):
        if n not in _fib_cache:
            _fib_cache[n] = _fib_memo(n-1) + _fib_memo(n-2)
        return _fib_cache[n]

    best_score = 0
    above_noise = 0
    total = 0

    for kw in keywords:
        kw_vals = [ALPH_IDX[c] for c in kw]
        p = len(kw)

        for fn_name, fn in pos_fns():
            # key[i] = kw[i%p] + g(i) mod 26
            key_vals = [(kw_vals[i % p] + fn(i)) % 26 for i in range(CT_LEN)]

            for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
                pt_vals = decrypt_fn(key_vals)
                score = crib_score(pt_vals)
                total += 1
                if score > best_score:
                    best_score = score
                if score > NOISE_FLOOR:
                    above_noise += 1

            # Also: key[i] = kw[i%p] * g(i) mod 26 (multiplicative)
            key_vals = [(kw_vals[i % p] * fn(i)) % 26 for i in range(CT_LEN)]

            for variant, decrypt_fn in [("vig", decrypt_vig), ("beau", decrypt_beau)]:
                pt_vals = decrypt_fn(key_vals)
                score = crib_score(pt_vals)
                total += 1
                if score > best_score:
                    best_score = score
                if score > NOISE_FLOOR:
                    above_noise += 1

    print(f"  Tested {total} position-modified key configs")
    print(f"  Best score: {best_score}/24")
    print(f"  Above-noise: {above_noise}")
    return {"total": total, "best": best_score, "above_noise": above_noise}


# ====================================================================
# MAIN
# ====================================================================
def main():
    print(f"E-SOLVE-04: Novel Key Derivation Attacks")
    print(f"CT: {CT[:45]}...")
    print()

    t0 = time.time()
    results = {}

    results["h16_columnar_key"] = test_columnar_key()
    results["h17_tableau_walk"] = test_tableau_walk()
    results["h18_ct_function"] = test_ct_function_key()
    results["h19_interleaved"] = test_interleaved_keys()
    results["h20_pos_modified"] = test_position_modified_key()

    elapsed = time.time() - t0

    print("\n" + "=" * 70)
    print(f"E-SOLVE-04 SUMMARY ({elapsed:.1f}s)")
    print("=" * 70)
    for name, res in results.items():
        print(f"  {name}: {res.get('above_noise', 0)} above-noise results")

    total_an = sum(r.get("above_noise", 0) for r in results.values())
    print(f"\n  OVERALL: {total_an} above-noise results found!")

    out_path = Path("results/e_solve_04_results.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2, default=str))
    print(f"  Results saved to {out_path}")


if __name__ == "__main__":
    main()
