"""Exact figures for the K4 crib parity pattern that the Lean proofs do not cover.

Run from the repository root:

    PYTHONPATH=src python3 formal/k4_parity/parity_figures.py

Conventions match the Lean files: letters A=0..Z=25, positions counted from 1. Every figure
here is an exact count or an exact rational, not a sample; the standard library is enough.

1. The pattern itself (13 of 13 same-letter pairs, 11 independent checks).
2. Chance under three different "what if it were random" questions:
   a. random cipher letters at the 24 crib positions (exactly 1/2048; also proved in Lean);
   b. K4's own 97 letters shuffled (exact, by summing over odd/even patterns);
   c. a random numbering of the cipher alphabet with the carved letters held fixed.
3. The KRYPTOS-keyed numbering, the plaintext-side class split, and the columnar key count.
"""
from __future__ import annotations

import sys
from fractions import Fraction
from itertools import combinations, permutations, product
from math import comb
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CRIB_DICT, CT  # noqa: E402

N = len(CT)
CRIB = {p + 1: ch for p, ch in CRIB_DICT.items()}  # 1-based, as in the Lean files


def val(ch: str) -> int:
    return ord(ch) - 65


def groups() -> dict[str, list[int]]:
    g: dict[str, list[int]] = {}
    for pos, ch in sorted(CRIB.items()):
        g.setdefault(ch, []).append(pos)
    return g


def same_letter_pairs() -> list[tuple[int, int]]:
    return [(a, b) for ps in groups().values() for a, b in combinations(ps, 2)]


def agree(numbering, a: int, b: int) -> bool:
    return (numbering(CT[a - 1]) + a) % 2 == (numbering(CT[b - 1]) + b) % 2


def shuffle_chance() -> Fraction:
    """Exact chance that a uniformly random rearrangement of K4's 97 letters gives 13/13.

    Only the odd/even value of each letter matters. A consistent outcome is fixed by one bit
    per plaintext letter, which determines the parity needed at each crib position. The chance
    of a particular parity pattern with w odd letters at the 24 positions, when the 97 letters
    contain `odd` odd-valued ones, is C(97-24, odd-w) / C(97, odd).
    """
    odd = sum(val(c) % 2 for c in CT)
    g = list(groups().values())
    total = Fraction(0)
    for bits in product((0, 1), repeat=len(g)):
        w = sum((b + pos) % 2 for b, ps in zip(bits, g) for pos in ps)
        total += Fraction(comb(N - 24, odd - w), comb(N, odd))
    return total


def random_alphabet_chance() -> Fraction:
    """Exact chance of 13/13 when the cipher alphabet is numbered by a uniformly random bijection.

    Only which 13 letters get odd numbers matters. Enumerate odd/even patterns on the 14 cipher
    letters that occur at crib positions, then count the ways to complete each to 13 odd letters.
    """
    letters = sorted({CT[p - 1] for p in CRIB})
    idx = {c: j for j, c in enumerate(letters)}
    pairs = same_letter_pairs()
    good = 0
    for mask in range(1 << len(letters)):
        odd = lambda c: (mask >> idx[c]) & 1  # noqa: E731
        if all(agree(odd, a, b) for a, b in pairs):
            w = bin(mask).count("1")
            if 0 <= 13 - w <= 26 - len(letters):
                good += comb(26 - len(letters), 13 - w)
    return Fraction(good, comb(26, 13))


def columnar_count() -> tuple[int, int]:
    """Columnar keys of width 2..9 for which par(tau(i) + i) is constant on the crib positions.

    Gather convention: write the text in rows of width w, read columns in key order, and
    output i takes input tau(i). Cribs are read at their ciphertext positions.
    """
    cribs0 = sorted(CRIB_DICT)
    total = constant = 0
    for w in range(2, 10):
        full, extra = divmod(N, w)
        collen = [full + (1 if c < extra else 0) for c in range(w)]
        for order in permutations(range(w)):
            tau = [r * w + c for c in order for r in range(collen[c])]
            total += 1
            constant += len({(tau[i] + i) & 1 for i in cribs0}) == 1
    return constant, total


def one_in(f: Fraction) -> str:
    return f"{f.numerator:,}/{f.denominator:,} = 1 in {float(1 / f):,.1f}"


def main() -> None:
    pairs = same_letter_pairs()
    g = groups()
    print("The pattern")
    print(f"  same-letter pairs agreeing: {sum(agree(val, a, b) for a, b in pairs)} of {len(pairs)}")
    print(f"  independent checks: {sum(len(p) - 1 for p in g.values())}")
    odd_class = sorted(c for c, ps in g.items() if (val(CT[ps[0] - 1]) + ps[0]) % 2)
    even_class = sorted(c for c, ps in g.items() if not (val(CT[ps[0] - 1]) + ps[0]) % 2)
    print(f"  odd class {odd_class}, even class {even_class}")

    print("Chance of 13/13")
    print(f"  random cipher letters at the cribs: {one_in(Fraction(2**13 * 13**24, 26**24))}")
    print(f"  K4's 97 letters shuffled:           {one_in(shuffle_chance())}")
    print(f"  random cipher-alphabet numbering:   {one_in(random_alphabet_chance())}")

    ka = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    print("Other figures")
    print(f"  KRYPTOS-keyed cipher numbering: {sum(agree(ka.index, a, b) for a, b in pairs)} of {len(pairs)} pairs agree")
    print(f"  plaintext alphabets splitting the classes: {one_in(Fraction(2 * comb(13, 6), comb(26, 13)))}")
    c, t = columnar_count()
    print(f"  columnar keys w=2..9 with constant par(tau(i)+i) on the cribs: {c:,} of {t:,}")


if __name__ == "__main__":
    main()
