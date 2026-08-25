"""Attainable-crib-ceiling filter, generalised over alignment and key frame.

WHAT THIS IS
------------
For any model of the form

    PT[q]  =  pt_alpha[ ( ct_idx[ CT[ align(q) ] ]  -  shift[ cls(q) ] )  mod 26 ]

where `shift` is an arbitrary free vector indexed by a CLASS label, the maximum
number of cribs simultaneously satisfiable over ALL possible keys is a closed
form that requires no search:

    a crib (q -> c) demands   shift[cls(q)] == t_q
    with                      t_q = ( ct_idx[CT[align(q)]] - pt_idx[c] ) mod 26

    t_q involves no key material. Cribs sharing a class must demand the same t.

    ceiling = sum over classes of ( max multiplicity of t within that class )

EPISTEMICS -- READ THIS
-----------------------
The ceiling is an UPPER BOUND, and the implication runs one way only:

    ceiling <  n_cribs   =>  IMPOSSIBLE for every key.        SOUND ELIMINATION
    ceiling == n_cribs   =>  NOT ELIMINATED BY THIS FILTER.   *NOT* "possible"

`ceiling == n` never means a solution exists. It means this particular
argument does not exclude one. Anything reported as "surviving" is surviving a
filter, not passing a test.

For STACKED additive layers (shift = s1[j mod p1] + s2[j mod p2]) the class
label j mod lcm(p1,p2) is used. The achievable shift vectors are then a proper
subgroup of all class-constant vectors, so the ceiling is a LOOSER upper
bound there. Still sound for elimination, weaker for survival.

Beaufort and variant Beaufort are covered: all three additive variants share
the "one free shift per class" structure, and the variant only changes the
sign convention inside t_q, which is handled by `variant`.

FRAME SAFETY
------------
This module never touches the frozen BEAN_EQ / BEAN_INEQ / BEAN_LINEAR sets.
Those are derived in the carved-CT frame and do not transfer across a
crib-moving layer -- the systemic defect recorded 2026-08-24. Everything here
is re-derived from (CT, crib map, alignment) on every call.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Callable, Dict, Iterable, List, Mapping, Sequence, Tuple

MOD = 26
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def index_table(alphabet: str) -> List[int]:
    """index_table(alpha)[ord(ch)-65] -> position of ch within `alphabet`."""
    if len(alphabet) != 26 or len(set(alphabet)) != 26:
        raise ValueError(f"alphabet must be a permutation of 26 letters: {alphabet!r}")
    t = [0] * 26
    for i, ch in enumerate(alphabet):
        t[ord(ch) - 65] = i
    return t


def keyword_mixed(keyword: str, base: str = AZ) -> str:
    """Keyword-mixed alphabet: unique keyword letters first, then the rest."""
    seen: List[str] = []
    for ch in keyword.upper():
        if ch.isalpha() and ch not in seen:
            seen.append(ch)
    for ch in base:
        if ch not in seen:
            seen.append(ch)
    return "".join(seen)


def required_shift(ct_ch: str, pt_ch: str, ct_tab: Sequence[int],
                   pt_tab: Sequence[int], variant: str) -> int:
    """The unique shift value a crib demands at its position."""
    c = ct_tab[ord(ct_ch) - 65]
    p = pt_tab[ord(pt_ch) - 65]
    if variant == "vig":
        return (c - p) % MOD
    if variant == "beau":
        return (c + p) % MOD
    if variant == "vbeau":
        return (p - c) % MOD
    raise ValueError(f"unknown variant {variant!r}")


def ceiling(
    ct: str,
    cribs: Mapping[int, str],
    align: Callable[[int], int],
    cls: Callable[[int], object],
    *,
    ct_tab: Sequence[int] | None = None,
    pt_tab: Sequence[int] | None = None,
    variant: str = "vig",
) -> Tuple[int, Dict[object, Dict[int, int]]]:
    """Return (ceiling, per-class multiset of demanded shifts)."""
    ct_tab = ct_tab if ct_tab is not None else index_table(AZ)
    pt_tab = pt_tab if pt_tab is not None else index_table(AZ)
    classes: Dict[object, Dict[int, int]] = defaultdict(lambda: defaultdict(int))
    for q, c in cribs.items():
        j = align(q)
        if j is None or not (0 <= j < len(ct)):
            raise IndexError(f"alignment sent crib {q} to out-of-range index {j}")
        t = required_shift(ct[j], c, ct_tab, pt_tab, variant)
        classes[cls(q)][t] += 1
    total = sum(max(d.values()) for d in classes.values())
    return total, {k: dict(v) for k, v in classes.items()}


# ── alignment / class builders for the two peel orders ────────────────────

def inverse(perm: Sequence[int]) -> List[int]:
    """iperm[q] = the index j with perm[j] == q  (perm is a gather: out[i]=in[perm[i]])."""
    ip = [0] * len(perm)
    for j, q in enumerate(perm):
        ip[q] = j
    return ip


def sub_outer(perm: Sequence[int], period: int):
    """Model A -- CT = Sub(Transpose(PT)).  Key runs in the CIPHERTEXT frame.
    Decrypt peels the substitution positionally first, then undoes the route."""
    ip = inverse(perm)
    return (lambda q: ip[q]), (lambda q: ip[q] % period)


def sub_inner(perm: Sequence[int], period: int):
    """Model B -- CT = Transpose(Sub(PT)).  Key runs in the PLAINTEXT frame.
    Decrypt undoes the route first, then peels the substitution."""
    ip = inverse(perm)
    return (lambda q: ip[q]), (lambda q: q % period)


def identity_perm(n: int = 97) -> List[int]:
    return list(range(n))
