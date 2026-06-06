"""Declared bounded transposition universe: columnar all-orderings w6/8/9
(E-FRAC-54's underdetermined set) + the 52-route grid universe."""
from __future__ import annotations
import hashlib
from itertools import permutations
from typing import Iterator, List, Tuple

from kryptos.kernel.transforms.transposition import columnar_perm
from kryptos.kernel.masking.route_null import grid_route_perms

_COLUMNAR_WIDTHS = (6, 8, 9)
_GRID_WIDTHS = (4, 5, 6, 7, 8, 11, 13, 14, 21, 24)


def iter_universe(n: int = 97) -> Iterator[Tuple[str, List[int]]]:
    yield ("identity", list(range(n)))
    yield ("reverse", list(range(n - 1, -1, -1)))
    for w in _GRID_WIDTHS:
        for name, perm in grid_route_perms(w, n=n):
            yield (name, list(perm))
    for w in _COLUMNAR_WIDTHS:
        for order in permutations(range(w)):
            yield (f"col{w}_{''.join(map(str, order))}", list(columnar_perm(w, order, n)))


def universe_hash(n: int = 97) -> str:
    h = hashlib.sha256()
    for name, perm in iter_universe(n=n):
        h.update(name.encode())
        h.update(bytes(perm))
    return h.hexdigest()
