#!/usr/bin/env python3
"""Audit: the 624 Bean-valid crib keystreams form exactly 2 affine orbits of 312.

[DERIVED FACT] (verified 2026-05-29). The 624 keystream value-vectors over the 24
crib positions that satisfy the Bean constraints (equality k[27]=k[65], 242
inequalities, 101 linear difference-relations) are CLOSED under the affine group
on Z/26Z, `x -> (alpha*x + beta) mod 26` with `gcd(alpha, 26) = 1` (order 12*26 =
312), and partition into EXACTLY 2 free orbits of 312.

Why every Bean constraint is affine-invariant:
  - equality  k[a] = k[b]                          -> a*k[a]+b = a*k[b]+b  (inv.)
  - linear    k[a] - k[b] - k[c] + k[d] = 0         coeffs (+1,-1,-1,+1) sum to 0,
              so alpha factors out and beta cancels -> invariant
  - inequality k[a] != k[b]                          preserved by any bijection
              (alpha a unit) -> invariant

CONSEQUENCE (the reusable false-positive trap). Any statistic on the crib
keystream that is INVARIANT under the affine group (IC, distinct-value count,
arithmetic-progression / step-N membership counts, palette-coverage counts,
modal-value count, circular value-clustering up to a unit rescale, ...) takes AT
MOST 2 distinct values across all 624 Bean-valid keystreams. Against the matched
(uniform-over-624) null its tail probability therefore FLOORS at 1/2 (or 1/k for a
k-valued statistic) -- it can NEVER be significant, regardless of the IID p-value.
This explains, definitively, why the retired crib-keystream "anomalies" (the
{G,K,O} step-4 AP, IC-above-random, the {B,G,I,K,O,W,Z} palette enrichment,
the K=10 over-frequency, same-PT clustering) were never exploitable: they are
affine-invariant decorations on a convention-invariant count multiset, not signal.

This is a REFUTATION tool, not a signal. Cite it before chasing any crib-keystream
value-distribution statistic.

Repro:
    PYTHONPATH=src python3 scripts/audit/audit_bean_affine_orbits.py
"""
from __future__ import annotations

import importlib.util
import sys
from math import gcd
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))

from kryptos.kernel.constants import (  # noqa: E402
    BEAN_EQ, BEAN_INEQ, BEAN_LINEAR, CRIB_POSITIONS, MOD,
)

# Reuse the tested CRT/nullspace enumerator from the sibling audit.
_spec = importlib.util.spec_from_file_location(
    "audit_bean_constraints", _HERE / "audit_bean_constraints.py")
_abc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_abc)


def enumerate_bean_valid_vectors() -> list[tuple[int, ...]]:
    """All Bean-valid keystream vectors over the crib positions (position order)."""
    positions = sorted(CRIB_POSITIONS)
    pos_to_col = {p: i for i, p in enumerate(positions)}
    rows = _abc.rows_for_linear_system(positions, BEAN_EQ, BEAN_LINEAR)
    ncols = len(positions)
    ns2 = _abc.nullspace_basis(rows, 2, ncols)
    ns13 = _abc.nullspace_basis(rows, 13, ncols)
    sol2 = _abc.enumerate_solutions_from_basis(ns2["basis"], 2)
    sol13 = _abc.enumerate_solutions_from_basis(ns13["basis"], 13)
    out: list[tuple[int, ...]] = []
    for s2 in sol2:
        for s13 in sol13:
            vec = tuple(_abc.crt_mod_2_13(a, b) for a, b in zip(s2, s13))
            if all(vec[pos_to_col[a]] != vec[pos_to_col[b]] for a, b in BEAN_INEQ):
                out.append(vec)
    return out


def affine_orbits(vectors: list[tuple[int, ...]]) -> list[int]:
    """Partition `vectors` into orbits under x -> (alpha*x + beta) mod MOD."""
    units = [a for a in range(MOD) if gcd(a, MOD) == 1]
    valid = set(vectors)
    seen: set[tuple[int, ...]] = set()
    sizes: list[int] = []
    for v in vectors:
        if v in seen:
            continue
        orb = {tuple((a * x + b) % MOD for x in v)
               for a in units for b in range(MOD)}
        assert orb <= valid, "Bean-valid set is NOT affine-closed"
        sizes.append(len(orb))
        seen |= orb
    return sorted(sizes)


def main() -> int:
    vecs = enumerate_bean_valid_vectors()
    sizes = affine_orbits(vecs)
    units = sum(1 for a in range(MOD) if gcd(a, MOD) == 1)
    print(f"Bean-valid crib keystreams: {len(vecs)}")
    print(f"affine group order: {units * MOD} ({units} units x {MOD} shifts)")
    print(f"orbit sizes: {sizes}")
    ok = len(vecs) == 624 and sizes == [312, 312]
    print(f"LEMMA (624 = 2 affine orbits of 312): {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
