#!/usr/bin/env python3
"""Columnar + periodic substitution, re-run with the Bean frame corrected.

ERRATUM 2026-09-29 (docs/audits/kryptos_text_integrity_audit_2026_09_29.md, section 5):
the variant LABELS below are swapped relative to the CLAUDE.md convention. The
branch labelled "beaufort" computes k = PT - CT (Variant Beaufort) and the
branch labelled "var_beaufort" computes k = CT + PT (Beaufort). The labels in
results/f_columnar_periodic_rederived_v1.json carry the same swap. Also,
"vigenere" (C - P) and the branch labelled "beaufort" (P - C) differ only in
sign and always give identical survivor sets, so the three variants are two
independent tests. Code behaviour is unchanged by this note; the clean-null
conclusion stands.

ID:     f_columnar_periodic_rederived_v1
Family: campaigns
Status: active
Origin: 2026-08-24, after the Bean frame-error retraction

WHY THIS RE-RUN EXISTS

The prior closures of this space (E-FRAC-26/27, E-FRAC-35, C-BEAN-01, and
f_columnar_sub_exhaustive) all gated candidate column orderings on the FROZEN
canonical Bean sets. Those sets are produced by
``derive_bean_constraints(ct, crib_dict, ...)``, which reads ct[p] at each
canonical crib position and pairs it with crib_dict[p]; they are a property of
THAT pairing. This model applies a transposition, which moves crib coordinates,
so the frozen sets do not hold and every "Bean failure" was a false rejection.
At widths 5 and 7 the gate admitted 0 of 120 and 0 of 5,040 orderings: nothing
was ever tested. See scripts/audit/audit_bean_equality_frame_transfer.py.

THE CORRECT METHOD USES NO BEAN FILTER AT ALL

Model: PT --sub(periodic key)--> X --columnar transpose--> CT.
For plaintext position ``pos``, ``pt_to_ct[pos]`` is the carved-CT index holding
X[pos], so the keystream at the 24 crib positions is DETERMINED:

    k[pos] = f(CT[pt_to_ct[pos]], crib[pos])        f per additive variant

Being derived this way it is additive-consistent by construction, so re-derived
Bean is VACUOUS on it -- Bean was only ever a variant-independent shadow of this
determined vector. The real and only constraint is that a period-p key must be
CONSTANT on each residue class mod p. That is what this campaign tests.

PRE-REGISTERED (before the run)

  Primary   : a (width, ordering, variant, period) survives iff the determined
              keystream is constant on every residue class mod p. Exhaustive over
              widths 4-9, all w! orderings, 3 variants, periods 1-26.
  Secondary : survivors are scored only after Phase 1 counts are known. crib_score
              is trivially 24 by construction and is NOT a discriminator; the
              discriminator is the quadgram score of the completed plaintext,
              threshold > -5.0 per char (the repo's documented gibberish floor,
              E-FRAC-34). Report the null: a survivor count alone means nothing
              without the count expected from the degrees of freedom.
  Stop rule : exhaustive. No sampling, no early cut.

Run:
    PYTHONPATH=src python3 scripts/campaigns/f_columnar_periodic_rederived_v1.py
    PYTHONPATH=src python3 scripts/campaigns/f_columnar_periodic_rederived_v1.py --widths 4-9 --workers 14
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
import time
from typing import Iterable, Sequence

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (  # noqa: E402
    ALPH_IDX, CRIB_DICT, CRIB_POSITIONS, CT, CT_LEN, MOD,
)
from kryptos.kernel.transforms.transposition import (  # noqa: E402
    columnar_perm, invert_perm,
)

CRIBS: tuple[int, ...] = tuple(sorted(CRIB_POSITIONS))
_CRIB_VALS: tuple[int, ...] = tuple(ALPH_IDX[CRIB_DICT[p]] for p in CRIBS)
VARIANTS = ("vigenere", "beaufort", "var_beaufort")

# For each period, the index pairs that a period-p key forces to be equal.
# Built once: within each residue class, chain consecutive members.
def _forced_equal_pairs(max_period: int) -> dict[int, tuple[tuple[int, int], ...]]:
    out: dict[int, tuple[tuple[int, int], ...]] = {}
    for p in range(1, max_period + 1):
        classes: dict[int, list[int]] = {}
        for j, pos in enumerate(CRIBS):
            classes.setdefault(pos % p, []).append(j)
        pairs: list[tuple[int, int]] = []
        for members in classes.values():
            pairs.extend((members[0], m) for m in members[1:])
        out[p] = tuple(pairs)
    return out


_FORCED: dict[int, tuple[tuple[int, int], ...]] = _forced_equal_pairs(26)


def pt_to_ct_for(width: int, col_order: Sequence[int], length: int = CT_LEN) -> tuple[int, ...]:
    """pt_to_ct[pos] = carved-CT index holding the pre-transposition value at pos."""
    return tuple(invert_perm(columnar_perm(width, list(col_order), length)))


def determined_keystream(
    pt_to_ct: Sequence[int], variant: str, ct: str = CT
) -> tuple[int, ...]:
    """The keystream the cribs FORCE at the 24 crib positions, in this frame."""
    if variant == "vigenere":
        return tuple((ALPH_IDX[ct[pt_to_ct[p]]] - v) % MOD
                     for p, v in zip(CRIBS, _CRIB_VALS))
    if variant == "beaufort":
        return tuple((v - ALPH_IDX[ct[pt_to_ct[p]]]) % MOD
                     for p, v in zip(CRIBS, _CRIB_VALS))
    if variant == "var_beaufort":
        return tuple((ALPH_IDX[ct[pt_to_ct[p]]] + v) % MOD
                     for p, v in zip(CRIBS, _CRIB_VALS))
    raise ValueError(f"unknown variant: {variant!r}")


def valid_periods(k24: Sequence[int], max_period: int = 26) -> frozenset[int]:
    """Periods whose residue classes are constant on this determined keystream."""
    ok = []
    for p in range(1, max_period + 1):
        if all(k24[a] == k24[b] for a, b in _FORCED[p]):
            ok.append(p)
    return frozenset(ok)


def scan_width(
    width: int, variants: Sequence[str] = VARIANTS, max_period: int = 26,
) -> dict:
    """Exhaustively scan every ordering at one width."""
    survivors: list[tuple[tuple[int, ...], str, int]] = []
    n = 0
    for col_order in itertools.permutations(range(width)):
        n += 1
        p2c = pt_to_ct_for(width, col_order)
        for variant in variants:
            vp = valid_periods(determined_keystream(p2c, variant), max_period)
            for p in sorted(vp):
                survivors.append((col_order, variant, p))
    return {
        "width": width,
        "orderings_scanned": n,
        "variants": list(variants),
        "max_period": max_period,
        "survivors": survivors,
        "survivor_count": len(survivors),
    }


def null_expectation(width: int, period: int, n_variants: int = 3) -> float:
    """Survivors expected at chance for one (width, period).

    A period-p key forces ``len(_FORCED[p])`` equalities among the 24 determined
    keystream values. If that vector carried no structure, each equality holds
    with probability 1/26 and they compose, so

        E[survivors] = (orderings x variants) * (1/26) ** forced_pairs

    Reporting this alongside the raw count is mandatory here: at p=26 only ONE
    equality is forced, so a large survivor count is guaranteed by the parameter
    count and means nothing on its own.
    """
    import math
    n = math.factorial(width) * n_variants
    return n * (1.0 / MOD) ** len(_FORCED[period])


def _worker(args: tuple) -> dict:
    width, variants, max_period = args
    return scan_width(width, variants, max_period)


def run(widths: Iterable[int], variants: Sequence[str] = VARIANTS,
        max_period: int = 26, workers: int | None = None) -> dict:
    widths = sorted(widths)
    started = time.perf_counter()
    tasks = [(w, tuple(variants), max_period) for w in widths]
    if workers and workers > 1 and len(tasks) > 1:
        import multiprocessing as mp
        with mp.Pool(min(workers, len(tasks))) as pool:
            per_width = pool.map(_worker, tasks)
    else:
        per_width = [_worker(t) for t in tasks]

    total_cfgs = sum(w["orderings_scanned"] * len(variants) * max_period
                     for w in per_width)
    total_surv = sum(w["survivor_count"] for w in per_width)
    by_period: dict[int, int] = {}
    observed_expected: list[dict] = []
    for w in per_width:
        obs: dict[int, int] = {}
        for _, _, p in w["survivors"]:
            by_period[p] = by_period.get(p, 0) + 1
            obs[p] = obs.get(p, 0) + 1
        for p in sorted(obs):
            e = null_expectation(w["width"], p, len(variants))
            observed_expected.append({
                "width": w["width"], "period": p, "observed": obs[p],
                "expected_at_chance": round(e, 1),
                "ratio": round(obs[p] / e, 2) if e else None,
            })
    tot_e = sum(d["expected_at_chance"] for d in observed_expected)
    return {
        "campaign_id": "f_columnar_periodic_rederived_v1",
        "model": "PT --sub(periodic key)--> X --columnar--> CT",
        "method": ("determined keystream in the transposed frame; periodicity is "
                   "the only filter; NO frozen Bean gate"),
        "stop_rule": "exhaustive",
        "widths": widths,
        "variants": list(variants),
        "max_period": max_period,
        "configurations_tested": total_cfgs,
        "survivor_count": total_surv,
        "survivors_by_width": {w["width"]: w["survivor_count"] for w in per_width},
        "survivors_by_period": dict(sorted(by_period.items())),
        "empty_periods": [p for p in range(1, max_period + 1) if p not in by_period],
        "null_model": ("(orderings x variants) * (1/26)**forced_equalities; "
                       "forced_equalities = 24 - distinct residues mod p"),
        "observed_vs_expected": observed_expected,
        "total_expected_at_chance": round(tot_e, 1),
        "overall_ratio": round(total_surv / tot_e, 3) if tot_e else None,
        "orderings_by_width": {w["width"]: w["orderings_scanned"] for w in per_width},
        "elapsed_sec": round(time.perf_counter() - started, 2),
        "per_width": per_width,
        "reproduction_command": (
            "PYTHONPATH=src python3 scripts/campaigns/"
            "f_columnar_periodic_rederived_v1.py --widths "
            f"{widths[0]}-{widths[-1]}"
        ),
    }


def _parse_widths(spec: str) -> list[int]:
    if "-" in spec:
        lo, hi = spec.split("-", 1)
        return list(range(int(lo), int(hi) + 1))
    return [int(x) for x in spec.split(",")]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--widths", default="4-9")
    ap.add_argument("--max-period", type=int, default=26)
    ap.add_argument("--workers", type=int, default=None)
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    res = run(_parse_widths(args.widths), VARIANTS, args.max_period, args.workers)
    slim = {k: v for k, v in res.items() if k != "per_width"}
    print(json.dumps(slim, indent=2))
    if args.out:
        with open(args.out, "w") as fh:
            json.dump(res, fh, indent=1)
        print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
