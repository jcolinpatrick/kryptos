"""E0b extended-position distance statistic + calibrated nulls (GAP-03).

Anomaly E0b (Materna 2020 / Bean 2021 sec 2.4): at the disclosed-plaintext
positions where PT in {K,R,Y,P,T,O,S}, the standard-alphabet (minor) distance
between PT and the carved CT clusters near zero (10 crib positions, sum 21,
mean 2.1, MC p ~ 1/5520). Bean reads this as one-to-one substitution with a
keyword-mixed alphabet near KRYPTOS.

This module operationalizes E0b into a forward side-effect predicate
(GAP-03 in docs/REAL_K4_EVIDENCE_ACQUISITION_PLAN.md):

- ``e0b_statistic``        : the distance statistic on any plaintext.
- ``e0b_bean_pvalue``      : VALIDATION null (CT-permutation) that reproduces
                             Bean's p ~ 1/5520 on the disclosed cribs.
- ``e0b_candidate_pvalue`` : the FORWARD side-effect under the crib-pinned
                             random-plaintext null (X/p0/Y triple): does a
                             candidate's OFF-crib K-set positions cluster near
                             zero like a true keyword-mixed solution would.

Pure, stdlib only. No K4-score input contaminates the derivation.
"""
from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Mapping, Tuple, Union

KRYPTOS_SET = frozenset("KRYPTOS")
MOD = 26


def minor_distance(a: str, b: str) -> int:
    """Circular (minor) distance in [0, 13] between two A-Z letters."""
    d = abs(ord(a) - ord(b))
    return min(d, MOD - d)


@dataclass(frozen=True)
class E0bStat:
    count: int
    sum_dist: int
    mean_dist: float
    positions: Tuple[int, ...]


def e0b_statistic(
    pt: Union[str, Mapping[int, str]],
    ct: str,
    *,
    kset: frozenset = KRYPTOS_SET,
) -> E0bStat:
    """Distance statistic at positions where PT in the K-set.

    ``pt`` may be a full plaintext string (indexed 0..len-1) or a mapping
    {position: letter} (e.g. CRIB_DICT). Distance is to ``ct`` at each position.
    """
    items = enumerate(pt) if isinstance(pt, str) else pt.items()
    positions = []
    total = 0
    for pos, letter in items:
        if letter in kset:
            positions.append(pos)
            total += minor_distance(letter, ct[pos])
    positions = tuple(sorted(positions))
    n = len(positions)
    return E0bStat(count=n, sum_dist=total,
                   mean_dist=(total / n if n else 0.0), positions=positions)


@dataclass(frozen=True)
class E0bBeanResult:
    count: int
    obs_sum: int
    obs_mean: float
    p_value: float
    n_mc: int


def e0b_bean_pvalue(
    ct: str,
    crib_dict: Mapping[int, str],
    *,
    n_mc: int = 200_000,
    seed: int = 0,
    kset: frozenset = KRYPTOS_SET,
) -> E0bBeanResult:
    """VALIDATION null: reproduce Bean's p ~ 1/5520 on the disclosed cribs.

    Null = a uniform permutation of the carved CT (preserves the exact letter
    multiset); the statistic is the distance sum at the K-set crib positions.
    Drawing k letters without replacement from the CT pool is the marginal of
    a permutation at k fixed positions, so it is exactly the permutation null.
    """
    positions = [p for p in sorted(crib_dict) if crib_dict[p] in kset]
    pt_letters = [crib_dict[p] for p in positions]
    obs = sum(minor_distance(pt_letters[j], ct[p]) for j, p in enumerate(positions))
    k = len(positions)
    pool = list(ct)
    rng = random.Random(seed)
    hits = 0
    for _ in range(n_mc):
        sample = rng.sample(pool, k)
        if sum(minor_distance(pt_letters[j], sample[j]) for j in range(k)) <= obs:
            hits += 1
    return E0bBeanResult(count=k, obs_sum=obs,
                         obs_mean=(obs / k if k else 0.0),
                         p_value=(hits / n_mc if n_mc else float("nan")),
                         n_mc=n_mc)


def e0b_candidate_pvalue(
    pt: str,
    ct: str,
    crib_dict: Mapping[int, str],
    *,
    n_mc: int = 100_000,
    seed: int = 0,
    kset: frozenset = KRYPTOS_SET,
) -> Tuple[float, float]:
    """FORWARD side-effect (the X/p0/Y triple).

    Statistic X = mean K-set distance of the candidate plaintext.
    Null Y = crib-pinned random plaintext (crib positions held to the disclosed
    letters, off-crib positions uniform random A-Z). p0 = fraction of null draws
    whose mean K-set distance is <= the candidate's. Small p => the candidate's
    K-set positions cluster near zero beyond what a crib-only match explains.
    """
    obs = e0b_statistic(pt, ct, kset=kset).mean_dist
    crib_pos = dict(crib_dict)
    n = len(ct)
    letters = [chr(65 + i) for i in range(MOD)]
    rng = random.Random(seed)
    hits = 0
    for _ in range(n_mc):
        total = 0
        cnt = 0
        for i in range(n):
            letter = crib_pos[i] if i in crib_pos else letters[rng.randrange(MOD)]
            if letter in kset:
                cnt += 1
                total += minor_distance(letter, ct[i])
        m = total / cnt if cnt else 0.0
        if m <= obs:
            hits += 1
    return obs, (hits / n_mc if n_mc else float("nan"))
