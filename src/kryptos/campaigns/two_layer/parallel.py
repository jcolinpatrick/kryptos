"""Parallel evaluation for the two-layer campaign.

Design principles:
1. Parallelize ONLY evaluation, not sampling. Sampling is cheap.
2. Deterministic regardless of worker count: we assign a stable index
   to each pair before dispatch and sort results back into index order.
3. Worker function is module-level (multiprocessing pickling).
4. Each worker lazily constructs its ngram scorer once via a module-
   global cache, avoiding pickling a 2MB dict for every task.
"""
from __future__ import annotations

import multiprocessing as mp
import os
from typing import Iterable, List, Optional, Tuple

from .evaluation import evaluate_composition
from .families import CompositionProfile, EvaluationResult, InnerFamily, OuterFamily
from .inner_layers import apply_inner_inverse
from .outer_layers import apply_outer


# Module-level cache so each worker builds the scorer once.
_WORKER_NGRAM = None
_WORKER_CT = None


def _worker_init(ct: str, use_ngram: bool) -> None:
    global _WORKER_NGRAM, _WORKER_CT
    _WORKER_CT = ct
    if use_ngram:
        try:
            from kryptos.kernel.scoring.ngram import get_default_scorer
            _WORKER_NGRAM = get_default_scorer()
        except Exception:
            _WORKER_NGRAM = None
    else:
        _WORKER_NGRAM = None


def _worker_evaluate_one(args):
    """Top-level pickle-safe worker: takes (idx, outer, inner) → (idx, profile, result)."""
    idx, outer, inner = args
    ct = _WORKER_CT
    if ct is None:
        from kryptos.kernel.constants import CT as _CT
        ct = _CT
    profile = CompositionProfile(
        profile_id=f"p{idx:08d}",
        outer=outer,
        inner=inner,
        total_complexity=outer.complexity_score + inner.complexity_score,
        is_elimination_grade=False,
        notes="",
    )
    try:
        stream = apply_outer(outer, ct)
        candidate = apply_inner_inverse(inner, stream)
        result = evaluate_composition(profile, candidate, ngram_scorer=_WORKER_NGRAM)
    except Exception as exc:  # noqa: BLE001
        return (idx, profile, None, f"{type(exc).__name__}: {exc}")
    return (idx, profile, result, None)


def default_worker_count() -> int:
    return max(1, (os.cpu_count() or 4) - 2)


def evaluate_pairs_parallel(
    pairs: Iterable[Tuple[OuterFamily, InnerFamily]],
    workers: int = 0,
    chunksize: int = 50,
    ct: Optional[str] = None,
    use_ngram: bool = True,
) -> List[Tuple[CompositionProfile, EvaluationResult]]:
    """Evaluate pairs in parallel. Returns results in stable index order.

    workers=0 → cpu_count-2 (project default)
    workers=1 → in-process (tests/debug)
    """
    pair_list = list(pairs)
    if workers == 0:
        workers = default_worker_count()

    if ct is None:
        from kryptos.kernel.constants import CT as _CT
        ct = _CT

    indexed = [(i, o, n) for i, (o, n) in enumerate(pair_list)]

    if workers == 1:
        _worker_init(ct, use_ngram)
        raw = [_worker_evaluate_one(args) for args in indexed]
    else:
        with mp.Pool(
            processes=workers,
            initializer=_worker_init,
            initargs=(ct, use_ngram),
        ) as pool:
            raw = pool.map(_worker_evaluate_one, indexed, chunksize=chunksize)

    raw.sort(key=lambda r: r[0])
    out: List[Tuple[CompositionProfile, EvaluationResult]] = []
    for (_idx, profile, result, err) in raw:
        if result is None:
            continue
        out.append((profile, result))
    return out
