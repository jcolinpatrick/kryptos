"""Shuffled-CT matched null and max-LLR over the transposition universe."""
from __future__ import annotations
import random
from typing import Dict, Iterable, List, Sequence, Tuple

from .forced_differences import forced_diffs_model1, forced_diffs_model2
from .llr_detector import llr

_MODELS = {"model1": forced_diffs_model1, "model2": forced_diffs_model2}


def shuffle_ct(ct_idx: Sequence[int], rng: random.Random) -> List[int]:
    out = list(ct_idx)
    rng.shuffle(out)
    return out


def max_llr_over_universe(ct_idx, crib_items, universe: Iterable[Tuple[str, Sequence[int]]],
                          variants: Sequence[str], models: Sequence[str],
                          lag_stats: Dict[int, List[float]], l_max: int = 12):
    best = {"name": None, "variant": None, "model": None, "llr": float("-inf"), "n_constraints": 0}
    for name, perm in universe:
        for model in models:
            fn = _MODELS[model]
            for variant in variants:
                diffs = fn(ct_idx, crib_items, perm, variant)
                score = llr(diffs, lag_stats, l_max=l_max)
                if score > best["llr"]:
                    best = {"name": name, "variant": variant, "model": model,
                            "llr": score, "n_constraints": len(diffs)}
    return best, best["llr"]


def matched_null_pvalue(real_max: float, ct_idx, crib_items, universe_factory,
                        variants, models, lag_stats, n_null: int, seed: int, l_max: int = 12):
    """universe_factory: zero-arg callable returning a fresh universe iterator."""
    rng = random.Random(seed)
    null_max: List[float] = []
    ge = 0
    for _ in range(n_null):
        sh = shuffle_ct(ct_idx, rng)
        _, mx = max_llr_over_universe(sh, crib_items, universe_factory(), variants, models, lag_stats, l_max)
        null_max.append(mx)
        if mx >= real_max:
            ge += 1
    p = (1 + ge) / (1 + n_null)
    return p, null_max
