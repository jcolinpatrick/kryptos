"""Anti-cherry-picking controls for the two-layer campaign."""
from __future__ import annotations

import math
import random
from typing import Dict

from kryptos.campaigns.two_layer.families import CompositionProfile


def compute_multiplicity_penalty(profile: CompositionProfile) -> float:
    """Penalty for the effective number of variants tried.

    Uses log of (outer pool * inner pool) so heavy sweeps get heavily
    penalized. Returns a value in (0, 1], where 1 = no penalty.
    """
    outer_pool = max(1, profile.outer.selection_pool_size or profile.outer.parameter_space_size or 1)
    inner_pool = max(1, profile.inner.parameter_space_size or 1)
    return 1.0 / (1.0 + math.log(1 + outer_pool * inner_pool))


def is_cherry_picked_width(width_spectrum: Dict[int, int], candidate_width: int) -> bool:
    """True if candidate_width has the max repeat count AND the spectrum
    has >1 width — i.e. the candidate's anomaly is single-width."""
    if len(width_spectrum) <= 1:
        return False
    if candidate_width not in width_spectrum:
        return False
    max_v = max(width_spectrum.values())
    return width_spectrum[candidate_width] == max_v and max_v > 0


def family_baseline_distribution(
    family_id: str,
    metric_fn,
    n_trials: int = 100,
    seed: int = 20260411,
) -> Dict[str, float]:
    """Sample a family's baseline metric distribution.

    `metric_fn` is a zero-arg callable returning a float for one random
    instance. Returns {mean, stdev, n}.
    """
    rng = random.Random(seed)
    samples = []
    for _ in range(n_trials):
        try:
            samples.append(float(metric_fn(rng)))
        except Exception:
            continue
    if not samples:
        return {"mean": 0.0, "stdev": 0.0, "n": 0, "family_id": 0.0}
    m = sum(samples) / len(samples)
    var = sum((x - m) ** 2 for x in samples) / max(1, len(samples) - 1)
    return {"mean": m, "stdev": math.sqrt(var), "n": float(len(samples))}
