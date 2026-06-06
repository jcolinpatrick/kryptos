"""Log-likelihood ratio of forced differences vs the uniform null."""
from __future__ import annotations
import math
from typing import Dict, List, Sequence, Tuple

_FLOOR = 1e-6  # guards log(0) for unseen delta at a lag


def llr(forced_diffs: Sequence[Tuple[int, int]], lag_stats: Dict[int, List[float]],
        l_max: int = 12) -> float:
    total = 0.0
    for delta, lag in forced_diffs:
        probs = lag_stats[min(lag, l_max) if lag >= 1 else 1]
        p = max(probs[delta % 26], _FLOOR)
        total += math.log(p / (1.0 / 26.0))
    return total
