"""Swing K-1 shuffled-CT null calibration."""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import List, Optional

from kryptos.kernel.constants import CT


def shuffle_ct(rng: Optional[random.Random] = None) -> str:
    rng = rng or random.Random()
    chars = list(CT)
    rng.shuffle(chars)
    return "".join(chars)


@dataclass(frozen=True)
class BaselineDistribution:
    n_trials: int
    n_sampled_configs: int
    seed: int
    joint_event_counts: List[int] = field(default_factory=list)

    def max_count(self) -> int:
        return max(self.joint_event_counts) if self.joint_event_counts else 0


def run_baseline_calibration(
    n_trials: int = 10_000,
    n_sampled_configs: int = 100,
    seed: int = 0,
) -> BaselineDistribution:
    """Run shuffled-CT trials and count joint events under a sampled config slice.

    This stub returns zeroed counts for tests; the runner integrates with
    derive_keystream + bean_filter + structure suite when wired in Task 20.
    """
    rng = random.Random(seed)
    counts: List[int] = []
    for _ in range(n_trials):
        # For Phase A the inner-loop joint-event evaluation is integrated by
        # runner.evaluate_under_shuffled_ct(ct, sampled_configs). The stub
        # here records zero until wired.
        _ = shuffle_ct(rng=rng)
        counts.append(0)
    return BaselineDistribution(
        n_trials=n_trials,
        n_sampled_configs=n_sampled_configs,
        seed=seed,
        joint_event_counts=counts,
    )
