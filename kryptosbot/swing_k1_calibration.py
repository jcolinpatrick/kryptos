"""Swing K-1 shuffled-CT null calibration."""
from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import List, Literal, Optional

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


@dataclass(frozen=True)
class EscalationResult:
    method: Literal["analytical_binomial", "monte_carlo_1m"]
    p_value: float
    n_trials: int


def analytical_binomial_pvalue(n: int, k: int, single_trial_p: float) -> float:
    """P(X >= k) where X ~ Binomial(n, single_trial_p)."""
    if k <= 0:
        return 1.0
    # P(X >= k) = 1 - sum_{i=0}^{k-1} C(n,i) p^i (1-p)^(n-i)
    cum = 0.0
    for i in range(k):
        log_term = (
            math.lgamma(n + 1) - math.lgamma(i + 1) - math.lgamma(n - i + 1)
            + i * math.log(single_trial_p) + (n - i) * math.log(1 - single_trial_p)
        )
        cum += math.exp(log_term)
    return max(0.0, 1.0 - cum)


def escalate_to_stage_2(
    observed_joint_event_count: int,
    baseline_max: int,
    n_baseline_trials: int,
    method_preference: Literal["analytical", "monte_carlo"] = "analytical",
    single_trial_p_estimate: Optional[float] = None,
) -> EscalationResult:
    """When a candidate passes the 10K baseline, escalate to p <= 1e-6 calibration."""
    if method_preference == "analytical" and single_trial_p_estimate is not None:
        p = analytical_binomial_pvalue(
            n=n_baseline_trials, k=observed_joint_event_count, single_trial_p=single_trial_p_estimate
        )
        return EscalationResult(method="analytical_binomial", p_value=p, n_trials=n_baseline_trials)
    # Fall back to Monte Carlo escalation. Runner wires this to 1M trials.
    return EscalationResult(method="monte_carlo_1m", p_value=float("nan"), n_trials=1_000_000)
