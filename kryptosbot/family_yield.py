"""Empirical-yield policy for the K4 controller.

Pure module. No persistence, no I/O. Computes yield classification from
ledger stats and bypass eligibility from structural theory metadata.

Both the theorist's landscape packet and the critic's empirical-death
gate read this module's classifier on the same per-cycle snapshot, so
the advisory rendering and the enforced rule cannot diverge.

See docs/specs/2026-05-16-yield-feedback-design.md.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# Imported lazily inside functions to avoid kernel import side effects
# in pure-module contexts. STORE_THRESHOLD = 10 in current kernel.


YieldStatus = Literal["healthy", "insufficient_data", "low_yield", "empirically_dead"]


@dataclass(frozen=True)
class FamilyYieldPolicy:
    """Thresholds for classifying a family's empirical yield.

    Defaults are tuned for the live ledger as of 2026-05-16. Edit in code
    rather than via CLI; deliberate friction (see spec §6.1).
    """
    min_trials: int = 50
    mean_score_below: float = 2.0
    require_zero_promotions: bool = True
    require_best_below_store_threshold: bool = True
    low_yield_trials: int = 50
    low_yield_mean_below: float = 2.0
    # Opt-in diagnostic: when true, the critic logs would_reject but
    # still returns approve. Used in tests and operator dry-runs only.
    shadow_mode: bool = False


@dataclass(frozen=True)
class FamilyYieldStats:
    """One row of the ledger aggregate query, per family.

    Numeric fields are kernel-verified outputs: ``best_score`` is the
    kernel-recomputed crib score from contracts._verify_against_kernel,
    not the worker self-report.
    """
    family: str
    trials: int
    mean_score: float
    best_score: float
    promotions: int        # count of theories advanced to PROMISING status
    eliminated: int


@dataclass(frozen=True)
class FamilyYieldVerdict:
    """Classifier output for one family."""
    family: str
    status: YieldStatus
    reasons: tuple[str, ...]  # always non-empty for low_yield/empirically_dead; may be empty for healthy
    stats: FamilyYieldStats


DEFAULT_POLICY = FamilyYieldPolicy()
