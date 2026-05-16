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


def _store_threshold() -> int:
    """Return the kernel's STORE threshold. Imported lazily so the
    pure module stays importable without the full kernel chain (used
    by some lightweight test contexts)."""
    from kryptos.kernel.constants import STORE_THRESHOLD
    return STORE_THRESHOLD


def classify_family_yield(
    stats: FamilyYieldStats,
    policy: FamilyYieldPolicy = DEFAULT_POLICY,
) -> FamilyYieldVerdict:
    """Classify a family's empirical yield against the policy.

    Order of checks matters: insufficient_data wins over every other
    status because the floor on trials is a precondition for any
    yield-based judgment. empirically_dead requires meeting ALL of
    {n >= min_trials, mean low, no promotions, best below store};
    low_yield is the same except for the best-score requirement.
    """
    if stats.trials < policy.min_trials:
        return FamilyYieldVerdict(
            family=stats.family,
            status="insufficient_data",
            reasons=(
                f"n={stats.trials} < min_trials={policy.min_trials}",
            ),
            stats=stats,
        )

    mean_low = stats.mean_score < policy.mean_score_below
    no_promos = (stats.promotions == 0) if policy.require_zero_promotions else True
    best_low = (
        stats.best_score < _store_threshold()
        if policy.require_best_below_store_threshold
        else True
    )

    if mean_low and no_promos and best_low:
        return FamilyYieldVerdict(
            family=stats.family,
            status="empirically_dead",
            reasons=(
                f"n={stats.trials}, mean={stats.mean_score:.2f}, "
                f"best={stats.best_score:.1f}, "
                f"promotions={stats.promotions}",
                f"empirically_dead: mean < {policy.mean_score_below}, "
                f"zero promotions, best < STORE_THRESHOLD",
            ),
            stats=stats,
        )

    low_yield_mean = stats.mean_score < policy.low_yield_mean_below
    if (
        stats.trials >= policy.low_yield_trials
        and low_yield_mean
        and no_promos
    ):
        return FamilyYieldVerdict(
            family=stats.family,
            status="low_yield",
            reasons=(
                f"n={stats.trials}, mean={stats.mean_score:.2f}, "
                f"best={stats.best_score:.1f}, "
                f"promotions={stats.promotions}",
                f"low_yield: mean < {policy.low_yield_mean_below}, "
                f"zero promotions, but best_score >= STORE_THRESHOLD",
            ),
            stats=stats,
        )

    return FamilyYieldVerdict(
        family=stats.family,
        status="healthy",
        reasons=(
            f"n={stats.trials}, mean={stats.mean_score:.2f}, "
            f"best={stats.best_score:.1f}, "
            f"promotions={stats.promotions}",
        ),
        stats=stats,
    )


def check_bypass_eligibility(
    *,
    family: str,
    subfamily: str,
    mechanism_signature: str,
    prior_subfamilies_in_family: frozenset[str],
    prior_mechanism_signatures_in_family: frozenset[str],
) -> tuple[bool, tuple[str, ...]]:
    """Decide whether a theory in an empirically-dead family bypasses the gate.

    The bypass is STRUCTURAL ONLY. Returns ``(eligible, reasons)`` where
    ``reasons`` lists EVERY blocker (not just the first one) so the critic
    can surface a complete diagnostic. Eligibility requires:

    - non-empty subfamily, normalized form not in prior_subfamilies_in_family
    - non-empty mechanism_signature, value not in prior_mechanism_signatures_in_family

    `novelty_basis` prose is intentionally NOT consulted here. The bypass is
    about whether the theory is structurally new, not whether it is
    described as new.

    Input contract: ``subfamily`` and ``mechanism_signature`` are assumed
    pre-normalized by the caller. The critic gate (Task 9) calls
    ``_normalize_subfamily()`` on the theory's subfamily and computes the
    canonical mechanism signature via ``mechanism_signature_for_theory()``
    before invoking this function. The priors frozensets are built from
    the ledger using the same normalization, so set membership comparison
    is exact. Whitespace-only or empty inputs are treated as ineligible
    (they cannot prove structural novelty).
    """
    reasons: list[str] = []

    if not subfamily:
        reasons.append(
            "empty subfamily: cannot prove structural novelty without a "
            "subfamily distinct from prior trials"
        )
    elif subfamily in prior_subfamilies_in_family:
        reasons.append(
            f"subfamily '{subfamily}' already represented in prior trials "
            f"for family '{family}'"
        )

    if not mechanism_signature:
        reasons.append(
            "empty mechanism signature: cannot prove structural novelty "
            "without a signature distinct from prior trials"
        )
    elif mechanism_signature in prior_mechanism_signatures_in_family:
        reasons.append(
            f"mechanism signature '{mechanism_signature[:16]}...' "
            f"already represented in prior trials for family '{family}'"
        )

    eligible = len(reasons) == 0
    return (eligible, tuple(reasons))
