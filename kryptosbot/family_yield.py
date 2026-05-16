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


_STATUS_ORDER: tuple[YieldStatus, ...] = (
    "empirically_dead",
    "low_yield",
    "healthy",
    "insufficient_data",
)

_STATUS_HEADERS: dict[YieldStatus, str] = {
    "empirically_dead": (
        "EMPIRICALLY DEAD (the critic will reject new theories in these "
        "families unless you specify a subfamily not previously tried, "
        "supply a structured mechanism signature distinct from prior "
        "trials, and document why this is not a relabeling)"
    ),
    "low_yield": "LOW YIELD",
    "healthy": "HEALTHY",
    "insufficient_data": "UNDEREXPLORED (insufficient data)",
}


def render_packet(yield_index: dict[str, FamilyYieldVerdict]) -> str:
    """Render the per-cycle yield index for the theorist prompt.

    Pure function. Deterministic ordering: by status (dead first, then
    low, then healthy, then insufficient_data), then alphabetical within
    each status. The output is human-readable plain text; the critic
    does NOT read this string (it reads the dict directly).
    """
    if not yield_index:
        return "=== RECENT FAMILY YIELD (advisory) ===\n  (no family yield data available this cycle)\n"

    by_status: dict[YieldStatus, list[FamilyYieldVerdict]] = {
        s: [] for s in _STATUS_ORDER
    }
    for v in yield_index.values():
        by_status.setdefault(v.status, []).append(v)

    lines: list[str] = ["=== RECENT FAMILY YIELD (advisory) ==="]
    for status in _STATUS_ORDER:
        verdicts = sorted(by_status.get(status, ()), key=lambda v: v.family)
        if not verdicts:
            continue
        lines.append("")
        lines.append(_STATUS_HEADERS[status] + ":")
        for v in verdicts:
            s = v.stats
            lines.append(
                f"  - {v.family:<20s} n={s.trials:<4d} "
                f"mean={s.mean_score:<5.2f} "
                f"best={s.best_score:<5.1f} "
                f"promotions={s.promotions}"
            )

    lines.append("")
    return "\n".join(lines)


def render_escape_pressure(
    *,
    streak: int,
    last_status: str,
    blocked: list[str],
    blocked_total: int,
) -> str:
    """Render cross-cycle escape pressure for the theorist prompt.

    Returns the empty string when there is no pressure worth surfacing
    (streak == 0 and last_status not in the pressure set). Escalates
    language at streak 1, 2, and >= 3.
    """
    if streak <= 0:
        return ""

    truncation_note = ""
    if blocked_total > len(blocked):
        truncation_note = f"; showing top {len(blocked)}"

    families_line = (
        f"{blocked_total} families blocked{truncation_note}: "
        + ", ".join(blocked)
    )

    if streak == 1:
        header = "PRIOR CYCLE NEEDED ESCAPE"
        body = (
            f"{families_line}. Consider proposing in healthy or "
            f"underexplored families this cycle, or supply a structurally "
            f"new mechanism if revisiting a blocked one."
        )
    elif streak == 2:
        header = "SECOND CONSECUTIVE ESCAPE-NEEDED CYCLE"
        body = (
            f"{families_line}. Avoid blocked families unless "
            f"mechanism_signature is new."
        )
    else:
        header = "REPEATED ESCAPE FAILURE"
        body = (
            f"{families_line}. This cycle MUST prioritize families "
            f"outside the blocked set; reusing blocked families requires a "
            f"structurally new mechanism."
        )

    return f"=== ESCAPE PRESSURE (cross-cycle, streak={streak}) ===\n  {header}\n  {body}\n"
