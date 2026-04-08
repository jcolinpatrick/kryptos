"""CP-SAT backed exact admissibility for periodic additive key families.

Family definition
-----------------

For a cipher variant V in {vigenere, beaufort, var_beaufort} and a key
period p >= 1, the `periodic_additive(V, p)` family is:

    k[i] = key[i mod p],   i in [0, 96],  key[j] in [0, 25] for all j
    plaintext is recovered by the V-specific additive rule

and the admissibility question is:

    Does there EXIST any assignment of key[0..p-1] such that the
    decryption satisfies all crib positions AND all Bean constraints
    (1 equality + 242 inequalities)?

This is a trivial CSP for CP-SAT: ~p integer variables in [0, 25],
1 equality on derived crib values per crib position (collapsed by
residue class), plus Bean eq/ineq mapped to residue classes.  A decision
is returned in well under a millisecond per (V, p) pair.

Why this matters
----------------

The existing repo already eliminates single-layer periodic substitution
at every period using score-distribution arguments (`period_consistency`).
What it does NOT produce is a formal certificate of the form

    "For variant=beaufort, period=6, under assumptions
     {A1 crib positions, A2 crib content, A3 additive model}, the CSP
     is UNSAT with conflict witness (pos_a, pos_b, residue=r)."

That certificate is the contribution here.  It converts 'we searched
the space and found nothing' into 'no such configuration can exist'.
Promoted certificates feed the negative-result ledger.

Backend choice
--------------

Primary: OR-Tools CP-SAT (integer domain propagation is its sweet spot).
Fallback: a pure-Python checker that mirrors the CP-SAT semantics exactly,
so this module remains importable on machines without ortools.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple, Union

from kryptos.admissibility.certificate import (
    AdmissibilityCertificate,
    EliminationCertificate,
    EliminationReason,
)
from kryptos.kernel.constants import (
    ALPH_IDX, BEAN_EQ, BEAN_INEQ, CRIB_DICT, CT, CT_LEN, MOD,
)

try:
    from ortools.sat.python import cp_model  # type: ignore
    HAS_CP_SAT = True
except ImportError:
    HAS_CP_SAT = False


# Family name used in certificates
FAMILY_PREFIX = "periodic_additive"

# Assumptions that MUST be listed on every certificate this module emits.
BASE_ASSUMPTIONS: Tuple[str, ...] = (
    "A1: crib positions correct (21-33, 63-73, 0-indexed)",
    "A2: crib content correct (EASTNORTHEAST, BERLINCLOCK)",
    "A3: additive single-mod-26 key per position",
    "A4: single-layer cipher (not one layer of a multi-layer construction)",
)


# ── Derivation of required key values at crib positions ─────────────────

def _derived_key_at_crib(
    variant: str,
    ct_override: Optional[Sequence[int]] = None,
) -> Dict[int, int]:
    """For each crib position, compute the mod-26 key value required by
    the variant's arithmetic.  This mirrors `K4ConstraintModel.add_crib_constraints`
    but returns a plain dict suitable for pure-Python reasoning.

    When ``ct_override`` is provided, CT values are read from it instead
    of the raw K4 ciphertext.  The override is a sequence of 97 ints in
    [0, 25].  This is the mechanism by which composition families
    (e.g. additive composed with a fixed transposition) reuse this
    checker: the caller reindexes CT through the fixed permutation and
    passes the result as ``ct_override``.
    """
    out: Dict[int, int] = {}
    for pos, pt_ch in CRIB_DICT.items():
        if ct_override is not None:
            ct_val = int(ct_override[pos])
        else:
            ct_val = ALPH_IDX[CT[pos]]
        pt_val = ALPH_IDX[pt_ch]
        if variant == "vigenere":
            k = (ct_val - pt_val) % MOD
        elif variant == "beaufort":
            k = (ct_val + pt_val) % MOD
        elif variant == "var_beaufort":
            k = (pt_val - ct_val) % MOD
        else:
            raise ValueError(f"Unknown variant: {variant!r}")
        out[pos] = k
    return out


@dataclass
class PeriodicResult:
    """Internal result of one (variant, period) admissibility check."""
    feasible: bool
    reason: Optional[EliminationReason]
    summary: str
    evidence: Dict[str, object]
    wall_ms: float


# ── Pure-Python checker (fallback + fast path) ──────────────────────────
#
# Because the whole problem collapses to 'can we assign a single value to
# each residue class?' the pure-Python path is actually faster than
# CP-SAT for this specific formulation.  CP-SAT is kept for (a) cross-
# verification and (b) future extensions where constraints become
# non-collapsible.

def _check_periodic_pure(
    variant: str,
    period: int,
    *,
    ct_override: Optional[Sequence[int]] = None,
    include_bean: bool = True,
) -> PeriodicResult:
    if period < 1:
        return PeriodicResult(
            feasible=False,
            reason=EliminationReason.EMPTY_PARAMETER_SPACE,
            summary=f"period={period} is not a valid key period",
            evidence={"variant": variant, "period": period},
            wall_ms=0.0,
        )

    t0 = time.perf_counter()
    derived = _derived_key_at_crib(variant, ct_override=ct_override)

    # Group required key values by residue class
    residue: Dict[int, Dict[int, int]] = {}  # r -> {pos: key_val}
    for pos, k in derived.items():
        r = pos % period
        residue.setdefault(r, {})[pos] = k

    # 1. Crib collision: same residue must yield same key value
    for r, posmap in residue.items():
        vals = set(posmap.values())
        if len(vals) > 1:
            # Pick a minimal witness: two positions with conflicting values
            items = sorted(posmap.items())
            a_pos, a_val = items[0]
            b_pos, b_val = next((p, v) for p, v in items if v != a_val)
            return PeriodicResult(
                feasible=False,
                reason=EliminationReason.CRIB_POSITION_CONTRADICTION,
                summary=(
                    f"variant={variant} period={period}: positions "
                    f"{a_pos} and {b_pos} share residue {r} but require "
                    f"key values {a_val} and {b_val}."
                ),
                evidence={
                    "variant": variant,
                    "period": period,
                    "residue": r,
                    "conflict": [a_pos, b_pos],
                    "required_values": [a_val, b_val],
                },
                wall_ms=(time.perf_counter() - t0) * 1000,
            )

    # Now each residue class has a single forced value (if any crib hit it)
    forced: Dict[int, int] = {r: next(iter(posmap.values()))
                              for r, posmap in residue.items()}

    # Bean constraints are derived from the RAW K4 ciphertext.  When
    # `ct_override` is supplied (e.g. for composition families), the
    # derivation no longer applies — the forced key values are being
    # read against a reindexed CT, so the original Bean pairs do not
    # translate 1:1.  In that case, skip Bean and produce a correct
    # but weaker admissibility check (any UNSAT is still formally
    # correct; some false SATs may survive).
    if not include_bean:
        return PeriodicResult(
            feasible=True,
            reason=None,
            summary=(
                f"variant={variant} period={period}: feasible (Bean skipped) — "
                f"{len(forced)} residue classes forced, no crib collision."
            ),
            evidence={
                "variant": variant,
                "period": period,
                "forced_residues": sorted(forced.keys()),
                "free_residues": [r for r in range(period) if r not in forced],
                "n_forced": len(forced),
                "n_free": period - len(forced),
                "bean_applied": False,
            },
            wall_ms=(time.perf_counter() - t0) * 1000,
        )

    # 2. Bean equality: positions that must share a key value
    for a, b in BEAN_EQ:
        ra, rb = a % period, b % period
        if ra in forced and rb in forced:
            if forced[ra] != forced[rb]:
                return PeriodicResult(
                    feasible=False,
                    reason=EliminationReason.BEAN_UNSAT,
                    summary=(
                        f"variant={variant} period={period}: Bean equality "
                        f"({a}, {b}) requires k[{ra}]==k[{rb}] but residue "
                        f"classes carry distinct forced values "
                        f"{forced[ra]} vs {forced[rb]}."
                    ),
                    evidence={
                        "variant": variant, "period": period,
                        "bean_type": "eq",
                        "positions": [a, b],
                        "residues": [ra, rb],
                        "forced_values": [forced[ra], forced[rb]],
                    },
                    wall_ms=(time.perf_counter() - t0) * 1000,
                )
        # Cross-residue equality with only one side forced: feasible if we
        # set the other residue class to match.  No additional constraint.
        # Same-residue equality is automatic.

    # 3. Bean inequality: positions that must NOT share a key value
    for a, b in BEAN_INEQ:
        ra, rb = a % period, b % period
        if ra == rb:
            # Periodic key forces equality, but Bean forces inequality.
            return PeriodicResult(
                feasible=False,
                reason=EliminationReason.BEAN_UNSAT,
                summary=(
                    f"variant={variant} period={period}: Bean inequality "
                    f"({a}, {b}) requires k[{a}]!=k[{b}] but both positions "
                    f"share residue {ra} so the periodic key forces equality."
                ),
                evidence={
                    "variant": variant, "period": period,
                    "bean_type": "ineq",
                    "positions": [a, b],
                    "residue": ra,
                },
                wall_ms=(time.perf_counter() - t0) * 1000,
            )
        if ra in forced and rb in forced and forced[ra] == forced[rb]:
            return PeriodicResult(
                feasible=False,
                reason=EliminationReason.BEAN_UNSAT,
                summary=(
                    f"variant={variant} period={period}: Bean inequality "
                    f"({a}, {b}) requires k[{ra}]!=k[{rb}] but residue "
                    f"classes are both forced to value {forced[ra]}."
                ),
                evidence={
                    "variant": variant, "period": period,
                    "bean_type": "ineq",
                    "positions": [a, b],
                    "residues": [ra, rb],
                    "forced_value": forced[ra],
                },
                wall_ms=(time.perf_counter() - t0) * 1000,
            )

    return PeriodicResult(
        feasible=True,
        reason=None,
        summary=(
            f"variant={variant} period={period}: feasible — "
            f"{len(forced)} residue classes forced, no Bean conflict."
        ),
        evidence={
            "variant": variant,
            "period": period,
            "forced_residues": sorted(forced.keys()),
            "free_residues": [r for r in range(period) if r not in forced],
            "n_forced": len(forced),
            "n_free": period - len(forced),
            "bean_applied": True,
        },
        wall_ms=(time.perf_counter() - t0) * 1000,
    )


# ── CP-SAT cross-verification (secondary path) ──────────────────────────

def _check_periodic_cpsat(
    variant: str,
    period: int,
    *,
    ct_override: Optional[Sequence[int]] = None,
    include_bean: bool = True,
    timeout_s: float = 5.0,
) -> PeriodicResult:
    """CP-SAT formulation of the same CSP.  Used as a cross-check.

    Returns a PeriodicResult equivalent to the pure-Python one; when the
    two disagree, the pure-Python path is authoritative for the reason
    code (it knows exactly which constraint triggered) and CP-SAT is
    used only for the SAT/UNSAT verdict.
    """
    if not HAS_CP_SAT:
        raise ImportError("ortools not installed")

    if period < 1:
        return PeriodicResult(
            feasible=False,
            reason=EliminationReason.EMPTY_PARAMETER_SPACE,
            summary=f"period={period} invalid",
            evidence={"variant": variant, "period": period},
            wall_ms=0.0,
        )

    t0 = time.perf_counter()
    model = cp_model.CpModel()
    key = [model.new_int_var(0, 25, f"k_{j}") for j in range(period)]

    # Crib constraints per residue class
    derived = _derived_key_at_crib(variant, ct_override=ct_override)
    for pos, kval in derived.items():
        model.add(key[pos % period] == kval)

    if include_bean:
        # Bean equality
        for a, b in BEAN_EQ:
            model.add(key[a % period] == key[b % period])
        # Bean inequality
        for a, b in BEAN_INEQ:
            model.add(key[a % period] != key[b % period])

    solver = cp_model.CpSolver()
    solver.parameters.max_time_in_seconds = timeout_s
    status = solver.solve(model)
    wall = (time.perf_counter() - t0) * 1000

    if status == cp_model.INFEASIBLE:
        return PeriodicResult(
            feasible=False,
            reason=EliminationReason.BEAN_UNSAT,  # generic; pure path refines
            summary=f"variant={variant} period={period}: CP-SAT INFEASIBLE",
            evidence={
                "variant": variant, "period": period,
                "cp_sat_status": "INFEASIBLE",
                "wall_ms": wall,
            },
            wall_ms=wall,
        )
    if status in (cp_model.OPTIMAL, cp_model.FEASIBLE):
        return PeriodicResult(
            feasible=True,
            reason=None,
            summary=f"variant={variant} period={period}: CP-SAT FEASIBLE",
            evidence={
                "variant": variant, "period": period,
                "cp_sat_status": "FEASIBLE",
                "witness": [solver.value(k) for k in key],
                "wall_ms": wall,
            },
            wall_ms=wall,
        )
    # Unknown / time out
    return PeriodicResult(
        feasible=False,
        reason=EliminationReason.RUNTIME_EXHAUSTED,
        summary=f"variant={variant} period={period}: CP-SAT status={status}",
        evidence={
            "variant": variant, "period": period,
            "cp_sat_status": str(status),
            "wall_ms": wall,
        },
        wall_ms=wall,
    )


# ── Public API ──────────────────────────────────────────────────────────

def check_periodic_additive(
    variant: str,
    period: int,
    *,
    use_cp_sat: bool = True,
    cross_verify: bool = False,
    ct_override: Optional[Sequence[int]] = None,
    include_bean: Optional[bool] = None,
    family_override: Optional[str] = None,
) -> AdmissibilityCertificate | EliminationCertificate:
    """Decide admissibility of the periodic_additive(variant, period) family.

    Args:
        variant: "vigenere" | "beaufort" | "var_beaufort"
        period: integer >= 1
        use_cp_sat: when True and OR-Tools is installed, prefer CP-SAT;
            when False or OR-Tools missing, use the pure-Python path.
        cross_verify: when True, run both backends and require agreement.
            Disagreement raises RuntimeError (it indicates a modelling bug).
        ct_override: optional 97-int sequence replacing the raw K4 CT.
            This is the composition-family escape hatch: callers who want
            to check periodic_additive on a reindexed CT (e.g. after
            undoing a fixed columnar transposition) pass the reindexed
            values here.  When present, `include_bean` defaults to False
            because the hard-coded Bean constraint set was derived from
            the raw K4 CT and does not translate to an arbitrary
            permutation of it.
        include_bean: explicitly include or exclude Bean constraints.
            When ``None`` (default), Bean is applied iff ``ct_override``
            is None.  Set to False to force a weaker-but-still-correct
            admissibility check that reports only crib-collision UNSATs.
        family_override: replace the family name in the returned
            certificate.  Used by composition campaigns to embed
            (width, col_order, period) context so certificates are
            ledger-distinguishable from the raw periodic sweep.

    Returns:
        AdmissibilityCertificate if the family survives,
        EliminationCertificate if the family is formally ruled out.

    Both outcomes carry:
        - family name "periodic_additive/<variant>/p<period>" (or the
          ``family_override`` value when provided)
        - BASE_ASSUMPTIONS
        - solver tag
        - structured evidence dict
    """
    if include_bean is None:
        include_bean = ct_override is None

    family = family_override or f"{FAMILY_PREFIX}/{variant}/p{period}"

    # The pure path is always authoritative for reason refinement.
    pure = _check_periodic_pure(
        variant, period,
        ct_override=ct_override, include_bean=include_bean,
    )

    if cross_verify and HAS_CP_SAT:
        cp = _check_periodic_cpsat(
            variant, period,
            ct_override=ct_override, include_bean=include_bean,
        )
        if cp.feasible != pure.feasible:
            raise RuntimeError(
                f"Backend disagreement for {family}: "
                f"pure={pure.feasible} cp_sat={cp.feasible}"
            )
        solver_tag = "pure_python+cp_sat"
    elif use_cp_sat and HAS_CP_SAT:
        # Use CP-SAT verdict but pure evidence for detail
        cp = _check_periodic_cpsat(
            variant, period,
            ct_override=ct_override, include_bean=include_bean,
        )
        if cp.feasible != pure.feasible:
            raise RuntimeError(
                f"Backend disagreement for {family}: "
                f"pure={pure.feasible} cp_sat={cp.feasible}"
            )
        solver_tag = "cp_sat"
    else:
        solver_tag = "pure_python"

    if pure.feasible:
        return AdmissibilityCertificate(
            family=family,
            summary=pure.summary,
            assumptions=list(BASE_ASSUMPTIONS),
            evidence={**pure.evidence, "wall_ms": pure.wall_ms},
            solver=solver_tag,
        )

    return EliminationCertificate(
        family=family,
        reason=pure.reason or EliminationReason.BEAN_UNSAT,
        summary=pure.summary,
        assumptions=list(BASE_ASSUMPTIONS),
        evidence={**pure.evidence, "wall_ms": pure.wall_ms},
        solver=solver_tag,
        is_exact=True,
    )


def sweep_periodic_additive(
    *,
    periods: Tuple[int, ...] = tuple(range(1, 27)),
    variants: Tuple[str, ...] = ("vigenere", "beaufort", "var_beaufort"),
    cross_verify: bool = False,
) -> List[AdmissibilityCertificate | EliminationCertificate]:
    """Run `check_periodic_additive` over a grid and return every
    certificate produced.  Order: (variant, period) ascending.
    """
    out: List[AdmissibilityCertificate | EliminationCertificate] = []
    for v in variants:
        for p in periods:
            out.append(check_periodic_additive(
                v, p, cross_verify=cross_verify,
            ))
    return out
