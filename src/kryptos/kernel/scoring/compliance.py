"""Mechanism compliance scoring — Tier 0-3 constraint evaluation.

Evaluates candidate encryption mechanisms against the full constraint
hierarchy derived from K4's confirmed properties:

  Tier 0 (HC): Hard constraints — binary pass/fail, any failure eliminates
  Tier 1 (CxS): Coupling constraints — stego-cipher statistical coupling
  Tier 2 (SC): Bean structural constraints — CT clustering metrics
  Tier 3 (XC): Extra-cryptographic constraints — mechanism properties

Usage:
    from kryptos.kernel.scoring.compliance import (
        MechanismDescription, score_mechanism_compliance,
    )

    mechanism = MechanismDescription(
        name="Beaufort-5wide",
        uses_ka=True, uses_az=True,
        grid_width=5, hand_executable=True,
        periodic=False, key_source="5-wide grid",
    )
    keystream = [ALPH.index(c) for c in BEAUFORT_KEYSTREAM_AT_CRIBS]
    result = score_mechanism_compliance(keystream, mechanism)
    print(result.verdict)  # COMPLIANT / PARTIAL / ELIMINATED
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

import warnings

from kryptos.kernel.constants import (
    ALPH,
    BEAN_INEQ,
    CRIB_DICT,
    CT,
    MOD,
    N_CRIBS,
)
# BEAUFORT_KEYSTREAM_AT_CRIBS moved to kryptos.kernel.retired in framework
# internal phase 2 (2026-04-20). Imported from retired/ below because
# this module is a historical-compliance anchor: CxS-2 pins the expected
# Beaufort keystream at crib positions as a *reference* for mechanism
# comparison, not as live evidence. This file is on the retired-namespace
# allow-list in tests/test_retired_usage.py.
#
# NULL_PALETTE is intentionally NOT imported here.
# Quarantine 2026-04-14: compliance scoring must not implicitly use the
# retired null palette. Callers that still need palette-based enrichment
# (CxS-1, CxS-3) must pass an explicit palette parameter into
# check_coupling_constraints and score_mechanism_compliance. Callers that
# pass palette=None get CxS-1=0.0 / CxS-3=0.0 and a DeprecationWarning.
# See memory/project_consensus_nulls_epistemic_status_2026_04_14.md.
from kryptos.kernel.retired import BEAUFORT_KEYSTREAM_AT_CRIBS
from kryptos.kernel.constraints.coupling import (
    ap_palette_containment,
    dual_alphabet_structure,
    keystream_palette_enrichment,
    mod5_ka_structure,
)


# ── Dataclasses ─────────────────────────────────────────────────────────────


@dataclass
class MechanismDescription:
    """Description of a candidate encryption mechanism's structural properties."""

    name: str
    uses_ka: bool
    uses_az: bool
    grid_width: int | None
    hand_executable: bool | None
    periodic: bool | None
    key_source: str | None
    notes: str = ""


@dataclass
class ComplianceScore:
    """Aggregate compliance score across all constraint tiers."""

    hard_pass: int = 0
    hard_fail: int = 0
    hard_unknown: int = 0
    coupling_score: float = 0.0
    bean_score: float = 0.0
    structural_score: float = 0.0
    total: float = 0.0
    details: dict = field(default_factory=dict)
    verdict: str = "PARTIAL"


# ── Reference keystream (precomputed at module level) ───────────────────────

_REFERENCE_KS: list[int] = [ALPH.index(c) for c in BEAUFORT_KEYSTREAM_AT_CRIBS]
_SORTED_CRIB_POSITIONS: list[int] = sorted(CRIB_DICT.keys())
_CRIB_POSITIONS_SET: frozenset[int] = frozenset(CRIB_DICT.keys())


def _validate_crib_keystream(keystream_at_cribs: list[int]) -> None:
    """Fail closed on malformed crib keystream inputs.

    Compliance scoring is only defined on the 24 crib positions. Letting
    shorter, longer, or out-of-range vectors flow through can produce
    legitimate-looking verdicts from invalid evidence.
    """
    if len(keystream_at_cribs) != N_CRIBS:
        raise ValueError(
            f"keystream_at_cribs must contain exactly {N_CRIBS} values, "
            f"got {len(keystream_at_cribs)}"
        )
    bad = [v for v in keystream_at_cribs if not 0 <= v < MOD]
    if bad:
        raise ValueError(
            f"keystream_at_cribs values must be integers in [0, {MOD}); "
            f"got invalid values {bad[:5]}"
        )


# ── Tier 0: Hard Constraints ───────────────────────────────────────────────


def check_hard_constraints(
    keystream_at_cribs: list[int],
    mechanism: MechanismDescription,
) -> dict[str, str]:
    """Evaluate hard constraints (HC-1 through HC-4).

    Any FAIL eliminates the mechanism. These are non-negotiable.

    Args:
        keystream_at_cribs: List of 24 integers (A=0) at crib positions.
        mechanism: Structural description of the candidate mechanism.

    Returns:
        Dict mapping constraint IDs to "PASS", "FAIL", or "UNKNOWN".
    """
    _validate_crib_keystream(keystream_at_cribs)
    results: dict[str, str] = {}

    # HC-1: Keystream matches reference Beaufort keystream at cribs
    results["HC-1"] = "PASS" if keystream_at_cribs == _REFERENCE_KS else "FAIL"

    # HC-2: Bean equality k[27]=k[65]
    # Positions 27 and 65 are at indices 6 and 15 in the sorted crib list
    idx_27 = 6   # _SORTED_CRIB_POSITIONS.index(27)
    idx_65 = 15  # _SORTED_CRIB_POSITIONS.index(65)
    if len(keystream_at_cribs) > max(idx_27, idx_65):
        results["HC-2"] = (
            "PASS" if keystream_at_cribs[idx_27] == keystream_at_cribs[idx_65]
            else "FAIL"
        )
    else:
        results["HC-2"] = "UNKNOWN"

    # HC-3: Bean inequalities — no crib-position pair should violate
    # Build a mapping from CT position → keystream index
    pos_to_idx: dict[int, int] = {
        pos: i for i, pos in enumerate(_SORTED_CRIB_POSITIONS)
    }
    violations = 0
    for a, b in BEAN_INEQ:
        if a in _CRIB_POSITIONS_SET and b in _CRIB_POSITIONS_SET:
            idx_a = pos_to_idx[a]
            idx_b = pos_to_idx[b]
            if keystream_at_cribs[idx_a] == keystream_at_cribs[idx_b]:
                violations += 1
    results["HC-3"] = "PASS" if violations == 0 else "FAIL"

    # HC-4: Periodic key proven impossible
    if mechanism.periodic is None:
        results["HC-4"] = "UNKNOWN"
    elif mechanism.periodic:
        results["HC-4"] = "FAIL"
    else:
        results["HC-4"] = "PASS"

    return results


# ── Tier 1: Coupling Constraints ──────────────────────────────────────────


def check_coupling_constraints(
    keystream_at_cribs: list[int],
    mechanism: MechanismDescription,
    palette: "frozenset[str] | None" = None,
) -> dict[str, float]:
    """Evaluate stego-cipher coupling constraints (CxS-1 through CxS-4).

    These quantify the statistical relationship between a proposed stego
    layer (null palette) and the cipher layer (keystream). Scores are
    normalized to [0.0, 1.0].

    QUARANTINE 2026-04-14: CxS-1 and CxS-3 require an explicit `palette`
    parameter. Previously this function silently used
    kryptos.kernel.constants.NULL_PALETTE as an implicit default, which
    anchored every compliance evaluation to the retired null-palette /
    null-mask construct (claim_id: null_palette_retired). When `palette`
    is None (the new default), CxS-1 and CxS-3 are returned as 0.0 and a
    DeprecationWarning is emitted. CxS-2 and CxS-4 are unaffected because
    they do not depend on any palette. Historical / regression callers
    that still want the real palette-enrichment math must pass the
    palette explicitly, e.g. `palette=frozenset("BGIKOWZ")`.

    Args:
        keystream_at_cribs: List of 24 integers (A=0) at crib positions.
        mechanism: Structural description of the candidate mechanism.
        palette: Explicit palette to use for CxS-1 and CxS-3. If None,
            the palette-dependent terms return 0.0. There is no implicit
            default — any caller that wants palette-enrichment scoring
            must name the palette itself.

    Returns:
        Dict mapping constraint IDs to normalized scores in [0.0, 1.0].
    """
    _validate_crib_keystream(keystream_at_cribs)
    results: dict[str, float] = {}

    if palette is None:
        warnings.warn(
            "check_coupling_constraints called with palette=None: CxS-1 and "
            "CxS-3 will be reported as 0.0. These terms were previously "
            "anchored to the retired kryptos.kernel.constants.NULL_PALETTE "
            "(claim_id: null_palette_retired, retired 2026-04-14). Pass an "
            "explicit palette if you need the historical palette-enrichment "
            "math. See memory/project_consensus_nulls_epistemic_status_2026_04_14.md.",
            DeprecationWarning,
            stacklevel=2,
        )
        results["CxS-1"] = 0.0
        results["CxS-3"] = 0.0
    else:
        # CxS-1: Keystream palette enrichment — normalized by 13
        cxs1 = keystream_palette_enrichment(keystream_at_cribs, palette)
        results["CxS-1"] = min(cxs1.observed / 13.0, 1.0)
        # CxS-3: AP palette containment — normalized by 12
        cxs3 = ap_palette_containment(keystream_at_cribs, palette)
        results["CxS-3"] = min(cxs3.observed / 12.0, 1.0)

    # CxS-2: Mod-5 KA structure — normalized by 14 (palette-independent)
    cxs2 = mod5_ka_structure(keystream_at_cribs)
    results["CxS-2"] = min(cxs2.observed / 14.0, 1.0)

    # CxS-4: Dual alphabet structure — binary from mechanism description
    results["CxS-4"] = 1.0 if (mechanism.uses_ka and mechanism.uses_az) else 0.0

    return results


# ── Tier 2: Bean Structural Constraints ───────────────────────────────────


def check_bean_constraints(
    keystream_at_cribs: list[int],
) -> dict[str, float]:
    """Evaluate Bean's structural metrics (SC-4 and SC-5).

    These are properties of the ciphertext at known crib positions,
    computed from CT and CRIB_DICT directly. The keystream_at_cribs
    parameter exists for interface consistency but is not used.

    SC-4: Sum of shortest circular distances between CT letters for
          same repeated PT letter, restricted to KRYPTOS set {K,R,Y,P,T,O,S}.
    SC-5: Mean of shortest circular distances between CT letters for
          ALL repeated PT letters (not just KRYPTOS set).

    Args:
        keystream_at_cribs: Not used (interface consistency).

    Returns:
        Dict with "SC-4" (int) and "SC-5" (float) values.
    """
    _validate_crib_keystream(keystream_at_cribs)
    positions = _SORTED_CRIB_POSITIONS
    kryptos_set = set("KRYPTOS")

    # Group crib positions by plaintext letter
    pt_groups: dict[str, list[int]] = defaultdict(list)
    for p in positions:
        pt_groups[CRIB_DICT[p]].append(p)

    def _circular_dist(a_idx: int, b_idx: int) -> int:
        """Shortest circular distance between two alphabet positions."""
        d = abs(a_idx - b_idx)
        return min(d, MOD - d)

    def _pair_distances(ct_positions: list[int]) -> list[int]:
        """Compute all pairwise shortest circular CT distances."""
        ct_nums = [ALPH.index(CT[p]) for p in ct_positions]
        dists: list[int] = []
        for i in range(len(ct_nums)):
            for j in range(i + 1, len(ct_nums)):
                dists.append(_circular_dist(ct_nums[i], ct_nums[j]))
        return dists

    # SC-4: KRYPTOS-set repeated PT letters
    sc4_total = 0
    for letter in kryptos_set:
        if len(pt_groups.get(letter, [])) >= 2:
            sc4_total += sum(_pair_distances(pt_groups[letter]))

    # SC-5: ALL repeated PT letters
    all_dists: list[int] = []
    for letter, pos_list in pt_groups.items():
        if len(pos_list) >= 2:
            all_dists.extend(_pair_distances(pos_list))

    sc5_mean = sum(all_dists) / len(all_dists) if all_dists else 0.0

    return {"SC-4": sc4_total, "SC-5": sc5_mean}


# ── Tier 3: Extra-Cryptographic Structural Constraints ────────────────────


def check_structural_constraints(
    mechanism: MechanismDescription,
) -> dict[str, bool]:
    """Evaluate extra-cryptographic structural constraints (XC-1 through XC-4).

    These check whether the mechanism's described properties match
    known K4 structural requirements.

    Args:
        mechanism: Structural description of the candidate mechanism.

    Returns:
        Dict mapping constraint IDs to True/False.
    """
    results: dict[str, bool] = {}

    # XC-1: Uses both KA and AZ alphabets
    results["XC-1"] = bool(mechanism.uses_ka and mechanism.uses_az)

    # XC-2: Grid width is a multiple of 5
    results["XC-2"] = (
        mechanism.grid_width is not None and mechanism.grid_width % 5 == 0
    )

    # XC-3: Hand-executable
    results["XC-3"] = mechanism.hand_executable is True

    # XC-4: 5-wide grid with identified key source
    results["XC-4"] = (
        mechanism.grid_width == 5 and mechanism.key_source is not None
    )

    return results


# ── Aggregate Scorer ──────────────────────────────────────────────────────


def score_mechanism_compliance(
    keystream_at_cribs: list[int],
    mechanism: MechanismDescription,
    palette: "frozenset[str] | None" = None,
) -> ComplianceScore:
    """Evaluate a candidate mechanism against the full constraint hierarchy.

    Runs all four constraint tiers and produces an aggregate ComplianceScore
    with a verdict: ELIMINATED, COMPLIANT, or PARTIAL.

    Verdict logic:
      - Any HC FAIL → ELIMINATED
      - coupling_score >= 2.5 → COMPLIANT
      - Otherwise → PARTIAL

    QUARANTINE 2026-04-14: the `palette` parameter is plumbed through to
    check_coupling_constraints. When palette is None (the default), the
    palette-dependent CxS-1 and CxS-3 terms are 0.0, which typically
    drops the total coupling_score below 2.5 and pushes the verdict to
    PARTIAL. This is intentional — the previous implicit use of
    NULL_PALETTE was the reason every compliance evaluation silently
    anchored to the retired null-palette construct.

    Args:
        keystream_at_cribs: List of 24 integers (A=0) at crib positions.
        mechanism: Structural description of the candidate mechanism.
        palette: Explicit palette for CxS-1 / CxS-3. See
            check_coupling_constraints for quarantine semantics.

    Returns:
        ComplianceScore with full breakdown and verdict.
    """
    # Run all checkers
    hard = check_hard_constraints(keystream_at_cribs, mechanism)
    coupling = check_coupling_constraints(keystream_at_cribs, mechanism, palette=palette)
    bean = check_bean_constraints(keystream_at_cribs)
    structural = check_structural_constraints(mechanism)

    # Count hard constraint outcomes
    hard_pass = sum(1 for v in hard.values() if v == "PASS")
    hard_fail = sum(1 for v in hard.values() if v == "FAIL")
    hard_unknown = sum(1 for v in hard.values() if v == "UNKNOWN")

    # Coupling score: CxS-1 + CxS-3 + CxS-4 (NOT CxS-2, subsumed by CxS-1)
    coupling_score = coupling["CxS-1"] + coupling["CxS-3"] + coupling["CxS-4"]

    # Bean score: +0.5 if SC-4 <= 21, +0.5 if SC-5 <= 3.7
    bean_score = 0.0
    if bean["SC-4"] <= 21:
        bean_score += 0.5
    if bean["SC-5"] <= 3.7:
        bean_score += 0.5

    # Structural score: count True / count total
    structural_true = sum(1 for v in structural.values() if v is True)
    structural_total = len(structural)
    structural_score = structural_true / structural_total if structural_total > 0 else 0.0

    # Total
    total = coupling_score + bean_score + structural_score

    # Verdict
    if hard_fail > 0:
        verdict = "ELIMINATED"
    elif coupling_score >= 2.5:
        verdict = "COMPLIANT"
    else:
        verdict = "PARTIAL"

    return ComplianceScore(
        hard_pass=hard_pass,
        hard_fail=hard_fail,
        hard_unknown=hard_unknown,
        coupling_score=coupling_score,
        bean_score=bean_score,
        structural_score=structural_score,
        total=total,
        details={
            "hard": hard,
            "coupling": coupling,
            "bean": bean,
            "structural": structural,
        },
        verdict=verdict,
    )
