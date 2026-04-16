"""
Auto-hedging renderers for ProvenanceClaim objects.

These renderers are the single place where epistemic hedges are inserted
into human-visible text. Callers must never hand-write hedges in prose;
instead, pass the claim through one of these functions. Renderers are
idempotent (repeated rendering does not stack hedges) and never strip
caveats from the claim's caveat list.
"""

from __future__ import annotations

from .provenance import (
    ProvenanceClaim,
    EpistemicClass as EC,
    ScopeConditions,
)


# Grouping order used by render_inventory
INVENTORY_ORDER: list[EC] = [
    EC.PUBLIC_FACT,
    EC.PRIMARY_SOURCE_FACT,
    EC.PROJECT_CONVENTION,
    EC.H1_CONDITIONAL_DERIVATION,
    EC.PROJECT_REVERIFIED_STATISTICAL_ANOMALY,
    EC.BEAN_REPORTED_NOT_RERUN,
    EC.PHYSICAL_FACT,
    EC.INTERPRETIVE_PHYSICAL_OBSERVATION,
    EC.STRUCTURAL_ELIMINATION,
    EC.CONDITIONAL_ELIMINATION,
    EC.RETIRED_CLAIM,
]

_SECTION_TITLES: dict[EC, str] = {
    EC.PUBLIC_FACT: "Public facts",
    EC.PRIMARY_SOURCE_FACT: "Primary-source facts",
    EC.PROJECT_CONVENTION: "Project conventions",
    EC.H1_CONDITIONAL_DERIVATION: "H1-conditional derivations (direct positional crib mapping)",
    EC.PROJECT_REVERIFIED_STATISTICAL_ANOMALY: "Project-reverified statistical anomalies",
    EC.BEAN_REPORTED_NOT_RERUN: "Bean-reported (NOT independently re-derived in project)",
    EC.PHYSICAL_FACT: "Physical facts (sculpture)",
    EC.INTERPRETIVE_PHYSICAL_OBSERVATION: "Interpretive physical observations",
    EC.STRUCTURAL_ELIMINATION: "Structural eliminations",
    EC.CONDITIONAL_ELIMINATION: "Conditional eliminations (scope-dependent)",
    EC.RETIRED_CLAIM: "Retired claims (do not revive)",
}


_H1_PREFIX = (
    "Under H1 (direct positional crib mapping on the carved 97-char CT, "
    "additive cipher class): "
)
_BEAN_REPORTED_SUFFIX = " [Bean-reported, not independently re-derived in project.]"
_PROJECT_ANOMALY_SUFFIX = (
    " [Project-verified anomaly; remains a filter/ranking feature, not a mandatory constraint.]"
)
_INTERPRETIVE_SUFFIX = (
    " [Physical existence may be confirmed; cryptographic role is unproven.]"
)
_CONDITIONAL_SUFFIX = " [Elimination scope: see scope_conditions.]"
_RETIRED_PREFIX = "[RETIRED] "
_RETIRED_SUFFIX = " [Do not revive without rehabilitation.]"

_CRIB_SCOPE_PHRASE = "at the 24 crib positions"
_BEAUFORT_A0_PHRASE = "under Beaufort A=0"
_EXTERNAL_STAT_PHRASE = "external statistic, not project-rerun"


def _apply_scope_phrases(text: str, scope: ScopeConditions) -> str:
    """Append scope-based hedges if they are not already present."""
    additions: list[str] = []
    if scope.applies_only_to_crib_positions is True and _CRIB_SCOPE_PHRASE not in text:
        additions.append(_CRIB_SCOPE_PHRASE)
    if scope.assumes_beaufort_a0 is True and _BEAUFORT_A0_PHRASE not in text:
        additions.append(_BEAUFORT_A0_PHRASE)
    if (
        scope.depends_on_external_author_statistic is True
        and _EXTERNAL_STAT_PHRASE not in text
    ):
        additions.append(_EXTERNAL_STAT_PHRASE)
    if additions:
        text = text + " (" + "; ".join(additions) + ")"
    return text


def _hedged_text(claim: ProvenanceClaim) -> str:
    text = claim.claim_text or ""
    ec = claim.epistemic_class

    if ec == EC.H1_CONDITIONAL_DERIVATION:
        if not text.startswith(_H1_PREFIX) and "Under H1" not in text[:40]:
            text = _H1_PREFIX + text
    elif ec == EC.BEAN_REPORTED_NOT_RERUN:
        if _BEAN_REPORTED_SUFFIX.strip() not in text:
            text = text + _BEAN_REPORTED_SUFFIX
    elif ec == EC.PROJECT_REVERIFIED_STATISTICAL_ANOMALY:
        if "Project-verified anomaly" not in text:
            text = text + _PROJECT_ANOMALY_SUFFIX
    elif ec == EC.INTERPRETIVE_PHYSICAL_OBSERVATION:
        if "cryptographic role is unproven" not in text:
            text = text + _INTERPRETIVE_SUFFIX
    elif ec == EC.CONDITIONAL_ELIMINATION:
        if "Elimination scope" not in text:
            text = text + _CONDITIONAL_SUFFIX
    elif ec == EC.RETIRED_CLAIM:
        if not text.startswith(_RETIRED_PREFIX):
            text = _RETIRED_PREFIX + text
        if "Do not revive" not in text:
            text = text + _RETIRED_SUFFIX

    text = _apply_scope_phrases(text, claim.scope_conditions)
    return text


def render_claim(claim: ProvenanceClaim, format: str = "text") -> str:
    """Render a single claim with auto-inserted hedges.

    format: "text" (default) emits the hedged claim_text followed by any
    caveats from the claim's caveats list on bullet lines.
    """
    hedged = _hedged_text(claim)
    if format != "text":
        raise ValueError(f"Unknown format: {format}")

    lines = [f"- [{claim.claim_id}] {hedged}"]
    for cav in claim.caveats:
        lines.append(f"    * {cav}")
    return "\n".join(lines)


def render_claim_inline(claim: ProvenanceClaim) -> str:
    """Short inline rendering for prompt context: hedged claim_text only."""
    return _hedged_text(claim)


def render_inventory(claims: list[ProvenanceClaim]) -> str:
    """Full inventory grouped by epistemic class with auto-hedges.

    Output:
        # Provenance inventory
        ## <section title>
        - [claim_id] <hedged text>
            * caveat
        ...
        ## Summary
        <counts>
    """
    by_class: dict[EC, list[ProvenanceClaim]] = {}
    for c in claims:
        by_class.setdefault(c.epistemic_class, []).append(c)

    lines: list[str] = ["# Provenance inventory", ""]

    for ec in INVENTORY_ORDER:
        section_claims = by_class.get(ec, [])
        if not section_claims:
            continue
        lines.append(f"## {_SECTION_TITLES.get(ec, ec.value)}")
        lines.append("")
        for claim in section_claims:
            lines.append(render_claim(claim))
        lines.append("")

    # Any classes not in INVENTORY_ORDER (e.g. HYPOTHESIS, INTERNAL_RESULT)
    extra = [
        ec for ec in by_class.keys() if ec not in INVENTORY_ORDER
    ]
    for ec in extra:
        lines.append(f"## Other: {ec.value}")
        lines.append("")
        for claim in by_class[ec]:
            lines.append(render_claim(claim))
        lines.append("")

    # Summary counts
    lines.append("## Summary")
    lines.append("")
    total = 0
    for ec in INVENTORY_ORDER + extra:
        n = len(by_class.get(ec, []))
        if n:
            lines.append(f"- {ec.value}: {n}")
            total += n
    lines.append(f"- total: {total}")
    return "\n".join(lines)
