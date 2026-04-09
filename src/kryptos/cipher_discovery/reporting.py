"""Report generator for cipher discovery findings.

Produces markdown and JSON reports ranked by K4 relevance and novelty.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .schema import CipherRecord, Taxonomy, CipherType
from .persistence import DiscoveryDB
from .config import DiscoveryConfig


def _novelty_rank(rec: CipherRecord) -> float:
    """Score combining K4 relevance and novelty (untested = higher)."""
    base = rec.k4_relevance_score
    if not rec.tested_in_project:
        base += 20.0  # significant bonus for untested
    if rec.exhaustion_status == "exhausted":
        base -= 30.0  # heavy penalty for exhausted
    base += rec.obscurity_score * 10.0  # obscure = more interesting
    return base


def generate_markdown_report(
    records: list[CipherRecord],
    stats: dict,
    output_path: Optional[str] = None,
) -> str:
    """Generate a comprehensive markdown report."""
    lines = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines.append("# Cipher Discovery Report")
    lines.append(f"Generated: {now}")
    lines.append("")

    # --- Summary ---
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Total cipher systems cataloged:** {stats.get('total_ciphers', len(records))}")
    lines.append(f"- **Tested in project:** {stats.get('tested_ciphers', 0)}")
    lines.append(f"- **Untested:** {stats.get('untested_ciphers', 0)}")
    lines.append("")

    # Taxonomy breakdown
    tax = stats.get("taxonomy_breakdown", {})
    if tax:
        lines.append("### Taxonomy Breakdown")
        lines.append("")
        for t, cnt in sorted(tax.items(), key=lambda x: -x[1]):
            lines.append(f"- {t}: {cnt}")
        lines.append("")

    # --- Top candidates by novelty-weighted K4 relevance ---
    ranked = sorted(records, key=lambda r: _novelty_rank(r), reverse=True)

    lines.append("## Top Candidates by K4 Relevance (novelty-weighted)")
    lines.append("")
    lines.append("Untested ciphers receive a bonus. Exhausted ciphers receive a penalty.")
    lines.append("")

    for i, rec in enumerate(ranked[:40], 1):
        novelty = _novelty_rank(rec)
        status_tag = "UNTESTED" if not rec.tested_in_project else (
            "EXHAUSTED" if rec.exhaustion_status == "exhausted" else "ACTIVE"
        )
        lines.append(f"### {i}. {rec.canonical_name}")
        lines.append("")
        lines.append(f"- **Status:** [{status_tag}]")
        lines.append(f"- **K4 Relevance Score:** {rec.k4_relevance_score:.1f}/100")
        lines.append(f"- **Novelty-weighted Score:** {novelty:.1f}")
        lines.append(f"- **Obscurity:** {rec.obscurity_score:.2f}")
        lines.append(f"- **Type:** {rec.cipher_type.value}")
        lines.append(f"- **Category:** {rec.category}")
        lines.append(f"- **Taxonomy:** {rec.taxonomy.value}")
        lines.append(f"- **Aliases:** {', '.join(rec.alias_names[:5]) if rec.alias_names else 'none'}")
        lines.append("")

        if rec.description:
            # Truncate long descriptions
            desc = rec.description[:500]
            if len(rec.description) > 500:
                desc += "..."
            lines.append(f"**Description:** {desc}")
            lines.append("")

        if rec.operational_mechanics:
            lines.append(f"**How it works:** {rec.operational_mechanics[:300]}")
            lines.append("")

        # Why hand-executable
        if rec.manual_execution_type:
            lines.append(f"**Hand-executable:** {rec.manual_execution_type}")
        if rec.tools_required:
            lines.append(f"**Tools needed:** {', '.join(rec.tools_required)}")
        lines.append("")

        # K4 relevance reasoning
        breakdown = rec.k4_score_breakdown
        if breakdown:
            top_factors = sorted(
                [(k, v) for k, v in breakdown.items()
                 if k != "total" and isinstance(v, (int, float)) and v > 3],
                key=lambda x: -x[1]
            )
            if top_factors:
                reasons = ", ".join(f"{k}={v:.1f}" for k, v in top_factors[:5])
                lines.append(f"**K4 relevance factors:** {reasons}")
                lines.append("")

        # Exhaustion cross-reference
        if rec.tested_in_project:
            ids_str = ", ".join(rec.exhaustion_log_ids[:5])
            if len(rec.exhaustion_log_ids) > 5:
                ids_str += f" ... (+{len(rec.exhaustion_log_ids)-5} more)"
            lines.append(f"**Project scripts:** {ids_str}")
            lines.append(f"**Exhaustion status:** {rec.exhaustion_status}")
            lines.append("")
        else:
            lines.append("**Project scripts:** NONE -- not yet tested")
            lines.append("")

        # Unresolved questions
        if rec.unresolved_questions:
            lines.append("**Open questions:**")
            for q in rec.unresolved_questions[:3]:
                lines.append(f"  - {q}")
            lines.append("")

        # Ambiguity flags
        if rec.ambiguity_flags:
            lines.append("**Ambiguity flags:**")
            for f in rec.ambiguity_flags[:3]:
                lines.append(f"  - {f}")
            lines.append("")

        lines.append("---")
        lines.append("")

    # --- Special section: Compass Cipher and Alphabet Code ---
    lines.append("## Special Analysis: Sanborn-Referenced Ambiguous Terms")
    lines.append("")

    for term in ["Compass Cipher", "Alphabet Code"]:
        matching = [r for r in records if r.canonical_name.lower() == term.lower()]
        if matching:
            rec = matching[0]
            lines.append(f"### {rec.canonical_name}")
            lines.append("")
            lines.append(f"{rec.description}")
            lines.append("")
            if rec.ambiguity_flags:
                lines.append("**Key ambiguities:**")
                for f in rec.ambiguity_flags:
                    lines.append(f"- {f}")
                lines.append("")
            if rec.unresolved_questions:
                lines.append("**Unresolved questions:**")
                for q in rec.unresolved_questions:
                    lines.append(f"- {q}")
                lines.append("")

    # --- Untested systems ---
    untested = [r for r in ranked if not r.tested_in_project and r.k4_relevance_score > 30]
    if untested:
        lines.append("## Untested Systems with K4 Relevance > 30")
        lines.append("")
        lines.append("| Rank | Cipher | K4 Score | Obscurity | Type |")
        lines.append("|------|--------|----------|-----------|------|")
        for i, rec in enumerate(untested[:20], 1):
            lines.append(
                f"| {i} | {rec.canonical_name} | {rec.k4_relevance_score:.1f} "
                f"| {rec.obscurity_score:.2f} | {rec.cipher_type.value} |"
            )
        lines.append("")

    # --- Exhausted systems ---
    exhausted = [r for r in records if rec.exhaustion_status == "exhausted"]
    if exhausted:
        lines.append("## Exhausted Systems (confirmed eliminated)")
        lines.append("")
        lines.append(f"Total: {len(exhausted)} systems with matching exhaustion log entries")
        lines.append("")

    # --- Coverage gaps ---
    lines.append("## Coverage Gaps and Remaining Blind Spots")
    lines.append("")
    lines.append("[POLICY] This report does not claim complete coverage.")
    lines.append("")
    lines.append("### Known gaps:")
    lines.append("- Bespoke systems that Sanborn/Scheidt may have invented (unknowable without physical evidence)")
    lines.append("- Obscure military field ciphers from classified manuals (TICOM archives partially explored)")
    lines.append("- Regional/cultural cipher traditions (Indian, Chinese, Japanese, Arabic) beyond well-known examples")
    lines.append("- Unpublished cipher contest entries and hobbyist inventions")
    lines.append("- Physical/spatial ciphers specific to the Kryptos sculpture geometry")
    lines.append("- Systems described only in private correspondence or unpublished manuscripts")
    lines.append("")
    lines.append("### Most productive areas for expansion:")
    lines.append("- TICOM and declassified NSA historical documents")
    lines.append("- ACA Cryptogram back issues (many obscure cipher types defined there)")
    lines.append("- Historical patent filings for cipher devices")
    lines.append("- Sanborn's archives (ongoing research)")
    lines.append("- Morse fractionation variants (Sanborn references Morse)")
    lines.append("- Compass/navigation themed encoding (Sanborn references compass)")
    lines.append("")

    # --- Truth taxonomy note ---
    lines.append("## Truth Taxonomy")
    lines.append("")
    lines.append("- Cipher system descriptions: [PUBLIC FACT] from cryptographic literature")
    lines.append("- K4 relevance scores: [HYPOTHESIS] based on heuristic rubric")
    lines.append("- Exhaustion cross-references: [INTERNAL RESULT] from this project's exhaustion_log.json")
    lines.append("- Sanborn/Scheidt references: [PUBLIC FACT] from Archives of American Art")
    lines.append("- Coverage assessments: [POLICY] -- no claim of completeness")
    lines.append("")

    report = "\n".join(lines)

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            f.write(report)

    return report


def generate_json_report(
    records: list[CipherRecord],
    stats: dict,
    output_path: Optional[str] = None,
) -> dict:
    """Generate a JSON report."""
    ranked = sorted(records, key=lambda r: _novelty_rank(r), reverse=True)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": stats,
        "top_candidates": [r.to_dict() for r in ranked[:40]],
        "untested_high_relevance": [
            r.to_dict() for r in ranked
            if not r.tested_in_project and r.k4_relevance_score > 30
        ][:20],
        "total_records": len(records),
    }

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, default=str)

    return report
