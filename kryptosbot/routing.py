"""
Pantheon routing for the kryptosbot controller.

Translates PANTHEON.md's "Routing Guide" table into Python dispatch for
selecting which Pantheon agent persona the controller should load in
each phase of each cycle.

Design principles:
  - Pure Python, no LLM calls. Routing is deterministic.
  - Uses the Pantheon roster discovered by pantheon.load_roster() as the
    source of truth for which agents exist, then applies rotation/family
    heuristics to pick one per call site.
  - Provides a safe fallback if an agent the policy wants is missing
    from the roster (e.g. someone deletes a .claude/agents/*.md file
    mid-development).

Public API:
  - select_theorist(cycle_number, roster) -> AgentSpec
      Rotates through a curated generator-role list across cycles so
      each cycle gets a different Pantheon frame. Used by
      _generate_theories in controller.py.
  - select_worker(theory, roster) -> AgentSpec
      Routes based on theory.family. Used by _run_worker.
  - select_redteam(roster) -> AgentSpec
      Always returns the red-team-disprover. Used by the critic-stage
      adversarial sibling call (Day 3).
  - select_stat_auditor(roster) -> AgentSpec
      Always returns the statistical-auditor. Used by the signal-gate
      sibling call (Day 5).
"""

from __future__ import annotations

import logging
from typing import Iterable

from .pantheon import AgentSpec

logger = logging.getLogger("kryptosbot.routing")


# ---------------------------------------------------------------------------
# Theorist rotation
# ---------------------------------------------------------------------------
# PANTHEON.md's "Operators" and "Interpretive Rivals" sections list the
# agents that propose mechanisms/hypotheses. We rotate through these so
# each cycle gets a different frame. Judges (statistical-auditor,
# red-team-disprover, script-auditor, results-analyst) are NOT in this
# list — they audit, they don't generate.
#
# Order is deliberate: alternating operators with interpretive rivals
# keeps adjacent cycles from reinforcing each other's priors.
THEORIST_ROTATION: list[str] = [
    "cryptanalyst",              # operator: algorithmic attacks, systematic elimination
    "escape-room-cryptanalyst",  # interpretive rival: physical/spatial/optical
    "stego-analyst",             # operator: null-mask, placement rules, stego-cipher coupling
    "archivist-historian",       # interpretive rival: primary sources, designer intent
    "keystream-forensics",       # operator: tape models, null consumption, crib-derived keystream
    "cipher-discovery-builder",  # operator: obscure ciphers, corpus expansion
]


def select_theorist(
    cycle_number: int,
    roster: dict[str, AgentSpec],
) -> AgentSpec:
    """
    Pick the theorist persona for a given cycle by round-robin rotation
    over THEORIST_ROTATION. If the preferred agent is missing from the
    roster (unusual), fall back to cryptanalyst, then to any agent, then
    raise.
    """
    if not roster:
        raise ValueError(
            "routing.select_theorist: roster is empty — cannot route"
        )

    n = len(THEORIST_ROTATION)
    idx = cycle_number % n
    preferred = THEORIST_ROTATION[idx]

    spec = roster.get(preferred)
    if spec is not None:
        return spec

    logger.warning(
        "routing: preferred theorist '%s' not in roster, falling back",
        preferred,
    )
    # Fall back to cryptanalyst if available
    if "cryptanalyst" in roster:
        return roster["cryptanalyst"]
    # Last resort: any operator-like agent (not a judge)
    for name in THEORIST_ROTATION:
        if name in roster:
            return roster[name]
    # Pathological case — return anything so the caller can proceed
    return next(iter(roster.values()))


# ---------------------------------------------------------------------------
# Worker routing
# ---------------------------------------------------------------------------
# Workers run a specific hypothesis test. The agent persona the worker
# should load depends on what the theory is doing. We route by theory.family
# with sensible catch-alls.
#
# The mapping is drawn from PANTHEON.md "Routing Guide" lines 280-298,
# adapted to the family_id values the controller actually sees in theories.
FAMILY_TO_WORKER_AGENT: dict[str, str] = {
    # Cipher families → primary attack operator
    "vigenere": "cryptanalyst",
    "beaufort": "cryptanalyst",
    "variant_beaufort": "cryptanalyst",
    "gromark": "cryptanalyst",
    "gronsfeld": "cryptanalyst",
    "porta": "cryptanalyst",
    "four_square": "cryptanalyst",
    "columnar": "cryptanalyst",
    "columnar_single": "cryptanalyst",
    "double_columnar": "cryptanalyst",
    "transposition": "cryptanalyst",
    "rail_fence": "cryptanalyst",
    "myszkowski": "cryptanalyst",
    "serpentine": "cryptanalyst",
    "spiral": "cryptanalyst",
    "route": "cryptanalyst",
    "polyalphabetic": "cryptanalyst",
    "quagmire_ii": "cryptanalyst",
    "fractionation": "cryptanalyst",
    "running_key": "cryptanalyst",
    "multi_layer": "cryptanalyst",
    "encoding": "cryptanalyst",
    "k3_continuity": "cryptanalyst",
    "k2_coords": "cryptanalyst",

    # Stego / null-mask work → specialist
    "stego_layer": "stego-analyst",
    "null_mask": "stego-analyst",
    "placement": "stego-analyst",

    # Keystream / tape work → specialist
    # NOTE: `key_tape` (with underscore) is the family label the theorist
    # actually emits — distinct from `keystream`. Both route to the same
    # specialist. Added 2026-04-13 during Day 4 routing audit.
    "keystream": "keystream-forensics",
    "key_tape": "keystream-forensics",
    "tape": "keystream-forensics",
    "otp": "keystream-forensics",
    "finite_key_tape": "keystream-forensics",

    # Physical / installation / spatial → interpretive rival
    "geometry": "escape-room-cryptanalyst",
    "grille": "escape-room-cryptanalyst",
    "overlay": "escape-room-cryptanalyst",
    "antipodes": "escape-room-cryptanalyst",
    "geodetic": "escape-room-cryptanalyst",
    "procedural": "escape-room-cryptanalyst",

    # Archive / historical → specialist
    # NOTE: crib_analysis was originally routed to archivist-historian but
    # that was wrong. Crib verification is mechanical cryptanalyst work —
    # checking a candidate plaintext against known crib positions — not
    # primary-source archival research. Reassigned 2026-04-13 during the
    # Day 4 routing audit.
    "archive_evidence": "archivist-historian",
    "crib_analysis": "cryptanalyst",

    # Default operator
    "unknown": "cryptanalyst",
    "_uncategorized": "cryptanalyst",
}


def select_worker(
    theory_family: str,
    roster: dict[str, AgentSpec],
) -> AgentSpec:
    """
    Pick the worker persona for a specific theory based on its family.
    Falls back to cryptanalyst if the mapped agent isn't in the roster,
    then to any available agent.
    """
    if not roster:
        raise ValueError(
            "routing.select_worker: roster is empty — cannot route"
        )

    family_norm = (theory_family or "").lower().replace(" ", "_").replace("/", "_")
    preferred = FAMILY_TO_WORKER_AGENT.get(family_norm, "cryptanalyst")

    spec = roster.get(preferred)
    if spec is not None:
        return spec

    logger.warning(
        "routing: preferred worker '%s' for family '%s' not in roster, falling back to cryptanalyst",
        preferred, family_norm,
    )
    if "cryptanalyst" in roster:
        return roster["cryptanalyst"]
    return next(iter(roster.values()))


# ---------------------------------------------------------------------------
# Adversarial / audit routing (used in Day 3 and Day 5)
# ---------------------------------------------------------------------------


def select_redteam(roster: dict[str, AgentSpec]) -> AgentSpec | None:
    """Return the red-team-disprover agent, or None if missing."""
    return roster.get("red-team-disprover")


def select_stat_auditor(roster: dict[str, AgentSpec]) -> AgentSpec | None:
    """Return the statistical-auditor agent, or None if missing."""
    return roster.get("statistical-auditor")


def select_results_analyst(roster: dict[str, AgentSpec]) -> AgentSpec | None:
    """Return the results-analyst agent for end-of-cycle synthesis (Day 5)."""
    return roster.get("results-analyst")


def select_pursuit_evaluator(roster: dict[str, AgentSpec]) -> AgentSpec | None:
    """Return the agent that evaluates sub-signal leads for pursuit (Day 6).

    Defaults to results-analyst — same persona as synthesis, different
    mode. If results-analyst is missing, falls back to research-chancellor
    so the phase still runs with a competent judgment engine. Returns
    None if neither is loaded; the controller treats that as a skip.
    """
    return roster.get("results-analyst") or roster.get("research-chancellor")


def select_chancellor(roster: dict[str, AgentSpec]) -> AgentSpec | None:
    """Return the research-chancellor agent, or None if missing."""
    return roster.get("research-chancellor")


# ---------------------------------------------------------------------------
# Diagnostic helper
# ---------------------------------------------------------------------------


def describe_routing_table(roster: dict[str, AgentSpec]) -> str:
    """
    Produce a human-readable summary of what the routing policy would
    pick for each call site, given the current roster. Useful for
    debugging and the Day 2 startup log.
    """
    lines: list[str] = []
    lines.append("Pantheon routing:")
    lines.append(f"  roster: {len(roster)} agents")

    lines.append(f"  theorist rotation ({len(THEORIST_ROTATION)} slots):")
    for i, name in enumerate(THEORIST_ROTATION):
        present = "✓" if name in roster else "MISSING"
        lines.append(f"    slot {i}: {name} [{present}]")

    lines.append("  worker dispatch (family → agent):")
    by_agent: dict[str, list[str]] = {}
    for fam, agent in FAMILY_TO_WORKER_AGENT.items():
        by_agent.setdefault(agent, []).append(fam)
    for agent in sorted(by_agent):
        present = "✓" if agent in roster else "MISSING"
        fams = ", ".join(sorted(by_agent[agent]))
        lines.append(f"    {agent} [{present}] ← {fams}")

    lines.append("  adversarial/audit:")
    lines.append(
        f"    red-team-disprover: "
        f"{'✓' if 'red-team-disprover' in roster else 'MISSING'}"
    )
    lines.append(
        f"    statistical-auditor: "
        f"{'✓' if 'statistical-auditor' in roster else 'MISSING'}"
    )
    lines.append(
        f"    research-chancellor: "
        f"{'✓' if 'research-chancellor' in roster else 'MISSING'}"
    )

    return "\n".join(lines)
