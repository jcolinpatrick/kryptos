"""Read-only MCP tool palette for LLM agent sessions.

Activates the in-process MCP tool servers (``dsl_tools``, ``research_tools``)
so LLM agents (theorist, Category-B legacy worker) can query the kernel,
exhaustion log, null baselines, and the theory ledger through *structured*
tools instead of shelling out via Bash. The servers were built and unit-tested
but never mounted into any ``ClaudeAgentOptions``; this module is the mount.

SAFETY
------
Only READ-ONLY / query tools are exposed. Tools that DISPATCH compute
(``submit_hypothesis_spec``) or MUTATE the ledger (``register_hypothesis``,
``update_hypothesis_status``, ``record_experiment_result``) are deliberately
EXCLUDED: letting an agent drive compute or write the ledger would bypass the
R3 critic gate and the deterministic Category-A worker invariant. Those stay
controller-owned.

The deterministic Category-A worker (``controller._run_worker``) makes no SDK
call and must never receive any MCP tools — mounting is for LLM sessions only.

``research_tools`` reads a module-global ledger / canonical-facts state that the
controller injects at init via ``research_tools.set_ledger`` /
``set_canonical_facts``; because ``create_sdk_mcp_server`` builds an in-process
server, that state is visible to the tools. Without injection the research
tools raise at call time (not at mount time).
"""

from __future__ import annotations

from .dsl_tools import create_dsl_mcp_server
from .research_tools import create_research_mcp_server

# mcp_servers dict keys; the SDK exposes each tool as ``mcp__<key>__<tool>``.
# Keep equal to the server ``name=`` so the allowlist prefixes resolve.
DSL_SERVER = "dsl_tools"
RESEARCH_SERVER = "research_tools"

# Read-only / bounded-search DSL tools (everything except the campaign-
# dispatching submit_hypothesis_spec, which stays controller-owned).
# sweep_clue_bounded runs a bounded, synchronous, kernel-verified search that
# writes nothing to the ledger — it is the theorist's search instrument (the
# LLM proposes a hypothesis; the tool enumerates its parameter space).
READONLY_DSL_TOOLS = [
    "sweep_clue_bounded",
    "poll_job",
    "query_exhaustion",
    "compute_null_baseline",
    "score_candidate_canonical",
    "get_procedural_recipe",
    "enumerate_admissible_transforms",
    "request_compute_budget_estimate",
]

# Read-only research tools (everything except the three ledger mutators).
READONLY_RESEARCH_TOOLS = [
    "get_canonical_facts",
    "get_open_anomalies",
    "search_theory_ledger",
    "get_family_status",
    "get_all_families",
    "summarize_recent_learnings",
    "get_ledger_summary",
]

# Tools that must never reach an agent's palette.
EXCLUDED_TOOLS = frozenset(
    {
        "submit_hypothesis_spec",  # dispatches compute (background thread)
        "register_hypothesis",  # mutates ledger
        "update_hypothesis_status",  # mutates ledger
        "record_experiment_result",  # mutates ledger
    }
)


def readonly_allowed_tool_names() -> list[str]:
    """``allowed_tools`` entries for the read-only palette (``mcp__server__tool``)."""
    return [f"mcp__{DSL_SERVER}__{t}" for t in READONLY_DSL_TOOLS] + [
        f"mcp__{RESEARCH_SERVER}__{t}" for t in READONLY_RESEARCH_TOOLS
    ]


def theorist_tool_guidance() -> str:
    """System-prompt block that tells the theorist the read-only query tools
    exist and when to call them.

    Mounting the palette is necessary but not sufficient: an agent that is not
    told the tools exist will not use them (observed in the 2026-05-31 bench
    run). Append this to the theorist system prompt ONLY when the palette is
    mounted (``enable_mcp_tools``). Every tool named here is in
    ``readonly_allowed_tool_names()``. Phrased to stay clear of promotion /
    delegation vocabulary so it does not trip the prompt-contract linter.
    """
    return (
        "## Your role: hypothesis generation\n"
        "Your job is to GENERATE hypotheses — which cipher families, keywords, "
        "and structures to try, including unconventional or frontier ideas. You "
        "do NOT execute, score, or judge: the kernel does, and its verdict is "
        "the only truth. Never declare a solve yourself; report only what the "
        "tools' kernel-verified numbers say.\n"
        "## In-process tools\n"
        "Call these directly instead of writing ad-hoc Bash. They neither run "
        "campaigns nor modify the ledger.\n"
        "- `mcp__dsl_tools__sweep_clue_bounded` — your PRIMARY instrument. Do "
        "NOT hand-author multi-config sweep specs (you author them incorrectly): "
        "give this tool the cipher families to compose and the candidate "
        "keywords, and it sweeps width / layer order / alphabet / "
        "keyword->layer assignment for you and returns the kernel-verified best "
        "crib_score and recovered plaintext. Iterate: try a family set, read the "
        "returned score, adjust. The tool's number is authoritative — your own "
        "belief about whether it solved is not.\n"
        "- `mcp__dsl_tools__query_exhaustion` — before proposing a cipher "
        "family, check whether it is already recorded as tested or eliminated, "
        "so you do not repropose closed work.\n"
        "- `mcp__dsl_tools__enumerate_admissible_transforms` — confirm the "
        "cipher kinds and alphabets your spec uses are translatable by the "
        "dispatcher before proposing them.\n"
        "- `mcp__dsl_tools__request_compute_budget_estimate` — estimate the "
        "wall-clock for a spec and avoid proposing an intractable enumeration.\n"
        "- `mcp__dsl_tools__score_candidate_canonical` — score a concrete "
        "97-character plaintext against the canonical kernel scorer.\n"
        "- `mcp__research_tools__get_family_status`, "
        "`mcp__research_tools__search_theory_ledger`, "
        "`mcp__research_tools__summarize_recent_learnings` — review prior "
        "outcomes for a family or approach.\n"
        "Prefer these tools for these checks: they return kernel- and "
        "ledger-backed facts rather than an estimate."
    )


def build_readonly_mcp_mount() -> tuple[dict, list[str]]:
    """Return ``(mcp_servers, allowed_tool_names)`` for read-only MCP access.

    Pass ``mcp_servers`` to ``ClaudeAgentOptions(mcp_servers=...)`` and extend
    that session's ``allowed_tools`` with ``allowed_tool_names``. Only mount on
    LLM sessions (theorist, legacy worker), never on the deterministic worker.
    """
    mcp_servers = {
        DSL_SERVER: create_dsl_mcp_server(),
        RESEARCH_SERVER: create_research_mcp_server(),
    }
    return mcp_servers, readonly_allowed_tool_names()
