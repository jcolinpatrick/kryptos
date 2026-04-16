"""
MCP tools for structured research state access.

Extends the K4 computational tools (k4_tools.py) with tools that let
Agent SDK workers query and update the theory ledger, anomaly registry,
and family status. Workers use these instead of parsing docs or prompts.

Requires a TheoryLedger instance to be injected before use.
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any, Optional

from claude_agent_sdk import tool, create_sdk_mcp_server, SdkMcpTool

from .models import (
    TheoryRecord, TheoryStatus,
    WorkerContract, WorkerStatus,
    ExperimentRecord,
    EvidenceLink, EvidenceType,
    CriticVerdict, CriticDecision,
)

logger = logging.getLogger("kryptosbot.research_tools")


# ---------------------------------------------------------------------------
# Shared state — injected by controller before creating MCP server
# ---------------------------------------------------------------------------

_ledger = None  # TheoryLedger instance
_canonical_facts: dict[str, Any] = {}


def set_ledger(ledger: Any) -> None:
    """Inject the TheoryLedger instance for tools to use."""
    global _ledger
    _ledger = ledger


def set_canonical_facts(facts: dict[str, Any]) -> None:
    """Inject canonical facts (loaded from kernel constants)."""
    global _canonical_facts
    _canonical_facts = facts


def _require_ledger() -> Any:
    if _ledger is None:
        raise RuntimeError("TheoryLedger not initialized — call set_ledger() first")
    return _ledger


# ---------------------------------------------------------------------------
# Tool: get_canonical_facts
# ---------------------------------------------------------------------------

@tool(
    "get_canonical_facts",
    "Get canonical K4 facts: ciphertext, crib positions, Bean constraints, "
    "and scoring thresholds. These are canonical K4 facts loaded from the "
    "kernel constants module. They deliberately do NOT include any retired "
    "claims (e.g., the retired null-palette / null-mask family, claim_id "
    "null_palette_retired). Retired claims are tracked in claims_registry "
    "and must not be treated as live evidence.",
    {},
)
async def get_canonical_facts_tool(args: dict[str, Any]) -> dict[str, Any]:
    result = dict(_canonical_facts) if _canonical_facts else {
        "error": "Canonical facts not loaded. Use kernel constants directly."
    }
    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


# ---------------------------------------------------------------------------
# Tool: get_open_anomalies
# ---------------------------------------------------------------------------

@tool(
    "get_open_anomalies",
    "Get all open/disputed anomalies in the K4 research landscape. "
    "These are unexplained observations that theories should address.",
    {},
)
async def get_open_anomalies_tool(args: dict[str, Any]) -> dict[str, Any]:
    ledger = _require_ledger()
    anomalies = ledger.get_open_anomalies()
    result = {
        "count": len(anomalies),
        "anomalies": [a.to_dict() for a in anomalies],
    }
    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


# ---------------------------------------------------------------------------
# Tool: search_theory_ledger
# ---------------------------------------------------------------------------

@tool(
    "search_theory_ledger",
    "Search the theory ledger for hypotheses matching a query. "
    "Can filter by family, status, and minimum score.",
    {
        "query": str,
        "family": str,
        "status": str,
        "min_score": float,
        "limit": int,
    },
)
async def search_theory_ledger_tool(args: dict[str, Any]) -> dict[str, Any]:
    ledger = _require_ledger()
    theories = ledger.search_theories(
        query=args.get("query", ""),
        family=args.get("family", ""),
        status=args.get("status", ""),
        min_score=args.get("min_score", 0.0),
        limit=args.get("limit", 20),
    )
    result = {
        "count": len(theories),
        "theories": [
            {
                "hypothesis_id": t.hypothesis_id,
                "title": t.title,
                "family": t.family,
                "status": t.status.value,
                "best_score": t.best_score,
                "mechanism": t.mechanism[:200],
                "outcome_summary": t.outcome_summary[:200],
            }
            for t in theories
        ],
    }
    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


# ---------------------------------------------------------------------------
# Tool: register_hypothesis
# ---------------------------------------------------------------------------

@tool(
    "register_hypothesis",
    "Register a new hypothesis in the theory ledger. Returns the hypothesis_id. "
    "Required: title, core_claim, mechanism, family. Optional: all other fields.",
    {
        "title": str,
        "core_claim": str,
        "mechanism": str,
        "family": str,
        "subfamily": str,
        "tags": list,
        "clue_anchors_used": list,
        "anomalies_exploited": list,
        "novelty_basis": str,
        "kill_criteria": list,
        "expected_signal": str,
        "compute_cost_estimate": str,
    },
)
async def register_hypothesis_tool(args: dict[str, Any]) -> dict[str, Any]:
    ledger = _require_ledger()

    theory = TheoryRecord(
        title=args.get("title", ""),
        core_claim=args.get("core_claim", ""),
        mechanism=args.get("mechanism", ""),
        family=args.get("family", ""),
        subfamily=args.get("subfamily", ""),
        tags=args.get("tags", []),
        clue_anchors_used=args.get("clue_anchors_used", []),
        anomalies_exploited=args.get("anomalies_exploited", []),
        novelty_basis=args.get("novelty_basis", ""),
        kill_criteria=args.get("kill_criteria", []),
        expected_signal=args.get("expected_signal", ""),
        compute_cost_estimate=args.get("compute_cost_estimate", ""),
    )

    # Check for duplicates
    if ledger.exists(theory.hypothesis_id):
        existing = ledger.get_theory(theory.hypothesis_id)
        return {"content": [{"type": "text", "text": json.dumps({
            "status": "duplicate",
            "hypothesis_id": theory.hypothesis_id,
            "existing_status": existing.status.value if existing else "unknown",
            "message": "A theory with identical core claim + mechanism + family already exists.",
        }, indent=2)}]}

    ledger.upsert_theory(theory)
    result = {
        "status": "registered",
        "hypothesis_id": theory.hypothesis_id,
        "title": theory.title,
    }
    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


# ---------------------------------------------------------------------------
# Tool: update_hypothesis_status
# ---------------------------------------------------------------------------

@tool(
    "update_hypothesis_status",
    "Update the status of a hypothesis in the theory ledger. "
    "Valid statuses: proposed, criticized, approved, running, completed, "
    "eliminated, promising, superseded, withdrawn.",
    {
        "hypothesis_id": str,
        "status": str,
        "outcome_summary": str,
        "failure_reason": str,
        "best_score": float,
        "best_plaintext": str,
    },
)
async def update_hypothesis_status_tool(args: dict[str, Any]) -> dict[str, Any]:
    ledger = _require_ledger()
    hyp_id = args["hypothesis_id"]

    if not ledger.exists(hyp_id):
        return {"content": [{"type": "text", "text": json.dumps({
            "error": f"Hypothesis {hyp_id} not found in ledger"
        })}]}

    status_str = args.get("status", "")
    try:
        status = TheoryStatus(status_str)
    except ValueError:
        return {"content": [{"type": "text", "text": json.dumps({
            "error": f"Invalid status '{status_str}'. Valid: {[s.value for s in TheoryStatus]}"
        })}]}

    extra: dict[str, Any] = {}
    if "outcome_summary" in args:
        extra["outcome_summary"] = args["outcome_summary"]
    if "failure_reason" in args:
        extra["failure_reason"] = args["failure_reason"]
    if "best_score" in args:
        extra["best_score"] = args["best_score"]
    if "best_plaintext" in args:
        extra["best_plaintext"] = args["best_plaintext"]

    ledger.update_theory_status(hyp_id, status, **extra)
    return {"content": [{"type": "text", "text": json.dumps({
        "status": "updated",
        "hypothesis_id": hyp_id,
        "new_status": status.value,
    }, indent=2)}]}


# ---------------------------------------------------------------------------
# Tool: get_family_status
# ---------------------------------------------------------------------------

@tool(
    "get_family_status",
    "Get the status of a cipher/approach family: active, exhausted, "
    "partially explored, or blocked. Includes elimination tier and evidence.",
    {"family_id": str},
)
async def get_family_status_tool(args: dict[str, Any]) -> dict[str, Any]:
    ledger = _require_ledger()
    fam_id = args.get("family_id", "")

    fam = ledger.get_family(fam_id)
    if not fam:
        # Try fuzzy match
        all_fams = ledger.get_all_families()
        matches = [f for f in all_fams if fam_id.lower() in f.family_id.lower()]
        if matches:
            fam = matches[0]

    if not fam:
        return {"content": [{"type": "text", "text": json.dumps({
            "error": f"Family '{fam_id}' not found",
            "suggestion": "Use get_all_families to see available families",
        })}]}

    return {"content": [{"type": "text", "text": json.dumps(fam.to_dict(), indent=2)}]}


# ---------------------------------------------------------------------------
# Tool: get_all_families
# ---------------------------------------------------------------------------

@tool(
    "get_all_families",
    "List all tracked cipher/approach families with their status and stats.",
    {},
)
async def get_all_families_tool(args: dict[str, Any]) -> dict[str, Any]:
    ledger = _require_ledger()
    families = ledger.get_all_families()
    result = {
        "count": len(families),
        "families": [
            {
                "family_id": f.family_id,
                "name": f.name,
                "status": f.status.value,
                "elimination_tier": f.elimination_tier,
                "total_theories": f.total_theories,
                "eliminated_theories": f.eliminated_theories,
                "best_score": f.best_score,
            }
            for f in families
        ],
    }
    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


# ---------------------------------------------------------------------------
# Tool: record_experiment_result
# ---------------------------------------------------------------------------

@tool(
    "record_experiment_result",
    "Record the structured result of an experiment. This is the primary "
    "way workers report outcomes to the controller.",
    {
        "hypothesis_id": str,
        "status": str,
        "score": float,
        "crib_score": int,
        "bean_passed": bool,
        "best_plaintext": str,
        "disproof_evidence": list,
        "supporting_evidence": list,
        "next_action": str,
        "family_generalization": str,
        "narrative_summary": str,
    },
)
async def record_experiment_result_tool(args: dict[str, Any]) -> dict[str, Any]:
    # Hardening note (post-audit, 2026-04-14):
    #
    # This tool previously built a WorkerContract directly from caller
    # arguments and mapped WorkerStatus.SUCCESS → TheoryStatus.PROMISING
    # unconditionally. That bypassed the main controller's _absorb_outcomes
    # path and gave any worker a backdoor to promote a theory by
    # self-reporting score=anything / bean_passed=True / crib_score=24.
    #
    # Now we route through the same two gates the controller uses:
    #
    #   1. _verify_against_kernel() recomputes crib_score, bean_passed, and
    #      score from best_plaintext against the kernel. Self-reported
    #      numeric fields are discarded in favor of kernel truth. Wrong
    #      length, empty PT with non-zero claims, or kernel failure all
    #      zero the scores and set verification_error.
    #
    #   2. SUCCESS is only promoted to PROMISING when the KERNEL-VERIFIED
    #      crib_score crosses SIGNAL_THRESHOLD. Otherwise SUCCESS becomes
    #      COMPLETED — the run finished without crashing but produced no
    #      signal worth pursuing. This mirrors controller._absorb_outcomes
    #      and closes the "promise via backdoor" loophole.
    ledger = _require_ledger()
    hyp_id = args["hypothesis_id"]

    if not ledger.exists(hyp_id):
        return {"content": [{"type": "text", "text": json.dumps({
            "error": f"Hypothesis {hyp_id} not found"
        })}]}

    status_val = args.get("status", "")
    valid_statuses = [s.value for s in WorkerStatus]
    if status_val not in valid_statuses:
        return {"content": [{"type": "text", "text": json.dumps({
            "error": f"Invalid status '{status_val}'; valid values: {valid_statuses}"
        })}]}
    worker_status = WorkerStatus(status_val)

    contract = WorkerContract(
        hypothesis_id=hyp_id,
        worker_role="agent_sdk",
        status=worker_status,
        score=float(args.get("score", 0.0) or 0.0),
        crib_score=int(args.get("crib_score", 0) or 0),
        bean_passed=bool(args.get("bean_passed", False)),
        best_plaintext=str(args.get("best_plaintext", "") or ""),
        disproof_evidence=args.get("disproof_evidence", []) or [],
        supporting_evidence=args.get("supporting_evidence", []) or [],
        next_action=str(args.get("next_action", "") or ""),
        family_generalization=str(args.get("family_generalization", "") or ""),
        narrative_summary=str(args.get("narrative_summary", "") or ""),
    )

    # Gate 1: kernel verification. Overwrites worker-reported numeric
    # fields with kernel-computed truth and preserves the worker's original
    # claim on the contract for audit.
    from .contracts import _verify_against_kernel
    _verify_against_kernel(contract)

    exp_id = f"exp-{uuid.uuid4().hex[:8]}"
    exp = ExperimentRecord(
        experiment_id=exp_id,
        hypothesis_id=hyp_id,
        worker_role=contract.worker_role,
        result=contract,
    )
    ledger.record_experiment(exp)

    # Gate 2: threshold-gated promotion. Never trust WorkerStatus.SUCCESS
    # alone — require kernel-verified crib_score to cross SIGNAL_THRESHOLD.
    try:
        from .constants import SIGNAL_THRESHOLD as _SIGNAL_THRESHOLD
    except ImportError:
        _SIGNAL_THRESHOLD = 18

    if worker_status == WorkerStatus.SUCCESS:
        if contract.crib_score >= _SIGNAL_THRESHOLD:
            theory_status = TheoryStatus.PROMISING
        else:
            theory_status = TheoryStatus.COMPLETED
            logger.info(
                "record_experiment_result: %s reported SUCCESS but verified "
                "crib_score=%d < SIGNAL=%d — recording as COMPLETED",
                hyp_id[:8], contract.crib_score, _SIGNAL_THRESHOLD,
            )
    else:
        theory_status = {
            WorkerStatus.DISPROVED: TheoryStatus.ELIMINATED,
            WorkerStatus.INCONCLUSIVE: TheoryStatus.COMPLETED,
            WorkerStatus.ERROR: TheoryStatus.COMPLETED,
            WorkerStatus.TIMEOUT: TheoryStatus.COMPLETED,
        }.get(worker_status, TheoryStatus.COMPLETED)

    ledger.update_theory_status(
        hyp_id,
        theory_status,
        best_score=contract.score,
        best_plaintext=contract.best_plaintext[:500],
        outcome_summary=contract.narrative_summary[:2000],
        failure_reason=(
            "; ".join(contract.disproof_evidence[:3])
            if contract.disproof_evidence else ""
        ),
    )

    # Add experiment to theory's experiment list
    theory = ledger.get_theory(hyp_id)
    if theory:
        theory.experiment_ids.append(exp_id)
        ledger.upsert_theory(theory)

    result = {
        "status": "recorded",
        "experiment_id": exp_id,
        "hypothesis_id": hyp_id,
        "theory_status": theory_status.value,
        "verified_crib_score": contract.crib_score,
        "verified_bean_passed": contract.bean_passed,
        "fields_overwritten": bool(getattr(contract, "fields_overwritten", False)),
        "verification_error": getattr(contract, "verification_error", "") or "",
    }
    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


# ---------------------------------------------------------------------------
# Tool: summarize_recent_learnings
# ---------------------------------------------------------------------------

@tool(
    "summarize_recent_learnings",
    "Get a structured summary of recent campaign learnings: "
    "what was tested, what was eliminated, what looks promising.",
    {"limit": int},
)
async def summarize_recent_learnings_tool(args: dict[str, Any]) -> dict[str, Any]:
    ledger = _require_ledger()
    limit = args.get("limit", 20)
    recent = ledger.recent_outcomes(limit=limit)

    eliminated = [t for t in recent if t.status == TheoryStatus.ELIMINATED]
    promising = [t for t in recent if t.status == TheoryStatus.PROMISING]
    completed = [t for t in recent if t.status == TheoryStatus.COMPLETED]

    result = {
        "total_recent": len(recent),
        "eliminated": [
            {
                "title": t.title,
                "family": t.family,
                "failure_reason": t.failure_reason[:200],
            }
            for t in eliminated
        ],
        "promising": [
            {
                "title": t.title,
                "family": t.family,
                "best_score": t.best_score,
                "outcome_summary": t.outcome_summary[:200],
            }
            for t in promising
        ],
        "completed": len(completed),
        "families_tested": list(set(t.family for t in recent)),
    }
    return {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}


# ---------------------------------------------------------------------------
# Tool: get_ledger_summary
# ---------------------------------------------------------------------------

@tool(
    "get_ledger_summary",
    "Get a high-level dashboard of the theory ledger: total theories, "
    "status breakdown, top scoring, open anomalies, tracked families.",
    {},
)
async def get_ledger_summary_tool(args: dict[str, Any]) -> dict[str, Any]:
    ledger = _require_ledger()
    summary = ledger.summary()
    return {"content": [{"type": "text", "text": json.dumps(summary, indent=2)}]}


# ---------------------------------------------------------------------------
# All research tools + MCP server factory
# ---------------------------------------------------------------------------

ALL_RESEARCH_TOOLS: list[SdkMcpTool] = [
    get_canonical_facts_tool,
    get_open_anomalies_tool,
    search_theory_ledger_tool,
    register_hypothesis_tool,
    update_hypothesis_status_tool,
    get_family_status_tool,
    get_all_families_tool,
    record_experiment_result_tool,
    summarize_recent_learnings_tool,
    get_ledger_summary_tool,
]


def create_research_mcp_server() -> dict:
    """Create MCP server config with all research state tools."""
    return create_sdk_mcp_server(
        name="research_tools",
        version="1.0.0",
        tools=ALL_RESEARCH_TOOLS,
    )
