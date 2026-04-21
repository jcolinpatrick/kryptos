"""
Sibling-call wrappers for invoking Pantheon agents from the controller.

All inter-agent orchestration in kryptosbot happens through this module's
sibling-call pattern, NOT through inline Task/Agent delegation from one
agent's session to another. The Python controller is the only orchestrator;
agents are isolated SDK sessions that the controller calls and merges.

Why sibling calls:
  - Subagents cannot spawn subagents in the Claude Agent SDK (verified
    from Anthropic docs and reinforced by Colin's explicit guidance).
  - Sibling calls are explicit and observable — the controller knows
    exactly which agents ran and what they returned.
  - Sibling calls survive SDK bugs around nested subagent semantics.
  - Failure isolation: a hung red-team session doesn't poison a worker
    or theorist session.

This module provides:
  - RedTeamVerdict dataclass + run_red_team_precheck(theory, ...) —
    proposal-time adversarial review (Day 3)
  - StatAuditVerdict dataclass + run_stat_audit(theory, contract, ...) —
    post-execution signal audit for kernel-verified crib_score >= SIGNAL
    (Day 5)
  - CycleSynthesis dataclass + run_results_synthesis(...) — end-of-cycle
    structured handoff to the next cycle's theorist (Day 5)

All sibling functions follow the same shape:
  - Take a structured input (theory, outcome, etc.)
  - Load the appropriate Pantheon agent persona via pantheon.load_agent
  - Build a system prompt using the agent's *_system_prompt() variant
    that fits the call site (audit, theorist, redteam_precheck, etc.)
  - Make a single SDK query() call with disallowed_tools=["Task", "Agent"]
    to enforce sibling discipline
  - Parse the structured response
  - Return a structured verdict dataclass
  - Handle errors gracefully — never raise to the controller, always
    return a degraded-but-valid verdict that the controller can absorb
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from claude_agent_sdk import ClaudeAgentOptions

from .models import TheoryRecord, WorkerContract
from .pantheon import AgentSpec, resolve_model_for_phase
from .sdk_wrapper import safe_query

logger = logging.getLogger("kryptosbot.pantheon_siblings")


# ---------------------------------------------------------------------------
# Red-team pre-check verdict
# ---------------------------------------------------------------------------


SEARCH_SPACE_RISK_VALUES: tuple[str, ...] = (
    "none",
    "unbounded_search",
    "exhausted_source_material",
    "underconstrained",
    "duplicate_family",
    "residual_caution",
    "other",
)


@dataclass
class RedTeamVerdict:
    """
    Structured verdict from a red-team-disprover proposal-time pre-check.

    The controller uses `verdict` to decide whether to dispatch the theory:
      - "pass"      → dispatch normally
      - "concerned" → dispatch but log warning
      - "reject"    → downgrade to REJECTED, do not dispatch
      - "error"     → degraded sibling call (parse failed, SDK failed,
                      timeout, etc.) — controller treats this as "pass"
                      to avoid losing theories due to red-team flakiness.
                      The error string explains what went wrong.

    `reasons` and `next_test` are advisory and logged regardless of verdict.

    `search_space_risk` is the Priority 5 structured taxonomy field. The
    red-team agent emits it directly rather than having the controller
    infer a label from reasons prose via a lexicon. See
    memory/project_priority5_search_space_risk_design.md for semantics
    and controller behavior per value. Default "none" so PASS verdicts
    and pre-Priority-5 ledger rows behave correctly.
    """
    verdict: str  # "pass" | "concerned" | "reject" | "error"
    confidence: float  # [0.0, 1.0]
    reasons: list[str] = field(default_factory=list)
    next_test: str = ""
    search_space_risk: str = "none"
    raw_output: str = ""
    error: Optional[str] = None
    wall_time_sec: float = 0.0
    turn_count: int = 0
    tool_count: int = 0

    @property
    def should_dispatch(self) -> bool:
        """True unless the verdict is an explicit reject."""
        return self.verdict != "reject"

    def to_log_line(self, theory_id: str) -> str:
        """Compact one-line summary for logging."""
        marker = {
            "pass": "✓",
            "concerned": "~",
            "reject": "✗",
            "error": "?",
        }.get(self.verdict, "?")
        reason_text = self.reasons[0] if self.reasons else ""
        if len(reason_text) > 80:
            reason_text = reason_text[:77] + "..."
        return (
            f"  redteam {marker} {theory_id[:8]} verdict={self.verdict} "
            f"conf={self.confidence:.2f} ({self.wall_time_sec:.0f}s, "
            f"{self.turn_count}t, {self.tool_count} tools) — {reason_text}"
        )


# ---------------------------------------------------------------------------
# Red-team pre-check call
# ---------------------------------------------------------------------------


_REDTEAM_USER_PROMPT_TEMPLATE = """\
You are pre-checking ONE proposed K4 theory before the controller dispatches a worker to test it. Apply your adversarial priors and decide whether the theory is worth the compute.

THEORY UNDER REVIEW:

  hypothesis_id : {hypothesis_id}
  title         : {title}
  family        : {family}
  core_claim    : {core_claim}
  mechanism     : {mechanism}
  kill_criteria : {kill_criteria}
  expected_signal: {expected_signal}
  anomalies_exploited: {anomalies_exploited}
  tags          : {tags}

YOUR TASK:
Decide whether to PASS this theory through to dispatch, mark it CONCERNED but allow dispatch, or REJECT it before compute is spent. Apply your bias toward finding noise, symmetric failure modes, and post-hoc constructions. Specifically check for:

1. **Symmetric failure modes** — does the hypothesis "explain" any data because every failure can be rescued by adjusting a free parameter? (e.g. "perturb up to N CT letters" with no stated N)
2. **Already eliminated** — does this restate a known-dead family in new vocabulary?
3. **Vague kill criteria** — would you actually be able to disprove this, or could the proposer always claim more search is needed?
4. **Numerology without mechanism** — is the proposal "X = alphabet size, therefore..." with no procedural rule connecting X to the K4 plaintext?
5. **Unstated budgets** — does the theory invoke an enumeration without saying when to stop?
6. **Cross-cycle echo** — has a near-identical mechanism been tested and disproved in this run already?

Output exactly ONE JSON object with the four fields specified in your operational mode override (verdict, confidence, reasons, next_test). No prose. No markdown fences.
"""


def _serialize_theory_for_redteam(theory: TheoryRecord) -> dict[str, str]:
    """Extract the fields red-team needs from a TheoryRecord."""
    return {
        "hypothesis_id": theory.hypothesis_id or "(unset)",
        "title": theory.title or "(no title)",
        "family": theory.family or "(no family)",
        "core_claim": theory.core_claim or "(no claim)",
        "mechanism": theory.mechanism or "(no mechanism)",
        "kill_criteria": (
            "; ".join(theory.kill_criteria) if theory.kill_criteria else "(none)"
        ),
        "expected_signal": theory.expected_signal or "(none)",
        "anomalies_exploited": (
            ", ".join(theory.anomalies_exploited)
            if theory.anomalies_exploited
            else "(none)"
        ),
        "tags": ", ".join(theory.tags) if theory.tags else "(none)",
    }


def _build_redteam_user_prompt(theory: TheoryRecord) -> str:
    """Render the user prompt for a red-team pre-check call."""
    fields = _serialize_theory_for_redteam(theory)
    return _REDTEAM_USER_PROMPT_TEMPLATE.format(**fields)


def _extract_json_object(raw: str) -> dict | None:
    """
    Pull the first top-level JSON object out of a raw model response.

    Same brace-walker pattern used in _day1_probe_skills.py — robust
    against markdown fences, leading/trailing prose, and string-internal
    braces.
    """
    if not raw:
        return None

    cleaned = raw
    for fence in ("```json", "```JSON", "```"):
        cleaned = cleaned.replace(fence, "")
    cleaned = cleaned.strip()

    # Try direct parse
    try:
        result = json.loads(cleaned)
        return result if isinstance(result, dict) else None
    except json.JSONDecodeError:
        pass

    # Brace-walking fallback
    for start in range(len(cleaned)):
        if cleaned[start] != "{":
            continue
        depth = 0
        in_string = False
        escape = False
        for end in range(start, len(cleaned)):
            ch = cleaned[end]
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    candidate = cleaned[start:end + 1]
                    try:
                        result = json.loads(candidate)
                        if isinstance(result, dict):
                            return result
                    except json.JSONDecodeError:
                        break
    return None


def _normalize_verdict_dict(parsed: dict) -> RedTeamVerdict:
    """
    Convert a parsed JSON dict into a RedTeamVerdict, applying tolerant
    field extraction so a slightly-off response shape still produces a
    usable verdict instead of falling all the way to "error".
    """
    verdict_raw = str(parsed.get("verdict", "")).strip().lower()
    if verdict_raw not in ("pass", "concerned", "reject"):
        # Tolerant alternatives the model might emit
        verdict_map = {
            "approve": "pass", "approved": "pass", "ok": "pass", "yes": "pass",
            "warn": "concerned", "warning": "concerned", "review": "concerned",
            "deny": "reject", "denied": "reject", "fail": "reject", "no": "reject",
            "block": "reject", "blocked": "reject",
        }
        verdict_raw = verdict_map.get(verdict_raw, "concerned")  # safe default

    try:
        confidence = float(parsed.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))
    except (TypeError, ValueError):
        confidence = 0.5

    reasons_raw = parsed.get("reasons", [])
    if isinstance(reasons_raw, str):
        reasons = [reasons_raw]
    elif isinstance(reasons_raw, list):
        reasons = [str(r).strip() for r in reasons_raw if r]
    else:
        reasons = []

    next_test = str(parsed.get("next_test", "")).strip()

    risk_raw = parsed.get("search_space_risk", None)
    if risk_raw is None:
        search_space_risk = "none"
    else:
        risk_str = str(risk_raw).strip().lower().replace("-", "_")
        if risk_str in SEARCH_SPACE_RISK_VALUES:
            search_space_risk = risk_str
        else:
            logger.warning(
                "red-team emitted unknown search_space_risk=%r; "
                "recording as 'other' so the failure mode is visible",
                risk_raw,
            )
            search_space_risk = "other"
    # PASS verdicts logically cannot carry a non-none risk value — a PASS
    # means the theory cleared structural concerns. If the agent emits
    # a risk on a PASS, treat it as a shape error and force "none" so
    # downstream gating stays consistent with verdict semantics.
    if verdict_raw == "pass" and search_space_risk != "none":
        search_space_risk = "none"
    # REJECT verdicts are blocked pre-dispatch, so their risk value is
    # diagnostic only. Leave whatever the agent emitted.

    return RedTeamVerdict(
        verdict=verdict_raw,
        confidence=confidence,
        reasons=reasons,
        next_test=next_test,
        search_space_risk=search_space_risk,
    )


async def run_red_team_precheck(
    theory: TheoryRecord,
    *,
    redteam_spec: AgentSpec,
    project_root: Path,
    allowed_tools: list[str],
    permission_mode: str = "bypassPermissions",
    max_turns: int = 20,
) -> RedTeamVerdict:
    """
    Make a sibling call to red-team-disprover for proposal-time pre-check.

    Returns a RedTeamVerdict regardless of success or failure. On any
    error (SDK failure, parse failure, malformed response), returns a
    verdict with verdict="error" — which the controller treats as "pass"
    to avoid losing theories to red-team flakiness. The error string
    explains what went wrong for log auditing.

    Args:
        theory: the candidate theory to pre-check
        redteam_spec: the red-team-disprover AgentSpec (loaded once
            per controller instance; the sibling call uses
            spec.redteam_precheck_system_prompt() as the system prompt)
        project_root: absolute path to the kryptos repo root
        allowed_tools: tools the red-team session can use (typically
            ["Read", "Bash", "Grep", "Glob"] for brief investigation)
        permission_mode: SDK permission mode
        max_turns: cap on red-team session turns. The wrapper directs
            red-team to use under 5 reasoning turns + 3 tool calls,
            so 20 gives ample headroom without allowing runaway loops.

    Returns: RedTeamVerdict
    """
    import time

    system_prompt = redteam_spec.redteam_precheck_system_prompt()
    user_prompt = _build_redteam_user_prompt(theory)
    model, fallback_model = resolve_model_for_phase(redteam_spec, "red_team")

    options = ClaudeAgentOptions(
        allowed_tools=allowed_tools,
        # Sibling-call discipline: red-team cannot spawn further subagents.
        disallowed_tools=["Task", "Agent"],
        permission_mode=permission_mode,
        system_prompt=system_prompt,
        cwd=str(project_root),
        max_turns=max_turns,
        setting_sources=["project"],
        model=model,
        fallback_model=fallback_model,
    )

    start = time.monotonic()
    result_chunks: list[str] = []
    content_chunks: list[str] = []
    turn_count = 0
    tool_count = 0

    try:
        async for message in safe_query(prompt=user_prompt, options=options):
            if hasattr(message, "result") and message.result:
                result_chunks.append(str(message.result))
            elif hasattr(message, "content"):
                turn_count += 1
                content = message.content
                if isinstance(content, list):
                    for block in content:
                        if hasattr(block, "text") and block.text:
                            content_chunks.append(block.text)
                        elif hasattr(block, "type") and block.type == "tool_use":
                            tool_count += 1
                else:
                    content_chunks.append(str(content))
    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.warning(
            "redteam pre-check SDK error for %s: %s: %s",
            theory.hypothesis_id, type(exc).__name__, exc,
        )
        return RedTeamVerdict(
            verdict="error",
            confidence=0.0,
            reasons=[f"SDK error: {type(exc).__name__}: {exc}"],
            error=f"sdk:{type(exc).__name__}",
            wall_time_sec=elapsed,
            turn_count=turn_count,
            tool_count=tool_count,
        )

    elapsed = time.monotonic() - start

    if result_chunks:
        raw = "".join(result_chunks).strip()
    else:
        raw = "".join(content_chunks).strip()

    parsed = _extract_json_object(raw)
    if parsed is None:
        logger.warning(
            "redteam pre-check parse failure for %s — raw length %d, "
            "first 200 chars: %r",
            theory.hypothesis_id, len(raw), raw[:200],
        )
        return RedTeamVerdict(
            verdict="error",
            confidence=0.0,
            reasons=["parse_failure: red-team output was not valid JSON"],
            raw_output=raw,
            error="parse_failure",
            wall_time_sec=elapsed,
            turn_count=turn_count,
            tool_count=tool_count,
        )

    verdict = _normalize_verdict_dict(parsed)
    verdict.raw_output = raw
    verdict.wall_time_sec = elapsed
    verdict.turn_count = turn_count
    verdict.tool_count = tool_count
    return verdict


# ===========================================================================
# Day 5: Statistical-auditor post-execution signal audit sibling call
# ===========================================================================


@dataclass
class StatAuditVerdict:
    """
    Structured verdict from a statistical-auditor post-execution signal
    audit. Used to gate alerts and ledger updates for any contract whose
    kernel-verified crib_score is at or above the SIGNAL threshold.

    The controller uses `verdict` to decide:
      - "confirmed" → allow alerts to fire, propagate finding normally
      - "concerned" → allow alerts to fire, record concerns on the contract
      - "rejected"  → SUPPRESS the alert; record rejection reasons on the
                      contract for audit
      - "error"     → degraded sibling call (parse failed, SDK failed,
                      timeout) — controller treats this as "concerned" so
                      no signal is silently dropped due to auditor flakiness

    `methodology_concerns` and `recommended_action` are advisory and
    logged regardless of verdict.
    """
    verdict: str  # "confirmed" | "concerned" | "rejected" | "error"
    confidence: float  # [0.0, 1.0]
    methodology_concerns: list[str] = field(default_factory=list)
    recommended_action: str = ""
    raw_output: str = ""
    error: Optional[str] = None
    wall_time_sec: float = 0.0
    turn_count: int = 0
    tool_count: int = 0

    @property
    def should_alert(self) -> bool:
        """True unless the verdict is an explicit reject."""
        return self.verdict != "rejected"

    def to_log_line(self, theory_id: str) -> str:
        """Compact one-line summary for logging."""
        marker = {
            "confirmed": "✓",
            "concerned": "~",
            "rejected": "✗",
            "error": "?",
        }.get(self.verdict, "?")
        concern = self.methodology_concerns[0] if self.methodology_concerns else ""
        if len(concern) > 80:
            concern = concern[:77] + "..."
        return (
            f"  stataudit {marker} {theory_id[:8]} verdict={self.verdict} "
            f"conf={self.confidence:.2f} ({self.wall_time_sec:.0f}s, "
            f"{self.turn_count}t, {self.tool_count} tools) — {concern}"
        )


_STAT_AUDIT_USER_PROMPT_TEMPLATE = """\
You are auditing ONE worker result that a kernel-verified scoring pass has flagged as at or above the SIGNAL threshold (crib_score >= 18). Decide whether the signal survives statistical scrutiny.

THEORY UNDER REVIEW:

  hypothesis_id : {hypothesis_id}
  title         : {title}
  family        : {family}
  core_claim    : {core_claim}
  mechanism     : {mechanism}

WORKER RESULT (kernel-verified — these score fields were independently recomputed from best_plaintext, NOT trusted from the worker's self-report):

  status              : {status}
  crib_score          : {crib_score} / 24
  bean_passed         : {bean_passed}
  score               : {score}
  best_plaintext      : {best_plaintext}
  fields_overwritten  : {fields_overwritten}
  worker_self_report  : {worker_self_report}
  verification_error  : {verification_error}
  duration_seconds    : {duration_seconds}

WORKER NARRATIVE (advisory, may be unreliable):
  {narrative_summary}

YOUR TASK:
Decide whether to CONFIRM this signal, mark it CONCERNED but allow it to propagate, or REJECT it. Apply your statistical-rigor priors. Specifically check for:

1. **Multiple-testing burden** — was this result produced by a search broad enough that crib_score >= 18 is no longer remarkable? Account for the cycle's effective search size, not just this single test.
2. **Null model mismatch** — does the implied null distribution match the actual search procedure, or is the threshold being applied to the wrong baseline?
3. **Post-hoc threshold setting** — did the worker (or the theory) move goalposts after seeing the data?
4. **Worker fabrication signs** — if `fields_overwritten` is True, the worker tried to inflate something. Read the `worker_self_report` and decide whether this changes your trust in the rest of the contract.
5. **Crib-pasting fingerprint** — does the best_plaintext have correct cribs at canonical positions but obviously gibberish filler? That's a known fabrication failure mode (Bean is variant-independent and was derived from these cribs, so any CT97 plaintext with correct cribs at positions 21-33 / 63-73 will pass Bean regardless of filler).
6. **Look-elsewhere effect** — was the signal location chosen post-hoc?
7. **Conflict with prior eliminations** — does this result require an existing elimination to be wrong? If yes, what specifically would have to fail?

Output exactly ONE JSON object with the four fields specified in your operational mode override (verdict, confidence, methodology_concerns, recommended_action). No prose. No markdown fences.
"""


def _serialize_contract_for_stat_audit(
    contract: WorkerContract,
    theory: TheoryRecord,
) -> dict[str, str]:
    """Extract the fields the stat-auditor needs from contract + theory."""
    pt = contract.best_plaintext or ""
    if len(pt) > 200:
        pt_display = pt[:200] + f"... ({len(pt)} chars total)"
    else:
        pt_display = pt or "(empty)"
    return {
        "hypothesis_id": theory.hypothesis_id or "(unset)",
        "title": theory.title or "(no title)",
        "family": theory.family or "(no family)",
        "core_claim": theory.core_claim or "(no claim)",
        "mechanism": theory.mechanism or "(no mechanism)",
        "status": contract.status.value,
        "crib_score": str(contract.crib_score),
        "bean_passed": str(contract.bean_passed),
        "score": f"{contract.score:.2f}",
        "best_plaintext": pt_display,
        "fields_overwritten": str(contract.fields_overwritten),
        "worker_self_report": (
            json.dumps(contract.worker_self_report)
            if contract.worker_self_report else "(none)"
        ),
        "verification_error": contract.verification_error or "(none)",
        "duration_seconds": f"{contract.duration_seconds:.0f}",
        "narrative_summary": (contract.narrative_summary or "(none)")[:500],
    }


def _build_stat_audit_user_prompt(
    contract: WorkerContract,
    theory: TheoryRecord,
) -> str:
    fields = _serialize_contract_for_stat_audit(contract, theory)
    return _STAT_AUDIT_USER_PROMPT_TEMPLATE.format(**fields)


def _normalize_stat_audit_dict(parsed: dict) -> StatAuditVerdict:
    """
    Convert a parsed JSON dict into a StatAuditVerdict, applying tolerant
    field extraction so a slightly-off response shape still produces a
    usable verdict instead of falling all the way to "error".
    """
    verdict_raw = str(parsed.get("verdict", "")).strip().lower()
    if verdict_raw not in ("confirmed", "concerned", "rejected"):
        verdict_map = {
            "confirm": "confirmed", "ok": "confirmed", "pass": "confirmed",
            "yes": "confirmed", "valid": "confirmed",
            "warn": "concerned", "warning": "concerned", "review": "concerned",
            "reject": "rejected", "deny": "rejected", "fail": "rejected",
            "no": "rejected", "block": "rejected", "invalid": "rejected",
        }
        verdict_raw = verdict_map.get(verdict_raw, "concerned")  # safe default

    try:
        confidence = float(parsed.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))
    except (TypeError, ValueError):
        confidence = 0.5

    concerns_raw = parsed.get("methodology_concerns", parsed.get("concerns", []))
    if isinstance(concerns_raw, str):
        concerns = [concerns_raw]
    elif isinstance(concerns_raw, list):
        concerns = [str(c).strip() for c in concerns_raw if c]
    else:
        concerns = []

    action = str(parsed.get("recommended_action", "")).strip()

    return StatAuditVerdict(
        verdict=verdict_raw,
        confidence=confidence,
        methodology_concerns=concerns,
        recommended_action=action,
    )


async def run_stat_audit(
    theory: TheoryRecord,
    contract: WorkerContract,
    *,
    audit_spec: AgentSpec,
    project_root: Path,
    allowed_tools: list[str],
    permission_mode: str = "bypassPermissions",
    max_turns: int = 20,
) -> StatAuditVerdict:
    """
    Make a sibling call to statistical-auditor for post-execution signal
    audit on a single contract.

    Returns a StatAuditVerdict regardless of success or failure. On any
    error (SDK failure, parse failure, malformed response), returns a
    verdict with verdict="error" — which the controller treats as
    "concerned" (NOT "confirmed") so a flaky audit doesn't silently
    suppress real signals AND doesn't silently confirm noise.
    """
    system_prompt = audit_spec.stat_audit_system_prompt()
    user_prompt = _build_stat_audit_user_prompt(contract, theory)
    model, fallback_model = resolve_model_for_phase(audit_spec, "stat_audit")

    options = ClaudeAgentOptions(
        allowed_tools=allowed_tools,
        disallowed_tools=["Task", "Agent"],
        permission_mode=permission_mode,
        system_prompt=system_prompt,
        cwd=str(project_root),
        max_turns=max_turns,
        setting_sources=["project"],
        model=model,
        fallback_model=fallback_model,
    )

    start = time.monotonic()
    result_chunks: list[str] = []
    content_chunks: list[str] = []
    turn_count = 0
    tool_count = 0

    try:
        async for message in safe_query(prompt=user_prompt, options=options):
            if hasattr(message, "result") and message.result:
                result_chunks.append(str(message.result))
            elif hasattr(message, "content"):
                turn_count += 1
                content = message.content
                if isinstance(content, list):
                    for block in content:
                        if hasattr(block, "text") and block.text:
                            content_chunks.append(block.text)
                        elif hasattr(block, "type") and block.type == "tool_use":
                            tool_count += 1
                else:
                    content_chunks.append(str(content))
    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.warning(
            "stat-audit SDK error for %s: %s: %s",
            theory.hypothesis_id, type(exc).__name__, exc,
        )
        return StatAuditVerdict(
            verdict="error",
            confidence=0.0,
            methodology_concerns=[f"SDK error: {type(exc).__name__}: {exc}"],
            error=f"sdk:{type(exc).__name__}",
            wall_time_sec=elapsed,
            turn_count=turn_count,
            tool_count=tool_count,
        )

    elapsed = time.monotonic() - start

    if result_chunks:
        raw = "".join(result_chunks).strip()
    else:
        raw = "".join(content_chunks).strip()

    parsed = _extract_json_object(raw)
    if parsed is None:
        logger.warning(
            "stat-audit parse failure for %s — raw length %d, first 200 chars: %r",
            theory.hypothesis_id, len(raw), raw[:200],
        )
        return StatAuditVerdict(
            verdict="error",
            confidence=0.0,
            methodology_concerns=["parse_failure: stat-audit output was not valid JSON"],
            raw_output=raw,
            error="parse_failure",
            wall_time_sec=elapsed,
            turn_count=turn_count,
            tool_count=tool_count,
        )

    verdict = _normalize_stat_audit_dict(parsed)
    verdict.raw_output = raw
    verdict.wall_time_sec = elapsed
    verdict.turn_count = turn_count
    verdict.tool_count = tool_count
    return verdict


# ===========================================================================
# Day 6: Lead-pursuit evaluator sibling call
# ===========================================================================


@dataclass
class PursuitVerdict:
    """
    Structured verdict from a lead-pursuit evaluator call on a sub-signal
    (6 <= crib_score <= 17) worker result.

    The controller uses `worth_pursuing` to decide whether to open a
    structured pursuit lead in the ledger. `rationale` is human-readable
    text explaining why (or why not). `suggested_variants` is an advisory
    list of short variant direction strings that will be surfaced to the
    next cycle's theorist as priority context.

    Verdict states:
      - "pursue"     → worth pursuing, open a lead
      - "skip"       → not worth the rotation slot, do not open a lead
      - "error"      → degraded sibling call (parse/SDK failure); controller
                       treats as "skip" so flaky calls cannot silently
                       flood the pursuit queue with bogus leads.
    """
    verdict: str  # "pursue" | "skip" | "error"
    confidence: float  # [0.0, 1.0]
    rationale: str = ""
    suggested_variants: list[str] = field(default_factory=list)
    raw_output: str = ""
    error: Optional[str] = None
    wall_time_sec: float = 0.0
    turn_count: int = 0
    tool_count: int = 0

    @property
    def worth_pursuing(self) -> bool:
        return self.verdict == "pursue"

    def to_log_line(self, theory_id: str) -> str:
        marker = {"pursue": "↪", "skip": "·", "error": "?"}.get(self.verdict, "?")
        rationale = self.rationale[:80]
        return (
            f"  pursuit {marker} {theory_id[:8]} verdict={self.verdict} "
            f"conf={self.confidence:.2f} ({self.wall_time_sec:.0f}s, "
            f"{self.turn_count}t, {self.tool_count} tools) — {rationale}"
        )


_PURSUIT_USER_PROMPT_TEMPLATE = """\
You are evaluating ONE worker result that scored in the "interesting but sub-signal" band (6 <= crib_score <= 17). Your job is to decide whether this result is worth opening a structured follow-up lead so the next theorist cycle considers it as priority context.

THEORY UNDER REVIEW:

  hypothesis_id : {hypothesis_id}
  title         : {title}
  family        : {family}
  core_claim    : {core_claim}
  mechanism     : {mechanism}

WORKER RESULT (kernel-verified):

  status              : {status}
  crib_score          : {crib_score} / 24
  bean_passed         : {bean_passed}
  score               : {score}
  best_plaintext      : {best_plaintext}
  duration_seconds    : {duration_seconds}

WORKER NARRATIVE (advisory):
  {narrative_summary}

SUPPORTING EVIDENCE:
{supporting_evidence_block}

YOUR TASK:
Decide one of:
  1. PURSUE — this result raises a specific, actionable follow-up question. Open a lead.
  2. SKIP   — this result is a normal near-noise outcome with no actionable variant direction. Do not open a lead.

Criteria for PURSUE:
  - The score is above pure chance and the proposed mechanism has a specific variant axis worth narrowing on (e.g. "same cipher, narrower keyword space", "same mask rule, different width").
  - The worker's own narrative identifies a specific next step that would either confirm or kill the lead within one worker dispatch.
  - The crib positions that scored are consistent with a mechanism, not random hits.

Criteria for SKIP (be strict — rotation slots are scarce):
  - Score is explainable as noise given the search size.
  - The proposed variant axis is unbounded (would trip the bounded-search policy in the next cycle).
  - The mechanism overlaps a known-eliminated family.
  - The worker self-report flags the result as inconclusive with no clear follow-up.

Be precise in `suggested_variants`: at most 3 short (≤80 char) variant directions, each one a specific narrowing of a parameter axis. Examples of good variants: "try width 11 instead of 13", "restrict keyword to alphabetic-set anagrams", "swap Beaufort for Variant Beaufort". Examples of bad variants (do not emit these): "explore more", "keep searching", "think harder".

Output exactly ONE JSON object with fields: verdict ("pursue"|"skip"), confidence (0.0-1.0), rationale (string), suggested_variants (list of strings). No prose. No markdown fences.
"""


def _serialize_contract_for_pursuit(
    contract: WorkerContract,
    theory: TheoryRecord,
) -> dict[str, str]:
    """Extract the fields the pursuit evaluator needs."""
    pt = contract.best_plaintext or ""
    if len(pt) > 200:
        pt = pt[:197] + "..."
    narrative = contract.narrative_summary or ""
    if len(narrative) > 400:
        narrative = narrative[:397] + "..."
    supporting = contract.supporting_evidence or []
    if supporting:
        ev_block = "\n".join(f"  - {e[:200]}" for e in supporting[:5])
    else:
        ev_block = "  (none)"
    return {
        "hypothesis_id": contract.hypothesis_id or "(unset)",
        "title": (theory.title if theory else "") or "(no title)",
        "family": (theory.family if theory else "") or "(none)",
        "core_claim": (theory.core_claim if theory else "") or "(none)",
        "mechanism": (theory.mechanism if theory else "") or "(none)",
        "status": contract.status.value,
        "crib_score": str(contract.crib_score),
        "bean_passed": str(contract.bean_passed),
        "score": f"{contract.score:.2f}",
        "best_plaintext": pt or "(empty)",
        "duration_seconds": f"{contract.duration_seconds:.1f}",
        "narrative_summary": narrative or "(none)",
        "supporting_evidence_block": ev_block,
    }


def _build_pursuit_user_prompt(
    contract: WorkerContract,
    theory: TheoryRecord,
) -> str:
    return _PURSUIT_USER_PROMPT_TEMPLATE.format(
        **_serialize_contract_for_pursuit(contract, theory)
    )


def _normalize_pursuit_dict(parsed: dict) -> PursuitVerdict:
    verdict_raw = str(parsed.get("verdict", "")).strip().lower()
    if verdict_raw not in ("pursue", "skip"):
        aliases = {
            "follow": "pursue", "follow_up": "pursue", "yes": "pursue",
            "open": "pursue", "lead": "pursue",
            "no": "skip", "close": "skip", "ignore": "skip", "drop": "skip",
        }
        verdict_raw = aliases.get(verdict_raw, "skip")
    try:
        confidence = float(parsed.get("confidence", 0.5))
        confidence = max(0.0, min(1.0, confidence))
    except (TypeError, ValueError):
        confidence = 0.5
    rationale = str(parsed.get("rationale", "")).strip()
    variants_raw = parsed.get("suggested_variants", [])
    if isinstance(variants_raw, str):
        variants = [variants_raw]
    elif isinstance(variants_raw, list):
        variants = [str(v).strip() for v in variants_raw if v]
    else:
        variants = []
    # Enforce the at-most-3 cap the prompt asks for; trim individual entries.
    variants = [v[:200] for v in variants[:3]]
    return PursuitVerdict(
        verdict=verdict_raw,
        confidence=confidence,
        rationale=rationale[:500],
        suggested_variants=variants,
    )


async def run_pursuit_evaluator(
    contract: WorkerContract,
    theory: TheoryRecord,
    *,
    pursuit_spec: AgentSpec,
    project_root: Path,
    allowed_tools: list[str],
    permission_mode: str = "bypassPermissions",
    max_turns: int = 12,
) -> PursuitVerdict:
    """
    Make a sibling call to the pursuit evaluator (default role:
    results-analyst) for ONE sub-signal contract in the 6-17 crib_score
    band. Returns a PursuitVerdict regardless of success or failure.

    On any SDK/parse error, returns verdict="error" — which the
    controller treats as "skip" so flaky sibling calls cannot flood
    the pursuit queue with ghost leads.
    """
    import time

    system_prompt = pursuit_spec.pursuit_system_prompt()
    user_prompt = _build_pursuit_user_prompt(contract, theory)
    model, fallback_model = resolve_model_for_phase(pursuit_spec, "pursuit")

    options = ClaudeAgentOptions(
        allowed_tools=allowed_tools,
        disallowed_tools=["Task", "Agent"],
        permission_mode=permission_mode,
        system_prompt=system_prompt,
        cwd=str(project_root),
        max_turns=max_turns,
        setting_sources=["project"],
        model=model,
        fallback_model=fallback_model,
    )

    start = time.monotonic()
    result_chunks: list[str] = []
    content_chunks: list[str] = []
    turn_count = 0
    tool_count = 0

    try:
        async for message in safe_query(prompt=user_prompt, options=options):
            if hasattr(message, "result") and message.result:
                result_chunks.append(str(message.result))
            elif hasattr(message, "content"):
                turn_count += 1
                content = message.content
                if isinstance(content, list):
                    for block in content:
                        if hasattr(block, "text") and block.text:
                            content_chunks.append(block.text)
                        elif hasattr(block, "type") and block.type == "tool_use":
                            tool_count += 1
                else:
                    content_chunks.append(str(content))
    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.warning(
            "pursuit evaluator SDK error for %s: %s: %s",
            contract.hypothesis_id, type(exc).__name__, exc,
        )
        return PursuitVerdict(
            verdict="error",
            confidence=0.0,
            rationale=f"SDK error: {type(exc).__name__}: {exc}",
            error=f"sdk:{type(exc).__name__}",
            wall_time_sec=elapsed,
            turn_count=turn_count,
            tool_count=tool_count,
        )

    elapsed = time.monotonic() - start
    raw = "".join(result_chunks).strip() if result_chunks else "".join(content_chunks).strip()
    parsed = _extract_json_object(raw)
    if parsed is None:
        logger.warning(
            "pursuit evaluator parse failure for %s — raw length %d, "
            "first 200 chars: %r",
            contract.hypothesis_id, len(raw), raw[:200],
        )
        return PursuitVerdict(
            verdict="error",
            confidence=0.0,
            rationale="parse_failure: pursuit output was not valid JSON",
            raw_output=raw,
            error="parse_failure",
            wall_time_sec=elapsed,
            turn_count=turn_count,
            tool_count=tool_count,
        )

    verdict = _normalize_pursuit_dict(parsed)
    verdict.raw_output = raw
    verdict.wall_time_sec = elapsed
    verdict.turn_count = turn_count
    verdict.tool_count = tool_count
    return verdict


# ===========================================================================
# Day 5: Cycle synthesis sibling call
# ===========================================================================


@dataclass
class CycleSynthesis:
    """
    Structured end-of-cycle synthesis from results-analyst.

    Persisted to the ledger and rendered in the next cycle's landscape
    brief as enriched context for the theorist. Output of `run_results_synthesis`.
    """
    headline: str = ""
    family_movements: list[str] = field(default_factory=list)
    evidence_added: list[str] = field(default_factory=list)
    recommended_next_focus: str = ""
    dispatched_count: int = 0
    disproved_count: int = 0
    signal_count: int = 0
    # Priority 5: per-category breakdown of the search_space_risk taxonomy
    # across dispatched theories. Keyed by one of SEARCH_SPACE_RISK_VALUES.
    # Replaces the Day 6 single-number `budget_risky_count` which collapsed
    # all non-none risks into one bucket and produced uninterpretable
    # metrics when the lexicon misclassified (see
    # feedback_concerned_vs_search_space_risk_separation.md for the
    # empirical motivation). Zero buckets are suppressed in display.
    risk_breakdown: dict[str, int] = field(default_factory=dict)
    raw_output: str = ""
    error: Optional[str] = None
    wall_time_sec: float = 0.0
    turn_count: int = 0
    tool_count: int = 0

    def to_landscape_block(self) -> str:
        """Render as a compact text block for the next cycle's landscape."""
        lines = []
        if self.headline:
            lines.append(f"Last cycle: {self.headline}")
        if self.recommended_next_focus:
            lines.append(f"  Suggested focus: {self.recommended_next_focus}")
        risky = {k: v for k, v in self.risk_breakdown.items()
                 if k != "none" and v > 0}
        if risky:
            parts = " ".join(f"{k}={v}" for k, v in sorted(risky.items()))
            lines.append(f"  risk-flagged dispatches: {parts}")
        for m in self.family_movements[:3]:
            lines.append(f"  • {m}")
        return "\n".join(lines)


_SYNTHESIS_USER_PROMPT_TEMPLATE = """\
You are synthesizing the outcomes of ONE research cycle that just completed. Produce a structured handoff for the next cycle's theorist.

CYCLE METADATA:
  cycle_number        : {cycle_number}
  dispatched_count    : {dispatched_count}
  disproved_count     : {disproved_count}
  signal_count        : {signal_count}
  alert_count         : {alert_count}
  risk_breakdown      : {risk_breakdown_inline}

DISPATCHED THEORIES (with kernel-verified outcomes):

{outcomes_block}

RED-TEAM PRE-CHECK VERDICTS:
{redteam_block}

SEARCH-SPACE RISK DISPATCHES (red-team structured risk field by category):
{risk_breakdown_block}

STATISTICAL AUDIT VERDICTS (post-execution, only for crib_score >= 18):
{stat_audit_block}

ALERTS THAT FIRED:
{alert_block}

YOUR TASK:
Read the cycle outcomes and produce a structured synthesis the next cycle's theorist will use as context. You are NOT writing a publication summary or recommending memory promotion. You are producing a compact, structured handoff.

SPECIAL POLICY FOR THIS HARDENING WINDOW:
Do NOT recommend moving away from, deprioritizing, or abandoning the
`w_delimiter_segments` anomaly lane solely because recent bounded W-focused
theories returned negative results. That anomaly remains the primary live
structural lead unless it is explicitly closed by controller policy. If a
W-focused cycle is cleanly negative, bias toward narrower W-bounded follow-up
variants rather than diversification-away language. In particular:
- demote width-specific geometry variants unless the width is independently justified
- keep delimiter / marker semantics, X-Q-Z-style marker letters, and crib-bridge geometry live
- do not overgeneralize a negative width-geometry cycle into "avoid W work"

Output exactly ONE JSON object with the seven fields specified in your operational mode override (headline, family_movements, evidence_added, recommended_next_focus, dispatched_count, disproved_count, signal_count). No prose. No markdown fences.
"""


def _is_w_focus_theory(theory: TheoryRecord) -> bool:
    """Return True if the theory is explicitly in the W-delimiter lane."""
    if "w_delimiter_segments" in (theory.anomalies_exploited or []):
        return True
    text = " ".join(
        str(part)
        for part in (theory.title, theory.core_claim, theory.mechanism)
        if part
    ).lower()
    return "w-delimit" in text or "w delimiter" in text or "w-segment" in text


def _normalize_w_focus_recommendation(
    focus: str,
    theories: list[TheoryRecord],
    contracts: list[WorkerContract],
) -> str:
    """Prevent synthesis from auto-demoting the W-delimiter lane.

    Narrow guard only: if a cycle materially focused on W-delimiter theories and
    all of those returned non-signal outcomes, do not allow results-synthesis to
    recommend abandoning or moving away from that lane. Replace such guidance
    with a bounded follow-up directive instead.
    """
    w_theories = [t for t in theories if _is_w_focus_theory(t)]
    if not w_theories:
        return focus

    by_id = {c.hypothesis_id: c for c in contracts}
    w_contracts = [by_id[t.hypothesis_id] for t in w_theories if t.hypothesis_id in by_id]
    if not w_contracts:
        return focus

    # Only intervene on cleanly non-signal W cycles. Signal/promise handling
    # should remain whatever the synthesis agent reported.
    if any(c.crib_score >= 18 for c in w_contracts):
        return focus

    lowered = focus.lower()
    demotion_markers = (
        "move away from w",
        "move away from w-delimiter",
        "move away from w delimiter",
        "move away from w-delimiter structural interpretations",
        "avoid further w-segment geometry variants",
        "avoid further w segment geometry variants",
        "avoid w-segment geometry",
        "avoid w segment geometry",
        "deprioritize w",
        "abandon w",
        "diversify away",
        "bias toward families with no recent",
    )
    if any(marker in lowered for marker in demotion_markers):
        return (
            "Continue aggressively along the W-delimiter lane, but keep it "
            "narrow: avoid new width-specific geometry variants unless the "
            "width is independently justified; prefer delimiter-marker, rare "
            "PT marker (X/Q/Z), and crib-bridge geometry variants."
        )
    return focus


def _format_outcomes_for_synthesis(
    theories: list[TheoryRecord],
    contracts: list[WorkerContract],
) -> str:
    """Render the dispatched-theories block for the synthesis prompt."""
    if not contracts:
        return "  (no contracts this cycle)"
    by_id = {t.hypothesis_id: t for t in theories}
    lines = []
    for c in contracts:
        t = by_id.get(c.hypothesis_id)
        title = (t.title if t else "(no theory record)")[:80]
        family = t.family if t else "(unknown)"
        flag = " [overwritten]" if c.fields_overwritten else ""
        lines.append(
            f"  - {c.hypothesis_id[:8]} family={family} status={c.status.value} "
            f"crib={c.crib_score}/24 bean={c.bean_passed} score={c.score:.1f}{flag}"
        )
        lines.append(f"      title: {title}")
    return "\n".join(lines)


def _format_redteam_for_synthesis(
    redteam_verdicts: dict[str, "RedTeamVerdict"],
) -> str:
    if not redteam_verdicts:
        return "  (none)"
    lines = []
    for hid, v in redteam_verdicts.items():
        reason = (v.reasons[0] if v.reasons else "")[:100]
        lines.append(f"  - {hid[:8]} {v.verdict} (conf {v.confidence:.2f}) {reason}")
    return "\n".join(lines)


def _format_stat_audit_for_synthesis(
    stat_verdicts: dict[str, "StatAuditVerdict"],
) -> str:
    if not stat_verdicts:
        return "  (none — no contracts hit the SIGNAL threshold)"
    lines = []
    for hid, v in stat_verdicts.items():
        concern = (v.methodology_concerns[0] if v.methodology_concerns else "")[:100]
        lines.append(f"  - {hid[:8]} {v.verdict} (conf {v.confidence:.2f}) {concern}")
    return "\n".join(lines)


def _format_alerts_for_synthesis(alert_summaries: list[str]) -> str:
    if not alert_summaries:
        return "  (none)"
    return "\n".join(f"  - {a}" for a in alert_summaries[:10])


def _format_risk_breakdown_for_synthesis(
    risk_by_hid: dict[str, tuple[str, str]],
) -> tuple[str, str, dict[str, int]]:
    """Render the search-space-risk dispatch block for the synthesis prompt.

    Priority 5. risk_by_hid maps hypothesis_id -> (search_space_risk,
    first_reason). Only dispatched theories with a non-"none" risk value
    are passed in by the caller. Returns three values:

      (inline_summary, block_detail, breakdown_dict)

    - inline_summary: compact one-line "k=v k=v" style for prompt metadata
    - block_detail: multi-line list of per-theory risk entries
    - breakdown_dict: {risk_value: count} for persisting on CycleSynthesis

    Zero buckets are omitted from the inline summary and block detail.
    The breakdown_dict always contains every non-zero bucket.
    """
    breakdown: dict[str, int] = {}
    lines: list[str] = []
    for hid, pair in risk_by_hid.items():
        try:
            risk_value, rationale = pair
        except (TypeError, ValueError):
            continue
        if not isinstance(risk_value, str) or risk_value == "none":
            continue
        breakdown[risk_value] = breakdown.get(risk_value, 0) + 1
        trimmed = rationale[:120] if isinstance(rationale, str) else ""
        lines.append(f"  - {hid[:8]} [{risk_value}] {trimmed}")

    if not breakdown:
        return "none=0", "  (no risk-flagged dispatches)", {}

    inline = " ".join(f"{k}={v}" for k, v in sorted(breakdown.items()))
    block = "\n".join(lines) if lines else "  (none)"
    return inline, block, breakdown


async def run_results_synthesis(
    *,
    cycle_number: int,
    theories: list[TheoryRecord],
    contracts: list[WorkerContract],
    redteam_verdicts: dict[str, RedTeamVerdict],
    stat_audit_verdicts: dict[str, StatAuditVerdict],
    alert_summaries: list[str],
    synthesis_spec: AgentSpec,
    project_root: Path,
    allowed_tools: list[str],
    permission_mode: str = "bypassPermissions",
    max_turns: int = 15,
    risk_by_hid: Optional[dict[str, tuple[str, str]]] = None,
) -> CycleSynthesis:
    """
    Make a sibling call to results-analyst for end-of-cycle synthesis.

    Returns a CycleSynthesis regardless of success or failure. On any
    error returns a degraded synthesis with `error` populated; the
    controller still persists it (the count fields and dispatched_count
    are filled from the inputs) so the next cycle has at least
    quantitative context.

    risk_by_hid: hypothesis_id -> (search_space_risk, first_reason) for
    every CONCERNED dispatch. Priority-5 structured field from the
    red-team verdict, read directly off the RedTeamVerdict.
    Only dispatched theories (present in `contracts`) contribute to the
    synthesis breakdown; pre-dispatch REJECTs are already filtered out
    of contracts by _red_team_filter.
    """
    dispatched = len(contracts)
    disproved = sum(
        1 for c in contracts
        if c.status.value == "disproved"
    )
    signal = sum(1 for c in contracts if c.crib_score >= 18)
    risk_by_hid = risk_by_hid or {}
    dispatched_ids = {c.hypothesis_id for c in contracts}
    dispatched_risks = {
        hid: risk_by_hid[hid]
        for hid in risk_by_hid
        if hid in dispatched_ids
    }

    outcomes_block = _format_outcomes_for_synthesis(theories, contracts)
    redteam_block = _format_redteam_for_synthesis(redteam_verdicts)
    stat_audit_block = _format_stat_audit_for_synthesis(stat_audit_verdicts)
    alert_block = _format_alerts_for_synthesis(alert_summaries)
    (
        risk_breakdown_inline,
        risk_breakdown_block,
        risk_breakdown_counts,
    ) = _format_risk_breakdown_for_synthesis(dispatched_risks)

    user_prompt = _SYNTHESIS_USER_PROMPT_TEMPLATE.format(
        cycle_number=cycle_number,
        dispatched_count=dispatched,
        disproved_count=disproved,
        signal_count=signal,
        alert_count=len(alert_summaries),
        risk_breakdown_inline=risk_breakdown_inline,
        outcomes_block=outcomes_block,
        redteam_block=redteam_block,
        stat_audit_block=stat_audit_block,
        alert_block=alert_block,
        risk_breakdown_block=risk_breakdown_block,
    )

    system_prompt = synthesis_spec.synthesis_system_prompt()
    model, fallback_model = resolve_model_for_phase(synthesis_spec, "synthesis")

    options = ClaudeAgentOptions(
        allowed_tools=allowed_tools,
        disallowed_tools=["Task", "Agent"],
        permission_mode=permission_mode,
        system_prompt=system_prompt,
        cwd=str(project_root),
        max_turns=max_turns,
        setting_sources=["project"],
        model=model,
        fallback_model=fallback_model,
    )

    start = time.monotonic()
    result_chunks: list[str] = []
    content_chunks: list[str] = []
    turn_count = 0
    tool_count = 0

    try:
        async for message in safe_query(prompt=user_prompt, options=options):
            if hasattr(message, "result") and message.result:
                result_chunks.append(str(message.result))
            elif hasattr(message, "content"):
                turn_count += 1
                content = message.content
                if isinstance(content, list):
                    for block in content:
                        if hasattr(block, "text") and block.text:
                            content_chunks.append(block.text)
                        elif hasattr(block, "type") and block.type == "tool_use":
                            tool_count += 1
                else:
                    content_chunks.append(str(content))
    except Exception as exc:
        elapsed = time.monotonic() - start
        logger.warning(
            "results-synthesis SDK error for cycle %d: %s: %s",
            cycle_number, type(exc).__name__, exc,
        )
        return CycleSynthesis(
            headline=f"(synthesis unavailable: SDK error)",
            dispatched_count=dispatched,
            disproved_count=disproved,
            signal_count=signal,
            risk_breakdown=dict(risk_breakdown_counts),
            error=f"sdk:{type(exc).__name__}",
            wall_time_sec=elapsed,
            turn_count=turn_count,
            tool_count=tool_count,
        )

    elapsed = time.monotonic() - start

    raw = "".join(result_chunks).strip() if result_chunks else "".join(content_chunks).strip()
    parsed = _extract_json_object(raw)
    if parsed is None:
        logger.warning(
            "results-synthesis parse failure for cycle %d — raw length %d, "
            "first 200 chars: %r",
            cycle_number, len(raw), raw[:200],
        )
        return CycleSynthesis(
            headline=f"(synthesis unavailable: parse failure)",
            dispatched_count=dispatched,
            disproved_count=disproved,
            signal_count=signal,
            risk_breakdown=dict(risk_breakdown_counts),
            raw_output=raw,
            error="parse_failure",
            wall_time_sec=elapsed,
            turn_count=turn_count,
            tool_count=tool_count,
        )

    # Tolerant extraction. Counts come from the inputs (authoritative),
    # not from the synthesis agent's self-report — the agent may include
    # them anyway, but the inputs are ground truth.
    headline = str(parsed.get("headline", "")).strip()
    fm_raw = parsed.get("family_movements", [])
    fm = [str(x).strip() for x in fm_raw if x] if isinstance(fm_raw, list) else []
    ev_raw = parsed.get("evidence_added", [])
    ev = [str(x).strip() for x in ev_raw if x] if isinstance(ev_raw, list) else []
    focus = str(parsed.get("recommended_next_focus", "")).strip()
    focus = _normalize_w_focus_recommendation(focus, theories, contracts)

    return CycleSynthesis(
        headline=headline,
        family_movements=fm,
        evidence_added=ev,
        recommended_next_focus=focus,
        dispatched_count=dispatched,
        disproved_count=disproved,
        signal_count=signal,
        risk_breakdown=dict(risk_breakdown_counts),
        raw_output=raw,
        wall_time_sec=elapsed,
        turn_count=turn_count,
        tool_count=tool_count,
    )
