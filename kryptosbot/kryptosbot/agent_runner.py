"""
Shared agent runner for KryptosBot campaign scripts.

Consolidates the duplicated agent session management, message handling,
verdict extraction, and result saving from run_lean.py, run_blitz_campaign.py,
run_bespoke_reasoning.py, and run_split_campaign.py into one function.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("kryptosbot.agent_runner")

# Crib detection for early termination.
# Bare substring matching on "EASTNORTHEAST" / "BERLINCLOCK" causes false
# positives because every agent prompt contains these strings and agents
# echo them while discussing the problem.  Instead we look for phrases
# that indicate an actual decryption result, not mere discussion.
_CRIB_MARKERS = (
    "CRIB HIT",
    "CRIB FOUND",
    "CRIB MATCH",
    "crib_hit",
    "crib_found",
    "crib hit!",
    "BREAKTHROUGH",
    "SOLUTION FOUND",
    "PLAINTEXT RECOVERED",
)
# A 97-char uppercase string containing a crib is the strongest signal.
_CRIB_STRINGS = ("EASTNORTHEAST", "BERLINCLOCK")
_MIN_CRIB_CONTEXT = 40  # crib must be inside a run of ≥40 uppercase letters


def _is_real_crib_hit(text: str) -> bool:
    """Check whether text contains a crib inside a plausible plaintext candidate.

    Returns True only if EASTNORTHEAST or BERLINCLOCK appears inside a
    contiguous run of ≥40 uppercase letters (i.e. a candidate decryption),
    not just mentioned in prose.

    Excludes pinned-crib SA results: if EASTNORTHEAST is at exactly position
    21 and BERLINCLOCK at exactly position 63 within the candidate string,
    and the surrounding text has poor quadgram quality, that's a solver
    artifact, not a real decryption.
    """
    import re
    for m in re.finditer(r"[A-Z]{40,}", text):
        chunk = m.group()
        for crib in _CRIB_STRINGS:
            if crib not in chunk:
                continue
            pos = chunk.index(crib)
            # Skip if crib is at the exact pinned position in a 97-char string
            # (SA solvers force-place cribs at pos 21 and 63)
            if len(chunk) == 97:
                if crib == "EASTNORTHEAST" and pos == 21:
                    continue
                if crib == "BERLINCLOCK" and pos == 63:
                    continue
            # Crib found at an unexpected position — likely real
            return True
    return False


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class AgentResult:
    """Structured result from a single agent session."""

    name: str
    raw_output: str
    elapsed_seconds: float
    crib_found: bool
    best_score: float | None
    verdict: dict | None
    raw_output_file: Path
    input_tokens: int = 0
    output_tokens: int = 0


class TokenTracker:
    """Track token usage across multiple agent sessions.

    Provides cumulative counts and approximate USD cost estimation.
    Pass a ``budget_usd`` to enable over-budget detection.
    """

    # Approximate pricing (Claude Sonnet 4 as of 2026-03)
    INPUT_COST_PER_M = 3.0  # $/M input tokens
    OUTPUT_COST_PER_M = 15.0  # $/M output tokens

    def __init__(self, budget_usd: float | None = None):
        self.total_input = 0
        self.total_output = 0
        self.budget_usd = budget_usd

    def add(self, input_tokens: int, output_tokens: int) -> None:
        self.total_input += input_tokens
        self.total_output += output_tokens

    def estimate_cost_usd(self) -> float:
        return (
            self.total_input * self.INPUT_COST_PER_M / 1_000_000
            + self.total_output * self.OUTPUT_COST_PER_M / 1_000_000
        )

    def is_over_budget(self) -> bool:
        if self.budget_usd is None:
            return False
        return self.estimate_cost_usd() > self.budget_usd

    def summary(self) -> str:
        cost = self.estimate_cost_usd()
        budget_str = f" / ${self.budget_usd:.2f}" if self.budget_usd else ""
        return (
            f"Tokens: {self.total_input:,} in + {self.total_output:,} out "
            f"= ${cost:.2f}{budget_str}"
        )


# ---------------------------------------------------------------------------
# Verdict / score extraction
# ---------------------------------------------------------------------------


def _extract_verdict(raw_output: str) -> dict | None:
    """Extract verdict JSON from agent output.

    Tries two regex patterns:
    1. ```json or ```verdict block containing "verdict_status" key
    2. Simple ```verdict block with any JSON content
    """
    # Pattern 1: block with verdict_status key (blitz style)
    match = re.search(
        r"```(?:json|verdict)?\s*\n(\{[^}]*\"verdict_status\"[^}]+\})\s*\n```",
        raw_output,
        re.DOTALL,
    )
    if match:
        try:
            return json.loads(match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass

    # Pattern 2: simple verdict fence (bespoke style)
    match = re.search(r"```verdict\s*\n(.+?)\n\s*```", raw_output, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass

    return None


def _extract_best_score(raw_output: str) -> float | None:
    """Extract best numeric score mentioned in agent output."""
    matches = re.findall(r"[Ss]core[:\s]+(-?\d+\.?\d*)", raw_output)
    if matches:
        return max(float(s) for s in matches)
    return None


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def run_agent_session(
    name: str,
    prompt: str,
    project_root: Path,
    results_dir: Path,
    *,
    max_turns: int = 25,
    crib_event: asyncio.Event | None = None,
    allowed_tools: list[str] | None = None,
    token_tracker: TokenTracker | None = None,
    env: dict[str, str] | None = None,
    max_buffer_size: int | None = None,
) -> AgentResult:
    """Run a single Claude agent session and return structured results.

    This is the unified message loop used by all KryptosBot campaign scripts.

    Args:
        name: Agent identifier (used for logging and output filenames).
        prompt: The full prompt to send to the agent.
        project_root: Working directory for the agent session.
        results_dir: Parent directory for agent output.  Raw output goes to
            ``results_dir/name/name_raw.txt``.
        max_turns: Maximum agentic turns before session ends.
        crib_event: If provided, set when crib strings are detected in output.
            Other tasks can wait on this for early termination.
        allowed_tools: SDK tools the agent may use.
            Defaults to Read, Write, Edit, Bash, Glob, Grep.
        token_tracker: Shared tracker for cumulative token usage.
        env: Extra environment variables for the agent process.
        max_buffer_size: SDK max_buffer_size setting (bytes).

    Returns:
        AgentResult with raw output, verdict, scores, and token counts.
    """
    from claude_agent_sdk import ClaudeAgentOptions
    from kryptosbot.sdk_wrapper import safe_query

    if allowed_tools is None:
        allowed_tools = ["Read", "Write", "Edit", "Bash", "Glob", "Grep"]
    if env is None:
        env = {"CLAUDECODE": ""}

    agent_dir = results_dir / name
    agent_dir.mkdir(parents=True, exist_ok=True)

    logger.info("LAUNCHING agent: %s (max_turns=%d)", name, max_turns)

    opts_kwargs: dict[str, Any] = {
        "allowed_tools": allowed_tools,
        "permission_mode": "bypassPermissions",
        "cwd": str(project_root),
        "max_turns": max_turns,
        "env": env,
    }
    if max_buffer_size is not None:
        opts_kwargs["max_buffer_size"] = max_buffer_size

    options = ClaudeAgentOptions(**opts_kwargs)

    output_chunks: list[str] = []
    crib_found = False
    input_tokens = 0
    output_tokens = 0
    start = time.monotonic()

    # Stream raw output to disk so `tail -f` works during the session
    raw_path = agent_dir / f"{name}_raw.txt"
    raw_fh = open(raw_path, "w", buffering=1)  # line-buffered

    def _append(chunk: str) -> None:
        output_chunks.append(chunk)
        raw_fh.write(chunk + "\n")

    try:
        async for message in safe_query(prompt=prompt, options=options):
            # --- Token tracking ---
            usage = getattr(message, "usage", None)
            if usage:
                input_tokens += getattr(usage, "input_tokens", 0)
                output_tokens += getattr(usage, "output_tokens", 0)

            # --- ResultMessage (final summary) ---
            if hasattr(message, "result") and message.result:
                chunk = str(message.result)
                _append(chunk)
                if (any(marker in chunk for marker in _CRIB_MARKERS)
                        or _is_real_crib_hit(chunk)):
                    crib_found = True
                    logger.warning("*** %s: POSSIBLE CRIB HIT ***", name)
                    if crib_event is not None:
                        crib_event.set()
                preview = chunk[:120].replace("\n", " ").strip()
                if preview:
                    logger.info("[%s] %s", name, preview[:80])

            # --- AssistantMessage (streaming content blocks) ---
            if hasattr(message, "content") and isinstance(message.content, list):
                for block in message.content:
                    if hasattr(block, "text") and block.text:
                        chunk = block.text
                        _append(chunk)
                        if (any(marker in chunk for marker in _CRIB_MARKERS)
                                or _is_real_crib_hit(chunk)):
                            crib_found = True
                            logger.warning(
                                "*** %s: POSSIBLE CRIB HIT ***", name
                            )
                            if crib_event is not None:
                                crib_event.set()
                    elif hasattr(block, "name"):
                        tool_name = getattr(block, "name", "?")
                        tool_input = getattr(block, "input", {})
                        summary = str(tool_input)[:120]
                        line = f"  [tool: {tool_name}] {summary}"
                        _append(line)

    except asyncio.CancelledError:
        logger.info("Agent %s cancelled (early termination)", name)
        _append("\n\n[SESSION CANCELLED -- early termination]")
    except Exception as e:
        logger.error("Agent %s FAILED: %s", name, e)
        _append(f"\n\nERROR: {e}")
    finally:
        raw_fh.close()

    elapsed = time.monotonic() - start
    raw_output = "\n".join(output_chunks)

    # Extract verdict and score
    verdict = _extract_verdict(raw_output)
    best_score = _extract_best_score(raw_output)

    # Update token tracker
    if token_tracker is not None:
        token_tracker.add(input_tokens, output_tokens)

    result = AgentResult(
        name=name,
        raw_output=raw_output,
        elapsed_seconds=round(elapsed, 1),
        crib_found=crib_found,
        best_score=best_score,
        verdict=verdict,
        raw_output_file=raw_path,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
    )

    # Save structured result JSON
    result_json = {
        "agent": name,
        "elapsed_seconds": result.elapsed_seconds,
        "output_length": len(raw_output),
        "crib_found": crib_found,
        "best_score": best_score,
        "verdict": verdict,
        "raw_output_file": str(raw_path),
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
    }
    result_path = agent_dir / f"{name}_result.json"
    result_path.write_text(json.dumps(result_json, indent=2))

    logger.info(
        "COMPLETED: %s (%.0fs, %d chars, crib=%s, score=%s, tokens=%d/%d)",
        name,
        elapsed,
        len(raw_output),
        crib_found,
        best_score,
        input_tokens,
        output_tokens,
    )

    return result
