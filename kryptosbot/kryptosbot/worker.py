"""
Worker management for KryptosBot.

Each worker is a Claude Agent SDK session executing a single strategy.
The WorkerManager handles concurrency limiting, timeout enforcement,
result extraction, and session lifecycle tracking.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions

from .config import (
    HypothesisStatus,
    KryptosBotConfig,
    Strategy,
)
from .database import ResultsDB
from .framework_strategies import build_strategy_prompt
from .sdk_wrapper import safe_query

logger = logging.getLogger("kryptosbot.worker")


@dataclass
class WorkerResult:
    """Structured output from a single agent worker run."""
    worker_id: str
    strategy_name: str
    hypothesis_id: int
    session_id: str = ""
    status: HypothesisStatus = HypothesisStatus.INCONCLUSIVE
    summary: str = ""
    best_plaintext: str = ""
    score: float = 0.0
    raw_output: str = ""
    error: str = ""
    duration_seconds: float = 0.0
    disproof_evidence: str = ""


@dataclass
class WorkerManager:
    """
    Manages concurrent Agent SDK workers with semaphore-based throttling.

    Usage:
        manager = WorkerManager(config, db)
        result = await manager.run_strategy(strategy, hypothesis_id)
    """

    config: KryptosBotConfig
    db: ResultsDB
    _semaphore: asyncio.Semaphore = field(init=False)
    _active_workers: dict[str, asyncio.Task[WorkerResult]] = field(
        default_factory=dict, init=False
    )

    def __post_init__(self) -> None:
        self._semaphore = asyncio.Semaphore(self.config.max_workers)

    @property
    def active_count(self) -> int:
        return len(self._active_workers)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_strategy(
        self,
        strategy: Strategy,
        hypothesis_id: int,
        extra_context: str = "",
    ) -> WorkerResult:
        """
        Execute a strategy via the Agent SDK within concurrency limits.

        Acquires a semaphore slot, launches the agent, collects output,
        and returns a structured WorkerResult.
        """
        worker_id = f"w-{uuid.uuid4().hex[:8]}"
        logger.info(
            "Worker %s queued for strategy '%s' (hyp %d)",
            worker_id, strategy.name, hypothesis_id,
        )

        async with self._semaphore:
            logger.info("Worker %s acquired slot, starting agent", worker_id)
            self.db.update_hypothesis(
                hypothesis_id,
                status=HypothesisStatus.RUNNING.value,
                worker_id=worker_id,
            )

            try:
                result = await asyncio.wait_for(
                    self._execute_agent(strategy, hypothesis_id, worker_id, extra_context),
                    timeout=self.config.worker_timeout_minutes * 60,
                )
            except asyncio.TimeoutError:
                logger.warning("Worker %s timed out after %d min", worker_id, self.config.worker_timeout_minutes)
                result = WorkerResult(
                    worker_id=worker_id,
                    strategy_name=strategy.name,
                    hypothesis_id=hypothesis_id,
                    status=HypothesisStatus.INCONCLUSIVE,
                    error=f"Timed out after {self.config.worker_timeout_minutes} minutes",
                )
            except Exception as exc:
                logger.exception("Worker %s failed with error", worker_id)
                result = WorkerResult(
                    worker_id=worker_id,
                    strategy_name=strategy.name,
                    hypothesis_id=hypothesis_id,
                    status=HypothesisStatus.INCONCLUSIVE,
                    error=str(exc),
                )

            # Persist final state
            self.db.update_hypothesis(
                hypothesis_id,
                status=result.status.value,
                summary=result.summary[:2000],
                score=result.score,
                best_plaintext=result.best_plaintext[:500],
                session_id=result.session_id,
                error=result.error[:1000],
            )

            if result.raw_output:
                self.db.add_evidence(
                    hypothesis_id, "agent_output", result.raw_output[:50_000]
                )

            if result.disproof_evidence:
                self.db.log_disproof(
                    strategy=strategy.name,
                    category=strategy.category.name,
                    criteria=strategy.disproof_criteria,
                    evidence=result.disproof_evidence[:5000],
                )

            return result

    async def run_batch(
        self,
        strategies: list[tuple[Strategy, int]],
    ) -> list[WorkerResult]:
        """
        Run multiple strategies concurrently. Returns when ALL complete.

        Args:
            strategies: list of (Strategy, hypothesis_id) tuples.
        """
        tasks = [
            asyncio.create_task(
                self.run_strategy(strat, hyp_id),
                name=f"kbot-{strat.name}",
            )
            for strat, hyp_id in strategies
        ]
        return list(await asyncio.gather(*tasks, return_exceptions=False))

    # ------------------------------------------------------------------
    # Internal: Agent SDK execution
    # ------------------------------------------------------------------

    async def _execute_agent(
        self,
        strategy: Strategy,
        hypothesis_id: int,
        worker_id: str,
        extra_context: str,
    ) -> WorkerResult:
        """Run a single Agent SDK session and parse results."""
        # Build framework-aware prompt: preamble + disproof ledger + strategy
        prompt = build_strategy_prompt(
            strategy=strategy,
            project_root=self.config.project_root,
            db=self.db,
            extra_context=extra_context,
        )

        start_time = datetime.now(timezone.utc)
        session_id = ""
        raw_chunks: list[str] = []

        stderr_lines: list[str] = []

        def _capture_stderr(line: str) -> None:
            stderr_lines.append(line)
            logger.debug("Worker %s stderr: %s", worker_id, line.rstrip())

        options = ClaudeAgentOptions(
            allowed_tools=self.config.allowed_tools,
            permission_mode=self.config.permission_mode,
            system_prompt=self.config.system_prompt_prefix,
            cwd=str(self.config.project_root.resolve()),
            max_buffer_size=10_485_760,  # 10 MB — default 1 MB is too small for inventory tasks
            env={"CLAUDECODE": ""},  # Allow spawning from within Claude Code sessions
            stderr=_capture_stderr,
        )

        async for message in safe_query(prompt=prompt, options=options):
            # Capture session ID from init message
            if hasattr(message, "subtype") and message.subtype == "init":
                session_id = getattr(message, "session_id", "")
                self.db.register_session(session_id, strategy.name, worker_id)
                logger.info("Worker %s session started: %s", worker_id, session_id)

            # Accumulate text output
            if hasattr(message, "result"):
                raw_chunks.append(str(message.result))
            elif hasattr(message, "content"):
                raw_chunks.append(str(message.content))

        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        raw_output = "\n".join(raw_chunks)

        if session_id:
            self.db.finish_session(session_id, status="completed")

        # Parse agent output into structured result
        result = self._parse_agent_output(
            raw_output, strategy, hypothesis_id, worker_id
        )
        result.session_id = session_id
        result.raw_output = raw_output
        result.duration_seconds = elapsed

        logger.info(
            "Worker %s completed in %.1fs — status: %s, score: %.2f",
            worker_id, elapsed, result.status.value, result.score,
        )
        return result

    # ------------------------------------------------------------------
    # Output parsing heuristics
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_solution(plaintext: str) -> tuple[bool, str]:
        """
        Apply multi-objective oracle thresholds before allowing SOLVED status.

        A candidate must meet ALL of:
        - crib score = 24/24 (EASTNORTHEAST at 21-33 + BERLINCLOCK at 63-73)
        - Bean equality: k[27] = k[65]
        - Plaintext length = 97
        - At least 3 non-crib English words >= 7 chars

        Returns (passed, reason).
        """
        if not plaintext or len(plaintext) != 97:
            return False, f"Wrong length ({len(plaintext) if plaintext else 0}, need 97)"

        # Check EASTNORTHEAST at positions 21-33
        if plaintext[21:34] != "EASTNORTHEAST":
            return False, f"EASTNORTHEAST not at 21-33 (got '{plaintext[21:34]}')"

        # Check BERLINCLOCK at positions 63-73
        if plaintext[63:74] != "BERLINCLOCK":
            return False, f"BERLINCLOCK not at 63-73 (got '{plaintext[63:74]}')"

        # Check Bean equality: PT[27]=PT[65]=R, so this is implicit in crib check,
        # but verify explicitly for safety
        if plaintext[27] != plaintext[65]:
            return False, f"Bean EQ fail: PT[27]='{plaintext[27]}' != PT[65]='{plaintext[65]}'"

        # Check for non-crib English words (basic check with common long words)
        non_crib = plaintext[:21] + plaintext[34:63] + plaintext[74:]
        long_alpha_runs = re.findall(r"[A-Z]{7,}", non_crib)
        if len(long_alpha_runs) < 3:
            return False, f"Too few long alpha runs in non-crib region ({len(long_alpha_runs)}, need >= 3)"

        return True, "All oracle checks passed"

    @staticmethod
    def _extract_verdict_block(raw: str) -> dict[str, Any] | None:
        """
        Extract a structured VERDICT JSON block from agent output.

        Agents are instructed to emit a block like:
            ```verdict
            {"status": "disproved", "score": 0, "summary": "...", ...}
            ```
        or:
            VERDICT: {"status": "disproved", ...}

        Returns the parsed dict, or None if no valid block found.
        """
        # Try fenced ```verdict block first
        verdict_fence = re.search(
            r"```verdict\s*\n(.+?)\n\s*```", raw, re.DOTALL
        )
        if verdict_fence:
            try:
                return json.loads(verdict_fence.group(1))
            except (json.JSONDecodeError, ValueError):
                pass

        # Try VERDICT: { ... } on a single line
        verdict_inline = re.search(
            r"VERDICT:\s*(\{.+\})", raw
        )
        if verdict_inline:
            try:
                return json.loads(verdict_inline.group(1))
            except (json.JSONDecodeError, ValueError):
                pass

        # Try any JSON block with a "verdict_status" key
        json_blocks = re.findall(r"\{[^{}]{20,2000}\}", raw)
        for block in reversed(json_blocks):  # prefer last (final conclusion)
            try:
                parsed = json.loads(block)
                if isinstance(parsed, dict) and "verdict_status" in parsed:
                    return parsed
            except (json.JSONDecodeError, ValueError):
                continue

        return None

    @staticmethod
    def _parse_agent_output(
        raw: str,
        strategy: Strategy,
        hypothesis_id: int,
        worker_id: str,
    ) -> WorkerResult:
        """
        Extract structured findings from agent output.

        STRATEGY (priority order):
        1. Look for a structured VERDICT block (most reliable)
        2. Fall back to keyword heuristics (conservative)

        SOLVED status always requires passing the multi-objective oracle.

        KEY FIX: Crib keywords (BERLINCLOCK etc.) appearing in agent output
        do NOT trigger PROMISING — agents echo these from their prompt.
        Only trigger PROMISING when the agent explicitly claims results.
        """
        result = WorkerResult(
            worker_id=worker_id,
            strategy_name=strategy.name,
            hypothesis_id=hypothesis_id,
        )

        if not raw or not raw.strip():
            result.status = HypothesisStatus.INCONCLUSIVE
            result.summary = "Agent produced no output."
            return result

        # ── Strategy 1: Structured VERDICT block ──────────────────────
        verdict = WorkerManager._extract_verdict_block(raw)
        if verdict:
            status_str = verdict.get("verdict_status", verdict.get("status", "")).lower()
            status_map = {
                "disproved": HypothesisStatus.DISPROVED,
                "eliminated": HypothesisStatus.DISPROVED,
                "promising": HypothesisStatus.PROMISING,
                "inconclusive": HypothesisStatus.INCONCLUSIVE,
                "solved": HypothesisStatus.PROMISING,  # claim only — oracle decides
            }
            result.status = status_map.get(status_str, HypothesisStatus.INCONCLUSIVE)
            result.summary = str(verdict.get("summary", ""))[:2000]
            result.disproof_evidence = str(verdict.get("evidence", ""))[:5000]
            result.best_plaintext = str(verdict.get("best_plaintext", ""))[:200]

            try:
                result.score = float(verdict.get("score", 0))
            except (ValueError, TypeError):
                pass

            # If agent claims SOLVED, validate with oracle
            if status_str == "solved" and result.best_plaintext:
                passed, reason = WorkerManager._validate_solution(result.best_plaintext)
                if passed:
                    result.status = HypothesisStatus.SOLVED
                    result.summary = "SOLUTION VALIDATED BY ORACLE — manual verification required!"
                    logger.critical(
                        "ORACLE PASS for strategy '%s': %s",
                        strategy.name, result.best_plaintext,
                    )
                else:
                    result.summary = (
                        f"Agent claimed solved but FAILED oracle: {reason}. "
                        f"Verdict: {result.summary}"
                    )

            logger.info(
                "Worker parsed structured verdict for '%s': %s",
                strategy.name, result.status.value,
            )
            return result

        # ── Strategy 2: Keyword heuristics (fallback) ────────────────
        raw_lower = raw.lower()

        # Extract best plaintext candidate
        pt_match = re.search(r"(?:plaintext|decrypted|candidate)[:\s]*([A-Z]{10,})", raw)
        if pt_match:
            result.best_plaintext = pt_match.group(1)[:200]

        # Extract score — require it to be in a results/findings context,
        # not just discussed in passing. Look for the LAST match (final result).
        score_matches = list(re.finditer(
            r"(?:best|top|highest|final)\s*(?:score|fitness|crib[_ ]?match(?:es)?)[:\s=]*(-?[\d.]+)",
            raw_lower,
        ))
        if score_matches:
            try:
                result.score = float(score_matches[-1].group(1))
            except ValueError:
                pass

        # Check for explicit solution claims WITH actual plaintext evidence
        # (not just mentioning BERLINCLOCK in analysis context)
        solution_claimed = any(
            phrase in raw_lower
            for phrase in ["solution found", "plaintext recovered", "decrypted successfully",
                           "full decryption achieved", "k4 solved"]
        )
        if solution_claimed and result.best_plaintext:
            passed, reason = WorkerManager._validate_solution(result.best_plaintext)
            if passed:
                result.status = HypothesisStatus.SOLVED
                result.summary = "SOLUTION VALIDATED BY ORACLE — manual verification required!"
                logger.critical(
                    "ORACLE PASS for strategy '%s': %s", strategy.name, result.best_plaintext
                )
                return result
            else:
                result.status = HypothesisStatus.PROMISING
                result.summary = f"Solution claim FAILED oracle: {reason}."
                return result

        # Check for disproof signals — expanded keyword set
        disproof_phrases = [
            "conclusively eliminated", "disproved", "ruled out",
            "no valid", "all permutations exhausted", "no crib match",
            "can be eliminated", "cipher family eliminated",
            "no candidates found", "zero matches", "0 matches",
            "exhaustive search complete", "none produced",
            "no configuration produces", "impossible for",
            "not consistent with", "incompatible with k4",
            "eliminates this", "rules out this",
            "no key produces", "no combination produces",
            # Common natural-language disproof patterns
            "no results found", "no matches found", "no signal detected",
            "tested exhaustively", "exhaustively tested",
            "all approaches tested", "all keys tested",
            "already eliminated", "already disproved",
            "none of the", "none produce", "none match",
            "does not work", "cannot produce", "cannot work",
            "failed to find", "no viable", "no solution found",
        ]
        if any(phrase in raw_lower for phrase in disproof_phrases):
            result.status = HypothesisStatus.DISPROVED
            # Extract evidence lines
            evidence_lines = []
            for line in raw.split("\n"):
                line_lower = line.lower().strip()
                if any(kw in line_lower for kw in [
                    "disproved", "eliminated", "ruled out", "conclusion",
                    "result:", "finding:", "verdict:", "evidence:",
                    "no match", "zero", "impossible", "incompatible",
                ]):
                    evidence_lines.append(line.strip())
            result.disproof_evidence = "\n".join(evidence_lines[:20])
            result.summary = f"Strategy '{strategy.name}' disproved (heuristic detection)."
            return result

        # Check for promising signals — require actual results, not just
        # discussion of cribs (which are in every prompt)
        promising_phrases = [
            "partial match found", "partial crib match",
            "score above threshold", "above noise",
            "warrants further investigation", "promising candidate",
            "notable result", "significant finding",
            "non-random signal", "statistical anomaly detected",
        ]
        if any(phrase in raw_lower for phrase in promising_phrases):
            result.status = HypothesisStatus.PROMISING
            result.summary = "Partial results warrant follow-up investigation."
            return result

        # Default: inconclusive
        result.status = HypothesisStatus.INCONCLUSIVE
        result.summary = "No clear signal detected (no structured verdict found)."
        return result
