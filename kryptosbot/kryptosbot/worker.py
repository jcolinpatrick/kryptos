"""
Worker management for KryptosBot.

Each worker is a Claude Agent SDK session executing a single strategy.
The WorkerManager handles concurrency limiting, timeout enforcement,
result extraction, and session lifecycle tracking.
"""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from claude_agent_sdk import ClaudeAgentOptions, query

from .config import (
    HypothesisStatus,
    KryptosBotConfig,
    Strategy,
)
from .database import ResultsDB
from .framework_strategies import build_strategy_prompt

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

        options = ClaudeAgentOptions(
            allowed_tools=self.config.allowed_tools,
            permission_mode=self.config.permission_mode,
            system_prompt=self.config.system_prompt_prefix,
            cwd=str(self.config.project_root.resolve()),
        )

        async for message in query(prompt=prompt, options=options):
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
    def _parse_agent_output(
        raw: str,
        strategy: Strategy,
        hypothesis_id: int,
        worker_id: str,
    ) -> WorkerResult:
        """
        Extract structured findings from the agent's free-text output.

        Uses keyword heuristics to classify the outcome. This is deliberately
        conservative: we'd rather mark something INCONCLUSIVE than wrongly
        claim DISPROVED.
        """
        raw_lower = raw.lower()
        result = WorkerResult(
            worker_id=worker_id,
            strategy_name=strategy.name,
            hypothesis_id=hypothesis_id,
        )

        # Check for the holy grail
        if "berlinclock" in raw_lower or "berlin clock" in raw_lower:
            # Look for actual plaintext near the crib mention
            if any(
                phrase in raw_lower
                for phrase in ["solution found", "plaintext recovered", "decrypted successfully"]
            ):
                result.status = HypothesisStatus.SOLVED
                result.summary = "POTENTIAL SOLUTION — manual verification required!"
            else:
                result.status = HypothesisStatus.PROMISING
                result.summary = "Crib reference detected in output — needs review."

        # Check for disproof signals
        elif any(
            phrase in raw_lower
            for phrase in [
                "conclusively eliminated",
                "disproved",
                "ruled out",
                "no valid",
                "all permutations exhausted",
                "no crib match",
                "can be eliminated",
            ]
        ):
            result.status = HypothesisStatus.DISPROVED
            # Try to extract the disproof evidence
            for line in raw.split("\n"):
                if any(kw in line.lower() for kw in ["disproved", "eliminated", "ruled out", "conclusion"]):
                    result.disproof_evidence += line.strip() + "\n"
            result.summary = f"Strategy '{strategy.name}' disproved."

        # Check for promising but not conclusive
        elif any(
            phrase in raw_lower
            for phrase in ["promising", "partial match", "high score", "notable", "warrants further"]
        ):
            result.status = HypothesisStatus.PROMISING
            result.summary = "Partial results warrant follow-up investigation."

        else:
            result.status = HypothesisStatus.INCONCLUSIVE
            result.summary = "No clear signal detected."

        # Try to extract a numeric score
        score_match = re.search(r"(?:best|top|highest)\s*(?:score|fitness)[:\s]*(-?[\d.]+)", raw_lower)
        if score_match:
            try:
                result.score = float(score_match.group(1))
            except ValueError:
                pass

        # Try to extract best plaintext candidate
        pt_match = re.search(r"(?:plaintext|decrypted|candidate)[:\s]*([A-Z]{10,})", raw)
        if pt_match:
            result.best_plaintext = pt_match.group(1)[:200]

        return result
