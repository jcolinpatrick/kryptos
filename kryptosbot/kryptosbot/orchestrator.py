"""
KryptosBot Orchestrator.

Manages the end-to-end lifecycle of a cryptanalytic campaign:
  1. Load/filter strategies from the built-in library
  2. Skip already-disproved strategies (unless overridden)
  3. Create hypothesis records in the database
  4. Dispatch workers in priority-ordered waves
  5. Analyze results and schedule follow-up investigations
  6. Generate summary reports

Designed for multi-day unattended operation with graceful shutdown.
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import (
    BUILTIN_STRATEGIES,
    HypothesisStatus,
    KryptosBotConfig,
    Strategy,
    StrategyCategory,
)
from .database import ResultsDB
from .framework_strategies import FRAMEWORK_STRATEGIES, get_framework_strategies
from .sdk_wrapper import preflight_check
from .worker import WorkerManager, WorkerResult

logger = logging.getLogger("kryptosbot.orchestrator")


class Orchestrator:
    """
    Coordinates the entire KryptosBot cryptanalytic campaign.

    Instantiate with a config, call `run()` to start. Handles SIGINT/SIGTERM
    for graceful shutdown during multi-day runs.
    """

    def __init__(self, config: KryptosBotConfig | None = None) -> None:
        self.config = config or KryptosBotConfig()
        self.db = ResultsDB(self.config.results_db_path)
        self.worker_mgr = WorkerManager(self.config, self.db)
        self._shutdown_event = asyncio.Event()
        self._custom_strategies: list[Strategy] = []

    # ------------------------------------------------------------------
    # Bootstrap: import existing knowledge from the framework
    # ------------------------------------------------------------------

    async def bootstrap_from_framework(self) -> dict[str, int]:
        """
        Scan the existing framework for prior results, disproof records,
        and known findings. Seeds the database so agents don't repeat work.

        This runs a single lightweight agent whose only job is to read
        CLAUDE.md, MEMORY.md, and any result/output files, then produce
        a structured report of what's already known.

        Returns counts of imported items.
        """
        logger.info("Bootstrapping from existing framework at %s", self.config.project_root)

        bootstrap_strategy = Strategy(
            name="_bootstrap_import",
            category=StrategyCategory.STATISTICAL,
            description="Internal: import existing framework knowledge into KryptosBot DB.",
            prompt_template=(
                "You are bootstrapping KryptosBot. Your ONLY task is to extract\n"
                "structured knowledge from the existing framework.\n\n"
                "1. Read CLAUDE.md and MEMORY.md completely.\n"
                "2. Search for result files, output directories, and log files.\n"
                "3. Identify ALL cipher families or approaches that have been:\n"
                "   - Conclusively disproved (with evidence)\n"
                "   - Partially explored (with current status)\n"
                "   - Identified as promising (with supporting data)\n"
                "4. Identify all scoring functions and their locations.\n"
                "5. Identify any configuration or parameters that are established conventions.\n\n"
                "Output a JSON document with this EXACT schema:\n"
                '{{\n'
                '  "disproved": [\n'
                '    {{"cipher": "...", "method": "...", "evidence": "...", "script": "..."}}\n'
                '  ],\n'
                '  "promising": [\n'
                '    {{"approach": "...", "score": 0.0, "plaintext_fragment": "...", "script": "..."}}\n'
                '  ],\n'
                '  "in_progress": [\n'
                '    {{"approach": "...", "status": "...", "last_parameters": "..."}}\n'
                '  ],\n'
                '  "conventions": {{\n'
                '    "scoring_function": "...",\n'
                '    "output_format": "...",\n'
                '    "result_directory": "..."\n'
                '  }},\n'
                '  "script_count": 0,\n'
                '  "total_approaches_tested": 0\n'
                '}}\n\n'
                "Write this to bootstrap_report.json in the project root.\n"
                "This is READ-ONLY. Do not modify any existing files."
            ),
            priority=0,
            estimated_minutes=15,
            tags=("bootstrap", "internal"),
        )


        hyp_id = self.db.create_hypothesis(
            strategy="_bootstrap_import",
            category="STATISTICAL",
            priority=0,
        )

        result = await self.worker_mgr.run_strategy(bootstrap_strategy, hyp_id)

        # Try to parse the bootstrap report from disk
        report_path = self.config.project_root / "bootstrap_report.json"
        counts = {"disproved": 0, "promising": 0, "in_progress": 0}

        if report_path.exists():
            try:
                import json
                report = json.loads(report_path.read_text())

                for entry in report.get("disproved", []):
                    self.db.log_disproof(
                        strategy=entry.get("method", "unknown"),
                        category=entry.get("cipher", "unknown"),
                        criteria=f"Pre-existing: {entry.get('cipher', '')}",
                        evidence=entry.get("evidence", "Imported from framework"),
                    )
                    counts["disproved"] += 1

                for entry in report.get("promising", []):
                    pid = self.db.create_hypothesis(
                        strategy=entry.get("approach", "unknown"),
                        category="IMPORTED",
                        priority=1,
                    )
                    self.db.update_hypothesis(
                        pid,
                        status=HypothesisStatus.PROMISING.value,
                        score=entry.get("score", 0.0),
                        best_plaintext=entry.get("plaintext_fragment", ""),
                        summary=f"Imported from framework: {entry.get('approach', '')}",
                    )
                    counts["promising"] += 1

                counts["in_progress"] = len(report.get("in_progress", []))

                logger.info(
                    "Bootstrap complete: %d disproofs, %d promising, %d in-progress imported",
                    counts["disproved"], counts["promising"], counts["in_progress"],
                )
            except Exception as exc:
                logger.warning("Failed to parse bootstrap report: %s", exc)
        else:
            logger.warning("Bootstrap agent did not produce bootstrap_report.json")

        return counts

    # ------------------------------------------------------------------
    # Strategy management
    # ------------------------------------------------------------------

    def add_strategy(self, strategy: Strategy) -> None:
        """Register a custom strategy beyond the built-in library."""
        self._custom_strategies.append(strategy)
        logger.info("Registered custom strategy: %s", strategy.name)

    def _get_active_strategies(self) -> list[Strategy]:
        """
        Return the list of strategies to execute this run, filtering
        by name, priority, and disproof status.

        Includes both FRAMEWORK_STRATEGIES and BUILTIN_STRATEGIES to
        maximize worker utilization. Framework strategies are preferred
        (they read CLAUDE.md/MEMORY.md first) but builtins add coverage.
        Deduplication by name ensures no double-dispatch.
        """
        seen_names: set[str] = set()
        all_strategies: list[Strategy] = []
        for s in FRAMEWORK_STRATEGIES + BUILTIN_STRATEGIES + self._custom_strategies:
            if s.name not in seen_names:
                seen_names.add(s.name)
                all_strategies.append(s)

        # Filter by name if specified
        if self.config.strategy_names:
            name_set = set(self.config.strategy_names)
            all_strategies = [s for s in all_strategies if s.name in name_set]

        # Filter by priority ceiling
        all_strategies = [
            s for s in all_strategies if s.priority <= self.config.priority_cutoff
        ]

        # Skip already-disproved strategies unless overridden
        if not self.config.repeat_disproved:
            all_strategies = [
                s for s in all_strategies
                if not self.db.is_strategy_disproved(s.name)
            ]

        # Skip strategies that already have a successful (non-error) run
        if self.config.skip_completed:
            before = len(all_strategies)
            all_strategies = [
                s for s in all_strategies
                if not self.db.has_completed_run(s.name)
            ]
            skipped = before - len(all_strategies)
            if skipped:
                logger.info(
                    "Dedup: skipped %d strategies with prior completed runs "
                    "(use skip_completed=False to override)", skipped,
                )

        # Sort by priority (ascending = highest priority first)
        all_strategies.sort(key=lambda s: s.priority)

        return all_strategies

    # ------------------------------------------------------------------
    # Main run loop
    # ------------------------------------------------------------------

    async def run(self) -> dict[str, Any]:
        """
        Execute a full campaign run. Returns a summary report dict.

        Strategies are dispatched in waves grouped by priority level.
        Within each wave, all strategies run concurrently (up to max_workers).
        """
        self._install_signal_handlers()

        logger.info("=" * 70)
        logger.info("KryptosBot campaign starting")
        logger.info("Max workers: %d", self.config.max_workers)
        logger.info("Project root: %s", self.config.project_root.resolve())
        logger.info("Results DB: %s", self.config.results_db_path)
        logger.info("=" * 70)

        # ── Preflight: verify SDK + CLI + auth before wasting time ──
        logger.info("Running preflight check...")
        ok, msg = await preflight_check()
        if not ok:
            logger.error(msg)
            print(f"\n{'='*70}\n{msg}\n{'='*70}\n", file=sys.stderr)
            raise RuntimeError(msg)

        strategies = self._get_active_strategies()

        if not strategies:
            logger.warning("No strategies to run — all filtered or disproved.")
            return self.db.summary_report()

        logger.info(
            "Dispatching ALL %d strategies concurrently (max_workers=%d): %s",
            len(strategies),
            self.config.max_workers,
            ", ".join(s.name for s in strategies),
        )

        # Create hypothesis records and dispatch everything at once
        dispatch_list: list[tuple[Strategy, int]] = []
        for strat in strategies:
            hyp_id = self.db.create_hypothesis(
                strategy=strat.name,
                category=strat.category.name,
                priority=strat.priority,
                tags=list(strat.tags),
            )
            dispatch_list.append((strat, hyp_id))

        # Fire all workers — semaphore in WorkerManager handles throttling
        all_results = await self.worker_mgr.run_batch(dispatch_list)

        # Log summary
        self._log_wave_summary(0, all_results)

        # Check for solutions
        solutions = [r for r in all_results if r.status == HypothesisStatus.SOLVED]
        if solutions:
            logger.critical(
                "!!! POTENTIAL SOLUTION FOUND in strategy '%s' !!!",
                solutions[0].strategy_name,
            )

        # Campaign complete
        report = self.db.summary_report()
        self._write_report(report, all_results)
        logger.info("Campaign complete. Report written.")
        return report

    async def run_single(self, strategy_name: str) -> WorkerResult:
        """Run a single named strategy — useful for targeted investigation."""
        # Preflight
        ok, msg = await preflight_check()
        if not ok:
            logger.error(msg)
            print(f"\n{'='*70}\n{msg}\n{'='*70}\n", file=sys.stderr)
            raise RuntimeError(msg)

        all_strats = FRAMEWORK_STRATEGIES + BUILTIN_STRATEGIES + self._custom_strategies
        match = [s for s in all_strats if s.name == strategy_name]
        if not match:
            raise ValueError(f"Unknown strategy: {strategy_name}")

        strat = match[0]
        hyp_id = self.db.create_hypothesis(
            strategy=strat.name,
            category=strat.category.name,
            priority=strat.priority,
            tags=list(strat.tags),
        )
        return await self.worker_mgr.run_strategy(strat, hyp_id)

    async def run_disproofs_only(self) -> list[WorkerResult]:
        """Run only disproof-category strategies. Great for building evidence."""
        from .config import StrategyCategory

        disproof_strats = [
            s for s in BUILTIN_STRATEGIES + self._custom_strategies
            if s.category == StrategyCategory.DISPROOF
            and not self.db.is_strategy_disproved(s.name)
        ]

        if not disproof_strats:
            logger.info("All disproof strategies already completed.")
            return []

        dispatch = []
        for strat in disproof_strats:
            hyp_id = self.db.create_hypothesis(
                strategy=strat.name,
                category=strat.category.name,
                priority=strat.priority,
                tags=list(strat.tags),
            )
            dispatch.append((strat, hyp_id))

        return await self.worker_mgr.run_batch(dispatch)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _group_by_priority(strategies: list[Strategy]) -> dict[int, list[Strategy]]:
        groups: dict[int, list[Strategy]] = {}
        for s in strategies:
            groups.setdefault(s.priority, []).append(s)
        return groups

    def _log_wave_summary(self, priority: int, results: list[WorkerResult]) -> None:
        solved = sum(1 for r in results if r.status == HypothesisStatus.SOLVED)
        promising = sum(1 for r in results if r.status == HypothesisStatus.PROMISING)
        disproved = sum(1 for r in results if r.status == HypothesisStatus.DISPROVED)
        inconclusive = sum(1 for r in results if r.status == HypothesisStatus.INCONCLUSIVE)
        errors = sum(1 for r in results if r.error)

        logger.info(
            "Wave %d complete — solved:%d promising:%d disproved:%d inconclusive:%d errors:%d",
            priority, solved, promising, disproved, inconclusive, errors,
        )

    def _write_report(self, report: dict[str, Any], results: list[WorkerResult]) -> None:
        """Write a JSON report and a human-readable summary to disk."""
        self.config.log_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # JSON report
        json_path = self.config.log_dir / f"report_{timestamp}.json"
        report["results"] = [
            {
                "strategy": r.strategy_name,
                "status": r.status.value,
                "score": r.score,
                "best_plaintext": r.best_plaintext,
                "duration_seconds": r.duration_seconds,
                "error": r.error,
                "summary": r.summary,
            }
            for r in results
        ]
        json_path.write_text(json.dumps(report, indent=2))

        # Human-readable summary
        txt_path = self.config.log_dir / f"report_{timestamp}.txt"
        lines = [
            "=" * 70,
            f"KryptosBot Campaign Report — {timestamp}",
            "=" * 70,
            f"Total hypotheses tested: {report['total_hypotheses']}",
            f"Status breakdown: {report['by_status']}",
            f"Total cipher families disproved: {report['total_disproofs']}",
            "",
            "--- Disproof Log ---",
        ]
        for entry in self.db.get_disproof_log():
            lines.append(
                f"  [{entry['disproved_at'][:10]}] {entry['strategy']}: {entry['criteria']}"
            )

        lines.extend(["", "--- Top Candidates ---"])
        for c in report.get("top_candidates", []):
            lines.append(
                f"  {c['strategy']}: score={c['score']:.2f}  plaintext={c['best_plaintext'][:40]}"
            )

        lines.extend(["", "--- Per-Strategy Results ---"])
        for r in results:
            lines.append(
                f"  {r.strategy_name}: {r.status.value} "
                f"(score={r.score:.2f}, {r.duration_seconds:.0f}s)"
            )
            if r.error:
                lines.append(f"    ERROR: {r.error[:100]}")

        txt_path.write_text("\n".join(lines))
        logger.info("Reports written to %s", self.config.log_dir)

    # ------------------------------------------------------------------
    # Signal handling for graceful shutdown
    # ------------------------------------------------------------------

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, self._handle_signal)

    def _handle_signal(self) -> None:
        logger.warning("Received shutdown signal — finishing current wave then stopping.")
        self._shutdown_event.set()
