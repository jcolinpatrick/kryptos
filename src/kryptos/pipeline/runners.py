"""Sweep engine — parallel experiment execution with checkpointing.

Provides a canonical runner that handles:
- Multiprocessing-safe parallel execution
- Checkpointing and resumability
- Deterministic seeds
- Run manifests for reproducibility
- Signal handling for graceful shutdown
"""
from __future__ import annotations

import json
import signal
import sys
import time
from multiprocessing import Pool
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from kryptos.kernel.config import SweepConfig
from kryptos.kernel.persistence.sqlite import Database
from kryptos.kernel.persistence.artifacts import RunManifest, JsonlWriter


WorkItem = Dict[str, Any]
WorkResult = Dict[str, Any]
WorkerFn = Callable[[WorkItem], WorkResult]


class SweepRunner:
    """Orchestrates parallel sweep campaigns with checkpointing."""

    def __init__(
        self,
        config: SweepConfig,
        worker_fn: WorkerFn,
        work_items: List[WorkItem],
        force: bool = False,
    ) -> None:
        self.config = config
        self.worker_fn = worker_fn
        self.work_items = work_items
        self.run_id = config.run_id
        self._force = force
        self._interrupted = False

    def execute(self) -> int:
        """Run the sweep. Returns 0 on success, 1 on failure."""
        db = Database(self.config.db_path)

        # Resume support
        completed_ids: set[str] = set()
        if not self._force:
            completed_ids = db.completed_job_ids(self.run_id)
            if completed_ids:
                print(f"Resuming: {len(completed_ids)} jobs already done.")

        # Filter to pending work
        pending = [
            item for item in self.work_items
            if item.get("job_id", "") not in completed_ids
        ]

        if not pending:
            print("All jobs already completed.")
            db.close()
            return 0

        # Register run
        db.register_run(
            self.run_id, self.config.name,
            self.config.to_dict(), len(self.work_items),
        )

        # Create manifest
        manifest = RunManifest.create(self.config.name, self.config.to_dict())
        manifest_path = Path(self.config.log_dir) / f"{self.run_id}_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest.save(manifest_path)

        print(f"Campaign: {self.config.name}  Run: {self.run_id}")
        print(f"Pending: {len(pending)} jobs  Workers: {self.config.workers}")

        # Set up logging
        log_path = Path(self.config.log_dir) / f"{self.run_id}.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)

        old_sigint = signal.signal(signal.SIGINT, self._signal_handler)
        old_sigterm = signal.signal(signal.SIGTERM, self._signal_handler)

        completed = 0
        global_best = 0
        t_start = time.monotonic()
        report_interval = max(1, len(pending) // 50)

        try:
            with JsonlWriter(log_path) as log:
                with Pool(processes=self.config.workers) as pool:
                    for result in pool.imap_unordered(self.worker_fn, pending):
                        job_id = result.get("job_id", "")

                        # Persist results before checkpoint so resume
                        # doesn't skip jobs whose results weren't stored
                        score = result.get("best_score", 0)

                        for tr in result.get("top_results", []):
                            db.store_result(
                                experiment_id=self.config.name,
                                config=tr,
                                score=tr.get("score", 0),
                                bean_pass=tr.get("bean_ok", False),
                                run_id=self.run_id,
                            )

                        db.checkpoint_job(self.run_id, job_id, result)
                        db.commit()
                        log.write(result)

                        completed += 1
                        if score > global_best:
                            global_best = score
                            print(f"*** NEW BEST: {score}/24 — {result.get('config_label', '')}")

                        for tr in result.get("top_results", []):
                            if tr.get("ALERT"):
                                print(f"\n{'!' * 60}")
                                print(f"BREAKTHROUGH: score={tr['score']}")
                                print(f"{'!' * 60}\n")

                        if completed % report_interval == 0 or completed == len(pending):
                            el = time.monotonic() - t_start
                            rate = completed / el if el > 0 else 0
                            eta = (len(pending) - completed) / rate if rate > 0 else 0
                            pct = 100 * completed / len(pending)
                            print(
                                f"  [{completed}/{len(pending)}] ({pct:.1f}%) "
                                f"best={global_best}/24 "
                                f"rate={rate:.1f}/s ETA={eta / 60:.1f}min",
                                flush=True,
                            )

                        if self._interrupted:
                            break

        except Exception as e:
            print(f"ERROR: {e}", file=sys.stderr)
            db.finalize_run(self.run_id, "FAILED")
            db.close()
            return 1
        finally:
            signal.signal(signal.SIGINT, old_sigint)
            signal.signal(signal.SIGTERM, old_sigterm)

        status = "COMPLETE" if (completed == len(pending) and not self._interrupted) else "PARTIAL"
        db.finalize_run(self.run_id, status)

        el = time.monotonic() - t_start
        print(f"\n{'=' * 60}")
        print(f"Status: {status}  Jobs: {completed}/{len(pending)}  "
              f"Time: {el / 60:.1f}min  Best: {global_best}/24")
        print(f"DB: {self.config.db_path}")
        print(f"{'=' * 60}")

        db.close()
        return 0

    def _signal_handler(self, signum, frame):
        print(f"\n[SIGNAL {signum}] Shutting down gracefully...", flush=True)
        self._interrupted = True
