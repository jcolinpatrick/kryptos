#!/usr/bin/env python3
"""
Primary entrypoint for the KryptosBot research controller.

Usage:
    python3 kryptosbot/run_controller.py [options]

Options:
    --cycles N          Max controller cycles (default: 10)
    --theories N        Theories per cycle (default: 5)
    --workers N         Max concurrent workers (default: 4)
    --timeout N         Worker timeout in minutes (default: 30)
    --dry-run           Generate + critic only, no dispatch
    --skip-critic       Skip the critic stage
    --status            Print current controller status and exit
    --summary           Print ledger summary and exit
    --db PATH           Theory ledger path (default: db/theory_ledger.sqlite)

Examples:
    # Full run with defaults
    python3 kryptosbot/run_controller.py

    # Dry run: generate and critique 10 theories without testing
    python3 kryptosbot/run_controller.py --dry-run --theories 10

    # Check current state
    python3 kryptosbot/run_controller.py --status

    # Conservative run: 2 cycles, 3 theories each
    python3 kryptosbot/run_controller.py --cycles 2 --theories 3
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Any, Optional

# Ensure repo root (for kryptosbot package) and src (for kernel) are on path
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

# IMPORTANT: kryptosbot.controller transitively imports
# kryptos.kernel.constants, which freezes its CT/cribs/Bean derivation
# at first import time from KRYPTOS_CT_OVERRIDE / KRYPTOS_CRIB_DICT_OVERRIDE.
# When --bench-challenge is set we must install those overrides BEFORE
# the controller import. The dispatcher and worker-contract verifier
# both read CT and CRIB_DICT from kryptos.kernel.constants, so this
# install is the single bottleneck that makes the bench challenge flow
# into every downstream call site (including forked multiprocessing
# workers, which inherit os.environ and the parent's already-imported
# kernel module). See kryptosbot/bench_loader.py for the contract.
_BENCH_CHALLENGE_FLAG = "--bench-challenge"
_BENCH_CHALLENGE_PATH: Path | None = None
if _BENCH_CHALLENGE_FLAG in sys.argv:
    _idx = sys.argv.index(_BENCH_CHALLENGE_FLAG)
    if _idx + 1 >= len(sys.argv):
        print(
            f"error: {_BENCH_CHALLENGE_FLAG} requires a path argument",
            file=sys.stderr,
        )
        sys.exit(2)
    _BENCH_CHALLENGE_PATH = Path(sys.argv[_idx + 1]).resolve()
    # Lazy import: bench_loader is stdlib-only, safe before kernel.
    from kryptosbot.bench_loader import (  # noqa: E402
        BenchLoaderError,
        load_k4bench_challenge,
    )
    try:
        _BENCH_CHALLENGE = load_k4bench_challenge(_BENCH_CHALLENGE_PATH)
    except BenchLoaderError as _exc:
        print(f"error: {_exc}", file=sys.stderr)
        sys.exit(2)
    _BENCH_CHALLENGE.install_kernel_overrides()
else:
    _BENCH_CHALLENGE = None  # type: ignore[assignment]

from kryptosbot.controller import ControllerConfig, ResearchController  # noqa: E402
from kryptosbot.theory_ledger import TheoryLedger  # noqa: E402
from kryptosbot import display  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="KryptosBot Research Controller",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--cycles", type=int, default=10, help="Max controller cycles")
    parser.add_argument("--theories", type=int, default=5, help="Theories per cycle")
    parser.add_argument("--workers", type=int, default=4, help="Max concurrent workers")
    parser.add_argument("--timeout", type=int, default=30, help="Worker timeout in minutes (default: 30)")
    parser.add_argument("--dry-run", action="store_true", help="Generate + critic only")
    parser.add_argument("--skip-critic", action="store_true", help="Skip critic stage")
    parser.add_argument("--status", action="store_true", help="Print status and exit")
    parser.add_argument("--summary", action="store_true", help="Print summary and exit")
    parser.add_argument(
        "--inventory", action="store_true",
        help="Print the full provenance inventory (auto-hedged) and exit",
    )
    parser.add_argument("--db", type=str, default="db/theory_ledger.sqlite", help="Ledger DB path")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress SDK/library logging")
    parser.add_argument(
        "--alert-on",
        choices=["none", "signal", "breakthrough"],
        default="signal",
        help=(
            "Contradiction-detector alert threshold. "
            "'signal' (default) fires on crib_score>=18; "
            "'breakthrough' only on crib_score==24 with bean_passed; "
            "'none' disables. Alerts are NOT a victory bell — they flag "
            "results that contradict current eliminations and warrant audit."
        ),
    )
    parser.add_argument(
        "--no-oranchak",
        action="store_true",
        help=(
            "SHORTHAND: set both --no-oranchak-corpora and "
            "--no-serpentine-anchor. Reproduces the pre-Campaign-C "
            "single-flag behavior (both community corpora and archive "
            "serpentine anchor suppressed)."
        ),
    )
    parser.add_argument(
        "--no-oranchak-corpora",
        action="store_true",
        help=(
            "Suppress only the Oranchak community reference corpora "
            "(quagmire keyword pools + k4_candidate_fills CSV) in the "
            "theorist prompt. Leaves the AAA-archive serpentine-"
            "Vigenère anchor in place. Campaign-C counterfactual; see "
            "docs/maturation/round3/K4_CAMPAIGN_C_PREREG.md."
        ),
    )
    parser.add_argument(
        "--no-serpentine-anchor",
        action="store_true",
        help=(
            "Suppress only the AAA-archive serpentine-Vigenère "
            "hypothesis seed block (Sanborn page-17 quote). Leaves the "
            "community Oranchak corpora in place. Future Campaign-D "
            "counterfactual; not currently scheduled."
        ),
    )
    parser.add_argument(
        "--verify-transport",
        action="store_true",
        help=(
            "Before starting the main run, verify the direct-API and "
            "subscription-SDK transports are alive. Halts with exit 1 "
            "if either probe fails. See K4_RUN_PROTOCOL_R3.md §7. "
            "Added after Campaign C attempt 1 (2026-04-24) wasted "
            "~3 hours on a silently-throttled subscription transport."
        ),
    )
    parser.add_argument(
        "--verify-transport-timeout",
        type=int,
        default=60,
        help=(
            "Per-probe timeout in seconds for --verify-transport "
            "(default: 60). Each probe has its own budget of this "
            "length."
        ),
    )
    parser.add_argument(
        "--bench-challenge",
        type=str,
        default=None,
        help=(
            "Run the controller against one K4Bench public challenge "
            "JSON instead of real K4. Installs KRYPTOS_CT_OVERRIDE / "
            "KRYPTOS_CRIB_DICT_OVERRIDE before any kernel import, "
            "forces a synthetic ledger under db/k4bench/ unless --db "
            "is explicitly under that tree, and tags every ledger "
            "entry with bench_id/suite_id. K4Bench is a calibration "
            "input mode for the existing controller; it does NOT "
            "create a parallel solver."
        ),
    )
    parser.add_argument(
        "--bench-attempts-out",
        type=str,
        default=None,
        help=(
            "When --bench-challenge is set, write the attempt artifact "
            "JSON to this path on completion. Defaults to "
            "bench/k4bench/attempts/<bench_id>.json."
        ),
    )
    # ------------------------------------------------------------------
    # K4Bench HandCipherCore deterministic-seed controls (2026-04-27).
    # These flags govern only the bench-mode HCC seed list — they have
    # no effect in real-K4 mode (where HCC seeds are always empty).
    # CRITICAL: --theories does NOT cap HCC seeds; only --hcc-seeds N
    # and --no-hcc-seeds do.
    # ------------------------------------------------------------------
    parser.add_argument(
        "--hcc-seeds",
        type=int,
        default=None,
        metavar="N",
        help=(
            "Bench mode: cap HandCipherCore deterministic coverage "
            "seeds at N. Default (when this flag is omitted) is "
            "uncapped — the full role × layer-order × family matrix "
            "from the clue pack runs. Use a small N (e.g. --hcc-seeds 8) "
            "to test only the highest-priority families. Note: "
            "--theories does NOT cap HCC seeds; only --hcc-seeds and "
            "--no-hcc-seeds do."
        ),
    )
    parser.add_argument(
        "--no-hcc-seeds",
        action="store_true",
        help=(
            "Bench mode: DISABLE HandCipherCore seeding entirely. "
            "Equivalent to --hcc-seeds 0. Use for LLM-only diagnostic "
            "runs where you want to see what the theorist agent "
            "produces in isolation. Mutually exclusive with --hcc-only "
            "and --hcc-seeds N."
        ),
    )
    parser.add_argument(
        "--hcc-only",
        action="store_true",
        help=(
            "Bench mode: skip the LLM theorist entirely; dispatch ONLY "
            "the HCC deterministic seed catalogue. Use for fast, "
            "tokens-free coverage runs where the LLM contribution is "
            "not needed. Mutually exclusive with --no-hcc-seeds. "
            "Combine with --hcc-seeds N to also cap the seed count."
        ),
    )
    # ------------------------------------------------------------------
    # K4Bench cost-control flags (2026-04-28). These plumb the existing
    # ``ControllerConfig`` skip fields and the new HCC-bypass gate onto
    # the CLI. They are only meaningful in bench mode (real-K4 mode is
    # unaffected because HCC seeds are empty); none of them change the
    # cryptanalytic behaviour of the worker / dispatcher / scoring path.
    # ------------------------------------------------------------------
    parser.add_argument(
        "--bench-fast",
        action="store_true",
        help=(
            "Bench mode: cost-control orchestrator. Implies "
            "--skip-synthesis, --skip-lead-pursuit, --skip-stat-audit, "
            "--deterministic-critic, and sets --redteam-min-crib so "
            "deterministic HCC seeds bypass the LLM red-team sibling "
            "call. LLM-generated theories (when present) still hit "
            "critic+red-team. Combine with --hcc-only for the "
            "cheapest tokens-free coverage run — every LLM-backed "
            "phase is suppressed. Real-K4 mode unchanged."
        ),
    )
    parser.add_argument(
        "--skip-red-team",
        action="store_true",
        help=(
            "Skip the proposal-time red-team-disprover sibling call "
            "entirely (both LLM-generated and HCC theories). Cost-"
            "control flag; not a cryptanalytic change. Mirrors the "
            "existing ``ControllerConfig.skip_red_team`` field."
        ),
    )
    parser.add_argument(
        "--skip-synthesis",
        action="store_true",
        help=(
            "Skip the end-of-cycle results-analyst synthesis (Day 5). "
            "Cost-control flag; mirrors the existing "
            "``ControllerConfig.skip_synthesis`` field. Synthesis is "
            "skipped by default under --bench-fast."
        ),
    )
    parser.add_argument(
        "--skip-lead-pursuit",
        action="store_true",
        help=(
            "Skip the Day-6 lead-pursuit evaluator (LLM sibling "
            "call against contracts in the [lead_pursuit_lo, "
            "lead_pursuit_hi] sub-signal band). Cost-control flag; "
            "mirrors the existing ``ControllerConfig.skip_lead_"
            "pursuit`` field. Skipped by default under --bench-fast "
            "so HCC-only runs do not pay tokens for sub-signal "
            "follow-ups that have no theorist on the next cycle."
        ),
    )
    parser.add_argument(
        "--skip-stat-audit",
        action="store_true",
        help=(
            "Skip the Day-5 statistical-auditor sibling call against "
            "post-execution contracts at or above stat_audit_"
            "threshold. Cost-control flag; mirrors the existing "
            "``ControllerConfig.skip_stat_audit`` field. Skipped by "
            "default under --bench-fast so a high HCC crib score "
            "does not trigger a stat-audit LLM call (the audit's "
            "purpose is to gate LLM-driven signal claims; "
            "deterministic HCC scores are auditable from the seed "
            "catalogue alone)."
        ),
    )
    parser.add_argument(
        "--deterministic-critic",
        action="store_true",
        help=(
            "Force the critic stage to remain deterministic (no LLM "
            "call). Today the critic is always deterministic so this "
            "flag is currently a banner annotation; reserved for a "
            "future LLM-backed critic path. Implied by --bench-fast."
        ),
    )
    parser.add_argument(
        "--redteam-min-crib",
        type=int,
        default=0,
        metavar="N",
        help=(
            "Bench mode: skip the red-team sibling call for HCC seeds "
            "whose pre-dispatch crib_score is below N. Default 0 = "
            "red-team every theory (existing behaviour). Any N>0 "
            "causes deterministic HCC seeds (those with "
            "minimal_test_spec.method=='bench_hand_cipher_core') to "
            "bypass red-team pre-dispatch; LLM-generated theories "
            "ALWAYS hit red-team regardless of N. Implied by "
            "--bench-fast."
        ),
    )
    args = parser.parse_args()
    # Validate mutually-exclusive HCC flag combinations. argparse's
    # add_mutually_exclusive_group can't express "either of these two
    # but not both AND not with --hcc-seeds 0", so we validate by hand.
    if args.no_hcc_seeds and args.hcc_only:
        parser.error(
            "--no-hcc-seeds and --hcc-only are mutually exclusive: "
            "--no-hcc-seeds disables HCC seeds (LLM only), --hcc-only "
            "disables the LLM (HCC only). Combining them would dispatch "
            "nothing."
        )
    if args.no_hcc_seeds and args.hcc_seeds is not None:
        parser.error(
            "--no-hcc-seeds and --hcc-seeds N are contradictory. Use "
            "one or the other, not both."
        )
    if args.hcc_seeds is not None and args.hcc_seeds < 0:
        parser.error("--hcc-seeds N requires N >= 0; for disable use --no-hcc-seeds.")
    return args


def _configure_logging(quiet: bool) -> None:
    """Set up logging — suppress noisy SDK internals."""
    level = logging.WARNING if quiet else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(message)s",
        datefmt="%H:%M:%S",
    )
    # Suppress SDK transport noise
    logging.getLogger("claude_agent_sdk").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    # When the entrypoint drives display, suppress controller/registries logger too
    # (the entrypoint prints its own formatted output)
    logging.getLogger("kryptosbot.controller").setLevel(logging.WARNING)
    logging.getLogger("kryptosbot.registries").setLevel(logging.WARNING)
    logging.getLogger("kryptosbot.contracts").setLevel(logging.WARNING)


def do_status(config: ControllerConfig) -> None:
    """Print current controller status."""
    controller = ResearchController(config)
    status = controller.get_status()
    display.print_status(status)


def do_summary(db_path: Path) -> None:
    """Print ledger summary."""
    ledger = TheoryLedger(db_path)
    summary = ledger.summary()
    display.print_summary(summary)


def do_inventory(db_path: Path) -> None:
    """Print the canonical provenance inventory with auto-hedges.

    Prefers the live ledger if the claims table is populated, else falls
    back to the in-process CANONICAL_CLAIMS registry.
    """
    from kryptosbot.claim_rendering import render_inventory
    from kryptosbot.claims_registry import CANONICAL_CLAIMS

    claims = []
    try:
        ledger = TheoryLedger(db_path)
        claims = ledger.get_all_claims()
    except Exception:
        claims = []
    if not claims:
        claims = CANONICAL_CLAIMS
    print(render_inventory(claims))


def _build_display_callbacks() -> "CycleCallbacks":
    """Return a CycleCallbacks bundle that routes events to display.print_*.

    This bundle replaces the inline display calls that used to live in
    do_run's per-cycle loop. The actual cycle work now runs in
    ``ResearchController._run_cycle_loop`` (one shared body for both
    library mode and TUI mode); see
    ``feedback_dup_cycle_loop_trap.md``.

    Adding TUI rendering for a new event:
       1. Add the corresponding field to ``CycleCallbacks`` in controller.py.
       2. Add a single ``cb.emit(...)`` line in ``_run_cycle_loop`` at
          the moment the event is meaningful.
       3. Wire the field below.

    Pinned by ``test_cycle_loop_characterization.py`` (test G).
    """
    from kryptosbot.controller import CycleCallbacks

    def _redteam_progress(event: str, detail: Any) -> None:
        if event == "start":
            agent_name, model, count = detail
            display.print_redteam_start(agent_name, model, count)
        elif event == "verdict":
            theory, verdict = detail
            reason = verdict.reasons[0] if verdict.reasons else ""
            display.print_redteam_verdict(
                theory_id=theory.hypothesis_id,
                theory_title=theory.title or "(untitled)",
                verdict=verdict.verdict,
                confidence=verdict.confidence,
                wall_time_sec=verdict.wall_time_sec,
                turn_count=verdict.turn_count,
                tool_count=verdict.tool_count,
                reason=reason,
            )
        elif event == "summary":
            # Post-Day-5 hardening: summary tuple widened to
            # (survivors, total, rejected, concerned, errors). Older
            # 3-tuple form still tolerated.
            if len(detail) == 5:
                survivors, total, rejected, concerned, errors = detail
            else:
                survivors, total, rejected = detail
                concerned = 0
                errors = 0
            display.print_redteam_summary(
                survivors, total, rejected,
                concerned=concerned, errors=errors,
            )
        elif event == "skipped":
            pass  # logger.info covers it

    def _stat_audit_progress(event: str, detail: Any) -> None:
        if event == "start":
            agent_name, model, count = detail
            display.print_stat_audit_start(agent_name, model, count)
        elif event == "verdict":
            theory, contract, verdict = detail
            concern = (
                verdict.methodology_concerns[0]
                if verdict.methodology_concerns else ""
            )
            display.print_stat_audit_verdict(
                theory_id=contract.hypothesis_id,
                theory_title=theory.title or "(untitled)",
                verdict=verdict.verdict,
                confidence=verdict.confidence,
                wall_time_sec=verdict.wall_time_sec,
                turn_count=verdict.turn_count,
                tool_count=verdict.tool_count,
                concern=concern,
            )
        elif event == "summary":
            confirmed, concerned, rejected, total = detail
            display.print_stat_audit_summary(
                confirmed, concerned, rejected, total,
            )
        elif event == "skipped":
            display.print_stat_audit_skipped(str(detail))

    def _pursuit_progress(event: str, detail: Any) -> None:
        if event == "start":
            agent_name, model, count = detail
            display.print_pursuit_start(agent_name, model, count)
        elif event == "verdict":
            theory, contract, verdict = detail
            display.print_pursuit_verdict(
                theory_id=contract.hypothesis_id,
                theory_title=theory.title or "(untitled)",
                verdict=verdict.verdict,
                confidence=verdict.confidence,
                wall_time_sec=verdict.wall_time_sec,
                turn_count=verdict.turn_count,
                tool_count=verdict.tool_count,
                rationale=verdict.rationale,
                suggested_variants=verdict.suggested_variants,
            )
        elif event == "summary":
            pursue, skip, error, total = detail
            display.print_pursuit_summary(pursue, skip, error, total)
        elif event == "skipped":
            display.print_pursuit_skipped(str(detail))

    def _synthesis_progress(event: str, detail: Any) -> None:
        if event == "start":
            agent_name, model = detail
            display.print_synthesis_start(agent_name, model)
        elif event == "result":
            display.print_synthesis_result(detail)
        elif event == "skipped":
            display.print_synthesis_skipped(str(detail))

    def _on_candidates_generated(count: int) -> None:
        # Display.print_generation_start was inline before generation,
        # display.print_candidates_generated after. The shared loop
        # only emits one event after candidates are produced; the
        # "generation_start" banner is now triggered by on_landscape
        # ending plus the theorist's own progress events. If a
        # generation-start banner is still desired, wire it through
        # on_theorist_event's "start" event below.
        display.print_candidates_generated(count)

    def _on_theorist_event(event: str, detail: Any) -> None:
        # Special-case: emit print_generation_start on the very first
        # theorist event of each cycle so the TUI banner still appears.
        # display.print_theorist_event handles the rest.
        if event == "start":
            display.print_generation_start()
        display.print_theorist_event(event, detail)

    return CycleCallbacks(
        on_cycle_begin=display.print_cycle_header,
        on_cycle_error=display.print_cycle_error,
        on_landscape=display.print_landscape,
        on_no_candidates=display.print_no_candidates,
        on_candidates_generated=_on_candidates_generated,
        on_dry_run_skip=display.print_dry_run_skip,
        on_run_halt=display.print_run_halt,
        on_theorist_event=_on_theorist_event,
        on_critic_start=display.print_critic_start,
        on_critic_result=display.print_critic_result,
        on_critic_summary=display.print_critic_summary,
        on_redteam_progress=_redteam_progress,
        on_dispatch_header=display.print_dispatch_header,
        on_worker_message=display.print_worker_event,
        on_dispatch_footer=display.print_dispatch_footer,
        on_outcome_summary=display.print_outcome_summary,
        on_stat_audit_progress=_stat_audit_progress,
        on_pursuit_progress=_pursuit_progress,
        on_synthesis_progress=_synthesis_progress,
    )


async def do_run(config: ControllerConfig) -> None:
    """Run the controller with formatted console output.

    Thin wrapper since the priority-1 cycle-loop collapse: the cycle
    body runs in ``ResearchController._run_cycle_loop``, which we drive
    here with a display-routing ``CycleCallbacks`` bundle. Setup phases
    (bootstrap, orphan reconcile, startup banner) remain inline because
    they happen before the cycle loop and have their own display surface.

    Pinned by ``test_cycle_loop_characterization.py`` (test G): the
    canonical trace produced via this path is identical to the trace
    produced by ``ResearchController.run`` with the same scenario.
    """
    controller = ResearchController(config)

    from kryptosbot.registries import bootstrap_all, bootstrap_controller_queue_reset

    # Synthetic-mode enforcement (2026-04-26). Refuse a real launch
    # against a synthetic-tainted ledger (or vice versa) BEFORE
    # bootstrap so the launch fails without mutating ledger state.
    # Mirrors ResearchController.run; the check must run on every
    # entry point that drives the controller against a ledger.
    from kryptos.kernel.constants import _SYNTHETIC_MODE
    controller.ledger.verify_and_pin_synthetic_mode(_SYNTHETIC_MODE)

    # Bootstrap registries — gated via ProblemContext. In real-K4 mode
    # the full bootstrap seeds KNOWN_FAMILIES, KNOWN_ANOMALIES, claims,
    # exhaustion-log families, campaign manifests, and reruns into the
    # ledger so the landscape has the live research state. In bench
    # mode every one of those would inject real-K4 rows into the
    # bench-scoped ledger and contaminate downstream queries (the
    # ledger backs status_counts, family_counts, get_open_anomalies,
    # get_active_families, recent_outcomes, get_theories_by_family —
    # so a single bootstrap call would re-leak real-K4 state into
    # every cycle of a bench run). Bench mode runs only the controller-
    # queue-reset bootstrap, which is generic lifecycle and carries no
    # K4-specific seed data.
    if config.problem.is_real_k4:
        bootstrap_result = bootstrap_all(controller.ledger, config.project_root)
    else:
        bootstrap_result = {
            "families_added": 0,
            "anomalies_added": 0,
            "claims_added": 0,
            "exhaustion_families": 0,
            "campaign_manifests_applied": 0,
            "local_reruns_applied": 0,
            "queue_reset_withdrawn":
                bootstrap_controller_queue_reset(controller.ledger),
        }
    display.print_bootstrap(
        families=bootstrap_result["families_added"],
        anomalies=bootstrap_result["anomalies_added"],
        exhaustion=bootstrap_result["exhaustion_families"],
    )

    # Load persisted state
    controller.state = controller.ledger.load_controller_state()

    # Reconcile any theories orphaned in RUNNING from a prior crash
    orphaned = controller.ledger.reconcile_orphaned_running()
    if orphaned:
        console_msg = f"  Reconciled {len(orphaned)} orphaned RUNNING theories"
        try:
            from kryptosbot.display import console, S_WARN
            from rich.text import Text
            console.print(Text(console_msg, style=S_WARN))
        except Exception:
            print(console_msg)

    # Startup banner — in bench mode, count HCC seeds at startup so the
    # banner shows the actual deterministic-coverage size (not just the
    # cap). Computing seeds at this point is cheap (pure Python; no API
    # call) and the same call _generate_theories will make on cycle 1.
    # In real-K4 mode the seed count is None and the banner falls back
    # to its pre-2026-04-27 layout bit-for-bit.
    hcc_seeds_count: Optional[int] = None
    llm_theories_count: Optional[int] = None
    total_candidates_count: Optional[int] = None
    if config.problem.is_bench:
        try:
            hcc_seeds_list = controller._collect_hcc_seeds()
            hcc_seeds_count = len(hcc_seeds_list)
        except Exception as exc:  # noqa: BLE001 — banner must never crash startup
            logger = logging.getLogger("kryptosbot.run_controller")
            logger.warning(
                "Could not count HCC seeds for startup banner: %s", exc,
            )
            hcc_seeds_count = 0
        # LLM contributes 0 when --hcc-only is set; otherwise up to
        # ``theories_per_cycle`` (the actual count depends on what the
        # theorist returns each cycle, but the banner shows the cap).
        llm_theories_count = 0 if config.hcc_only else config.theories_per_cycle
        total_candidates_count = hcc_seeds_count + llm_theories_count

    # 2026-04-28: K4Bench cost-control banner annotations. Real-K4
    # runs leave these as None so the existing banner layout is bit-
    # identical to the pre-flag version. In bench mode we always
    # render the three phase rows so the operator can see at-a-glance
    # which LLM calls are paying tokens.
    critic_mode_label: Optional[str] = None
    redteam_mode_label: Optional[str] = None
    synthesis_mode_label: Optional[str] = None
    lead_pursuit_mode_label: Optional[str] = None
    stat_audit_mode_label: Optional[str] = None
    if config.problem.is_bench:
        # Critic stage is always deterministic today; --deterministic-
        # critic is recorded for clarity / future-proofing.
        critic_mode_label = (
            "deterministic (--deterministic-critic)"
            if config.deterministic_critic
            else "deterministic"
        )
        if config.skip_red_team:
            redteam_mode_label = "skipped (--skip-red-team)"
        elif config.redteam_min_crib_score > 0:
            redteam_mode_label = (
                f"LLM-backed for LLM theories; HCC seeds bypass "
                f"(--redteam-min-crib={config.redteam_min_crib_score})"
            )
        else:
            redteam_mode_label = "LLM-backed (all approved theories)"
        if config.skip_synthesis:
            synthesis_mode_label = "skipped (--skip-synthesis)"
        else:
            synthesis_mode_label = "LLM-backed"
        if config.skip_lead_pursuit:
            lead_pursuit_mode_label = "skipped (--skip-lead-pursuit)"
        else:
            lead_pursuit_mode_label = "LLM-backed"
        if config.skip_stat_audit:
            stat_audit_mode_label = "skipped (--skip-stat-audit)"
        else:
            stat_audit_mode_label = "LLM-backed"

    display.print_startup(
        cycle_start=controller.state.cycle_number + 1,
        max_cycles=config.max_cycles,
        theories_per_cycle=config.theories_per_cycle,
        workers=config.max_concurrent_workers,
        timeout_minutes=config.worker_timeout_minutes,
        proposed=controller.state.theories_proposed,
        tested=controller.state.theories_tested,
        eliminated=controller.state.theories_eliminated,
        dry_run=config.dry_run,
        hcc_seeds=hcc_seeds_count,
        llm_theories=llm_theories_count,
        total_candidates=total_candidates_count,
        hcc_seeds_cap=config.hcc_seeds_cap,
        hcc_only=config.hcc_only,
        no_hcc_seeds=(config.hcc_seeds_cap == 0),
        bench_fast=config.bench_fast,
        critic_mode=critic_mode_label,
        redteam_mode=redteam_mode_label,
        synthesis_mode=synthesis_mode_label,
        lead_pursuit_mode=lead_pursuit_mode_label,
        stat_audit_mode=stat_audit_mode_label,
    )

    # Snapshot session baseline so _assess_landscape's cycle_delta
    # reflects new work in this session. Without this call, the TUI
    # path historically reported cycle_delta=0 because the baseline
    # attributes were never populated. Mirrors ResearchController.run
    # which makes the same call right before the cycle loop.
    controller._snapshot_session_baseline()

    # Run the shared cycle-loop body with display-routing callbacks.
    # ResearchController._run_cycle_loop handles all per-cycle work,
    # logger.* calls, and emits CycleCallbacks events as it goes.
    callbacks = _build_display_callbacks()
    await controller._run_cycle_loop(callbacks)

    display.print_completion(controller.state.to_dict())


async def main() -> None:
    args = parse_args()
    _configure_logging(args.quiet)

    # Transport pre-flight gate. Runs direct-API + subscription-SDK
    # probes before any controller state is loaded so a flaky
    # transport halts early without touching the ledger.
    if args.verify_transport:
        from datetime import datetime, timezone
        from kryptosbot.transport_preflight import (
            verify_transport_async as _verify,
        )

        ts = datetime.now(timezone.utc).isoformat()
        print(f"[{ts}] transport-verify: running pre-flight probes "
              f"(per-probe timeout={args.verify_transport_timeout}s)")
        ok, summary = await _verify(timeout_sec=args.verify_transport_timeout)
        ts_done = datetime.now(timezone.utc).isoformat()
        print(f"[{ts_done}] transport-verify result:")
        print(summary)
        if not ok:
            print(
                f"[{ts_done}] HALT: transport verification failed — "
                "refusing to launch main run. Wait for a fresh "
                "subscription window or diagnose the failing probe."
            )
            sys.exit(1)
        print(f"[{ts_done}] transport-verify: PROCEED")

    project_root = _ROOT
    # Campaign-C flag semantics (2026-04-24):
    #   --no-oranchak            → both sub-blocks off (shorthand,
    #                              reproduces pre-split single-flag behavior)
    #   --no-oranchak-corpora    → community corpora only off
    #   --no-serpentine-anchor   → archive anchor only off
    # Either the shorthand or the specific flag is sufficient to
    # suppress the corresponding sub-block.
    include_oranchak_corpora = not (args.no_oranchak or args.no_oranchak_corpora)
    include_serpentine_anchor = not (args.no_oranchak or args.no_serpentine_anchor)

    # K4Bench mode: kernel overrides were already installed at module
    # import time (see top of file). Now resolve the ledger path so a
    # bench run cannot stomp the real-K4 ledger, suppress real-K4 prompt
    # anchors, and remember the challenge for the attempt artifact emit
    # at completion time.
    bench_challenge = _BENCH_CHALLENGE
    db_default_real = Path("db/theory_ledger.sqlite")
    if bench_challenge is not None:
        from kryptosbot.bench_loader import (
            BenchLoaderError as _BenchLoaderError,
            derive_synthetic_ledger_path,
        )
        # If the user left --db at its default, force the bench default.
        # If they passed an explicit --db, derive_synthetic_ledger_path
        # validates it lives under db/k4bench/ (or carries a bench /
        # synthetic segment) and refuses the real-K4 path outright.
        requested = None if Path(args.db) == db_default_real else Path(args.db)
        try:
            ledger_path = derive_synthetic_ledger_path(
                bench_challenge.bench_id,
                project_root=project_root,
                requested=requested,
            )
        except _BenchLoaderError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(2)
        # Bench prompts must not include real-K4 anchors. Suppressing
        # both Oranchak blocks is structural: their content references
        # K4-shaped fills and the AAA-archive serpentine anchor, which
        # leak K4 cribs (EASTNORTHEAST, BERLINCLOCK) and K4-specific
        # community references into a synthetic-challenge prompt.
        include_oranchak_corpora = False
        include_serpentine_anchor = False
    else:
        ledger_path = Path(args.db)

    # 2026-04-27: HCC controls. ``--no-hcc-seeds`` and ``--hcc-seeds N``
    # both feed the same ``hcc_seeds_cap`` field (0 vs N); the CLI
    # validator already enforced their mutual exclusion. ``--hcc-only``
    # is a separate flag that the controller checks AFTER computing
    # the seed list.
    if args.no_hcc_seeds:
        hcc_seeds_cap = 0
    else:
        hcc_seeds_cap = args.hcc_seeds  # None or positive int

    # 2026-04-28: K4Bench cost-control flags. ``--bench-fast`` is a
    # meta flag that defaults the three sub-flags ON, but each may
    # also be set explicitly. The default redteam-min-crib threshold
    # under --bench-fast is 1 (any positive value causes HCC bypass;
    # the field's intent is "minimum predictive crib_score to spend
    # an LLM red-team call on", and HCC seeds carry no pre-dispatch
    # score so they always fall below the threshold).
    skip_red_team = bool(args.skip_red_team)
    skip_synthesis = bool(args.skip_synthesis) or bool(args.bench_fast)
    skip_lead_pursuit = (
        bool(args.skip_lead_pursuit) or bool(args.bench_fast)
    )
    skip_stat_audit = (
        bool(args.skip_stat_audit) or bool(args.bench_fast)
    )
    deterministic_critic = (
        bool(args.deterministic_critic) or bool(args.bench_fast)
    )
    redteam_min_crib_score = int(args.redteam_min_crib)
    if args.bench_fast and redteam_min_crib_score == 0:
        redteam_min_crib_score = 1

    config = ControllerConfig(
        project_root=project_root,
        ledger_db_path=ledger_path,
        max_cycles=args.cycles,
        theories_per_cycle=args.theories,
        max_concurrent_workers=args.workers,
        worker_timeout_minutes=args.timeout,
        dry_run=args.dry_run,
        skip_critic=args.skip_critic,
        alert_threshold=args.alert_on,
        include_oranchak_corpora=include_oranchak_corpora,
        include_serpentine_anchor=include_serpentine_anchor,
        bench_challenge_payload=(
            bench_challenge.canonical_facts() if bench_challenge else None
        ),
        bench_challenge_prompt_block=(
            bench_challenge.prompt_block() if bench_challenge else None
        ),
        hcc_seeds_cap=hcc_seeds_cap,
        hcc_only=args.hcc_only,
        bench_fast=bool(args.bench_fast),
        skip_red_team=skip_red_team,
        skip_synthesis=skip_synthesis,
        skip_lead_pursuit=skip_lead_pursuit,
        skip_stat_audit=skip_stat_audit,
        deterministic_critic=deterministic_critic,
        redteam_min_crib_score=redteam_min_crib_score,
    )

    if args.status:
        do_status(config)
        return

    if args.summary:
        do_summary(config.ledger_db_path)
        return

    if args.inventory:
        do_inventory(config.ledger_db_path)
        return

    # Redirect stderr to suppress SDK subprocess noise during runs.
    # Restore on exit so interactive shells aren't affected.
    import os
    if args.quiet:
        _devnull_fd = os.open(os.devnull, os.O_WRONLY)
        _saved_stderr_fd = os.dup(2)
        os.dup2(_devnull_fd, 2)
        try:
            await do_run(config)
        finally:
            os.dup2(_saved_stderr_fd, 2)
            os.close(_devnull_fd)
            os.close(_saved_stderr_fd)
    else:
        await do_run(config)

    # Bench mode: emit the attempt artifact JSON so the offline
    # evaluator can score the run against the sealed answer file. The
    # artifact contains nothing the controller hadn't already written
    # to the ledger; it just packages the best candidate(s) into the
    # k4bench.attempts.v1 schema.
    if bench_challenge is not None:
        from kryptosbot.bench_attempts import emit_attempt_artifact

        attempts_out: Path | None = (
            Path(args.bench_attempts_out) if args.bench_attempts_out else None
        )
        try:
            artifact_path = emit_attempt_artifact(
                challenge=bench_challenge,
                ledger_db_path=config.ledger_db_path,
                project_root=project_root,
                output_path=attempts_out,
            )
            print(f"K4Bench: wrote attempt artifact -> {artifact_path}")
        except Exception as exc:  # noqa: BLE001 — boundary, never crash the run
            print(
                f"K4Bench: warning — failed to emit attempt artifact: {exc}",
                file=sys.stderr,
            )


if __name__ == "__main__":
    asyncio.run(main())
