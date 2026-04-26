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

# Ensure repo root (for kryptosbot package) and src (for kernel) are on path
_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.controller import ControllerConfig, ResearchController
from kryptosbot.theory_ledger import TheoryLedger
from kryptosbot import display


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
    return parser.parse_args()


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


async def do_run(config: ControllerConfig) -> None:
    """Run the controller with formatted console output."""
    controller = ResearchController(config)

    from kryptosbot.registries import bootstrap_all
    from kryptosbot.models import TheoryStatus, CriticDecision

    # Bootstrap registries
    bootstrap_result = bootstrap_all(controller.ledger, config.project_root)
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

    # Startup banner
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
    )

    total_max = controller.state.cycle_number + config.max_cycles

    for cycle_idx in range(config.max_cycles):
        controller.state.cycle_number += 1
        from datetime import datetime, timezone
        controller.state.last_cycle_at = datetime.now(timezone.utc).isoformat()
        controller._begin_cycle_phase_state()  # Day 5: reset per-cycle dicts

        display.print_cycle_header(controller.state.cycle_number, total_max)

        try:
            # Step 1: Landscape
            landscape = controller._assess_landscape()
            display.print_landscape(landscape)

            # Step 2: Generate
            display.print_generation_start()
            candidates = await controller._generate_theories(
                landscape, on_progress=display.print_theorist_event,
            )

            if not candidates:
                if controller.should_abort_run():
                    display.print_run_halt(
                        controller.fatal_agent_error or "fatal agent failure",
                    )
                    break
                display.print_no_candidates()
                continue

            display.print_candidates_generated(len(candidates))

            # Step 3: Critic
            display.print_critic_start()
            approved = []
            for theory in candidates:
                if config.skip_critic:
                    theory.status = TheoryStatus.APPROVED
                    approved.append(theory)
                    display.print_critic_result(theory.title, "approve", 1.0, "")
                else:
                    verdict = controller.critic.evaluate(theory)
                    theory.critic_verdict = verdict
                    theory.status = (
                        TheoryStatus.APPROVED
                        if verdict.decision == CriticDecision.APPROVE
                        else TheoryStatus.CRITICIZED
                    )
                    controller.ledger.upsert_theory(theory)

                    if verdict.decision == CriticDecision.APPROVE:
                        approved.append(theory)

                    display.print_critic_result(
                        theory.title,
                        verdict.decision.value,
                        verdict.confidence,
                        verdict.reasons[0] if verdict.reasons else "",
                    )

            display.print_critic_summary(len(approved), len(candidates))

            # Day 6: close any open pursuit lead whose lead_id is
            # referenced in an approved theory's tags via the
            # "pursuit_lead:<id>" convention. Best-effort bookkeeping.
            controller._close_referenced_pursuit_leads(approved)

            if not approved:
                continue

            # Step 3b: Red-team pre-check (Day 3 Pantheon integration)
            # Sibling call to red-team-disprover for each approved theory
            # before workers are dispatched. See
            # controller._red_team_filter for the rationale.
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
                    # (survivors, total, rejected, concerned, errors)
                    # so the display can distinguish PASS / CONCERNED /
                    # REJECT / ERROR. Older 3-tuple form still tolerated.
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
                    # Brief notice that the phase was bypassed
                    pass  # nothing to render; logger.info covers it

            approved = await controller._red_team_filter(
                approved, on_progress=_redteam_progress,
            )

            if not approved:
                continue

            if config.dry_run:
                display.print_dry_run_skip()
                continue

            # Step 4: Dispatch
            display.print_dispatch_header(len(approved))
            outcomes = await controller._dispatch_theories(
                approved, on_worker_message=display.print_worker_event,
            )
            display.print_dispatch_footer()
            display.print_outcome_summary(outcomes)

            # Step 5: Absorb
            controller._absorb_outcomes(outcomes)

            # Step 5c: Day 5 — statistical-auditor post-execution review
            # for any contract with kernel-verified crib_score >= 18.
            # Populates controller._cycle_stat_audit_verdicts which
            # _run_alerts consumes to gate signal-level alerts.
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

            try:
                await controller._stat_audit_filter(
                    approved, outcomes, on_progress=_stat_audit_progress,
                )
            except Exception as exc:
                display.print_cycle_error(controller.state.cycle_number, exc)

            # Step 5b: Contradiction-detector alerts (honors the stat-audit gate)
            controller._run_alerts(approved, outcomes)

            # Step 5b'. Campaign-A hardening (2026-04-22): runtime halt
            # counters. Mirrors controller.run's hook per
            # feedback_dup_cycle_loop_trap — both cycle loops must patch
            # or the TUI-driven path drifts silently while the library-
            # driven path halts.
            hardening_reason = controller._check_cycle_hardening_halts(
                candidates=candidates,
                outcomes=outcomes,
                triggered_alerts=controller._cycle_alert_events,
            )
            if hardening_reason:
                # TUI rendering happens via display.print_run_halt below
                # after persist + synthesis. Log inline so -q mode users
                # still see the reason in the log stream.
                import logging
                logging.getLogger("kryptosbot.controller").warning(
                    "Campaign-A hardening halt: %s", hardening_reason,
                )

            # Step 5d: Day 6 — lead-pursuit evaluator for sub-signal
            # (6-17) contracts. Best-effort; never blocks the cycle.
            # Opens PursuitLead rows in the ledger for each "pursue"
            # verdict so the next cycle's theorist sees them as
            # priority context.
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

            try:
                await controller._run_lead_pursuit(
                    approved, outcomes, on_progress=_pursuit_progress,
                )
            except Exception as exc:
                display.print_cycle_error(controller.state.cycle_number, exc)

            # Step 6: Persist
            controller._update_state_counts()
            controller.ledger.save_controller_state(controller.state)
            controller.ledger.refresh_family_stats()

            # Step 6b: Day 5 — end-of-cycle results synthesis. Best-effort;
            # never blocks the cycle. Result is written to
            # controller._last_synthesis where the next cycle's
            # _assess_landscape can render it for the theorist.
            def _synthesis_progress(event: str, detail: Any) -> None:
                if event == "start":
                    agent_name, model = detail
                    display.print_synthesis_start(agent_name, model)
                elif event == "result":
                    display.print_synthesis_result(detail)
                elif event == "skipped":
                    display.print_synthesis_skipped(str(detail))

            try:
                await controller._run_synthesis(
                    approved, outcomes, on_progress=_synthesis_progress,
                )
            except Exception as exc:
                display.print_cycle_error(controller.state.cycle_number, exc)

        except Exception as exc:
            display.print_cycle_error(controller.state.cycle_number, exc)
            controller.ledger.save_controller_state(controller.state)

        # Campaign-A hardening (2026-04-22): break after persist +
        # synthesis if any halt condition tripped this (or a prior)
        # cycle. Uses the existing display.print_run_halt surface so the
        # TUI output matches the fatal-agent-failure halt already wired
        # at generate-time above.
        if controller.state.halt_reason_hardening:
            display.print_run_halt(controller.state.halt_reason_hardening)
            break

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

    config = ControllerConfig(
        project_root=project_root,
        ledger_db_path=Path(args.db),
        max_cycles=args.cycles,
        theories_per_cycle=args.theories,
        max_concurrent_workers=args.workers,
        worker_timeout_minutes=args.timeout,
        dry_run=args.dry_run,
        skip_critic=args.skip_critic,
        alert_threshold=args.alert_on,
        include_oranchak_corpora=include_oranchak_corpora,
        include_serpentine_anchor=include_serpentine_anchor,
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


if __name__ == "__main__":
    asyncio.run(main())
