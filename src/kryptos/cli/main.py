"""Main CLI entry point for the Kryptos research suite.

Usage:
    kryptos doctor              — Run environment checks
    kryptos sweep <config>      — Run a sweep campaign
    kryptos reproduce <manifest> — Reproduce a prior run
    kryptos novelty generate    — Generate new hypotheses
    kryptos novelty triage      — Triage pending hypotheses
    kryptos novelty status      — Show novelty engine status
    kryptos report <db> top     — Show top results from a database
"""
from __future__ import annotations

import argparse
import sys


def cmd_doctor(args: argparse.Namespace) -> int:
    from kryptos.cli.doctor import run_doctor
    return 0 if run_doctor(verbose=True) else 1


def cmd_sweep(args: argparse.Namespace) -> int:
    from kryptos.kernel.config import SweepConfig
    config = SweepConfig.from_toml(args.config)
    if hasattr(args, "workers") and args.workers:
        config_dict = config.to_dict()
        config_dict["workers"] = args.workers
        config = SweepConfig.from_dict(config_dict)

    print(f"Sweep config loaded: {config.name}")
    print(f"Run ID: {config.run_id}")
    print("Sweep execution delegated to pipeline.runners.SweepRunner")
    return 0


def cmd_reproduce(args: argparse.Namespace) -> int:
    from kryptos.cli.reproduce import reproduce_run
    return reproduce_run(args.manifest)


def cmd_novelty_generate(args: argparse.Namespace) -> int:
    from kryptos.novelty.generators import all_generators
    from kryptos.novelty.ledger import NoveltyLedger

    print("Generating hypotheses...")
    hypotheses = list(all_generators())
    print(f"Generated {len(hypotheses)} hypotheses.")

    with NoveltyLedger() as ledger:
        new_count = 0
        for hyp in hypotheses:
            if not ledger.already_tested(hyp.hypothesis_id):
                ledger.record(hyp)
                new_count += 1
        ledger.conn.commit()
        ledger.update_rq_coverage()

    print(f"Recorded {new_count} new hypotheses ({len(hypotheses) - new_count} already known).")
    return 0


def cmd_novelty_triage(args: argparse.Namespace) -> int:
    from kryptos.novelty.ledger import NoveltyLedger
    from kryptos.novelty.triage import triage_batch
    from kryptos.novelty.hypothesis import Hypothesis, HypothesisStatus, ResearchQuestion
    import json

    with NoveltyLedger() as ledger:
        # Get untriaged hypotheses
        cursor = ledger.conn.execute(
            "SELECT * FROM hypotheses WHERE status = 'proposed' "
            "ORDER BY priority_score DESC LIMIT ?",
            (args.limit if hasattr(args, "limit") else 100,),
        )
        cols = [d[0] for d in cursor.description]
        rows = [dict(zip(cols, row)) for row in cursor.fetchall()]

        if not rows:
            print("No hypotheses pending triage.")
            return 0

        print(f"Triaging {len(rows)} hypotheses...")

        # Convert to Hypothesis objects
        hypotheses: list[Hypothesis] = []
        for row in rows:
            rq_raw = json.loads(row.get("research_questions") or "[]")
            rqs = []
            for rq in rq_raw:
                try:
                    rqs.append(ResearchQuestion(rq) if isinstance(rq, str) else rq)
                except ValueError:
                    pass
            hyp = Hypothesis(
                description=row["description"],
                transform_stack=json.loads(row["transform_stack"] or "[]"),
                research_questions=rqs,
                triage_score=row.get("triage_score", 0.0),
                provenance=row.get("provenance", ""),
                tags=json.loads(row.get("tags") or "[]"),
            )
            hyp.created_at = row.get("created_at", "")
            hypotheses.append(hyp)

        # Run triage
        triaged = triage_batch(hypotheses)

        # Update ledger
        for hyp in triaged:
            ledger.record(hyp)
        ledger.update_rq_coverage()

        # Summary
        promoted = sum(1 for h in triaged if h.status == HypothesisStatus.PROMOTED)
        eliminated = sum(1 for h in triaged if h.status == HypothesisStatus.ELIMINATED)
        print(f"Results: {promoted} promoted, {eliminated} eliminated, "
              f"{len(triaged) - promoted - eliminated} triaged")

    return 0


def cmd_novelty_status(args: argparse.Namespace) -> int:
    from kryptos.novelty.ledger import NoveltyLedger

    with NoveltyLedger() as ledger:
        summary = ledger.summary()
        coverage = ledger.get_rq_coverage()
        underexplored = ledger.get_underexplored_rqs()

    print("Novelty Engine Status")
    print("=" * 50)
    print("\nHypothesis counts by status:")
    for status, count in sorted(summary.items()):
        print(f"  {status:15s}: {count}")

    if coverage:
        print("\nResearch Question Coverage:")
        for rq, stats in sorted(coverage.items()):
            total = stats.get("total_hypotheses", 0)
            elim = stats.get("eliminated", 0)
            surv = stats.get("survived", 0)
            prom = stats.get("promoted", 0)
            print(f"  {rq}: {total} total ({elim} elim, {surv} surv, {prom} prom)")

    if underexplored:
        print(f"\nUnder-explored RQs (< 10 hypotheses): {', '.join(underexplored)}")

    return 0


def cmd_report_top(args: argparse.Namespace) -> int:
    from kryptos.kernel.persistence.sqlite import Database

    db = Database(args.db)
    results = db.top_results(
        limit=args.limit if hasattr(args, "limit") else 20,
        min_score=args.min_score if hasattr(args, "min_score") else 0,
    )
    db.close()

    if not results:
        print("No results found.")
        return 0

    print(f"Top {len(results)} results from {args.db}:")
    print("-" * 60)
    for r in results:
        score = r.get('score')
        score_str = f"{score:3d}" if isinstance(score, int) else "  ?"
        print(f"  Score: {score_str}  "
              f"Bean: {'Y' if r.get('bean_pass') else 'N'}  "
              f"Exp: {r.get('experiment_id', '?')}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="kryptos",
        description="Kryptos K4 Cryptanalysis Research Suite",
    )
    sub = parser.add_subparsers(dest="command")

    # doctor
    sub.add_parser("doctor", help="Run environment checks")

    # sweep
    sweep_p = sub.add_parser("sweep", help="Run a sweep campaign")
    sweep_p.add_argument("config", help="Path to TOML config file")
    sweep_p.add_argument("--workers", type=int, help="Number of worker processes")
    sweep_p.add_argument("--force", action="store_true", help="Force re-run")

    # reproduce
    repro_p = sub.add_parser("reproduce", help="Reproduce a prior run")
    repro_p.add_argument("manifest", help="Path to run manifest JSON")

    # novelty
    novelty_p = sub.add_parser("novelty", help="Novelty engine commands")
    novelty_sub = novelty_p.add_subparsers(dest="novelty_cmd")
    novelty_sub.add_parser("generate", help="Generate new hypotheses")
    triage_p = novelty_sub.add_parser("triage", help="Triage pending hypotheses")
    triage_p.add_argument("--limit", type=int, default=100, help="Max hypotheses to triage")
    novelty_sub.add_parser("status", help="Show novelty engine status")

    # report
    report_p = sub.add_parser("report", help="Report on results")
    report_p.add_argument("db", help="Path to SQLite database")
    report_p.add_argument("action", choices=["top", "summary"], help="Report action")
    report_p.add_argument("--limit", type=int, default=20)
    report_p.add_argument("--min-score", type=int, default=0)

    args = parser.parse_args()

    if args.command == "doctor":
        return cmd_doctor(args)
    elif args.command == "sweep":
        return cmd_sweep(args)
    elif args.command == "reproduce":
        return cmd_reproduce(args)
    elif args.command == "novelty":
        if args.novelty_cmd == "generate":
            return cmd_novelty_generate(args)
        elif args.novelty_cmd == "triage":
            return cmd_novelty_triage(args)
        elif args.novelty_cmd == "status":
            return cmd_novelty_status(args)
        else:
            novelty_p.print_help()
            return 1
    elif args.command == "report":
        if args.action == "top":
            return cmd_report_top(args)
        else:
            print("Summary not yet implemented")
            return 1
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
