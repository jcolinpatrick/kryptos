"""CLI entry points for the composition framework.

Provides subcommands: preview, run, report, resume, coverage.
Integrated into the main kryptos CLI via cli/main.py.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List


def cmd_composition_preview(args: argparse.Namespace) -> int:
    """Preview a composition campaign without running it."""
    from kryptos.composition.orchestrator import CampaignPolicy, preview_campaign

    policy = _build_policy(args)
    preview = preview_campaign(policy)

    print(f"Campaign: {policy.name}")
    print(f"Campaign ID: {preview['campaign_id']}")
    print(f"Total compositions: {preview['total_stacks']}")
    print(f"Estimated pruned: {preview['estimated_pruned']}")
    print(f"Estimated to test: {preview['estimated_to_test']}")
    print(f"\nFamily breakdown:")
    for key, count in sorted(preview["families"].items()):
        print(f"  {key}: {count}")
    print(f"\nPolicy: {json.dumps(preview['policy'], indent=2)}")
    return 0


def cmd_composition_run(args: argparse.Namespace) -> int:
    """Run a composition campaign."""
    from kryptos.composition.orchestrator import CampaignPolicy, run_campaign

    policy = _build_policy(args)

    if hasattr(args, "workers") and args.workers:
        policy.workers = args.workers
    if hasattr(args, "force") and args.force:
        policy.force = True
    if hasattr(args, "beam_width") and args.beam_width:
        policy.beam_width = args.beam_width
    if hasattr(args, "threshold") and args.threshold is not None:
        policy.score_threshold = args.threshold
    if hasattr(args, "aggressive") and args.aggressive:
        policy.aggressive_pruning = True

    summary = run_campaign(policy)
    return 0 if summary.get("tested", 0) >= 0 else 1


def cmd_composition_report(args: argparse.Namespace) -> int:
    """Report on composition campaign results."""
    from kryptos.composition.ledger import CompositionLedger

    db_path = getattr(args, "db", "db/composition_ledger.sqlite")
    campaign_id = getattr(args, "campaign_id", None)
    limit = getattr(args, "limit", 20)
    min_score = getattr(args, "min_score", 0)

    ledger = CompositionLedger(db_path)

    if campaign_id:
        summary = ledger.campaign_summary(campaign_id)
        if summary:
            print(f"Campaign: {summary.get('name', '?')}")
            print(f"  Status:     {summary.get('status', '?')}")
            print(f"  Total:      {summary.get('total_branches', 0)}")
            print(f"  Tested:     {summary.get('tested_branches', 0)}")
            print(f"  Pruned:     {summary.get('pruned_branches', 0)}")
            print(f"  Best score: {summary.get('best_score', 0)}")
            print(f"  Started:    {summary.get('started_at', '?')}")
            print()

    # Top results
    results = ledger.top_results(limit=limit, min_score=min_score,
                                 campaign_id=campaign_id)
    if results:
        print(f"Top {len(results)} results (score >= {min_score}):")
        print("-" * 70)
        for r in results:
            score = r.get("score", 0)
            bean = "Y" if r.get("bean_pass") else "N"
            ic_val = r.get("ic_value", 0.0) or 0.0
            pt = r.get("plaintext", "")
            pt_preview = pt[:50] + "..." if len(pt) > 50 else pt
            print(f"  Score: {score:3d}  Bean: {bean}  IC: {ic_val:.4f}  {pt_preview}")
    else:
        print("No results found.")

    ledger.close()
    return 0


def cmd_composition_coverage(args: argparse.Namespace) -> int:
    """Show coverage statistics across composition families."""
    from kryptos.composition.ledger import CompositionLedger

    db_path = getattr(args, "db", "db/composition_ledger.sqlite")
    campaign_id = getattr(args, "campaign_id", None)

    ledger = CompositionLedger(db_path)

    # List campaigns
    campaigns = ledger.all_campaigns()
    if campaigns:
        print("Campaigns:")
        for c in campaigns:
            print(
                f"  [{c.get('status', '?'):8s}] {c.get('name', '?'):<30s} "
                f"tested={c.get('tested_branches', 0)} "
                f"pruned={c.get('pruned_branches', 0)} "
                f"best={c.get('best_score', 0)}"
            )
        print()

    # Coverage by family
    coverage = ledger.coverage_by_family(campaign_id)
    if coverage:
        print("Coverage by family+order:")
        current_key = ""
        for row in coverage:
            key = row["campaign_key"]
            if key != current_key:
                if current_key:
                    print()
                current_key = key
                print(f"  {key}:")
            print(f"    {row['status']:10s}: {row['count']}")
    else:
        print("No coverage data.")

    # Pruning summary
    pruning = ledger.pruning_summary(campaign_id)
    if pruning:
        print(f"\nPruning breakdown:")
        for ptype, count in sorted(pruning.items()):
            print(f"  {ptype}: {count}")

    # Open branches
    open_count = len(ledger.open_branches(campaign_id, limit=10000))
    print(f"\nOpen (untested) branches: {open_count}")

    ledger.close()
    return 0


def _build_policy(args: argparse.Namespace) -> "CampaignPolicy":
    """Build a CampaignPolicy from CLI args."""
    from kryptos.composition.orchestrator import CampaignPolicy

    if hasattr(args, "policy_file") and args.policy_file:
        with open(args.policy_file) as f:
            data = json.load(f)
        return CampaignPolicy.from_dict(data)

    # Build from individual args
    kwargs: Dict[str, Any] = {}

    if hasattr(args, "name") and args.name:
        kwargs["name"] = args.name
    if hasattr(args, "outer") and args.outer:
        kwargs["outer_families"] = args.outer
    if hasattr(args, "inner") and args.inner:
        kwargs["inner_families"] = args.inner
    if hasattr(args, "peel_orders") and args.peel_orders:
        kwargs["peel_orders"] = args.peel_orders
    if hasattr(args, "workers") and args.workers:
        kwargs["workers"] = args.workers
    if hasattr(args, "db") and args.db:
        kwargs["db_path"] = args.db

    return CampaignPolicy(**kwargs)


def add_composition_subparser(subparsers: Any) -> None:
    """Add the 'composition' subcommand tree to the main CLI parser."""
    comp_p = subparsers.add_parser(
        "composition",
        help="Multi-layer composition search framework",
    )
    comp_sub = comp_p.add_subparsers(dest="comp_cmd")

    # Common args
    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--name", default="default", help="Campaign name")
        p.add_argument("--outer", nargs="+", default=["additive_mask"],
                       help="Outer layer families")
        p.add_argument("--inner", nargs="+", default=["identity"],
                       help="Inner layer families")
        p.add_argument("--peel-orders", nargs="+", default=["outer_first"],
                       choices=["outer_first", "inner_first"],
                       help="Peel orders to test")
        p.add_argument("--db", default="db/composition_ledger.sqlite",
                       help="Ledger database path")
        p.add_argument("--policy-file", help="JSON policy file (overrides other args)")

    # preview
    preview_p = comp_sub.add_parser("preview", help="Preview campaign without running")
    add_common(preview_p)

    # run
    run_p = comp_sub.add_parser("run", help="Run a composition campaign")
    add_common(run_p)
    run_p.add_argument("--workers", type=int, default=1,
                       help="Number of parallel workers")
    run_p.add_argument("--force", action="store_true",
                       help="Ignore checkpoints, rerun all")
    run_p.add_argument("--beam-width", type=int, default=0,
                       help="Max branches to test (0=unlimited)")
    run_p.add_argument("--threshold", type=int, default=None,
                       help="Minimum score to store detailed results")
    run_p.add_argument("--aggressive", action="store_true",
                       help="Enable heuristic pruning")

    # report
    report_p = comp_sub.add_parser("report", help="Show campaign results")
    report_p.add_argument("--db", default="db/composition_ledger.sqlite")
    report_p.add_argument("--campaign-id", help="Filter to specific campaign")
    report_p.add_argument("--limit", type=int, default=20)
    report_p.add_argument("--min-score", type=int, default=0)

    # coverage
    cov_p = comp_sub.add_parser("coverage", help="Show coverage statistics")
    cov_p.add_argument("--db", default="db/composition_ledger.sqlite")
    cov_p.add_argument("--campaign-id", help="Filter to specific campaign")
