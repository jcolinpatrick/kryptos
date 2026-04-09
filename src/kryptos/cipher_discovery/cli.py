"""CLI entry point for cipher discovery subsystem.

Usage:
    PYTHONPATH=src python3 -m kryptos.cipher_discovery.cli discover
    PYTHONPATH=src python3 -m kryptos.cipher_discovery.cli report
    PYTHONPATH=src python3 -m kryptos.cipher_discovery.cli status
    PYTHONPATH=src python3 -m kryptos.cipher_discovery.cli query <term>
    PYTHONPATH=src python3 -m kryptos.cipher_discovery.cli review
"""
from __future__ import annotations

import argparse
import json
import logging
import sys

from .config import DiscoveryConfig
from .persistence import DiscoveryDB
from .pipeline import run_discovery_pipeline
from .reporting import generate_markdown_report, generate_json_report


def cmd_discover(args):
    """Run full discovery pipeline."""
    config = DiscoveryConfig(db_path=args.db)
    stats = run_discovery_pipeline(config, exhaustion_log_path=args.exhaustion_log)
    print(json.dumps(stats, indent=2))


def cmd_report(args):
    """Generate discovery report."""
    config = DiscoveryConfig(db_path=args.db)
    db = DiscoveryDB(config.db_path)
    try:
        records = db.get_all_ciphers()
        stats = db.get_stats()
    finally:
        db.close()

    if not records:
        print("No records in database. Run 'discover' first.")
        return

    if args.format == "json":
        report = generate_json_report(records, stats, args.output)
        if not args.output:
            print(json.dumps(report, indent=2, default=str))
    else:
        report = generate_markdown_report(records, stats, args.output)
        if not args.output:
            print(report)

    if args.output:
        print(f"Report written to {args.output}")


def cmd_status(args):
    """Show pipeline status."""
    config = DiscoveryConfig(db_path=args.db)
    db = DiscoveryDB(config.db_path)
    try:
        stats = db.get_stats()
    finally:
        db.close()
    print(json.dumps(stats, indent=2))


def cmd_query(args):
    """Search the knowledge base."""
    config = DiscoveryConfig(db_path=args.db)
    db = DiscoveryDB(config.db_path)
    try:
        results = db.search_ciphers(args.term)
    finally:
        db.close()

    if not results:
        print(f"No results for '{args.term}'")
        return

    for rec in results:
        status = "UNTESTED" if not rec.tested_in_project else rec.exhaustion_status.upper()
        print(f"  [{status}] {rec.canonical_name} (K4={rec.k4_relevance_score:.1f}, "
              f"obscurity={rec.obscurity_score:.2f})")
        if rec.alias_names:
            print(f"    Aliases: {', '.join(rec.alias_names[:5])}")
        if rec.description:
            print(f"    {rec.description[:120]}...")
        print()


def cmd_review(args):
    """Show human review queue."""
    config = DiscoveryConfig(db_path=args.db)
    db = DiscoveryDB(config.db_path)
    try:
        queue = db.get_review_queue()
    finally:
        db.close()

    if not queue:
        print("Review queue is empty.")
        return

    for item in queue:
        print(f"  [{item['status']}] {item['record_id_a']} <-> {item['record_id_b']}")
        print(f"    Reason: {item['reason']}")
        print()


def main():
    parser = argparse.ArgumentParser(
        prog="cipher_discovery",
        description="Cipher discovery subsystem for Kryptos K4",
    )
    parser.add_argument("--db", default="db/cipher_discovery.sqlite",
                        help="Database path")
    parser.add_argument("--exhaustion-log", default="exhaustion_log.json",
                        help="Path to exhaustion log")

    sub = parser.add_subparsers(dest="command")

    # discover
    sub.add_parser("discover", help="Run full discovery pipeline")

    # report
    p_report = sub.add_parser("report", help="Generate findings report")
    p_report.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p_report.add_argument("--output", "-o", help="Output file path")

    # status
    sub.add_parser("status", help="Show pipeline status")

    # query
    p_query = sub.add_parser("query", help="Search knowledge base")
    p_query.add_argument("term", help="Search term")

    # review
    sub.add_parser("review", help="Show human review queue")

    args = parser.parse_args()

    if args.command == "discover":
        cmd_discover(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "status":
        cmd_status(args)
    elif args.command == "query":
        cmd_query(args)
    elif args.command == "review":
        cmd_review(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    main()
