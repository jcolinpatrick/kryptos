#!/usr/bin/env python3
"""CT-Perturbation Stage B — campaign runner stub.

Status: STUB v0.1 (2026-05-04). The full Stage B runner is deferred per
``docs/campaigns/ct_perturbation_stage_b_prereg.md``: operator must
supply the predeclared ambiguous-position set (`§3`) and a separate
brainstorm/plan/build cycle is required for the full sweep harness
(see Stage A's ``ct_perturbation_stage_a.py``, 1836 lines, as the
reference scope).

What this stub does:
    - Validates the ``--ambiguous-positions PATH`` JSON manifest using
      the framework's ``load_ambiguous_positions`` schema validator.
    - Computes the Stage B universe size for the supplied ``A``.
    - Refuses ``--execute-full`` until the full runner v1 is built,
      with a clean instructive message pointing to the prereg.
    - Runs the synthetic-recovery probe in dry-run mode (loads
      manifests, exits cleanly) so personas can validate their
      Stage B specs before requesting full execution.

What this stub does NOT do:
    - It does not enumerate H2 variants and execute them. That requires
      the v1 runner with worker pool, checkpointing, JSONL writer, and
      Bonferroni-aware p-value gating per prereg §5.
    - It does not implement synthetic recovery (§7.1, §7.2) end-to-end.
      The probe is wired but only validates I/O contracts.

Why this stub exists:
    Without it, kryptosbot personas that propose Stage B specs hit
    ``inconclusive`` results with "infrastructure missing" notes, which
    pollutes the ledger and wastes worker cycles. With this stub, they
    instead get a deterministic exit code + clear message that maps to
    a recognizable rejection class.

Exit codes:
    0  manifest validated, dry-run summary printed
    2  configuration error (missing arg, schema invalid, k>20, etc.)
    3  ``--execute-full`` requested but full runner not yet implemented

Usage:
    PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_b.py \\
        --ambiguous-positions PATH/TO/A.json \\
        [--allow-large-ambiguous-set] \\
        [--dry-run]

The full runner v1 must be specified separately (brainstorm + writing-plans
+ subagent-driven build) before ``--execute-full`` is supported.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Standalone bootstrap (script lives 2 levels deep under repo root).
_HERE = Path(__file__).resolve()
_ROOT = _HERE.parent.parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


from kryptosbot.ct_perturbation import (  # noqa: E402
    AmbiguousPositionsManifest,
    load_ambiguous_positions,
    stage_b_universe_size,
)


_K_MAX_DEFAULT = 20  # prereg §3.3
_PREREG_PATH = "docs/campaigns/ct_perturbation_stage_b_prereg.md"


def _build_argparser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description=(
            "CT-Perturbation Stage B — STUB v0.1. Full runner deferred. "
            "See docs/campaigns/ct_perturbation_stage_b_prereg.md."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "--ambiguous-positions",
        type=Path,
        required=True,
        help=(
            "Path to operator-predeclared ambiguous-position JSON. "
            "Schema: ct_perturbation_stage_b.ambiguous_positions.v1. "
            "See prereg §3.2."
        ),
    )
    ap.add_argument(
        "--allow-large-ambiguous-set",
        action="store_true",
        help=f"Permit |A| > {_K_MAX_DEFAULT} (default refuses).",
    )
    ap.add_argument(
        "--keyword-count",
        type=int,
        default=719,
        help="Keyword pool size for universe-size estimation (default 719).",
    )
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate manifest and print summary; do not attempt execution.",
    )
    ap.add_argument(
        "--execute-full",
        action="store_true",
        help=(
            "Reserved for v1 runner; in this stub, exits with code 3 and "
            "instructions for the v1 build."
        ),
    )
    return ap


def _print_summary(manifest: AmbiguousPositionsManifest, n_keywords: int) -> None:
    universe = stage_b_universe_size(manifest, n_keywords=n_keywords)
    k = len(manifest.positions)
    print()
    print("=" * 72)
    print("  CT-Perturbation Stage B — manifest validated")
    print("=" * 72)
    print(f"  schema_version:      {manifest.schema_version}")
    print(f"  primary_source:      {manifest.archive_provenance.get('primary_source', '(unset)')}")
    print(f"  evaluator:           {manifest.archive_provenance.get('evaluator', '(unset)')}")
    print(f"  evaluation_date:     {manifest.archive_provenance.get('evaluation_date', '(unset)')}")
    print(f"  k = |A|:             {k}")
    print(f"  positions:           {sorted(manifest.positions)}")
    print()
    print("  Universe sizing (per prereg §3.3):")
    for key, value in universe.items():
        if isinstance(value, int):
            print(f"    {key:30s} {value:>15,}")
        else:
            print(f"    {key:30s} {value}")
    print()
    print("=" * 72)
    print("  Status: STUB v0.1 — full runner not yet built.")
    print(f"  See {_PREREG_PATH} for full campaign spec.")
    print("=" * 72)
    print()


def main(argv: list[str] | None = None) -> int:
    args = _build_argparser().parse_args(argv)

    if not args.ambiguous_positions.exists():
        print(
            f"ERROR: --ambiguous-positions path does not exist: "
            f"{args.ambiguous_positions}",
            file=sys.stderr,
        )
        print(
            f"\nStage B requires an operator-predeclared ambiguous-position "
            f"set per prereg §3.\nSee {_PREREG_PATH} for the schema.",
            file=sys.stderr,
        )
        return 2

    try:
        manifest = load_ambiguous_positions(args.ambiguous_positions)
    except (ValueError, json.JSONDecodeError) as e:
        print(
            f"ERROR: --ambiguous-positions failed schema validation: {e}",
            file=sys.stderr,
        )
        print(
            f"\nSee {_PREREG_PATH} §3.2 for the v1 schema and §3.1 for the "
            f"operator-decision contract.",
            file=sys.stderr,
        )
        return 2

    k = len(manifest.positions)
    if k > _K_MAX_DEFAULT and not args.allow_large_ambiguous_set:
        print(
            f"ERROR: |A| = {k} exceeds k_max_default = {_K_MAX_DEFAULT}; "
            f"pass --allow-large-ambiguous-set to override.",
            file=sys.stderr,
        )
        print(
            f"\nLarger archive evidence sets monotonically increase the "
            f"search universe; see prereg §3.3 cardinality table.",
            file=sys.stderr,
        )
        return 2

    _print_summary(manifest, n_keywords=args.keyword_count)

    if args.execute_full:
        print(
            "\nERROR: --execute-full is not supported in this stub (v0.1).",
            file=sys.stderr,
        )
        print(
            "\nThe full Stage B runner is a separate project requiring its "
            "own brainstorm/plan/build cycle (Stage A's runner is 1836 "
            f"lines; Stage B will be similar). See {_PREREG_PATH} §9 for "
            "the binding CLI spec.",
            file=sys.stderr,
        )
        print(
            "\nUntil then, this stub validates manifests and reports universe "
            "sizes only.",
            file=sys.stderr,
        )
        return 3

    return 0


if __name__ == "__main__":
    sys.exit(main())
