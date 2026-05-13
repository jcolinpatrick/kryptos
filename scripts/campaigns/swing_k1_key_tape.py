"""CLI entry point for Swing K-1 keystream-recovery campaign.

Design and execution plan tracked in internal project notes.

Examples
--------
  PYTHONPATH=src python3 scripts/campaigns/swing_k1_key_tape.py --help
  PYTHONPATH=src python3 scripts/campaigns/swing_k1_key_tape.py --dry-run --max-configs 100 \\
      --out-dir analysis_runs/key_tape_m2_m5_smoke_$(date +%s)
  PYTHONPATH=src python3 scripts/campaigns/swing_k1_key_tape.py --execute-full \\
      --out-dir analysis_runs/key_tape_m2_m5_2026_05_11 --n-workers 24
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="swing_k1: key_tape M2..M5 keystream-recovery runner")
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true",
                      help="Bounded run with --max-configs; serial; for verification")
    mode.add_argument("--execute-full", action="store_true",
                      help="Run the full preregistered universe under parallel pool")
    p.add_argument("--out-dir", type=Path, required=True)
    p.add_argument("--max-configs", type=int, default=None)
    p.add_argument("--only-m1", action="store_true",
                   help="Restrict to M1 control-arm configs (6 total). For instrumentation.")
    p.add_argument("--n-workers", type=int, default=24)
    p.add_argument("--per-task-timeout-sec", type=float, default=60.0)
    args = p.parse_args(argv)

    from kryptosbot.swing_k1_runner import run_parallel, run_serial

    if args.dry_run:
        summary = run_serial(
            out_dir=args.out_dir,
            max_configs=args.max_configs,
            only_m1=args.only_m1,
        )
    else:
        summary = run_parallel(
            out_dir=args.out_dir,
            max_configs=args.max_configs,
            only_m1=args.only_m1,
            n_workers=args.n_workers,
            per_task_timeout_sec=args.per_task_timeout_sec,
        )
    print(f"Swing K-1 complete. Summary:")
    for k, v in summary.items():
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
