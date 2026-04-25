#!/usr/bin/env python3
"""Launch the kryptosbot controller against a synthetic CT bundle.

Reads a synthetic-bundle manifest produced by ``build_synthetic.py``,
sets ``KRYPTOS_CT_OVERRIDE`` for the controller subprocess, points it
at a fresh per-run DB, and writes a sentinel alongside the DB so
synthetic results can never be confused with real K4 work.

This script does NOT modify kryptosbot's controller code. It's a thin
wrapper that exercises the same controller code path the real-K4
campaigns use, with a different CT loaded into the kernel.

See ``docs/maturation/round3/SYNTHETIC_SIGNAL_CALIBRATION_SPEC.md``.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# Standalone bootstrap (script is 3 dirs deep)
_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)


def _load_manifest(bundle_dir: Path) -> dict:
    manifest_path = bundle_dir / "manifest.json"
    if not manifest_path.exists():
        raise SystemExit(f"No manifest at {manifest_path}. Run build_synthetic.py first.")
    return json.loads(manifest_path.read_text())


def _write_sentinel(db_path: Path, manifest: dict, manifest_path: Path) -> Path:
    """Write a sentinel JSON alongside the DB so any forensic inspection
    immediately reveals this DB carries synthetic results, not real K4."""
    sentinel_path = db_path.with_suffix(".synthetic_mode.json")
    sentinel = {
        "synthetic_mode": True,
        "test_id": manifest["test_id"],
        "manifest_path": str(manifest_path),
        "synthetic_ct": manifest["ct"],
        "mechanism": manifest["mechanism"],
        "launched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "db_path": str(db_path),
        "warning": (
            "This database contains synthetic-mode results from the synthetic-signal "
            "calibration. Results MUST NOT be merged with real K4 campaign results. "
            "See docs/maturation/round3/SYNTHETIC_SIGNAL_CALIBRATION_SPEC.md."
        ),
    }
    sentinel_path.write_text(json.dumps(sentinel, indent=2, sort_keys=True) + "\n")
    return sentinel_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--test-id", required=True,
        help="Test bundle id (e.g., t1_serpentine, t2_defector). Reads "
             "synth_signal/<test_id>/manifest.json.",
    )
    parser.add_argument(
        "--cycles", type=int, default=30,
        help="Max controller cycles (T1 default per spec: 30 → extension 60). "
             "T2 default per spec: 100.",
    )
    parser.add_argument(
        "--theories", type=int, default=5,
        help="Theories per cycle (matches Campaign A/B/C envelope of 5).",
    )
    parser.add_argument(
        "--bundle-dir", default="synth_signal",
        help="Parent directory containing test bundles (default: ./synth_signal).",
    )
    parser.add_argument(
        "--db-dir", default="db",
        help="Directory for the per-run DB (default: ./db).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Verify env-var propagation, sentinel write, controller dry-run; do "
             "not actually run cycles. Use this before any real launch.",
    )
    parser.add_argument(
        "--alert-on", choices=("none", "signal", "breakthrough"), default="signal",
        help="Pass-through to controller --alert-on (default: signal).",
    )
    args = parser.parse_args(argv)

    bundle_dir = Path(args.bundle_dir) / args.test_id
    if not bundle_dir.is_absolute():
        bundle_dir = Path(_ROOT) / bundle_dir

    manifest = _load_manifest(bundle_dir)
    manifest_path = bundle_dir / "manifest.json"

    if manifest["test_id"] != args.test_id:
        raise SystemExit(
            f"Manifest test_id {manifest['test_id']!r} != arg {args.test_id!r}"
        )

    # Build per-run DB path. Always fresh; never reuse.
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    db_dir = Path(args.db_dir)
    if not db_dir.is_absolute():
        db_dir = Path(_ROOT) / db_dir
    db_dir.mkdir(parents=True, exist_ok=True)
    db_path = db_dir / f"synth_{args.test_id}_{timestamp}.sqlite"
    if db_path.exists():
        raise SystemExit(f"DB path collision: {db_path} already exists")

    sentinel_path = _write_sentinel(db_path, manifest, manifest_path)
    print(f"Bundle    : {bundle_dir}")
    print(f"Test id   : {manifest['test_id']}")
    print(f"Mechanism : {manifest['mechanism']['family']} keyword={manifest['mechanism']['period_keyword']!r}")
    print(f"DB        : {db_path}")
    print(f"Sentinel  : {sentinel_path}")
    print(f"Cycles    : {args.cycles}  Theories/cycle: {args.theories}")
    print()

    env = os.environ.copy()
    env["KRYPTOS_CT_OVERRIDE"] = manifest["ct"]
    # Ensure src on path for the subprocess
    env["PYTHONPATH"] = (
        os.path.join(_ROOT, "src")
        + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    )

    cmd = [
        sys.executable, "-u",
        os.path.join(_ROOT, "kryptosbot", "run_controller.py"),
        "--cycles", str(args.cycles),
        "--theories", str(args.theories),
        "--db", str(db_path),
        "--alert-on", args.alert_on,
    ]
    if args.dry_run:
        cmd.append("--dry-run")
        print("DRY-RUN: env-var propagated, sentinel written, "
              "controller invoked with --dry-run flag.")

    print(f"Invoking: {' '.join(cmd)}")
    print(f"Env: KRYPTOS_CT_OVERRIDE={manifest['ct'][:8]}...{manifest['ct'][-8:]}")
    print()
    print("=" * 70)
    print()

    # Stream the controller's output to our stdout
    proc = subprocess.run(cmd, env=env)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
