#!/usr/bin/env python3
"""Build all standard null-baseline distributions.

Framework maturation Phase 6 (2026-04-21). Run once per kernel commit
that materially changes the scoring paths. Rebuild is cheap for
crib_score (sub-second per 100K samples) and modest for ngram_score
(~minute). Full-distribution files land gitignored under
``results/null_baselines/``; the manifest summary lands at
``null_baselines/manifest.json`` which IS committed.

Usage:
    PYTHONPATH=src python3 scripts/_infra/calibrate_null_baselines.py
    PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py --quick
    PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py --only crib_score
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
if str(_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_ROOT / "src"))
# kryptosbot/ lives at repo root (not under src/), so it needs a separate
# path entry for the script to import the null_baselines module.
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from kryptosbot.null_baselines import (
    _KERNEL_COMMIT,
    _MANIFEST_PATH,
    build_null_distribution,
    save_to_cache,
)


# Standard coverage matrix. Keep this list small so rebuilds stay
# checkpointable. The Phase-6 acceptance criterion is that the manifest
# contains entries for (crib_score, ngram_score) × (random_text,
# shuffled_ct) × AZ × n=97.
_STANDARD_JOBS: list[dict] = [
    {"scorer_name": "crib_score",  "method": "random_text",  "alphabet": "AZ"},
    {"scorer_name": "crib_score",  "method": "shuffled_ct",  "alphabet": "AZ"},
    {"scorer_name": "ngram_score", "method": "random_text",  "alphabet": "AZ"},
    {"scorer_name": "ngram_score", "method": "shuffled_ct",  "alphabet": "AZ"},
    {"scorer_name": "crib_score",  "method": "matched_variant_family",
     "alphabet": "AZ"},
]

# Quick-mode sample counts (for smoke / CI).  Full run uses 100_000 for
# crib_score (fast) and 50_000 for ngram_score (slower).
_DEFAULT_SAMPLES = {
    "crib_score": 100_000,
    "ngram_score": 50_000,
    "composite": 25_000,
}
_QUICK_SAMPLES = {
    "crib_score": 5_000,
    "ngram_score": 2_000,
    "composite": 1_000,
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quick", action="store_true",
                    help="Build with reduced sample counts for smoke testing")
    ap.add_argument("--only", type=str, default=None,
                    help="Build only jobs matching this scorer name")
    ap.add_argument("--seed", type=int, default=42,
                    help="Deterministic RNG seed")
    ap.add_argument("--n-chars", type=int, default=97,
                    help="Ciphertext/plaintext length (default 97)")
    args = ap.parse_args(argv)

    sample_map = _QUICK_SAMPLES if args.quick else _DEFAULT_SAMPLES

    jobs = _STANDARD_JOBS
    if args.only:
        jobs = [j for j in jobs if j["scorer_name"] == args.only]
        if not jobs:
            print(f"No standard jobs match scorer_name={args.only!r}", file=sys.stderr)
            return 2

    print(f"Calibrating {len(jobs)} null distributions "
          f"(quick={args.quick}, n_chars={args.n_chars}, seed={args.seed})")
    print(f"Kernel commit: {_KERNEL_COMMIT}")
    print(f"Manifest: {_MANIFEST_PATH}")
    print()

    t0 = time.monotonic()
    for i, job in enumerate(jobs, 1):
        scorer = job["scorer_name"]
        method = job["method"]
        alphabet = job["alphabet"]
        n_samples = sample_map.get(scorer, 10_000)

        print(f"[{i}/{len(jobs)}] {scorer} × {method} × {alphabet} × n={args.n_chars} "
              f"({n_samples} samples) ...", flush=True)
        t1 = time.monotonic()
        try:
            dist = build_null_distribution(
                scorer_name=scorer,
                method=method,
                n_chars=args.n_chars,
                alphabet=alphabet,
                n_samples=n_samples,
                seed=args.seed,
            )
            path = save_to_cache(dist)
        except NotImplementedError as exc:
            print(f"    skipped: {exc}")
            continue
        except Exception as exc:
            print(f"    FAILED: {type(exc).__name__}: {exc}", file=sys.stderr)
            continue
        dt = time.monotonic() - t1
        max_val = dist.sorted_scores[-1] if dist.sorted_scores else None
        print(f"    mean={dist.mean:.4f}  stdev={dist.stdev:.4f}  "
              f"max={max_val}  parametric={dist.parametric_model}  "
              f"({dt:.2f}s) -> {path.relative_to(_ROOT)}", flush=True)

    total_dt = time.monotonic() - t0
    print(f"\nDone in {total_dt:.1f}s. Manifest: {_MANIFEST_PATH.relative_to(_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
