#!/usr/bin/env python3
"""Build the R2-4 matched_variant_family null distributions.

Round 2 Phase R2-4 (2026-04-21). Phase 6 shipped Vigenère-AZ as the only
``matched_variant_family`` baseline. K4's search space is composition-
heavy; without family-matched nulls on Beaufort / VarBeau / columnar_*
the alert gating path over-rejects on those families (genuine signal
gets called noise).

This script calibrates the 6 additional distributions the brief §5.1
specifies:

  crib_score    × matched_variant_family × beaufort
  crib_score    × matched_variant_family × variant_beaufort
  crib_score    × matched_variant_family × columnar_single
  crib_score    × matched_variant_family × columnar_double
  ngram_score   × matched_variant_family × columnar_single
  ngram_score   × matched_variant_family × columnar_double

Each with 50,000 samples per brief §5.4. Full distributions are gitignored
under ``results/null_baselines/``; the manifest summary at
``null_baselines/manifest.json`` IS committed.

Usage:
    PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines_r2_4.py
    PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines_r2_4.py --quick
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
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from kryptosbot.null_baselines import (
    _KERNEL_COMMIT,
    _MANIFEST_PATH,
    build_null_distribution,
    save_to_cache,
)


# R2-4 §5.1 — six new distributions, plus vigenere added 2026-05-04.
# The vigenere family job was added because the alert path in
# kryptosbot/alerts.py requests family='vigenere' for Vigenere-tagged
# theories, but R2-4 only built beaufort/var_beaufort/columnar_*. The
# legacy "" cache (built by calibrate_null_baselines.py, encrypts random
# PT under random key) is semantically distinct from the explicit-vigenere
# cache (decrypts real CT under random key) — the explicit form is what
# the alert lookup needs. Without this job, the alert path falls back to
# random_text null silently, degrading p-value gating for Vigenere theories.
_R2_4_JOBS: list[dict] = [
    {"scorer_name": "crib_score",  "family": "vigenere"},
    {"scorer_name": "crib_score",  "family": "beaufort"},
    {"scorer_name": "crib_score",  "family": "variant_beaufort"},
    {"scorer_name": "crib_score",  "family": "columnar_single"},
    {"scorer_name": "crib_score",  "family": "columnar_double"},
    {"scorer_name": "ngram_score", "family": "columnar_single"},
    {"scorer_name": "ngram_score", "family": "columnar_double"},
    # 2026-05-26 — dispatchable transposition families (rail_fence,
    # myszkowski, route) added so the real-K4 instrument campaign scores
    # genuine transposition hits against their own matched-family null
    # (ok_matched_family) instead of the random_text strawman. crib_score
    # only, matching the additive families (beaufort/var_beaufort/vigenere);
    # ngram nulls remain columnar-only.
    {"scorer_name": "crib_score",  "family": "rail_fence"},
    {"scorer_name": "crib_score",  "family": "myszkowski"},
    {"scorer_name": "crib_score",  "family": "route"},
    # G-1 (2026-06-10) — free-scoring-mode nulls. The dispatcher's
    # crib_alignment="free" path scores cribs with score_candidate_free
    # (support {0, 11, 13, 24}); those scores must gate against
    # free-built nulls, never anchored ones. The free random_text and
    # shuffled_ct entries back the family-less alert path; the
    # per-family entries back ok_free_matched. Tails are parametric
    # (free_crib_substring), so the 1/N empirical floor does not apply.
    {"scorer_name": "crib_score", "family": "",
     "method": "random_text", "scoring_mode": "free"},
    {"scorer_name": "crib_score", "family": "",
     "method": "shuffled_ct", "scoring_mode": "free"},
    {"scorer_name": "crib_score", "family": "vigenere", "scoring_mode": "free"},
    {"scorer_name": "crib_score", "family": "beaufort", "scoring_mode": "free"},
    {"scorer_name": "crib_score", "family": "variant_beaufort", "scoring_mode": "free"},
    {"scorer_name": "crib_score", "family": "columnar_single", "scoring_mode": "free"},
    {"scorer_name": "crib_score", "family": "columnar_double", "scoring_mode": "free"},
    {"scorer_name": "crib_score", "family": "rail_fence", "scoring_mode": "free"},
    {"scorer_name": "crib_score", "family": "myszkowski", "scoring_mode": "free"},
    {"scorer_name": "crib_score", "family": "route", "scoring_mode": "free"},
]

# §5.4 — 50_000 samples (vs Phase 6's 100_000) to keep total calibration
# under 5 minutes on the 28-vCPU VM. Quick mode for smoke checks.
_DEFAULT_SAMPLES = 50_000
_QUICK_SAMPLES = 2_000


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--quick", action="store_true",
                    help="Build with reduced sample counts for smoke testing")
    ap.add_argument("--seed", type=int, default=42,
                    help="Deterministic RNG seed")
    ap.add_argument("--only-family", type=str, default=None,
                    help="Build only jobs whose family contains this string")
    args = ap.parse_args(argv)

    n_samples = _QUICK_SAMPLES if args.quick else _DEFAULT_SAMPLES
    jobs = _R2_4_JOBS
    if args.only_family:
        jobs = [j for j in jobs if args.only_family in j["family"]]
        if not jobs:
            print(f"no jobs match family substring {args.only_family!r}",
                  file=sys.stderr)
            return 2

    print(f"R2-4 calibration: {len(jobs)} distributions")
    print(f"  samples per distribution: {n_samples}")
    print(f"  kernel commit: {_KERNEL_COMMIT}")
    print(f"  manifest: {_MANIFEST_PATH}")
    print()

    t0 = time.monotonic()
    for i, job in enumerate(jobs, 1):
        scorer = job["scorer_name"]
        family = job["family"]
        method = job.get("method", "matched_variant_family")
        scoring_mode = job.get("scoring_mode", "anchored")
        tag = f"{scorer} × {method} × {family or '(none)'}"
        if scoring_mode != "anchored":
            tag += f" × {scoring_mode}"
        print(f"[{i}/{len(jobs)}] {tag} ({n_samples} samples) ...",
              flush=True)
        t1 = time.monotonic()
        try:
            dist = build_null_distribution(
                scorer_name=scorer,
                method=method,
                n_chars=97,
                alphabet="AZ",
                n_samples=n_samples,
                seed=args.seed,
                family=family,
                scoring_mode=scoring_mode,
            )
            path = save_to_cache(dist)
        except Exception as exc:
            print(f"    FAILED: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            continue
        dt = time.monotonic() - t1
        max_val = dist.sorted_scores[-1] if dist.sorted_scores else None
        if dist.parametric_model == "free_crib_substring":
            params = dist.free_tail_params or {}
            print(f"    mean={dist.mean:.4f}  max={max_val}  "
                  f"model={params.get('letter_model')}  "
                  f"p(13)={dist.p_value(13.0):.3g}  "
                  f"p(11)={dist.p_value(11.0):.3g}  "
                  f"p(24)={dist.p_value(24.0):.3g}  ({dt:.1f}s)  -> "
                  f"{path.relative_to(_ROOT)}", flush=True)
            continue
        # Tail floor: 1/N when the observation exceeds the empirical range.
        tail_floor = 1.0 / max(1, dist.n_samples)
        print(f"    mean={dist.mean:.4f}  stdev={dist.stdev:.4f}  "
              f"max={max_val}  tail_floor=1/{dist.n_samples} "
              f"({tail_floor:.2e})  ({dt:.1f}s)  -> "
              f"{path.relative_to(_ROOT)}", flush=True)

    total_dt = time.monotonic() - t0
    print(f"\nDone in {total_dt:.1f}s. "
          f"Manifest: {_MANIFEST_PATH.relative_to(_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
