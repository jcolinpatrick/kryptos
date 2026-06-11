#!/usr/bin/env python3
"""f_solver_free_alignment_2026_06_11 — solver multi-layer free-alignment sweep.

Pre-registration: docs/campaigns/solver_free_alignment_2026_06_11.md
(thresholds frozen before any config executed).

Universe: kryptosbot.solver.build_sweep_specs rounds 0+1 under
crib_alignment="free" (484 specs, ~250,348 configs). Dispatch: real-K4 path
(execute() per spec, no challenge args) so score_candidate_free engages.
Controls C0-C2 run first; campaign aborts if any fails.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

CAMPAIGN_ID = "f_solver_free_alignment_2026_06_11"
PREREG = "docs/campaigns/solver_free_alignment_2026_06_11.md"
OUT_DIR = os.path.join(_ROOT, "results", "solver_free_alignment_2026_06_11")
JOBS_DIR = os.path.join(OUT_DIR, "jobs")
HIT_THRESHOLD = 11  # frozen: free support {0,11,13,24}; rule S at >=11


def control_c0() -> dict:
    """Known-answer readiness gate (fail-closed)."""
    proc = subprocess.run(
        [sys.executable, os.path.join(_ROOT, "kryptosbot", "self_test.py"),
         "--panel", "all", "--mode", "dry-run", "--cycles", "20000"],
        capture_output=True, text=True,
        env={**os.environ, "PYTHONPATH": os.path.join(_ROOT, "src")},
    )
    ok = proc.returncode == 0 and "solved: 3/3" in proc.stdout
    return {"control": "C0", "pass": ok, "returncode": proc.returncode,
            "tail": proc.stdout.strip().splitlines()[-1:]}


def control_c1() -> dict:
    """Kernel free matcher finds displaced cribs."""
    from kryptos.kernel.scoring.aggregate import score_candidate_free

    pt = list("Q" * 97)
    pt[5:18] = "EASTNORTHEAST"
    pt[60:71] = "BERLINCLOCK"
    fb = score_candidate_free("".join(pt))
    crib = int(getattr(fb, "crib_score", 0) or 0)
    canonical = bool(getattr(fb, "canonical_positions", True))
    ok = crib == 24 and not canonical
    return {"control": "C1", "pass": ok, "crib_score": crib,
            "canonical_positions": canonical}


def control_c2() -> dict:
    """Worker path free-scores a synthetic displaced-crib CT (template-verbatim)."""
    from kryptos.kernel.transforms.vigenere import encrypt_text, CipherVariant
    from kryptosbot.job_dispatcher import _evaluate_one

    pt = list("Q" * 97)
    pt[5:18] = "EASTNORTHEAST"
    pt[60:71] = "BERLINCLOCK"
    key = [ord(c) - 65 for c in "PALIMPSEST"]
    synthetic_ct = encrypt_text("".join(pt), key, CipherVariant.VIGENERE)

    work_item = {
        "config_id": "control_c2",
        "pipeline_dict": {
            "name": "control_c2",
            "direction": "decrypt",
            "steps": [{
                "type": "vigenere",
                "params": {"key": key, "direction": "decrypt"},
            }],
        },
        "crib_alignment": "free",
        "challenge_ciphertext": synthetic_ct,
        "challenge_crib_dict": None,
    }
    res = _evaluate_one(work_item)
    ok = (
        res.get("crib_score") == 24
        and res.get("scoring_mode") == "free"
        and not res.get("canonical_positions", True)
        and res.get("error") is None
    )
    return {"control": "C2", "pass": ok, "crib_score": res.get("crib_score"),
            "scoring_mode": res.get("scoring_mode"),
            "canonical_positions": res.get("canonical_positions"),
            "error": res.get("error")}


def main() -> int:
    os.makedirs(JOBS_DIR, exist_ok=True)
    from kryptosbot.solver import _k4_ingredients, build_sweep_specs
    from kryptosbot.job_dispatcher import execute

    git_head = subprocess.run(
        ["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=_ROOT
    ).stdout.strip()

    summary: dict = {
        "campaign_id": CAMPAIGN_ID,
        "prereg": PREREG,
        "git_head": git_head,
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "hit_threshold": HIT_THRESHOLD,
    }

    # ── Controls (fail-closed) ───────────────────────────────────────────
    controls = [control_c0(), control_c1(), control_c2()]
    summary["controls"] = controls
    for c in controls:
        print(f"  [{c['control']}] pass={c['pass']}", flush=True)
    if not all(c["pass"] for c in controls):
        summary["verdict"] = "ABORTED_CONTROL_FAILURE"
        _write(summary)
        print("CONTROL FAILURE — campaign aborted before any arm.", flush=True)
        return 1

    # ── Frozen universe ──────────────────────────────────────────────────
    ing = _k4_ingredients(max_keywords=12)
    specs = []
    for rnd in (0, 1):
        specs.extend(build_sweep_specs(ing, round_idx=rnd, crib_alignment="free"))
    blob = json.dumps([s.to_dict() for s in specs], sort_keys=True)
    summary["keywords"] = list(ing.keywords)
    summary["n_specs"] = len(specs)
    summary["expected_total"] = sum(s.expected_cardinality() for s in specs)
    summary["universe_sha256"] = hashlib.sha256(blob.encode()).hexdigest()
    print(f"  universe: {len(specs)} specs / {summary['expected_total']:,} configs "
          f"/ sha256 {summary['universe_sha256'][:16]}", flush=True)

    # ── Dispatch (real-K4 path; serial specs, pooled configs) ───────────
    per_spec: list[dict] = []
    hits: list[dict] = []
    rejections: list[dict] = []
    total_tested = 0
    best = {"score": 0.0}
    t0 = time.time()
    for i, spec in enumerate(specs):
        res = execute(spec, artifact_root=Path(JOBS_DIR))
        verdict = str(res.admissibility_verdict)
        rejected = not verdict.startswith("ok")
        tested = int(res.total_tested or 0)
        total_tested += tested
        cand = res.best_candidate or {}
        score = float(cand.get("crib_score", 0) or 0)
        row = {
            "hypothesis_id": spec.hypothesis_id,
            "spec_hash": spec.spec_hash,
            "admissibility_verdict": verdict,
            "tested": tested,
            "best_crib": score,
            "scoring_mode": cand.get("scoring_mode"),
        }
        per_spec.append(row)
        if rejected:
            rejections.append({**row, "reasons": list(res.admissibility_reasons or [])})
        if score > best["score"]:
            best = {"score": score, "spec": spec.hypothesis_id,
                    "config_id": cand.get("config_id"),
                    "candidate_pt": cand.get("candidate_pt"),
                    "ngram": cand.get("ngram_score"),
                    "canonical_positions": cand.get("canonical_positions")}
        if score >= HIT_THRESHOLD:
            hits.append({**row, "config_id": cand.get("config_id"),
                         "candidate_pt": cand.get("candidate_pt")})
            print(f"  !! HIT >= {HIT_THRESHOLD}: {spec.hypothesis_id} "
                  f"crib={score}", flush=True)
        if (i + 1) % 50 == 0 or i + 1 == len(specs):
            print(f"  [{i+1}/{len(specs)}] tested={total_tested:,} "
                  f"best={best['score']} elapsed={time.time()-t0:.0f}s", flush=True)

    summary["total_tested"] = total_tested
    summary["wall_time_sec"] = time.time() - t0
    summary["best"] = best
    summary["hits_ge_threshold"] = hits
    summary["admissibility_rejections"] = rejections
    summary["per_spec"] = per_spec
    summary["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # ── Verdict (frozen rules §5) ────────────────────────────────────────
    if hits:
        summary["verdict"] = "HITS_REQUIRE_INVESTIGATION"  # rule S / DETECT-24
    else:
        summary["verdict"] = "CLEAN_NULL"
    _write(summary)
    print(f"VERDICT: {summary['verdict']} (best={best['score']}, "
          f"tested={total_tested:,}, rejections={len(rejections)})", flush=True)
    return 0


def _write(summary: dict) -> None:
    path = os.path.join(OUT_DIR, "summary.json")
    with open(path, "w") as f:
        json.dump(summary, f, indent=1)
    print(f"  summary -> {path}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
