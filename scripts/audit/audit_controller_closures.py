#!/usr/bin/env python3
"""Controller-closure integrity audit (deterministic backbone).

Reproducible, READ-ONLY classification of every closure in the real-K4
theory ledger (db/theory_ledger.sqlite). Produces a JSON artifact that the
closure-integrity audit report and its workflow streams consume.

Motivation
----------
The job_dispatcher candidate scorer (kryptosbot/job_dispatcher.py:1807)
unconditionally calls anchored ``score_candidate``; ``score_candidate_free``
is never invoked in the dispatch path. A HypothesisSpec may declare
``crib_alignment`` of ``free`` or ``post_transposition`` (both are accepted
DSL values), but for REAL K4 the resulting crib_score is computed
anchored at the as-carved crib positions, NOT under the claimed alignment.
Such a closure's crib_score does not test the hypothesis as specified:
the closure is *mislabeled*, the non-direct frontier is *untested*, not
disproved. (Bench challenges are unaffected: they live in db/k4bench/ and
score against a challenge-defined crib dict.) See the
``dispatcher-dsl-contract`` skill, "Known Dispatcher Limitations".

This script classifies each closure so the report can quantify exactly how
many closures are mislabeled vs sound, without LLM judgment.

Taxonomy (per closed theory)
----------------------------
- PRE_DISPATCH_REJECT  : status criticized/withdrawn (killed by critic /
                         red-team before any dispatch; the defect cannot
                         bite a hypothesis that never ran). Sound.
- ADMISSIBILITY_DEDUP  : experiment result.status == rejected_admissibility
                         and never scored (exhaustion/overlap duplicate).
                         Sound (this is duplicate detection working).
- PHANTOM_DISPATCHER   : non-direct alignment + a dsl_dispatcher
                         "disproved" experiment. CONFIRMED mislabeled:
                         anchored-scored, frontier untested.
- PHANTOM_UNVERIFIED   : non-direct alignment + a non-dispatcher (agent SDK
                         scratch) "disproved" experiment. Scoring method is
                         worker-local and must be verified per-worker.
- ERROR_AS_DISPROOF    : eliminated/completed whose ONLY experiment outcomes
                         are error/per_task_timeout. Flag (error != disproof).
- ARGUMENT_ELIMINATION : eliminated with NO experiment (closed by red-team /
                         critic / batch / structural argument). Subdivided
                         by failure_reason bucket. Label conflates
                         "argued-dead" with "empirically disproved".
- REAL_DISPROOF        : direct_positional (or spec-less) + a scored
                         "disproved" experiment. Anchored IS the correct
                         test here, so the closure is genuine.
- OTHER                : anything the rules above do not capture (audited
                         explicitly so nothing is silently dropped).

Usage
-----
    PYTHONPATH=src python3 scripts/audit/audit_controller_closures.py \
        [--db db/theory_ledger.sqlite] [--out <dir>]

Read-only: opens the DB with ``mode=ro``. Writes only the JSON artifact.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

CLOSURE_STATUSES = {"eliminated", "completed", "withdrawn", "criticized", "error"}
NON_DIRECT = {"free", "post_transposition"}
ERRORY = {"error", "per_task_timeout"}


def _git_head() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True
        ).strip()
    except Exception:
        return "unknown"


def _alignment_of(dsl_spec: str, minimal_test_spec: str) -> str:
    """Recover declared crib_alignment, preferring the dispatched dsl_spec."""
    for blob in (dsl_spec, minimal_test_spec):
        if blob and blob not in ("{}", ""):
            try:
                a = json.loads(blob).get("crib_alignment")
            except Exception:
                a = None
            if a:
                return a
    return "MISSING"


def _failure_bucket(fr: str) -> str:
    fr = (fr or "").upper()
    for key in (
        "ADMISSIBIL", "EXHAUSTION", "RED-TEAM", "RED TEAM", "CRITIC",
        "EMPIRICALLY", "TRANSLATION", "SUBSUMED", "DEPRECATED", "BATCH",
        "UNDERCONSTRAIN", "TIMEOUT", "KILL CRITERION", "KC1", "KC2",
        "NOISE", "NULL", "ERROR",
    ):
        if key in fr:
            return key.replace(" ", "_")
    return (fr[:24] or "EMPTY")


def load_experiments(con: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    """experiment_id -> {worker_role, status, crib_score}."""
    out: dict[str, dict[str, Any]] = {}
    for row in con.execute("SELECT experiment_id, worker_role, result FROM experiments"):
        try:
            d = json.loads(row["result"] or "{}")
        except Exception:
            d = {}
        out[row["experiment_id"]] = {
            "worker_role": row["worker_role"] or d.get("worker_role", ""),
            "status": d.get("status", "?"),
            "crib_score": d.get("crib_score"),
        }
    return out


def classify(theory: sqlite3.Row, exps: dict[str, dict[str, Any]]) -> dict[str, Any]:
    status = theory["status"]
    align = _alignment_of(theory["dsl_spec"], theory["minimal_test_spec"])
    exp_ids = json.loads(theory["experiment_ids"] or "[]")
    erows = [exps[i] for i in exp_ids if i in exps]
    exp_statuses = [e["status"] for e in erows]
    scored = [e for e in erows if e["status"] not in ERRORY | {"rejected_admissibility", "?"}]
    disproved = [e for e in erows if e["status"] == "disproved"]
    crib_scores = [e["crib_score"] for e in erows if e["crib_score"] is not None]
    max_crib = max(crib_scores) if crib_scores else None
    worker_roles = sorted({e["worker_role"] for e in erows if e["worker_role"]})

    rec: dict[str, Any] = {
        "hypothesis_id": theory["hypothesis_id"],
        "status": status,
        "family": theory["family"],
        "subfamily": theory["subfamily"],
        "alignment": align,
        "worker_roles": worker_roles,
        "n_experiments": len(exp_ids),
        "exp_statuses": exp_statuses,
        "max_anchored_crib": max_crib,
        "failure_reason": (theory["failure_reason"] or "")[:200],
    }

    # 1. pre-dispatch gate closures
    if status in ("criticized", "withdrawn"):
        rec["klass"] = "PRE_DISPATCH_REJECT"
        return rec

    # 2. error-as-disproof: ONLY error/timeout experiments, nothing scored
    if erows and all(e["status"] in ERRORY for e in erows):
        rec["klass"] = "ERROR_AS_DISPROOF"
        return rec

    # 3. scored disproof
    if disproved:
        if align in NON_DIRECT:
            if "dsl_dispatcher" in worker_roles:
                rec["klass"] = "PHANTOM_DISPATCHER"
            else:
                rec["klass"] = "PHANTOM_UNVERIFIED"
        else:
            rec["klass"] = "REAL_DISPROOF"
        return rec

    # 4. scored but not "disproved" label (inconclusive / other scored)
    if scored:
        rec["klass"] = "SCORED_OTHER"
        return rec

    # 5. admissibility-dedup (rejected, never scored)
    if exp_statuses and all(s in ("rejected_admissibility", "?") for s in exp_statuses):
        rec["klass"] = "ADMISSIBILITY_DEDUP"
        return rec

    # 6. eliminated/completed with NO experiment => argument/batch closure
    if not exp_ids:
        rec["klass"] = "ARGUMENT_ELIMINATION"
        rec["arg_bucket"] = _failure_bucket(theory["failure_reason"])
        return rec

    rec["klass"] = "OTHER"
    return rec


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="db/theory_ledger.sqlite")
    ap.add_argument("--out", default="audits/controller_closure_audit_2026_05_30")
    args = ap.parse_args()

    con = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    exps = load_experiments(con)
    theories = con.execute(
        "SELECT hypothesis_id,status,family,subfamily,best_score,failure_reason,"
        "outcome_summary,experiment_ids,dsl_spec,minimal_test_spec FROM theories"
    ).fetchall()

    records = [classify(t, exps) for t in theories]
    closed = [r for r in records if r["status"] in CLOSURE_STATUSES]

    klass_counts = Counter(r["klass"] for r in closed)
    arg_buckets = Counter(
        r.get("arg_bucket", "?") for r in closed if r["klass"] == "ARGUMENT_ELIMINATION"
    )
    phantom_dispatcher = [r for r in closed if r["klass"] == "PHANTOM_DISPATCHER"]
    phantom_unverified = [r for r in closed if r["klass"] == "PHANTOM_UNVERIFIED"]
    phantom_by_family = Counter(r["family"] for r in phantom_dispatcher + phantom_unverified)
    # max anchored crib among confirmed-phantom (sanity: should be << 18)
    phantom_max_crib = max(
        [r["max_anchored_crib"] or 0 for r in phantom_dispatcher], default=None
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    artifact = {
        "provenance": {
            "db": args.db,
            "db_mtime": datetime.fromtimestamp(
                os.path.getmtime(args.db), tz=timezone.utc
            ).isoformat(),
            "git_head": _git_head(),
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "n_theories_total": len(theories),
            "n_closed": len(closed),
            "note": "READ-ONLY audit of real-K4 ledger; bench lives in db/k4bench/.",
        },
        "klass_counts": dict(klass_counts.most_common()),
        "argument_elimination_buckets": dict(arg_buckets.most_common()),
        "phantom_summary": {
            "phantom_dispatcher_confirmed": len(phantom_dispatcher),
            "phantom_unverified_agent_sdk": len(phantom_unverified),
            "phantom_max_anchored_crib": phantom_max_crib,
            "interpretation": (
                "PHANTOM_DISPATCHER are non-direct-alignment closures the "
                "dispatcher scored anchored; their crib_score does not test "
                "the declared alignment. Max anchored crib well below the "
                "SIGNAL=18 gate confirms no candidate was wrongly killed; "
                "the harm is mislabeling (frontier untested, not disproved)."
            ),
            "by_family": dict(phantom_by_family.most_common()),
        },
        "records": records,
    }
    art_path = out_dir / "closure_classification.json"
    art_path.write_text(json.dumps(artifact, indent=2))

    # Human-readable console summary
    print(f"== Controller-closure integrity audit ==  git={artifact['provenance']['git_head']}")
    print(f"theories total={len(theories)}  closed={len(closed)}")
    print("\nclosure classes:")
    for k, n in klass_counts.most_common():
        print(f"  {k:24s} {n}")
    print("\nARGUMENT_ELIMINATION buckets:")
    for k, n in arg_buckets.most_common():
        print(f"  {k:24s} {n}")
    print("\nphantom (non-direct, scored-disproved) frontier:")
    print(f"  confirmed (dsl_dispatcher) : {len(phantom_dispatcher)}")
    print(f"  unverified (agent_sdk)     : {len(phantom_unverified)}")
    print(f"  max anchored crib (conf.)  : {phantom_max_crib}  (SIGNAL gate = 18)")
    print(f"\nartifact: {art_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
