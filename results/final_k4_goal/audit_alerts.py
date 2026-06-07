#!/usr/bin/env python3
"""Canonical audit of every historical SIGNAL/BREAKTHROUGH alert.

For each alert file under results/breakthroughs/, extract the candidate
plaintext, classify whether it is a real-K4 claim or a K4Bench synthetic
calibration artifact, and re-score it. Real-K4 alerts get the full canonical
treatment; we explicitly flag the forced-crib signature (cribs in place but a
gibberish, non-English body) which is how every historical alert fails.

Usage:
    PYTHONPATH=src python3 results/final_k4_goal/audit_alerts.py
"""
import glob
import json
import os

from kryptos.kernel.constants import CT, CRIB_POSITIONS
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ngram import get_default_scorer

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
NG = get_default_scorer()
RANDOM_NGRAM_PC = -6.43  # random_text null mean (null_baselines manifest)


def english_body_ratio(pt):
    body = pt.replace("EASTNORTHEAST", "").replace("BERLINCLOCK", "")
    if not body:
        return 0.0
    return sum(c in "AEIOU" for c in body) / len(body)


def main():
    out = []
    files = sorted(glob.glob(os.path.join(ROOT, "results", "breakthroughs", "*.json")))
    print(f"{'alert':52s} {'kind':8s} {'crib':>4s} {'bean':>5s} {'is_bt':>5s} {'ngram_pc':>8s} {'vowel':>5s} verdict")
    print("-" * 120)
    for f in files:
        d = json.load(open(f))
        name = os.path.basename(f).replace("alert_", "")[:50]
        blob = json.dumps(d)
        kind = "K4Bench" if "k4b" in f.lower() else "real-K4"
        pt = None
        if isinstance(d, dict):
            pt = d.get("best_plaintext") or d.get("plaintext")
        crib = bean = isbt = ngpc = vr = None
        verdict = "NO_PT"
        if pt and isinstance(pt, str) and pt.isalpha():
            ngpc = round(NG.score_per_char(pt.upper()), 3)
            vr = round(english_body_ratio(pt.upper()), 3)
            if len(pt) == 97:
                bd = score_candidate(pt.upper(), ngram_scorer=NG)
                crib, bean, isbt = bd.crib_score, bool(bd.bean_passed), bool(bd.is_breakthrough)
            # forced-crib verdict: ENE/BCL present but body not English
            has_cribs = ("EASTNORTHEAST" in pt and "BERLINCLOCK" in pt)
            if has_cribs and vr < 0.30 and ngpc < -4.5:
                verdict = "FORCED-CRIB (gibberish body)"
            elif has_cribs:
                verdict = "REVIEW"
            else:
                verdict = "noise"
            if kind == "K4Bench":
                verdict = "calibration-artifact (synthetic CT)"
        out.append(dict(alert=name, kind=kind, crib=crib, bean=bean, is_bt=isbt,
                        ngram_pc=ngpc, vowel=vr, verdict=verdict, pt=pt))
        cs = f"{crib}" if crib is not None else "-"
        bs = f"{bean}" if bean is not None else "-"
        bt = f"{isbt}" if isbt is not None else "-"
        ns = f"{ngpc}" if ngpc is not None else "-"
        vs = f"{vr}" if vr is not None else "-"
        print(f"{name:52s} {kind:8s} {cs:>4s} {bs:>5s} {bt:>5s} {ns:>8s} {vs:>5s} {verdict}")
    print("-" * 120)
    real = [r for r in out if r["kind"] == "real-K4"]
    solves = [r for r in real if r["is_bt"]]
    print(f"\nreal-K4 alerts: {len(real)}  |  kernel-validated solves (is_breakthrough): {len(solves)}")
    print(f"K4Bench calibration alerts: {len(out) - len(real)} (expected to score as noise vs real cribs)")
    json.dump(out, open(os.path.join(os.path.dirname(__file__), "alert_audit.json"), "w"), indent=2)
    print("Wrote alert_audit.json")


if __name__ == "__main__":
    main()
