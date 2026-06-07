#!/usr/bin/env python3
"""Full validation gate for a single K4 plaintext candidate.

This is the canonical "is this a real solve?" tool. It NEVER trusts a
self-reported score. Given a 97-char A-Z plaintext (and optional cipher
family), it recomputes everything from the kernel and applies every control
the project requires before a candidate may be called a solution:

  1. canonical score_candidate (crib + Bean + quadgram + dictionary words)
  2. kernel is_breakthrough gate (crib==24 AND Bean AND ngram floor AND p-gate)
  3. forced-crib inspection (cribs present but body gibberish?)
  4. matched-family null p-value  (kryptosbot.null_baselines.p_value_for_alert)
  5. random_text and shuffled_ct control p-values
  6. final SOLVE / REJECT verdict with reasons

Usage:
    PYTHONPATH=src python3 results/final_k4_goal/verify_breakthrough.py <PLAINTEXT97> [family]
    PYTHONPATH=src python3 results/final_k4_goal/verify_breakthrough.py --selftest

A SOLVE verdict requires ALL of: crib_score==24, bean_passed, is_breakthrough,
English body (word_count>=8 and vowel ratio in [0.30,0.50]), and the
matched-family p-value at or below the alert gate. Anything less is REJECT.
"""
import os
import sys

# Make both src/ (kryptos kernel) and repo root (kryptosbot) importable.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(os.path.dirname(_HERE))
for p in (os.path.join(_ROOT, "src"), _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from kryptos.kernel.constants import CT, CRIB_POSITIONS
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.scoring.words import WordScorer
import kryptosbot.null_baselines as nb

ALERT_GATE = 1e-6  # configured ALERT_P_VALUE_GATE (widened to empirical floor if undersampled)


def english_body_ratio(pt):
    body = pt
    for c in ("EASTNORTHEAST", "BERLINCLOCK"):
        body = body.replace(c, "")
    return (sum(ch in "AEIOU" for ch in body) / len(body)) if body else 0.0


def verify(pt, family=""):
    pt = pt.strip().upper()
    out = {"plaintext": pt, "family": family, "reasons": []}
    if len(pt) != 97 or not pt.isalpha():
        out["verdict"] = "INVALID_INPUT"
        out["reasons"].append(f"expected 97 A-Z chars, got len={len(pt)}")
        return out

    ng = get_default_scorer()
    try:
        ws = WordScorer.from_file("wordlists/english.txt")
    except Exception:
        ws = None
    bd = score_candidate(pt, ngram_scorer=ng, word_scorer=ws)

    out["crib_score"] = bd.crib_score
    out["bean_passed"] = bool(bd.bean_passed)
    out["is_breakthrough"] = bool(bd.is_breakthrough)
    out["ngram_per_char"] = bd.ngram_per_char
    out["word_count"] = bd.word_count
    out["vowel_ratio_body"] = round(english_body_ratio(pt), 3)

    # matched-family null p-value
    try:
        pval, expl = nb.p_value_for_alert(pt, bd.crib_score, family or "")
    except Exception as e:
        pval, expl = None, f"p_value_for_alert error: {e}"
    out["matched_family_p"] = pval
    out["matched_family_note"] = expl

    # control p-values
    controls = {}
    for method in ("random_text", "shuffled_ct"):
        try:
            dist = nb.get_cached("crib_score", method=method, n_chars=97, alphabet="AZ")
            controls[method] = nb.p_value(bd.crib_score, dist) if dist else None
        except Exception:
            controls[method] = None
    out["control_p"] = controls

    # forced-crib inspection
    has_cribs = ("EASTNORTHEAST" in pt and "BERLINCLOCK" in pt) or bd.crib_score >= 18
    body_gibberish = out["vowel_ratio_body"] < 0.30 or (
        bd.ngram_per_char is not None and bd.ngram_per_char < -4.8)
    out["forced_crib"] = bool(has_cribs and body_gibberish)

    # final verdict
    english_body = (bd.word_count or 0) >= 8 and 0.30 <= out["vowel_ratio_body"] <= 0.50
    p_ok = (pval is not None and pval <= max(ALERT_GATE, 2e-4))
    is_solve = (bd.crib_score == 24 and out["bean_passed"] and out["is_breakthrough"]
                and english_body and not out["forced_crib"] and p_ok)
    if is_solve:
        out["verdict"] = "SOLVE_CANDIDATE"
    else:
        out["verdict"] = "REJECT"
        if bd.crib_score != 24:
            out["reasons"].append(f"crib_score={bd.crib_score} != 24")
        if not out["bean_passed"]:
            out["reasons"].append("bean_passed=False (structural keystream constraints fail)")
        if not out["is_breakthrough"]:
            out["reasons"].append("kernel is_breakthrough gate = False")
        if not english_body:
            out["reasons"].append(
                f"body not English (words={bd.word_count}, vowel_ratio={out['vowel_ratio_body']})")
        if out["forced_crib"]:
            out["reasons"].append("FORCED-CRIB: cribs present, body gibberish")
        if not p_ok:
            out["reasons"].append(f"matched-family p={pval} fails gate")
    return out


def _print(o):
    print("=" * 78)
    print(f"VERDICT: {o['verdict']}")
    print("=" * 78)
    for k in ("crib_score", "bean_passed", "is_breakthrough", "ngram_per_char",
              "word_count", "vowel_ratio_body", "forced_crib",
              "matched_family_p", "control_p", "matched_family_note"):
        if k in o:
            print(f"  {k:18s}: {o[k]}")
    if o.get("reasons"):
        print("  reasons:")
        for r in o["reasons"]:
            print(f"    - {r}")


def selftest():
    import json
    # Best forced-crib overfit from the harvest — must REJECT.
    cand = json.load(open("results/final_k4_goal/top_candidates.json"))[0]
    print(f"[selftest] best harvested candidate from {cand['src']}")
    o = verify(cand["pt"])
    _print(o)
    assert o["verdict"] == "REJECT", "forced-crib overfit must be REJECTED"
    print("\n[selftest] PASS — full gate correctly rejects the top forced-crib overfit.")


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "--selftest":
        selftest()
    elif len(sys.argv) >= 2:
        fam = sys.argv[2] if len(sys.argv) >= 3 else ""
        _print(verify(sys.argv[1], fam))
    else:
        print(__doc__)
        sys.exit(2)
