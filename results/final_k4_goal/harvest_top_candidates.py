#!/usr/bin/env python3
"""Full-repo canonical candidate harvest + ranking.

Scans result JSONs for any 97-char A-Z plaintext, re-scores each with the
FULL kernel scorer (crib + Bean + quadgram ngram + dictionary word scorer),
and ranks them. This is the "top 20 verified candidates" table: every number
is recomputed by the kernel from the raw plaintext string, never trusted from
a result file's self-report.

A genuine solve must show: crib_score==24 AND bean_passed AND a real English
body (high word_count / long longest_word / ngram_per_char well above the
random_text null mean of ~ -6.43). Forced-crib artifacts show crib_score high
but word_count ~ 0-2 and ngram at the noise floor.

Usage:
    PYTHONPATH=src python3 results/final_k4_goal/harvest_top_candidates.py [--deep]

Default scans results/*.json (top level). --deep also scans one level of
subdirectories (skips the 150k+ nested per-job files, which are summaries).
"""
import glob
import json
import os
import sys

from kryptos.kernel.constants import CT, CRIB_POSITIONS
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.scoring.ngram import get_default_scorer
from kryptos.kernel.scoring.words import WordScorer

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")


def looks_like_pt(s):
    return isinstance(s, str) and len(s) == 97 and s.isalpha() and s.isupper()


def harvest(obj, found):
    if isinstance(obj, str):
        if looks_like_pt(obj):
            found.add(obj)
    elif isinstance(obj, dict):
        for v in obj.values():
            harvest(v, found)
    elif isinstance(obj, list):
        for v in obj:
            harvest(v, found)


def main():
    deep = "--deep" in sys.argv
    ngram = get_default_scorer()
    wl_path = os.path.join(ROOT, "wordlists", "english.txt")
    word_scorer = None
    if os.path.exists(wl_path):
        try:
            word_scorer = WordScorer.from_file(wl_path)
        except Exception as e:
            print(f"WARN: word scorer load failed: {e}")

    patterns = [os.path.join(ROOT, "results", "*.json")]
    if deep:
        patterns.append(os.path.join(ROOT, "results", "*", "*.json"))
    files = []
    for pat in patterns:
        files.extend(glob.glob(pat))
    files = sorted(set(files))

    # plaintext -> (source_file, breakdown)
    seen = {}
    n_scanned = 0
    for f in files:
        try:
            sz = os.path.getsize(f)
            if sz > 8_000_000:  # skip huge files
                continue
            d = json.load(open(f))
        except Exception:
            continue
        n_scanned += 1
        found = set()
        harvest(d, found)
        for pt in found:
            if pt in seen:
                continue
            bd = score_candidate(pt, ngram_scorer=ngram, word_scorer=word_scorer)
            seen[pt] = (os.path.relpath(f, ROOT), bd)

    rows = []
    for pt, (src, bd) in seen.items():
        rows.append(dict(
            crib=bd.crib_score, bean=bool(bd.bean_passed),
            ngram_pc=bd.ngram_per_char, words=bd.word_count,
            longest=bd.longest_word, is_bt=bool(bd.is_breakthrough),
            src=src, pt=pt,
        ))

    # Rank: real solves first (bean+highword), then by crib, then ngram, then words
    def keyf(r):
        return (
            1 if (r["crib"] == 24 and r["bean"] and (r["words"] or 0) >= 8) else 0,
            r["crib"],
            (r["words"] or 0),
            (r["ngram_pc"] or -99),
        )
    rows.sort(key=keyf, reverse=True)

    print("=" * 118)
    print(f"TOP VERIFIED CANDIDATES  (scanned {n_scanned} files, {len(seen)} unique 97-char PTs, deep={deep})")
    print("full kernel scorer: crib + Bean + quadgram + dictionary words")
    print(f"random_text null ngram_per_char mean ~ -6.43; English bodies score notably higher (less negative)")
    print("=" * 118)
    print(f"{'#':>2} {'crib':>4} {'bean':>5} {'ngram_pc':>9} {'words':>5} {'longest':>10} {'is_bt':>5}  source")
    print("-" * 118)
    top = rows[:20]
    for i, r in enumerate(top, 1):
        ng = f"{r['ngram_pc']:.3f}" if isinstance(r["ngram_pc"], (int, float)) else "-"
        lw = str(r["longest"] or "")
        print(f"{i:>2} {r['crib']:>4} {str(r['bean']):>5} {ng:>9} {str(r['words'] or 0):>5} {lw:>10} {str(r['is_bt']):>5}  {r['src']}")
    print("-" * 118)
    # Solve check
    solves = [r for r in rows if r["crib"] == 24 and r["bean"] and (r["words"] or 0) >= 8]
    print(f"\nKERNEL-VALIDATED SOLVES (crib==24 & bean & words>=8): {len(solves)}")
    for r in solves:
        print("  SOLVE CANDIDATE:", r["src"], r["pt"])

    json.dump([{k: v for k, v in r.items()} for r in rows[:50]],
              open(os.path.join(os.path.dirname(__file__), "top_candidates.json"), "w"),
              indent=2)
    print(f"\nWrote top_candidates.json (top 50)")


if __name__ == "__main__":
    main()
