#!/usr/bin/env python3
"""
e_crib_38_omission_quagmire_search
==================================

FAMILY: crib_analysis
STATUS: active

The decrypt-and-score half of the single-omission hypothesis. Companion to
e_crib_37, which used the attainable-crib-ceiling filter and returned a clean
null because that filter saturates above period 25 with only 24 cribs.

This test does not saturate. For every one of the 2,548 corrected 98-character
ciphertexts it runs Quagmire III -- the family K1 and K2 actually used -- over
the thematic keyword pool, decrypts, and scores. English separates from random
by roughly 9 sigma on quadgram score, and a hard crib gate sits in front, so
false positives are expected to be essentially zero and a hit would mean
something.

PRE-REGISTERED, before the first run:
  expected false positives ~0; expected true positives LOW (Stage A found
  nothing across 2,425 substitution variants against this same family). The
  reason to run anyway is that an insertion RE-INDEXES everything downstream,
  which a substitution does not, so it is a different transformation; and the
  prior is the strongest available -- Sanborn committed exactly this error on
  K2, admitted it, explained it as aesthetic balance, and never fixed the copper.

  ALERT THRESHOLD: crib_hits >= 20 of 24, OR ngram >= -5.0 per quadgram with
  crib_hits >= 12. Anything weaker is reported as a distribution, not a hit.

Repro:
  PYTHONPATH=src python3 -u scripts/crib_analysis/e_crib_38_omission_quagmire_search.py --workers 20
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))
sys.path.insert(0, os.path.join(_ROOT, "scripts", "lib"))

from crib_filter import AZ, keyword_mixed  # noqa: E402
from kryptos.kernel.constants import CT, CRIB_DICT  # noqa: E402

NTRUE = 98
SUBST = os.environ.get("K4_SUBST") == "1"
_QG = None


def qg():
    global _QG
    if _QG is None:
        with open(os.path.join(_ROOT, "data", "english_quadgrams.json")) as fh:
            d = json.load(fh)
        floor = min(d.values()) - 1.0
        arr = [floor] * (26 ** 4)
        for q, v in d.items():
            if len(q) == 4 and q.isalpha():
                arr[(ord(q[0]) - 65) * 17576 + (ord(q[1]) - 65) * 676
                    + (ord(q[2]) - 65) * 26 + (ord(q[3]) - 65)] = v
        _QG = arr
    return _QG


def load_keywords():
    kws = set()
    for name in ("thematic_keywords_v2.txt", "thematic_keywords.txt"):
        p = os.path.join(_ROOT, "wordlists", name)
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                w = "".join(ch for ch in line.strip().upper() if ch.isalpha())
                if 3 <= len(w) <= 26:
                    kws.add(w)
    return sorted(kws)


def _job(args):
    d, letter, keywords = args
    ct2 = (CT[:d] + letter + CT[d+1:]) if SUBST else (CT[:d] + letter + CT[d:])
    cribs = dict(CRIB_DICT) if SUBST else {(q + 1 if q >= d else q): c for q, c in CRIB_DICT.items()}
    QG = qg()
    best = None
    for kw in keywords:
        alpha = keyword_mixed(kw)
        idx = {c: i for i, c in enumerate(alpha)}
        P = len(set(kw))
        if P < 2:
            continue
        key = [idx[c] for c in dict.fromkeys(kw)]
        # Quagmire III: pi(c) - pi(p) = k[r]  ->  pi(p) = pi(c) - k[r]
        pt = []
        for j, ch in enumerate(ct2):
            pt.append(alpha[(idx[ch] - key[j % P]) % 26])
        pts = "".join(pt)
        hits = sum(1 for q, c in cribs.items() if pts[q] == c)
        if hits < 4:
            continue
        a = [ord(x) - 65 for x in pts]
        s = 0.0
        for j in range(len(a) - 3):
            s += QG[a[j] * 17576 + a[j + 1] * 676 + a[j + 2] * 26 + a[j + 3]]
        s /= (len(a) - 3)
        if best is None or (hits, s) > (best[0], best[1]):
            best = (hits, s, kw, pts)
    return (d, letter, best)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workers", type=int,
                    default=max(1, len(os.sched_getaffinity(0)) - 2))
    args = ap.parse_args()
    kws = load_keywords()
    print("=" * 84)
    print(("SINGLE-SUBSTITUTION" if SUBST else "SINGLE-OMISSION") + " x QUAGMIRE III — decrypt and score, no saturation")
    print("=" * 84)
    print(f"  corrected ciphertexts : {NTRUE * 26:,}")
    print(f"  keywords              : {len(kws):,}")
    print(f"  configurations        : {NTRUE * 26 * len(kws):,}")
    print(f"  ALERT: crib_hits >= 20/24, or ngram >= -5.0 with crib_hits >= 12")
    print()
    span = 97 if SUBST else NTRUE
    jobs = [(d, L, kws) for d in range(span) for L in AZ if not (SUBST and L == CT[d])]
    alerts, dist, best_overall = [], [], None
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        for d, L, best in ex.map(_job, jobs, chunksize=8):
            if best is None:
                continue
            hits, s, kw, pts = best
            dist.append(hits)
            if best_overall is None or (hits, s) > (best_overall[0], best_overall[1]):
                best_overall = (hits, s, kw, d, L, pts)
            if hits >= 20 or (s >= -5.0 and hits >= 12):
                alerts.append({"d": d, "letter": L, "keyword": kw,
                               "crib_hits": hits, "ngram": round(s, 3),
                               "plaintext": pts})
    from collections import Counter
    c = Counter(dist)
    print(f"  best crib_hits distribution over {len(dist):,} corrected ciphertexts:")
    for h in sorted(c):
        print(f"     {h:>2}/24 : {c[h]:>6,}")
    if best_overall:
        hits, s, kw, d, L, pts = best_overall
        print()
        print(f"  BEST OVERALL: {hits}/24 cribs, ngram {s:.3f}/quadgram, "
              f"keyword {kw}, insert '{L}' at {d}")
        print(f"    {pts}")
    print()
    print(f"  ALERTS: {len(alerts)}")
    for a in alerts[:10]:
        print("   ", a)
    if not alerts:
        print("    none — clean null, as predicted.")
    art = os.path.join(_ROOT, "results", "e_crib_38_omission_quagmire_search.json")
    with open(art, "w") as fh:
        json.dump({"alerts": alerts, "distribution": dict(c),
                   "best": best_overall[:5] if best_overall else None,
                   "n_keywords": len(kws)}, fh, indent=2)
    print(f"\nartifact: {art}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
