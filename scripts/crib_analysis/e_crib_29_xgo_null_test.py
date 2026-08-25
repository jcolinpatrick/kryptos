#!/usr/bin/env python3
"""
e_crib_29_xgo_null_test
=======================

FAMILY: crib_analysis
STATUS: active

QUESTION
--------
Under the released cribs alone, the K4 keystream at positions 22,23,24 is
determined. Extending that keystream BACKWARD by one period predicts the
plaintext at 18,19,20. Over the full admissible rule space
(alphabet x variant x period) this yields 80 distinct candidate trigrams.

Exactly one of them, 'XGO', is an X-separator followed by a two-letter English
word that grammatically continues into the crib 'EASTNORTHEAST'. That trigram
was independently proposed on narrative grounds before any keystream was
derived.

HOW SURPRISING IS THAT?

PRE-REGISTERED STATISTICS (fixed before any trial is run)
---------------------------------------------------------
  S1  the predicted-trigram set contains exactly 'XGO'
  S2  it contains 'X' + one of 24 common two-letter English words
      (the criterion that actually fired on the real ciphertext)
  S3  analyst-degrees-of-freedom version: S2, OR the set contains a
      two-letter word followed by 'X', OR it contains a top-300 English
      trigram (i.e. any trigram that would have looked "readable")

NULL MODELS
-----------
  shuffled_ct   random permutation of the real 97 CT letters   (primary)
  matched_freq  i.i.d. letters drawn from the CT letter distribution
  uniform       i.i.d. uniform letters

In every null the released cribs stay pinned at 21-33 and 63-73; only the
ciphertext varies. This asks: "would ANY ciphertext have handed us a trigram
this suggestive?"

DECISION RULE
-------------
  p(S2) <= 1e-3  -> the coincidence is worth a mechanism hunt
  p(S2) >  1e-2  -> the coincidence is unremarkable; drop it

Repro:
  PYTHONPATH=src python3 -u scripts/crib_analysis/e_crib_29_xgo_null_test.py \
      --trials 1000000 --workers 14
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter

import numpy as np

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT, KRYPTOS_ALPHABET as KA  # noqa: E402

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABETS = {"AZ": AZ, "KA": KA}
VARIANTS = ("vig", "beau", "vbeau")
OUT_POS = (18, 19, 20)

TWO_LETTER = [
    "GO", "TO", "IT", "IS", "IN", "ON", "AT", "AS", "BE", "BY", "DO", "IF",
    "ME", "MY", "NO", "OF", "OR", "SO", "UP", "US", "WE", "HE", "AM", "AN",
]


def admissible_rules() -> list[tuple[str, str, int]]:
    """(alphabet, variant, period) where all three source positions are cribs."""
    out = []
    for an in ALPHABETS:
        for v in VARIANTS:
            for p in range(1, 80):
                if all((q + p) in CRIB_DICT for q in OUT_POS):
                    out.append((an, v, p))
    return out


def build_targets() -> dict[str, np.ndarray]:
    """Boolean masks over the 17576 trigram codes, one per pre-registered stat."""
    def code(t: str) -> int:
        return (ord(t[0]) - 65) * 676 + (ord(t[1]) - 65) * 26 + (ord(t[2]) - 65)

    s1 = np.zeros(17576, dtype=bool)
    s1[code("XGO")] = True

    s2 = np.zeros(17576, dtype=bool)
    for w in TWO_LETTER:
        s2[code("X" + w)] = True

    s3 = s2.copy()
    for w in TWO_LETTER:
        s3[code(w + "X")] = True
    # top-300 English trigrams by wordlist frequency
    tri: Counter[str] = Counter()
    wl = os.path.join(_ROOT, "wordlists", "english.txt")
    with open(wl, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            w = line.strip().upper()
            if w.isalpha():
                for i in range(len(w) - 2):
                    tri[w[i:i + 3]] += 1
    for t, _ in tri.most_common(300):
        s3[code(t)] = True
    return {"S1_XGO": s1, "S2_X_plus_word": s2, "S3_analyst_dof": s3}


def make_lut() -> dict[str, tuple[np.ndarray, np.ndarray]]:
    """For each alphabet: AZcode->alphaIdx, and alphaIdx->AZcode."""
    lut = {}
    for an, alpha in ALPHABETS.items():
        fwd = np.zeros(26, dtype=np.int64)
        inv = np.zeros(26, dtype=np.int64)
        for i, ch in enumerate(alpha):
            fwd[ord(ch) - 65] = i
            inv[i] = ord(ch) - 65
        lut[an] = (fwd, inv)
    return lut


def predicted_codes(ct_block: np.ndarray, rules, lut, crib_idx) -> np.ndarray:
    """(T, n_rules) trigram codes predicted by each rule."""
    T = ct_block.shape[0]
    out = np.empty((T, len(rules)), dtype=np.int64)
    cache: dict[str, np.ndarray] = {}
    for r, (an, v, p) in enumerate(rules):
        fwd, inv = lut[an]
        if an not in cache:
            cache[an] = fwd[ct_block]
        ct_a = cache[an]
        parts = []
        for q in OUT_POS:
            s = q + p
            c_s = ct_a[:, s]
            t_s = crib_idx[an][s]
            c_q = ct_a[:, q]
            if v == "vig":
                k = (c_s - t_s) % 26
                pr = (c_q - k) % 26
            elif v == "beau":
                k = (c_s + t_s) % 26
                pr = (k - c_q) % 26
            else:
                k = (t_s - c_s) % 26
                pr = (c_q + k) % 26
            parts.append(inv[pr])
        out[:, r] = parts[0] * 676 + parts[1] * 26 + parts[2]
    return out


def run_null(null: str, trials: int, chunk: int, seed: int, rules, lut, crib_idx,
             targets) -> dict:
    rng = np.random.default_rng(seed)
    ct_codes = np.frombuffer(CT.encode(), dtype=np.uint8).astype(np.int64) - 65
    freq = np.bincount(ct_codes, minlength=26) / 97.0
    hits = {k: 0 for k in targets}
    done = 0
    while done < trials:
        n = min(chunk, trials - done)
        if null == "shuffled_ct":
            block = np.tile(ct_codes, (n, 1))
            block = rng.permuted(block, axis=1)
        elif null == "matched_freq":
            block = rng.choice(26, size=(n, 97), p=freq)
        else:
            block = rng.integers(0, 26, size=(n, 97))
        codes = predicted_codes(block, rules, lut, crib_idx)
        for name, mask in targets.items():
            hits[name] += int(mask[codes].any(axis=1).sum())
        done += n
    return {k: {"hits": v, "trials": trials, "p": v / trials} for k, v in hits.items()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=1_000_000)
    ap.add_argument("--chunk", type=int, default=25_000)
    ap.add_argument("--seed", type=int, default=20260825)
    ap.add_argument("--workers", type=int, default=14, help="unused: numpy path is vectorised")
    ap.add_argument("--benchmark", action="store_true")
    args = ap.parse_args()

    rules = admissible_rules()
    lut = make_lut()
    crib_idx = {an: {p: ALPHABETS[an].index(c) for p, c in CRIB_DICT.items()}
                for an in ALPHABETS}
    targets = build_targets()

    print("=" * 78)
    print("XGO COINCIDENCE — MONTE CARLO NULL TEST")
    print("=" * 78)
    print(f"  admissible rules            : {len(rules)}")
    print(f"  periods used                : {sorted({p for _,_,p in rules})}")
    print(f"  pre-registered statistics   : {list(targets)}")
    print(f"  |S1| |S2| |S3| trigrams     : "
          f"{targets['S1_XGO'].sum()} {targets['S2_X_plus_word'].sum()} "
          f"{targets['S3_analyst_dof'].sum()} of 17576")
    print()

    # observed on the real ciphertext
    real = np.frombuffer(CT.encode(), dtype=np.uint8).astype(np.int64)[None, :] - 65
    obs = predicted_codes(real, rules, lut, crib_idx)[0]
    distinct = sorted({c for c in obs})
    def dec(c):
        return chr(65 + c // 676) + chr(65 + (c // 26) % 26) + chr(65 + c % 26)
    print(f"  REAL CT: {len(distinct)} distinct predicted trigrams")
    for name, mask in targets.items():
        fired = sorted({dec(c) for c in obs if mask[c]})
        print(f"    {name:<18} fired={bool(fired)}  {fired}")
    print()

    if args.benchmark:
        t0 = time.perf_counter()
        run_null("shuffled_ct", 25_000, 25_000, 1, rules, lut, crib_idx, targets)
        dt = time.perf_counter() - t0
        print(f"  benchmark: 25000 trials in {dt:.2f}s -> {25_000/dt:,.0f} trials/s")
        print()

    results = {}
    for null in ("shuffled_ct", "matched_freq", "uniform"):
        t0 = time.perf_counter()
        r = run_null(null, args.trials, args.chunk, args.seed, rules, lut, crib_idx, targets)
        dt = time.perf_counter() - t0
        results[null] = r
        print(f"  NULL = {null}   ({args.trials:,} trials, {dt:.1f}s)")
        for name, v in r.items():
            print(f"    {name:<18} hits={v['hits']:>8,}   p = {v['p']:.5f}")
        print()

    p2 = results["shuffled_ct"]["S2_X_plus_word"]["p"]
    print("  DECISION RULE (pre-registered):")
    print(f"    p(S2 | shuffled_ct) = {p2:.5f}")
    if p2 <= 1e-3:
        verdict = "WORTH A MECHANISM HUNT"
    elif p2 > 1e-2:
        verdict = "UNREMARKABLE — DROP IT"
    else:
        verdict = "INTERMEDIATE — suggestive, not evidential"
    print(f"    -> {verdict}")

    art = os.path.join(_ROOT, "results", "e_crib_29_xgo_null_test.json")
    with open(art, "w") as fh:
        json.dump({"rules": len(rules), "results": results, "verdict": verdict,
                   "observed_distinct": [dec(c) for c in distinct]}, fh, indent=2)
    print(f"\nartifact: {art}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
