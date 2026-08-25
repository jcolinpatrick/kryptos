#!/usr/bin/env python3
"""
e_crib_30_opening_keystream_discriminator
=========================================

FAMILY: crib_analysis
STATUS: active

QUESTION
--------
If K4 at positions 0-17 is an additive cipher (Vigenere / Beaufort / variant
Beaufort, standard or KRYPTOS-keyed alphabet) driven by a key taken from some
running TEXT, then the TRUE plaintext opening is the one whose derived
keystream is itself English.

'YESWONDERFULTHINGS' is a narrative hypothesis for that opening. It gives an
18-character CONTIGUOUS known-plaintext run, which the released cribs alone
cannot give (they are 13 and 11 characters, in two separate places).

So: derive the keystream implied by every English 18-gram in a 240-million-
character corpus, score each keystream with the quadgram model, and ask where
'YESWONDERFULTHINGS' lands. This is simultaneously
  (a) a discriminator test for the narrative hypothesis, and
  (b) a genuine running-key crib-drag over the whole corpus, since any offset
      at which BOTH sides score as English is a running-key hit.

CONTROLS (this is the important part)
-------------------------------------
The released cribs are ground truth. Score the keystream they imply too. If
EASTNORTHEAST's and BERLINCLOCK's own keystreams do NOT look English, then
K4's key is not text-derived and this test has no power to confirm anything --
it can then only fail to distinguish, never confirm. Reporting that honestly
matters more than the headline number.

PRE-REGISTERED (fixed before running)
-------------------------------------
  T1  'YESWONDERFULTHINGS' is DISTINGUISHED only if its keystream quadgram
      score sits in the top 1e-4 of the corpus 18-gram distribution for at
      least one (alphabet, variant) combo.
  T2  the test is POWERED only if the crib-implied keystreams score above the
      median of a random-letter null. Otherwise report NO POWER.
  T3  a running-key HIT requires both sides above the English 5th percentile
      AND a combined score in the top 20 of the whole sweep.

Repro:
  PYTHONPATH=src OMP_NUM_THREADS=1 python3 -u \
    scripts/crib_analysis/e_crib_30_opening_keystream_discriminator.py \
    --corpus <corpus.txt> --workers 14
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor

os.environ.setdefault("OMP_NUM_THREADS", "1")
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("MKL_NUM_THREADS", "1")

import numpy as np

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT, KRYPTOS_ALPHABET as KA  # noqa: E402

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABETS = {"AZ": AZ, "KA": KA}
VARIANTS = ("vig", "beau", "vbeau")
COMBOS = [(a, v) for a in ALPHABETS for v in VARIANTS]
OPENING = "YESWONDERFULTHINGS"
NLEN = len(OPENING)

_QG: np.ndarray | None = None


def load_qg() -> np.ndarray:
    global _QG
    if _QG is None:
        with open(os.path.join(_ROOT, "data", "english_quadgrams.json")) as fh:
            d = json.load(fh)
        floor = min(d.values()) - 1.0
        arr = np.full(26 ** 4, floor, dtype=np.float32)
        for q, v in d.items():
            if len(q) == 4 and q.isalpha():
                c = ((ord(q[0]) - 65) * 17576 + (ord(q[1]) - 65) * 676
                     + (ord(q[2]) - 65) * 26 + (ord(q[3]) - 65))
                arr[c] = v
        _QG = arr
    return _QG


def luts():
    out = {}
    for an, alpha in ALPHABETS.items():
        fwd = np.zeros(26, dtype=np.int16)
        inv = np.zeros(26, dtype=np.int16)
        for i, ch in enumerate(alpha):
            fwd[ord(ch) - 65] = i
            inv[i] = ord(ch) - 65
        out[an] = (fwd, inv)
    return out


def keystream_codes(pt_az: np.ndarray, ct_az: np.ndarray, an: str, v: str, L) -> np.ndarray:
    """pt_az: (n,len) AZ codes. Returns keystream as AZ codes, same shape."""
    fwd, inv = L[an]
    p = fwd[pt_az]
    c = fwd[ct_az]
    if v == "vig":
        k = (c - p) % 26
    elif v == "beau":
        k = (c + p) % 26
    else:
        k = (p - c) % 26
    return inv[k]


def score_seq(seq_az: np.ndarray, qg: np.ndarray) -> np.ndarray:
    """seq_az: (n, m) AZ codes -> (n,) summed quadgram log-prob."""
    n, m = seq_az.shape
    s = np.zeros(n, dtype=np.float64)
    a = seq_az.astype(np.int32)
    for j in range(m - 3):
        code = a[:, j] * 17576 + a[:, j + 1] * 676 + a[:, j + 2] * 26 + a[:, j + 3]
        s += qg[code]
    return s


def _worker(job):
    corpus_path, start, length, topk = job
    qg = load_qg()
    L = luts()
    ct_head = np.frombuffer(CT[:NLEN].encode(), dtype=np.uint8).astype(np.int16) - 65

    mm = np.memmap(corpus_path, dtype=np.uint8, mode="r")
    end = min(start + length + NLEN - 1, mm.shape[0])
    block = np.asarray(mm[start:end], dtype=np.uint8).astype(np.int16) - 65
    n = block.shape[0] - NLEN + 1
    if n <= 0:
        return {"count": 0, "hist": None, "top": {}}

    fwd_all = {an: L[an][0] for an in ALPHABETS}
    inv_all = {an: L[an][1] for an in ALPHABETS}

    # K[j] over all offsets, per combo, built from shifted views (no (n,18) copy)
    bins = np.arange(-260.0, 40.0, 1.0)
    hist = {f"{a}-{v}": np.zeros(len(bins) - 1, dtype=np.int64) for a, v in COMBOS}
    top = {f"{a}-{v}": [] for a, v in COMBOS}

    CH = 2_000_000
    for s0 in range(0, n, CH):
        s1 = min(s0 + CH, n)
        m = s1 - s0
        for an, v in COMBOS:
            key = f"{an}-{v}"
            fwd, inv = fwd_all[an], inv_all[an]
            kcols = np.empty((NLEN, m), dtype=np.int32)
            for j in range(NLEN):
                p = fwd[block[s0 + j:s0 + j + m]]
                c = fwd[ct_head[j]]
                if v == "vig":
                    kk = (c - p) % 26
                elif v == "beau":
                    kk = (c + p) % 26
                else:
                    kk = (p - c) % 26
                kcols[j] = inv[kk]
            sc = np.zeros(m, dtype=np.float32)
            for j in range(NLEN - 3):
                code = (kcols[j] * 17576 + kcols[j + 1] * 676
                        + kcols[j + 2] * 26 + kcols[j + 3])
                sc += qg[code]
            hist[key] += np.histogram(sc, bins=bins)[0]
            idx = np.argpartition(sc, -topk)[-topk:]
            for i in idx:
                top[key].append((float(sc[i]), int(start + s0 + i)))
            del kcols
        del_ = None
    for key in top:
        top[key] = sorted(top[key], reverse=True)[:topk]
    return {"count": n, "hist": {k: v.tolist() for k, v in hist.items()},
            "top": top, "bins": bins.tolist()}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus", required=True)
    ap.add_argument("--workers", type=int, default=14)
    ap.add_argument("--topk", type=int, default=25)
    ap.add_argument("--limit", type=int, default=0, help="cap corpus chars (0=all)")
    ap.add_argument("--benchmark", action="store_true")
    args = ap.parse_args()

    qg = load_qg()
    L = luts()
    size = os.path.getsize(args.corpus)
    if args.limit:
        size = min(size, args.limit)

    print("=" * 78)
    print("OPENING-KEYSTREAM DISCRIMINATOR  /  RUNNING-KEY CRIB-DRAG AT 0-17")
    print("=" * 78)
    print(f"  corpus            : {args.corpus}")
    print(f"  corpus characters : {size:,}   (18-gram offsets: {size-17:,})")
    print(f"  combos            : {len(COMBOS)}  {[f'{a}-{v}' for a,v in COMBOS]}")
    print(f"  workers           : {args.workers}")
    print()

    # ---------- CONTROL: do the KNOWN cribs imply an English keystream? ----------
    print("  CONTROL (pre-registered T2) — keystream implied by the RELEASED cribs")
    print("  If K4's key were a running text, these MUST look English.")
    rng = np.random.default_rng(7)
    ctl = {}
    for label, lo, hi in (("EASTNORTHEAST", 21, 34), ("BERLINCLOCK", 63, 74)):
        pt = "".join(CRIB_DICT[i] for i in range(lo, hi))
        ct = CT[lo:hi]
        pt_az = np.frombuffer(pt.encode(), dtype=np.uint8).astype(np.int16)[None, :] - 65
        ct_az = np.frombuffer(ct.encode(), dtype=np.uint8).astype(np.int16)[None, :] - 65
        m = hi - lo
        rand = rng.integers(0, 26, size=(200_000, m))
        eng_null = score_seq(rand, qg) / (m - 3)
        print(f"    {label} ({m} chars, {m-3} quadgrams)")
        for an, v in COMBOS:
            k = keystream_codes(pt_az, ct_az, an, v, L)
            s = score_seq(k, qg)[0] / (m - 3)
            pct = float((eng_null < s).mean())
            ks = "".join(AZ[c] for c in k[0])
            ctl[f"{label}|{an}-{v}"] = {"keystream": ks, "per_qg": s, "pct_vs_random": pct}
            print(f"      {an}-{v:<6} k={ks:<14} score/qg={s:>7.3f}"
                  f"   percentile vs random letters: {pct*100:>5.1f}%")
        print(f"      (random-letter null mean = {eng_null.mean():.3f}, "
              f"English text ~ -3.0 per quadgram)")
        print()

    # ---------- the sweep ----------
    chunk = max(4_000_000, (size // (args.workers * 4)) + 1)
    jobs = [(args.corpus, s, chunk, args.topk) for s in range(0, size - NLEN, chunk)]
    print(f"  sweeping {len(jobs)} chunks of ~{chunk:,} chars ...")
    t0 = time.perf_counter()
    agg_hist = {f"{a}-{v}": None for a, v in COMBOS}
    agg_top = {f"{a}-{v}": [] for a, v in COMBOS}
    total = 0
    bins = None
    with ProcessPoolExecutor(max_workers=args.workers) as ex:
        for r in ex.map(_worker, jobs):
            if not r["count"]:
                continue
            total += r["count"]
            bins = r["bins"]
            for k, h in r["hist"].items():
                h = np.array(h, dtype=np.int64)
                agg_hist[k] = h if agg_hist[k] is None else agg_hist[k] + h
            for k, t in r["top"].items():
                agg_top[k].extend(t)
    dt = time.perf_counter() - t0
    print(f"  swept {total:,} offsets x {len(COMBOS)} combos in {dt:.1f}s "
          f"({total*len(COMBOS)/dt/1e6:.1f}M offset-combos/s)")
    print()

    # ---------- where does YESWONDERFULTHINGS land? ----------
    print("  RESULT (pre-registered T1: distinguished iff top 1e-4)")
    pt_az = np.frombuffer(OPENING.encode(), dtype=np.uint8).astype(np.int16)[None, :] - 65
    ct_az = np.frombuffer(CT[:NLEN].encode(), dtype=np.uint8).astype(np.int16)[None, :] - 65
    bins_a = np.array(bins)
    out = {}
    for an, v in COMBOS:
        key = f"{an}-{v}"
        k = keystream_codes(pt_az, ct_az, an, v, L)
        s = float(score_seq(k, qg)[0])
        ks = "".join(AZ[c] for c in k[0])
        h = agg_hist[key]
        n_above = int(h[bins_a[:-1] >= s].sum())
        frac = n_above / max(total, 1)
        tops = sorted(agg_top[key], reverse=True)[:5]
        out[key] = {"keystream": ks, "score": s, "frac_corpus_above": frac,
                    "top5": tops}
        verdict = "DISTINGUISHED" if frac <= 1e-4 else "not distinguished"
        print(f"    {key:<10} k[0:18]={ks}")
        print(f"               score={s:>9.2f}   corpus 18-grams scoring higher: "
              f"{n_above:,} / {total:,} = {frac:.3%}   -> {verdict}")
    print()

    print("  BEST RUNNING-KEY CANDIDATES FOUND (top keystream scores in corpus)")
    mm = np.memmap(args.corpus, dtype=np.uint8, mode="r")
    for an, v in COMBOS:
        key = f"{an}-{v}"
        print(f"    {key}")
        for sc, off in sorted(agg_top[key], reverse=True)[:5]:
            cand = bytes(mm[off:off + NLEN]).decode()
            ca = np.frombuffer(cand.encode(), dtype=np.uint8).astype(np.int16)[None, :] - 65
            kk = keystream_codes(ca, ct_az, an, v, L)
            kss = "".join(AZ[c] for c in kk[0])
            print(f"      score={sc:>9.2f}  PT={cand}  ->  K={kss}")
    print()

    art = os.path.join(_ROOT, "results", "e_crib_30_opening_keystream_discriminator.json")
    with open(art, "w") as fh:
        json.dump({"control": ctl, "opening": out, "offsets_swept": total,
                   "corpus": args.corpus, "corpus_chars": size}, fh, indent=2)
    print(f"artifact: {art}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
