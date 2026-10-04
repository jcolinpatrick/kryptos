#!/usr/bin/env python3
"""
Cipher: English running key + width-31 grid turn (fill rows / read columns), both layer orders
Family: transposition
Status: exhausted
Keyspace: see PREREG (16 distinct width-31 turn orderings x 7 tableau cells x 2 layer orders; Tier 2b widths 2-96, 1,492 orderings)
Last run: 2026-10-04 (full_prereg_2026_10_04; result in docs/campaigns/w31_running_key_prereg_2026_10_04.md section 13)
Best score: n/a (Tier 1 family max -5.823 vs bar -4.924; 0 promoted, 0 nominated)

E-W31RK-01: is K4 an English running key combined with a width-31 grid turn?

    Order A (Tier 1):  PT -> running key indexed by PT position -> X -> width-31 turn -> CT
    Order B (Tier 2a): PT -> width-31 turn -> Y -> running key indexed by CT position -> CT

In order A the cribs force two CONTIGUOUS stretches of the key text (plaintext positions 21-33
and 63-73), so an English key is testable without knowing its source: S_A is their mean
quadgram log10. In order B the forced key letters are scattered (every 3rd-4th key letter);
S_B is their mean English unigram log10 and can only nominate.

Pre-registration: docs/campaigns/w31_running_key_prereg_2026_10_04.md
PROMOTED means "hand to red-team", never "solved".
"""
from __future__ import annotations

import argparse
import cProfile
import hashlib
import json
import math
import os
import pstats
import random
import re
import statistics as st
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT  # noqa: E402
from kryptos.kernel.scoring.ngram import get_default_scorer  # noqa: E402

# ── FROZEN PRE-REGISTRATION CONSTANTS (changing any needs a new campaign id) ──────────
PREREG = {
    "campaign": "E-W31RK-01",
    "n": 97,
    "tier1_width": 31,
    "tier2b_widths": [2, 96],
    "fills": ["LR-TB", "RL-TB", "LR-BT", "RL-BT"],
    "reads": ["TB-LR", "BT-LR", "TB-RL", "BT-RL"],
    "blanks": ["end", "start"],
    "directions": ["P", "P^-1"],
    "cells": ["AZ-vig", "AZ-beau", "AZ-varb", "KA-vig", "KA-beau", "KA-varb", "sculpt"],
    "crib_fragments": [[21, 33], [63, 73]],
    "statistic_A": "mean quadgram log10 (kernel default scorer) over K[21..33] and K[63..73] (18 quadgrams)",
    "statistic_B": "mean English unigram log10 (calibration corpus) over the 24 forced key letters",
    "tau": -4.924,
    "bar_tier1": -4.924,
    "bar_tier2a": -1.272,
    "bar_tier2b": -4.941,
    "null_seeds_tier1_2a": [0, 1999],
    "null_seeds_tier2b": [0, 999],
    "calib_h1_seed": 20261004, "calib_h1_n": 20000,
    "calib_pc_tier1_seed0": 10000, "calib_pc_tier1_n": 500,
    "calib_pc_tier2_seed0": 50000, "calib_pc_tier2_n": 1000,
    "quadgram_file": "data/english_quadgrams.json", "quadgram_sha256_16": "fcd82bc26db56042",
    "corpus": {
        "reference/carter_gutenberg.txt": "5edf7326bec21317",
        "reference/running_key_texts/cia_charter.txt": "17f7da62085bd13d",
        "reference/running_key_texts/jfk_berlin.txt": "14c3336b237422cd",
        "reference/running_key_texts/kahn_codebreakers_1967.txt": "8ecbf6a0944c9d7a",
        "reference/running_key_texts/nsa_act_1947.txt": "a96466af3849d2ea",
        "reference/running_key_texts/reagan_berlin.txt": "1c1fc07020e25dcb",
        "reference/running_key_texts/udhr.txt": "305445ac2e6bd0f9",
    },
}
# ──────────────────────────────────────────────────────────────────────────────────────

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
N = PREREG["n"]
A_RANGE = range(PREREG["crib_fragments"][0][0], PREREG["crib_fragments"][0][1] + 1)
B_RANGE = range(PREREG["crib_fragments"][1][0], PREREG["crib_fragments"][1][1] + 1)

# key index from (ct letter, pt letter), and the alphabet that names the key letter
DERIVE = {
    "AZ-vig": (lambda c, p: (AZ.index(c) - AZ.index(p)) % 26, AZ),
    "AZ-beau": (lambda c, p: (AZ.index(c) + AZ.index(p)) % 26, AZ),
    "AZ-varb": (lambda c, p: (AZ.index(p) - AZ.index(c)) % 26, AZ),
    "KA-vig": (lambda c, p: (KA.index(c) - KA.index(p)) % 26, KA),
    "KA-beau": (lambda c, p: (KA.index(c) + KA.index(p)) % 26, KA),
    "KA-varb": (lambda c, p: (KA.index(p) - KA.index(c)) % 26, KA),
    "sculpt": (lambda c, p: (KA.index(c) - AZ.index(p)) % 26, AZ),
}
# ct letter from (pt letter, key letter); inverse of DERIVE
ENC = {
    "AZ-vig": lambda p, k: AZ[(AZ.index(p) + AZ.index(k)) % 26],
    "AZ-beau": lambda p, k: AZ[(AZ.index(k) - AZ.index(p)) % 26],
    "AZ-varb": lambda p, k: AZ[(AZ.index(p) - AZ.index(k)) % 26],
    "KA-vig": lambda p, k: KA[(KA.index(p) + KA.index(k)) % 26],
    "KA-beau": lambda p, k: KA[(KA.index(k) - KA.index(p)) % 26],
    "KA-varb": lambda p, k: KA[(KA.index(p) - KA.index(k)) % 26],
    "sculpt": lambda p, k: KA[(AZ.index(p) + AZ.index(k)) % 26],
}
assert list(DERIVE) == PREREG["cells"] == list(ENC)


# ── turn permutations ────────────────────────────────────────────────────────────────
def grid_cells(n: int, w: int, fill: str, blanks_at_start: bool) -> list[tuple[int, int]]:
    """Row-major fill from a corner; the first n cells of the fill sequence hold letters
    (the LAST n when blanks are at the start)."""
    rows = -(-n // w)
    seq: list[tuple[int, int]] = []
    rr = range(rows) if fill.endswith("TB") else range(rows - 1, -1, -1)
    for r in rr:
        cc = range(w) if fill.startswith("LR") else range(w - 1, -1, -1)
        seq += [(r, c) for c in cc]
    return seq[len(seq) - n:] if blanks_at_start else seq[:n]


def turn_perm(n: int, w: int, fill: str, read: str, blanks_at_start: bool) -> list[int]:
    """Encryption gather permutation: out[j] = in[src[j]]; column-major read from a corner."""
    cells = grid_cells(n, w, fill, blanks_at_start)
    where = {rc: i for i, rc in enumerate(cells)}
    rows = -(-n // w)
    src: list[int] = []
    cols = range(w) if read.endswith("LR") else range(w - 1, -1, -1)
    for c in cols:
        rr = range(rows) if read.startswith("TB") else range(rows - 1, -1, -1)
        src += [where[(r, c)] for r in rr if (r, c) in where]
    return src


def invert(src: list[int]) -> list[int]:
    inv = [0] * len(src)
    for j, q in enumerate(src):
        inv[q] = j
    return inv


def distinct_orderings(widths) -> list[dict]:
    """Every label maps to a distinct permutation; duplicates are recorded on the first label."""
    seen: dict[tuple, dict] = {}
    for w in widths:
        for fl in PREREG["fills"]:
            for rd in PREREG["reads"]:
                for bl in PREREG["blanks"]:
                    s = turn_perm(N, w, fl, rd, bl == "start")
                    for d, src in (("P", s), ("P^-1", invert(s))):
                        key = tuple(src)
                        lab = f"w{w}|{fl}|{rd}|blanks-{bl}|{d}"
                        if key in seen:
                            seen[key]["aliases"].append(lab)
                        else:
                            seen[key] = {"id": lab, "width": w, "src": src, "aliases": [lab]}
    return list(seen.values())


# ── statistics ───────────────────────────────────────────────────────────────────────
SC = None
LOGU = None


def _init_scorers(unigram: dict | None = None) -> None:
    global SC, LOGU
    SC = get_default_scorer()
    LOGU = unigram


def forced_key(ct: str, cribs: dict, src: list[int], cell: str, order: str) -> dict[int, str]:
    """Key letters forced by the cribs, keyed by key-text position (PT index in A, CT index in B)."""
    pos = {s: j for j, s in enumerate(src)}  # PT index q lands at CT index pos[q]
    f, alpha = DERIVE[cell]
    return {(q if order == "A" else pos[q]): alpha[f(ct[pos[q]], p)] for q, p in cribs.items()}


def s_frag(k1: str, k2: str) -> float:
    return (SC.score(k1) + SC.score(k2)) / ((len(k1) - 3) + (len(k2) - 3))


def stat_A(ct: str, cribs: dict, src: list[int], cell: str) -> float:
    k = forced_key(ct, cribs, src, cell, "A")
    return s_frag("".join(k[q] for q in A_RANGE), "".join(k[q] for q in B_RANGE))


def stat_B(ct: str, cribs: dict, src: list[int], cell: str) -> float:
    k = forced_key(ct, cribs, src, cell, "B")
    return sum(LOGU[ch] for ch in k.values()) / len(k)


def family_max(ct: str, cribs: dict, ords: list[dict], stat) -> float:
    return max(stat(ct, cribs, o["src"], cell) for o in ords for cell in PREREG["cells"])


# ── corpus ───────────────────────────────────────────────────────────────────────────
def load_corpus(check: bool = True) -> dict[str, str]:
    out = {}
    for rel, h in PREREG["corpus"].items():
        raw = open(os.path.join(_ROOT, rel), encoding="utf-8", errors="replace").read()
        got = hashlib.sha256(raw.encode()).hexdigest()[:16]
        if check and got != h:
            raise SystemExit(f"PREREG deviation: corpus {rel} sha256 {got} != frozen {h}")
        out[rel] = re.sub("[^A-Z]", "", raw.upper())
    return out


def unigram_table(corpus: dict[str, str]) -> dict[str, float]:
    u = Counter("".join(corpus.values()))
    tot = sum(u.values())
    return {c: math.log10(u[c] / tot) for c in AZ}


def check_quadgram_file() -> str:
    got = hashlib.sha256(open(os.path.join(_ROOT, PREREG["quadgram_file"]), "rb").read()).hexdigest()[:16]
    if got != PREREG["quadgram_sha256_16"]:
        raise SystemExit(f"PREREG deviation: quadgram file sha256 {got} != frozen {PREREG['quadgram_sha256_16']}")
    return got


# ── parallel workers ─────────────────────────────────────────────────────────────────
_W: dict = {}
_PIN_COUNTER = None  # set in main() before pools are created (fork start method inherits it)


def _worker_init(unigram, ords_by_tier, cpus, affinity) -> None:
    for v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"):
        os.environ[v] = "1"
    _init_scorers(unigram)
    _W["ords"] = ords_by_tier
    if affinity == "pin" and hasattr(os, "sched_setaffinity") and cpus and _PIN_COUNTER is not None:
        with _PIN_COUNTER.get_lock():
            ident = _PIN_COUNTER.value
            _PIN_COUNTER.value += 1
        cpu = cpus[ident % len(cpus)]
        os.sched_setaffinity(0, {cpu})
        print(f"  [affinity] worker {ident} pid {os.getpid()} -> cpu {cpu}", flush=True)


def _null_task(args) -> tuple[str, int, float]:
    tier, seed = args
    r = random.Random(seed)
    ct = list(CT)
    r.shuffle(ct)
    ct = "".join(ct)
    stat = stat_B if tier == "2a" else stat_A
    return tier, seed, family_max(ct, CRIB_DICT, _W["ords"][tier], stat)


def _synthetic(r: random.Random, corpus: dict[str, str], ords: list[dict], order: str):
    names = list(corpus)
    kn, pn = r.sample(names, 2)
    kt, ptt = corpus[kn], corpus[pn]
    o = r.randrange(len(kt) - N)
    key = kt[o:o + N]
    o2 = r.randrange(len(ptt) - N)
    pt = list(ptt[o2:o2 + N])
    pt[21:34] = "EASTNORTHEAST"
    pt[63:74] = "BERLINCLOCK"
    pt = "".join(pt)
    od = r.choice(ords)
    cell = r.choice(PREREG["cells"])
    src = od["src"]
    if order == "A":
        x = "".join(ENC[cell](pt[q], key[q]) for q in range(N))
        ct = "".join(x[s] for s in src)
    else:
        y = "".join(pt[s] for s in src)
        ct = "".join(ENC[cell](y[j], key[j]) for j in range(N))
    return ct, {q: pt[q] for q in CRIB_DICT}, od, cell


def _pc_task(args):
    tier, seed = args
    r = random.Random(seed)
    corpus = _W["corpus"]
    order = "B" if tier == "2a" else "A"
    ct, cribs, od, cell = _synthetic(r, corpus, _W["ords"][tier], order)
    stat = stat_B if tier == "2a" else stat_A
    true = stat(ct, cribs, od["src"], cell)
    if tier == "1":
        best = max(((stat(ct, cribs, o["src"], c), o["id"], c) for o in _W["ords"][tier] for c in PREREG["cells"]))
        return tier, true, best[1] == od["id"] and best[2] == cell
    return tier, true, None


def _pc_worker_init(unigram, ords_by_tier, corpus, cpus, affinity):
    _worker_init(unigram, ords_by_tier, cpus, affinity)
    _W["corpus"] = corpus


# ── universe / plan ──────────────────────────────────────────────────────────────────
def build_universe() -> dict[str, list[dict]]:
    t1 = distinct_orderings([PREREG["tier1_width"]])
    lo, hi = PREREG["tier2b_widths"]
    t2b = distinct_orderings(range(lo, hi + 1))
    return {"1": t1, "2a": t1, "2b": t2b}


def universe_hash(univ: dict[str, list[dict]]) -> str:
    h = hashlib.sha256(json.dumps(PREREG, sort_keys=True).encode())
    for tier in ("1", "2a", "2b"):
        for o in univ[tier]:
            for cell in PREREG["cells"]:
                h.update(f"{tier}|{o['id']}|{cell}|{hashlib.sha256(bytes(o['src'])).hexdigest()[:16]}\n".encode())
    return h.hexdigest()


# ── modes ────────────────────────────────────────────────────────────────────────────
def self_test() -> bool:
    ok = True
    sys.path.insert(0, os.path.join(_ROOT, "kryptosbot"))
    import panel_cribs as pc  # noqa: E402
    k3 = pc._K3_PT
    s1 = turn_perm(336, 42, "LR-TB", "BT-LR", False)
    i1 = "".join(k3[s] for s in s1)
    s2 = turn_perm(336, 14, "LR-TB", "BT-LR", False)
    ok &= ("".join(i1[s] for s in s2) == pc._K3_CT.replace("?", "")); print("K3 reproduced by two turns:", ok)
    c = ENC["KA-vig"]("B", "P") == "E"; ok &= c; print("KA tableau: B with key P gives E:", c)
    k1pt = pc._K1_PT.replace("IQLUSION", "ILLUSION")
    f, a = DERIVE["KA-vig"]
    k1 = "".join(a[f(x, y)] for x, y in zip(pc._K1_CT, k1pt))
    c = k1.startswith("PALIMPSESTPALIMPSEST") and k1[56] == "C"; ok &= c; print("K1 keyword recovered (with the C slip):", c)
    k2 = "".join(a[f(x, y)] for x, y in zip(pc._K2_CT.replace("?", ""), pc._K2_PT))
    c = k2.startswith("ABSCISSAABSCISSA"); ok &= c; print("K2 keyword recovered:", c)
    for cell in PREREG["cells"]:
        fd, al = DERIVE[cell]
        c = all(al[fd(ENC[cell](p, k), p)] == k for p in AZ for k in AZ); ok &= c
    print("ENC/DERIVE inverse for all 7 cells:", ok)
    n16 = len(distinct_orderings([31])); c = n16 == 16; ok &= c; print("distinct width-31 orderings == 16:", c, n16)
    print("SELF-TEST", "PASS" if ok else "FAIL")
    return ok


def run_pool(tasks, fn, init, initargs, workers, batch):
    with ProcessPoolExecutor(max_workers=workers, initializer=init, initargs=initargs) as ex:
        return list(ex.map(fn, tasks, chunksize=batch))


def calibrate(args, univ, corpus, unigram, cpus) -> dict:
    _init_scorers(unigram)
    r = random.Random(PREREG["calib_h1_seed"])
    texts = list(corpus.values())
    wts = [len(t) for t in texts]
    h1 = []
    for _ in range(PREREG["calib_h1_n"]):
        t = r.choices(texts, weights=wts)[0]
        o = r.randrange(len(t) - N)
        w = t[o:o + N]
        h1.append(s_frag(w[21:34], w[63:74]))
    h1.sort()
    tau = h1[int(0.05 * len(h1))]
    out = {"h1_mean": st.mean(h1), "tau_recomputed": tau}
    lo, hi = PREREG["null_seeds_tier1_2a"]
    lo2, hi2 = PREREG["null_seeds_tier2b"]
    tasks = [("1", s) for s in range(lo, hi + 1)] + [("2a", s) for s in range(lo, hi + 1)] + [("2b", s) for s in range(lo2, hi2 + 1)]
    res = run_pool(tasks, _null_task, _worker_init, (unigram, univ, cpus, args.affinity), args.workers, args.batch_size)
    nulls = {t: sorted(v for tt, _, v in res if tt == t) for t in ("1", "2a", "2b")}
    for t, v in nulls.items():
        out[f"null_{t}_q99"] = v[int(0.99 * len(v))]
        out[f"null_{t}_median"] = st.median(v)
    out["null_1_fwer_at_tau"] = sum(v >= PREREG["tau"] for v in nulls["1"]) / len(nulls["1"])
    pct = [("1", PREREG["calib_pc_tier1_seed0"] + i) for i in range(PREREG["calib_pc_tier1_n"])]
    pct += [("2a", PREREG["calib_pc_tier2_seed0"] + i) for i in range(PREREG["calib_pc_tier2_n"])]
    pct += [("2b", PREREG["calib_pc_tier2_seed0"] + i) for i in range(PREREG["calib_pc_tier2_n"])]
    pcs = run_pool(pct, _pc_task, _pc_worker_init, (unigram, univ, corpus, cpus, args.affinity), args.workers, args.batch_size)
    p1 = [(t, ok) for tier, t, ok in pcs if tier == "1"]
    out["pc_tier1_true_ge_tau"] = sum(t >= PREREG["tau"] for t, _ in p1) / len(p1)
    out["pc_tier1_true_is_family_max"] = sum(bool(ok) for _, ok in p1) / len(p1)
    for t, bar in (("2a", PREREG["bar_tier2a"]), ("2b", PREREG["bar_tier2b"])):
        v = [x for tier, x, _ in pcs if tier == t]
        out[f"pc_tier{t}_power_at_frozen_bar"] = sum(x >= bar for x in v) / len(v)
    return out


def real_run(args, univ, unigram, cpus) -> dict:
    _init_scorers(unigram)
    rows = []
    for tier, order, stat, bar in (("1", "A", stat_A, PREREG["bar_tier1"]), ("2a", "B", stat_B, PREREG["bar_tier2a"]),
                                   ("2b", "A", stat_A, PREREG["bar_tier2b"])):
        for o in univ[tier]:
            for cell in PREREG["cells"]:
                s = stat(CT, CRIB_DICT, o["src"], cell)
                k = forced_key(CT, CRIB_DICT, o["src"], cell, order)
                frag = ("".join(k[q] for q in A_RANGE) + "|" + "".join(k[q] for q in B_RANGE)) if order == "A" else "".join(k[j] for j in sorted(k))
                rows.append({"tier": tier, "order": order, "ordering": o["id"], "aliases": o["aliases"], "cell": cell,
                             "stat": round(s, 4), "forced_key": frag, "passes_bar": s >= bar})
    lo, hi = PREREG["null_seeds_tier1_2a"]
    lo2, hi2 = PREREG["null_seeds_tier2b"]
    tasks = [("1", s) for s in range(lo, hi + 1)] + [("2a", s) for s in range(lo, hi + 1)] + [("2b", s) for s in range(lo2, hi2 + 1)]
    res = run_pool(tasks, _null_task, _worker_init, (unigram, univ, cpus, args.affinity), args.workers, args.batch_size)
    summary = {}
    for t in ("1", "2a", "2b"):
        nv = sorted(v for tt, _, v in res if tt == t)
        kmax = max(r["stat"] for r in rows if r["tier"] == t)
        summary[t] = {"configs": sum(r["tier"] == t for r in rows), "k4_family_max": kmax,
                      "family_wise_p": sum(v >= kmax for v in nv) / len(nv),
                      "null_q99_recomputed": nv[int(0.99 * len(nv))], "null_median_recomputed": st.median(nv),
                      "n_pass_bar": sum(r["passes_bar"] for r in rows if r["tier"] == t)}
    summary["1"]["promoted"] = [r for r in rows if r["tier"] == "1" and r["passes_bar"]]
    summary["2a"]["nominated"] = [r for r in rows if r["tier"] == "2a" and r["passes_bar"]]
    summary["2b"]["nominated"] = [r for r in rows if r["tier"] == "2b" and r["passes_bar"]]
    return {"summary": summary, "rows": rows}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true", help="print counts and the universe hash")
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--calibrate", action="store_true", help="re-run section 5 calibration (no real-K4 statistic)")
    mode.add_argument("--run", action="store_true", help="real-K4 run (all tiers) + recomputed nulls")
    mode.add_argument("--benchmark", action="store_true", help="time the Tier-1 null at several worker counts")
    ap.add_argument("--workers", type=int, default=max(1, (len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else (os.cpu_count() or 2)) - 2))
    ap.add_argument("--batch-size", type=int, default=8, help="tasks per worker dispatch (chunksize)")
    ap.add_argument("--affinity", choices=["auto", "none", "pin"], default="auto", help="auto/none = OS scheduling; pin = one CPU per worker")
    ap.add_argument("--bench-workers", default="14,20,26")
    ap.add_argument("--profile", action="store_true", help="cProfile the selected mode")
    ap.add_argument("--out", default=os.path.join(_ROOT, "results", "e_w31rk_01"))
    ap.add_argument("--run-id", default=time.strftime("run_%Y%m%d_%H%M%S"))
    args = ap.parse_args()
    cpus = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else list(range(os.cpu_count() or 1))
    global _PIN_COUNTER
    if args.affinity == "pin":
        import multiprocessing as mp
        _PIN_COUNTER = mp.Value("i", 0)

    univ = build_universe()
    uh = universe_hash(univ)
    if args.plan:
        print(f"{PREREG['campaign']} universe hash: {uh}")
        for t in ("1", "2a", "2b"):
            print(f"  tier {t}: {len(univ[t])} distinct orderings x {len(PREREG['cells'])} cells = {len(univ[t]) * len(PREREG['cells'])}")
        return
    if args.self_test:
        sys.exit(0 if self_test() else 1)

    check_quadgram_file()
    corpus = load_corpus()
    unigram = unigram_table(corpus)
    print(f"{PREREG['campaign']} | universe {uh[:16]} | workers {args.workers} | batch {args.batch_size} | affinity {args.affinity} | usable CPUs {len(cpus)}")
    prof = cProfile.Profile() if args.profile else None
    if prof:
        prof.enable()
    t0 = time.perf_counter()
    if args.benchmark:
        lo, hi = PREREG["null_seeds_tier1_2a"]
        for w in [int(x) for x in args.bench_workers.split(",")]:
            t = time.perf_counter()
            run_pool([("1", s) for s in range(lo, lo + 400)], _null_task, _worker_init, (unigram, univ, cpus, args.affinity), w, args.batch_size)
            print(f"  benchmark workers={w}: 400 null families in {time.perf_counter() - t:.2f}s")
        out = None
    elif args.calibrate:
        out = {"mode": "calibrate", "universe_hash": uh, "calibration": calibrate(args, univ, corpus, unigram, cpus)}
    else:
        out = {"mode": "run", "universe_hash": uh, "prereg": PREREG, **real_run(args, univ, unigram, cpus)}
    if prof:
        prof.disable()
        pstats.Stats(prof).sort_stats("cumulative").print_stats(15)
    if out is not None:
        out["elapsed_s"] = round(time.perf_counter() - t0, 2)
        out["env"] = {"python": sys.version.split()[0], "workers": args.workers, "batch_size": args.batch_size,
                      "affinity": args.affinity, "usable_cpus": len(cpus)}
        d = os.path.join(args.out, args.run_id)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, f"{out['mode']}.json")
        with open(path, "w") as fh:
            json.dump(out, fh, indent=1, default=str)
        print(json.dumps({k: v for k, v in out.items() if k not in ("rows", "prereg")}, indent=1, default=str)[:6000])
        print("written:", path)


if __name__ == "__main__":
    main()
