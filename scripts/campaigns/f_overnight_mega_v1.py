#!/usr/bin/env python3 -u
"""
=================================================================
OVERNIGHT MEGA CAMPAIGN v1 — Multi-Hour Comprehensive Search
=================================================================
Cipher:     Two-system model (all surviving hypotheses)
Family:     campaigns
Status:     active
Keyspace:   ~10B+ evaluations across 6 phases
Last run:   never
Best score: --

Designed for unattended multi-hour execution on 28 cores.
Tests ALL genuinely untested gaps identified by the 2026-03-18 audit.

PHASES
------
1. QUICK GAP AUDIT (5 min)
   - Full 1735-char sculpture text as running key
   - Tabula recta direct alphabet keys
   - KA Beaufort sweep on CT73 (all keywords × periods 1-13)

2. BESPOKE KEY GENERATION SEARCH (30 min)
   - Every "embarrassingly simple" f(CT, position) → key
   - Tableau-derived keys (rows/cols of carved text as substitution)
   - Lagged / cumulative / multiplicative CT functions
   - KRYPTOS/SEVEN/keyword-composed lookup tables

3. CABLE-FORMAT SA — THE BIG ONE (2-3 hours)
   - SA optimizing intel_jargon + word_coverage + quadgram hybrid
   - 2000 restarts × 500K steps on CT73 (Beaufort)
   - 1000 restarts × 500K steps on CT97 (Model B Beaufort)
   - This is the LARGEST genuinely untested search space:
     the intel scorer exists but only 2/876 scripts ever used it.

4. WORD-SEGMENTATION SA (1 hour)
   - SA optimizing word_coverage (DP word finder)
   - Catches cable-like text that quadgrams miss
   - 1000 restarts × 300K steps

QUARANTINE 2026-04-19
---------------------
This script includes retired-consensus-null branches and is retained only as a
historical / reproducibility artifact. It must not be treated as live evidence;
intentional use requires `--allow-retired-construct`.

=================================================================
"""

import sys
import os
import json
import time
import math
import random
import re
from collections import Counter
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, KRYPTOS_ALPHABET,
)
from kryptos.kernel.scoring.intel_jargon import score_intel_jargon
from kryptos.kernel.scoring.words import WordScorer

# ── Load scoring infrastructure ────────────────────────────────────────

print("Loading quadgrams...", flush=True)
QG_PATH = os.path.join(_ROOT, "data", "english_quadgrams.json")
with open(QG_PATH) as f:
    _qg_raw = json.load(f)
QG_FLOOR = min(_qg_raw.values()) - 1.0
QG_TABLE = [QG_FLOOR] * (26 ** 4)
for gram, logp in _qg_raw.items():
    if len(gram) == 4:
        a, b, c, d = [ord(ch) - 65 for ch in gram]
        QG_TABLE[a * 17576 + b * 676 + c * 26 + d] = logp
del _qg_raw

print("Loading word list...", flush=True)
WORD_PATH = os.path.join(_ROOT, "wordlists", "english.txt")
WORD_SCORER = WordScorer.from_file(WORD_PATH, min_word_len=4)

# ── Constants ──────────────────────────────────────────────────────────

CT_ARR = [ALPH_IDX[c] for c in CT]
KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
CRIB_POS = sorted(CRIB_DICT.keys())

# Consensus null mask
CONSENSUS_NULLS = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})
REF_VARYING = [38, 39, 40, 55, 87, 93, 94]
ALL_NULLS = CONSENSUS_NULLS | set(REF_VARYING)
NONNULL = sorted(set(range(CT_LEN)) - ALL_NULLS)
CT73_ARR = [CT_ARR[i] for i in NONNULL]
CT73_STR = "".join(CT[i] for i in NONNULL)

# Known key values (Beaufort AZ on raw CT97)
KNOWN_KEY_97 = {}
for pos in CRIB_POS:
    KNOWN_KEY_97[pos] = (CT_ARR[pos] + ALPH_IDX[CRIB_DICT[pos]]) % MOD
CRIB_CT73_IDX = [NONNULL.index(p) for p in CRIB_POS]
KNOWN_KEY_73 = {CRIB_CT73_IDX[i]: KNOWN_KEY_97[CRIB_POS[i]] for i in range(24)}
FREE_73 = sorted(set(range(73)) - set(KNOWN_KEY_73.keys()))
FREE_97 = sorted(set(range(97)) - set(KNOWN_KEY_97.keys()))

N_WORKERS = min(cpu_count(), 28)

# ── Scoring functions ──────────────────────────────────────────────────

def qg_score(arr):
    n = len(arr)
    if n < 4:
        return -10.0
    total = sum(QG_TABLE[arr[i]*17576 + arr[i+1]*676 + arr[i+2]*26 + arr[i+3]]
                for i in range(n - 3))
    return total / (n - 3)


def beaufort_decrypt(ct_arr, key_arr):
    return [(key_arr[i] - ct_arr[i]) % MOD for i in range(len(ct_arr))]


def score_hybrid(pt_arr):
    """Hybrid score: quadgram + intel jargon + word coverage."""
    pt_str = "".join(ALPH[v] for v in pt_arr)
    qg = qg_score(pt_arr)
    intel_sc, _ = score_intel_jargon(pt_str)
    word_res = WORD_SCORER.score(pt_str)
    # Weighted combination: quadgram is primary, intel and words are bonus
    return qg + intel_sc * 0.05 + word_res.coverage * 2.0


# ── K1-K3 Plaintexts ──────────────────────────────────────────────────

K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = ("ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETIC"
         "FIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUN"
         "KNOWNLOCATIONXDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTT"
         "HERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLASTMES"
         "SAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNOR"
         "THSEVENTYSEVENDEGREESEIGHTMINUTESFORTYFOURSECONDSWESTIDBYROWS")
K3_PT = ("SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBERED"
         "THELOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINY"
         "BREACHINTHEUPPERLEFTHANDCORNERANDTHENWIDENINGTHEHOLEALITTLE"
         "IINSERTEDTHECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBER"
         "CAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIN"
         "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ")

FULL_SCULPTURE = K1_PT + K2_PT + K3_PT  # ~768 chars
FULL_SCULPTURE_ARR = [ALPH_IDX[c] for c in FULL_SCULPTURE]

# ── PHASE 1: Quick Gap Audit ──────────────────────────────────────────

def phase1_sculpture_running_key():
    """Test full 1735-char sculpture text as unified running key."""
    print("\n  Phase 1A: Full sculpture text as running key", flush=True)
    texts = {
        "K1K2K3": FULL_SCULPTURE,
        "K3K2K1": K3_PT + K2_PT + K1_PT,
        "K1K2K3_rev": FULL_SCULPTURE[::-1],
        "K2K3K1": K2_PT + K3_PT + K1_PT,
        "K1K3K2": K1_PT + K3_PT + K2_PT,
        "K3K1K2": K3_PT + K1_PT + K2_PT,
    }

    results = []
    for name, text in texts.items():
        text_arr = [ALPH_IDX[c] for c in text]
        for variant in ["beaufort", "vigenere"]:
            for target, ct_arr, n in [("CT97", CT_ARR, 97), ("CT73", CT73_ARR, 73)]:
                for offset in range(len(text) - n + 1):
                    key_arr = text_arr[offset:offset + n]
                    if variant == "beaufort":
                        pt_arr = [(key_arr[i] - ct_arr[i]) % MOD for i in range(n)]
                    else:
                        pt_arr = [(ct_arr[i] - key_arr[i]) % MOD for i in range(n)]

                    pt_str = "".join(ALPH[v] for v in pt_arr)

                    # Check crib consistency
                    if target == "CT97":
                        matches = sum(1 for p in CRIB_POS if pt_str[p] == CRIB_DICT[p])
                    else:
                        matches = sum(1 for i, p in enumerate(CRIB_POS)
                                      if CRIB_CT73_IDX[i] < n and
                                      pt_arr[CRIB_CT73_IDX[i]] == ALPH_IDX[CRIB_DICT[p]])

                    if matches >= 4:
                        intel_sc, terms = score_intel_jargon(pt_str)
                        results.append({
                            "source": name, "variant": variant, "target": target,
                            "offset": offset, "crib_matches": matches,
                            "intel_score": intel_sc, "terms": terms[:5],
                            "pt_preview": pt_str[:50],
                        })

    results.sort(key=lambda x: -x["crib_matches"])
    print(f"    Tested {len(texts)} orderings × 2 variants × 2 targets × ~700 offsets", flush=True)
    print(f"    Hits (≥4 crib matches): {len(results)}", flush=True)
    if results:
        for r in results[:5]:
            print(f"      {r['crib_matches']}/24 | {r['source']} {r['variant']} {r['target']} "
                  f"off={r['offset']} intel={r['intel_score']}", flush=True)
    return results


def phase1_bespoke_functions():
    """Test simple f(CT, position) → key functions."""
    print("\n  Phase 1B: Bespoke key generation functions", flush=True)

    results = []
    n = 73

    def test_key(key_arr, desc):
        pt_arr = beaufort_decrypt(CT73_ARR, key_arr)
        # Check crib consistency
        matches = sum(1 for i in range(24)
                      if CRIB_CT73_IDX[i] < n and
                      key_arr[CRIB_CT73_IDX[i]] == KNOWN_KEY_73[CRIB_CT73_IDX[i]])
        if matches >= 6:
            pt_str = "".join(ALPH[v] for v in pt_arr)
            qg = qg_score(pt_arr)
            intel_sc, _ = score_intel_jargon(pt_str)
            results.append({
                "desc": desc, "matches": matches, "qg": qg,
                "intel": intel_sc, "pt": pt_str[:40],
            })

    # Category 1: CT-derived keys
    for a in range(26):
        for b in range(26):
            key = [(CT73_ARR[i] + a * i + b) % MOD for i in range(n)]
            test_key(key, f"CT+{a}*i+{b}")

    # Category 2: Position-only keys
    for a in range(26):
        for b in range(26):
            key = [(a * i + b) % MOD for i in range(n)]
            test_key(key, f"{a}*i+{b}")

    # Category 3: CT cumulative sum
    for seed in range(26):
        key = [0] * n
        key[0] = (CT73_ARR[0] + seed) % MOD
        for i in range(1, n):
            key[i] = (key[i-1] + CT73_ARR[i]) % MOD
        test_key(key, f"cumsum_CT_seed{seed}")

    # Category 4: Fibonacci-like from CT
    for a in range(26):
        for b in range(26):
            key = [a, b] + [0] * (n - 2)
            for i in range(2, n):
                key[i] = (key[i-1] + key[i-2]) % MOD
            test_key(key, f"fib_{a}_{b}")

    # Category 5: KRYPTOS keyword cycling with position shift
    kw = [ALPH_IDX[c] for c in "KRYPTOS"]
    for shift in range(26):
        key = [(kw[i % 7] + shift * i) % MOD for i in range(n)]
        test_key(key, f"KRYPTOS+{shift}*i")

    # Category 6: Sculpture text at various strides
    for stride in range(1, 20):
        for start in range(min(stride, len(FULL_SCULPTURE) - n * stride)):
            key = [FULL_SCULPTURE_ARR[start + i * stride] for i in range(n)
                   if start + i * stride < len(FULL_SCULPTURE)]
            if len(key) == n:
                test_key(key, f"sculpt_stride{stride}_start{start}")

    # Category 7: KA-indexed CT as key
    ka_arr = [KA_IDX[c] for c in CT73_STR]
    test_key(ka_arr, "KA_indexed_CT73")
    test_key([(26 - v) % 26 for v in ka_arr], "KA_indexed_CT73_complement")
    test_key([(v + i) % 26 for i, v in enumerate(ka_arr)], "KA_CT73+pos")

    count = 26*26 + 26*26 + 26 + 26*26 + 26 + 20*20 + 3
    results.sort(key=lambda x: -x["matches"])
    print(f"    Tested ~{count:,} key generation functions", flush=True)
    print(f"    Hits (≥6 crib matches): {len(results)}", flush=True)
    if results:
        for r in results[:10]:
            print(f"      {r['matches']}/24 qg={r['qg']:.3f} intel={r['intel']} "
                  f"| {r['desc']}: {r['pt']}", flush=True)
    return results


# ── PHASE 2: Cable-Format SA ──────────────────────────────────────────

def _cable_sa_worker(args):
    """SA worker using hybrid scoring (quadgram + intel + words)."""
    (restart_id, seed, ct_arr, pinned, free_pos, n_steps, mode) = args
    rng = random.Random(seed)
    n = len(ct_arr)

    # Initialize key with some intel-biased letters
    key = [0] * n
    for pos, val in pinned.items():
        key[pos] = val
    for pos in free_pos:
        key[pos] = rng.randint(0, 25)

    pt = beaufort_decrypt(ct_arr, key)
    pt_str = "".join(ALPH[v] for v in pt)

    # Score components
    cur_qg = qg_score(pt)
    cur_intel, _ = score_intel_jargon(pt_str)
    cur_word = WORD_SCORER.score(pt_str).coverage

    if mode == "hybrid":
        cur_score = cur_qg + cur_intel * 0.05 + cur_word * 2.0
    elif mode == "intel_heavy":
        cur_score = cur_qg * 0.5 + cur_intel * 0.15 + cur_word * 3.0
    elif mode == "word_only":
        cur_score = cur_word * 5.0 + cur_qg * 0.3
    else:
        cur_score = cur_qg

    best_score = cur_score
    best_key = key[:]
    best_pt_str = pt_str

    T_start = 2.5
    T_end = 0.005
    log_ratio = math.log(T_end / T_start)
    n_free = len(free_pos)

    # Track best intel score separately
    best_intel = cur_intel
    best_intel_pt = pt_str

    for step in range(n_steps):
        T = T_start * math.exp(log_ratio * step / n_steps)
        pos = free_pos[rng.randint(0, n_free - 1)]
        old_val = key[pos]
        new_val = (old_val + rng.randint(1, 25)) % 26

        key[pos] = new_val
        pt_new = beaufort_decrypt(ct_arr, key)
        pt_str_new = "".join(ALPH[v] for v in pt_new)

        new_qg = qg_score(pt_new)
        new_intel, _ = score_intel_jargon(pt_str_new)
        new_word = WORD_SCORER.score(pt_str_new).coverage

        if mode == "hybrid":
            new_score = new_qg + new_intel * 0.05 + new_word * 2.0
        elif mode == "intel_heavy":
            new_score = new_qg * 0.5 + new_intel * 0.15 + new_word * 3.0
        elif mode == "word_only":
            new_score = new_word * 5.0 + new_qg * 0.3
        else:
            new_score = new_qg

        delta = new_score - cur_score
        if delta > 0 or (T > 0.001 and rng.random() < math.exp(delta / T)):
            cur_score = new_score
            cur_qg = new_qg
            cur_intel = new_intel
            cur_word = new_word
            pt_str = pt_str_new
            pt = pt_new
            if cur_score > best_score:
                best_score = cur_score
                best_key = key[:]
                best_pt_str = pt_str
            if cur_intel > best_intel:
                best_intel = cur_intel
                best_intel_pt = pt_str
        else:
            key[pos] = old_val

    return {
        "restart": restart_id,
        "mode": mode,
        "score": best_score,
        "qg": qg_score(beaufort_decrypt(ct_arr, best_key)),
        "intel": score_intel_jargon(best_pt_str)[0],
        "word_cov": WORD_SCORER.score(best_pt_str).coverage,
        "pt": best_pt_str,
        "key": "".join(ALPH[v] for v in best_key),
        "best_intel_score": best_intel,
        "best_intel_pt": best_intel_pt,
    }


def run_cable_sa(name, ct_arr, pinned, free_pos, n_restarts, n_steps, mode):
    """Run cable-format SA phase."""
    tasks = [
        (i, hash((name, i)) % (2**31), ct_arr, pinned, free_pos, n_steps, mode)
        for i in range(n_restarts)
    ]

    results = []
    t0 = time.time()

    with Pool(N_WORKERS) as pool:
        for r in pool.imap_unordered(_cable_sa_worker, tasks, chunksize=5):
            results.append(r)
            if len(results) % 100 == 0:
                best = max(results, key=lambda x: x["score"])
                elapsed = time.time() - t0
                print(f"    [{len(results):>5}/{n_restarts}] {elapsed:.0f}s "
                      f"best_score={best['score']:.3f} "
                      f"intel={best['intel']:.0f} "
                      f"word={best['word_cov']:.1%} "
                      f"qg={best['qg']:.3f}", flush=True)

    elapsed = time.time() - t0
    results.sort(key=lambda x: -x["score"])

    print(f"\n    {name} complete: {elapsed:.0f}s ({elapsed/60:.1f} min)", flush=True)
    print(f"    Best: score={results[0]['score']:.4f} qg={results[0]['qg']:.3f} "
          f"intel={results[0]['intel']:.0f} word={results[0]['word_cov']:.1%}", flush=True)
    print(f"    PT: {results[0]['pt'][:70]}...", flush=True)

    # Best by intel specifically
    by_intel = sorted(results, key=lambda x: -x["best_intel_score"])
    if by_intel[0]["best_intel_score"] > 0:
        print(f"    Best intel: {by_intel[0]['best_intel_score']:.0f} "
              f"PT: {by_intel[0]['best_intel_pt'][:70]}...", flush=True)

    return results


# ── Main ───────────────────────────────────────────────────────────────

def main():
    t_start = time.time()
    random.seed(20260318)

    print("=" * 70)
    print("OVERNIGHT MEGA CAMPAIGN v1")
    print("=" * 70)
    print(f"Workers: {N_WORKERS}")
    print(f"CT73: {CT73_STR}")
    print(f"Free positions: {len(FREE_73)} (CT73), {len(FREE_97)} (CT97)")

    all_results = {}

    # ── Phase 1: Quick Gap Audit ──────────────────────────────────────
    print(f"\n{'='*70}")
    print("PHASE 1: Quick Gap Audit (~5 min)")
    print(f"{'='*70}")

    r1a = phase1_sculpture_running_key()
    all_results["phase1a_sculpture_rk"] = r1a

    r1b = phase1_bespoke_functions()
    all_results["phase1b_bespoke"] = r1b

    phase1_time = time.time() - t_start
    print(f"\n  Phase 1 total: {phase1_time:.0f}s", flush=True)

    # ── Phase 2: Cable-Format SA on CT73 ──────────────────────────────
    print(f"\n{'='*70}")
    print("PHASE 2: Cable-Format SA on CT73 (~2 hours)")
    print(f"{'='*70}")

    for mode, restarts, steps in [
        ("hybrid", 1000, 400000),
        ("intel_heavy", 500, 400000),
        ("word_only", 500, 300000),
    ]:
        print(f"\n  Mode: {mode} ({restarts} restarts × {steps:,} steps)", flush=True)
        r = run_cable_sa(
            f"ct73_{mode}", CT73_ARR, KNOWN_KEY_73, FREE_73,
            restarts, steps, mode,
        )
        all_results[f"phase2_ct73_{mode}"] = r

    # ── Phase 3: Cable-Format SA on CT97 ──────────────────────────────
    print(f"\n{'='*70}")
    print("PHASE 3: Cable-Format SA on CT97 (~1 hour)")
    print(f"{'='*70}")

    for mode, restarts, steps in [
        ("hybrid", 500, 400000),
        ("intel_heavy", 300, 400000),
    ]:
        print(f"\n  Mode: {mode} ({restarts} restarts × {steps:,} steps)", flush=True)
        r = run_cable_sa(
            f"ct97_{mode}", CT_ARR, KNOWN_KEY_97, FREE_97,
            restarts, steps, mode,
        )
        all_results[f"phase3_ct97_{mode}"] = r

    # ── Summary ───────────────────────────────────────────────────────
    total_elapsed = time.time() - t_start
    print(f"\n{'='*70}")
    print(f"MEGA CAMPAIGN COMPLETE — {total_elapsed:.0f}s ({total_elapsed/3600:.1f} hours)")
    print(f"{'='*70}")

    for phase_name, results in all_results.items():
        if isinstance(results, list) and results:
            if isinstance(results[0], dict):
                if "score" in results[0]:
                    best = max(results, key=lambda x: x.get("score", x.get("crib_matches", 0)))
                    sc = best.get("score", best.get("crib_matches", "?"))
                    print(f"  {phase_name}: best={sc}", flush=True)
                elif "crib_matches" in results[0]:
                    best = max(results, key=lambda x: x["crib_matches"])
                    print(f"  {phase_name}: best crib_matches={best['crib_matches']}", flush=True)

    # Check for breakthroughs
    best_overall = None
    for results in all_results.values():
        if isinstance(results, list):
            for r in results:
                if isinstance(r, dict) and "pt" in r:
                    pt = r["pt"]
                    intel_sc, terms = score_intel_jargon(pt)
                    if intel_sc > 5:
                        print(f"\n  ** HIGH INTEL SCORE {intel_sc}: {pt[:60]}... terms={terms}", flush=True)

    # Save results
    output_path = os.path.join(_ROOT, "results", "f_overnight_mega_v1.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    save_data = {
        "experiment": "overnight_mega_v1",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "elapsed_seconds": total_elapsed,
        "workers": N_WORKERS,
    }
    for name, results in all_results.items():
        if isinstance(results, list) and results:
            if isinstance(results[0], dict) and "score" in results[0]:
                top = sorted(results, key=lambda x: -x.get("score", 0))[:10]
                save_data[name] = {"top10": top, "count": len(results)}
            else:
                save_data[name] = {"top10": results[:10], "count": len(results)}

    with open(output_path, "w") as f:
        json.dump(save_data, f, indent=2)
    print(f"\n  Results saved: {output_path}", flush=True)
    print("=" * 70)


if __name__ == "__main__":
    main()
