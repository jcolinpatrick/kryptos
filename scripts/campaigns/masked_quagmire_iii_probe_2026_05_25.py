#!/usr/bin/env python3
"""Masked Quagmire III probe on the arbitrary_null_mask frontier (2026-05-25).

Pre-registered, bounded, null-calibrated test of Quagmire III (the cipher
family K1-K3 actually use) under arbitrary null masks with |mask| != 24.

WHY OPEN: every prior masked K4 probe used Vigenere/Beaufort/additive-tape
mechanisms. The proof "all periodic substitution periods 1-26 eliminated by
the 242-Bean set" is align=direct_ct_pt (decrypt in place at length 97) and the
null-mask variant proof is align=ct73_null_extracted (|mask|==24 -> length 73).
Under |mask| != 24, the extracted CT' has length != 73, Bean is RE-DERIVED
per-mask on CT', and neither proof transfers. So masked Quagmire III is genuinely
open. We deliberately keep ALL masks |mask| != 24 to stay OFF the closed slice.

Design contract (explicit-CT, per CLAUDE.md ct_perturbation discipline):
  - CT passed explicitly; never mutate kernel.constants.
  - Bean RE-DERIVED for each mask from extracted CT' against remapped cribs,
    in the SAME alphabet index space the Quagmire cipher operates in.
  - Quagmire III convention pinned by a hard regression gate (K1 + K2) that must
    pass before any masked sweep runs.

Repro:
  PYTHONPATH=src python3 -u scripts/campaigns/masked_quagmire_iii_probe_2026_05_25.py
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import sys
import time
from datetime import datetime, timezone
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT, CRIB_POSITIONS, CT_LEN
from kryptos.kernel.masking.mask import extract_ct, remap_crib_dict, validate_mask
from kryptos.kernel.transforms.quagmire import quagmire_decrypt
from kryptos.kernel.constraints.bean import (
    derive_bean_constraints,
    check_bean,
    Alphabet,
)
from kryptos.kernel.alphabet import keyword_mixed_alphabet
from kryptos.kernel.scoring.aggregate import score_candidate

# Quagmire III uses the KRYPTOS-mixed alphabet for BOTH PT and CT indices.
# Bean must be re-derived in the SAME index space the cipher operates in.
KRYPTOS_MIXED = keyword_mixed_alphabet("KRYPTOS")  # KRYPTOSABCDEFGHIJLMNQUVWXZ
KA_ALPHABET = Alphabet(label="KRYPTOS_MIXED", sequence=KRYPTOS_MIXED)
KA_IDX = {ch: i for i, ch in enumerate(KRYPTOS_MIXED)}

# ---------------------------------------------------------------------------
# Universe definitions (generative rules)
# ---------------------------------------------------------------------------

CRIB_SET = frozenset(CRIB_POSITIONS)
NON_CRIB = [p for p in range(CT_LEN) if p not in CRIB_SET]
# Contiguous non-crib gaps: [0,20], [34,62], [74,96]
GAPS = [(0, 20), (34, 62), (74, 96)]


def build_masks():
    """Generative mask rules. All |mask| != 24, none touch crib positions."""
    masks = {}  # frozenset -> rule description (dedup by content)

    # Rule R1: residue masks p mod m == r, crib positions removed.
    for m in range(2, 8):  # m in {2..7}
        for r in range(m):
            mask = frozenset(p for p in NON_CRIB if p % m == r)
            if not mask:
                continue
            if len(mask) == 24:  # off-limits slice
                continue
            masks.setdefault(mask, f"residue m={m} r={r} |mask|={len(mask)}")

    # Rule R2: contiguous-block masks of length L within a single non-crib gap.
    for (lo, hi) in GAPS:
        gap_len = hi - lo + 1
        for L in range(1, 21):  # block lengths 1..20
            if L > gap_len:
                break
            for start in range(lo, hi - L + 2):
                mask = frozenset(range(start, start + L))
                if mask & CRIB_SET:
                    continue
                if len(mask) == 24:
                    continue
                masks.setdefault(mask, f"block [{start},{start+L-1}] L={L} |mask|={L}")

    return masks


def build_keys():
    """Bounded Quagmire III key universe: motivated keyword pool x small period.

    CT alphabet fixed to KRYPTOS (the panel tableau, canonical for K1-K3).
    PT-alphabet keyword swept over a K4-context pool (Quagmire III/IV space).
    period_keyword swept over the same pool. indicator='K' (K1-K3 convention).
    """
    # Motivated K4-context pool: the panel keyword, the K1-K3 cyclewords/keywords,
    # and a modest thematic set fitting CIA public-art context. Bounded & stated.
    keyword_pool = [
        "KRYPTOS",       # panel tableau keyword
        "PALIMPSEST",    # K1 cycleword
        "ABSCISSA",      # K2 cycleword
        "ORDINATE",      # K2 thematic (coordinate pair w/ ABSCISSA)
        "LATITUDE",      # K2/K3 geographic theme
        "LONGITUDE",     # K2/K3 geographic theme
        "BERLIN",        # K4 crib
        "CLOCK",         # K4 crib
        "EAST",          # K4 crib
        "NORTH",         # K4 crib
        "SHADOW",        # K3 thematic (shadow forces)
        "IQLUSION",      # K1 deliberate misspelling
        "UNDERGRUUND",   # K3 deliberate misspelling
        "DESPARATLY",    # K3 deliberate misspelling
        "WESTIDARW",     # K4 anomaly region letters near W
        "LANGLEY",       # CIA HQ location
        "SANBORN",       # creator (context, not self-trivia keyword per se)
        "WELCOME",       # invitation theme
    ]
    periods = list(range(3, 13))  # bounded small period range 3..12
    keys = []
    for pt_kw in keyword_pool:
        for per_kw in keyword_pool:
            for _ in [0]:
                keys.append((pt_kw, per_kw))
    # period is implied by len(per_kw); but we ALSO sweep an explicit truncation
    # of the period keyword to the period range to broaden small-period coverage.
    expanded = []
    for pt_kw, per_kw in keys:
        for p in periods:
            # period keyword truncated/cycled to length p (bounded period control)
            base = (per_kw * ((p // len(per_kw)) + 1))[:p]
            expanded.append((pt_kw, base, p, per_kw))
    return keyword_pool, periods, expanded


def universe_hash(masks, keys):
    h = hashlib.sha256()
    for mask in sorted(masks.keys(), key=lambda s: tuple(sorted(s))):
        h.update(b"M")
        h.update(",".join(str(p) for p in sorted(mask)).encode())
    for (pt_kw, per_base, p, per_src) in sorted(keys):
        h.update(b"K")
        h.update(f"{pt_kw}|{per_base}|{p}|{per_src}".encode())
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Per-config evaluation
# ---------------------------------------------------------------------------

def compute_keystream(ct_prime: str, pt_prime: str):
    """Additive shift keystream in the KRYPTOS-mixed index space:
    k[i] = (ct_idx[i] - pt_idx[i]) mod 26 (the Quagmire III shift)."""
    return [(KA_IDX[c] - KA_IDX[p]) % 26 for c, p in zip(ct_prime, pt_prime)]


# Worker-global key list and CT, set per pool via initializer (avoids
# re-pickling the full key universe for every one of 915 mask tasks).
_W_KEYS = None
_W_CT = None


def _init_worker(keys, ct):
    global _W_KEYS, _W_CT
    _W_KEYS = keys
    _W_CT = ct


def eval_mask(mask_tuple):
    """Process ONE mask against ALL keys. Bean is derived ONCE per mask
    (it depends only on the extracted CT + remapped cribs, not the key).

    Returns a compact per-mask summary (scalars + best plaintexts only) to
    keep inter-process IPC small. Reads keys/CT from worker globals.
    """
    ct = _W_CT
    keys = _W_KEYS
    mask = frozenset(mask_tuple)
    ct_prime = extract_ct(ct, mask)
    cribs2 = remap_crib_dict(CRIB_DICT, mask)

    # Bean constraints: derived ONCE per mask (key-independent).
    eq, ineq, linear = derive_bean_constraints(ct_prime, cribs2, alphabet=KA_ALPHABET)

    best_crib = -1
    best = None              # (crib, pt_kw, per_base, pt) for overall best crib
    best_bean_crib = -1
    best_bean = None         # best crib among bean-passing configs
    bean_count = 0

    for (pt_kw, per_base) in keys:
        pt = quagmire_decrypt(
            ct_prime, period_keyword=per_base,
            ct_alphabet_keyword="KRYPTOS", pt_alphabet_keyword=pt_kw,
            indicator="K",
        )
        ks = compute_keystream(ct_prime, pt)
        bres = check_bean(ks, eq, ineq, linear)
        sb = score_candidate(pt, crib_dict=cribs2)
        cs = sb.crib_score
        ng = float(sb.ngram_score) if sb.ngram_score is not None else 0.0
        if cs > best_crib:
            best_crib = cs
            best = (cs, pt_kw, per_base, ng, pt)
        if bres.passed:
            bean_count += 1
            if cs > best_bean_crib:
                best_bean_crib = cs
                best_bean = (cs, pt_kw, per_base, ng, pt)

    return {
        "mask": sorted(mask),
        "mask_len": len(mask),
        "best": best,            # (crib, pt_kw, per_base, ngram, pt)
        "best_bean": best_bean,  # same shape or None
        "bean_count": bean_count,
    }


# ---------------------------------------------------------------------------
# Regression gate
# ---------------------------------------------------------------------------

def regression_check():
    K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
    K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
    K2_CT = ("VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK"
             "DQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDV")
    K2_PT = ("ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLE"
             "THEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATI")
    pt1 = quagmire_decrypt(K1_CT, period_keyword="PALIMPSEST",
                           ct_alphabet_keyword="KRYPTOS",
                           pt_alphabet_keyword="KRYPTOS", indicator="K")
    pt2 = quagmire_decrypt(K2_CT, period_keyword="ABSCISSA",
                           ct_alphabet_keyword="KRYPTOS",
                           pt_alphabet_keyword="KRYPTOS", indicator="K")
    return pt1 == K1_PT, pt2 == K2_PT, pt1, pt2


# ---------------------------------------------------------------------------
# Null calibration
# ---------------------------------------------------------------------------

def shuffled_ct(ct, seed):
    import random
    rng = random.Random(seed)
    chars = list(ct)
    rng.shuffle(chars)
    return "".join(chars)


def _summary_to_rec(entry):
    """Map a (crib, pt_kw, per_base, ngram, pt) tuple + mask to the legacy
    record dict shape used by main()/JSON."""
    if entry is None:
        return None
    cs, pt_kw, per_base, ng, pt = entry
    return {
        "pt_kw": pt_kw, "period_keyword": per_base, "period": len(per_base),
        "crib_score": cs, "bean_passed": True, "ngram_score": ng, "pt": pt,
    }


def run_universe(ct, masks, keys_full, workers, label=""):
    # keys_full carries (pt_kw, per_base, p, per_src); workers only need (pt_kw, per_base)
    keys = [(pt_kw, per_base) for (pt_kw, per_base, p, src) in keys_full]
    mask_tasks = [tuple(sorted(mk)) for mk in masks.keys()]
    n_configs = len(mask_tasks) * len(keys)

    best = None              # legacy rec dict for overall-best crib
    best_crib = -1
    bean_pass_records = []   # one rec per mask that had >=1 bean pass (its best)
    with Pool(workers, initializer=_init_worker, initargs=(keys, ct)) as pool:
        for ms in pool.imap_unordered(eval_mask, mask_tasks, chunksize=4):
            b = ms["best"]
            if b is not None and b[0] > best_crib:
                best_crib = b[0]
                cs, pt_kw, per_base, ng, pt = b
                best = {
                    "mask": ms["mask"], "mask_len": ms["mask_len"],
                    "pt_kw": pt_kw, "period_keyword": per_base, "period": len(per_base),
                    "crib_score": cs, "bean_passed": False, "ngram_score": ng, "pt": pt,
                }
            if ms["best_bean"] is not None:
                rec = _summary_to_rec(ms["best_bean"])
                rec["mask"] = ms["mask"]; rec["mask_len"] = ms["mask_len"]
                # bean_count rolled into a synthetic expansion for counting
                rec["_bean_count"] = ms["bean_count"]
                bean_pass_records.append(rec)
    return best, bean_pass_records, n_configs


def main():
    workers = max(1, cpu_count() - 2)
    started = datetime.now(timezone.utc).isoformat()
    t0 = time.time()

    print("=== REGRESSION GATE (Quagmire III K1/K2) ===")
    k1ok, k2ok, pt1, pt2 = regression_check()
    print(f"K1 rediscovered: {k1ok}")
    print(f"K2 rediscovered: {k2ok}")
    if not (k1ok and k2ok):
        print("REGRESSION FAILED -- aborting. Quagmire convention wrong.")
        print("K1 got:", pt1[:40])
        print("K2 got:", pt2[:40])
        sys.exit(2)
    print("Regression PASS. Proceeding to masked sweep.\n")

    masks = build_masks()
    keyword_pool, periods, keys = build_keys()
    uhash = universe_hash(masks, keys)
    total = len(masks) * len(keys)
    print(f"Masks: {len(masks)} | Keys: {len(keys)} | Total configs: {total}")
    print(f"Universe SHA-256: {uhash}")
    print(f"Workers: {workers}\n")

    # Analytic max-of-N crib expectation (computed BEFORE running).
    # Per-position crib match prob ~1/26; with 24 crib positions, crib_score ~ Binomial(24, 1/26).
    # E[max over N] approximation via order statistics of the binomial.
    import statistics
    p_match = 1.0 / 26.0
    mu = 24 * p_match
    sigma = math.sqrt(24 * p_match * (1 - p_match))
    # Gumbel-ish max approximation for N iid: E[max] ~ mu + sigma*sqrt(2 ln N)
    approx_max = mu + sigma * math.sqrt(2 * math.log(max(total, 2)))
    print(f"Analytic: per-config E[crib_score]={mu:.3f}, sd={sigma:.3f}")
    print(f"Analytic max-of-N (N={total}) approx: {approx_max:.2f}/24\n")

    # REAL sweep
    print("=== REAL CT SWEEP ===")
    real_best, real_bean, n_real = run_universe(CT, masks, keys, workers)
    print(f"Scored {n_real} configs. Best crib_score={real_best['crib_score']}/24 "
          f"bean={real_best['bean_passed']} ngram={real_best['ngram_score']:.2f}")
    real_bean_total = sum(r.get("_bean_count", 0) for r in real_bean)
    print(f"Bean-pass count (configs): {real_bean_total} across {len(real_bean)} masks")

    # Among bean-pass, find best crib_score
    real_bean_best = None
    if real_bean:
        real_bean_best = max(real_bean, key=lambda r: r["crib_score"])
        print(f"Best bean-pass crib_score={real_bean_best['crib_score']}/24 "
              f"ngram={real_bean_best['ngram_score']:.2f}")

    # NULL calibration: B>=20 shuffled-CT universe runs, collect max crib_score.
    print("\n=== NULL CALIBRATION (shuffled CT, B=20) ===")
    B = 20
    null_maxes = []
    null_bean_maxes = []
    for b in range(B):
        sct = shuffled_ct(CT, seed=1000 + b)
        nb, nbean, _ = run_universe(sct, masks, keys, workers)
        null_maxes.append(nb["crib_score"])
        nbean_best = max((r["crib_score"] for r in nbean), default=0)
        null_bean_maxes.append(nbean_best)
        nbean_total = sum(r.get("_bean_count", 0) for r in nbean)
        print(f"  null[{b}] max crib={nb['crib_score']} bean-pass-max-crib={nbean_best} "
              f"(bean-pass configs={nbean_total} across {len(nbean)} masks)")

    null_mean = statistics.mean(null_maxes)
    null_sd = statistics.pstdev(null_maxes) if len(null_maxes) > 1 else 0.0
    # empirical p-value: fraction of null runs whose max >= real best
    p_emp = (sum(1 for m in null_maxes if m >= real_best["crib_score"]) + 1) / (B + 1)
    bean_null_mean = statistics.mean(null_bean_maxes)
    real_bean_crib = real_bean_best["crib_score"] if real_bean_best else 0
    p_emp_bean = (sum(1 for m in null_bean_maxes if m >= real_bean_crib) + 1) / (B + 1)

    print(f"\nNull max-of-N crib: mean={null_mean:.2f} sd={null_sd:.2f}")
    print(f"Real best crib={real_best['crib_score']} -> empirical p={p_emp:.4f}")
    print(f"Null bean-pass max crib: mean={bean_null_mean:.2f}")
    print(f"Real bean-pass best crib={real_bean_crib} -> empirical p={p_emp_bean:.4f}")

    elapsed = time.time() - t0
    rate = (n_real * (B + 1)) / elapsed if elapsed else 0

    # Verdict
    SIGNAL = 18
    beats_null = real_best["crib_score"] > max(null_maxes)
    bean_signal = (real_bean_best is not None
                   and real_bean_best["crib_score"] >= SIGNAL
                   and real_bean_best["crib_score"] > max(null_bean_maxes))
    if bean_signal:
        verdict = "SIGNAL_CANDIDATE_FLAG_FOR_DISPROOF"
    else:
        verdict = "CLEAN_NULL"

    out = {
        "task": "masked_quagmire_iii_probe",
        "alignment_model": "arbitrary_null_mask",
        "mechanism": "Quagmire III (CT alphabet KRYPTOS, indicator K, PT-keyword swept)",
        "command": "PYTHONPATH=src python3 -u scripts/campaigns/masked_quagmire_iii_probe_2026_05_25.py",
        "started_at": started,
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "ciphertext": CT,
        "universe": {
            "n_masks": len(masks),
            "n_keys": len(keys),
            "total_configs": total,
            "universe_sha256": uhash,
            "mask_rules": "residue p%m==r for m in 2..7 (crib-pos removed); contiguous blocks L in 1..20 within non-crib gaps; all |mask| != 24",
            "key_rules": f"keyword_pool ({len(keyword_pool)}) as PT-alphabet kw x period_keyword (truncated/cycled to p in {periods}); CT alphabet=KRYPTOS, indicator=K",
            "keyword_pool": keyword_pool,
            "periods": periods,
            "scope_excluded": "|mask|==24 (CT73 algebraic-proof slice) — never enumerated",
        },
        "regression": {"k1_rediscovered": k1ok, "k2_rediscovered": k2ok},
        "analytic": {
            "per_config_E_crib": mu,
            "per_config_sd": sigma,
            "max_of_N_approx": approx_max,
        },
        "thresholds": {"NOISE": 6, "STORE": 10, "SIGNAL": 18, "BREAKTHROUGH": 24},
        "real_best": {k: real_best[k] for k in
                      ("mask", "mask_len", "pt_kw", "period_keyword", "period",
                       "crib_score", "bean_passed", "ngram_score", "pt")},
        "real_bean_pass_count": sum(r.get("_bean_count", 0) for r in real_bean),
        "real_bean_pass_mask_count": len(real_bean),
        "real_bean_best": ({k: real_bean_best[k] for k in
                            ("mask", "mask_len", "pt_kw", "period_keyword", "period",
                             "crib_score", "bean_passed", "ngram_score", "pt")}
                           if real_bean_best else None),
        "null_calibration": {
            "B": B,
            "method": "shuffled CT (Fisher-Yates), same universe re-run per shuffle",
            "null_max_crib": null_maxes,
            "null_max_mean": null_mean,
            "null_max_sd": null_sd,
            "null_bean_pass_max_crib": null_bean_maxes,
            "null_bean_max_mean": bean_null_mean,
            "p_empirical_crib": p_emp,
            "p_empirical_bean_crib": p_emp_bean,
        },
        "verdict": verdict,
        "status": "disproved" if verdict == "CLEAN_NULL" else "inconclusive",
        "stop_rule": "exhaustive over enumerated universe; null B=20 fixed pre-reg",
        "runtime_sec": elapsed,
        "configs_per_sec": rate,
        "workers": workers,
    }

    out_path = os.path.join(_ROOT, "results", "masked_quagmire_iii_probe_2026_05_25.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nVERDICT: {verdict}")
    print(f"Wrote {out_path}")
    print(f"Runtime {elapsed:.1f}s, {rate:.0f} cfg/s (incl null)")


if __name__ == "__main__":
    main()
