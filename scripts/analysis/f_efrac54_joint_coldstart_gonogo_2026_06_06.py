#!/usr/bin/env python3
"""Decisive go/no-go for the two-sided E-FRAC-54 detector with the STRONG cold-start
joint search (src/kryptos/detectors/efrac54_joint_search.py).

Unlike the prior favorable test (which FIXED the true plaintext and searched only
sigma), this is the REALISTIC test: the strong search must find BOTH sigma and the
73-letter plaintext from a cold start, on the real (planted) CT and on shuffled CT.

  detection := real_best_t  >  95th-pct of shuffle_best_t   (per plant)

The deep E-FRAC-54 question: with 73 free PT letters + 26 sigma DOF, can the strong
joint search make BOTH the plaintext AND the implied keystream look English even on
NOISE (saturation)? If it can, the shuffle searches reach the real score and there is
no separation -> the two-sided detector self-defeats at full search strength.
"""
from __future__ import annotations
import json
import math
import os
import random
import sys
from multiprocessing import Pool

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
for p in (os.path.join(_ROOT, "src"), _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from kryptos.kernel.constants import ALPH, ALPH_IDX, CRIB_DICT, CRIB_POSITIONS, CT_LEN  # noqa: E402
from kryptos.kernel.scoring.ngram import get_default_scorer  # noqa: E402
from kryptos.detectors.efrac54_joint import (  # noqa: E402
    CandidateTuple, score_joint, encrypt_with_model, generate_shuffled_surrogate,
)
from kryptos.detectors.efrac54_joint_search import joint_search  # noqa: E402

KAHN = os.path.join(_ROOT, "reference", "running_key_texts", "kahn_codebreakers_1967.txt")
N = CT_LEN
NONCRIB = [i for i in range(N) if i not in set(CRIB_POSITIONS)]
VARIANT = "vigenere"
N_ITERS = 100000
RESTARTS = 2
N_SHUFFLES = 16


def english_letters():
    txt = open(KAHN, encoding="utf-8", errors="ignore").read().upper()
    return [c for c in txt if "A" <= c <= "Z"]


def _one_plant(args):
    idx, off, koff, width, kappa_seed = args
    eng = english_letters()
    eng_idx = [ALPH_IDX[c] for c in eng]
    pt_list = eng[off:off + N][:]
    for pos, ch in CRIB_DICT.items():
        pt_list[pos] = ch
    pt = "".join(pt_list)
    key_nums = eng_idx[koff:koff + N]
    rng = random.Random(1000 + idx)
    sigma_true = list(range(26))
    rng.shuffle(sigma_true)
    kappa = tuple(random.Random(kappa_seed).sample(range(width), width))
    ct = encrypt_with_model(pt, sigma_true, width, list(kappa), key_nums, VARIANT)
    scorer = get_default_scorer()

    pt_nc_true = "".join(pt[i] for i in NONCRIB)
    oracle_t = score_joint(ct, CandidateTuple(tuple(sigma_true), width, kappa, pt_nc_true),
                           scorer, VARIANT).t
    real_best = joint_search(ct, width, kappa, VARIANT, scorer,
                             n_iters=N_ITERS, restarts=RESTARTS, rng=random.Random(7 + idx)).t
    shuf = []
    r2 = random.Random(31 + idx)
    for m in range(N_SHUFFLES):
        sct = generate_shuffled_surrogate(ct, r2)
        shuf.append(joint_search(sct, width, kappa, VARIANT, scorer,
                                 n_iters=N_ITERS, restarts=RESTARTS,
                                 rng=random.Random(900 + 11 * m + idx)).t)
    shuf.sort()
    thr95 = shuf[int(0.95 * (len(shuf) - 1))]
    return {"idx": idx, "width": width, "oracle_t": round(oracle_t, 3),
            "real_best_t": round(real_best, 3), "shuf95_t": round(thr95, 3),
            "shuf_max_t": round(shuf[-1], 3), "shuf_mean_t": round(sum(shuf) / len(shuf), 3),
            "detected": real_best > thr95, "real_reached_oracle": real_best >= oracle_t - 1.0}


def main():
    eng = english_letters()
    print(f"[corpus] kahn letters={len(eng)} | strong cold-start search n_iters={N_ITERS} restarts={RESTARTS}")
    rng = random.Random(5)
    plants = []
    for i in range(6):
        off = rng.randrange(2000, len(eng) - 200)
        koff = rng.randrange(2000, len(eng) - 200)
        width = rng.choice((6, 8, 9))
        plants.append((i, off, koff, width, 1000 + i))

    with Pool(min(6, os.cpu_count() or 4)) as pool:
        rows = pool.map(_one_plant, plants)

    rate = sum(r["detected"] for r in rows) / len(rows)
    reached = sum(r["real_reached_oracle"] for r in rows) / len(rows)
    for r in rows:
        print(f"  plant {r['idx']} w{r['width']}: oracle={r['oracle_t']} real={r['real_best_t']} "
              f"shuf[mean/95/max]={r['shuf_mean_t']}/{r['shuf95_t']}/{r['shuf_max_t']} "
              f"-> {'DETECT' if r['detected'] else 'miss'} (real~oracle={r['real_reached_oracle']})")
    powerful = rate >= 0.80
    if not reached:
        verdict = "SEARCH_TOO_WEAK"  # could not even recover plants -> inconclusive
    elif powerful:
        verdict = "TWO_SIDED_DETECTOR_VALIDATED"
    else:
        verdict = "SATURATION_AT_FULL_SEARCH"  # strong search reaches high t on noise too
    out = {
        "campaign": "efrac54_joint_coldstart_gonogo_2026_06_06",
        "detector": "src/kryptos/detectors/efrac54_joint.py + efrac54_joint_search.py",
        "test": "STRONG cold-start joint (sigma + 73-letter PT) search; real vs shuffled CT",
        "n_plants": len(rows), "variant": VARIANT,
        "n_iters": N_ITERS, "restarts": RESTARTS, "n_shuffles": N_SHUFFLES,
        "detection_rate": rate, "real_reached_oracle_rate": reached,
        "rows": rows, "verdict": verdict,
        "scope": ("Realistic cold-start test (no PT given). real_reached_oracle confirms the "
                  "search is strong; detection_rate vs SATURATION distinguishes whether the "
                  "two-sided statistic separates real from noise when the search is strong on both."),
    }
    json.dump(out, open(os.path.join(_ROOT, "results", "efrac54_joint_coldstart_gonogo_2026_06_06.json"), "w"), indent=1)
    print(f"\n=== VERDICT: {verdict} ===")
    print(f"detection_rate={rate:.2f} | real_reached_oracle_rate={reached:.2f}")


if __name__ == "__main__":
    main()
