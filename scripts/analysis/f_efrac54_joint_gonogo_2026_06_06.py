#!/usr/bin/env python3
"""Go/no-go validation of the prior two-sided detector src/kryptos/detectors/efrac54_joint.py.

Model (efrac54_joint): C[i] = sigma(PT[i]) (+/-) K[pi(i)]  -- PT/CT aligned, KEY transposed.
Statistic: t = L_PT + L_K (both implied PT and implied keystream must look English).

E-FRAC-54's core worry is SIGMA-SATURATION: can the ~26 monoalphabetic DOF make the
implied keystream K_hat look English even on NOISE? This harness tests exactly that,
in the detector's FAVOR: it FIXES the true plaintext and the true transposition (so the
only free axis is sigma), then asks whether a sigma-hillclimb on SHUFFLED CT can reach
the joint score of the true solution on real CT.

  detection := real_best_t  >  95th-percentile of shuffle_best_t   (per plant)

Interpretation:
  - If detection rate is HIGH: the two-sided statistic resists sigma-saturation even
    when the shuffle is handed the true English plaintext -> the statistic has real
    power my forced-difference detector lacked (necessary condition met). Full-detector
    power still requires a tractable joint (sigma + plaintext) search, which is separate.
  - If detection rate is LOW: even with PT and transposition given for free, sigma DOF
    saturate the joint score on noise -> the two-sided statistic is underpowered, i.e.
    E-FRAC-54's saturation defeats it too.
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
from kryptos.kernel.transforms.transposition import columnar_perm  # noqa: E402
from kryptos.detectors.efrac54_joint import (  # noqa: E402
    CandidateTuple, score_joint, encrypt_with_model, generate_shuffled_surrogate,
)

KAHN = os.path.join(_ROOT, "reference", "running_key_texts", "kahn_codebreakers_1967.txt")
N = CT_LEN
NONCRIB = [i for i in range(N) if i not in CRIB_POSITIONS]
N_FREE = len(NONCRIB)
VARIANT = "vigenere"
_SCORER = None


def _scorer():
    global _SCORER
    if _SCORER is None:
        _SCORER = get_default_scorer()
    return _SCORER


def english_letters(path):
    txt = open(path, encoding="utf-8", errors="ignore").read().upper()
    return [c for c in txt if "A" <= c <= "Z"]


def make_pt_with_cribs(eng_letters, off):
    pt = eng_letters[off:off + N][:]
    for pos, ch in CRIB_DICT.items():
        pt[pos] = ch
    return "".join(pt)


def true_pt_nc(pt):
    return "".join(pt[i] for i in NONCRIB)


def sigma_hillclimb(ct, width, kappa, pt_nc, variant, rng, n_evals=2500, restarts=2):
    """Best joint t over a hill-climb on sigma (26-perm), PT and transposition fixed."""
    scorer = _scorer()

    def score(sig):
        return score_joint(ct, CandidateTuple(tuple(sig), width, tuple(kappa), pt_nc),
                           scorer, variant).t

    best_t = -math.inf
    for _ in range(restarts):
        sigma = list(range(26))
        rng.shuffle(sigma)
        cur = score(sigma)
        for it in range(n_evals):
            T = max(1e-3, 1.0 * (1 - it / n_evals))
            a, b = rng.randrange(26), rng.randrange(26)
            if a == b:
                continue
            sigma[a], sigma[b] = sigma[b], sigma[a]
            new = score(sigma)
            if new >= cur or rng.random() < math.exp((new - cur) / T):
                cur = new
            else:
                sigma[a], sigma[b] = sigma[b], sigma[a]
            if cur > best_t:
                best_t = cur
    return best_t


def _one_plant(args):
    idx, off, koff, width, kappa_seed = args
    eng = english_letters(KAHN)
    eng_idx = [ALPH_IDX[c] for c in eng]
    pt = make_pt_with_cribs(eng, off)
    pt_nc = true_pt_nc(pt)
    key_nums = eng_idx[koff:koff + N]
    rng = random.Random(1000 + idx)
    sigma_true = list(range(26))
    rng.shuffle(sigma_true)
    kappa = tuple(random.Random(kappa_seed).sample(range(width), width))
    ct = encrypt_with_model(pt, sigma_true, width, list(kappa), key_nums, VARIANT)

    # oracle: true sigma joint score on the real CT (upper bound on real search)
    oracle_t = score_joint(ct, CandidateTuple(tuple(sigma_true), width, kappa, pt_nc),
                           _scorer(), VARIANT).t
    # real: sigma-hillclimb on the real CT
    real_best = sigma_hillclimb(ct, width, kappa, pt_nc, VARIANT, random.Random(7 + idx))
    # null: sigma-hillclimb on shuffled CT (PT + transposition still handed to the shuffle)
    shuf_best = []
    r2 = random.Random(31 + idx)
    for m in range(20):
        sct = generate_shuffled_surrogate(ct, r2)
        shuf_best.append(sigma_hillclimb(sct, width, kappa, pt_nc, VARIANT, random.Random(99 + 7 * m + idx),
                                         n_evals=2500, restarts=1))
    shuf_best.sort()
    thr95 = shuf_best[int(0.95 * (len(shuf_best) - 1))]
    detected = real_best > thr95
    return {"idx": idx, "width": width, "oracle_t": round(oracle_t, 3),
            "real_best_t": round(real_best, 3), "shuf95_t": round(thr95, 3),
            "shuf_max_t": round(shuf_best[-1], 3), "detected": detected}


def main():
    eng = english_letters(KAHN)
    print(f"[corpus] kahn letters={len(eng)}")
    plants = []
    rng = random.Random(5)
    for i in range(8):
        off = rng.randrange(2000, len(eng) - 200)
        koff = rng.randrange(2000, len(eng) - 200)
        width = rng.choice((6, 8, 9))
        plants.append((i, off, koff, width, 1000 + i))

    with Pool(min(8, os.cpu_count() or 4)) as pool:
        rows = pool.map(_one_plant, plants)

    rate = sum(r["detected"] for r in rows) / len(rows)
    for r in rows:
        print(f"  plant {r['idx']} w{r['width']}: oracle={r['oracle_t']} real_best={r['real_best_t']} "
              f"shuf95={r['shuf95_t']} shuf_max={r['shuf_max_t']} -> {'DETECT' if r['detected'] else 'miss'}")
    # also: does the oracle (true sigma) beat the shuffle search? (statistic-level separation)
    oracle_beats = sum(1 for r in rows if r["oracle_t"] > r["shuf95_t"]) / len(rows)
    powerful = rate >= 0.80
    verdict = "STATISTIC_RESISTS_SIGMA_SATURATION" if powerful else "DETECTOR_UNDERPOWERED_SIGMA_SATURATION"
    out = {
        "campaign": "efrac54_joint_gonogo_2026_06_06",
        "detector": "src/kryptos/detectors/efrac54_joint.py",
        "test": "sigma-saturation with TRUE plaintext + TRUE transposition given (favorable to detector)",
        "n_plants": len(rows), "variant": VARIANT,
        "detection_rate_search": rate,
        "oracle_beats_shuffle95_rate": oracle_beats,
        "rows": rows,
        "verdict": verdict,
        "scope": ("Necessary-condition test: PT and transposition handed to BOTH real and "
                  "shuffle (only sigma searched). High rate => two-sided statistic resists "
                  "sigma-saturation (unlike the forced-difference detector). Full cold-start "
                  "joint (sigma+plaintext) search power is a separate, harder question."),
    }
    json.dump(out, open(os.path.join(_ROOT, "results", "efrac54_joint_gonogo_2026_06_06.json"), "w"), indent=1)
    print(f"\n=== VERDICT: {verdict} ===")
    print(f"detection_rate(search)={rate:.2f} | oracle_beats_shuffle95={oracle_beats:.2f}")


if __name__ == "__main__":
    main()
