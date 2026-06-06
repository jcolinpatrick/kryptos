#!/usr/bin/env python3
"""Mono-invariant running-key detector run (E-FRAC-54 / BIN-D D1).

Pre-registration: docs/campaigns/mono_trans_runkey_detector_2026_06_06.md
Output:           results/mono_trans_runkey_detector_2026_06_06.json

Two-sided detector for Mono+Trans+Running-key using mono-invariant forced
running-key differences. Runs the pre-registered synthetic go/no-go gate first;
if underpowered, emits DETECTOR_UNDERPOWERED and the real-K4 numbers are
descriptive only (cannot eliminate or escalate).
"""
from __future__ import annotations
import itertools
import json
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

from kryptos.kernel.constants import CT, CRIB_DICT, ALPH_IDX  # noqa: E402
from kryptos.kernel.transforms.transposition import columnar_perm  # noqa: E402
from kryptos.detectors.mono_invariant_runkey import english_lag_stats as els  # noqa: E402
from kryptos.detectors.mono_invariant_runkey import synthesize as syn  # noqa: E402
from kryptos.detectors.mono_invariant_runkey import null_calibration as nc  # noqa: E402
from kryptos.detectors.mono_invariant_runkey import transposition_universe as tu  # noqa: E402

KAHN = os.path.join(_ROOT, "reference", "running_key_texts", "kahn_codebreakers_1967.txt")
L_MAX = 12
VARIANTS = ("vigenere", "beaufort", "var_beaufort")
MODELS = ("model1", "model2")
POWER_FLOOR = 0.80
CRIB_ITEMS = [(p, ALPH_IDX[ch]) for p, ch in sorted(CRIB_DICT.items())]
CT_IDX = [ALPH_IDX[c] for c in CT]

_STATS = None
_ENG = None


def _load():
    global _STATS, _ENG
    if _STATS is None:
        text = open(KAHN, encoding="utf-8", errors="ignore").read()
        _STATS = els.build_lag_stats(text, l_max=L_MAX)
        _ENG = [ord(c) - 65 for c in text.upper() if "A" <= c.upper() <= "Z"]
    return _STATS, _ENG


def _sub_universe():
    """Representative (subsampled) universe for the synthetic gate. Smaller than the
    real universe -> a SMALLER look-elsewhere burden, so failing recovery here is a
    conservative (lower-bound) statement of underpower."""
    yield ("identity", list(range(97)))
    yield ("reverse", list(range(96, -1, -1)))
    for w in (6, 8, 9):
        for order in itertools.islice(itertools.permutations(range(w)), 0, 4000, 11):
            yield (f"col{w}", list(columnar_perm(w, order, 97)))


def detection_rate(model, variant, n_trials=10, n_null=30):
    stats, eng = _load()
    rng = random.Random(100)
    synth = syn.synthesize_model1 if model == "model1" else syn.synthesize_model2
    rec = 0
    gaps = []
    for t in range(n_trials):
        off = rng.randrange(len(eng) - 200)
        runkey = eng[off:off + 97]
        pt = [rng.randrange(26) for _ in range(97)]
        crib = [(p, pt[p]) for p in [pp for pp, _ in CRIB_ITEMS]]
        sigma = list(range(26))
        rng.shuffle(sigma)
        perm = list(columnar_perm(8, tuple(random.Random(t).sample(range(8), 8)), 97))
        ct = synth(pt, runkey, sigma, perm, variant)
        _, real_max = nc.max_llr_over_universe(ct, crib, _sub_universe(), (variant,), (model,), stats, L_MAX)
        nm = []
        r2 = random.Random(7 + t)
        for _ in range(n_null):
            sh = nc.shuffle_ct(ct, r2)
            nm.append(nc.max_llr_over_universe(sh, crib, _sub_universe(), (variant,), (model,), stats, L_MAX)[1])
        nm.sort()
        thr = nm[int(0.95 * len(nm))]
        gaps.append(round(real_max - thr, 3))
        if real_max > thr:
            rec += 1
    return rec / n_trials, gaps


def _null_worker(seed):
    stats, _ = _load()
    rng = random.Random(seed)
    sh = nc.shuffle_ct(CT_IDX, rng)
    _, mx = nc.max_llr_over_universe(sh, CRIB_ITEMS, tu.iter_universe(), VARIANTS, MODELS, stats, L_MAX)
    return mx


def main():
    stats, eng = _load()
    sha = els.corpus_sha256(KAHN)
    print(f"[corpus] kahn_codebreakers_1967 sha256={sha[:16]} eng_letters={len(eng)}")

    # ── Synthetic go/no-go gate ──────────────────────────────────────────────
    rates = {}
    for model in MODELS:
        for variant in VARIANTS:
            r, gaps = detection_rate(model, variant)
            rates[f"{model}/{variant}"] = {"rate": r, "real_minus_null95_gaps": gaps}
            print(f"[synthetic] {model}/{variant} detection_rate={r:.2f} gaps={gaps}")
    model1_best = max(rates[f"model1/{v}"]["rate"] for v in VARIANTS)
    underpowered = model1_best < POWER_FLOOR

    # ── Descriptive real-K4 (non-conclusive if underpowered) ─────────────────
    print("[real-K4] full-universe max-LLR ...")
    uhash = tu.universe_hash()
    real_best, real_max = nc.max_llr_over_universe(CT_IDX, CRIB_ITEMS, tu.iter_universe(), VARIANTS, MODELS, stats, L_MAX)
    n_null = 48
    with Pool(min(28, os.cpu_count() or 4)) as pool:
        null_max = pool.map(_null_worker, list(range(1000, 1000 + n_null)))
    ge = sum(1 for x in null_max if x >= real_max)
    p_desc = (1 + ge) / (1 + n_null)
    null_max.sort()

    if underpowered:
        verdict = "DETECTOR_UNDERPOWERED"
        scope = ("Mono+Trans+Running-key remains UNDERDETERMINED; the mono-invariant "
                 "forced-difference detector cannot recover planted solutions, so the "
                 "real-K4 numbers below are DESCRIPTIVE ONLY and support neither "
                 "elimination nor escalation. D1 stays bin-D but is now characterized: "
                 "no positional forced-difference detector helps at K4's parameters.")
    elif p_desc < 0.05:
        verdict = "CANDIDATE_ESCALATE"
        scope = "Real-K4 max-LLR exceeds matched null; route to adversarial review."
    else:
        verdict = "CLEAN_NULL"
        scope = "ELIMINATED_UNDER_BOUNDED_MONO_TRANS_RUNKEY_UNIVERSE (D1 -> bin B)."

    out = {
        "campaign": "mono_trans_runkey_detector_2026_06_06",
        "prereg": "docs/campaigns/mono_trans_runkey_detector_2026_06_06.md",
        "corpus": {"source_id": "kahn_codebreakers_1967", "sha256": sha},
        "universe_hash": uhash,
        "l_max": L_MAX, "power_floor": POWER_FLOOR,
        "synthetic_detection_rates": rates,
        "model1_best_rate": model1_best,
        "detector_underpowered": underpowered,
        "real_k4": {
            "best_config": real_best, "max_llr": real_max,
            "descriptive_p_value": p_desc, "n_null": n_null,
            "null_max_min": null_max[0], "null_max_max": null_max[-1],
            "CONCLUSIVE": (not underpowered),
        },
        "verdict": verdict,
        "scope": scope,
    }
    outpath = os.path.join(_ROOT, "results", "mono_trans_runkey_detector_2026_06_06.json")
    json.dump(out, open(outpath, "w"), indent=1)
    print(f"\n=== VERDICT: {verdict} ===")
    print(f"model1_best_synthetic_rate={model1_best:.2f} (floor {POWER_FLOOR}) "
          f"| real_K4 max_LLR={real_max:.3f} best={real_best['name']}/{real_best['model']}/{real_best['variant']} "
          f"desc_p={p_desc:.3f} [CONCLUSIVE={not underpowered}]")
    print(f"wrote {outpath}")


if __name__ == "__main__":
    main()
