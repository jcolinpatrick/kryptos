#!/usr/bin/env python3
"""C7 — segmented (cut) PUBLIC-tape inner, direct-positional closure.

alignment_model = direct_ct_pt ; submodel = segmented_cut_public_tape

Extends the dynamic-solve C7 lead (spec_h36 tested a SINGLE two-segment tape at
ONE cut). Here a single PUBLIC key tape T is physically CUT at position C and the
second piece RESTARTS the tape: keystream K[i] = T[i] for i<C, K[i] = T[i-C] for
i>=C. The cut is swept across the inter-crib gap C in {34..62} (the
EAST/NORTHEAST group ends at 33, BERLIN/CLOCK starts at 63), so the cut falls
BETWEEN the two crib groups and the Bean equality k[27]=k[65] is VOID by
construction (positions 27 and 65 lie in different segments). Motivated by the
physical-cut evidence (ABSCISSA = "cut off", triangle at the K1/K2 chart
boundary).

Direct-positional, fixed public tape => anchored `score_candidate` (crib_score)
is the honest discriminator; no crib-forcing => no order-statistic trap. The
n-gram path uses a RANDOM-tape matched null (same cut x variant sweep) and the
portable per-char English floor as the lead disqualifier.

PROVENANCE: tapes are PUBLIC only (K1/K2/K3 PT & CT, K1+K2+K3 PT, KRYPTOS
tableau row-major), via kryptosbot.panel_cribs. Mirrors gen_tapes.py /
f_non_direct_alignment_tape_inner. NEVER leaked/sealed K4 text; NEVER a short
keyword cycled to length.

Pre-registration: docs/campaigns/c7_segmented_public_tape_2026_05_29.md
Output: results/c7_segmented_public_tape_2026_05_29.json
"""
from __future__ import annotations

import json
import os
import random
import sys
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
for p in (os.path.join(_ROOT, "src"), _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from kryptos.kernel.constants import CT, CT_LEN  # noqa: E402
from kryptos.kernel.alphabet import AZ, KA  # noqa: E402
from kryptos.kernel.transforms.vigenere import CipherVariant  # noqa: E402
from kryptos.kernel.transforms.key_tape import apply_key_tape  # noqa: E402
from kryptos.kernel.scoring.aggregate import score_candidate  # noqa: E402
from kryptos.kernel.scoring.ngram import get_default_scorer  # noqa: E402
from kryptos.kernel.masking.route_null import mean_equality_permutation_p  # noqa: E402
from kryptosbot.panel_cribs import (  # noqa: E402  PUBLIC FACTS
    _K1_PT, _K1_CT, _K2_PT, _K2_CT, _K3_PT, _K3_CT,
)

# ── Pre-registered constants (locked before any data) ───────────────────────
N = 97
assert CT_LEN == N
CUT_POSITIONS = tuple(range(34, 63))   # inter-crib gap, 29 cuts (34..62 incl.)
VARIANTS = (CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT)
NGRAM_PER_CHAR_FLOOR = -4.5            # docs/preregistered_thresholds_2026_04_08.md
SIGNAL_CRIB = 18
_N_QUADGRAMS = N - 3                   # 94
NULL_RANDOM_TAPES = 64
NULL_SEED = 20260529
_ALPHA = {"AZ": AZ, "KA": KA}

# ── Public tape corpus (mirrors gen_tapes.py; PUBLIC sources only) ───────────
_AZ_SEQ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_KA_SEQ = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
_AZ_IDX = {c: i for i, c in enumerate(_AZ_SEQ)}
_KA_IDX = {c: i for i, c in enumerate(_KA_SEQ)}


def _tableau_rowmajor():
    return "".join(_KA_SEQ[r:] + _KA_SEQ[:r] for r in range(26))


def _fit97(values):
    if len(values) >= N:
        return values[:N], "TRUNC97"
    return [values[i % len(values)] for i in range(N)], "CYCLE97"


def _map_string(s, alphabet):
    idx = _AZ_IDX if alphabet == "AZ" else _KA_IDX
    return [idx[c] for c in s if c in idx]


_SOURCES = [
    ("K1_PT", _K1_PT), ("K2_PT", _K2_PT), ("K3_PT", _K3_PT),
    ("K1_CT", _K1_CT), ("K2_CT", _K2_CT), ("K3_CT", _K3_CT),
    ("K1K2K3_PT", _K1_PT + _K2_PT + _K3_PT),
    ("KRYPTOS_TABLEAU_ROWMAJOR", _tableau_rowmajor()),
]


def public_tapes():
    out = []
    for source, raw in _SOURCES:
        for alphabet in ("AZ", "KA"):
            values, fit_rule = _fit97(_map_string(raw, alphabet))
            assert len(values) == N and all(0 <= v <= 25 for v in values)
            out.append({
                "tape_id": f"{source}__{alphabet}", "source": f"{source}__{alphabet}",
                "alphabet": alphabet, "fit_rule": fit_rule, "values": tuple(values),
            })
    return out


# ── Core (importable, tested) ───────────────────────────────────────────────
def cut_keystream(tape, C, n=N):
    """Physically-cut tape: segment 1 = T[:C], segment 2 = T restarted (T[:n-C])."""
    return tuple(tape[:C]) + tuple(tape[:n - C])


def decrypt_cut_tape(ct, tape, C, *, variant, alphabet):
    """Direct-positional decrypt of CT with a cut+restart public tape."""
    return apply_key_tape(ct, cut_keystream(tape, C, len(ct)), variant=variant,
                          direction="decrypt", alphabet=alphabet)


# ── Multiprocessing workers ─────────────────────────────────────────────────
_SCORER = None


def _init_worker():
    global _SCORER
    _SCORER = get_default_scorer()


def _eval_tape(trec):
    """All (cut x variant) for one public tape -> records + this tape's best ngram."""
    alpha = _ALPHA[trec["alphabet"]]
    recs = []
    best_ng = None
    for C in CUT_POSITIONS:
        for v in VARIANTS:
            pt = decrypt_cut_tape(CT, trec["values"], C, variant=v, alphabet=alpha)
            crib = int(score_candidate(pt).crib_score)
            total = float(_SCORER.score(pt))
            if best_ng is None or total > best_ng:
                best_ng = total
            recs.append({
                "tape_id": trec["tape_id"], "alphabet": trec["alphabet"],
                "cut": C, "variant": v.value, "crib_score": crib,
                "ngram_total": total, "ngram_per_char": total / _N_QUADGRAMS,
                "pt": pt,
            })
    return {"records": recs, "best_ngram": best_ng}


def _eval_random_tape(seed_alpha):
    """Best ngram over (cut x variant) for one RANDOM length-97 tape (matched null)."""
    seed, alpha_name = seed_alpha
    rng = random.Random(seed)
    tape = tuple(rng.randrange(26) for _ in range(N))
    alpha = _ALPHA[alpha_name]
    best = None
    for C in CUT_POSITIONS:
        for v in VARIANTS:
            pt = decrypt_cut_tape(CT, tape, C, variant=v, alphabet=alpha)
            total = float(_SCORER.score(pt))
            if best is None or total > best:
                best = total
    return best


def main():
    tapes = public_tapes()
    n_cfg = len(tapes) * len(CUT_POSITIONS) * len(VARIANTS)
    print(f"[universe] tapes={len(tapes)} cuts={len(CUT_POSITIONS)} "
          f"({CUT_POSITIONS[0]}..{CUT_POSITIONS[-1]}) "
          f"variants={[v.value for v in VARIANTS]} configs={n_cfg}")

    workers = max(1, cpu_count() - 2)
    with Pool(workers, initializer=_init_worker) as pool:
        real_out = pool.map(_eval_tape, tapes)
    real = [r for d in real_out for r in d["records"]]
    real_best_by_tape = [d["best_ngram"] for d in real_out]
    by_crib = sorted(real, key=lambda r: r["crib_score"], reverse=True)
    by_ngram = sorted(real, key=lambda r: r["ngram_total"], reverse=True)
    max_crib = by_crib[0]["crib_score"]
    real_best = by_ngram[0]
    print(f"[real] configs={len(real)} max_crib_score={max_crib} "
          f"best_ngram/char={real_best['ngram_per_char']:.3f}")

    # Random-tape matched null (same cut x variant sweep).
    null_args = [(NULL_SEED + i, "AZ" if i % 2 == 0 else "KA")
                 for i in range(NULL_RANDOM_TAPES)]
    with Pool(workers, initializer=_init_worker) as pool:
        null_best = pool.map(_eval_random_tape, null_args)
    null_max = max(null_best)
    null_beats_real = null_max >= real_best["ngram_total"]
    mean_eq_p = mean_equality_permutation_p(real_best_by_tape, null_best, trials=20000)
    print(f"[null] random tapes={NULL_RANDOM_TAPES} null_max/char={null_max/_N_QUADGRAMS:.3f} "
          f"null_beats_real={null_beats_real} mean_equality_permutation_p={mean_eq_p:.3f}")

    # Pre-registered gate.
    promoted = []
    for r in by_crib:
        crib_hit = r["crib_score"] >= SIGNAL_CRIB
        ngram_hit = (r["ngram_per_char"] >= NGRAM_PER_CHAR_FLOOR
                     and r["ngram_total"] > null_max)
        if crib_hit or ngram_hit:
            promoted.append(r)
    verdict = "CLEAN_NULL" if not promoted else "CANDIDATE_ESCALATE"
    print(f"[gate] promoted={len(promoted)}  VERDICT={verdict}")

    out = {
        "alignment_model": "direct_ct_pt",
        "submodel": "segmented_cut_public_tape",
        "cut_positions": list(CUT_POSITIONS),
        "variants": [v.value for v in VARIANTS],
        "n_tapes": len(tapes),
        "tape_ids": [t["tape_id"] for t in tapes],
        "n_configs": n_cfg,
        "gate": {
            "ngram_per_char_floor": NGRAM_PER_CHAR_FLOOR,
            "signal_crib_score": SIGNAL_CRIB,
            "ngram_must_beat_random_tape_null_max": True,
        },
        "max_crib_score": max_crib,
        "real_top_by_crib": by_crib[:12],
        "real_top_by_ngram": by_ngram[:12],
        "null": {
            "kind": "random_length97_tape_matched_cut_variant_sweep",
            "n_random_tapes": NULL_RANDOM_TAPES, "seed": NULL_SEED,
            "null_max_total": null_max,
            "null_max_per_char": null_max / _N_QUADGRAMS,
            "null_beats_real": null_beats_real,
            "mean_equality_permutation_p": mean_eq_p,
            "note": ("mean_equality_permutation_p large => public-tape and "
                     "random-tape best-ngram distributions are identical => no "
                     "public-source advantage under this cut model."),
        },
        "n_promoted": len(promoted),
        "promoted": promoted,
        "verdict": verdict,
        "scope_eliminated": (
            "direct_positional segmented CUT public-tape (single tape, cut+restart) "
            "over 16 public tapes x cuts {34..62} x 3 variants"),
        "scope_not_eliminated": (
            "two independent public tapes (one per segment); cuts outside the "
            "inter-crib gap; crib-forced segment keys; non-public tapes; "
            "null-bearing / variable-length models"),
    }
    outpath = os.path.join(_ROOT, "results", "c7_segmented_public_tape_2026_05_29.json")
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[out] {outpath}")
    return verdict


if __name__ == "__main__":
    main()
