#!/usr/bin/env python3
"""Non-direct-alignment NON-PERIODIC public-tape inner closure.

alignment_model = non_direct_alignment ; submodel = non_periodic_public_tape_inner

Closes the still-open non-periodic-inner sub-arm that the 2026-05-28 crib-forcing
closure (`f_non_direct_alignment_cribforce_2026_05_28.py`) explicitly left open:
that arm crib-FORCED a PERIODIC inner; this one applies a NON-PERIODIC FINITE
PUBLIC KEY TAPE inner over the SAME 52-route reordering universe (hash-asserted
equal -> directly comparable).

Model: an outer named grid-route reordering pi maps CT -> I = pi(CT) (gather:
I[j] = CT[perm[j]]); an inner finite public key tape decrypts I IN PLACE -> PT,
with cribs at canonical PLAINTEXT positions 21-33 / 63-73. Because the named
route physically permutes CT before an in-place inner decrypt, anchored
`score_candidate` is the correct kernel-verified scorer (post_transposition, NOT
the unimplemented `free` path). Bean does NOT apply by construction (the inner
key is a fixed tape, not crib-forced; the periodic-Bean derivation is irrelevant).

PROVENANCE (LOAD-BEARING): every tape is derived PROGRAMMATICALLY from PUBLIC
repo strings only (solved K1/K2/K3 plaintexts & ciphertexts; the public KRYPTOS
tableau), imported from kryptosbot.panel_cribs. NEVER any leaked/sealed K4
plaintext. NEVER a short keyword cycled to length (that is PERIODIC, out of
scope). Mirrors tools/workflows/k4_c6_tape_content/gen_tapes.py exactly.

Pre-registration: docs/campaigns/non_direct_alignment_tape_inner_2026_05_29.md
Output: results/non_direct_alignment_tape_inner_2026_05_29.json
"""
from __future__ import annotations

import hashlib
import json
import os
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
from kryptos.kernel.masking.route_null import (  # noqa: E402
    grid_route_perms, family_matched_null_perms, honest_null_summary,
    mean_equality_permutation_p,
)
from kryptosbot.panel_cribs import (  # noqa: E402  PUBLIC FACTS
    _K1_PT, _K1_CT, _K2_PT, _K2_CT, _K3_PT, _K3_CT,
)

# ── Pre-registered constants (locked before any data) ───────────────────────
N = 97
assert CT_LEN == N
REAL_WIDTHS = (4, 5, 6, 7, 8, 11, 13, 14, 21, 24)   # == closed periodic-inner arm
HELD_OUT_WIDTHS = (3, 9, 10, 12, 15, 16, 17, 18, 19, 20, 22, 23)  # null, disjoint
VARIANTS = (CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT)
NGRAM_PER_CHAR_FLOOR = -4.5            # docs/preregistered_thresholds_2026_04_08.md
SIGNAL_CRIB = 18                       # kernel SIGNAL threshold
_N_QUADGRAMS = N - 3                   # 94
EXPECTED_REORDERING_HASH = (
    "7a9ac67336cd37e2f7be75c59d549b75618395c47a4bcd515d652232996ae6aa"
)
_ALPHA = {"AZ": AZ, "KA": KA}


# ── Public tape corpus (mirrors gen_tapes.py; PUBLIC sources only) ───────────
_AZ_SEQ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_KA_SEQ = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
_AZ_IDX = {c: i for i, c in enumerate(_AZ_SEQ)}
_KA_IDX = {c: i for i, c in enumerate(_KA_SEQ)}


def _tableau_rowmajor() -> str:
    return "".join(_KA_SEQ[r:] + _KA_SEQ[:r] for r in range(26))


def _fit97(values, src_len):
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
            values, fit_rule = _fit97(_map_string(raw, alphabet), len(raw))
            assert len(values) == N and all(0 <= v <= 25 for v in values)
            out.append({
                "tape_id": f"{source}__{alphabet}", "source": f"{source}__{alphabet}",
                "alphabet": alphabet, "fit_rule": fit_rule,
                "values": tuple(values),
            })
    return out


# ── Reordering universe (byte-identical to the closed periodic-inner arm) ────
def build_reordering_universe():
    aligns, seen = [], set()

    def add(name, perm):
        assert sorted(perm) == list(range(N)), f"{name} not a permutation"
        key = tuple(perm)
        if key in seen:
            return
        seen.add(key)
        aligns.append((name, perm))

    add("identity", list(range(N)))
    add("reverse", list(range(N - 1, -1, -1)))
    for w in REAL_WIDTHS:
        for name, perm in grid_route_perms(w, n=N):
            add(name, perm)
    return aligns


def reordering_hash(aligns):
    h = hashlib.sha256()
    for name, perm in aligns:
        h.update(name.encode())
        h.update(bytes(perm))
    return h.hexdigest()


# ── Core (importable, tested) ───────────────────────────────────────────────
def apply_perm(ct, perm):
    """Gather: I[j] = CT[perm[j]] (matches the closed periodic-inner arm)."""
    return "".join(ct[perm[j]] for j in range(len(perm)))


def decrypt_reordered_tape(ct, perm, tape, *, variant, alphabet):
    """CT --gather(perm)--> I --finite-tape decrypt (in place)--> PT."""
    intermediate = apply_perm(ct, perm)
    return apply_key_tape(intermediate, tape, variant=variant,
                          direction="decrypt", alphabet=alphabet)


def eval_reordering(ct, name, perm, tapes, scorer):
    """All (tape x variant) decrypts for one reordering -> per-config records."""
    recs = []
    for trec in tapes:
        alpha = _ALPHA[trec["alphabet"]]
        for v in VARIANTS:
            pt = decrypt_reordered_tape(ct, perm, trec["values"],
                                        variant=v, alphabet=alpha)
            crib = int(score_candidate(pt).crib_score)
            total = float(scorer.score(pt))
            recs.append({
                "alignment": name, "tape_id": trec["tape_id"],
                "alphabet": trec["alphabet"], "variant": v.value,
                "crib_score": crib, "ngram_total": total,
                "ngram_per_char": total / _N_QUADGRAMS,
                "pt": pt,
            })
    return recs


def best_ngram_for_reordering(ct, perm, tapes, scorer):
    """Best n-gram total over all (tape x variant) for one reordering."""
    best = None
    for trec in tapes:
        alpha = _ALPHA[trec["alphabet"]]
        for v in VARIANTS:
            pt = decrypt_reordered_tape(ct, perm, trec["values"],
                                        variant=v, alphabet=alpha)
            total = float(scorer.score(pt))
            if best is None or total > best:
                best = total
    return best


# ── Multiprocessing workers ─────────────────────────────────────────────────
_SCORER = None
_TAPES = None


def _init_worker():
    global _SCORER, _TAPES
    _SCORER = get_default_scorer()
    _TAPES = public_tapes()


def _eval_named(args):
    name, perm = args
    return eval_reordering(CT, name, perm, _TAPES, _SCORER)


def _eval_null(args):
    _name, perm = args
    return best_ngram_for_reordering(CT, perm, _TAPES, _SCORER)


def main():
    aligns = build_reordering_universe()
    rh = reordering_hash(aligns)
    print(f"[universe] reorderings={len(aligns)}  reordering_sha256={rh}")
    assert rh == EXPECTED_REORDERING_HASH, (
        f"reordering universe drifted ({rh}); refusing non-comparable universe")
    tapes = public_tapes()
    n_cfg = len(aligns) * len(tapes) * len(VARIANTS)
    print(f"[universe] tapes={len(tapes)} variants={[v.value for v in VARIANTS]} "
          f"configs={n_cfg}")

    workers = max(1, cpu_count() - 2)

    # Real sweep over the 52 named reorderings.
    with Pool(workers, initializer=_init_worker) as pool:
        real_lists = pool.map(_eval_named, aligns)
    real = [r for sub in real_lists for r in sub]
    real.sort(key=lambda r: r["ngram_total"], reverse=True)
    by_crib = sorted(real, key=lambda r: r["crib_score"], reverse=True)
    max_crib = by_crib[0]["crib_score"] if by_crib else 0
    real_best = real[0] if real else None
    print(f"[real] configs={len(real)} max_crib_score={max_crib} "
          f"best_ngram/char={real_best['ngram_per_char']:.3f}" if real_best else "[real] none")

    # Family-matched null: SAME grid-route grammar at HELD-OUT widths only.
    null_aligns = list(family_matched_null_perms(
        real_widths=set(REAL_WIDTHS), held_out_widths=set(HELD_OUT_WIDTHS), n=N))
    with Pool(workers, initializer=_init_worker) as pool:
        null_best = pool.map(_eval_null, null_aligns)
    summary = honest_null_summary(
        real_best["ngram_total"] if real_best else None, null_best)
    # Per-reordering best totals (max over tape x variant per reordering) make
    # the real and null distributions apples-to-apples for the mean-equality
    # permutation test -- the INFERENTIAL "are these the same distribution?"
    # number the statistical-auditor (2026-05-29) used to show real ~ null.
    real_best_by_reorder = {}
    for r in real:
        a = r["alignment"]
        if a not in real_best_by_reorder or r["ngram_total"] > real_best_by_reorder[a]:
            real_best_by_reorder[a] = r["ngram_total"]
    mean_eq_p = mean_equality_permutation_p(
        list(real_best_by_reorder.values()), null_best, trials=20000)
    print(f"[null] family-matched reorderings={len(null_aligns)} "
          f"consistent={summary.n_consistent_null} "
          f"null_max/char={(summary.null_max_total/_N_QUADGRAMS):.3f}"
          if summary.null_max_total is not None else "[null] no consistent null")
    print(f"[honest] null_beats_real={summary.null_beats_real} "
          f"mean_equality_permutation_p={mean_eq_p:.3f} "
          f"(real ~ null when p is large)" if mean_eq_p is not None else "")

    # Pre-registered gate: crib_score leads (fixed-tape honest discriminator);
    # n-gram path requires the per-char floor AND beating the matched-null max.
    promoted = []
    for r in by_crib:
        crib_hit = r["crib_score"] >= SIGNAL_CRIB
        ngram_hit = (r["ngram_per_char"] >= NGRAM_PER_CHAR_FLOOR
                     and summary.null_max_total is not None
                     and r["ngram_total"] > summary.null_max_total)
        if crib_hit or ngram_hit:
            promoted.append(r)

    verdict = "CLEAN_NULL" if not promoted else "CANDIDATE_ESCALATE"
    print(f"[gate] promoted={len(promoted)}  VERDICT={verdict}")

    out = {
        "alignment_model": "non_direct_alignment",
        "submodel": "non_periodic_public_tape_inner",
        "reordering_hash": rh,
        "real_widths": list(REAL_WIDTHS),
        "held_out_null_widths": list(HELD_OUT_WIDTHS),
        "variants": [v.value for v in VARIANTS],
        "n_tapes": len(tapes),
        "tape_ids": [t["tape_id"] for t in tapes],
        "n_configs": n_cfg,
        "gate": {
            "ngram_per_char_floor": NGRAM_PER_CHAR_FLOOR,
            "signal_crib_score": SIGNAL_CRIB,
            "ngram_must_beat_family_matched_null_max": True,
        },
        "max_crib_score": max_crib,
        "real_top_by_crib": by_crib[:12],
        "real_top_by_ngram": real[:12],
        "null": {
            "kind": "family_matched_grid_route_held_out_widths",
            "n_reorderings": len(null_aligns),
            "n_consistent": summary.n_consistent_null,
            "null_max_total": summary.null_max_total,
            "null_max_per_char": (summary.null_max_total / _N_QUADGRAMS)
                                 if summary.null_max_total is not None else None,
            "null_beats_real": summary.null_beats_real,
            "mean_equality_permutation_p": mean_eq_p,
            "p_conditioned_NONINFERENTIAL": summary.p_conditioned_on_consistent_null,
            "note": (
                "DECISIVE: mean_equality_permutation_p (large => real and null "
                "per-reordering distributions are statistically identical => any "
                "max-of-universe edge is order-statistic noise). "
                "p_conditioned_NONINFERENTIAL is NOT a significance value (a 0.0 "
                "here means 'no consistent null perm scored >= real best', not "
                "'significant'). " + summary.note),
        },
        "n_promoted": len(promoted),
        "promoted": promoted,
        "verdict": verdict,
        "scope_eliminated": (
            "non_direct_alignment x non-periodic finite PUBLIC-tape inner over the "
            "52-route hash-locked universe (id/reverse + grid routes widths "
            f"{list(REAL_WIDTHS)} x 5 routes) x 16 public tapes x 3 variants"),
        "scope_not_eliminated": (
            "non-public tapes; crib-forced free-residue (period-97) inners; "
            "non-named / evidence-motivated alignments; null-bearing variants"),
    }
    outpath = os.path.join(_ROOT, "results",
                           "non_direct_alignment_tape_inner_2026_05_29.json")
    os.makedirs(os.path.dirname(outpath), exist_ok=True)
    with open(outpath, "w") as f:
        json.dump(out, f, indent=2)
    print(f"[out] {outpath}")
    return verdict


if __name__ == "__main__":
    main()
