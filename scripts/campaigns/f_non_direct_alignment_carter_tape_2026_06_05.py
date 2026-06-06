#!/usr/bin/env python3
"""non_direct_alignment x Carter Vol.1 offset-swept finite-tape inner.

Pre-registration: docs/campaigns/non_direct_alignment_carter_tape_2026_06_05.md
Output:           results/non_direct_alignment_carter_tape_2026_06_05.json

Completes the 2026-05-29 clean-null 52-route tape-inner harness with the ONE
allowlisted public running-key source it never swept: Carter Vol.1
(source_id=carter_tomb_vol1), offset-swept over all 287,417 length-97 windows.

Structure (REUSED verbatim from the tested 2026-05-29 runner, so the cipher
convention is byte-identical): outer NAMED grid route physically permutes CT
(gather I[j]=CT[perm[j]]); inner finite Carter tape decrypts I in place; cribs
anchored at canonical PT positions -> kernel score_candidate (post_transposition).

The swept Carter offset axis is handled by a numpy crib-led prefilter that is
VALIDATED against the kernel (decrypt_reordered_tape -> score_candidate) on
random samples before any sweep (fail-closed). The prefilter computes the exact
crib_score for every offset; the kernel is the authority and the prefilter is
only an accelerator that must reproduce it.
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import random
import sys

import numpy as np

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
for p in (os.path.join(_ROOT, "src"), _ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

# ── Import the TESTED 2026-05-29 runner module by path (identical convention) ──
_SIB = os.path.join(_ROOT, "scripts", "campaigns",
                    "f_non_direct_alignment_tape_inner_2026_05_29.py")
_spec = importlib.util.spec_from_file_location("ndatp_sib", _SIB)
sib = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sib)

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT  # noqa: E402
from kryptos.kernel.scoring.aggregate import score_candidate  # noqa: E402
from kryptos.kernel.scoring.ngram import get_default_scorer  # noqa: E402
from kryptos.kernel.masking.route_null import (  # noqa: E402
    family_matched_null_perms, mean_equality_permutation_p,
)
from kryptos.admissibility import resolve_license_path  # noqa: E402

N = CT_LEN
assert N == 97
REAL_WIDTHS = sib.REAL_WIDTHS
HELD_OUT_WIDTHS = sib.HELD_OUT_WIDTHS
VARIANTS = sib.VARIANTS                      # 3 CipherVariant
_ALPHA = sib._ALPHA                          # {"AZ": AZ, "KA": KA}
_N_QUADGRAMS = sib._N_QUADGRAMS              # 94
decrypt_reordered_tape = sib.decrypt_reordered_tape

CRIB_POS = sorted(CRIB_DICT)                  # 24 positions
CRIB_CHAR = {p: CRIB_DICT[p] for p in CRIB_POS}

# Locked pre-registered thresholds (see pre-reg doc) ──────────────────────────
NGRAM_FLOOR = -4.5
SIGNAL_CRIB = 18
KILL_CRIB = 13            # max crib < 13 is the noise-floor kill clause
ALPHABETS = ("AZ", "KA")

# ── Carter source (admissibility-allowlisted public corpus) ──────────────────
def load_carter():
    src_id = "carter_tomb_vol1"
    path = resolve_license_path(src_id)        # provenance gate: allowlisted source -> path
    assert path is not None and os.path.exists(path), f"carter source unresolved: {path!r}"
    raw = open(path, encoding="utf-8", errors="ignore").read()
    return src_id, str(path), raw


def carter_index_arrays(raw):
    """Return {alphabet: int16 np.array of alphabet indices} via the SAME
    _map_string the public-tape harness uses (no hand-rolled mapping)."""
    raw_up = raw.upper()                       # Carter is mixed-case; tapes are A-Z
    out = {}
    for a in ALPHABETS:
        idx = sib._map_string(raw_up, a)        # list[int] alphabet indices (letters only)
        out[a] = np.asarray(idx, dtype=np.int16)
    return out


def required_tape_at_cribs(perm, variant, alpha_name):
    """For a fixed (perm, variant, alphabet), the unique tape index req_t[k] at
    each crib position that makes decrypt yield the crib letter. Computed via 26
    kernel decrypts with CONSTANT tapes -> zero convention risk (position-wise
    stream cipher: PT[p] depends only on I[p] and tape[p])."""
    alpha = _ALPHA[alpha_name]
    # alphabet index -> letter, recovered from the kernel mapping itself
    idx_to_letter = {}
    for L in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        idx_to_letter[sib._map_string(L, alpha_name)[0]] = L
    req = {}
    pt_by_t = []
    for t in range(26):
        pt_by_t.append(decrypt_reordered_tape(CT, perm, [t] * N,
                                               variant=variant, alphabet=alpha))
    for p in CRIB_POS:
        want = CRIB_CHAR[p]
        hit = [t for t in range(26) if pt_by_t[t][p] == want]
        assert len(hit) == 1, f"non-unique req tape at p={p}: {hit}"
        req[p] = hit[0]
    return req


def crib_score_over_offsets(carter_idx, req, n_off):
    """Exact crib_score for every Carter offset, vectorized."""
    score = np.zeros(n_off, dtype=np.int16)
    for p in CRIB_POS:                          # tape position == PT position p
        score += (carter_idx[p:p + n_off] == req[p])
    return score


def build_real_universe():
    return sib.build_reordering_universe()      # 52 routes, hash-locked


def build_null_universe():
    aligns, seen = [], set()
    for name, perm in family_matched_null_perms(
            real_widths=set(REAL_WIDTHS), held_out_widths=set(HELD_OUT_WIDTHS), n=N):
        key = tuple(perm)
        if key not in seen:
            seen.add(key)
            aligns.append((name, perm))
    return aligns


def validate_prefilter(carter, n_off, n_samples=240):
    """Fail-closed: prefilter crib_score MUST equal the kernel at random configs."""
    rng = random.Random(20260605)
    universe = build_real_universe()
    bad = 0
    for _ in range(n_samples):
        name, perm = rng.choice(universe)
        variant = rng.choice(VARIANTS)
        a = rng.choice(ALPHABETS)
        off = rng.randrange(n_off)
        req = required_tape_at_cribs(perm, variant, a)
        vec = int(sum(1 for p in CRIB_POS if int(carter[a][p + off]) == req[p]))
        tape = carter[a][off:off + N].tolist()
        pt = decrypt_reordered_tape(CT, perm, tape, variant=variant, alphabet=_ALPHA[a])
        kern = int(score_candidate(pt).crib_score)
        if vec != kern:
            bad += 1
            print(f"  MISMATCH {name}/{variant.value}/{a}/off={off}: vec={vec} kern={kern}")
    assert bad == 0, f"prefilter validation FAILED on {bad}/{n_samples} samples"
    return n_samples


def sweep(universe, carter, n_off, scorer, *, top_k=25, rand_sample=80, tag=""):
    """Crib-led exact max over all offsets; full-score top + random sample for
    ngram. Returns per-config best records + per-reordering best ngram total."""
    rng = random.Random(7)
    recs = []
    per_reorder_best_ngram = []
    global_best_crib = 0
    promoted = []
    for name, perm in universe:
        reorder_best_ngram = None
        for variant in VARIANTS:
            for a in ALPHABETS:
                req = required_tape_at_cribs(perm, variant, a)
                cs = crib_score_over_offsets(carter[a], req, n_off)
                mx = int(cs.max())
                global_best_crib = max(global_best_crib, mx)
                # offsets to full-score: top-k by crib + random sample
                order = np.argsort(cs)[::-1][:top_k]
                sample = set(int(o) for o in order)
                sample |= set(rng.randrange(n_off) for _ in range(rand_sample))
                for off in sample:
                    tape = carter[a][off:off + N].tolist()
                    pt = decrypt_reordered_tape(CT, perm, tape,
                                                variant=variant, alphabet=_ALPHA[a])
                    kc = int(score_candidate(pt).crib_score)
                    total = float(scorer.score(pt))
                    pc = total / _N_QUADGRAMS
                    if reorder_best_ngram is None or total > reorder_best_ngram:
                        reorder_best_ngram = total
                    rec = {"reorder": name, "variant": variant.value, "alphabet": a,
                           "offset": int(off), "crib_vec": int(cs[off]),
                           "crib_kernel": kc, "ngram_total": total,
                           "ngram_per_char": pc}
                    if kc != int(cs[off]):
                        rec["PREFILTER_MISMATCH"] = True
                    if kc >= SIGNAL_CRIB or (pc >= NGRAM_FLOOR):
                        rec["pt"] = pt
                        promoted.append(rec)  # candidate; final gate vs null below
                    recs.append(rec)
                # also record the exact-max crib config (may be outside sample)
                bo = int(cs.argmax())
                recs.append({"reorder": name, "variant": variant.value, "alphabet": a,
                             "offset": bo, "crib_vec": mx, "crib_kernel": None,
                             "exact_max": True})
        per_reorder_best_ngram.append(reorder_best_ngram)
    return {
        "global_best_crib": global_best_crib,
        "per_reorder_best_ngram": per_reorder_best_ngram,
        "promoted_raw": promoted,
        "n_full_scored": len(recs),
    }


def main():
    src_id, src_path, raw = load_carter()
    carter = carter_index_arrays(raw)
    n_off = len(carter["AZ"]) - N + 1
    assert n_off == 287417, n_off
    scorer = get_default_scorer()

    print(f"[carter] source={src_id} letters={len(carter['AZ'])} offsets={n_off}")
    print("[validate] prefilter vs kernel ...")
    nval = validate_prefilter(carter, n_off)
    print(f"[validate] OK on {nval} samples")

    real_univ = build_real_universe()
    null_univ = build_null_universe()
    real_hash = sib.reordering_hash(real_univ)
    print(f"[universe] real routes={len(real_univ)} hash={real_hash[:16]} "
          f"null routes={len(null_univ)}")

    cardinality = len(real_univ) * n_off * len(VARIANTS) * len(ALPHABETS)
    print(f"[sweep] REAL cardinality={cardinality:,}")
    real = sweep(real_univ, carter, n_off, scorer, tag="real")
    print(f"[sweep] real global_best_crib={real['global_best_crib']}")
    print("[sweep] NULL (family-matched held-out widths) ...")
    null = sweep(null_univ, carter, n_off, scorer, tag="null")
    print(f"[sweep] null global_best_crib={null['global_best_crib']}")

    real_ng = [x for x in real["per_reorder_best_ngram"] if x is not None]
    null_ng = [x for x in null["per_reorder_best_ngram"] if x is not None]
    null_max_ngram = max(null_ng) if null_ng else float("-inf")
    real_max_ngram = max(real_ng) if real_ng else float("-inf")
    mean_eq_p = mean_equality_permutation_p(real_ng, null_ng) if real_ng and null_ng else None

    # Final promotion gate: crib>=18 OR (ngram_per_char>=floor AND ngram_total>null_max)
    promoted = [r for r in real["promoted_raw"]
                if r["crib_kernel"] is not None and (
                    r["crib_kernel"] >= SIGNAL_CRIB or
                    (r["ngram_per_char"] >= NGRAM_FLOOR and r["ngram_total"] > null_max_ngram))]

    best_crib = real["global_best_crib"]
    if promoted:
        verdict = "CANDIDATE_ESCALATE"
    elif best_crib >= SIGNAL_CRIB:
        verdict = "CANDIDATE_ESCALATE"
    elif best_crib < KILL_CRIB and (mean_eq_p is None or mean_eq_p > 0.05):
        verdict = "CLEAN_NULL"
    elif best_crib < KILL_CRIB:
        verdict = "CLEAN_NULL_NGRAM_ADVISORY"
    else:
        verdict = "INVESTIGATE"  # 13 <= best_crib < 18, no ngram promotion

    out = {
        "campaign": "non_direct_alignment_carter_tape_2026_06_05",
        "prereg": "docs/campaigns/non_direct_alignment_carter_tape_2026_06_05.md",
        "source_id": src_id, "n_offsets": n_off,
        "real_universe_hash": real_hash,
        "cardinality_real": cardinality,
        "real_global_best_crib": real["global_best_crib"],
        "null_global_best_crib": null["global_best_crib"],
        "real_best_ngram_total": real_max_ngram,
        "null_max_ngram_total": null_max_ngram,
        "real_best_ngram_per_char": (real_max_ngram / _N_QUADGRAMS),
        "mean_equality_permutation_p": mean_eq_p,
        "n_promoted": len(promoted),
        "promoted": promoted[:20],
        "prefilter_validated_samples": nval,
        "thresholds": {"ngram_floor": NGRAM_FLOOR, "signal_crib": SIGNAL_CRIB,
                       "kill_crib": KILL_CRIB},
        "verdict": verdict,
        "scope": ("ELIMINATED_UNDER_BOUNDED_CARTER_TAPE_NONDIRECT_UNIVERSE"
                  if verdict.startswith("CLEAN_NULL") else verdict),
    }
    outpath = os.path.join(_ROOT, "results",
                           "non_direct_alignment_carter_tape_2026_06_05.json")
    json.dump(out, open(outpath, "w"), indent=1)
    print(f"\n=== VERDICT: {verdict} ===")
    print(f"real_best_crib={real['global_best_crib']} null_best_crib={null['global_best_crib']} "
          f"real_best_ngram/char={real_max_ngram/_N_QUADGRAMS:.3f} mean_eq_p={mean_eq_p}")
    print(f"wrote {outpath}")


if __name__ == "__main__":
    main()
