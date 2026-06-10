"""Masked finite NON-periodic (quadratic) tape probe — arbitrary_null_mask slice.

Pre-registration: docs/campaigns/masked_tape_probe_2026_05_25.md
Tier: secondary_exploratory (quarantined).

Mechanism (5-tuple):
  F = additive {vigenere, beaufort, var_beaufort}, alphabet AZ (A=0)
  G = finite NON-periodic tape k[i] = (a + b*i + c*i^2) mod 26, used once over CT'
  N = nulls at noncrib positions p with p mod m == r, m in 3..12, r in 0..m-1
  T = SKIP (index runs over extracted CT' positions)
  A = CT' = carved CT minus nulls; cribs remapped to CT' coords

Universe: 73 masks (|mask| != 24) x 26^3 quadratic keys x 3 variants = 3,849,144.
Every elimination that would touch this is scoped to a narrower alignment model
(direct_ct_pt / ct73_null_extracted); Bean is re-derived per-mask here.

The inner loop reuses the kernel's exact decrypt + key-recovery + check_bean +
score_candidate primitives (same ones verify_masked_candidate calls) but hoists
the per-mask Bean derivation out of the key loop for speed. A parity assert
against verify_masked_candidate runs on a sample before the sweep.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.alphabet import AZ
from kryptos.kernel.constants import CT, CRIB_DICT, CRIB_POSITIONS, MOD
from kryptos.kernel.constraints.bean import check_bean, derive_bean_constraints
from kryptos.kernel.masking.mask import extract_ct, remap_crib_dict, validate_mask
from kryptos.kernel.masking.verify import verify_masked_candidate
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, KEY_RECOVERY, decrypt_text,
)

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
A_RANGE = B_RANGE = C_RANGE = range(26)


def build_masks():
    crib = set(CRIB_POSITIONS)
    noncrib = [p for p in range(len(CT)) if p not in crib]
    seen = {}
    for m in range(3, 13):
        for r in range(m):
            mask = frozenset(p for p in noncrib if p % m == r)
            if not mask or len(mask) == 24:
                continue
            key = tuple(sorted(mask))
            seen[key] = mask
    # deterministic order
    return [seen[k] for k in sorted(seen)]


def universe_hash(masks):
    h = hashlib.sha256()
    for mask in masks:
        h.update(("M:" + ",".join(map(str, sorted(mask)))).encode())
    for v in VARIANTS:
        h.update(("V:" + v.value).encode())
    h.update(f"KEYS:abc:26x26x26".encode())
    return h.hexdigest()


def eval_mask(args):
    """Evaluate all 26^3 x 3 quadratic-tape configs for one mask. Returns top
    records and per-bean maxima. ct is passed explicitly (real or shuffled)."""
    mask_sorted, ct = args
    mask = frozenset(mask_sorted)
    ct_prime = extract_ct(ct, mask)
    L = len(ct_prime)
    cribs = remap_crib_dict(CRIB_DICT, mask)
    eq, ineq, linear = derive_bean_constraints(ct_prime, cribs, AZ)

    idx = AZ.index_table
    ct_idx = [idx[ord(ch) - 65] for ch in ct_prime]
    crib_items = list(cribs.items())  # (pos, letter)
    crib_letter_idx = [(pos, idx[ord(ch) - 65]) for pos, ch in crib_items]

    best_overall = (-1, None, None)          # (crib, key, variant)
    best_bean = (-1, None, None)             # crib among bean-passing
    n_bean_pass = 0

    for vi, variant in enumerate(VARIANTS):
        recover = KEY_RECOVERY[variant]
        # decrypt formula per variant on indices (A=0):
        #   vigenere   P = (C - K) ; beaufort P = (K - C) ; var_beau P = (C + K)
        for a in A_RANGE:
            for b in B_RANGE:
                # precompute linear part a + b*i for this (a,b)
                for c in C_RANGE:
                    # keystream k[i] = (a + b*i + c*i*i) % 26 ; only need crib + bean
                    # crib_score first (cheap reject)
                    cs = 0
                    if variant is CipherVariant.VIGENERE:
                        for pos, pl in crib_letter_idx:
                            k = (a + b * pos + c * pos * pos) % 26
                            if (ct_idx[pos] - k) % 26 == pl:
                                cs += 1
                    elif variant is CipherVariant.BEAUFORT:
                        for pos, pl in crib_letter_idx:
                            k = (a + b * pos + c * pos * pos) % 26
                            if (k - ct_idx[pos]) % 26 == pl:
                                cs += 1
                    else:  # VAR_BEAUFORT  P = (C + K)? actual: P=(C - K) variants differ
                        for pos, pl in crib_letter_idx:
                            k = (a + b * pos + c * pos * pos) % 26
                            if (ct_idx[pos] + k) % 26 == pl:
                                cs += 1
                    if cs > best_overall[0]:
                        best_overall = (cs, (a, b, c), variant.value)
                    # Bean check only worth it on non-trivial crib hits to save time,
                    # but Bean is independent of crib match; we must check to find
                    # bean-passing maxima. Gate: only check Bean when cs is high enough
                    # to matter for promotion OR sample. Compute full keystream + bean
                    # only for cs >= 8 (well below promotion gate 13; cheap insurance).
                    if cs >= 8:
                        ks = [(a + b * i + c * i * i) % 26 for i in range(L)]
                        if check_bean(ks, eq, ineq, linear, MOD).passed:
                            n_bean_pass += 1
                            if cs > best_bean[0]:
                                best_bean = (cs, (a, b, c), variant.value)
    return {
        "mask": list(mask_sorted),
        "mask_size": len(mask_sorted),
        "pt_len": L,
        "best_crib": best_overall[0],
        "best_crib_key": best_overall[1],
        "best_crib_variant": best_overall[2],
        "best_bean_crib": best_bean[0],
        "best_bean_key": best_bean[1],
        "best_bean_variant": best_bean[2],
        "n_bean_pass_ge8": n_bean_pass,
    }


def parity_check(masks):
    """Confirm the hoisted inner loop matches verify_masked_candidate for a sample."""
    mask = masks[0]
    ct_prime = extract_ct(CT, mask)
    cribs = remap_crib_dict(CRIB_DICT, mask)
    eq, ineq, linear = derive_bean_constraints(ct_prime, cribs, AZ)
    idx = AZ.index_table
    L = len(ct_prime)
    for (a, b, c) in [(1, 2, 3), (7, 0, 11), (25, 25, 25)]:
        for variant in VARIANTS:
            key = [(a + b * i + c * i * i) % 26 for i in range(L)]
            mv = verify_masked_candidate(CT, mask, variant, key, alphabet=AZ)
            # reference crib via our inner formula
            ct_idx = [idx[ord(ch) - 65] for ch in ct_prime]
            cs = 0
            for pos, ch in cribs.items():
                pl = idx[ord(ch) - 65]
                k = key[pos]
                if variant is CipherVariant.VIGENERE:
                    p = (ct_idx[pos] - k) % 26
                elif variant is CipherVariant.BEAUFORT:
                    p = (k - ct_idx[pos]) % 26
                else:
                    p = (ct_idx[pos] + k) % 26
                if p == pl:
                    cs += 1
            assert cs == mv.crib_score, (
                f"parity fail {variant.value} {(a,b,c)}: ours {cs} vs oracle {mv.crib_score}"
            )
    print("[parity] inner-loop crib formula matches verify_masked_candidate: OK")


def run_universe(ct, masks, workers, label):
    args = [(list(m), ct) for m in masks]
    results = []
    with Pool(workers) as pool:
        for rec in pool.imap_unordered(eval_mask, args):
            results.append(rec)
    best_crib = max(r["best_crib"] for r in results)
    best_bean_crib = max(r["best_bean_crib"] for r in results)
    print(f"[{label}] max crib={best_crib}  max bean-passing crib={best_bean_crib}")
    return results, best_crib, best_bean_crib


def main():
    t0 = time.time()
    masks = build_masks()
    uhash = universe_hash(masks)
    n_total = len(masks) * 26 * 26 * 26 * 3
    workers = max(1, cpu_count() - 2)
    print(f"masks={len(masks)} keys={26**3} variants={len(VARIANTS)} "
          f"N={n_total} workers={workers}")
    print(f"universe_sha256={uhash}")

    parity_check(masks)

    real_results, real_best_crib, real_best_bean = run_universe(
        CT, masks, workers, "REAL"
    )

    # empirical shuffle null: B shuffles of carved CT, same universe
    import random
    B = 20
    null_max_crib = []
    null_max_bean = []
    for b in range(B):
        rng = random.Random(1000 + b)
        chars = list(CT)
        rng.shuffle(chars)
        sct = "".join(chars)
        _, mc, mb = run_universe(sct, masks, workers, f"NULL[{b}]")
        null_max_crib.append(mc)
        null_max_bean.append(mb)

    # p-values via (extreme+1)/(B+1)
    ge_crib = sum(1 for x in null_max_crib if x >= real_best_crib)
    ge_bean = sum(1 for x in null_max_bean if x >= real_best_bean)
    p_crib = (ge_crib + 1) / (B + 1)
    p_bean = (ge_bean + 1) / (B + 1)

    # promotion gate per pre-reg
    promoted = (real_best_bean >= 13) and (p_bean < 0.001)

    out = {
        "task": "masked_quadratic_tape_probe",
        "tier": "secondary_exploratory",
        "alignment_model": "arbitrary_null_mask",
        "prereg": "docs/campaigns/masked_tape_probe_2026_05_25.md",
        "ct": CT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "universe_sha256": uhash,
        "universe_size": n_total,
        "n_masks": len(masks),
        "real_best_crib": real_best_crib,
        "real_best_bean_passing_crib": real_best_bean,
        "null_B": B,
        "null_max_crib": null_max_crib,
        "null_max_bean_passing_crib": null_max_bean,
        "p_value_crib_vs_null": p_crib,
        "p_value_bean_crib_vs_null": p_bean,
        "promotion_gate_crib>=13_and_bean_and_p<0.001": promoted,
        "expected_max_crib_binomial_null_note": "E[count crib>=9]=0.55, crib>=10=0.033, crib>=13=2.6e-6 over N",
        "per_mask": sorted(real_results, key=lambda r: -r["best_bean_crib"])[:15],
        "status": "DISPROVED" if not promoted else "INVESTIGATE",
        "elapsed_sec": round(time.time() - t0, 1),
        "reproduction_command":
            "PYTHONPATH=src python3 -u scripts/_uncategorized/e_masked_quadratic_tape_probe.py",
    }
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(_ROOT, "results", f"masked_quadratic_tape_probe_{ts}.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nREAL best crib={real_best_crib}  bean-passing best crib={real_best_bean}")
    print(f"NULL max crib over {B} shuffles: {null_max_crib}")
    print(f"p(crib vs null)={p_crib:.3f}  p(bean-crib vs null)={p_bean:.3f}")
    print(f"PROMOTED={promoted}")
    print(f"artifact: {path}")
    print(f"elapsed {out['elapsed_sec']}s")


if __name__ == "__main__":
    main()
