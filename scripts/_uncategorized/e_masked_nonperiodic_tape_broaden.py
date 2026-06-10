"""Masked finite NON-periodic tape probe — BROADENED arbitrary_null_mask slice.

Pre-registration: docs/campaigns/masked_tape_probe_broaden_2026_05_25.md
Tier: secondary_exploratory (quarantined).

Extends scripts/_uncategorized/e_masked_quadratic_tape_probe.py along the axes
that run deferred:
  1. Alphabets: AZ (A=0) AND KA (keyword-mixed). A=1 shown degenerate (parity).
  2. Mask families: contiguous-block + symmetric edge-padding (|mask| != 24,
     never touching crib positions 21-33 / 63-73).
  3. Tape generators: cubic k[i]=(a+b*i+c*i^2+d*i^3) and Fibonacci-style
     k[0]=s0,k[1]=s1,k[i]=k[i-1]+k[i-2] (all mod 26), single-use over CT'.

Universe: 285 masks x 26,676 keys (26000 cubic + 676 fib) x 3 variants x 2
alphabets = 45,615,960 configs.

Inner loop reuses the kernel's exact decrypt/key-recovery/Bean/score primitives
(the ones verify_masked_candidate calls), hoisting per-mask Bean derivation out
of the key loop. A parity assert against verify_masked_candidate runs first.
"""
from __future__ import annotations

import hashlib
import json
import os
import random
import sys
import time
from datetime import datetime, timezone
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.alphabet import AZ, KA
from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, CRIB_POSITIONS, MOD
from kryptos.kernel.constraints.bean import check_bean, derive_bean_constraints
from kryptos.kernel.masking.mask import extract_ct, remap_crib_dict
from kryptos.kernel.masking.verify import verify_masked_candidate
from kryptos.kernel.transforms.vigenere import CipherVariant, KEY_RECOVERY

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
ALPHABETS = [AZ, KA]

# cubic coeff ranges (PRE-REGISTERED)
CUBIC_A = range(26)
CUBIC_B = range(10)
CUBIC_C = range(10)
CUBIC_D = range(10)
N_CUBIC = 26 * 10 * 10 * 10  # 26000
N_FIB = 26 * 26              # 676
BEAN_GATE = 8                # compute full keystream + Bean only for crib >= 8


def build_masks():
    crib = set(CRIB_POSITIONS)
    L = CT_LEN
    seen = {}
    # contiguous-block
    for k in (4, 6, 8, 10, 12):
        for start in range(0, L - k + 1):
            run = set(range(start, start + k))
            if run & crib or len(run) == 24:
                continue
            seen[tuple(sorted(run))] = frozenset(run)
    # symmetric edge-padding
    for h in (2, 4, 6, 8, 10):
        for t in (2, 4, 6, 8, 10):
            m = set(range(0, h)) | set(range(L - t, L))
            if m & crib or len(m) == 24:
                continue
            seen[tuple(sorted(m))] = frozenset(m)
    return [seen[k] for k in sorted(seen)]


def universe_hash(masks):
    h = hashlib.sha256()
    for mask in masks:
        h.update(("M:" + ",".join(map(str, sorted(mask)))).encode())
    for alpha in ALPHABETS:
        h.update(("ALPHA:" + alpha.label + ":" + alpha.sequence).encode())
    for v in VARIANTS:
        h.update(("V:" + v.value).encode())
    h.update(b"GEN:cubic:a0-25,b0-9,c0-9,d0-9")
    h.update(b"GEN:fib:s0_0-25,s1_0-25")
    return h.hexdigest()


def _cubic_keystream(a, b, c, d, L):
    return [(a + b * i + c * i * i + d * i * i * i) % 26 for i in range(L)]


def _fib_keystream(s0, s1, L):
    ks = [s0 % 26, s1 % 26]
    for i in range(2, L):
        ks.append((ks[i - 1] + ks[i - 2]) % 26)
    return ks[:L]


def _crib_score(ct_idx, crib_letter_idx, ks, variant):
    cs = 0
    if variant is CipherVariant.VIGENERE:      # P = (C - K)
        for pos, pl in crib_letter_idx:
            if (ct_idx[pos] - ks[pos]) % 26 == pl:
                cs += 1
    elif variant is CipherVariant.BEAUFORT:    # P = (K - C)
        for pos, pl in crib_letter_idx:
            if (ks[pos] - ct_idx[pos]) % 26 == pl:
                cs += 1
    else:                                      # VAR_BEAUFORT P = (C + K)
        for pos, pl in crib_letter_idx:
            if (ct_idx[pos] + ks[pos]) % 26 == pl:
                cs += 1
    return cs


def eval_mask(args):
    """Evaluate all keys x variants x alphabets for one mask on the given ct."""
    mask_sorted, ct = args
    mask = frozenset(mask_sorted)
    ct_prime = extract_ct(ct, mask)
    L = len(ct_prime)

    best_overall = -1
    best_overall_meta = None
    best_bean = -1
    best_bean_meta = None
    n_bean_pass = 0

    for alpha in ALPHABETS:
        idx = alpha.index_table
        cribs = remap_crib_dict(CRIB_DICT, mask)
        eq, ineq, linear = derive_bean_constraints(ct_prime, cribs, alpha)
        ct_idx = [idx[ord(ch) - 65] for ch in ct_prime]
        crib_letter_idx = [(pos, idx[ord(ch) - 65]) for pos, ch in cribs.items()]
        crib_positions = [pos for pos, _ in crib_letter_idx]

        for variant in VARIANTS:
            # ---- cubic family ----
            for a in CUBIC_A:
                for b in CUBIC_B:
                    for c in CUBIC_C:
                        for d in CUBIC_D:
                            # crib-only keystream values (cheap); full only if needed
                            cs = 0
                            if variant is CipherVariant.VIGENERE:
                                for pos, pl in crib_letter_idx:
                                    k = (a + b * pos + c * pos * pos + d * pos * pos * pos) % 26
                                    if (ct_idx[pos] - k) % 26 == pl:
                                        cs += 1
                            elif variant is CipherVariant.BEAUFORT:
                                for pos, pl in crib_letter_idx:
                                    k = (a + b * pos + c * pos * pos + d * pos * pos * pos) % 26
                                    if (k - ct_idx[pos]) % 26 == pl:
                                        cs += 1
                            else:
                                for pos, pl in crib_letter_idx:
                                    k = (a + b * pos + c * pos * pos + d * pos * pos * pos) % 26
                                    if (ct_idx[pos] + k) % 26 == pl:
                                        cs += 1
                            if cs > best_overall:
                                best_overall = cs
                                best_overall_meta = (alpha.label, variant.value,
                                                     "cubic", (a, b, c, d))
                            if cs >= BEAN_GATE:
                                ks = _cubic_keystream(a, b, c, d, L)
                                if check_bean(ks, eq, ineq, linear, MOD).passed:
                                    n_bean_pass += 1
                                    if cs > best_bean:
                                        best_bean = cs
                                        best_bean_meta = (alpha.label, variant.value,
                                                          "cubic", (a, b, c, d))
            # ---- fibonacci family ----
            for s0 in range(26):
                for s1 in range(26):
                    ks = _fib_keystream(s0, s1, L)
                    cs = _crib_score(ct_idx, crib_letter_idx, ks, variant)
                    if cs > best_overall:
                        best_overall = cs
                        best_overall_meta = (alpha.label, variant.value, "fib", (s0, s1))
                    if cs >= BEAN_GATE:
                        if check_bean(ks, eq, ineq, linear, MOD).passed:
                            n_bean_pass += 1
                            if cs > best_bean:
                                best_bean = cs
                                best_bean_meta = (alpha.label, variant.value,
                                                  "fib", (s0, s1))
    return {
        "mask": list(mask_sorted),
        "mask_size": len(mask_sorted),
        "pt_len": L,
        "best_crib": best_overall,
        "best_crib_meta": best_overall_meta,
        "best_bean_crib": best_bean,
        "best_bean_meta": best_bean_meta,
        "n_bean_pass_ge8": n_bean_pass,
    }


def parity_check(masks):
    """Confirm hoisted inner loop matches verify_masked_candidate, both alphabets."""
    mask = masks[0]
    ct_prime = extract_ct(CT, mask)
    L = len(ct_prime)
    for alpha in ALPHABETS:
        for variant in VARIANTS:
            # cubic sample
            a, b, c, d = 3, 2, 1, 4
            key = _cubic_keystream(a, b, c, d, L)
            mv = verify_masked_candidate(CT, mask, variant, key, alphabet=alpha)
            cribs = remap_crib_dict(CRIB_DICT, mask)
            idx = alpha.index_table
            ct_idx = [idx[ord(ch) - 65] for ch in ct_prime]
            cli = [(pos, idx[ord(ch) - 65]) for pos, ch in cribs.items()]
            cs = _crib_score(ct_idx, cli, key, variant)
            assert cs == mv.crib_score, (
                f"parity fail {alpha.label} {variant.value} cubic: "
                f"ours {cs} vs oracle {mv.crib_score}"
            )
            # fib sample
            key = _fib_keystream(5, 9, L)
            mv = verify_masked_candidate(CT, mask, variant, key, alphabet=alpha)
            cs = _crib_score(ct_idx, cli, key, variant)
            assert cs == mv.crib_score, (
                f"parity fail {alpha.label} {variant.value} fib: "
                f"ours {cs} vs oracle {mv.crib_score}"
            )
    print("[parity] inner-loop crib formula matches verify_masked_candidate (AZ+KA): OK")


def a1_relabel_check(masks):
    """A=1 is a +1 uniform relabel of the output alphabet on a mod-26 additive
    cipher. For the cubic family the constant term `a` sweeps 0..25, so the SET
    of decryptions under A=1 equals A=0. Verify: best crib over the cubic family
    on AZ equals best crib when CT is relabeled +1 (i.e. the universe is closed
    under the +1 shift)."""
    mask = masks[len(masks) // 2]
    ct_prime = extract_ct(CT, mask)
    L = len(ct_prime)
    cribs = remap_crib_dict(CRIB_DICT, mask)
    idx = AZ.index_table
    # A=0 best over cubic, vigenere
    ct_idx = [idx[ord(ch) - 65] for ch in ct_prime]
    cli = [(pos, idx[ord(ch) - 65]) for pos, ch in cribs.items()]
    def best_cubic_vig(ct_idx_local, crib_shift):
        best = -1
        for a in CUBIC_A:
            for b in CUBIC_B:
                for c in CUBIC_C:
                    for d in CUBIC_D:
                        cs = 0
                        for pos, pl in cli:
                            k = (a + b * pos + c * pos * pos + d * pos ** 3) % 26
                            if (ct_idx_local[pos] - k) % 26 == (pl + crib_shift) % 26:
                                cs += 1
                        if cs > best:
                            best = cs
        return best
    base = best_cubic_vig(ct_idx, 0)
    # A=1: every index +1 on both CT and PT-target -> equality preserved exactly,
    # AND absorbed by `a`. shift both by +1:
    ct_idx_shift = [(v + 1) % 26 for v in ct_idx]
    shifted = best_cubic_vig(ct_idx_shift, 1)
    assert base == shifted, (
        f"A=1 relabel changed result base={base} shifted={shifted} -- HALT, "
        f"convention-dependent"
    )
    print(f"[A=1 check] cubic-vig best invariant under +1 relabel: {base} == {shifted} OK")


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
    per_mask_keys = (N_CUBIC + N_FIB)
    n_total = len(masks) * per_mask_keys * len(VARIANTS) * len(ALPHABETS)
    workers = max(1, cpu_count() - 2)
    print(f"masks={len(masks)} keys/mask-variant-alpha={per_mask_keys} "
          f"variants={len(VARIANTS)} alphabets={len(ALPHABETS)} N={n_total} workers={workers}")
    print(f"universe_sha256={uhash}")

    parity_check(masks)
    a1_relabel_check(masks)

    real_results, real_best_crib, real_best_bean = run_universe(CT, masks, workers, "REAL")

    B = 20
    null_max_crib, null_max_bean = [], []
    for b in range(B):
        rng = random.Random(2000 + b)
        chars = list(CT)
        rng.shuffle(chars)
        sct = "".join(chars)
        _, mc, mb = run_universe(sct, masks, workers, f"NULL[{b}]")
        null_max_crib.append(mc)
        null_max_bean.append(mb)

    ge_crib = sum(1 for x in null_max_crib if x >= real_best_crib)
    ge_bean = sum(1 for x in null_max_bean if x >= real_best_bean)
    p_crib = (ge_crib + 1) / (B + 1)
    p_bean = (ge_bean + 1) / (B + 1)
    promoted = (real_best_bean >= 13) and (p_bean < 0.001)

    out = {
        "task": "masked_nonperiodic_tape_broaden",
        "tier": "secondary_exploratory",
        "alignment_model": "arbitrary_null_mask",
        "prereg": "docs/campaigns/masked_tape_probe_broaden_2026_05_25.md",
        "extends": "docs/campaigns/masked_tape_probe_2026_05_25.md (hash 58d695c7...)",
        "ct": CT,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "universe_sha256": uhash,
        "universe_size": n_total,
        "n_masks": len(masks),
        "mask_families": "contiguous_block(k=4,6,8,10,12) + symmetric_edge(h,t in 2..10)",
        "generators": "cubic(a0-25,b/c/d 0-9)=26000 + fibonacci(s0,s1 0-25)=676",
        "alphabets": [a.label for a in ALPHABETS],
        "variants": [v.value for v in VARIANTS],
        "real_best_crib": real_best_crib,
        "real_best_bean_passing_crib": real_best_bean,
        "null_B": B,
        "null_max_crib": null_max_crib,
        "null_max_bean_passing_crib": null_max_bean,
        "p_value_crib_vs_null": p_crib,
        "p_value_bean_crib_vs_null": p_bean,
        "analytic_max_of_N_note": "E[crib>=10]=0.385, >=11=0.0195, >=13=3.1e-05 over N",
        "promotion_gate_crib>=13_and_bean_and_p<0.001": promoted,
        "per_mask_top": sorted(real_results, key=lambda r: -r["best_bean_crib"])[:15],
        "per_mask_top_by_crib": sorted(real_results, key=lambda r: -r["best_crib"])[:5],
        "status": "DISPROVED" if not promoted else "INVESTIGATE",
        "elapsed_sec": round(time.time() - t0, 1),
        "reproduction_command":
            "PYTHONPATH=src python3 -u scripts/_uncategorized/e_masked_nonperiodic_tape_broaden.py",
    }
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(_ROOT, "results", f"masked_nonperiodic_tape_broaden_{ts}.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2)
    print(f"\nREAL best crib={real_best_crib}  bean-passing best crib={real_best_bean}")
    print(f"NULL max crib over {B} shuffles: {null_max_crib}")
    print(f"NULL max bean-crib over {B} shuffles: {null_max_bean}")
    print(f"p(crib vs null)={p_crib:.3f}  p(bean-crib vs null)={p_bean:.3f}")
    print(f"PROMOTED={promoted}  STATUS={out['status']}")
    print(f"artifact: {path}")
    print(f"elapsed {out['elapsed_sec']}s")


if __name__ == "__main__":
    main()
