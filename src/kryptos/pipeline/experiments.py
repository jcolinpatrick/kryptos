"""Canonical experiment definitions.

Provides templates for common experiment types, ensuring they all
go through the canonical evaluation path.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from kryptos.kernel.constants import CT, CT_LEN
from kryptos.kernel.alphabet import Alphabet, AZ, KA, build_alphabet_pairs
from kryptos.kernel.transforms.vigenere import CipherVariant, remove_additive_mask
from kryptos.kernel.transforms.transposition import (
    unmask_block_transposition, apply_perm, invert_perm,
)
from kryptos.kernel.constraints.crib import compute_implied_keys, check_vimark_consistency
from kryptos.kernel.constraints.bean import (
    verify_bean_simple, expand_keystream_vimark, verify_bean_from_implied,
)
from kryptos.pipeline.evaluation import evaluate_candidate


def block_transposition_worker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Worker function for block-transposition sweep.

    Processes one permutation across all mask x alphabet x variant x period combos.
    Designed for multiprocessing Pool.
    """
    import time

    perm = args["perm"]
    masks = args.get("masks", ["NONE"])
    alpha_pairs = args.get("alpha_pairs", [])
    variants = args.get("variants", ["vigenere", "beaufort", "var_beaufort"])
    periods = args.get("periods", [4, 5, 6, 7])
    store_threshold = args.get("store_threshold", 10)
    boustro = args.get("cycle_boustro", False)
    job_id = args.get("job_id", "")
    config_label = args.get("config_label", "")

    t0 = time.monotonic()
    best_score = 0
    tests = 0
    top_results: list[dict] = []

    # Undo transposition
    trans_ct = unmask_block_transposition(CT, perm, boustro)

    for mask_kw in masks:
        unmasked = remove_additive_mask(trans_ct, mask_kw)

        for pa_label, pa_seq, ca_label, ca_seq in alpha_pairs:
            pa_idx = [0] * 26
            for i, ch in enumerate(pa_seq):
                pa_idx[ord(ch) - 65] = i
            ca_idx = [0] * 26
            for i, ch in enumerate(ca_seq):
                ca_idx[ord(ch) - 65] = i

            for var_name in variants:
                variant = CipherVariant(var_name)
                for period in periods:
                    tests += 1

                    # Compute implied keys
                    from kryptos.kernel.constants import CRIB_ENTRIES, MOD
                    from kryptos.kernel.transforms.vigenere import KEY_RECOVERY

                    fn = KEY_RECOVERY[variant]
                    implied: list[tuple[int, int]] = []
                    for pos, pt_ch in CRIB_ENTRIES:
                        c = ca_idx[ord(unmasked[pos]) - 65]
                        p = pa_idx[ord(pt_ch) - 65]
                        implied.append((pos, fn(c, p)))

                    n_consistent, total, primer = check_vimark_consistency(implied, period)

                    if n_consistent > best_score:
                        best_score = n_consistent

                    if n_consistent >= store_threshold:
                        bean_ok = False
                        if primer is not None:
                            ks = expand_keystream_vimark(primer)
                            bean_ok = verify_bean_simple(ks)
                        else:
                            # No full primer (high period) — check Bean
                            # from implied keys directly
                            bean_ok = verify_bean_from_implied(dict(implied))

                        entry = {
                            "score": n_consistent,
                            "mask": mask_kw,
                            "PA": pa_label,
                            "CA": ca_label,
                            "variant": var_name,
                            "period": period,
                            "bean_ok": bean_ok,
                        }
                        if primer is not None:
                            entry["primer"] = list(primer)
                        if bean_ok and n_consistent >= 24:
                            entry["ALERT"] = True
                        top_results.append(entry)

    elapsed = time.monotonic() - t0
    return {
        "job_id": job_id,
        "config_label": config_label,
        "perm": list(perm),
        "cycle_boustro": boustro,
        "best_score": best_score,
        "tests": tests,
        "elapsed": round(elapsed, 4),
        "status": "complete",
        "error": None,
        "top_results": top_results,
    }


def full_transposition_worker(args: Dict[str, Any]) -> Dict[str, Any]:
    """Worker for full-text transposition sweep.

    Unlike block_transposition_worker, this operates on the full 97-char text.
    """
    import time

    perm = args["perm"]
    variants = args.get("variants", ["vigenere", "beaufort", "var_beaufort"])
    periods = args.get("periods", list(range(3, 16)))
    store_threshold = args.get("store_threshold", 10)
    job_id = args.get("job_id", "")

    t0 = time.monotonic()
    inv = invert_perm(perm)
    intermediate = apply_perm(CT, inv)

    best_score = 0
    tests = 0
    top_results: list[dict] = []

    for var_name in variants:
        variant = CipherVariant(var_name)
        implied = compute_implied_keys(intermediate, variant)
        kv = dict(implied)

        for period in periods:
            tests += 1
            n_con, total, primer = check_vimark_consistency(implied, period)

            if n_con > best_score:
                best_score = n_con

            if n_con >= store_threshold:
                bean_ok = False
                if primer is not None:
                    ks = expand_keystream_vimark(primer)
                    bean_ok = verify_bean_simple(ks)
                else:
                    # No full primer (high period) — check Bean
                    # from implied keys directly
                    bean_ok = verify_bean_from_implied(kv)

                top_results.append({
                    "score": n_con,
                    "variant": var_name,
                    "period": period,
                    "bean_ok": bean_ok,
                    "primer": list(primer) if primer else None,
                    "ALERT": bean_ok and n_con >= 24,
                })

    return {
        "job_id": job_id,
        "best_score": best_score,
        "tests": tests,
        "elapsed": round(time.monotonic() - t0, 4),
        "status": "complete",
        "top_results": top_results,
    }
