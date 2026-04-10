#!/usr/bin/env python3
"""
Cipher: two-layer outer transposition + KA inner substitution (TABP v2c)
Family: campaigns/tabp
Status: active
Keyspace: ~250K composed Ts × {Vig, Beau, VarBeau} × period {1..26} × KA
Last run:
Best score:

TABP v2c — Two-Layer Outer Transposition + KA Inner (closes the 2×2 matrix)
============================================================================

Combines v2b's two-layer outer transposition enumeration with v2a's KA
(KRYPTOS-keyed alphabet) inner substitution arithmetic. This closes the
(AZ/KA) × (single/multi-layer) matrix of TABP additive-periodic variants:

                  single-layer outer   two-layer outer
    AZ inner       v1                   v2b
    KA inner       v2a                  v2c   ← this script

Under the combined hypothesis:
    CT = KA-substitute(T2(T1(PT)), key)
       = KA-substitute(T_eff(PT), key)    where T_eff = T2 ∘ T1

Same composition math as v2b, but all substitution arithmetic uses KA
indexing. Bean re-derivation uses alph_idx=KA_IDX, producing a different
(equally valid) constraint set per composed T.

Rationale: if Sanborn composed TWO transpositions AND used a KA-based
inner cipher (consistent with K1-K3 Quagmire III heritage), this is the
remaining untested variant in the additive-periodic TABP class.

Expected behavior given v1/v2a/v2b priors: clean null. The filter structure
is identical — Bean INEQ kills periods 1-25, period 26 admits ~2% of T_eff
with exactly 2 missing residues, non-crib decryption stays at noise floor.

Parallelization:
  mp.Pool(cpu_count() - 2), chunks of 512 composed Ts.
  Expected wall-clock: comparable to v2b (~25-40s).
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import sys
import time
from itertools import permutations, product
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Standalone bootstrap ──────────────────────────────────────────────
_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    ALPH_IDX,
    CRIB_DICT,
    CRIB_POSITIONS,
    CT,
    CT_LEN,
    KRYPTOS_ALPHABET,
    MOD,
    STORE_THRESHOLD,
)

# KA (KRYPTOS) indexing — overrides AZ for all substitution arithmetic
KA_IDX: Dict[str, int] = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
KA_CHAR: str = KRYPTOS_ALPHABET
from kryptos.kernel.constraints.bean import rederive_bean_for_transposition
from kryptos.kernel.scoring.ngram import NgramScorer, get_default_scorer
from kryptos.kernel.scoring.words import WordScorer
from kryptos.kernel.transforms.transposition import (
    columnar_perm,
    compose_perms,
    invert_perm,
    rail_fence_perm,
    serpentine_perm,
    spiral_perm,
    validate_perm,
)

# ── Configuration ──────────────────────────────────────────────────────

MAX_PERIOD = 26
VARIANTS = ("vig", "beau", "varbeau")
WORKER_COUNT = max(1, mp.cpu_count() - 2)
CHUNK_SIZE = 512
TOP_K_PER_CHUNK = 100
NGRAM_PREFILTER = -6.2

# Output paths
RESULTS_DIR = Path(_ROOT) / "results"
SUMMARY_PATH = RESULTS_DIR / "f_tabp_transposition_outer_v2c_multilayer_ka.json"
SURVIVORS_PATH = (
    RESULTS_DIR / "f_tabp_transposition_outer_v2c_multilayer_ka_survivors.jsonl"
)

# ── Worker scorers (one load per process) ─────────────────────────────

_WORKER_NGRAM_SCORER: Optional[NgramScorer] = None
_WORKER_WORD_SCORER: Optional[WordScorer] = None


def _init_worker() -> None:
    global _WORKER_NGRAM_SCORER, _WORKER_WORD_SCORER
    _WORKER_NGRAM_SCORER = get_default_scorer()
    word_path = os.path.join(_ROOT, "wordlists", "english.txt")
    with open(word_path, "r") as f:
        words = set(
            w.strip().upper() for w in f
            if len(w.strip()) >= 4 and w.strip().isalpha()
        )
    _WORKER_WORD_SCORER = WordScorer(words, min_word_len=4)

# ── Layer enumeration ──────────────────────────────────────────────────

def enumerate_layer_a_structural() -> List[Tuple[str, List[int]]]:
    """Layer A: structural transpositions (small, diverse)."""
    out: List[Tuple[str, List[int]]] = []

    # Rail fence depths 2..10
    for depth in range(2, 11):
        try:
            perm = rail_fence_perm(CT_LEN, depth)
            if validate_perm(perm, CT_LEN):
                out.append((f"rail{depth}", perm))
        except Exception:
            pass

    # Spiral on various grid shapes
    grids = [
        (4, 25), (5, 20), (7, 14), (8, 13), (10, 10),
        (3, 33), (6, 17), (11, 9), (12, 9), (13, 8),
    ]
    for rows, cols in grids:
        if rows * cols < CT_LEN:
            continue
        for cw in (True, False):
            try:
                perm = spiral_perm(rows, cols, length=CT_LEN, clockwise=cw)
                if validate_perm(perm, CT_LEN):
                    tag = "cw" if cw else "ccw"
                    out.append((f"spiral{rows}x{cols}{tag}", perm))
            except Exception:
                pass
        for vert in (True, False):
            try:
                perm = serpentine_perm(
                    rows, cols, length=CT_LEN, vertical=vert
                )
                if validate_perm(perm, CT_LEN):
                    tag = "v" if vert else "h"
                    out.append((f"serp{rows}x{cols}{tag}", perm))
            except Exception:
                pass

    return out


def enumerate_layer_b_columnar() -> List[Tuple[str, List[int]]]:
    """Layer B: small columnar full enumeration (widths 5, 7)."""
    out: List[Tuple[str, List[int]]] = []
    for w in (5, 7):
        for order in permutations(range(w)):
            try:
                perm = columnar_perm(w, list(order), length=CT_LEN)
                if not validate_perm(perm, CT_LEN):
                    continue
                label = f"col{w}_{''.join(str(i) for i in order)}"
                out.append((label, perm))
            except Exception:
                continue
    return out


def enumerate_compositions() -> List[Tuple[str, List[int]]]:
    """Build all effective permutations from (layer_a, layer_b) compositions.

    Encryption order: PT → layer_a → layer_b → substitute → CT.
    The effective permutation applied to PT before substitution is
    compose(layer_b_perm, layer_a_perm) with gather convention:

        intermediate[i] = layer_b_perm[layer_a_perm[i]] applied to PT

    Actually no — for "apply layer_a first, then layer_b" with the
    gather convention `output[i] = input[perm[i]]`:

        after_layer_a[i] = PT[layer_a_perm[i]]
        after_layer_b[i] = after_layer_a[layer_b_perm[i]]
                         = PT[layer_a_perm[layer_b_perm[i]]]

    So the composed permutation P satisfies:
        P[i] = layer_a_perm[layer_b_perm[i]]
    which is compose_perms(layer_a_perm, layer_b_perm) in the
    transposition module's convention.

    Then pt_to_ct = invert_perm(P).
    """
    layer_a = enumerate_layer_a_structural()
    layer_b = enumerate_layer_b_columnar()

    print(f"Layer A: {len(layer_a)} structural transpositions")
    print(f"Layer B: {len(layer_b)} columnar permutations")
    print(f"Compositions: {len(layer_a)} × {len(layer_b)} = "
          f"{len(layer_a) * len(layer_b)}")

    out: List[Tuple[str, List[int]]] = []

    # Also include identity pair as baseline
    for la_label, la_perm in layer_a:
        for lb_label, lb_perm in layer_b:
            composed = compose_perms(la_perm, lb_perm)
            if not validate_perm(composed, CT_LEN):
                continue
            pt_to_ct = invert_perm(composed)
            label = f"{la_label}_x_{lb_label}"
            out.append((label, pt_to_ct))

    return out

# ── Filter pipeline (same as v1, inlined for independence) ─────────────

def _compute_implied_keys(
    pt_to_ct: List[int], variant: str
) -> Dict[int, int]:
    """KA-aware implied key computation."""
    implied: Dict[int, int] = {}
    for k in CRIB_POSITIONS:
        ct_pos = pt_to_ct[k]
        ct_val = KA_IDX[CT[ct_pos]]
        pt_val = KA_IDX[CRIB_DICT[k]]
        if variant == "vig":
            implied[ct_pos] = (ct_val - pt_val) % MOD
        elif variant == "beau":
            implied[ct_pos] = (ct_val + pt_val) % MOD
        else:
            implied[ct_pos] = (pt_val - ct_val) % MOD
    return implied


def _decrypt_tabp(
    pt_to_ct: List[int], variant: str, keystream: List[int]
) -> str:
    """KA-aware TABP decryption. Recovered letters come from KA_CHAR."""
    chars = []
    for k in range(CT_LEN):
        i = pt_to_ct[k]
        ct_val = KA_IDX[CT[i]]
        key_val = keystream[i]
        if variant == "vig":
            m = (ct_val - key_val) % MOD
        elif variant == "beau":
            m = (key_val - ct_val) % MOD
        else:
            m = (ct_val + key_val) % MOD
        chars.append(KA_CHAR[m])
    return "".join(chars)


def tabp_filter_chunk(
    chunk: List[Tuple[str, List[int]]],
) -> List[Dict]:
    if _WORKER_NGRAM_SCORER is None:
        _init_worker()
    ngram_scorer = _WORKER_NGRAM_SCORER
    word_scorer = _WORKER_WORD_SCORER

    non_crib_positions = [i for i in range(CT_LEN) if i not in CRIB_POSITIONS]
    candidates: List[Dict] = []

    for label, pt_to_ct in chunk:
        try:
            # KA-specific Bean re-derivation
            _eq_pairs, ineq_pairs = rederive_bean_for_transposition(
                pt_to_ct, alph_idx=KA_IDX
            )
        except Exception:
            continue

        for period in range(1, MAX_PERIOD + 1):
            bean_violated = False
            for a, b in ineq_pairs:
                if (a % period) == (b % period):
                    bean_violated = True
                    break
            if bean_violated:
                continue

            for variant in VARIANTS:
                implied = _compute_implied_keys(pt_to_ct, variant)

                residue_values: Dict[int, int] = {}
                consistent = True
                for pos, val in implied.items():
                    r = pos % period
                    existing = residue_values.get(r)
                    if existing is None:
                        residue_values[r] = val
                    elif existing != val:
                        consistent = False
                        break
                if not consistent:
                    continue

                missing = [r for r in range(period) if r not in residue_values]
                if len(missing) > 3:
                    continue

                if missing:
                    key_iter = (
                        {**residue_values, **dict(zip(missing, vals))}
                        for vals in product(range(MOD), repeat=len(missing))
                    )
                else:
                    key_iter = iter([dict(residue_values)])

                for kv in key_iter:
                    keystream = [kv[i % period] for i in range(CT_LEN)]
                    pt = _decrypt_tabp(pt_to_ct, variant, keystream)
                    non_crib_text = "".join(pt[i] for i in non_crib_positions)

                    try:
                        ngram_pc = ngram_scorer.score_per_char(non_crib_text)
                    except Exception:
                        continue

                    if ngram_pc < NGRAM_PREFILTER:
                        continue

                    try:
                        word_result = word_scorer.score(non_crib_text)
                    except Exception:
                        word_result = None

                    candidates.append({
                        "label": label,
                        "variant": variant,
                        "period": period,
                        "key": [kv[i] for i in range(period)],
                        "missing_residues": len(missing),
                        "ngram_pc_noncrib": ngram_pc,
                        "word_coverage": (
                            word_result.coverage if word_result else 0.0
                        ),
                        "word_count": (
                            word_result.word_count if word_result else 0
                        ),
                        "longest_word": (
                            word_result.longest if word_result else 0
                        ),
                        "pt": pt,
                        "ineq_count": len(ineq_pairs),
                    })

    candidates.sort(
        key=lambda c: (c["ngram_pc_noncrib"], c["word_count"]),
        reverse=True,
    )
    return candidates[:TOP_K_PER_CHUNK]

# ── Orchestration ──────────────────────────────────────────────────────

def chunkify(items, n):
    for i in range(0, len(items), n):
        yield items[i:i + n]


def run_campaign(dry_run: bool = False) -> Dict:
    print(f"[TABP v2b] Building two-layer composition enumeration...")
    t0 = time.time()
    all_ts = enumerate_compositions()
    enum_time = time.time() - t0
    print(f"[TABP v2b] {len(all_ts)} composed Ts in {enum_time:.1f}s")

    if dry_run:
        print("[TABP v2b] Dry run — exiting.")
        return {"dry_run": True, "total_ts": len(all_ts)}

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if SURVIVORS_PATH.exists():
        SURVIVORS_PATH.unlink()

    chunks = list(chunkify(all_ts, CHUNK_SIZE))
    print(f"[TABP v2b] Dispatching {len(chunks)} chunks of {CHUNK_SIZE} Ts "
          f"to {WORKER_COUNT} workers")

    all_candidates: List[Dict] = []
    t_start = time.time()

    with mp.Pool(WORKER_COUNT, initializer=_init_worker) as pool:
        last_print = t_start
        for chunk_idx, chunk_candidates in enumerate(
            pool.imap_unordered(tabp_filter_chunk, chunks)
        ):
            all_candidates.extend(chunk_candidates)
            elapsed = time.time() - t_start
            # Throttle progress reports for large chunk counts
            if (time.time() - last_print > 10.0 or
                chunk_idx == len(chunks) - 1 or
                chunk_idx < 5 or
                chunk_candidates):
                rate = (chunk_idx + 1) / elapsed if elapsed > 0 else 0
                eta = (
                    (len(chunks) - chunk_idx - 1) / rate if rate > 0 else 0
                )
                best = (
                    max((c["ngram_pc_noncrib"] for c in chunk_candidates),
                        default=float("-inf"))
                )
                best_str = (
                    f"best_ngram={best:.2f}"
                    if chunk_candidates else "-"
                )
                print(
                    f"[TABP v2b] chunk {chunk_idx + 1}/{len(chunks)} "
                    f"({len(chunk_candidates)} cand, {best_str}) "
                    f"elapsed={elapsed:.1f}s eta={eta:.1f}s"
                )
                last_print = time.time()

    wall_clock = time.time() - t_start
    print(f"[TABP v2b] Campaign complete. Wall clock: {wall_clock:.1f}s")
    print(f"[TABP v2b] Total candidates: {len(all_candidates)}")

    all_candidates.sort(
        key=lambda c: (c["ngram_pc_noncrib"], c["word_count"]),
        reverse=True,
    )

    # Write only top-1000 to jsonl (lower tier is noise)
    with open(SURVIVORS_PATH, "w") as f:
        for c in all_candidates[:1000]:
            f.write(json.dumps(c) + "\n")

    top = all_candidates[:25]
    print(f"\n=== TOP 10 BY NGRAM_PER_CHAR (non-crib) ===")
    for i, c in enumerate(top[:10]):
        print(f"{i+1:2}. {c['label'][:35]:35} {c['variant']:8} p={c['period']:2} "
              f"ngram={c['ngram_pc_noncrib']:.3f} "
              f"words={c['word_count']:3} longest={c['longest_word']}")
        print(f"    {c['pt']}")

    best_ngram = (
        max((c["ngram_pc_noncrib"] for c in all_candidates), default=None)
    )
    best_word_count = (
        max((c["word_count"] for c in all_candidates), default=0)
    )

    summary = {
        "campaign_id": "f_tabp_transposition_outer_v2c_multilayer_ka",
        "alphabet": "KA (KRYPTOS)",
        "alphabet_order": KRYPTOS_ALPHABET,
        "total_ts": len(all_ts),
        "chunks": len(chunks),
        "workers": WORKER_COUNT,
        "wall_clock_sec": wall_clock,
        "enum_time_sec": enum_time,
        "total_candidates": len(all_candidates),
        "best_ngram_pc_noncrib": best_ngram,
        "best_word_count": best_word_count,
        "top_25_candidates": top,
        "ngram_prefilter": NGRAM_PREFILTER,
        "scope_notes": (
            "TABP v2c: two-layer outer transposition + KA inner periodic "
            "substitution. Same composition enumeration as v2b (49 layer A "
            "× 5160 layer B = 252K composed Ts) but with KA alphabet "
            "arithmetic throughout (same as K1-K3 Quagmire III family). "
            "Closes the (AZ/KA) × (single/multi-layer) 2×2 matrix of "
            "TABP additive-periodic variants."
        ),
    }

    with open(SUMMARY_PATH, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n[TABP v2b] Summary written to {SUMMARY_PATH}")

    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    result = run_campaign(dry_run=args.dry_run)
    if result.get("dry_run"):
        return 0

    best_ngram = result.get("best_ngram_pc_noncrib")
    if best_ngram is not None and best_ngram >= -4.8:
        print(f"\n⚠  BREAKTHROUGH CANDIDATE: ngram={best_ngram:.3f}")
        return 3
    if best_ngram is not None and best_ngram >= -5.3:
        print(f"\n⚠  INTERESTING: best ngram={best_ngram:.3f}")
        return 2
    if result["total_candidates"] > 0:
        print(f"\n{result['total_candidates']} candidates at noise floor "
              f"(best={best_ngram:.3f}).")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
