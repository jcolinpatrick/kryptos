#!/usr/bin/env python3
"""
Cipher: transposition-first + extended-period inner substitution (TABP v3)
Family: campaigns/tabp
Status: active
Keyspace: 6165 outer Ts × {Vig,Beau,VarBeau} × period 27-50 (scored on covered subset)
Last run:
Best score:

TABP v3 — Extended Period, Determined-Positions-Only Scoring
=============================================================

Extends TABP v1 beyond the period ≤ 26 cap. At periods > 26, the 24
crib positions cannot cover all p residue classes (pigeonhole forces
p-24 residues to be missing). The standard v1 pipeline enumerates
missing residues which becomes infeasible for p > 26 (26^k blowup).

This campaign uses a DIFFERENT approach: instead of enumerating, we
decrypt only the positions whose residue class IS covered by the
crib-derived keys, and score that determined subset. The missing-residue
positions are skipped entirely.

For period p with k covered residues out of 24 crib constraints:
  - Determined positions: those where (position % p) is in covered_set
  - Count: ~97 × (k / p)  (roughly linear in coverage)
  - Typical values:
    p=27, k=24: determined ~87 positions
    p=30, k=24: determined ~78
    p=40, k=24: determined ~58
    p=50, k=24: determined ~47

Scoring the determined positions with ngram_per_char gives us
signal/noise discrimination on a shorter but valid subset. A true
solution would have English-like text at determined positions;
random keys produce noise.

This complements v1-v2c by covering the period 27-50 range that
they structurally couldn't test.

Parallelization:
  mp.Pool(cpu_count() - 2), chunks of 256 Ts, periods 27-50 inner loop.
  Expected wall-clock: ~30-60 seconds on 26 workers.
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    ALPH_IDX, CRIB_DICT, CRIB_POSITIONS, CT, CT_LEN, MOD,
)
from kryptos.kernel.constraints.bean import rederive_bean_for_transposition
from kryptos.kernel.scoring.ngram import NgramScorer, get_default_scorer
from kryptos.kernel.scoring.words import WordScorer

# Import T enumeration from v1
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from f_tabp_transposition_outer_v1 import enumerate_all_transpositions

# ── Configuration ──────────────────────────────────────────────────────

PERIOD_RANGE = range(27, 51)  # period 27..50 inclusive; v1/v2b cover 1..26
VARIANTS = ("vig", "beau", "varbeau")
WORKER_COUNT = max(1, mp.cpu_count() - 2)
CHUNK_SIZE = 256
TOP_K_PER_CHUNK = 50

# Ngram prefilter on determined-subset text
# Baseline: at these short lengths, quadgram scores are noisier. Use a
# slightly looser threshold than v1 (which used -6.2).
NGRAM_PREFILTER = -6.0

# Minimum determined-subset length for scoring to be meaningful.
# Below ~30 chars, quadgram scores are too noisy to trust.
MIN_DETERMINED_LEN = 30

RESULTS_DIR = Path(_ROOT) / "results"
SUMMARY_PATH = RESULTS_DIR / "f_tabp_extended_period_v3.json"
SURVIVORS_PATH = RESULTS_DIR / "f_tabp_extended_period_v3_survivors.jsonl"

# ── Worker state ───────────────────────────────────────────────────────

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


# ── Filter pipeline (determined-only variant) ──────────────────────────

def _compute_implied_keys(
    pt_to_ct: List[int], variant: str
) -> Dict[int, int]:
    implied: Dict[int, int] = {}
    for k in CRIB_POSITIONS:
        ct_pos = pt_to_ct[k]
        ct_val = ALPH_IDX[CT[ct_pos]]
        pt_val = ALPH_IDX[CRIB_DICT[k]]
        if variant == "vig":
            implied[ct_pos] = (ct_val - pt_val) % MOD
        elif variant == "beau":
            implied[ct_pos] = (ct_val + pt_val) % MOD
        else:
            implied[ct_pos] = (pt_val - ct_val) % MOD
    return implied


def _decrypt_determined_positions(
    pt_to_ct: List[int],
    variant: str,
    residue_values: Dict[int, int],
    period: int,
) -> Tuple[str, List[int]]:
    """Decrypt ONLY the positions whose residue is covered by
    residue_values. Returns (decrypted_text, original_position_indices)
    where the text is the concatenation of decrypted chars in order
    and original_position_indices maps text[i] back to original 0-96.
    """
    decoded_chars = []
    positions = []
    for k in range(CT_LEN):
        i = pt_to_ct[k]
        r = i % period
        if r not in residue_values:
            continue
        ct_val = ALPH_IDX[CT[i]]
        key_val = residue_values[r]
        if variant == "vig":
            m = (ct_val - key_val) % MOD
        elif variant == "beau":
            m = (key_val - ct_val) % MOD
        else:
            m = (ct_val + key_val) % MOD
        decoded_chars.append(chr(ord("A") + m))
        positions.append(k)  # original PT position k
    return "".join(decoded_chars), positions


def tabp_extended_period_chunk(
    chunk: List[Tuple[str, List[int]]],
) -> List[Dict]:
    """Worker: for each T, test periods 27..50 using determined-subset scoring."""
    if _WORKER_NGRAM_SCORER is None:
        _init_worker()
    ngram_scorer = _WORKER_NGRAM_SCORER
    word_scorer = _WORKER_WORD_SCORER

    candidates: List[Dict] = []

    for label, pt_to_ct in chunk:
        try:
            _eq_pairs, ineq_pairs = rederive_bean_for_transposition(pt_to_ct)
        except Exception:
            continue

        for period in PERIOD_RANGE:
            # Bean INEQ variant-independent pre-filter
            if any((a % period) == (b % period) for a, b in ineq_pairs):
                continue

            for variant in VARIANTS:
                implied = _compute_implied_keys(pt_to_ct, variant)

                # Period consistency within covered residues
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

                # Decrypt only determined positions
                det_text, det_positions = _decrypt_determined_positions(
                    pt_to_ct, variant, residue_values, period
                )

                if len(det_text) < MIN_DETERMINED_LEN:
                    continue

                # Score — but also need to strip crib positions from the
                # determined text to avoid tautological matches.
                noncrib_det = "".join(
                    det_text[i] for i, pos in enumerate(det_positions)
                    if pos not in CRIB_POSITIONS
                )

                if len(noncrib_det) < MIN_DETERMINED_LEN:
                    continue

                try:
                    ngram_pc = ngram_scorer.score_per_char(noncrib_det)
                except Exception:
                    continue

                if ngram_pc < NGRAM_PREFILTER:
                    continue

                try:
                    wr = word_scorer.score(noncrib_det)
                except Exception:
                    wr = None

                candidates.append({
                    "label": label,
                    "variant": variant,
                    "period": period,
                    "key_residues": sorted(residue_values.items()),
                    "covered_residues": len(residue_values),
                    "missing_residues": period - len(residue_values),
                    "determined_length": len(det_text),
                    "noncrib_det_length": len(noncrib_det),
                    "ngram_pc": ngram_pc,
                    "word_count": wr.word_count if wr else 0,
                    "longest_word": wr.longest if wr else 0,
                    "word_coverage": wr.coverage if wr else 0.0,
                    "noncrib_det_text": noncrib_det,
                    "ineq_count": len(ineq_pairs),
                })

    candidates.sort(
        key=lambda c: (c["ngram_pc"], c["word_count"]),
        reverse=True,
    )
    return candidates[:TOP_K_PER_CHUNK]


# ── Orchestration ──────────────────────────────────────────────────────

def chunkify(items, n):
    for i in range(0, len(items), n):
        yield items[i:i + n]


def run_campaign(dry_run: bool = False) -> Dict:
    print(f"[TABP v3] Building T enumeration from v1 set...")
    t0 = time.time()
    all_ts = enumerate_all_transpositions()
    enum_time = time.time() - t0
    print(f"[TABP v3] {len(all_ts)} single-layer Ts in {enum_time:.1f}s")
    print(f"[TABP v3] Period range: {PERIOD_RANGE.start}..{PERIOD_RANGE.stop - 1}")

    if dry_run:
        return {"dry_run": True, "total_ts": len(all_ts)}

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    if SURVIVORS_PATH.exists():
        SURVIVORS_PATH.unlink()

    chunks = list(chunkify(all_ts, CHUNK_SIZE))
    print(f"[TABP v3] Dispatching {len(chunks)} chunks to {WORKER_COUNT} workers")

    all_candidates: List[Dict] = []
    t_start = time.time()

    with mp.Pool(WORKER_COUNT, initializer=_init_worker) as pool:
        for chunk_idx, chunk_candidates in enumerate(
            pool.imap_unordered(tabp_extended_period_chunk, chunks)
        ):
            all_candidates.extend(chunk_candidates)
            elapsed = time.time() - t_start
            best = (
                max((c["ngram_pc"] for c in chunk_candidates),
                    default=float("-inf"))
            )
            best_str = (
                f"best_ngram={best:.2f}"
                if chunk_candidates else "-"
            )
            print(
                f"[TABP v3] chunk {chunk_idx + 1}/{len(chunks)} "
                f"({len(chunk_candidates)} cand, {best_str}) "
                f"elapsed={elapsed:.1f}s"
            )

    wall_clock = time.time() - t_start
    print(f"[TABP v3] Campaign complete. Wall clock: {wall_clock:.1f}s")
    print(f"[TABP v3] Total candidates: {len(all_candidates)}")

    all_candidates.sort(
        key=lambda c: (c["ngram_pc"], c["word_count"]),
        reverse=True,
    )

    with open(SURVIVORS_PATH, "w") as f:
        for c in all_candidates[:1000]:
            f.write(json.dumps(c) + "\n")

    top = all_candidates[:25]

    # Per-period breakdown
    per_period = {}
    for c in all_candidates:
        p = c["period"]
        if p not in per_period:
            per_period[p] = {"count": 0, "best_ngram": float("-inf")}
        per_period[p]["count"] += 1
        if c["ngram_pc"] > per_period[p]["best_ngram"]:
            per_period[p]["best_ngram"] = c["ngram_pc"]

    print(f"\n=== PER-PERIOD BREAKDOWN ===")
    for p in sorted(per_period.keys()):
        s = per_period[p]
        print(f"  p={p:>2}: {s['count']:>5} candidates, best_ngram={s['best_ngram']:.3f}")

    print(f"\n=== TOP 10 BY NGRAM_PER_CHAR ===")
    for i, c in enumerate(top[:10]):
        print(
            f"{i+1:2}. {c['label'][:30]:30} {c['variant']:8} "
            f"p={c['period']:2} ngram={c['ngram_pc']:.3f} "
            f"words={c['word_count']:3} len={c['noncrib_det_length']:3}"
        )
        print(f"    {c['noncrib_det_text'][:97]}")

    best_ngram = (
        max((c["ngram_pc"] for c in all_candidates), default=None)
    )

    summary = {
        "campaign_id": "f_tabp_extended_period_v3",
        "total_ts": len(all_ts),
        "period_range": [PERIOD_RANGE.start, PERIOD_RANGE.stop - 1],
        "chunks": len(chunks),
        "workers": WORKER_COUNT,
        "wall_clock_sec": wall_clock,
        "total_candidates": len(all_candidates),
        "best_ngram_pc": best_ngram,
        "per_period_stats": {str(p): per_period[p] for p in sorted(per_period.keys())},
        "top_25_candidates": top,
        "ngram_prefilter": NGRAM_PREFILTER,
        "scope_notes": (
            "TABP v3 extended period: tests periods 27-50 on v1's 6165 "
            "single-layer Ts using determined-positions-only scoring "
            "(no missing-residue enumeration). Fills the gap above v1/v2c "
            "MAX_PERIOD=26. Scoring is on the non-crib subset of positions "
            "whose residue class is covered by crib-derived keys."
        ),
    }

    with open(SUMMARY_PATH, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n[TABP v3] Summary written to {SUMMARY_PATH}")

    return summary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    result = run_campaign(dry_run=args.dry_run)
    if result.get("dry_run"):
        return 0

    best = result.get("best_ngram_pc")
    if best is not None and best >= -4.8:
        print(f"\n⚠ BREAKTHROUGH CANDIDATE: ngram={best:.3f}")
        return 3
    if best is not None and best >= -5.3:
        print(f"\n⚠ INTERESTING: best ngram={best:.3f}")
        return 2
    if result["total_candidates"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
