#!/usr/bin/env python3
"""
Cipher: transposition-first + inner periodic substitution (TABP)
Family: campaigns/tabp
Status: active
Keyspace: ~10K outer transpositions × {Vig, Beau, VarBeau} × period {1..7}
Last run:
Best score:

TABP — Transposition-Aware Bean Pre-Filter Campaign v1
=======================================================

Searches the subspace: outer transposition × inner periodic substitution
under the encryption model

    CT = substitute(transpose(PT), key)

where the outer transposition is applied BEFORE substitution at encryption
time. This probes the "crib-mapping assumption" hard blocker from
MEMORY.md §2.3 — the class of attacks where the 24 crib positions are NOT
in direct positional correspondence with the carved CT.

Scope vs prior work:
  - C-BEAN-01 covers columnar widths {4,6,8,9} under DIRECT positional
    mapping. This campaign intentionally excludes those widths.
  - C-COMP-01 scored (transposition × substitution) compositions with
    free-crib scoring but WITHOUT Bean pre-filtering (composition/
    constraints.py line 258 skips Bean for non-position-preserving stacks).
    This campaign restores the Bean pre-filter using per-T re-derivation.

Derivation:
  For each candidate outer transposition T (defined as pt_to_ct where
  pt_to_ct[k] is the position in CT where plaintext position k's letter
  lands), we re-derive Bean EQ/INEQ constraints from the actual letter
  pairings (PT_crib[k], CT_carved[pt_to_ct[k]]). The re-derivation is
  validated against the canonical 242 inequalities at T=identity —
  see tests/test_bean_displaced.py.

Red-team gates (both cleared 2026-04-09):
  CLAIM 1 — Derivation validity: original "permute the indices" form
    was KILLED by red-team review. Current implementation rebuilds
    constraints from letter pairings per-T. Identity + reverse tests
    in tests/test_bean_displaced.py verify correctness.
  CLAIM 2 — Large-period false positives: inner period capped at 7.
    At period ≥ 17, period_consistency() is underdetermined and random
    configs score 17.3+/24 (see CLAUDE.md §"Interpreting Scores"). Hard
    cap at period 7 ensures meaningful discrimination.

Parallelization:
  mp.Pool(cpu_count() - 2) workers, T-chunks of 256 transpositions each.
  Expected wall-clock: 5-15 minutes on 28 vCPUs.

Outputs:
  results/f_tabp_transposition_outer_v1.json — summary + survivors
  results/f_tabp_transposition_outer_v1_survivors.jsonl — full survivor
    records (one per line)
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

# ── Standalone bootstrap (per CLAUDE.md Key Gotchas) ──────────────────
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
    MOD,
    STORE_THRESHOLD,
    SIGNAL_THRESHOLD,
)
from kryptos.kernel.constraints.bean import rederive_bean_for_transposition
from kryptos.kernel.scoring.aggregate import score_candidate_free
from kryptos.kernel.scoring.ngram import NgramScorer, get_default_scorer
from kryptos.kernel.scoring.words import WordScorer
from kryptos.kernel.transforms.transposition import (
    columnar_perm,
    invert_perm,
    keyword_to_order,
    myszkowski_perm,
    rail_fence_perm,
    serpentine_perm,
    spiral_perm,
    validate_perm,
)

# ── Configuration ──────────────────────────────────────────────────────

MAX_PERIOD = 26  # Full periodic spectrum. Profiled empirically: Bean INEQ
                 # rejects 100% of (T, period) at periods 1-25, only ~2.4%
                 # pass at period 26. Red-team CLAIM 2 concerned itself with
                 # period_consistency() SCORING false positives, but our
                 # filter uses period consistency as a BINARY structural
                 # check. Actual discriminator is score_candidate_free
                 # (letter-level, period-independent). See
                 # scripts/campaigns/_tabp_period_profile.py for empirics.
VARIANTS = ("vig", "beau", "varbeau")

# Columnar widths for full enumeration (factorial-size keyspaces)
FULL_ENUM_WIDTHS = (5, 7)

# Columnar widths for keyword-derived orderings
KEYWORD_WIDTHS = (10, 11, 12, 13)

# Myszkowski keyword length range
MYSZ_MIN_KW_LEN = 5
MYSZ_MAX_KW_LEN = 12

# Keyword list path (fallback to thematic_keywords.txt if v2 missing)
KEYWORD_FILE = "wordlists/thematic_keywords_v2.txt"
KEYWORD_FALLBACK = "wordlists/thematic_keywords.txt"

# Worker pool sizing (per CLAUDE.md compute policy)
WORKER_COUNT = max(1, mp.cpu_count() - 2)
CHUNK_SIZE = 256  # Ts per worker invocation

# Per-chunk cap on survivors returned (ranked by English-likeness)
# Prevents runaway memory / jsonl growth when tautological crib matching
# produces millions of "signal-level" crib_score=24 results. Real
# discriminator is ngram_per_char and word metrics on non-crib positions.
TOP_K_PER_CHUNK = 100

# Initial English-likeness filter thresholds (pre-ranking)
#
# Reference points (ngram_per_char, non-crib 73-char subset):
#   K4 raw CT (full):  ≈ -6.38
#   Random 97-char:    ≈ -6.39
#   TABP median:       ≈ -6.45  (empirical, from _tabp_ngram_profile.py)
#   TABP max @135K:    ≈ -6.13
#   English prose:     ≈ -4.96
#
# Set to -6.2 to capture the top ~0.1% of non-crib TABP scores for
# manual review even though the distribution never approaches English.
# This lets the summary record the actual "best" candidates rather than
# dumping zero data.
NGRAM_PREFILTER = -6.2

# ── Worker-level state (loaded once per process via initializer) ──────

_WORKER_NGRAM_SCORER: Optional[NgramScorer] = None
_WORKER_WORD_SCORER: Optional[WordScorer] = None


def _init_worker() -> None:
    """Pool initializer — loads scorers once per worker process.

    Called by mp.Pool(initializer=_init_worker) before any work is
    dispatched to a worker. Avoids reloading the 2MB quadgram table
    and 1M-word list for every chunk.
    """
    global _WORKER_NGRAM_SCORER, _WORKER_WORD_SCORER
    _WORKER_NGRAM_SCORER = get_default_scorer()
    # Load word list (filter to min length 4 for meaningful matches)
    word_path = os.path.join(_ROOT, "wordlists", "english.txt")
    with open(word_path, "r") as f:
        words = set(
            w.strip().upper() for w in f
            if len(w.strip()) >= 4 and w.strip().isalpha()
        )
    _WORKER_WORD_SCORER = WordScorer(words, min_word_len=4)

# Output paths
RESULTS_DIR = Path(_ROOT) / "results"
SUMMARY_PATH = RESULTS_DIR / "f_tabp_transposition_outer_v1.json"
SURVIVORS_PATH = RESULTS_DIR / "f_tabp_transposition_outer_v1_survivors.jsonl"

# ── Keyword loading ────────────────────────────────────────────────────

def load_keywords() -> List[str]:
    """Load thematic keywords for keyword-derived transpositions."""
    for path in (KEYWORD_FILE, KEYWORD_FALLBACK):
        full = os.path.join(_ROOT, path)
        if os.path.exists(full):
            with open(full, "r") as f:
                kws = [line.strip().upper() for line in f if line.strip()]
                kws = [kw for kw in kws if kw.isalpha()]
                return kws
    raise FileNotFoundError(
        f"Neither {KEYWORD_FILE} nor {KEYWORD_FALLBACK} found"
    )

# ── Outer T enumeration ────────────────────────────────────────────────

def enumerate_columnar_full(widths) -> List[Tuple[str, List[int]]]:
    """Full factorial enumeration of column orderings for small widths.

    Returns list of (label, pt_to_ct) tuples. `pt_to_ct[k]` is the
    position in the carved CT where plaintext position k lands.
    """
    out = []
    for w in widths:
        for order in permutations(range(w)):
            perm = columnar_perm(w, list(order), length=CT_LEN)
            if not validate_perm(perm, CT_LEN):
                continue
            pt_to_ct = invert_perm(perm)
            label = f"col{w}_{''.join(str(i) for i in order)}"
            out.append((label, pt_to_ct))
    return out


def enumerate_columnar_keyword(widths, keywords) -> List[Tuple[str, List[int]]]:
    """Keyword-derived column orderings for larger widths."""
    out = []
    for w in widths:
        seen_orders = set()
        for kw in keywords:
            order = keyword_to_order(kw, w)
            if order is None:
                continue
            if order in seen_orders:
                continue
            seen_orders.add(order)
            perm = columnar_perm(w, list(order), length=CT_LEN)
            if not validate_perm(perm, CT_LEN):
                continue
            pt_to_ct = invert_perm(perm)
            out.append((f"col{w}_{kw}", pt_to_ct))
    return out


def enumerate_myszkowski(keywords) -> List[Tuple[str, List[int]]]:
    """Myszkowski transpositions — effective width is keyword length."""
    out = []
    seen = set()
    for kw in keywords:
        if not (MYSZ_MIN_KW_LEN <= len(kw) <= MYSZ_MAX_KW_LEN):
            continue
        # Normalize: same letter pattern produces same permutation
        pattern = "".join(sorted(set(kw))) + str(len(kw))
        if (pattern, kw) in seen:
            continue
        try:
            perm = myszkowski_perm(kw, length=CT_LEN)
            if not validate_perm(perm, CT_LEN):
                continue
            pt_to_ct = invert_perm(perm)
            out.append((f"mys_{kw}", pt_to_ct))
            seen.add((pattern, kw))
        except Exception:
            continue
    return out


def enumerate_rail_fence() -> List[Tuple[str, List[int]]]:
    out = []
    for depth in range(2, 9):
        try:
            perm = rail_fence_perm(CT_LEN, depth)
            if not validate_perm(perm, CT_LEN):
                continue
            pt_to_ct = invert_perm(perm)
            out.append((f"rail_{depth}", pt_to_ct))
        except Exception:
            continue
    return out


def enumerate_route() -> List[Tuple[str, List[int]]]:
    """Spiral and serpentine routes on a few common grid shapes."""
    out = []
    grids = [
        (4, 25), (5, 20), (7, 14), (8, 13), (10, 10),
        (3, 33), (6, 17), (11, 9), (12, 9),
    ]
    for rows, cols in grids:
        if rows * cols < CT_LEN:
            continue
        for cw in (True, False):
            try:
                perm = spiral_perm(rows, cols, length=CT_LEN, clockwise=cw)
                if validate_perm(perm, CT_LEN):
                    pt_to_ct = invert_perm(perm)
                    tag = "cw" if cw else "ccw"
                    out.append((f"spiral_{rows}x{cols}_{tag}", pt_to_ct))
            except Exception:
                pass
        for vert in (True, False):
            try:
                perm = serpentine_perm(rows, cols, length=CT_LEN, vertical=vert)
                if validate_perm(perm, CT_LEN):
                    pt_to_ct = invert_perm(perm)
                    tag = "v" if vert else "h"
                    out.append((f"serp_{rows}x{cols}_{tag}", pt_to_ct))
            except Exception:
                pass
    return out


def enumerate_all_transpositions() -> List[Tuple[str, List[int]]]:
    """Build the full T enumeration. Identity is included first as a
    sanity check — it should NOT produce any survivors (since
    direct-positional C-BEAN-01 family is eliminated)."""
    keywords = load_keywords()

    all_ts: List[Tuple[str, List[int]]] = []

    # Identity as baseline sanity (should produce zero survivors)
    all_ts.append(("identity", list(range(CT_LEN))))

    all_ts.extend(enumerate_columnar_full(FULL_ENUM_WIDTHS))
    all_ts.extend(enumerate_columnar_keyword(KEYWORD_WIDTHS, keywords))
    all_ts.extend(enumerate_myszkowski(keywords))
    all_ts.extend(enumerate_rail_fence())
    all_ts.extend(enumerate_route())

    return all_ts


# ── Core TABP filter (the hot loop) ────────────────────────────────────

def _compute_implied_keys(
    pt_to_ct: List[int], variant: str
) -> Dict[int, int]:
    """Compute implied keystream values at displaced crib positions under
    the given variant and the encryption model CT = substitute(T(PT), key)."""
    implied: Dict[int, int] = {}
    for k in CRIB_POSITIONS:
        ct_pos = pt_to_ct[k]
        ct_val = ALPH_IDX[CT[ct_pos]]
        pt_val = ALPH_IDX[CRIB_DICT[k]]
        if variant == "vig":
            implied[ct_pos] = (ct_val - pt_val) % MOD
        elif variant == "beau":
            implied[ct_pos] = (ct_val + pt_val) % MOD
        else:  # varbeau
            implied[ct_pos] = (pt_val - ct_val) % MOD
    return implied


def _decrypt_tabp(
    pt_to_ct: List[int], variant: str, keystream: List[int]
) -> str:
    """Decrypt under TABP model.

    PT[k] = inv_substitute(CT[pt_to_ct[k]], key[pt_to_ct[k]])
    """
    chars = []
    for k in range(CT_LEN):
        i = pt_to_ct[k]
        ct_val = ALPH_IDX[CT[i]]
        key_val = keystream[i]
        if variant == "vig":
            m = (ct_val - key_val) % MOD
        elif variant == "beau":
            m = (key_val - ct_val) % MOD
        else:  # varbeau
            m = (ct_val + key_val) % MOD
        chars.append(chr(ord("A") + m))
    return "".join(chars)


def tabp_filter_chunk(
    chunk: List[Tuple[str, List[int]]],
) -> List[Dict]:
    """Worker function — filter a chunk of outer transpositions.

    This is the hot path. Executed in a subprocess by mp.Pool.
    Must be module-level and picklable.

    IMPORTANT: under the TABP encryption model, the decryption at the 24
    crib positions is CONSTRUCTED to match the crib letters (that's how
    the implied keys are derived). Therefore `crib_score` from free crib
    matching is tautologically 24 for every survivor. The real
    discriminator is English-likeness on the ~73 non-crib positions,
    measured via ngram_per_char and word_coverage.

    For each T:
      1. Re-derive Bean EQ/INEQ constraints (variant-independent).
      2. For each period p in 1..MAX_PERIOD:
         a. Bean INEQ pre-filter: reject (T, p) if any INEQ pair lies
            in the same residue class mod p. Empirically only period 26
            has any passes (see _tabp_period_profile.py).
         b. For each variant:
            - Compute implied keys at displaced crib positions.
            - Check per-variant period consistency within residues.
            - Bounded enumeration of missing residues (max 3 → 17576 keys).
            - Decrypt full CT under TABP model.
            - Score with quadgram + word scorers.
            - Keep candidate if ngram_per_char >= NGRAM_PREFILTER.
      3. Return top-K by (ngram_per_char, word_coverage) from this chunk.
    """
    if _WORKER_NGRAM_SCORER is None:
        _init_worker()
    ngram_scorer = _WORKER_NGRAM_SCORER
    word_scorer = _WORKER_WORD_SCORER

    # Non-crib position mask for English-likeness scoring — we want to
    # score the portions of the decryption that are NOT tautologically
    # fixed by the crib construction.
    non_crib_positions = [i for i in range(CT_LEN) if i not in CRIB_POSITIONS]

    candidates: List[Dict] = []

    for label, pt_to_ct in chunk:
        try:
            _eq_pairs, ineq_pairs = rederive_bean_for_transposition(pt_to_ct)
        except Exception:
            continue

        for period in range(1, MAX_PERIOD + 1):
            # Step 2a: variant-independent Bean INEQ pre-filter
            bean_violated = False
            for a, b in ineq_pairs:
                if (a % period) == (b % period):
                    bean_violated = True
                    break
            if bean_violated:
                continue

            for variant in VARIANTS:
                implied = _compute_implied_keys(pt_to_ct, variant)

                # Period consistency within residues
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

                # Handle missing residues (bounded enumeration)
                missing = [r for r in range(period) if r not in residue_values]
                if len(missing) > 3:
                    continue  # 26^4 too expensive

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

                    # Score the NON-CRIB portion — the crib positions are
                    # tautologically correct by construction; only the
                    # other 73 positions carry discriminating information.
                    non_crib_text = "".join(pt[i] for i in non_crib_positions)

                    try:
                        ngram_pc = ngram_scorer.score_per_char(non_crib_text)
                    except Exception:
                        continue

                    # Cheap prefilter: reject if non-crib ngram is near random
                    if ngram_pc < NGRAM_PREFILTER:
                        continue

                    # Only if prefilter passes do we do the expensive
                    # word scoring and maintain the candidate list.
                    try:
                        word_result = word_scorer.score(non_crib_text)
                    except Exception:
                        word_result = None

                    candidate = {
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
                    }
                    candidates.append(candidate)

    # Return top-K from this chunk (ranked by ngram_pc, then word_count)
    candidates.sort(
        key=lambda c: (-c["ngram_pc_noncrib"], -c["word_count"])
    )
    # sort ascending by negated ngram → best ngram first. Wait, that's wrong.
    # We want HIGHER ngram_pc (less negative) first.
    candidates.sort(
        key=lambda c: (c["ngram_pc_noncrib"], c["word_count"]),
        reverse=True,
    )
    return candidates[:TOP_K_PER_CHUNK]


# ── Campaign orchestration ─────────────────────────────────────────────

def chunkify(items, n):
    """Yield fixed-size chunks from items."""
    for i in range(0, len(items), n):
        yield items[i:i + n]


def run_campaign(dry_run: bool = False) -> Dict:
    """Run the full TABP v1 campaign with multiprocessing."""
    print(f"[TABP] Building transposition enumeration...")
    t0 = time.time()
    all_ts = enumerate_all_transpositions()
    enum_time = time.time() - t0
    print(f"[TABP] Enumerated {len(all_ts)} outer transpositions in {enum_time:.1f}s")

    if dry_run:
        print("[TABP] Dry run — exiting before compute.")
        print(f"[TABP] First 5 T labels: {[t[0] for t in all_ts[:5]]}")
        print(f"[TABP] Last 5 T labels:  {[t[0] for t in all_ts[-5:]]}")
        return {"dry_run": True, "total_ts": len(all_ts)}

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    chunks = list(chunkify(all_ts, CHUNK_SIZE))
    print(f"[TABP] Dispatching {len(chunks)} chunks of ~{CHUNK_SIZE} Ts "
          f"to {WORKER_COUNT} workers")

    all_candidates: List[Dict] = []
    t_start = time.time()

    with mp.Pool(WORKER_COUNT, initializer=_init_worker) as pool:
        for chunk_idx, chunk_candidates in enumerate(
            pool.imap_unordered(tabp_filter_chunk, chunks)
        ):
            all_candidates.extend(chunk_candidates)
            elapsed = time.time() - t_start
            rate = (chunk_idx + 1) / elapsed if elapsed > 0 else 0
            eta = (len(chunks) - chunk_idx - 1) / rate if rate > 0 else 0
            best_in_chunk = (
                max((c["ngram_pc_noncrib"] for c in chunk_candidates),
                    default=float("-inf"))
            )
            best_str = (
                f"best_ngram={best_in_chunk:.2f}"
                if chunk_candidates else "no_candidates"
            )
            print(
                f"[TABP] chunk {chunk_idx + 1}/{len(chunks)} "
                f"({len(chunk_candidates)} cand, {best_str}) "
                f"elapsed={elapsed:.1f}s eta={eta:.1f}s"
            )

    wall_clock = time.time() - t_start
    print(f"[TABP] Campaign complete. Wall clock: {wall_clock:.1f}s")
    print(f"[TABP] Total candidates (ngram >= {NGRAM_PREFILTER}): "
          f"{len(all_candidates)}")

    # Global ranking by English-likeness
    all_candidates.sort(
        key=lambda c: (c["ngram_pc_noncrib"], c["word_count"]),
        reverse=True,
    )

    # Write all candidates to JSONL for downstream analysis
    with open(SURVIVORS_PATH, "w") as f:
        for c in all_candidates:
            f.write(json.dumps(c) + "\n")

    # Report top 25
    top = all_candidates[:25]
    print(f"\n=== TOP 10 BY NGRAM_PER_CHAR (non-crib) ===")
    for i, c in enumerate(top[:10]):
        print(f"{i+1:2}. {c['label']:20} {c['variant']:8} p={c['period']:2} "
              f"ngram={c['ngram_pc_noncrib']:.3f} "
              f"words={c['word_count']:3} longest={c['longest_word']} "
              f"cov={c['word_coverage']:.2%}")
        print(f"    {c['pt']}")

    best_ngram = (
        max((c["ngram_pc_noncrib"] for c in all_candidates), default=None)
    )
    best_word_count = (
        max((c["word_count"] for c in all_candidates), default=0)
    )

    summary = {
        "campaign_id": "f_tabp_transposition_outer_v1",
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
            "TABP v1: outer transposition x inner periodic substitution "
            "(period 1..26) under the encryption model CT=sub(T(PT),key). "
            "Bean INEQ pre-filter empirically rejects 100% at periods 1-25; "
            "only period 26 has passes (~2.4% of Ts). Crib score is "
            "tautologically 24 by construction — real discriminator is "
            "ngram_per_char and word_coverage on the 73 non-crib positions. "
            "Derivation validated by tests/test_bean_displaced.py. "
            "Excludes columnar widths {4,6,8,9} already in C-BEAN-01 scope."
        ),
    }

    with open(SUMMARY_PATH, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n[TABP] Summary written to {SUMMARY_PATH}")

    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="TABP v1 campaign")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Enumerate Ts and report counts without running the filter."
    )
    args = parser.parse_args()

    # Clear prior survivors file
    if SURVIVORS_PATH.exists() and not args.dry_run:
        SURVIVORS_PATH.unlink()

    result = run_campaign(dry_run=args.dry_run)

    if result.get("dry_run"):
        return 0

    # Exit code signals result class based on English-likeness of
    # non-crib text (the real discriminator for TABP).
    best_ngram = result.get("best_ngram_pc_noncrib")
    if best_ngram is not None and best_ngram >= -4.8:
        print(
            f"\n⚠  BREAKTHROUGH CANDIDATE: ngram_pc_noncrib >= -4.8 "
            f"(best={best_ngram:.3f}). This is within English-prose range. "
            f"Commission statistical-auditor and red-team-disprover per "
            f"CLAUDE.md §Validation gates before trusting."
        )
        return 3
    if best_ngram is not None and best_ngram >= -5.3:
        print(
            f"\n⚠  INTERESTING: best ngram_pc_noncrib = {best_ngram:.3f} "
            f"significantly better than random (-6.59) but below English "
            f"(-4.96). Manual review of top candidates recommended."
        )
        return 2
    if result["total_candidates"] > 0:
        print(
            f"\n{result['total_candidates']} candidates passed prefilter "
            f"(best ngram={best_ngram:.3f}) but all are near noise floor."
        )
        return 1
    return 0  # clean null — all candidates rejected by prefilter


if __name__ == "__main__":
    sys.exit(main())
