#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: _infra
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""DRAGNET v4 — Exhaustive Double Columnar + Single Columnar Gap Closure.

Closes two critical gaps from 250+ experiments:

  Phase 1: Double Columnar Exhaustive
    Width pairs: (7,9), (9,7), (8,8), (8,9), (9,8), (9,9)
    Models: DC-A (sub→trans→trans), DC-B (trans→sub→trans)
    Periods: 8, 13 (Bean-compatible, ≥10 constraints each)
    Variants: Vigenère + Beaufort
    Algorithm: Numpy-vectorized constraint propagation with early termination

  Phase 2: Single Columnar Exhaustive w10-12
    Widths 10, 11, 12 — full permutation enumeration
    Models: A (sub→trans), B (trans→sub)
    Periods: 8, 13

  Phase 3: Dictionary Keyword Columnar w13-15
    Keywords from wordlists/english.txt → unique orderings per width
    Widths: 13, 14, 15

Usage:
  PYTHONPATH=src python3 -u scripts/dragnet_v4.py --workers 14
  PYTHONPATH=src python3 -u scripts/dragnet_v4.py --phase 1 --workers 14
  PYTHONPATH=src python3 -u scripts/dragnet_v4.py --phase 2 --workers 14
  PYTHONPATH=src python3 -u scripts/dragnet_v4.py --phase 3 --workers 14
  PYTHONPATH=src python3 -u scripts/dragnet_v4.py --resume
"""
from __future__ import annotations

import argparse
import json
import math
import multiprocessing as mp
import signal
import sqlite3
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from itertools import permutations
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from kryptos.kernel.constants import (
    ALPH, ALPH_IDX, CT, CT_LEN, MOD,
    CRIB_DICT, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
)

# ── Precomputed constants ────────────────────────────────────────────────
CT_INT: List[int] = [ALPH_IDX[c] for c in CT]
CT_NP = np.array(CT_INT, dtype=np.int32)
N: int = CT_LEN
CRIB_POS: List[int] = sorted(CRIB_POSITIONS)
CRIB_PT: Dict[int, int] = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
PERIODS: List[int] = [8, 13]

# ── Paths ────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"
CHECKPOINT_PATH = RESULTS_DIR / "dragnet_v4_checkpoint.json"
DB_PATH = RESULTS_DIR / "dragnet_v4_results.sqlite"
QUADGRAM_PATH = PROJECT_ROOT / "data" / "english_quadgrams.json"
WORDLIST_PATH = PROJECT_ROOT / "wordlists" / "english.txt"

# ── Global shutdown ──────────────────────────────────────────────────────
_shutdown = False


def _signal_handler(signum, frame):
    global _shutdown
    _shutdown = True


# ══════════════════════════════════════════════════════════════════════════
# Quadgram scorer
# ══════════════════════════════════════════════════════════════════════════

class QuadgramScorer:
    __slots__ = ("_lp", "_floor")

    def __init__(self, path: Path):
        with open(path) as f:
            data = json.load(f)
        if "logp" in data:
            data = data["logp"]
        self._lp: Dict[str, float] = data
        self._floor: float = min(data.values())

    def score_per_char(self, text: str) -> float:
        lp = self._lp
        fl = self._floor
        t = text.upper()
        n = len(t) - 3
        if n <= 0:
            return fl
        return sum(lp.get(t[i:i+4], fl) for i in range(n)) / n


# ══════════════════════════════════════════════════════════════════════════
# Helpers
# ══════════════════════════════════════════════════════════════════════════

def columnar_perm(col_order: List[int], width: int, length: int) -> List[int]:
    """Build permutation: plaintext position j → CT position sigma[j]."""
    n_rows = (length + width - 1) // width
    n_long = length % width
    if n_long == 0:
        n_long = width
    sigma = [0] * length
    ct_pos = 0
    for col in col_order:
        col_len = n_rows if col < n_long else n_rows - 1
        for row in range(col_len):
            inter_pos = row * width + col
            if inter_pos < length:
                sigma[inter_pos] = ct_pos
                ct_pos += 1
    return sigma


def build_constraint_pairs(positions, period, residue_fn=None):
    """Build constraint pairs from crib positions."""
    groups = defaultdict(list)
    for j in positions:
        r = residue_fn(j) if residue_fn else (j % period)
        groups[r].append(j)
    pairs = []
    diffs = []
    for r in sorted(groups.keys()):
        g = groups[r]
        if len(g) >= 2:
            for i in range(1, len(g)):
                pairs.append((g[0], g[i]))
                diffs.append((CRIB_PT[g[0]] - CRIB_PT[g[i]]) % MOD)
    n_residues = sum(1 for g in groups.values() if g)
    return pairs, diffs, n_residues


def fast_ic(vals) -> float:
    freq = [0] * 26
    for v in vals:
        freq[v] += 1
    n = len(vals)
    if n < 2:
        return 0.0
    return sum(f * (f - 1) for f in freq) / (n * (n - 1))


def fast_bean(key_vals) -> bool:
    for a, b in BEAN_EQ:
        if a < len(key_vals) and b < len(key_vals):
            if key_vals[a] != key_vals[b]:
                return False
    for a, b in BEAN_INEQ:
        if a < len(key_vals) and b < len(key_vals):
            if key_vals[a] == key_vals[b]:
                return False
    return True


def int_to_text(vals) -> str:
    return "".join(ALPH[v % 26] for v in vals)


def english_bigram_count(text: str) -> int:
    common = frozenset({
        'TH', 'HE', 'IN', 'AN', 'ER', 'ON', 'RE', 'ED', 'ND', 'HA',
        'AT', 'EN', 'ES', 'OF', 'OR', 'NT', 'EA', 'TI', 'TO', 'IT',
    })
    return sum(1 for i in range(len(text) - 1) if text[i:i+2] in common)


def precompute_perms(width: int) -> Tuple[List[List[int]], List[Tuple]]:
    """Precompute all columnar permutations for a given width."""
    perms = []
    orders = []
    for order in permutations(range(width)):
        sigma = columnar_perm(list(order), width, N)
        perms.append(sigma)
        orders.append(order)
    return perms, orders


# ══════════════════════════════════════════════════════════════════════════
# Database
# ══════════════════════════════════════════════════════════════════════════

def init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phase INTEGER NOT NULL,
            phase_name TEXT,
            model TEXT,
            variant TEXT,
            score_cribs INTEGER NOT NULL,
            score_quadgram REAL,
            score_ic REAL,
            bean_pass INTEGER NOT NULL DEFAULT 0,
            english_bigrams INTEGER DEFAULT 0,
            config TEXT,
            plaintext TEXT,
            timestamp REAL NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_score ON candidates(score_cribs DESC)"
    )
    conn.commit()
    conn.close()


def store_candidate(
    db_path: Path, phase: int, phase_name: str, model: str, variant: str,
    cribs: int, qg: Optional[float], ic_val: Optional[float],
    bean: bool, bigrams: int, config: Dict[str, Any], pt: str,
) -> None:
    try:
        conn = sqlite3.connect(str(db_path), timeout=10.0)
        conn.execute(
            "INSERT INTO candidates "
            "(phase, phase_name, model, variant, score_cribs, score_quadgram, "
            "score_ic, bean_pass, english_bigrams, config, plaintext, timestamp) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (phase, phase_name, model, variant, cribs, qg, ic_val,
             int(bean), bigrams, json.dumps(config), pt, time.time()),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════
# Checkpoint
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class Checkpoint:
    phase_done: Dict[str, bool] = field(default_factory=dict)
    phase_tested: Dict[str, int] = field(default_factory=dict)
    phase_best: Dict[str, int] = field(default_factory=dict)
    best_candidates: List[Dict[str, Any]] = field(default_factory=list)
    start_time: float = 0.0

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(asdict(self), f, indent=2)
        tmp.rename(path)

    @classmethod
    def load(cls, path: Path) -> "Checkpoint":
        with open(path) as f:
            d = json.load(f)
        return cls(**d)

    def add_candidate(self, cand: Dict[str, Any]) -> None:
        self.best_candidates.append(cand)
        self.best_candidates.sort(
            key=lambda x: (-x.get("cribs", 0), -(x.get("qg_pc", -99)))
        )
        self.best_candidates = self.best_candidates[:200]


# ══════════════════════════════════════════════════════════════════════════
# Decode + score helpers
# ══════════════════════════════════════════════════════════════════════════

def decode_dca(sigma1, sigma2, period, variant):
    """DC-A: CT = σ₂(σ₁(Vig(PT, key[j%p]))). Recover key + plaintext."""
    sign = -1 if variant == "vig" else 1
    key = [None] * period
    for j in CRIB_POS:
        ct_pos = sigma2[sigma1[j]]
        k_val = (CT_INT[ct_pos] + sign * CRIB_PT[j]) % MOD
        r = j % period
        if key[r] is None:
            key[r] = k_val
    key = [k if k is not None else 0 for k in key]
    inv = [0] * N
    for j in range(N):
        inv[sigma2[sigma1[j]]] = j
    pt = [0] * N
    for i in range(N):
        j = inv[i]
        if variant == "vig":
            pt[j] = (CT_INT[i] - key[j % period]) % MOD
        else:
            pt[j] = (key[j % period] - CT_INT[i]) % MOD
    return key, pt


def decode_dcb(sigma1, sigma2, period, variant):
    """DC-B: CT = σ₂(Vig(σ₁(PT), key[i%p])). Recover key + plaintext."""
    sign = -1 if variant == "vig" else 1
    key = [None] * period
    for j in CRIB_POS:
        ct_pos = sigma2[sigma1[j]]
        k_val = (CT_INT[ct_pos] + sign * CRIB_PT[j]) % MOD
        r = sigma1[j] % period
        if key[r] is None:
            key[r] = k_val
    key = [k if k is not None else 0 for k in key]
    s1_inv = [0] * N
    for j in range(N):
        s1_inv[sigma1[j]] = j
    s2_inv = [0] * N
    for j in range(N):
        s2_inv[sigma2[j]] = j
    pt = [0] * N
    for ct_idx in range(N):
        inter_idx = s2_inv[ct_idx]
        pt_idx = s1_inv[inter_idx]
        if variant == "vig":
            pt[pt_idx] = (CT_INT[ct_idx] - key[inter_idx % period]) % MOD
        else:
            pt[pt_idx] = (key[inter_idx % period] - CT_INT[ct_idx]) % MOD
    return key, pt


def score_hit(key, pt, model, variant, period, order1, order2, w1, w2,
              scorer, db_path, phase):
    """Score a decoded hit and store to DB."""
    pt_str = int_to_text(pt)
    full_key = [key[j % period] for j in range(N)]
    bean = fast_bean(full_key)
    qg_pc = scorer.score_per_char(pt_str)
    ic_val = fast_ic(pt)
    bigrams = english_bigram_count(pt_str)
    config = {
        "model": model, "variant": variant, "period": period,
        "w1": w1, "w2": w2,
        "order1": list(order1), "order2": list(order2),
        "key": int_to_text(key),
    }
    store_candidate(
        db_path, phase, "double_columnar", model, variant,
        24, qg_pc, ic_val, bean, bigrams, config, pt_str,
    )
    return {
        "cribs": 24, "qg_pc": qg_pc, "ic": ic_val, "bean": bean,
        "bigrams": bigrams, "config": config, "pt": pt_str[:80],
    }


# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: Double Columnar — numpy-vectorized workers
# ══════════════════════════════════════════════════════════════════════════

def phase1_worker_dca(args):
    """DC-A worker: numpy-vectorized constraint check over all σ₂."""
    (s1_start, s1_end, perms1_list, orders1_list,
     all_s2_np, orders2_list, w1, w2, db_path_str) = args

    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)
    ct_np = np.array(CT_INT, dtype=np.int32)
    n2 = all_s2_np.shape[0]
    hits = []
    checked = 0
    best_bigrams = 0

    for period in PERIODS:
        cpairs, pt_diffs, _ = build_constraint_pairs(CRIB_POS, period)
        if len(cpairs) < 10:
            continue

        for i1 in range(s1_start, s1_end):
            if _shutdown:
                return {"checked": checked, "hits": hits, "best_bigrams": best_bigrams}
            sigma1 = perms1_list[i1]

            # Vectorized: check all σ₂ at once
            mask = np.ones(n2, dtype=bool)
            for ci, (j1, j2) in enumerate(cpairs):
                ip1 = sigma1[j1]
                ip2 = sigma1[j2]
                # Get CT positions for all remaining σ₂
                ct_pos1 = all_s2_np[mask, ip1]
                ct_pos2 = all_s2_np[mask, ip2]
                ct_diff = (ct_np[ct_pos1] - ct_np[ct_pos2]) % 26
                ok = ct_diff == pt_diffs[ci]
                indices = np.where(mask)[0]
                mask[indices[~ok]] = False
                if not mask.any():
                    break

            checked += n2
            hit_indices = np.where(mask)[0]
            for i2 in hit_indices:
                sigma2 = perms1_list[i2] if w1 == w2 else all_s2_np[i2].tolist()
                # Get the actual perm list (all_s2_np rows)
                sigma2 = all_s2_np[i2].tolist()
                for variant in ("vig", "beau"):
                    key, pt = decode_dca(sigma1, sigma2, period, variant)
                    result = score_hit(
                        key, pt, "DC-A", variant, period,
                        orders1_list[i1], orders2_list[i2], w1, w2,
                        scorer, db_p, 1,
                    )
                    hits.append(result)
                    if result["bigrams"] > best_bigrams:
                        best_bigrams = result["bigrams"]

    return {"checked": checked, "hits": hits, "best_bigrams": best_bigrams}


def phase1_worker_dcb(args):
    """DC-B worker: numpy-vectorized constraint check over all σ₂."""
    (s1_start, s1_end, perms1_list, orders1_list,
     all_s2_np, orders2_list, w1, w2, db_path_str) = args

    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)
    ct_np = np.array(CT_INT, dtype=np.int32)
    n2 = all_s2_np.shape[0]
    hits = []
    checked = 0
    best_bigrams = 0

    for period in PERIODS:
        for i1 in range(s1_start, s1_end):
            if _shutdown:
                return {"checked": checked, "hits": hits, "best_bigrams": best_bigrams}
            sigma1 = perms1_list[i1]

            # DC-B: residue grouping depends on σ₁
            dcb_groups = defaultdict(list)
            for j in CRIB_POS:
                dcb_groups[sigma1[j] % period].append(j)
            cpairs = []
            pt_diffs = []
            for r in range(period):
                g = dcb_groups[r]
                if len(g) >= 2:
                    for k in range(1, len(g)):
                        cpairs.append((g[0], g[k]))
                        pt_diffs.append((CRIB_PT[g[0]] - CRIB_PT[g[k]]) % MOD)
            if len(cpairs) < 10:
                checked += n2
                continue

            mask = np.ones(n2, dtype=bool)
            for ci, (j1, j2) in enumerate(cpairs):
                ip1 = sigma1[j1]
                ip2 = sigma1[j2]
                ct_pos1 = all_s2_np[mask, ip1]
                ct_pos2 = all_s2_np[mask, ip2]
                ct_diff = (ct_np[ct_pos1] - ct_np[ct_pos2]) % 26
                ok = ct_diff == pt_diffs[ci]
                indices = np.where(mask)[0]
                mask[indices[~ok]] = False
                if not mask.any():
                    break

            checked += n2
            hit_indices = np.where(mask)[0]
            for i2 in hit_indices:
                sigma2 = all_s2_np[i2].tolist()
                for variant in ("vig", "beau"):
                    key, pt = decode_dcb(sigma1, sigma2, period, variant)
                    result = score_hit(
                        key, pt, "DC-B", variant, period,
                        orders1_list[i1], orders2_list[i2], w1, w2,
                        scorer, db_p, 1,
                    )
                    hits.append(result)
                    if result["bigrams"] > best_bigrams:
                        best_bigrams = result["bigrams"]

    return {"checked": checked, "hits": hits, "best_bigrams": best_bigrams}


def run_phase1(n_workers: int, checkpoint: Checkpoint) -> Checkpoint:
    """Phase 1: Double Columnar Exhaustive."""
    width_pairs = [(7, 9), (9, 7), (8, 8), (8, 9), (9, 8), (9, 9)]

    print(f"\n{'='*72}")
    print(f"PHASE 1: Double Columnar Exhaustive")
    print(f"{'='*72}")
    print(f"Width pairs: {width_pairs}")
    print(f"Periods: {PERIODS}")
    print(f"Models: DC-A, DC-B | Variants: Vig, Beaufort")
    print(f"Workers: {n_workers}", flush=True)

    # Precompute permutations per width
    perm_cache: Dict[int, Tuple[List, List]] = {}
    for w in sorted(set(w for pair in width_pairs for w in pair)):
        t0 = time.time()
        perms, orders = precompute_perms(w)
        perm_cache[w] = (perms, orders)
        print(f"  Width {w}: {len(perms):,} permutations ({time.time()-t0:.1f}s)",
              flush=True)

    for period in PERIODS:
        cpairs, _, nres = build_constraint_pairs(CRIB_POS, period)
        print(f"  Period {period}: {len(cpairs)} constraints from {nres} residues")

    total_hits = []
    total_checked = 0
    phase_t0 = time.time()

    for w1, w2 in width_pairs:
        if _shutdown:
            break

        tag = f"dc_{w1}x{w2}"
        if checkpoint.phase_done.get(tag):
            print(f"\n  ({w1},{w2}): already done — skipping", flush=True)
            continue

        perms1, orders1 = perm_cache[w1]
        perms2, orders2 = perm_cache[w2]
        n1 = len(perms1)
        n2 = len(perms2)

        # Build numpy array of σ₂ permutations
        all_s2_np = np.array(perms2, dtype=np.int32)
        mem_mb = all_s2_np.nbytes / 1e6

        print(f"\n  ({w1},{w2}): {n1:,} × {n2:,} × {len(PERIODS)} periods "
              f"(σ₂ array: {mem_mb:.0f} MB)", flush=True)

        pair_t0 = time.time()
        pair_hits = []
        pair_checked = 0

        # Chunk σ₁ indices across workers
        chunk_size = max(1, n1 // n_workers)
        chunks = []
        for start in range(0, n1, chunk_size):
            end = min(start + chunk_size, n1)
            chunks.append((start, end))

        for model_name, worker_fn, model_label in [
            ("DC-A", phase1_worker_dca, "DC-A"),
            ("DC-B", phase1_worker_dcb, "DC-B"),
        ]:
            if _shutdown:
                break
            print(f"    {model_label} ...", end="", flush=True)
            mt0 = time.time()

            tasks = [
                (s, e, perms1, orders1, all_s2_np, orders2, w1, w2, str(DB_PATH))
                for s, e in chunks
            ]
            with mp.Pool(n_workers) as pool:
                results = pool.map(worker_fn, tasks)

            m_checked = sum(r["checked"] for r in results)
            m_hits = []
            for r in results:
                m_hits.extend(r["hits"])
            m_best = max((r["best_bigrams"] for r in results), default=0)
            elapsed = time.time() - mt0
            rate = m_checked / elapsed if elapsed > 0 else 0
            print(f" {m_checked:,} checked, {len(m_hits)} hits, "
                  f"best_bg={m_best} ({elapsed:.1f}s, {rate:.0f}/s)", flush=True)

            pair_checked += m_checked
            pair_hits.extend(m_hits)

        pair_elapsed = time.time() - pair_t0
        print(f"    ({w1},{w2}) total: {pair_checked:,} checked, "
              f"{len(pair_hits)} hits, {pair_elapsed:.1f}s", flush=True)

        total_checked += pair_checked
        total_hits.extend(pair_hits)

        checkpoint.phase_done[tag] = True
        checkpoint.phase_tested[tag] = pair_checked
        checkpoint.phase_best[tag] = max(
            (h.get("bigrams", 0) for h in pair_hits), default=0
        )
        for h in pair_hits:
            checkpoint.add_candidate(h)
        checkpoint.save(CHECKPOINT_PATH)

    phase_elapsed = time.time() - phase_t0
    print(f"\n  Phase 1 complete: {total_checked:,} pairs, "
          f"{len(total_hits)} hits, {phase_elapsed:.1f}s ({phase_elapsed/60:.1f}min)")

    if total_hits:
        total_hits.sort(key=lambda h: -h.get("bigrams", 0))
        print(f"  Top hits by English bigrams:")
        for h in total_hits[:10]:
            c = h['config']
            print(f"    {c['model']} {c['variant']} ({c['w1']},{c['w2']}) "
                  f"p={c['period']} bg={h['bigrams']} qg={h['qg_pc']:.2f} "
                  f"PT={h['pt'][:60]}")
    else:
        print(f"  No 24/24 hits across all width pairs. ELIMINATED.")

    checkpoint.phase_done["phase1"] = True
    checkpoint.phase_tested["phase1"] = total_checked
    checkpoint.save(CHECKPOINT_PATH)
    return checkpoint


# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: Single Columnar Exhaustive w10-12
# ══════════════════════════════════════════════════════════════════════════

def phase2_worker(args):
    """Single columnar worker: tests a chunk of orderings."""
    (order_start, order_end, width, model, db_path_str) = args

    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)
    checked = 0
    hits = []
    best_score = 0

    for idx, order in enumerate(permutations(range(width))):
        if idx < order_start:
            continue
        if idx >= order_end:
            break
        if _shutdown:
            break

        sigma = columnar_perm(list(order), width, N)

        for period in PERIODS:
            checked += 1

            if model == "A":
                # Model A: CT = σ(Vig(PT, key[j%p]))
                residue_groups = defaultdict(list)
                for j in CRIB_POS:
                    residue_groups[j % period].append(j)

                fail = False
                for r, group in residue_groups.items():
                    if len(group) < 2:
                        continue
                    ref_val = (CT_INT[sigma[group[0]]] - CRIB_PT[group[0]]) % MOD
                    for j in group[1:]:
                        val = (CT_INT[sigma[j]] - CRIB_PT[j]) % MOD
                        if val != ref_val:
                            fail = True
                            break
                    if fail:
                        break

                if not fail:
                    for variant in ("vig", "beau"):
                        sign = -1 if variant == "vig" else 1
                        key = [None] * period
                        for j in CRIB_POS:
                            k_val = (CT_INT[sigma[j]] + sign * CRIB_PT[j]) % MOD
                            r = j % period
                            if key[r] is None:
                                key[r] = k_val
                        key = [k if k is not None else 0 for k in key]

                        inv_sigma = [0] * N
                        for j in range(N):
                            inv_sigma[sigma[j]] = j
                        pt = [0] * N
                        for i in range(N):
                            j = inv_sigma[i]
                            if variant == "vig":
                                pt[j] = (CT_INT[i] - key[j % period]) % MOD
                            else:
                                pt[j] = (key[j % period] - CT_INT[i]) % MOD

                        pt_str = int_to_text(pt)
                        full_key = [key[j % period] for j in range(N)]
                        bean = fast_bean(full_key)
                        qg_pc = scorer.score_per_char(pt_str)
                        ic_val = fast_ic(pt)
                        bigrams = english_bigram_count(pt_str)

                        config = {
                            "model": "SC-A", "variant": variant,
                            "period": period, "width": width,
                            "order": list(order), "key": int_to_text(key),
                        }
                        store_candidate(
                            db_p, 2, "single_columnar", "SC-A", variant,
                            24, qg_pc, ic_val, bean, bigrams, config, pt_str,
                        )
                        hits.append({
                            "cribs": 24, "qg_pc": qg_pc, "ic": ic_val,
                            "bean": bean, "bigrams": bigrams,
                            "config": config, "pt": pt_str[:80],
                        })
                        if bigrams > best_score:
                            best_score = bigrams

            else:
                # Model B: CT = Vig(σ(PT), key[i%p])
                residue_groups = defaultdict(list)
                for j in CRIB_POS:
                    residue_groups[sigma[j] % period].append(j)

                fail = False
                for r, group in residue_groups.items():
                    if len(group) < 2:
                        continue
                    ref_val = (CT_INT[sigma[group[0]]] - CRIB_PT[group[0]]) % MOD
                    for j in group[1:]:
                        val = (CT_INT[sigma[j]] - CRIB_PT[j]) % MOD
                        if val != ref_val:
                            fail = True
                            break
                    if fail:
                        break

                if not fail:
                    for variant in ("vig", "beau"):
                        sign = -1 if variant == "vig" else 1
                        key = [None] * period
                        for j in CRIB_POS:
                            k_val = (CT_INT[sigma[j]] + sign * CRIB_PT[j]) % MOD
                            r = sigma[j] % period
                            if key[r] is None:
                                key[r] = k_val
                        key = [k if k is not None else 0 for k in key]

                        inter = [0] * N
                        for i in range(N):
                            if variant == "vig":
                                inter[i] = (CT_INT[i] - key[i % period]) % MOD
                            else:
                                inter[i] = (key[i % period] - CT_INT[i]) % MOD
                        inv_sigma = [0] * N
                        for j in range(N):
                            inv_sigma[sigma[j]] = j
                        pt = [0] * N
                        for i in range(N):
                            pt[inv_sigma[i]] = inter[i]

                        pt_str = int_to_text(pt)
                        full_key = [key[i % period] for i in range(N)]
                        bean = fast_bean(full_key)
                        qg_pc = scorer.score_per_char(pt_str)
                        ic_val = fast_ic(pt)
                        bigrams = english_bigram_count(pt_str)

                        config = {
                            "model": "SC-B", "variant": variant,
                            "period": period, "width": width,
                            "order": list(order), "key": int_to_text(key),
                        }
                        store_candidate(
                            db_p, 2, "single_columnar", "SC-B", variant,
                            24, qg_pc, ic_val, bean, bigrams, config, pt_str,
                        )
                        hits.append({
                            "cribs": 24, "qg_pc": qg_pc, "ic": ic_val,
                            "bean": bean, "bigrams": bigrams,
                            "config": config, "pt": pt_str[:80],
                        })
                        if bigrams > best_score:
                            best_score = bigrams

    return {"checked": checked, "hits": hits, "best_score": best_score}


def run_phase2(n_workers: int, checkpoint: Checkpoint) -> Checkpoint:
    """Phase 2: Single Columnar Exhaustive w10-12."""
    print(f"\n{'='*72}")
    print(f"PHASE 2: Single Columnar Exhaustive (widths 10-12)")
    print(f"{'='*72}")
    print(f"Periods: {PERIODS} | Models: SC-A, SC-B | Workers: {n_workers}",
          flush=True)

    phase_t0 = time.time()
    total_checked = 0
    total_hits = []

    for width in [10, 11, 12]:
        tag = f"sc_w{width}"
        if checkpoint.phase_done.get(tag):
            print(f"\n  Width {width}: already done — skipping", flush=True)
            continue

        n_orderings = math.factorial(width)
        print(f"\n  Width {width}: {n_orderings:,} orderings", flush=True)

        for model in ["A", "B"]:
            if _shutdown:
                break
            model_tag = f"sc_w{width}_{model}"
            if checkpoint.phase_done.get(model_tag):
                print(f"    SC-{model}: already done — skipping", flush=True)
                continue

            t0 = time.time()
            chunk_size = max(1, n_orderings // n_workers)
            tasks = []
            for start in range(0, n_orderings, chunk_size):
                end = min(start + chunk_size, n_orderings)
                tasks.append((start, end, width, model, str(DB_PATH)))

            with mp.Pool(n_workers) as pool:
                results = pool.map(phase2_worker, tasks)

            w_checked = sum(r["checked"] for r in results)
            w_hits = []
            for r in results:
                w_hits.extend(r["hits"])
            w_best = max((r["best_score"] for r in results), default=0)
            elapsed = time.time() - t0

            print(f"    SC-{model}: {w_checked:,} checked, {len(w_hits)} hits, "
                  f"best_bg={w_best} ({elapsed:.1f}s)", flush=True)

            total_checked += w_checked
            total_hits.extend(w_hits)

            checkpoint.phase_done[model_tag] = True
            checkpoint.phase_tested[model_tag] = w_checked
            checkpoint.save(CHECKPOINT_PATH)

        checkpoint.phase_done[tag] = True
        checkpoint.save(CHECKPOINT_PATH)

        if _shutdown:
            break

    phase_elapsed = time.time() - phase_t0
    print(f"\n  Phase 2 complete: {total_checked:,} checked, "
          f"{len(total_hits)} hits, {phase_elapsed:.1f}s")

    if total_hits:
        total_hits.sort(key=lambda h: -h.get("bigrams", 0))
        print(f"  Top hits:")
        for h in total_hits[:10]:
            c = h['config']
            print(f"    {c['model']} {c['variant']} w={c['width']} p={c['period']} "
                  f"bg={h['bigrams']} qg={h['qg_pc']:.2f} PT={h['pt'][:60]}")
    else:
        print(f"  No 24/24 hits. ELIMINATED.")

    checkpoint.phase_done["phase2"] = True
    checkpoint.phase_tested["phase2"] = total_checked
    checkpoint.save(CHECKPOINT_PATH)
    return checkpoint


# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: Dictionary Keyword Columnar w13-15
# ══════════════════════════════════════════════════════════════════════════

def keyword_to_order(keyword: str) -> Tuple[int, ...]:
    """Convert keyword to column order. Ties broken left-to-right."""
    indexed = sorted(range(len(keyword)), key=lambda i: keyword[i])
    order = [0] * len(keyword)
    for rank, col in enumerate(indexed):
        order[col] = rank
    return tuple(order)


def load_keyword_orders(width: int) -> List[Tuple[int, ...]]:
    """Load unique column orderings from wordlist."""
    seen = set()
    orders = []
    with open(WORDLIST_PATH) as f:
        for line in f:
            word = line.strip().upper()
            if len(word) != width:
                continue
            if not word.isalpha():
                continue
            order = keyword_to_order(word)
            if order not in seen:
                seen.add(order)
                orders.append(order)
    return orders


def phase3_worker(args):
    """Keyword columnar worker."""
    (orders_batch, width, model, db_path_str) = args

    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)
    checked = 0
    hits = []
    best_score = 0

    for order in orders_batch:
        if _shutdown:
            break
        sigma = columnar_perm(list(order), width, N)

        for period in PERIODS:
            checked += 1

            if model == "A":
                residue_groups = defaultdict(list)
                for j in CRIB_POS:
                    residue_groups[j % period].append(j)
                fail = False
                for r, group in residue_groups.items():
                    if len(group) < 2:
                        continue
                    ref_val = (CT_INT[sigma[group[0]]] - CRIB_PT[group[0]]) % MOD
                    for j in group[1:]:
                        if (CT_INT[sigma[j]] - CRIB_PT[j]) % MOD != ref_val:
                            fail = True
                            break
                    if fail:
                        break
            else:
                residue_groups = defaultdict(list)
                for j in CRIB_POS:
                    residue_groups[sigma[j] % period].append(j)
                fail = False
                for r, group in residue_groups.items():
                    if len(group) < 2:
                        continue
                    ref_val = (CT_INT[sigma[group[0]]] - CRIB_PT[group[0]]) % MOD
                    for j in group[1:]:
                        if (CT_INT[sigma[j]] - CRIB_PT[j]) % MOD != ref_val:
                            fail = True
                            break
                    if fail:
                        break

            if fail:
                continue

            model_label = f"KW-{model}"
            for variant in ("vig", "beau"):
                sign = -1 if variant == "vig" else 1
                key = [None] * period
                for j in CRIB_POS:
                    k_val = (CT_INT[sigma[j]] + sign * CRIB_PT[j]) % MOD
                    r = (j % period) if model == "A" else (sigma[j] % period)
                    if key[r] is None:
                        key[r] = k_val
                key = [k if k is not None else 0 for k in key]

                if model == "A":
                    inv_sigma = [0] * N
                    for j in range(N):
                        inv_sigma[sigma[j]] = j
                    pt = [0] * N
                    for i in range(N):
                        j = inv_sigma[i]
                        if variant == "vig":
                            pt[j] = (CT_INT[i] - key[j % period]) % MOD
                        else:
                            pt[j] = (key[j % period] - CT_INT[i]) % MOD
                else:
                    inter = [0] * N
                    for i in range(N):
                        if variant == "vig":
                            inter[i] = (CT_INT[i] - key[i % period]) % MOD
                        else:
                            inter[i] = (key[i % period] - CT_INT[i]) % MOD
                    inv_sigma = [0] * N
                    for j in range(N):
                        inv_sigma[sigma[j]] = j
                    pt = [0] * N
                    for i in range(N):
                        pt[inv_sigma[i]] = inter[i]

                pt_str = int_to_text(pt)
                full_key = [key[(j if model == "A" else j) % period] for j in range(N)]
                bean = fast_bean(full_key)
                qg_pc = scorer.score_per_char(pt_str)
                ic_val = fast_ic(pt)
                bigrams = english_bigram_count(pt_str)

                config = {
                    "model": model_label, "variant": variant,
                    "period": period, "width": width,
                    "order": list(order), "key": int_to_text(key),
                }
                store_candidate(
                    db_p, 3, "keyword_columnar", model_label, variant,
                    24, qg_pc, ic_val, bean, bigrams, config, pt_str,
                )
                hits.append({
                    "cribs": 24, "qg_pc": qg_pc, "ic": ic_val,
                    "bean": bean, "bigrams": bigrams,
                    "config": config, "pt": pt_str[:80],
                })
                if bigrams > best_score:
                    best_score = bigrams

    return {"checked": checked, "hits": hits, "best_score": best_score}


def run_phase3(n_workers: int, checkpoint: Checkpoint) -> Checkpoint:
    """Phase 3: Dictionary Keyword Columnar w13-15."""
    print(f"\n{'='*72}")
    print(f"PHASE 3: Dictionary Keyword Columnar (widths 13-15)")
    print(f"{'='*72}")
    print(f"Periods: {PERIODS} | Wordlist: {WORDLIST_PATH}", flush=True)

    phase_t0 = time.time()
    total_checked = 0
    total_hits = []

    for width in [13, 14, 15]:
        tag = f"kw_w{width}"
        if checkpoint.phase_done.get(tag):
            print(f"\n  Width {width}: already done — skipping", flush=True)
            continue

        orders = load_keyword_orders(width)
        print(f"\n  Width {width}: {len(orders):,} unique orderings", flush=True)

        if not orders:
            checkpoint.phase_done[tag] = True
            checkpoint.save(CHECKPOINT_PATH)
            continue

        for model in ["A", "B"]:
            if _shutdown:
                break
            model_tag = f"kw_w{width}_{model}"
            if checkpoint.phase_done.get(model_tag):
                continue

            t0 = time.time()
            batch_size = max(1, len(orders) // n_workers)
            tasks = [
                (orders[i:i+batch_size], width, model, str(DB_PATH))
                for i in range(0, len(orders), batch_size)
            ]

            with mp.Pool(n_workers) as pool:
                results = pool.map(phase3_worker, tasks)

            w_checked = sum(r["checked"] for r in results)
            w_hits = []
            for r in results:
                w_hits.extend(r["hits"])
            w_best = max((r["best_score"] for r in results), default=0)
            elapsed = time.time() - t0

            print(f"    KW-{model}: {w_checked:,} checked, {len(w_hits)} hits, "
                  f"best_bg={w_best} ({elapsed:.1f}s)", flush=True)

            total_checked += w_checked
            total_hits.extend(w_hits)
            checkpoint.phase_done[model_tag] = True
            checkpoint.phase_tested[model_tag] = w_checked
            checkpoint.save(CHECKPOINT_PATH)

        checkpoint.phase_done[tag] = True
        checkpoint.save(CHECKPOINT_PATH)
        if _shutdown:
            break

    phase_elapsed = time.time() - phase_t0
    print(f"\n  Phase 3 complete: {total_checked:,} checked, "
          f"{len(total_hits)} hits, {phase_elapsed:.1f}s")

    if total_hits:
        total_hits.sort(key=lambda h: -h.get("bigrams", 0))
        print(f"  Top hits:")
        for h in total_hits[:10]:
            c = h['config']
            print(f"    {c['model']} {c['variant']} w={c['width']} p={c['period']} "
                  f"bg={h['bigrams']} qg={h['qg_pc']:.2f} PT={h['pt'][:60]}")
    else:
        print(f"  No 24/24 hits. ELIMINATED.")

    checkpoint.phase_done["phase3"] = True
    checkpoint.phase_tested["phase3"] = total_checked
    checkpoint.save(CHECKPOINT_PATH)
    return checkpoint


# ══════════════════════════════════════════════════════════════════════════
# Verification
# ══════════════════════════════════════════════════════════════════════════

def verify():
    """Run quick sanity checks."""
    print("Running verification checks...", flush=True)

    for w in range(7, 13):
        sigma = columnar_perm(list(range(w)), w, N)
        assert sorted(sigma) == list(range(N)), f"Width {w}: invalid permutation"
    print("  columnar_perm: valid permutations at w7-12 ✓")

    for period in PERIODS:
        cpairs, _, nres = build_constraint_pairs(CRIB_POS, period)
        print(f"  Period {period}: {len(cpairs)} constraints, {nres} residues")
        assert len(cpairs) >= 10, f"Period {period}: too few constraints"
    print("  Constraint counts: ✓")

    scorer = QuadgramScorer(QUADGRAM_PATH)
    eng = scorer.score_per_char("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG")
    rnd = scorer.score_per_char("XQZJVBKWPFLMHGDCYNRSTAOIEU" * 4)
    assert eng > rnd
    print(f"  Quadgram scorer: OK (eng={eng:.2f}, rnd={rnd:.2f}) ✓")

    print("All checks passed.\n", flush=True)


# ══════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════

def print_summary(checkpoint: Checkpoint):
    print(f"\n{'='*72}")
    print(f"DRAGNET v4 — FINAL SUMMARY")
    print(f"{'='*72}")

    total_tested = sum(checkpoint.phase_tested.values())
    print(f"Total configs tested: {total_tested:,}")

    for key in sorted(checkpoint.phase_done.keys()):
        done = checkpoint.phase_done[key]
        tested = checkpoint.phase_tested.get(key, 0)
        best = checkpoint.phase_best.get(key, 0)
        if tested > 0:
            print(f"  {key}: {'DONE' if done else 'incomplete'} "
                  f"({tested:,} tested, best_bg={best})")

    if checkpoint.best_candidates:
        print(f"\nTop {min(20, len(checkpoint.best_candidates))} candidates:")
        for i, c in enumerate(checkpoint.best_candidates[:20]):
            cfg = c.get("config", {})
            print(f"  {i+1}. cribs={c.get('cribs',0)} bg={c.get('bigrams',0)} "
                  f"qg={c.get('qg_pc',-99):.2f} bean={c.get('bean',False)} "
                  f"{cfg.get('model','?')} {cfg.get('variant','?')}")
            print(f"     PT: {c.get('pt','')[:70]}")
    else:
        print(f"\nNo candidates found above threshold.")
        print(f"VERDICT: All tested configurations ELIMINATED (NOISE).")

    print(f"\nArtifact: {DB_PATH}")
    print(f"Checkpoint: {CHECKPOINT_PATH}")
    print(f"Repro: PYTHONPATH=src python3 -u scripts/dragnet_v4.py --workers 14")


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="DRAGNET v4")
    parser.add_argument("--phase", default="all", choices=["1", "2", "3", "all"])
    parser.add_argument("--workers", type=int, default=14)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    print("=" * 72)
    print("DRAGNET v4 — Double Columnar + Single Columnar Gap Closure")
    print("=" * 72)
    print(f"Phase: {args.phase} | Workers: {args.workers}")
    print(f"DB: {DB_PATH}")
    print(f"Checkpoint: {CHECKPOINT_PATH}")
    print()

    verify()
    init_db(DB_PATH)

    if args.resume and CHECKPOINT_PATH.exists():
        checkpoint = Checkpoint.load(CHECKPOINT_PATH)
        n_done = sum(1 for v in checkpoint.phase_done.values() if v)
        print(f"Resumed from checkpoint: {n_done} steps done")
    else:
        checkpoint = Checkpoint(start_time=time.time())

    if checkpoint.start_time == 0:
        checkpoint.start_time = time.time()

    phase_map = {"1": [1], "2": [2], "3": [3], "all": [1, 2, 3]}
    phases = phase_map[args.phase]

    try:
        for p in phases:
            if _shutdown:
                break
            if p == 1:
                checkpoint = run_phase1(args.workers, checkpoint)
            elif p == 2:
                checkpoint = run_phase2(args.workers, checkpoint)
            elif p == 3:
                checkpoint = run_phase3(args.workers, checkpoint)
    except Exception as e:
        print(f"\nFATAL ERROR: {e}", flush=True)
        import traceback
        traceback.print_exc()
    finally:
        checkpoint.save(CHECKPOINT_PATH)
        print_summary(checkpoint)

    elapsed = time.time() - checkpoint.start_time
    print(f"\nTotal wall time: {elapsed:.1f}s ({elapsed/60:.1f}min)")


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()
