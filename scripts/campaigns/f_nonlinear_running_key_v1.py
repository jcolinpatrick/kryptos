#!/usr/bin/env python3 -u
"""
Cipher:   running_key (non-linear readout)
Family:   campaigns
Status:   active
Keyspace: ~60K texts × 115 transforms × 6 cipher modes ≈ 41.6M configs
Last run: never
Best score: N/A

NON-LINEAR RUNNING KEY SWEEP — Overnight Campaign v1

PURPOSE: Test whether a known source text, read in a NON-LINEAR order
(reversed, grid-column, skip-N, boustrophedon), serves as the running
key for K4 under Vigenere/Beaufort/VarBeaufort with AZ or KA alphabets.

WHAT'S NEW: Prior running-key campaigns scanned ALL source texts LINEARLY.
K123 texts were tested with some non-linear transforms, but external corpus
texts (Kahn, Carter, 60K Gutenberg) were LINEAR ONLY. This campaign fills
that gap with 115 deterministic transforms per source text.

TRANSFORMS:
  A. Reversed: entire source text reversed
  B. Grid-column: write into grid of width W, read columns top-to-bottom
     Widths 5-40 (36 widths)
  C. Grid-column reversed: same but columns read bottom-to-top (36 widths)
  D. Boustrophedon: write into grid, alternate row direction, read columns
     Widths 5-40 (36 widths)
  E. Skip-N: read every Nth character (N=2,3,5,7,11,13)

MODEL: For CT97 (raw ciphertext) and 6 cipher modes:
  Vigenere AZ:    K[i] = (CT_AZ[i] - PT_AZ[i]) mod 26
  Beaufort AZ:    K[i] = (CT_AZ[i] + PT_AZ[i]) mod 26
  VarBeaufort AZ: K[i] = (PT_AZ[i] - CT_AZ[i]) mod 26
  Vigenere KA:    K[i] = (CT_KA[i] - PT_KA[i]) mod 26
  Beaufort KA:    K[i] = (CT_KA[i] + PT_KA[i]) mod 26
  VarBeaufort KA: K[i] = (PT_KA[i] - CT_KA[i]) mod 26

At the 24 crib positions, the required key values are KNOWN for each mode.
We check whether the transformed source text has these exact values at the
right positions for any sliding window offset.

OPTIMIZATION: Numpy-vectorized pair-check with early exit.
  - Pick 2 crib positions as "pair filter"
  - Vectorize check across all offsets: O(L) numpy ops
  - P(pair match) = 1/676 → ~0.15% of offsets survive to full check
  - Full check on survivors: 22 more positions

PARALLELIZATION: 26 workers, each processes one source file at a time.
Files distributed via multiprocessing.Pool.imap_unordered.

CHECKPOINTING: SQLite WAL database tracks completed source files.
Resumable: on restart, skips already-completed files.

Usage:
  # Dry run (3 texts, no writes):
  PYTHONPATH=src python3 -u scripts/campaigns/f_nonlinear_running_key_v1.py --dry-run

  # Benchmark (100 texts):
  PYTHONPATH=src python3 -u scripts/campaigns/f_nonlinear_running_key_v1.py --benchmark

  # Full overnight run:
  PYTHONPATH=src python3 -u scripts/campaigns/f_nonlinear_running_key_v1.py

  # Morning report:
  PYTHONPATH=src python3 -u scripts/campaigns/f_nonlinear_running_key_v1.py --report

  # Resume interrupted run:
  PYTHONPATH=src python3 -u scripts/campaigns/f_nonlinear_running_key_v1.py --resume
"""

import sys
import os
import re
import json
import time
import sqlite3
import argparse
import hashlib
from pathlib import Path
from multiprocessing import Pool, cpu_count
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict

import numpy as np

# ── Path setup ─────────────────────────────────────────────────────────────

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    STORE_THRESHOLD,
)

# ── Constants ──────────────────────────────────────────────────────────────

N = CT_LEN  # 97
AZ = ALPH
KA = KRYPTOS_ALPHABET
AZ_IDX = ALPH_IDX
KA_IDX = {c: i for i, c in enumerate(KA)}

# Crib data sorted by position
CRIB_LIST = sorted(CRIB_DICT.items())  # [(pos, char), ...]
CRIB_POS = np.array([p for p, _ in CRIB_LIST], dtype=np.int32)
CRIB_CHARS = [ch for _, ch in CRIB_LIST]

# CT as numeric arrays
CT_AZ = np.array([AZ_IDX[c] for c in CT], dtype=np.int8)
CT_KA = np.array([KA_IDX[c] for c in CT], dtype=np.int8)

# PT crib values in each alphabet
PT_AZ = np.array([AZ_IDX[ch] for _, ch in CRIB_LIST], dtype=np.int8)
PT_KA = np.array([KA_IDX[ch] for _, ch in CRIB_LIST], dtype=np.int8)

# CT values at crib positions in each alphabet
CT_CRIB_AZ = np.array([CT_AZ[p] for p in CRIB_POS], dtype=np.int8)
CT_CRIB_KA = np.array([CT_KA[p] for p in CRIB_POS], dtype=np.int8)

# Required key values at crib positions for each mode
# Mode: (variant, alphabet_name)
MODES = [
    ("vig",    "AZ"),
    ("beau",   "AZ"),
    ("vbeau",  "AZ"),
    ("vig",    "KA"),
    ("beau",   "KA"),
    ("vbeau",  "KA"),
]

def _compute_required_keys():
    """Compute required key values at each crib position for each mode."""
    required = {}
    for variant, alph_name in MODES:
        ct_crib = CT_CRIB_AZ if alph_name == "AZ" else CT_CRIB_KA
        pt_crib = PT_AZ if alph_name == "AZ" else PT_KA
        if variant == "vig":
            k = (ct_crib.astype(np.int16) - pt_crib.astype(np.int16)) % MOD
        elif variant == "beau":
            k = (ct_crib.astype(np.int16) + pt_crib.astype(np.int16)) % MOD
        else:  # vbeau
            k = (pt_crib.astype(np.int16) - ct_crib.astype(np.int16)) % MOD
        required[(variant, alph_name)] = k.astype(np.int8)
    return required

REQUIRED_KEYS = _compute_required_keys()

# Pair filter: pick 2 crib positions for early-exit pair check
# Choose positions with the most diverse required values across modes
# to maximize discriminating power
PAIR_A_IDX = 0   # first crib position in sorted order
PAIR_B_IDX = 12  # a position from ENE that's far from PAIR_A in the CT

# Bean constraint positions
BEAN_EQ_POS = BEAN_EQ[0]  # (27, 65)

# ── Transform widths ───────────────────────────────────────────────────────

GRID_WIDTHS = list(range(5, 41))  # 5 to 40 inclusive
SKIP_VALUES = [2, 3, 5, 7, 11, 13]

# ── Transform definitions (numpy-optimized) ───────────────────────────────

def make_reverse_perm(L):
    """Reversed readout permutation: T[i] = S[L-1-i]."""
    return np.arange(L - 1, -1, -1, dtype=np.int32)


def make_grid_column_perm(L, width):
    """Grid column readout: write rows of 'width', read columns top-to-bottom.

    S written row-by-row into grid, then read column-by-column.
    Uses numpy reshape+transpose for speed.
    """
    nrows = (L + width - 1) // width
    padded = nrows * width
    indices = np.arange(padded, dtype=np.int32)
    grid = indices.reshape(nrows, width)
    perm = grid.T.ravel()
    return perm[perm < L].copy()


def make_grid_column_rev_perm(L, width):
    """Grid column readout with columns read bottom-to-top."""
    nrows = (L + width - 1) // width
    padded = nrows * width
    indices = np.arange(padded, dtype=np.int32)
    grid = indices.reshape(nrows, width)
    perm = grid[::-1, :].T.ravel()
    return perm[perm < L].copy()


def make_boustrophedon_column_perm(L, width):
    """Boustrophedon row-fill then column-read.

    Text written into grid with alternating row direction
    (even rows L→R, odd rows R→L), then columns read top-to-bottom.
    Uses numpy for speed.
    """
    nrows = (L + width - 1) // width
    padded = nrows * width
    indices = np.arange(padded, dtype=np.int32)
    grid = indices.reshape(nrows, width).copy()
    grid[1::2, :] = grid[1::2, ::-1]  # reverse odd rows
    perm = grid.T.ravel()
    return perm[perm < L].copy()


def make_skip_perm(L, skip_n):
    """Skip-N readout: read positions 0, N, 2N, ..., then 1, N+1, 2N+1, ...

    Equivalent to writing into grid of width=skip_n, reading columns.
    Uses numpy reshape+transpose for speed.
    """
    n_per_lane = (L + skip_n - 1) // skip_n
    padded = n_per_lane * skip_n
    indices = np.arange(padded, dtype=np.int32).reshape(n_per_lane, skip_n)
    perm = indices.T.ravel()
    return perm[perm < L].copy()


# ── Transform registry ─────────────────────────────────────────────────────

def get_all_transforms(L):
    """Generate all (name, perm_array) pairs for a source of length L.

    Returns list of (transform_name, perm_array).
    Only generates transforms where the output length >= N (97).
    """
    transforms = []

    if L < N:
        return transforms

    # A. Reversed
    transforms.append(("reversed", make_reverse_perm(L)))

    # B. Grid-column read (widths 5-40)
    for w in GRID_WIDTHS:
        if L >= w:  # need at least one full row
            transforms.append((f"grid_col_w{w}", make_grid_column_perm(L, w)))

    # C. Grid-column reversed (widths 5-40)
    for w in GRID_WIDTHS:
        if L >= w:
            transforms.append((f"grid_colrev_w{w}", make_grid_column_rev_perm(L, w)))

    # D. Boustrophedon column-read (widths 5-40)
    for w in GRID_WIDTHS:
        if L >= w:
            p = make_boustrophedon_column_perm(L, w)
            if len(p) >= N:
                transforms.append((f"boust_col_w{w}", p))

    # E. Skip-N
    for skip in SKIP_VALUES:
        # Output length equals L (just reordered), so always >= N if L >= N
        transforms.append((f"skip_{skip}", make_skip_perm(L, skip)))

    return transforms


# ── Precomputed pair requirements per mode ─────────────────────────────────

def _precompute_pair_reqs():
    """Precompute pair filter values grouped by alphabet for batched checking."""
    az_modes = []
    ka_modes = []
    for i, (variant, alph_name) in enumerate(MODES):
        req = REQUIRED_KEYS[(variant, alph_name)]
        va = int(req[PAIR_A_IDX])
        vb = int(req[PAIR_B_IDX])
        if alph_name == "AZ":
            az_modes.append((i, va, vb))
        else:
            ka_modes.append((i, va, vb))
    return az_modes, ka_modes

AZ_PAIR_MODES, KA_PAIR_MODES = _precompute_pair_reqs()

# Precompute crib position offsets as a Python tuple for fast inner loop
_CRIB_POS_TUPLE = tuple(int(p) for p in CRIB_POS)


# ── Scoring engine (vectorized, alphabet-batched) ──────────────────────────

def scan_source_all_transforms(args):
    """Process one source file: load, apply all transforms, scan all modes.

    Optimization: per-transform, compute pair-position indices ONCE,
    then check all 3 modes of same alphabet using the same lookup values.

    Returns (source_id, hits_list, error_or_None).
    """
    source_path, source_id = args[:2]
    max_alpha = args[2] if len(args) > 2 else 0
    hits = []

    # Load and clean source text
    try:
        with open(source_path, 'r', errors='replace') as f:
            raw = f.read()
    except Exception as e:
        return source_id, [], f"read error: {e}"

    alpha = re.sub(r'[^A-Za-z]', '', raw).upper()
    L = len(alpha)
    if L < N:
        return source_id, [], None

    # Cap text length if configured (0 = no cap)
    if max_alpha > 0 and L > max_alpha:
        alpha = alpha[:max_alpha]
        L = max_alpha

    # Convert to numpy int arrays for both alphabets
    src_az = np.frombuffer(
        bytes(AZ_IDX[c] for c in alpha), dtype=np.int8
    ).copy()
    src_ka = np.frombuffer(
        bytes(KA_IDX[c] for c in alpha), dtype=np.int8
    ).copy()

    # Generate all transforms
    transforms = get_all_transforms(L)

    pa = int(CRIB_POS[PAIR_A_IDX])
    pb = int(CRIB_POS[PAIR_B_IDX])

    for tfm_name, perm in transforms:
        perm_len = len(perm)
        if perm_len < N:
            continue

        n_valid = perm_len - N + 1
        if n_valid <= 0:
            continue

        # Precompute pair-position source indices for this transform (shared by all modes)
        off_range = np.arange(n_valid, dtype=np.int32)
        idx_a = perm[off_range + pa]
        idx_b = perm[off_range + pb]

        # Process AZ modes (3 variants sharing the same source lookups)
        vals_a_az = src_az[idx_a]
        vals_b_az = src_az[idx_b]
        for mode_idx, va, vb in AZ_PAIR_MODES:
            mask = (vals_a_az == va) & (vals_b_az == vb)
            survivors = np.where(mask)[0]
            if len(survivors) == 0:
                continue
            variant, alph_name = MODES[mode_idx]
            req_key = REQUIRED_KEYS[(variant, alph_name)]
            for off_idx in survivors:
                off = int(off_idx)
                score = 0
                for cp in _CRIB_POS_TUPLE:
                    if src_az[perm[off + cp]] == req_key[score]:
                        score += 1
                    else:
                        # CRIB_POS is sorted, req_key indexed by position in sorted order
                        # We need proper indexing
                        break
                # Proper full check (can't use sequential break — positions aren't contiguous)
                score = sum(1 for ci in range(N_CRIBS) if src_az[perm[off + _CRIB_POS_TUPLE[ci]]] == req_key[ci])

                if score >= STORE_THRESHOLD:
                    hits.append(_build_hit(
                        source_id, source_path, tfm_name, off, variant, alph_name,
                        score, perm, src_az, L, perm_len))

        # Process KA modes
        vals_a_ka = src_ka[idx_a]
        vals_b_ka = src_ka[idx_b]
        for mode_idx, va, vb in KA_PAIR_MODES:
            mask = (vals_a_ka == va) & (vals_b_ka == vb)
            survivors = np.where(mask)[0]
            if len(survivors) == 0:
                continue
            variant, alph_name = MODES[mode_idx]
            req_key = REQUIRED_KEYS[(variant, alph_name)]
            for off_idx in survivors:
                off = int(off_idx)
                score = sum(1 for ci in range(N_CRIBS) if src_ka[perm[off + _CRIB_POS_TUPLE[ci]]] == req_key[ci])

                if score >= STORE_THRESHOLD:
                    hits.append(_build_hit(
                        source_id, source_path, tfm_name, off, variant, alph_name,
                        score, perm, src_ka, L, perm_len))

    return source_id, hits, None


def _build_hit(source_id, source_path, tfm_name, off, variant, alph_name,
               score, perm, src, L, perm_len):
    """Construct a hit dict with full metadata."""
    key_window = np.array([src[perm[off + i]] for i in range(N)], dtype=np.int8)
    ct_arr = CT_AZ if alph_name == "AZ" else CT_KA

    if variant == "vig":
        pt_arr = (ct_arr.astype(np.int16) - key_window.astype(np.int16)) % MOD
    elif variant == "beau":
        pt_arr = (key_window.astype(np.int16) - ct_arr.astype(np.int16)) % MOD
    else:
        pt_arr = (ct_arr.astype(np.int16) + key_window.astype(np.int16)) % MOD

    alph_str = AZ if alph_name == "AZ" else KA
    pt_text = ''.join(alph_str[v] for v in pt_arr)
    key_text = ''.join(AZ[v] for v in key_window)

    bean_eq_pass = (pt_text[BEAN_EQ_POS[0]] == pt_text[BEAN_EQ_POS[1]])

    return {
        'source_id': source_id,
        'source_path': str(source_path),
        'transform': tfm_name,
        'offset': off,
        'variant': variant,
        'alphabet': alph_name,
        'score': score,
        'pt': pt_text,
        'key_fragment': key_text[:20] + '...',
        'bean_eq': bean_eq_pass,
        'source_len': L,
        'perm_len': perm_len,
    }


# ── Source discovery ──────────────────────────────────────────────────────���

def discover_sources(root: Path, gutenberg_cache: Optional[Path] = None,
                     limit: Optional[int] = None) -> List[Tuple[str, str]]:
    """Discover all source texts. Returns [(path, source_id), ...]."""
    sources = []

    # Local reference texts
    for ext in ('*.txt', '*.md'):
        for f in sorted((root / 'reference').glob(ext)):
            sid = f"local:{f.stem}"
            sources.append((str(f), sid))
        for f in sorted((root / 'reference' / 'running_key_texts').glob(ext)):
            sid = f"rkt:{f.stem}"
            sources.append((str(f), sid))

    # Gutenberg cache
    if gutenberg_cache and gutenberg_cache.is_dir():
        gfiles = sorted(gutenberg_cache.glob('*.txt'))
        for f in gfiles:
            sid = f"pg:{f.stem}"
            sources.append((str(f), sid))

    if limit:
        sources = sources[:limit]

    return sources


# ── Database ───────────────────────────────────────────────────────────────

DB_PATH = _ROOT / "db" / "nonlinear_rk_v1.sqlite"

def init_db(db_path: Path) -> sqlite3.Connection:
    """Initialize SQLite WAL database."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            run_id INTEGER PRIMARY KEY AUTOINCREMENT,
            started_at TEXT NOT NULL,
            status TEXT DEFAULT 'running',
            n_sources INTEGER,
            n_transforms_per_source INTEGER,
            n_modes INTEGER,
            config TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS completed_sources (
            source_id TEXT PRIMARY KEY,
            run_id INTEGER,
            completed_at TEXT,
            n_hits INTEGER DEFAULT 0,
            error TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS hits (
            hit_id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            source_id TEXT,
            source_path TEXT,
            transform TEXT,
            offset INTEGER,
            variant TEXT,
            alphabet TEXT,
            score INTEGER,
            pt TEXT,
            key_fragment TEXT,
            bean_eq INTEGER,
            source_len INTEGER,
            perm_len INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_hits_score ON hits(score DESC)
    """)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_hits_transform ON hits(transform)
    """)
    conn.commit()
    return conn


def get_completed_sources(conn) -> set:
    """Get set of already-completed source IDs."""
    rows = conn.execute("SELECT source_id FROM completed_sources").fetchall()
    return {r[0] for r in rows}


def save_results(conn, run_id, source_id, hits, error=None):
    """Save results for one source file."""
    now = time.strftime('%Y-%m-%dT%H:%M:%S')
    conn.execute(
        "INSERT OR REPLACE INTO completed_sources (source_id, run_id, completed_at, n_hits, error) "
        "VALUES (?, ?, ?, ?, ?)",
        (source_id, run_id, now, len(hits), error)
    )
    for h in hits:
        conn.execute(
            "INSERT INTO hits (run_id, source_id, source_path, transform, offset, "
            "variant, alphabet, score, pt, key_fragment, bean_eq, source_len, perm_len) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (run_id, h['source_id'], h['source_path'], h['transform'],
             h['offset'], h['variant'], h['alphabet'], h['score'],
             h['pt'], h['key_fragment'], 1 if h['bean_eq'] else 0,
             h['source_len'], h['perm_len'])
        )
    conn.commit()


# ── Reporting ──────────────────────────────────────────────────────────────

def generate_report(db_path: Path):
    """Generate morning report from database.

    Reports across ALL data in the database (not filtered by run_id)
    because multiple runs accumulate into the same completed_sources
    and hits tables. Filtering by last run_id would miss Phase 1
    results when Phase 2 creates a new run_id.
    """
    conn = sqlite3.connect(str(db_path))

    # Run summary
    runs = conn.execute(
        "SELECT run_id, started_at, status, n_sources FROM runs ORDER BY run_id"
    ).fetchall()

    if not runs:
        print("No runs found in database.")
        return

    print(f"{'='*70}")
    print(f"NON-LINEAR RUNNING KEY CAMPAIGN — MORNING REPORT")
    print(f"{'='*70}")
    for r in runs:
        print(f"  Run {r[0]}: started={r[1]} status={r[2]} planned={r[3]}")
    print()

    # Completion stats (across all runs)
    completed = conn.execute(
        "SELECT COUNT(*) FROM completed_sources"
    ).fetchone()[0]
    errors = conn.execute(
        "SELECT COUNT(*) FROM completed_sources WHERE error IS NOT NULL"
    ).fetchone()[0]
    print(f"Sources completed: {completed}")
    print(f"Sources with errors: {errors}")
    print()

    # Hit statistics (across all runs)
    total_hits = conn.execute(
        "SELECT COUNT(*) FROM hits"
    ).fetchone()[0]
    print(f"Total hits (score >= {STORE_THRESHOLD}): {total_hits}")
    print()

    # Score distribution
    print("Score distribution:")
    rows = conn.execute(
        "SELECT score, COUNT(*) FROM hits GROUP BY score ORDER BY score DESC"
    ).fetchall()
    for score, count in rows:
        print(f"  Score {score:2d}: {count:6d} hits")
    print()

    # Best hits
    print("Top 20 hits:")
    top = conn.execute(
        "SELECT score, transform, variant, alphabet, source_id, offset, pt, bean_eq "
        "FROM hits ORDER BY score DESC, bean_eq DESC LIMIT 20"
    ).fetchall()
    for row in top:
        score, tfm, var, alph, sid, off, pt, bean = row
        bean_str = "BEAN-EQ" if bean else ""
        print(f"  {score:2d}/24 {tfm:20s} {var:6s} {alph} off={off:>8d} {sid[:30]:30s} {bean_str}")
        print(f"         PT: {pt[:50]}...")
    print()

    # By transform (specific, not grouped)
    print("Top transforms (specific):")
    rows = conn.execute("""
        SELECT transform, COUNT(*) as n_hits, MAX(score) as best_score
        FROM hits
        GROUP BY transform
        ORDER BY best_score DESC, n_hits DESC
        LIMIT 15
    """).fetchall()
    for tfm, n_hits, best in rows:
        print(f"  {tfm:25s}: {n_hits:5d} hits, best={best:2d}")
    print()

    # By transform family (grouped)
    print("Hits by transform family:")
    rows = conn.execute("""
        SELECT
            CASE
                WHEN transform = 'reversed' THEN 'reversed'
                WHEN transform LIKE 'grid_col_w%' THEN 'grid_column'
                WHEN transform LIKE 'grid_colrev_w%' THEN 'grid_col_rev'
                WHEN transform LIKE 'boust_col_w%' THEN 'boustrophedon'
                WHEN transform LIKE 'skip_%' THEN 'skip_N'
                ELSE transform
            END as family,
            COUNT(*) as n_hits,
            MAX(score) as best_score,
            AVG(score) as avg_score
        FROM hits
        GROUP BY family
        ORDER BY best_score DESC, n_hits DESC
    """).fetchall()
    for family, n_hits, best, avg in rows:
        print(f"  {family:20s}: {n_hits:6d} hits, best={best:2d}, avg={avg:.1f}")
    print()

    # By source family
    print("Hits by source family:")
    rows = conn.execute("""
        SELECT
            CASE
                WHEN source_id LIKE 'pg:%' THEN 'gutenberg'
                WHEN source_id LIKE 'rkt:%' THEN 'running_key_texts'
                ELSE 'local_reference'
            END as family,
            COUNT(*) as n_hits,
            MAX(score) as best_score
        FROM hits
        GROUP BY family
        ORDER BY best_score DESC
    """).fetchall()
    for family, n_hits, best in rows:
        print(f"  {family:20s}: {n_hits:6d} hits, best={best:2d}")
    print()

    # Bean equality analysis
    bean_pass = conn.execute(
        "SELECT COUNT(*) FROM hits WHERE bean_eq=1"
    ).fetchone()[0]
    bean_high = conn.execute(
        "SELECT COUNT(*) FROM hits WHERE bean_eq=1 AND score >= 12"
    ).fetchone()[0]
    print(f"Hits with Bean equality pass: {bean_pass}/{total_hits} ({bean_high} at score >= 12)")
    print()

    # Variant/alphabet breakdown at score >= 12
    print("Score >= 12 by variant/alphabet:")
    rows = conn.execute("""
        SELECT variant, alphabet, COUNT(*), MAX(score)
        FROM hits WHERE score >= 12
        GROUP BY variant, alphabet
        ORDER BY MAX(score) DESC, COUNT(*) DESC
    """).fetchall()
    for var, alph, n, best in rows:
        print(f"  {var:8s} {alph}: {n:4d} hits, best={best}")
    print()

    # Source text clustering at score >= 11
    print("Source clustering (score >= 11, sources with 3+ hits):")
    clusters = conn.execute("""
        SELECT source_id, COUNT(*) as n, MAX(score) as best,
               GROUP_CONCAT(DISTINCT transform) as transforms
        FROM hits WHERE score >= 11
        GROUP BY source_id
        HAVING COUNT(*) >= 3
        ORDER BY best DESC, n DESC
        LIMIT 15
    """).fetchall()
    if clusters:
        for sid, n, best, tfms in clusters:
            print(f"  {sid[:40]:40s} n={n:3d} best={best:2d} transforms={tfms[:60]}")
    else:
        print("  (none)")

    # Offset proximity clustering at score >= 12
    print()
    print("Offset proximity (score >= 12, same source within ±50 chars):")
    high_hits = conn.execute("""
        SELECT source_id, transform, offset, score, variant, alphabet
        FROM hits WHERE score >= 12
        ORDER BY source_id, offset
    """).fetchall()
    if high_hits:
        prev_src, prev_off = None, None
        for sid, tfm, off, score, var, alph in high_hits:
            proximity = ""
            if prev_src == sid and abs(off - prev_off) <= 50:
                proximity = f" ← NEAR PREVIOUS (Δ={off - prev_off})"
            print(f"  {score:2d}/24 {sid[:30]:30s} off={off:>8d} {tfm:20s} {var} {alph}{proximity}")
            prev_src, prev_off = sid, off
    else:
        print("  (no hits at score >= 12)")

    # Transform equivalence detection
    print()
    print("Potential transform equivalences (same source+offset+score, different transform):")
    equiv = conn.execute("""
        SELECT a.transform, b.transform, COUNT(*) as n_shared
        FROM hits a
        JOIN hits b ON a.source_id = b.source_id
            AND a.offset = b.offset
            AND a.score = b.score
            AND a.variant = b.variant
            AND a.alphabet = b.alphabet
            AND a.transform < b.transform
        WHERE a.score >= 10
        GROUP BY a.transform, b.transform
        HAVING COUNT(*) >= 3
        ORDER BY n_shared DESC
        LIMIT 10
    """).fetchall()
    if equiv:
        for ta, tb, n in equiv:
            print(f"  {ta:25s} ≡ {tb:25s}  ({n} shared hits)")
    else:
        print("  (none detected)")

    print()
    print(f"{'='*70}")
    print(f"Database: {db_path}")
    print(f"{'='*70}")

    conn.close()


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Non-linear running key sweep")
    parser.add_argument('--dry-run', action='store_true',
                        help='Process 3 texts, print results, no DB writes')
    parser.add_argument('--benchmark', action='store_true',
                        help='Process 100 texts, measure throughput')
    parser.add_argument('--report', action='store_true',
                        help='Generate morning report from existing DB')
    parser.add_argument('--resume', action='store_true',
                        help='Resume interrupted run (skip completed sources)')
    parser.add_argument('--workers', type=int, default=max(1, cpu_count() - 2),
                        help=f'Number of worker processes (default: {max(1, cpu_count() - 2)})')
    parser.add_argument('--limit', type=int, default=None,
                        help='Limit number of source texts to process')
    parser.add_argument('--gutenberg', type=str,
                        default='/data/tmp/gutenberg_cache',
                        help='Path to Gutenberg cache directory')
    parser.add_argument('--db', type=str, default=str(DB_PATH),
                        help=f'Path to SQLite database (default: {DB_PATH})')
    parser.add_argument('--local-only', action='store_true',
                        help='Only process local reference texts (no Gutenberg)')
    parser.add_argument('--max-alpha', type=int, default=2_000_000,
                        help='Max alpha chars per source (0=no cap, default: 2000000)')
    args = parser.parse_args()

    db_path = Path(args.db)

    if args.report:
        generate_report(db_path)
        return

    # Discover sources
    gutenberg_path = None if args.local_only else Path(args.gutenberg)
    if gutenberg_path and not gutenberg_path.is_dir():
        print(f"Warning: Gutenberg cache not found at {gutenberg_path}, using local only")
        gutenberg_path = None

    limit = args.limit
    if args.dry_run:
        limit = 3
    elif args.benchmark:
        limit = 100

    sources = discover_sources(_ROOT, gutenberg_path, limit=limit)
    print(f"Discovered {len(sources)} source texts", flush=True)

    if not sources:
        print("No sources found. Exiting.")
        return

    # Preview transform count
    sample_L = 100000
    n_tfm = len(get_all_transforms(sample_L))
    print(f"Transforms per source (L={sample_L}): {n_tfm}", flush=True)
    print(f"Cipher modes: {len(MODES)}", flush=True)
    print(f"Workers: {args.workers}", flush=True)
    print(flush=True)

    # Database setup (skip for dry-run)
    conn = None
    run_id = 0
    completed = set()

    if not args.dry_run:
        conn = init_db(db_path)

        # Check for resume
        if args.resume:
            completed = get_completed_sources(conn)
            print(f"Resume mode: {len(completed)} sources already completed", flush=True)

        # Create run record
        now = time.strftime('%Y-%m-%dT%H:%M:%S')
        cur = conn.execute(
            "INSERT INTO runs (started_at, status, n_sources, n_transforms_per_source, n_modes, config) "
            "VALUES (?, 'running', ?, ?, ?, ?)",
            (now, len(sources), n_tfm, len(MODES),
             json.dumps({
                 'grid_widths': GRID_WIDTHS,
                 'skip_values': SKIP_VALUES,
                 'workers': args.workers,
                 'gutenberg': str(gutenberg_path),
                 'local_only': args.local_only,
                 'limit': limit,
                 'resume': args.resume,
                 'store_threshold': STORE_THRESHOLD,
                 'max_alpha': args.max_alpha,
             }))
        )
        run_id = cur.lastrowid
        conn.commit()
        print(f"Run ID: {run_id}", flush=True)

    # Filter out already-completed sources
    if completed:
        sources = [(p, sid) for p, sid in sources if sid not in completed]
        print(f"After filtering completed: {len(sources)} sources remaining", flush=True)

    if not sources:
        print("All sources already completed. Nothing to do.")
        if conn:
            conn.execute("UPDATE runs SET status='completed' WHERE run_id=?", (run_id,))
            conn.commit()
            conn.close()
        return

    # Run
    t0 = time.time()
    global_best = 0
    total_processed = 0
    total_hits = 0
    total_errors = 0

    print(f"\n{'='*70}", flush=True)
    print(f"STARTING SWEEP: {len(sources)} sources × {n_tfm} transforms × {len(MODES)} modes", flush=True)
    print(f"{'='*70}\n", flush=True)

    # Use pool for parallel processing
    # Append max_alpha to each source tuple for the worker function
    max_alpha = args.max_alpha
    work_items = [(p, sid, max_alpha) for p, sid in sources]

    with Pool(processes=args.workers) as pool:
        results_iter = pool.imap_unordered(
            scan_source_all_transforms,
            work_items,
            chunksize=max(1, min(50, len(sources) // args.workers))
        )

        for source_id, hits, error in results_iter:
            total_processed += 1
            if error:
                total_errors += 1

            if hits:
                total_hits += len(hits)
                best_this = max(h['score'] for h in hits)
                if best_this > global_best:
                    global_best = best_this
                    best_hit = max(hits, key=lambda h: h['score'])
                    print(f"\n*** NEW BEST: {best_this}/24 ***", flush=True)
                    print(f"  Source: {best_hit['source_id']}", flush=True)
                    print(f"  Transform: {best_hit['transform']}", flush=True)
                    print(f"  Variant: {best_hit['variant']} {best_hit['alphabet']}", flush=True)
                    print(f"  Offset: {best_hit['offset']}", flush=True)
                    print(f"  PT: {best_hit['pt'][:60]}...", flush=True)
                    print(f"  Bean EQ: {'PASS' if best_hit['bean_eq'] else 'FAIL'}", flush=True)
                    print(flush=True)

            # Save to DB
            if conn:
                save_results(conn, run_id, source_id, hits, error)

            # Progress logging
            elapsed = time.time() - t0
            rate = total_processed / elapsed if elapsed > 0 else 0
            remaining = (len(sources) - total_processed) / rate if rate > 0 else 0

            if total_processed % 500 == 0 or total_processed == len(sources):
                print(
                    f"[{total_processed:>6d}/{len(sources)}] "
                    f"{rate:.1f} src/s | "
                    f"hits={total_hits} best={global_best}/24 "
                    f"err={total_errors} | "
                    f"elapsed={elapsed:.0f}s eta={remaining:.0f}s",
                    flush=True
                )

    # Finalize
    elapsed = time.time() - t0
    print(f"\n{'='*70}", flush=True)
    print(f"SWEEP COMPLETE", flush=True)
    print(f"{'='*70}", flush=True)
    print(f"Sources processed: {total_processed}", flush=True)
    print(f"Total hits (score >= {STORE_THRESHOLD}): {total_hits}", flush=True)
    print(f"Global best score: {global_best}/24", flush=True)
    print(f"Errors: {total_errors}", flush=True)
    print(f"Elapsed: {elapsed:.1f}s ({elapsed/3600:.2f}h)", flush=True)
    print(f"Rate: {total_processed/elapsed:.1f} sources/sec", flush=True)
    print(f"Database: {db_path}", flush=True)

    if conn:
        conn.execute(
            "UPDATE runs SET status='completed' WHERE run_id=?", (run_id,)
        )
        conn.commit()
        conn.close()

    # Generate report
    if not args.dry_run:
        print(f"\n{'='*70}", flush=True)
        generate_report(db_path)


if __name__ == '__main__':
    main()
