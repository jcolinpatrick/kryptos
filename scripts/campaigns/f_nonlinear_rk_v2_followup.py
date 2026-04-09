#!/usr/bin/env python3 -u
"""
Cipher:   running_key (non-linear readout follow-up)
Family:   campaigns
Status:   active
Keyspace: targeted — v1 top-band exploitation
Last run: never
Best score: N/A

NON-LINEAR RUNNING KEY v2 — DISCIPLINED FOLLOW-UP

PURPOSE: Determine whether the v1 grid_colrev w30-33 lead survives
disciplined perturbation, quantify the KA+vig asymmetry against proper
conditional nulls, and convert the top-band hits into a statistically
interpretable verdict.

FIVE WORKSTREAMS:
  A. Targeted transform sweep (grid_colrev w28-35 on all sources)
  B. Conditional null / enrichment analysis
  C. Top-hit structural audit (crib positions, Bean, fragments)
  D. Source neighborhood analysis (offset/width perturbation)
  E. Secondary filters (quadgram, Bean inequality patterns)

Usage:
  PYTHONPATH=src python3 -u scripts/campaigns/f_nonlinear_rk_v2_followup.py --dry-run
  PYTHONPATH=src python3 -u scripts/campaigns/f_nonlinear_rk_v2_followup.py --benchmark
  PYTHONPATH=src python3 -u scripts/campaigns/f_nonlinear_rk_v2_followup.py
  PYTHONPATH=src python3 -u scripts/campaigns/f_nonlinear_rk_v2_followup.py --report
"""

import sys
import os
import re
import json
import time
import math
import sqlite3
import argparse
from pathlib import Path
from multiprocessing import Pool, cpu_count
from collections import Counter, defaultdict
from typing import List, Tuple, Optional, Dict

import numpy as np
from scipy.stats import binom, poisson

# ── Path setup ─────────────────────────────────────────────────────────────

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT / "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, KRYPTOS_ALPHABET,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS, CRIB_WORDS,
    BEAN_EQ, BEAN_INEQ,
    STORE_THRESHOLD, NOISE_FLOOR,
)

# ── Constants ──────────────────────────────────────────────────────────────

N = CT_LEN  # 97
AZ = ALPH
KA = KRYPTOS_ALPHABET
AZ_IDX = ALPH_IDX
KA_IDX = {c: i for i, c in enumerate(KA)}

CRIB_LIST = sorted(CRIB_DICT.items())
CRIB_POS = np.array([p for p, _ in CRIB_LIST], dtype=np.int32)
_CRIB_POS_TUPLE = tuple(int(p) for p in CRIB_POS)

CT_AZ = np.array([AZ_IDX[c] for c in CT], dtype=np.int8)
CT_KA = np.array([KA_IDX[c] for c in CT], dtype=np.int8)

PT_AZ = np.array([AZ_IDX[ch] for _, ch in CRIB_LIST], dtype=np.int8)
PT_KA = np.array([KA_IDX[ch] for _, ch in CRIB_LIST], dtype=np.int8)
CT_CRIB_AZ = np.array([CT_AZ[p] for p in CRIB_POS], dtype=np.int8)
CT_CRIB_KA = np.array([CT_KA[p] for p in CRIB_POS], dtype=np.int8)

MODES = [
    ("vig", "AZ"), ("beau", "AZ"), ("vbeau", "AZ"),
    ("vig", "KA"), ("beau", "KA"), ("vbeau", "KA"),
]

def _compute_required_keys():
    required = {}
    for variant, alph_name in MODES:
        ct_crib = CT_CRIB_AZ if alph_name == "AZ" else CT_CRIB_KA
        pt_crib = PT_AZ if alph_name == "AZ" else PT_KA
        if variant == "vig":
            k = (ct_crib.astype(np.int16) - pt_crib.astype(np.int16)) % MOD
        elif variant == "beau":
            k = (ct_crib.astype(np.int16) + pt_crib.astype(np.int16)) % MOD
        else:
            k = (pt_crib.astype(np.int16) - ct_crib.astype(np.int16)) % MOD
        required[(variant, alph_name)] = k.astype(np.int8)
    return required

REQUIRED_KEYS = _compute_required_keys()

# English letter frequencies for conditional null
ENG_FREQ = {
    'A': 0.082, 'B': 0.015, 'C': 0.028, 'D': 0.043, 'E': 0.127,
    'F': 0.022, 'G': 0.020, 'H': 0.061, 'I': 0.070, 'J': 0.002,
    'K': 0.008, 'L': 0.040, 'M': 0.024, 'N': 0.067, 'O': 0.075,
    'P': 0.019, 'Q': 0.001, 'R': 0.060, 'S': 0.063, 'T': 0.091,
    'U': 0.028, 'V': 0.010, 'W': 0.023, 'X': 0.002, 'Y': 0.020, 'Z': 0.001
}

# Bean constraint data
BEAN_EQ_POS = BEAN_EQ[0]

# ENE and BCL position ranges
ENE_RANGE = list(range(21, 34))  # 13 positions
BCL_RANGE = list(range(63, 74))  # 11 positions

# Focused widths for Workstream A
FOCUSED_WIDTHS = list(range(28, 36))  # 28-35 inclusive

# Quadgram loading
QG_PATH = _ROOT / "data" / "english_quadgrams.json"
QG = None
QG_FLOOR = None

def _load_quadgrams():
    global QG, QG_FLOOR
    if QG is not None:
        return
    with open(QG_PATH) as f:
        QG = json.load(f)
    QG_FLOOR = min(QG.values()) - 1.0

def quadgram_score(text):
    """Compute quadgram log-probability per character."""
    _load_quadgrams()
    if len(text) < 4:
        return QG_FLOOR
    total = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        total += QG.get(qg, QG_FLOOR)
    return total / (len(text) - 3)


# ── Transform (exact v1 semantics) ────────────────────────────────────────

def make_grid_colrev_perm(L, width):
    """Grid column readout with columns read bottom-to-top.
    EXACT v1 semantics: numpy reshape + [::-1, :] transpose."""
    nrows = (L + width - 1) // width
    padded = nrows * width
    indices = np.arange(padded, dtype=np.int32)
    grid = indices.reshape(nrows, width)
    perm = grid[::-1, :].T.ravel()
    return perm[perm < L].copy()


# ── Database ───────────────────────────────────────────────────────────────

DB_PATH = _ROOT / "db" / "nonlinear_rk_v2.sqlite"

def init_db(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")

    conn.execute("""CREATE TABLE IF NOT EXISTS v2_runs (
        run_id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT NOT NULL,
        status TEXT DEFAULT 'running',
        config TEXT
    )""")

    # Workstream A: targeted sweep hits
    conn.execute("""CREATE TABLE IF NOT EXISTS ws_a_hits (
        hit_id INTEGER PRIMARY KEY AUTOINCREMENT,
        run_id INTEGER,
        source_id TEXT, source_path TEXT,
        width INTEGER, offset INTEGER,
        variant TEXT, alphabet TEXT,
        score INTEGER, pt TEXT,
        bean_eq INTEGER, bean_ineq_pass INTEGER, bean_ineq_fail INTEGER,
        ene_score INTEGER, bcl_score INTEGER,
        qg_score REAL,
        source_len INTEGER
    )""")

    conn.execute("""CREATE TABLE IF NOT EXISTS ws_a_completed (
        source_id TEXT PRIMARY KEY,
        run_id INTEGER, completed_at TEXT
    )""")

    # Workstream B: conditional null summary
    conn.execute("""CREATE TABLE IF NOT EXISTS ws_b_conditional_null (
        mode TEXT PRIMARY KEY,
        variant TEXT, alphabet TEXT,
        e_score REAL, geo_mean_p REAL, p_pair REAL,
        expected_10plus REAL, observed_10plus INTEGER,
        expected_12plus REAL, observed_12plus INTEGER,
        enrichment_10 REAL, enrichment_12 REAL,
        notes TEXT
    )""")

    # Workstream C: structural audit of each top candidate
    conn.execute("""CREATE TABLE IF NOT EXISTS ws_c_audit (
        audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
        source TEXT, -- 'v1' or 'v2'
        source_id TEXT, transform TEXT,
        width INTEGER, offset INTEGER,
        variant TEXT, alphabet TEXT,
        score INTEGER,
        ene_score INTEGER, bcl_score INTEGER,
        matched_positions TEXT, -- JSON array
        failed_positions TEXT,  -- JSON array of {pos, expected, actual}
        bean_eq INTEGER,
        bean_ineq_pass INTEGER, bean_ineq_fail INTEGER,
        bean_ineq_failures TEXT, -- JSON array of (a,b) pairs that fail
        has_north INTEGER, has_berli INTEGER,
        longest_crib_run INTEGER,
        qg_score REAL,
        pt TEXT
    )""")

    # Workstream D: neighborhood persistence
    conn.execute("""CREATE TABLE IF NOT EXISTS ws_d_neighborhood (
        seed_source_id TEXT,
        seed_offset INTEGER,
        seed_width INTEGER,
        seed_score INTEGER,
        test_width INTEGER,
        test_offset INTEGER,
        test_score INTEGER,
        delta_width INTEGER,
        delta_offset INTEGER,
        variant TEXT, alphabet TEXT
    )""")

    # Workstream E: width enrichment
    conn.execute("""CREATE TABLE IF NOT EXISTS ws_e_width_enrichment (
        width INTEGER PRIMARY KEY,
        n_hits_10plus INTEGER,
        n_hits_11plus INTEGER,
        n_hits_12plus INTEGER,
        best_score INTEGER,
        expected_10plus REAL,
        enrichment REAL
    )""")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_wsa_score ON ws_a_hits(score DESC)")
    conn.commit()
    return conn


# ── Workstream A: Targeted sweep worker ────────────────────────────────────

def ws_a_scan_source(args):
    """Scan one source with focused grid_colrev widths 28-35, all 6 modes."""
    source_path, source_id, widths = args
    hits = []

    try:
        with open(source_path, 'r', errors='replace') as f:
            raw = f.read()
    except Exception:
        return source_id, [], True

    alpha = re.sub(r'[^A-Za-z]', '', raw).upper()
    L = len(alpha)
    if L < N:
        return source_id, [], False

    src_az = np.frombuffer(bytes(AZ_IDX[c] for c in alpha), dtype=np.int8).copy()
    src_ka = np.frombuffer(bytes(KA_IDX[c] for c in alpha), dtype=np.int8).copy()

    for width in widths:
        perm = make_grid_colrev_perm(L, width)
        perm_len = len(perm)
        if perm_len < N:
            continue
        n_valid = perm_len - N + 1
        if n_valid <= 0:
            continue

        off_range = np.arange(n_valid, dtype=np.int32)
        pa = int(CRIB_POS[0])
        pb = int(CRIB_POS[12])
        idx_a = perm[off_range + pa]
        idx_b = perm[off_range + pb]

        for src, src_label, mode_list in [
            (src_az, "AZ", [m for m in MODES if m[1] == "AZ"]),
            (src_ka, "KA", [m for m in MODES if m[1] == "KA"]),
        ]:
            vals_a = src[idx_a]
            vals_b = src[idx_b]

            for variant, alph_name in mode_list:
                req_key = REQUIRED_KEYS[(variant, alph_name)]
                va, vb = int(req_key[0]), int(req_key[12])
                mask = (vals_a == va) & (vals_b == vb)
                survivors = np.where(mask)[0]

                for off_idx in survivors:
                    off = int(off_idx)
                    score = sum(1 for ci in range(N_CRIBS)
                                if src[perm[off + _CRIB_POS_TUPLE[ci]]] == req_key[ci])

                    if score >= NOISE_FLOOR:
                        hit = _build_full_hit(
                            source_id, source_path, width, off,
                            variant, alph_name, score, perm, src, L)
                        hits.append(hit)

    return source_id, hits, False


def _build_full_hit(source_id, source_path, width, off, variant, alph_name,
                    score, perm, src, L):
    """Build a hit with full audit metadata."""
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

    # Crib analysis
    matched = []
    failed = []
    ene_score = 0
    bcl_score = 0
    for pos, ch in CRIB_LIST:
        if pt_text[pos] == ch:
            matched.append(pos)
            if 21 <= pos <= 33:
                ene_score += 1
            elif 63 <= pos <= 73:
                bcl_score += 1
        else:
            failed.append({"pos": pos, "exp": ch, "act": pt_text[pos]})

    # Bean analysis
    bean_eq = 1 if pt_text[BEAN_EQ_POS[0]] == pt_text[BEAN_EQ_POS[1]] else 0

    alph_idx = AZ_IDX if alph_name == "AZ" else KA_IDX
    ct_nums = CT_AZ if alph_name == "AZ" else CT_KA
    pt_nums = np.array([alph_idx[c] for c in pt_text], dtype=np.int8)

    bean_fail_pairs = []
    for a, b in BEAN_INEQ:
        if variant == "vig":
            ka = (int(ct_nums[a]) - int(pt_nums[a])) % MOD
            kb = (int(ct_nums[b]) - int(pt_nums[b])) % MOD
        elif variant == "beau":
            ka = (int(ct_nums[a]) + int(pt_nums[a])) % MOD
            kb = (int(ct_nums[b]) + int(pt_nums[b])) % MOD
        else:
            ka = (int(pt_nums[a]) - int(ct_nums[a])) % MOD
            kb = (int(pt_nums[b]) - int(ct_nums[b])) % MOD
        if ka == kb:
            bean_fail_pairs.append((a, b))

    bean_ineq_pass = 242 - len(bean_fail_pairs)

    # Quadgram
    qg = quadgram_score(pt_text)

    return {
        'source_id': source_id,
        'source_path': str(source_path),
        'width': width,
        'offset': off,
        'variant': variant,
        'alphabet': alph_name,
        'score': score,
        'pt': pt_text,
        'bean_eq': bean_eq,
        'bean_ineq_pass': bean_ineq_pass,
        'bean_ineq_fail': len(bean_fail_pairs),
        'bean_ineq_failures': json.dumps(bean_fail_pairs),
        'ene_score': ene_score,
        'bcl_score': bcl_score,
        'matched_positions': json.dumps(matched),
        'failed_positions': json.dumps(failed),
        'has_north': 1 if 'NORTH' in pt_text else 0,
        'has_berli': 1 if 'BERLI' in pt_text else 0,
        'longest_crib_run': _longest_crib_run(matched),
        'qg_score': qg,
        'source_len': L,
    }


def _longest_crib_run(matched_positions):
    """Longest consecutive run of matched crib positions."""
    if not matched_positions:
        return 0
    s = sorted(matched_positions)
    best = 1
    run = 1
    for i in range(1, len(s)):
        if s[i] == s[i-1] + 1:
            run += 1
            best = max(best, run)
        else:
            run = 1
    return best


# ── Source discovery ───────────────────────────────────────────────────────

def discover_sources(root, gutenberg_cache=None, limit=None):
    sources = []
    for ext in ('*.txt', '*.md'):
        for f in sorted((root / 'reference').glob(ext)):
            sources.append((str(f), f"local:{f.stem}"))
        for f in sorted((root / 'reference' / 'running_key_texts').glob(ext)):
            sources.append((str(f), f"rkt:{f.stem}"))
    if gutenberg_cache and gutenberg_cache.is_dir():
        for f in sorted(gutenberg_cache.glob('*.txt')):
            sources.append((str(f), f"pg:{f.stem}"))
    if limit:
        sources = sources[:limit]
    return sources


# ── Workstream B: Conditional null computation ─────────────────────────────

def compute_conditional_nulls(v1_db_path, v2_conn):
    """Compute mode-conditioned expected hit rates using English letter frequencies."""
    v1 = sqlite3.connect(str(v1_db_path))

    freq_az = [ENG_FREQ[AZ[v]] for v in range(26)]
    freq_ka = [ENG_FREQ[KA[v]] for v in range(26)]

    # Get observed counts from v1 (excluding skip_N duplicates)
    obs = {}
    rows = v1.execute("""
        SELECT variant, alphabet,
            SUM(CASE WHEN score >= 10 THEN 1 ELSE 0 END),
            SUM(CASE WHEN score >= 12 THEN 1 ELSE 0 END)
        FROM hits WHERE transform NOT LIKE 'skip_%'
        GROUP BY variant, alphabet
    """).fetchall()
    for var, alph, s10, s12 in rows:
        obs[(var, alph)] = (s10, s12)

    # Calibrate total trials from total score-10+ count
    total_10plus = sum(v[0] for v in obs.values())

    for variant, alph_name in MODES:
        freq = freq_az if alph_name == "AZ" else freq_ka
        req_key = REQUIRED_KEYS[(variant, alph_name)]

        # P(match) at each crib position using English letter freq
        p_match = [freq[int(req_key[i])] for i in range(N_CRIBS)]
        e_score = sum(p_match)
        geo_mean = math.exp(sum(math.log(p) for p in p_match) / N_CRIBS)
        p_pair = p_match[0] * p_match[12]

        # Expected fraction of trials producing score >= 10
        # Use Poisson-binomial approximation: for non-uniform p,
        # P(X >= k) where X = sum of Bernoulli(p_i)
        # Use normal approximation: mu = sum(p_i), var = sum(p_i*(1-p_i))
        mu = e_score
        var = sum(p * (1 - p) for p in p_match)
        sigma = math.sqrt(var) if var > 0 else 0.001

        # P(score >= 10) using normal approx with continuity correction
        from scipy.stats import norm
        p_ge10 = 1 - norm.cdf(9.5, mu, sigma)
        p_ge12 = 1 - norm.cdf(11.5, mu, sigma)

        # Each mode gets 1/6 of total trial volume
        # Back-calibrate total trials from total observed score-10+
        # Total score-10+ across all modes = total_10plus
        # Expected score-10+ for this mode = total_trials_per_mode * p_ge10
        # Sum over modes of (trials_per_mode * p_ge10_mode) = total_10plus
        # Since trials_per_mode is same for all: T * sum(p_ge10_mode) = total_10plus
        # T = total_10plus / sum(p_ge10_modes)
        # We compute this outside the loop below

        mode_key = f"{variant}_{alph_name}"
        o10, o12 = obs.get((variant, alph_name), (0, 0))

        v2_conn.execute(
            "INSERT OR REPLACE INTO ws_b_conditional_null VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (mode_key, variant, alph_name,
             e_score, geo_mean, p_pair,
             0, o10,  # expected_10plus filled below
             0, o12,  # expected_12plus filled below
             0, 0,    # enrichment filled below
             "")
        )

    # Now calibrate and fill expected counts
    # Recompute all p_ge10 values
    p_ge10_by_mode = {}
    p_ge12_by_mode = {}
    for variant, alph_name in MODES:
        freq = freq_az if alph_name == "AZ" else freq_ka
        req_key = REQUIRED_KEYS[(variant, alph_name)]
        p_match = [freq[int(req_key[i])] for i in range(N_CRIBS)]
        mu = sum(p_match)
        var = sum(p * (1 - p) for p in p_match)
        sigma = math.sqrt(var) if var > 0 else 0.001
        p_ge10_by_mode[(variant, alph_name)] = 1 - norm.cdf(9.5, mu, sigma)
        p_ge12_by_mode[(variant, alph_name)] = 1 - norm.cdf(11.5, mu, sigma)

    # Compute P(score >= k) for each mode using Poisson-binomial via
    # recursive convolution (exact for 24 Bernoulli variables)
    mode_expected = {}
    for variant, alph_name in MODES:
        freq = freq_az if alph_name == "AZ" else freq_ka
        req_key = REQUIRED_KEYS[(variant, alph_name)]
        p_match = [freq[int(req_key[i])] for i in range(N_CRIBS)]

        # Exact Poisson-binomial PMF via recursive convolution
        # pmf[k] = P(exactly k matches)
        pmf = [1.0] + [0.0] * N_CRIBS
        for p in p_match:
            new_pmf = [0.0] * (N_CRIBS + 1)
            for k in range(N_CRIBS + 1):
                new_pmf[k] += pmf[k] * (1 - p)
                if k > 0:
                    new_pmf[k] += pmf[k - 1] * p
            pmf = new_pmf

        p_ge10 = sum(pmf[k] for k in range(10, N_CRIBS + 1))
        p_ge12 = sum(pmf[k] for k in range(12, N_CRIBS + 1))
        mode_expected[(variant, alph_name)] = (p_ge10, p_ge12)

    sum_p10 = sum(v[0] for v in mode_expected.values())
    T = total_10plus / sum_p10 if sum_p10 > 0 else 0

    for variant, alph_name in MODES:
        mode_key = f"{variant}_{alph_name}"
        p10, p12 = mode_expected[(variant, alph_name)]
        exp10 = T * p10
        exp12 = T * p12
        o10, o12 = obs.get((variant, alph_name), (0, 0))
        enr10 = o10 / exp10 if exp10 > 0.001 else 0
        enr12 = o12 / exp12 if exp12 > 0.001 else 0

        v2_conn.execute("""
            UPDATE ws_b_conditional_null SET
                expected_10plus=?, expected_12plus=?,
                enrichment_10=?, enrichment_12=?
            WHERE mode=?
        """, (exp10, exp12, enr10, enr12, mode_key))

    v2_conn.commit()
    v1.close()


# ── Workstream C: Structural audit ────────────────────────────────────────

def audit_v1_top_hits(v1_db_path, v2_conn):
    """Pull all score >= 12 hits from v1 and compute full structural audit."""
    v1 = sqlite3.connect(str(v1_db_path))

    rows = v1.execute("""
        SELECT source_id, source_path, transform, offset, variant, alphabet,
               score, pt, source_len
        FROM hits WHERE score >= 11 AND transform NOT LIKE 'skip_%'
        ORDER BY score DESC
        LIMIT 100
    """).fetchall()

    _load_quadgrams()

    for (source_id, source_path, transform, offset, variant, alph_name,
         score, pt_text, source_len) in rows:

        # Parse width from transform name
        width = 0
        if 'w' in transform:
            try:
                width = int(transform.split('w')[-1])
            except ValueError:
                pass

        matched = []
        failed = []
        ene_score = bcl_score = 0
        for pos, ch in CRIB_LIST:
            if pos < len(pt_text) and pt_text[pos] == ch:
                matched.append(pos)
                if 21 <= pos <= 33: ene_score += 1
                elif 63 <= pos <= 73: bcl_score += 1
            else:
                actual = pt_text[pos] if pos < len(pt_text) else "?"
                failed.append({"pos": pos, "exp": ch, "act": actual})

        bean_eq = 1 if pt_text[BEAN_EQ_POS[0]] == pt_text[BEAN_EQ_POS[1]] else 0

        alph_idx = AZ_IDX if alph_name == "AZ" else KA_IDX
        ct_nums = CT_AZ if alph_name == "AZ" else CT_KA
        pt_nums = [alph_idx[c] for c in pt_text]
        bean_fail_pairs = []
        for a, b in BEAN_INEQ:
            if variant == "vig":
                ka = (int(ct_nums[a]) - pt_nums[a]) % MOD
                kb = (int(ct_nums[b]) - pt_nums[b]) % MOD
            elif variant == "beau":
                ka = (int(ct_nums[a]) + pt_nums[a]) % MOD
                kb = (int(ct_nums[b]) + pt_nums[b]) % MOD
            else:
                ka = (pt_nums[a] - int(ct_nums[a])) % MOD
                kb = (pt_nums[b] - int(ct_nums[b])) % MOD
            if ka == kb:
                bean_fail_pairs.append((a, b))

        qg = quadgram_score(pt_text)

        v2_conn.execute(
            "INSERT INTO ws_c_audit VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            ('v1', source_id, transform, width, offset, variant, alph_name,
             score, ene_score, bcl_score,
             json.dumps(matched), json.dumps(failed),
             bean_eq, 242 - len(bean_fail_pairs), len(bean_fail_pairs),
             json.dumps(bean_fail_pairs),
             1 if 'NORTH' in pt_text else 0,
             1 if 'BERLI' in pt_text else 0,
             _longest_crib_run(matched),
             qg, pt_text)
        )

    v2_conn.commit()
    v1.close()


# ── Workstream D: Neighborhood persistence ─────────────────────────────────

def test_neighborhoods(v1_db_path, v2_conn):
    """For each v1 hit at score >= 12, test nearby widths and offsets."""
    v1 = sqlite3.connect(str(v1_db_path))

    seeds = v1.execute("""
        SELECT source_id, source_path, transform, offset, variant, alphabet, score
        FROM hits WHERE score >= 12 AND transform NOT LIKE 'skip_%'
        AND transform LIKE 'grid_colrev%'
        ORDER BY score DESC
    """).fetchall()

    for (source_id, source_path, transform, seed_offset, variant, alph_name,
         seed_score) in seeds:
        seed_width = int(transform.split('w')[-1])

        try:
            with open(source_path, 'r', errors='replace') as f:
                raw = f.read()
        except Exception:
            continue

        alpha = re.sub(r'[^A-Za-z]', '', raw).upper()
        L = len(alpha)
        if L < N:
            continue

        alph_idx = AZ_IDX if alph_name == "AZ" else KA_IDX
        src = np.frombuffer(bytes(alph_idx[c] for c in alpha), dtype=np.int8).copy()
        req_key = REQUIRED_KEYS[(variant, alph_name)]

        # Test widths seed-3..seed+3, offsets seed-500..seed+500 (step 1)
        for dw in range(-3, 4):
            test_width = seed_width + dw
            if test_width < 2:
                continue

            perm = make_grid_colrev_perm(L, test_width)
            perm_len = len(perm)
            if perm_len < N:
                continue

            for d_off in range(-500, 501, 1):
                test_off = seed_offset + d_off
                if test_off < 0 or test_off + N > perm_len:
                    continue

                score = sum(1 for ci in range(N_CRIBS)
                            if src[perm[test_off + _CRIB_POS_TUPLE[ci]]] == req_key[ci])

                # Store if score >= 6 (anything above pure noise)
                if score >= NOISE_FLOOR:
                    v2_conn.execute(
                        "INSERT INTO ws_d_neighborhood VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                        (source_id, seed_offset, seed_width, seed_score,
                         test_width, test_off, score, dw, d_off,
                         variant, alph_name)
                    )

    v2_conn.commit()
    v1.close()


# ── Reporting ──────────────────────────────────────────────────────────────

def generate_report(db_path, v1_db_path):
    conn = sqlite3.connect(str(db_path))

    print(f"{'='*72}")
    print(f"NON-LINEAR RUNNING KEY v2 — FOLLOW-UP REPORT")
    print(f"{'='*72}")

    # ── Workstream A: Targeted sweep ──
    print(f"\n{'─'*72}")
    print("WORKSTREAM A: TARGETED grid_colrev w28-35 SWEEP")
    print(f"{'─'*72}")

    completed = conn.execute("SELECT COUNT(*) FROM ws_a_completed").fetchone()[0]
    total_hits = conn.execute("SELECT COUNT(*) FROM ws_a_hits WHERE score >= 10").fetchone()[0]
    print(f"Sources completed: {completed}")
    print(f"Hits (score >= 10): {total_hits}")

    if total_hits > 0:
        print("\nScore distribution:")
        for row in conn.execute("SELECT score, COUNT(*) FROM ws_a_hits WHERE score >= 10 GROUP BY score ORDER BY score DESC").fetchall():
            print(f"  Score {row[0]:2d}: {row[1]:5d}")

        print("\nTop 10 hits:")
        for row in conn.execute("""
            SELECT score, width, variant, alphabet, source_id, offset, ene_score, bcl_score,
                   bean_eq, bean_ineq_fail, qg_score, pt
            FROM ws_a_hits WHERE score >= 10
            ORDER BY score DESC, bean_ineq_fail ASC LIMIT 10
        """).fetchall():
            score, w, var, alph, sid, off, ene, bcl, beq, bif, qg, pt = row
            print(f"  {score:2d}/24 w={w:2d} {var:6s} {alph} ENE={ene:2d}/13 BCL={bcl:2d}/11 "
                  f"Bean-iq-fail={bif:3d} qg={qg:.2f} {sid[:25]}")
            print(f"         PT: {pt[:55]}...")

        print("\nBy width:")
        for row in conn.execute("""
            SELECT width, COUNT(*) as n, MAX(score) as best
            FROM ws_a_hits WHERE score >= 10
            GROUP BY width ORDER BY best DESC, n DESC
        """).fetchall():
            print(f"  w={row[0]:2d}: {row[1]:5d} hits, best={row[2]:2d}")

    # ── Workstream B: Conditional null ──
    print(f"\n{'─'*72}")
    print("WORKSTREAM B: CONDITIONAL NULL ANALYSIS")
    print(f"{'─'*72}")

    rows = conn.execute("""
        SELECT mode, e_score, expected_10plus, observed_10plus, enrichment_10,
               expected_12plus, observed_12plus, enrichment_12
        FROM ws_b_conditional_null
        ORDER BY enrichment_12 DESC
    """).fetchall()
    if rows:
        print(f"\n  {'Mode':15s} {'E[score]':>8s} {'Exp10+':>8s} {'Obs10+':>8s} {'Enr10':>7s} "
              f"{'Exp12+':>8s} {'Obs12+':>8s} {'Enr12':>7s}")
        for mode, es, e10, o10, en10, e12, o12, en12 in rows:
            print(f"  {mode:15s} {es:8.2f} {e10:8.1f} {o10:8d} {en10:7.2f} "
                  f"{e12:8.2f} {o12:8d} {en12:7.2f}")
        print("\n  INTERPRETATION:")
        print("  Enrichment ~1.0 = consistent with null (mode-conditioned)")
        print("  Enrichment >>1.0 = genuinely enriched beyond English-frequency effects")
    else:
        print("  (not yet computed)")

    # ── Workstream C: Structural audit ──
    print(f"\n{'─'*72}")
    print("WORKSTREAM C: TOP-HIT STRUCTURAL AUDIT")
    print(f"{'─'*72}")

    audits = conn.execute("""
        SELECT score, source_id, transform, width, offset, variant, alphabet,
               ene_score, bcl_score, bean_eq, bean_ineq_fail,
               has_north, has_berli, longest_crib_run, qg_score
        FROM ws_c_audit WHERE score >= 12
        ORDER BY score DESC
    """).fetchall()
    if audits:
        for a in audits:
            sc, sid, tfm, w, off, var, alph, ene, bcl, beq, bif, north, berli, lcr, qg = a
            print(f"  {sc:2d}/24 {tfm:20s} {var} {alph} ENE={ene}/13 BCL={bcl}/11 "
                  f"Bean-iq-fail={bif} NORTH={'Y' if north else 'N'} BERLI={'Y' if berli else 'N'} "
                  f"crib-run={lcr} qg={qg:.2f}")
            print(f"         {sid[:50]}")

        # Bean failure pattern analysis
        print("\n  Bean inequality failure patterns among 12+ hits:")
        fail_patterns = conn.execute("""
            SELECT bean_ineq_failures FROM ws_c_audit WHERE score >= 12
        """).fetchall()
        all_fail_pairs = Counter()
        for (fp_json,) in fail_patterns:
            if fp_json:
                for pair in json.loads(fp_json):
                    all_fail_pairs[tuple(pair)] += 1
        if all_fail_pairs:
            print(f"  Most common failing pairs (across {len(fail_patterns)} candidates):")
            for pair, count in all_fail_pairs.most_common(10):
                print(f"    ({pair[0]:2d},{pair[1]:2d}): fails in {count}/{len(fail_patterns)} candidates")
    else:
        print("  (not yet computed)")

    # ── Workstream D: Neighborhood persistence ──
    print(f"\n{'─'*72}")
    print("WORKSTREAM D: NEIGHBORHOOD PERSISTENCE")
    print(f"{'─'*72}")

    seeds = conn.execute("""
        SELECT DISTINCT seed_source_id, seed_width, seed_offset, seed_score
        FROM ws_d_neighborhood ORDER BY seed_score DESC
    """).fetchall()
    if seeds:
        for sid, sw, soff, sscore in seeds:
            n_tested = conn.execute(
                "SELECT COUNT(*) FROM ws_d_neighborhood WHERE seed_source_id=? AND seed_offset=?",
                (sid, soff)).fetchone()[0]
            best_neighbor = conn.execute(
                "SELECT MAX(test_score) FROM ws_d_neighborhood WHERE seed_source_id=? AND seed_offset=? AND (delta_width!=0 OR delta_offset!=0)",
                (sid, soff)).fetchone()[0]
            n_above_seed = conn.execute(
                "SELECT COUNT(*) FROM ws_d_neighborhood WHERE seed_source_id=? AND seed_offset=? AND test_score>=? AND (delta_width!=0 OR delta_offset!=0)",
                (sid, soff, sscore)).fetchone()[0]
            avg_neighbor = conn.execute(
                "SELECT AVG(test_score) FROM ws_d_neighborhood WHERE seed_source_id=? AND seed_offset=? AND (delta_width!=0 OR delta_offset!=0)",
                (sid, soff)).fetchone()[0] or 0

            print(f"  Seed: {sid[:30]:30s} w={sw} off={soff} score={sscore}")
            print(f"    Neighbors tested: {n_tested}, best neighbor: {best_neighbor}, "
                  f"above seed: {n_above_seed}, avg neighbor: {avg_neighbor:.1f}")

            # Score heatmap by (delta_width, delta_offset_bucket)
            heatmap = conn.execute("""
                SELECT delta_width,
                    CASE WHEN delta_offset BETWEEN -10 AND 10 THEN 'near'
                         WHEN delta_offset BETWEEN -100 AND 100 THEN 'mid'
                         ELSE 'far' END as proximity,
                    MAX(test_score), AVG(test_score), COUNT(*)
                FROM ws_d_neighborhood
                WHERE seed_source_id=? AND seed_offset=?
                GROUP BY delta_width, proximity
                ORDER BY delta_width, proximity
            """, (sid, soff)).fetchall()
            if heatmap:
                print(f"    {'dw':>4s} {'zone':>5s} {'best':>5s} {'avg':>5s} {'n':>5s}")
                for dw, prox, best, avg, n in heatmap:
                    print(f"    {dw:>4d} {prox:>5s} {best:>5d} {avg:>5.1f} {n:>5d}")
            print()
    else:
        print("  (not yet computed)")

    # ── Workstream E: Width enrichment ──
    print(f"\n{'─'*72}")
    print("WORKSTREAM E: WIDTH ENRICHMENT (from Workstream A)")
    print(f"{'─'*72}")

    rows = conn.execute("""
        SELECT width, n_hits_10plus, best_score, expected_10plus, enrichment
        FROM ws_e_width_enrichment
        ORDER BY width
    """).fetchall()
    if rows:
        print(f"  {'Width':>5s} {'Hits10+':>8s} {'Best':>5s} {'Expected':>9s} {'Enrichment':>11s}")
        for w, n10, best, exp, enr in rows:
            flag = " <<<" if enr > 1.5 else ""
            print(f"  {w:>5d} {n10:>8d} {best:>5d} {exp:>9.1f} {enr:>11.2f}{flag}")
    else:
        print("  (not yet computed)")

    print(f"\n{'='*72}")
    print(f"Database: {db_path}")
    print(f"{'='*72}")
    conn.close()


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Non-linear RK v2 follow-up")
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--benchmark', action='store_true')
    parser.add_argument('--report', action='store_true')
    parser.add_argument('--resume', action='store_true')
    parser.add_argument('--workers', type=int, default=max(1, cpu_count() - 2))
    parser.add_argument('--limit', type=int, default=None)
    parser.add_argument('--gutenberg', type=str, default='/data/tmp/gutenberg_cache')
    parser.add_argument('--db', type=str, default=str(DB_PATH))
    parser.add_argument('--v1-db', type=str,
                        default=str(_ROOT / "db" / "nonlinear_rk_v1.sqlite"))
    parser.add_argument('--local-only', action='store_true')
    args = parser.parse_args()

    db_path = Path(args.db)
    v1_db_path = Path(args.v1_db)

    if args.report:
        generate_report(db_path, v1_db_path)
        return

    conn = init_db(db_path)

    # ── Phase 1: Workstreams B, C, D (fast, from v1 data) ──
    print("=" * 72, flush=True)
    print("PHASE 1: Analytical workstreams (B, C, D) from v1 data", flush=True)
    print("=" * 72, flush=True)

    if v1_db_path.exists():
        print("\nWorkstream B: Conditional null analysis...", flush=True)
        t0 = time.time()
        compute_conditional_nulls(v1_db_path, conn)
        print(f"  Done in {time.time()-t0:.1f}s", flush=True)

        print("\nWorkstream C: Structural audit of v1 top hits...", flush=True)
        t0 = time.time()
        audit_v1_top_hits(v1_db_path, conn)
        print(f"  Done in {time.time()-t0:.1f}s", flush=True)

        print("\nWorkstream D: Neighborhood persistence tests...", flush=True)
        t0 = time.time()
        test_neighborhoods(v1_db_path, conn)
        print(f"  Done in {time.time()-t0:.1f}s", flush=True)
    else:
        print(f"WARNING: v1 database not found at {v1_db_path}", flush=True)

    # ── Phase 2: Workstream A (targeted sweep, parallelized) ──
    print("\n" + "=" * 72, flush=True)
    print("PHASE 2: Workstream A — targeted grid_colrev w28-35 sweep", flush=True)
    print("=" * 72, flush=True)

    gutenberg_path = None if args.local_only else Path(args.gutenberg)
    if gutenberg_path and not gutenberg_path.is_dir():
        gutenberg_path = None

    limit = args.limit
    if args.dry_run:
        limit = 5
    elif args.benchmark:
        limit = 200

    sources = discover_sources(_ROOT, gutenberg_path, limit=limit)
    print(f"Discovered {len(sources)} sources", flush=True)
    print(f"Widths: {FOCUSED_WIDTHS}", flush=True)
    print(f"Workers: {args.workers}", flush=True)

    # Filter completed (resume)
    completed = set()
    if args.resume:
        completed = {r[0] for r in conn.execute("SELECT source_id FROM ws_a_completed").fetchall()}
        print(f"Resume: {len(completed)} already completed", flush=True)

    work_items = [(p, sid, FOCUSED_WIDTHS) for p, sid in sources if sid not in completed]
    print(f"Work items: {len(work_items)}", flush=True)

    # Create run record
    now = time.strftime('%Y-%m-%dT%H:%M:%S')
    cur = conn.execute("INSERT INTO v2_runs (started_at, config) VALUES (?, ?)",
                       (now, json.dumps({'widths': FOCUSED_WIDTHS, 'workers': args.workers,
                                         'limit': limit, 'n_sources': len(work_items)})))
    run_id = cur.lastrowid
    conn.commit()

    t0 = time.time()
    global_best = 0
    total_processed = 0
    total_hits = 0

    with Pool(processes=args.workers) as pool:
        for source_id, hits, error in pool.imap_unordered(
            ws_a_scan_source, work_items,
            chunksize=max(1, min(50, len(work_items) // args.workers))
        ):
            total_processed += 1
            store_hits = [h for h in hits if h['score'] >= 10]
            total_hits += len(store_hits)

            for h in store_hits:
                conn.execute(
                    "INSERT INTO ws_a_hits VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (run_id, h['source_id'], h['source_path'], h['width'], h['offset'],
                     h['variant'], h['alphabet'], h['score'], h['pt'],
                     h['bean_eq'], h['bean_ineq_pass'], h['bean_ineq_fail'],
                     h['ene_score'], h['bcl_score'], h['qg_score'], h['source_len']))

                if h['score'] > global_best:
                    global_best = h['score']
                    print(f"\n*** NEW BEST: {h['score']}/24 w={h['width']} "
                          f"{h['variant']} {h['alphabet']} {h['source_id'][:30]} "
                          f"off={h['offset']} ***", flush=True)

                # Also insert into audit table for v2 high-scorers
                if h['score'] >= 11:
                    conn.execute(
                        "INSERT INTO ws_c_audit VALUES (NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        ('v2', h['source_id'], f"grid_colrev_w{h['width']}",
                         h['width'], h['offset'], h['variant'], h['alphabet'],
                         h['score'], h['ene_score'], h['bcl_score'],
                         h['matched_positions'], h['failed_positions'],
                         h['bean_eq'], h['bean_ineq_pass'], h['bean_ineq_fail'],
                         h['bean_ineq_failures'],
                         h['has_north'], h['has_berli'], h['longest_crib_run'],
                         h['qg_score'], h['pt']))

            conn.execute("INSERT OR REPLACE INTO ws_a_completed VALUES (?,?,?)",
                         (source_id, run_id, time.strftime('%Y-%m-%dT%H:%M:%S')))
            conn.commit()

            if total_processed % 1000 == 0 or total_processed == len(work_items):
                elapsed = time.time() - t0
                rate = total_processed / elapsed if elapsed > 0 else 0
                eta = (len(work_items) - total_processed) / rate if rate > 0 else 0
                print(f"[{total_processed:>6d}/{len(work_items)}] {rate:.1f} src/s | "
                      f"hits={total_hits} best={global_best}/24 | "
                      f"elapsed={elapsed:.0f}s eta={eta:.0f}s", flush=True)

    # ── Phase 3: Width enrichment (Workstream E) ──
    print("\nWorkstream E: Width enrichment...", flush=True)
    total_a_hits = conn.execute("SELECT COUNT(*) FROM ws_a_hits WHERE score >= 10").fetchone()[0]
    n_widths = len(FOCUSED_WIDTHS)

    for w in FOCUSED_WIDTHS:
        n10 = conn.execute("SELECT COUNT(*) FROM ws_a_hits WHERE width=? AND score>=10", (w,)).fetchone()[0]
        n11 = conn.execute("SELECT COUNT(*) FROM ws_a_hits WHERE width=? AND score>=11", (w,)).fetchone()[0]
        n12 = conn.execute("SELECT COUNT(*) FROM ws_a_hits WHERE width=? AND score>=12", (w,)).fetchone()[0]
        best = conn.execute("SELECT MAX(score) FROM ws_a_hits WHERE width=?", (w,)).fetchone()[0] or 0
        # Expected under uniform: each width gets 1/n_widths of hits
        exp10 = total_a_hits / n_widths if n_widths > 0 else 0
        enr = n10 / exp10 if exp10 > 0 else 0
        conn.execute("INSERT OR REPLACE INTO ws_e_width_enrichment VALUES (?,?,?,?,?,?,?)",
                     (w, n10, n11, n12, best, exp10, enr))
    conn.commit()

    # Finalize
    elapsed = time.time() - t0
    conn.execute("UPDATE v2_runs SET status='completed' WHERE run_id=?", (run_id,))
    conn.commit()

    print(f"\n{'='*72}", flush=True)
    print(f"v2 COMPLETE: {total_processed} sources, {total_hits} hits, best={global_best}/24, "
          f"elapsed={elapsed:.0f}s", flush=True)
    print(f"{'='*72}\n", flush=True)

    generate_report(db_path, v1_db_path)
    conn.close()


if __name__ == '__main__':
    main()
