#!/usr/bin/env python3
"""
Cipher: multi-vector campaign
Family: campaigns
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-MARATHON-01 — 24-Hour Final Assault on K4.

260+ experiments, 669B+ configs, all noise. This is the largest single K4
computation ever attempted: 4 phases, ~504B SA iterations, plus exhaustive
columnar and fast triage of untested hypotheses.

Phase 0: Quick Triage (~30 min) — grid rotation, tableau keys, K1-K3 running key, DRYAD
Phase 1: Width-9+ Columnar Exhaustive (~3 hr) — strongest structural hypothesis
Phase 2: Massive SA Campaign (~18 hr) — 100,800 restarts × 5M iterations
Phase 3: Deep Dive (~1.5 hr) — polish top 1000 candidates

Usage:
  PYTHONPATH=src python3 -u scripts/e_marathon_01_final_assault.py --workers 28
  PYTHONPATH=src python3 -u scripts/e_marathon_01_final_assault.py --workers 28 --resume
  PYTHONPATH=src python3 -u scripts/e_marathon_01_final_assault.py --workers 28 --phase 2
"""
from __future__ import annotations

import argparse
import json
import math
import multiprocessing as mp
import os
import signal
import sqlite3
import sys
import time
from dataclasses import asdict, dataclass, field
from itertools import permutations
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from kryptos.kernel.constants import (
    ALPH, ALPH_IDX, CT, CT_LEN, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    KRYPTOS_ALPHABET,
)

# ═══════════════════════════════════════════════════════════════════════════
# Global constants
# ═══════════════════════════════════════════════════════════════════════════

N = CT_LEN  # 97
CT_INT = np.array([ALPH_IDX[c] for c in CT], dtype=np.int8)
CRIB_POS = np.array(sorted(CRIB_DICT.keys()), dtype=np.int32)
CRIB_VAL = np.array([ALPH_IDX[CRIB_DICT[p]] for p in sorted(CRIB_DICT.keys())], dtype=np.int8)
BEAN_EQ_A = np.array([a for a, _ in BEAN_EQ], dtype=np.int32)
BEAN_EQ_B = np.array([b for _, b in BEAN_EQ], dtype=np.int32)
BEAN_INEQ_A = np.array([a for a, _ in BEAN_INEQ], dtype=np.int32)
BEAN_INEQ_B = np.array([b for _, b in BEAN_INEQ], dtype=np.int32)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results" / "marathon_01"
CHECKPOINT_PATH = RESULTS_DIR / "checkpoint.json"
DB_PATH = RESULTS_DIR / "marathon.sqlite"
QUADGRAM_PATH = PROJECT_ROOT / "data" / "english_quadgrams.json"
WORDLIST_PATH = PROJECT_ROOT / "wordlists" / "english.txt"
THEMATIC_KW_PATH = PROJECT_ROOT / "wordlists" / "thematic_keywords.txt"
PROGRESS_LOG = RESULTS_DIR / "progress.log"

# Sculpture texts (PUBLIC FACT)
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCRTBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUABOROFDARKNESS"
K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELD"
    "XTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATION"
    "XDOESLANGLEYKNOWABOUTTHISTHEYSHOULDITSBURIEDOUTTHERESOMEWHEREXWHOKNOWS"
    "THEEXACTLOCATIONONLYWWTHISISHISTLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTY"
    "SEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHTMINUTES"
    "FORTYFOURSECONDSWESTXLAYERTWO"
)
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFJPASSAGEDEBABORETURNST"
    "OTHEEARLIESTTASKWASENTALANTSANDHOWTESIDWALLSITTWASFORCED"
    "HEWALLSLOWLYWERECAVINGINTHEYWEREONLYABLETONOTREADITVERYC"
    "LEARLYWASTHEREACHAROOMBEYONDTHECHAMBERQCANYOUSEEANYTHINGQ"
)

_shutdown = False


def _signal_handler(signum, frame):
    global _shutdown
    _shutdown = True
    print(f"\n[SHUTDOWN] Signal {signum} received, finishing current batch...", flush=True)


# ═══════════════════════════════════════════════════════════════════════════
# Quadgram LUT (numpy, process-global)
# ═══════════════════════════════════════════════════════════════════════════

QUADGRAM_LUT = None
LONG_WORDS = None


def load_quadgrams():
    global QUADGRAM_LUT
    with open(QUADGRAM_PATH) as f:
        qdata = json.load(f)
    floor_val = min(qdata.values()) - 1.0
    QUADGRAM_LUT = np.full(26 ** 4, floor_val, dtype=np.float32)
    for qgram, logp in qdata.items():
        if len(qgram) == 4 and qgram.isalpha():
            idx = (ALPH_IDX[qgram[0]] * 17576 +
                   ALPH_IDX[qgram[1]] * 676 +
                   ALPH_IDX[qgram[2]] * 26 +
                   ALPH_IDX[qgram[3]])
            QUADGRAM_LUT[idx] = logp


def load_dictionary():
    global LONG_WORDS
    LONG_WORDS = set()
    with open(WORDLIST_PATH) as f:
        for line in f:
            w = line.strip().upper()
            if len(w) >= 7:
                LONG_WORDS.add(w)


def _ensure_resources():
    if QUADGRAM_LUT is None:
        load_quadgrams()
    if LONG_WORDS is None:
        load_dictionary()


# ═══════════════════════════════════════════════════════════════════════════
# Core numpy helpers (shared by all phases)
# ═══════════════════════════════════════════════════════════════════════════

def quadgram_score_fast(pt_int: np.ndarray) -> float:
    p = pt_int.astype(np.int32)
    indices = p[:-3] * 17576 + p[1:-2] * 676 + p[2:-1] * 26 + p[3:]
    return float(np.sum(QUADGRAM_LUT[indices]))


def calc_ic(pt_int: np.ndarray) -> float:
    n = len(pt_int)
    if n < 2:
        return 0.0
    counts = np.bincount(pt_int.astype(np.int32), minlength=26)
    return float(np.sum(counts * (counts - 1))) / (n * (n - 1))


def decrypt_sa(sigma_inv: np.ndarray, key: np.ndarray) -> np.ndarray:
    """PT[j] = (CT[sigma_inv[j]] - K[sigma_inv[j]]) mod 26."""
    ct_reord = CT_INT[sigma_inv]
    k_reord = key[sigma_inv]
    return (ct_reord - k_reord) % 26


def crib_score(pt_int: np.ndarray) -> int:
    return int(np.sum(pt_int[CRIB_POS] == CRIB_VAL))


def bean_check(key: np.ndarray) -> bool:
    eq_ok = bool(np.all(key[BEAN_EQ_A] == key[BEAN_EQ_B]))
    ineq_ok = bool(np.all(key[BEAN_INEQ_A] != key[BEAN_INEQ_B]))
    return eq_ok and ineq_ok


def count_dict_words(pt_str: str) -> int:
    found = set()
    for wlen in range(7, min(20, len(pt_str) + 1)):
        for i in range(len(pt_str) - wlen + 1):
            sub = pt_str[i:i + wlen]
            if sub in LONG_WORDS:
                found.add(sub)
    return len(found)


def int_to_text(vals) -> str:
    return "".join(chr((v % 26) + 65) for v in vals)


def text_to_int(text: str) -> List[int]:
    return [ALPH_IDX[c] for c in text.upper() if c in ALPH_IDX]


def score_free_fast(text: str) -> int:
    """Position-free crib score: 0/11/13/24."""
    t = text.upper()
    s = 0
    if "EASTNORTHEAST" in t:
        s += 13
    if "BERLINCLOCK" in t:
        s += 11
    return s


# ═══════════════════════════════════════════════════════════════════════════
# Database
# ═══════════════════════════════════════════════════════════════════════════

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
            crib_score INTEGER NOT NULL,
            crib_free INTEGER DEFAULT 0,
            qg_per_char REAL,
            ic REAL,
            bean_pass INTEGER NOT NULL DEFAULT 0,
            dict_words INTEGER DEFAULT 0,
            config TEXT,
            plaintext TEXT,
            sigma_inv TEXT,
            key_vals TEXT,
            timestamp REAL NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_crib ON candidates(crib_score DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_qg ON candidates(qg_per_char DESC)")
    conn.commit()
    conn.close()


def store_candidate(
    phase: int, phase_name: str, model: str,
    cribs: int, crib_free: int, qg_pc: float, ic_val: float,
    bean: bool, dict_words: int, config: dict, pt: str,
    sigma_inv: Optional[str] = None, key_vals: Optional[str] = None,
) -> None:
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=10.0)
        conn.execute(
            "INSERT INTO candidates "
            "(phase, phase_name, model, crib_score, crib_free, qg_per_char, "
            "ic, bean_pass, dict_words, config, plaintext, sigma_inv, key_vals, timestamp) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (phase, phase_name, model, cribs, crib_free, qg_pc, ic_val,
             int(bean), dict_words, json.dumps(config), pt, sigma_inv, key_vals, time.time()),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════
# Checkpoint
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class Checkpoint:
    phases_done: List[int] = field(default_factory=list)
    sa_seeds_done: int = 0
    phase1_done: bool = False
    top_candidates: List[Dict[str, Any]] = field(default_factory=list)
    total_configs: int = 0
    start_time: float = 0.0

    def save(self) -> None:
        CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = CHECKPOINT_PATH.with_suffix(".tmp")
        with open(tmp, "w") as f:
            json.dump(asdict(self), f, indent=2)
        tmp.rename(CHECKPOINT_PATH)

    @classmethod
    def load(cls) -> "Checkpoint":
        if CHECKPOINT_PATH.exists():
            with open(CHECKPOINT_PATH) as f:
                d = json.load(f)
            return cls(**d)
        return cls(start_time=time.time())

    def add_candidate(self, cand: Dict[str, Any]) -> None:
        self.top_candidates.append(cand)
        self.top_candidates.sort(
            key=lambda x: (-x.get("crib_score", 0), -x.get("qg_per_char", -99))
        )
        self.top_candidates = self.top_candidates[:1000]


# ═══════════════════════════════════════════════════════════════════════════
# Progress logging
# ═══════════════════════════════════════════════════════════════════════════

def log_progress(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}\n"
    print(line.rstrip(), flush=True)
    try:
        with open(PROGRESS_LOG, "a") as f:
            f.write(line)
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 0: Quick Triage
# ═══════════════════════════════════════════════════════════════════════════

def _decrypt_with_key(ct_ints: List[int], key_ints: List[int], variant: str) -> List[int]:
    """Decrypt ct with key using given variant. Returns PT ints."""
    n = min(len(ct_ints), len(key_ints))
    pt = []
    for i in range(n):
        c, k = ct_ints[i], key_ints[i]
        if variant == "vig":
            pt.append((c - k) % 26)
        elif variant == "beau":
            pt.append((k - c) % 26)
        else:  # varbeau
            pt.append((c + k) % 26)
    return pt


def phase0_grid_rotation(ct_ints: List[int]) -> List[Dict]:
    """Phase 0A: Grid rotation — all grids fitting 97±1, 4 rotations, read orders."""
    results = []
    n = len(ct_ints)

    # Grid dimensions where rows*cols >= n and rows*cols <= n+1
    grids = []
    for r in range(2, n):
        for c in range(2, n):
            prod = r * c
            if n <= prod <= n + 1:
                grids.append((r, c))
            if prod > n + 1:
                break

    for rows, cols in grids:
        prod = rows * cols
        # For each padding position (if prod > n, we insert a pad char)
        pad_positions = [None] if prod == n else list(range(prod))

        for pad_pos in pad_positions:
            # Build padded text
            if pad_pos is None:
                padded = list(ct_ints)
            else:
                padded = list(ct_ints[:pad_pos]) + [0] + list(ct_ints[pad_pos:])
                padded = padded[:prod]

            # Fill grid
            grid = []
            idx = 0
            for r in range(rows):
                row = []
                for c in range(cols):
                    row.append(padded[idx] if idx < len(padded) else 0)
                    idx += 1
                grid.append(row)

            # 4 rotations × 2 read directions
            for rot in range(4):
                g = [row[:] for row in grid]
                for _ in range(rot):
                    g = list(zip(*g[::-1]))  # 90° CW rotation

                act_rows = len(g)
                act_cols = len(g[0]) if act_rows > 0 else 0

                for read_dir in ("lr", "rl"):
                    flat = []
                    for ri in range(act_rows):
                        if read_dir == "lr":
                            flat.extend(g[ri])
                        else:
                            flat.extend(reversed(g[ri]))

                    # Remove padding position
                    if pad_pos is not None:
                        # Position moved by rotation — just take first n
                        flat = [int(v) for v in flat[:n]]
                    else:
                        flat = [int(v) for v in flat[:n]]

                    if len(flat) != n:
                        continue

                    # This IS the transposed CT. Now decrypt with each variant.
                    for variant in ("vig", "beau", "varbeau"):
                        for alph_name, alph in (("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)):
                            # For grid rotation, treat as pure transposition: no key
                            # Just score the reordered text
                            pt_str = "".join(chr(v + 65) for v in flat)
                            pt_arr = np.array(flat, dtype=np.int8)

                            cs = crib_score(pt_arr)
                            cs_free = score_free_fast(pt_str)

                            if cs >= 10 or cs_free >= 11:
                                qg = quadgram_score_fast(pt_arr) / n
                                ic_val = calc_ic(pt_arr)
                                results.append({
                                    "method": "grid_rotation",
                                    "grid": f"{rows}x{cols}",
                                    "rotation": rot * 90,
                                    "read_dir": read_dir,
                                    "pad_pos": pad_pos,
                                    "variant": variant,
                                    "alphabet": alph_name,
                                    "crib_score": cs,
                                    "crib_free": cs_free,
                                    "qg_per_char": qg,
                                    "ic": ic_val,
                                    "plaintext": pt_str[:50],
                                })

            if _shutdown:
                return results

    return results


def phase0_tableau_keys(ct_ints: List[int]) -> List[Dict]:
    """Phase 0B: Read KA tableau in various orders as running key."""
    results = []
    tab = []
    for r in range(26):
        row = [(ALPH_IDX[KRYPTOS_ALPHABET[(r + c) % 26]]) for c in range(26)]
        tab.append(row)

    # Key sources from tableau
    keys = {}
    # Main diagonal
    keys["main_diag"] = [tab[i][i] for i in range(26)]
    # Anti-diagonal
    keys["anti_diag"] = [tab[i][25 - i] for i in range(26)]
    # Offset diagonals
    for off in range(1, 26):
        keys[f"diag_off{off}"] = [tab[i][(i + off) % 26] for i in range(26)]
    # Row reads
    for r in range(26):
        keys[f"row{r}"] = tab[r]
    # Column reads
    for c in range(26):
        keys[f"col{c}"] = [tab[r][c] for r in range(26)]
    # Spiral (simplified: row-by-row full tableau)
    full_rows = []
    for r in range(26):
        full_rows.extend(tab[r])
    keys["full_rows"] = full_rows
    # Column-by-column
    full_cols = []
    for c in range(26):
        for r in range(26):
            full_cols.append(tab[r][c])
    keys["full_cols"] = full_cols

    n = len(ct_ints)
    for key_name, key_vals in keys.items():
        # Extend key to >= n by cycling
        ext_key = (key_vals * ((n // len(key_vals)) + 2))[:n]

        for variant in ("vig", "beau", "varbeau"):
            pt = _decrypt_with_key(ct_ints, ext_key, variant)
            pt_arr = np.array(pt, dtype=np.int8)
            pt_str = int_to_text(pt)

            cs = crib_score(pt_arr)
            cs_free = score_free_fast(pt_str)

            if cs >= 10 or cs_free >= 11:
                qg = quadgram_score_fast(pt_arr) / n
                ic_val = calc_ic(pt_arr)
                results.append({
                    "method": "tableau_key",
                    "key_source": key_name,
                    "variant": variant,
                    "crib_score": cs,
                    "crib_free": cs_free,
                    "qg_per_char": qg,
                    "ic": ic_val,
                    "plaintext": pt_str[:50],
                })

            # Also try with offsets into the key
            for offset in range(1, min(len(key_vals), 26)):
                shifted = (key_vals * 4)[offset:offset + n]
                if len(shifted) < n:
                    continue
                pt2 = _decrypt_with_key(ct_ints, shifted, variant)
                pt2_arr = np.array(pt2, dtype=np.int8)
                pt2_str = int_to_text(pt2)
                cs2 = crib_score(pt2_arr)
                cs2_free = score_free_fast(pt2_str)
                if cs2 >= 10 or cs2_free >= 11:
                    qg2 = quadgram_score_fast(pt2_arr) / n
                    results.append({
                        "method": "tableau_key",
                        "key_source": f"{key_name}+{offset}",
                        "variant": variant,
                        "crib_score": cs2,
                        "crib_free": cs2_free,
                        "qg_per_char": qg2,
                        "plaintext": pt2_str[:50],
                    })

        if _shutdown:
            return results

    return results


def phase0_known_plaintext_keys(ct_ints: List[int]) -> List[Dict]:
    """Phase 0C: K1/K2/K3 plaintexts as running keys."""
    results = []
    n = len(ct_ints)

    sources = {
        "K1_PT": K1_PT,
        "K2_PT": K2_PT,
        "K3_PT": K3_PT,
        "K1K2K3_PT": K1_PT + K2_PT + K3_PT,
        "K3K1K2_PT": K3_PT + K1_PT + K2_PT,
        "K1_CT": K1_CT,
        "K2_CT": K2_CT,
        "K3_CT": K3_CT,
        "ANTIPODES_CT": K3_CT + CT + K1_CT + K2_CT,
        "KRYPTOS_CT": K1_CT + K2_CT + K3_CT + CT,
    }

    for src_name, src_text in sources.items():
        key_full = text_to_int(src_text)
        if not key_full:
            continue
        max_offset = max(1, len(key_full) - n + 1)

        for offset in range(max_offset):
            key_slice = key_full[offset:offset + n]
            if len(key_slice) < n:
                # Cycle
                key_slice = (key_full * ((n // len(key_full)) + 2))[offset:offset + n]

            for variant in ("vig", "beau", "varbeau"):
                pt = _decrypt_with_key(ct_ints, key_slice, variant)
                pt_arr = np.array(pt, dtype=np.int8)
                pt_str = int_to_text(pt)

                cs = crib_score(pt_arr)
                cs_free = score_free_fast(pt_str)

                if cs >= 10 or cs_free >= 11:
                    qg = quadgram_score_fast(pt_arr) / n
                    ic_val = calc_ic(pt_arr)
                    results.append({
                        "method": "known_pt_key",
                        "source": src_name,
                        "offset": offset,
                        "variant": variant,
                        "crib_score": cs,
                        "crib_free": cs_free,
                        "qg_per_char": qg,
                        "ic": ic_val,
                        "plaintext": pt_str[:50],
                    })

        if _shutdown:
            return results

    return results


def phase0_dryad(ct_ints: List[int]) -> List[Dict]:
    """Phase 0D: 2D DRYAD lookup using K1/K2/K3 plaintext in a grid."""
    results = []
    n = len(ct_ints)

    sources = {
        "K1_PT": text_to_int(K1_PT),
        "K2_PT": text_to_int(K2_PT),
        "K3_PT": text_to_int(K3_PT),
        "ALL_PT": text_to_int(K1_PT + K2_PT + K3_PT),
    }

    for src_name, src_vals in sources.items():
        if len(src_vals) < 26:
            continue

        # Build grid: 26 rows × (len/26) cols
        ncols = len(src_vals) // 26
        if ncols < 1:
            continue

        for alph_name, row_alph in (("AZ", ALPH), ("KA", KRYPTOS_ALPHABET)):
            row_idx = {ALPH_IDX[c]: i for i, c in enumerate(row_alph)}

            for col_mod in range(1, min(ncols + 1, 50)):
                pt = []
                valid = True
                for i in range(n):
                    ct_char = ct_ints[i]
                    r = row_idx.get(ct_char)
                    if r is None or r >= 26:
                        valid = False
                        break
                    c = i % col_mod
                    if c >= ncols:
                        c = c % ncols
                    grid_idx = r * ncols + c
                    if grid_idx >= len(src_vals):
                        valid = False
                        break
                    pt.append(src_vals[grid_idx])

                if not valid or len(pt) != n:
                    continue

                pt_arr = np.array(pt, dtype=np.int8)
                pt_str = int_to_text(pt)
                cs = crib_score(pt_arr)
                cs_free = score_free_fast(pt_str)

                if cs >= 10 or cs_free >= 11:
                    qg = quadgram_score_fast(pt_arr) / n
                    results.append({
                        "method": "dryad",
                        "source": src_name,
                        "alphabet": alph_name,
                        "col_mod": col_mod,
                        "crib_score": cs,
                        "crib_free": cs_free,
                        "qg_per_char": qg,
                        "plaintext": pt_str[:50],
                    })

        if _shutdown:
            return results

    return results


def run_phase0(ckpt: Checkpoint) -> None:
    """Run Phase 0: Quick Triage of untested hypotheses."""
    if 0 in ckpt.phases_done:
        log_progress("Phase 0 already done, skipping.")
        return

    log_progress("=== PHASE 0: Quick Triage ===")
    _ensure_resources()
    ct_ints = [ALPH_IDX[c] for c in CT]
    all_results = []
    configs_tested = 0

    # 0A: Grid Rotation
    log_progress("Phase 0A: Grid Rotation...")
    t0 = time.time()
    grid_results = phase0_grid_rotation(ct_ints)
    configs_tested += 50000  # approximate
    log_progress(f"  Grid rotation: {len(grid_results)} hits from ~50K configs ({time.time()-t0:.1f}s)")
    all_results.extend(grid_results)

    if not _shutdown:
        # 0B: Tableau Keys
        log_progress("Phase 0B: Tableau-Derived Keys...")
        t0 = time.time()
        tab_results = phase0_tableau_keys(ct_ints)
        configs_tested += 500
        log_progress(f"  Tableau keys: {len(tab_results)} hits ({time.time()-t0:.1f}s)")
        all_results.extend(tab_results)

    if not _shutdown:
        # 0C: Known Plaintext Keys
        log_progress("Phase 0C: K1/K2/K3 Running Keys...")
        t0 = time.time()
        pt_results = phase0_known_plaintext_keys(ct_ints)
        configs_tested += 200
        log_progress(f"  Known PT keys: {len(pt_results)} hits ({time.time()-t0:.1f}s)")
        all_results.extend(pt_results)

    if not _shutdown:
        # 0D: DRYAD
        log_progress("Phase 0D: DRYAD Lookup...")
        t0 = time.time()
        dryad_results = phase0_dryad(ct_ints)
        configs_tested += 2000
        log_progress(f"  DRYAD: {len(dryad_results)} hits ({time.time()-t0:.1f}s)")
        all_results.extend(dryad_results)

    # Store results
    for r in all_results:
        store_candidate(
            phase=0, phase_name=r.get("method", "phase0"),
            model=r.get("variant", ""), cribs=r.get("crib_score", 0),
            crib_free=r.get("crib_free", 0),
            qg_pc=r.get("qg_per_char", -99.0), ic_val=r.get("ic", 0.0),
            bean=False, dict_words=0, config=r, pt=r.get("plaintext", ""),
        )
        ckpt.add_candidate(r)

    # Save triage JSON
    triage_path = RESULTS_DIR / "phase0_triage.json"
    with open(triage_path, "w") as f:
        json.dump({"total_configs": configs_tested, "hits": all_results,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")}, f, indent=2)

    ckpt.total_configs += configs_tested
    ckpt.phases_done.append(0)
    ckpt.save()
    log_progress(f"Phase 0 DONE: {configs_tested} configs, {len(all_results)} hits stored.")


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1: Width-9+ Columnar Exhaustive
# ═══════════════════════════════════════════════════════════════════════════

def columnar_perm_local(col_order: List[int], width: int, length: int = N) -> List[int]:
    """Build columnar transposition permutation. output[i] = input[perm[i]]."""
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


def _p1_running_key_worker(args) -> List[Dict]:
    """Test a batch of columnar orderings with running key model."""
    width, orders_batch, model, batch_id = args
    _ensure_resources()

    ct_int_list = [ALPH_IDX[c] for c in CT]
    crib_pos_set = set(CRIB_DICT.keys())
    crib_pt = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
    hits = []

    for order in orders_batch:
        order = list(order)
        sigma = columnar_perm_local(order, width)

        for model_name in ("A", "B"):
            # Model A: sub then trans → CT = trans(sub(PT))
            #   To decrypt: PT = sub_inv(trans_inv(CT))
            #   trans_inv maps CT positions back to intermediate positions
            #   At crib position j in PT: intermediate[j] = sub(PT[j])
            #   CT[sigma[j]] = intermediate[j] for model A (sub->trans means
            #   we first substitute, then columnar. So the columnar reads from
            #   the substituted text.)
            #
            # Model B: trans then sub → CT = sub(trans(PT))
            #   Columnar first on PT, then substitute.
            #   CT[i] = sub(trans(PT)[i])
            #   trans(PT)[i] = PT[trans_inv[i]] = PT[sigma_inv[i]]

            for variant in ("vig", "beau", "varbeau"):
                # Derive key at crib positions
                key_known = {}  # position -> key value
                inconsistent = False

                if model_name == "A":
                    # CT[sigma[j]] = encrypt(PT[j], K[j])
                    # For vig: CT[sigma[j]] = (PT[j] + K[j]) mod 26
                    #   K[j] = (CT[sigma[j]] - PT[j]) mod 26
                    for j in sorted(crib_pos_set):
                        ct_val = ct_int_list[sigma[j]]
                        pt_val = crib_pt[j]
                        if variant == "vig":
                            k = (ct_val - pt_val) % 26
                        elif variant == "beau":
                            k = (ct_val + pt_val) % 26
                        else:
                            k = (pt_val - ct_val) % 26
                        key_known[j] = k
                else:
                    # Model B: CT[i] = encrypt(PT[sigma_inv[i]], K[i])
                    # So for a crib position j in PT, we need sigma[j] = i
                    # CT[sigma[j]] = encrypt(PT[j], K[sigma[j]])
                    for j in sorted(crib_pos_set):
                        i = sigma[j]
                        ct_val = ct_int_list[i]
                        pt_val = crib_pt[j]
                        if variant == "vig":
                            k = (ct_val - pt_val) % 26
                        elif variant == "beau":
                            k = (ct_val + pt_val) % 26
                        else:
                            k = (pt_val - ct_val) % 26
                        key_known[i] = k

                # Check Bean constraints on known key values
                # Bean EQ: k[27] == k[65]
                k27 = key_known.get(27)
                k65 = key_known.get(65)
                if k27 is not None and k65 is not None and k27 != k65:
                    continue
                # Bean INEQ
                bean_fail = False
                for a, b in BEAN_INEQ:
                    ka = key_known.get(a)
                    kb = key_known.get(b)
                    if ka is not None and kb is not None and ka == kb:
                        bean_fail = True
                        break
                if bean_fail:
                    continue

                # Build full key: known positions fixed, unknown = 0
                full_key = [0] * N
                for pos, val in key_known.items():
                    full_key[pos] = val

                # Decrypt full plaintext
                pt_ints = [0] * N
                if model_name == "A":
                    for j in range(N):
                        ct_val = ct_int_list[sigma[j]]
                        if variant == "vig":
                            pt_ints[j] = (ct_val - full_key[j]) % 26
                        elif variant == "beau":
                            pt_ints[j] = (full_key[j] - ct_val) % 26
                        else:
                            pt_ints[j] = (ct_val + full_key[j]) % 26
                else:
                    for j in range(N):
                        i = sigma[j]
                        ct_val = ct_int_list[i]
                        if variant == "vig":
                            pt_ints[j] = (ct_val - full_key[i]) % 26
                        elif variant == "beau":
                            pt_ints[j] = (full_key[i] - ct_val) % 26
                        else:
                            pt_ints[j] = (ct_val + full_key[i]) % 26

                pt_arr = np.array(pt_ints, dtype=np.int8)
                pt_str = int_to_text(pt_ints)

                # Score
                cs = crib_score(pt_arr)
                cs_free = score_free_fast(pt_str)
                qg = quadgram_score_fast(pt_arr) / N

                if cs >= 20 or qg > -4.0 or cs_free >= 13:
                    ic_val = calc_ic(pt_arr)
                    dw = count_dict_words(pt_str)
                    hits.append({
                        "width": width,
                        "order": order,
                        "model": model_name,
                        "variant": variant,
                        "crib_score": cs,
                        "crib_free": cs_free,
                        "qg_per_char": qg,
                        "ic": ic_val,
                        "dict_words": dw,
                        "plaintext": pt_str,
                        "key_known": {str(k): v for k, v in key_known.items()},
                    })

    return hits


def run_phase1(ckpt: Checkpoint, n_workers: int) -> None:
    """Run Phase 1: Width-9+ Columnar Exhaustive with running key."""
    if 1 in ckpt.phases_done:
        log_progress("Phase 1 already done, skipping.")
        return

    log_progress("=== PHASE 1: Width-9+ Columnar Exhaustive ===")
    _ensure_resources()
    workers = max(1, min(n_workers, 14))
    all_hits = []
    total_configs = 0
    t_start = time.time()

    # Width 7-9: full permutation enumeration with running key
    for width in (7, 8, 9):
        if _shutdown:
            break

        n_perms = math.factorial(width)
        log_progress(f"  Width {width}: {n_perms} orderings × 2 models × 3 variants = {n_perms * 6} configs")

        all_orders = list(permutations(range(width)))
        batch_size = max(1, len(all_orders) // (workers * 4))
        batches = []
        for i in range(0, len(all_orders), batch_size):
            chunk = all_orders[i:i + batch_size]
            batches.append((width, chunk, "running_key", len(batches)))

        with mp.Pool(workers) as pool:
            results = pool.map(_p1_running_key_worker, batches)

        for batch_hits in results:
            all_hits.extend(batch_hits)
        total_configs += n_perms * 6

        log_progress(f"    Width {width} done: {len(all_hits)} cumulative hits ({time.time()-t_start:.0f}s)")

    # Width 10-13: keyword-based orderings with running key
    if not _shutdown:
        keywords = []
        try:
            with open(THEMATIC_KW_PATH) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        keywords.append(line.upper())
        except FileNotFoundError:
            log_progress("  WARNING: thematic_keywords.txt not found, skipping width 10-13")
            keywords = []

        for width in (10, 11, 12, 13):
            if _shutdown:
                break

            # Generate unique orderings from keywords of matching length
            seen_orders = set()
            kw_orders = []
            for kw in keywords:
                if len(kw) >= width:
                    # Take first 'width' chars, compute order
                    sub = kw[:width]
                    indexed = sorted(enumerate(sub), key=lambda x: (x[1], x[0]))
                    order = [0] * width
                    for rank, (orig_pos, _) in enumerate(indexed):
                        order[orig_pos] = rank
                    ot = tuple(order)
                    if ot not in seen_orders:
                        seen_orders.add(ot)
                        kw_orders.append(ot)

            if not kw_orders:
                continue

            log_progress(f"  Width {width}: {len(kw_orders)} keyword orderings × 6 = {len(kw_orders) * 6} configs")

            batch_size = max(1, len(kw_orders) // (workers * 2))
            batches = []
            for i in range(0, len(kw_orders), batch_size):
                chunk = kw_orders[i:i + batch_size]
                batches.append((width, chunk, "keyword_running_key", len(batches)))

            with mp.Pool(workers) as pool:
                results = pool.map(_p1_running_key_worker, batches)

            for batch_hits in results:
                all_hits.extend(batch_hits)
            total_configs += len(kw_orders) * 6

            log_progress(f"    Width {width} done: {len(all_hits)} cumulative hits ({time.time()-t_start:.0f}s)")

    # Store hits
    for h in all_hits:
        store_candidate(
            phase=1, phase_name="columnar_running_key",
            model=f"w{h['width']}_{h['model']}_{h['variant']}",
            cribs=h["crib_score"], crib_free=h.get("crib_free", 0),
            qg_pc=h["qg_per_char"], ic_val=h.get("ic", 0.0),
            bean=True, dict_words=h.get("dict_words", 0),
            config=h, pt=h["plaintext"],
        )
        ckpt.add_candidate(h)

    # Save JSON
    p1_path = RESULTS_DIR / "phase1_columnar.json"
    with open(p1_path, "w") as f:
        json.dump({"total_configs": total_configs, "hits": all_hits[:500],
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")}, f, indent=2)

    ckpt.total_configs += total_configs
    ckpt.phases_done.append(1)
    ckpt.save()
    elapsed = time.time() - t_start
    log_progress(f"Phase 1 DONE: {total_configs} configs, {len(all_hits)} hits, {elapsed:.0f}s")


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: Massive SA Campaign
# ═══════════════════════════════════════════════════════════════════════════

def _make_initial_state(restart_id: int, rng: np.random.RandomState,
                        top_orderings: List) -> Tuple[np.ndarray, np.ndarray]:
    """Create initial (sigma_inv, key) based on restart_id initialization mix."""
    mode = restart_id % 20

    if mode < 12:
        # 60% random perm + random key
        sigma_inv = rng.permutation(N).astype(np.int32)
        key = rng.randint(0, 26, size=N, dtype=np.int8)
    elif mode < 15:
        # 15% width-9 seeded
        if top_orderings:
            idx = rng.randint(0, len(top_orderings))
            order = top_orderings[idx]
            sigma = columnar_perm_local(list(order), 9)
            # sigma maps PT pos -> CT pos. sigma_inv is the inverse.
            sigma_inv = np.zeros(N, dtype=np.int32)
            for j in range(N):
                sigma_inv[sigma[j]] = j
            # Small perturbation
            for _ in range(rng.randint(0, 10)):
                a, b = rng.randint(0, N, size=2)
                sigma_inv[a], sigma_inv[b] = sigma_inv[b], sigma_inv[a]
        else:
            sigma_inv = rng.permutation(N).astype(np.int32)
        key = rng.randint(0, 26, size=N, dtype=np.int8)
    elif mode < 17:
        # 10% identity perm (pure substitution test)
        sigma_inv = np.arange(N, dtype=np.int32)
        key = rng.randint(0, 26, size=N, dtype=np.int8)
    elif mode < 18:
        # 5% rail fence seeded
        from kryptos.kernel.transforms.transposition import rail_fence_perm, invert_perm
        depth = rng.randint(3, 16)
        perm = rail_fence_perm(N, depth)
        sigma_inv = np.array(invert_perm(perm), dtype=np.int32)
        key = rng.randint(0, 26, size=N, dtype=np.int8)
    else:
        # 10% position-free mode (random, will use free scoring)
        sigma_inv = rng.permutation(N).astype(np.int32)
        key = rng.randint(0, 26, size=N, dtype=np.int8)

    # Enforce Bean equality
    key[65] = key[27]
    return sigma_inv, key


def _sa_worker(args) -> Dict:
    """Run a single 3-phase SA restart (5M iterations total)."""
    restart_id, seed, top_orderings_serialized = args
    _ensure_resources()

    rng = np.random.RandomState(seed)
    top_orderings = top_orderings_serialized  # list of tuples

    use_free_scoring = (restart_id % 20 >= 18)

    sigma_inv, key = _make_initial_state(restart_id, rng, top_orderings)
    pt_int = decrypt_sa(sigma_inv, key)

    qg = quadgram_score_fast(pt_int)
    cs = crib_score(pt_int)
    bean_ok = bean_check(key)

    # Track global best
    best_qg = qg
    best_sigma = sigma_inv.copy()
    best_key = key.copy()
    best_pt = pt_int.copy()
    best_cs = cs
    best_bean = bean_ok
    best_obj = -1e18

    current_qg = qg

    # ── Sub-phase A: Discover (2M iters, quadgram only) ─────────────
    iters_a, t_a_start, t_a_end = 2_000_000, 5.0, 0.01
    cooling_a = (t_a_end / t_a_start) ** (1.0 / iters_a)
    temp = t_a_start

    for it in range(iters_a):
        r = rng.random()

        if r < 0.50:
            # Perm swap
            i, j = rng.randint(0, N, size=2)
            while i == j:
                j = rng.randint(0, N)
            sigma_inv[i], sigma_inv[j] = sigma_inv[j], sigma_inv[i]
            new_pt = decrypt_sa(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            delta = new_qg - current_qg
            if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                if new_qg > best_qg:
                    best_qg = new_qg
                    best_sigma = sigma_inv.copy()
                    best_key = key.copy()
                    best_pt = new_pt.copy()
                    best_cs = crib_score(new_pt)
                    best_bean = bean_check(key)
            else:
                sigma_inv[i], sigma_inv[j] = sigma_inv[j], sigma_inv[i]

        elif r < 0.80:
            # Key change
            pos = rng.randint(0, N)
            old_val = int(key[pos])
            new_val = rng.randint(0, 26)
            while new_val == old_val:
                new_val = rng.randint(0, 26)
            key[pos] = new_val
            if pos == 27:
                key[65] = new_val
            elif pos == 65:
                key[27] = new_val

            new_pt = decrypt_sa(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            delta = new_qg - current_qg
            if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                if new_qg > best_qg:
                    best_qg = new_qg
                    best_sigma = sigma_inv.copy()
                    best_key = key.copy()
                    best_pt = new_pt.copy()
                    best_cs = crib_score(new_pt)
                    best_bean = bean_check(key)
            else:
                key[pos] = old_val
                if pos == 27:
                    key[65] = old_val
                elif pos == 65:
                    key[27] = old_val

        else:
            # Segment reverse
            i = rng.randint(0, N - 1)
            seg_len = rng.randint(2, min(15, N - i + 1))
            j = i + seg_len
            sigma_inv[i:j] = sigma_inv[i:j][::-1]
            new_pt = decrypt_sa(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            delta = new_qg - current_qg
            if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                if new_qg > best_qg:
                    best_qg = new_qg
                    best_sigma = sigma_inv.copy()
                    best_key = key.copy()
                    best_pt = new_pt.copy()
                    best_cs = crib_score(new_pt)
                    best_bean = bean_check(key)
            else:
                sigma_inv[i:j] = sigma_inv[i:j][::-1]

        temp *= cooling_a

    # ── Sub-phase B: Lock (2M iters, quadgram + ramping crib + Bean) ──
    # Restore best from A
    sigma_inv = best_sigma.copy()
    key = best_key.copy()
    pt_int = best_pt.copy()
    current_qg = best_qg

    iters_b = 2_000_000
    t_b_start, t_b_end = 2.0, 0.01
    cooling_b = (t_b_end / t_b_start) ** (1.0 / iters_b)
    temp = t_b_start

    p2_best_obj = -1e18
    p2_best_pt = pt_int.copy()
    p2_best_sigma = sigma_inv.copy()
    p2_best_key = key.copy()
    p2_best_cs = crib_score(pt_int)
    p2_best_qg = current_qg
    p2_best_bean = bean_check(key)

    def objective_b(qg_val, cs_val, bean_val, crib_w):
        score = qg_val / N
        if use_free_scoring:
            pt_s = int_to_text(pt_int)
            score += score_free_fast(pt_s) * crib_w * 0.5
        else:
            score += cs_val * crib_w
        if bean_val:
            score += 0.5
        return score

    for it in range(iters_b):
        progress = it / max(iters_b - 1, 1)
        crib_weight = 0.1 + 4.9 * progress

        cur_cs = crib_score(pt_int)
        cur_bean = bean_check(key)
        cur_obj = objective_b(current_qg, cur_cs, cur_bean, crib_weight)

        r = rng.random()

        if r < 0.50:
            i, j = rng.randint(0, N, size=2)
            while i == j:
                j = rng.randint(0, N)
            sigma_inv[i], sigma_inv[j] = sigma_inv[j], sigma_inv[i]
            new_pt = decrypt_sa(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            new_cs = crib_score(new_pt)
            new_bean = bean_check(key)
            new_obj = objective_b(new_qg, new_cs, new_bean, crib_weight)

            delta = new_obj - cur_obj
            if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                if new_obj > p2_best_obj:
                    p2_best_obj = new_obj
                    p2_best_pt = new_pt.copy()
                    p2_best_sigma = sigma_inv.copy()
                    p2_best_key = key.copy()
                    p2_best_cs = new_cs
                    p2_best_qg = new_qg
                    p2_best_bean = new_bean
            else:
                sigma_inv[i], sigma_inv[j] = sigma_inv[j], sigma_inv[i]

        elif r < 0.80:
            pos = rng.randint(0, N)
            old_val = int(key[pos])
            new_val = rng.randint(0, 26)
            while new_val == old_val:
                new_val = rng.randint(0, 26)
            key[pos] = new_val
            if pos == 27:
                key[65] = new_val
            elif pos == 65:
                key[27] = new_val

            new_pt = decrypt_sa(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            new_cs = crib_score(new_pt)
            new_bean = bean_check(key)
            new_obj = objective_b(new_qg, new_cs, new_bean, crib_weight)

            delta = new_obj - cur_obj
            if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                if new_obj > p2_best_obj:
                    p2_best_obj = new_obj
                    p2_best_pt = new_pt.copy()
                    p2_best_sigma = sigma_inv.copy()
                    p2_best_key = key.copy()
                    p2_best_cs = new_cs
                    p2_best_qg = new_qg
                    p2_best_bean = new_bean
            else:
                key[pos] = old_val
                if pos == 27:
                    key[65] = old_val
                elif pos == 65:
                    key[27] = old_val

        else:
            i = rng.randint(0, N - 1)
            seg_len = rng.randint(2, min(15, N - i + 1))
            j = i + seg_len
            sigma_inv[i:j] = sigma_inv[i:j][::-1]
            new_pt = decrypt_sa(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            new_cs = crib_score(new_pt)
            new_bean = bean_check(key)
            new_obj = objective_b(new_qg, new_cs, new_bean, crib_weight)

            delta = new_obj - cur_obj
            if delta > 0 or rng.random() < math.exp(delta / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                if new_obj > p2_best_obj:
                    p2_best_obj = new_obj
                    p2_best_pt = new_pt.copy()
                    p2_best_sigma = sigma_inv.copy()
                    p2_best_key = key.copy()
                    p2_best_cs = new_cs
                    p2_best_qg = new_qg
                    p2_best_bean = new_bean
            else:
                sigma_inv[i:j] = sigma_inv[i:j][::-1]

        temp *= cooling_b

    # ── Sub-phase C: Polish (1M iters, max crib weight) ───────────────
    sigma_inv = p2_best_sigma.copy()
    key = p2_best_key.copy()
    pt_int = p2_best_pt.copy()
    current_qg = p2_best_qg

    iters_c = 1_000_000
    t_c_start, t_c_end = 0.5, 0.001
    cooling_c = (t_c_end / t_c_start) ** (1.0 / iters_c)
    temp = t_c_start
    crib_weight_c = 5.0

    for it in range(iters_c):
        cur_cs = crib_score(pt_int)
        cur_bean = bean_check(key)
        cur_obj = current_qg / N + cur_cs * crib_weight_c + (0.5 if cur_bean else 0.0)

        r = rng.random()

        if r < 0.40:
            # Perm swap
            i, j = rng.randint(0, N, size=2)
            while i == j:
                j = rng.randint(0, N)
            sigma_inv[i], sigma_inv[j] = sigma_inv[j], sigma_inv[i]
            new_pt = decrypt_sa(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            new_cs = crib_score(new_pt)
            new_bean = bean_check(key)
            new_obj = new_qg / N + new_cs * crib_weight_c + (0.5 if new_bean else 0.0)

            if new_obj > cur_obj or rng.random() < math.exp((new_obj - cur_obj) / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                if new_obj > p2_best_obj:
                    p2_best_obj = new_obj
                    p2_best_pt = new_pt.copy()
                    p2_best_sigma = sigma_inv.copy()
                    p2_best_key = key.copy()
                    p2_best_cs = new_cs
                    p2_best_qg = new_qg
                    p2_best_bean = new_bean
            else:
                sigma_inv[i], sigma_inv[j] = sigma_inv[j], sigma_inv[i]

        elif r < 0.80:
            # Key change
            pos = rng.randint(0, N)
            old_val = int(key[pos])
            new_val = rng.randint(0, 26)
            while new_val == old_val:
                new_val = rng.randint(0, 26)
            key[pos] = new_val
            if pos == 27:
                key[65] = new_val
            elif pos == 65:
                key[27] = new_val

            new_pt = decrypt_sa(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            new_cs = crib_score(new_pt)
            new_bean = bean_check(key)
            new_obj = new_qg / N + new_cs * crib_weight_c + (0.5 if new_bean else 0.0)

            if new_obj > cur_obj or rng.random() < math.exp((new_obj - cur_obj) / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                if new_obj > p2_best_obj:
                    p2_best_obj = new_obj
                    p2_best_pt = new_pt.copy()
                    p2_best_sigma = sigma_inv.copy()
                    p2_best_key = key.copy()
                    p2_best_cs = new_cs
                    p2_best_qg = new_qg
                    p2_best_bean = new_bean
            else:
                key[pos] = old_val
                if pos == 27:
                    key[65] = old_val
                elif pos == 65:
                    key[27] = old_val

        else:
            # Segment reverse
            i = rng.randint(0, N - 1)
            seg_len = rng.randint(2, min(15, N - i + 1))
            j = i + seg_len
            sigma_inv[i:j] = sigma_inv[i:j][::-1]
            new_pt = decrypt_sa(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            new_cs = crib_score(new_pt)
            new_bean = bean_check(key)
            new_obj = new_qg / N + new_cs * crib_weight_c + (0.5 if new_bean else 0.0)

            if new_obj > cur_obj or rng.random() < math.exp((new_obj - cur_obj) / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                if new_obj > p2_best_obj:
                    p2_best_obj = new_obj
                    p2_best_pt = new_pt.copy()
                    p2_best_sigma = sigma_inv.copy()
                    p2_best_key = key.copy()
                    p2_best_cs = new_cs
                    p2_best_qg = new_qg
                    p2_best_bean = new_bean
            else:
                sigma_inv[i:j] = sigma_inv[i:j][::-1]

        temp *= cooling_c

    # Final evaluation
    pt_str = int_to_text(p2_best_pt)
    dw = count_dict_words(pt_str)
    ic_val = calc_ic(p2_best_pt)
    cs_free = score_free_fast(pt_str)

    return {
        "restart_id": restart_id,
        "plaintext": pt_str,
        "crib_score": int(p2_best_cs),
        "crib_free": cs_free,
        "bean_ok": bool(p2_best_bean),
        "qg_per_char": float(p2_best_qg / N),
        "ic": float(ic_val),
        "dict_words": dw,
        "sigma_inv": p2_best_sigma.tolist(),
        "key": p2_best_key.tolist(),
        "init_mode": restart_id % 20,
    }


def run_phase2(ckpt: Checkpoint, n_workers: int) -> None:
    """Run Phase 2: Massive SA Campaign — 100,800 restarts × 5M iterations."""
    if 2 in ckpt.phases_done:
        log_progress("Phase 2 already done, skipping.")
        return

    log_progress("=== PHASE 2: Massive SA Campaign ===")

    total_restarts = 100_800
    done = ckpt.sa_seeds_done
    batch_size = n_workers

    # Collect top width-9 orderings from Phase 1 for seeding
    top_orderings = []
    for c in ckpt.top_candidates:
        if isinstance(c.get("order"), list) and c.get("width") == 9:
            top_orderings.append(tuple(c["order"]))
    if not top_orderings:
        # Use a few default orderings
        top_orderings = [tuple(range(9))]

    log_progress(f"  Total restarts: {total_restarts}, batch size: {batch_size}")
    log_progress(f"  Resuming from seed {done}")
    log_progress(f"  Top width-9 orderings for seeding: {len(top_orderings)}")

    t_start = time.time()
    best_overall = {"qg_per_char": -99.0, "crib_score": 0}
    breakthroughs = []

    while done < total_restarts and not _shutdown:
        batch_sz = min(batch_size, total_restarts - done)
        tasks = []
        for i in range(batch_sz):
            rid = done + i
            seed = 5_000_000 + rid * 7919
            tasks.append((rid, seed, top_orderings))

        with mp.Pool(n_workers) as pool:
            batch_results = pool.map(_sa_worker, tasks)

        for res in batch_results:
            # Store threshold: crib_score >= 20 OR qg_per_char > -4.0
            if res["crib_score"] >= 20 or res["qg_per_char"] > -4.0:
                store_candidate(
                    phase=2, phase_name="sa_campaign",
                    model=f"init{res['init_mode']}",
                    cribs=res["crib_score"], crib_free=res["crib_free"],
                    qg_pc=res["qg_per_char"], ic_val=res["ic"],
                    bean=res["bean_ok"], dict_words=res["dict_words"],
                    config={"restart_id": res["restart_id"], "init_mode": res["init_mode"]},
                    pt=res["plaintext"],
                )
                ckpt.add_candidate(res)

            # Track best
            if res["qg_per_char"] > best_overall["qg_per_char"]:
                best_overall = res

            # Breakthrough detection
            if (res["crib_score"] == 24 and res["bean_ok"]
                    and res["qg_per_char"] > -4.84
                    and res["ic"] > 0.055
                    and res["dict_words"] >= 3):
                breakthroughs.append(res)
                log_progress(f"!!! BREAKTHROUGH R{res['restart_id']}: "
                             f"crib={res['crib_score']}/24 bean=PASS "
                             f"qg/c={res['qg_per_char']:.3f} ic={res['ic']:.4f} "
                             f"words={res['dict_words']}")
                log_progress(f"    PT: {res['plaintext']}")

        done += batch_sz
        ckpt.sa_seeds_done = done
        ckpt.save()

        # Progress every 10 batches
        if (done // batch_size) % 10 == 0:
            elapsed = time.time() - t_start
            rate = done / max(elapsed, 1)
            eta = (total_restarts - done) / max(rate, 0.001)
            log_progress(
                f"  SA progress: {done}/{total_restarts} ({done/total_restarts:.1%}) "
                f"elapsed={elapsed/3600:.1f}h ETA={eta/3600:.1f}h "
                f"best_qg={best_overall['qg_per_char']:.3f} "
                f"best_crib={best_overall['crib_score']}/24"
            )

    # Save breakthroughs
    if breakthroughs:
        bt_path = RESULTS_DIR / "breakthrough_candidates.json"
        with open(bt_path, "w") as f:
            json.dump(breakthroughs, f, indent=2, default=str)

    if done >= total_restarts:
        ckpt.phases_done.append(2)
    ckpt.save()

    elapsed = time.time() - t_start
    total_iters = done * 5_000_000
    log_progress(f"Phase 2 {'DONE' if done >= total_restarts else 'INTERRUPTED'}: "
                 f"{done} restarts, {total_iters/1e9:.1f}B iterations, "
                 f"{elapsed/3600:.1f}h, {len(breakthroughs)} breakthroughs")


# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3: Deep Dive on Top Candidates
# ═══════════════════════════════════════════════════════════════════════════

def _deep_dive_worker(args) -> Dict:
    """Polish a single candidate with 5M additional SA iterations."""
    cand, n_iters, seed = args
    _ensure_resources()

    rng = np.random.RandomState(seed)

    # Reconstruct state from candidate
    if "sigma_inv" in cand and isinstance(cand["sigma_inv"], list):
        sigma_inv = np.array(cand["sigma_inv"], dtype=np.int32)
    else:
        sigma_inv = rng.permutation(N).astype(np.int32)

    if "key" in cand and isinstance(cand["key"], list):
        key = np.array(cand["key"], dtype=np.int8)
    else:
        key = rng.randint(0, 26, size=N, dtype=np.int8)

    key[65] = key[27]

    pt_int = decrypt_sa(sigma_inv, key)
    current_qg = quadgram_score_fast(pt_int)

    best_qg = current_qg
    best_sigma = sigma_inv.copy()
    best_key = key.copy()
    best_pt = pt_int.copy()

    # Polish SA: gentle temperature, crib-weighted
    cooling = (0.001 / 1.0) ** (1.0 / n_iters)
    temp = 1.0
    crib_w = 5.0

    for it in range(n_iters):
        cur_cs = crib_score(pt_int)
        cur_bean = bean_check(key)
        cur_obj = current_qg / N + cur_cs * crib_w + (0.5 if cur_bean else 0.0)

        r = rng.random()

        if r < 0.40:
            i, j = rng.randint(0, N, size=2)
            while i == j:
                j = rng.randint(0, N)
            sigma_inv[i], sigma_inv[j] = sigma_inv[j], sigma_inv[i]
            new_pt = decrypt_sa(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            new_cs = crib_score(new_pt)
            new_bean = bean_check(key)
            new_obj = new_qg / N + new_cs * crib_w + (0.5 if new_bean else 0.0)

            if new_obj > cur_obj or rng.random() < math.exp((new_obj - cur_obj) / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                if new_qg > best_qg:
                    best_qg = new_qg
                    best_sigma = sigma_inv.copy()
                    best_key = key.copy()
                    best_pt = new_pt.copy()
            else:
                sigma_inv[i], sigma_inv[j] = sigma_inv[j], sigma_inv[i]

        elif r < 0.80:
            pos = rng.randint(0, N)
            old_val = int(key[pos])
            new_val = rng.randint(0, 26)
            while new_val == old_val:
                new_val = rng.randint(0, 26)
            key[pos] = new_val
            if pos == 27:
                key[65] = new_val
            elif pos == 65:
                key[27] = new_val

            new_pt = decrypt_sa(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            new_cs = crib_score(new_pt)
            new_bean = bean_check(key)
            new_obj = new_qg / N + new_cs * crib_w + (0.5 if new_bean else 0.0)

            if new_obj > cur_obj or rng.random() < math.exp((new_obj - cur_obj) / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                if new_qg > best_qg:
                    best_qg = new_qg
                    best_sigma = sigma_inv.copy()
                    best_key = key.copy()
                    best_pt = new_pt.copy()
            else:
                key[pos] = old_val
                if pos == 27:
                    key[65] = old_val
                elif pos == 65:
                    key[27] = old_val

        else:
            i = rng.randint(0, N - 1)
            seg_len = rng.randint(2, min(15, N - i + 1))
            j = i + seg_len
            sigma_inv[i:j] = sigma_inv[i:j][::-1]
            new_pt = decrypt_sa(sigma_inv, key)
            new_qg = quadgram_score_fast(new_pt)
            new_cs = crib_score(new_pt)
            new_bean = bean_check(key)
            new_obj = new_qg / N + new_cs * crib_w + (0.5 if new_bean else 0.0)

            if new_obj > cur_obj or rng.random() < math.exp((new_obj - cur_obj) / max(temp, 1e-10)):
                pt_int = new_pt
                current_qg = new_qg
                if new_qg > best_qg:
                    best_qg = new_qg
                    best_sigma = sigma_inv.copy()
                    best_key = key.copy()
                    best_pt = new_pt.copy()
            else:
                sigma_inv[i:j] = sigma_inv[i:j][::-1]

        temp *= cooling

    pt_str = int_to_text(best_pt)
    cs = crib_score(best_pt)
    cs_free = score_free_fast(pt_str)
    ic_val = calc_ic(best_pt)
    bean_ok = bean_check(best_key)
    dw = count_dict_words(pt_str)

    return {
        "plaintext": pt_str,
        "crib_score": int(cs),
        "crib_free": cs_free,
        "bean_ok": bool(bean_ok),
        "qg_per_char": float(best_qg / N),
        "ic": float(ic_val),
        "dict_words": dw,
        "sigma_inv": best_sigma.tolist(),
        "key": best_key.tolist(),
    }


def run_phase3(ckpt: Checkpoint, n_workers: int) -> None:
    """Run Phase 3: Deep Dive on top 1000 candidates."""
    if 3 in ckpt.phases_done:
        log_progress("Phase 3 already done, skipping.")
        return

    log_progress("=== PHASE 3: Deep Dive on Top Candidates ===")

    candidates = ckpt.top_candidates[:1000]
    if not candidates:
        log_progress("  No candidates to polish. Skipping.")
        ckpt.phases_done.append(3)
        ckpt.save()
        return

    log_progress(f"  Polishing {len(candidates)} candidates with 5M iters each")
    t_start = time.time()

    # Round 1: 5M iterations on all candidates
    tasks = []
    for i, cand in enumerate(candidates):
        tasks.append((cand, 5_000_000, 9_000_000 + i * 31))

    polished = []
    batch_size = n_workers
    for bi in range(0, len(tasks), batch_size):
        if _shutdown:
            break
        batch = tasks[bi:bi + batch_size]
        with mp.Pool(min(n_workers, len(batch))) as pool:
            results = pool.map(_deep_dive_worker, batch)
        polished.extend(results)

        if (bi // batch_size) % 10 == 0:
            log_progress(f"  Round 1: {len(polished)}/{len(candidates)} polished")

    # Sort by composite score
    polished.sort(key=lambda x: (-x["crib_score"], -x["qg_per_char"]))

    # Round 2: Top 100 get 10M more iterations
    if not _shutdown and len(polished) >= 10:
        top100 = polished[:100]
        log_progress(f"  Round 2: 10M iterations on top {len(top100)} candidates")

        tasks2 = []
        for i, cand in enumerate(top100):
            tasks2.append((cand, 10_000_000, 10_000_000 + i * 37))

        round2 = []
        for bi in range(0, len(tasks2), batch_size):
            if _shutdown:
                break
            batch = tasks2[bi:bi + batch_size]
            with mp.Pool(min(n_workers, len(batch))) as pool:
                results = pool.map(_deep_dive_worker, batch)
            round2.extend(results)

        # Merge round2 into polished
        for r in round2:
            polished.append(r)
        polished.sort(key=lambda x: (-x["crib_score"], -x["qg_per_char"]))

    # Store to DB
    for r in polished[:500]:
        store_candidate(
            phase=3, phase_name="deep_dive",
            model="polish", cribs=r["crib_score"], crib_free=r.get("crib_free", 0),
            qg_pc=r["qg_per_char"], ic_val=r["ic"],
            bean=r["bean_ok"], dict_words=r["dict_words"],
            config={}, pt=r["plaintext"],
        )

    # Generate human-readable review file
    review_path = RESULTS_DIR / "top_1000_for_review.txt"
    with open(review_path, "w") as f:
        f.write("=" * 80 + "\n")
        f.write("E-MARATHON-01: Top Candidates for Human Review\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total candidates polished: {len(polished)}\n")
        f.write("=" * 80 + "\n\n")

        for i, r in enumerate(polished[:1000]):
            f.write(f"--- Rank {i+1} ---\n")
            f.write(f"  Crib: {r['crib_score']}/24  Free: {r.get('crib_free', '?')}/24  "
                    f"Bean: {'PASS' if r['bean_ok'] else 'FAIL'}  "
                    f"QG/c: {r['qg_per_char']:.3f}  IC: {r['ic']:.4f}  "
                    f"Words: {r['dict_words']}\n")
            f.write(f"  PT: {r['plaintext']}\n\n")

    # Check for breakthroughs
    breakthroughs = [r for r in polished
                     if r["crib_score"] == 24 and r["bean_ok"]
                     and r["qg_per_char"] > -4.84 and r["ic"] > 0.055
                     and r["dict_words"] >= 3]

    if breakthroughs:
        bt_path = RESULTS_DIR / "breakthrough_candidates.json"
        existing = []
        if bt_path.exists():
            with open(bt_path) as f:
                existing = json.load(f)
        existing.extend(breakthroughs)
        with open(bt_path, "w") as f:
            json.dump(existing, f, indent=2, default=str)
        log_progress(f"  !!! {len(breakthroughs)} BREAKTHROUGHS from Phase 3 !!!")

    ckpt.phases_done.append(3)
    ckpt.save()

    elapsed = time.time() - t_start
    log_progress(f"Phase 3 DONE: {len(polished)} candidates polished, "
                 f"{elapsed/3600:.1f}h, {len(breakthroughs)} breakthroughs")


# ═══════════════════════════════════════════════════════════════════════════
# Main orchestrator
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="E-MARATHON-01: 24-Hour Final Assault on K4")
    parser.add_argument("--workers", type=int, default=mp.cpu_count() - 2,
                        help="Number of worker processes")
    parser.add_argument("--phase", type=int, default=None,
                        help="Run only this phase (0-3)")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from checkpoint")
    args = parser.parse_args()

    n_workers = max(1, args.workers)

    # Signal handlers for graceful shutdown
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # Setup
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    init_db(DB_PATH)

    if args.resume and CHECKPOINT_PATH.exists():
        ckpt = Checkpoint.load()
        log_progress(f"Resumed from checkpoint: phases_done={ckpt.phases_done}, "
                     f"sa_seeds={ckpt.sa_seeds_done}, configs={ckpt.total_configs}")
    else:
        ckpt = Checkpoint(start_time=time.time())

    # Header
    log_progress("=" * 80)
    log_progress("E-MARATHON-01: 24-Hour Final Assault on K4")
    log_progress(f"CT: {CT}")
    log_progress(f"Workers: {n_workers}, CPUs: {mp.cpu_count()}")
    log_progress(f"Output: {RESULTS_DIR}")
    log_progress("=" * 80)

    # Load shared resources
    log_progress("Loading quadgrams...")
    load_quadgrams()
    log_progress("Loading dictionary...")
    load_dictionary()
    log_progress(f"Resources loaded: {len(QUADGRAM_LUT)} quadgrams, {len(LONG_WORDS)} words")

    t_total = time.time()

    # Run phases
    if args.phase is not None:
        phases = [args.phase]
    else:
        phases = [0, 1, 2, 3]

    for phase in phases:
        if _shutdown:
            break
        if phase == 0:
            run_phase0(ckpt)
        elif phase == 1:
            run_phase1(ckpt, n_workers)
        elif phase == 2:
            run_phase2(ckpt, n_workers)
        elif phase == 3:
            run_phase3(ckpt, n_workers)

    # Final summary
    elapsed = time.time() - t_total
    log_progress("")
    log_progress("=" * 80)
    log_progress("FINAL SUMMARY")
    log_progress(f"Phases completed: {sorted(ckpt.phases_done)}")
    log_progress(f"Total configs tested: {ckpt.total_configs}")
    log_progress(f"SA restarts completed: {ckpt.sa_seeds_done}")
    log_progress(f"Total SA iterations: {ckpt.sa_seeds_done * 5_000_000 / 1e9:.1f}B")
    log_progress(f"Total elapsed: {elapsed/3600:.1f}h")

    # Top candidates summary
    if ckpt.top_candidates:
        log_progress(f"\nTop 10 candidates (of {len(ckpt.top_candidates)} stored):")
        for i, c in enumerate(ckpt.top_candidates[:10]):
            pt = c.get("plaintext", "?")[:70]
            cs = c.get("crib_score", 0)
            qg = c.get("qg_per_char", -99)
            bean = c.get("bean_ok", False)
            log_progress(f"  #{i+1}: crib={cs}/24 qg/c={qg:.3f} "
                         f"bean={'Y' if bean else 'N'} PT={pt}...")

    # Check for breakthroughs
    bt_path = RESULTS_DIR / "breakthrough_candidates.json"
    if bt_path.exists():
        with open(bt_path) as f:
            bts = json.load(f)
        if bts:
            log_progress(f"\n{'='*80}")
            log_progress(f"!!! {len(bts)} BREAKTHROUGH CANDIDATE(S) FOUND !!!")
            for b in bts:
                log_progress(f"  PT: {b.get('plaintext', '?')}")
            log_progress(f"{'='*80}")
    else:
        log_progress("\nNo breakthroughs found. Result: NOISE (as expected for SA at this depth).")

    log_progress("=" * 80)
    log_progress("Done.")


if __name__ == "__main__":
    main()
