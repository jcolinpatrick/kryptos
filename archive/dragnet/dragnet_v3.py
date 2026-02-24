#!/usr/bin/env python3
"""DRAGNET v3 — Untested Attack Vectors for Kryptos K4.

Five-phase experiment targeting gaps identified across 242+ prior experiments:

  Phase 1: Null/Skip Patterns (NEVER TESTED)
    - DRYAD/BATCO-style null insertion: doubled letters as nulls, mod-7 nulls,
      every-Nth null removal, then standard cipher attacks on reduced CT.
    - ~150K configs

  Phase 2: Shared-Key Transposition (NEVER TESTED)
    - Same keyword drives BOTH columnar transposition order AND Vigenere key.
    - Tests all keyword-length matches between columnar width and key period.
    - ~500K configs

  Phase 3: Non-Standard Tableau Lookup (NOVEL ANGLES)
    - 6 role permutations of (row, col, cell) x 4 alphabet combos (AZ/KA)
      applied to the Vigenere tableau visible on the sculpture.
    - ~200K configs

  Phase 4: Sculpture-Parameter Position Cipher (UNDER-TESTED)
    - YAR/RQ/compass-bearing values as position-dependent key modifiers.
    - Additive, multiplicative, and XOR-style position-dependent key derivation.
    - ~300K configs

  Phase 5: Multi-Layer Cascade (NOVEL COMBINATION)
    - Pipeline: CT → remove nulls → undo transposition → undo substitution
    - Combines Phase 1 null removal with Phase 2/3 ciphers in cascade.
    - Tests the "two separate systems" hypothesis directly.
    - ~100K configs

Usage:
  PYTHONPATH=src python3 -u scripts/dragnet_v3.py --phase all --workers 28
  PYTHONPATH=src python3 -u scripts/dragnet_v3.py --phase 1 --workers 28
  PYTHONPATH=src python3 -u scripts/dragnet_v3.py --phase 2 --workers 28
  PYTHONPATH=src python3 -u scripts/dragnet_v3.py --phase 3 --workers 28
  PYTHONPATH=src python3 -u scripts/dragnet_v3.py --phase 4 --workers 28
  PYTHONPATH=src python3 -u scripts/dragnet_v3.py --phase 5 --workers 28
  PYTHONPATH=src python3 -u scripts/dragnet_v3.py --resume
"""
from __future__ import annotations

import argparse
import itertools
import json
import logging
import math
import multiprocessing as mp
import signal
import sqlite3
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Project imports ──────────────────────────────────────────────────────
from kryptos.kernel.constants import (
    ALPH, ALPH_IDX, CT, CT_LEN, MOD,
    CRIB_DICT, CRIB_ENTRIES, CRIB_POSITIONS, CRIB_WORDS, N_CRIBS,
    BEAN_EQ, BEAN_INEQ, KRYPTOS_ALPHABET,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
)

# ── Precomputed integer arrays ──────────────────────────────────────────
CT_INT: List[int] = [ALPH_IDX[c] for c in CT]
CRIB_POS_LIST: List[int] = sorted(CRIB_POSITIONS)
CRIB_PT_INT: Dict[int, int] = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
NON_CRIB_POS: List[int] = [i for i in range(CT_LEN) if i not in CRIB_POSITIONS]

# KA integer mapping
KA_IDX: Dict[str, int] = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
KA_INT: List[int] = [KA_IDX[c] for c in KRYPTOS_ALPHABET]

# ── Paths ────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"
CHECKPOINT_PATH = RESULTS_DIR / "dragnet_v3_checkpoint.json"
DB_PATH = RESULTS_DIR / "dragnet_v3_results.sqlite"
LOG_PATH = RESULTS_DIR / "dragnet_v3.log"
QUADGRAM_PATH = PROJECT_ROOT / "data" / "english_quadgrams.json"

# ── Doubled-letter positions in CT (0-indexed) ─────────────────────────
# BB at 18-19, QQ at 25-26, SS at 31-32 & 40-41, ZZ at 45-46, TT at 67-68
DOUBLED_POSITIONS = [18, 25, 31, 40, 45, 67]  # first char of each pair
ALL_DOUBLED = {18, 19, 25, 26, 31, 32, 40, 41, 45, 46, 67, 68}

# ── Global shutdown flag ────────────────────────────────────────────────
_shutdown_requested = False


def _signal_handler(signum, frame):
    global _shutdown_requested
    _shutdown_requested = True


# ══════════════════════════════════════════════════════════════════════════
# Logging
# ══════════════════════════════════════════════════════════════════════════

def setup_logging() -> logging.Logger:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("dragnet_v3")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fh = logging.FileHandler(str(LOG_PATH), mode="a")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    ))
    logger.addHandler(fh)

    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
    ))
    logger.addHandler(ch)
    return logger


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

    def score(self, text: str) -> float:
        lp = self._lp
        fl = self._floor
        t = text.upper()
        return sum(lp.get(t[i:i+4], fl) for i in range(len(t) - 3))

    def score_per_char(self, text: str) -> float:
        n = len(text) - 3
        return self.score(text) / n if n > 0 else self._floor


# ══════════════════════════════════════════════════════════════════════════
# Common cipher and scoring functions
# ══════════════════════════════════════════════════════════════════════════

def vig_decrypt_int(c: int, k: int) -> int:
    return (c - k) % 26

def beau_decrypt_int(c: int, k: int) -> int:
    return (k - c) % 26

def varbeau_decrypt_int(c: int, k: int) -> int:
    return (c + k) % 26

def vig_encrypt_int(p: int, k: int) -> int:
    return (p + k) % 26

def beau_encrypt_int(p: int, k: int) -> int:
    return (k - p) % 26

def varbeau_encrypt_int(p: int, k: int) -> int:
    return (p - k) % 26

def vig_recover_int(c: int, p: int) -> int:
    return (c - p) % 26

def beau_recover_int(c: int, p: int) -> int:
    return (c + p) % 26

def varbeau_recover_int(c: int, p: int) -> int:
    return (p - c) % 26


DECRYPT_FNS = {
    "vigenere": vig_decrypt_int,
    "beaufort": beau_decrypt_int,
    "var_beaufort": varbeau_decrypt_int,
}
ENCRYPT_FNS = {
    "vigenere": vig_encrypt_int,
    "beaufort": beau_encrypt_int,
    "var_beaufort": varbeau_encrypt_int,
}
RECOVER_FNS = {
    "vigenere": vig_recover_int,
    "beaufort": beau_recover_int,
    "var_beaufort": varbeau_recover_int,
}
VARIANT_NAMES = ["vigenere", "beaufort", "var_beaufort"]


def fast_crib_score_on(pt_int: List[int], crib_map: Dict[int, int]) -> int:
    """Count crib matches. crib_map maps position→expected int value."""
    s = 0
    for pos, expected in crib_map.items():
        if pos < len(pt_int) and pt_int[pos] == expected:
            s += 1
    return s


def fast_crib_score(pt_int: List[int]) -> int:
    return fast_crib_score_on(pt_int, CRIB_PT_INT)


def fast_ic(pt_int: List[int]) -> float:
    freq = [0] * 26
    for v in pt_int:
        freq[v] += 1
    n = len(pt_int)
    if n < 2:
        return 0.0
    return sum(f * (f - 1) for f in freq) / (n * (n - 1))


def fast_bean_check(key_int: List[int]) -> bool:
    for a, b in BEAN_EQ:
        if a < len(key_int) and b < len(key_int):
            if key_int[a] != key_int[b]:
                return False
    for a, b in BEAN_INEQ:
        if a < len(key_int) and b < len(key_int):
            if key_int[a] == key_int[b]:
                return False
    return True


def int_to_text(vals: List[int]) -> str:
    return "".join(ALPH[v % 26] for v in vals)


def invert_perm(perm: List[int]) -> List[int]:
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


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
            score_cribs INTEGER NOT NULL,
            score_quadgram REAL,
            score_ic REAL,
            bean_pass INTEGER NOT NULL DEFAULT 0,
            config TEXT,
            plaintext TEXT,
            reduced_len INTEGER,
            timestamp REAL NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_score ON candidates(score_cribs DESC)"
    )
    conn.commit()
    conn.close()


def store_candidate(
    db_path: Path, phase: int, phase_name: str,
    cribs: int, qg: Optional[float], ic_val: Optional[float],
    bean: bool, config: Dict[str, Any], pt: str,
    reduced_len: Optional[int] = None,
) -> None:
    try:
        conn = sqlite3.connect(str(db_path), timeout=10.0)
        conn.execute(
            "INSERT INTO candidates "
            "(phase, phase_name, score_cribs, score_quadgram, score_ic, "
            "bean_pass, config, plaintext, reduced_len, timestamp) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                phase, phase_name, cribs, qg, ic_val, int(bean),
                json.dumps(config), pt, reduced_len, time.time(),
            ),
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
    phase: int = 0
    phase_done: Dict[str, bool] = field(default_factory=dict)
    phase_tested: Dict[str, int] = field(default_factory=dict)
    best_candidates: List[Dict[str, Any]] = field(default_factory=list)
    start_time: float = 0.0
    last_save: float = 0.0

    def save(self, path: Path) -> None:
        self.last_save = time.time()
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
# Corpus management
# ══════════════════════════════════════════════════════════════════════════

def get_corpus_files() -> List[Path]:
    files: List[Path] = []
    ref_dir = PROJECT_ROOT / "reference"
    rk_dir = ref_dir / "running_key_texts"
    if rk_dir.is_dir():
        for f in sorted(rk_dir.glob("*.txt")):
            files.append(f)
    for name in [
        "carter_gutenberg.txt", "carter_vol1.txt", "carter_vol1_extract.txt",
        "carter_text_cache.txt",
        "great_big_story_cracking_the_uncrackable_code_2019.txt",
    ]:
        p = ref_dir / name
        if p.exists():
            files.append(p)
    corpus_dir = PROJECT_ROOT / "corpus"
    if corpus_dir.is_dir():
        for f in sorted(corpus_dir.glob("*.txt")):
            files.append(f)
    return files


def clean_text(raw: str) -> str:
    return "".join(c for c in raw.upper() if c in ALPH_IDX)


def get_sculpture_texts() -> List[Tuple[str, str]]:
    k1_pt = clean_text(
        "BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT "
        "LIES THE NUANCE OF IQLUSION"
    )
    k2_pt = clean_text(
        "IT WAS TOTALLY INVISIBLE HOWS THAT POSSIBLE THEY USED THE EARTHS "
        "MAGNETIC FIELD X THE INFORMATION WAS GATHERED AND TRANSMITTED "
        "UNDERGRUUND TO AN UNKNOWN LOCATION X DOES LANGLEY KNOW ABOUT THIS "
        "THEY SHOULD ITS BURIED OUT THERE SOMEWHERE X WHO KNOWS THE EXACT "
        "LOCATION ONLY WW THIS WAS HIS LAST MESSAGE X THIRTY EIGHT DEGREES "
        "FIFTY SEVEN MINUTES SIX POINT FIVE SECONDS NORTH SEVENTY SEVEN "
        "DEGREES EIGHT MINUTES FORTY FOUR SECONDS WEST ID BY ROWS"
    )
    k3_pt = clean_text(
        "SLOWLY DESPARATLY SLOWLY THE REMAINS OF PASSAGE DEBRIS THAT "
        "ENCUMBERED THE LOWER PART OF THE DOORWAY WAS REMOVED WITH TREMBLING "
        "HANDS I MADE A TINY BREACH IN THE UPPER LEFT HAND CORNER AND THEN "
        "WIDENING THE HOLE A LITTLE I INSERTED THE CANDLE AND PEERED IN THE "
        "HOT AIR ESCAPING FROM THE CHAMBER CAUSED THE FLAME TO FLICKER BUT "
        "PRESENTLY DETAILS OF THE ROOM WITHIN EMERGED FROM THE MIST X CAN "
        "YOU SEE ANYTHING Q"
    )
    k1_ct = clean_text(
        "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
    )
    k2_ct = clean_text(
        "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKK"
        "DQMCPFQZDQMMIAGPFXHQRLGTIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECG"
        "YUXUEENJTBJLBQCRTBJDFHRRYIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVH"
    )
    k3_ct = clean_text(
        "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
        "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETP"
        "EOCASDAHSATLHCTICEUEAAHTDSTTHLNHASEEHPIEAHTTSHNEDRNMIAHTTDGKTA"
        "EWJRVIKNLERAHSEJKDWKNLCGLPRHNSIEKNLTEPKAEORNDSITKNDDPNKAHNTQK"
    )
    combos: List[Tuple[str, str]] = [
        ("K1_PT", k1_pt),
        ("K2_PT", k2_pt),
        ("K3_PT", k3_pt),
        ("K1_CT", k1_ct),
        ("K2_CT", k2_ct),
        ("K3_CT", k3_ct),
        ("K1PT+K2PT", k1_pt + k2_pt),
        ("K2PT+K3PT", k2_pt + k3_pt),
        ("K1PT+K2PT+K3PT", k1_pt + k2_pt + k3_pt),
        ("K3PT+K2PT+K1PT", k3_pt + k2_pt + k1_pt),
        ("K1CT+K2CT+K3CT", k1_ct + k2_ct + k3_ct),
        ("K3CT+K4CT+K1PT", k3_ct + CT + k1_pt),
        ("KRYPTOS*20", clean_text("KRYPTOS" * 20)),
        ("PALIMPSEST*12", clean_text("PALIMPSEST" * 12)),
        ("ABSCISSA*15", clean_text("ABSCISSA" * 15)),
    ]
    return combos


def load_all_texts() -> List[Tuple[str, List[int], int]]:
    """Load all running key source texts as integer arrays."""
    all_texts: List[Tuple[str, List[int], int]] = []
    for fp in get_corpus_files():
        try:
            raw = fp.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        text = clean_text(raw)
        if len(text) >= CT_LEN:
            text_int = [ALPH_IDX[c] for c in text]
            all_texts.append((fp.stem, text_int, len(text)))
    for name, text in get_sculpture_texts():
        if len(text) >= CT_LEN:
            text_int = [ALPH_IDX[c] for c in text]
            all_texts.append((name, text_int, len(text)))
    return all_texts


# ══════════════════════════════════════════════════════════════════════════
# Columnar transposition helpers
# ══════════════════════════════════════════════════════════════════════════

def keyword_to_col_order(keyword: str) -> List[int]:
    """Convert a keyword to column reading order.

    Returns rank[i] = reading rank of column i (0 = read first).
    Ties broken left-to-right (stable sort).
    """
    indexed = sorted(range(len(keyword)), key=lambda i: keyword[i])
    order = [0] * len(keyword)
    for rank, col in enumerate(indexed):
        order[col] = rank
    return order


def columnar_decrypt(ct_int: List[int], col_order: List[int]) -> List[int]:
    """Undo columnar transposition: given CT read by columns in col_order,
    recover the row-major plaintext.

    col_order[c] = rank of column c (0 = first column read into CT).
    """
    width = len(col_order)
    n = len(ct_int)
    nrows = math.ceil(n / width)
    remainder = n % width
    if remainder == 0:
        remainder = width

    # Columns sorted by rank
    rank_to_col = [0] * width
    for c, r in enumerate(col_order):
        rank_to_col[r] = c

    col_len = [nrows if c < remainder else nrows - 1 for c in range(width)]

    # Compute start positions in CT for each column
    starts = [0] * width
    cumul = 0
    for r in range(width):
        c = rank_to_col[r]
        starts[c] = cumul
        cumul += col_len[c]

    # Read out row-major
    pt = [0] * n
    for c in range(width):
        for row in range(col_len[c]):
            pt_pos = row * width + c
            ct_pos = starts[c] + row
            if pt_pos < n and ct_pos < n:
                pt[pt_pos] = ct_int[ct_pos]
    return pt


def columnar_encrypt(pt_int: List[int], col_order: List[int]) -> List[int]:
    """Apply columnar transposition: write row-major, read by columns."""
    width = len(col_order)
    n = len(pt_int)
    nrows = math.ceil(n / width)
    remainder = n % width
    if remainder == 0:
        remainder = width

    rank_to_col = [0] * width
    for c, r in enumerate(col_order):
        rank_to_col[r] = c

    col_len = [nrows if c < remainder else nrows - 1 for c in range(width)]

    ct = [0] * n
    pos = 0
    for r in range(width):
        c = rank_to_col[r]
        for row in range(col_len[c]):
            src = row * width + c
            if src < n:
                ct[pos] = pt_int[src]
                pos += 1
    return ct


# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: Null/Skip Pattern Search
# ══════════════════════════════════════════════════════════════════════════
#
# Hypothesis: Doubled letters in K4 CT are nulls (DRYAD/BATCO convention).
# Remove them, then test standard ciphers on the reduced text.
# Also test: every-Nth removal, mod-7 removal, specific position sets.

def generate_null_masks() -> List[Tuple[str, List[int]]]:
    """Generate different null removal masks.

    Each mask is a list of positions to KEEP (0-indexed into original CT).
    Returns (description, keep_positions).
    """
    masks: List[Tuple[str, List[int]]] = []

    # 1. Remove second char of each doubled pair
    second_of_doubled = {19, 26, 32, 41, 46, 68}
    keep = [i for i in range(CT_LEN) if i not in second_of_doubled]
    masks.append(("rm_doubled_2nd", keep))

    # 2. Remove first char of each doubled pair
    first_of_doubled = {18, 25, 31, 40, 45, 67}
    keep = [i for i in range(CT_LEN) if i not in first_of_doubled]
    masks.append(("rm_doubled_1st", keep))

    # 3. Remove both chars of doubled pairs
    keep = [i for i in range(CT_LEN) if i not in ALL_DOUBLED]
    masks.append(("rm_doubled_both", keep))

    # 4. Remove positions ≡ 4 mod 7 (doubled-letter pattern)
    for mod_val in range(7):
        remove = {i for i in range(CT_LEN) if i % 7 == mod_val}
        keep = [i for i in range(CT_LEN) if i not in remove]
        masks.append((f"rm_mod7eq{mod_val}", keep))

    # 5. Remove every Nth character (N=2..10)
    for step in range(2, 11):
        for offset in range(step):
            remove = set(range(offset, CT_LEN, step))
            keep = [i for i in range(CT_LEN) if i not in remove]
            if len(keep) >= 60:  # Need enough chars for cribs
                masks.append((f"rm_every{step}_off{offset}", keep))

    # 6. Remove positions where CT char matches a specific letter (null indicator)
    for null_char_idx in range(26):
        null_char = ALPH[null_char_idx]
        remove = {i for i in range(CT_LEN) if CT[i] == null_char}
        if 1 <= len(remove) <= 20:  # Reasonable null count
            keep = [i for i in range(CT_LEN) if i not in remove]
            masks.append((f"rm_char_{null_char}", keep))

    # 7. Remove positions from mod-7 doubled positions specifically
    # (5 of 6 doubled positions are ≡ 4 mod 7, p<0.001)
    mod7_eq4 = {i for i in range(CT_LEN) if i % 7 == 4}
    keep = [i for i in range(CT_LEN) if i not in mod7_eq4]
    masks.append(("rm_mod7eq4_struct", keep))

    # 8. Remove the 6 doubled positions only (one from each pair)
    masks.append(("rm_6doubled_pos", [i for i in range(CT_LEN) if i not in first_of_doubled]))

    return masks


def remap_cribs_for_mask(keep_positions: List[int]) -> Dict[int, int]:
    """Remap crib positions after null removal.

    Original crib at position P maps to new position = index of P in keep_positions.
    If P was removed, that crib is lost.
    """
    pos_map = {old: new for new, old in enumerate(keep_positions)}
    new_cribs: Dict[int, int] = {}
    for pos, expected_int in CRIB_PT_INT.items():
        if pos in pos_map:
            new_cribs[pos_map[pos]] = expected_int
    return new_cribs


def phase1_worker(args: Tuple) -> Dict[str, Any]:
    """Test null removal + cipher variant on reduced CT."""
    (mask_name, keep_positions, variant_name,
     period_start, period_end, db_path_str) = args

    decrypt_fn = DECRYPT_FNS[variant_name]
    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)

    # Build reduced CT
    reduced_ct_int = [CT_INT[i] for i in keep_positions]
    reduced_len = len(reduced_ct_int)

    # Remap cribs
    new_cribs = remap_cribs_for_mask(keep_positions)
    n_possible_cribs = len(new_cribs)

    if n_possible_cribs < 8:
        # Too few cribs to discriminate — skip
        return {
            "task_id": f"p1|{mask_name}|{variant_name}|{period_start}-{period_end}",
            "n_tested": 0, "best_cribs": 0, "results": [],
        }

    n_tested = 0
    best_cribs_chunk = 0
    results: List[Dict[str, Any]] = []

    for period in range(period_start, period_end):
        if _shutdown_requested:
            break
        if period >= reduced_len:
            continue

        # Test all possible periodic keys of this period
        # For each residue class, determine the required key value from cribs
        # Then check consistency
        residue_constraints: Dict[int, List[Tuple[int, int]]] = {}
        for new_pos, expected_pt in new_cribs.items():
            r = new_pos % period
            required_k = (reduced_ct_int[new_pos] - expected_pt) % 26
            if variant_name == "beaufort":
                required_k = (reduced_ct_int[new_pos] + expected_pt) % 26
            elif variant_name == "var_beaufort":
                required_k = (expected_pt - reduced_ct_int[new_pos]) % 26
            residue_constraints.setdefault(r, []).append((new_pos, required_k))

        # Check if constraints within each residue are consistent
        key = [None] * period
        consistent = True
        cribs_satisfied = 0

        for r, constraints in residue_constraints.items():
            k_vals = set(req_k for _, req_k in constraints)
            if len(k_vals) == 1:
                key[r] = constraints[0][1]
                cribs_satisfied += len(constraints)
            else:
                consistent = False
                # Pick the most popular key value
                from collections import Counter
                counts = Counter(req_k for _, req_k in constraints)
                best_k, best_count = counts.most_common(1)[0]
                key[r] = best_k
                cribs_satisfied += best_count

        n_tested += 1

        if cribs_satisfied > best_cribs_chunk:
            best_cribs_chunk = cribs_satisfied

        if cribs_satisfied >= min(STORE_THRESHOLD, n_possible_cribs - 2):
            # Fill in unconstrained residues with 0 (we'll check all 26 later
            # but for now just test the crib-constrained key)
            full_key = [key[i % period] if key[i % period] is not None else 0
                        for i in range(reduced_len)]
            pt_int = [decrypt_fn(reduced_ct_int[j], full_key[j])
                       for j in range(reduced_len)]
            cribs_actual = fast_crib_score_on(pt_int, new_cribs)
            pt_str = int_to_text(pt_int)
            qg_pc = scorer.score_per_char(pt_str)
            ic_val = fast_ic(pt_int)
            bean = fast_bean_check(full_key)

            config = {
                "mask": mask_name, "variant": variant_name,
                "period": period, "key": [k if k is not None else -1 for k in key],
                "reduced_len": reduced_len, "n_possible_cribs": n_possible_cribs,
                "consistent": consistent,
            }
            cand = {
                "cribs": cribs_actual, "qg_pc": qg_pc, "ic": ic_val,
                "bean": bean, "config": config, "pt": pt_str,
            }
            results.append(cand)
            store_candidate(
                db_p, 1, "null_skip", cribs_actual, qg_pc, ic_val, bean,
                config, pt_str, reduced_len,
            )

            if cribs_actual >= SIGNAL_THRESHOLD:
                print(f"\n*** SIGNAL P1 *** cribs={cribs_actual}/{n_possible_cribs} "
                      f"mask={mask_name} var={variant_name} p={period} "
                      f"PT={pt_str[:60]}...")

    # Also test running key from corpus on reduced CT
    # (deferred to phase1_rk_worker for parallelism)

    return {
        "task_id": f"p1|{mask_name}|{variant_name}|{period_start}-{period_end}",
        "n_tested": n_tested,
        "best_cribs": best_cribs_chunk,
        "results": results,
    }


def phase1_rk_worker(args: Tuple) -> Dict[str, Any]:
    """Test null removal + running key on reduced CT."""
    (mask_name, keep_positions, variant_name,
     text_name, text_int, text_len,
     offset_start, offset_end, db_path_str) = args

    decrypt_fn = DECRYPT_FNS[variant_name]
    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)

    reduced_ct_int = [CT_INT[i] for i in keep_positions]
    reduced_len = len(reduced_ct_int)
    new_cribs = remap_cribs_for_mask(keep_positions)
    n_possible_cribs = len(new_cribs)

    if n_possible_cribs < 8:
        return {
            "task_id": f"p1rk|{mask_name}|{variant_name}|{text_name}|{offset_start}",
            "n_tested": 0, "best_cribs": 0, "results": [],
        }

    n_tested = 0
    best_cribs_chunk = 0
    results: List[Dict[str, Any]] = []

    for offset in range(offset_start, min(offset_end, text_len - reduced_len + 1)):
        if _shutdown_requested:
            break

        n_tested += 1
        key_int = text_int[offset:offset + reduced_len]
        pt_int = [decrypt_fn(reduced_ct_int[j], key_int[j])
                   for j in range(reduced_len)]
        cribs = fast_crib_score_on(pt_int, new_cribs)

        if cribs > best_cribs_chunk:
            best_cribs_chunk = cribs

        if cribs >= min(STORE_THRESHOLD, n_possible_cribs - 2):
            pt_str = int_to_text(pt_int)
            qg_pc = scorer.score_per_char(pt_str)
            ic_val = fast_ic(pt_int)
            bean = fast_bean_check(key_int)

            config = {
                "mask": mask_name, "variant": variant_name,
                "source": text_name, "offset": offset,
                "reduced_len": reduced_len, "n_possible_cribs": n_possible_cribs,
            }
            results.append({
                "cribs": cribs, "qg_pc": qg_pc, "ic": ic_val,
                "bean": bean, "config": config, "pt": pt_str,
            })
            store_candidate(
                db_p, 1, "null_skip_rk", cribs, qg_pc, ic_val, bean,
                config, pt_str, reduced_len,
            )

    return {
        "task_id": f"p1rk|{mask_name}|{variant_name}|{text_name}|{offset_start}",
        "n_tested": n_tested,
        "best_cribs": best_cribs_chunk,
        "results": results,
    }


def build_phase1_tasks(db_path: Path) -> List[Tuple]:
    """Build all Phase 1 tasks: null masks x variants x periods + running key."""
    tasks: List[Tuple] = []
    masks = generate_null_masks()
    all_texts = load_all_texts()

    # Periodic key tasks
    for mask_name, keep_positions in masks:
        reduced_len = len(keep_positions)
        for vname in VARIANT_NAMES:
            # Periods 1 through min(30, reduced_len)
            max_period = min(30, reduced_len)
            # Split into chunks of 10 periods
            for p_start in range(1, max_period + 1, 10):
                p_end = min(p_start + 10, max_period + 1)
                tasks.append((
                    mask_name, keep_positions, vname,
                    p_start, p_end, str(db_path),
                ))

    # Running key tasks (top masks only — too many otherwise)
    top_masks = [m for m in masks if m[0] in (
        "rm_doubled_2nd", "rm_doubled_1st", "rm_doubled_both",
        "rm_mod7eq4", "rm_mod7eq4_struct", "rm_6doubled_pos",
    )]
    for mask_name, keep_positions in top_masks:
        reduced_len = len(keep_positions)
        for vname in VARIANT_NAMES:
            for text_name, text_int, text_len in all_texts:
                n_offsets = text_len - reduced_len + 1
                if n_offsets <= 0:
                    continue
                chunk_size = 50000
                for start in range(0, n_offsets, chunk_size):
                    end = min(start + chunk_size, n_offsets)
                    tasks.append((
                        mask_name, keep_positions, vname,
                        text_name, text_int, text_len,
                        start, end, str(db_path),
                    ))

    return tasks


def run_phase1(
    workers: int, checkpoint: Checkpoint, logger: logging.Logger,
) -> Checkpoint:
    """Phase 1: Null/Skip Pattern Search."""
    phase_key = "phase1"
    if checkpoint.phase_done.get(phase_key):
        logger.info("Phase 1 already complete, skipping")
        return checkpoint

    logger.info("=" * 72)
    logger.info("PHASE 1: Null/Skip Pattern Search (NEVER TESTED)")
    logger.info("=" * 72)

    masks = generate_null_masks()
    logger.info(f"Null masks: {len(masks)}")
    for name, keep in masks[:10]:
        logger.info(f"  {name}: {len(keep)} chars kept (removed {CT_LEN - len(keep)})")
    if len(masks) > 10:
        logger.info(f"  ... and {len(masks) - 10} more")

    init_db(DB_PATH)

    # Build periodic key tasks
    periodic_tasks: List[Tuple] = []
    for mask_name, keep_positions in masks:
        reduced_len = len(keep_positions)
        for vname in VARIANT_NAMES:
            max_period = min(30, reduced_len)
            for p_start in range(1, max_period + 1, 10):
                p_end = min(p_start + 10, max_period + 1)
                periodic_tasks.append((
                    mask_name, keep_positions, vname,
                    p_start, p_end, str(DB_PATH),
                ))

    logger.info(f"Phase 1 periodic tasks: {len(periodic_tasks)}")

    completed = 0
    total_tested = checkpoint.phase_tested.get(phase_key, 0)
    start_time = time.time()
    last_progress = start_time
    best_overall = 0

    with mp.Pool(workers) as pool:
        for result in pool.imap_unordered(phase1_worker, periodic_tasks, chunksize=4):
            if _shutdown_requested:
                pool.terminate()
                break
            completed += 1
            total_tested += result["n_tested"]
            for cand in result.get("results", []):
                checkpoint.add_candidate(cand)
            if result["best_cribs"] > best_overall:
                best_overall = result["best_cribs"]

            now = time.time()
            if now - last_progress >= 60:
                elapsed = now - start_time
                logger.info(
                    f"P1-periodic: {completed}/{len(periodic_tasks)} | "
                    f"{total_tested:,} tested | best={best_overall} | "
                    f"elapsed={elapsed/60:.1f}m"
                )
                last_progress = now

    logger.info(f"P1 periodic done: {total_tested:,} configs, best={best_overall}")

    # Running key tasks on top masks
    if not _shutdown_requested:
        all_texts = load_all_texts()
        top_mask_names = {
            "rm_doubled_2nd", "rm_doubled_1st", "rm_doubled_both",
            "rm_mod7eq4", "rm_mod7eq4_struct", "rm_6doubled_pos",
        }
        top_masks = [m for m in masks if m[0] in top_mask_names]

        rk_tasks: List[Tuple] = []
        for mask_name, keep_positions in top_masks:
            reduced_len = len(keep_positions)
            for vname in VARIANT_NAMES:
                for text_name, text_int, text_len in all_texts:
                    n_offsets = text_len - reduced_len + 1
                    if n_offsets <= 0:
                        continue
                    chunk_size = 50000
                    for start in range(0, n_offsets, chunk_size):
                        end = min(start + chunk_size, n_offsets)
                        rk_tasks.append((
                            mask_name, keep_positions, vname,
                            text_name, text_int, text_len,
                            start, end, str(DB_PATH),
                        ))

        if rk_tasks:
            logger.info(f"Phase 1 running-key tasks: {len(rk_tasks)}")
            rk_completed = 0
            rk_tested = 0

            with mp.Pool(workers) as pool:
                for result in pool.imap_unordered(phase1_rk_worker, rk_tasks, chunksize=1):
                    if _shutdown_requested:
                        pool.terminate()
                        break
                    rk_completed += 1
                    rk_tested += result["n_tested"]
                    total_tested += result["n_tested"]
                    for cand in result.get("results", []):
                        checkpoint.add_candidate(cand)
                    if result["best_cribs"] > best_overall:
                        best_overall = result["best_cribs"]

                    now = time.time()
                    if now - last_progress >= 60:
                        elapsed = now - start_time
                        logger.info(
                            f"P1-rk: {rk_completed}/{len(rk_tasks)} | "
                            f"{rk_tested:,} offsets | best={best_overall} | "
                            f"elapsed={elapsed/60:.1f}m"
                        )
                        last_progress = now

            logger.info(f"P1 running-key done: {rk_tested:,} offsets")

    elapsed = time.time() - start_time
    logger.info(f"Phase 1 complete: {total_tested:,} total configs in {elapsed/60:.1f}m")
    logger.info(f"Phase 1 best cribs: {best_overall}")
    checkpoint.phase_tested[phase_key] = total_tested
    checkpoint.phase_done[phase_key] = True
    checkpoint.phase = max(checkpoint.phase, 1)
    checkpoint.save(CHECKPOINT_PATH)
    return checkpoint


# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: Shared-Key Transposition (Same keyword for sub + trans)
# ══════════════════════════════════════════════════════════════════════════
#
# Hypothesis: Sanborn used ONE keyword for everything — the keyword gives
# both the Vigenère key AND the columnar column ordering.
# This has NEVER been tested as a joint model.

# Thematic keyword candidates from Sanborn's known references
PHASE2_KEYWORDS = [
    # Core Kryptos words
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "IQLUSION", "SHADOW",
    "LUCID", "MEMORY", "ENIGMA", "CIPHER", "SECRET",
    # K2 theme (Operation Gold)
    "BERLINTUNNEL", "LANGLEY", "MAGNETIC",
    "INVISIBLE", "UNDERGROUND", "BURIED",
    # K3 theme (Carter/Tut)
    "TUTANKHAMUN", "CARTER", "CANDLE", "CHAMBER", "MIST",
    "TREMBLING", "PASSAGE", "DEBRIS", "DOORWAY", "FLICKERING",
    # Sanborn references
    "SANBORN", "SCHEIDT", "WEBSTER", "LODESTONE", "COMPASS",
    "SCULPTURE", "COPPERPLATE", "PETRIFIED",
    # CIA/intelligence
    "CENTRAL", "INTELLIGENCE", "AGENCY", "CLASSIFIED",
    "DIRECTOR", "COVERT", "CLANDESTINE",
    # Berlin
    "CHECKPOINT", "CHARLIE", "CHARLIE", "FRIEDRICHSTRASSE",
    "BERLIN", "WALL", "BERLINCLOCK", "WELTZEITUHR",
    # Historical
    "HIEROGLYPH", "ROSETTA", "PHARAOH", "PYRAMID",
    "SPHINX", "OBELISK", "OSIRIS", "ANUBIS",
    # NATO/military
    "ALPHA", "BRAVO", "DELTA", "FOXTROT", "NOVEMBER",
    "OSCAR", "TANGO", "WHISKEY", "YANKEE",
    # Compound keywords (length 7-14, matching likely widths)
    "KRYPTOSPALIMPSEST", "KRYPTOSABSCISSA", "EASTNORTHEAST",
    "BERLINCLOCK", "SHADOWLIGHT", "SECRETCODE",
    "HIDDENTRUTH", "NIGHTLIGHT", "DARKSECRET",
    # Misspelling-derived
    "DESPARATLY", "IQLUSION", "UNDERGRUUND", "DIGETAL",
    # YAR-related
    "YAR", "YARKRYPTOS", "KRYPTOSYAR",
]
# Remove duplicates while preserving order
_seen = set()
PHASE2_KEYWORDS_UNIQUE: List[str] = []
for _kw in PHASE2_KEYWORDS:
    _kw_upper = _kw.upper()
    if _kw_upper not in _seen:
        _seen.add(_kw_upper)
        PHASE2_KEYWORDS_UNIQUE.append(_kw_upper)
PHASE2_KEYWORDS = PHASE2_KEYWORDS_UNIQUE


def derive_vig_key_from_keyword(keyword: str, length: int) -> List[int]:
    """Repeat keyword to produce a key of given length."""
    key_int = [ALPH_IDX[c] for c in keyword.upper() if c in ALPH_IDX]
    if not key_int:
        return [0] * length
    return [key_int[i % len(key_int)] for i in range(length)]


def derive_ka_key_from_keyword(keyword: str, length: int) -> List[int]:
    """Repeat keyword using KRYPTOS alphabet indices."""
    key_int = [KA_IDX.get(c, 0) for c in keyword.upper() if c in KA_IDX]
    if not key_int:
        return [0] * length
    return [key_int[i % len(key_int)] for i in range(length)]


def phase2_worker(args: Tuple) -> Dict[str, Any]:
    """Test shared-key model: keyword → col order + cipher key."""
    (keyword, model, variant_name, alphabet, db_path_str) = args

    decrypt_fn = DECRYPT_FNS[variant_name]
    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)

    kw_len = len(keyword)
    col_order = keyword_to_col_order(keyword)

    if alphabet == "AZ":
        key_int = derive_vig_key_from_keyword(keyword, CT_LEN)
    else:
        key_int = derive_ka_key_from_keyword(keyword, CT_LEN)

    n_tested = 0
    best_cribs_chunk = 0
    results: List[Dict[str, Any]] = []

    if model == "A":
        # Model A: PT → columnar → IT → sub → CT
        # Decrypt: CT → unsub → IT → undo columnar → PT
        it_int = [decrypt_fn(CT_INT[j], key_int[j]) for j in range(CT_LEN)]
        pt_int = columnar_decrypt(it_int, col_order)
    else:
        # Model B: PT → sub → IT → columnar → CT
        # Decrypt: CT → undo columnar → IT → unsub → PT
        it_int = columnar_decrypt(CT_INT, col_order)
        pt_int = [decrypt_fn(it_int[j], key_int[j]) for j in range(CT_LEN)]

    n_tested += 1
    cribs = fast_crib_score(pt_int)

    if cribs > best_cribs_chunk:
        best_cribs_chunk = cribs

    if cribs >= STORE_THRESHOLD:
        pt_str = int_to_text(pt_int)
        qg_pc = scorer.score_per_char(pt_str)
        ic_val = fast_ic(pt_int)
        bean = fast_bean_check(key_int)

        config = {
            "keyword": keyword, "model": model,
            "variant": variant_name, "alphabet": alphabet,
            "col_order": col_order,
        }
        results.append({
            "cribs": cribs, "qg_pc": qg_pc, "ic": ic_val,
            "bean": bean, "config": config, "pt": pt_str,
        })
        store_candidate(
            db_p, 2, "shared_key", cribs, qg_pc, ic_val, bean,
            config, pt_str,
        )

        if cribs >= SIGNAL_THRESHOLD:
            print(f"\n*** SIGNAL P2 *** cribs={cribs}/{N_CRIBS} "
                  f"kw={keyword} model={model} var={variant_name} "
                  f"alph={alphabet} PT={pt_str[:60]}...")

    # Also test with keyword shifted by each possible amount (Caesar shift)
    for shift in range(1, 26):
        if _shutdown_requested:
            break
        shifted_key = [(k + shift) % 26 for k in key_int]
        n_tested += 1

        if model == "A":
            it_int = [decrypt_fn(CT_INT[j], shifted_key[j]) for j in range(CT_LEN)]
            pt_int = columnar_decrypt(it_int, col_order)
        else:
            it_int = columnar_decrypt(CT_INT, col_order)
            pt_int = [decrypt_fn(it_int[j], shifted_key[j]) for j in range(CT_LEN)]

        cribs = fast_crib_score(pt_int)
        if cribs > best_cribs_chunk:
            best_cribs_chunk = cribs

        if cribs >= STORE_THRESHOLD:
            pt_str = int_to_text(pt_int)
            qg_pc = scorer.score_per_char(pt_str)
            ic_val = fast_ic(pt_int)
            bean = fast_bean_check(shifted_key)

            config = {
                "keyword": keyword, "model": model,
                "variant": variant_name, "alphabet": alphabet,
                "shift": shift, "col_order": col_order,
            }
            results.append({
                "cribs": cribs, "qg_pc": qg_pc, "ic": ic_val,
                "bean": bean, "config": config, "pt": pt_str,
            })
            store_candidate(
                db_p, 2, "shared_key_shifted", cribs, qg_pc, ic_val, bean,
                config, pt_str,
            )

    return {
        "task_id": f"p2|{keyword}|{model}|{variant_name}|{alphabet}",
        "n_tested": n_tested,
        "best_cribs": best_cribs_chunk,
        "results": results,
    }


def phase2_exhaustive_worker(args: Tuple) -> Dict[str, Any]:
    """Exhaustive shared-key: all keywords of width W from wordlist."""
    (width, model, variant_name, alphabet,
     words_chunk, db_path_str) = args

    decrypt_fn = DECRYPT_FNS[variant_name]
    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)

    n_tested = 0
    best_cribs_chunk = 0
    results: List[Dict[str, Any]] = []

    for word in words_chunk:
        if _shutdown_requested:
            break

        col_order = keyword_to_col_order(word)
        if alphabet == "AZ":
            key_int = derive_vig_key_from_keyword(word, CT_LEN)
        else:
            key_int = derive_ka_key_from_keyword(word, CT_LEN)

        for shift in range(26):
            if _shutdown_requested:
                break
            n_tested += 1

            if shift > 0:
                sk = [(k + shift) % 26 for k in key_int]
            else:
                sk = key_int

            if model == "A":
                it_int = [decrypt_fn(CT_INT[j], sk[j]) for j in range(CT_LEN)]
                pt_int = columnar_decrypt(it_int, col_order)
            else:
                it_int = columnar_decrypt(CT_INT, col_order)
                pt_int = [decrypt_fn(it_int[j], sk[j]) for j in range(CT_LEN)]

            cribs = fast_crib_score(pt_int)
            if cribs > best_cribs_chunk:
                best_cribs_chunk = cribs

            if cribs >= STORE_THRESHOLD:
                pt_str = int_to_text(pt_int)
                qg_pc = scorer.score_per_char(pt_str)
                ic_val = fast_ic(pt_int)
                bean = fast_bean_check(sk)

                config = {
                    "keyword": word, "model": model,
                    "variant": variant_name, "alphabet": alphabet,
                    "shift": shift, "width": width,
                }
                results.append({
                    "cribs": cribs, "qg_pc": qg_pc, "ic": ic_val,
                    "bean": bean, "config": config, "pt": pt_str,
                })
                store_candidate(
                    db_p, 2, "shared_key_exhaust", cribs, qg_pc, ic_val, bean,
                    config, pt_str,
                )

    return {
        "task_id": f"p2x|w{width}|{model}|{variant_name}|{alphabet}|{len(words_chunk)}",
        "n_tested": n_tested,
        "best_cribs": best_cribs_chunk,
        "results": results,
    }


def run_phase2(
    workers: int, checkpoint: Checkpoint, logger: logging.Logger,
) -> Checkpoint:
    """Phase 2: Shared-Key Transposition."""
    phase_key = "phase2"
    if checkpoint.phase_done.get(phase_key):
        logger.info("Phase 2 already complete, skipping")
        return checkpoint

    logger.info("=" * 72)
    logger.info("PHASE 2: Shared-Key Transposition (NEVER TESTED)")
    logger.info("=" * 72)
    logger.info(f"Thematic keywords: {len(PHASE2_KEYWORDS)}")

    init_db(DB_PATH)

    # Part A: Thematic keywords
    tasks_a: List[Tuple] = []
    for kw in PHASE2_KEYWORDS:
        for model in ["A", "B"]:
            for vname in VARIANT_NAMES:
                for alph in ["AZ", "KA"]:
                    tasks_a.append((kw, model, vname, alph, str(DB_PATH)))

    logger.info(f"Phase 2A (thematic): {len(tasks_a)} tasks")

    completed = 0
    total_tested = 0
    start_time = time.time()
    last_progress = start_time
    best_overall = 0

    with mp.Pool(workers) as pool:
        for result in pool.imap_unordered(phase2_worker, tasks_a, chunksize=4):
            if _shutdown_requested:
                pool.terminate()
                break
            completed += 1
            total_tested += result["n_tested"]
            for cand in result.get("results", []):
                checkpoint.add_candidate(cand)
            if result["best_cribs"] > best_overall:
                best_overall = result["best_cribs"]

            now = time.time()
            if now - last_progress >= 60:
                elapsed = now - start_time
                logger.info(
                    f"P2A: {completed}/{len(tasks_a)} | "
                    f"{total_tested:,} tested | best={best_overall} | "
                    f"elapsed={elapsed/60:.1f}m"
                )
                last_progress = now

    logger.info(f"P2A done: {total_tested:,} configs, best={best_overall}")

    # Part B: Exhaustive wordlist at key widths
    if not _shutdown_requested:
        wl_path = PROJECT_ROOT / "wordlists" / "english.txt"
        if wl_path.exists():
            all_words = wl_path.read_text().strip().upper().split("\n")
            # Only words of length matching viable widths
            target_widths = [7, 8, 9, 11, 13, 14]
            for width in target_widths:
                if _shutdown_requested:
                    break
                width_words = [w.strip() for w in all_words
                               if len(w.strip()) == width and w.strip().isalpha()]
                if not width_words:
                    continue

                logger.info(f"P2B: width={width}, {len(width_words)} words")

                # Chunk the words
                chunk_size = 200
                tasks_b: List[Tuple] = []
                for model in ["A", "B"]:
                    for vname in VARIANT_NAMES:
                        for alph in ["AZ", "KA"]:
                            for i in range(0, len(width_words), chunk_size):
                                chunk = width_words[i:i+chunk_size]
                                tasks_b.append((
                                    width, model, vname, alph,
                                    chunk, str(DB_PATH),
                                ))

                b_completed = 0
                with mp.Pool(workers) as pool:
                    for result in pool.imap_unordered(
                        phase2_exhaustive_worker, tasks_b, chunksize=1
                    ):
                        if _shutdown_requested:
                            pool.terminate()
                            break
                        b_completed += 1
                        total_tested += result["n_tested"]
                        for cand in result.get("results", []):
                            checkpoint.add_candidate(cand)
                        if result["best_cribs"] > best_overall:
                            best_overall = result["best_cribs"]

                        now = time.time()
                        if now - last_progress >= 60:
                            elapsed = now - start_time
                            logger.info(
                                f"P2B w={width}: {b_completed}/{len(tasks_b)} | "
                                f"{total_tested:,} tested | best={best_overall}"
                            )
                            last_progress = now

    elapsed = time.time() - start_time
    logger.info(f"Phase 2 complete: {total_tested:,} configs in {elapsed/60:.1f}m")
    logger.info(f"Phase 2 best cribs: {best_overall}")
    checkpoint.phase_tested[phase_key] = total_tested
    checkpoint.phase_done[phase_key] = True
    checkpoint.phase = max(checkpoint.phase, 2)
    checkpoint.save(CHECKPOINT_PATH)
    return checkpoint


# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: Non-Standard Tableau Lookup
# ══════════════════════════════════════════════════════════════════════════
#
# The Vigenère tableau is physically visible on the Kryptos sculpture.
# Standard usage: cell = row ⊕ col where row/col/cell map to PT/KEY/CT.
# But there are 6 permutations of (row, col, cell) → (PT, KEY, CT),
# and 4 alphabet combos for row/col headers (AZ×AZ, KA×AZ, AZ×KA, KA×KA).
# This gives 24 tableau interpretations × running keys.

def build_tableau(row_alph: str, col_alph: str) -> List[List[int]]:
    """Build a 26×26 tableau where cell[r][c] = (row_alph[r] + col_alph[c]) % 26.

    Returns integer values (standard A=0 alphabet).
    """
    row_vals = [ALPH_IDX[ch] for ch in row_alph]
    col_vals = [ALPH_IDX[ch] for ch in col_alph]
    return [[(rv + cv) % 26 for cv in col_vals] for rv in row_vals]


def tableau_lookup(tableau: List[List[int]], row_idx: int, col_idx: int) -> int:
    """Standard forward lookup: given row and col indices, return cell value."""
    return tableau[row_idx][col_idx]


def tableau_reverse_row(tableau: List[List[int]], cell_val: int, col_idx: int) -> int:
    """Given cell value and column index, find the row index."""
    for r in range(26):
        if tableau[r][col_idx] == cell_val:
            return r
    return -1


def tableau_reverse_col(tableau: List[List[int]], cell_val: int, row_idx: int) -> int:
    """Given cell value and row index, find the column index."""
    row = tableau[row_idx]
    for c in range(26):
        if row[c] == cell_val:
            return c
    return -1


# Role permutations: which of (row, col, cell) maps to (PT, KEY, CT)?
# Standard Vigenère: row=PT, col=KEY, cell=CT → decrypt: find row where cell=CT given col=KEY
ROLE_PERMS = [
    # (pt_role, key_role, ct_role) — what each refers to in the tableau
    ("row", "col", "cell"),   # Standard Vigenère
    ("col", "row", "cell"),   # Transposed Vigenère
    ("row", "cell", "col"),   # KEY read from cell, CT from column
    ("col", "cell", "row"),   # KEY read from cell, CT from row
    ("cell", "row", "col"),   # PT from cell (lookup CT row, KEY col → PT cell)
    ("cell", "col", "row"),   # PT from cell (lookup CT col, KEY row → PT cell)
]


def tableau_decrypt(
    ct_int: int, key_int: int,
    tableau: List[List[int]],
    pt_role: str, key_role: str, ct_role: str,
) -> int:
    """Decrypt a single character using non-standard tableau roles.

    Given CT and KEY, find PT.
    """
    # Map roles to tableau positions (row, col, cell)
    # We know ct and key values, need to find pt.

    if pt_role == "row" and key_role == "col" and ct_role == "cell":
        # Standard: find row where tableau[row][key] == ct
        return tableau_reverse_row(tableau, ct_int, key_int)

    elif pt_role == "col" and key_role == "row" and ct_role == "cell":
        # Transposed: find col where tableau[key][col] == ct
        return tableau_reverse_col(tableau, ct_int, key_int)

    elif pt_role == "row" and key_role == "cell" and ct_role == "col":
        # KEY=cell, CT=col → given CT (col idx) and KEY (cell val),
        # find row where tableau[row][ct] == key
        return tableau_reverse_row(tableau, key_int, ct_int)

    elif pt_role == "col" and key_role == "cell" and ct_role == "row":
        # KEY=cell, CT=row → given CT (row idx) and KEY (cell val),
        # find col where tableau[ct][col] == key
        return tableau_reverse_col(tableau, key_int, ct_int)

    elif pt_role == "cell" and key_role == "row" and ct_role == "col":
        # PT=cell → tableau[key][ct] = PT
        return tableau[key_int][ct_int]

    elif pt_role == "cell" and key_role == "col" and ct_role == "row":
        # PT=cell → tableau[ct][key] = PT
        return tableau[ct_int][key_int]

    return -1


def phase3_worker(args: Tuple) -> Dict[str, Any]:
    """Test non-standard tableau + running key."""
    (row_alph_name, col_alph_name, role_idx,
     text_name, text_int, text_len,
     offset_start, offset_end, db_path_str) = args

    row_alph = KRYPTOS_ALPHABET if row_alph_name == "KA" else ALPH
    col_alph = KRYPTOS_ALPHABET if col_alph_name == "KA" else ALPH
    tableau = build_tableau(row_alph, col_alph)
    pt_role, key_role, ct_role = ROLE_PERMS[role_idx]

    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)

    # Map CT chars through the appropriate alphabet
    if ct_role == "row" or ct_role == "col":
        # CT values need to be indices into the row/col alphabet
        ct_alph = row_alph if ct_role == "row" else col_alph
        ct_idx_map = {c: i for i, c in enumerate(ct_alph)}
        ct_mapped = [ct_idx_map.get(c, 0) for c in CT]
    else:
        # CT is a cell value — use standard A=0
        ct_mapped = CT_INT[:]

    # Similarly map key values
    if key_role == "row":
        key_alph = row_alph
    elif key_role == "col":
        key_alph = col_alph
    else:  # cell
        key_alph = ALPH  # cell values are standard
    key_idx_map = {c: i for i, c in enumerate(key_alph)}

    n_tested = 0
    best_cribs_chunk = 0
    results: List[Dict[str, Any]] = []

    for offset in range(offset_start, min(offset_end, text_len - CT_LEN + 1)):
        if _shutdown_requested:
            break

        n_tested += 1

        # Map key text through appropriate alphabet
        raw_key = text_int[offset:offset + CT_LEN]
        key_mapped = [raw_key[j] if key_role == "cell"
                      else key_idx_map.get(ALPH[raw_key[j]], 0)
                      for j in range(CT_LEN)]

        pt_int = []
        valid = True
        for j in range(CT_LEN):
            p = tableau_decrypt(ct_mapped[j], key_mapped[j],
                                tableau, pt_role, key_role, ct_role)
            if p < 0:
                valid = False
                break
            # Map PT back to standard A=0
            if pt_role == "row":
                p_std = ALPH_IDX.get(row_alph[p], p)
            elif pt_role == "col":
                p_std = ALPH_IDX.get(col_alph[p], p)
            else:
                p_std = p
            pt_int.append(p_std)

        if not valid:
            continue

        cribs = fast_crib_score(pt_int)
        if cribs > best_cribs_chunk:
            best_cribs_chunk = cribs

        if cribs >= STORE_THRESHOLD:
            pt_str = int_to_text(pt_int)
            qg_pc = scorer.score_per_char(pt_str)
            ic_val = fast_ic(pt_int)
            bean = fast_bean_check(key_mapped)

            config = {
                "row_alph": row_alph_name, "col_alph": col_alph_name,
                "roles": f"pt={pt_role},key={key_role},ct={ct_role}",
                "source": text_name, "offset": offset,
            }
            results.append({
                "cribs": cribs, "qg_pc": qg_pc, "ic": ic_val,
                "bean": bean, "config": config, "pt": pt_str,
            })
            store_candidate(
                db_p, 3, "tableau_nonstandard", cribs, qg_pc, ic_val, bean,
                config, pt_str,
            )

            if cribs >= SIGNAL_THRESHOLD:
                print(f"\n*** SIGNAL P3 *** cribs={cribs}/{N_CRIBS} "
                      f"row={row_alph_name} col={col_alph_name} "
                      f"roles=pt={pt_role},key={key_role},ct={ct_role} "
                      f"src={text_name} off={offset}")

    return {
        "task_id": f"p3|{row_alph_name}|{col_alph_name}|r{role_idx}|{text_name}|{offset_start}",
        "n_tested": n_tested,
        "best_cribs": best_cribs_chunk,
        "results": results,
    }


def phase3_periodic_worker(args: Tuple) -> Dict[str, Any]:
    """Test non-standard tableau + periodic key."""
    (row_alph_name, col_alph_name, role_idx,
     period_start, period_end, db_path_str) = args

    row_alph = KRYPTOS_ALPHABET if row_alph_name == "KA" else ALPH
    col_alph = KRYPTOS_ALPHABET if col_alph_name == "KA" else ALPH
    tableau = build_tableau(row_alph, col_alph)
    pt_role, key_role, ct_role = ROLE_PERMS[role_idx]

    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)

    # Map CT through appropriate alphabet
    if ct_role == "row":
        ct_alph = row_alph
    elif ct_role == "col":
        ct_alph = col_alph
    else:
        ct_alph = ALPH
    ct_idx_map = {c: i for i, c in enumerate(ct_alph)}
    ct_mapped = [ct_idx_map.get(c, 0) for c in CT]

    n_tested = 0
    best_cribs_chunk = 0
    results: List[Dict[str, Any]] = []

    for period in range(period_start, period_end):
        if _shutdown_requested:
            break

        # For each residue class, determine required key from cribs
        residue_constraints: Dict[int, List[Tuple[int, int]]] = {}
        for pos, expected_pt in CRIB_PT_INT.items():
            r = pos % period
            # What key value makes tableau_decrypt(ct_mapped[pos], key, ...) == expected_pt?
            # We need to enumerate all 26 possible key values
            for k_try in range(26):
                p = tableau_decrypt(ct_mapped[pos], k_try, tableau,
                                    pt_role, key_role, ct_role)
                if p >= 0:
                    # Map back to standard
                    if pt_role == "row":
                        p_std = ALPH_IDX.get(row_alph[p], p)
                    elif pt_role == "col":
                        p_std = ALPH_IDX.get(col_alph[p], p)
                    else:
                        p_std = p
                    if p_std == expected_pt:
                        residue_constraints.setdefault(r, []).append((pos, k_try))
                        break  # First match

        # Check consistency within each residue
        key = [None] * period
        cribs_satisfied = 0
        for r, constraints in residue_constraints.items():
            from collections import Counter
            k_vals = Counter(req_k for _, req_k in constraints)
            best_k, best_count = k_vals.most_common(1)[0]
            key[r] = best_k
            cribs_satisfied += best_count

        n_tested += 1

        if cribs_satisfied > best_cribs_chunk:
            best_cribs_chunk = cribs_satisfied

        if cribs_satisfied >= STORE_THRESHOLD:
            full_key = [key[i % period] if key[i % period] is not None else 0
                        for i in range(CT_LEN)]
            pt_int = []
            for j in range(CT_LEN):
                p = tableau_decrypt(ct_mapped[j], full_key[j], tableau,
                                    pt_role, key_role, ct_role)
                if p < 0:
                    pt_int.append(0)
                else:
                    if pt_role == "row":
                        pt_int.append(ALPH_IDX.get(row_alph[p], p))
                    elif pt_role == "col":
                        pt_int.append(ALPH_IDX.get(col_alph[p], p))
                    else:
                        pt_int.append(p)

            pt_str = int_to_text(pt_int)
            qg_pc = scorer.score_per_char(pt_str)
            ic_val = fast_ic(pt_int)
            bean = fast_bean_check(full_key)

            config = {
                "row_alph": row_alph_name, "col_alph": col_alph_name,
                "roles": f"pt={pt_role},key={key_role},ct={ct_role}",
                "period": period,
                "key": [k if k is not None else -1 for k in key],
            }
            results.append({
                "cribs": cribs_satisfied, "qg_pc": qg_pc, "ic": ic_val,
                "bean": bean, "config": config, "pt": pt_str,
            })
            store_candidate(
                db_p, 3, "tableau_periodic", cribs_satisfied, qg_pc, ic_val,
                bean, config, pt_str,
            )

    return {
        "task_id": f"p3p|{row_alph_name}|{col_alph_name}|r{role_idx}|{period_start}-{period_end}",
        "n_tested": n_tested,
        "best_cribs": best_cribs_chunk,
        "results": results,
    }


def run_phase3(
    workers: int, checkpoint: Checkpoint, logger: logging.Logger,
) -> Checkpoint:
    """Phase 3: Non-Standard Tableau Lookup."""
    phase_key = "phase3"
    if checkpoint.phase_done.get(phase_key):
        logger.info("Phase 3 already complete, skipping")
        return checkpoint

    logger.info("=" * 72)
    logger.info("PHASE 3: Non-Standard Tableau Lookup (NOVEL ANGLES)")
    logger.info("=" * 72)
    logger.info(f"Role permutations: {len(ROLE_PERMS)}")
    logger.info(f"Alphabet combos: 4 (AZ×AZ, KA×AZ, AZ×KA, KA×KA)")

    init_db(DB_PATH)
    all_texts = load_all_texts()
    total_tested = 0
    start_time = time.time()
    last_progress = start_time
    best_overall = 0

    # Part A: Periodic key
    alph_combos = [("AZ", "AZ"), ("KA", "AZ"), ("AZ", "KA"), ("KA", "KA")]
    periodic_tasks: List[Tuple] = []
    for row_a, col_a in alph_combos:
        for ri in range(len(ROLE_PERMS)):
            for p_start in range(1, 31, 10):
                p_end = min(p_start + 10, 31)
                periodic_tasks.append((
                    row_a, col_a, ri, p_start, p_end, str(DB_PATH),
                ))

    logger.info(f"Phase 3 periodic tasks: {len(periodic_tasks)}")

    with mp.Pool(workers) as pool:
        for result in pool.imap_unordered(phase3_periodic_worker, periodic_tasks, chunksize=4):
            if _shutdown_requested:
                pool.terminate()
                break
            total_tested += result["n_tested"]
            for cand in result.get("results", []):
                checkpoint.add_candidate(cand)
            if result["best_cribs"] > best_overall:
                best_overall = result["best_cribs"]

    logger.info(f"P3 periodic: {total_tested:,} configs, best={best_overall}")

    # Part B: Running key
    if not _shutdown_requested:
        rk_tasks: List[Tuple] = []
        for row_a, col_a in alph_combos:
            for ri in range(len(ROLE_PERMS)):
                for text_name, text_int, text_len in all_texts:
                    n_offsets = text_len - CT_LEN + 1
                    if n_offsets <= 0:
                        continue
                    chunk_size = 50000
                    for start in range(0, n_offsets, chunk_size):
                        end = min(start + chunk_size, n_offsets)
                        rk_tasks.append((
                            row_a, col_a, ri,
                            text_name, text_int, text_len,
                            start, end, str(DB_PATH),
                        ))

        logger.info(f"Phase 3 running-key tasks: {len(rk_tasks)}")
        rk_completed = 0

        with mp.Pool(workers) as pool:
            for result in pool.imap_unordered(phase3_worker, rk_tasks, chunksize=1):
                if _shutdown_requested:
                    pool.terminate()
                    break
                rk_completed += 1
                total_tested += result["n_tested"]
                for cand in result.get("results", []):
                    checkpoint.add_candidate(cand)
                if result["best_cribs"] > best_overall:
                    best_overall = result["best_cribs"]

                now = time.time()
                if now - last_progress >= 60:
                    elapsed = now - start_time
                    logger.info(
                        f"P3-rk: {rk_completed}/{len(rk_tasks)} | "
                        f"{total_tested:,} tested | best={best_overall} | "
                        f"elapsed={elapsed/60:.1f}m"
                    )
                    last_progress = now

    elapsed = time.time() - start_time
    logger.info(f"Phase 3 complete: {total_tested:,} configs in {elapsed/60:.1f}m")
    logger.info(f"Phase 3 best cribs: {best_overall}")
    checkpoint.phase_tested[phase_key] = total_tested
    checkpoint.phase_done[phase_key] = True
    checkpoint.phase = max(checkpoint.phase, 3)
    checkpoint.save(CHECKPOINT_PATH)
    return checkpoint


# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: Sculpture-Parameter Position Cipher
# ══════════════════════════════════════════════════════════════════════════
#
# Uses YAR, RQ, compass bearing, and other sculpture-derived values as
# position-dependent key modifiers.

# YAR values: test BOTH A=0 [24,0,17] and A=1 [25,1,18] conventions,
# plus the user's [24,1,17] variant
YAR_SEQUENCES = [
    ("YAR_A0", [24, 0, 17]),      # A=0: Y=24, A=0, R=17
    ("YAR_A1", [25, 1, 18]),      # A=1: Y=25, A=1, R=18
    ("YAR_user", [24, 1, 17]),    # User's stated convention
]

# RQ values
RQ_SEQUENCES = [
    ("RQ_A0", [17, 16]),          # A=0: R=17, Q=16
    ("RQ_A1", [18, 17]),          # A=1: R=18, Q=17
]

# Compass bearing: ENE ≈ 67.5° → various derived values
COMPASS_VALS = [67, 68, 45, 90, 135, 180, 225, 270, 315]

# "T IS YOUR POSITION" → T=19 (A=0) or T=20 (A=1)
T_VALS = [19, 20]


def generate_position_keys() -> List[Tuple[str, List[int]]]:
    """Generate position-dependent keys from sculpture parameters.

    Each entry is (description, key_of_length_97).
    """
    keys: List[Tuple[str, List[int]]] = []

    # 1. YAR-repeating as periodic key
    for yar_name, yar_vals in YAR_SEQUENCES:
        # Period-3 repeating
        key = [yar_vals[i % 3] for i in range(CT_LEN)]
        keys.append((f"{yar_name}_repeat3", key))

        # YAR cycling with T offset
        for t in T_VALS:
            key = [(yar_vals[i % 3] + t) % 26 for i in range(CT_LEN)]
            keys.append((f"{yar_name}_plus_T{t}", key))

        # YAR as additive increment per position
        for base in range(26):
            key = [(base + yar_vals[i % 3] * (i // 3)) % 26 for i in range(CT_LEN)]
            keys.append((f"{yar_name}_incr_base{base}", key))

    # 2. RQ-repeating
    for rq_name, rq_vals in RQ_SEQUENCES:
        key = [rq_vals[i % 2] for i in range(CT_LEN)]
        keys.append((f"{rq_name}_repeat2", key))

    # 3. YAR+RQ combined (period 5)
    for yar_name, yar_vals in YAR_SEQUENCES:
        for rq_name, rq_vals in RQ_SEQUENCES:
            combined = yar_vals + rq_vals  # length 5
            key = [combined[i % 5] for i in range(CT_LEN)]
            keys.append((f"{yar_name}_{rq_name}_repeat5", key))

    # 4. Position-dependent: key[i] = f(i, params)
    for yar_name, yar_vals in YAR_SEQUENCES:
        y, a, r = yar_vals
        # Linear: key[i] = (y*i + a) mod 26
        key = [(y * i + a) % 26 for i in range(CT_LEN)]
        keys.append((f"{yar_name}_linear_yi_plus_a", key))

        # key[i] = (y*i + r) mod 26
        key = [(y * i + r) % 26 for i in range(CT_LEN)]
        keys.append((f"{yar_name}_linear_yi_plus_r", key))

        # key[i] = (y + a*i + r*i^2) mod 26
        key = [(y + a * i + r * (i * i)) % 26 for i in range(CT_LEN)]
        keys.append((f"{yar_name}_quadratic", key))

        # key[i] = (y*a + r*i) mod 26
        key = [(y * a + r * i) % 26 for i in range(CT_LEN)]
        keys.append((f"{yar_name}_ya_plus_ri", key))

        # Fibonacci-like: seed y, a, then each next = (prev2 + prev1) mod 26
        fib = [y, a]
        for i in range(2, CT_LEN):
            fib.append((fib[-1] + fib[-2]) % 26)
        keys.append((f"{yar_name}_fibonacci", fib))

        # Seed y, a, r then each next = (sum of last 3) mod 26
        tri = [y, a, r]
        for i in range(3, CT_LEN):
            tri.append((tri[-1] + tri[-2] + tri[-3]) % 26)
        keys.append((f"{yar_name}_tribonacci", tri))

    # 5. Compass-derived periodic keys
    for bearing in COMPASS_VALS:
        # Period = bearing mod 26
        p = bearing % 26
        if 1 <= p <= 25:
            key = [(i * p) % 26 for i in range(CT_LEN)]
            keys.append((f"compass_{bearing}_mult", key))

        # Bearing as shift
        key = [bearing % 26] * CT_LEN
        keys.append((f"compass_{bearing}_const", key))

    # 6. T-position modifier: key[i] = (i + T) mod 26
    for t in T_VALS:
        key = [(i + t) % 26 for i in range(CT_LEN)]
        keys.append((f"T{t}_additive_pos", key))

        key = [(i * t) % 26 for i in range(CT_LEN)]
        keys.append((f"T{t}_mult_pos", key))

    # 7. KRYPTOS alphabet position key: key[i] = KA_IDX[CT[i]]
    # (self-referential: the CT character's position in the KA alphabet)
    key = [KA_IDX.get(c, 0) for c in CT]
    keys.append(("CT_self_KA_idx", key))

    # Also in standard alphabet
    key = [ALPH_IDX[c] for c in CT]
    keys.append(("CT_self_AZ_idx", key))

    # 8. Autokey variants seeded with YAR/RQ
    for yar_name, yar_vals in YAR_SEQUENCES:
        # Autokey: key starts with YAR, then appends plaintext (for Vigenere)
        # We can't do this directly — instead test autokey-like where
        # key[i] = CT[i-3] for i >= 3, seeded with YAR
        key = list(yar_vals)
        for i in range(3, CT_LEN):
            key.append(CT_INT[i - 3])
        keys.append((f"{yar_name}_autokey_ct", key))

        # Autokey with key feedback
        key = list(yar_vals)
        for i in range(3, CT_LEN):
            key.append(key[i - 3])
        keys.append((f"{yar_name}_autokey_key", key))

    return keys


def phase4_worker(args: Tuple) -> Dict[str, Any]:
    """Test position-dependent key + cipher variant."""
    (key_name, position_key, variant_name, db_path_str) = args

    decrypt_fn = DECRYPT_FNS[variant_name]
    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)

    pt_int = [decrypt_fn(CT_INT[j], position_key[j]) for j in range(CT_LEN)]
    cribs = fast_crib_score(pt_int)

    result = {
        "task_id": f"p4|{key_name}|{variant_name}",
        "n_tested": 1,
        "best_cribs": cribs,
        "results": [],
    }

    if cribs >= max(4, NOISE_FLOOR):
        pt_str = int_to_text(pt_int)
        qg_pc = scorer.score_per_char(pt_str)
        ic_val = fast_ic(pt_int)
        bean = fast_bean_check(position_key)

        config = {
            "key_name": key_name, "variant": variant_name,
            "key_preview": position_key[:20],
        }

        if cribs >= STORE_THRESHOLD:
            store_candidate(
                db_p, 4, "position_cipher", cribs, qg_pc, ic_val, bean,
                config, pt_str,
            )

        if cribs >= SIGNAL_THRESHOLD:
            print(f"\n*** SIGNAL P4 *** cribs={cribs}/{N_CRIBS} "
                  f"key={key_name} var={variant_name} PT={pt_str[:60]}...")

        result["results"].append({
            "cribs": cribs, "qg_pc": qg_pc, "ic": ic_val,
            "bean": bean, "config": config, "pt": pt_str,
        })

    return result


def phase4_columnar_worker(args: Tuple) -> Dict[str, Any]:
    """Test position key + columnar transposition."""
    (key_name, position_key, variant_name, width,
     model, db_path_str) = args

    decrypt_fn = DECRYPT_FNS[variant_name]
    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)

    n_tested = 0
    best_cribs_chunk = 0
    results: List[Dict[str, Any]] = []

    # Try all column orderings (width! is feasible for w <= 8)
    # For w > 8, try keyword-derived orderings only
    if width <= 8:
        orderings = list(itertools.permutations(range(width)))
    else:
        # Use keyword orderings from thematic list
        orderings = []
        for kw in PHASE2_KEYWORDS:
            if len(kw) == width:
                order = keyword_to_col_order(kw)
                if order not in orderings:
                    orderings.append(order)
        # Also add identity and reverse
        orderings.append(list(range(width)))
        orderings.append(list(range(width - 1, -1, -1)))

    for col_order in orderings:
        if _shutdown_requested:
            break
        n_tested += 1

        if model == "A":
            # PT → columnar → IT → sub → CT
            it_int = [decrypt_fn(CT_INT[j], position_key[j]) for j in range(CT_LEN)]
            pt_int = columnar_decrypt(it_int, list(col_order))
        else:
            # PT → sub → IT → columnar → CT
            it_int = columnar_decrypt(CT_INT, list(col_order))
            pt_int = [decrypt_fn(it_int[j], position_key[j]) for j in range(CT_LEN)]

        cribs = fast_crib_score(pt_int)
        if cribs > best_cribs_chunk:
            best_cribs_chunk = cribs

        if cribs >= STORE_THRESHOLD:
            pt_str = int_to_text(pt_int)
            qg_pc = scorer.score_per_char(pt_str)
            ic_val = fast_ic(pt_int)
            bean = fast_bean_check(position_key)

            config = {
                "key_name": key_name, "variant": variant_name,
                "width": width, "model": model,
                "col_order": list(col_order),
            }
            results.append({
                "cribs": cribs, "qg_pc": qg_pc, "ic": ic_val,
                "bean": bean, "config": config, "pt": pt_str,
            })
            store_candidate(
                db_p, 4, "position_columnar", cribs, qg_pc, ic_val, bean,
                config, pt_str,
            )

            if cribs >= SIGNAL_THRESHOLD:
                print(f"\n*** SIGNAL P4c *** cribs={cribs}/{N_CRIBS} "
                      f"key={key_name} var={variant_name} w={width} "
                      f"model={model} PT={pt_str[:60]}...")

    return {
        "task_id": f"p4c|{key_name}|{variant_name}|w{width}|{model}",
        "n_tested": n_tested,
        "best_cribs": best_cribs_chunk,
        "results": results,
    }


def run_phase4(
    workers: int, checkpoint: Checkpoint, logger: logging.Logger,
) -> Checkpoint:
    """Phase 4: Sculpture-Parameter Position Cipher."""
    phase_key = "phase4"
    if checkpoint.phase_done.get(phase_key):
        logger.info("Phase 4 already complete, skipping")
        return checkpoint

    logger.info("=" * 72)
    logger.info("PHASE 4: Sculpture-Parameter Position Cipher (UNDER-TESTED)")
    logger.info("=" * 72)

    position_keys = generate_position_keys()
    logger.info(f"Position keys: {len(position_keys)}")

    init_db(DB_PATH)
    total_tested = 0
    start_time = time.time()
    last_progress = start_time
    best_overall = 0

    # Part A: Direct position key + variant (no transposition)
    tasks_a: List[Tuple] = []
    for key_name, key_vals in position_keys:
        for vname in VARIANT_NAMES:
            tasks_a.append((key_name, key_vals, vname, str(DB_PATH)))

    logger.info(f"Phase 4A (direct): {len(tasks_a)} tasks")

    with mp.Pool(workers) as pool:
        for result in pool.imap_unordered(phase4_worker, tasks_a, chunksize=8):
            if _shutdown_requested:
                pool.terminate()
                break
            total_tested += result["n_tested"]
            for cand in result.get("results", []):
                checkpoint.add_candidate(cand)
            if result["best_cribs"] > best_overall:
                best_overall = result["best_cribs"]

    logger.info(f"P4A done: {total_tested:,} tested, best={best_overall}")

    # Part B: Position key + columnar transposition
    if not _shutdown_requested:
        # Select the most promising position keys (top 30)
        top_keys = position_keys[:30]  # First 30 include all YAR variants

        tasks_b: List[Tuple] = []
        for key_name, key_vals in top_keys:
            for vname in VARIANT_NAMES:
                for width in [7, 8]:  # Only exhaustive-enumerable widths
                    for model in ["A", "B"]:
                        tasks_b.append((
                            key_name, key_vals, vname, width, model,
                            str(DB_PATH),
                        ))

        logger.info(f"Phase 4B (columnar, w=7,8): {len(tasks_b)} tasks")

        with mp.Pool(workers) as pool:
            for result in pool.imap_unordered(phase4_columnar_worker, tasks_b, chunksize=1):
                if _shutdown_requested:
                    pool.terminate()
                    break
                total_tested += result["n_tested"]
                for cand in result.get("results", []):
                    checkpoint.add_candidate(cand)
                if result["best_cribs"] > best_overall:
                    best_overall = result["best_cribs"]

                now = time.time()
                if now - last_progress >= 60:
                    elapsed = now - start_time
                    logger.info(
                        f"P4B: {total_tested:,} tested | best={best_overall} | "
                        f"elapsed={elapsed/60:.1f}m"
                    )
                    last_progress = now

    elapsed = time.time() - start_time
    logger.info(f"Phase 4 complete: {total_tested:,} configs in {elapsed/60:.1f}m")
    logger.info(f"Phase 4 best cribs: {best_overall}")
    checkpoint.phase_tested[phase_key] = total_tested
    checkpoint.phase_done[phase_key] = True
    checkpoint.phase = max(checkpoint.phase, 4)
    checkpoint.save(CHECKPOINT_PATH)
    return checkpoint


# ══════════════════════════════════════════════════════════════════════════
# PHASE 5: Multi-Layer Cascade
# ══════════════════════════════════════════════════════════════════════════
#
# Sanborn's "two separate systems" statement.
# Pipeline: CT → [null removal] → [undo transposition] → [undo substitution] → PT
# Combines best null masks from Phase 1 with shared-key and position ciphers.

def phase5_worker(args: Tuple) -> Dict[str, Any]:
    """Test multi-layer: null removal + columnar + substitution."""
    (mask_name, keep_positions, keyword, variant_name,
     model, alphabet, db_path_str) = args

    decrypt_fn = DECRYPT_FNS[variant_name]
    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)

    # Step 1: Remove nulls
    reduced_ct_int = [CT_INT[i] for i in keep_positions]
    reduced_len = len(reduced_ct_int)

    # Step 2: Column order from keyword
    kw_len = len(keyword)
    col_order = keyword_to_col_order(keyword)

    # Step 3: Key from keyword
    if alphabet == "AZ":
        key_int = derive_vig_key_from_keyword(keyword, reduced_len)
    else:
        key_int = derive_ka_key_from_keyword(keyword, reduced_len)

    n_tested = 0
    best_cribs_chunk = 0
    results: List[Dict[str, Any]] = []
    new_cribs = remap_cribs_for_mask(keep_positions)
    n_possible_cribs = len(new_cribs)

    if n_possible_cribs < 8:
        return {
            "task_id": f"p5|{mask_name}|{keyword}|{variant_name}|{model}",
            "n_tested": 0, "best_cribs": 0, "results": [],
        }

    # Test with 26 key shifts
    for shift in range(26):
        if _shutdown_requested:
            break
        n_tested += 1

        if shift > 0:
            sk = [(k + shift) % 26 for k in key_int]
        else:
            sk = key_int

        if model == "A":
            # Decrypt: unsub → undo columnar
            it_int = [decrypt_fn(reduced_ct_int[j], sk[j]) for j in range(reduced_len)]
            pt_int = columnar_decrypt(it_int, col_order)
        else:
            # Decrypt: undo columnar → unsub
            it_int = columnar_decrypt(reduced_ct_int, col_order)
            pt_int = [decrypt_fn(it_int[j], sk[j]) for j in range(reduced_len)]

        cribs = fast_crib_score_on(pt_int, new_cribs)
        if cribs > best_cribs_chunk:
            best_cribs_chunk = cribs

        if cribs >= min(STORE_THRESHOLD, n_possible_cribs - 2):
            pt_str = int_to_text(pt_int)
            qg_pc = scorer.score_per_char(pt_str)
            ic_val = fast_ic(pt_int)
            bean = fast_bean_check(sk)

            config = {
                "mask": mask_name, "keyword": keyword,
                "variant": variant_name, "model": model,
                "alphabet": alphabet, "shift": shift,
                "reduced_len": reduced_len,
                "n_possible_cribs": n_possible_cribs,
            }
            results.append({
                "cribs": cribs, "qg_pc": qg_pc, "ic": ic_val,
                "bean": bean, "config": config, "pt": pt_str,
            })
            store_candidate(
                db_p, 5, "cascade_null_col_sub", cribs, qg_pc, ic_val, bean,
                config, pt_str, reduced_len,
            )

            if cribs >= SIGNAL_THRESHOLD:
                print(f"\n*** SIGNAL P5 *** cribs={cribs}/{n_possible_cribs} "
                      f"mask={mask_name} kw={keyword} var={variant_name} "
                      f"model={model} shift={shift} PT={pt_str[:60]}...")

    return {
        "task_id": f"p5|{mask_name}|{keyword}|{variant_name}|{model}",
        "n_tested": n_tested,
        "best_cribs": best_cribs_chunk,
        "results": results,
    }


def phase5_rk_worker(args: Tuple) -> Dict[str, Any]:
    """Test multi-layer: null removal + columnar + running key."""
    (mask_name, keep_positions, col_keyword,
     text_name, text_int, text_len,
     variant_name, model,
     offset_start, offset_end, db_path_str) = args

    decrypt_fn = DECRYPT_FNS[variant_name]
    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)

    reduced_ct_int = [CT_INT[i] for i in keep_positions]
    reduced_len = len(reduced_ct_int)
    col_order = keyword_to_col_order(col_keyword)
    new_cribs = remap_cribs_for_mask(keep_positions)
    n_possible_cribs = len(new_cribs)

    if n_possible_cribs < 8:
        return {
            "task_id": f"p5rk|{mask_name}|{col_keyword}|{text_name}|{offset_start}",
            "n_tested": 0, "best_cribs": 0, "results": [],
        }

    n_tested = 0
    best_cribs_chunk = 0
    results: List[Dict[str, Any]] = []

    for offset in range(offset_start, min(offset_end, text_len - reduced_len + 1)):
        if _shutdown_requested:
            break
        n_tested += 1

        key_int = text_int[offset:offset + reduced_len]

        if model == "A":
            it_int = [decrypt_fn(reduced_ct_int[j], key_int[j]) for j in range(reduced_len)]
            pt_int = columnar_decrypt(it_int, col_order)
        else:
            it_int = columnar_decrypt(reduced_ct_int, col_order)
            pt_int = [decrypt_fn(it_int[j], key_int[j]) for j in range(reduced_len)]

        cribs = fast_crib_score_on(pt_int, new_cribs)
        if cribs > best_cribs_chunk:
            best_cribs_chunk = cribs

        if cribs >= min(STORE_THRESHOLD, n_possible_cribs - 2):
            pt_str = int_to_text(pt_int)
            qg_pc = scorer.score_per_char(pt_str)
            ic_val = fast_ic(pt_int)
            bean = fast_bean_check(key_int)

            config = {
                "mask": mask_name, "col_keyword": col_keyword,
                "variant": variant_name, "model": model,
                "source": text_name, "offset": offset,
                "reduced_len": reduced_len,
            }
            results.append({
                "cribs": cribs, "qg_pc": qg_pc, "ic": ic_val,
                "bean": bean, "config": config, "pt": pt_str,
            })
            store_candidate(
                db_p, 5, "cascade_null_col_rk", cribs, qg_pc, ic_val, bean,
                config, pt_str, reduced_len,
            )

    return {
        "task_id": f"p5rk|{mask_name}|{col_keyword}|{text_name}|{offset_start}",
        "n_tested": n_tested,
        "best_cribs": best_cribs_chunk,
        "results": results,
    }


def run_phase5(
    workers: int, checkpoint: Checkpoint, logger: logging.Logger,
) -> Checkpoint:
    """Phase 5: Multi-Layer Cascade."""
    phase_key = "phase5"
    if checkpoint.phase_done.get(phase_key):
        logger.info("Phase 5 already complete, skipping")
        return checkpoint

    logger.info("=" * 72)
    logger.info("PHASE 5: Multi-Layer Cascade (TWO SEPARATE SYSTEMS)")
    logger.info("=" * 72)

    init_db(DB_PATH)
    total_tested = 0
    start_time = time.time()
    last_progress = start_time
    best_overall = 0

    # Top null masks (most promising)
    masks_all = generate_null_masks()
    top_mask_names = {
        "rm_doubled_2nd", "rm_doubled_1st", "rm_doubled_both",
        "rm_mod7eq4", "rm_mod7eq4_struct", "rm_6doubled_pos",
    }
    top_masks = [(n, k) for n, k in masks_all if n in top_mask_names]

    # Top keywords for columnar
    col_keywords = [kw for kw in PHASE2_KEYWORDS if 5 <= len(kw) <= 14][:30]

    # Part A: Null + columnar + periodic sub (keyword-derived)
    tasks_a: List[Tuple] = []
    for mask_name, keep_positions in top_masks:
        for kw in col_keywords:
            for vname in VARIANT_NAMES:
                for model in ["A", "B"]:
                    for alph in ["AZ", "KA"]:
                        tasks_a.append((
                            mask_name, keep_positions, kw, vname,
                            model, alph, str(DB_PATH),
                        ))

    logger.info(f"Phase 5A (keyword cascade): {len(tasks_a)} tasks")

    with mp.Pool(workers) as pool:
        completed = 0
        for result in pool.imap_unordered(phase5_worker, tasks_a, chunksize=4):
            if _shutdown_requested:
                pool.terminate()
                break
            completed += 1
            total_tested += result["n_tested"]
            for cand in result.get("results", []):
                checkpoint.add_candidate(cand)
            if result["best_cribs"] > best_overall:
                best_overall = result["best_cribs"]

            now = time.time()
            if now - last_progress >= 60:
                elapsed = now - start_time
                logger.info(
                    f"P5A: {completed}/{len(tasks_a)} | "
                    f"{total_tested:,} tested | best={best_overall} | "
                    f"elapsed={elapsed/60:.1f}m"
                )
                last_progress = now

    logger.info(f"P5A done: {total_tested:,} configs, best={best_overall}")

    # Part B: Null + columnar + running key (top masks × top keywords × top texts)
    if not _shutdown_requested:
        all_texts = load_all_texts()
        # Use fewer combos to keep tractable
        cascade_masks = [(n, k) for n, k in top_masks if n in (
            "rm_doubled_2nd", "rm_doubled_both", "rm_mod7eq4_struct",
        )]
        cascade_keywords = [kw for kw in col_keywords if len(kw) in (7, 8, 9)][:10]

        tasks_b: List[Tuple] = []
        for mask_name, keep_positions in cascade_masks:
            for kw in cascade_keywords:
                for text_name, text_int, text_len in all_texts:
                    reduced_len = len(keep_positions)
                    n_offsets = text_len - reduced_len + 1
                    if n_offsets <= 0:
                        continue
                    for vname in VARIANT_NAMES:
                        for model in ["A", "B"]:
                            chunk_size = 50000
                            for start in range(0, n_offsets, chunk_size):
                                end = min(start + chunk_size, n_offsets)
                                tasks_b.append((
                                    mask_name, keep_positions, kw,
                                    text_name, text_int, text_len,
                                    vname, model,
                                    start, end, str(DB_PATH),
                                ))

        if tasks_b:
            logger.info(f"Phase 5B (cascade + running key): {len(tasks_b)} tasks")
            b_completed = 0

            with mp.Pool(workers) as pool:
                for result in pool.imap_unordered(phase5_rk_worker, tasks_b, chunksize=1):
                    if _shutdown_requested:
                        pool.terminate()
                        break
                    b_completed += 1
                    total_tested += result["n_tested"]
                    for cand in result.get("results", []):
                        checkpoint.add_candidate(cand)
                    if result["best_cribs"] > best_overall:
                        best_overall = result["best_cribs"]

                    now = time.time()
                    if now - last_progress >= 60:
                        elapsed = now - start_time
                        logger.info(
                            f"P5B: {b_completed}/{len(tasks_b)} | "
                            f"{total_tested:,} tested | best={best_overall} | "
                            f"elapsed={elapsed/60:.1f}m"
                        )
                        last_progress = now

    elapsed = time.time() - start_time
    logger.info(f"Phase 5 complete: {total_tested:,} configs in {elapsed/60:.1f}m")
    logger.info(f"Phase 5 best cribs: {best_overall}")
    checkpoint.phase_tested[phase_key] = total_tested
    checkpoint.phase_done[phase_key] = True
    checkpoint.phase = max(checkpoint.phase, 5)
    checkpoint.save(CHECKPOINT_PATH)
    return checkpoint


# ══════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════

def print_summary(checkpoint: Checkpoint, logger: logging.Logger) -> None:
    total_time = time.time() - checkpoint.start_time if checkpoint.start_time else 0
    logger.info("")
    logger.info("=" * 72)
    logger.info("DRAGNET v3 FINAL SUMMARY")
    logger.info("=" * 72)
    logger.info(f"Total runtime: {total_time/3600:.2f} hours")

    for phase_key in ["phase1", "phase2", "phase3", "phase4", "phase5"]:
        tested = checkpoint.phase_tested.get(phase_key, 0)
        done = checkpoint.phase_done.get(phase_key, False)
        status = "COMPLETE" if done else "INCOMPLETE"
        logger.info(f"  {phase_key}: {tested:,} configs [{status}]")

    total_tested = sum(checkpoint.phase_tested.values())
    logger.info(f"Total configs tested: {total_tested:,}")

    if checkpoint.best_candidates:
        logger.info(f"\nTop 20 candidates:")
        for i, c in enumerate(checkpoint.best_candidates[:20]):
            config = c.get("config", {})
            logger.info(
                f"  #{i+1}: cribs={c.get('cribs',0)} "
                f"qg/c={c.get('qg_pc', -99):.3f} "
                f"IC={c.get('ic', 0):.4f} "
                f"bean={'PASS' if c.get('bean') else 'FAIL'}"
            )
            # Show relevant config details
            config_str = json.dumps(config, default=str)
            if len(config_str) > 120:
                config_str = config_str[:120] + "..."
            logger.info(f"       config: {config_str}")
            pt = c.get("pt", "")
            if pt:
                logger.info(f"       PT: {pt[:80]}")
    else:
        logger.info("No candidates above store threshold.")

    if DB_PATH.exists():
        try:
            conn = sqlite3.connect(str(DB_PATH))
            total = conn.execute("SELECT COUNT(*) FROM candidates").fetchone()[0]
            by_phase = conn.execute(
                "SELECT phase, phase_name, COUNT(*), MAX(score_cribs) "
                "FROM candidates GROUP BY phase, phase_name"
            ).fetchall()
            conn.close()
            logger.info(f"\nDatabase: {total} stored candidates")
            for phase, pname, cnt, max_cr in by_phase:
                logger.info(f"  Phase {phase} ({pname}): "
                            f"{cnt} entries, max cribs={max_cr}")
        except Exception:
            pass

    logger.info("=" * 72)


# ══════════════════════════════════════════════════════════════════════════
# Verification
# ══════════════════════════════════════════════════════════════════════════

def verify() -> None:
    """Verify infrastructure before running."""
    # 1. Cipher roundtrips
    for vname in VARIANT_NAMES:
        enc = ENCRYPT_FNS[vname]
        dec = DECRYPT_FNS[vname]
        for p in range(26):
            for k in range(26):
                c = enc(p, k)
                assert dec(c, k) == p, f"Roundtrip failed: {vname} p={p} k={k}"

    # 2. Columnar roundtrip
    test_pt = list(range(CT_LEN))
    for width in [7, 8, 9, 11]:
        order = list(range(width))
        ct = columnar_encrypt(test_pt, order)
        recovered = columnar_decrypt(ct, order)
        assert recovered == test_pt, f"Columnar identity failed w={width}"

        # Non-trivial order
        order = list(range(width - 1, -1, -1))
        ct = columnar_encrypt(test_pt, order)
        recovered = columnar_decrypt(ct, order)
        assert recovered == test_pt, f"Columnar reverse failed w={width}"

    # 3. Null mask crib remapping
    keep = list(range(CT_LEN))  # Identity mask
    new_cribs = remap_cribs_for_mask(keep)
    assert new_cribs == CRIB_PT_INT, "Identity mask should preserve all cribs"

    # 4. Keyword col order
    order = keyword_to_col_order("KRYPTOS")
    assert len(order) == 7
    assert sorted(order) == list(range(7)), "Col order must be a permutation"

    print("Verification PASSED: cipher roundtrips, columnar roundtrips, "
          "crib remapping, keyword ordering")


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="DRAGNET v3 — Untested Attack Vectors for Kryptos K4",
    )
    parser.add_argument("--phase", type=str, default="all",
                        choices=["1", "2", "3", "4", "5", "all"])
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    logger = setup_logging()
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 72)
    logger.info("DRAGNET v3 — Untested Attack Vectors")
    logger.info(f"Workers: {args.workers} | Phase: {args.phase} | "
                f"Resume: {args.resume}")
    logger.info(f"CT: {CT}")
    logger.info(f"CT length: {CT_LEN} | Cribs: {N_CRIBS}")
    logger.info("=" * 72)
    logger.info("Phase 1: Null/Skip patterns (NEVER TESTED)")
    logger.info("Phase 2: Shared-key transposition (NEVER TESTED)")
    logger.info("Phase 3: Non-standard tableau lookup (NOVEL ANGLES)")
    logger.info("Phase 4: Sculpture-parameter position cipher (UNDER-TESTED)")
    logger.info("Phase 5: Multi-layer cascade (TWO SEPARATE SYSTEMS)")
    logger.info("=" * 72)

    verify()

    # Load or create checkpoint
    if args.resume and CHECKPOINT_PATH.exists():
        checkpoint = Checkpoint.load(CHECKPOINT_PATH)
        logger.info(f"Resumed from checkpoint: phases done={checkpoint.phase_done}")
    else:
        checkpoint = Checkpoint(start_time=time.time())

    if checkpoint.start_time == 0:
        checkpoint.start_time = time.time()

    # Verify quadgram scorer
    try:
        test_scorer = QuadgramScorer(QUADGRAM_PATH)
        ts = test_scorer.score_per_char("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG")
        logger.info(f"Quadgram scorer OK (test={ts:.3f})")
    except Exception as e:
        logger.error(f"Quadgram scorer FAILED: {e}")
        sys.exit(1)

    init_db(DB_PATH)

    # Log corpus info
    corpus = get_corpus_files()
    logger.info(f"Corpus files: {len(corpus)}")
    for f in corpus:
        try:
            logger.info(f"  {f.name} ({f.stat().st_size:,} bytes)")
        except Exception:
            logger.info(f"  {f.name} (size unknown)")
    logger.info(f"Sculpture texts: {len(get_sculpture_texts())}")
    logger.info(f"Position keys: {len(generate_position_keys())}")
    logger.info(f"Null masks: {len(generate_null_masks())}")
    logger.info(f"Thematic keywords: {len(PHASE2_KEYWORDS)}")

    try:
        phase_map = {
            "1": [1], "2": [2], "3": [3], "4": [4], "5": [5],
            "all": [1, 2, 3, 4, 5],
        }
        phases_to_run = phase_map[args.phase]

        for phase_num in phases_to_run:
            if _shutdown_requested:
                break

            if phase_num == 1:
                checkpoint = run_phase1(args.workers, checkpoint, logger)
            elif phase_num == 2:
                checkpoint = run_phase2(args.workers, checkpoint, logger)
            elif phase_num == 3:
                checkpoint = run_phase3(args.workers, checkpoint, logger)
            elif phase_num == 4:
                checkpoint = run_phase4(args.workers, checkpoint, logger)
            elif phase_num == 5:
                checkpoint = run_phase5(args.workers, checkpoint, logger)

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        checkpoint.save(CHECKPOINT_PATH)
        print_summary(checkpoint, logger)
        logger.info("DRAGNET v3 finished.")


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()
