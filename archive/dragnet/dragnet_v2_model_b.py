#!/usr/bin/env python3
"""DRAGNET v2 — Model B + Route Transpositions for Kryptos K4.

Two-phase exhaustive search:
  Phase 1: Model B columnar CSP (PT → substitute → IT → columnar transpose → CT)
  Phase 2: Route transpositions + running key, both Model A and Model B

Model A (Dragnet v1): PT → transpose → IT → substitute → CT
Model B (NEW):        PT → substitute → IT → transpose → CT

K3's actual method applies transposition first then substitution, making Model B
the more natural architecture if K4 follows a similar pattern.

Usage:
  PYTHONPATH=src python3 -u scripts/dragnet_v2_model_b.py --phase all --workers 28
  PYTHONPATH=src python3 -u scripts/dragnet_v2_model_b.py --phase 1 --workers 28
  PYTHONPATH=src python3 -u scripts/dragnet_v2_model_b.py --phase 2 --workers 28
  PYTHONPATH=src python3 -u scripts/dragnet_v2_model_b.py --resume
"""
from __future__ import annotations

import argparse
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
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
)

# ── Precomputed integer arrays (module level, shared by workers) ─────────
CT_INT: List[int] = [ALPH_IDX[c] for c in CT]
CRIB_POS_LIST: List[int] = sorted(CRIB_POSITIONS)
CRIB_PT_INT: Dict[int, int] = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}
NON_CRIB_POS: List[int] = [i for i in range(CT_LEN) if i not in CRIB_POSITIONS]

# ── Paths ────────────────────────────────────────────────────────────────
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RESULTS_DIR = PROJECT_ROOT / "results"
CHECKPOINT_PATH = RESULTS_DIR / "dragnet_v2_checkpoint.json"
DB_PATH = RESULTS_DIR / "dragnet_v2_results.sqlite"
LOG_PATH = RESULTS_DIR / "dragnet_v2.log"
QUADGRAM_PATH = PROJECT_ROOT / "data" / "english_quadgrams.json"

# ── Global state for clean shutdown ──────────────────────────────────────
_shutdown_requested = False


def _signal_handler(signum, frame):
    global _shutdown_requested
    _shutdown_requested = True


# ══════════════════════════════════════════════════════════════════════════
# Logging setup
# ══════════════════════════════════════════════════════════════════════════

def setup_logging() -> logging.Logger:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    logger = logging.getLogger("dragnet_v2")
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
# Quadgram scorer (fast, self-contained)
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
# Fast inline scoring
# ══════════════════════════════════════════════════════════════════════════

def fast_crib_score(pt_int: List[int]) -> int:
    s = 0
    for pos, expected in CRIB_PT_INT.items():
        if pt_int[pos] == expected:
            s += 1
    return s


def fast_ic(pt_int: List[int]) -> float:
    freq = [0] * 26
    for v in pt_int:
        freq[v] += 1
    n = len(pt_int)
    return sum(f * (f - 1) for f in freq) / (n * (n - 1))


def fast_bean_check(key_int: List[int]) -> bool:
    """Bean check for Model B: key aligns with PT positions directly."""
    for a, b in BEAN_EQ:
        if a < len(key_int) and b < len(key_int):
            if key_int[a] != key_int[b]:
                return False
    for a, b in BEAN_INEQ:
        if a < len(key_int) and b < len(key_int):
            if key_int[a] == key_int[b]:
                return False
    return True


def bean_check_permuted(key_int: List[int], inv_perm: List[int]) -> bool:
    """Bean check for Model A: key aligns with IT/CT positions.

    Bean constraints refer to PT positions. In Model A, the key at PT
    position j is key_int[inv_perm[j]] (the IT/CT position mapped to j).
    """
    for a, b in BEAN_EQ:
        if key_int[inv_perm[a]] != key_int[inv_perm[b]]:
            return False
    for a, b in BEAN_INEQ:
        if key_int[inv_perm[a]] == key_int[inv_perm[b]]:
            return False
    return True


def int_to_text(vals: List[int]) -> str:
    return "".join(ALPH[v] for v in vals)


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
            model TEXT,
            route_name TEXT,
            score_cribs INTEGER NOT NULL,
            score_quadgram REAL,
            score_ic REAL,
            bean_pass INTEGER NOT NULL DEFAULT 0,
            permutation TEXT,
            key_fragment TEXT,
            plaintext TEXT,
            source_text TEXT,
            source_offset INTEGER,
            width INTEGER,
            cipher_variant TEXT,
            timestamp REAL NOT NULL
        )
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_score ON candidates(score_cribs DESC)"
    )
    conn.commit()
    conn.close()


def store_candidate(
    db_path: Path, phase: int, cribs: int,
    qg: Optional[float], ic_val: Optional[float], bean: bool,
    perm: Optional[List[int]], key_frag: Optional[str],
    pt: str, source: Optional[str], offset: Optional[int],
    width: Optional[int], variant: Optional[str],
    model: Optional[str], route_name: Optional[str],
) -> None:
    try:
        conn = sqlite3.connect(str(db_path), timeout=10.0)
        conn.execute(
            "INSERT INTO candidates "
            "(phase, model, route_name, score_cribs, score_quadgram, score_ic, "
            "bean_pass, permutation, key_fragment, plaintext, source_text, "
            "source_offset, width, cipher_variant, timestamp) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                phase, model, route_name, cribs, qg, ic_val, int(bean),
                json.dumps(perm) if perm else None,
                key_frag, pt, source, offset, width, variant, time.time()
            ),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════
# Checkpoint system
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class Checkpoint:
    phase: int = 0
    phase1_files_done: List[str] = field(default_factory=list)
    phase1_total_tested: int = 0
    phase2_files_done: List[str] = field(default_factory=list)
    phase2_total_tested: int = 0
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

    for name in [
        "sanborn_correspondence.md", "smithsonian_archive.md",
        "youtube_transcript.md",
    ]:
        p = ref_dir / name
        if p.exists():
            files.append(p)

    corpus_dir = PROJECT_ROOT / "corpus"
    if corpus_dir.is_dir():
        for f in sorted(corpus_dir.glob("*.txt")):
            files.append(f)

    wl = PROJECT_ROOT / "wordlists" / "english.txt"
    if wl.exists():
        files.append(wl)

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


# ══════════════════════════════════════════════════════════════════════════
# Cipher variant helpers
# ══════════════════════════════════════════════════════════════════════════

def vig_decrypt_int(c: int, k: int) -> int:
    return (c - k) % 26

def beau_decrypt_int(c: int, k: int) -> int:
    return (k - c) % 26

def varbeau_decrypt_int(c: int, k: int) -> int:
    return (c + k) % 26

def vig_recover_int(c: int, p: int) -> int:
    return (c - p) % 26

def beau_recover_int(c: int, p: int) -> int:
    return (c + p) % 26

def varbeau_recover_int(c: int, p: int) -> int:
    return (p - c) % 26

def vig_encrypt_int(p: int, k: int) -> int:
    return (p + k) % 26

def beau_encrypt_int(p: int, k: int) -> int:
    return (k - p) % 26

def varbeau_encrypt_int(p: int, k: int) -> int:
    return (p - k) % 26


VARIANTS = [
    ("vigenere", vig_decrypt_int, vig_recover_int),
    ("beaufort", beau_decrypt_int, beau_recover_int),
    ("var_beaufort", varbeau_decrypt_int, varbeau_recover_int),
]

ENCRYPT_FNS = {
    "vigenere": vig_encrypt_int,
    "beaufort": beau_encrypt_int,
    "var_beaufort": varbeau_encrypt_int,
}

DECRYPT_FNS = {
    "vigenere": vig_decrypt_int,
    "beaufort": beau_decrypt_int,
    "var_beaufort": varbeau_decrypt_int,
}

WIDTHS = [7, 8, 9, 11, 13, 14]


# ══════════════════════════════════════════════════════════════════════════
# Columnar constraint structures (precomputed per width)
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class ColumnarConstraints:
    width: int
    nrows: int
    remainder: int
    col_len: List[int]
    crib_by_col: Dict[int, List[Tuple[int, int, int]]]

    @classmethod
    def build(cls, width: int) -> "ColumnarConstraints":
        nrows = math.ceil(CT_LEN / width)
        remainder = CT_LEN % width
        if remainder == 0:
            remainder = width
        col_len = [nrows if c < remainder else nrows - 1 for c in range(width)]
        crib_by_col: Dict[int, List[Tuple[int, int, int]]] = {}
        for pos in CRIB_POS_LIST:
            col = pos % width
            row = pos // width
            crib_val = CRIB_PT_INT[pos]
            crib_by_col.setdefault(col, []).append((row, crib_val, pos))
        return cls(width=width, nrows=nrows, remainder=remainder,
                   col_len=col_len, crib_by_col=crib_by_col)


# Build base constraints once at module load
COLUMNAR_CONSTRAINTS: Dict[int, ColumnarConstraints] = {
    w: ColumnarConstraints.build(w) for w in WIDTHS
}


def build_model_b_constraints(
    width: int, base_cc: ColumnarConstraints,
    key_int: List[int], encrypt_fn,
) -> ColumnarConstraints:
    """Build Model B columnar constraints.

    In Model B, encryption is PT → encrypt → IT → columnar → CT.
    At crib position j, IT[j] = encrypt(PT[j], key[j]).
    The CSP finds column ordering where CT (column-read) matches IT values.
    """
    crib_by_col: Dict[int, List[Tuple[int, int, int]]] = {}
    for pos in CRIB_POS_LIST:
        col = pos % width
        row = pos // width
        crib_val = encrypt_fn(CRIB_PT_INT[pos], key_int[pos])
        crib_by_col.setdefault(col, []).append((row, crib_val, pos))
    return ColumnarConstraints(
        width=base_cc.width, nrows=base_cc.nrows,
        remainder=base_cc.remainder, col_len=base_cc.col_len,
        crib_by_col=crib_by_col,
    )


def compute_col_start_positions(
    rank_to_col: List[int], col_len: List[int], width: int,
) -> List[int]:
    starts = [0] * width
    cumul = 0
    for r in range(width):
        c = rank_to_col[r]
        starts[c] = cumul
        cumul += col_len[c]
    return starts


def check_column_at_rank(
    col: int, rank: int, it_int: List[int],
    cc: ColumnarConstraints,
    assigned_ranks: Dict[int, int],
    used_ranks: set,
) -> int:
    constraints = cc.crib_by_col.get(col, [])
    if not constraints:
        return -1

    known_sum = 0
    n_unknown_lower = 0
    for assigned_col, assigned_rank in assigned_ranks.items():
        if assigned_rank < rank:
            known_sum += cc.col_len[assigned_col]

    for r in range(rank):
        if r not in used_ranks:
            n_unknown_lower += 1

    assigned_full = sum(1 for c in assigned_ranks if c < cc.remainder)
    assigned_short = sum(1 for c in assigned_ranks if c >= cc.remainder)
    total_full_unassigned = cc.remainder - assigned_full
    if col < cc.remainder:
        total_full_unassigned -= 1
    total_short_unassigned = (cc.width - cc.remainder) - assigned_short
    if col >= cc.remainder:
        total_short_unassigned -= 1

    min_full = max(0, n_unknown_lower - total_short_unassigned)
    max_full = min(n_unknown_lower, total_full_unassigned)

    base = known_sum + n_unknown_lower * (cc.nrows - 1)

    best_matches = 0
    for n_full in range(min_full, max_full + 1):
        start = base + n_full
        matches = 0
        ok = True
        for row, crib_val, pos in constraints:
            it_pos = start + row
            if it_pos >= CT_LEN:
                ok = False
                break
            if it_int[it_pos] == crib_val:
                matches += 1
            else:
                ok = False
        if ok and matches == len(constraints):
            return -1
        if matches > best_matches:
            best_matches = matches

    return best_matches


def solve_columnar_csp(
    it_int: List[int], cc: ColumnarConstraints,
) -> Tuple[Optional[List[int]], int]:
    width = cc.width
    cols_by_constraint = sorted(
        range(width),
        key=lambda c: len(cc.crib_by_col.get(c, [])),
        reverse=True,
    )

    best_order: Optional[List[int]] = None
    best_matches = 0

    assignment: Dict[int, int] = {}
    used_ranks: set = set()

    col_idx = 0
    next_rank = 0

    while True:
        if col_idx == width:
            total_matches = 0
            rank_to_col = [0] * width
            for c, r in assignment.items():
                rank_to_col[r] = c
            starts = compute_col_start_positions(rank_to_col, cc.col_len, width)

            for col, constraints in cc.crib_by_col.items():
                for row, crib_val, pos in constraints:
                    it_pos = starts[col] + row
                    if it_pos < CT_LEN and it_int[it_pos] == crib_val:
                        total_matches += 1

            if total_matches > best_matches:
                best_matches = total_matches
                best_order = [assignment[c] for c in range(width)]

            if total_matches == N_CRIBS:
                return best_order, best_matches

            col_idx -= 1
            if col_idx < 0:
                break
            prev_col = cols_by_constraint[col_idx]
            prev_rank = assignment.pop(prev_col)
            used_ranks.discard(prev_rank)
            next_rank = prev_rank + 1
            continue

        col = cols_by_constraint[col_idx]

        found = False
        for rank in range(next_rank, width):
            if rank in used_ranks:
                continue

            score = check_column_at_rank(
                col, rank, it_int, cc, assignment, used_ranks
            )

            if score == 0 and cc.crib_by_col.get(col):
                continue

            assignment[col] = rank
            used_ranks.add(rank)
            found = True
            col_idx += 1
            next_rank = 0
            break

        if not found:
            col_idx -= 1
            if col_idx < 0:
                break
            prev_col = cols_by_constraint[col_idx]
            prev_rank = assignment.pop(prev_col)
            used_ranks.discard(prev_rank)
            next_rank = prev_rank + 1

    return best_order, best_matches


def reconstruct_plaintext(
    it_int: List[int], col_order: List[int], cc: ColumnarConstraints,
) -> List[int]:
    """Reconstruct row-major text from column-ordered reading."""
    rank_to_col = [0] * cc.width
    for c, r in enumerate(col_order):
        rank_to_col[r] = c
    starts = compute_col_start_positions(rank_to_col, cc.col_len, cc.width)

    pt = [0] * CT_LEN
    for c in range(cc.width):
        for r in range(cc.col_len[c]):
            pt_pos = r * cc.width + c
            it_pos = starts[c] + r
            if pt_pos < CT_LEN and it_pos < CT_LEN:
                pt[pt_pos] = it_int[it_pos]
    return pt


# ══════════════════════════════════════════════════════════════════════════
# Route permutation generators
# ══════════════════════════════════════════════════════════════════════════

GRID_SIZES = [(7, 14), (14, 7), (9, 11), (11, 9), (10, 10), (8, 13), (13, 8)]


def invert_perm(perm: List[int]) -> List[int]:
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def rotation_grid_perm(
    rows: int, cols: int, rotation: str, length: int = CT_LEN,
) -> List[int]:
    """Permutation for: write row-by-row into grid, rotate, read row-by-row.

    perm[output_idx] = original flat position.
    Only positions < length are included (padding skipped).
    """
    perm: List[int] = []
    if rotation == "CW90":
        # Rotated grid: cols rows × rows cols
        for nr in range(cols):
            for nc in range(rows):
                orig = (rows - 1 - nc) * cols + nr
                if orig < length:
                    perm.append(orig)
    elif rotation == "CCW90":
        for nr in range(cols):
            for nc in range(rows):
                orig = nc * cols + (cols - 1 - nr)
                if orig < length:
                    perm.append(orig)
    elif rotation == "180":
        for nr in range(rows):
            for nc in range(cols):
                orig = (rows - 1 - nr) * cols + (cols - 1 - nc)
                if orig < length:
                    perm.append(orig)
    return perm


def col_major_perm(
    rows: int, cols: int, length: int = CT_LEN,
) -> List[int]:
    """Write row-by-row, read column-by-column (top-to-bottom, left-to-right)."""
    perm: List[int] = []
    for c in range(cols):
        for r in range(rows):
            pos = r * cols + c
            if pos < length:
                perm.append(pos)
    return perm


def spiral_perm_gen(
    rows: int, cols: int, length: int = CT_LEN, clockwise: bool = True,
) -> List[int]:
    """Spiral reading from outside in."""
    visited = [[False] * cols for _ in range(rows)]
    dirs = (
        [(0, 1), (1, 0), (0, -1), (-1, 0)]
        if clockwise
        else [(1, 0), (0, 1), (-1, 0), (0, -1)]
    )
    perm: List[int] = []
    r, c, d = 0, 0, 0
    for _ in range(rows * cols):
        pos = r * cols + c
        if pos < length:
            perm.append(pos)
        visited[r][c] = True
        nr, nc = r + dirs[d][0], c + dirs[d][1]
        if 0 <= nr < rows and 0 <= nc < cols and not visited[nr][nc]:
            r, c = nr, nc
        else:
            d = (d + 1) % 4
            nr, nc = r + dirs[d][0], c + dirs[d][1]
            if 0 <= nr < rows and 0 <= nc < cols and not visited[nr][nc]:
                r, c = nr, nc
            else:
                break
    return perm


def serpentine_perm_gen(
    rows: int, cols: int, length: int = CT_LEN, vertical: bool = False,
) -> List[int]:
    """Serpentine (boustrophedon) reading on a grid."""
    perm: List[int] = []
    if not vertical:
        for r in range(rows):
            rng = range(cols) if r % 2 == 0 else range(cols - 1, -1, -1)
            for c in rng:
                pos = r * cols + c
                if pos < length:
                    perm.append(pos)
    else:
        for c in range(cols):
            rng = range(rows) if c % 2 == 0 else range(rows - 1, -1, -1)
            for r in rng:
                pos = r * cols + c
                if pos < length:
                    perm.append(pos)
    return perm


def generate_all_route_perms() -> List[Tuple[str, List[int], List[int]]]:
    """Generate all route permutations: (name, perm, inv_perm)."""
    routes: List[Tuple[str, List[int], List[int]]] = []
    for rows, cols in GRID_SIZES:
        for rot in ["CW90", "CCW90", "180"]:
            perm = rotation_grid_perm(rows, cols, rot)
            if len(perm) == CT_LEN:
                routes.append((f"rot_{rows}x{cols}_{rot}", perm, invert_perm(perm)))

        for cw_label, cw in [("CW", True), ("CCW", False)]:
            perm = spiral_perm_gen(rows, cols, clockwise=cw)
            if len(perm) == CT_LEN:
                routes.append((f"spiral_{rows}x{cols}_{cw_label}", perm, invert_perm(perm)))

        for vert_label, vert in [("horiz", False), ("vert", True)]:
            perm = serpentine_perm_gen(rows, cols, vertical=vert)
            if len(perm) == CT_LEN:
                routes.append((f"serp_{rows}x{cols}_{vert_label}", perm, invert_perm(perm)))

        perm = col_major_perm(rows, cols)
        if len(perm) == CT_LEN:
            routes.append((f"colmajor_{rows}x{cols}", perm, invert_perm(perm)))

    return routes


ALL_ROUTES: List[Tuple[str, List[int], List[int]]] = generate_all_route_perms()


# Precompute crib checks for Phase 2 (avoid function calls in inner loop).
# For each (route, variant, crib_pos): required_key = recover(CT[inv_perm[j]], PT[j]).
# Then checking is just: key_int[pos] == required_key.
def _build_p2_crib_checks():
    checks = []
    for route_name, perm, inv_perm in ALL_ROUTES:
        for vi, (vname, dec_fn, rec_fn) in enumerate(VARIANTS):
            crib_checks = []
            for j in CRIB_POS_LIST:
                ip = inv_perm[j]
                req_key = rec_fn(CT_INT[ip], CRIB_PT_INT[j])
                crib_checks.append((j, ip, req_key))
            checks.append((route_name, vi, vname, perm, inv_perm, crib_checks))
    return checks


P2_CRIB_CHECKS = _build_p2_crib_checks()


# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: Model B Columnar CSP
# ══════════════════════════════════════════════════════════════════════════

def phase1_model_b_chunk(args: Tuple) -> Dict[str, Any]:
    """Process a chunk of running-key offsets for Model B columnar.

    Model B: PT → encrypt(PT, key) → IT → columnar → CT.
    CSP searches CT (column-read) for encrypted crib values.
    """
    (text_name, text_int, text_len, width, variant_name,
     offset_start, offset_end, db_path_str) = args

    encrypt_fn = ENCRYPT_FNS[variant_name]
    decrypt_fn = DECRYPT_FNS[variant_name]
    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)
    base_cc = COLUMNAR_CONSTRAINTS[width]

    results: List[Dict[str, Any]] = []
    n_tested = 0
    best_cribs_chunk = 0

    for offset in range(offset_start, min(offset_end, text_len - CT_LEN + 1)):
        if _shutdown_requested:
            break

        n_tested += 1
        key_int = text_int[offset:offset + CT_LEN]

        # Build Model B constraints: IT[j] = encrypt(PT[j], key[j]) at cribs
        mb_cc = build_model_b_constraints(width, base_cc, key_int, encrypt_fn)

        # CSP on CT_INT (the column-ordered reading of IT)
        best_order, best_cribs_csp = solve_columnar_csp(CT_INT, mb_cc)

        if best_cribs_csp > best_cribs_chunk:
            best_cribs_chunk = best_cribs_csp

            if best_cribs_csp >= STORE_THRESHOLD and best_order:
                # Reconstruct: undo columnar from CT to get IT, then decrypt
                it_arr = reconstruct_plaintext(CT_INT, best_order, mb_cc)
                pt_arr = [decrypt_fn(it_arr[j], key_int[j])
                          for j in range(CT_LEN)]
                pt_str = int_to_text(pt_arr)
                qg_pc = scorer.score_per_char(pt_str)
                ic_val = fast_ic(pt_arr)
                bean = fast_bean_check(key_int)

                cand = {
                    "cribs": best_cribs_csp, "qg_pc": qg_pc, "ic": ic_val,
                    "bean": bean, "width": width, "variant": variant_name,
                    "source": text_name, "offset": offset, "model": "B",
                    "perm": best_order, "pt": pt_str,
                }
                results.append(cand)
                store_candidate(
                    db_p, 1, best_cribs_csp, qg_pc, ic_val, bean,
                    best_order, None, pt_str, text_name, offset,
                    width, variant_name, "B", None,
                )

                if best_cribs_csp >= SIGNAL_THRESHOLD:
                    print(f"\n*** SIGNAL *** cribs={best_cribs_csp}/{N_CRIBS} "
                          f"src={text_name} off={offset} var={variant_name} "
                          f"w={width} model=B PT={pt_str[:60]}...")

    return {
        "task_id": f"{text_name}|w{width}|{variant_name}|{offset_start}-{offset_end}",
        "n_tested": n_tested,
        "best_cribs": best_cribs_chunk,
        "results": results,
    }


def build_phase1_tasks(
    checkpoint: Checkpoint, db_path: Path, chunk_size: int = 5000,
) -> List[Tuple]:
    done_set = set(checkpoint.phase1_files_done)
    tasks: List[Tuple] = []

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

    for name, text_int, text_len in all_texts:
        n_offsets = text_len - CT_LEN + 1
        for width in WIDTHS:
            for vname, _, _ in VARIANTS:
                if width <= 9:
                    cs = chunk_size
                elif width <= 11:
                    cs = max(2000, chunk_size)
                else:
                    cs = max(1000, chunk_size // 2)

                for start in range(0, n_offsets, cs):
                    end = min(start + cs, n_offsets)
                    task_id = f"{name}|w{width}|{vname}|{start}-{end}"
                    if task_id in done_set:
                        continue
                    tasks.append((
                        name, text_int, text_len, width, vname,
                        start, end, str(db_path),
                    ))

    return tasks


def run_phase1(
    workers: int, checkpoint: Checkpoint, logger: logging.Logger,
) -> Checkpoint:
    """Phase 1: Model B columnar CSP — PT → sub → IT → columnar → CT."""
    logger.info("=" * 72)
    logger.info("PHASE 1: Model B Columnar CSP (PT → sub → IT → columnar → CT)")
    logger.info("=" * 72)

    init_db(DB_PATH)
    tasks = build_phase1_tasks(checkpoint, DB_PATH)

    if not tasks:
        logger.info("Phase 1: No tasks remaining (all done or no corpus)")
        checkpoint.phase = 1
        return checkpoint

    total_tasks = len(tasks)
    logger.info(f"Phase 1: {total_tasks} chunk-tasks to process")

    tasks.sort(key=lambda t: (t[3], t[4], t[0], t[5]))

    completed = 0
    total_tested = checkpoint.phase1_total_tested
    start_time = time.time()
    last_progress = start_time
    last_checkpoint_time = start_time
    best_overall = {"cribs": 0}

    with mp.Pool(workers) as pool:
        for result in pool.imap_unordered(phase1_model_b_chunk, tasks, chunksize=1):
            if _shutdown_requested:
                logger.warning("Shutdown requested during Phase 1")
                pool.terminate()
                break

            completed += 1
            total_tested += result["n_tested"]
            checkpoint.phase1_files_done.append(result["task_id"])
            checkpoint.phase1_total_tested = total_tested

            for cand in result.get("results", []):
                checkpoint.add_candidate(cand)
                if cand.get("cribs", 0) > best_overall.get("cribs", 0):
                    best_overall = cand

            if result["best_cribs"] > best_overall.get("cribs", 0):
                best_overall["cribs"] = result["best_cribs"]

            now = time.time()
            elapsed = now - start_time

            if now - last_progress >= 60:
                rate = total_tested / elapsed if elapsed > 0 else 0
                pct = completed / total_tasks * 100
                eta_h = ((total_tasks - completed) / (completed / elapsed) / 3600
                         if completed > 0 else 0)
                logger.info(
                    f"P1: {completed}/{total_tasks} ({pct:.1f}%) | "
                    f"{total_tested:,} offsets | {rate:.0f}/s | "
                    f"best={best_overall.get('cribs', 0)} | "
                    f"elapsed={elapsed/3600:.2f}h | ETA={eta_h:.1f}h"
                )
                last_progress = now

            if now - last_checkpoint_time >= 600:
                checkpoint.save(CHECKPOINT_PATH)
                logger.info(f"Checkpoint saved ({completed}/{total_tasks})")
                last_checkpoint_time = now

    elapsed = time.time() - start_time
    logger.info(f"Phase 1 complete: {total_tested:,} offsets in {elapsed/3600:.2f}h")
    logger.info(f"Phase 1 best cribs: {best_overall.get('cribs', 0)}")
    checkpoint.phase = 1
    checkpoint.save(CHECKPOINT_PATH)
    return checkpoint


# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: Route Transpositions + Running Key (Both Models)
# ══════════════════════════════════════════════════════════════════════════

def phase2_route_chunk(args: Tuple) -> Dict[str, Any]:
    """Process a chunk of offsets with all route permutations, both models.

    Model A: PT[j] = decrypt(CT[inv_perm[j]], key[inv_perm[j]])
    Model B: PT[j] = decrypt(CT[inv_perm[j]], key[j])
    """
    (text_name, text_int, text_len,
     offset_start, offset_end, db_path_str) = args

    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)
    decrypt_fns = [vig_decrypt_int, beau_decrypt_int, varbeau_decrypt_int]

    n_tested = 0
    best_cribs_chunk = 0
    results: List[Dict[str, Any]] = []

    for offset in range(offset_start, min(offset_end, text_len - CT_LEN + 1)):
        if _shutdown_requested:
            break

        key_int = text_int[offset:offset + CT_LEN]

        for route_name, vi, vname, perm, inv_perm, checks in P2_CRIB_CHECKS:
            n_tested += 2  # Both models

            # Model A: key at IT/CT positions (inv_perm[j])
            ca = 0
            for j, ip, rk in checks:
                if key_int[ip] == rk:
                    ca += 1

            # Model B: key at PT positions (j)
            cb = 0
            for j, ip, rk in checks:
                if key_int[j] == rk:
                    cb += 1

            dfn = decrypt_fns[vi]

            # Process Model A — store only on new chunk best
            if ca > best_cribs_chunk:
                best_cribs_chunk = ca
                if ca >= STORE_THRESHOLD:
                    pt_arr = [dfn(CT_INT[inv_perm[j]], key_int[inv_perm[j]])
                              for j in range(CT_LEN)]
                    pt_str = int_to_text(pt_arr)
                    qg_pc = scorer.score_per_char(pt_str)
                    ic_val = fast_ic(pt_arr)
                    bean = bean_check_permuted(key_int, inv_perm)

                    cand = {
                        "cribs": ca, "qg_pc": qg_pc, "ic": ic_val,
                        "bean": bean, "variant": vname, "route": route_name,
                        "source": text_name, "offset": offset, "model": "A",
                        "pt": pt_str,
                    }
                    results.append(cand)
                    store_candidate(
                        db_p, 2, ca, qg_pc, ic_val, bean,
                        perm, None, pt_str, text_name, offset,
                        None, vname, "A", route_name,
                    )
                    if ca >= SIGNAL_THRESHOLD:
                        print(f"\n*** SIGNAL *** cribs={ca}/{N_CRIBS} model=A "
                              f"route={route_name} var={vname} "
                              f"src={text_name} off={offset} "
                              f"PT={pt_str[:60]}...")

            # Process Model B — store only on new chunk best
            if cb > best_cribs_chunk:
                best_cribs_chunk = cb
                if cb >= STORE_THRESHOLD:
                    pt_arr = [dfn(CT_INT[inv_perm[j]], key_int[j])
                              for j in range(CT_LEN)]
                    pt_str = int_to_text(pt_arr)
                    qg_pc = scorer.score_per_char(pt_str)
                    ic_val = fast_ic(pt_arr)
                    bean = fast_bean_check(key_int)

                    cand = {
                        "cribs": cb, "qg_pc": qg_pc, "ic": ic_val,
                        "bean": bean, "variant": vname, "route": route_name,
                        "source": text_name, "offset": offset, "model": "B",
                        "pt": pt_str,
                    }
                    results.append(cand)
                    store_candidate(
                        db_p, 2, cb, qg_pc, ic_val, bean,
                        perm, None, pt_str, text_name, offset,
                        None, vname, "B", route_name,
                    )
                    if cb >= SIGNAL_THRESHOLD:
                        print(f"\n*** SIGNAL *** cribs={cb}/{N_CRIBS} model=B "
                              f"route={route_name} var={vname} "
                              f"src={text_name} off={offset} "
                              f"PT={pt_str[:60]}...")

    return {
        "task_id": f"{text_name}|{offset_start}-{offset_end}",
        "n_tested": n_tested,
        "best_cribs": best_cribs_chunk,
        "results": results,
    }


def build_phase2_tasks(
    checkpoint: Checkpoint, db_path: Path, chunk_size: int = 50000,
) -> List[Tuple]:
    done_set = set(checkpoint.phase2_files_done)
    tasks: List[Tuple] = []

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

    for name, text_int, text_len in all_texts:
        n_offsets = text_len - CT_LEN + 1
        for start in range(0, n_offsets, chunk_size):
            end = min(start + chunk_size, n_offsets)
            task_id = f"{name}|{start}-{end}"
            if task_id in done_set:
                continue
            tasks.append((
                name, text_int, text_len, start, end, str(db_path),
            ))

    return tasks


def run_phase2(
    workers: int, checkpoint: Checkpoint, logger: logging.Logger,
) -> Checkpoint:
    """Phase 2: Route transpositions + running key, both Model A and B."""
    logger.info("=" * 72)
    logger.info("PHASE 2: Route Transpositions + Running Key (Both Models)")
    logger.info("=" * 72)
    logger.info(f"Routes: {len(ALL_ROUTES)} | Variants: {len(VARIANTS)} | "
                f"Models: A+B")
    logger.info(f"Checks per offset: {len(P2_CRIB_CHECKS) * 2}")

    init_db(DB_PATH)
    tasks = build_phase2_tasks(checkpoint, DB_PATH)

    if not tasks:
        logger.info("Phase 2: No tasks remaining")
        checkpoint.phase = 2
        return checkpoint

    total_tasks = len(tasks)
    logger.info(f"Phase 2: {total_tasks} chunk-tasks to process")

    completed = 0
    total_tested = checkpoint.phase2_total_tested
    start_time = time.time()
    last_progress = start_time
    last_checkpoint_time = start_time
    best_overall = {"cribs": 0}

    with mp.Pool(workers) as pool:
        for result in pool.imap_unordered(phase2_route_chunk, tasks, chunksize=1):
            if _shutdown_requested:
                logger.warning("Shutdown requested during Phase 2")
                pool.terminate()
                break

            completed += 1
            total_tested += result["n_tested"]
            checkpoint.phase2_files_done.append(result["task_id"])
            checkpoint.phase2_total_tested = total_tested

            for cand in result.get("results", []):
                checkpoint.add_candidate(cand)
                if cand.get("cribs", 0) > best_overall.get("cribs", 0):
                    best_overall = cand

            if result["best_cribs"] > best_overall.get("cribs", 0):
                best_overall["cribs"] = result["best_cribs"]

            now = time.time()
            elapsed = now - start_time

            if now - last_progress >= 60:
                rate = total_tested / elapsed if elapsed > 0 else 0
                pct = completed / total_tasks * 100
                eta_h = ((total_tasks - completed) / (completed / elapsed) / 3600
                         if completed > 0 else 0)
                logger.info(
                    f"P2: {completed}/{total_tasks} ({pct:.1f}%) | "
                    f"{total_tested:,} checks | {rate:.0f}/s | "
                    f"best={best_overall.get('cribs', 0)} | "
                    f"elapsed={elapsed/3600:.2f}h | ETA={eta_h:.1f}h"
                )
                last_progress = now

            if now - last_checkpoint_time >= 600:
                checkpoint.save(CHECKPOINT_PATH)
                logger.info(f"Checkpoint saved ({completed}/{total_tasks})")
                last_checkpoint_time = now

    elapsed = time.time() - start_time
    logger.info(f"Phase 2 complete: {total_tested:,} checks in {elapsed/3600:.2f}h")
    logger.info(f"Phase 2 best cribs: {best_overall.get('cribs', 0)}")
    checkpoint.phase = 2
    checkpoint.save(CHECKPOINT_PATH)
    return checkpoint


# ══════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════

def print_summary(checkpoint: Checkpoint, logger: logging.Logger) -> None:
    total_time = time.time() - checkpoint.start_time if checkpoint.start_time else 0
    logger.info("")
    logger.info("=" * 72)
    logger.info("DRAGNET v2 FINAL SUMMARY")
    logger.info("=" * 72)
    logger.info(f"Total runtime: {total_time/3600:.2f} hours")
    logger.info(f"Phase 1 (Model B columnar): {checkpoint.phase1_total_tested:,} offsets")
    logger.info(f"Phase 2 (Route transpositions): {checkpoint.phase2_total_tested:,} checks")

    if checkpoint.best_candidates:
        logger.info(f"\nTop 10 candidates:")
        for i, c in enumerate(checkpoint.best_candidates[:10]):
            logger.info(
                f"  #{i+1}: cribs={c.get('cribs',0)} "
                f"qg/c={c.get('qg_pc', -99):.3f} "
                f"IC={c.get('ic', 0):.4f} "
                f"bean={'PASS' if c.get('bean') else 'FAIL'} "
                f"model={c.get('model','?')} "
                f"src={c.get('source', '?')} "
                f"var={c.get('variant', '?')}"
            )
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
                "SELECT phase, model, COUNT(*), MAX(score_cribs) "
                "FROM candidates GROUP BY phase, model"
            ).fetchall()
            conn.close()
            logger.info(f"\nDatabase: {total} stored candidates")
            for phase, model, cnt, max_cr in by_phase:
                logger.info(f"  Phase {phase} Model {model}: "
                            f"{cnt} entries, max cribs={max_cr}")
        except Exception:
            pass

    logger.info("=" * 72)


# ══════════════════════════════════════════════════════════════════════════
# Verification
# ══════════════════════════════════════════════════════════════════════════

def verify_roundtrip() -> None:
    """Verify Model B encryption/decryption roundtrips correctly."""
    test_pt = [p % 26 for p in range(CT_LEN)]
    test_key = [(p * 7 + 3) % 26 for p in range(CT_LEN)]

    # Test with identity permutation (no transposition)
    for vname in ["vigenere", "beaufort", "var_beaufort"]:
        enc = ENCRYPT_FNS[vname]
        dec = DECRYPT_FNS[vname]
        it = [enc(test_pt[j], test_key[j]) for j in range(CT_LEN)]
        ct = it[:]  # identity transposition
        recovered = [dec(ct[j], test_key[j]) for j in range(CT_LEN)]
        assert recovered == test_pt, f"Model B identity roundtrip FAILED for {vname}"

    # Test with non-trivial permutation (shift left by 1)
    perm = list(range(1, CT_LEN)) + [0]
    inv = [CT_LEN - 1] + list(range(CT_LEN - 1))

    for vname in ["vigenere", "beaufort", "var_beaufort"]:
        enc = ENCRYPT_FNS[vname]
        dec = DECRYPT_FNS[vname]
        it = [enc(test_pt[j], test_key[j]) for j in range(CT_LEN)]
        ct = [it[perm[i]] for i in range(CT_LEN)]  # CT[i] = IT[perm[i]]
        # Model B decrypt: PT[j] = dec(CT[inv[j]], key[j])
        recovered = [dec(ct[inv[j]], test_key[j]) for j in range(CT_LEN)]
        assert recovered == test_pt, f"Model B perm roundtrip FAILED for {vname}"

    # Verify route permutations are valid bijections on {0..96}
    for name, perm, inv in ALL_ROUTES:
        assert len(perm) == CT_LEN, f"Route {name}: len={len(perm)}, expected {CT_LEN}"
        assert sorted(perm) == list(range(CT_LEN)), f"Route {name}: not a permutation"

    print(f"Verification PASSED: 6 roundtrips + {len(ALL_ROUTES)} route permutations OK")


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="DRAGNET v2 — Model B + Route Transpositions for K4",
    )
    parser.add_argument("--phase", type=str, default="all",
                        choices=["1", "2", "all"])
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()

    logger = setup_logging()
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 72)
    logger.info("DRAGNET v2 — Model B + Route Transpositions")
    logger.info(f"Workers: {args.workers} | Phase: {args.phase} | "
                f"Resume: {args.resume}")
    logger.info(f"CT: {CT}")
    logger.info(f"CT length: {CT_LEN} | Cribs: {N_CRIBS}")
    logger.info(f"Phase 1 widths: {WIDTHS}")
    logger.info(f"Phase 2 routes: {len(ALL_ROUTES)} | "
                f"Crib check combos: {len(P2_CRIB_CHECKS)} routes×variants")
    logger.info("=" * 72)

    # Roundtrip verification
    verify_roundtrip()

    # Load or create checkpoint
    if args.resume and CHECKPOINT_PATH.exists():
        checkpoint = Checkpoint.load(CHECKPOINT_PATH)
        logger.info(f"Resumed: phase={checkpoint.phase}, "
                     f"p1={checkpoint.phase1_total_tested:,}, "
                     f"p2={checkpoint.phase2_total_tested:,}")
    else:
        checkpoint = Checkpoint(start_time=time.time())

    if checkpoint.start_time == 0:
        checkpoint.start_time = time.time()

    # Verify infrastructure
    try:
        test_scorer = QuadgramScorer(QUADGRAM_PATH)
        ts = test_scorer.score_per_char("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG")
        logger.info(f"Quadgram scorer OK (test={ts:.3f})")
    except Exception as e:
        logger.error(f"Quadgram scorer FAILED: {e}")
        sys.exit(1)

    init_db(DB_PATH)

    corpus = get_corpus_files()
    logger.info(f"Corpus files: {len(corpus)}")
    for f in corpus:
        try:
            logger.info(f"  {f.name} ({f.stat().st_size:,} bytes)")
        except Exception:
            logger.info(f"  {f.name} (size unknown)")
    logger.info(f"Sculpture texts: {len(get_sculpture_texts())}")

    try:
        if args.phase in ("1", "all"):
            if checkpoint.phase < 1 or (args.phase == "1" and not args.resume):
                checkpoint = run_phase1(args.workers, checkpoint, logger)

        if _shutdown_requested:
            checkpoint.save(CHECKPOINT_PATH)
            print_summary(checkpoint, logger)
            return

        if args.phase in ("2", "all"):
            if checkpoint.phase < 2 or args.phase == "2":
                checkpoint = run_phase2(args.workers, checkpoint, logger)

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        checkpoint.save(CHECKPOINT_PATH)
        print_summary(checkpoint, logger)
        logger.info("DRAGNET v2 finished.")


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()
