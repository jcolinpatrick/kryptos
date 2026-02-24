#!/usr/bin/env python3
"""DRAGNET — Multi-day autonomous Kryptos K4 experiment.

Three-phase exhaustive search:
  Phase 1: Corpus running key + constraint-propagation columnar transposition
  Phase 2: Simulated annealing on arbitrary permutations + key optimization
  Phase 3: Hybrid — SA seeded from Phase 1 top candidates

Usage:
  PYTHONPATH=src python3 -u scripts/dragnet.py --phase all --workers 16
  PYTHONPATH=src python3 -u scripts/dragnet.py --phase 1 --workers 16
  PYTHONPATH=src python3 -u scripts/dragnet.py --phase 2 --workers 16
  PYTHONPATH=src python3 -u scripts/dragnet.py --phase 3 --workers 16
  PYTHONPATH=src python3 -u scripts/dragnet.py --resume
"""
from __future__ import annotations

import argparse
import json
import logging
import math
import multiprocessing as mp
import random
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
CHECKPOINT_PATH = RESULTS_DIR / "dragnet_checkpoint.json"
DB_PATH = RESULTS_DIR / "dragnet_results.sqlite"
LOG_PATH = RESULTS_DIR / "dragnet.log"
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
    logger = logging.getLogger("dragnet")
    logger.setLevel(logging.DEBUG)
    # Remove existing handlers to avoid duplicates on re-import
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
    """Fast quadgram scorer using dict lookup."""
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
    """Count crib matches on integer plaintext."""
    s = 0
    for pos, expected in CRIB_PT_INT.items():
        if pt_int[pos] == expected:
            s += 1
    return s


def fast_ic(pt_int: List[int]) -> float:
    """IC from integer plaintext."""
    freq = [0] * 26
    for v in pt_int:
        freq[v] += 1
    n = len(pt_int)
    return sum(f * (f - 1) for f in freq) / (n * (n - 1))


def fast_bean_check(key_int: List[int]) -> bool:
    """Fast Bean constraint check on integer keystream."""
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
) -> None:
    try:
        conn = sqlite3.connect(str(db_path), timeout=10.0)
        conn.execute(
            "INSERT INTO candidates "
            "(phase, score_cribs, score_quadgram, score_ic, bean_pass, "
            "permutation, key_fragment, plaintext, source_text, source_offset, "
            "width, cipher_variant, timestamp) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                phase, cribs, qg, ic_val, int(bean),
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
    phase2_iterations: int = 0
    phase3_iterations: int = 0
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
    """Return all corpus files in priority order."""
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
    """Extract only uppercase A-Z from raw text."""
    return "".join(c for c in raw.upper() if c in ALPH_IDX)


def get_sculpture_texts() -> List[Tuple[str, str]]:
    """Generate running key candidates from K1/K2/K3 plaintext/ciphertext."""
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


VARIANTS = [
    ("vigenere", vig_decrypt_int, vig_recover_int),
    ("beaufort", beau_decrypt_int, beau_recover_int),
    ("var_beaufort", varbeau_decrypt_int, varbeau_recover_int),
]

WIDTHS = [0, 7, 8, 9, 11, 13, 14]


# ══════════════════════════════════════════════════════════════════════════
# Columnar constraint structures (precomputed per width)
# ══════════════════════════════════════════════════════════════════════════

@dataclass
class ColumnarConstraints:
    """Precomputed constraint structure for a given width."""
    width: int
    nrows: int
    remainder: int  # number of columns with nrows entries
    col_len: List[int]  # length of each column
    # crib_by_col[col] = list of (row, crib_int_value, pt_position)
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
            if col not in crib_by_col:
                crib_by_col[col] = []
            crib_by_col[col].append((row, crib_val, pos))

        return cls(width=width, nrows=nrows, remainder=remainder,
                   col_len=col_len, crib_by_col=crib_by_col)


# Build constraints once at module load
COLUMNAR_CONSTRAINTS: Dict[int, ColumnarConstraints] = {}
for _w in WIDTHS:
    if _w > 0:
        COLUMNAR_CONSTRAINTS[_w] = ColumnarConstraints.build(_w)


def compute_col_start_positions(
    rank_to_col: List[int], col_len: List[int], width: int,
) -> List[int]:
    """Compute start position in IT for each column given the rank order."""
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
    """Check how many crib constraints column 'col' satisfies at 'rank'.

    To compute the start position of column 'col' at rank 'rank',
    we need to know the total length of all columns with lower rank.
    We know some of them (the already-assigned columns) but not all.

    For columns with rank < 'rank':
      - Some are assigned (known col, known length)
      - The rest are unassigned: their lengths can be nrows or nrows-1.

    We compute the range [min_start, max_start] and check ALL possible
    starts in that range for crib satisfaction.

    Returns the number of crib matches (0 if impossible for ALL start values).
    Returns -1 if ALL start values produce full crib matches for this column.
    """
    constraints = cc.crib_by_col.get(col, [])
    if not constraints:
        return -1  # No constraints => trivially satisfied

    # Compute the known part of start
    known_sum = 0
    n_unknown_lower = 0
    for assigned_col, assigned_rank in assigned_ranks.items():
        if assigned_rank < rank:
            known_sum += cc.col_len[assigned_col]

    # Count unassigned ranks below 'rank'
    for r in range(rank):
        if r not in used_ranks:
            n_unknown_lower += 1

    # Each unknown lower-rank column has length nrows or nrows-1.
    # The number of full columns (length=nrows) available among unassigned:
    # Total full cols: cc.remainder
    # Full cols already assigned: sum(1 for c, r in assigned_ranks.items() if c < cc.remainder)
    assigned_full = sum(1 for c in assigned_ranks if c < cc.remainder)
    assigned_short = sum(1 for c in assigned_ranks if c >= cc.remainder)
    total_full_unassigned = cc.remainder - assigned_full
    if col < cc.remainder:
        total_full_unassigned -= 1  # Don't count 'col' itself
    total_short_unassigned = (cc.width - cc.remainder) - assigned_short
    if col >= cc.remainder:
        total_short_unassigned -= 1

    total_unassigned_excl_col = total_full_unassigned + total_short_unassigned

    # Of the n_unknown_lower unassigned lower-rank columns,
    # the number of full ones ranges from:
    min_full = max(0, n_unknown_lower - total_short_unassigned)
    max_full = min(n_unknown_lower, total_full_unassigned)

    # Each full adds nrows, each short adds nrows-1.
    # start = known_sum + n_full * nrows + (n_unknown_lower - n_full) * (nrows - 1)
    #       = known_sum + n_unknown_lower * (nrows - 1) + n_full
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
            return -1  # Fully satisfied
        if matches > best_matches:
            best_matches = matches

    return best_matches


def solve_columnar_csp(
    it_int: List[int], cc: ColumnarConstraints,
) -> Tuple[Optional[List[int]], int]:
    """Solve the columnar column-ordering CSP using backtracking with pruning.

    Returns (best_column_order, best_crib_count).
    Column order: col_order[c] = rank of column c (0 = read first).

    The CSP assigns a rank (0..width-1) to each column (0..width-1).
    At crib positions in each column, the IT values must match.
    """
    width = cc.width
    # Sort columns by number of constraints (most constrained first = MRV heuristic)
    cols_by_constraint = sorted(
        range(width),
        key=lambda c: len(cc.crib_by_col.get(c, [])),
        reverse=True,
    )

    best_order: Optional[List[int]] = None
    best_matches = 0

    # Iterative backtracking (avoid recursion depth issues)
    # State: list of (col, rank) assignments in order of cols_by_constraint
    assignment: Dict[int, int] = {}
    used_ranks: set = set()
    stack: List[Tuple[int, int]] = []  # (col_idx_in_order, next_rank_to_try)

    col_idx = 0
    next_rank = 0

    while True:
        if col_idx == width:
            # Full assignment found — evaluate
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

            # Backtrack
            col_idx -= 1
            if col_idx < 0:
                break
            prev_col = cols_by_constraint[col_idx]
            prev_rank = assignment.pop(prev_col)
            used_ranks.discard(prev_rank)
            next_rank = prev_rank + 1
            continue

        col = cols_by_constraint[col_idx]

        # Try ranks from next_rank to width-1
        found = False
        for rank in range(next_rank, width):
            if rank in used_ranks:
                continue

            # Check if this assignment is compatible
            score = check_column_at_rank(
                col, rank, it_int, cc, assignment, used_ranks
            )

            if score == 0 and cc.crib_by_col.get(col):
                # Zero matches — prune this branch
                continue

            # Accept this assignment
            assignment[col] = rank
            used_ranks.add(rank)
            found = True
            col_idx += 1
            next_rank = 0
            break

        if not found:
            # Backtrack
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
    """Reconstruct plaintext from intermediate text and column ordering."""
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
# PHASE 1: Corpus running key + constraint-propagation columnar
# ══════════════════════════════════════════════════════════════════════════

def phase1_process_chunk(args: Tuple) -> Dict[str, Any]:
    """Process a chunk of running key offsets for one source/width/variant.

    Returns dict with statistics and any candidates found.
    """
    (text_name, text_int, text_len, width, variant_name,
     offset_start, offset_end, db_path_str) = args

    fn_map_decrypt = {
        "vigenere": vig_decrypt_int,
        "beaufort": beau_decrypt_int,
        "var_beaufort": varbeau_decrypt_int,
    }
    decrypt_fn = fn_map_decrypt[variant_name]
    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)

    results: List[Dict[str, Any]] = []
    n_tested = 0
    best_cribs_chunk = 0

    cc = COLUMNAR_CONSTRAINTS.get(width) if width > 0 else None

    for offset in range(offset_start, min(offset_end, text_len - CT_LEN + 1)):
        if _shutdown_requested:
            break

        n_tested += 1
        key_int = text_int[offset:offset + CT_LEN]

        if width == 0:
            # Direct running key — no transposition
            pt_int = [decrypt_fn(CT_INT[i], key_int[i]) for i in range(CT_LEN)]
            cribs = fast_crib_score(pt_int)

            if cribs > best_cribs_chunk:
                best_cribs_chunk = cribs

            if cribs >= STORE_THRESHOLD:
                pt_str = int_to_text(pt_int)
                qg_pc = scorer.score_per_char(pt_str)
                ic_val = fast_ic(pt_int)
                bean = fast_bean_check(key_int)

                cand = {
                    "cribs": cribs, "qg_pc": qg_pc, "ic": ic_val,
                    "bean": bean, "width": 0, "variant": variant_name,
                    "source": text_name, "offset": offset, "pt": pt_str,
                }
                results.append(cand)
                store_candidate(
                    db_p, 1, cribs, qg_pc, ic_val, bean,
                    None, None, pt_str, text_name, offset, 0, variant_name,
                )

            if cribs >= SIGNAL_THRESHOLD:
                pt_str = int_to_text(pt_int)
                print(f"\n*** SIGNAL *** cribs={cribs}/{N_CRIBS} "
                      f"src={text_name} off={offset} var={variant_name} "
                      f"w=0 PT={pt_str[:60]}...")

        else:
            # Columnar with constraint-propagation CSP solver
            # CSP is sound and complete for 24/24 detection at all widths.
            # Verified: 0/600 false negatives across widths 7-14.
            it_int = [decrypt_fn(CT_INT[i], key_int[i]) for i in range(CT_LEN)]
            best_order, best_cribs_csp = solve_columnar_csp(it_int, cc)

            if best_cribs_csp > best_cribs_chunk:
                best_cribs_chunk = best_cribs_csp

            if best_cribs_csp >= STORE_THRESHOLD and best_order:
                pt_arr = reconstruct_plaintext(it_int, best_order, cc)
                pt_str = int_to_text(pt_arr)
                qg_pc = scorer.score_per_char(pt_str)
                ic_val = fast_ic(pt_arr)
                bean = fast_bean_check(key_int)

                cand = {
                    "cribs": best_cribs_csp, "qg_pc": qg_pc, "ic": ic_val,
                    "bean": bean, "width": width, "variant": variant_name,
                    "source": text_name, "offset": offset,
                    "perm": best_order, "pt": pt_str,
                }
                results.append(cand)
                store_candidate(
                    db_p, 1, best_cribs_csp, qg_pc, ic_val, bean,
                    best_order, None, pt_str,
                    text_name, offset, width, variant_name,
                )

            if best_cribs_csp >= SIGNAL_THRESHOLD and best_order:
                pt_arr = reconstruct_plaintext(it_int, best_order, cc)
                pt_str = int_to_text(pt_arr)
                print(f"\n*** SIGNAL *** cribs={best_cribs_csp}/{N_CRIBS} "
                      f"src={text_name} off={offset} var={variant_name} "
                      f"w={width} PT={pt_str[:60]}...")

    return {
        "task_id": f"{text_name}|w{width}|{variant_name}|{offset_start}-{offset_end}",
        "n_tested": n_tested,
        "best_cribs": best_cribs_chunk,
        "results": results,
    }


def build_phase1_tasks(
    checkpoint: Checkpoint, db_path: Path, chunk_size: int = 5000,
) -> List[Tuple]:
    """Build chunked Phase 1 tasks for parallel processing."""
    done_set = set(checkpoint.phase1_files_done)
    tasks: List[Tuple] = []

    # Gather all corpus texts
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
                # For width 0: very fast per offset, large chunks
                # For width 7-14: CSP solver, moderate speed per offset
                # Width 13 is slowest (~3ms/offset), width 7 fastest (~0.01ms)
                if width == 0:
                    cs = max(chunk_size * 4, 20000)
                elif width <= 9:
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
    """Phase 1: Corpus running key + constraint-propagation columnar."""
    logger.info("=" * 72)
    logger.info("PHASE 1: Corpus running key + constraint-propagation columnar")
    logger.info("=" * 72)

    init_db(DB_PATH)
    tasks = build_phase1_tasks(checkpoint, DB_PATH)

    if not tasks:
        logger.info("Phase 1: No tasks remaining (all done or no corpus)")
        checkpoint.phase = 1
        return checkpoint

    total_tasks = len(tasks)
    logger.info(f"Phase 1: {total_tasks} chunk-tasks to process")

    # Sort tasks: fast first (width 0), then increasing width
    tasks.sort(key=lambda t: (t[3], t[4], t[0], t[5]))

    completed = 0
    total_tested = checkpoint.phase1_total_tested
    start_time = time.time()
    last_progress = start_time
    last_checkpoint_time = start_time
    best_overall = {"cribs": 0}

    with mp.Pool(workers) as pool:
        for result in pool.imap_unordered(phase1_process_chunk, tasks, chunksize=1):
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
                eta_h = (total_tasks - completed) / (completed / elapsed) / 3600 if completed > 0 else 0
                logger.info(
                    f"P1: {completed}/{total_tasks} ({pct:.1f}%) | "
                    f"{total_tested:,} offsets | "
                    f"{rate:.0f}/s | "
                    f"best={best_overall.get('cribs', 0)} | "
                    f"elapsed={elapsed/3600:.2f}h | "
                    f"ETA={eta_h:.1f}h"
                )
                last_progress = now

            if now - last_checkpoint_time >= 600:
                checkpoint.save(CHECKPOINT_PATH)
                logger.info(f"Checkpoint saved ({completed}/{total_tasks})")
                last_checkpoint_time = now

            # Detailed summary every 10 min
            if now - last_checkpoint_time < 5 and completed % max(1, total_tasks // 20) == 0:
                top5 = checkpoint.best_candidates[:5]
                if top5:
                    logger.info("Top 5 candidates:")
                    for i, c in enumerate(top5):
                        logger.info(
                            f"  #{i+1}: cribs={c.get('cribs',0)} "
                            f"qg={c.get('qg_pc',-99):.3f} "
                            f"src={c.get('source','?')} "
                            f"w={c.get('width','?')}"
                        )

    elapsed = time.time() - start_time
    logger.info(f"Phase 1 complete: {total_tested:,} offsets in {elapsed/3600:.2f}h")
    logger.info(f"Phase 1 best cribs: {best_overall.get('cribs', 0)}")
    checkpoint.phase = 1
    checkpoint.save(CHECKPOINT_PATH)
    return checkpoint


# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: Simulated Annealing — arbitrary permutation + key optimization
# ══════════════════════════════════════════════════════════════════════════

def sa_coopt_worker(args: Tuple) -> Dict[str, Any]:
    """SA chain co-optimizing permutation AND non-crib key values.

    Model:
      Forward:  IT = apply_perm(PT, sigma)  =>  CT[i] = encrypt(IT[i], key[i])
      Decrypt:  IT[i] = decrypt(CT[i], key[i])  =>  PT[j] = IT[sigma_inv[j]]

    For crib positions j: PT[j] is known, so:
      key[sigma_inv[j]] = recover(CT[sigma_inv[j]], PT[j])

    SA alternates between permutation swaps and key perturbations at non-crib
    positions, maximizing a composite score.
    """
    (chain_id, seed, n_iterations, variant_name,
     db_path_str, initial_perm) = args

    rng = random.Random(seed)
    scorer = QuadgramScorer(QUADGRAM_PATH)
    db_p = Path(db_path_str)

    fn_decrypt = {"vigenere": vig_decrypt_int, "beaufort": beau_decrypt_int,
                  "var_beaufort": varbeau_decrypt_int}[variant_name]
    fn_recover = {"vigenere": vig_recover_int, "beaufort": beau_recover_int,
                  "var_beaufort": varbeau_recover_int}[variant_name]

    # Initialize permutation (sigma[i] = which PT position is at IT position i)
    if initial_perm is not None:
        sigma = list(initial_perm)
    else:
        sigma = list(range(CT_LEN))
        rng.shuffle(sigma)

    inv_sigma = [0] * CT_LEN
    for i, s in enumerate(sigma):
        inv_sigma[s] = i

    # Initialize key and plaintext
    key = [0] * CT_LEN

    # Crib-determined key values
    crib_it_positions: set = set()
    for j in CRIB_POS_LIST:
        it_pos = inv_sigma[j]
        key[it_pos] = fn_recover(CT_INT[it_pos], CRIB_PT_INT[j])
        crib_it_positions.add(it_pos)

    # Random key for non-crib positions
    for i in range(CT_LEN):
        if i not in crib_it_positions:
            key[i] = rng.randint(0, 25)

    # Compute plaintext: PT[j] = decrypt(CT[inv_sigma[j]], key[inv_sigma[j]])
    pt_int = [fn_decrypt(CT_INT[inv_sigma[j]], key[inv_sigma[j]]) for j in range(CT_LEN)]

    # Precompute quadgram lookup for speed
    qg_lp = scorer._lp
    qg_floor = scorer._floor

    def qg_score_fast(pt: List[int]) -> float:
        total = 0.0
        for i in range(len(pt) - 3):
            gram = ALPH[pt[i]] + ALPH[pt[i+1]] + ALPH[pt[i+2]] + ALPH[pt[i+3]]
            total += qg_lp.get(gram, qg_floor)
        return total / (len(pt) - 3)

    def composite_score(cr: int, qg: float, iv: float, bn: bool) -> float:
        """Composite SA score. Since arbitrary permutations always give 24/24
        cribs (underdetermination), the primary discriminator is quadgram
        quality (English-likeness). IC and Bean are secondary bonuses.
        Real English has qg/c ~ -4.0; random is ~ -6.5.
        """
        s = qg * 100.0  # Primary: quadgram quality (range ~ -650 to -400)
        if iv > 0.05:
            s += 20.0    # IC bonus
        if iv > 0.06:
            s += 50.0    # Strong IC bonus
        if bn:
            s += 30.0    # Bean bonus
        return s

    cribs = fast_crib_score(pt_int)
    qg = qg_score_fast(pt_int)
    ic_val = fast_ic(pt_int)
    bean = fast_bean_check(key)
    comp = composite_score(cribs, qg, ic_val, bean)

    best_comp = comp
    best_cribs = cribs
    best_qg = qg
    best_ic = ic_val
    best_bean = bean
    best_sigma = sigma[:]
    best_key = key[:]
    best_pt = pt_int[:]

    T_start = 30.0
    T_min = 0.005
    alpha = 0.999997
    T = T_start

    accepted = 0
    sa_start_time = time.time()
    last_report_time = sa_start_time

    for iteration in range(n_iterations):
        if _shutdown_requested:
            break

        move_type = rng.random()

        if move_type < 0.55:
            # === Permutation swap ===
            i1, i2 = rng.sample(range(CT_LEN), 2)

            # What PT positions were at IT positions i1, i2?
            old_j1 = sigma[i1]  # PT pos at IT pos i1
            old_j2 = sigma[i2]  # PT pos at IT pos i2

            # Swap
            sigma[i1], sigma[i2] = sigma[i2], sigma[i1]
            inv_sigma[sigma[i1]] = i1
            inv_sigma[sigma[i2]] = i2

            # Recompute key at positions that are now crib-mapped
            saved_key_i1 = key[i1]
            saved_key_i2 = key[i2]

            j1_new = sigma[i1]  # New PT pos at IT pos i1
            j2_new = sigma[i2]  # New PT pos at IT pos i2

            if j1_new in CRIB_POSITIONS:
                key[i1] = fn_recover(CT_INT[i1], CRIB_PT_INT[j1_new])
            if j2_new in CRIB_POSITIONS:
                key[i2] = fn_recover(CT_INT[i2], CRIB_PT_INT[j2_new])

            # Recompute PT at the affected positions
            # PT positions affected: old_j1, old_j2, j1_new, j2_new
            affected_pts = {old_j1, old_j2, j1_new, j2_new}
            saved_pt = {j: pt_int[j] for j in affected_pts}

            for j in affected_pts:
                itp = inv_sigma[j]
                pt_int[j] = fn_decrypt(CT_INT[itp], key[itp])

            new_cribs = fast_crib_score(pt_int)
            new_qg = qg_score_fast(pt_int)
            new_ic = fast_ic(pt_int)
            new_bean = fast_bean_check(key)
            new_comp = composite_score(new_cribs, new_qg, new_ic, new_bean)

            delta = new_comp - comp
            if delta > 0 or (T > T_min and rng.random() < math.exp(min(delta / T, 50))):
                comp = new_comp
                cribs = new_cribs
                qg = new_qg
                ic_val = new_ic
                bean = new_bean
                accepted += 1
            else:
                # Revert
                sigma[i1], sigma[i2] = sigma[i2], sigma[i1]
                inv_sigma[sigma[i1]] = i1
                inv_sigma[sigma[i2]] = i2
                key[i1] = saved_key_i1
                key[i2] = saved_key_i2
                for j, v in saved_pt.items():
                    pt_int[j] = v

        else:
            # === Key perturbation at a non-crib PT position ===
            j = rng.choice(NON_CRIB_POS)
            itp = inv_sigma[j]

            # Only perturb if this IT position is NOT crib-determined
            # (j is non-crib, but sigma[itp]=j could have changed)
            if sigma[itp] in CRIB_POSITIONS:
                continue

            old_key_val = key[itp]
            new_key_val = rng.randint(0, 25)
            if new_key_val == old_key_val:
                continue

            old_pt_val = pt_int[j]
            new_pt_val = fn_decrypt(CT_INT[itp], new_key_val)

            key[itp] = new_key_val
            pt_int[j] = new_pt_val

            new_cribs = fast_crib_score(pt_int)
            new_qg = qg_score_fast(pt_int)
            new_ic = fast_ic(pt_int)
            new_bean = fast_bean_check(key)
            new_comp = composite_score(new_cribs, new_qg, new_ic, new_bean)

            delta = new_comp - comp
            if delta > 0 or (T > T_min and rng.random() < math.exp(min(delta / T, 50))):
                comp = new_comp
                cribs = new_cribs
                qg = new_qg
                ic_val = new_ic
                bean = new_bean
                accepted += 1
            else:
                key[itp] = old_key_val
                pt_int[j] = old_pt_val

        if comp > best_comp:
            best_comp = comp
            best_cribs = cribs
            best_qg = qg
            best_ic = ic_val
            best_bean = bean
            best_sigma = sigma[:]
            best_key = key[:]
            best_pt = pt_int[:]
            is_new_best = True
        else:
            is_new_best = False

        T = max(T * alpha, T_min)

        # Periodic reheat
        if iteration > 0 and iteration % 5_000_000 == 0:
            T = T_start * 0.3
            if rng.random() < 0.2:
                sigma = best_sigma[:]
                key = best_key[:]
                pt_int = best_pt[:]
                inv_sigma = [0] * CT_LEN
                for i, s in enumerate(sigma):
                    inv_sigma[s] = i
                comp = best_comp
                cribs = best_cribs
                qg = best_qg
                ic_val = best_ic
                bean = best_bean

        # Store only new personal bests that pass multi-objective thresholds.
        # With arbitrary permutations, cribs is always 24/24 (underdetermined).
        # SA gibberish typically reaches qg/c ~ -3.5, IC ~ 0.10, Bean PASS.
        # Real English: qg/c ~ -4.0, IC ~ 0.067.
        if is_new_best and qg > -5.0:
            store_candidate(
                db_p, 2, cribs, qg, ic_val, bean,
                sigma[:], None, int_to_text(pt_int),
                f"SA-{chain_id}", None, None, variant_name,
            )

        # Alert only for new personal bests with exceptional scores
        if is_new_best and qg > -4.0 and ic_val > 0.06 and bean:
            print(f"\n*** SA BREAKTHROUGH CANDIDATE *** "
                  f"chain={chain_id} iter={iteration:,} "
                  f"qg/c={qg:.3f} IC={ic_val:.4f} bean=PASS "
                  f"PT={int_to_text(pt_int)[:70]}...")

        # Periodic progress report (every 120 seconds)
        if iteration > 0 and iteration % 500_000 == 0:
            now = time.time()
            if now - last_report_time >= 120:
                elapsed_sa = now - sa_start_time
                rate = iteration / elapsed_sa
                pct = iteration / n_iterations * 100
                eta_h = (n_iterations - iteration) / rate / 3600 if rate > 0 else 0
                print(f"[SA-{chain_id}] {pct:.0f}% ({iteration:,}/{n_iterations:,}) "
                      f"{rate:,.0f} it/s | T={T:.3f} | "
                      f"best qg/c={best_qg:.3f} IC={best_ic:.4f} "
                      f"bean={'P' if best_bean else 'F'} | "
                      f"ETA={eta_h:.1f}h", flush=True)
                last_report_time = now

    return {
        "chain_id": chain_id,
        "best_cribs": best_cribs,
        "best_qg": best_qg,
        "best_ic": best_ic,
        "best_bean": best_bean,
        "best_sigma": best_sigma,
        "best_pt": int_to_text(best_pt),
        "iterations": n_iterations,
        "accepted": accepted,
        "variant": variant_name,
    }


def run_phase2(
    workers: int, checkpoint: Checkpoint, logger: logging.Logger,
    iterations_per_chain: int = 20_000_000,
) -> Checkpoint:
    """Phase 2: SA permutation + key co-optimization."""
    logger.info("=" * 72)
    logger.info("PHASE 2: Simulated Annealing — arbitrary permutations")
    logger.info("=" * 72)

    init_db(DB_PATH)

    n_chains = workers
    variant_names = ["vigenere", "beaufort", "var_beaufort"]

    tasks = []
    for i in range(n_chains):
        variant = variant_names[i % 3]
        seed = int(time.time() * 1000) + i * 7919
        tasks.append((
            i, seed, iterations_per_chain, variant, str(DB_PATH), None
        ))

    logger.info(f"Phase 2: {n_chains} SA chains, {iterations_per_chain:,} iters each")
    est_total = n_chains * iterations_per_chain
    logger.info(f"Phase 2: {est_total:,} total iterations")

    start_time = time.time()
    all_results = []

    with mp.Pool(workers) as pool:
        for result in pool.imap_unordered(sa_coopt_worker, tasks):
            if _shutdown_requested:
                pool.terminate()
                break

            all_results.append(result)
            r = result
            logger.info(
                f"SA chain {r['chain_id']} done: "
                f"cribs={r['best_cribs']} qg/c={r['best_qg']:.3f} "
                f"IC={r['best_ic']:.4f} bean={'PASS' if r['best_bean'] else 'FAIL'} "
                f"variant={r['variant']} accepted={r['accepted']:,}"
            )
            checkpoint.add_candidate({
                "cribs": r["best_cribs"], "qg_pc": r["best_qg"],
                "ic": r["best_ic"], "bean": r["best_bean"],
                "source": f"SA-{r['chain_id']}", "variant": r["variant"],
                "pt": r["best_pt"],
            })
            checkpoint.save(CHECKPOINT_PATH)

    elapsed = time.time() - start_time
    total_iters = sum(r.get("iterations", 0) for r in all_results)
    logger.info(f"Phase 2 complete: {total_iters:,} iters in {elapsed/3600:.2f}h")
    if all_results:
        best = max(all_results, key=lambda r: r.get("best_cribs", 0))
        logger.info(f"Phase 2 best: cribs={best['best_cribs']} "
                     f"qg/c={best['best_qg']:.3f}")

    checkpoint.phase2_iterations = total_iters
    checkpoint.phase = 2
    checkpoint.save(CHECKPOINT_PATH)
    return checkpoint


# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: Hybrid — SA seeded from Phase 1/2 top candidates
# ══════════════════════════════════════════════════════════════════════════

def get_phase1_seeds(db_path: Path, limit: int = 100) -> List[Dict]:
    """Retrieve top Phase 1/2 candidates from the database."""
    if not db_path.exists():
        return []
    try:
        conn = sqlite3.connect(str(db_path))
        rows = conn.execute(
            "SELECT score_cribs, score_quadgram, score_ic, bean_pass, "
            "permutation, plaintext, source_text, cipher_variant "
            "FROM candidates "
            "ORDER BY score_cribs DESC, score_quadgram DESC "
            "LIMIT ?",
            (limit,),
        ).fetchall()
        conn.close()
    except Exception:
        return []

    seeds = []
    for row in rows:
        perm = json.loads(row[4]) if row[4] else None
        seeds.append({
            "cribs": row[0], "qg": row[1], "ic": row[2], "bean": bool(row[3]),
            "perm": perm, "pt": row[5], "source": row[6], "variant": row[7],
        })
    return seeds


def run_phase3(
    workers: int, checkpoint: Checkpoint, logger: logging.Logger,
    iterations_per_chain: int = 30_000_000,
) -> Checkpoint:
    """Phase 3: Hybrid SA seeded from earlier phases."""
    logger.info("=" * 72)
    logger.info("PHASE 3: Hybrid SA seeded from Phase 1/2 top candidates")
    logger.info("=" * 72)

    init_db(DB_PATH)

    seeds = get_phase1_seeds(DB_PATH, limit=100)
    logger.info(f"Phase 3: {len(seeds)} seed candidates from database")

    variant_names = ["vigenere", "beaufort", "var_beaufort"]
    tasks = []

    n_seeded = min(len(seeds), workers)
    n_random = workers - n_seeded

    for i, seed_data in enumerate(seeds[:n_seeded]):
        perm = seed_data.get("perm")
        variant = seed_data.get("variant") or variant_names[i % 3]
        s = int(time.time() * 1000) + i * 7919 + 999983
        tasks.append((
            f"seed-{i}", s, iterations_per_chain, variant, str(DB_PATH), perm
        ))

    for i in range(n_random):
        variant = variant_names[i % 3]
        s = int(time.time() * 1000) + (n_seeded + i) * 7919 + 1999993
        tasks.append((
            f"rand-{i}", s, iterations_per_chain, variant, str(DB_PATH), None
        ))

    logger.info(f"Phase 3: {n_seeded} seeded + {n_random} random, "
                f"{iterations_per_chain:,} iters each")

    start_time = time.time()
    all_results = []

    with mp.Pool(min(workers, len(tasks))) as pool:
        for result in pool.imap_unordered(sa_coopt_worker, tasks):
            if _shutdown_requested:
                pool.terminate()
                break

            all_results.append(result)
            r = result
            logger.info(
                f"P3 chain {r['chain_id']} done: "
                f"cribs={r['best_cribs']} qg/c={r['best_qg']:.3f} "
                f"IC={r['best_ic']:.4f} bean={'PASS' if r['best_bean'] else 'FAIL'}"
            )
            checkpoint.add_candidate({
                "cribs": r["best_cribs"], "qg_pc": r["best_qg"],
                "ic": r["best_ic"], "bean": r["best_bean"],
                "source": f"P3-{r['chain_id']}", "variant": r["variant"],
                "pt": r["best_pt"],
            })
            checkpoint.save(CHECKPOINT_PATH)

    elapsed = time.time() - start_time
    total_iters = sum(r.get("iterations", 0) for r in all_results)
    logger.info(f"Phase 3 complete: {total_iters:,} iters in {elapsed/3600:.2f}h")

    checkpoint.phase3_iterations = total_iters
    checkpoint.phase = 3
    checkpoint.save(CHECKPOINT_PATH)
    return checkpoint


# ══════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════

def print_summary(checkpoint: Checkpoint, logger: logging.Logger) -> None:
    total_time = time.time() - checkpoint.start_time if checkpoint.start_time else 0
    logger.info("")
    logger.info("=" * 72)
    logger.info("DRAGNET FINAL SUMMARY")
    logger.info("=" * 72)
    logger.info(f"Total runtime: {total_time/3600:.2f} hours")
    logger.info(f"Phase 1 offsets: {checkpoint.phase1_total_tested:,}")
    logger.info(f"Phase 2 SA iters: {checkpoint.phase2_iterations:,}")
    logger.info(f"Phase 3 hybrid iters: {checkpoint.phase3_iterations:,}")

    if checkpoint.best_candidates:
        logger.info(f"\nTop 10 candidates:")
        for i, c in enumerate(checkpoint.best_candidates[:10]):
            logger.info(
                f"  #{i+1}: cribs={c.get('cribs',0)} "
                f"qg/c={c.get('qg_pc', -99):.3f} "
                f"IC={c.get('ic', 0):.4f} "
                f"bean={'PASS' if c.get('bean') else 'FAIL'} "
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
                "SELECT phase, COUNT(*), MAX(score_cribs), "
                "MAX(score_quadgram) FROM candidates GROUP BY phase"
            ).fetchall()
            conn.close()
            logger.info(f"\nDatabase: {total} stored candidates")
            for phase, cnt, max_cr, max_qg in by_phase:
                logger.info(f"  Phase {phase}: {cnt} entries, "
                            f"max cribs={max_cr}, max qg/c={max_qg:.3f}" if max_qg else
                            f"  Phase {phase}: {cnt} entries, max cribs={max_cr}")
        except Exception:
            pass

    logger.info("=" * 72)


# ══════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="DRAGNET — Multi-day autonomous Kryptos K4 experiment",
    )
    parser.add_argument("--phase", type=str, default="all",
                        choices=["1", "2", "3", "all"])
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--sa-iters", type=int, default=100_000_000,
                        help="SA iterations per chain for Phase 2 (default 100M)")
    parser.add_argument("--sa3-iters", type=int, default=200_000_000,
                        help="SA iterations per chain for Phase 3 (default 200M)")
    args = parser.parse_args()

    logger = setup_logging()
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 72)
    logger.info("DRAGNET — Kryptos K4 Multi-Day Autonomous Experiment")
    logger.info(f"Workers: {args.workers} | Phase: {args.phase} | "
                f"Resume: {args.resume}")
    logger.info(f"CT: {CT}")
    logger.info(f"CT length: {CT_LEN} | Cribs: {N_CRIBS}")
    logger.info(f"Quadgram: {QUADGRAM_PATH}")
    logger.info(f"DB: {DB_PATH}")
    logger.info("=" * 72)

    # Load or create checkpoint
    if args.resume and CHECKPOINT_PATH.exists():
        checkpoint = Checkpoint.load(CHECKPOINT_PATH)
        logger.info(f"Resumed: phase={checkpoint.phase}, "
                     f"p1={checkpoint.phase1_total_tested:,}, "
                     f"p2={checkpoint.phase2_iterations:,}")
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
        logger.info(f"  {f.name} ({f.stat().st_size:,} bytes)")
    logger.info(f"Sculpture texts: {len(get_sculpture_texts())}")
    logger.info(f"Widths to test: {WIDTHS}")
    logger.info(f"Variants: {[v[0] for v in VARIANTS]}")

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
                checkpoint = run_phase2(
                    args.workers, checkpoint, logger,
                    iterations_per_chain=args.sa_iters,
                )

        if _shutdown_requested:
            checkpoint.save(CHECKPOINT_PATH)
            print_summary(checkpoint, logger)
            return

        if args.phase in ("3", "all"):
            if checkpoint.phase < 3 or args.phase == "3":
                checkpoint = run_phase3(
                    args.workers, checkpoint, logger,
                    iterations_per_chain=args.sa3_iters,
                )

    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
    finally:
        checkpoint.save(CHECKPOINT_PATH)
        print_summary(checkpoint, logger)
        logger.info("DRAGNET finished.")


if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()
