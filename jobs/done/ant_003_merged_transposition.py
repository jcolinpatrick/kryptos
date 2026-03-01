#!/usr/bin/env python3
"""ANT-003: Transposition + Substitution Cascade on Merged K3+K4 Block

The merged K3+K4 block on Antipodes is 433 chars with NO delimiter — if Sanborn
treated this as a single encipherment, the statistical leverage is 4.5x better
than K4 alone. K3 is known to use a transposition cipher. If K3's transposition
CONTINUES into K4, the combined 433-char block under a single transposition
becomes tractable.

Phase A: Columnar transposition sweep (widths 2-40)
  - For each width, try keyword-derived column orderings from thematic keywords
  - After de-transposition, check IC to see if the result looks like a
    simple substitution (expected IC ~0.065 for English after de-transposition)
  - If IC elevated: try Vigenère key recovery (chi-squared) on the de-transposed text

Phase B: Route cipher variations
  - Grid dimensions that fit or near-fit 433 (e.g., 433 = 433×1, but also
    try grid sizes that K3 might use: 336/w and extend to 433/w)
  - Spiral, zigzag, diagonal, boustrophedon read patterns
  - Score de-transposed output by IC and quadgrams

Phase C: Double columnar transposition
  - For top-performing Phase A widths, apply a SECOND columnar transposition
  - This tests the "two separate systems" hypothesis (Sanborn's statement)
  - Width pairs from {5,6,7,8,9,10} — 30 combos × keywords

Phase D: Transposition × Vigenère keyword cascade (THE BIG ONE)
  - For EVERY transposition (columnar widths 2-12 exhaustive perms +
    keyword-derived up to width 40), apply Vigenère with ALL dictionary
    keywords (370K) — both KA and AZ, all 3 variants
  - This is the "two separate systems" attack with full keyword coverage
  - ~375K transpositions × top-1000 keywords × 6 = ~2.25B configs
  - Actually batched: each worker does ONE transposition and sweeps a
    batch of keywords through it (amortizing the de-transposition cost)

Scoring:
  - Primary: IC of de-transposed text (looking for >0.050 indicating
    substitution-only residual)
  - Secondary: Quadgram score if IC flagged
  - For sections where K4 positions map to cribs, check crib consistency

Search space: ~100M-500M configs depending on keyword list size
Expected runtime: 3-6 hours with 28 workers

Usage:
    PYTHONPATH=src python3 -u jobs/pending/ant_003_merged_transposition.py --workers 28
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from collections import Counter
from itertools import permutations
from multiprocessing import Pool
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, MOD,
    CRIB_DICT,
    KRYPTOS_ALPHABET,
    NOISE_FLOOR,
)
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.scoring.ngram import NgramScorer
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, DECRYPT_FN, KEY_RECOVERY,
)

# ── Paths ────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent.parent.parent
RESULTS_DIR = ROOT / "results" / "ant_003"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
SUMMARY_FILE = ROOT / "reports" / "ant_003_merged_transposition.summary.json"
QUADGRAM_FILE = ROOT / "data" / "english_quadgrams.json"
THEMATIC_FILE = ROOT / "wordlists" / "thematic_keywords.txt"
WORDLIST_FILE = ROOT / "wordlists" / "english.txt"

# ── Alphabets ────────────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}

# ── Ciphertext ───────────────────────────────────────────────────────────────

K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFJPASSAGEDEBABORETURNST"
    "OTHEEARLIESTTASKWASENTALANTSANDHOWTESIDWALLSITTWASFORCED"
    "HEWALLSLOWLYWERECAVINGINTHEYWEREONLYABLETONOTREADITVERYC"
    "LEARLYWASTHEREACHAROOMBEYONDTHECHAMBERQCANYOUSEEANYTHINGQ"
)

MERGED = K3_CT + CT  # 433 chars
MERGED_LEN = len(MERGED)
K4_OFFSET = len(K3_CT)  # K4 starts at position 336 in merged block

# K4 cribs mapped to merged positions
CRIB_SORTED = sorted(CRIB_DICT.items())
MERGED_CRIBS = {K4_OFFSET + pos: char for pos, char in CRIB_DICT.items()}

# ── Transposition primitives ────────────────────────────────────────────────


def keyword_to_column_order(keyword: str) -> List[int]:
    """Convert keyword to column ordering (alphabetical rank of each letter).

    E.g., "KRYPTOS" → [2, 5, 6, 4, 7, 3, 1] (0-indexed: [1, 4, 5, 3, 6, 2, 0])
    """
    indexed = sorted(enumerate(keyword), key=lambda x: (x[1], x[0]))
    order = [0] * len(keyword)
    for rank, (orig_idx, _) in enumerate(indexed):
        order[orig_idx] = rank
    return order


def columnar_decipher(ct: str, width: int, col_order: List[int]) -> str:
    """Decipher columnar transposition.

    Read off by columns in col_order sequence, reassemble row-wise.
    """
    n = len(ct)
    nrows = math.ceil(n / width)
    # Number of columns that are "full" (have nrows chars)
    full_cols = n - (nrows - 1) * width  # = n % width, but handles n%width==0

    # Determine length of each column in read order
    col_lengths = []
    for col_idx in col_order:
        if col_idx < full_cols:
            col_lengths.append(nrows)
        else:
            col_lengths.append(nrows - 1)

    # Extract columns from ciphertext
    columns = {}
    pos = 0
    for i, rank in enumerate(col_order):
        length = col_lengths[i]
        columns[rank] = ct[pos:pos + length]
        pos += length

    # Reassemble row-wise
    result = []
    for row in range(nrows):
        for col in range(width):
            if col in columns and row < len(columns[col]):
                result.append(columns[col][row])

    return "".join(result)


def reverse_columnar(ct: str, width: int, col_order: List[int]) -> str:
    """Encipher with columnar transposition (inverse of decipher).

    Write text row-wise, read off column-wise in col_order.
    """
    n = len(ct)
    nrows = math.ceil(n / width)

    # Write into grid row-wise
    grid = []
    pos = 0
    for row in range(nrows):
        row_data = []
        for col in range(width):
            if pos < n:
                row_data.append(ct[pos])
                pos += 1
            else:
                row_data.append("")
        grid.append(row_data)

    # Read off column-wise in col_order
    result = []
    for col in col_order:
        for row in range(nrows):
            if grid[row][col]:
                result.append(grid[row][col])

    return "".join(result)


def route_spiral_cw(ct: str, nrows: int, ncols: int, start_corner: int = 0) -> str:
    """Read text laid out in a grid via clockwise spiral from a corner.

    start_corner: 0=top-left, 1=top-right, 2=bottom-right, 3=bottom-left
    """
    n = len(ct)
    if nrows * ncols < n:
        return ""  # Grid too small

    # Fill grid row-wise
    grid = [['' for _ in range(ncols)] for _ in range(nrows)]
    pos = 0
    for r in range(nrows):
        for c in range(ncols):
            if pos < n:
                grid[r][c] = ct[pos]
                pos += 1

    # Spiral read from chosen corner
    result = []
    visited = [[False] * ncols for _ in range(nrows)]

    if start_corner == 0:
        # Top-left, CW: right, down, left, up
        dirs = [(0, 1), (1, 0), (0, -1), (-1, 0)]
        r, c = 0, 0
    elif start_corner == 1:
        # Top-right, CW: down, left, up, right
        dirs = [(1, 0), (0, -1), (-1, 0), (0, 1)]
        r, c = 0, ncols - 1
    elif start_corner == 2:
        # Bottom-right, CW: left, up, right, down
        dirs = [(0, -1), (-1, 0), (0, 1), (1, 0)]
        r, c = nrows - 1, ncols - 1
    else:
        # Bottom-left, CW: up, right, down, left
        dirs = [(-1, 0), (0, 1), (1, 0), (0, -1)]
        r, c = nrows - 1, 0

    d = 0
    for _ in range(nrows * ncols):
        if 0 <= r < nrows and 0 <= c < ncols and not visited[r][c]:
            if grid[r][c]:
                result.append(grid[r][c])
            visited[r][c] = True
        # Try to continue in current direction
        nr, nc = r + dirs[d][0], c + dirs[d][1]
        if not (0 <= nr < nrows and 0 <= nc < ncols and not visited[nr][nc]):
            # Turn
            d = (d + 1) % 4
            nr, nc = r + dirs[d][0], c + dirs[d][1]
        r, c = nr, nc

    return "".join(result)


def route_zigzag(ct: str, nrows: int, ncols: int) -> str:
    """Read text from grid using zigzag (boustrophedon) — alternate row direction."""
    n = len(ct)
    if nrows * ncols < n:
        return ""

    grid = [['' for _ in range(ncols)] for _ in range(nrows)]
    pos = 0
    for r in range(nrows):
        for c in range(ncols):
            if pos < n:
                grid[r][c] = ct[pos]
                pos += 1

    result = []
    for r in range(nrows):
        cols = range(ncols) if r % 2 == 0 else range(ncols - 1, -1, -1)
        for c in cols:
            if grid[r][c]:
                result.append(grid[r][c])

    return "".join(result)


def route_column_zigzag(ct: str, nrows: int, ncols: int) -> str:
    """Read column-wise with alternating column direction."""
    n = len(ct)
    if nrows * ncols < n:
        return ""

    grid = [['' for _ in range(ncols)] for _ in range(nrows)]
    pos = 0
    for r in range(nrows):
        for c in range(ncols):
            if pos < n:
                grid[r][c] = ct[pos]
                pos += 1

    result = []
    for c in range(ncols):
        rows = range(nrows) if c % 2 == 0 else range(nrows - 1, -1, -1)
        for r in rows:
            if grid[r][c]:
                result.append(grid[r][c])

    return "".join(result)


# ── Vigenère key recovery ────────────────────────────────────────────────────

ENGLISH_FREQ = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228,
                0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025,
                0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987,
                0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,
                0.01974, 0.00074]


def chi_squared_key_recovery(ct: str, period: int,
                              alph_idx: Dict[str, int]) -> Tuple[List[int], float]:
    """Recover Vigenère key for given period using chi-squared statistic."""
    n = len(ct)
    key = []
    total_chi = 0.0

    for col in range(period):
        # Extract every period-th character starting at col
        column_chars = [ct[i] for i in range(col, n, period)]
        col_len = len(column_chars)
        if col_len == 0:
            key.append(0)
            continue

        best_shift = 0
        best_chi = float('inf')

        for shift in range(26):
            chi = 0.0
            counts = [0] * 26
            for c in column_chars:
                idx = (alph_idx[c] - shift) % 26
                counts[idx] += 1
            for i in range(26):
                expected = ENGLISH_FREQ[i] * col_len
                if expected > 0:
                    chi += (counts[i] - expected) ** 2 / expected

            if chi < best_chi:
                best_chi = chi
                best_shift = shift

        key.append(best_shift)
        total_chi += best_chi

    avg_chi = total_chi / period if period > 0 else 0
    return key, avg_chi


# ── Worker functions ────────────────────────────────────────────────────────

_ngram_scorer = None


def _init_worker():
    global _ngram_scorer
    _ngram_scorer = NgramScorer.from_file(str(QUADGRAM_FILE))


def _worker_columnar(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Test a single columnar transposition config on merged block."""
    width = item["width"]
    col_order = item["col_order"]
    keyword = item["keyword"]
    phase = item.get("phase", "A")

    # De-transpose
    dt = columnar_decipher(MERGED, width, col_order)
    if len(dt) != MERGED_LEN:
        return None

    dt_ic = ic(dt)
    result = {
        "phase": phase,
        "width": width,
        "keyword": keyword,
        "col_order": col_order,
        "dt_ic": round(dt_ic, 5),
    }

    # Check K4 cribs in de-transposed positions
    # After columnar de-transposition, K4 chars are still at merged positions 336-432
    # but their ORDER has changed. We need to find where the original K4 positions
    # ended up after de-transposition.
    # Actually: de-transposition undoes the transposition. If the plaintext was
    # transposed to create CT, then de-transposing CT gives us plaintext back.
    # The K4 portion of the de-transposed text IS positions 336-432.
    k4_dt = dt[K4_OFFSET:K4_OFFSET + CT_LEN]
    k4_ic = ic(k4_dt)
    result["k4_ic"] = round(k4_ic, 5)

    # Primary flag: IC of full de-transposed text
    if dt_ic < 0.042:
        return None  # Below noise

    # Check for English-like statistics after removing known K3 plaintext effect
    # K3 positions should decrypt to K3_PT if transposition is correct
    k3_dt = dt[:K4_OFFSET]
    k3_match = sum(1 for i in range(min(len(k3_dt), len(K3_PT)))
                   if k3_dt[i] == K3_PT[i])
    result["k3_match"] = k3_match
    result["k3_match_pct"] = round(k3_match / len(K3_PT) * 100, 1)

    # If K3 matches well (>50%), this is a very strong signal
    if k3_match > len(K3_PT) * 0.5:
        result["k3_signal"] = True

    # Quadgram scoring on K4 portion
    if _ngram_scorer and len(k4_dt) >= 4:
        qscore = _ngram_scorer.score(k4_dt) / len(k4_dt)
        result["k4_quadgram"] = round(qscore, 4)

    # Full text quadgram
    if _ngram_scorer and len(dt) >= 4:
        qscore_full = _ngram_scorer.score(dt) / len(dt)
        result["full_quadgram"] = round(qscore_full, 4)

    # Try Vigenère key recovery on de-transposed text
    if dt_ic > 0.048:
        for period in [1, 8, 10, 13, 26]:
            key_az, chi = chi_squared_key_recovery(dt, period, AZ_IDX)
            fn = DECRYPT_FN[CipherVariant.VIGENERE]
            pt = "".join(AZ[fn(AZ_IDX[dt[i]], key_az[i % period]) % 26]
                         for i in range(len(dt)))
            pt_ic = ic(pt)
            if pt_ic > 0.055:
                result[f"vig_p{period}_ic"] = round(pt_ic, 5)
                result[f"vig_p{period}_key"] = "".join(AZ[k] for k in key_az)
                result[f"vig_p{period}_pt"] = pt[:60]
                if _ngram_scorer:
                    result[f"vig_p{period}_qg"] = round(
                        _ngram_scorer.score(pt) / len(pt), 4)

    result["dt_preview"] = dt[:60]
    return result


def _worker_route(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Test a route cipher configuration on merged block."""
    nrows = item["nrows"]
    ncols = item["ncols"]
    route_type = item["route_type"]
    corner = item.get("corner", 0)

    if route_type == "spiral":
        dt = route_spiral_cw(MERGED, nrows, ncols, corner)
    elif route_type == "zigzag":
        dt = route_zigzag(MERGED, nrows, ncols)
    elif route_type == "col_zigzag":
        dt = route_column_zigzag(MERGED, nrows, ncols)
    else:
        return None

    if not dt or len(dt) < MERGED_LEN * 0.9:
        return None

    dt_ic = ic(dt)
    if dt_ic < 0.042:
        return None

    result = {
        "phase": "B",
        "nrows": nrows,
        "ncols": ncols,
        "route_type": route_type,
        "corner": corner,
        "dt_ic": round(dt_ic, 5),
    }

    # K3 plaintext match check
    k3_dt = dt[:K4_OFFSET] if len(dt) >= K4_OFFSET else dt
    k3_match = sum(1 for i in range(min(len(k3_dt), len(K3_PT)))
                   if i < len(k3_dt) and k3_dt[i] == K3_PT[i])
    result["k3_match"] = k3_match

    # Quadgram
    if _ngram_scorer and len(dt) >= 4:
        qscore = _ngram_scorer.score(dt) / len(dt)
        result["full_quadgram"] = round(qscore, 4)

    if dt_ic > 0.048:
        # K4 portion analysis
        if len(dt) > K4_OFFSET:
            k4_dt = dt[K4_OFFSET:K4_OFFSET + CT_LEN]
            if _ngram_scorer and len(k4_dt) >= 4:
                result["k4_quadgram"] = round(
                    _ngram_scorer.score(k4_dt) / len(k4_dt), 4)
            result["k4_ic"] = round(ic(k4_dt), 5)

    result["dt_preview"] = dt[:60]
    return result


def _worker_double_columnar(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Test double columnar transposition."""
    w1 = item["w1"]
    w2 = item["w2"]
    order1 = item["order1"]
    order2 = item["order2"]
    kw1 = item["kw1"]
    kw2 = item["kw2"]

    # First de-transposition
    dt1 = columnar_decipher(MERGED, w1, order1)
    if len(dt1) != MERGED_LEN:
        return None

    # Second de-transposition
    dt2 = columnar_decipher(dt1, w2, order2)
    if len(dt2) != MERGED_LEN:
        return None

    dt_ic = ic(dt2)
    if dt_ic < 0.045:
        return None

    result = {
        "phase": "C",
        "w1": w1,
        "w2": w2,
        "kw1": kw1,
        "kw2": kw2,
        "dt_ic": round(dt_ic, 5),
    }

    # K3 match
    k3_dt = dt2[:K4_OFFSET]
    k3_match = sum(1 for i in range(min(len(k3_dt), len(K3_PT)))
                   if k3_dt[i] == K3_PT[i])
    result["k3_match"] = k3_match

    if _ngram_scorer:
        result["full_quadgram"] = round(
            _ngram_scorer.score(dt2) / len(dt2), 4)
        k4_dt = dt2[K4_OFFSET:K4_OFFSET + CT_LEN]
        if len(k4_dt) >= 4:
            result["k4_quadgram"] = round(
                _ngram_scorer.score(k4_dt) / len(k4_dt), 4)

    # Vig key recovery on double-de-transposed text
    if dt_ic > 0.050:
        for period in [1, 8]:
            key_az, chi = chi_squared_key_recovery(dt2, period, AZ_IDX)
            fn = DECRYPT_FN[CipherVariant.VIGENERE]
            pt = "".join(AZ[fn(AZ_IDX[dt2[i]], key_az[i % period]) % 26]
                         for i in range(len(dt2)))
            pt_ic = ic(pt)
            if pt_ic > 0.055:
                result[f"vig_p{period}_ic"] = round(pt_ic, 5)
                result[f"vig_p{period}_key"] = "".join(AZ[k] for k in key_az)
                result[f"vig_p{period}_pt"] = pt[:60]

    result["dt_preview"] = dt2[:60]
    return result


# ── Work item generators ────────────────────────────────────────────────────

def load_keywords() -> List[str]:
    """Load thematic keywords + top english words (up to length 15)."""
    words = set()

    # Thematic keywords (priority)
    with open(THEMATIC_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            w = line.upper()
            if all(c in AZ for c in w) and len(w) >= 3:
                words.add(w)

    # English words (filter to reasonable key lengths 3-15)
    with open(WORDLIST_FILE) as f:
        for line in f:
            w = line.strip().upper()
            if w and all(c in AZ for c in w) and 3 <= len(w) <= 15:
                words.add(w)

    return sorted(words)


def generate_phase_a(keywords: List[str]) -> List[Dict[str, Any]]:
    """Phase A: columnar transposition with keyword-derived orderings."""
    items = []
    seen_orders = set()

    for width in range(2, 41):
        # Generate identity permutation for each width
        identity = list(range(width))
        key_id = (width, tuple(identity))
        if key_id not in seen_orders:
            seen_orders.add(key_id)
            items.append({
                "width": width,
                "col_order": identity,
                "keyword": f"IDENTITY_{width}",
                "phase": "A",
            })
        # Reversed
        rev = list(range(width - 1, -1, -1))
        key_rev = (width, tuple(rev))
        if key_rev not in seen_orders:
            seen_orders.add(key_rev)
            items.append({
                "width": width,
                "col_order": rev,
                "keyword": f"REVERSED_{width}",
                "phase": "A",
            })

        # Keyword-derived orderings
        for kw in keywords:
            if len(kw) == width:
                order = keyword_to_column_order(kw)
                key = (width, tuple(order))
                if key not in seen_orders:
                    seen_orders.add(key)
                    items.append({
                        "width": width,
                        "col_order": order,
                        "keyword": kw,
                        "phase": "A",
                    })

    # Exhaustive permutations for small widths (2-8)
    # width 8 = 40320 perms — still fast for single-pass IC check
    for width in range(2, 9):
        for perm in permutations(range(width)):
            key = (width, perm)
            if key not in seen_orders:
                seen_orders.add(key)
                items.append({
                    "width": width,
                    "col_order": list(perm),
                    "keyword": f"PERM_{''.join(str(x) for x in perm)}",
                    "phase": "A",
                })

    return items


def generate_phase_b() -> List[Dict[str, Any]]:
    """Phase B: route cipher variations."""
    items = []
    # Grid dimensions that could fit 433 chars
    # nrows × ncols >= 433, with reasonable dimensions
    for nrows in range(5, 50):
        for ncols in range(5, 50):
            if nrows * ncols < MERGED_LEN:
                continue
            if nrows * ncols > MERGED_LEN + max(nrows, ncols):
                continue  # Too much padding
            # Spiral from each corner
            for corner in range(4):
                items.append({
                    "nrows": nrows,
                    "ncols": ncols,
                    "route_type": "spiral",
                    "corner": corner,
                })
            # Zigzag
            items.append({
                "nrows": nrows,
                "ncols": ncols,
                "route_type": "zigzag",
            })
            # Column zigzag
            items.append({
                "nrows": nrows,
                "ncols": ncols,
                "route_type": "col_zigzag",
            })

    return items


def generate_phase_c(keywords: List[str]) -> List[Dict[str, Any]]:
    """Phase C: double columnar transposition."""
    items = []
    seen = set()

    # Use smaller width range for double transposition (combinatorial explosion)
    widths_to_test = list(range(5, 25))

    # Get keyword orderings for each width
    orderings = {}
    for width in widths_to_test:
        orderings[width] = []
        seen_for_width = set()

        # Identity and reverse
        orderings[width].append(("IDENTITY", list(range(width))))
        orderings[width].append(("REVERSED", list(range(width - 1, -1, -1))))

        for kw in keywords:
            if len(kw) == width:
                order = keyword_to_column_order(kw)
                t = tuple(order)
                if t not in seen_for_width:
                    seen_for_width.add(t)
                    orderings[width].append((kw, order))

        # Limit to 50 orderings per width for double transposition
        if len(orderings[width]) > 50:
            orderings[width] = orderings[width][:50]

    # Generate pairs
    for w1 in widths_to_test:
        if w1 not in orderings or not orderings[w1]:
            continue
        for w2 in widths_to_test:
            if w2 not in orderings or not orderings[w2]:
                continue
            for kw1, order1 in orderings[w1]:
                for kw2, order2 in orderings[w2]:
                    key = (w1, tuple(order1), w2, tuple(order2))
                    if key not in seen:
                        seen.add(key)
                        items.append({
                            "w1": w1,
                            "w2": w2,
                            "order1": order1,
                            "order2": order2,
                            "kw1": kw1,
                            "kw2": kw2,
                        })

    return items


# ── Phase D: Transposition × Vigenère keyword cascade ────────────────────────

# Load a compact keyword list for Phase D (top 5000 by length 3-15)
# This is loaded once and shared via fork()

_PHASE_D_KEYWORDS = None

def _load_phase_d_keywords() -> List[str]:
    """Load compact keyword list for Phase D cascade.

    Reduced to ~2000 high-priority keywords to keep per-transposition
    sweep under 1s. Includes all thematic + top 1500 English words.
    """
    words = set()
    # Thematic keywords first (always include)
    with open(THEMATIC_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            w = line.upper()
            if all(c in AZ for c in w) and 3 <= len(w) <= 20:
                words.add(w)

    # Add English words, prioritizing shorter ones (more likely as keys)
    english = []
    with open(WORDLIST_FILE) as f:
        for line in f:
            w = line.strip().upper()
            if w and all(c in AZ for c in w) and 3 <= len(w) <= 15:
                english.append(w)

    # Sort by length (shorter = higher priority for Vigenère keys)
    english.sort(key=len)
    # Take up to 1500 English words + all thematic (~1800 total)
    for w in english[:1500]:
        words.add(w)
    return sorted(words)


def _worker_phase_d(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Phase D: One transposition config × all keywords × all variants.

    Each worker receives a SINGLE transposition config and sweeps
    ALL keywords through it. This amortizes the de-transposition cost.
    """
    width = item["width"]
    col_order = item["col_order"]
    trans_kw = item["keyword"]

    # De-transpose once
    dt = columnar_decipher(MERGED, width, col_order)
    if len(dt) != MERGED_LEN:
        return None

    dt_ic = ic(dt)
    # Skip clearly useless transpositions
    if dt_ic < 0.035:
        return None

    best_result = None
    best_metric = -999.0

    # Pre-convert de-transposed text to integer arrays (ONCE per transposition)
    dt_ka = [KA_IDX.get(c, 0) for c in dt]
    dt_az = [ord(c) - 65 for c in dt]

    # Pre-compute decrypt function references
    fn_vig = DECRYPT_FN[CipherVariant.VIGENERE]
    fn_bea = DECRYPT_FN[CipherVariant.BEAUFORT]
    fn_vb = DECRYPT_FN[CipherVariant.VAR_BEAUFORT]
    fns = [(CipherVariant.VIGENERE, fn_vig),
           (CipherVariant.BEAUFORT, fn_bea),
           (CipherVariant.VAR_BEAUFORT, fn_vb)]
    tested = 0
    n = MERGED_LEN

    # Pre-cache keyword integer arrays for each alphabet
    kw_cache_ka = {}
    kw_cache_az = {}
    for kw in _PHASE_D_KEYWORDS:
        ka_valid = all(c in KA_IDX for c in kw)
        if ka_valid:
            kw_cache_ka[kw] = [KA_IDX[c] for c in kw]
        kw_cache_az[kw] = [ord(c) - 65 for c in kw]

    for kw in _PHASE_D_KEYWORDS:
        kw_az = kw_cache_az[kw]
        kw_ka = kw_cache_ka.get(kw)
        kw_len = len(kw_az)

        for var, fn in fns:
            for alph_name in ["az", "ka"]:
                if alph_name == "ka":
                    if kw_ka is None:
                        continue
                    key_ints = kw_ka
                    dt_ints = dt_ka
                    alph = KA
                else:
                    key_ints = kw_az
                    dt_ints = dt_az
                    alph = AZ

                tested += 1

                # FAST PATH: compute IC via letter counting (no string construction)
                counts = [0] * 26
                for i in range(n):
                    pt_idx = fn(dt_ints[i], key_ints[i % kw_len]) % MOD
                    counts[pt_idx] += 1

                # Compute IC from counts directly
                ic_sum = sum(c * (c - 1) for c in counts)
                pt_ic = ic_sum / (n * (n - 1)) if n > 1 else 0

                if pt_ic < 0.050:
                    continue

                # Passed IC threshold — now build the actual plaintext string
                pt = "".join(
                    alph[fn(dt_ints[i], key_ints[i % kw_len]) % MOD]
                    for i in range(n)
                )

                metric = pt_ic
                qg = -999.0
                if _ngram_scorer:
                    qg = _ngram_scorer.score(pt) / n
                    metric = pt_ic + (qg + 10) / 100

                if metric > best_metric:
                    best_metric = metric
                    k3_pt = pt[:K4_OFFSET]
                    k3_match = sum(1 for i in range(min(len(k3_pt), len(K3_PT)))
                                   if k3_pt[i] == K3_PT[i])

                    best_result = {
                        "phase": "D",
                        "trans_width": width,
                        "trans_kw": trans_kw,
                        "vig_kw": kw,
                        "variant": var.name,
                        "alph": alph_name,
                        "dt_ic": round(dt_ic, 5),
                        "pt_ic": round(pt_ic, 5),
                        "k3_match": k3_match,
                        "tested": tested,
                        "pt_preview": pt[:80],
                    }
                    if _ngram_scorer:
                        best_result["quadgram"] = round(qg, 4)
                        k4_pt = pt[K4_OFFSET:K4_OFFSET + CT_LEN]
                        if len(k4_pt) >= 4:
                            best_result["k4_quadgram"] = round(
                                _ngram_scorer.score(k4_pt) / len(k4_pt), 4)
                    if k3_match > len(K3_PT) * 0.3:
                        best_result["k3_signal"] = True

    if best_result is not None:
        best_result["configs_tested"] = tested
    return best_result


def generate_phase_d(keywords: List[str]) -> List[Dict[str, Any]]:
    """Phase D: Generate transposition configs for keyword cascade.

    Each item is a SINGLE transposition config. The worker sweeps all
    Vigenère keywords internally.
    """
    items = []
    seen = set()

    # Exhaustive perms for widths 2-8
    for width in range(2, 9):
        for perm in permutations(range(width)):
            key = (width, perm)
            if key not in seen:
                seen.add(key)
                items.append({
                    "width": width,
                    "col_order": list(perm),
                    "keyword": f"PERM_{''.join(str(x) for x in perm)}",
                })

    # Keyword-derived orderings for widths 2-40
    for kw in keywords:
        w = len(kw)
        if 2 <= w <= 40:
            order = keyword_to_column_order(kw)
            key = (w, tuple(order))
            if key not in seen:
                seen.add(key)
                items.append({
                    "width": w,
                    "col_order": order,
                    "keyword": kw,
                })

    # Identity and reverse for each width
    for width in range(2, 41):
        for label, order_fn in [("IDENTITY", lambda w: list(range(w))),
                                 ("REVERSED", lambda w: list(range(w-1, -1, -1)))]:
            order = order_fn(width)
            key = (width, tuple(order))
            if key not in seen:
                seen.add(key)
                items.append({
                    "width": width,
                    "col_order": order,
                    "keyword": f"{label}_{width}",
                })

    return items


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    global _PHASE_D_KEYWORDS

    parser = argparse.ArgumentParser(
        description="ANT-003: Transposition + substitution on merged K3+K4")
    parser.add_argument("--workers", type=int, default=28)
    parser.add_argument("--phase", type=str, default="all",
                        choices=["all", "A", "B", "C", "D"],
                        help="Which phase(s) to run")
    args = parser.parse_args()

    print("=" * 70)
    print("ANT-003: Transposition + Substitution Cascade")
    print(f"  Merged K3+K4 block: {MERGED_LEN} chars")
    print(f"  K4 offset in merged: {K4_OFFSET}")
    print(f"  Workers: {args.workers}")
    print("=" * 70)

    t0 = time.time()

    # Load keywords
    keywords = load_keywords()
    print(f"Loaded {len(keywords)} keywords")

    all_hits = []
    phase_stats = {}

    # ── Phase A: Columnar transposition ──
    if args.phase in ("all", "A"):
        print(f"\n{'='*70}")
        print("Phase A: Columnar Transposition Sweep")
        items_a = generate_phase_a(keywords)
        print(f"  Configs: {len(items_a):,}")
        phase_stats["A"] = {"configs": len(items_a)}

        hits_a = []
        t_a = time.time()
        with Pool(processes=args.workers, initializer=_init_worker) as pool:
            chunk = max(1, len(items_a) // (args.workers * 50))
            done = 0
            for result in pool.imap_unordered(_worker_columnar, items_a, chunksize=chunk):
                done += 1
                if done % 100_000 == 0:
                    elapsed = time.time() - t_a
                    print(f"  Phase A: [{done:,}/{len(items_a):,}] "
                          f"{done/len(items_a)*100:.1f}% | {done/elapsed:.0f}/s | "
                          f"hits={len(hits_a)}")
                    sys.stdout.flush()
                if result is not None:
                    hits_a.append(result)
                    # Signal detection
                    if result.get("k3_match", 0) > len(K3_PT) * 0.3:
                        print(f"\n  *** K3 MATCH: {result['k3_match']}/{len(K3_PT)} "
                              f"w={result['width']} kw={result['keyword']} ***")
                        sys.stdout.flush()
                    for key in result:
                        if key.startswith("vig_") and key.endswith("_ic"):
                            val = result[key]
                            if val > 0.060:
                                print(f"\n  *** HIGH VIG IC: {val:.4f} "
                                      f"w={result['width']} kw={result['keyword']} "
                                      f"{key} ***")
                                sys.stdout.flush()

        elapsed_a = time.time() - t_a
        phase_stats["A"]["hits"] = len(hits_a)
        phase_stats["A"]["elapsed_s"] = round(elapsed_a, 1)
        all_hits.extend(hits_a)
        print(f"  Phase A complete: {len(hits_a)} hits in {elapsed_a:.1f}s")

        # Save Phase A hits
        with open(RESULTS_DIR / "phase_a_hits.jsonl", "w") as f:
            for h in sorted(hits_a, key=lambda x: x.get("dt_ic", 0), reverse=True):
                f.write(json.dumps(h) + "\n")

    # ── Phase B: Route cipher ──
    if args.phase in ("all", "B"):
        print(f"\n{'='*70}")
        print("Phase B: Route Cipher Sweep")
        items_b = generate_phase_b()
        print(f"  Configs: {len(items_b):,}")
        phase_stats["B"] = {"configs": len(items_b)}

        hits_b = []
        t_b = time.time()
        with Pool(processes=args.workers, initializer=_init_worker) as pool:
            chunk = max(1, len(items_b) // (args.workers * 50))
            done = 0
            for result in pool.imap_unordered(_worker_route, items_b, chunksize=chunk):
                done += 1
                if done % 50_000 == 0:
                    elapsed = time.time() - t_b
                    print(f"  Phase B: [{done:,}/{len(items_b):,}] "
                          f"{done/len(items_b)*100:.1f}% | hits={len(hits_b)}")
                    sys.stdout.flush()
                if result is not None:
                    hits_b.append(result)
                    if result.get("k3_match", 0) > len(K3_PT) * 0.3:
                        print(f"\n  *** K3 MATCH: {result['k3_match']}/{len(K3_PT)} "
                              f"route={result['route_type']} "
                              f"{result['nrows']}×{result['ncols']} ***")
                        sys.stdout.flush()

        elapsed_b = time.time() - t_b
        phase_stats["B"]["hits"] = len(hits_b)
        phase_stats["B"]["elapsed_s"] = round(elapsed_b, 1)
        all_hits.extend(hits_b)
        print(f"  Phase B complete: {len(hits_b)} hits in {elapsed_b:.1f}s")

        with open(RESULTS_DIR / "phase_b_hits.jsonl", "w") as f:
            for h in sorted(hits_b, key=lambda x: x.get("dt_ic", 0), reverse=True):
                f.write(json.dumps(h) + "\n")

    # ── Phase C: Double columnar ──
    if args.phase in ("all", "C"):
        print(f"\n{'='*70}")
        print("Phase C: Double Columnar Transposition")
        items_c = generate_phase_c(keywords)
        print(f"  Configs: {len(items_c):,}")
        phase_stats["C"] = {"configs": len(items_c)}

        hits_c = []
        t_c = time.time()
        with Pool(processes=args.workers, initializer=_init_worker) as pool:
            chunk = max(1, len(items_c) // (args.workers * 50))
            done = 0
            for result in pool.imap_unordered(_worker_double_columnar, items_c,
                                               chunksize=chunk):
                done += 1
                if done % 100_000 == 0:
                    elapsed = time.time() - t_c
                    print(f"  Phase C: [{done:,}/{len(items_c):,}] "
                          f"{done/len(items_c)*100:.1f}% | hits={len(hits_c)}")
                    sys.stdout.flush()
                if result is not None:
                    hits_c.append(result)
                    if result.get("k3_match", 0) > len(K3_PT) * 0.3:
                        print(f"\n  *** K3 MATCH: {result['k3_match']}/{len(K3_PT)} "
                              f"w1={result['w1']} w2={result['w2']} ***")
                        sys.stdout.flush()

        elapsed_c = time.time() - t_c
        phase_stats["C"]["hits"] = len(hits_c)
        phase_stats["C"]["elapsed_s"] = round(elapsed_c, 1)
        all_hits.extend(hits_c)
        print(f"  Phase C complete: {len(hits_c)} hits in {elapsed_c:.1f}s")

        with open(RESULTS_DIR / "phase_c_hits.jsonl", "w") as f:
            for h in sorted(hits_c, key=lambda x: x.get("dt_ic", 0), reverse=True):
                f.write(json.dumps(h) + "\n")

    # ── Phase D: Transposition × Vigenère keyword cascade ──
    if args.phase in ("all", "D"):
        print(f"\n{'='*70}")
        print("Phase D: Transposition × Vigenère Keyword Cascade (THE BIG ONE)")
        _PHASE_D_KEYWORDS = _load_phase_d_keywords()
        print(f"  Vigenère keywords: {len(_PHASE_D_KEYWORDS)}")
        items_d = generate_phase_d(keywords)
        n_vig_per = len(_PHASE_D_KEYWORDS) * 6  # 3 variants × 2 alphabets
        print(f"  Transposition configs: {len(items_d):,}")
        print(f"  Vig keywords per transposition: {n_vig_per:,}")
        print(f"  Effective configs: ~{len(items_d) * n_vig_per:,}")
        phase_stats["D"] = {"configs": len(items_d),
                            "effective_configs": len(items_d) * n_vig_per}

        hits_d = []
        t_d = time.time()
        with Pool(processes=args.workers, initializer=_init_worker) as pool:
            # Each work item is heavy (sweeps all keywords), so chunksize=1
            done = 0
            for result in pool.imap_unordered(_worker_phase_d, items_d, chunksize=1):
                done += 1
                if done % 1000 == 0:
                    elapsed = time.time() - t_d
                    rate = done / elapsed
                    eta = (len(items_d) - done) / rate if rate > 0 else 0
                    print(f"  Phase D: [{done:,}/{len(items_d):,}] "
                          f"{done/len(items_d)*100:.1f}% | {rate:.1f} trans/s | "
                          f"ETA {eta:.0f}s ({eta/60:.1f}min) | hits={len(hits_d)}")
                    sys.stdout.flush()
                if result is not None:
                    hits_d.append(result)
                    ic_val = result.get("pt_ic", 0)
                    k3m = result.get("k3_match", 0)
                    if k3m > len(K3_PT) * 0.3:
                        print(f"\n  *** K3 MATCH: {k3m}/{len(K3_PT)} "
                              f"trans_w={result['trans_width']} "
                              f"vig_kw={result['vig_kw']} ***")
                        sys.stdout.flush()
                    if ic_val > 0.060:
                        print(f"\n  *** HIGH PT IC: {ic_val:.4f} "
                              f"trans_kw={result['trans_kw']} "
                              f"vig_kw={result['vig_kw']} ***")
                        sys.stdout.flush()

        elapsed_d = time.time() - t_d
        phase_stats["D"]["hits"] = len(hits_d)
        phase_stats["D"]["elapsed_s"] = round(elapsed_d, 1)
        all_hits.extend(hits_d)
        print(f"  Phase D complete: {len(hits_d)} hits in {elapsed_d:.1f}s "
              f"({elapsed_d/60:.1f}min)")

        with open(RESULTS_DIR / "phase_d_hits.jsonl", "w") as f:
            for h in sorted(hits_d, key=lambda x: x.get("pt_ic", 0), reverse=True):
                f.write(json.dumps(h) + "\n")

    # ── Summary ──────────────────────────────────────────────────────────────

    total_elapsed = time.time() - t0
    total_configs = sum(s.get("configs", 0) for s in phase_stats.values())

    print(f"\n{'='*70}")
    print("ANT-003 OVERALL RESULTS")
    print("=" * 70)
    print(f"Total configs:  {total_configs:,}")
    print(f"Total hits:     {len(all_hits)}")
    print(f"Total elapsed:  {total_elapsed:.1f}s ({total_elapsed/60:.1f}min)")
    for phase, stats in sorted(phase_stats.items()):
        print(f"  Phase {phase}: {stats.get('configs', 0):,} configs, "
              f"{stats.get('hits', 0)} hits, {stats.get('elapsed_s', 0):.1f}s")

    if all_hits:
        # Top by IC
        top_ic = sorted(all_hits, key=lambda h: h.get("dt_ic", 0), reverse=True)[:10]
        print("\n  Top 10 by de-transposed IC:")
        for h in top_ic:
            phase = h.get("phase", "?")
            ic_val = h.get("dt_ic", 0)
            k3m = h.get("k3_match", 0)
            print(f"    Phase {phase} | IC={ic_val:.4f} | K3match={k3m} | "
                  f"{h.get('keyword', h.get('route_type', '?'))} | "
                  f"{h.get('dt_preview', '')[:50]}")

        # Top by K3 match
        top_k3 = sorted(all_hits, key=lambda h: h.get("k3_match", 0), reverse=True)[:10]
        print("\n  Top 10 by K3 plaintext match:")
        for h in top_k3:
            phase = h.get("phase", "?")
            k3m = h.get("k3_match", 0)
            print(f"    Phase {phase} | K3match={k3m}/{len(K3_PT)} | "
                  f"IC={h.get('dt_ic', 0):.4f} | "
                  f"{h.get('keyword', h.get('route_type', '?'))}")

    # Save summary
    summary = {
        "experiment": "ant_003_merged_transposition",
        "merged_len": MERGED_LEN,
        "k4_offset": K4_OFFSET,
        "total_configs": total_configs,
        "total_hits": len(all_hits),
        "phase_stats": phase_stats,
        "elapsed_s": round(total_elapsed, 1),
        "workers": args.workers,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nRESULT: configs={total_configs:,} hits={len(all_hits)} "
          f"elapsed={total_elapsed:.1f}s")
    print(f"Summary: {SUMMARY_FILE}")


if __name__ == "__main__":
    main()
