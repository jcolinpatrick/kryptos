"""
Local parallel hypothesis tester for K4 candidates.

Takes structured hypotheses (from api_client) and tests them across
all available CPU cores using the existing kbot_harness infrastructure.

Features:
  - Parallel permutation testing (all available cores)
  - Plaintext generator execution (non-periodic substitution, autokey, etc.)
  - Hill-climbing optimizer for refining promising permutations
  - Sandboxed generator execution (subprocess with timeout + restricted imports)
  - Reading order generation from grid structures
"""

from __future__ import annotations

import json
import logging
import multiprocessing as mp
import os
import random
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from math import gcd
from pathlib import Path
from typing import Any

logger = logging.getLogger("kryptosbot.hypothesis_tester")

# ---------------------------------------------------------------------------
# Constants (duplicated to avoid import in worker processes)
# ---------------------------------------------------------------------------

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
K4_LEN = 97
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CRIBS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]

# All 24 individual crib positions
CRIB_POSITIONS = set()
for _pos, _text in CRIBS:
    for _j in range(len(_text)):
        CRIB_POSITIONS.add(_pos + _j)

_HARDCODED_KEYWORDS = [
    # --- PRIORITY TIER: Highest-plausibility Bean-PASSING (len 8) ---
    # These keywords score highest on constructor plausibility AND satisfy
    # all Bean constraints. DEFECTOR/PARALLAX/COLOPHON are the primary focus.
    #
    # Cold War / espionage — K4 cribs (EASTNORTHEAST, BERLINCLOCK) suggest
    # an operational message about exfiltrating a defector from East Berlin.
    # Berlin Wall fell Nov 1989; Kryptos dedicated Nov 1990. Sanborn worked
    # with Ed Scheidt (CIA Crypto Center 1963-1989).
    "DEFECTOR",     # one who defects — narrative fit: East Berlin exfiltration
    "SPYPLANE",     # surveillance aircraft (U-2 / Cold War)
    # Known Sanborn-series keywords that Bean-PASS
    "PARALLAX",     # apparent shift in position (KNOWN series keyword, Bean PASS)
    "COLOPHON",     # scribe's note at end of manuscript (KNOWN series keyword, Bean PASS)
    # Architecture / sculpture / archaeology
    "PEDESTAL",     # base of a column, statue, vase
    "MONOLITH",     # large single block of stone
    "FERETRUM",     # medieval reliquary or shrine
    "CEREMENT",     # burial shroud (archaeology, death theme)
    # Time / navigation — BERLINCLOCK crib connection
    # HOROLOGE — ELIMINATED (pigeonhole: all 6 AZ/KA × Vig/Beau/VBeau fail letter-supply)
    # HOROLOGY — ELIMINATED (same as HOROLOGE)
    "TOPOLOGY",     # mathematics of geometric properties

    # --- TIER 2: Strong Sanborn-aesthetic, Bean-PASSING (len 8) ---
    "CALATHOS",     # basket-like ornament in Greek architecture
    "APOPHYGE",     # curvature on top/bottom of columns
    "LARARIUM",     # Roman household shrine
    "LOGOGRAM",     # character that represents a word
    "LOGOTYPE",     # symbol/emblem as trademark
    "MONOTYPE",     # print made on metal plate
    "PARADIGM",     # pattern, system of thought
    "CAVALIER",     # military horseman, early modern cavalry
    "NIHILIST",     # nihilism (also a historical cipher name)
    "PARAVANE",     # naval cable-cutting/mine-sweeping device
    "DETECTOR",     # surveillance device (same E-E Bean pattern as DEFECTOR)
    "PEDERERO",     # ordnance for firing stones in siege warfare
    "VISIGOTH",     # ancient East Germanic tribe
    "YAMAGANE",     # unrefined copper (Kryptos IS copper!)

    # --- TIER 3: Plausible, Bean-PASSING (len 8) ---
    "PALATINE",     # feudal lord with palatine powers
    "POLONIUM",     # radioactive element Po (Curie, espionage)
    "VANADIUM",     # chemical element V
    "SELENIUM",     # chemical element Se
    "KURULTAI",     # Mongol/Turkic political-military council
    "VIGILANT",     # watchful for danger
    "CEREMONY",     # ritual with cultural significance
    "SELEUCID",     # Greek-Macedonian dynasty 312-63 BCE
    "HEREDITY",     # hereditary transmission
    "HOMOTOPY",     # continuous deformation (topology)
    "CODOMAIN",     # target set of a function (mathematics)
    "MONOPOLE",     # single magnetic pole
    "DERELICT",     # abandoned, forsaken (archaeology)
    "BASALTIC",     # of basalt (stone, sculpture)

    # --- Core Kryptos words (Bean-impossible, identity baseline only) ---
    "KRYPTOS",      # sculpture name (len 7, Bean impossible)
    "PALIMPSEST",   # K1-K2 keyword (len 10, Bean impossible)
    "ABSCISSA",     # K3 keyword (len 8, Bean eq FAIL)
]

# Priority keywords for intensive search — these get extra hill-climbing restarts
PRIORITY_KEYWORDS = [
    # NOTE: ALL top keywords fail full 242-pair Bean check on raw 97-char text.
    # These are retained for null-mask / two-system testing where Bean constraints
    # apply to the 73-char real CT, not the 97-char carved text.
    "DEFECTOR",     # Cold War narrative: East Berlin defection (4/6 pigeonhole)
    "PARALLAX",     # Known Sanborn keyword, geometry (3/6 pigeonhole)
    "COLOPHON",     # Known Sanborn keyword, manuscripts (3/6 pigeonhole)
    "TOPOLOGY",     # Mathematics of geometric properties
    "PEDESTAL",     # Sculpture base — Sanborn's medium
    "MONOLITH",     # Large single stone — monument/sculpture
    # K-for-C hypothesis keywords (thematic but weaker pigeonhole survival)
    "KOMPASS",      # German COMPASS — lodestone theme (5/6 pigeonhole, fails Bean eq at p=7)
    "KOLOPHON",     # Greek COLOPHON (3/6 pigeonhole)
    "KRYPTA",       # German/Greek CRYPT (3/6 pigeonhole)
    "KRYPTEIA",     # Spartan secret police (2/6 pigeonhole)
    "KLEPSYDRA",    # Greek water clock — BERLINCLOCK + pool theme (2/6 pigeonhole)
    "SPYPLANE",     # Surveillance — Cold War
]

# --- Bean constraints (derived dynamically for worker-process isolation) ---
# Source: Bean 2021 "Cryptodiagnosis of Kryptos K4"
# Full variant-independent set: pairs where derived key differs for ALL 3 variants
BEAN_EQ = [(27, 65)]

# Build CRIB_DICT for Bean derivation
_CRIB_DICT: dict[int, str] = {}
for _pos, _text in CRIBS:
    for _j, _ch in enumerate(_text):
        _CRIB_DICT[_pos + _j] = _ch

def _derive_bean_ineq() -> list[tuple[int, int]]:
    """Derive the full variant-independent Bean inequality set (242 pairs)."""
    positions = sorted(_CRIB_DICT.keys())
    pairs: list[tuple[int, int]] = []
    for i in range(len(positions)):
        for j in range(i + 1, len(positions)):
            a, b = positions[i], positions[j]
            ca, pa = ord(K4[a]) - 65, ord(_CRIB_DICT[a]) - 65
            cb, pb = ord(K4[b]) - 65, ord(_CRIB_DICT[b]) - 65
            vig_eq = (ca - pa) % 26 == (cb - pb) % 26
            beau_eq = (ca + pa) % 26 == (cb + pb) % 26
            vbeau_eq = (pa - ca) % 26 == (pb - cb) % 26
            if not vig_eq and not beau_eq and not vbeau_eq:
                pairs.append((a, b))
    return pairs

BEAN_INEQ = _derive_bean_ineq()
assert len(BEAN_INEQ) == 242, f"Expected 242 VI inequalities, got {len(BEAN_INEQ)}"

# Bean-impossible lengths (precomputed: collapsed inequality OR equality-inequality contradiction)
_BEAN_IMPOSSIBLE_LENGTHS: set[int] = set()
for _L in range(1, 100):
    _impossible = False
    # Check 1: any inequality pair collapses to same position
    for _i, _j in BEAN_INEQ:
        if _i % _L == _j % _L:
            _impossible = True
            break
    # Check 2: equality-inequality contradiction (same position pair, opposite requirements)
    if not _impossible:
        _eq_pair = (BEAN_EQ[0][0] % _L, BEAN_EQ[0][1] % _L)
        for _i, _j in BEAN_INEQ:
            _ineq_pair = (_i % _L, _j % _L)
            if _ineq_pair == _eq_pair or _ineq_pair == (_eq_pair[1], _eq_pair[0]):
                _impossible = True
                break
    if _impossible:
        _BEAN_IMPOSSIBLE_LENGTHS.add(_L)

# Crib lookup dict for per-position access
CRIB_DICT: dict[int, str] = {}
for _pos, _text in CRIBS:
    for _j, _ch in enumerate(_text):
        CRIB_DICT[_pos + _j] = _ch


def _bean_passes(keyword: str) -> bool:
    """Check if keyword satisfies Bean equality + all 242 variant-independent inequalities."""
    L = len(keyword)
    if L in _BEAN_IMPOSSIBLE_LENGTHS:
        return False
    if keyword[27 % L] != keyword[65 % L]:
        return False
    for i, j in BEAN_INEQ:
        if keyword[i % L] == keyword[j % L]:
            return False
    return True


def _load_bean_wordlist() -> list[str]:
    """Load Bean-passing keywords from the extracted wordlist file."""
    wordlist_path = Path(__file__).resolve().parent.parent.parent / "results" / "bean_keywords" / "bean_keywords_wordlist.txt"
    if not wordlist_path.exists():
        logger.warning("Bean wordlist not found at %s — using hardcoded keywords only", wordlist_path)
        return []
    words = []
    with open(wordlist_path) as f:
        for line in f:
            w = line.strip()
            if w and w.isalpha():
                words.append(w)
    logger.info("Loaded %d Bean-passing keywords from %s", len(words), wordlist_path)
    return words


def _build_keyword_list() -> list[str]:
    """Build deduplicated keyword list: hardcoded + Bean wordlist, all Bean-filtered."""
    seen: set[str] = set()
    result: list[str] = []
    # Hardcoded keywords first (includes non-Bean for identity baseline)
    for kw in _HARDCODED_KEYWORDS:
        upper = kw.upper()
        if upper not in seen:
            seen.add(upper)
            result.append(upper)
    # Bean wordlist (already filtered, but double-check)
    for kw in _load_bean_wordlist():
        upper = kw.upper()
        if upper not in seen:
            seen.add(upper)
            result.append(upper)
    return result


_ALL_KEYWORDS = _build_keyword_list()

# Only use Bean-passing keywords for swap search / climbing
KEYWORDS = [kw for kw in _ALL_KEYWORDS if _bean_passes(kw)]
logger.info("Keywords: %d total, %d Bean-passing", len(_ALL_KEYWORDS), len(KEYWORDS))


# ---------------------------------------------------------------------------
# Worker functions (run in separate processes)
# ---------------------------------------------------------------------------

_QUADGRAMS: dict[str, float] | None = None
_QG_FLOOR: float = -10.0


def _load_quadgrams() -> dict[str, float]:
    global _QUADGRAMS, _QG_FLOOR
    if _QUADGRAMS is not None:
        return _QUADGRAMS
    # Use absolute path from module location to survive forked workers with different cwd
    _module_dir = Path(__file__).resolve().parent.parent.parent  # kryptosbot/kryptosbot/ -> kryptos/
    candidates = [
        _module_dir / "data" / "english_quadgrams.json",
        Path("data/english_quadgrams.json"),
        Path("english_quadgrams.json"),
    ]
    for p in candidates:
        if p.exists():
            with open(p) as f:
                _QUADGRAMS = json.load(f)
            _QG_FLOOR = min(_QUADGRAMS.values()) - 1.0
            return _QUADGRAMS
    raise FileNotFoundError(f"Cannot find english_quadgrams.json (tried: {[str(c) for c in candidates]})")


def _score_text(text: str) -> float:
    """Score candidate plaintext: quadgrams + intel jargon bonus.

    The jargon bonus ensures plaintexts containing intelligence acronyms
    (CIA, KGB, DDR, etc.) aren't rejected as noise by quadgram scoring.
    """
    qg = _load_quadgrams()
    if len(text) < 4:
        return -999.0
    qg_score = sum(qg.get(text[i:i+4], _QG_FLOOR) for i in range(len(text) - 3))
    # Intel jargon bonus (each found term adds ~15-45 points to score)
    jargon_bonus = _score_intel_jargon(text)
    return qg_score + jargon_bonus


# Intel jargon terms for scoring — must be self-contained for multiprocessing workers.
# Only 4+ char terms to avoid false positives on random text.
_INTEL_TERMS_HIGH = [  # +15 each
    "DEADDROP", "CLASSIFIED", "INTERCEPT", "DEFECTOR",
    "GCHQ", "STASI", "ASSET", "AGENT", "COVERT", "SECRET",
    "BURIED", "HIDDEN", "MARKER", "SIGNAL", "CIPHER",
]
_INTEL_TERMS_MED = [  # +10 each
    "SIGINT", "HUMINT", "COMINT", "ELINT", "OPSEC", "COMSEC",
    "INTEL", "RECON", "EXFIL", "INFIL", "CHECKPOINT", "SECTOR",
    "CURTAIN", "LANGLEY", "MOSCOW", "BERLIN", "KREMLIN",
    "KRYPTOS", "SANBORN", "PALIMPSEST", "LODESTONE", "WELTZEITUHR",
    "CIA", "KGB", "NSA", "FBI", "DCI", "NRO", "DIA", "GRU", "DDR",
    "BND", "SIS", "SVR", "FSB",
]
_INTEL_TERMS_LOW = [  # +5 each
    "NEAR", "STOP", "KNOW", "DOES", "ONLY", "THIS", "WHAT",
    "WHERE", "FIVE", "CLOCK", "POINT", "PACES", "LOCATION",
    "EXACTLY", "NORTH", "SOUTH", "EAST", "WEST",
]


def _score_intel_jargon(text: str) -> float:
    """Fast inline intel jargon scorer for worker processes."""
    text = text.upper()
    bonus = 0.0
    for term in _INTEL_TERMS_HIGH:
        if term in text:
            bonus += 15.0
    for term in _INTEL_TERMS_MED:
        if term in text:
            bonus += 10.0
    for term in _INTEL_TERMS_LOW:
        if term in text:
            bonus += 5.0
    return bonus


def _vig_decrypt(ct: str, key: str, alpha: str = AZ) -> str:
    result = []
    klen = len(key)
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        ki = alpha.index(key[i % klen])
        pi = (ci - ki) % 26
        result.append(alpha[pi])
    return "".join(result)


def _beau_decrypt(ct: str, key: str, alpha: str = AZ) -> str:
    result = []
    klen = len(key)
    for i, c in enumerate(ct):
        ci = alpha.index(c)
        ki = alpha.index(key[i % klen])
        pi = (ki - ci) % 26
        result.append(alpha[pi])
    return "".join(result)


def _apply_perm(text: str, perm: list[int]) -> str:
    """Gather convention: output[i] = text[perm[i]]."""
    return "".join(text[p] for p in perm)


def _decrypt_with_method(ct: str, cipher: str, keyword: str, alphabet: str) -> str:
    """Decrypt using specified method string components."""
    alpha = KA if alphabet == "KA" else AZ
    if cipher == "beau":
        return _beau_decrypt(ct, keyword, alpha)
    return _vig_decrypt(ct, keyword, alpha)


def _test_single_perm(perm: list[int]) -> dict:
    """Test one permutation: unscramble K4, try all keywords × ciphers × alphabets."""
    candidate_ct = _apply_perm(K4, perm)

    best_score = -9999.0
    best_pt = ""
    best_method = ""
    crib_hits = 0

    for kw in KEYWORDS:
        for cipher_name, decrypt_fn in [("vig", _vig_decrypt), ("beau", _beau_decrypt)]:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                pt = decrypt_fn(candidate_ct, kw, alpha)
                score = _score_text(pt)

                hits = 0
                for pos, crib_text in CRIBS:
                    end = pos + len(crib_text)
                    if end <= len(pt):
                        hits += sum(1 for j, c in enumerate(crib_text) if pt[pos + j] == c)

                if score > best_score or hits > crib_hits:
                    if score > best_score:
                        best_score = score
                        best_pt = pt
                        best_method = f"{cipher_name}/{kw}/{alpha_name}"
                    if hits > crib_hits:
                        crib_hits = hits

    return {
        "score": round(best_score, 2),
        "plaintext": best_pt,
        "method": best_method,
        "crib_hits": crib_hits,
    }


def _test_perm_batch(args: tuple) -> list[dict]:
    """Worker: test a batch of permutations."""
    perms_with_labels, threshold = args
    results = []
    for perm, label in perms_with_labels:
        try:
            r = _test_single_perm(perm)
            r["label"] = label
            if r["score"] > threshold or r["crib_hits"] >= 3:
                results.append(r)
        except Exception:
            pass
    return results


# ---------------------------------------------------------------------------
# Hill-climbing optimizer
# ---------------------------------------------------------------------------

def _hillclimb_worker(args: tuple) -> dict:
    """Worker for parallel hill-climbing restarts.

    Args tuple: (seed_perm, cipher, keyword, alphabet, fixed_positions,
                 iterations, restart_id)
    """
    seed_perm, cipher, keyword, alphabet, fixed_positions, iterations, restart_id = args

    alpha = KA if alphabet == "KA" else AZ
    decrypt_fn = _beau_decrypt if cipher == "beau" else _vig_decrypt

    # Positions we're allowed to swap
    fixed_set = set(fixed_positions) if fixed_positions else set()
    mutable = [i for i in range(K4_LEN) if i not in fixed_set]

    if len(mutable) < 2:
        # Nothing to optimize
        ct = _apply_perm(K4, seed_perm)
        pt = decrypt_fn(ct, keyword, alpha)
        return {
            "score": round(_score_text(pt), 2),
            "plaintext": pt,
            "perm": seed_perm,
            "iterations_used": 0,
            "restart_id": restart_id,
        }

    # Start from seed (possibly with random shuffle of mutable positions)
    perm = list(seed_perm)
    if restart_id > 0:
        # Randomize mutable positions for diversity
        vals = [perm[i] for i in mutable]
        random.shuffle(vals)
        for i, idx in enumerate(mutable):
            perm[idx] = vals[i]

    ct = _apply_perm(K4, perm)
    pt = decrypt_fn(ct, keyword, alpha)
    best_score = _score_text(pt)
    best_perm = list(perm)
    best_pt = pt

    no_improve = 0
    for it in range(iterations):
        # Pick two random mutable positions and swap
        i, j = random.sample(mutable, 2)
        perm[i], perm[j] = perm[j], perm[i]

        ct = _apply_perm(K4, perm)
        pt = decrypt_fn(ct, keyword, alpha)
        score = _score_text(pt)

        if score > best_score:
            best_score = score
            best_perm = list(perm)
            best_pt = pt
            no_improve = 0
        else:
            # Revert swap
            perm[i], perm[j] = perm[j], perm[i]
            no_improve += 1

        # Early exit if stuck
        if no_improve > min(5000, iterations // 3):
            break

    # Also check crib hits for the best
    crib_hits = 0
    for pos, crib_text in CRIBS:
        end = pos + len(crib_text)
        if end <= len(best_pt):
            crib_hits += sum(1 for k, c in enumerate(crib_text) if best_pt[pos + k] == c)

    return {
        "score": round(best_score, 2),
        "plaintext": best_pt,
        "perm": best_perm,
        "crib_hits": crib_hits,
        "method": f"{cipher}/{keyword}/{alphabet}",
        "iterations_used": it + 1 if 'it' in dir() else 0,
        "restart_id": restart_id,
    }


def run_hillclimb(
    seed_perm: list[int],
    cipher: str = "vig",
    keyword: str = "KRYPTOS",
    alphabet: str = "AZ",
    fixed_positions: list[int] | None = None,
    iterations: int = 50000,
    restarts: int = 0,
    num_workers: int = 0,
) -> dict:
    """Run hill-climbing from a seed permutation.

    Uses parallel restarts across all CPUs. Restart 0 uses the seed directly;
    restarts 1+ randomize the mutable positions for diversity.

    Returns best result dict with score, plaintext, perm, crib_hits.
    """
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    if fixed_positions is None:
        fixed_positions = []

    # Total restarts = 1 (seed) + restarts (random)
    total = max(1, restarts + 1)

    # If no restarts specified, use all workers
    if restarts == 0:
        total = num_workers

    args_list = [
        (seed_perm, cipher, keyword, alphabet, fixed_positions, iterations, rid)
        for rid in range(total)
    ]

    start = time.monotonic()
    best_result: dict | None = None

    with ProcessPoolExecutor(max_workers=num_workers) as pool:
        futures = [pool.submit(_hillclimb_worker, a) for a in args_list]
        for future in as_completed(futures):
            try:
                result = future.result()
                if best_result is None or result["score"] > best_result["score"]:
                    best_result = result
            except Exception as e:
                logger.error("Hillclimb restart failed: %s", e)

    elapsed = time.monotonic() - start

    if best_result:
        best_result["elapsed_seconds"] = round(elapsed, 2)
        best_result["total_restarts"] = total
        logger.info(
            "Hillclimb: best=%.1f, cribs=%d, %d restarts, %.1fs",
            best_result["score"], best_result.get("crib_hits", 0), total, elapsed,
        )
    else:
        best_result = {"score": -9999.0, "plaintext": "", "perm": seed_perm,
                       "elapsed_seconds": round(elapsed, 2)}

    return best_result


def _screen_combo(args: tuple) -> dict:
    """Quick-score a seed perm with one cipher/keyword/alphabet combo (no climbing)."""
    perm, cipher, keyword, alphabet = args
    alpha = KA if alphabet == "KA" else AZ
    decrypt_fn = _beau_decrypt if cipher == "beau" else _vig_decrypt
    ct = _apply_perm(K4, perm)
    pt = decrypt_fn(ct, keyword, alpha)
    score = _score_text(pt)

    crib_hits = 0
    for pos, crib_text in CRIBS:
        end = pos + len(crib_text)
        if end <= len(pt):
            crib_hits += sum(1 for k, c in enumerate(crib_text) if pt[pos + k] == c)

    return {
        "score": round(score, 2),
        "cipher": cipher,
        "keyword": keyword,
        "alphabet": alphabet,
        "crib_hits": crib_hits,
    }


def run_hillclimb_multi_keyword(
    seed_perm: list[int],
    *,
    fixed_positions: list[int] | None = None,
    iterations: int = 50000,
    top_n_combos: int = 3,
    num_workers: int = 0,
) -> dict:
    """Screen all keyword/cipher/alphabet combos, hill-climb the top N.

    1. Quick-score the seed perm against all 56 combos (fast, parallel)
    2. Hill-climb the top_n_combos most promising ones
    3. Return the single best result across all combos

    This is the key campaign optimization: a good permutation may only shine
    with the right keyword, so we test all of them.
    """
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    if fixed_positions is None:
        fixed_positions = []

    start = time.monotonic()

    # Phase 1: Screen all 56 combos
    combos = []
    for kw in KEYWORDS:
        for cipher in ("vig", "beau"):
            for alpha in ("AZ", "KA"):
                combos.append((list(seed_perm), cipher, kw, alpha))

    screen_results = []
    with ProcessPoolExecutor(max_workers=num_workers) as pool:
        screen_results = list(pool.map(_screen_combo, combos))

    screen_results.sort(key=lambda r: r["score"], reverse=True)

    # Phase 2: Hill-climb top N combos
    best_result: dict | None = None
    for combo_result in screen_results[:top_n_combos]:
        hc = run_hillclimb(
            seed_perm=seed_perm,
            cipher=combo_result["cipher"],
            keyword=combo_result["keyword"],
            alphabet=combo_result["alphabet"],
            fixed_positions=fixed_positions,
            iterations=iterations,
            num_workers=num_workers,
        )
        if best_result is None or hc["score"] > best_result["score"]:
            best_result = hc

    elapsed = time.monotonic() - start

    if best_result:
        best_result["elapsed_seconds"] = round(elapsed, 2)
        best_result["screen_top3"] = [
            f"{r['cipher']}/{r['keyword']}/{r['alphabet']}={r['score']:.1f}"
            for r in screen_results[:5]
        ]
        logger.info(
            "Multi-keyword hillclimb: best=%.1f, method=%s, %.1fs",
            best_result["score"],
            best_result.get("method", "?"),
            elapsed,
        )
    else:
        best_result = {"score": -9999.0, "plaintext": "", "perm": seed_perm,
                       "elapsed_seconds": round(elapsed, 2)}

    return best_result


# ---------------------------------------------------------------------------
# Reading order generators
# ---------------------------------------------------------------------------

def _grid_positions(width: int, height: int, n: int) -> list[tuple[int, int]]:
    """Generate grid positions for K4 (last n characters in a width×height grid)."""
    total = width * height
    start = total - n
    positions = []
    for idx in range(start, total):
        r, c = divmod(idx, width)
        positions.append((r, c))
    return positions


def generate_reading_order_perms(order_type: str, grid_width: int = 31, grid_height: int = 28) -> list[tuple[list[int], str]]:
    """Generate permutations from different grid reading orders."""
    k4_positions = _grid_positions(grid_width, grid_height, K4_LEN)
    pos_to_k4idx = {pos: i for i, pos in enumerate(k4_positions)}
    results = []

    if order_type == "row_major":
        perm = list(range(K4_LEN))
        results.append((perm, "row_major"))

    elif order_type == "col_major":
        sorted_by_col = sorted(k4_positions, key=lambda p: (p[1], p[0]))
        perm = [pos_to_k4idx[p] for p in sorted_by_col]
        results.append((perm, "col_major"))

    elif order_type == "reverse":
        perm = list(range(K4_LEN - 1, -1, -1))
        results.append((perm, "reverse"))

    elif order_type == "boustrophedon":
        rows: dict[int, list[tuple[int, int]]] = {}
        for pos in k4_positions:
            rows.setdefault(pos[0], []).append(pos)
        ordered = []
        for i, row_num in enumerate(sorted(rows.keys())):
            row_positions = sorted(rows[row_num], key=lambda p: p[1])
            if i % 2 == 1:
                row_positions.reverse()
            ordered.extend(row_positions)
        perm = [pos_to_k4idx[p] for p in ordered]
        results.append((perm, "boustrophedon"))

    elif order_type == "spiral_cw":
        all_rows = sorted(set(p[0] for p in k4_positions))
        all_cols = sorted(set(p[1] for p in k4_positions))
        if all_rows and all_cols:
            top, bottom = all_rows[0], all_rows[-1]
            left, right = all_cols[0], all_cols[-1]
            ordered = []
            visited = set()
            while top <= bottom and left <= right:
                for c in range(left, right + 1):
                    pos = (top, c)
                    if pos in pos_to_k4idx and pos not in visited:
                        ordered.append(pos); visited.add(pos)
                top += 1
                for r in range(top, bottom + 1):
                    pos = (r, right)
                    if pos in pos_to_k4idx and pos not in visited:
                        ordered.append(pos); visited.add(pos)
                right -= 1
                for c in range(right, left - 1, -1):
                    pos = (bottom, c)
                    if pos in pos_to_k4idx and pos not in visited:
                        ordered.append(pos); visited.add(pos)
                bottom -= 1
                for r in range(bottom, top - 1, -1):
                    pos = (r, left)
                    if pos in pos_to_k4idx and pos not in visited:
                        ordered.append(pos); visited.add(pos)
                left += 1
            perm = [pos_to_k4idx[p] for p in ordered if p in pos_to_k4idx]
            if len(perm) == K4_LEN:
                results.append((perm, "spiral_cw"))

    elif order_type == "diagonal":
        diags: dict[int, list[tuple[int, int]]] = {}
        for pos in k4_positions:
            d = pos[0] + pos[1]
            diags.setdefault(d, []).append(pos)
        ordered = []
        for d in sorted(diags.keys()):
            ordered.extend(sorted(diags[d], key=lambda p: p[0]))
        perm = [pos_to_k4idx[p] for p in ordered]
        results.append((perm, "diagonal"))

    elif order_type == "step_n":
        for step in range(2, K4_LEN):
            if gcd(step, K4_LEN) == 1:
                perm = [(i * step) % K4_LEN for i in range(K4_LEN)]
                results.append((perm, f"step_{step}"))

    elif order_type == "grille_index":
        grille = "HJLVKDJQZKIVPCMWSAFOPCKBDLHIFXRYVFIJMXEIOMQFJNXZKILKRDIYSCLMQVZACEIMVSEFHLQKRGILVHNQXWTCDKIKJUFQRXCD"
        chars_with_idx = [(c, i) for i, c in enumerate(grille[:K4_LEN])]
        sorted_chars = sorted(chars_with_idx, key=lambda x: (x[0], x[1]))
        rank_perm = [0] * K4_LEN
        for rank, (_, orig_idx) in enumerate(sorted_chars):
            rank_perm[orig_idx] = rank
        results.append((rank_perm, "grille_rank"))
        inv_perm = [0] * K4_LEN
        for i, p in enumerate(rank_perm):
            inv_perm[p] = i
        results.append((inv_perm, "grille_rank_inv"))
        ka_perm = [KA.index(c) % K4_LEN for c in grille[:K4_LEN]]
        if len(set(ka_perm)) == K4_LEN:
            results.append((ka_perm, "grille_ka_index"))

    return results


# ---------------------------------------------------------------------------
# Sandboxed generator execution
# ---------------------------------------------------------------------------

_SANDBOX_WRAPPER = '''
import json
import sys

# Restricted builtins — block dangerous operations
_BLOCKED = set(["__import__", "exec", "eval", "compile", "open", "input",
                "breakpoint", "exit", "quit"])

K4 = "{k4}"
K4_LEN = {k4_len}

{user_code}

if __name__ == "__main__":
    try:
        results = generate(K4)
        valid = []
        for item in results[:100000]:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                perm, label = item
            elif isinstance(item, list):
                perm, label = item, "unnamed"
            else:
                continue
            if (isinstance(perm, (list, tuple)) and len(perm) == K4_LEN
                    and sorted(perm) == list(range(K4_LEN))):
                valid.append([list(perm), str(label)])
        json.dump(valid, sys.stdout)
    except Exception as e:
        json.dump({{"error": str(e)}}, sys.stdout)
'''


def _execute_generator_sandboxed(
    code: str,
    name: str,
    timeout: float = 30.0,
) -> list[tuple[list[int], str]]:
    """Execute generator code in a subprocess sandbox.

    The generated code runs in a separate Python process with:
    - Timeout enforcement (default 30s)
    - No network access (code doesn't import networking)
    - Output size cap (10MB)
    - Restricted to stdlib only
    """
    wrapper = _SANDBOX_WRAPPER.format(
        k4=K4,
        k4_len=K4_LEN,
        user_code=code,
    )

    perms = []
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False, prefix=f'gen_{name}_'
        ) as f:
            f.write(wrapper)
            tmp_path = f.name

        result = subprocess.run(
            [sys.executable, tmp_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=os.getcwd(),
        )

        if result.returncode != 0:
            stderr = result.stderr[:500] if result.stderr else "no stderr"
            logger.error("Generator %s failed (rc=%d): %s", name, result.returncode, stderr)
        else:
            stdout = result.stdout[:10_000_000]  # 10MB cap
            data = json.loads(stdout)
            if isinstance(data, dict) and "error" in data:
                logger.error("Generator %s error: %s", name, data["error"])
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, list) and len(item) == 2:
                        perm, label = item
                        if isinstance(perm, list) and len(perm) == K4_LEN:
                            perms.append((perm, str(label)))

    except subprocess.TimeoutExpired:
        logger.error("Generator %s timed out after %.0fs", name, timeout)
    except (json.JSONDecodeError, Exception) as e:
        logger.error("Generator %s parse error: %s", name, e)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    logger.info("Generator %s produced %d valid permutations", name, len(perms))
    return perms


# ---------------------------------------------------------------------------
# Plaintext generator sandbox (non-periodic substitution, autokey, etc.)
# ---------------------------------------------------------------------------

_PLAINTEXT_SANDBOX_WRAPPER = '''
import json
import sys
import math
import itertools
import collections
import string
import re
import random

K4 = "{k4}"
K4_LEN = {k4_len}
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Known cribs for self-scoring
CRIBS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
CRIB_DICT = {{}}
for _pos, _text in CRIBS:
    for _j, _ch in enumerate(_text):
        CRIB_DICT[_pos + _j] = _ch

def crib_hits(pt):
    """Count how many crib positions match."""
    hits = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt) and pt[pos] == ch:
            hits += 1
    return hits

{user_code}

if __name__ == "__main__":
    try:
        results = generate(K4)
        valid = []
        for item in results[:50000]:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                pt = str(item[0])
                label = str(item[1])
            else:
                continue
            if len(pt) >= 10 and pt.isalpha():
                valid.append([pt, label])
        json.dump(valid, sys.stdout)
    except Exception as e:
        json.dump({{"error": str(e)}}, sys.stdout)
'''


def _execute_plaintext_generator_sandboxed(
    code: str,
    name: str,
    timeout: float = 60.0,
) -> list[tuple[str, str]]:
    """Execute a plaintext generator in a subprocess sandbox.

    Unlike the permutation generator, this returns (plaintext, label) tuples.
    The generator does its own transposition AND substitution (autokey, running
    key, Quagmire, etc.) and returns candidate plaintexts directly.

    Longer timeout (60s) since these do more work per hypothesis.
    """
    wrapper = _PLAINTEXT_SANDBOX_WRAPPER.format(
        k4=K4,
        k4_len=K4_LEN,
        user_code=code,
    )

    candidates: list[tuple[str, str]] = []
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False, prefix=f'ptgen_{name}_'
        ) as f:
            f.write(wrapper)
            tmp_path = f.name

        result = subprocess.run(
            [sys.executable, tmp_path],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=os.getcwd(),
        )

        if result.returncode != 0:
            stderr = result.stderr[:500] if result.stderr else "no stderr"
            logger.error("PT generator %s failed (rc=%d): %s", name, result.returncode, stderr)
        else:
            stdout = result.stdout[:10_000_000]  # 10MB cap
            data = json.loads(stdout)
            if isinstance(data, dict) and "error" in data:
                logger.error("PT generator %s error: %s", name, data["error"])
            elif isinstance(data, list):
                for item in data:
                    if isinstance(item, list) and len(item) >= 2:
                        pt, label = str(item[0]), str(item[1])
                        if len(pt) >= 10 and pt.isalpha():
                            candidates.append((pt, label))

    except subprocess.TimeoutExpired:
        logger.error("PT generator %s timed out after %.0fs", name, timeout)
    except (json.JSONDecodeError, Exception) as e:
        logger.error("PT generator %s parse error: %s", name, e)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    logger.info("PT generator %s produced %d candidates", name, len(candidates))
    return candidates


def _is_crib_constructed(pt: str) -> bool:
    """Detect plaintexts that trivially place known cribs without real decryption.

    Returns True (= artifact) when non-crib positions show degenerate patterns:
    uniform fill (all A's/X's), very low unique char count, or extreme quadgram
    garbage outside the crib regions.
    """
    if len(pt) < 97:
        return False  # length guard handled separately

    # Collect non-crib characters
    crib_positions = set(CRIB_DICT.keys())
    non_crib = [pt[i] for i in range(len(pt)) if i not in crib_positions]
    if not non_crib:
        return True

    # Check 1: uniform or near-uniform fill (e.g., all A's, all X's)
    from collections import Counter
    counts = Counter(non_crib)
    unique = len(counts)
    if unique <= 3:
        return True

    # Check 2: dominant single character (>60% of non-crib positions)
    most_common_count = counts.most_common(1)[0][1]
    if most_common_count / len(non_crib) > 0.60:
        return True

    # Check 3: non-crib quadgram quality is extreme garbage
    non_crib_str = ''.join(non_crib)
    if len(non_crib_str) >= 4:
        qg = _load_quadgrams()
        nc_score = sum(qg.get(non_crib_str[i:i+4], _QG_FLOOR)
                       for i in range(len(non_crib_str) - 3))
        nc_per_char = nc_score / len(non_crib_str)
        # Random English ≈ -4.5/char; pure garbage < -6.0/char
        if nc_per_char < -6.0:
            return True

    return False


def _score_plaintext_candidates(
    candidates: list[tuple[str, str]],
) -> list[dict]:
    """Score plaintext candidates: crib hits + quadgram quality + Bean check.

    Includes a crib-construction guard that detects and penalizes plaintexts
    where Opus trivially places known crib text at known positions while
    filling non-crib positions with garbage.
    """
    results = []
    for pt, label in candidates:
        hits = 0
        for pos, ch in CRIB_DICT.items():
            if pos < len(pt) and pt[pos] == ch:
                hits += 1

        score = _score_text(pt)

        # --- Crib-construction guard ---
        constructed = False

        # Guard 1: Wrong length — crib positions (21-33, 63-73) only meaningful
        # on 97-char text. Shorter texts get coincidental matches.
        if len(pt) != 97 and hits > 0:
            hits = 0
            constructed = True

        # Guard 2: Trivially constructed — cribs placed by construction, not
        # derived from ciphertext. Zero out crib hits.
        if hits >= 20 and _is_crib_constructed(pt):
            hits = 0
            constructed = True

        results.append({
            "score": round(score, 2),
            "plaintext": pt,
            "method": label,
            "crib_hits": hits,
            "label": label,
            "constructed": constructed,
        })

    return results


# ---------------------------------------------------------------------------
# Hypothesis execution
# ---------------------------------------------------------------------------

@dataclass
class HypothesisResult:
    """Result from testing a single hypothesis."""
    name: str
    description: str
    candidates_tested: int
    best_score: float
    best_plaintext: str
    best_method: str
    best_crib_hits: int
    elapsed_seconds: float
    top_results: list[dict] = field(default_factory=list)
    best_perm: list[int] | None = None


def test_hypothesis(
    hypothesis: dict,
    num_workers: int = 0,
    score_threshold: float = -450.0,
) -> HypothesisResult:
    """Test a single hypothesis, returning structured results."""
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    name = hypothesis.get("name", "unknown")
    desc = hypothesis.get("description", "")
    h_type = hypothesis.get("type", "")
    data = hypothesis.get("data", {})

    start = time.monotonic()
    logger.info("Testing hypothesis: %s (%s)", name, h_type)

    # --- Hill-climbing type ---
    if h_type == "hillclimb":
        return _test_hillclimb(name, desc, data, num_workers, start)

    # --- Plaintext generator type (non-periodic substitution) ---
    if h_type == "plaintext_generator":
        code = data.get("python_code", "")
        if not code:
            logger.warning("No python_code for plaintext_generator %s", name)
            return HypothesisResult(
                name=name, description=desc,
                candidates_tested=0, best_score=-9999.0,
                best_plaintext="", best_method="", best_crib_hits=0,
                elapsed_seconds=0.0,
            )

        candidates = _execute_plaintext_generator_sandboxed(code, name)
        if not candidates:
            return HypothesisResult(
                name=name, description=desc,
                candidates_tested=0, best_score=-9999.0,
                best_plaintext="", best_method="", best_crib_hits=0,
                elapsed_seconds=time.monotonic() - start,
            )

        all_results = _score_plaintext_candidates(candidates)
        elapsed = time.monotonic() - start

        best = max(all_results, key=lambda r: r["crib_hits"] * 1000 + r["score"])
        top = sorted(all_results, key=lambda r: r["crib_hits"] * 1000 + r["score"], reverse=True)[:20]

        return HypothesisResult(
            name=name,
            description=desc,
            candidates_tested=len(candidates),
            best_score=best["score"],
            best_plaintext=best.get("plaintext", ""),
            best_method=best.get("method", ""),
            best_crib_hits=best.get("crib_hits", 0),
            elapsed_seconds=round(elapsed, 2),
            top_results=top,
        )

    # --- Permutation generation types ---
    perms: list[tuple[list[int], str]] = []

    if h_type == "permutation":
        perm = data.get("perm", [])
        if len(perm) == K4_LEN and sorted(perm) == list(range(K4_LEN)):
            perms.append((perm, name))
        else:
            logger.warning("Invalid permutation for %s: length=%d", name, len(perm))

    elif h_type == "reading_order":
        order = data.get("order", "")
        gw = data.get("grid_width", 31)
        gh = data.get("grid_height", 28)
        perms = generate_reading_order_perms(order, gw, gh)

    elif h_type == "generator":
        code = data.get("python_code", "")
        if code:
            perms = _execute_generator_sandboxed(code, name)

    elif h_type == "partial_swap":
        # Apply specific position swaps to K4 CT, build the perm
        swap_positions = data.get("swap_positions", [])
        perm = list(range(K4_LEN))
        for pair in swap_positions:
            if isinstance(pair, (list, tuple)) and len(pair) == 2:
                a, b = int(pair[0]), int(pair[1])
                if 0 <= a < K4_LEN and 0 <= b < K4_LEN:
                    perm[a], perm[b] = perm[b], perm[a]
        if sorted(perm) == list(range(K4_LEN)):
            perms.append((perm, name))
        else:
            logger.warning("Invalid partial_swap for %s", name)

    elif h_type == "reading_orders_all":
        for order_type in ["row_major", "col_major", "reverse", "boustrophedon",
                           "spiral_cw", "diagonal", "step_n", "grille_index"]:
            perms.extend(generate_reading_order_perms(order_type))

    if not perms:
        logger.warning("No valid permutations for hypothesis: %s", name)
        return HypothesisResult(
            name=name, description=desc,
            candidates_tested=0, best_score=-9999.0,
            best_plaintext="", best_method="", best_crib_hits=0,
            elapsed_seconds=0.0,
        )

    # Test permutations in parallel
    all_results = _test_perms_parallel(perms, num_workers, score_threshold)

    elapsed = time.monotonic() - start

    best = max(all_results, key=lambda r: r["score"]) if all_results else {
        "score": -9999.0, "plaintext": "", "method": "", "crib_hits": 0, "label": ""
    }
    top = sorted(all_results, key=lambda r: r["score"], reverse=True)[:20]

    # Find the actual perm for the best result
    best_perm = None
    if best.get("label"):
        for p, lbl in perms:
            if lbl == best["label"]:
                best_perm = p
                break

    result = HypothesisResult(
        name=name,
        description=desc,
        candidates_tested=len(perms),
        best_score=best["score"],
        best_plaintext=best.get("plaintext", ""),
        best_method=best.get("method", ""),
        best_crib_hits=best.get("crib_hits", 0),
        elapsed_seconds=round(elapsed, 2),
        top_results=top,
        best_perm=best_perm,
    )

    logger.info(
        "  %s: %d tested, best=%.1f, cribs=%d, %.1fs",
        name, len(perms), result.best_score, result.best_crib_hits, elapsed,
    )
    return result


def _test_hillclimb(
    name: str, desc: str, data: dict, num_workers: int, start: float,
) -> HypothesisResult:
    """Handle hillclimb-type hypothesis."""
    seed_perm = data.get("seed_perm", [])
    if len(seed_perm) != K4_LEN or sorted(seed_perm) != list(range(K4_LEN)):
        logger.warning("Invalid seed permutation for hillclimb %s", name)
        return HypothesisResult(
            name=name, description=desc,
            candidates_tested=0, best_score=-9999.0,
            best_plaintext="", best_method="", best_crib_hits=0,
            elapsed_seconds=0.0,
        )

    cipher = data.get("cipher", "vig")
    keyword = data.get("keyword", "KRYPTOS")
    alphabet = data.get("alphabet", "AZ")
    iterations = data.get("iterations", 50000)
    fixed = data.get("fixed_positions", [])
    restarts = data.get("restarts", num_workers)

    hc_result = run_hillclimb(
        seed_perm=seed_perm,
        cipher=cipher,
        keyword=keyword,
        alphabet=alphabet,
        fixed_positions=fixed,
        iterations=iterations,
        restarts=restarts,
        num_workers=num_workers,
    )

    elapsed = time.monotonic() - start
    return HypothesisResult(
        name=name,
        description=desc,
        candidates_tested=hc_result.get("total_restarts", 1),
        best_score=hc_result.get("score", -9999.0),
        best_plaintext=hc_result.get("plaintext", ""),
        best_method=hc_result.get("method", f"{cipher}/{keyword}/{alphabet}"),
        best_crib_hits=hc_result.get("crib_hits", 0),
        elapsed_seconds=round(elapsed, 2),
        top_results=[hc_result],
        best_perm=hc_result.get("perm"),
    )


def _test_perms_parallel(
    perms: list[tuple[list[int], str]],
    num_workers: int,
    threshold: float,
) -> list[dict]:
    """Test permutations across multiple processes."""
    if len(perms) <= 100:
        results = []
        for perm, label in perms:
            r = _test_single_perm(perm)
            r["label"] = label
            if r["score"] > threshold or r["crib_hits"] >= 3:
                results.append(r)
        return results

    batch_size = max(50, len(perms) // (num_workers * 4))
    batches = []
    for i in range(0, len(perms), batch_size):
        batch = perms[i:i + batch_size]
        batches.append((batch, threshold))

    results = []
    with ProcessPoolExecutor(max_workers=num_workers) as pool:
        futures = {pool.submit(_test_perm_batch, batch): i for i, batch in enumerate(batches)}
        for future in as_completed(futures):
            try:
                batch_results = future.result()
                results.extend(batch_results)
            except Exception as e:
                logger.error("Batch failed: %s", e)

    return results


# ---------------------------------------------------------------------------
# Batch testing (main entry point)
# ---------------------------------------------------------------------------

def test_all_hypotheses(
    hypotheses: list[dict],
    num_workers: int = 0,
    score_threshold: float = -450.0,
) -> list[HypothesisResult]:
    """Test all hypotheses and return results sorted by best score."""
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    results = []
    for h in hypotheses:
        try:
            r = test_hypothesis(h, num_workers=num_workers, score_threshold=score_threshold)
            results.append(r)
        except Exception as e:
            logger.error("Hypothesis %s failed: %s", h.get("name", "?"), e)
            results.append(HypothesisResult(
                name=h.get("name", "unknown"),
                description=str(e),
                candidates_tested=0,
                best_score=-9999.0,
                best_plaintext="",
                best_method="",
                best_crib_hits=0,
                elapsed_seconds=0.0,
            ))

    results.sort(key=lambda r: r.best_score, reverse=True)
    return results


# ---------------------------------------------------------------------------
# Bean-guided partial transposition search
# ---------------------------------------------------------------------------

def _recover_key_at_cribs(ct_str: str, cipher: str = "vig") -> dict[int, int]:
    """Recover keystream values at crib positions from a candidate CT string."""
    keys = {}
    for pos, pt_ch in CRIB_DICT.items():
        if pos < len(ct_str):
            ci = AZ.index(ct_str[pos])
            pi = AZ.index(pt_ch)
            if cipher == "vig":
                keys[pos] = (ci - pi) % 26
            else:  # beaufort
                keys[pos] = (ci + pi) % 26
    return keys


def _check_bean_keys(keys: dict[int, int]) -> tuple[int, int, list[tuple[int, int]]]:
    """Check Bean constraints on a keystream dict.

    Returns (eq_pass, ineq_pass, ineq_failure_pairs).
    """
    eq_pass = 0
    for a, b in BEAN_EQ:
        if a in keys and b in keys and keys[a] == keys[b]:
            eq_pass += 1

    ineq_pass = 0
    ineq_fails = []
    for a, b in BEAN_INEQ:
        if a in keys and b in keys:
            if keys[a] != keys[b]:
                ineq_pass += 1
            else:
                ineq_fails.append((a, b))

    return eq_pass, ineq_pass, ineq_fails


def _minor_differences(ct_str: str) -> tuple[float, int]:
    """Compute Bean's 'minor differences' statistic.

    For crib positions where PT is in {K,R,Y,P,T,O,S}, measure the
    shortest distance between PT and CT letters in the standard alphabet.
    Returns (mean_distance, count).
    """
    kryptos_set = set("KRYPTOS")
    diffs = []
    for pos, pt_ch in CRIB_DICT.items():
        if pt_ch in kryptos_set and pos < len(ct_str):
            d = abs(AZ.index(ct_str[pos]) - AZ.index(pt_ch))
            diffs.append(min(d, 26 - d))
    if not diffs:
        return 13.0, 0
    return sum(diffs) / len(diffs), len(diffs)


def run_identity_and_bean_diagnostic() -> dict:
    """Test identity permutation and run Bean diagnostics for all combos.

    Returns comprehensive diagnostic: scores, crib hits, Bean constraint
    satisfaction, minor differences — for every keyword/cipher/alphabet.
    """
    results = []

    for kw in _ALL_KEYWORDS:
        for cipher, decrypt_fn in [("vig", _vig_decrypt), ("beau", _beau_decrypt)]:
            for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
                pt = decrypt_fn(K4, kw, alpha)
                score = _score_text(pt)

                hits = 0
                for pos, crib_text in CRIBS:
                    end = pos + len(crib_text)
                    if end <= len(pt):
                        hits += sum(1 for j, c in enumerate(crib_text) if pt[pos + j] == c)

                keys = _recover_key_at_cribs(K4, cipher)
                eq_pass, ineq_pass, ineq_fails = _check_bean_keys(keys)
                md_mean, md_count = _minor_differences(K4)

                results.append({
                    "method": f"{cipher}/{kw}/{alpha_name}",
                    "score": round(score, 2),
                    "crib_hits": hits,
                    "bean_eq": eq_pass,
                    "bean_ineq_pass": ineq_pass,
                    "bean_ineq_fail": len(ineq_fails),
                    "bean_fail_positions": ineq_fails,
                    "minor_diff_mean": round(md_mean, 2),
                    "keyword_len": len(kw),
                    "keyword_bean_pass": _bean_passes(kw),
                })

    results.sort(key=lambda r: r["score"], reverse=True)
    return {
        "total_combos": len(results),
        "top_by_score": results[:20],
        "top_by_cribs": sorted(results, key=lambda r: r["crib_hits"], reverse=True)[:10],
        "minor_diff_mean": results[0]["minor_diff_mean"] if results else -1,
    }


def _exhaustive_single_swap_worker(args: tuple) -> list[dict]:
    """Test all C(97,2)=4656 single CT-position swaps for one combo."""
    cipher, keyword, alphabet = args
    alpha = KA if alphabet == "KA" else AZ
    decrypt_fn = _beau_decrypt if cipher == "beau" else _vig_decrypt

    base_pt = decrypt_fn(K4, keyword, alpha)
    base_score = _score_text(base_pt)

    results = []
    ct_chars = list(K4)

    for i in range(K4_LEN - 1):
        for j in range(i + 1, K4_LEN):
            ct_chars[i], ct_chars[j] = ct_chars[j], ct_chars[i]
            swapped_ct = "".join(ct_chars)
            pt = decrypt_fn(swapped_ct, keyword, alpha)
            score = _score_text(pt)
            ct_chars[i], ct_chars[j] = ct_chars[j], ct_chars[i]  # revert

            if score > base_score + 3.0:
                hits = 0
                for pos, crib_text in CRIBS:
                    end = pos + len(crib_text)
                    if end <= len(pt):
                        hits += sum(1 for k, c in enumerate(crib_text) if pt[pos + k] == c)

                results.append({
                    "score": round(score, 2),
                    "plaintext": pt,
                    "method": f"swap({i},{j})/{cipher}/{keyword}/{alphabet}",
                    "crib_hits": hits,
                    "swap": [i, j],
                    "improvement": round(score - base_score, 2),
                })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:100]


def run_exhaustive_single_swap(num_workers: int = 0) -> dict:
    """Exhaustive single-swap search: all C(97,2)=4656 CT swaps × all combos.

    Tests the hypothesis that K4 is mostly direct substitution with 1 pair
    of positions transposed. Total: ~4656 × KEYWORDS × 2 × 2 candidates.
    """
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    start = time.monotonic()

    args_list = []
    for kw in KEYWORDS:
        for cipher in ("vig", "beau"):
            for alpha in ("AZ", "KA"):
                args_list.append((cipher, kw, alpha))

    all_results: list[dict] = []

    with ProcessPoolExecutor(max_workers=num_workers) as pool:
        futures = [pool.submit(_exhaustive_single_swap_worker, a) for a in args_list]
        for future in as_completed(futures):
            try:
                all_results.extend(future.result())
            except Exception as e:
                logger.error("Swap search failed: %s", e)

    elapsed = time.monotonic() - start
    all_results.sort(key=lambda r: r["score"], reverse=True)

    # Identify hot-swap positions (positions that appear in top results)
    position_freq: dict[int, int] = {}
    for r in all_results[:100]:
        for p in r["swap"]:
            position_freq[p] = position_freq.get(p, 0) + 1
    hot_positions = sorted(position_freq.items(), key=lambda x: x[1], reverse=True)[:20]

    return {
        "elapsed_seconds": round(elapsed, 2),
        "total_combos": len(args_list),
        "swaps_per_combo": K4_LEN * (K4_LEN - 1) // 2,
        "improvements_found": len(all_results),
        "top_results": all_results[:50],
        "best": all_results[0] if all_results else None,
        "hot_positions": hot_positions,
    }


def _multi_swap_from_identity_worker(args: tuple) -> dict:
    """Hill-climb from identity permutation with swap-count tracking."""
    cipher, keyword, alphabet, iterations, restart_id = args
    alpha = KA if alphabet == "KA" else AZ
    decrypt_fn = _beau_decrypt if cipher == "beau" else _vig_decrypt

    perm = list(range(K4_LEN))
    # For restart > 0: apply a small random perturbation (2-8 swaps)
    if restart_id > 0:
        n_perturb = random.randint(2, 8)
        for _ in range(n_perturb):
            a, b = random.sample(range(K4_LEN), 2)
            perm[a], perm[b] = perm[b], perm[a]

    ct = _apply_perm(K4, perm)
    pt = decrypt_fn(ct, keyword, alpha)
    best_score = _score_text(pt)
    best_perm = list(perm)
    best_pt = pt
    swaps_made = 0

    no_improve = 0
    for it in range(iterations):
        i, j = random.sample(range(K4_LEN), 2)
        perm[i], perm[j] = perm[j], perm[i]

        ct = _apply_perm(K4, perm)
        pt = decrypt_fn(ct, keyword, alpha)
        score = _score_text(pt)

        if score > best_score:
            best_score = score
            best_perm = list(perm)
            best_pt = pt
            no_improve = 0
            swaps_made += 1
        else:
            perm[i], perm[j] = perm[j], perm[i]
            no_improve += 1

        if no_improve > min(10000, iterations // 3):
            break

    # Count how many positions differ from identity
    displaced = sum(1 for i in range(K4_LEN) if best_perm[i] != i)

    crib_hits = 0
    for pos, crib_text in CRIBS:
        end = pos + len(crib_text)
        if end <= len(best_pt):
            crib_hits += sum(1 for k, c in enumerate(crib_text) if best_pt[pos + k] == c)

    # Bean check on the resulting CT
    result_ct = _apply_perm(K4, best_perm)
    keys = _recover_key_at_cribs(result_ct, cipher)
    eq_pass, ineq_pass, _ = _check_bean_keys(keys)

    return {
        "score": round(best_score, 2),
        "plaintext": best_pt,
        "perm": best_perm,
        "crib_hits": crib_hits,
        "method": f"near_id/{cipher}/{keyword}/{alphabet}",
        "displaced_positions": displaced,
        "swaps_accepted": swaps_made,
        "bean_eq": eq_pass,
        "bean_ineq_pass": ineq_pass,
        "restart_id": restart_id,
    }


def run_near_identity_hillclimb(
    *,
    iterations: int = 100000,
    num_workers: int = 0,
    top_n_combos: int = 5,
) -> dict:
    """Hill-climb from identity permutation across best keyword combos.

    Starts from no-transposition (Bean's hypothesis), lets optimizer find
    the minimal number of swaps needed to improve the decryption.
    Tracks displaced_positions to measure how "far" from identity the
    best solution is.
    """
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    start = time.monotonic()

    # Screen all combos with identity first
    identity = list(range(K4_LEN))
    screen_args = [(identity, cipher, kw, alpha)
                   for kw in KEYWORDS
                   for cipher in ("vig", "beau")
                   for alpha in ("AZ", "KA")]
    screen_results = []
    with ProcessPoolExecutor(max_workers=num_workers) as pool:
        screen_results = list(pool.map(_screen_combo, screen_args))
    screen_results.sort(key=lambda r: r["score"], reverse=True)

    # Hill-climb top N combos from identity
    best_result: dict | None = None
    for combo in screen_results[:top_n_combos]:
        # Multiple restarts per combo
        hc_args = [
            (combo["cipher"], combo["keyword"], combo["alphabet"],
             iterations, rid)
            for rid in range(num_workers)
        ]

        with ProcessPoolExecutor(max_workers=num_workers) as pool:
            futures = [pool.submit(_multi_swap_from_identity_worker, a) for a in hc_args]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if best_result is None or result["score"] > best_result["score"]:
                        best_result = result
                except Exception as e:
                    logger.error("Near-identity climb failed: %s", e)

    elapsed = time.monotonic() - start

    if best_result:
        best_result["elapsed_seconds"] = round(elapsed, 2)
        best_result["identity_top5"] = [
            f"{r['cipher']}/{r['keyword']}/{r['alphabet']}={r['score']:.1f}"
            for r in screen_results[:5]
        ]
    else:
        best_result = {"score": -9999.0, "elapsed_seconds": round(elapsed, 2)}

    return best_result


def _focused_double_swap_worker(args: tuple) -> list[dict]:
    """Try all 2-swap combos from a set of hot positions."""
    cipher, keyword, alphabet, hot_pos_list = args
    alpha = KA if alphabet == "KA" else AZ
    decrypt_fn = _beau_decrypt if cipher == "beau" else _vig_decrypt

    base_pt = decrypt_fn(K4, keyword, alpha)
    base_score = _score_text(base_pt)

    results = []
    ct_chars = list(K4)
    n = len(hot_pos_list)

    # Try all pairs of swaps from the hot positions
    for s1 in range(n - 1):
        for s2 in range(s1 + 1, n):
            i1, j1 = hot_pos_list[s1]
            i2, j2 = hot_pos_list[s2]
            # Skip if positions overlap
            if len({i1, j1, i2, j2}) < 4:
                continue

            ct_chars[i1], ct_chars[j1] = ct_chars[j1], ct_chars[i1]
            ct_chars[i2], ct_chars[j2] = ct_chars[j2], ct_chars[i2]
            swapped_ct = "".join(ct_chars)
            pt = decrypt_fn(swapped_ct, keyword, alpha)
            score = _score_text(pt)
            ct_chars[i2], ct_chars[j2] = ct_chars[j2], ct_chars[i2]  # revert
            ct_chars[i1], ct_chars[j1] = ct_chars[j1], ct_chars[i1]  # revert

            if score > base_score + 5.0:
                hits = 0
                for pos, crib_text in CRIBS:
                    end = pos + len(crib_text)
                    if end <= len(pt):
                        hits += sum(1 for k, c in enumerate(crib_text) if pt[pos + k] == c)

                results.append({
                    "score": round(score, 2),
                    "plaintext": pt,
                    "method": f"dswap({i1},{j1})+({i2},{j2})/{cipher}/{keyword}/{alphabet}",
                    "crib_hits": hits,
                    "swaps": [[i1, j1], [i2, j2]],
                    "improvement": round(score - base_score, 2),
                })

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:50]


def run_focused_double_swap(
    hot_swap_pairs: list[list[int]],
    num_workers: int = 0,
) -> dict:
    """Try all 2-swap combos from a list of promising swap pairs.

    Takes the hot swap pairs from run_exhaustive_single_swap() and tests
    all combinations of applying 2 of them simultaneously.
    """
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    start = time.monotonic()

    args_list = []
    for kw in KEYWORDS:
        for cipher in ("vig", "beau"):
            for alpha in ("AZ", "KA"):
                args_list.append((cipher, kw, alpha, hot_swap_pairs))

    all_results: list[dict] = []
    with ProcessPoolExecutor(max_workers=num_workers) as pool:
        futures = [pool.submit(_focused_double_swap_worker, a) for a in args_list]
        for future in as_completed(futures):
            try:
                all_results.extend(future.result())
            except Exception as e:
                logger.error("Double swap failed: %s", e)

    elapsed = time.monotonic() - start
    all_results.sort(key=lambda r: r["score"], reverse=True)

    return {
        "elapsed_seconds": round(elapsed, 2),
        "pairs_tested": len(hot_swap_pairs),
        "improvements_found": len(all_results),
        "top_results": all_results[:30],
        "best": all_results[0] if all_results else None,
    }


# ---------------------------------------------------------------------------
# Priority keyword deep search
# ---------------------------------------------------------------------------

def _priority_keyword_deep_worker(args: tuple) -> dict:
    """Deep hill-climbing from identity for one priority keyword combo.

    Uses longer iteration budget and more aggressive restart strategy
    than the general near-identity search.
    """
    cipher, keyword, alphabet, iterations, restart_id = args
    alpha = KA if alphabet == "KA" else AZ
    decrypt_fn = _beau_decrypt if cipher == "beau" else _vig_decrypt

    perm = list(range(K4_LEN))

    # Restart strategy: restart 0 = identity, 1-3 = small perturbation (2-5 swaps),
    # 4+ = medium perturbation (5-15 swaps) for diversity
    if restart_id > 0:
        n_perturb = random.randint(2, 5) if restart_id <= 3 else random.randint(5, 15)
        for _ in range(n_perturb):
            a, b = random.sample(range(K4_LEN), 2)
            perm[a], perm[b] = perm[b], perm[a]

    ct = _apply_perm(K4, perm)
    pt = decrypt_fn(ct, keyword, alpha)
    best_score = _score_text(pt)
    best_perm = list(perm)
    best_pt = pt

    no_improve = 0
    for it in range(iterations):
        i, j = random.sample(range(K4_LEN), 2)
        perm[i], perm[j] = perm[j], perm[i]

        ct = _apply_perm(K4, perm)
        pt = decrypt_fn(ct, keyword, alpha)
        score = _score_text(pt)

        if score > best_score:
            best_score = score
            best_perm = list(perm)
            best_pt = pt
            no_improve = 0
        else:
            perm[i], perm[j] = perm[j], perm[i]
            no_improve += 1

        if no_improve > min(15000, iterations // 3):
            break

    displaced = sum(1 for i in range(K4_LEN) if best_perm[i] != i)

    crib_hits = 0
    for pos, crib_text in CRIBS:
        end = pos + len(crib_text)
        if end <= len(best_pt):
            crib_hits += sum(1 for k, c in enumerate(crib_text) if best_pt[pos + k] == c)

    return {
        "score": round(best_score, 2),
        "plaintext": best_pt,
        "perm": best_perm,
        "crib_hits": crib_hits,
        "method": f"priority/{cipher}/{keyword}/{alphabet}",
        "keyword": keyword,
        "cipher": cipher,
        "alphabet": alphabet,
        "displaced_positions": displaced,
        "restart_id": restart_id,
    }


def run_priority_keyword_sweep(
    *,
    iterations: int = 200000,
    num_workers: int = 0,
    restarts_per_combo: int = 0,
) -> dict:
    """Intensive hill-climbing sweep over PRIORITY_KEYWORDS.

    For each priority keyword × cipher × alphabet combo:
    - Multiple restarts from identity with varied perturbation
    - Longer iteration budget than general search
    - Reports per-keyword best results

    Returns dict with overall best + per-keyword breakdown.
    """
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    if restarts_per_combo <= 0:
        restarts_per_combo = max(4, num_workers // 2)

    # Deduplicate priority keywords
    seen = set()
    priority_kws = []
    for kw in PRIORITY_KEYWORDS:
        kw_upper = kw.upper()
        if kw_upper not in seen and _bean_passes(kw_upper):
            seen.add(kw_upper)
            priority_kws.append(kw_upper)

    start = time.monotonic()
    total_combos = 0
    all_results: list[dict] = []
    per_keyword: dict[str, dict] = {}

    for kw in priority_kws:
        kw_start = time.monotonic()
        kw_args = []
        for cipher in ("vig", "beau"):
            for alpha in ("AZ", "KA"):
                for rid in range(restarts_per_combo):
                    kw_args.append((cipher, kw, alpha, iterations, rid))
                    total_combos += 1

        kw_results = []
        with ProcessPoolExecutor(max_workers=num_workers) as pool:
            futures = [pool.submit(_priority_keyword_deep_worker, a) for a in kw_args]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    kw_results.append(result)
                    all_results.append(result)
                except Exception as e:
                    logger.error("Priority keyword %s failed: %s", kw, e)

        kw_elapsed = time.monotonic() - kw_start

        if kw_results:
            best = max(kw_results, key=lambda r: r["score"])
            per_keyword[kw] = {
                "best_score": best["score"],
                "best_method": best["method"],
                "best_plaintext": best["plaintext"][:60],
                "best_crib_hits": best["crib_hits"],
                "displaced": best["displaced_positions"],
                "combos_tested": len(kw_results),
                "elapsed_seconds": round(kw_elapsed, 2),
                "perm": best["perm"],
            }

    elapsed = time.monotonic() - start
    all_results.sort(key=lambda r: r["score"], reverse=True)

    overall_best = all_results[0] if all_results else None

    return {
        "elapsed_seconds": round(elapsed, 2),
        "total_combos": total_combos,
        "priority_keywords": priority_kws,
        "per_keyword": per_keyword,
        "overall_best": overall_best,
        "top_results": all_results[:30],
    }


# ---------------------------------------------------------------------------
# Product cipher workers (transposition × substitution)
# ---------------------------------------------------------------------------

# Thematic keywords for column-order derivation (must be self-contained for workers)
_PRODUCT_KEYWORDS = [
    "KRYPTOS", "SANBORN", "SCHEIDT", "BERLIN", "URANIA", "KOMPASS",
    "DEFECTOR", "PARALLAX", "COLOPHON", "ABSCISSA", "PALIMPSEST",
    "SHADOW", "COMPASS", "LODESTONE", "SPHINX", "PHARAOH",
    "CARTER", "EGYPT", "CLOCK", "POINT", "TOPOLOGY", "PEDESTAL",
    "MONOLITH", "SPYPLANE", "KLEPSYDRA", "QUARTZ", "CIPHER",
    "HIDDEN", "SECRET", "COVERT", "SIGNAL", "MARKER", "BEACON",
    "PATROL", "SECTOR", "CURTAIN", "BORDER", "ESCAPE", "TUNNEL",
    "TRANSIT", "CONTACT", "HANDLER", "AGENT", "SLEEPER", "MOLE",
    "LANGLEY", "MOSCOW", "PRAGUE", "VIENNA", "ZURICH", "CAIRO",
    "TUTANKHAMUN", "HIEROGLYPH", "ALEXANDERPLATZ", "WELTZEITUHR",
    "MENGENLEHREUHR", "CALATHOS", "APOPHYGE", "NIHILIST",
]


def _product_w9_worker(args: tuple) -> dict:
    """Test a batch of width-9 columnar transposition permutations × substitution.

    For each column order:
    1. Build columnar transposition permutation (width 9)
    2. Undo transposition: intermediate = CT[inv_perm]
    3. For each substitution type × period:
       - Recover key from cribs (mapped through transposition)
       - Check key consistency
       - If consistent: decrypt, score
    """
    batch_perms, batch_id = args

    K4_LOCAL = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
    CRIBS_LOCAL = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
    AZ_LOCAL = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    KA_LOCAL = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

    # Build crib dict
    crib_dict: dict[int, str] = {}
    for pos, text in CRIBS_LOCAL:
        for j, ch in enumerate(text):
            crib_dict[pos + j] = ch
    crib_positions = sorted(crib_dict.keys())

    qg = _load_quadgrams()

    best_score = -9999.0
    best_pt = ""
    best_method = ""
    best_crib_hits = 0
    best_col_order: list[int] = []
    configs_tested = 0

    for col_order in batch_perms:
        width = 9
        n = 97

        # Build columnar transposition permutation
        from collections import defaultdict
        cols: dict[int, list[int]] = defaultdict(list)
        for pos in range(n):
            _, c = divmod(pos, width)
            cols[c].append(pos)
        perm: list[int] = []
        for rank in range(width):
            col_idx = list(col_order).index(rank)
            perm.extend(cols[col_idx])

        # Inverse: undo transposition
        inv_perm = [0] * n
        for i, p in enumerate(perm):
            inv_perm[p] = i

        # intermediate[i] = K4[inv_perm[i]] — what we'd get after undoing transposition
        intermediate = "".join(K4_LOCAL[inv_perm[i]] for i in range(n))

        # Map crib positions through inverse transposition:
        # If PT goes through transposition then substitution to become CT,
        # then to undo: CT → undo sub → undo transposition → PT.
        # The intermediate text after undoing transposition is the "pre-sub" text.
        # Cribs are in the PT, so after undoing transposition, we need:
        # PT[i] = crib_dict[i] for crib positions in the ORIGINAL plaintext.
        # The intermediate = undo_transposition(CT).
        # Then: intermediate[i] = sub(PT[i]) where PT positions map through transposition.
        #
        # Actually: CT = sub(transposed_PT), where transposed_PT = PT[perm].
        # So: intermediate = undo_transpose(CT) = CT[inv_perm]
        # And: intermediate[i] = sub(PT[i])  (substitution operates position-by-position)
        # So crib positions in PT map directly to same positions in intermediate.

        # For each substitution variant × period, check crib consistency
        for variant_name, key_fn in [
            ("vig", lambda c, p: (c - p) % 26),
            ("beau", lambda c, p: (c + p) % 26),
            ("vbeau", lambda c, p: (p - c) % 26),
        ]:
            for alpha_name, alpha in [("AZ", AZ_LOCAL), ("KA", KA_LOCAL)]:
                # Recover key values at crib positions
                key_at_crib: dict[int, int] = {}
                for pos in crib_positions:
                    c_val = alpha.index(intermediate[pos])
                    p_val = alpha.index(crib_dict[pos])
                    key_at_crib[pos] = key_fn(c_val, p_val)

                # Test periods 1 through 13
                for period in range(1, 14):
                    configs_tested += 1
                    # Check consistency: all crib positions with same residue mod period
                    # must have the same key value
                    residue_keys: dict[int, int] = {}
                    consistent = True
                    for pos in crib_positions:
                        r = pos % period
                        k = key_at_crib[pos]
                        if r in residue_keys:
                            if residue_keys[r] != k:
                                consistent = False
                                break
                        else:
                            residue_keys[r] = k
                    if not consistent:
                        continue

                    # Consistent! Build full key and decrypt
                    full_key = [residue_keys.get(i % period, 0) for i in range(n)]
                    pt_chars = []
                    for i in range(n):
                        c_val = alpha.index(intermediate[i])
                        k = full_key[i]
                        if variant_name == "vig":
                            p_val = (c_val - k) % 26
                        elif variant_name == "beau":
                            p_val = (k - c_val) % 26
                        else:  # vbeau
                            p_val = (c_val + k) % 26
                        pt_chars.append(alpha[p_val])
                    pt = "".join(pt_chars)

                    # Score
                    score = sum(qg.get(pt[i:i+4], _QG_FLOOR) for i in range(len(pt) - 3))
                    score += _score_intel_jargon(pt)

                    # Count crib hits
                    hits = 0
                    for pos, text in CRIBS_LOCAL:
                        for k_idx, ch in enumerate(text):
                            if pos + k_idx < len(pt) and pt[pos + k_idx] == ch:
                                hits += 1

                    if score > best_score or hits > best_crib_hits:
                        if score > best_score:
                            best_score = score
                            best_pt = pt
                            best_method = f"product_w9/{variant_name}/p{period}/{alpha_name}/col={''.join(str(c) for c in col_order)}"
                            best_col_order = list(col_order)
                        if hits > best_crib_hits:
                            best_crib_hits = hits

        # Also test autokey with short primers (1-3 chars)
        for alpha_name, alpha in [("AZ", AZ_LOCAL), ("KA", KA_LOCAL)]:
            for primer_len in range(1, 4):
                # Try to derive primer from cribs
                # With autokey vig: C = (P + K) mod 26, first `primer_len` key chars = primer
                # At crib positions < primer_len, K = primer[pos]
                # At crib positions >= primer_len, K = PT[pos - primer_len]
                # For simplicity, brute-force primers of length 1-2, derive length 3
                if primer_len <= 2:
                    for p0 in range(26):
                        primer_vals = [p0] if primer_len == 1 else None
                        if primer_len == 2:
                            continue  # Skip len-2 brute force in w9 (too many combos per perm)
                        primer_str = alpha[p0]
                        configs_tested += 1

                        # Autokey Vigenère decrypt on intermediate
                        pt_chars = []
                        for i in range(n):
                            c_val = alpha.index(intermediate[i])
                            if i < 1:
                                k = p0
                            else:
                                k = alpha.index(pt_chars[i - 1])
                            p_val = (c_val - k) % 26
                            pt_chars.append(alpha[p_val])
                        pt = "".join(pt_chars)

                        hits = 0
                        for pos, text in CRIBS_LOCAL:
                            for k_idx, ch in enumerate(text):
                                if pos + k_idx < len(pt) and pt[pos + k_idx] == ch:
                                    hits += 1

                        score = sum(qg.get(pt[i:i+4], _QG_FLOOR) for i in range(len(pt) - 3))
                        score += _score_intel_jargon(pt)

                        if score > best_score or hits > best_crib_hits:
                            if score > best_score:
                                best_score = score
                                best_pt = pt
                                best_method = f"product_w9/autokey/{primer_str}/{alpha_name}/col={''.join(str(c) for c in col_order)}"
                                best_col_order = list(col_order)
                            if hits > best_crib_hits:
                                best_crib_hits = hits

    return {
        "score": round(best_score, 2),
        "plaintext": best_pt,
        "method": best_method,
        "crib_hits": best_crib_hits,
        "col_order": best_col_order,
        "configs_tested": configs_tested,
        "batch_id": batch_id,
    }


def run_product_cipher_w9(num_workers: int = 0) -> dict:
    """Exhaustive width-9 transposition × substitution product cipher.

    Tests all 9! = 362,880 column permutations × substitution types.
    Uses crib consistency to prune >99.9% of configs instantly.
    """
    from itertools import permutations

    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    all_perms = list(permutations(range(9)))
    total = len(all_perms)

    # Split into batches for workers
    batch_size = max(1, total // (num_workers * 4))
    batches = []
    for i in range(0, total, batch_size):
        batches.append((all_perms[i:i + batch_size], len(batches)))

    print(f"  Product W9: {total} column permutations in {len(batches)} batches "
          f"across {num_workers} workers...")

    start = time.monotonic()
    results = []
    with ProcessPoolExecutor(max_workers=num_workers) as pool:
        futures = [pool.submit(_product_w9_worker, batch) for batch in batches]
        for i, future in enumerate(as_completed(futures)):
            try:
                result = future.result()
                results.append(result)
                if (i + 1) % max(1, len(batches) // 10) == 0:
                    best_so_far = max(results, key=lambda r: r["score"])
                    print(f"    [{i+1}/{len(batches)}] best_score={best_so_far['score']:.1f} "
                          f"cribs={best_so_far['crib_hits']} method={best_so_far['method'][:60]}")
            except Exception as e:
                logger.error("Product W9 batch failed: %s", e)

    elapsed = time.monotonic() - start
    total_configs = sum(r["configs_tested"] for r in results)

    best = max(results, key=lambda r: r["score"]) if results else {
        "score": -9999.0, "plaintext": "", "method": "", "crib_hits": 0, "col_order": [],
    }

    # Collect top results by crib hits
    top_by_cribs = sorted(results, key=lambda r: r["crib_hits"], reverse=True)[:20]

    return {
        "elapsed_seconds": round(elapsed, 2),
        "total_perms": total,
        "total_configs": total_configs,
        "best": best,
        "top_by_cribs": top_by_cribs,
    }


def _product_general_worker(args: tuple) -> dict:
    """Test keyword-derived columnar transpositions × substitution for a given width."""
    width, keywords, worker_id = args

    K4_LOCAL = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
    CRIBS_LOCAL = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
    AZ_LOCAL = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    KA_LOCAL = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    n = 97

    crib_dict: dict[int, str] = {}
    for pos, text in CRIBS_LOCAL:
        for j, ch in enumerate(text):
            crib_dict[pos + j] = ch
    crib_positions = sorted(crib_dict.keys())

    qg = _load_quadgrams()

    best_score = -9999.0
    best_pt = ""
    best_method = ""
    best_crib_hits = 0
    configs_tested = 0

    # Generate unique column orders from keywords
    seen_orders: set[tuple] = set()
    col_orders: list[tuple[int, ...]] = []

    for kw in keywords:
        kw_upper = kw.upper()
        if len(kw_upper) < width:
            continue
        # keyword_to_order logic (inline for worker isolation)
        kw_slice = kw_upper[:width]
        indexed = [(ch, i) for i, ch in enumerate(kw_slice)]
        ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
        order = [0] * width
        for rank, (_, pos) in enumerate(ranked):
            order[pos] = rank
        order_t = tuple(order)
        if order_t not in seen_orders:
            seen_orders.add(order_t)
            col_orders.append(order_t)

    for col_order in col_orders:
        # Build columnar perm
        from collections import defaultdict
        cols: dict[int, list[int]] = defaultdict(list)
        for pos in range(n):
            _, c = divmod(pos, width)
            cols[c].append(pos)
        perm: list[int] = []
        for rank in range(width):
            col_idx = list(col_order).index(rank)
            perm.extend(cols[col_idx])

        inv_perm = [0] * n
        for i, p in enumerate(perm):
            inv_perm[p] = i

        intermediate = "".join(K4_LOCAL[inv_perm[i]] for i in range(n))

        for variant_name, key_fn in [
            ("vig", lambda c, p: (c - p) % 26),
            ("beau", lambda c, p: (c + p) % 26),
            ("vbeau", lambda c, p: (p - c) % 26),
        ]:
            for alpha_name, alpha in [("AZ", AZ_LOCAL), ("KA", KA_LOCAL)]:
                key_at_crib: dict[int, int] = {}
                for pos in crib_positions:
                    c_val = alpha.index(intermediate[pos])
                    p_val = alpha.index(crib_dict[pos])
                    key_at_crib[pos] = key_fn(c_val, p_val)

                for period in range(1, min(width + 1, 14)):
                    configs_tested += 1
                    residue_keys: dict[int, int] = {}
                    consistent = True
                    for pos in crib_positions:
                        r = pos % period
                        k = key_at_crib[pos]
                        if r in residue_keys:
                            if residue_keys[r] != k:
                                consistent = False
                                break
                        else:
                            residue_keys[r] = k
                    if not consistent:
                        continue

                    full_key = [residue_keys.get(i % period, 0) for i in range(n)]
                    pt_chars = []
                    for i in range(n):
                        c_val = alpha.index(intermediate[i])
                        k = full_key[i]
                        if variant_name == "vig":
                            p_val = (c_val - k) % 26
                        elif variant_name == "beau":
                            p_val = (k - c_val) % 26
                        else:
                            p_val = (c_val + k) % 26
                        pt_chars.append(alpha[p_val])
                    pt = "".join(pt_chars)

                    score = sum(qg.get(pt[i:i+4], _QG_FLOOR) for i in range(len(pt) - 3))
                    score += _score_intel_jargon(pt)

                    hits = 0
                    for pos, text in CRIBS_LOCAL:
                        for k_idx, ch in enumerate(text):
                            if pos + k_idx < len(pt) and pt[pos + k_idx] == ch:
                                hits += 1

                    if score > best_score:
                        best_score = score
                        best_pt = pt
                        best_method = f"product_w{width}/{variant_name}/p{period}/{alpha_name}/col={''.join(str(c) for c in col_order)}"
                    if hits > best_crib_hits:
                        best_crib_hits = hits

    return {
        "score": round(best_score, 2),
        "plaintext": best_pt,
        "method": best_method,
        "crib_hits": best_crib_hits,
        "configs_tested": configs_tested,
        "width": width,
        "worker_id": worker_id,
    }


def run_product_cipher_general(num_workers: int = 0) -> dict:
    """Keyword-derived transpositions × substitution for widths 4-14.

    For each width, generates column orders from thematic keywords,
    then tests all substitution types with crib consistency checking.
    """
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    # Build task list: one task per width
    tasks = []
    for width in range(4, 15):
        tasks.append((width, _PRODUCT_KEYWORDS, len(tasks)))

    print(f"  Product General: widths 4-14, {len(_PRODUCT_KEYWORDS)} keywords, "
          f"{len(tasks)} tasks across {num_workers} workers...")

    start = time.monotonic()
    results = []
    with ProcessPoolExecutor(max_workers=num_workers) as pool:
        futures = [pool.submit(_product_general_worker, task) for task in tasks]
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
                print(f"    Width {result['width']:2d}: score={result['score']:.1f} "
                      f"cribs={result['crib_hits']} configs={result['configs_tested']} "
                      f"method={result['method'][:60]}")
            except Exception as e:
                logger.error("Product general worker failed: %s", e)

    elapsed = time.monotonic() - start
    total_configs = sum(r["configs_tested"] for r in results)

    best = max(results, key=lambda r: r["score"]) if results else {
        "score": -9999.0, "plaintext": "", "method": "", "crib_hits": 0,
    }

    return {
        "elapsed_seconds": round(elapsed, 2),
        "total_configs": total_configs,
        "widths_tested": list(range(4, 15)),
        "best": best,
        "per_width": {r["width"]: {"score": r["score"], "crib_hits": r["crib_hits"],
                                    "method": r["method"]} for r in results},
    }


def _running_key_product_worker(args: tuple) -> dict:
    """Test running-key cipher on transposed text for one (perm, passage) combo."""
    col_order, width, passage, passage_name, worker_id = args

    K4_LOCAL = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
    CRIBS_LOCAL = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
    AZ_LOCAL = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    n = 97
    import re as _re

    # Sanitize passage
    passage_clean = _re.sub(r"[^A-Z]", "", passage.upper())
    if len(passage_clean) < n:
        return {
            "score": -9999.0, "plaintext": "", "method": "", "crib_hits": 0,
            "configs_tested": 0, "worker_id": worker_id,
        }

    # Build columnar perm
    from collections import defaultdict
    cols: dict[int, list[int]] = defaultdict(list)
    for pos in range(n):
        _, c = divmod(pos, width)
        cols[c].append(pos)
    perm: list[int] = []
    for rank in range(width):
        col_idx = list(col_order).index(rank)
        perm.extend(cols[col_idx])

    inv_perm = [0] * n
    for i, p in enumerate(perm):
        inv_perm[p] = i

    intermediate = "".join(K4_LOCAL[inv_perm[i]] for i in range(n))

    qg = _load_quadgrams()
    best_score = -9999.0
    best_pt = ""
    best_method = ""
    best_crib_hits = 0
    configs_tested = 0

    max_offset = min(len(passage_clean) - n, 200)

    for offset in range(0, max(1, max_offset)):
        for variant_name, decrypt_fn in [
            ("vig", lambda c, k: (c - k) % 26),
            ("beau", lambda c, k: (k - c) % 26),
            ("vbeau", lambda c, k: (c + k) % 26),
        ]:
            configs_tested += 1
            pt_chars = []
            for i in range(n):
                c_val = AZ_LOCAL.index(intermediate[i])
                k_val = AZ_LOCAL.index(passage_clean[offset + i])
                p_val = decrypt_fn(c_val, k_val)
                pt_chars.append(AZ_LOCAL[p_val])
            pt = "".join(pt_chars)

            hits = 0
            for pos, text in CRIBS_LOCAL:
                for k_idx, ch in enumerate(text):
                    if pos + k_idx < len(pt) and pt[pos + k_idx] == ch:
                        hits += 1

            score = sum(qg.get(pt[i:i+4], _QG_FLOOR) for i in range(len(pt) - 3))
            score += _score_intel_jargon(pt)

            if score > best_score:
                best_score = score
                best_pt = pt
                best_method = (f"running_key_w{width}/"
                               f"{variant_name}/{passage_name}/off{offset}/"
                               f"col={''.join(str(c) for c in col_order)}")
            if hits > best_crib_hits:
                best_crib_hits = hits

    return {
        "score": round(best_score, 2),
        "plaintext": best_pt,
        "method": best_method,
        "crib_hits": best_crib_hits,
        "configs_tested": configs_tested,
        "worker_id": worker_id,
    }


def run_running_key_product(num_workers: int = 0) -> dict:
    """Running-key cipher on transposed text.

    Uses top transposition candidates (keyword-derived, widths 7-11)
    combined with corpus passages as running keys.
    """
    if num_workers <= 0:
        num_workers = mp.cpu_count() or 4

    # Load corpus passages
    passages: list[tuple[str, str]] = []  # (name, text)

    # Try to load from reference directory
    ref_dir = Path(__file__).resolve().parent.parent.parent / "reference"
    if ref_dir.exists():
        for txt_file in sorted(ref_dir.glob("*.txt")):
            try:
                text = txt_file.read_text(errors="ignore")
                if len(text) >= 200:
                    passages.append((txt_file.stem, text))
            except Exception:
                pass

    # Load wordlist as potential key source
    wordlist_dir = Path(__file__).resolve().parent.parent.parent / "wordlists"
    if wordlist_dir.exists():
        for wl_file in sorted(wordlist_dir.glob("*.txt")):
            try:
                text = wl_file.read_text(errors="ignore")
                if len(text) >= 200:
                    passages.append((wl_file.stem, text))
            except Exception:
                pass

    if not passages:
        print("  No corpus passages found for running-key test.")
        return {"elapsed_seconds": 0, "total_configs": 0, "best": {
            "score": -9999.0, "plaintext": "", "method": "", "crib_hits": 0,
        }}

    # Generate column orders from keywords for widths 7-11
    tasks = []
    seen_combos: set[tuple] = set()
    for width in [9, 7, 8, 10, 11]:
        for kw in _PRODUCT_KEYWORDS:
            kw_upper = kw.upper()
            if len(kw_upper) < width:
                continue
            kw_slice = kw_upper[:width]
            indexed = [(ch, i) for i, ch in enumerate(kw_slice)]
            ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
            order = [0] * width
            for rank, (_, pos) in enumerate(ranked):
                order[pos] = rank
            order_t = tuple(order)

            for passage_name, passage_text in passages:
                combo_key = (order_t, width, passage_name)
                if combo_key in seen_combos:
                    continue
                seen_combos.add(combo_key)
                tasks.append((order_t, width, passage_text, passage_name, len(tasks)))

    print(f"  Running-key product: {len(tasks)} tasks ({len(passages)} passages × "
          f"keyword column orders), {num_workers} workers...")

    start = time.monotonic()
    results = []
    with ProcessPoolExecutor(max_workers=num_workers) as pool:
        futures = [pool.submit(_running_key_product_worker, task) for task in tasks]
        for i, future in enumerate(as_completed(futures)):
            try:
                result = future.result()
                results.append(result)
                if (i + 1) % max(1, len(tasks) // 5) == 0:
                    best_so_far = max(results, key=lambda r: r["score"])
                    print(f"    [{i+1}/{len(tasks)}] best_score={best_so_far['score']:.1f} "
                          f"cribs={best_so_far['crib_hits']}")
            except Exception as e:
                logger.error("Running-key worker failed: %s", e)

    elapsed = time.monotonic() - start
    total_configs = sum(r["configs_tested"] for r in results)

    best = max(results, key=lambda r: r["score"]) if results else {
        "score": -9999.0, "plaintext": "", "method": "", "crib_hits": 0,
    }

    return {
        "elapsed_seconds": round(elapsed, 2),
        "total_configs": total_configs,
        "total_tasks": len(tasks),
        "passages_used": len(passages),
        "best": best,
    }
