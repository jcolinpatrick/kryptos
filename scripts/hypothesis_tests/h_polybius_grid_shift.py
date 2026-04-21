#!/usr/bin/env python3
"""
Cipher: two-stage Polybius grid-shift + classical
Family: hypothesis_tests
Status: active
Keyspace: thematic_keywords_v2 (primary) x 7 ORD x 4 M x 7 P x 3 V ~ 406K
Last run:
Best score: TBD

PURPOSE
-------
Falsification harness for an externally proposed two-stage cipher:
  Stage 1: PT looked up in 5x5 Polybius (25 letters, missing M in {J,Q,X,Z}),
           moved by position-dependent (dc, dr) cycling with period P in {2..8},
           read off at new grid cell -> intermediate text INT.
  Stage 2: INT encrypted by Vig/Beau/VarBeau periodic cipher with thematic
           keyword K -> CT.

DESIGN POSTURE
--------------
- Local harness only. NO controller dispatch, NO API workers.
- Bean is DIAGNOSTIC ONLY (Bean H1 only transfers when P|38, see
  memory/project_polybius_grid_shift_campaign_v2.md).
- Filter (residue-consistency) is the signal detector, not ngram.
  Random-INT survivor rate measured at 0/280K per period in
  scripts/exploration/e_polybius_grid_shift_filter_probe.py.
- Synthetic-positive test is the correctness gate. Halts on failure.
- Default expected verdict: bounded_null.

RED-TEAM HISTORY
----------------
v1: red-teamed 2026-04-18, found 2 BLOCKERs.
v2: addressed BLOCKER 1 (Bean transferability under multilayer).
v3 (this): probe closed BLOCKER 1 empirically (filter is hyper-restrictive),
   collapsed BLOCKER 2 into "any survivor is candidate signal," addressed
   SERIOUS issues.
"""

import argparse
import hashlib
import json
import os
import random
import string
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from itertools import product
from multiprocessing import Pool, cpu_count
from pathlib import Path

_ROOT = os.path.dirname(os.path.abspath(__file__))
while not os.path.exists(os.path.join(_ROOT, "src")):
    _ROOT = os.path.dirname(_ROOT)
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT


# ── Constants ────────────────────────────────────────────────────────

ALPH = string.ascii_uppercase
PT_AT_CRIBS = dict(CRIB_DICT)
CRIB_POSITIONS = sorted(PT_AT_CRIBS.keys())
CT_AT_CRIBS = {p: CT[p] for p in CRIB_POSITIONS}
NON_CRIB_POSITIONS = [i for i in range(CT_LEN) if i not in PT_AT_CRIBS]

PRIMARY_ORDERINGS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "IQLUSION",
    "UNDERGROUND", "SANBORN", "SCHEIDT",
]
SECONDARY_ORDERINGS = PRIMARY_ORDERINGS + [
    "STANDARD", "HYDRA", "LIGHT", "HIDDEN",
    "SECRET", "YARD", "COMPASS", "SHADOW",
]
MISSING_LETTERS = ["J", "Q", "X", "Z"]
PERIODS = list(range(2, 9))
VARIANTS = ["vig", "beau", "varbeau"]


# ── Grid + positions ─────────────────────────────────────────────────


def build_grid(keyword: str, missing: str) -> tuple:
    """5x5 Polybius row-major. Keyword first (dedup), then remaining
    A-Z minus missing letter."""
    seen = set()
    keyword_letters = []
    for c in keyword.upper():
        if c.isalpha() and c != missing and c not in seen:
            seen.add(c)
            keyword_letters.append(c)
    rest = [c for c in ALPH if c != missing and c not in seen]
    grid = tuple(keyword_letters + rest)
    assert len(grid) == 25, f"grid len {len(grid)} for keyword={keyword} missing={missing}"
    return grid


def grid_index(letter: str, grid: tuple) -> int:
    try:
        return grid.index(letter)
    except ValueError:
        return -1


def grid_position(letter: str, grid: tuple):
    """Return (row, col) for letter in grid, None if missing."""
    idx = grid_index(letter, grid)
    if idx < 0:
        return None
    return (idx // 5, idx % 5)


def grid_letter_at(row: int, col: int, grid: tuple) -> str:
    return grid[row * 5 + col]


# ── Stage-2 cipher ───────────────────────────────────────────────────


def stage2_encrypt(int_letter: str, key_letter: str, variant: str) -> str:
    """Encrypt one INT letter with one key letter under variant. A=0."""
    i = ord(int_letter) - 65
    k = ord(key_letter) - 65
    if variant == "vig":          # CT = INT + K
        c = (i + k) % 26
    elif variant == "beau":       # CT = K - INT
        c = (k - i) % 26
    elif variant == "varbeau":    # CT = INT - K
        c = (i - k) % 26
    else:
        raise ValueError(f"unknown variant {variant}")
    return chr(c + 65)


def stage2_decrypt(ct_letter: str, key_letter: str, variant: str) -> str:
    """Inverse of stage2_encrypt. Recovers INT given CT and key."""
    c = ord(ct_letter) - 65
    k = ord(key_letter) - 65
    if variant == "vig":          # INT = CT - K
        i = (c - k) % 26
    elif variant == "beau":       # INT = K - CT  (Beaufort is reciprocal)
        i = (k - c) % 26
    elif variant == "varbeau":    # INT = CT + K
        i = (c + k) % 26
    else:
        raise ValueError(f"unknown variant {variant}")
    return chr(i + 65)


def invert_stage2_at_cribs(ct_at_cribs: dict, key: str, variant: str) -> dict:
    return {
        pos: stage2_decrypt(ct_letter, key[pos % len(key)], variant)
        for pos, ct_letter in ct_at_cribs.items()
    }


def invert_stage2_full(ct: str, key: str, variant: str) -> str:
    return "".join(
        stage2_decrypt(ct[i], key[i % len(key)], variant)
        for i in range(len(ct))
    )


# ── Stage-1 cipher ───────────────────────────────────────────────────


def stage1_encrypt_letter(pt_letter: str, dc: int, dr: int,
                          grid: tuple, missing: str) -> str:
    """Apply position-dependent grid shift. PT=M passes through."""
    if pt_letter == missing:
        return missing
    pos = grid_position(pt_letter, grid)
    if pos is None:
        # PT letter is not in grid AND not the missing letter -> impossible
        # (every A-Z letter is either in the 25-letter grid or is missing)
        raise ValueError(f"PT letter {pt_letter} not in grid and not missing letter")
    new_row = (pos[0] + dr) % 5
    new_col = (pos[1] + dc) % 5
    return grid_letter_at(new_row, new_col, grid)


def stage1_decrypt_letter(int_letter: str, dc: int, dr: int,
                          grid: tuple, missing: str) -> str:
    """Inverse: shift back by (-dc, -dr)."""
    if int_letter == missing:
        return missing
    pos = grid_position(int_letter, grid)
    if pos is None:
        raise ValueError(f"INT letter {int_letter} not in grid and not missing letter")
    new_row = (pos[0] - dr) % 5
    new_col = (pos[1] - dc) % 5
    return grid_letter_at(new_row, new_col, grid)


def stage1_encrypt(pt: str, movement: list, grid: tuple, missing: str) -> str:
    """Encrypt full PT through stage 1 with movement = [(dc_0, dr_0), ...]."""
    P = len(movement)
    out = []
    for i, p in enumerate(pt):
        dc, dr = movement[i % P]
        out.append(stage1_encrypt_letter(p, dc, dr, grid, missing))
    return "".join(out)


def stage1_decrypt(int_text: str, movement: list, grid: tuple, missing: str) -> str:
    """Decrypt full INT through stage 1 inverse."""
    P = len(movement)
    out = []
    for i, c in enumerate(int_text):
        dc, dr = movement[i % P]
        out.append(stage1_decrypt_letter(c, dc, dr, grid, missing))
    return "".join(out)


# ── Residue-consistency filter ───────────────────────────────────────


def derive_movement_from_cribs(int_at_cribs: dict, grid: tuple,
                               missing: str, period: int):
    """Try to derive a movement rule from crib (PT, INT) pairs.
    Returns dict {residue: (dc, dr)} if consistent, None if not.
    Pass-through and inverse-consistency rejection enforced."""
    movement = {}
    for pos in CRIB_POSITIONS:
        residue = pos % period
        pt = PT_AT_CRIBS[pos]
        int_l = int_at_cribs[pos]

        # Pass-through: PT=M requires INT=M, contributes no offset.
        if pt == missing:
            if int_l != missing:
                return None
            continue

        # Inverse-consistency: INT=M while PT!=M is impossible.
        if int_l == missing:
            return None

        pt_pos = grid_position(pt, grid)
        int_pos = grid_position(int_l, grid)
        offset = ((int_pos[1] - pt_pos[1]) % 5,    # dc
                  (int_pos[0] - pt_pos[0]) % 5)    # dr

        if residue in movement:
            if movement[residue] != offset:
                return None
        else:
            movement[residue] = offset

    return movement


# ── Ngram scoring ────────────────────────────────────────────────────


_QUADGRAMS = None
_QUADGRAM_FLOOR = -10.0


def load_quadgrams():
    global _QUADGRAMS
    if _QUADGRAMS is None:
        with open(os.path.join(_ROOT, "data", "english_quadgrams.json")) as f:
            _QUADGRAMS = json.load(f)
    return _QUADGRAMS


def ngram_score(text: str) -> float:
    """Mean log-prob quadgram score on text. Higher is more English."""
    qg = load_quadgrams()
    text = "".join(c for c in text.upper() if c.isalpha())
    if len(text) < 4:
        return _QUADGRAM_FLOOR
    s = 0.0
    for i in range(len(text) - 3):
        s += qg.get(text[i:i+4], _QUADGRAM_FLOOR)
    return s / (len(text) - 3)


def ngram_score_non_crib(plaintext: str) -> float:
    chars = "".join(plaintext[i] for i in NON_CRIB_POSITIONS)
    return ngram_score(chars)


# ── Readable substring detection ─────────────────────────────────────


_READABLE_WORDS = None


def load_readable_words():
    """Load a curated readable-words set for substring detection.
    Combines thematic_keywords_v2 + english.txt filtered to length 5-12
    with vowel/consonant balance (proxy for top-20K common words)."""
    global _READABLE_WORDS
    if _READABLE_WORDS is not None:
        return _READABLE_WORDS

    words = set()

    # Thematic seed
    tpath = os.path.join(_ROOT, "wordlists", "thematic_keywords_v2.txt")
    with open(tpath) as f:
        for line in f:
            w = line.strip().upper()
            if w and not w.startswith("#") and w.isalpha() and 5 <= len(w) <= 12:
                words.add(w)

    # English filter: length 5-8, vowel/consonant balance
    epath = os.path.join(_ROOT, "wordlists", "english.txt")
    with open(epath) as f:
        for line in f:
            w = line.strip().upper()
            if not (5 <= len(w) <= 8 and w.isalpha() and w.isascii()):
                continue
            vowels = sum(1 for c in w if c in "AEIOU")
            if vowels < 2 or vowels > len(w) - 2:
                continue
            # Drop runs of 3+ same letter
            if any(w[i] == w[i+1] == w[i+2] for i in range(len(w) - 2)):
                continue
            words.add(w)

    _READABLE_WORDS = words
    return _READABLE_WORDS


def find_readable_substrings(text: str, min_len: int = 5) -> list:
    """Return list of (start, end, word) for readable substrings of text.
    A substring is readable iff it's in the readable-words set AND its
    quadgram score > -7."""
    words = load_readable_words()
    text_clean = "".join(c if c.isalpha() else "_" for c in text.upper())

    hits = []
    for start in range(len(text_clean)):
        for length in range(min_len, min(13, len(text_clean) - start + 1)):
            sub = text_clean[start:start + length]
            if "_" in sub:
                continue
            if sub in words and ngram_score(sub) > -7.0:
                hits.append((start, start + length, sub))
    return hits


# ── Pipeline ─────────────────────────────────────────────────────────


def evaluate_one(ct: str, key: str, variant: str, ord_kw: str,
                 missing: str, period: int) -> dict:
    """One configuration. Returns dict with at minimum:
       {survived, movement, plaintext, ngram, readable_hits} (when survived).
    Otherwise just {survived: False, fail_reason}."""
    grid = build_grid(ord_kw, missing)
    int_at_cribs = invert_stage2_at_cribs({i: ct[i] for i in CRIB_POSITIONS},
                                          key, variant)
    movement_dict = derive_movement_from_cribs(int_at_cribs, grid, missing, period)
    if movement_dict is None:
        return {"survived": False}

    # Extend movement to a full period array.
    if len(movement_dict) < period:
        # Cribs don't cover all residue classes -> pass-through positions
        # at residues with no constraint. For our M in {J,Q,X,Z}, this
        # means a residue where every crib position has PT=M (impossible
        # since cribs don't contain those letters). So this branch should
        # only fire if a residue class has zero crib positions (period > 24
        # or extreme cases). For our P in 2..8, every residue has cribs.
        # Default unconstrained residues to (0, 0) and flag.
        movement = [(movement_dict.get(r, (0, 0))) for r in range(period)]
    else:
        movement = [movement_dict[r] for r in range(period)]

    # Full decrypt: stage-2 inverse on whole CT, then stage-1 inverse.
    int_full = invert_stage2_full(ct, key, variant)
    plaintext = stage1_decrypt(int_full, movement, grid, missing)

    # Verify cribs match (sanity).
    for pos in CRIB_POSITIONS:
        if plaintext[pos] != PT_AT_CRIBS[pos]:
            return {"survived": False, "fail_reason": "crib_mismatch_post_decrypt"}

    ng = ngram_score_non_crib(plaintext)
    hits = find_readable_substrings(plaintext)

    # Filter readable hits: drop those entirely within crib regions.
    non_crib_hits = []
    for start, end, word in hits:
        positions = list(range(start, end))
        if any(p not in PT_AT_CRIBS for p in positions):
            non_crib_hits.append({"start": start, "end": end, "word": word})

    return {
        "survived": True,
        "movement": movement,
        "plaintext": plaintext,
        "ngram_non_crib": ng,
        "readable_hits": non_crib_hits,
        "key": key,
        "variant": variant,
        "ordering": ord_kw,
        "missing": missing,
        "period": period,
    }


# ── Wordlist loading ─────────────────────────────────────────────────


def load_thematic_keywords() -> list:
    """Load thematic_keywords_v2 filtered to length 3-12, A-Z only."""
    path = os.path.join(_ROOT, "wordlists", "thematic_keywords_v2.txt")
    keys = set()
    with open(path) as f:
        for line in f:
            w = line.strip().upper()
            if w and not w.startswith("#") and w.isalpha() and 3 <= len(w) <= 12:
                keys.add(w)
    return sorted(keys)


def wordlist_hash(keys: list) -> str:
    h = hashlib.sha256("\n".join(keys).encode()).hexdigest()
    return h


# ── Per-variant unit tests ───────────────────────────────────────────


def unit_test_stage2_roundtrip():
    """Assert stage2 encrypt/decrypt roundtrips for every (variant, letter, key) triple."""
    for variant in VARIANTS:
        for i in range(26):
            for k in range(26):
                int_l = chr(i + 65)
                key_l = chr(k + 65)
                ct = stage2_encrypt(int_l, key_l, variant)
                back = stage2_decrypt(ct, key_l, variant)
                assert back == int_l, (
                    f"stage2 roundtrip fail: variant={variant} INT={int_l} "
                    f"K={key_l} CT={ct} back={back}"
                )


def unit_test_stage1_roundtrip():
    """Assert stage1 encrypt/decrypt roundtrips."""
    for missing in MISSING_LETTERS:
        grid = build_grid("KRYPTOS", missing)
        for letter in ALPH:
            if letter == missing:
                continue
            for dc in range(5):
                for dr in range(5):
                    enc = stage1_encrypt_letter(letter, dc, dr, grid, missing)
                    dec = stage1_decrypt_letter(enc, dc, dr, grid, missing)
                    assert dec == letter, (
                        f"stage1 roundtrip fail: missing={missing} letter={letter} "
                        f"(dc, dr)=({dc}, {dr}) enc={enc} dec={dec}"
                    )


def run_unit_tests():
    print("Running per-variant unit tests...")
    unit_test_stage2_roundtrip()
    print("  stage2 roundtrip: 3 variants x 676 (letter, key) pairs PASS")
    unit_test_stage1_roundtrip()
    print("  stage1 roundtrip: 4 missing x 25 letters x 25 (dc, dr) PASS")


# ── Synthetic-positive test ──────────────────────────────────────────


def synthetic_positive_test() -> bool:
    """Plant a known PT under chosen two-stage params, encrypt, run harness,
    assert recovery. Halt on failure."""
    print("\nRunning synthetic-positive test...")

    # Build a 97-char PT that contains the cribs at the right positions
    # (21..33 EASTNORTHEAST, 63..73 BERLINCLOCK).
    pt = ["A"] * CT_LEN
    filler = "WHOEVERREADSTHISFINDSANCIENTKNOWLEDGEHIDDENBELOW"
    fi = 0
    for i in range(CT_LEN):
        if i in PT_AT_CRIBS:
            pt[i] = PT_AT_CRIBS[i]
        else:
            pt[i] = filler[fi % len(filler)]
            fi += 1
    pt = "".join(pt)
    # Drop missing letter J/Q/X/Z from filler (will use M=Z for the plant)
    PLANT_M = "Z"
    pt = "".join(c if c != PLANT_M else "Y" for c in pt)
    # But preserve cribs even after substitution.
    pt = list(pt)
    for i, c in PT_AT_CRIBS.items():
        pt[i] = c
    pt = "".join(pt)

    PLANT_ORD = "KRYPTOS"
    PLANT_P = 4
    PLANT_MOVEMENT = [(1, 1), (2, 1), (1, 2), (2, 2)]
    PLANT_V = "vig"
    PLANT_K = "SHADOW"

    grid = build_grid(PLANT_ORD, PLANT_M)

    # Encrypt: stage 1 then stage 2
    int_text = stage1_encrypt(pt, PLANT_MOVEMENT, grid, PLANT_M)
    ct_planted = "".join(
        stage2_encrypt(int_text[i], PLANT_K[i % len(PLANT_K)], PLANT_V)
        for i in range(CT_LEN)
    )

    print(f"  Plant: PT[:30]={pt[:30]}...")
    print(f"  Plant: ORD={PLANT_ORD} M={PLANT_M} P={PLANT_P} MOVEMENT={PLANT_MOVEMENT} V={PLANT_V} K={PLANT_K}")
    print(f"  Plant: CT[:30]={ct_planted[:30]}...")

    # Run harness on planted CT with the planted parameters and verify recovery.
    result = evaluate_one(ct_planted, PLANT_K, PLANT_V, PLANT_ORD, PLANT_M, PLANT_P)
    if not result["survived"]:
        print(f"  FAIL: planted config did not survive filter.")
        return False
    if result["plaintext"] != pt:
        print(f"  FAIL: recovered PT does not match planted.")
        print(f"    Recovered[:60]={result['plaintext'][:60]}")
        print(f"    Expected [:60]={pt[:60]}")
        return False
    if result["movement"] != PLANT_MOVEMENT:
        print(f"  FAIL: recovered movement != planted.")
        print(f"    Recovered={result['movement']}")
        print(f"    Expected ={PLANT_MOVEMENT}")
        return False
    print(f"  PASS: planted config recovered exactly.")

    # Sweep over wrong (V, K, ORD, M, P) and verify zero false positives.
    print("  Checking zero false positives across thematic wordlist...")
    keys = load_thematic_keywords()
    fp_count = 0
    fp_examples = []
    for ord_kw, missing, period, variant, key in product(
        PRIMARY_ORDERINGS, MISSING_LETTERS, PERIODS, VARIANTS, keys
    ):
        if (ord_kw, missing, period, variant, key) == (
            PLANT_ORD, PLANT_M, PLANT_P, PLANT_V, PLANT_K
        ):
            continue
        r = evaluate_one(ct_planted, key, variant, ord_kw, missing, period)
        if r["survived"]:
            fp_count += 1
            if len(fp_examples) < 5:
                fp_examples.append({
                    "ord": ord_kw, "M": missing, "P": period, "V": variant, "K": key,
                    "ngram": r["ngram_non_crib"],
                    "plaintext_head": r["plaintext"][:30],
                })

    total_other = (len(PRIMARY_ORDERINGS) * len(MISSING_LETTERS) *
                   len(PERIODS) * len(VARIANTS) * len(keys)) - 1
    print(f"  Survivor count across {total_other} other configs: {fp_count}")

    # Classify each survivor: identity duplicate of planted (same PT)
    # vs. genuine alternate solution (different PT).
    identity_dups = 0
    novel_survivors = []
    for ex in fp_examples:
        if ex["plaintext_head"] == pt[:30]:
            identity_dups += 1
        else:
            novel_survivors.append(ex)

    # Re-scan all (V, K, ORD, M, P) survivors for full PT comparison
    # (fp_examples only stored the first 5, count totals are accurate but
    # identity vs novel breakdown for FULL fp_count requires re-scan).
    if fp_count > len(fp_examples):
        # Conservative: re-evaluate to classify all
        full_identity = 0
        full_novel = []
        for ord_kw, missing, period, variant, key in product(
            PRIMARY_ORDERINGS, MISSING_LETTERS, PERIODS, VARIANTS, keys
        ):
            if (ord_kw, missing, period, variant, key) == (
                PLANT_ORD, PLANT_M, PLANT_P, PLANT_V, PLANT_K
            ):
                continue
            r = evaluate_one(ct_planted, key, variant, ord_kw, missing, period)
            if r["survived"]:
                if r["plaintext"] == pt:
                    full_identity += 1
                else:
                    full_novel.append({
                        "ord": ord_kw, "M": missing, "P": period, "V": variant, "K": key,
                        "ngram": r["ngram_non_crib"],
                        "plaintext_head": r["plaintext"][:30],
                    })
        identity_dups = full_identity
        novel_survivors = full_novel

    print(f"  Algebraic-identity duplicates (same PT as planted): {identity_dups}")
    print(f"  Novel survivors (different PT): {len(novel_survivors)}")

    if novel_survivors:
        print(f"  Sample novel survivors (first 5):")
        for ex in novel_survivors[:5]:
            print(f"    {ex}")
        # Novel survivor with similar or higher ngram than planted = harness bug
        # OR a genuinely degenerate cipher class. Either way, halt.
        planted_ng = result["ngram_non_crib"]
        max_novel_ng = max((s["ngram"] for s in novel_survivors), default=-100.0)
        if max_novel_ng > planted_ng - 0.5:
            print(f"  FAIL: novel survivors with comparable ngram detected.")
            print(f"    Planted ngram={planted_ng:.3f}  Max novel ngram={max_novel_ng:.3f}")
            return False
        print(f"  Novel survivors all have ngram < planted - 0.5; tolerable.")

    print(f"  PASS: planted recovered, all survivors are identity duplicates "
          f"or low-ngram noise.")
    return True


# ── Parallel search ──────────────────────────────────────────────────


def _worker(args):
    ct, key, variant, ord_kw, missing, period = args
    return evaluate_one(ct, key, variant, ord_kw, missing, period)


def run_search(ct: str, orderings: list, missing_letters: list,
               periods: list, variants: list, keys: list,
               n_workers: int = None) -> dict:
    if n_workers is None:
        n_workers = max(1, cpu_count() - 2)

    tasks = list(product([ct], keys, variants, orderings, missing_letters, periods))
    print(f"  Total configs: {len(tasks):,}")
    print(f"  Workers: {n_workers}")

    survivors = []
    t0 = time.time()
    with Pool(n_workers) as pool:
        for i, result in enumerate(pool.imap_unordered(_worker, tasks, chunksize=200)):
            if result["survived"]:
                survivors.append(result)
            if (i + 1) % 50000 == 0:
                elapsed = time.time() - t0
                rate = (i + 1) / elapsed
                eta = (len(tasks) - (i + 1)) / rate
                print(f"    {i+1:>10,}/{len(tasks):,}  rate={rate:>8.0f}/s  "
                      f"eta={eta:>5.0f}s  survivors={len(survivors)}")
    elapsed = time.time() - t0
    print(f"  Done in {elapsed:.1f}s. Survivors: {len(survivors)}")
    return {"survivors": survivors, "elapsed_sec": elapsed, "total_configs": len(tasks)}


# ── Manifest writer ──────────────────────────────────────────────────


def write_manifest(tier: str, ct_label: str, results: dict, scope: dict):
    """Write campaign manifest JSON."""
    survivors = results["survivors"]

    # Filter "promotion" survivors: ngram > -7 AND at least one readable hit
    promoted = [
        s for s in survivors
        if s["ngram_non_crib"] > -7.0 and len(s["readable_hits"]) > 0
    ]

    if promoted:
        verdict = "unexpected_hit"
    elif survivors:
        verdict = "narrow_residual"
    else:
        verdict = "bounded_null"

    manifest = {
        "manifest_version": "1.0",
        "campaign_id": f"f_polybius_grid_shift_v1_{tier}",
        "campaign_name": f"Two-stage Polybius+classical ({tier} tier)",
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "git_commit": "",
        "verdict": verdict,
        "verdict_summary": (
            f"Tested {results['total_configs']:,} configurations of two-stage "
            f"Polybius + classical cipher under crib-driven residue-consistency "
            f"filter. {len(survivors)} filter survivor(s); {len(promoted)} cleared "
            f"non-crib readability gate (ngram > -7 AND >=1 readable substring)."
        ),
        "evidence_pointer": "",
        "family_updates": {},
        "scope_caveats": [
            "Bean is diagnostic only; H1 Bean equality only transfers when "
            "P|38 (P in {1,2}) under multilayer-with-period-P models. See "
            "memory/project_polybius_grid_shift_campaign_v2.md.",
            "Pass-through rule (PT=M -> INT=M) is unfalsifiable from cribs "
            "for M in {J,Q,X,Z}; treated as model assumption.",
            "Wordlist is thematic_keywords_v2; broader English wordlist not tested.",
        ],
        "scope_does_not_cover": [
            "Non-periodic movement rules",
            "Period > 8",
            "Stage-2 ciphers other than Vig/Beau/VarBeau",
            "Grids larger than 5x5",
            "Multi-keyword movement rules",
            "Wordlists outside thematic_keywords_v2",
        ],
        "total_profiles_evaluated": results["total_configs"],
        "joint_anomaly_successes": len(promoted),
        "populations_tested": [tier],
        "variants_tested": VARIANTS,
        "notes": (
            f"Elapsed: {results['elapsed_sec']:.1f}s. "
            f"Wordlist hash: {scope.get('wordlist_hash', 'N/A')}. "
            f"CT label: {ct_label}."
        ),
    }

    if promoted:
        manifest["promoted_candidates"] = promoted

    target_dir = Path(_ROOT) / "results" / "campaign_manifests"
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / f"f_polybius_grid_shift_v1_{tier}.json"
    target.write_text(json.dumps(manifest, indent=2))
    print(f"  Wrote {target}")
    return target


# ── Main ─────────────────────────────────────────────────────────────


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-tests", action="store_true",
                    help="Skip unit + synthetic-positive tests (DANGEROUS)")
    ap.add_argument("--tier", choices=["primary", "secondary", "both"],
                    default="primary", help="Which tier to run on real CT")
    ap.add_argument("--workers", type=int, default=None)
    args = ap.parse_args()

    print("=" * 78)
    print("Polybius grid-shift falsification harness v1")
    print("=" * 78)

    if not args.skip_tests:
        run_unit_tests()
        ok = synthetic_positive_test()
        if not ok:
            print("\nSYNTHETIC-POSITIVE FAILED. Halting before real CT run.")
            sys.exit(1)

    keys = load_thematic_keywords()
    wlh = wordlist_hash(keys)
    print(f"\nWordlist: {len(keys)} keys, SHA256={wlh[:16]}")

    if args.tier in ("primary", "both"):
        print("\n" + "=" * 78)
        print(f"PRIMARY TIER: {len(PRIMARY_ORDERINGS)} orderings (Kryptos-relevant)")
        print("=" * 78)
        results = run_search(CT, PRIMARY_ORDERINGS, MISSING_LETTERS,
                             PERIODS, VARIANTS, keys, args.workers)
        write_manifest("primary", "K4_real", results,
                       {"wordlist_hash": wlh})

    if args.tier in ("secondary", "both"):
        print("\n" + "=" * 78)
        print(f"SECONDARY TIER: {len(SECONDARY_ORDERINGS)} orderings (broader)")
        print("=" * 78)
        results = run_search(CT, SECONDARY_ORDERINGS, MISSING_LETTERS,
                             PERIODS, VARIANTS, keys, args.workers)
        write_manifest("secondary", "K4_real", results,
                       {"wordlist_hash": wlh})


if __name__ == "__main__":
    main()
