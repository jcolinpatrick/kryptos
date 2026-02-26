#!/usr/bin/env python3
"""ANT-004: Progressive Difficulty Attack on Antipodes Segments

Kryptos uses progressively harder ciphers: K1/K2 = Vigenère, K3 = transposition,
K4 = ??? (likely multi-layer). If the Antipodes is a separate puzzle with
progressive difficulty, each segment might use a different method.

The Antipodes has two natural streams defined by the SPACE delimiter:
  Stream Alpha: K3+K4 (433 chars, before SPACE) — transposition + ???
  Stream Beta:  K1+K2 (432 chars, after SPACE) — Vigenère (PALIMPSEST/ABSCISSA)

This script attacks EACH stream independently with multiple method tiers:

Tier 1: Vigenère/Beaufort with ALL dictionary keywords (both KA and AZ)
  - Period scan IC → chi-squared key recovery for best periods
  - Every keyword from wordlist as repeating key
  - Running key from the OTHER stream's plaintext

Tier 2: Columnar transposition + Vigenère cascade
  - For widths matching Antipodes row widths (32-36), plus 2-40
  - De-transpose, then try Vigenère with recovered/dictionary keys
  - Also try: transpose first, THEN Vigenère (reverse order)

Tier 3: Running key from reference texts
  - K3 plaintext as running key for K4
  - K1+K2 plaintext as running key for stream alpha
  - Carter "Wonderful Things" passage
  - Reversed plaintexts

Tier 4: Width-aligned operations
  - The Antipodes row widths (32-36) may define a grid
  - Try operations aligned to actual row boundaries
  - Rail fence at various depths
  - Disrupted transposition with Antipodes-specific widths

Search space: ~5-10M configs total
Expected runtime: 3-6 hours with 28 workers

Usage:
    PYTHONPATH=src python3 -u jobs/pending/ant_004_progressive.py --workers 28
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from collections import Counter
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
RESULTS_DIR = ROOT / "results" / "ant_004"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
SUMMARY_FILE = ROOT / "reports" / "ant_004_progressive.summary.json"
QUADGRAM_FILE = ROOT / "data" / "english_quadgrams.json"
WORDLIST_FILE = ROOT / "wordlists" / "english.txt"
THEMATIC_FILE = ROOT / "wordlists" / "thematic_keywords.txt"

# ── Alphabets ────────────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}

# ── Antipodes ciphertext segments ────────────────────────────────────────────

K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOE"
    "TFOLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLB"
    "TEEFOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"
    "AECTDDHILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"
    "ECDMRIPFEIMEHNLSSTTRTVDOHW"
)
K4_CT = CT
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"

# Full K2 CT (Antipodes version — E at pos 114 for UNDERGROUND)
K2_CT = (
    "VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNAQZGZLECGYUXUEENJTBJLBQCETBJDFHRR"
    "YIZETKZEMVDUFKSJHKFWHKUWQLSZFTIHHDDDUVHDWKBFUFPWNTDFIYCUQZERE"
    "EVLDKFEZMOQQJLTTUGSYQPFEUNLAVIDXFLGGTEZFKZBSFDQVGOGIPUFXHHDRKF"
    "FHQNTGPUAECNUVPDJMQCLQUMUNEDFQELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE"
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKPDQUMEBEDMHDAFMJGZNUPLGEWJLLAETG"
)

# Antipodes row widths (for width-aligned operations)
ANTIPODES_ROW_WIDTHS = [
    34,33,35,34,34,34,34,35,33,33,  # rows 1-10
    34,35,33,34,33,32,33,34,34,33,  # rows 11-20
    34,34,33,33,33,33,35,33,34,34,  # rows 21-30
    34,34,35,36,33,33,34,34,34,34,  # rows 31-40
    32,32,33,34,34,33,35,            # rows 41-47
]

# Known plaintexts
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELD"
    "XTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGROUNDTOANUNKNOWNLOCATION"
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

# Streams
STREAM_ALPHA = K3_CT + K4_CT   # 433 chars
STREAM_BETA = K1_CT + K2_CT    # 63 + 370 = 433 chars

# ── Crib precomputation for K4 ──────────────────────────────────────────────

CRIB_SORTED = sorted(CRIB_DICT.items())
CPOS = [p for p, _ in CRIB_SORTED]

def _precompute_expected():
    results = {}
    ct_ints_ka = [KA_IDX[CT[p]] for p in CPOS]
    ct_ints_az = [ord(CT[p]) - 65 for p in CPOS]
    pt_chars = [c for _, c in CRIB_SORTED]
    pt_ints_ka = [KA_IDX[c] for c in pt_chars]
    pt_ints_az = [ord(c) - 65 for c in pt_chars]
    for var in (CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT):
        kr = KEY_RECOVERY[var]
        for alph_name, ct_ints, pt_ints in [("ka", ct_ints_ka, pt_ints_ka),
                                             ("az", ct_ints_az, pt_ints_az)]:
            expected = [kr(ct_ints[i], pt_ints[i]) % MOD for i in range(len(CPOS))]
            results[(var, alph_name)] = expected
    return results

EXPECTED = _precompute_expected()

# ── English frequency table ─────────────────────────────────────────────────

ENGLISH_FREQ = [0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228,
                0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025,
                0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987,
                0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,
                0.01974, 0.00074]

# ── Common words for detection ──────────────────────────────────────────────

COMMON_WORDS_7PLUS = {
    "BETWEEN", "ABSENCE", "NUANCE", "ILLUSION", "INVISIBLE", "POSSIBLE",
    "MAGNETIC", "INFORMATION", "GATHERED", "TRANSMITTED", "UNDERGROUND",
    "UNKNOWN", "LOCATION", "LANGLEY", "BURIED", "SOMEWHERE", "MESSAGE",
    "DEGREES", "MINUTES", "SECONDS", "CHAMBER", "PASSAGE", "REMAINS",
    "SLOWLY", "DESPERATELY", "ANYTHING", "CLEARLY", "TREMBLING",
    "FLICKERING", "CANDLE", "DOORWAY", "ENCUMBERED", "WONDERFUL",
    "DISCOVERY", "ANCIENT", "TUTANKHAMUN", "TREASURE", "OPENING",
    "POSITION", "NORTHEAST", "BEARING", "DIRECTION", "COMPASS",
    "LATITUDE", "LONGITUDE", "MERIDIAN", "EQUATORIAL", "SANBORN",
    "KRYPTOS", "SCHEIDT", "SCULPTURE", "TABLEAU", "ALPHABET",
    "DECRYPT", "ENCIPHER", "PLAINTEXT", "CIPHERTEXT",
    "SPECIAL", "THROUGH", "WITHOUT", "ANOTHER", "BECAUSE", "AGAINST",
    "HOWEVER", "NOTHING", "EVERYTHING", "SOMETHING", "ALREADY",
}


def count_long_words(text: str) -> int:
    """Count common English words >=7 chars found in text."""
    count = 0
    for w in COMMON_WORDS_7PLUS:
        if w in text:
            count += 1
    return count


# ── Core crypto functions ───────────────────────────────────────────────────

def decrypt_vig(ct: str, key_ints: List[int], variant: CipherVariant,
                alph: str, alph_idx: Dict[str, int]) -> str:
    fn = DECRYPT_FN[variant]
    return "".join(
        alph[fn(alph_idx[ct[i]], key_ints[i % len(key_ints)]) % MOD]
        for i in range(len(ct))
    )


def chi_squared_recover(ct: str, period: int,
                         alph_idx: Dict[str, int]) -> Tuple[List[int], float]:
    """Chi-squared Vigenère key recovery."""
    n = len(ct)
    key = []
    total_chi = 0.0
    for col in range(period):
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
    return key, total_chi / period if period > 0 else 0


def columnar_decipher(ct: str, width: int, col_order: List[int]) -> str:
    """Decipher columnar transposition."""
    n = len(ct)
    nrows = math.ceil(n / width)
    full_cols = n - (nrows - 1) * width

    col_lengths = []
    for col_idx in col_order:
        col_lengths.append(nrows if col_idx < full_cols else nrows - 1)

    columns = {}
    pos = 0
    for i, rank in enumerate(col_order):
        length = col_lengths[i]
        columns[rank] = ct[pos:pos + length]
        pos += length

    result = []
    for row in range(nrows):
        for col in range(width):
            if col in columns and row < len(columns[col]):
                result.append(columns[col][row])
    return "".join(result)


def keyword_to_column_order(keyword: str) -> List[int]:
    indexed = sorted(enumerate(keyword), key=lambda x: (x[1], x[0]))
    order = [0] * len(keyword)
    for rank, (orig_idx, _) in enumerate(indexed):
        order[orig_idx] = rank
    return order


def rail_fence_decipher(ct: str, rails: int) -> str:
    """Decipher rail fence cipher."""
    n = len(ct)
    if rails <= 1 or rails >= n:
        return ct

    # Calculate lengths per rail
    cycle = 2 * (rails - 1)
    rail_lens = [0] * rails
    for i in range(n):
        rail = i % cycle
        if rail >= rails:
            rail = cycle - rail
        rail_lens[rail] += 1

    # Extract rails
    rail_texts = []
    pos = 0
    for r in range(rails):
        rail_texts.append(ct[pos:pos + rail_lens[r]])
        pos += rail_lens[r]

    # Reconstruct
    result = [''] * n
    rail_pos = [0] * rails
    for i in range(n):
        rail = i % cycle
        if rail >= rails:
            rail = cycle - rail
        result[i] = rail_texts[rail][rail_pos[rail]]
        rail_pos[rail] += 1

    return "".join(result)


# ── Worker functions ────────────────────────────────────────────────────────

_ngram_scorer = None


def _init_worker():
    global _ngram_scorer
    _ngram_scorer = NgramScorer.from_file(str(QUADGRAM_FILE))


def _worker_tier1(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Tier 1: Vigenère/Beaufort keyword on a target segment."""
    keyword = item["keyword"]
    variant = item["variant"]
    alph_name = item["alph"]
    target_name = item["target"]
    target_ct = item["target_ct"]

    alph = KA if alph_name == "ka" else AZ
    alph_idx = KA_IDX if alph_name == "ka" else AZ_IDX

    for c in keyword:
        if c not in alph_idx:
            return None

    key_ints = [alph_idx[c] for c in keyword]
    pt = decrypt_vig(target_ct, key_ints, variant, alph, alph_idx)

    pt_ic = ic(pt)

    # Fast reject
    if pt_ic < 0.045:
        # For K4, still check cribs
        if target_name == "k4":
            expected = EXPECTED[(variant, alph_name)]
            key_len = len(key_ints)
            crib_score = sum(1 for i, pos in enumerate(CPOS)
                            if key_ints[pos % key_len] == expected[i])
            if crib_score <= NOISE_FLOOR:
                return None
        else:
            return None

    result = {
        "tier": 1,
        "keyword": keyword,
        "variant": variant.name,
        "alph": alph_name,
        "target": target_name,
        "ic": round(pt_ic, 5),
    }

    # Crib score for K4
    if target_name == "k4":
        expected = EXPECTED[(variant, alph_name)]
        key_len = len(key_ints)
        crib_score = sum(1 for i, pos in enumerate(CPOS)
                        if key_ints[pos % key_len] == expected[i])
        result["crib_score"] = crib_score

    # Word detection
    words = count_long_words(pt)
    result["words"] = words

    # Quadgram
    if _ngram_scorer and len(pt) >= 4:
        result["quadgram"] = round(_ngram_scorer.score(pt) / len(pt), 4)

    result["pt_preview"] = pt[:80]
    return result


def _worker_tier2(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Tier 2: Columnar transposition + Vigenère cascade."""
    width = item["width"]
    col_order = item["col_order"]
    trans_kw = item["trans_kw"]
    target_ct = item["target_ct"]
    target_name = item["target"]
    order = item.get("order", "trans_then_vig")  # or "vig_then_trans"

    if order == "trans_then_vig":
        # De-transpose first
        dt = columnar_decipher(target_ct, width, col_order)
        if not dt or len(dt) != len(target_ct):
            return None

        dt_ic = ic(dt)
        if dt_ic < 0.038:  # Below random, skip
            return None

        result = {
            "tier": 2,
            "width": width,
            "trans_kw": trans_kw,
            "target": target_name,
            "order": order,
            "dt_ic": round(dt_ic, 5),
        }

        # If IC elevated, try Vigenère key recovery
        if dt_ic > 0.042:
            # Try key recovery for best periods
            for period in [1, 3, 5, 7, 8, 10, 13, 26]:
                key_az, chi = chi_squared_recover(dt, period, AZ_IDX)
                fn = DECRYPT_FN[CipherVariant.VIGENERE]
                pt = "".join(AZ[fn(AZ_IDX[dt[i]], key_az[i % period]) % 26]
                             for i in range(len(dt)))
                pt_ic = ic(pt)
                if pt_ic > 0.050:
                    result[f"vig_p{period}_ic"] = round(pt_ic, 5)
                    result[f"vig_p{period}_key"] = "".join(AZ[k] for k in key_az)
                    words = count_long_words(pt)
                    result[f"vig_p{period}_words"] = words
                    if _ngram_scorer:
                        result[f"vig_p{period}_qg"] = round(
                            _ngram_scorer.score(pt) / len(pt), 4)
                    if pt_ic > 0.055 or words >= 3:
                        result[f"vig_p{period}_pt"] = pt[:80]

        # Check if any Vigenère recovery succeeded
        has_signal = any(k.endswith("_ic") and k.startswith("vig_")
                        and result[k] > 0.055 for k in result)
        if not has_signal and dt_ic < 0.048:
            return None

        return result

    else:  # vig_then_trans
        # This path handled in tier2b
        return None


def _worker_tier3(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Tier 3: Running key from reference texts."""
    target_ct = item["target_ct"]
    target_name = item["target"]
    rk_source = item["rk_source"]
    rk_name = item["rk_name"]
    offset = item["offset"]
    variant = item["variant"]
    alph_name = item["alph"]
    direction = item.get("direction", "forward")

    alph = KA if alph_name == "ka" else AZ
    alph_idx = KA_IDX if alph_name == "ka" else AZ_IDX

    n = len(target_ct)

    # Build running key
    rk = rk_source
    if direction == "reversed":
        rk = rk[::-1]

    if offset + n > len(rk):
        return None

    rk_segment = rk[offset:offset + n]
    key_ints = [alph_idx.get(c, 0) for c in rk_segment]

    fn = DECRYPT_FN[variant]
    pt = "".join(
        alph[fn(alph_idx[target_ct[i]], key_ints[i]) % MOD]
        for i in range(n)
    )

    pt_ic = ic(pt)
    words = count_long_words(pt)

    if pt_ic < 0.045 and words < 3:
        return None

    result = {
        "tier": 3,
        "target": target_name,
        "rk_name": rk_name,
        "offset": offset,
        "direction": direction,
        "variant": variant.name,
        "alph": alph_name,
        "ic": round(pt_ic, 5),
        "words": words,
    }

    if _ngram_scorer and len(pt) >= 4:
        result["quadgram"] = round(_ngram_scorer.score(pt) / len(pt), 4)

    result["pt_preview"] = pt[:80]
    return result


def _worker_tier4(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Tier 4: Width-aligned and rail fence operations."""
    op = item["op"]
    target_ct = item["target_ct"]
    target_name = item["target"]

    if op == "rail_fence":
        rails = item["rails"]
        dt = rail_fence_decipher(target_ct, rails)
    elif op == "columnar_width_aligned":
        width = item["width"]
        col_order = item["col_order"]
        dt = columnar_decipher(target_ct, width, col_order)
    else:
        return None

    if not dt:
        return None

    dt_ic = ic(dt)
    if dt_ic < 0.040:
        return None

    result = {
        "tier": 4,
        "op": op,
        "target": target_name,
        "dt_ic": round(dt_ic, 5),
    }

    if op == "rail_fence":
        result["rails"] = item["rails"]
    elif op == "columnar_width_aligned":
        result["width"] = item["width"]
        result["keyword"] = item.get("keyword", "?")

    # Quadgram
    if _ngram_scorer and len(dt) >= 4:
        result["quadgram"] = round(_ngram_scorer.score(dt) / len(dt), 4)

    # Word detection
    words = count_long_words(dt)
    result["words"] = words

    # Vigenère key recovery on de-transposed text
    if dt_ic > 0.042:
        for period in [1, 8, 10, 13]:
            key_az, chi = chi_squared_recover(dt, period, AZ_IDX)
            fn = DECRYPT_FN[CipherVariant.VIGENERE]
            pt = "".join(AZ[fn(AZ_IDX[dt[i]], key_az[i % period]) % 26]
                         for i in range(len(dt)))
            pt_ic = ic(pt)
            if pt_ic > 0.050:
                result[f"vig_p{period}_ic"] = round(pt_ic, 5)
                result[f"vig_p{period}_key"] = "".join(AZ[k] for k in key_az)
                if _ngram_scorer:
                    result[f"vig_p{period}_qg"] = round(
                        _ngram_scorer.score(pt) / len(pt), 4)
                if pt_ic > 0.055:
                    result[f"vig_p{period}_pt"] = pt[:80]

    result["dt_preview"] = dt[:80]
    return result


# ── Tier 2b: Transposition × keyword Vigenère cascade on K4 alone ────────

_TIER2B_KEYWORDS = None


def _load_tier2b_keywords() -> List[str]:
    """Load compact keyword list for Tier 2b cascade (~1800 words)."""
    words = set()
    with open(THEMATIC_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            w = line.upper()
            if all(c in AZ for c in w) and 3 <= len(w) <= 20:
                words.add(w)
    english = []
    with open(WORDLIST_FILE) as f:
        for line in f:
            w = line.strip().upper()
            if w and all(c in AZ for c in w) and 3 <= len(w) <= 15:
                english.append(w)
    english.sort(key=len)
    for w in english[:1500]:
        words.add(w)
    return sorted(words)


def _worker_tier2b(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Tier 2b: One transposition on K4 × all keywords × all variants.

    Each worker de-transposes K4 once, then sweeps all keywords through
    Vigenère/Beaufort/VarBeau in both KA and AZ space.
    """
    width = item["width"]
    col_order = item["col_order"]
    trans_kw = item["trans_kw"]

    # De-transpose K4 once
    dt = columnar_decipher(K4_CT, width, col_order)
    if not dt or len(dt) != CT_LEN:
        return None

    dt_ic = ic(dt)
    if dt_ic < 0.030:  # Very generous threshold — K4 IC is 0.036
        return None

    best_result = None
    best_metric = -999.0

    dt_ka = [KA_IDX.get(c, 0) for c in dt]
    dt_az = [ord(c) - 65 for c in dt]

    fn_vig = DECRYPT_FN[CipherVariant.VIGENERE]
    fn_bea = DECRYPT_FN[CipherVariant.BEAUFORT]
    fn_vb = DECRYPT_FN[CipherVariant.VAR_BEAUFORT]
    fns = [(CipherVariant.VIGENERE, fn_vig),
           (CipherVariant.BEAUFORT, fn_bea),
           (CipherVariant.VAR_BEAUFORT, fn_vb)]
    tested = 0
    n = CT_LEN

    # Pre-cache keyword integer arrays
    kw_cache_ka = {}
    kw_cache_az = {}
    for kw in _TIER2B_KEYWORDS:
        ka_valid = all(c in KA_IDX for c in kw)
        if ka_valid:
            kw_cache_ka[kw] = [KA_IDX[c] for c in kw]
        kw_cache_az[kw] = [ord(c) - 65 for c in kw]

    for kw in _TIER2B_KEYWORDS:
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

                # FAST PATH: IC via counting (no string construction)
                counts = [0] * 26
                for i in range(n):
                    pt_idx = fn(dt_ints[i], key_ints[i % kw_len]) % MOD
                    counts[pt_idx] += 1

                ic_sum = sum(c * (c - 1) for c in counts)
                pt_ic = ic_sum / (n * (n - 1)) if n > 1 else 0

                if pt_ic < 0.045:
                    continue

                # Build plaintext string for flagged configs only
                pt = "".join(
                    alph[fn(dt_ints[i], key_ints[i % kw_len]) % MOD]
                    for i in range(n)
                )

                words = count_long_words(pt)
                metric = pt_ic
                qg = -999.0
                if _ngram_scorer and n >= 4:
                    qg = _ngram_scorer.score(pt) / n
                    metric = pt_ic + (qg + 10) / 100

                if metric > best_metric:
                    best_metric = metric
                    best_result = {
                        "tier": "2b",
                        "trans_width": width,
                        "trans_kw": trans_kw,
                        "vig_kw": kw,
                        "variant": var.name,
                        "alph": alph_name,
                        "dt_ic": round(dt_ic, 5),
                        "pt_ic": round(pt_ic, 5),
                        "words": words,
                        "tested": tested,
                        "pt_preview": pt[:80],
                    }
                    if _ngram_scorer:
                        best_result["quadgram"] = round(qg, 4)

    if best_result is not None:
        best_result["configs_tested"] = tested
    return best_result


def generate_tier2b(keywords: List[str]) -> List[Dict[str, Any]]:
    """Generate transposition configs for K4-only cascade."""
    items = []
    seen = set()

    # Exhaustive perms for widths 2-9
    from itertools import permutations as perms
    for width in range(2, 10):
        for perm in perms(range(width)):
            key = (width, perm)
            if key not in seen:
                seen.add(key)
                items.append({
                    "width": width,
                    "col_order": list(perm),
                    "trans_kw": f"PERM_{''.join(str(x) for x in perm)}",
                })

    # Keyword-derived orderings
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
                    "trans_kw": kw,
                })

    # Identity and reverse
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
                    "trans_kw": f"{label}_{width}",
                })

    return items


# ── Work item generators ────────────────────────────────────────────────────

def load_keywords() -> List[str]:
    words = set()
    with open(THEMATIC_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            w = line.upper()
            if all(c in AZ for c in w) and len(w) >= 3:
                words.add(w)
    with open(WORDLIST_FILE) as f:
        for line in f:
            w = line.strip().upper()
            if w and all(c in AZ for c in w) and 3 <= len(w) <= 20:
                words.add(w)
    return sorted(words)


def generate_tier1(keywords: List[str]) -> List[Dict[str, Any]]:
    """Tier 1: Vigenère keyword sweep on both streams + K4 alone."""
    items = []
    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
    alphs = ["ka", "az"]
    targets = [
        ("k4", K4_CT),
        ("alpha", STREAM_ALPHA),
        ("beta", STREAM_BETA),
    ]
    for kw in keywords:
        for var in variants:
            for alph in alphs:
                for tname, tct in targets:
                    items.append({
                        "keyword": kw,
                        "variant": var,
                        "alph": alph,
                        "target": tname,
                        "target_ct": tct,
                    })
    return items


def generate_tier2(keywords: List[str]) -> List[Dict[str, Any]]:
    """Tier 2: Columnar transposition + Vigenère cascade."""
    items = []
    seen = set()
    targets = [
        ("k4", K4_CT),
        ("alpha", STREAM_ALPHA),
    ]

    for tname, tct in targets:
        # Exhaustive permutations for small widths
        from itertools import permutations as perms
        for width in range(2, 8):
            for perm in perms(range(width)):
                key = (tname, width, perm)
                if key not in seen:
                    seen.add(key)
                    items.append({
                        "width": width,
                        "col_order": list(perm),
                        "trans_kw": f"PERM_{''.join(str(x) for x in perm)}",
                        "target": tname,
                        "target_ct": tct,
                        "order": "trans_then_vig",
                    })

        # Keyword-derived orderings for widths 2-40
        for kw in keywords:
            w = len(kw)
            if 2 <= w <= 40:
                order = keyword_to_column_order(kw)
                key = (tname, w, tuple(order))
                if key not in seen:
                    seen.add(key)
                    items.append({
                        "width": w,
                        "col_order": order,
                        "trans_kw": kw,
                        "target": tname,
                        "target_ct": tct,
                        "order": "trans_then_vig",
                    })

        # Antipodes-specific widths (32-36) with identity/reverse
        for width in range(32, 37):
            for label, order in [("IDENTITY", list(range(width))),
                                  ("REVERSED", list(range(width-1, -1, -1)))]:
                key = (tname, width, tuple(order))
                if key not in seen:
                    seen.add(key)
                    items.append({
                        "width": width,
                        "col_order": order,
                        "trans_kw": f"{label}_{width}",
                        "target": tname,
                        "target_ct": tct,
                        "order": "trans_then_vig",
                    })

    return items


def generate_tier3() -> List[Dict[str, Any]]:
    """Tier 3: Running key from reference texts."""
    items = []
    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
    alphs = ["ka", "az"]

    # Running key sources
    rk_sources = [
        ("K3_PT", K3_PT),
        ("K2_PT", K2_PT),
        ("K1_PT", K1_PT),
        ("K1K2_PT", K1_PT + K2_PT),
        ("K3K2K1_PT", K3_PT + K2_PT + K1_PT),
        ("ALL_PT", K1_PT + K2_PT + K3_PT),
        ("ALL_PT_REV", (K1_PT + K2_PT + K3_PT)[::-1]),
        ("K3_PT_REV", K3_PT[::-1]),
        ("K2_PT_REV", K2_PT[::-1]),
    ]

    targets = [
        ("k4", K4_CT),
        ("alpha", STREAM_ALPHA),
    ]

    for tname, tct in targets:
        n = len(tct)
        for rk_name, rk_source in rk_sources:
            max_offset = len(rk_source) - n
            if max_offset < 0:
                continue
            # Sample offsets: 0, 1, ..., min(max_offset, 200) for short sources,
            # or step through for long sources
            step = max(1, max_offset // 200)
            for offset in range(0, max_offset + 1, step):
                for var in variants:
                    for alph in alphs:
                        for direction in ["forward", "reversed"]:
                            items.append({
                                "target_ct": tct,
                                "target": tname,
                                "rk_source": rk_source,
                                "rk_name": rk_name,
                                "offset": offset,
                                "variant": var,
                                "alph": alph,
                                "direction": direction,
                            })
    return items


def generate_tier4(keywords: List[str]) -> List[Dict[str, Any]]:
    """Tier 4: Width-aligned operations and rail fence."""
    items = []
    targets = [
        ("k4", K4_CT),
        ("alpha", STREAM_ALPHA),
    ]

    for tname, tct in targets:
        # Rail fence (depths 2-30)
        for rails in range(2, 31):
            items.append({
                "op": "rail_fence",
                "rails": rails,
                "target": tname,
                "target_ct": tct,
            })

        # Width-aligned columnar with Antipodes row widths
        for width in set(ANTIPODES_ROW_WIDTHS):
            # Identity and reverse
            for label, order in [("IDENTITY", list(range(width))),
                                  ("REVERSED", list(range(width-1, -1, -1)))]:
                items.append({
                    "op": "columnar_width_aligned",
                    "width": width,
                    "col_order": order,
                    "keyword": f"{label}_{width}",
                    "target": tname,
                    "target_ct": tct,
                })
            # Keyword-derived
            for kw in keywords:
                if len(kw) == width:
                    order = keyword_to_column_order(kw)
                    items.append({
                        "op": "columnar_width_aligned",
                        "width": width,
                        "col_order": order,
                        "keyword": kw,
                        "target": tname,
                        "target_ct": tct,
                    })

    return items


# ── Main ─────────────────────────────────────────────────────────────────────

def run_tier(name: str, items: List, worker_fn, pool_args: Dict,
             results_dir: Path) -> Tuple[List, Dict]:
    """Run a tier with pool and return hits + stats."""
    print(f"\n{'='*70}")
    print(f"Tier {name}: {len(items):,} configs")
    print("=" * 70)
    sys.stdout.flush()

    if not items:
        return [], {"configs": 0, "hits": 0, "elapsed_s": 0}

    hits = []
    t0 = time.time()

    with Pool(**pool_args) as pool:
        chunk = max(1, len(items) // (pool_args["processes"] * 100))
        done = 0
        for result in pool.imap_unordered(worker_fn, items, chunksize=chunk):
            done += 1
            if done % 500_000 == 0:
                elapsed = time.time() - t0
                rate = done / elapsed
                print(f"  Tier {name}: [{done:,}/{len(items):,}] "
                      f"{done/len(items)*100:.1f}% | {rate:.0f}/s | "
                      f"hits={len(hits)}")
                sys.stdout.flush()
            if result is not None:
                hits.append(result)
                # Signal detection
                ic_val = result.get("ic", result.get("dt_ic", 0))
                crib = result.get("crib_score", 0)
                words = result.get("words", 0)
                if crib >= 18:
                    print(f"\n  *** SIGNAL crib={crib}: {result} ***")
                    sys.stdout.flush()
                if ic_val > 0.060:
                    print(f"\n  *** HIGH IC={ic_val:.4f}: "
                          f"{result.get('keyword', result.get('trans_kw', '?'))} "
                          f"target={result.get('target', '?')} ***")
                    sys.stdout.flush()
                if words >= 5:
                    print(f"\n  *** WORDS={words}: "
                          f"{result.get('pt_preview', result.get('dt_preview', ''))[:60]} ***")
                    sys.stdout.flush()

    elapsed = time.time() - t0
    stats = {"configs": len(items), "hits": len(hits), "elapsed_s": round(elapsed, 1)}

    # Save hits
    hits_file = results_dir / f"tier_{name}_hits.jsonl"
    with open(hits_file, "w") as f:
        for h in sorted(hits, key=lambda x: x.get("ic", x.get("dt_ic", 0)),
                        reverse=True):
            f.write(json.dumps(h, default=str) + "\n")

    print(f"  Tier {name} complete: {len(hits)} hits in {elapsed:.1f}s "
          f"({elapsed/60:.1f}min)")
    return hits, stats


def main():
    parser = argparse.ArgumentParser(
        description="ANT-004: Progressive difficulty attack on Antipodes")
    parser.add_argument("--workers", type=int, default=28)
    parser.add_argument("--tier", type=str, default="all",
                        choices=["all", "1", "2", "3", "4"])
    args = parser.parse_args()

    print("=" * 70)
    print("ANT-004: Progressive Difficulty Attack on Antipodes Segments")
    print("=" * 70)
    print(f"Workers: {args.workers}")
    print(f"K4: {CT_LEN} chars | Stream Alpha: {len(STREAM_ALPHA)} chars "
          f"| Stream Beta: {len(STREAM_BETA)} chars")
    print()

    t0 = time.time()
    keywords = load_keywords()
    print(f"Loaded {len(keywords)} keywords")

    pool_args = {"processes": args.workers, "initializer": _init_worker}
    all_hits = []
    all_stats = {}

    # ── Tier 1: Vigenère keyword sweep ──
    if args.tier in ("all", "1"):
        items = generate_tier1(keywords)
        hits, stats = run_tier("1_vig", items, _worker_tier1, pool_args, RESULTS_DIR)
        all_hits.extend(hits)
        all_stats["tier1"] = stats

    # ── Tier 2: Columnar + Vigenère cascade (chi-squared recovery) ──
    if args.tier in ("all", "2"):
        items = generate_tier2(keywords)
        hits, stats = run_tier("2_trans", items, _worker_tier2, pool_args, RESULTS_DIR)
        all_hits.extend(hits)
        all_stats["tier2"] = stats

    # ── Tier 2b: Transposition × keyword Vigenère cascade on K4 (THE BIG ONE) ──
    if args.tier in ("all", "2"):
        global _TIER2B_KEYWORDS
        _TIER2B_KEYWORDS = _load_tier2b_keywords()
        items_2b = generate_tier2b(keywords)
        n_vig = len(_TIER2B_KEYWORDS) * 6
        print(f"\n{'='*70}")
        print("Tier 2b: Transposition × Keyword Cascade on K4")
        print(f"  Transposition configs: {len(items_2b):,}")
        print(f"  Vig keywords per trans: {n_vig:,}")
        print(f"  Effective configs: ~{len(items_2b) * n_vig:,}")
        print("=" * 70)
        sys.stdout.flush()

        hits_2b = []
        t_2b = time.time()
        with Pool(**pool_args) as pool:
            done = 0
            for result in pool.imap_unordered(_worker_tier2b, items_2b, chunksize=1):
                done += 1
                if done % 1000 == 0:
                    elapsed = time.time() - t_2b
                    rate = done / elapsed
                    eta = (len(items_2b) - done) / rate if rate > 0 else 0
                    print(f"  Tier 2b: [{done:,}/{len(items_2b):,}] "
                          f"{done/len(items_2b)*100:.1f}% | {rate:.1f}/s | "
                          f"ETA {eta:.0f}s ({eta/60:.1f}min) | hits={len(hits_2b)}")
                    sys.stdout.flush()
                if result is not None:
                    hits_2b.append(result)
                    if result.get("pt_ic", 0) > 0.060:
                        print(f"\n  *** HIGH PT IC: {result['pt_ic']:.4f} "
                              f"trans={result['trans_kw']} vig={result['vig_kw']} ***")
                        sys.stdout.flush()

        elapsed_2b = time.time() - t_2b
        all_stats["tier2b"] = {
            "configs": len(items_2b),
            "effective_configs": len(items_2b) * n_vig,
            "hits": len(hits_2b),
            "elapsed_s": round(elapsed_2b, 1),
        }
        all_hits.extend(hits_2b)
        with open(RESULTS_DIR / "tier_2b_hits.jsonl", "w") as f:
            for h in sorted(hits_2b, key=lambda x: x.get("pt_ic", 0), reverse=True):
                f.write(json.dumps(h, default=str) + "\n")
        print(f"  Tier 2b complete: {len(hits_2b)} hits in {elapsed_2b:.1f}s "
              f"({elapsed_2b/60:.1f}min)")

    # ── Tier 3: Running key ──
    if args.tier in ("all", "3"):
        items = generate_tier3()
        hits, stats = run_tier("3_rk", items, _worker_tier3, pool_args, RESULTS_DIR)
        all_hits.extend(hits)
        all_stats["tier3"] = stats

    # ── Tier 4: Width-aligned + rail fence ──
    if args.tier in ("all", "4"):
        items = generate_tier4(keywords)
        hits, stats = run_tier("4_width", items, _worker_tier4, pool_args, RESULTS_DIR)
        all_hits.extend(hits)
        all_stats["tier4"] = stats

    # ── Overall summary ──
    total_elapsed = time.time() - t0
    total_configs = sum(s.get("configs", 0) for s in all_stats.values())
    total_hits = len(all_hits)

    print(f"\n{'='*70}")
    print("ANT-004 OVERALL RESULTS")
    print("=" * 70)
    print(f"Total configs:  {total_configs:,}")
    print(f"Total hits:     {total_hits}")
    print(f"Total elapsed:  {total_elapsed:.1f}s ({total_elapsed/60:.1f}min)")
    for tier, stats in sorted(all_stats.items()):
        print(f"  {tier}: {stats['configs']:,} configs, "
              f"{stats['hits']} hits, {stats['elapsed_s']:.1f}s")

    if all_hits:
        # Top by IC
        top = sorted(all_hits,
                     key=lambda h: h.get("ic", h.get("dt_ic", 0)),
                     reverse=True)[:15]
        print("\n  Top 15 by IC:")
        for h in top:
            tier = h.get("tier", "?")
            ic_val = h.get("ic", h.get("dt_ic", 0))
            target = h.get("target", "?")
            preview = h.get("pt_preview", h.get("dt_preview", ""))[:50]
            extra = ""
            if "crib_score" in h:
                extra += f" crib={h['crib_score']}"
            if "words" in h:
                extra += f" words={h['words']}"
            if "quadgram" in h:
                extra += f" qg={h['quadgram']:.3f}"
            print(f"    T{tier} | IC={ic_val:.4f} | {target} |{extra}")
            print(f"         {preview}")

    # Save summary
    summary = {
        "experiment": "ant_004_progressive",
        "total_configs": total_configs,
        "total_hits": total_hits,
        "tier_stats": all_stats,
        "elapsed_s": round(total_elapsed, 1),
        "workers": args.workers,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    SUMMARY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SUMMARY_FILE, "w") as f:
        json.dump(summary, f, indent=2)

    print(f"\nRESULT: configs={total_configs:,} hits={total_hits} "
          f"elapsed={total_elapsed:.1f}s")
    print(f"Summary: {SUMMARY_FILE}")


if __name__ == "__main__":
    main()
