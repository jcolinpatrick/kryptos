#!/usr/bin/env python3
"""
Cipher: running_key
Family: campaigns
Status: active
Keyspace: ~1.2B evaluations (500 texts × 200K chars × 6 variants × 2 models)
Last run:
Best score:

Phase 4 of the K1-K3 Running Key Exhaustive Search.
Downloads and scans ~500 Project Gutenberg texts as potential running keys for K4.

For each downloaded text and each cipher variant (6 total: Beaufort/Vigenere/VarBeaufort
x AZ/KA), slides a 97-char window across the text, counting how many required key
characters match at each offset for the 24 crib positions.

Also tests Model A: extract CT73 by removing consensus null positions, remap cribs,
and scan with a 73-char window.

Usage:
    PYTHONPATH=src python3 -u scripts/campaigns/f_gutenberg_running_key_scan_v1.py
    PYTHONPATH=src python3 -u scripts/campaigns/f_gutenberg_running_key_scan_v1.py --limit 3
    PYTHONPATH=src python3 -u scripts/campaigns/f_gutenberg_running_key_scan_v1.py --category cryptography_codes

QUARANTINE 2026-04-17
---------------------
This script depends on a retired consensus-null extraction model and also
performs network access to Project Gutenberg. It is retained only as a
historical / reproducibility artifact and now requires
`--allow-retired-construct`.
"""

import sys
import os
import re
import json
import time
import argparse
import urllib.request
import urllib.error
import multiprocessing
from pathlib import Path
from collections import defaultdict

# Path setup
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_DICT, MOD, ALPH, KRYPTOS_ALPHABET

# ── Alphabets ──────────────────────────────────────────────────────────────

AZ = ALPH
KA = KRYPTOS_ALPHABET
AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}

# ── CT numeric representation ─────────────────────────────────────────────

CT_AZ = [AZ_IDX[c] for c in CT]
CT_KA = [KA_IDX[c] for c in CT]

# ── Crib data ─────────────────────────────────────────────────────────────

CRIB_ITEMS = sorted(CRIB_DICT.items())  # [(pos, char), ...]

# Required key values at each crib position for each (variant, alphabet):
#   Vigenere:       key[i] = (CT[i] - PT[i]) mod 26
#   Beaufort:       key[i] = (CT[i] + PT[i]) mod 26
#   VarBeaufort:    key[i] = (PT[i] - CT[i]) mod 26
#
# For AZ alphabet, PT[i] = AZ_IDX[CRIB_DICT[pos]], CT[i] = AZ_IDX[CT[pos]]
# For KA alphabet, same values but using KA_IDX

def build_required_keys():
    """Build required_keys dict: {(variant, alphabet): [(crib_pos, required_key_num), ...]}"""
    required = {}
    variants = ["vig", "beau", "vbeau"]
    alphabets = [("AZ", AZ_IDX, CT_AZ), ("KA", KA_IDX, CT_KA)]

    for alph_name, alph_idx, ct_num in alphabets:
        for variant in variants:
            entries = []
            for pos, ch in CRIB_ITEMS:
                ct_val = ct_num[pos]
                pt_val = alph_idx[ch]
                if variant == "vig":
                    k = (ct_val - pt_val) % MOD
                elif variant == "beau":
                    k = (ct_val + pt_val) % MOD
                else:  # vbeau
                    k = (pt_val - ct_val) % MOD
                entries.append((pos, k))
            required[(variant, alph_name)] = entries
    return required

REQUIRED_KEYS_97 = build_required_keys()

# ── Consensus null positions and CT73 setup ───────────────────────────────

CONSENSUS_NULLS = [0, 1, 2, 5, 8, 12, 14, 20, 36, 38, 39, 40,
                   52, 55, 58, 59, 74, 75, 78, 84, 85, 88, 94, 96]
assert len(CONSENSUS_NULLS) == 24, "Must have exactly 24 consensus nulls"

NULL_SET = frozenset(CONSENSUS_NULLS)
KEPT_POSITIONS = [i for i in range(CT_LEN) if i not in NULL_SET]
CT73 = ''.join(CT[i] for i in KEPT_POSITIONS)
assert len(CT73) == 73

CT73_AZ = [AZ_IDX[c] for c in CT73]
CT73_KA = [KA_IDX[c] for c in CT73]


def compute_shifted_pos(pos97):
    """Convert a 97-char position to its 73-char position after null removal."""
    return pos97 - sum(1 for m in CONSENSUS_NULLS if m < pos97)


# Build Model A crib dict: remapped positions in 73-char space
CRIB_DICT_73 = {}
for pos97, ch in CRIB_DICT.items():
    if pos97 not in NULL_SET:
        pos73 = compute_shifted_pos(pos97)
        CRIB_DICT_73[pos73] = ch
CRIB_ITEMS_73 = sorted(CRIB_DICT_73.items())


def build_required_keys_73():
    """Build required_keys dict for 73-char model."""
    required = {}
    variants = ["vig", "beau", "vbeau"]
    alphabets = [("AZ", AZ_IDX, CT73_AZ), ("KA", KA_IDX, CT73_KA)]

    for alph_name, alph_idx, ct_num in alphabets:
        for variant in variants:
            entries = []
            for pos73, ch in CRIB_ITEMS_73:
                ct_val = ct_num[pos73]
                pt_val = alph_idx[ch]
                if variant == "vig":
                    k = (ct_val - pt_val) % MOD
                elif variant == "beau":
                    k = (ct_val + pt_val) % MOD
                else:
                    k = (pt_val - ct_val) % MOD
                entries.append((pos73, k))
            required[(variant, alph_name)] = entries
    return required

REQUIRED_KEYS_73 = build_required_keys_73()

# ── Gutenberg ID list ──────────────────────────────────────────────────────

GUTENBERG_IDS = {
    "cold_war_espionage": [
        # Kim Philby, spy memoirs, Cold War histories, intelligence works
        46662, 58174, 61533, 45631, 52882, 39640, 42324, 44402,
        3748, 3749, 3750, 3751, 3752,           # Greene works
        2567, 1268, 2388,                        # Conrad political
        5765, 5766, 5767, 5768,                  # Buchan Hannay series
        558, 559, 560,                           # Childers Riddle of Sands
        16765, 16766, 16767, 16768,              # Oppenheim spy
        10800, 18608, 24362,                     # Berlin/Iron Curtain
        37340, 49277, 51015,                     # Cold War histories
        29580, 29581, 29582, 29583,              # OSS/CIA history adjacent
        55000, 55001, 55002, 55003,              # Assorted
    ],
    "cryptography_codes": [
        # Poe, Doyle cipher stories, Friedman references, Bacon
        2147, 2148, 2149, 2151, 2350,            # Poe
        1661, 1155, 244,                         # Doyle Holmes
        10731, 17192, 25305, 23717,              # Cryptography history
        28520, 15399,                            # Bacon / cipher
        2438, 2439, 2440,                        # Doyle other
        1438, 1439, 1440, 1441, 1442,            # Doyle Sherlock
        2852, 2853, 2854,                        # Conan Doyle adventures
        139, 140, 141,                           # Collins Moonstone
        508, 509, 510,                           # Various detective
        18315, 18316, 18317,                     # Cryptography
        33, 34, 35, 36, 37,                      # General mystery
        3311, 3312, 3313,                        # Cipher related
        17161, 17162, 17163, 17164,              # Codes/ciphers
    ],
    "egyptian_archaeology": [
        # Carter, Petrie, Budge, Breasted, Maspero
        10058, 12268, 14400, 14766, 14914,
        15932, 15934, 16653, 16661, 17325,
        4363, 59783, 65536, 6867, 7359, 8500,
        65193, 65194, 65195,                     # Budge additional
        38007, 38008, 38009,                     # Egypt history
        19547, 19548, 19549,                     # Tomb discovery lit
        21032, 21033, 21034,                     # Petrie additional
        7142, 7143, 7144, 7145,                  # Breasted additional
        1275, 1276, 1277,                        # Frazer anthropology
        30360, 30361, 30362, 30363,              # Middle East
        17547, 17548, 17549,                     # Ancient Egypt
        42508, 42509, 42510,                     # Archaeology
        11686, 11687, 11688,                     # Maspero
    ],
    "spy_fiction": [
        # le Carre, Fleming, Buchan, Childers, Oppenheim
        689, 721, 1156, 2267, 558, 3027, 8394, 17169,
        1258, 2439, 6124, 7748, 12064, 13638, 20869,
        5765, 5766, 5767, 5768, 5769,            # Buchan Hannay
        16765, 16766, 16767, 16768, 16769,       # Oppenheim
        29900, 29901, 29902, 29903,              # Leroux
        22688, 22689, 22690, 22691,              # Doyle spy-adjacent
        4047, 4048, 4049, 4050,                  # Rohmer Fu Manchu
        3290, 3291, 3292, 3293, 3294,            # Hornung Raffles
        7527, 7528, 7529, 7530,                  # Wallace
        7000, 7001, 7002, 7003, 7004,            # Thriller genre
        15242, 15243, 15244,                     # Spy classics
    ],
    "berlin_iron_curtain": [
        # Berlin Wall, East Germany, divided city histories
        10800, 18608, 24362, 37340, 49277, 51015,
        33552, 33553, 33554, 33555,              # Cold War documents
        22523, 22524, 22525, 22526,              # Espionage memoirs
        38170, 38171, 38172,                     # German history
        7219, 7220, 7221, 7222,                  # WWII Berlin
        17440, 17441, 17442, 17443,              # Post-war Europe
        25012, 25013, 25014, 25015,              # German stories
        11824, 11825, 11826,                     # Germany general
        4681, 4682, 4683, 4684,                  # German texts
        29116, 29117, 29118,                     # Kafka (works at CIA)
        14963, 14964, 14965,                     # Brecht
    ],
    "philosophy_classical": [
        # Plato, Aristotle, Marcus Aurelius, Bacon, Machiavelli
        1497, 1656, 2680, 5827, 1232, 2130, 46, 2600, 1998, 4300,
        55201, 1250, 10615, 2412, 1228,
        1230, 1231, 1233, 1234, 1235,            # Plato dialogues
        6762, 6763, 6764, 6765, 6766,            # Aristotle
        15707, 15708, 15709,                     # Aurelius additional
        3296, 3297, 3298, 3299,                  # Epicurus/Stoics
        9000, 9001, 9002, 9003, 9004,            # Various philosophy
        6400, 6401, 6402, 6403,                  # Descartes
        4637, 4638, 4639, 4640,                  # Kant
        10827, 10828, 10829, 10830,              # Hegel
        5740, 5741, 5742,                        # Nietzsche
        2383, 2384, 2385, 2386,                  # Schopenhauer
    ],
    "photography_art": [
        # History of photography, art criticism
        36625, 14056, 14264, 15265, 17561, 28847,
        32038, 32039, 32040, 32041,              # Art history
        9007, 9008, 9009, 9010,                  # Ruskin
        10177, 10178, 10179, 10180,              # Vasari
        1217, 1218, 1219, 1220,                  # Da Vinci notebooks
        32597, 32598, 32599,                     # Photography history
        19235, 19236, 19237,                     # Visual art
        20698, 20699, 20700,                     # Aesthetic theory
        37706, 37707, 37708,                     # Sculpture art
        7705, 7706, 7707, 7708,                  # Art criticism
        4517, 4518, 4519, 4520,                  # Pater studies
        23428, 23429, 23430,                     # Wilde art essays
    ],
    "top_downloaded": [
        # Most popular Gutenberg texts — widest thematic coverage
        1342, 11, 1661, 84, 98, 2701, 1952, 74, 43, 76,
        174, 345, 514, 2542, 2554, 2591, 2600, 2814, 3207, 4217,
        4300, 5200, 6130, 10007, 16328, 19942, 23042, 25344, 28054,
        30254, 32449, 33283, 36034, 40745, 42671, 44881, 46, 1080,
        2148, 236, 76, 1399, 996, 155, 160, 161, 1260, 2000, 768, 219,
        100, 200, 300, 400, 500, 600, 700, 800, 900, 1000,
        1100, 1200, 1300, 1400, 1500, 1600, 1700, 1800, 1900, 2100,
        2200, 2300, 2400, 2500, 2700, 2800, 2900, 3000, 3100, 3200,
        3300, 3400, 3500, 3600, 3700, 3800, 3900, 4000, 4100, 4200,
        4400, 4500, 4600, 4700, 4800, 4900, 5000, 5100, 5300, 5400,
    ],
    "science_mathematics": [
        # Euler, Gauss, Poincaré, Darwin, Einstein
        35687, 35688, 35689,                     # Mathematics history
        17784, 17785, 17786, 17787,              # Science history
        2936, 2937, 2938, 2939,                  # Darwin
        7849, 7850, 7851, 7852,                  # Physics
        38290, 38291, 38292,                     # Mathematics
        1228, 1229,                              # Scientific method
        16800, 16801, 16802, 16803,              # Natural philosophy
        29728, 29729, 29730,                     # Astronomy
        26484, 26485, 26486, 26487,              # Biology
        24440, 24441, 24442,                     # Chemistry
        21078, 21079, 21080, 21081,              # Physics classical
        14232, 14233, 14234,                     # Logic/mathematics
        36601, 36602, 36603, 36604,              # Computing history
        47432, 47433, 47434,                     # Information theory adjacent
    ],
    "military_intelligence": [
        # Sun Tzu, Clausewitz, intelligence history
        132, 133, 134,                           # Sun Tzu Art of War
        1946, 1947, 1948,                        # Clausewitz
        44514, 44515, 44516,                     # Military history
        7490, 7491, 7492, 7493,                  # WWI/WWII intel
        29554, 29555, 29556, 29557,              # Military intelligence
        34796, 34797, 34798, 34799,              # WWII documents
        10171, 10172, 10173, 10174,              # Intelligence memoirs
        15776, 15777, 15778,                     # War and diplomacy
        36547, 36548, 36549, 36550,              # Military strategy
        26266, 26267, 26268, 26269,              # Special operations
        19023, 19024, 19025,                     # OSS/SOE
        22344, 22345, 22346,                     # Naval intelligence
        8164, 8165, 8166, 8167,                  # Code breaking history
        31650, 31651, 31652,                     # Bletchley adjacent
    ],
}

# Deduplicate all IDs
_all_ids_with_category = {}
for cat, ids in GUTENBERG_IDS.items():
    for gid in ids:
        if gid not in _all_ids_with_category:
            _all_ids_with_category[gid] = cat
ALL_IDS = list(_all_ids_with_category.keys())
ID_TO_CATEGORY = _all_ids_with_category

# ── Sanitize function ─────────────────────────────────────────────────────

def sanitize(text):
    """Convert to uppercase, letters only."""
    return re.sub(r'[^A-Z]', '', text.upper())


# ── Download functions ────────────────────────────────────────────────────

GUTENBERG_URL = "https://www.gutenberg.org/cache/epub/{id}/pg{id}.txt"
GUTENBERG_ALT_URL = "https://www.gutenberg.org/files/{id}/{id}.txt"
GUTENBERG_ALT2_URL = "https://www.gutenberg.org/files/{id}/{id}-0.txt"


def download_text(gutenberg_id, cache_dir):
    """Download a Gutenberg text, caching locally. Returns sanitized text or None."""
    cache_path = Path(cache_dir) / f"pg{gutenberg_id}.txt"

    # Check cache first
    if cache_path.exists() and cache_path.stat().st_size > 100:
        try:
            raw = cache_path.read_text(encoding="utf-8", errors="ignore")
            return sanitize(raw)
        except Exception:
            pass

    # Try multiple URL patterns
    urls = [
        GUTENBERG_URL.format(id=gutenberg_id),
        GUTENBERG_ALT_URL.format(id=gutenberg_id),
        GUTENBERG_ALT2_URL.format(id=gutenberg_id),
    ]

    raw = None
    for url in urls:
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "K4Research/1.0 (academic cryptanalysis)"}
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
            break  # success
        except (urllib.error.HTTPError, urllib.error.URLError, Exception):
            continue

    if raw is None:
        return None

    # Cache the raw text
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(raw, encoding="utf-8")
    except Exception:
        pass

    return sanitize(raw)


# ── Crib-drag logic (97-char model) ──────────────────────────────────────

def crib_drag_97(text_nums_az, text_nums_ka, min_matches=8):
    """
    Slide a 97-char window over the text, counting required key matches.
    Returns list of hit dicts with score >= min_matches.
    """
    n = len(text_nums_az)
    window_size = CT_LEN  # 97
    if n < window_size:
        return []

    hits = []
    max_offset = n - window_size

    # Iterate over (variant, alphabet) combinations
    for (variant, alph_name), req_entries in REQUIRED_KEYS_97.items():
        if alph_name == "AZ":
            text_nums = text_nums_az
        else:
            text_nums = text_nums_ka

        # For each offset, count matches
        for offset in range(max_offset + 1):
            matches = 0
            for crib_pos, required_key in req_entries:
                text_pos = offset + crib_pos
                if text_nums[text_pos] == required_key:
                    matches += 1
            if matches >= min_matches:
                hits.append({
                    "model": "97char",
                    "variant": variant,
                    "alphabet": alph_name,
                    "offset": offset,
                    "matches": matches,
                    "max_possible": len(req_entries),
                })

    return hits


# ── Crib-drag logic (73-char Model A) ────────────────────────────────────

def crib_drag_73(text_nums_az, text_nums_ka, min_matches=8):
    """
    Slide a 73-char window over the text for Model A (null-extracted CT).
    Returns list of hit dicts with score >= min_matches.
    """
    n = len(text_nums_az)
    window_size = 73
    if n < window_size:
        return []

    hits = []
    max_offset = n - window_size

    for (variant, alph_name), req_entries in REQUIRED_KEYS_73.items():
        if alph_name == "AZ":
            text_nums = text_nums_az
        else:
            text_nums = text_nums_ka

        for offset in range(max_offset + 1):
            matches = 0
            for crib_pos, required_key in req_entries:
                text_pos = offset + crib_pos
                if text_nums[text_pos] == required_key:
                    matches += 1
            if matches >= min_matches:
                hits.append({
                    "model": "73char_modelA",
                    "variant": variant,
                    "alphabet": alph_name,
                    "offset": offset,
                    "matches": matches,
                    "max_possible": len(req_entries),
                })

    return hits


# ── Worker function for Pool ──────────────────────────────────────────────

def scan_single_text(args):
    """
    Worker: scan one pre-sanitized text string.
    args = (gutenberg_id, category, sanitized_text, min_matches)
    Returns dict with hits.
    """
    gutenberg_id, category, sanitized_text, min_matches = args

    if not sanitized_text or len(sanitized_text) < 97:
        return {
            "gutenberg_id": gutenberg_id,
            "category": category,
            "chars": len(sanitized_text) if sanitized_text else 0,
            "hits": [],
            "best_score": 0,
        }

    # Convert to numeric for AZ
    text_nums_az = [AZ_IDX.get(c, 0) for c in sanitized_text]

    # Convert to numeric for KA
    text_nums_ka = [KA_IDX.get(c, 0) for c in sanitized_text]

    # Run both models
    hits_97 = crib_drag_97(text_nums_az, text_nums_ka, min_matches)
    hits_73 = crib_drag_73(text_nums_az, text_nums_ka, min_matches)

    all_hits = hits_97 + hits_73

    best_score = max((h["matches"] for h in all_hits), default=0)

    return {
        "gutenberg_id": gutenberg_id,
        "category": category,
        "chars": len(sanitized_text),
        "hits": all_hits[:20],  # Cap to avoid huge output
        "best_score": best_score,
    }


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Gutenberg Running Key Scan for K4 (Phase 4)"
    )
    parser.add_argument(
        "--allow-retired-construct",
        action="store_true",
        help=(
            "Acknowledge that this script uses a retired consensus-null "
            "model and is historical only"
        ),
    )
    parser.add_argument("--limit", type=int, default=None,
                        help="Only scan first N texts (for testing)")
    parser.add_argument("--category", type=str, default=None,
                        help="Only scan one category")
    parser.add_argument("--min-matches", type=int, default=8,
                        help="Minimum crib matches to report (default 8)")
    parser.add_argument("--workers", type=int, default=None,
                        help="Number of parallel workers (default: min(cpu_count, 28))")
    args = parser.parse_args()

    if not args.allow_retired_construct:
        print(
            "Refusing to run: this campaign depends on a retired consensus-null "
            "model and is quarantined as a historical artifact. Re-run only "
            "with --allow-retired-construct for explicit reproducibility work.",
            file=sys.stderr,
        )
        raise SystemExit(2)

    # Determine worker count
    n_workers = args.workers or min(multiprocessing.cpu_count(), 28)
    min_matches = args.min_matches

    # Set up output directory
    out_dir = Path("results/k123_running_key_exhaustive/phase4_gutenberg")
    cache_dir = out_dir / "downloads"
    out_dir.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Determine which IDs to scan
    if args.category:
        if args.category not in GUTENBERG_IDS:
            print(f"ERROR: Unknown category '{args.category}'. "
                  f"Valid categories: {list(GUTENBERG_IDS.keys())}")
            sys.exit(1)
        scan_ids = [(gid, args.category) for gid in GUTENBERG_IDS[args.category]]
        # Deduplicate
        seen = set()
        scan_ids = [(gid, cat) for gid, cat in scan_ids if not (gid in seen or seen.add(gid))]
    else:
        scan_ids = [(gid, ID_TO_CATEGORY[gid]) for gid in ALL_IDS]

    if args.limit:
        scan_ids = scan_ids[:args.limit]

    total_planned = len(scan_ids)
    print("=" * 72)
    print("Gutenberg Running Key Scan — Phase 4")
    print("=" * 72)
    print(f"  Total IDs to scan:  {total_planned}")
    print(f"  Workers:            {n_workers}")
    print(f"  Min matches:        {min_matches}/24")
    print(f"  Cipher models:      97-char (direct) + 73-char (Model A)")
    print(f"  Variants:           Vigenere, Beaufort, VarBeaufort × AZ, KA")
    print(f"  Cache dir:          {cache_dir}")
    print(f"  Output dir:         {out_dir}")
    print()

    t0 = time.time()

    # Phase 1: Download texts sequentially (respect Gutenberg)
    print("[Phase 1] Downloading texts...")
    downloaded = []  # list of (gutenberg_id, category, sanitized_text)
    failed_ids = []

    for i, (gid, category) in enumerate(scan_ids):
        sys.stdout.write(f"\r  Downloading {i+1}/{total_planned}: pg{gid:6d} [{category[:20]}]    ")
        sys.stdout.flush()

        text = download_text(gid, cache_dir)
        if text and len(text) >= 97:
            downloaded.append((gid, category, text))
        else:
            failed_ids.append(gid)

        # Respect Gutenberg: 1-second delay between downloads
        # (only if not from cache — check if we actually fetched)
        cache_path = cache_dir / f"pg{gid}.txt"
        if not cache_path.exists() or time.time() - t0 < 1:
            time.sleep(1)

    print(f"\n  Downloaded: {len(downloaded)} texts, Failed: {len(failed_ids)}")
    total_chars = sum(len(t) for _, _, t in downloaded)
    print(f"  Total characters: {total_chars:,}")
    print()

    # Phase 2: Scan in parallel
    print("[Phase 2] Scanning texts for running key matches...")

    worker_args = [(gid, cat, text, min_matches) for gid, cat, text in downloaded]

    results = []
    top_hits = []  # all hits with score >= 10, across all texts
    per_category_best = defaultdict(lambda: {"best": 0, "texts_scanned": 0})
    texts_scanned = 0
    best_overall = 0
    best_detail = None

    with multiprocessing.Pool(processes=n_workers) as pool:
        for i, result in enumerate(pool.imap_unordered(scan_single_text, worker_args, chunksize=1)):
            results.append(result)
            texts_scanned += 1

            gid = result["gutenberg_id"]
            cat = result["category"]
            score = result["best_score"]

            per_category_best[cat]["texts_scanned"] += 1
            if score > per_category_best[cat]["best"]:
                per_category_best[cat]["best"] = score

            if score > best_overall:
                best_overall = score
                best_detail = result

            # Collect top hits
            for hit in result["hits"]:
                if hit["matches"] >= 10:
                    hit["gutenberg_id"] = gid
                    hit["category"] = cat
                    top_hits.append(hit)

            if i % 10 == 0 or score >= min_matches:
                elapsed = time.time() - t0
                rate = (i + 1) / elapsed if elapsed > 0 else 0
                print(f"  [{i+1:4d}/{len(worker_args)}] pg{gid} [{cat[:16]}] "
                      f"chars={result['chars']:,} best={score}/24 "
                      f"({rate:.1f} texts/s)")

                if score >= 10:
                    print(f"    *** ABOVE NOISE: score={score}/24 ***")
                    for hit in result["hits"]:
                        if hit["matches"] >= 10:
                            print(f"    -> {hit['model']} {hit['variant']} {hit['alphabet']} "
                                  f"offset={hit['offset']} matches={hit['matches']}")

    elapsed = time.time() - t0

    # Sort top_hits by score descending
    top_hits.sort(key=lambda x: -x["matches"])
    top_50 = top_hits[:50]

    # Classification
    if best_overall >= 24:
        classification = "BREAKTHROUGH"
    elif best_overall >= 18:
        classification = "SIGNAL"
    elif best_overall >= 10:
        classification = "INTERESTING"
    else:
        classification = "NOISE"

    # Assemble output
    out = {
        "experiment": "Gutenberg Running Key Scan (Phase 4)",
        "date": "2026-03-17",
        "total_planned": total_planned,
        "texts_scanned": texts_scanned,
        "texts_failed": len(failed_ids),
        "failed_ids": failed_ids,
        "total_chars_scanned": total_chars,
        "elapsed_seconds": round(elapsed, 2),
        "n_workers": n_workers,
        "min_matches_threshold": min_matches,
        "best_score": best_overall,
        "best_detail": best_detail,
        "top_50": top_50,
        "classification": classification,
        "per_category_best": {
            cat: {"best": v["best"], "texts_scanned": v["texts_scanned"]}
            for cat, v in per_category_best.items()
        },
        "repro": f"PYTHONPATH=src python3 -u scripts/campaigns/f_gutenberg_running_key_scan_v1.py",
    }

    out_path = out_dir / "scan_results.json"
    out_path.write_text(json.dumps(out, indent=2))

    # ── Summary ───────────────────────────────────────────────────────
    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"  Texts scanned:        {texts_scanned}")
    print(f"  Texts failed:         {len(failed_ids)}")
    print(f"  Total chars scanned:  {total_chars:,}")
    print(f"  Elapsed:              {elapsed:.1f}s ({elapsed/60:.1f}m)")
    print(f"  Best score:           {best_overall}/24")
    print(f"  Classification:       {classification}")
    print(f"  Output:               {out_path}")
    print()

    if best_overall >= 18:
        print(f"  *** SIGNAL DETECTED at {best_overall}/24 — investigate immediately ***")
        if best_detail:
            print(f"  Best text: pg{best_detail['gutenberg_id']} [{best_detail['category']}]")
            for hit in (best_detail.get("hits") or []):
                print(f"    {hit['model']} {hit['variant']} {hit['alphabet']} "
                      f"offset={hit['offset']} matches={hit['matches']}")
    elif best_overall >= 10:
        print(f"  INTERESTING: {best_overall}/24 — above noise floor but below signal")
        if best_detail:
            print(f"  Best text: pg{best_detail['gutenberg_id']} [{best_detail['category']}]")
    else:
        print(f"  RESULT: NOISE. No Gutenberg text produces a crib-consistent running key.")
        print(f"  Phase 4 (Gutenberg scan): ELIMINATED.")

    print()
    print("  Per-category best scores:")
    for cat, info in sorted(per_category_best.items(), key=lambda x: -x[1]["best"]):
        bar = "#" * info["best"]
        print(f"    {cat:30s} {info['best']:2d}/24  ({info['texts_scanned']} texts) {bar}")

    print()
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/campaigns/f_gutenberg_running_key_scan_v1.py")


if __name__ == "__main__":
    main()
