#!/usr/bin/env python3
"""
K2 Coordinates as Straddling Checkerboard — FULL EXHAUSTION (multiprocessing rewrite)

What this version does
----------------------
- Reuses a single multiprocessing pool across the whole run
- Parallelizes Tier A, Tier B, and Tier C
- Streams tasks lazily instead of building giant work lists
- Precomputes digit streams / fill alphabets / additive keys once
- Uses configurable hit thresholds consistently in all tiers

Usage examples
--------------
# Full run
PYTHONPATH=src python3 -u scripts/analysis/e_k2_checkerboard_decode_exhaust.py

# Quick smoke-test
PYTHONPATH=src python3 -u scripts/analysis/e_k2_checkerboard_decode_exhaust.py --quick

# Only selected tiers
PYTHONPATH=src python3 -u scripts/analysis/e_k2_checkerboard_decode_exhaust.py --tiers A B

# Limit header permutations
PYTHONPATH=src python3 -u scripts/analysis/e_k2_checkerboard_decode_exhaust.py --max-headers 100000

# Parallelism
PYTHONPATH=src python3 -u scripts/analysis/e_k2_checkerboard_decode_exhaust.py --workers 8
"""

import sys
import json
import time
import math
import argparse
import logging
import multiprocessing as mp
from pathlib import Path
from itertools import combinations, permutations

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, KRYPTOS_ALPHABET

# ── Logging ──────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────

AZ = ALPH
KA = KRYPTOS_ALPHABET

CRIB_ENE = "EASTNORTHEAST"
CRIB_BC = "BERLINCLOCK"

K2_DIGITS_IN_ORDER = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]

_seen = set()
K2_UNIQUE_IN_ORDER = []
for _d in K2_DIGITS_IN_ORDER:
    if _d not in _seen:
        K2_UNIQUE_IN_ORDER.append(_d)
        _seen.add(_d)

K2_REMAINING = [d for d in range(10) if d not in _seen]
ALL_PAIRS = list(combinations(range(10), 2))

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
    "BERLINCLOCK", "EASTNORTHEAST", "SHADOW", "ENIGMA", "CIPHER",
    "SANBORN", "SCHEIDT", "COLOPHON", "PARALLAX",
    "TOWER", "CHART", "LAYER", "FIVE", "CLOCK", "NORTH",
    "MEDUSA", "KRYPTEIA",
]

# ── Worker globals (initialized once per process) ───────────────────────────

G_FILL_ALPHABETS = None
G_DIGIT_STREAMS = None
G_ADDITIVE_KEYS = None
G_THRESH_FIXED = 5
G_THRESH_FREE = 7


# ── Helpers ──────────────────────────────────────────────────────────────────

def keyword_mixed_alphabet(kw: str, base: str = AZ) -> str:
    seen = set()
    out = []
    base_set = set(base)

    for ch in kw.upper():
        if ch in base_set and ch not in seen:
            seen.add(ch)
            out.append(ch)

    for ch in base:
        if ch not in seen:
            seen.add(ch)
            out.append(ch)

    return "".join(out)


def build_checkerboard_from_header(header, row_labels, fill_alphabet):
    """
    Build straddling checkerboard.

    Returns:
        (letter_to_code, code_to_letter)
    """
    r1, r2 = row_labels

    non_escape_cols = [i for i in range(10) if header[i] != r1 and header[i] != r2]
    l2c = {}
    c2l = {}

    idx = 0

    # Single-digit row
    for col in non_escape_cols:
        if idx < len(fill_alphabet):
            digit = header[col]
            l2c[fill_alphabet[idx]] = (digit,)
            c2l[(digit,)] = fill_alphabet[idx]
            idx += 1

    # First escape row
    for col in range(10):
        if idx < len(fill_alphabet):
            digit = header[col]
            l2c[fill_alphabet[idx]] = (r1, digit)
            c2l[(r1, digit)] = fill_alphabet[idx]
            idx += 1

    # Second escape row
    for col in non_escape_cols:
        if idx < len(fill_alphabet):
            digit = header[col]
            l2c[fill_alphabet[idx]] = (r2, digit)
            c2l[(r2, digit)] = fill_alphabet[idx]
            idx += 1

    return l2c, c2l


def decode_digits(digits, row_labels, code_to_letter):
    """
    Parse digit stream via straddling checkerboard.
    Returns decoded string or None.
    """
    r1, r2 = row_labels
    result = []
    i = 0

    while i < len(digits):
        d = digits[i]
        if d == r1 or d == r2:
            if i + 1 >= len(digits):
                return None
            code = (d, digits[i + 1])
            if code not in code_to_letter:
                return None
            result.append(code_to_letter[code])
            i += 2
        else:
            code = (d,)
            if code not in code_to_letter:
                return None
            result.append(code_to_letter[code])
            i += 1

    return "".join(result)


def check_cribs_fixed(decoded, ene_pos: int = 21, bc_pos: int = 63):
    if decoded is None:
        return 0, 0, 0

    n = len(decoded)

    ene_score = sum(
        1
        for i, ch in enumerate(CRIB_ENE)
        if ene_pos + i < n and decoded[ene_pos + i] == ch
    )

    bc_score = sum(
        1
        for i, ch in enumerate(CRIB_BC)
        if bc_pos + i < n and decoded[bc_pos + i] == ch
    )

    return ene_score + bc_score, ene_score, bc_score


def check_cribs_free(decoded):
    if decoded is None or len(decoded) < 11:
        return 0, -1, -1

    best = 0
    best_ep = -1
    best_bp = -1
    n = len(decoded)

    # Need enough room for ENE (13) and BC (11)
    for p in range(max(1, n - 12)):
        s = sum(
            1
            for i, ch in enumerate(CRIB_ENE)
            if p + i < n and decoded[p + i] == ch
        )
        if s >= 3:
            for q in range(max(1, n - 10)):
                s2 = sum(
                    1
                    for i, ch in enumerate(CRIB_BC)
                    if q + i < n and decoded[q + i] == ch
                )
                total = s + s2
                if total > best:
                    best = total
                    best_ep = p
                    best_bp = q

    return best, best_ep, best_bp


def should_keep_hit(pt_len, fixed, free):
    return (
        fixed >= G_THRESH_FIXED
        or free >= G_THRESH_FREE
        or pt_len == 73
    )


def ct_to_digits(ct, mapping_fn):
    return [mapping_fn(ch) for ch in ct]


def make_digit_mappings():
    dm = {
        "KA_mod10": lambda ch: KA.index(ch) % 10,
        "AZ_mod10": lambda ch: AZ.index(ch) % 10,
    }

    for kw in KEYWORDS:
        for base, tag in [(AZ, "AZ"), (KA, "KA")]:
            alpha = keyword_mixed_alphabet(kw, base)
            mp_dict = {ch: i % 10 for i, ch in enumerate(alpha)}

            def _mk(m):
                return lambda ch: m[ch]

            dm[f"kw_{kw}_{tag}_mod10"] = _mk(mp_dict)

    return dm


def make_fill_alphabets():
    fa = {"AZ": AZ, "KA": KA}
    for kw in KEYWORDS:
        fa[f"kw_{kw}_AZ"] = keyword_mixed_alphabet(kw, AZ)
        fa[f"kw_{kw}_KA"] = keyword_mixed_alphabet(kw, KA)
    return fa


def make_additive_keys():
    ak = {}

    # Constant shifts
    for shift in range(10):
        ak[f"const_{shift}"] = [shift] * CT_LEN

    # KRYPTOS repeated seeds
    for label, seed in [
        ("KRYPTOS_KA", [KA.index(c) % 10 for c in "KRYPTOS"]),
        ("KRYPTOS_AZ", [AZ.index(c) % 10 for c in "KRYPTOS"]),
    ]:
        ak[f"{label}_rep"] = (seed * (CT_LEN // len(seed) + 1))[:CT_LEN]

    # K2 repeated
    k2_key = (K2_DIGITS_IN_ORDER * (CT_LEN // len(K2_DIGITS_IN_ORDER) + 1))[:CT_LEN]
    ak["K2_digits_rep"] = k2_key

    # K2 unique repeated
    k2u_key = (K2_UNIQUE_IN_ORDER * (CT_LEN // len(K2_UNIQUE_IN_ORDER) + 1))[:CT_LEN]
    ak["K2_unique_rep"] = k2u_key

    # K2 chain-add style
    chain = list(K2_DIGITS_IN_ORDER)
    while len(chain) < CT_LEN:
        chain.append((chain[-len(K2_DIGITS_IN_ORDER)] + chain[-len(K2_DIGITS_IN_ORDER) + 1]) % 10)
    ak["K2_chain_add"] = chain[:CT_LEN]

    # Fibonacci-like
    for seed_name, seed in [("fib_38", [3, 8]), ("fib_57", [5, 7])]:
        fib = list(seed)
        while len(fib) < CT_LEN:
            fib.append((fib[-1] + fib[-2]) % 10)
        ak[seed_name] = fib[:CT_LEN]

    return ak


def chunked(iterable, chunk_size):
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= chunk_size:
            yield batch
            batch = []
    if batch:
        yield batch


def init_worker(fill_alphabets, digit_streams, additive_keys, thresh_fixed, thresh_free):
    global G_FILL_ALPHABETS, G_DIGIT_STREAMS, G_ADDITIVE_KEYS, G_THRESH_FIXED, G_THRESH_FREE
    G_FILL_ALPHABETS = fill_alphabets
    G_DIGIT_STREAMS = digit_streams
    G_ADDITIVE_KEYS = additive_keys
    G_THRESH_FIXED = thresh_fixed
    G_THRESH_FREE = thresh_free


# ── Worker functions ─────────────────────────────────────────────────────────

def score_tier_a_batch(task):
    """
    task:
      {
        "row_labels": (r1, r2),
        "fill_name": str,
        "map_name": str,
        "headers": [header1, header2, ...],
      }
    """
    row_labels = tuple(task["row_labels"])
    fill_name = task["fill_name"]
    map_name = task["map_name"]
    headers = task["headers"]

    fill_alpha = G_FILL_ALPHABETS[fill_name]
    digit_stream = G_DIGIT_STREAMS[map_name]

    hits = []
    local_best_fixed = 0
    local_best_free = 0
    local_len73 = 0
    tested = 0

    for header in headers:
        tested += 1
        _, c2l = build_checkerboard_from_header(header, row_labels, fill_alpha)
        decoded = decode_digits(digit_stream, row_labels, c2l)
        if decoded is None:
            continue

        pt_len = len(decoded)
        if pt_len < 50 or pt_len > 90:
            continue

        fixed, ene_s, bc_s = check_cribs_fixed(decoded)
        free, free_ep, free_bp = check_cribs_free(decoded)

        if fixed > local_best_fixed:
            local_best_fixed = fixed
        if free > local_best_free:
            local_best_free = free
        if pt_len == 73:
            local_len73 += 1

        if should_keep_hit(pt_len, fixed, free):
            hits.append({
                "tier": "A",
                "row_labels": list(row_labels),
                "header": list(header),
                "fill": fill_name,
                "digit_map": map_name,
                "pt_len": pt_len,
                "fixed": fixed,
                "ene_score": ene_s,
                "bc_score": bc_s,
                "free": free,
                "free_ene_pos": free_ep,
                "free_bc_pos": free_bp,
                "decoded": decoded[:80],
            })

    return {
        "tested": tested,
        "len73": local_len73,
        "best_fixed": local_best_fixed,
        "best_free": local_best_free,
        "hits": hits,
    }


def score_general_batch(task):
    """
    task:
      {
        "tier": "B" or "C",
        "items": [config, config, ...]
      }

    Tier B config:
      {
        "row_labels": (...),
        "header_name": str,
        "header": [...],
        "fill_name": str,
        "map_name": str,
        "add_name": str,
        "sign": +1 / -1
      }

    Tier C config:
      {
        "row_labels": (...),
        "header": [...],
        "fill_name": str,
        "map_name": str
      }
    """
    tier = task["tier"]
    items = task["items"]

    hits = []
    local_best_fixed = 0
    local_best_free = 0
    local_len73 = 0
    tested = 0

    for item in items:
        tested += 1

        row_labels = tuple(item["row_labels"])
        header = item["header"]
        fill_name = item["fill_name"]
        map_name = item["map_name"]

        fill_alpha = G_FILL_ALPHABETS[fill_name]
        _, c2l = build_checkerboard_from_header(header, row_labels, fill_alpha)

        if tier == "B":
            base_digits = G_DIGIT_STREAMS[map_name]
            add_key = G_ADDITIVE_KEYS[item["add_name"]]
            sign = item["sign"]
            digits = [(base_digits[i] + sign * add_key[i]) % 10 for i in range(CT_LEN)]
        else:
            digits = G_DIGIT_STREAMS[map_name]

        decoded = decode_digits(digits, row_labels, c2l)
        if decoded is None:
            continue

        pt_len = len(decoded)
        if pt_len < 50 or pt_len > 90:
            continue

        fixed, ene_s, bc_s = check_cribs_fixed(decoded)
        free, free_ep, free_bp = check_cribs_free(decoded)

        if fixed > local_best_fixed:
            local_best_fixed = fixed
        if free > local_best_free:
            local_best_free = free
        if pt_len == 73:
            local_len73 += 1

        if should_keep_hit(pt_len, fixed, free):
            hit = {
                "tier": tier,
                "row_labels": list(row_labels),
                "header": list(header),
                "fill": fill_name,
                "digit_map": map_name,
                "pt_len": pt_len,
                "fixed": fixed,
                "ene_score": ene_s,
                "bc_score": bc_s,
                "free": free,
                "free_ene_pos": free_ep,
                "free_bc_pos": free_bp,
                "decoded": decoded[:80],
            }

            if tier == "B":
                hit["header_name"] = item["header_name"]
                hit["additive"] = f"{'+' if item['sign'] > 0 else '-'}{item['add_name']}"

            hits.append(hit)

    return {
        "tested": tested,
        "len73": local_len73,
        "best_fixed": local_best_fixed,
        "best_free": local_best_free,
        "hits": hits,
    }


# ── Task generators ──────────────────────────────────────────────────────────

def generate_headers(max_headers=None):
    count = 0
    for hdr in permutations(range(10)):
        if max_headers is not None and count >= max_headers:
            break
        yield hdr
        count += 1


def tier_a_tasks(fill_alphabets, digit_streams, max_headers, batch_size):
    """
    Yields tasks lazily for Tier A.
    """
    for row_labels in ALL_PAIRS:
        for fill_name in fill_alphabets.keys():
            for map_name in digit_streams.keys():
                header_iter = generate_headers(max_headers=max_headers)
                for header_batch in chunked(header_iter, batch_size):
                    yield {
                        "row_labels": row_labels,
                        "fill_name": fill_name,
                        "map_name": map_name,
                        "headers": header_batch,
                    }


def tier_b_item_iter(fill_names, map_names, additive_names, headers_dict):
    for row_labels in ALL_PAIRS:
        for hdr_name, hdr in headers_dict.items():
            for fill_name in fill_names:
                for map_name in map_names:
                    for add_name in additive_names:
                        for sign in (+1, -1):
                            yield {
                                "row_labels": row_labels,
                                "header_name": hdr_name,
                                "header": hdr,
                                "fill_name": fill_name,
                                "map_name": map_name,
                                "add_name": add_name,
                                "sign": sign,
                            }


def tier_b_tasks(fill_names, map_names, additive_names, headers_dict, batch_size):
    for batch in chunked(tier_b_item_iter(fill_names, map_names, additive_names, headers_dict), batch_size):
        yield {
            "tier": "B",
            "items": batch,
        }


def build_tier_c_headers():
    headers = []

    # all permutations of K2 unique digits in first 6 slots, remaining 4 fixed sorted
    for perm in permutations(K2_UNIQUE_IN_ORDER):
        headers.append(list(perm) + sorted(K2_REMAINING))

    # all permutations of remaining 4 in last 4 slots, unique-ordered first 6 fixed
    for perm_rem in permutations(K2_REMAINING):
        headers.append(K2_UNIQUE_IN_ORDER + list(perm_rem))

    # dedupe
    seen = set()
    out = []
    for h in headers:
        key = tuple(h)
        if key not in seen:
            seen.add(key)
            out.append(h)
    return out


def tier_c_item_iter(fill_names, map_names, c_headers):
    for row_labels in ALL_PAIRS:
        for hdr in c_headers:
            for fill_name in fill_names:
                for map_name in map_names:
                    yield {
                        "row_labels": row_labels,
                        "header": hdr,
                        "fill_name": fill_name,
                        "map_name": map_name,
                    }


def tier_c_tasks(fill_names, map_names, c_headers, batch_size):
    for batch in chunked(tier_c_item_iter(fill_names, map_names, c_headers), batch_size):
        yield {
            "tier": "C",
            "items": batch,
        }


# ── Main ─────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="Exhaustive K2 Checkerboard Decode")

    p.add_argument(
        "--tiers",
        nargs="+",
        choices=["A", "B", "C"],
        default=["A", "B", "C"],
        help="Which exhaustion tiers to run (default: all)",
    )

    p.add_argument(
        "--quick",
        action="store_true",
        help="Quick smoke-test: reduced fills/mappings/headers",
    )

    p.add_argument(
        "--max-headers",
        type=int,
        default=None,
        help="Cap on Tier A header permutations per (pair,fill,mapping). None = full 10!",
    )

    p.add_argument(
        "--workers",
        type=int,
        default=max(1, mp.cpu_count() - 1),
        help="Parallel workers (default: cpu_count - 1)",
    )

    p.add_argument(
        "--batch-size",
        type=int,
        default=25000,
        help="Task batch size (Tier A = headers per task; Tier B/C = configs per task)",
    )

    p.add_argument("--hit-threshold-fixed", type=int, default=5)
    p.add_argument("--hit-threshold-free", type=int, default=7)

    p.add_argument(
        "--start-method",
        choices=["spawn", "fork", "forkserver"],
        default="spawn",
        help="multiprocessing start method (default: spawn)",
    )

    return p.parse_args()


def merge_worker_result(res, all_hits, state, tier_tag):
    state["total_configs"] += res["tested"]
    state["total_len73"] += res["len73"]
    if res["best_fixed"] > state["global_best_fixed"]:
        state["global_best_fixed"] = res["best_fixed"]
    if res["best_free"] > state["global_best_free"]:
        state["global_best_free"] = res["best_free"]

    for h in res["hits"]:
        all_hits.append(h)
        log.warning(
            f"  HIT({tier_tag}): "
            f"rl={tuple(h['row_labels'])} "
            f"fill={h['fill']} "
            f"map={h['digit_map']} "
            f"len={h['pt_len']} "
            f"fixed={h['fixed']} "
            f"free={h['free']}"
            + (f" additive={h['additive']}" if 'additive' in h else "")
        )
        log.warning(f"    PT: {h['decoded']}")


def run():
    args = parse_args()
    t0 = time.time()

    log.info("=" * 70)
    log.info("K2 COORDINATES AS STRADDLING CHECKERBOARD — FULL EXHAUSTION")
    log.info("=" * 70)
    log.info(f"CT length     : {CT_LEN}")
    log.info(f"K2 unique     : {K2_UNIQUE_IN_ORDER}")
    log.info(f"K2 remaining  : {K2_REMAINING}")
    log.info(f"Workers       : {args.workers}")
    log.info(f"Batch size    : {args.batch_size}")
    log.info(f"Max headers   : {args.max_headers or 'ALL (3,628,800)'}")
    log.info(f"Tiers         : {args.tiers}")
    log.info(f"Quick mode    : {args.quick}")
    log.info(f"Start method  : {args.start_method}")

    digit_mappings = make_digit_mappings()
    fill_alphabets = make_fill_alphabets()
    additive_keys = make_additive_keys()

    # Precompute digit streams once
    digit_streams = {
        map_name: ct_to_digits(CT, map_fn)
        for map_name, map_fn in digit_mappings.items()
    }

    log.info(f"Digit mappings: {len(digit_streams)}")
    log.info(f"Fill alphabets: {len(fill_alphabets)}")
    log.info(f"Additive keys : {len(additive_keys)}")

    if args.quick:
        log.info("QUICK MODE – restricting fills/mappings/headers")

        fill_alphabets = {
            "AZ": fill_alphabets["AZ"],
            "KA": fill_alphabets["KA"],
            "kw_KRYPTOS_AZ": fill_alphabets["kw_KRYPTOS_AZ"],
        }

        digit_streams = {
            "KA_mod10": digit_streams["KA_mod10"],
            "AZ_mod10": digit_streams["AZ_mod10"],
        }

        if args.max_headers is None:
            args.max_headers = 10_000

    state = {
        "total_configs": 0,
        "global_best_fixed": 0,
        "global_best_free": 0,
        "total_len73": 0,
    }
    all_hits = []

    ctx = mp.get_context(args.start_method)
    pool = ctx.Pool(
        processes=args.workers,
        initializer=init_worker,
        initargs=(
            fill_alphabets,
            digit_streams,
            additive_keys,
            args.hit_threshold_fixed,
            args.hit_threshold_free,
        ),
    )

    try:
        # ════════════════════════════════════════════════════════════════════
        # TIER A
        # ════════════════════════════════════════════════════════════════════
        if "A" in args.tiers:
            log.info("")
            log.info("=" * 70)
            log.info("TIER A: Full 10! header permutation sweep")
            log.info(f"  Row-label pairs : {len(ALL_PAIRS)}")
            log.info(f"  Headers/pair    : up to {args.max_headers or math.factorial(10):,}")
            log.info(f"  Fill alphabets  : {len(fill_alphabets)}")
            log.info(f"  Digit mappings  : {len(digit_streams)}")
            log.info("=" * 70)

            tier_a_t0 = time.time()

            task_iter = tier_a_tasks(
                fill_alphabets=fill_alphabets,
                digit_streams=digit_streams,
                max_headers=args.max_headers,
                batch_size=args.batch_size,
            )

            for res in pool.imap_unordered(score_tier_a_batch, task_iter, chunksize=1):
                merge_worker_result(res, all_hits, state, "A")

            elapsed_a = time.time() - tier_a_t0
            log.info(
                f"\nTier A complete: tested={state['total_configs']:,} "
                f"elapsed={elapsed_a:.1f}s "
                f"best_fixed={state['global_best_fixed']} "
                f"best_free={state['global_best_free']}"
            )

        # ════════════════════════════════════════════════════════════════════
        # TIER B
        # ════════════════════════════════════════════════════════════════════
        if "B" in args.tiers:
            log.info("")
            log.info("=" * 70)
            log.info("TIER B: Additive pre-key exhaustion (all 45 pairs)")
            log.info("=" * 70)

            tier_b_t0 = time.time()

            primary_hdr = K2_UNIQUE_IN_ORDER + sorted(K2_REMAINING)
            b_headers = {
                "k2_primary": primary_hdr,
                "standard_09": list(range(10)),
                "reversed_90": list(range(9, -1, -1)),
            }

            if args.quick:
                b_headers = {"k2_primary": primary_hdr}

            b_fill_names = [
                k for k in fill_alphabets.keys()
                if k in {
                    "AZ", "KA",
                    "kw_KRYPTOS_AZ", "kw_KRYPTOS_KA",
                    "kw_PALIMPSEST_AZ", "kw_DEFECTOR_AZ",
                }
            ]
            b_fill_names = b_fill_names or list(fill_alphabets.keys())

            b_map_names = [
                k for k in digit_streams.keys()
                if k in {
                    "KA_mod10", "AZ_mod10",
                    "kw_KRYPTOS_AZ_mod10", "kw_KRYPTOS_KA_mod10",
                    "kw_DEFECTOR_AZ_mod10", "kw_PALIMPSEST_AZ_mod10",
                }
            ]
            b_map_names = b_map_names or list(digit_streams.keys())

            b_add_names = list(additive_keys.keys())

            task_iter = tier_b_tasks(
                fill_names=b_fill_names,
                map_names=b_map_names,
                additive_names=b_add_names,
                headers_dict=b_headers,
                batch_size=args.batch_size,
            )

            for res in pool.imap_unordered(score_general_batch, task_iter, chunksize=1):
                merge_worker_result(res, all_hits, state, "B")

            elapsed_b = time.time() - tier_b_t0
            log.info(
                f"\nTier B complete: cumulative_tested={state['total_configs']:,} "
                f"elapsed={elapsed_b:.1f}s "
                f"best_fixed={state['global_best_fixed']} "
                f"best_free={state['global_best_free']}"
            )

        # ════════════════════════════════════════════════════════════════════
        # TIER C
        # ════════════════════════════════════════════════════════════════════
        if "C" in args.tiers:
            log.info("")
            log.info("=" * 70)
            log.info("TIER C: Keyword-fill × broader header set (all 45 pairs)")
            log.info("=" * 70)

            tier_c_t0 = time.time()
            c_headers = build_tier_c_headers()

            log.info(f"  Unique K2-derived headers: {len(c_headers)}")
            log.info(f"  Fill alphabets            : {len(fill_alphabets)}")
            log.info(f"  Digit mappings            : {len(digit_streams)}")

            task_iter = tier_c_tasks(
                fill_names=list(fill_alphabets.keys()),
                map_names=list(digit_streams.keys()),
                c_headers=c_headers,
                batch_size=args.batch_size,
            )

            for res in pool.imap_unordered(score_general_batch, task_iter, chunksize=1):
                merge_worker_result(res, all_hits, state, "C")

            elapsed_c = time.time() - tier_c_t0
            log.info(
                f"\nTier C complete: cumulative_tested={state['total_configs']:,} "
                f"elapsed={elapsed_c:.1f}s "
                f"best_fixed={state['global_best_fixed']} "
                f"best_free={state['global_best_free']}"
            )

    finally:
        pool.close()
        pool.join()

    # ── Summary ────────────────────────────────────────────────────────────

    elapsed = time.time() - t0

    if state["global_best_fixed"] >= 18 or state["global_best_free"] >= 18:
        verdict = "SIGNAL"
    elif state["global_best_fixed"] >= 10 or state["global_best_free"] >= 10:
        verdict = "INTERESTING"
    elif state["global_best_fixed"] >= args.hit_threshold_fixed or state["global_best_free"] >= args.hit_threshold_free:
        verdict = "WEAK_HITS"
    else:
        verdict = "NOISE"

    all_hits.sort(key=lambda h: max(h.get("fixed", 0), h.get("free", 0)), reverse=True)

    log.info("")
    log.info("=" * 70)
    log.info("SUMMARY")
    log.info("=" * 70)
    log.info(f"Total configs tested : {state['total_configs']:,}")
    log.info(f"Elapsed              : {elapsed:.1f}s  ({elapsed/60:.1f} min)")
    log.info(f"Global best fixed    : {state['global_best_fixed']}/24")
    log.info(f"Global best free     : {state['global_best_free']}/24")
    log.info(f"Total length-73 hits : {state['total_len73']}")
    log.info(f"Verdict              : {verdict}")

    output = {
        "experiment": "e_k2_checkerboard_decode_exhaust",
        "description": "K2 coordinates as straddling checkerboard — full exhaustion (multiprocessing rewrite)",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_configs": state["total_configs"],
        "elapsed_seconds": round(elapsed, 2),
        "global_best_fixed": state["global_best_fixed"],
        "global_best_free": state["global_best_free"],
        "total_len73_decodes": state["total_len73"],
        "verdict": verdict,
        "tiers_run": args.tiers,
        "quick_mode": args.quick,
        "max_headers": args.max_headers,
        "workers": args.workers,
        "batch_size": args.batch_size,
        "start_method": args.start_method,
        "hit_threshold_fixed": args.hit_threshold_fixed,
        "hit_threshold_free": args.hit_threshold_free,
        "k2_construction": {
            "k2_digits": K2_DIGITS_IN_ORDER,
            "k2_unique": K2_UNIQUE_IN_ORDER,
            "remaining": K2_REMAINING,
            "primary_header": K2_UNIQUE_IN_ORDER + sorted(K2_REMAINING),
            "primary_row_labels": [3, 8],
        },
        "top_hits": [
            {k: (list(v) if isinstance(v, tuple) else v) for k, v in h.items()}
            for h in all_hits[:30]
        ],
    }

    outpath = Path(__file__).resolve().parents[2] / "results" / "k2_checkerboard_decode_exhaust.json"
    outpath.parent.mkdir(parents=True, exist_ok=True)
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2)

    log.info(f"\nResults saved to: {outpath}")


if __name__ == "__main__":
    mp.freeze_support()
    run()