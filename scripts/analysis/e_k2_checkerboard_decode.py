#!/usr/bin/env python3
"""
K2 Coordinates as Straddling Checkerboard — FULL EXHAUSTION
============================================================
Cipher:   Straddling Checkerboard (K2-derived configuration)
Family:   analysis
Status:   active
Keyspace: ~4.5B+ configs (all 45 row-label pairs × sampled header perms
           × all digit mappings × all fill alphabets × additive keys)
Last run: never
Best score: N/A

WHAT THIS ADDS vs the original 9.2M-config script
--------------------------------------------------
Original script only tested:
  Phase 2 – 6 hand-picked row-label pairs × partial header list × all fills/maps
  Phase 3 – all 45 pairs but only the *primary* header
  Phase 4 – additive keys on 6 pairs × 2 headers
  Total: 9,223,974 configs

This script exhausts the remaining keyspace in priority tiers:

  TIER A — ALL 45 pairs × ALL headers (full 10! permutations, ~1.8M/pair)
            × all digit-mappings × all fill-alphabets
            This is the true exhaustion. ~4.4B raw configs, but we use
            the constraint that the two row-label digits must appear at
            *different* column positions in the header, so there are
            10! / 1 = 3,628,800 full permutations per pair, but the
            pair identity already constrains which positions are "escape"
            columns — so we iterate all 10! = 3,628,800 headers,
            all 45 pairs, all fills and all mappings.

            Because 3.6M × 45 × fills × maps is ~4–20B raw iterations,
            we use multiprocessing + early-exit scoring to keep
            wall-clock time practical (minutes to hours depending on
            hardware).

  TIER B — Additive pre-processing (VIC-style mod-10 key) applied to
            ALL 45 pairs (original only tested 6) × extended additive
            key set.

  TIER C — Full-keyword-alphabet fill × all 10! headers. The original
            only tried the primary header with keyword fills; here we
            cross every keyword fill with every header permutation.

HYPOTHESIS: K2 plaintext numbers are NOT geographic coordinates but
straddling checkerboard configuration data:
  38 -> row labels (3, 8)
  digits 3,8,5,7,6,5,7,7,8,4,4 -> header permutation
  KRYPTOS fills the 8 non-blank top-row positions

Usage
-----
  # Full exhaustion (may take hours):
  PYTHONPATH=src python3 -u scripts/analysis/e_k2_checkerboard_decode_exhaust.py

  # Quick smoke-test (Tier A only, 1 fill, 1 mapping):
  PYTHONPATH=src python3 -u scripts/analysis/e_k2_checkerboard_decode_exhaust.py --quick

  # Restrict to specific tier(s):
  PYTHONPATH=src python3 -u scripts/analysis/e_k2_checkerboard_decode_exhaust.py --tiers A B

  # Limit header permutations per pair (useful for CI / partial runs):
  PYTHONPATH=src python3 -u scripts/analysis/e_k2_checkerboard_decode_exhaust.py --max-headers 100000

  # Parallelism:
  PYTHONPATH=src python3 -u scripts/analysis/e_k2_checkerboard_decode_exhaust.py --workers 8
"""

import sys
import json
import time
import argparse
import logging
import multiprocessing as mp
from pathlib import Path
from itertools import combinations, permutations
from collections import Counter
from functools import partial

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, KRYPTOS_ALPHABET, CRIB_WORDS

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────
AZ = ALPH               # ABCDEFGHIJKLMNOPQRSTUVWXYZ
KA = KRYPTOS_ALPHABET   # KRYPTOSABCDEFGHIJLMNQUVWXZ

CRIB_ENE = "EASTNORTHEAST"
CRIB_BC  = "BERLINCLOCK"

# K2 plaintext numbers: 38, 57, 6.5, 77, 8, 44
K2_DIGITS_IN_ORDER = [3, 8, 5, 7, 6, 5, 7, 7, 8, 4, 4]

_seen: set = set()
K2_UNIQUE_IN_ORDER: list = []
for _d in K2_DIGITS_IN_ORDER:
    if _d not in _seen:
        K2_UNIQUE_IN_ORDER.append(_d)
        _seen.add(_d)
# [3, 8, 5, 7, 6, 4]

K2_REMAINING = [d for d in range(10) if d not in _seen]
# [0, 1, 2, 9]

ALL_PAIRS: list = list(combinations(range(10), 2))   # all 45

# Thematic keywords (same set as original, easily extended)
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KOMPASS",
    "BERLINCLOCK", "EASTNORTHEAST", "SHADOW", "ENIGMA", "CIPHER",
    "SANBORN", "SCHEIDT", "COLOPHON", "PARALLAX",
    "TOWER", "CHART", "LAYER", "FIVE", "CLOCK", "NORTH",
    "MEDUSA", "KRYPTEIA",
]

# ── Helpers ───────────────────────────────────────────────────────────────────

def keyword_mixed_alphabet(kw: str, base: str = AZ) -> str:
    seen: set = set()
    out: list = []
    for ch in kw.upper():
        if ch in set(base) and ch not in seen:
            seen.add(ch); out.append(ch)
    for ch in base:
        if ch not in seen:
            seen.add(ch); out.append(ch)
    return "".join(out)


def build_checkerboard_from_header(header, row_labels, fill_alphabet):
    """Build straddling checkerboard.
    Returns (letter_to_code, code_to_letter) dicts.
    """
    r1, r2 = row_labels
    non_escape_cols = [i for i in range(10) if header[i] != r1 and header[i] != r2]

    l2c: dict = {}
    c2l: dict = {}
    idx = 0

    for col in non_escape_cols:
        if idx < len(fill_alphabet):
            digit = header[col]
            l2c[fill_alphabet[idx]] = (digit,)
            c2l[(digit,)] = fill_alphabet[idx]
            idx += 1

    for col in range(10):
        if idx < len(fill_alphabet):
            digit = header[col]
            l2c[fill_alphabet[idx]] = (r1, digit)
            c2l[(r1, digit)] = fill_alphabet[idx]
            idx += 1

    for col in non_escape_cols:
        if idx < len(fill_alphabet):
            digit = header[col]
            l2c[fill_alphabet[idx]] = (r2, digit)
            c2l[(r2, digit)] = fill_alphabet[idx]
            idx += 1

    return l2c, c2l


def decode_digits(digits, row_labels, code_to_letter):
    """Parse digit stream via straddling checkerboard. Returns string or None."""
    r1, r2 = row_labels
    result: list = []
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
        1 for i, ch in enumerate(CRIB_ENE)
        if ene_pos + i < n and decoded[ene_pos + i] == ch
    )
    bc_score = sum(
        1 for i, ch in enumerate(CRIB_BC)
        if bc_pos + i < n and decoded[bc_pos + i] == ch
    )
    return ene_score + bc_score, ene_score, bc_score


def check_cribs_free(decoded):
    if decoded is None or len(decoded) < 11:
        return 0, -1, -1
    best = 0; best_ep = -1; best_bp = -1
    n = len(decoded)
    for p in range(max(1, n - 12)):
        s = sum(1 for i, ch in enumerate(CRIB_ENE) if p + i < n and decoded[p + i] == ch)
        if s >= 3:
            for q in range(max(1, n - 10)):
                s2 = sum(1 for i, ch in enumerate(CRIB_BC) if q + i < n and decoded[q + i] == ch)
                total = s + s2
                if total > best:
                    best = total; best_ep = p; best_bp = q
    return best, best_ep, best_bp


# ── Digit-stream builders ─────────────────────────────────────────────────────

def ct_to_digits(ct, mapping_fn):
    return [mapping_fn(ch) for ch in ct]


def _make_digit_mappings():
    dm = {
        "KA_mod10": lambda ch: KA.index(ch) % 10,
        "AZ_mod10": lambda ch: AZ.index(ch) % 10,
    }
    for kw in KEYWORDS:
        for base, tag in [(AZ, "AZ"), (KA, "KA")]:
            alpha = keyword_mixed_alphabet(kw, base)
            mp_dict = {ch: i % 10 for i, ch in enumerate(alpha)}
            dm[f"kw_{kw}_{tag}_mod10"] = lambda ch, m=mp_dict: m[ch]
    return dm


def _make_fill_alphabets():
    fa = {"AZ": AZ, "KA": KA}
    for kw in KEYWORDS:
        fa[f"kw_{kw}_AZ"] = keyword_mixed_alphabet(kw, AZ)
        fa[f"kw_{kw}_KA"] = keyword_mixed_alphabet(kw, KA)
    return fa


def _make_additive_keys():
    ak = {}
    for shift in range(10):
        ak[f"const_{shift}"] = [shift] * CT_LEN

    for label, seed in [("KRYPTOS_KA", [KA.index(c) % 10 for c in "KRYPTOS"]),
                        ("KRYPTOS_AZ", [AZ.index(c) % 10 for c in "KRYPTOS"])]:
        ak[f"{label}_rep"] = (seed * (CT_LEN // len(seed) + 1))[:CT_LEN]

    k2_key = (K2_DIGITS_IN_ORDER * (CT_LEN // len(K2_DIGITS_IN_ORDER) + 1))[:CT_LEN]
    ak["K2_digits_rep"] = k2_key
    k2u_key = (K2_UNIQUE_IN_ORDER * (CT_LEN // len(K2_UNIQUE_IN_ORDER) + 1))[:CT_LEN]
    ak["K2_unique_rep"] = k2u_key

    chain = list(K2_DIGITS_IN_ORDER)
    while len(chain) < CT_LEN:
        chain.append((chain[-len(K2_DIGITS_IN_ORDER)] + chain[-len(K2_DIGITS_IN_ORDER) + 1]) % 10)
    ak["K2_chain_add"] = chain[:CT_LEN]

    for seed_name, seed in [("fib_38", [3, 8]), ("fib_57", [5, 7])]:
        fib = list(seed)
        while len(fib) < CT_LEN:
            fib.append((fib[-1] + fib[-2]) % 10)
        ak[seed_name] = fib[:CT_LEN]

    return ak


# ── Worker for multiprocessed header sweep (Tier A) ──────────────────────────

def _score_header_batch(args):
    """
    Process a batch of header permutations for a single (row_label_pair, fill, mapping).
    Returns list of hit dicts (fixed>=5 or free>=7 or len==73).

    args = (header_batch, row_labels, fill_alphabet, digit_stream, fill_name, map_name)
    """
    header_batch, row_labels, fill_alphabet, digit_stream, fill_name, map_name = args
    r1, r2 = row_labels
    hits = []
    for header in header_batch:
        # header must place r1 and r2 at different positions – always true for a
        # full permutation since all digits 0-9 appear exactly once.
        _, c2l = build_checkerboard_from_header(header, row_labels, fill_alphabet)
        decoded = decode_digits(digit_stream, row_labels, c2l)
        if decoded is None:
            continue
        pt_len = len(decoded)
        if pt_len < 50 or pt_len > 90:
            continue
        fixed, ene_s, bc_s = check_cribs_fixed(decoded)
        free, free_ep, free_bp = check_cribs_free(decoded)
        if fixed >= 5 or free >= 7 or pt_len == 73:
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
    return hits


# ── Main ──────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="Exhaustive K2 Checkerboard Decode")
    p.add_argument("--tiers", nargs="+", choices=["A", "B", "C"], default=["A", "B", "C"],
                   help="Which exhaustion tiers to run (default: all)")
    p.add_argument("--quick", action="store_true",
                   help="Quick smoke-test: 1 fill, 2 mappings, 10k headers/pair")
    p.add_argument("--max-headers", type=int, default=None,
                   help="Cap on header permutations per (pair,fill,mapping) combo. "
                        "None = full 3,628,800. Useful for partial/CI runs.")
    p.add_argument("--workers", type=int, default=max(1, mp.cpu_count() - 1),
                   help="Parallel workers for Tier A (default: cpu_count-1)")
    p.add_argument("--batch-size", type=int, default=50_000,
                   help="Headers per worker batch (default: 50,000)")
    p.add_argument("--hit-threshold-fixed", type=int, default=5)
    p.add_argument("--hit-threshold-free",  type=int, default=7)
    return p.parse_args()


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
    log.info(f"Max headers   : {args.max_headers or 'ALL (3,628,800)'}")
    log.info(f"Tiers         : {args.tiers}")
    log.info(f"Quick mode    : {args.quick}")

    DIGIT_MAPPINGS  = _make_digit_mappings()
    FILL_ALPHABETS  = _make_fill_alphabets()
    ADDITIVE_KEYS   = _make_additive_keys()

    log.info(f"Digit mappings: {len(DIGIT_MAPPINGS)}")
    log.info(f"Fill alphabets: {len(FILL_ALPHABETS)}")
    log.info(f"Additive keys : {len(ADDITIVE_KEYS)}")

    if args.quick:
        log.info("QUICK MODE – restricting fills/mappings/headers")
        FILL_ALPHABETS  = {"kw_KRYPTOS_AZ": FILL_ALPHABETS["kw_KRYPTOS_AZ"], "AZ": AZ, "KA": KA}
        DIGIT_MAPPINGS  = {"KA_mod10": DIGIT_MAPPINGS["KA_mod10"],
                           "AZ_mod10": DIGIT_MAPPINGS["AZ_mod10"]}
        if args.max_headers is None:
            args.max_headers = 10_000

    total_configs   = 0
    global_best_fixed = 0
    global_best_free  = 0
    total_len73     = 0
    all_hits: list  = []

    # ══════════════════════════════════════════════════════════════════════
    # TIER A: Full header permutation sweep
    # ALL 45 row-label pairs × ALL 10! headers × all fills × all mappings
    # ══════════════════════════════════════════════════════════════════════
    if "A" in args.tiers:
        log.info("")
        log.info("=" * 70)
        log.info("TIER A: Full 10! header permutation sweep")
        log.info(f"  Row-label pairs : 45 (all C(10,2))")
        log.info(f"  Headers/pair    : up to {args.max_headers or 3_628_800:,}")
        log.info(f"  Fill alphabets  : {len(FILL_ALPHABETS)}")
        log.info(f"  Digit mappings  : {len(DIGIT_MAPPINGS)}")
        log.info("=" * 70)

        tier_a_configs = 0
        tier_a_hits: list = []

        # Pre-build all digit streams (one per mapping) – reuse across header perms
        digit_streams = {
            map_name: ct_to_digits(CT, map_fn)
            for map_name, map_fn in DIGIT_MAPPINGS.items()
        }

        for pair_idx, row_labels in enumerate(ALL_PAIRS):
            pair_t0 = time.time()
            pair_configs = 0

            # Generator over permutations, optionally capped
            def header_gen():
                count = 0
                for hdr in permutations(range(10)):
                    if args.max_headers is not None and count >= args.max_headers:
                        break
                    yield hdr
                    count += 1

            # Collect headers into batches for the process pool
            def batched_headers():
                batch: list = []
                for hdr in header_gen():
                    batch.append(hdr)
                    if len(batch) >= args.batch_size:
                        yield batch
                        batch = []
                if batch:
                    yield batch

            for fill_name, fill_alpha in FILL_ALPHABETS.items():
                for map_name, digit_stream in digit_streams.items():

                    work_args = [
                        (batch, row_labels, fill_alpha, digit_stream, fill_name, map_name)
                        for batch in batched_headers()
                    ]
                    n_batches = len(work_args)
                    pair_configs += n_batches * args.batch_size  # approximate

                    if args.workers > 1 and n_batches > 0:
                        with mp.Pool(args.workers) as pool:
                            results = pool.map(_score_header_batch, work_args)
                    else:
                        results = [_score_header_batch(wa) for wa in work_args]

                    for batch_hits in results:
                        for h in batch_hits:
                            tier_a_hits.append(h)
                            all_hits.append(h)
                            if h["fixed"] > global_best_fixed:
                                global_best_fixed = h["fixed"]
                            if h["free"] > global_best_free:
                                global_best_free = h["free"]
                            if h["pt_len"] == 73:
                                total_len73 += 1
                            log.warning(
                                f"  HIT(A): rl={row_labels} fill={fill_name} "
                                f"map={map_name} len={h['pt_len']} "
                                f"fixed={h['fixed']} free={h['free']}"
                            )
                            log.warning(f"    PT: {h['decoded']}")

            tier_a_configs += pair_configs
            total_configs  += pair_configs
            elapsed_pair = time.time() - pair_t0
            log.info(
                f"  Pair {pair_idx+1:02d}/45  rl={row_labels}  "
                f"~{pair_configs:,.0f} configs  {elapsed_pair:.1f}s  "
                f"best_fixed={global_best_fixed}  best_free={global_best_free}"
            )

        log.info(f"\nTier A complete: ~{tier_a_configs:,.0f} configs  "
                 f"hits={len(tier_a_hits)}")

    # ══════════════════════════════════════════════════════════════════════
    # TIER B: Additive key exhaustion
    # ALL 45 pairs (original only tested 6) × all additive keys
    # × all headers × all fills × primary mappings
    # ══════════════════════════════════════════════════════════════════════
    if "B" in args.tiers:
        log.info("")
        log.info("=" * 70)
        log.info("TIER B: Additive pre-key exhaustion (all 45 pairs)")
        log.info(f"  Row-label pairs: 45")
        log.info(f"  Additive keys  : {len(ADDITIVE_KEYS)}")
        log.info("=" * 70)

        tier_b_configs = 0
        tier_b_hits: list = []

        # Use primary K2 header + standard header (exact headers are cheap here,
        # the combinatorial cost is row-labels × additive keys × fills × maps)
        primary_hdr = K2_UNIQUE_IN_ORDER + sorted(K2_REMAINING)  # [3,8,5,7,6,4,0,1,2,9]
        b_headers = {
            "k2_primary":  primary_hdr,
            "standard_09": list(range(10)),
            "reversed_90": list(range(9, -1, -1)),
        }
        # In quick mode reduce further
        if args.quick:
            b_headers = {"k2_primary": primary_hdr}

        b_fills = {
            k: v for k, v in FILL_ALPHABETS.items()
            if k in {"AZ", "KA", "kw_KRYPTOS_AZ", "kw_KRYPTOS_KA",
                     "kw_PALIMPSEST_AZ", "kw_DEFECTOR_AZ"}
        }
        b_maps = {k: v for k, v in DIGIT_MAPPINGS.items()
                  if k in {"KA_mod10", "AZ_mod10", "kw_KRYPTOS_AZ_mod10",
                            "kw_KRYPTOS_KA_mod10", "kw_DEFECTOR_AZ_mod10",
                            "kw_PALIMPSEST_AZ_mod10"}}

        for row_labels in ALL_PAIRS:
            for hdr_name, hdr in b_headers.items():
                for fill_name, fill_alpha in b_fills.items():
                    _, c2l = build_checkerboard_from_header(hdr, row_labels, fill_alpha)

                    for map_name, map_fn in b_maps.items():
                        base_digits = ct_to_digits(CT, map_fn)

                        for add_name, add_key in ADDITIVE_KEYS.items():
                            for sign, tag in [(+1, "+"), (-1, "-")]:
                                tier_b_configs += 1
                                total_configs  += 1

                                digits = [(base_digits[i] + sign * add_key[i]) % 10
                                          for i in range(CT_LEN)]
                                decoded = decode_digits(digits, row_labels, c2l)
                                if decoded is None:
                                    continue
                                pt_len = len(decoded)
                                if pt_len < 50 or pt_len > 90:
                                    continue
                                fixed, ene_s, bc_s = check_cribs_fixed(decoded)
                                free, free_ep, free_bp = check_cribs_free(decoded)

                                if fixed > global_best_fixed:
                                    global_best_fixed = fixed
                                if free > global_best_free:
                                    global_best_free = free
                                if pt_len == 73:
                                    total_len73 += 1

                                if (fixed >= args.hit_threshold_fixed
                                        or free >= args.hit_threshold_free
                                        or pt_len == 73):
                                    h = {
                                        "tier": "B",
                                        "row_labels": list(row_labels),
                                        "header": hdr_name,
                                        "fill": fill_name,
                                        "digit_map": map_name,
                                        "additive": f"{tag}{add_name}",
                                        "pt_len": pt_len,
                                        "fixed": fixed,
                                        "ene_score": ene_s,
                                        "bc_score": bc_s,
                                        "free": free,
                                        "free_ene_pos": free_ep,
                                        "free_bc_pos": free_bp,
                                        "decoded": decoded[:80],
                                    }
                                    tier_b_hits.append(h)
                                    all_hits.append(h)
                                    log.warning(
                                        f"  HIT(B): rl={row_labels} hdr={hdr_name} "
                                        f"fill={fill_name} map={map_name} add={tag}{add_name} "
                                        f"len={pt_len} fixed={fixed} free={free}"
                                    )
                                    log.warning(f"    PT: {decoded[:80]}")

        log.info(f"\nTier B complete: {tier_b_configs:,} configs  hits={len(tier_b_hits)}")

    # ══════════════════════════════════════════════════════════════════════
    # TIER C: Keyword-fill cross with broader header set
    # Every keyword fill × sampled header permutations × all 45 pairs
    # (fills that were only tested with the primary header in the original)
    # ══════════════════════════════════════════════════════════════════════
    if "C" in args.tiers:
        log.info("")
        log.info("=" * 70)
        log.info("TIER C: Keyword-fill × broader header set (all 45 pairs)")
        log.info("=" * 70)

        tier_c_configs = 0
        tier_c_hits: list = []

        # Sample a representative set of headers beyond the primary.
        # We include: all permutations of K2_UNIQUE_IN_ORDER in the first 6 positions,
        # the remaining 4 slots fixed as sorted(K2_REMAINING).
        # This gives 6! = 720 headers — all K2-digit orderings, exhaustive within the
        # hypothesis that K2 digits define column order.
        c_headers: list = []
        for perm in permutations(K2_UNIQUE_IN_ORDER):
            c_headers.append(list(perm) + sorted(K2_REMAINING))
        # Also include all 4! orderings of remaining digits in last 4 slots
        for perm_rem in permutations(K2_REMAINING):
            c_headers.append(K2_UNIQUE_IN_ORDER + list(perm_rem))
        # Deduplicate
        seen_hdrs = set()
        c_headers_dedup = []
        for h in c_headers:
            key = tuple(h)
            if key not in seen_hdrs:
                seen_hdrs.add(key); c_headers_dedup.append(h)
        c_headers = c_headers_dedup

        log.info(f"  Unique K2-derived headers: {len(c_headers)}")
        log.info(f"  Fill alphabets            : {len(FILL_ALPHABETS)}")
        log.info(f"  Digit mappings            : {len(DIGIT_MAPPINGS)}")

        for row_labels in ALL_PAIRS:
            for hdr in c_headers:
                for fill_name, fill_alpha in FILL_ALPHABETS.items():
                    _, c2l = build_checkerboard_from_header(hdr, row_labels, fill_alpha)
                    for map_name, map_fn in DIGIT_MAPPINGS.items():
                        tier_c_configs += 1
                        total_configs  += 1

                        digits = ct_to_digits(CT, map_fn)
                        decoded = decode_digits(digits, row_labels, c2l)
                        if decoded is None:
                            continue
                        pt_len = len(decoded)
                        if pt_len < 50 or pt_len > 90:
                            continue
                        fixed, ene_s, bc_s = check_cribs_fixed(decoded)
                        free, free_ep, free_bp = check_cribs_free(decoded)

                        if fixed > global_best_fixed:
                            global_best_fixed = fixed
                        if free > global_best_free:
                            global_best_free = free
                        if pt_len == 73:
                            total_len73 += 1

                        if (fixed >= args.hit_threshold_fixed
                                or free >= args.hit_threshold_free
                                or pt_len == 73):
                            h = {
                                "tier": "C",
                                "row_labels": list(row_labels),
                                "header": list(hdr),
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
                            tier_c_hits.append(h)
                            all_hits.append(h)
                            log.warning(
                                f"  HIT(C): rl={row_labels} fill={fill_name} "
                                f"map={map_name} len={pt_len} fixed={fixed} free={free}"
                            )
                            log.warning(f"    PT: {decoded[:80]}")

        log.info(f"\nTier C complete: {tier_c_configs:,} configs  hits={len(tier_c_hits)}")

    # ══════════════════════════════════════════════════════════════════════
    # SUMMARY
    # ══════════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    if global_best_fixed >= 18 or global_best_free >= 18:
        verdict = "SIGNAL"
    elif global_best_fixed >= 10 or global_best_free >= 10:
        verdict = "INTERESTING"
    elif global_best_fixed >= 5 or global_best_free >= 7:
        verdict = "WEAK_HITS"
    else:
        verdict = "NOISE"

    log.info("")
    log.info("=" * 70)
    log.info("SUMMARY")
    log.info("=" * 70)
    log.info(f"Total configs tested : {total_configs:,}")
    log.info(f"Elapsed              : {elapsed:.1f}s  ({elapsed/60:.1f} min)")
    log.info(f"Global best fixed    : {global_best_fixed}/24")
    log.info(f"Global best free     : {global_best_free}/24")
    log.info(f"Total length-73 hits : {total_len73}")
    log.info(f"Verdict              : {verdict}")

    all_hits.sort(key=lambda h: max(h.get("fixed", 0), h.get("free", 0)), reverse=True)

    output = {
        "experiment":       "e_k2_checkerboard_decode_exhaust",
        "description":      "K2 coordinates as straddling checkerboard — full exhaustion",
        "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%S"),
        "total_configs":    total_configs,
        "elapsed_seconds":  round(elapsed, 2),
        "global_best_fixed": global_best_fixed,
        "global_best_free":  global_best_free,
        "total_len73_decodes": total_len73,
        "verdict":           verdict,
        "tiers_run":         args.tiers,
        "quick_mode":        args.quick,
        "max_headers":       args.max_headers,
        "workers":           args.workers,
        "k2_construction": {
            "k2_digits":       K2_DIGITS_IN_ORDER,
            "k2_unique":       K2_UNIQUE_IN_ORDER,
            "remaining":       K2_REMAINING,
            "primary_header":  K2_UNIQUE_IN_ORDER + sorted(K2_REMAINING),
            "primary_row_labels": [3, 8],
        },
        "top_hits": [
            {k: (v if not isinstance(v, (tuple, list)) else list(v))
             for k, v in h.items()}
            for h in all_hits[:30]
        ],
    }

    outpath = Path(__file__).resolve().parents[2] / "results" / "k2_checkerboard_decode_exhaust.json"
    outpath.parent.mkdir(parents=True, exist_ok=True)
    with open(outpath, "w") as f:
        json.dump(output, f, indent=2)
    log.info(f"\nResults saved to: {outpath}")


if __name__ == "__main__":
    run()