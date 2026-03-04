#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""blitz_wildcard.py — Lateral & creative permutation approaches for K4 Model 2.

Implements 13 novel families not previously attempted:
  0. CSP Constraint Propagation — force-assign crib positions, enumerate valid assignments
  1. Self-referential permutations — K4 letter values define reading order
  2. Interleaved stream decomposition — split into p streams, test orderings
  3. K1/K2/K3 CT/PT as transposition key
  4. Fold permutations — all 96 fold points + variants
  5. Quadratic/cubic permutations mod 97
  6. Clock arithmetic — 24-fold Weltzeituhr symmetry
  7. GE running key / mod-26 difference with K4
  8. KA-index sort and relabeling permutations
  9. Grille coordinate permutations (novel formulas)
  10. Creative/lateral approaches (8-lines-73, period-8, morse, etc.)
  11. CSP with structured extensions (GE-ordered, period-8)
  12. K4<->GE positional mapping
  13. CSP best config deep dive

Run: PYTHONPATH=src python3 -u scripts/blitz_wildcard.py
"""
from __future__ import annotations

import sys
import os
import json
import time
import random
import itertools
from collections import defaultdict, Counter
from pathlib import Path

sys.path.insert(0, 'scripts')
from kbot_harness import (
    test_perm, test_unscramble, score_text, score_text_per_char,
    has_cribs, vig_decrypt, vig_encrypt, beau_decrypt,
    apply_permutation, load_quadgrams,
    K4_CARVED, GRILLE_EXTRACT, AZ, KA, KEYWORDS, CRIBS,
)

# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
N = 97
GE = GRILLE_EXTRACT  # 106 chars (no T)

# Crib positions in real_CT / PT space (0-indexed)
CRIB_DEFS = [
    (21, "EASTNORTHEAST"),   # positions 21-33
    (63, "BERLINCLOCK"),     # positions 63-73
]
CRIB_MAP = {}
for _start, _text in CRIB_DEFS:
    for _j, _ch in enumerate(_text):
        CRIB_MAP[_start + _j] = _ch

# K4 positions indexed by letter
K4_POSITIONS = defaultdict(list)
for _i, _ch in enumerate(K4_CARVED):
    K4_POSITIONS[_ch].append(_i)

# Grille binary mask (28 rows, 1=HOLE)
GRILLE_MASK_RAW = [
    "000000001010100000000010000000001",
    "100000000010000001000100110000011",
    "000000000000001000000000000000011",
    "000000000000000000001000000100110",
    "000000010000000010000100000000110",
    "000000001000000000000000000000011",
    "100000000000000000000000000000011",
    "000000000000000000000001000001000",
    "000000000000000000001000000010000",
    "000000000000000000000000000001000",
    "000000001000000000000000000000000",
    "000001100000000000000000000001000",
    "000000000000001000100000000000010",
    "000000000001000000000000000010000",
    "000110100001000000000000001000010",
    "000010100000000000000000010000010",
    "001001000010010000000000000100010",
    "000000000001000000000100000100010",
    "000000000000010001001000000010001",
    "000000000000000010010000000001000",
    "000000001100000010100100010001001",
    "000000000000000100001010100100011",
    "000000000100000000001000011000010",
    "100000000000000000001000001000010",
    "100000010000010000001000000000010",
    "000010000000000000010000100000011",
    "000000000000000000001000010000000",
    "000000000000001000000010100000010",
]
GRILLE_ROWS = len(GRILLE_MASK_RAW)
GRILLE_COLS = max(len(r) for r in GRILLE_MASK_RAW)
HOLE_POSITIONS = [
    (r, c)
    for r, row_str in enumerate(GRILLE_MASK_RAW)
    for c, ch in enumerate(row_str)
    if ch == '1'
]

# K3 ciphertext (from known Kryptos sculpture text)
K3_CT = (
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNE"
    "TPRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETP"
    "OLSEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEE"
    "FOASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEVMEAEEO"
    "IDYMWAERITXAPNETOABMIVKSZALMOTHEOXFRAMPNTTHEBFCEAGAIVEASDAEHH"
)
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHATENCUMBEREDTHE"
    "LOWERPARTOFTHEDOORWAYWASREMOVEDWITHTREMBLINGHANDSIMADEATINYBREAC"
    "HINTHEUPPE"
)
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"

# ─────────────────────────────────────────────────────────────────────────────
# RESULTS TRACKING
# ─────────────────────────────────────────────────────────────────────────────
results_dir = Path("results/blitz_wildcard")
results_dir.mkdir(parents=True, exist_ok=True)

all_results: list[dict] = []
best_score = -9999.0
best_entry: dict | None = None
total_tested = 0
CRIB_HITS: list[dict] = []


def report_result(approach, note, score, cribs, extra=None):
    global best_score, best_entry, total_tested, CRIB_HITS
    total_tested += 1
    entry = {
        "approach": approach,
        "note": str(note)[:300],
        "score": score,
        "cribs": cribs,
        "extra": extra or {},
    }
    all_results.append(entry)
    if cribs:
        CRIB_HITS.append(entry)
        print(f"\n{'='*60}")
        print(f"🎯 CRIB HIT! approach={approach}, score={score:.2f}")
        print(f"   cribs={cribs}, note={note}")
        print(f"{'='*60}\n")
    if score > best_score:
        best_score = score
        best_entry = entry
        if score > -600:
            print(f"  ★ NEW BEST [{approach}]: score={score:.2f}")


def try_sigma(sigma, name, note=""):
    """Validate + test a permutation σ where real_CT[j]=K4[σ[j]]."""
    sigma = list(sigma)
    if len(sigma) != N or sorted(sigma) != list(range(N)):
        return None
    res = test_perm(sigma)
    if res is None:
        return None
    score = res.get("score", -9999)
    crib_hit = res.get("crib_hit", False)
    cribs = res.get("cribs", [])
    report_result(name, note, score, cribs if crib_hit else [], res)
    return res


def save_results():
    out = results_dir / "results.json"
    with open(out, "w") as f:
        json.dump({
            "total_tested": total_tested,
            "best_score": best_score,
            "crib_hits": len(CRIB_HITS),
            "best_entry": best_entry,
            "crib_hit_details": CRIB_HITS,
            "all_results": all_results[-1000:],
        }, f, indent=2)
    return out


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def compute_expected_ct(keyword, cipher_type, alpha=AZ):
    """Compute expected real_CT chars at each crib position for given key."""
    expected = {}
    for crib_start, crib_text in CRIB_DEFS:
        for j, pt_char in enumerate(crib_text):
            pos = crib_start + j
            ki = alpha.index(keyword[pos % len(keyword)])
            pi = alpha.index(pt_char)
            if cipher_type == "vig":
                expected[pos] = alpha[(pi + ki) % 26]
            elif cipher_type == "beau":
                expected[pos] = alpha[(ki - pi) % 26]
    return expected


def argsort(seq):
    """Return indices that would sort seq (stable)."""
    return sorted(range(len(seq)), key=lambda i: seq[i])


def is_valid_perm(sigma, n=N):
    return len(sigma) == n and sorted(sigma) == list(range(n))


# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 0: CSP CONSTRAINT PROPAGATION
# Key insight: for each key config, compute expected real_CT at 24 crib positions.
# Find which K4_CARVED positions have those chars. Enumerate valid assignments.
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("APPROACH 0: CSP Constraint Propagation")
print("="*70)
t0 = time.time()

ALL_CONFIGS = [
    (kw, alpha_name, alpha, cipher_name)
    for kw in KEYWORDS
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]
    for cipher_name in ["vig", "beau"]
]


def csp_enumerate(expected_map, cap=50000):
    """
    Enumerate all valid 24-position crib assignments.
    expected_map = {crib_pos: expected_CT_char}
    Returns list of dicts {crib_pos: carved_pos}.
    """
    crib_positions = sorted(expected_map.keys())
    domains = {}
    for pos in crib_positions:
        ch = expected_map[pos]
        avail = list(K4_POSITIONS.get(ch, []))
        if not avail:
            return []
        domains[pos] = avail

    # Most-constrained first
    order = sorted(crib_positions, key=lambda p: len(domains[p]))
    results_list: list[dict] = []
    assignment: dict = {}
    used: set = set()

    def bt(idx):
        if len(results_list) >= cap:
            return
        if idx == len(order):
            results_list.append(dict(assignment))
            return
        pos = order[idx]
        for cp in domains[pos]:
            if cp not in used:
                assignment[pos] = cp
                used.add(cp)
                bt(idx + 1)
                used.discard(cp)
                del assignment[pos]

    bt(0)
    return results_list


def extend_sigma(crib_assign, sort_key=None):
    """Extend a 24-position crib assignment to a full 97-position permutation."""
    used = set(crib_assign.values())
    free_rt = sorted(set(range(N)) - set(crib_assign.keys()))
    free_cv = sorted(set(range(N)) - used)

    if sort_key:
        free_rt = sorted(free_rt, key=sort_key)
        free_cv = sorted(free_cv, key=sort_key)

    sigma = [0] * N
    for pos, cp in crib_assign.items():
        sigma[pos] = cp
    for i, pos in enumerate(free_rt):
        sigma[pos] = free_cv[i]
    return sigma


# Feasibility analysis
csp_summary = []
for kw, alpha_name, alpha, cipher_name in ALL_CONFIGS:
    expected = compute_expected_ct(kw, cipher_name, alpha)
    domain_sizes = {}
    impossible = False
    for pos, ch in expected.items():
        avail = K4_POSITIONS.get(ch, [])
        if not avail:
            impossible = True
            break
        domain_sizes[pos] = len(avail)

    if impossible:
        csp_summary.append({"config": f"{kw}/{cipher_name}/{alpha_name}", "status": "IMPOSSIBLE"})
        continue

    import math
    log_ub = sum(math.log(sz) for sz in domain_sizes.values())
    forced = sum(1 for sz in domain_sizes.values() if sz == 1)
    csp_summary.append({
        "config": f"{kw}/{cipher_name}/{alpha_name}",
        "status": "FEASIBLE",
        "forced": forced,
        "log_ub": log_ub,
        "domain_sizes": domain_sizes,
    })

feasible = [s for s in csp_summary if s["status"] == "FEASIBLE"]
feasible.sort(key=lambda s: (s.get("log_ub", 9999), -s.get("forced", 0)))

print(f"\n{len(feasible)}/{len(ALL_CONFIGS)} configs feasible.")
print("Top 15 most constrained configs:")
for s in feasible[:15]:
    print(f"  {s['config']}: forced={s['forced']}/24, log_ub={s.get('log_ub',0):.2f}")

# Show forced assignments for top config
if feasible:
    best_cfg = feasible[0]
    cfg_str = best_cfg["config"]
    kw, cipher_name, alpha_name = cfg_str.split("/")
    alpha = AZ if alpha_name == "AZ" else KA
    expected_top = compute_expected_ct(kw, cipher_name, alpha)
    print(f"\nForced/near-forced assignments for {cfg_str}:")
    for pos in sorted(expected_top.keys()):
        avail = K4_POSITIONS.get(expected_top[pos], [])
        flag = "**FORCED**" if len(avail) == 1 else ""
        print(f"  σ({pos:2d}): PT={CRIB_MAP.get(pos,'?')}, expCT={expected_top[pos]}, "
              f"K4_avail={avail} {flag}")

# Enumerate and test for top 20 configs
print("\nEnumerating and testing for top 20 configs...")
EXTENSION_STRATEGIES = [
    ("natural", None),
    ("reverse", lambda p: -p),
    ("mod7",    lambda p: (p % 7, p // 7)),
    ("mod8",    lambda p: (p % 8, p // 8)),
    ("GE",      lambda p: AZ.index(GE[p % len(GE)])),
    ("K4val",   lambda p: AZ.index(K4_CARVED[p])),
]

for cfg_idx, s in enumerate(feasible[:20]):
    cfg_str = s["config"]
    kw, cipher_name, alpha_name = cfg_str.split("/")
    alpha = AZ if alpha_name == "AZ" else KA
    expected = compute_expected_ct(kw, cipher_name, alpha)
    assignments = csp_enumerate(expected, cap=10000)

    print(f"\n  Config {cfg_idx+1}: {cfg_str} → {len(assignments)} valid assignments")

    for assign_idx, assign in enumerate(assignments):
        for strat_name, strat_fn in EXTENSION_STRATEGIES:
            sigma = extend_sigma(assign, strat_fn)
            if is_valid_perm(sigma):
                try_sigma(sigma, f"CSP-{cfg_str}-{strat_name}",
                         f"assign#{assign_idx}")

        if assign_idx % 1000 == 999:
            print(f"    ... {assign_idx+1}/{len(assignments)} assignments tested")

print(f"\nCSP: {total_tested} tested, {time.time()-t0:.1f}s elapsed")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 1: SELF-REFERENTIAL PERMUTATIONS
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("APPROACH 1: Self-Referential Permutations")
print("="*70)
t1 = time.time()

for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    # Argsort by letter value
    sig = argsort([alpha.index(K4_CARVED[i]) for i in range(N)])
    try_sigma(sig, f"SELF-argsort-{alpha_name}", "argsort by letter value")

    # Inverse
    inv = [0] * N
    for rank, pos in enumerate(sig):
        inv[pos] = rank
    try_sigma(inv, f"SELF-inv-argsort-{alpha_name}", "inverse argsort")

    # Reverse tie-breaking
    sig_rev = argsort([(alpha.index(K4_CARVED[i]), -i) for i in range(N)])
    try_sigma(sig_rev, f"SELF-argsort-rev-{alpha_name}", "argsort, rev pos tie-break")

    # 2-gram sort
    sig_2g = argsort([(alpha.index(K4_CARVED[i]), alpha.index(K4_CARVED[(i+1)%N])) for i in range(N)])
    try_sigma(sig_2g, f"SELF-2gram-{alpha_name}", "2-gram argsort")

# Rank-within-letter-group (each letter's positions ranked by occurrence order)
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    running_c: dict = {}
    rank_list = []
    for i, ch in enumerate(K4_CARVED):
        if ch not in running_c:
            running_c[ch] = 0
        rank_list.append((alpha.index(ch), running_c[ch], i))
        running_c[ch] += 1
    sig_r = [t[2] for t in sorted(rank_list)]
    try_sigma(sig_r, f"SELF-rank-within-{alpha_name}", f"rank within letter ({alpha_name})")

print(f"Self-ref: {total_tested} tested, {time.time()-t1:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 2: INTERLEAVED STREAMS (cipher-aware)
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("APPROACH 2: Interleaved Streams")
print("="*70)
t2 = time.time()


def make_interleave_sigma(period, group_order):
    """
    Interleave permutation: real_CT is col-major (read by columns in group_order).
    sigma[j] = carved position of real_CT[j].
    Equivalent to: fill real_CT into rows, read by columns in group_order.
    """
    cols = [list(range(r, N, period)) for r in range(period)]
    carved_pos = [0] * N
    offset = 0
    for col_idx in group_order:
        for sub_idx, real_pos in enumerate(cols[col_idx]):
            carved_pos[real_pos] = offset + sub_idx
        offset += len(cols[col_idx])
    return carved_pos


# Cipher-aware: for each config, find group ordering that matches most cribs
for period in [7, 8, 13, 11, 6, 5]:
    for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
        for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
            for cipher_name in ["vig", "beau"]:
                expected = compute_expected_ct(kw, cipher_name, alpha)

                if period <= 7:
                    orders = list(itertools.permutations(range(period)))
                else:
                    orders = [tuple(range(period)), tuple(reversed(range(period)))]
                    rng = random.Random(42)
                    for _ in range(300):
                        o = list(range(period))
                        rng.shuffle(o)
                        orders.append(tuple(o))

                best_match = -1
                best_ord = None
                for order in orders:
                    sig = make_interleave_sigma(period, order)
                    if not is_valid_perm(sig):
                        continue
                    match = sum(1 for pos, ch in expected.items()
                                if sig[pos] < N and K4_CARVED[sig[pos]] == ch)
                    if match > best_match:
                        best_match = match
                        best_ord = order

                if best_ord and best_match >= 5:
                    sig = make_interleave_sigma(period, best_ord)
                    if is_valid_perm(sig):
                        try_sigma(sig,
                                  f"INTERLEAVE-p{period}-{kw}-{cipher_name}-{alpha_name}",
                                  f"best_match={best_match}/24, order={best_ord}")
                        if best_match >= 10:
                            print(f"  HIGH MATCH: p={period} {kw}/{cipher_name}/{alpha_name}"
                                  f" match={best_match}/24")

print(f"Interleaved: {total_tested} tested, {time.time()-t2:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 3: K1/K3 AS TRANSPOSITION KEY
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("APPROACH 3: K1/K3 CT/PT as Transposition Key")
print("="*70)
t3 = time.time()

k3_ct_97 = (K3_CT * 2)[:97]
k3_pt_97 = (K3_PT * 2)[:97]
k1_pt_97 = (K1_PT * 2)[:97]

for source_name, source in [
    ("K3CT", k3_ct_97),
    ("K3PT", k3_pt_97),
    ("K1PT", k1_pt_97),
]:
    for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
        idx_seq = [alpha.index(c) if c in alpha else 0 for c in source]
        sig = argsort(idx_seq)
        try_sigma(sig, f"{source_name}-argsort-{alpha_name}", f"argsort by {source_name}")

        inv = [0] * N
        for rank, pos in enumerate(sig):
            inv[pos] = rank
        try_sigma(inv, f"{source_name}-inv-argsort-{alpha_name}", "inverse")

# Columnar transposition with various widths
def columnar_from_key(key_str, width):
    """Columnar transposition: fill row by row, read col by col in key order."""
    key = key_str[:width]
    col_order = argsort([AZ.index(c) if c in AZ else ord(c) for c in key])
    n_rows = (N + width - 1) // width
    # sigma[i] = where position i goes in the output
    result = []
    for col in col_order:
        for row in range(n_rows):
            pos = row * width + col
            if pos < N:
                result.append(pos)
    return result[:N]

for source_name, source in [("K3CT", K3_CT), ("K3PT", K3_PT), ("K1PT", K1_PT)]:
    for width in [7, 8, 11, 13]:
        if width <= len(source):
            sig = columnar_from_key(source, width)
            if is_valid_perm(sig):
                try_sigma(sig, f"{source_name}-columnar-w{width}", f"columnar w={width}")

print(f"K1/K3 key: {total_tested} tested, {time.time()-t3:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 4: FOLD PERMUTATIONS
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("APPROACH 4: Fold Permutations")
print("="*70)
t4 = time.time()


def fold_sigma(n, fp):
    """Fold at fp: swap positions i and (2*fp - 1 - i) for i < fp."""
    s = list(range(n))
    for i in range(fp):
        mirror = 2 * fp - 1 - i
        if 0 <= mirror < n:
            s[i], s[mirror] = s[mirror], s[i]
    return s


for fp in range(2, N - 1):
    s = fold_sigma(N, fp)
    if is_valid_perm(s):
        try_sigma(s, f"FOLD-{fp}", f"fold at {fp}")

# Double folds
for fp1 in [13, 21, 33, 49, 63, 73]:
    for fp2 in [13, 21, 33, 49, 63, 73]:
        if fp1 != fp2:
            s1 = fold_sigma(N, fp1)
            s2 = fold_sigma(N, fp2)
            composed = [s2[s1[i]] for i in range(N)]
            if is_valid_perm(composed):
                try_sigma(composed, f"FOLD-double-{fp1}-{fp2}", "double fold")

# Rotations
for k in [7, 8, 13, 21, 24, 48, 63, 73, 1, 2, 3]:
    try_sigma([(i + k) % N for i in range(N)], f"ROTATE+{k}", f"shift by +{k}")
    try_sigma([(i - k) % N for i in range(N)], f"ROTATE-{k}", f"shift by -{k}")

# Complete reversal
try_sigma(list(range(N - 1, -1, -1)), "REVERSE", "complete reversal")

print(f"Fold: {total_tested} tested, {time.time()-t4:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 5: QUADRATIC / CUBIC PERMUTATIONS MOD 97
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("APPROACH 5: Quadratic/Cubic Permutations mod 97")
print("="*70)
t5 = time.time()
quad_count = 0
for a in range(97):
    for b in range(97):
        s = [(a * i * i + b * i) % 97 for i in range(97)]
        if is_valid_perm(s):
            try_sigma(s, f"QUAD-a{a}b{b}", f"a·i²+b·i mod 97")
            quad_count += 1

cubic_count = 0
for a in range(1, 97):
    for b in range(97):
        s = [(a * i * i * i + b * i) % 97 for i in range(97)]
        if is_valid_perm(s):
            try_sigma(s, f"CUBIC-a{a}b{b}", f"a·i³+b·i mod 97")
            cubic_count += 1

print(f"Quad valid: {quad_count}, Cubic valid: {cubic_count}")
print(f"Poly perms: {total_tested} tested, {time.time()-t5:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 6: CLOCK ARITHMETIC (WELTZEITUHR)
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("APPROACH 6: Clock Arithmetic")
print("="*70)
t6 = time.time()

# Multiplicative permutations mod 97 (all of them)
for k in range(1, 97):
    s = [(i * k) % 97 for i in range(97)]
    if is_valid_perm(s):
        try_sigma(s, f"MULT-{k}", f"σ(i)={k}i mod 97")

# Group-based clock permutations
for group_size in [4, 8, 12, 24]:
    n_groups = (N + group_size - 1) // group_size
    for shift in range(1, n_groups):
        sigma = []
        for g in range(n_groups):
            new_g = (g + shift) % n_groups
            base = new_g * group_size
            for j in range(group_size):
                p = base + j
                if p < N:
                    sigma.append(p)
        if is_valid_perm(sigma[:N]):
            try_sigma(sigma[:N], f"CLOCK-gs{group_size}-sh{shift}", "clock group shift")

print(f"Clock: {total_tested} tested, {time.time()-t6:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 7: GE RUNNING KEY / MOD-26 DIFFERENCE
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("APPROACH 7: GE Running Key / Mod-26 Difference")
print("="*70)
t7 = time.time()

for offset in range(0, 30):
    for direction in [1, -1]:
        diff = [(AZ.index(K4_CARVED[i]) - AZ.index(GE[(i * direction + offset) % len(GE)])) % 26
                for i in range(N)]
        s = argsort(diff)
        try_sigma(s, f"GE-diff-off{offset}-dir{direction}", f"(K4-GE) diff argsort")

        inv = [0] * N
        for r, p in enumerate(s):
            inv[p] = r
        try_sigma(inv, f"GE-diff-off{offset}-dir{direction}-inv", "inverse")

# GE extended cyclically as argsort key
for alpha_name, alpha in [("AZ", AZ), ("KA", KA)]:
    ge_97 = [alpha.index(GE[i % len(GE)]) for i in range(N)]
    s = argsort(ge_97)
    try_sigma(s, f"GE-cyc-argsort-{alpha_name}", "GE cyclic argsort")

print(f"GE diff: {total_tested} tested, {time.time()-t7:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 8: KA-ALPHABET RELABELING
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("APPROACH 8: KA-Alphabet Relabeling")
print("="*70)
t8 = time.time()

# Nested sort: KA then AZ, AZ then KA
for primary, secondary in [("KA", "AZ"), ("AZ", "KA")]:
    pa = KA if primary == "KA" else AZ
    sa = AZ if secondary == "AZ" else KA
    keys_ns = [(pa.index(K4_CARVED[i]), sa.index(K4_CARVED[i])) for i in range(N)]
    s = argsort(keys_ns)
    try_sigma(s, f"NESTED-{primary}-{secondary}", f"sort by {primary} then {secondary}")

# Caesar shifts on KA index
for k in range(1, 26):
    shifted = [(KA.index(K4_CARVED[i]) + k) % 26 for i in range(N)]
    s = argsort(shifted)
    try_sigma(s, f"KA-shift-{k}", f"KA index +{k} argsort")

# XOR on AZ index
for k in range(1, 26):
    xored = [AZ.index(K4_CARVED[i]) ^ k for i in range(N)]
    s = argsort(xored)
    try_sigma(s, f"AZ-xor-{k}", f"AZ XOR {k} argsort")

# AZ + KA combined value
for w1, w2 in [(1, 2), (2, 1), (1, 3), (3, 1)]:
    combined = [w1 * AZ.index(K4_CARVED[i]) + w2 * KA.index(K4_CARVED[i]) for i in range(N)]
    s = argsort(combined)
    try_sigma(s, f"AZ{w1}+KA{w2}", f"weighted {w1}*AZ+{w2}*KA")

print(f"KA relabeling: {total_tested} tested, {time.time()-t8:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 9: GRILLE COORDINATE PERMUTATIONS
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("APPROACH 9: Grille Coordinate Permutations")
print("="*70)
t9 = time.time()

FORMULAS = [
    ("r*r+c",       lambda r, c: r*r + c),
    ("c*c+r",       lambda r, c: c*c + r),
    ("r*c+r",       lambda r, c: r*c + r),
    ("r*c+c",       lambda r, c: r*c + c),
    ("r+c_sq",      lambda r, c: r + c*c),
    ("r*33+c",      lambda r, c: r*33 + c),
    ("c*28+r",      lambda r, c: c*28 + r),
    ("r_xor_c",     lambda r, c: r ^ c),
    ("r_and_c",     lambda r, c: r & c),
    ("r+c",         lambda r, c: r + c),
    ("abs_r_m_c",   lambda r, c: abs(r - c)),
    ("r*7+c*3",     lambda r, c: r*7 + c*3),
    ("r*13+c*7",    lambda r, c: r*13 + c*7),
    ("r*8+c*11",    lambda r, c: r*8 + c*11),
    ("r+1_c+1",     lambda r, c: (r+1)*(c+1)),
    ("r_sq+c_sq",   lambda r, c: r**2 + c**2),
]

for fname, fn in FORMULAS:
    try:
        vals = [(fn(r, c) % N, orig_idx) for orig_idx, (r, c) in enumerate(HOLE_POSITIONS)]
        vals_sorted = sorted(vals)
        seen: set = set()
        perm = []
        for v, idx in vals_sorted:
            if v not in seen:
                seen.add(v)
                perm.append(v)
        if len(perm) >= N and is_valid_perm(perm[:N]):
            try_sigma(perm[:N], f"GRILLE-{fname}", f"hole formula mod N")

        # Sort holes by formula value → rank order as permutation
        sorted_holes = sorted(range(len(HOLE_POSITIONS)), key=lambda i: fn(*HOLE_POSITIONS[i]))
        hole_perm = [sorted_holes[i] % N for i in range(min(N, len(sorted_holes)))]
        if len(hole_perm) >= N and is_valid_perm(hole_perm[:N]):
            try_sigma(hole_perm[:N], f"GRILLE-rank-{fname}", "hole rank perm")
    except Exception:
        pass

# Grille path on K4 grid
for gw in [7, 8, 9, 10, 11, 12, 13, 14]:
    gh = (N + gw - 1) // gw
    visited: set = set()
    perm: list = []
    for hr, hc in HOLE_POSITIONS:
        kr = min(hr * gh // GRILLE_ROWS, gh - 1)
        kc = min(hc * gw // GRILLE_COLS, gw - 1)
        k4pos = kr * gw + kc
        if 0 <= k4pos < N and k4pos not in visited:
            visited.add(k4pos)
            perm.append(k4pos)
    remaining = sorted(set(range(N)) - visited)
    perm.extend(remaining)
    if is_valid_perm(perm[:N]):
        try_sigma(perm[:N], f"GRILLE-PATH-gw{gw}", f"hole path on K4 grid w={gw}")

print(f"Grille coord: {total_tested} tested, {time.time()-t9:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 10: CREATIVE LATERAL APPROACHES
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("APPROACH 10: Creative Lateral Approaches")
print("="*70)
t10 = time.time()

# 10a: "8 Lines 73" — 8 physical lines, permute them
K4_LINES = [list(range(s, min(s + 12, N))) for s in range(0, N, 12)]
# Adjust last line
while K4_LINES and not K4_LINES[-1]:
    K4_LINES.pop()

print(f"  8-line permutations: {len(K4_LINES)} lines")
LINE_CAP = 5040  # 7! max
for lo_idx, line_order in enumerate(itertools.permutations(range(len(K4_LINES)))):
    if lo_idx >= LINE_CAP:
        break
    perm: list = []
    for li in line_order:
        perm.extend(K4_LINES[li])
    if is_valid_perm(perm):
        try_sigma(perm, f"LINES-order-{''.join(map(str,line_order))}", "line reorder")
print(f"  Line perms done ({min(LINE_CAP, len(list(itertools.permutations(range(len(K4_LINES))))))} tested)")

# 10b: Period-8 block inner permutation (cap at 1000)
BLOCK_CAP = 1000
for bp_idx, bp in enumerate(itertools.permutations(range(8))):
    if bp_idx >= BLOCK_CAP:
        break
    perm = []
    for block in range(N // 8 + 1):
        for pos_in_block in range(8):
            actual = block * 8 + bp[pos_in_block]
            if actual < N:
                perm.append(actual)
    if is_valid_perm(perm[:N]):
        try_sigma(perm[:N], f"PERIOD8-bp{bp_idx}", f"period-8 inner={bp}")
print(f"  Period-8 block perms done ({BLOCK_CAP} tested)")

# 10c: IDBYROWS — fill by rows, read by columns (various widths)
for width in [7, 8, 9, 10, 11, 12, 13, 14, 97]:
    n_rows = (N + width - 1) // width
    # Read by columns
    perm = []
    for col in range(width):
        for row in range(n_rows):
            pos = row * width + col
            if pos < N:
                perm.append(pos)
    if is_valid_perm(perm[:N]):
        try_sigma(perm[:N], f"IDBYROWS-w{width}", f"col-major w={width}")

    # Fill by columns, read by rows
    perm2 = []
    for row in range(n_rows):
        for col in range(width):
            pos = col * n_rows + row
            if pos < N:
                perm2.append(pos)
    if is_valid_perm(perm2[:N]):
        try_sigma(perm2[:N], f"IDBYCOLS-w{width}", f"row-major (fill cols) w={width}")

# 10d: T-absence: T positions go to end or start
t_pos = [i for i, ch in enumerate(K4_CARVED) if ch == 'T']
non_t = [i for i, ch in enumerate(K4_CARVED) if ch != 'T']
print(f"  T positions in K4: {t_pos}")

for strategy_name, perm in [
    ("T-end", non_t + t_pos),
    ("T-start", t_pos + non_t),
    ("T-end-rev", list(reversed(non_t)) + t_pos),
    ("T-start-rev", t_pos + list(reversed(non_t))),
]:
    if is_valid_perm(perm):
        try_sigma(perm, f"T-ABSENT-{strategy_name}", "T-avoidance")

# 10e: Mod-based hierarchical sorts
for mod in [7, 8, 11, 12, 13, 24]:
    for rev in [False, True]:
        keys = [(i % mod, (-1 if rev else 1) * (i // mod)) for i in range(N)]
        s = argsort(keys)
        try_sigma(s, f"HIER-mod{mod}-{'rev' if rev else 'fwd'}", f"mod {mod} hier sort")

# 10f: Morse code values as sort key
MORSE = {
    'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
    'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
    'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
    'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
    'Y': '-.--', 'Z': '--..',
}
morse_len = [len(MORSE.get(K4_CARVED[i], '.')) for i in range(N)]
try_sigma(argsort(morse_len), "MORSE-len", "Morse code length argsort")
morse_dots = [MORSE.get(K4_CARVED[i], '.').count('.') for i in range(N)]
try_sigma(argsort(morse_dots), "MORSE-dots", "Morse dot count argsort")
morse_dashes = [MORSE.get(K4_CARVED[i], '.').count('-') for i in range(N)]
try_sigma(argsort(morse_dashes), "MORSE-dashes", "Morse dash count argsort")

# 10g: Next-same-letter distance
def next_same_letter_dist(text, pos):
    ch = text[pos]
    for j in range(pos + 1, len(text)):
        if text[j] == ch:
            return j - pos
    # Wrap around
    for j in range(0, pos):
        if text[j] == ch:
            return len(text) - pos + j
    return 0

nsl = [next_same_letter_dist(K4_CARVED, i) for i in range(N)]
try_sigma(argsort(nsl), "NEXT-SAME-LETTER", "next same letter distance")
try_sigma(argsort([-x for x in nsl]), "NEXT-SAME-LETTER-rev", "next same letter distance (rev)")

print(f"Creative: {total_tested} tested, {time.time()-t10:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 11: CRIB POSITION → CARVED POSITION DIRECT CONSTRAINT CHECK
# For the most constrained config, analytically determine forced assignments
# and report them for human analysis
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("APPROACH 11: Forced Assignment Analysis + Exhaustive CSP")
print("="*70)
t11 = time.time()

if feasible:
    cfg_str = feasible[0]["config"]
    kw, cipher_name, alpha_name = cfg_str.split("/")
    alpha = AZ if alpha_name == "AZ" else KA
    expected = compute_expected_ct(kw, cipher_name, alpha)
    assignments = csp_enumerate(expected, cap=100000)

    print(f"\nDeep analysis for {cfg_str}: {len(assignments)} assignments")

    # Find truly forced (same value in all assignments)
    if assignments:
        forced_map = {}
        for pos in expected:
            vals = [a[pos] for a in assignments]
            if len(set(vals)) == 1:
                forced_map[pos] = vals[0]

        print(f"Truly forced positions (same in all {len(assignments)} assignments): {len(forced_map)}")
        for pos, cpos in sorted(forced_map.items()):
            print(f"  σ({pos:2d})={cpos}: carved=K4[{cpos}]={K4_CARVED[cpos]}, "
                  f"expCT={expected[pos]}, PT={CRIB_MAP.get(pos,'?')}")

        # What if we construct ALL extensions with many different orderings
        ext_strategies = [
            ("natural", None),
            ("reverse", lambda p: -p),
            ("mod7_fwd", lambda p: (p % 7, p // 7)),
            ("mod7_rev", lambda p: (p % 7, -(p // 7))),
            ("mod8_fwd", lambda p: (p % 8, p // 8)),
            ("mod8_rev", lambda p: (p % 8, -(p // 8))),
            ("mod13",    lambda p: (p % 13, p // 13)),
            ("GE_AZ",    lambda p: AZ.index(GE[p % len(GE)])),
            ("GE_KA",    lambda p: KA.index(GE[p % len(GE)])),
            ("K4_AZ",    lambda p: AZ.index(K4_CARVED[p])),
            ("K4_KA",    lambda p: KA.index(K4_CARVED[p])),
            ("T_first",  lambda p: (0 if K4_CARVED[p] == 'T' else 1, p)),
            ("T_last",   lambda p: (1 if K4_CARVED[p] == 'T' else 0, p)),
            ("hole_first", lambda p: (0 if any(hr * GRILLE_COLS + hc == p for hr, hc in HOLE_POSITIONS) else 1, p)),
        ]

        for assign in assignments:
            for strat_name, strat_fn in ext_strategies:
                sigma = extend_sigma(assign, strat_fn)
                if is_valid_perm(sigma):
                    try_sigma(sigma, f"CSP-DEEP-{cfg_str}-{strat_name}", f"deep ext")

        print(f"  Tested {len(assignments) * len(ext_strategies)} extensions")

print(f"Deep CSP: {total_tested} tested, {time.time()-t11:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 12: K4 SELF-ENCRYPTION AT CRIB POSITIONS
# Examine what crib positions imply about σ structure
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("APPROACH 12: Systematic Crib Position Verification")
print("="*70)
t12 = time.time()

# For each config, count how many crib expected chars exist in K4 at all
print("Quick feasibility check for all 56 configs:")
all_feasible_info = []
for kw, alpha_name, alpha, cipher_name in ALL_CONFIGS:
    expected = compute_expected_ct(kw, cipher_name, alpha)
    char_counts = Counter(expected.values())
    k4_counts = Counter(K4_CARVED)
    feasible_for_config = True
    deficit = 0
    for ch, needed in char_counts.items():
        available = k4_counts.get(ch, 0)
        if available < needed:
            feasible_for_config = False
            deficit += needed - available

    if feasible_for_config:
        all_feasible_info.append({
            "config": f"{kw}/{cipher_name}/{alpha_name}",
            "char_counts": dict(char_counts),
            "exact_match_chars": [ch for ch, needed in char_counts.items()
                                   if k4_counts.get(ch, 0) == needed],
        })

print(f"Strictly feasible (multiset): {len(all_feasible_info)}/{len(ALL_CONFIGS)}")
for info in all_feasible_info:
    em = info["exact_match_chars"]
    if em:
        print(f"  {info['config']}: exact-match chars={em} → FORCED!")

# For configs with many exact-match chars, the CSP is very tight
# Report the configs with most forced characters
sorted_by_forced = sorted(all_feasible_info,
                           key=lambda x: -len(x["exact_match_chars"]))
print("\nTop 5 most constrained (most exact-match = forced chars):")
for info in sorted_by_forced[:5]:
    print(f"  {info['config']}: exact={info['exact_match_chars']}")

print(f"Crib verification: {total_tested} tested, {time.time()-t12:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# APPROACH 13: MODULAR MULTIPLICATIVE INVERSES + COMPOSITIONS
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("APPROACH 13: Modular Inverses and Compositions")
print("="*70)
t13 = time.time()

# Compose two multiplicative permutations
good_mults = [k for k in range(1, 97) if is_valid_perm([(i * k) % 97 for i in range(97)])]
print(f"  Valid multiplicative perms mod 97: {len(good_mults)}")

# Sample compositions of two multiplicative perms
for k1 in good_mults[:10]:
    for k2 in good_mults[:10]:
        if k1 != k2:
            s = [((i * k1) * k2) % 97 for i in range(97)]
            if is_valid_perm(s):
                try_sigma(s, f"MULT-COMPOSE-{k1}x{k2}", f"k={k1}*{k2}={k1*k2%97} mod 97")

# Affine + multiplicative
for a in good_mults[:5]:
    for b in range(0, 97, 7):
        s = [(a * i + b) % 97 for i in range(97)]
        if is_valid_perm(s):
            try_sigma(s, f"AFFINE-a{a}b{b}", f"a={a},b={b}")

# k=96 = -1 mod 97: σ(i) = -i mod 97 = 97-i for i>0
s_neg = [(97 - i) % 97 for i in range(97)]
if is_valid_perm(s_neg):
    try_sigma(s_neg, "MULT-96-NEG", "σ(i)=-i mod 97")

print(f"Modular: {total_tested} tested, {time.time()-t13:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# FINAL SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
elapsed_total = time.time() - t0

print("\n" + "="*70)
print("FINAL SUMMARY")
print("="*70)
print(f"Total permutations tested : {total_tested}")
print(f"Total elapsed             : {elapsed_total:.1f}s")
print(f"CRIB HITS FOUND           : {len(CRIB_HITS)}")
print(f"Best score                : {best_score:.2f}")

if best_entry:
    print(f"Best approach : {best_entry['approach']}")
    print(f"Best note     : {best_entry['note']}")

if CRIB_HITS:
    print("\n🎯 CRIB HIT DETAILS:")
    for hit in CRIB_HITS:
        print(f"  Approach : {hit['approach']}")
        print(f"  Score    : {hit['score']:.2f}")
        print(f"  Cribs    : {hit['cribs']}")
        extra = hit.get("extra", {})
        if extra.get("pt"):
            print(f"  PT       : {extra['pt']}")

print("\nCSP Analysis - Top 10 configs:")
for i, s in enumerate(feasible[:10]):
    print(f"  {i+1}. {s['config']}: forced={s['forced']}/24, log_ub={s.get('log_ub',0):.2f}")

scores = [r["score"] for r in all_results if r["score"] > -9000]
if scores:
    print(f"\nScore distribution: min={min(scores):.2f}, max={max(scores):.2f}, "
          f"mean={sum(scores)/len(scores):.2f}")
    print(f"  Above -500: {sum(1 for s in scores if s > -500)}")
    print(f"  Above -400: {sum(1 for s in scores if s > -400)}")

out_path = save_results()
print(f"\nResults saved to: {out_path}")

if CRIB_HITS:
    status = "solved"
elif best_score > -400:
    status = "promising"
else:
    status = "inconclusive"

print(f"\nVerdict: {status.upper()}")
