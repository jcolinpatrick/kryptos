#!/usr/bin/env python3
"""
Cipher: multi-method blitz
Family: blitz
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""blitz_csp_focused.py — Deep CSP analysis for all 18 multiset-feasible configs.

Key finding from blitz_wildcard: Only 18/56 key configs have enough characters
in K4_CARVED to satisfy the 24 crib constraints (multiset feasibility).
This script does deep CSP + pattern analysis on all 18.

Focus:
1. For each feasible config, enumerate ALL valid 24-position crib assignments
2. Identify forced assignments (same value in all assignments)
3. For KRYPTOS/vig/AZ (primary hypothesis): detailed analysis
4. Report exact forced σ values for human analysis
5. Try more extension strategies on top configs

Run: PYTHONPATH=src python3 -u scripts/blitz_csp_focused.py
"""
from __future__ import annotations
import sys, json, time, itertools, random
from collections import defaultdict, Counter
from pathlib import Path

sys.path.insert(0, 'scripts')
from kbot_harness import (
    test_perm, test_unscramble, score_text, score_text_per_char,
    has_cribs, vig_decrypt, vig_encrypt, beau_decrypt,
    apply_permutation, load_quadgrams,
    K4_CARVED, GRILLE_EXTRACT, AZ, KA, KEYWORDS, CRIBS,
)

N = 97
GE = GRILLE_EXTRACT

CRIB_DEFS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
CRIB_MAP = {}
for _s, _t in CRIB_DEFS:
    for _j, _c in enumerate(_t):
        CRIB_MAP[_s + _j] = _c

K4_POS = defaultdict(list)
for _i, _c in enumerate(K4_CARVED):
    K4_POS[_c].append(_i)

results_dir = Path("results/blitz_wildcard")
results_dir.mkdir(parents=True, exist_ok=True)
all_results = []
best_score = -9999.0
best_entry = None
total_tested = 0
CRIB_HITS = []


def report(approach, note, score, cribs, extra=None):
    global best_score, best_entry, total_tested, CRIB_HITS
    total_tested += 1
    entry = {"approach": approach, "note": str(note)[:300], "score": score,
             "cribs": cribs, "extra": extra or {}}
    all_results.append(entry)
    if cribs:
        CRIB_HITS.append(entry)
        print(f"\n🎯 CRIB HIT! {approach}: score={score:.2f}, cribs={cribs}\n")
    if score > best_score:
        best_score = score
        best_entry = entry
        if score > -650:
            print(f"  ★ BEST [{approach}]: {score:.2f}")


def try_sigma(sigma, name, note=""):
    sigma = list(sigma)
    if len(sigma) != N or sorted(sigma) != list(range(N)):
        return None
    res = test_perm(sigma)
    if not res:
        return None
    score = res.get("score", -9999)
    crib_hit = res.get("crib_hit", False)
    report(name, note, score, res.get("cribs", []) if crib_hit else [], res)
    return res


def compute_expected(kw, cipher, alpha):
    exp = {}
    for start, text in CRIB_DEFS:
        for j, pt in enumerate(text):
            pos = start + j
            ki = alpha.index(kw[pos % len(kw)])
            pi = alpha.index(pt)
            exp[pos] = alpha[(pi + ki) % 26] if cipher == "vig" else alpha[(ki - pi) % 26]
    return exp


def is_vp(s, n=N):
    return len(s) == n and sorted(s) == list(range(n))


def csp_enum(exp_map, cap=500000):
    """Full CSP backtracking with cap."""
    positions = sorted(exp_map.keys())
    domains = {}
    for pos in positions:
        ch = exp_map[pos]
        avail = list(K4_POS.get(ch, []))
        if not avail:
            return []
        domains[pos] = avail
    order = sorted(positions, key=lambda p: len(domains[p]))
    results = []
    assign = {}
    used = set()

    def bt(idx):
        if len(results) >= cap:
            return
        if idx == len(order):
            results.append(dict(assign))
            return
        pos = order[idx]
        for cp in domains[pos]:
            if cp not in used:
                assign[pos] = cp
                used.add(cp)
                bt(idx + 1)
                used.discard(cp)
                del assign[pos]
    bt(0)
    return results


def extend(assign, sort_fn=None):
    used = set(assign.values())
    free_rt = sorted(set(range(N)) - set(assign.keys()))
    free_cv = sorted(set(range(N)) - used)
    if sort_fn:
        free_rt = sorted(free_rt, key=sort_fn)
        free_cv = sorted(free_cv, key=sort_fn)
    sigma = [0] * N
    for pos, cp in assign.items():
        sigma[pos] = cp
    for i, pos in enumerate(free_rt):
        sigma[pos] = free_cv[i]
    return sigma


# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: Find all 18 feasible configs
# ─────────────────────────────────────────────────────────────────────────────
print("="*70)
print("STEP 1: Identify strictly feasible configs (multiset check)")
print("="*70)

k4_counts = Counter(K4_CARVED)
ALL_CONFIGS = [(kw, an, a, cn)
               for kw in KEYWORDS
               for an, a in [("AZ", AZ), ("KA", KA)]
               for cn in ["vig", "beau"]]

FEASIBLE_CONFIGS = []
for kw, an, a, cn in ALL_CONFIGS:
    exp = compute_expected(kw, cn, a)
    char_needs = Counter(exp.values())
    ok = all(k4_counts.get(ch, 0) >= need for ch, need in char_needs.items())
    if ok:
        exact_match = [ch for ch, need in char_needs.items() if k4_counts.get(ch, 0) == need]
        FEASIBLE_CONFIGS.append({
            "kw": kw, "alpha_name": an, "alpha": a, "cipher": cn,
            "config": f"{kw}/{cn}/{an}",
            "exact_match": exact_match,
            "n_exact": len(exact_match),
            "exp": exp,
        })

FEASIBLE_CONFIGS.sort(key=lambda x: -x["n_exact"])
print(f"\n{len(FEASIBLE_CONFIGS)}/56 configs feasible.")
print("\nAll feasible configs (sorted by forced chars):")
for fc in FEASIBLE_CONFIGS:
    print(f"  {fc['config']:30s}  exact_match={fc['exact_match']} ({fc['n_exact']})")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: Full CSP for each feasible config
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("STEP 2: Full CSP enumeration for each feasible config")
print("="*70)

# Extension strategies
EXT_STRATS = [
    ("natural",  None),
    ("reverse",  lambda p: -p),
    ("mod7",     lambda p: (p % 7, p // 7)),
    ("mod7rev",  lambda p: (p % 7, -(p // 7))),
    ("mod8",     lambda p: (p % 8, p // 8)),
    ("mod8rev",  lambda p: (p % 8, -(p // 8))),
    ("mod13",    lambda p: (p % 13, p // 13)),
    ("GE_AZ",    lambda p: AZ.index(GE[p % len(GE)])),
    ("GE_KA",    lambda p: KA.index(GE[p % len(GE)])),
    ("K4_AZ",    lambda p: AZ.index(K4_CARVED[p])),
    ("K4_KA",    lambda p: KA.index(K4_CARVED[p])),
    ("T_last",   lambda p: (1 if K4_CARVED[p] == 'T' else 0, p)),
    ("mod24",    lambda p: (p % 24, p // 24)),
    ("mod11",    lambda p: (p % 11, p // 11)),
]

config_results = {}
t_start = time.time()

for fc in FEASIBLE_CONFIGS:
    cfg = fc["config"]
    exp = fc["exp"]
    kw = fc["kw"]
    alpha = fc["alpha"]
    an = fc["alpha_name"]
    cipher = fc["cipher"]

    print(f"\n  Processing {cfg}...", end=" ", flush=True)

    # Full CSP enumeration
    assignments = csp_enum(exp, cap=100000)
    print(f"{len(assignments)} assignments", flush=True)

    if not assignments:
        config_results[cfg] = {"status": "IMPOSSIBLE", "n_assign": 0}
        continue

    # Find truly forced positions
    forced = {}
    for pos in exp:
        vals = [a[pos] for a in assignments]
        if len(set(vals)) == 1:
            forced[pos] = vals[0]

    print(f"    Forced positions: {len(forced)}/24")
    for pos, cpos in sorted(forced.items()):
        print(f"      σ({pos:2d})={cpos}: K4[{cpos}]={K4_CARVED[cpos]}, "
              f"expCT={exp[pos]}, PT={CRIB_MAP.get(pos,'?')}")

    # Near-forced (2-3 options)
    near_forced = {}
    for pos in exp:
        vals = sorted(set(a[pos] for a in assignments))
        if 2 <= len(vals) <= 3:
            near_forced[pos] = vals

    config_results[cfg] = {
        "status": "FEASIBLE",
        "n_assign": len(assignments),
        "forced": forced,
        "near_forced": near_forced,
    }

    # Test all assignments with all extension strategies
    n_ext_tested = 0
    for assign_idx, assign in enumerate(assignments):
        for strat_name, strat_fn in EXT_STRATS:
            sigma = extend(assign, strat_fn)
            if is_vp(sigma):
                try_sigma(sigma, f"CSP2-{cfg}-{strat_name}", f"assign#{assign_idx}")
                n_ext_tested += 1

        if assign_idx % 5000 == 4999:
            print(f"    ...{assign_idx+1}/{len(assignments)} tested, "
                  f"elapsed {time.time()-t_start:.1f}s")

    print(f"    Tested {n_ext_tested} extensions, best={best_score:.2f}, "
          f"elapsed {time.time()-t_start:.1f}s")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: KRYPTOS/vig/AZ detailed analysis (primary hypothesis)
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("STEP 3: KRYPTOS/vig/AZ — Primary Hypothesis Analysis")
print("="*70)

kryptos_cfg = next((fc for fc in FEASIBLE_CONFIGS if fc["config"] == "KRYPTOS/vig/AZ"), None)
if kryptos_cfg:
    exp_k = kryptos_cfg["exp"]
    assignments_k = csp_enum(exp_k, cap=500000)
    cr = config_results.get("KRYPTOS/vig/AZ", {})

    print(f"\nKRYPTOS/vig/AZ: {len(assignments_k)} valid crib assignments")
    print("\nDetailed domain analysis:")
    for pos in sorted(exp_k.keys()):
        avail = K4_POS.get(exp_k[pos], [])
        opts_in_solutions = sorted(set(a[pos] for a in assignments_k)) if assignments_k else []
        forced_flag = "**FORCED**" if len(opts_in_solutions) == 1 else ""
        print(f"  σ({pos:2d}): PT={CRIB_MAP.get(pos,'?')}, expCT={exp_k[pos]}, "
              f"K4_avail={avail}, solution_opts={opts_in_solutions} {forced_flag}")

    if assignments_k:
        # Build the forced partial permutation (positions appearing in all assignments)
        full_forced = {pos: list(set(a[pos] for a in assignments_k))[0]
                       for pos in exp_k
                       if len(set(a[pos] for a in assignments_k)) == 1}

        print(f"\nFully forced positions in KRYPTOS/vig/AZ: {len(full_forced)}/24")
        print("FORCED σ VALUES (for human analysis):")
        for pos, cpos in sorted(full_forced.items()):
            print(f"  σ({pos}) = {cpos}  [PT={CRIB_MAP.get(pos,'?')}, "
                  f"expCT={exp_k[pos]}, K4[{cpos}]={K4_CARVED[cpos]}]")

        # Additional extension strategies for KRYPTOS/vig/AZ
        print(f"\nTesting all {len(assignments_k)} assignments with extended strategies...")
        additional_strats = [
            ("hole_order",   lambda p: next((i for i, (hr,hc) in enumerate(
                [(r,c) for r,row in enumerate([
                "000000001010100000000010000000001","100000000010000001000100110000011",
                "000000000000001000000000000000011","000000000000000000001000000100110",
                "000000010000000010000100000000110","000000001000000000000000000000011",
                "100000000000000000000000000000011","000000000000000000000001000001000",
                "000000000000000000001000000010000","000000000000000000000000000001000",
                "000000001000000000000000000000000","000001100000000000000000000001000",
                "000000000000001000100000000000010","000000000001000000000000000010000",
                "000110100001000000000000001000010","000010100000000000000000010000010",
                "001001000010010000000000000100010","000000000001000000000100000100010",
                "000000000000010001001000000010001","000000000000000010010000000001000",
                "000000001100000010100100010001001","000000000000000100001010100100011",
                "000000000100000000001000011000010","100000000000000000001000001000010",
                "100000010000010000001000000000010","000010000000000000010000100000011",
                "000000000000000000001000010000000","000000000000001000000010100000010",
                ]) for c,ch in enumerate(row) if ch=='1']
            ) if hr*33+hc == p), len([(r,c) for r,row in enumerate([
                "000000001010100000000010000000001","100000000010000001000100110000011",
                "000000000000001000000000000000011","000000000000000000001000000100110",
                "000000010000000010000100000000110","000000001000000000000000000000011",
                "100000000000000000000000000000011","000000000000000000000001000001000",
                "000000000000000000001000000010000","000000000000000000000000000001000",
                "000000001000000000000000000000000","000001100000000000000000000001000",
                "000000000000001000100000000000010","000000000001000000000000000010000",
                "000110100001000000000000001000010","000010100000000000000000010000010",
                "001001000010010000000000000100010","000000000001000000000100000100010",
                "000000000000010001001000000010001","000000000000000010010000000001000",
                "000000001100000010100100010001001","000000000000000100001010100100011",
                "000000000100000000001000011000010","100000000000000000001000001000010",
                "100000010000010000001000000000010","000010000000000000010000100000011",
                "000000000000000000001000010000000","000000000000001000000010100000010",
            ]) for c,ch in enumerate(row) if ch=='1']))),
        ]

        for assign_idx, assign in enumerate(assignments_k):
            for strat_name, strat_fn in EXT_STRATS + [
                ("mod97_GE", lambda p: (AZ.index(GE[p % len(GE)]), p % 7)),
                ("K4_then_GE", lambda p: (AZ.index(K4_CARVED[p]), AZ.index(GE[p % len(GE)]))),
                ("crib_aware", lambda p: (0 if p in exp_k else 1, p)),
            ]:
                try:
                    sigma = extend(assign, strat_fn)
                    if is_vp(sigma):
                        try_sigma(sigma, f"KRYPTOS-deep-{strat_name}", f"assign#{assign_idx}")
                except:
                    pass

            if assign_idx % 10000 == 9999:
                print(f"  ...{assign_idx+1}/{len(assignments_k)} KRYPTOS assignments done")
else:
    print("  KRYPTOS/vig/AZ not in feasible list — ELIMINATED!")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: KRYPTOS/beau/AZ analysis (secondary hypothesis)
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("STEP 4: Other primary candidates")
print("="*70)

for target_cfg in ["KRYPTOS/beau/AZ", "KRYPTOS/vig/KA", "KRYPTOS/beau/KA",
                   "ABSCISSA/vig/AZ", "ABSCISSA/beau/AZ"]:
    fc = next((x for x in FEASIBLE_CONFIGS if x["config"] == target_cfg), None)
    if fc:
        exp = fc["exp"]
        assigns = csp_enum(exp, cap=100000)
        print(f"\n  {target_cfg}: {len(assigns)} assignments")
        for assign_idx, assign in enumerate(assigns[:50000]):
            for sn, sf in EXT_STRATS[:6]:
                sigma = extend(assign, sf)
                if is_vp(sigma):
                    try_sigma(sigma, f"PRI-{target_cfg}-{sn}", f"#{assign_idx}")
    else:
        print(f"  {target_cfg}: NOT FEASIBLE (eliminated)")

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5: Pattern Analysis — what do forced assignments tell us?
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("STEP 5: Cross-config Pattern Analysis")
print("="*70)

# Collect all forced σ values across all feasible configs
print("\nForced σ assignments across all feasible configs:")
forced_by_pos = defaultdict(list)  # crib_pos → list of (config, carved_pos)
for cfg, cr in config_results.items():
    if cr.get("status") == "FEASIBLE":
        for pos, cpos in cr.get("forced", {}).items():
            forced_by_pos[pos].append((cfg, cpos))

# Show positions with forced assignments
for pos in sorted(forced_by_pos.keys()):
    entries = forced_by_pos[pos]
    # Find consistent carved positions across configs
    cpos_vals = set(cpos for _, cpos in entries)
    print(f"  PT pos {pos:2d} ({CRIB_MAP.get(pos,'?')}): forced in {len(entries)} configs")
    for cfg, cpos in entries:
        print(f"    {cfg}: σ({pos})={cpos}, K4[{cpos}]={K4_CARVED[cpos]}")

# Are any carved positions forced to the same value across multiple configs?
print("\nConsistent forced values across configs (same carved_pos for same PT_pos):")
for pos, entries in sorted(forced_by_pos.items()):
    all_cpos = [cpos for _, cpos in entries]
    if len(set(all_cpos)) == 1:
        print(f"  σ({pos})={all_cpos[0]} forced in ALL {len(entries)} configs "
              f"[PT={CRIB_MAP.get(pos,'?')}, K4[{all_cpos[0]}]={K4_CARVED[all_cpos[0]]}]")

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
print("\n" + "="*70)
print("FINAL SUMMARY")
print("="*70)
print(f"Total tested: {total_tested}")
print(f"CRIB HITS:    {len(CRIB_HITS)}")
print(f"Best score:   {best_score:.2f}")

if CRIB_HITS:
    print("\n🎯 CRIB HITS:")
    for h in CRIB_HITS:
        print(f"  {h['approach']}: {h['score']:.2f}, {h['cribs']}")
        if h.get("extra", {}).get("pt"):
            print(f"  PT: {h['extra']['pt']}")
else:
    print(f"\nNo crib hits. Best: {best_entry}")

out = results_dir / "csp_focused_results.json"
with open(out, "w") as f:
    json.dump({
        "total": total_tested,
        "crib_hits": CRIB_HITS,
        "best": best_entry,
        "config_results": {k: {kk: vv for kk, vv in v.items() if kk not in ("forced",)}
                           for k, v in config_results.items()},
        "forced_by_pos": {str(k): v for k, v in forced_by_pos.items()},
    }, f, indent=2)
print(f"\nSaved to {out}")

if CRIB_HITS:
    status = "solved"
elif best_score > -400:
    status = "promising"
else:
    status = "inconclusive"
print(f"Verdict: {status.upper()}")
