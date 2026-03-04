#!/usr/bin/env python3
"""
Cipher: non-columnar transposition
Family: transposition/other
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_strip_perm.py — ALL strip/row permutations for K4 unscrambling

Model 2: PT → Cipher(key) → real_CT → STRIP_PERMUTE(σ) → K4_carved

Strip permutation: divide K4 into N equal-length strips (last may be shorter),
then permute the strip ORDER. This is block transposition — completely different
from columnar transposition (which permutes columns within a fixed grid).

The Kobek-Byrne Smithsonian note refers to "scrambled strips" — this is the
direct computational test of that hypothesis.

Strategy:
  For each (L, keyword, cipher_type, alpha):
    1. Compute expected real_CT at 24 crib positions (EASTNORTHEAST + BERLINCLOCK)
    2. For each output strip index k, find valid source strip indices satisfying
       ALL crib constraints that fall within strip k (typically 0–9 chars per strip)
    3. Constraint-guided backtracking search (most-constrained-first ordering)
    4. Score valid results with quadgrams + crib verification

Strip lengths tested:
  L=13  → N=8  strips (7×13 + 1×6)   →  8! = 40,320      [fast]
  L=14  → N=7  strips (6×14 + 1×13)  →  7! = 5,040       [fast]
  L=15  → N=7  strips (6×15 + 1×7)   →  7! = 5,040       [fast]
  L=16  → N=7  strips (6×16 + 1×1)   →  7! = 5,040       [fast]
  L=11  → N=9  strips (8×11 + 1×9)   →  9! = 362,880     [fast]
  L=12  → N=9  strips (8×12 + 1×1)   →  9! = 362,880     [fast]
  L=10  → N=10 strips (9×10 + 1×7)   → 10! = 3,628,800   [medium]
  L=9   → N=11 strips (10×9 + 1×7)   → 11! = 39.9M       [constraint-pruned]
  L=8   → N=13 strips (12×8 + 1×1)   → 13! = 6.2B        [heavy constraint filter]

All search is crib-constraint-guided: the 24 crib positions create strong
constraints on just 4–6 output strip indices. Unconstrained strips contribute
no additional branching until a constrained strip finds a match.

Run:
  PYTHONPATH=src python3 -u scripts/blitz_strip_perm.py
"""

import json
import math
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

# ─────────────────────────────── constants ────────────────────────────────

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4) == 97, f"K4 length {len(K4)} != 97"

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Standard crib positions (MEMORY.md ground truth)
ENE_START = 21  # EASTNORTHEAST at PT[21:34]
BC_START  = 63  # BERLINCLOCK   at PT[63:74]

CRIB_CHARS = (
    [(ENE_START + i, c) for i, c in enumerate("EASTNORTHEAST")] +
    [(BC_START  + i, c) for i, c in enumerate("BERLINCLOCK")]
)
assert len(CRIB_CHARS) == 24, f"Expected 24 crib chars, got {len(CRIB_CHARS)}"

# Self-encrypting positions (Bean analysis): PT[32]=CT[32]='S', PT[73]=CT[73]='K'
# Under Vigenère: key[32%klen] = 0, key[73%klen] = 0
SELF_ENC = [(32, 'S'), (73, 'K')]

# Keywords to test (known K4-related keywords + primes for completeness)
KEYWORDS = [
    # Known K4 candidates
    "KRYPTOS",
    "PALIMPSEST",
    "ABSCISSA",
    "SHADOW",
    "SANBORN",
    "SCHEIDT",
    "BERLIN",
    "CLOCK",
    "EAST",
    "NORTH",
    "LIGHT",
    "ANTIPODES",
    "MEDUSA",
    "ENIGMA",
    "PYRAMID",
    # Sculpture-related
    "IQLUSION",
    "UNDERGRUUND",
    "VIRTUAL",
    "STEGANOGRAPHY",
    "CRYPTOGRAPHY",
    "KRYPTOSABCDE",
    # Interesting keyword lengths matching strip sizes
    "ABCDEFGHIJKLM",   # length 13 = ENE crib length
    "ABCDEFGHIJK",     # length 11 = BC  crib length
]

ALPHAS = [("AZ", AZ), ("KA", KA)]

# Strip lengths to test
STRIP_LENGTHS = [13, 14, 15, 16, 11, 12, 10, 9, 8]

# ─────────────────────────────── quadgrams ────────────────────────────────

_quad_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          '..', 'data', 'english_quadgrams.json')
try:
    with open(_quad_path) as _f:
        QUAD_LOG = json.load(_f)   # values are already log10 probabilities
    MISS = min(QUAD_LOG.values()) - 1.0   # below lowest observed entry
    print(f"[quadgrams] loaded {len(QUAD_LOG):,} entries  "
          f"range=[{min(QUAD_LOG.values()):.3f}, {max(QUAD_LOG.values()):.3f}]  "
          f"MISS={MISS:.3f}")
except Exception as _e:
    print(f"[quadgrams] WARNING: could not load: {_e}", file=sys.stderr)
    QUAD_LOG = {}
    MISS = -8.63


def quadgram_score(text: str) -> float:
    n = len(text)
    if n < 4:
        return MISS
    return sum(QUAD_LOG.get(text[i:i+4], MISS) for i in range(n - 3)) / (n - 3)


# ─────────────────────────────── crypto ────────────────────────────────────

def alpha_index(alpha: str) -> dict:
    return {c: i for i, c in enumerate(alpha)}


def expected_ct_at_cribs(keyword: str, cipher: str, alpha: str, ai: dict,
                         crib_chars=None) -> dict:
    """
    Compute expected real_CT characters at each crib PT position.
    Returns dict {pt_pos: expected_char}.
    """
    if crib_chars is None:
        crib_chars = CRIB_CHARS
    n    = len(alpha)
    ki   = [ai.get(c, 0) for c in keyword]
    klen = len(keyword)
    exp  = {}
    for pt_pos, pt_char in crib_chars:
        k_val = ki[pt_pos % klen]
        p_val = ai.get(pt_char, 0)
        if cipher == 'vig':
            exp[pt_pos] = alpha[(p_val + k_val) % n]
        else:  # beaufort
            exp[pt_pos] = alpha[(k_val - p_val) % n]
    return exp


def decrypt_full(ct: str, keyword: str, cipher: str, alpha: str, ai: dict) -> str:
    """Vigenère/Beaufort decrypt a full ciphertext."""
    n    = len(alpha)
    klen = len(keyword)
    ki   = [ai.get(c, 0) for c in keyword]
    out  = []
    for j, c in enumerate(ct):
        ci = ai.get(c, 0)
        kv = ki[j % klen]
        out.append(alpha[(ci - kv) % n] if cipher == 'vig' else alpha[(kv - ci) % n])
    return ''.join(out)


# ─────────────────────────────── strip logic ──────────────────────────────

def split_strips(k4: str, L: int) -> list:
    """Return list of strips; last strip may be shorter than L."""
    return [k4[i:i+L] for i in range(0, len(k4), L)]


def build_strip_constraints(L: int, expected: dict) -> tuple:
    """
    For each output strip index k (0..N-1), find the set of source strip
    indices s that satisfy ALL crib constraints falling in output strip k.

    Constraint for (k → s): for all crib positions p with p // L == k,
        K4[s * L + (p % L)] == expected[p]
    (The character at offset p%L inside source strip s must be the required char.)

    If s*L + offset >= 97, that source strip cannot provide the required
    character (position doesn't exist), so it's invalid.

    Returns:
        constraints: list of N sets of valid source indices
        N: total number of strips
        by_k: dict mapping output strip index → list of crib positions in it
    """
    strips = split_strips(K4, L)
    N      = len(strips)

    # Group crib positions by their output strip index
    by_k = {}
    for pt_pos in expected:
        k = pt_pos // L
        if k < N:
            by_k.setdefault(k, []).append(pt_pos)

    constraints = []
    for k in range(N):
        if k not in by_k:
            constraints.append(set(range(N)))  # unconstrained
        else:
            valid = set()
            for s in range(N):
                ok = True
                for pt_pos in by_k[k]:
                    off = pt_pos % L
                    src = s * L + off
                    if src >= 97 or K4[src] != expected[pt_pos]:
                        ok = False
                        break
                if ok:
                    valid.add(s)
            constraints.append(valid)

    return constraints, N, by_k


def backtrack_strips(N: int, order: list, constraints_by_order: list,
                     k: int, perm: list, used: set, out: list) -> None:
    """
    Backtracking permutation search.
    order[i] = output strip index processed at step i (most constrained first).
    perm_by_order[i] = source strip chosen for output strip order[i].
    out: accumulates complete permutations (as dicts {output_k: source_s}).
    """
    if k == N:
        # Convert perm_by_order → full permutation array perm[output_k] = source_s
        full = [0] * N
        for i in range(N):
            full[order[i]] = perm[i]
        out.append(full)
        return
    for s in constraints_by_order[k]:
        if s not in used:
            perm.append(s)
            used.add(s)
            backtrack_strips(N, order, constraints_by_order, k + 1, perm, used, out)
            perm.pop()
            used.discard(s)


def reconstruct_ct(perm: list, strips: list) -> str:
    """Reconstruct real_CT from strip permutation: real_CT = strips[perm[0]] + ..."""
    return ''.join(strips[perm[k]] for k in range(len(perm)))


# ─────────────────────────────── single search ────────────────────────────

def search_one_config(args: tuple) -> list:
    """
    Enumerate all strip permutations satisfying crib constraints for one config.
    Returns list of result dicts (may be empty).
    """
    L, keyword, cipher, alpha_name, alpha, ene_s, bc_s = args

    # Optionally override crib positions
    crib_chars = (
        [(ene_s + i, c) for i, c in enumerate("EASTNORTHEAST")] +
        [(bc_s  + i, c) for i, c in enumerate("BERLINCLOCK")]
    )

    ai  = alpha_index(alpha)
    exp = expected_ct_at_cribs(keyword, cipher, alpha, ai, crib_chars=crib_chars)

    # Build constraints
    constraints, N, by_k = build_strip_constraints(L, exp)

    # Fast infeasibility check: constrained strip with 0 valid sources → bail
    for k, cset in enumerate(constraints):
        if len(cset) == 0:
            return []

    # Sort output strips by constraint tightness (most constrained first)
    order = sorted(range(N), key=lambda k: len(constraints[k]))
    constraints_by_order = [constraints[order[i]] for i in range(N)]

    # Backtracking search
    raw_results = []
    backtrack_strips(N, order, constraints_by_order, 0, [], set(), raw_results)

    # Score results
    strips  = split_strips(K4, L)
    scored  = []
    for perm in raw_results:
        real_ct = reconstruct_ct(perm, strips)
        pt      = decrypt_full(real_ct, keyword, cipher, alpha, ai)
        qg      = quadgram_score(pt)

        # Crib verification (at search positions)
        ene_ok  = pt[ene_s : ene_s+13] == "EASTNORTHEAST"
        bc_ok   = pt[bc_s  : bc_s +11] == "BERLINCLOCK"

        # Count total crib matches (independent sanity check)
        n_match = sum(1 for j, c in crib_chars if j < len(pt) and pt[j] == c)

        # Self-encrypting check (PT[32]=S means real_CT[32]=S iff vig key[32%klen]=0)
        se_ok   = (len(real_ct) > 73 and
                   real_ct[32] == 'S' and
                   real_ct[73] == 'K')

        scored.append({
            'L':        L,
            'keyword':  keyword,
            'cipher':   cipher,
            'alpha':    alpha_name,
            'perm':     perm,
            'real_ct':  real_ct,
            'pt':       pt,
            'quadgram': round(qg, 5),
            'n_crib':   n_match,
            'ene_ok':   ene_ok,
            'bc_ok':    bc_ok,
            'se_ok':    se_ok,
            'ene_start': ene_s,
            'bc_start':  bc_s,
        })

    return scored


# ─────────────────────────────── main ─────────────────────────────────────

def main():
    out_dir  = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            '..', 'blitz_results', 'wildcard')
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, 'strip_perm_results.jsonl')
    print(f"Output → {out_file}")

    # ── PART 1: Fixed standard crib positions ──────────────────────────────
    print("\n" + "═"*70)
    print("PART 1: Fixed crib positions (ENE=21, BC=63)")
    print("═"*70)

    configs_p1 = []
    for L in STRIP_LENGTHS:
        N    = math.ceil(97 / L)
        fact = math.factorial(N)
        print(f"  L={L:2d}: N={N} strips, {fact:>12,} max permutations")
        for kw in KEYWORDS:
            for ci in ('vig', 'beau'):
                for an, al in ALPHAS:
                    configs_p1.append((L, kw, ci, an, al, ENE_START, BC_START))

    print(f"\nTotal Part 1 configs: {len(configs_p1):,}")
    ncores = max(1, min(multiprocessing.cpu_count() - 1, 12))
    print(f"Using {ncores} worker cores")

    best_qg       = -999.0
    total_results = 0
    breakthroughs = []
    t0            = time.time()

    with open(out_file, 'w') as outf:
        with ProcessPoolExecutor(max_workers=ncores) as ex:
            futures = {ex.submit(search_one_config, cfg): cfg for cfg in configs_p1}
            done    = 0
            for fut in as_completed(futures):
                cfg  = futures[fut]
                done += 1
                try:
                    results = fut.result()
                except Exception as e:
                    print(f"  ERROR {cfg[:4]}: {e}", file=sys.stderr)
                    results = []

                for r in results:
                    total_results += 1
                    outf.write(json.dumps(r) + '\n')
                    outf.flush()

                    # Track best quadgram
                    if r['quadgram'] > best_qg:
                        best_qg = r['quadgram']
                        print(f"\n★ NEW BEST  qg={r['quadgram']:.5f}  "
                              f"L={r['L']} {r['keyword']}/{r['cipher']}/{r['alpha']}")
                        print(f"  PT:     {r['pt'][:80]}")
                        print(f"  ENE:    {r['pt'][21:34]}  (need EASTNORTHEAST)")
                        print(f"  BC:     {r['pt'][63:74]}  (need BERLINCLOCK)")
                        print(f"  ncrib:  {r['n_crib']}/24  se_ok:{r['se_ok']}")

                    # Partial crib breakthroughs
                    if r['ene_ok'] or r['bc_ok']:
                        breakthroughs.append(r)
                        tag = ("ENE+BC" if r['ene_ok'] and r['bc_ok'] else
                               "ENE"    if r['ene_ok'] else "BC")
                        print(f"\n{'!'*60}")
                        print(f"!!! CRIB MATCH [{tag}] !!!")
                        print(f"  L={r['L']} {r['keyword']}/{r['cipher']}/{r['alpha']}")
                        print(f"  perm: {r['perm']}")
                        print(f"  PT:   {r['pt']}")
                        print(f"  qg:   {r['quadgram']:.5f}  ncrib:{r['n_crib']}/24")
                        print('!'*60)

                if done % 200 == 0 or done == len(configs_p1):
                    elapsed = time.time() - t0
                    rate    = done / elapsed if elapsed > 0 else 0
                    eta     = (len(configs_p1) - done) / rate if rate > 0 else 0
                    print(f"  Progress: {done:>5}/{len(configs_p1)} "
                          f"({done/len(configs_p1)*100:.1f}%)  "
                          f"results:{total_results}  best_qg:{best_qg:.5f}  "
                          f"elapsed:{elapsed:.0f}s  ETA:{eta:.0f}s")

    # ── PART 2: Variable crib positions (coarse scan) ──────────────────────
    print("\n" + "═"*70)
    print("PART 2: Variable crib positions (ENE: 0..30, BC: 50..80)")
    print("═"*70)

    # Focus on small L (L≥13: fastest) and top keywords only
    TOP_KEYWORDS = ["KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW"]
    TOP_L        = [13, 14, 11, 12]

    configs_p2 = []
    for ene_s in range(0, 30):
        for bc_s in range(50, 80):
            if abs(ene_s - bc_s) < 13:
                continue  # cribs would overlap
            for L in TOP_L:
                for kw in TOP_KEYWORDS:
                    for ci in ('vig', 'beau'):
                        for an, al in ALPHAS:
                            configs_p2.append((L, kw, ci, an, al, ene_s, bc_s))

    print(f"Total Part 2 configs: {len(configs_p2):,}")

    t1            = time.time()
    done_p2       = 0
    results_p2    = 0
    best_qg_p2    = -999.0
    breakthroughs_p2 = []

    out_file_p2 = os.path.join(out_dir, 'strip_perm_varcrib_results.jsonl')
    with open(out_file_p2, 'w') as outf2:
        with ProcessPoolExecutor(max_workers=ncores) as ex2:
            futures2 = {ex2.submit(search_one_config, cfg): cfg for cfg in configs_p2}
            for fut in as_completed(futures2):
                done_p2 += 1
                try:
                    results = fut.result()
                except Exception as e:
                    results = []

                for r in results:
                    results_p2 += 1
                    outf2.write(json.dumps(r) + '\n')
                    outf2.flush()

                    if r['quadgram'] > best_qg_p2:
                        best_qg_p2 = r['quadgram']
                        print(f"\n★ P2 BEST  qg={r['quadgram']:.5f}  "
                              f"L={r['L']} {r['keyword']}/{r['cipher']}/{r['alpha']}  "
                              f"ENE={r['ene_start']} BC={r['bc_start']}")
                        print(f"  PT: {r['pt'][:80]}")

                    if r['ene_ok'] or r['bc_ok']:
                        breakthroughs_p2.append(r)
                        tag = ("ENE+BC" if r['ene_ok'] and r['bc_ok'] else
                               "ENE"    if r['ene_ok'] else "BC")
                        print(f"\n{'!'*60}")
                        print(f"!!! P2 CRIB MATCH [{tag}] !!!")
                        print(f"  ENE@{r['ene_start']} BC@{r['bc_start']}")
                        print(f"  L={r['L']} {r['keyword']}/{r['cipher']}/{r['alpha']}")
                        print(f"  PT:   {r['pt']}")
                        print('!'*60)

                if done_p2 % 5000 == 0 or done_p2 == len(configs_p2):
                    elapsed2 = time.time() - t1
                    rate2 = done_p2 / elapsed2 if elapsed2 > 0 else 0
                    eta2  = (len(configs_p2) - done_p2) / rate2 if rate2 > 0 else 0
                    print(f"  P2 progress: {done_p2:>7}/{len(configs_p2):>7}  "
                          f"results:{results_p2}  best:{best_qg_p2:.5f}  "
                          f"ETA:{eta2:.0f}s")

    # ── Summary ────────────────────────────────────────────────────────────
    total_time = time.time() - t0
    print("\n" + "═"*70)
    print("SUMMARY")
    print("═"*70)
    print(f"  Wall time:           {total_time:.1f}s")
    print(f"  Part 1 configs:      {len(configs_p1):,}")
    print(f"  Part 1 results:      {total_results:,}")
    print(f"  Part 1 best_qg:      {best_qg:.5f}")
    print(f"  Part 1 breakthroughs:{len(breakthroughs)}")
    print(f"  Part 2 configs:      {len(configs_p2):,}")
    print(f"  Part 2 results:      {results_p2:,}")
    print(f"  Part 2 best_qg:      {best_qg_p2:.5f}")
    print(f"  Part 2 breakthroughs:{len(breakthroughs_p2)}")
    print(f"\nInterpretation:")
    print(f"  Noise baseline:      ≈ -6.9 qg/char")
    print(f"  English threshold:   ≈ -4.8 qg/char")

    all_bt = breakthroughs + breakthroughs_p2
    if all_bt:
        print(f"\n★ BREAKTHROUGHS FOUND ({len(all_bt)} total):")
        for r in sorted(all_bt, key=lambda x: -x['quadgram']):
            print(f"  L={r['L']} {r['keyword']}/{r['cipher']}/{r['alpha']}  "
                  f"qg={r['quadgram']:.5f}  ncrib={r['n_crib']}/24")
            print(f"    PT: {r['pt']}")
    else:
        print(f"\n✗ No crib breakthroughs found.")
        print(f"  Strip permutation (all tested L values) ELIMINATED for all keywords.")

    print(f"\nOutput files:")
    print(f"  {out_file}")
    print(f"  {out_file_p2}")


if __name__ == '__main__':
    main()
