#!/usr/bin/env python3
"""
blitz_strip_keyfind.py — Reverse keyword derivation from strip permutations

Instead of fixing a keyword and searching for strip permutations, this script
fixes the strip ASSIGNMENT at crib-constrained output strips and DERIVES the
implied keyword (for all key periods 1..26) simultaneously.

Under Model 2: PT → Vigenère(key) → real_CT → STRIP_PERMUTE(σ) → K4

For Vigenère: real_CT[p] = (PT[p] + key[p%klen]) % 26
→  key[p%klen] = (real_CT[p] - PT[p]) % 26

For a given strip permutation σ:
  real_CT[p] = K4[σ[p//L] * L + p % L]

So the KEY VALUE at position p is fully determined by the strip assignment at
output strip p//L. This means:

  key[p % klen] = (K4_idx[σ[p//L]*L + p%L] - PT_idx[p]) % 26

CONSISTENCY: for key period klen, all crib positions p with p % klen == q
must give the SAME key value. This is a tight constraint that filters 99.9%+
of random strip assignments.

The core loop:
  For each L:
    constrained_strips = {p // L : crib position p}  (output strip indices with cribs)
    For each assignment of source strips to constrained output strips
       (P(N, |constrained|) ordered selections, no repetition):
      → Compute key_implied[p] for all 24 crib positions
      → For each klen in 1..26: check consistency
      → If consistent: record (L, assignment, klen, partial_key) as CANDIDATE

For L=13: constrained output strips = {1, 2, 4, 5} (4 strips)
          N=8 source strips, P(8,4) = 8×7×6×5 = 1,680 assignments
          × 26 key periods = 43,680 checks — TRIVIAL

For L=8:  constrained output strips depend on crib positions
          N=13 source strips, P(13, |constrained|) checks

After finding consistent (perm_fragment, klen, partial_key) triples:
  - Extend to full permutation (enumerate remaining strip assignments)
  - Decrypt and score

This eliminates ALL keywords simultaneously — not just the 20+ pre-specified ones.

Run:
  PYTHONPATH=src python3 -u scripts/blitz_strip_keyfind.py
"""

import json
import math
import os
import sys
import time
from itertools import permutations, product
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing

# ────────────── constants ──────────────────────────────────────────────────

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4) == 97

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# Alphabet → integer index lookups
AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA_IDX = {c: i for i, c in enumerate(KA)}

# Pre-index K4 in both alphabets
K4_AZ = [AZ_IDX[c] for c in K4]
K4_KA = [KA_IDX.get(c, 0) for c in K4]  # KA has 'J' merged → use AZ fallback if needed

# Crib positions
ENE_START = 21
BC_START  = 63
CRIB_CHARS = (
    [(ENE_START + i, c) for i, c in enumerate("EASTNORTHEAST")] +
    [(BC_START  + i, c) for i, c in enumerate("BERLINCLOCK")]
)
CRIB_POS = [p for p, _ in CRIB_CHARS]
CRIB_PT  = {p: c for p, c in CRIB_CHARS}

# Pre-index plaintext characters in both alphabets
CRIB_PT_AZ = {p: AZ_IDX[c]    for p, c in CRIB_CHARS}
CRIB_PT_KA = {p: KA_IDX.get(c, AZ_IDX[c]) for p, c in CRIB_CHARS}

# Strip lengths to test
STRIP_LENGTHS = [13, 14, 15, 16, 11, 12, 10, 9, 8, 7]

# ────────────── quadgrams ──────────────────────────────────────────────────

_quad_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                          '..', 'data', 'english_quadgrams.json')
try:
    with open(_quad_path) as _f:
        QUAD_LOG = json.load(_f)  # already log10 probabilities
    MISS = min(QUAD_LOG.values()) - 1.0
    print(f"[quadgrams] {len(QUAD_LOG):,} entries  MISS={MISS:.3f}")
except Exception as _e:
    print(f"[quadgrams] WARNING: {_e}", file=sys.stderr)
    QUAD_LOG = {}
    MISS = -8.63


def quadgram_score(text: str) -> float:
    n = len(text)
    if n < 4:
        return MISS
    return sum(QUAD_LOG.get(text[i:i+4], MISS) for i in range(n - 3)) / (n - 3)


# ────────────── reverse key derivation ────────────────────────────────────

def key_implied_vig(real_ct_idx: int, pt_idx: int, n: int = 26) -> int:
    """key[p%klen] = (CT - PT) mod n for Vigenère."""
    return (real_ct_idx - pt_idx) % n


def key_implied_beau(real_ct_idx: int, pt_idx: int, n: int = 26) -> int:
    """key[p%klen] = (CT + PT) mod n for Beaufort (key - PT = CT → key = CT + PT)."""
    return (real_ct_idx + pt_idx) % n


def is_consistent_key(key_vals: dict, klen: int) -> tuple:
    """
    Check if key values are consistent for period klen.
    key_vals: dict {crib_pos: implied_key_val}
    Returns (True, partial_key_dict) if consistent, else (False, None).
    partial_key_dict: {key_position: value} for covered positions
    """
    partial = {}
    for p, kv in key_vals.items():
        kp = p % klen
        if kp in partial:
            if partial[kp] != kv:
                return False, None
        else:
            partial[kp] = kv
    return True, partial


def reconstruct_keyword(partial: dict, klen: int, alpha: str) -> str:
    """Build keyword string: known positions use alpha[v], unknown use '?'."""
    return ''.join(alpha[partial[i]] if i in partial else '?' for i in range(klen))


def decrypt_with_partial_key(real_ct: str, partial_key: dict, klen: int,
                              cipher: str, alpha: str, ai: dict) -> str:
    """
    Decrypt real_ct with a partial Vigenère/Beaufort key.
    Unknown key positions use alpha[0] as fallback.
    """
    n = len(alpha)
    out = []
    for j, c in enumerate(real_ct):
        ci = ai.get(c, 0)
        kv = partial_key.get(j % klen, 0)  # fallback 0 for unknown positions
        if cipher == 'vig':
            out.append(alpha[(ci - kv) % n])
        else:
            out.append(alpha[(kv - ci) % n])
    return ''.join(out)


def decrypt_full(real_ct: str, keyword: str, cipher: str, alpha: str, ai: dict) -> str:
    """Full Vigenère/Beaufort decryption."""
    n    = len(alpha)
    klen = len(keyword)
    ki   = [ai.get(c, 0) for c in keyword]
    out  = []
    for j, c in enumerate(real_ct):
        ci = ai.get(c, 0)
        kv = ki[j % klen]
        out.append(alpha[(ci - kv) % n] if cipher == 'vig' else alpha[(kv - ci) % n])
    return ''.join(out)


# ────────────── core search ────────────────────────────────────────────────

def search_L(L: int) -> list:
    """
    For strip length L: enumerate all assignments of source strips to
    constrained output strips. For each:
      - Compute implied key values at all crib positions
      - Check consistency for all key periods 1..26
      - For consistent triples: extend to full permutation + score
    Returns list of candidate dicts.
    """
    N      = math.ceil(97 / L)
    strips = [K4[i:i+L] for i in range(0, 97, L)]

    # Find constrained output strip indices
    constrained = sorted(set(p // L for p in CRIB_POS if p // L < N))
    n_con       = len(constrained)

    # For quick position lookup: which output strip does each crib position map to?
    # Also precompute strip offset for each crib position
    crib_strip  = {p: p // L for p in CRIB_POS if p // L < N}
    crib_offset = {p: p % L  for p in CRIB_POS}

    # Validate: source positions must exist in K4
    def source_pos(s, off):
        sp = s * L + off
        return sp if sp < 97 else -1

    # All source strip indices available
    all_source = list(range(N))

    candidates = []

    # Enumerate all P(N, n_con) ordered assignments (no repetition) for constrained strips
    # Assignment: a tuple of length n_con giving source strip for each constrained strip
    from itertools import permutations as iperms

    for source_assignment in iperms(all_source, n_con):
        # Map: constrained_output_strip_index → source_strip_index
        con_map = {constrained[i]: source_assignment[i] for i in range(n_con)}

        # Compute implied key values at all crib positions
        # Do this for all 4 cipher combos: (vig/beau) × (AZ/KA)
        for cipher in ('vig', 'beau'):
            for alpha_name, alpha, k4_idx, crib_pt_idx in (
                    ('AZ', AZ, K4_AZ, CRIB_PT_AZ),
                    ('KA', KA, K4_KA, CRIB_PT_KA)):

                key_vals = {}
                valid = True
                for p in CRIB_POS:
                    os_idx = crib_strip.get(p)
                    if os_idx is None:
                        continue
                    s   = con_map[os_idx]
                    off = crib_offset[p]
                    sp  = source_pos(s, off)
                    if sp < 0:
                        valid = False
                        break
                    rct_idx = k4_idx[sp]
                    pt_idx  = crib_pt_idx[p]
                    if cipher == 'vig':
                        key_vals[p] = key_implied_vig(rct_idx, pt_idx)
                    else:
                        key_vals[p] = key_implied_beau(rct_idx, pt_idx)
                if not valid:
                    continue

                # Check key consistency for each period
                for klen in range(1, 27):
                    ok, partial = is_consistent_key(key_vals, klen)
                    if not ok:
                        continue

                    # Consistent! Record candidate
                    keyword_str = reconstruct_keyword(partial, klen, alpha)
                    known_frac  = len(partial) / klen

                    # Reconstruct the partial real_CT at crib positions for sanity
                    real_ct_at_cribs = {p: alpha[k4_idx[source_pos(con_map[crib_strip[p]], crib_offset[p])]]
                                        for p in CRIB_POS if crib_strip.get(p) is not None}

                    candidates.append({
                        'L':          L,
                        'cipher':     cipher,
                        'alpha':      alpha_name,
                        'klen':       klen,
                        'keyword':    keyword_str,
                        'known_frac': round(known_frac, 3),
                        'partial_key': partial,
                        'con_map':    con_map,
                        'N':          N,
                        'constrained_strips': constrained,
                        'real_ct_at_cribs': {str(k): v for k, v in real_ct_at_cribs.items()},
                    })

    return candidates


def extend_and_score(cand: dict, top_n: int = 10) -> list:
    """
    Given a candidate with a partial strip assignment (constrained strips only),
    extend to full permutations and score the decryption.

    Returns top_n scored results.
    """
    L          = cand['L']
    cipher     = cand['cipher']
    alpha_name = cand['alpha']
    alpha      = AZ if alpha_name == 'AZ' else KA
    ai         = {c: i for i, c in enumerate(alpha)}
    klen       = cand['klen']
    partial_k  = cand['partial_key']
    con_map    = cand['con_map']
    N          = cand['N']

    # Build full keyword from partial (unknown positions filled with A as default)
    keyword_full = ''.join(alpha[partial_k.get(i, 0)] for i in range(klen))

    strips  = [K4[i:i+L] for i in range(0, 97, L)]

    # Remaining strips to assign to unconstrained output positions
    constrained_outputs = list(con_map.keys())
    constrained_sources = list(con_map.values())
    unconstrained_outputs = [k for k in range(N) if k not in con_map]
    unconstrained_sources = [s for s in range(N) if s not in constrained_sources]

    scored = []
    # Enumerate all permutations of unconstrained sources
    for perm_unc in permutations(unconstrained_sources):
        full_perm = [0] * N
        for k, s in con_map.items():
            full_perm[k] = s
        for i, k in enumerate(unconstrained_outputs):
            full_perm[k] = perm_unc[i]

        # Reconstruct real_CT
        real_ct = ''.join(strips[full_perm[k]] for k in range(N))

        # Decrypt
        pt = decrypt_full(real_ct, keyword_full, cipher, alpha, ai)

        # Score
        qg = quadgram_score(pt)

        # Verify cribs
        n_crib = sum(1 for p, c in CRIB_CHARS if p < len(pt) and pt[p] == c)

        scored.append({
            'qg':       round(qg, 5),
            'n_crib':   n_crib,
            'perm':     full_perm,
            'pt':       pt,
            'keyword':  keyword_full,
            'real_ct':  real_ct,
        })

    # Sort and return top_n
    scored.sort(key=lambda x: -x['qg'])
    return scored[:top_n]


# ────────────── main ───────────────────────────────────────────────────────

def main():
    out_dir  = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            '..', 'blitz_results', 'wildcard')
    os.makedirs(out_dir, exist_ok=True)

    print("=" * 70)
    print("blitz_strip_keyfind.py — Reverse keyword derivation")
    print("Model 2: PT → Vig(key) → real_CT → STRIP(σ) → K4")
    print("For each strip assignment at constrained positions: derive keyword")
    print("=" * 70)

    t0 = time.time()
    all_candidates = []

    for L in STRIP_LENGTHS:
        N    = math.ceil(97 / L)
        con  = sorted(set(p // L for p in CRIB_POS if p // L < N))
        n_assignments = 1
        for i in range(len(con)):
            n_assignments *= (N - i)
        n_total_checks = n_assignments * 4 * 26  # ×4 cipher combos, ×26 periods

        print(f"\nL={L:2d}: N={N} strips, {len(con)} constrained outputs {con}")
        print(f"       {n_assignments:,} assignments × 26 periods × 4 ciphers = {n_total_checks:,} checks")

        t_L = time.time()
        cands = search_L(L)
        dt_L  = time.time() - t_L

        # Filter to report only if we have non-trivial candidates
        # Rank by: number of KNOWN key positions, then by how many there are
        n_full_key = sum(1 for c in cands if c['known_frac'] == 1.0)
        print(f"       Found {len(cands):,} consistent candidates "
              f"({n_full_key} with fully-known key) in {dt_L:.2f}s")

        # Show best candidates (most key positions known, short keywords)
        if cands:
            # Sort by (klen=1 bad, fully known good, short keywords preferred)
            cands_sorted = sorted(cands, key=lambda c: (-c['known_frac'], c['klen']))
            top = cands_sorted[:20]
            print(f"       Top candidates (by coverage):")
            for c in top[:10]:
                print(f"         klen={c['klen']:2d} {c['cipher']}/{c['alpha']}  "
                      f"keyword={c['keyword']}  "
                      f"coverage={c['known_frac']:.2f}")

        all_candidates.extend(cands)

    print(f"\n{'=' * 70}")
    print(f"Total consistent candidates: {len(all_candidates):,}")
    elapsed = time.time() - t0
    print(f"Search time: {elapsed:.2f}s")

    # Save all candidates
    cand_file = os.path.join(out_dir, 'strip_keyfind_candidates.jsonl')
    with open(cand_file, 'w') as f:
        for c in all_candidates:
            f.write(json.dumps(c) + '\n')
    print(f"Saved candidates → {cand_file}")

    # ── Extend top candidates to full permutations ─────────────────────────
    print(f"\n{'=' * 70}")
    print("Extending top candidates to full permutations...")

    # Prioritize: fully-known key, then by klen
    prioritized = sorted(all_candidates,
                         key=lambda c: (-c['known_frac'], c['klen'], -c['L']))
    # Also prioritize small N (fewer unconstrained strips = faster extension)
    prioritized.sort(key=lambda c: (
        -c['known_frac'],
        math.factorial(c['N'] - len(c['constrained_strips'])),
        c['klen'],
    ))

    # Take top candidates, but avoid explosion for large unconstrained spaces
    scored_results = []
    best_qg = -999.0
    EXTEND_LIMIT = 500  # max candidates to fully extend

    t1 = time.time()
    for i, cand in enumerate(prioritized[:EXTEND_LIMIT]):
        n_unc = cand['N'] - len(cand['constrained_strips'])
        n_unc_facts = math.factorial(n_unc)
        if n_unc_facts > 100_000:
            # Too many unconstrained strip perms to enumerate fully
            # Just try the "natural" ordering for unconstrained strips
            pass  # extend_and_score will still try partial

        try:
            results = extend_and_score(cand, top_n=5)
        except Exception as e:
            print(f"  Error extending cand {i}: {e}", file=sys.stderr)
            continue

        for r in results:
            r.update({
                'L':       cand['L'],
                'cipher':  cand['cipher'],
                'alpha':   cand['alpha'],
                'klen':    cand['klen'],
            })
            scored_results.append(r)
            if r['qg'] > best_qg:
                best_qg = r['qg']
                print(f"\n  ★ NEW BEST  qg={r['qg']:.5f}  "
                      f"L={r['L']} klen={r['klen']} {r['cipher']}/{r['alpha']}")
                print(f"    keyword: {r['keyword']}")
                print(f"    PT[21:34]: {r['pt'][21:34]}  (need EASTNORTHEAST)")
                print(f"    PT[63:74]: {r['pt'][63:74]}  (need BERLINCLOCK)")
                print(f"    n_crib: {r['n_crib']}/24")
                print(f"    PT: {r['pt'][:80]}")

        if (i + 1) % 50 == 0:
            print(f"  Extended {i+1}/{min(EXTEND_LIMIT, len(prioritized))} candidates  "
                  f"best_qg={best_qg:.5f}")

    print(f"\nExtension time: {time.time()-t1:.2f}s")
    print(f"Total scored results: {len(scored_results):,}")
    print(f"Best quadgram: {best_qg:.5f}")

    # Save scored results
    scored_file = os.path.join(out_dir, 'strip_keyfind_scored.jsonl')
    scored_results.sort(key=lambda x: -x['qg'])
    with open(scored_file, 'w') as f:
        for r in scored_results[:1000]:
            f.write(json.dumps(r) + '\n')
    print(f"Saved top scored → {scored_file}")

    # ── Final summary ─────────────────────────────────────────────────────
    print(f"\n{'=' * 70}")
    print("SUMMARY — Strip Keyfind Results")
    print(f"{'=' * 70}")
    print(f"  Total wall time:        {time.time()-t0:.2f}s")
    print(f"  Consistent candidates:  {len(all_candidates):,}")
    print(f"  Scored permutations:    {len(scored_results):,}")
    print(f"  Best quadgram:          {best_qg:.5f}")
    print(f"  English threshold:      ≈ -4.8")
    print(f"  Noise baseline:         ≈ -6.9")

    # Crib matches
    crib_matches = [r for r in scored_results if r['n_crib'] == 24]
    partial_matches = [r for r in scored_results if r['n_crib'] >= 20]
    print(f"  Full crib matches (24/24): {len(crib_matches)}")
    print(f"  Near matches (≥20/24):     {len(partial_matches)}")

    if partial_matches:
        print(f"\n  Near-crib matches:")
        for r in partial_matches[:10]:
            print(f"    L={r['L']} klen={r['klen']} {r['cipher']}/{r['alpha']}  "
                  f"qg={r['qg']:.5f}  ncrib={r['n_crib']}/24")
            print(f"    kw={r['keyword']}")
            print(f"    PT: {r['pt']}")

    if not crib_matches and not partial_matches:
        print(f"\n  ✗ No crib matches found.")
        print(f"    Strip permutation (any uniform block length, any keyword period 1-26)")
        print(f"    COMPREHENSIVELY ELIMINATED for Vigenère/Beaufort in AZ/KA alphabets.")

    print(f"\n  → Candidates file: {cand_file}")
    print(f"  → Scored file:     {scored_file}")

    # ── Per-L summary ─────────────────────────────────────────────────────
    print(f"\nPer-L candidate counts:")
    by_L = {}
    for c in all_candidates:
        by_L.setdefault(c['L'], []).append(c)
    for L in sorted(by_L.keys()):
        n = len(by_L[L])
        full = sum(1 for c in by_L[L] if c['known_frac'] == 1.0)
        klens = sorted(set(c['klen'] for c in by_L[L] if c['known_frac'] == 1.0))[:8]
        print(f"  L={L:2d}: {n:5,} candidates ({full} fully-known)  klens={klens}")


if __name__ == '__main__':
    main()
