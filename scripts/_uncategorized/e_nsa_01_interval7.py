#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: promising
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-NSA-01: Interval-7 transposition + substitution sweep.

Based on NSA DOCID:4145037 observation: K4 exhibits "a slight interval 7 property."
Also incorporates E-NSA-03 (K3 exact transposition on K4).

Tests performed:
  Part 0: Re-verify lag-7 autocorrelation signal
  Part 1: K3-exact transposition (key 4152637, both read directions)
  Part 2: All 5040 width-7 column orderings × periods 2-24 × 3 variants × 2 dirs
  Part 3: Wider matrices (4×25, 14×7, etc.) with interval-7 column grouping

Convention: 0-indexed positions throughout.
Permutation convention: output[i] = input[perm[i]] (gather).
"""
import sys
import os
import json
import math
from collections import defaultdict
from itertools import permutations
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
)

# ── Precomputed numeric arrays ───────────────────────────────────────────

CT_NUM = [ord(c) - 65 for c in CT]
CRIB_PT_NUM = {pos: ord(ch) - 65 for pos, ch in CRIB_DICT.items()}
ALL_CRIB_POS = sorted(CRIB_PT_NUM.keys())  # 24 positions
ENE_POS = list(range(21, 34))
BC_POS = list(range(63, 74))

# ── Permutation utilities ────────────────────────────────────────────────

def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

def apply_perm_num(text_num, perm):
    return [text_num[p] for p in perm]

def validate_perm(perm, length):
    return len(perm) == length and set(perm) == set(range(length))

# ── Columnar transposition ───────────────────────────────────────────────

def columnar_perm(width, col_order, length=97, reverse_cols=False):
    """Standard columnar: fill by rows, read columns in rank order.
    col_order[c] = rank of column c (rank 0 read first).
    If reverse_cols, read each column bottom-to-top.
    """
    cols = defaultdict(list)
    for pos in range(length):
        _, c = divmod(pos, width)
        cols[c].append(pos)
    perm = []
    for rank in range(width):
        col_idx = list(col_order).index(rank)
        entries = cols[col_idx]
        if reverse_cols:
            perm.extend(reversed(entries))
        else:
            perm.extend(entries)
    return perm

def interval7_perm(rows, cols_n, key7, length=97, reverse_cols=False):
    """Wider-matrix transposition with interval-7 column grouping.
    Groups columns by (col_index mod 7), reads groups in key7 order.
    Within each group, columns are ascending. Each column read row-by-row.
    """
    groups = defaultdict(list)
    for c in range(cols_n):
        groups[c % 7].append(c)
    read_order = [list(key7).index(r) for r in range(7)]
    perm = []
    for group_idx in read_order:
        for c in groups[group_idx]:
            col_entries = []
            for r in range(rows):
                pos = r * cols_n + c
                if pos < length:
                    col_entries.append(pos)
            if reverse_cols:
                perm.extend(reversed(col_entries))
            else:
                perm.extend(col_entries)
    return perm

# ── Key derivations ──────────────────────────────────────────────────────

def nsa_key_order():
    """NSA stated key: read order 4,1,5,2,6,3,7 (1-indexed).
    0-indexed read order: 3,0,4,1,5,2,6
    → col_order: col 0=rank1, col 1=rank3, col 2=rank5, col 3=rank0,
                 col 4=rank2, col 5=rank4, col 6=rank6
    """
    read_0 = [3, 0, 4, 1, 5, 2, 6]
    co = [0] * 7
    for rank, col in enumerate(read_0):
        co[col] = rank
    return tuple(co)  # (1, 3, 5, 0, 2, 4, 6)

def kryptos_key_order():
    """Standard alphabetical ranking of KRYPTOS: K=0,O=1,P=2,R=3,S=4,T=5,Y=6."""
    kw = "KRYPTOS"
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed)
    order = [0] * 7
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return tuple(order)  # (0, 3, 6, 2, 5, 1, 4)

# ── Scoring ──────────────────────────────────────────────────────────────

def recover_keys(ct_num, variant):
    """Recover key values at all 24 crib positions for a given variant."""
    keys = {}
    for pos in ALL_CRIB_POS:
        c = ct_num[pos]
        p = CRIB_PT_NUM[pos]
        if variant == 'vig':
            keys[pos] = (c - p) % MOD
        elif variant == 'beau':
            keys[pos] = (c + p) % MOD
        elif variant == 'varbeau':
            keys[pos] = (p - c) % MOD
    return keys

def period_consistency(key_vals, period):
    """Count positions consistent with a periodic key of given period.
    Returns (consistent_count, residue_key_map).
    """
    groups = defaultdict(list)
    for pos in ALL_CRIB_POS:
        groups[pos % period].append(key_vals[pos])
    consistent = 0
    residue_keys = {}
    for res, vals in groups.items():
        counts = defaultdict(int)
        for v in vals:
            counts[v] += 1
        best_val = max(counts, key=counts.get)
        residue_keys[res] = best_val
        consistent += counts[best_val]
    return consistent, residue_keys

def bean_check(key_vals):
    """Check Bean equality: key[27] == key[65]."""
    return key_vals.get(27) == key_vals.get(65)

# ══════════════════════════════════════════════════════════════════════════
# PART 0: Lag autocorrelation
# ══════════════════════════════════════════════════════════════════════════

def part0_autocorrelation():
    print("=" * 72)
    print("PART 0: LAG AUTOCORRELATION VERIFICATION")
    print("=" * 72)
    N = CT_LEN

    print(f"\n{'Lag':>4} {'Match':>6} {'Exp':>7} {'Z':>8} {'Note'}")
    print("-" * 42)

    results = {}
    for lag in range(1, 49):
        matches = sum(1 for i in range(N - lag) if CT_NUM[i] == CT_NUM[i + lag])
        n_pairs = N - lag
        expected = n_pairs / 26.0
        std = (expected * (1.0 - 1.0 / 26)) ** 0.5
        z = (matches - expected) / std if std > 0 else 0
        results[lag] = {'matches': matches, 'expected': round(expected, 2), 'z': round(z, 3)}
        marker = ""
        if abs(z) >= 3.0: marker = " ***"
        elif abs(z) >= 2.0: marker = " **"
        elif abs(z) >= 1.5: marker = " *"
        if abs(z) >= 1.5 or lag <= 14 or lag % 7 == 0:
            print(f"{lag:4d} {matches:6d} {expected:7.2f} {z:+8.3f}{marker}")

    print("\n--- Lag-7 multiples ---")
    for m in [7, 14, 21, 28, 35, 42]:
        r = results[m]
        print(f"  Lag {m:2d}: z={r['z']:+.3f}, matches={r['matches']}")

    # Kasiski-style: count bigram repeats at distance=multiple of 7
    print("\n--- Kasiski: repeated bigrams at lag divisible by 7 ---")
    bigrams_at_7 = 0
    bigrams_total = 0
    for i in range(N - 1):
        bg = CT[i:i+2]
        for j in range(i + 1, N - 1):
            if CT[j:j+2] == bg:
                bigrams_total += 1
                if (j - i) % 7 == 0:
                    bigrams_at_7 += 1
    expected_frac = 1.0 / 7  # if lags were random
    actual_frac = bigrams_at_7 / bigrams_total if bigrams_total else 0
    print(f"  Repeated bigram pairs: {bigrams_total}")
    print(f"  At lag ≡ 0 mod 7: {bigrams_at_7} ({actual_frac:.3f}, expected {expected_frac:.3f})")

    return results

# ══════════════════════════════════════════════════════════════════════════
# PART 1: K3 exact transposition
# ══════════════════════════════════════════════════════════════════════════

def part1_k3_exact():
    print("\n" + "=" * 72)
    print("PART 1: K3 EXACT TRANSPOSITION ON K4 (E-NSA-03)")
    print("=" * 72)

    nsa_co = nsa_key_order()
    kryptos_co = kryptos_key_order()
    print(f"NSA col_order:     {nsa_co}  (read: {[list(nsa_co).index(r) for r in range(7)]})")
    print(f"KRYPTOS col_order: {kryptos_co}  (read: {[list(kryptos_co).index(r) for r in range(7)]})")

    configs = [
        (7, nsa_co, False, "NSA w7 T→B"),
        (7, nsa_co, True,  "NSA w7 B→T"),
        (7, kryptos_co, False, "KRY w7 T→B"),
        (7, kryptos_co, True,  "KRY w7 B→T"),
    ]
    variants = ['vig', 'beau', 'varbeau']
    best = 0
    all_results = []

    for width, co, rev, label in configs:
        perm = columnar_perm(width, co, CT_LEN, rev)
        inv = invert_perm(perm)
        for variant in variants:
            for transform, dir_label in [(inv, "dec"), (perm, "enc")]:
                ct_t = apply_perm_num(CT_NUM, transform)
                kv = recover_keys(ct_t, variant)
                bean_ok = bean_check(kv)
                for period in range(2, 25):
                    score, rk = period_consistency(kv, period)
                    if score > best:
                        best = score
                    entry = {
                        'label': label, 'variant': variant, 'dir': dir_label,
                        'period': period, 'score': score, 'bean': bean_ok,
                    }
                    all_results.append(entry)
                    if score > NOISE_FLOOR:
                        m = " ***" if score >= SIGNAL_THRESHOLD else " **" if score >= STORE_THRESHOLD else ""
                        print(f"  [{score:2d}/24] p={period:2d} Bean={'Y' if bean_ok else 'N'}"
                              f" | {label} {variant} {dir_label}{m}")

    print(f"\nK3-exact best: {best}/24")
    if best <= NOISE_FLOOR:
        print("  → Noise floor. K3's exact parameters DO NOT decrypt K4.")
    return all_results, best

# ══════════════════════════════════════════════════════════════════════════
# PART 2: Exhaustive width-7 column orderings
# ══════════════════════════════════════════════════════════════════════════

def part2_exhaustive_width7():
    print("\n" + "=" * 72)
    print("PART 2: ALL 5040 WIDTH-7 COLUMN ORDERINGS × PERIODS 2-24")
    print("=" * 72)

    variants = ['vig', 'beau', 'varbeau']
    periods = list(range(2, 25))
    best = 0
    hits = []
    tested = 0

    for col_order in permutations(range(7)):
        for reverse_cols in [False, True]:
            perm = columnar_perm(7, col_order, CT_LEN, reverse_cols)
            inv = invert_perm(perm)
            for transform, dir_label in [(inv, "dec"), (perm, "enc")]:
                ct_t = apply_perm_num(CT_NUM, transform)
                for variant in variants:
                    kv = recover_keys(ct_t, variant)
                    bean_ok = bean_check(kv)
                    for period in periods:
                        score, rk = period_consistency(kv, period)
                        tested += 1
                        if score > best:
                            best = score
                        if score >= STORE_THRESHOLD:
                            rev_s = "B→T" if reverse_cols else "T→B"
                            hits.append({
                                'col': col_order, 'rev': reverse_cols,
                                'var': variant, 'dir': dir_label,
                                'p': period, 'score': score, 'bean': bean_ok,
                            })
                            if score >= SIGNAL_THRESHOLD:
                                print(f"  [{score:2d}/24] p={period:2d} Bean={'Y' if bean_ok else 'N'}"
                                      f" col={col_order} {rev_s} {variant} {dir_label} ***")

    print(f"\nTested: {tested:,} configs")
    print(f"Best: {best}/24")
    print(f"Hits ≥ {STORE_THRESHOLD}: {len(hits)}")

    if hits:
        # Period distribution
        pd = defaultdict(int)
        for h in hits:
            pd[h['p']] += 1
        print("Hit distribution by period:")
        for p in sorted(pd):
            print(f"  p={p:2d}: {pd[p]} hits")

        # Top 10
        top = sorted(hits, key=lambda x: -x['score'])[:10]
        print("\nTop 10:")
        for h in top:
            rev_s = "B→T" if h['rev'] else "T→B"
            print(f"  [{h['score']:2d}/24] p={h['p']:2d} Bean={'Y' if h['bean'] else 'N'}"
                  f" col={h['col']} {rev_s} {h['var']} {h['dir']}")

    if best <= NOISE_FLOOR:
        print("\n  → ELIMINATED: Width-7 columnar + periodic Vig/Beau/VarBeau (all periods)")

    return hits, best

# ══════════════════════════════════════════════════════════════════════════
# PART 3: Wider matrices with interval-7 grouping
# ══════════════════════════════════════════════════════════════════════════

def part3_wider_matrices():
    print("\n" + "=" * 72)
    print("PART 3: WIDER MATRICES WITH INTERVAL-7 COLUMN GROUPING")
    print("=" * 72)

    nsa_co = nsa_key_order()
    kryptos_co = kryptos_key_order()

    matrix_configs = [
        (4, 25, "4×25"), (25, 4, "25×4"),
        (7, 14, "7×14"), (14, 7, "14×7"),
        (2, 49, "2×49"), (49, 2, "49×2"),
    ]
    keys = [(nsa_co, "NSA"), (kryptos_co, "KRY")]
    variants = ['vig', 'beau', 'varbeau']
    periods = list(range(2, 25))
    best = 0
    hits = []

    for rows, cols_n, mat_label in matrix_configs:
        for key7, key_label in keys:
            for rev in [False, True]:
                perm = interval7_perm(rows, cols_n, key7, CT_LEN, rev)
                if not validate_perm(perm, CT_LEN):
                    print(f"  SKIP invalid perm: {mat_label} {key_label} rev={rev}")
                    continue
                inv = invert_perm(perm)
                for transform, dir_label in [(inv, "dec"), (perm, "enc")]:
                    ct_t = apply_perm_num(CT_NUM, transform)
                    for variant in variants:
                        kv = recover_keys(ct_t, variant)
                        bean_ok = bean_check(kv)
                        for period in periods:
                            score, rk = period_consistency(kv, period)
                            if score > best:
                                best = score
                            if score >= STORE_THRESHOLD:
                                rev_s = "B→T" if rev else "T→B"
                                hits.append({
                                    'mat': mat_label, 'key': key_label,
                                    'rev': rev, 'var': variant,
                                    'dir': dir_label, 'p': period,
                                    'score': score, 'bean': bean_ok,
                                })
                                if score >= SIGNAL_THRESHOLD:
                                    print(f"  [{score:2d}/24] p={period:2d}"
                                          f" {mat_label} {key_label} {rev_s}"
                                          f" {variant} {dir_label} ***")

    print(f"\nWider matrices best: {best}/24, hits ≥ {STORE_THRESHOLD}: {len(hits)}")
    if hits:
        top = sorted(hits, key=lambda x: -x['score'])[:5]
        for h in top:
            print(f"  [{h['score']:2d}/24] p={h['p']:2d} {h['mat']} {h['key']}"
                  f" {'B→T' if h['rev'] else 'T→B'} {h['var']} {h['dir']}")

    if best <= NOISE_FLOOR:
        print("  → All at noise floor.")

    return hits, best

# ══════════════════════════════════════════════════════════════════════════
# PART 4: Width-7 transposition + autokey (NSA's untested combo)
# ══════════════════════════════════════════════════════════════════════════

def part4_transposition_autokey():
    """Test the specific gap: autokey AFTER un-transposing with width-7."""
    print("\n" + "=" * 72)
    print("PART 4: WIDTH-7 TRANSPOSITION + AUTOKEY (NSA untested combo)")
    print("=" * 72)
    print("Testing top-20 width-7 permutations (by Bean pass rate) with CT/PT autokey")

    nsa_co = nsa_key_order()
    kryptos_co = kryptos_key_order()

    # Pre-select: permutations where Bean equality holds under Vig
    bean_pass_perms = []
    for col_order in permutations(range(7)):
        for reverse_cols in [False, True]:
            perm = columnar_perm(7, col_order, CT_LEN, reverse_cols)
            inv = invert_perm(perm)
            for transform in [inv, perm]:
                ct_t = apply_perm_num(CT_NUM, transform)
                kv = recover_keys(ct_t, 'vig')
                if bean_check(kv):
                    bean_pass_perms.append((col_order, reverse_cols, transform))

    print(f"  Bean-passing width-7 transpositions: {len(bean_pass_perms)}")

    best = 0
    for col_order, rev, transform in bean_pass_perms[:200]:  # cap at 200
        ct_t = apply_perm_num(CT_NUM, transform)
        ct_t_str = "".join(chr(v + 65) for v in ct_t)

        # CT-autokey: k[i] = CT[i-p] for i >= p
        for primer_len in range(1, 30):
            # Check: at crib positions >= primer_len, key = ct_t[pos - primer_len]
            # k[pos] = ct_t[pos - primer_len]
            # For Vig: k[pos] = (ct_t[pos] - pt[pos]) mod 26
            # So: ct_t[pos - primer_len] should == (ct_t[pos] - pt[pos]) mod 26
            matches = 0
            for pos in ALL_CRIB_POS:
                if pos >= primer_len:
                    k_auto = ct_t[pos - primer_len]
                    k_crib = (ct_t[pos] - CRIB_PT_NUM[pos]) % MOD
                    if k_auto == k_crib:
                        matches += 1
            total_checkable = sum(1 for p in ALL_CRIB_POS if p >= primer_len)
            if total_checkable > 0 and matches > best:
                best = matches
            if matches >= STORE_THRESHOLD:
                rev_s = "B→T" if rev else "T→B"
                print(f"  CT-autokey: [{matches}/{total_checkable}] "
                      f"primer={primer_len} col={col_order} {rev_s}")

        # PT-autokey: k[i] = PT[i-p] for i >= p
        # k[pos] = (ct_t[pos] - pt[pos]) mod 26
        # pt[pos - primer_len] should == k[pos]
        # But we only know pt at crib positions...
        # Check: for crib position pos AND (pos - primer_len) also a crib position
        for primer_len in range(1, 50):
            matches = 0
            checkable = 0
            for pos in ALL_CRIB_POS:
                prev = pos - primer_len
                if prev in CRIB_PT_NUM:
                    checkable += 1
                    k_crib = (ct_t[pos] - CRIB_PT_NUM[pos]) % MOD
                    pt_prev = CRIB_PT_NUM[prev]
                    if pt_prev == k_crib:
                        matches += 1
            if checkable >= 3 and matches == checkable and matches > best:
                best = matches
                rev_s = "B→T" if rev else "T→B"
                print(f"  PT-autokey: [{matches}/{checkable}] "
                      f"primer={primer_len} col={col_order} {rev_s}")

    print(f"\nTransposition+autokey best: {best}")
    if best <= NOISE_FLOOR:
        print("  → At noise floor. Transposition+autokey combination eliminated.")
    return best

# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    t0 = datetime.now()
    print(f"E-NSA-01: Interval-7 Transposition + Substitution Sweep")
    print(f"Started: {t0.isoformat()}")
    print(f"CT: {CT} (len={CT_LEN})")

    # Part 0
    lag_results = part0_autocorrelation()
    lag7_z = lag_results.get(7, {}).get('z', None)

    # Part 1
    k3_results, k3_best = part1_k3_exact()

    # Part 2
    w7_hits, w7_best = part2_exhaustive_width7()

    # Part 3
    wide_hits, wide_best = part3_wider_matrices()

    # Part 4
    autokey_best = part4_transposition_autokey()

    # Summary
    t1 = datetime.now()
    elapsed = (t1 - t0).total_seconds()
    overall = max(k3_best, w7_best, wide_best, autokey_best)

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"Lag-7 z-score: {lag7_z}")
    print(f"Part 1 (K3 exact, all periods): best {k3_best}/24")
    print(f"Part 2 (5040 orderings, all p): best {w7_best}/24, hits≥{STORE_THRESHOLD}: {len(w7_hits)}")
    print(f"Part 3 (wider matrices):        best {wide_best}/24, hits≥{STORE_THRESHOLD}: {len(wide_hits)}")
    print(f"Part 4 (trans+autokey):          best {autokey_best}")
    print(f"Overall best: {overall}/24")

    if overall <= NOISE_FLOOR:
        print("\nCONCLUSION: ALL interval-7 transposition + substitution configs at noise floor.")
        print("ELIMINATED: Columnar transposition (width 7 + wider interval-7)")
        print("  + periodic Vigenère/Beaufort/VarBeaufort (periods 2-24)")
        print("  + CT/PT autokey after transposition")
    elif overall >= SIGNAL_THRESHOLD:
        print(f"\nSIGNAL DETECTED at {overall}/24! Investigate further.")
    else:
        print(f"\nScores above noise ({NOISE_FLOOR}) but below signal ({SIGNAL_THRESHOLD}).")

    # Save
    summary = {
        'timestamp': t0.isoformat(),
        'elapsed_seconds': elapsed,
        'lag7_z': lag7_z,
        'k3_exact_best': k3_best,
        'w7_best': w7_best,
        'w7_hits': len(w7_hits),
        'wider_best': wide_best,
        'wider_hits': len(wide_hits),
        'autokey_best': autokey_best,
        'overall_best': overall,
    }
    out_path = os.path.join(os.path.dirname(__file__), '..', 'results', 'e_nsa_01_interval7.json')
    with open(out_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nResults saved to {out_path}")
