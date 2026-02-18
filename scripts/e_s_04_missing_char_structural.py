#!/usr/bin/env python3
"""E-S-04: Missing character structural analysis.

Following E-S-03's elimination of grid-based transpositions for pos 74+,
this tests whether ANY insertion at pos 74-98 improves cipher diagnostics:

1. IC change: does any 98-char CT have better/worse IC?
2. Lag-7 autocorrelation: does the signal strengthen or weaken?
3. Digraphic compatibility: 98 is even, enabling Playfair/Two-Square without padding
4. Factor analysis: 98 = 2×7×7. Test period-7 and period-49 Vigenère directly.
5. Double transposition: width-7 columnar applied twice (algebraically pruned)
6. Bifid cipher on 5×5 Polybius: 98 is even (required for Bifid)
"""
import sys
import os
import json
import time
import math
from collections import defaultdict, Counter
from itertools import permutations

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, MOD, ALPH, KRYPTOS_ALPHABET,
    CRIB_DICT, N_CRIBS, BEAN_EQ,
)

CT_NUM = [ord(c) - 65 for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_PT = {p: ord(CRIB_DICT[p]) - 65 for p in CRIB_POS}
WIDTH = 7
GRID_LEN = 98
INSERT_RANGE = list(range(74, 99))  # positions 74-98


def ic(nums):
    """Index of coincidence."""
    n = len(nums)
    if n < 2:
        return 0.0
    counts = Counter(nums)
    return sum(c * (c - 1) for c in counts.values()) / (n * (n - 1))


def lag_autocorrelation(nums, lag):
    """Count matching pairs at given lag distance."""
    return sum(1 for i in range(len(nums) - lag) if nums[i] == nums[i + lag])


def expected_matches(n, lag, alphabet=26):
    """Expected matches at lag for random text."""
    return (n - lag) / alphabet


def z_score(observed, expected, n_trials, alphabet=26):
    """Z-score for autocorrelation match count."""
    p = 1.0 / alphabet
    variance = n_trials * p * (1 - p)
    if variance <= 0:
        return 0.0
    return (observed - expected) / math.sqrt(variance)


# ── Analysis 1: IC and autocorrelation ─────────────────────────────────

def analyze_ic_and_autocorrelation():
    print("=" * 72)
    print("ANALYSIS 1: IC AND LAG-7 AUTOCORRELATION")
    print("=" * 72)

    # Baseline (97-char)
    base_ic = ic(CT_NUM)
    base_lag7 = lag_autocorrelation(CT_NUM, 7)
    base_exp7 = expected_matches(97, 7)
    base_z7 = z_score(base_lag7, base_exp7, 90)
    print(f"\n  Baseline (97 chars):")
    print(f"    IC = {base_ic:.6f}")
    print(f"    Lag-7: {base_lag7} matches (exp={base_exp7:.2f}, z={base_z7:.3f})")

    best_ic_delta = 0
    best_z7 = 0
    best_ic_cfg = None
    best_z7_cfg = None
    ic_toward_english = []

    for ip in INSERT_RANGE:
        for lv in range(26):
            ct98 = list(CT_NUM)
            ct98.insert(ip, lv)

            this_ic = ic(ct98)
            this_lag7 = lag_autocorrelation(ct98, 7)
            this_exp7 = expected_matches(98, 7)
            this_z7 = z_score(this_lag7, this_exp7, 91)

            ic_delta = this_ic - base_ic
            if abs(ic_delta) > abs(best_ic_delta):
                best_ic_delta = ic_delta
                best_ic_cfg = dict(pos=ip, letter=chr(lv+65), ic=this_ic, delta=ic_delta)

            if this_z7 > best_z7:
                best_z7 = this_z7
                best_z7_cfg = dict(pos=ip, letter=chr(lv+65), matches=this_lag7,
                                   z=this_z7)

            if this_ic > 0.055:
                ic_toward_english.append(dict(pos=ip, letter=chr(lv+65),
                                              ic=this_ic))

    print(f"\n  IC analysis (650 candidates):")
    print(f"    Max |IC delta|: {best_ic_delta:+.6f}")
    if best_ic_cfg:
        print(f"    Config: ins='{best_ic_cfg['letter']}'@{best_ic_cfg['pos']}, "
              f"IC={best_ic_cfg['ic']:.6f}")
    print(f"    ICs > 0.055 (English-like): {len(ic_toward_english)}")

    print(f"\n  Lag-7 analysis (650 candidates):")
    print(f"    Best z-score: {best_z7:.3f}")
    if best_z7_cfg:
        print(f"    Config: ins='{best_z7_cfg['letter']}'@{best_z7_cfg['pos']}, "
              f"matches={best_z7_cfg['matches']}, z={best_z7_cfg['z']:.3f}")

    # Also check all lags 1-20 for baseline and best candidate
    print(f"\n  All lags (baseline 97-char):")
    for lag in range(1, 21):
        m = lag_autocorrelation(CT_NUM, lag)
        e = expected_matches(97, lag)
        z = z_score(m, e, 97 - lag)
        marker = " ***" if abs(z) > 2.5 else ""
        print(f"    Lag {lag:2d}: {m:2d} matches (exp={e:.2f}, z={z:+.3f}){marker}")

    return best_ic_cfg, best_z7_cfg


# ── Analysis 2: Period-7 Vigenère (no transposition) ───────────────────

def analyze_period7_direct():
    """Test if any 98-char CT has period-7 key consistency at cribs."""
    print("\n" + "=" * 72)
    print("ANALYSIS 2: PERIOD-7 VIGENÈRE (no transposition)")
    print("=" * 72)

    best_score = 0
    best_cfg = None

    for ip in INSERT_RANGE:
        for lv in range(26):
            ct98 = list(CT_NUM)
            ct98.insert(ip, lv)

            # Compute key at crib positions
            key_by_residue = defaultdict(list)
            for pt_pos in CRIB_POS:
                cv = ct98[pt_pos]
                pv = CRIB_PT[pt_pos]
                kv = (cv - pv) % MOD
                key_by_residue[pt_pos % 7].append(kv)

            # Check consistency
            score = 0
            for vals in key_by_residue.values():
                counts = Counter(vals)
                score += max(counts.values())

            if score > best_score:
                best_score = score
                best_cfg = dict(pos=ip, letter=chr(lv+65), score=score,
                                variant='vig')

    # Also Beaufort
    best_beau = 0
    best_beau_cfg = None
    for ip in INSERT_RANGE:
        for lv in range(26):
            ct98 = list(CT_NUM)
            ct98.insert(ip, lv)

            key_by_residue = defaultdict(list)
            for pt_pos in CRIB_POS:
                cv = ct98[pt_pos]
                pv = CRIB_PT[pt_pos]
                kv = (cv + pv) % MOD
                key_by_residue[pt_pos % 7].append(kv)

            score = 0
            for vals in key_by_residue.values():
                counts = Counter(vals)
                score += max(counts.values())

            if score > best_beau:
                best_beau = score
                best_beau_cfg = dict(pos=ip, letter=chr(lv+65), score=score,
                                     variant='beau')

    print(f"  Vigenère period 7: best {best_score}/24")
    if best_cfg:
        print(f"    Config: {best_cfg}")
    print(f"  Beaufort period 7: best {best_beau}/24")
    if best_beau_cfg:
        print(f"    Config: {best_beau_cfg}")

    # Expected random at period 7 with 24 cribs
    # 7 residue classes, ~3.4 per class
    # Expected = sum over groups of E[max(multinomial)]
    # For group size n, E[max] ≈ 1 + n*(n-1)/(2*26)
    groups = defaultdict(int)
    for p in CRIB_POS:
        groups[p % 7] += 1
    exp = sum(1 + n * (n - 1) / (2 * 26) for n in groups.values())
    print(f"  Expected random at p=7: {exp:.1f}/24")

    return max(best_score, best_beau)


# ── Analysis 3: Bifid cipher ──────────────────────────────────────────

def bifid_encrypt_check(ct98, polybius_key, period=None):
    """Check if ct98 could be Bifid-encrypted plaintext using given Polybius square.
    For Bifid, length must be even (98 is!).
    If period is None, use full-length Bifid.
    Returns crib consistency score.
    """
    # Build Polybius square (5×5, I=J)
    square = {}
    inv_square = {}
    for i, ch in enumerate(polybius_key):
        r, c = divmod(i, 5)
        v = ord(ch) - 65
        square[v] = (r, c)
        inv_square[(r, c)] = v

    # For Bifid decryption:
    # 1. Convert CT to row/col pairs
    # 2. Un-interleave the row and col streams
    # 3. Re-pair to get PT coordinates
    # 4. Convert back to letters

    if period is None:
        period = len(ct98)

    pt = []
    for block_start in range(0, len(ct98), period):
        block = ct98[block_start:block_start + period]
        blen = len(block)

        # Convert to row/col
        rows_cols = []
        for v in block:
            if v not in square:
                return -1
            rows_cols.append(square[v])

        # Separate into rows and cols
        row_stream = [rc[0] for rc in rows_cols]
        col_stream = [rc[1] for rc in rows_cols]

        # In Bifid encryption, the combined stream was: all rows then all cols
        # of the PLAINTEXT, then re-paired to give CT
        # So to DECRYPT: the CT rows_cols when combined give:
        # combined = row_stream + col_stream (of the CT)
        # Wait, I need to think about this more carefully.
        #
        # Bifid ENCRYPTION:
        # 1. PT → (pt_rows, pt_cols) via Polybius
        # 2. combined = pt_rows + pt_cols
        # 3. Re-pair: ct_pairs = [(combined[0], combined[n]), (combined[1], combined[n+1]), ...]
        # 4. CT = Polybius_inv(ct_pairs)
        #
        # Bifid DECRYPTION:
        # 1. CT → (ct_rows, ct_cols) via Polybius
        # 2. These ct pairs came from re-pairing, so:
        #    combined[i] = ct_rows[i], combined[n+i] = ct_cols[i]
        # 3. combined = ct_rows + ct_cols
        # 4. Split: pt_rows = combined[:n], pt_cols = combined[n:]
        # 5. PT = Polybius_inv(zip(pt_rows, pt_cols))

        combined = row_stream + col_stream
        half = blen
        pt_rows = combined[:half]
        pt_cols = combined[half:]

        if len(pt_rows) != len(pt_cols):
            return -1

        for pr, pc in zip(pt_rows, pt_cols):
            if (pr, pc) in inv_square:
                pt.append(inv_square[(pr, pc)])
            else:
                return -1

    # Score against cribs
    score = 0
    for pos in CRIB_POS:
        if pos < len(pt) and pt[pos] == CRIB_PT[pos]:
            score += 1

    return score


def analyze_bifid():
    """Test Bifid cipher on 98-char candidates."""
    print("\n" + "=" * 72)
    print("ANALYSIS 3: BIFID CIPHER (98 = even, no padding needed)")
    print("=" * 72)

    # Standard Polybius squares to try
    std = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # standard (no J)
    kryptos_bifid = ""
    seen = set()
    for ch in KRYPTOS_ALPHABET:
        if ch == 'J':
            continue
        if ch not in seen:
            kryptos_bifid += ch
            seen.add(ch)
    # Pad if needed
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            kryptos_bifid += ch
            seen.add(ch)

    polybius_keys = [
        ("standard", std),
        ("kryptos", kryptos_bifid[:25]),
    ]

    # Bifid periods to test
    bifid_periods = [None, 5, 7, 10, 14, 49, 98]

    best_score = 0
    best_cfg = None

    for ip in INSERT_RANGE:
        for lv in range(26):
            ct98 = list(CT_NUM)
            ct98.insert(ip, lv)

            for pname, pkey in polybius_keys:
                for bp in bifid_periods:
                    sc = bifid_encrypt_check(ct98, pkey, bp)
                    if sc > best_score:
                        best_score = sc
                        best_cfg = dict(pos=ip, letter=chr(lv+65),
                                        polybius=pname,
                                        bifid_period=bp, score=sc)

    print(f"  Bifid best: {best_score}/24")
    if best_cfg:
        print(f"  Config: {best_cfg}")
    print(f"  Expected random: ~{24/26:.1f}/24")

    return best_score


# ── Analysis 4: Double columnar transposition (pruned) ─────────────────

def analyze_double_columnar():
    """Test double width-7 columnar transposition with algebraic pruning.

    The idea: apply two successive width-7 columnar transpositions.
    Combined permutation is the composition of two columnar permutations.
    Total: 5040^2 = 25.4M pairs, × 650 insertions = too many.

    Pruning: first transposition is arbitrary (5040 options).
    For each, compute the intermediate text. Then check if the intermediate
    text can be columnar-transposed to produce a period-7 consistent key.
    This second check is the same as phase 4 but on intermediate text.

    Optimization: for the first transposition T1, compute intermediate = T1_inv(CT98).
    Then for the second transposition T2: final = T2_inv(intermediate).
    Key at crib positions: K[pt_pos] = (final[pt_pos] - PT[pt_pos]) mod 26.
    But final[pt_pos] = intermediate[T2_inv_perm[pt_pos]].

    For period 7: key[pt_pos mod 7] must be consistent.
    """
    print("\n" + "=" * 72)
    print("ANALYSIS 4: DOUBLE WIDTH-7 COLUMNAR TRANSPOSITION")
    print("=" * 72)

    def build_col_perm(col_order):
        """Width-7 columnar: fill by rows, read by columns in order."""
        perm = []
        for rank in range(WIDTH):
            ci = col_order.index(rank)
            for row in range(GRID_LEN // WIDTH):
                perm.append(row * WIDTH + ci)
        return perm

    def invert(perm):
        inv = [0] * len(perm)
        for i, p in enumerate(perm):
            inv[p] = i
        return inv

    # Precompute all 5040 columnar permutations
    all_col_perms = []
    for co in permutations(range(WIDTH)):
        perm = build_col_perm(list(co))
        all_col_perms.append((list(co), perm, invert(perm)))

    print(f"  Permutations: {len(all_col_perms)} × {len(all_col_perms)} = "
          f"{len(all_col_perms)**2:,}")
    print(f"  Candidates: 650")
    print(f"  With pruning, testing outer loop only ({len(all_col_perms)} × 650)")

    best_score = 0
    best_cfg = None
    total_inner = 0
    t0 = time.time()

    for ip in INSERT_RANGE:
        for lv in range(26):
            ct98 = list(CT_NUM)
            ct98.insert(ip, lv)

            # For each first transposition T1:
            for co1, perm1, inv1 in all_col_perms:
                # Undo T1: intermediate[j] = ct98[inv1[j]]
                intermediate = [ct98[inv1[j]] for j in range(GRID_LEN)]

                # Now need second transposition T2 such that
                # final[pt_pos] = intermediate[T2_inv[pt_pos]]
                # and K[pt_pos mod 7] = (final[pt_pos] - PT[pt_pos]) mod 26 is consistent

                # For each crib pt_pos, we need T2_inv[pt_pos], which depends on T2.
                # But T2_inv[pt_pos] = where pt_pos maps under the inverse of T2.
                #
                # For columnar T2 with order co2:
                # T2_perm[i] maps: position in column-read order to position in row order
                # T2_inv[pt_pos] = the column-read position that corresponds to row position pt_pos
                #
                # For a 7×14 grid: pt_pos = row*7 + col
                # T2 reads columns in order co2. Column ci (where co2[ci]=rank) is read at
                # positions rank*14 + 0..13. So T2_perm[rank*14 + r] = r*7 + ci.
                # T2_inv[r*7 + ci] = rank*14 + r = co2[ci]*14 + r.
                #
                # So T2_inv[pt_pos] = co2[pt_pos % 7] * 14 + pt_pos // 7

                # For period-7 key consistency:
                # K[pt_pos % 7] = (intermediate[co2[pt_pos%7]*14 + pt_pos//7] - PT[pt_pos]) mod 26
                #
                # Group by pt_pos%7 = c:
                #   K[c] = (intermediate[co2[c]*14 + r] - PT[r*7+c]) mod 26
                #   for each crib at (r, c)
                #
                # For a given c, co2[c] determines which column of intermediate is used.
                # There are 7 choices for co2[c] (0-6).
                # For each choice, we get a set of key values from the cribs in column c.
                # If all agree, that choice works.

                # Algebraic pruning: for each column c, try all 7 possible source columns
                feasible_by_col = {}
                for c in range(WIDTH):
                    cribs_in_col = [(p, CRIB_PT[p]) for p in CRIB_POS if p % WIDTH == c]
                    if not cribs_in_col:
                        feasible_by_col[c] = list(range(7))  # any source column works
                        continue

                    valid_sources = []
                    for src in range(WIDTH):
                        # Key values for this source column
                        kvs = set()
                        for pt_pos, pt_val in cribs_in_col:
                            r = pt_pos // WIDTH
                            idx = src * (GRID_LEN // WIDTH) + r
                            if idx >= GRID_LEN:
                                break
                            kv = (intermediate[idx] - pt_val) % MOD
                            kvs.add(kv)
                        if len(kvs) == 1:
                            valid_sources.append(src)

                    feasible_by_col[c] = valid_sources
                    if not valid_sources:
                        break

                if any(not v for v in feasible_by_col.values()):
                    continue

                total_inner += 1

                # Check if there's a valid assignment (all source columns distinct)
                # This is a constraint satisfaction problem
                # With 7 columns and typically 0-2 valid sources each, this is fast
                def find_assignment(col_idx, used, assignment):
                    if col_idx == WIDTH:
                        return assignment.copy()
                    for src in feasible_by_col[col_idx]:
                        if src not in used:
                            assignment[col_idx] = src
                            used.add(src)
                            result = find_assignment(col_idx + 1, used, assignment)
                            if result is not None:
                                return result
                            used.remove(src)
                    return None

                assignment = find_assignment(0, set(), {})
                if assignment is not None:
                    # We found a valid double transposition!
                    # Compute actual key and score
                    co2 = [0] * WIDTH
                    for c, src in assignment.items():
                        co2[c] = src
                    # Verify
                    score = 0
                    key = {}
                    for pt_pos in CRIB_POS:
                        c = pt_pos % WIDTH
                        r = pt_pos // WIDTH
                        idx = co2[c] * (GRID_LEN // WIDTH) + r
                        kv = (intermediate[idx] - CRIB_PT[pt_pos]) % MOD
                        residue = c
                        if residue not in key:
                            key[residue] = kv
                        if key[residue] == kv:
                            score += 1

                    if score > best_score:
                        best_score = score
                        best_cfg = dict(
                            co1=co1, co2=co2, insert_pos=ip,
                            letter=chr(lv+65), score=score, key=key,
                        )
                        print(f"  *** [{score}/24] co1={co1} co2={co2} "
                              f"ins='{chr(lv+65)}'@{ip} key={key}")

    elapsed = time.time() - t0
    print(f"\n  Completed: {elapsed:.1f}s")
    print(f"  Inner feasible checks: {total_inner:,}")
    print(f"  Best: {best_score}/24")
    if best_cfg:
        print(f"  Config: {best_cfg}")

    return best_score, best_cfg


# ── Analysis 5: Comprehensive period sweep (no transposition) ──────────

def analyze_all_periods():
    """Check period consistency for all periods 2-49 on 98-char candidates."""
    print("\n" + "=" * 72)
    print("ANALYSIS 5: ALL PERIODS 2-49 (no transposition, Vig + Beaufort)")
    print("=" * 72)

    periods = list(range(2, 50))
    best_by_period = {}  # period -> (score, config)

    for period in periods:
        best_s = 0
        best_c = None

        # Expected random for this period
        groups = defaultdict(int)
        for p in CRIB_POS:
            groups[p % period] += 1
        exp_random = sum(1 + n * (n - 1) / (2 * 26) for n in groups.values())

        for ip in INSERT_RANGE:
            for lv in range(26):
                ct98 = list(CT_NUM)
                ct98.insert(ip, lv)

                for variant in ['vig', 'beau']:
                    key_by_res = defaultdict(list)
                    for pt_pos in CRIB_POS:
                        cv = ct98[pt_pos]
                        pv = CRIB_PT[pt_pos]
                        if variant == 'vig':
                            kv = (cv - pv) % MOD
                        else:
                            kv = (cv + pv) % MOD
                        key_by_res[pt_pos % period].append(kv)

                    score = 0
                    for vals in key_by_res.values():
                        counts = Counter(vals)
                        score += max(counts.values())

                    if score > best_s:
                        best_s = score
                        best_c = dict(pos=ip, letter=chr(lv+65), variant=variant)

        excess = best_s - exp_random
        best_by_period[period] = (best_s, exp_random, excess, best_c)

    print(f"\n  {'Period':>6} {'Best':>5} {'ExpRand':>8} {'Excess':>7} Config")
    print(f"  {'-'*6} {'-'*5} {'-'*8} {'-'*7} {'-'*30}")
    for period in sorted(best_by_period.keys()):
        s, e, ex, c = best_by_period[period]
        marker = " ***" if ex > 5 else ""
        cfg_str = f"ins='{c['letter']}'@{c['pos']} {c['variant']}" if c else ""
        print(f"  {period:6d} {s:5d} {e:8.1f} {ex:+7.1f} {cfg_str}{marker}")

    # Highlight any significant results
    significant = [(p, s, e, ex, c) for p, (s, e, ex, c) in best_by_period.items()
                    if ex > 5]
    if significant:
        print(f"\n  SIGNIFICANT (excess > 5): {len(significant)}")
        for p, s, e, ex, c in significant:
            print(f"    Period {p}: {s}/24 (exp={e:.1f}, excess={ex:.1f})")
    else:
        print(f"\n  No significant periods (all excess ≤ 5)")

    return best_by_period


# ══════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("E-S-04: Missing Character — Structural Analysis")
    print(f"CT: {CT} (len={CT_LEN})")
    print(f"Insert range: {INSERT_RANGE[0]}-{INSERT_RANGE[-1]} ({len(INSERT_RANGE)} positions)")
    t_start = time.time()

    # Analysis 1: IC and autocorrelation
    ic_cfg, z7_cfg = analyze_ic_and_autocorrelation()

    # Analysis 2: Period-7 Vigenère
    p7_best = analyze_period7_direct()

    # Analysis 3: Bifid
    bifid_best = analyze_bifid()

    # Analysis 4: Double columnar
    dc_best, dc_cfg = analyze_double_columnar()

    # Analysis 5: All periods
    period_results = analyze_all_periods()

    total_t = time.time() - t_start

    print("\n" + "=" * 72)
    print("FINAL SUMMARY")
    print("=" * 72)
    print(f"  IC/autocorrelation: analyzed (see above)")
    print(f"  Period-7 direct:    best = {p7_best}/24")
    print(f"  Bifid cipher:       best = {bifid_best}/24")
    print(f"  Double columnar:    best = {dc_best}/24")
    print(f"  Total time: {total_t:.1f}s")

    # Save
    summary = {
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'total_seconds': total_t,
        'insert_range': [INSERT_RANGE[0], INSERT_RANGE[-1]],
        'period7_direct_best': p7_best,
        'bifid_best': bifid_best,
        'double_columnar_best': dc_best,
        'double_columnar_config': dc_cfg,
    }
    out = os.path.join(os.path.dirname(__file__), '..', 'results',
                       'e_s_04_missing_char_structural.json')
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nSaved to {out}")
