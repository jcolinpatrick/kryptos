#!/usr/bin/env python3
"""E-NSA-02: Missing character insertion sweep.

Based on NSA DOCID:4145037 — the NSA analyst's own hypothesis:
"Could there possibly be a missing letter in the remaining section
which is presently making it impossible to find a solution?"

Precedent: K2 had one missing 'S', changing "ID BY ROWS" to "LAYER TWO".

Hypothesis: K4's true ciphertext is 98 characters. One character was
omitted during engraving. We test all 26 × 98 = 2,548 insertions.

For each candidate 98-char CT:
  1. Compute Vig/Beaufort key at crib positions (21-33, 63-73)
  2. Check Bean equality: k[27] == k[65]
  3. Check periodic key consistency for periods 2-24
  4. Score = number of crib positions consistent with best period

Convention: 0-indexed positions throughout.
The cribs (EASTNORTHEAST at 21-33, BERLINCLOCK at 63-73) are based on
the TRUE (intended) 98-char ciphertext, not the engraved 97-char version.
"""
import sys
import os
import json
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, MOD,
    CRIB_DICT, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD, BREAKTHROUGH_THRESHOLD,
)

# ── Constants ────────────────────────────────────────────────────────────

CT_NUM = [ord(c) - 65 for c in CT]
CRIB_PT_NUM = {pos: ord(ch) - 65 for pos, ch in CRIB_DICT.items()}
ALL_CRIB_POS = sorted(CRIB_PT_NUM.keys())  # 24 positions: 21-33, 63-73
ENE_POS = list(range(21, 34))
BC_POS = list(range(63, 74))

# ── Scoring ──────────────────────────────────────────────────────────────

def recover_keys(ct98_num, variant):
    """Recover key at all 24 crib positions (0-indexed in 98-char CT)."""
    keys = {}
    for pos in ALL_CRIB_POS:
        if pos >= len(ct98_num):
            continue
        c = ct98_num[pos]
        p = CRIB_PT_NUM[pos]
        if variant == 'vig':
            keys[pos] = (c - p) % MOD
        elif variant == 'beau':
            keys[pos] = (c + p) % MOD
        elif variant == 'varbeau':
            keys[pos] = (p - c) % MOD
    return keys

def bean_check(kv):
    return kv.get(27) == kv.get(65)

def period_consistency(kv, period):
    groups = defaultdict(list)
    for pos, k in kv.items():
        groups[pos % period].append(k)
    consistent = 0
    for vals in groups.values():
        counts = defaultdict(int)
        for v in vals:
            counts[v] += 1
        consistent += max(counts.values())
    return consistent

def best_period_score(kv, periods=range(2, 25)):
    """Return (best_score, best_period) across all tested periods."""
    best_s, best_p = 0, 0
    for p in periods:
        s = period_consistency(kv, p)
        if s > best_s:
            best_s, best_p = s, p
    return best_s, best_p

# ── Main sweep ───────────────────────────────────────────────────────────

def run_insertion_sweep():
    """Test all 2548 single-character insertions."""
    print("=" * 72)
    print("E-NSA-02: MISSING CHARACTER INSERTION SWEEP")
    print("=" * 72)
    print(f"Original CT length: {CT_LEN}")
    print(f"Testing: 26 letters × 98 insertion positions = 2,548 candidates")
    print(f"Cribs at positions 21-33 (ENE) and 63-73 (BC) in the 98-char CT")

    variants = ['vig', 'beau', 'varbeau']
    best_overall = 0
    best_config = None
    hits = []
    bean_passes = 0
    total = 0

    for insert_pos in range(98):
        for letter_val in range(26):
            # Build 98-char candidate CT
            ct98 = list(CT_NUM)
            ct98.insert(insert_pos, letter_val)

            total += 1
            for variant in variants:
                kv = recover_keys(ct98, variant)
                if len(kv) < N_CRIBS:
                    continue  # insertion pushed a crib position off the end

                bean_ok = bean_check(kv)
                if bean_ok:
                    bean_passes += 1

                best_s, best_p = best_period_score(kv)

                if best_s > best_overall:
                    best_overall = best_s
                    best_config = {
                        'insert_pos': insert_pos,
                        'letter': chr(letter_val + 65),
                        'variant': variant,
                        'period': best_p,
                        'score': best_s,
                        'bean': bean_ok,
                    }

                if best_s >= STORE_THRESHOLD:
                    hits.append({
                        'pos': insert_pos,
                        'letter': chr(letter_val + 65),
                        'var': variant,
                        'period': best_p,
                        'score': best_s,
                        'bean': bean_ok,
                    })
                    if best_s >= SIGNAL_THRESHOLD:
                        print(f"  *** [{best_s:2d}/24] p={best_p:2d}"
                              f" ins='{chr(letter_val+65)}'@{insert_pos}"
                              f" {variant} Bean={'Y' if bean_ok else 'N'}")

        # Progress
        if (insert_pos + 1) % 20 == 0:
            print(f"  ... {insert_pos+1}/98 positions done, best so far: {best_overall}/24")

    return total, best_overall, best_config, hits, bean_passes

def run_insertion_with_transposition():
    """Phase 2: For top insertion candidates, also try width-7 transposition."""
    print("\n" + "=" * 72)
    print("PHASE 2: TOP INSERTION CANDIDATES + WIDTH-7 TRANSPOSITION")
    print("=" * 72)

    from itertools import permutations as perms

    # First pass: find insertions where Bean holds under Vigenere
    bean_candidates = []
    for insert_pos in range(98):
        for letter_val in range(26):
            ct98 = list(CT_NUM)
            ct98.insert(insert_pos, letter_val)
            kv = recover_keys(ct98, 'vig')
            if len(kv) == N_CRIBS and bean_check(kv):
                bean_candidates.append((insert_pos, letter_val, ct98))

    print(f"  Bean-passing insertions (Vig): {len(bean_candidates)}")

    # For each Bean-passing insertion, try K3-style width-7 transposition
    # (limited: only KRYPTOS and NSA key orders, both directions)
    kryptos_co = _kryptos_key()
    nsa_co = _nsa_key()
    key_orders = [kryptos_co, nsa_co]

    best = 0
    for insert_pos, letter_val, ct98 in bean_candidates:
        for co in key_orders:
            perm = _columnar_perm_98(7, co, 98)
            inv = _invert(perm)
            for transform in [inv, perm]:
                ct_t = [ct98[p] for p in transform]
                for variant in ['vig', 'beau', 'varbeau']:
                    kv = recover_keys(ct_t, variant)
                    if len(kv) < N_CRIBS:
                        continue
                    for period in range(2, 25):
                        score = period_consistency(kv, period)
                        if score > best:
                            best = score
                        if score >= SIGNAL_THRESHOLD:
                            print(f"  *** [{score:2d}/24] p={period:2d}"
                                  f" ins='{chr(letter_val+65)}'@{insert_pos}"
                                  f" width-7 {variant}")

    print(f"  Insertion+transposition best: {best}/24")
    return best

def _kryptos_key():
    kw = "KRYPTOS"
    indexed = [(ch, i) for i, ch in enumerate(kw)]
    ranked = sorted(indexed)
    order = [0] * 7
    for rank, (_, pos) in enumerate(ranked):
        order[pos] = rank
    return tuple(order)

def _nsa_key():
    read_0 = [3, 0, 4, 1, 5, 2, 6]
    co = [0] * 7
    for rank, col in enumerate(read_0):
        co[col] = rank
    return tuple(co)

def _columnar_perm_98(width, col_order, length):
    cols = defaultdict(list)
    for pos in range(length):
        _, c = divmod(pos, width)
        cols[c].append(pos)
    perm = []
    for rank in range(width):
        col_idx = list(col_order).index(rank)
        perm.extend(cols[col_idx])
    return perm

def _invert(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

# ── Also test: deletion instead of insertion ──

def run_deletion_sweep():
    """What if the true CT is 96 chars (one EXTRA char was added)?"""
    print("\n" + "=" * 72)
    print("BONUS: DELETION SWEEP (true CT = 96 chars, one extra in engraved)")
    print("=" * 72)

    variants = ['vig', 'beau', 'varbeau']
    best_overall = 0
    hits = []

    for del_pos in range(97):
        ct96 = CT_NUM[:del_pos] + CT_NUM[del_pos+1:]

        # Cribs need adjustment: if del_pos <= crib_start, shift crib positions
        # But Sanborn designed cribs for the TRUE CT. If true CT is 96 chars,
        # then cribs are at positions relative to 96-char CT.
        # Our known cribs (21-33, 63-73) might be for the 97-char version.
        # We try BOTH: cribs at original positions (shifted down by 1 if del > pos)
        # and cribs at same absolute positions in 96-char CT.

        for variant in variants:
            # Approach: cribs at 21-33, 63-73 in the 96-char CT
            kv = {}
            for pos in ALL_CRIB_POS:
                if pos < len(ct96):
                    c = ct96[pos]
                    p = CRIB_PT_NUM[pos]
                    if variant == 'vig':
                        kv[pos] = (c - p) % MOD
                    elif variant == 'beau':
                        kv[pos] = (c + p) % MOD
                    elif variant == 'varbeau':
                        kv[pos] = (p - c) % MOD

            if len(kv) >= N_CRIBS - 1:
                bean_ok = kv.get(27) == kv.get(65) if 27 in kv and 65 in kv else False
                best_s, best_p = best_period_score(kv)
                if best_s > best_overall:
                    best_overall = best_s
                if best_s >= STORE_THRESHOLD:
                    hits.append({
                        'del_pos': del_pos, 'var': variant,
                        'period': best_p, 'score': best_s, 'bean': bean_ok,
                    })
                    if best_s >= SIGNAL_THRESHOLD:
                        print(f"  *** [{best_s:2d}/24] p={best_p:2d}"
                              f" del@{del_pos} {variant} Bean={'Y' if bean_ok else 'N'}")

    print(f"Deletion sweep best: {best_overall}/24, hits≥{STORE_THRESHOLD}: {len(hits)}")
    return best_overall, hits

# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    t0 = datetime.now()
    print(f"Started: {t0.isoformat()}")
    print(f"CT: {CT}")

    # Phase 1: Pure insertion sweep
    total, best, best_cfg, hits, bean_ct = run_insertion_sweep()

    # Phase 1b: Deletion sweep
    del_best, del_hits = run_deletion_sweep()

    # Phase 2: Top candidates + transposition
    trans_best = run_insertion_with_transposition()

    t1 = datetime.now()
    elapsed = (t1 - t0).total_seconds()

    overall = max(best, del_best, trans_best)

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"Insertion sweep: {total} candidates, best={best}/24")
    if best_cfg:
        print(f"  Best config: insert '{best_cfg['letter']}' at pos {best_cfg['insert_pos']},"
              f" {best_cfg['variant']} p={best_cfg['period']}, Bean={'Y' if best_cfg['bean'] else 'N'}")
    print(f"  Bean-passing candidates: {bean_ct}")
    print(f"  Hits ≥ {STORE_THRESHOLD}: {len(hits)}")
    print(f"Deletion sweep: best={del_best}/24, hits ≥ {STORE_THRESHOLD}: {len(del_hits)}")
    print(f"Insertion+transposition: best={trans_best}/24")
    print(f"Overall best: {overall}/24")

    if overall <= NOISE_FLOOR:
        print("\nCONCLUSION: Single-character insertion/deletion does NOT unlock K4")
        print("  with periodic Vigenère/Beaufort (periods 2-24).")
        print("ELIMINATED: Missing single character + periodic substitution.")
    elif overall >= SIGNAL_THRESHOLD:
        print(f"\nSIGNAL DETECTED at {overall}/24! Investigate further.")

    # Save
    summary = {
        'timestamp': t0.isoformat(),
        'elapsed_seconds': elapsed,
        'insertion_best': best,
        'insertion_best_config': best_cfg,
        'insertion_hits': len(hits),
        'insertion_bean_passes': bean_ct,
        'deletion_best': del_best,
        'deletion_hits': len(del_hits),
        'insertion_transposition_best': trans_best,
        'overall_best': overall,
    }
    out_path = os.path.join(os.path.dirname(__file__), '..', 'results', 'e_nsa_02_missing_char.json')
    with open(out_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"\nResults saved to {out_path}")
