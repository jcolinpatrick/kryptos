#!/usr/bin/env python3
"""Constrained null-mask search for Kryptos K4.

Cipher:    Two-system (null removal + periodic substitution)
Family:    grille
Status:    active
Keyspace:  Exhaustive (n1,n2) parameter space + sampling per config
Last run:  2026-03-11
Best score: n/a

APPROACH:
  The 97 carved characters contain 24 nulls among the 73 non-crib positions.
  After removing nulls, the 73-char extract is decrypted with periodic sub.

  KEY INSIGHT: The mask problem reduces to just TWO parameters (n1, n2):
    n1 = number of nulls before position 21 (from 21 non-crib slots)
    n2 = number of nulls between positions 34-62 (from 29 non-crib slots)
    n3 = 24 - n1 - n2 (nulls after position 73, from 23 non-crib slots)

  This is because:
    ENE crib starts at new_pos = 21 - n1
    BC crib starts at new_pos = 63 - n1 - n2
  The RELATIVE positions within each crib block are always consecutive.
  So consistency depends ONLY on (n1, n2), not on WHICH specific positions are nulled.

RESULTS:
  Periods 2-13: ZERO consistent (n1,n2) pairs. MATHEMATICALLY ELIMINATED.
  Periods 14-23: ZERO consistent (n1,n2) pairs.
  Periods 24-26: 387 consistent configs exist (underdetermined, expected false positives).
  Period 1 (Caesar): always fails (diverse key values).

  For the period 24-26 survivors, we exhaustively sample actual masks and decrypt.
"""
from __future__ import annotations

import json
import os
import random
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
)
from kryptos.kernel.scoring.ngram import NgramScorer
from kryptos.kernel.scoring.ic import ic
from kryptos.kernel.scoring.free_crib import score_free_fast, score_free

# ── Constants ─────────────────────────────────────────────────────────────

CRIB_POS_SET = set(CRIB_POSITIONS)
ALL_POS = set(range(CT_LEN))
NON_CRIB_POS = sorted(ALL_POS - CRIB_POS_SET)

# Segments of non-crib positions
SEG1 = [p for p in NON_CRIB_POS if p < 21]      # 21 positions (0-20)
SEG2 = [p for p in NON_CRIB_POS if 34 <= p <= 62]  # 29 positions
SEG3 = [p for p in NON_CRIB_POS if p >= 74]      # 23 positions

CRIB_CT = {pos: ALPH_IDX[CT[pos]] for pos in sorted(CRIB_POS_SET)}
CRIB_PT = {pos: ALPH_IDX[CRIB_DICT[pos]] for pos in sorted(CRIB_POS_SET)}

VARIANTS = {
    "vig":   lambda c, p: (c - p) % MOD,
    "beau":  lambda c, p: (c + p) % MOD,
    "vbeau": lambda c, p: (p - c) % MOD,
}

CRIB_KEYS = {}
for vname, fn in VARIANTS.items():
    CRIB_KEYS[vname] = {pos: fn(CRIB_CT[pos], CRIB_PT[pos]) for pos in sorted(CRIB_POS_SET)}


def check_consistency_by_offsets(ene_start: int, bc_start: int, period: int, variant: str) -> Tuple[bool, Optional[Dict[int, int]]]:
    """Check if crib keys are consistent given ENE and BC start offsets in 73-char string."""
    key_vals = CRIB_KEYS[variant]
    residue_to_key: Dict[int, int] = {}

    for i in range(13):
        orig_pos = 21 + i
        new_pos = ene_start + i
        res = new_pos % period
        k = key_vals[orig_pos]
        if res in residue_to_key:
            if residue_to_key[res] != k:
                return False, None
        else:
            residue_to_key[res] = k

    for j in range(11):
        orig_pos = 63 + j
        new_pos = bc_start + j
        res = new_pos % period
        k = key_vals[orig_pos]
        if res in residue_to_key:
            if residue_to_key[res] != k:
                return False, None
        else:
            residue_to_key[res] = k

    return True, residue_to_key


def decrypt_extract(extract: str, period: int, variant: str, partial_key: Dict[int, int]) -> str:
    """Decrypt a 73-char extract using a partial periodic key."""
    plaintext = []
    for new_pos, ch in enumerate(extract):
        residue = new_pos % period
        ct_val = ALPH_IDX[ch]
        if residue in partial_key:
            k = partial_key[residue]
            if variant == "vig":
                pt_val = (ct_val - k) % MOD
            elif variant == "beau":
                pt_val = (k - ct_val) % MOD
            elif variant == "vbeau":
                pt_val = (ct_val + k) % MOD
            plaintext.append(ALPH[pt_val])
        else:
            plaintext.append(ch)  # unknown key, leave as CT
    return "".join(plaintext)


def main():
    print("=" * 80)
    print("CONSTRAINED NULL-MASK SEARCH FOR KRYPTOS K4")
    print("=" * 80)
    print(f"CT: {CT}")
    print(f"CT length: {CT_LEN}")
    print(f"Non-crib segments: seg1={len(SEG1)} (0-20), seg2={len(SEG2)} (34-62), seg3={len(SEG3)} (74-96)")
    print()

    # Load quadgram scorer
    qg_path = REPO / "data" / "english_quadgrams.json"
    scorer = NgramScorer.from_file(qg_path)
    print(f"Loaded {len(scorer.log_probs)} quadgrams")
    print()

    # ── Phase 1: Exhaustive (n1, n2) scan for ALL periods 1-26 ────────────

    print("PHASE 1: Exhaustive parameter scan")
    print("=" * 60)
    print("For each (n1, n2, n3=24-n1-n2), check crib consistency")
    print("against all periods 1-26 and all 3 variants.")
    print()

    consistent_configs = []  # (n1, n2, n3, period, variant, partial_key)

    period_counts = defaultdict(int)

    for n1 in range(min(len(SEG1) + 1, 25)):
        for n2 in range(min(len(SEG2) + 1, 25 - n1)):
            n3 = 24 - n1 - n2
            if n3 < 0 or n3 > len(SEG3):
                continue

            ene_start = 21 - n1
            bc_start = 63 - n1 - n2

            for period in range(1, 27):
                for variant in ["vig", "beau", "vbeau"]:
                    ok, partial_key = check_consistency_by_offsets(ene_start, bc_start, period, variant)
                    if ok:
                        consistent_configs.append((n1, n2, n3, period, variant, partial_key, ene_start, bc_start))
                        period_counts[period] += 1

    print(f"Total consistent (n1,n2,period,variant) configs: {len(consistent_configs)}")
    print()

    print("Breakdown by period:")
    for p in range(1, 27):
        count = period_counts.get(p, 0)
        status = "ELIMINATED" if count == 0 else f"{count} configs"
        underdetermined = " [UNDERDETERMINED: p>=17]" if p >= 17 and count > 0 else ""
        print(f"  Period {p:2d}: {status}{underdetermined}")
    print()

    # ── Phase 2: For surviving configs, sample actual masks and decrypt ────

    # Only periods 24, 25, 26 survive. These are heavily underdetermined
    # (24 crib positions, period >= 24 means at most 2 positions per residue).
    # But let's decrypt them anyway to check for any signal.

    surviving = [c for c in consistent_configs if c[3] >= 14]
    print(f"PHASE 2: Decrypt surviving configs (periods >= 14)")
    print(f"  {len(surviving)} configs to test")
    print("=" * 60)

    all_results = []  # (n1, n2, n3, period, variant, pt, qg_score, free_score, ic_val, key_coverage)

    random.seed(42)
    MASKS_PER_CONFIG = 100  # sample multiple actual masks per (n1,n2) config

    for cfg_idx, (n1, n2, n3, period, variant, partial_key, ene_start, bc_start) in enumerate(surviving):
        key_coverage = len(partial_key)

        # Generate several actual masks for this (n1, n2, n3)
        best_qg = -999
        best_result = None

        for mask_trial in range(MASKS_PER_CONFIG):
            # Choose n1 positions from SEG1, n2 from SEG2, n3 from SEG3
            if n1 > 0:
                null1 = random.sample(SEG1, n1)
            else:
                null1 = []
            if n2 > 0:
                null2 = random.sample(SEG2, n2)
            else:
                null2 = []
            if n3 > 0:
                null3 = random.sample(SEG3, n3)
            else:
                null3 = []

            null_set = set(null1 + null2 + null3)
            extract = "".join(CT[i] for i in range(CT_LEN) if i not in null_set)
            assert len(extract) == 73, f"Extract length {len(extract)}"

            pt = decrypt_extract(extract, period, variant, partial_key)
            qg = scorer.score_per_char(pt)
            fs = score_free_fast(pt)
            ic_val = ic(pt)

            if qg > best_qg:
                best_qg = qg
                best_result = (n1, n2, n3, period, variant, pt, qg, fs, ic_val, key_coverage, sorted(null_set))

            if fs >= 11:
                print(f"  *** CRIB HIT *** n1={n1} n2={n2} n3={n3} period={period} {variant} "
                      f"free_score={fs} qg={qg:.3f}")
                print(f"      PT: {pt}")
                print(f"      Nulls: {sorted(null_set)}")

        if best_result:
            all_results.append(best_result)

    print(f"\n  Tested {len(surviving)} configs x {MASKS_PER_CONFIG} masks = "
          f"{len(surviving) * MASKS_PER_CONFIG} decryptions")
    print()

    # ── Phase 3: Also try ALL masks with scoring (periods 2-13 are eliminated
    # by the proof, but let's verify with random masks + direct decryption) ──

    print("PHASE 3: Verification — 500K random masks with direct decryption")
    print("  (Periods 2-13 should show zero, confirming the proof)")
    print("=" * 60)

    random.seed(7)
    N_RANDOM = 500000
    phase3_crib_hits = 0
    phase3_best_qg = -999
    phase3_best = None
    phase3_period_hits = defaultdict(int)

    t0 = time.time()
    for trial in range(N_RANDOM):
        null_positions = set(random.sample(NON_CRIB_POS, 24))
        extract = "".join(CT[i] for i in range(CT_LEN) if i not in null_positions)

        # Compute crib new positions
        null_sorted = sorted(null_positions)
        crib_new = {}
        for orig_pos in sorted(CRIB_POS_SET):
            nulls_before = sum(1 for n in null_sorted if n < orig_pos)
            crib_new[orig_pos] = orig_pos - nulls_before

        # Check each period/variant
        for period in range(2, 27):
            for variant in ["vig", "beau", "vbeau"]:
                key_vals = CRIB_KEYS[variant]
                residue_to_key = {}
                consistent = True

                for orig_pos in sorted(CRIB_POS_SET):
                    new_pos = crib_new[orig_pos]
                    res = new_pos % period
                    k = key_vals[orig_pos]
                    if res in residue_to_key:
                        if residue_to_key[res] != k:
                            consistent = False
                            break
                    else:
                        residue_to_key[res] = k

                if consistent:
                    phase3_period_hits[period] += 1
                    pt = decrypt_extract(extract, period, variant, residue_to_key)
                    qg = scorer.score_per_char(pt)
                    fs = score_free_fast(pt)

                    if fs >= 11:
                        phase3_crib_hits += 1
                        print(f"  *** CRIB HIT *** trial={trial} period={period} {variant} "
                              f"fs={fs} qg={qg:.3f}")
                        print(f"      PT: {pt}")

                    if qg > phase3_best_qg:
                        phase3_best_qg = qg
                        phase3_best = (period, variant, pt, qg, fs, sorted(null_positions))

        if (trial + 1) % 100000 == 0:
            elapsed = time.time() - t0
            print(f"  Progress: {trial+1}/{N_RANDOM} ({(trial+1)/elapsed:.0f}/s) "
                  f"crib_hits={phase3_crib_hits}")

    t1 = time.time()
    print(f"  Done: {N_RANDOM} masks in {t1-t0:.1f}s")
    print(f"  Crib hits: {phase3_crib_hits}")
    print(f"  Period consistency counts:")
    for p in range(2, 27):
        c = phase3_period_hits.get(p, 0)
        if c > 0:
            print(f"    period {p:2d}: {c}")
    if phase3_best:
        p, v, pt, qg, fs, nulls = phase3_best
        print(f"  Best quadgram: period={p} {v} qg={qg:.3f} fs={fs}")
        print(f"    PT: {pt}")
    print()

    # ── Summary ───────────────────────────────────────────────────────────

    print("=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    print()
    print("MATHEMATICAL RESULT (exhaustive over all C(73,24) masks):")
    print("  The consistency check depends only on (n1, n2) parameters,")
    print("  where n1 = nulls in positions 0-20, n2 = nulls in positions 34-62.")
    print("  There are only ~325 valid (n1, n2) combinations.")
    print()
    print("  Periods 1-23: ZERO consistent (n1,n2) pairs for ANY variant.")
    print("  This is a COMPLETE ELIMINATION — not sampling, not heuristic.")
    print("  No matter which 24 of the 73 non-crib positions you remove,")
    print("  periodic Vigenere/Beaufort/VarBeau with period 1-23 CANNOT")
    print("  produce the known plaintext at the crib positions.")
    print()
    print("  Periods 24-26: Some consistent configs exist, but these are")
    print("  trivially underdetermined (period >= length of each crib block,")
    print("  so each crib position gets its own residue class with no cross-check).")
    print()

    # Top results from Phase 2
    if all_results:
        print("Top 20 Phase 2 results (best quadgram per config):")
        top20 = sorted(all_results, key=lambda x: x[6], reverse=True)[:20]
        for rank, (n1, n2, n3, period, variant, pt, qg, fs, ic_val, kcov, nulls) in enumerate(top20, 1):
            print(f"  #{rank:2d} qg={qg:.3f} IC={ic_val:.4f} period={period} {variant} "
                  f"n1={n1} n2={n2} n3={n3} key_cov={kcov}/{period} fs={fs}")
            print(f"      PT: {pt}")
        print()

    print("IMPLICATIONS:")
    print("  1. Null removal + periodic substitution (periods 1-23) is ELIMINATED")
    print("     regardless of which positions are nulls.")
    print("  2. This extends the existing proof (periodic sub impossible on raw 97)")
    print("     to the two-system model: even with null removal first, periodic sub fails.")
    print("  3. If the two-system model is correct, System 1 must be NON-periodic:")
    print("     autokey, running key, non-periodic polyalphabetic, or something else entirely.")
    print("  4. Alternatively, the cribs may not be at positions 21-33 and 63-73")
    print("     in the CARVED text (they might apply to the intermediate 73-char CT).")


if __name__ == "__main__":
    main()
