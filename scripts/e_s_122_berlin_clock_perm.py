#!/usr/bin/env python3
"""E-S-122: Berlin Clock (Mengenlehreuhr) permutation tests for K4.

The Mengenlehreuhr displays time using 23 lamps:
  Row 1: 4 red lamps, each = 5 hours (0-4 lit)
  Row 2: 4 red/yellow lamps, each = 1 hour (0-4 lit)
  Row 3: 11 lamps (alt yellow/red), each = 5 minutes (0-11 lit)
  Row 4: 4 yellow lamps, each = 1 minute (0-4 lit)
  Top: 1 seconds blinker

Key historical times:
  23:30 — Berlin Wall opened (~11:30 PM, Nov 9, 1989)
  19:00 — Press conference by Schabowski (7 PM)
  00:00 — Midnight ("absence of light")

Hypothesis: lamp on/off pattern at a time generates a transposition permutation.

Stage 4 of Progressive Solve Plan.
"""
import json
import itertools
import os
import sys
import time as time_mod

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, NOISE_FLOOR,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.scoring.ic import ic


def berlin_clock_lamps(hours, minutes, seconds=0):
    """Generate Berlin Clock lamp pattern for given time.

    Returns list of 24 booleans:
      [0]: seconds blinker (on for even seconds)
      [1-4]: 5-hour row (4 lamps)
      [5-8]: 1-hour row (4 lamps)
      [9-19]: 5-minute row (11 lamps)
      [20-23]: 1-minute row (4 lamps)
    """
    lamps = [False] * 24

    # Seconds blinker
    lamps[0] = (seconds % 2 == 0)

    # 5-hour row
    five_hours = hours // 5
    for i in range(five_hours):
        lamps[1 + i] = True

    # 1-hour row
    one_hours = hours % 5
    for i in range(one_hours):
        lamps[5 + i] = True

    # 5-minute row
    five_mins = minutes // 5
    for i in range(five_mins):
        lamps[9 + i] = True

    # 1-minute row
    one_mins = minutes % 5
    for i in range(one_mins):
        lamps[20 + i] = True

    return lamps


def lamps_to_permutation(lamps, length):
    """Convert lamp pattern to a transposition permutation.

    Strategy: lit positions are read first, then unlit positions.
    For text longer than 24 lamps, extend pattern cyclically.
    """
    n_lamps = len(lamps)
    lit_positions = []
    unlit_positions = []

    for i in range(length):
        lamp_idx = i % n_lamps
        if lamps[lamp_idx]:
            lit_positions.append(i)
        else:
            unlit_positions.append(i)

    # Permutation: first read all lit positions, then unlit
    perm = lit_positions + unlit_positions
    return perm


def lamps_to_block_permutation(lamps, length):
    """Apply lamp pattern as block permutation on 24-char blocks.

    Within each 24-char block, lit positions come first, unlit second.
    """
    n_lamps = len(lamps)
    block_perm_lit = [i for i in range(n_lamps) if lamps[i]]
    block_perm_unlit = [i for i in range(n_lamps) if not lamps[i]]
    block_perm = block_perm_lit + block_perm_unlit

    # Build full permutation for text
    perm = []
    block_start = 0
    while block_start < length:
        block_end = min(block_start + n_lamps, length)
        block_size = block_end - block_start

        for p in block_perm:
            if p < block_size:
                perm.append(block_start + p)

        block_start += n_lamps

    return perm[:length]


def lamps_to_selection_mask(lamps, length):
    """Use lamps as a selection mask: extract chars at lit positions, then unlit.

    Different from permutation — this reorders based on cyclic lamp pattern.
    """
    lit_chars = []
    unlit_chars = []
    for i in range(length):
        if lamps[i % len(lamps)]:
            lit_chars.append(i)
        else:
            unlit_chars.append(i)
    return lit_chars + unlit_chars


def lamps_to_numeric_key(lamps):
    """Convert lamp pattern to numeric key.

    On=1, Off=0. Group into values.
    """
    # Binary to decimal in groups
    key = []
    binary_str = "".join("1" if l else "0" for l in lamps)

    # Various groupings
    keys = {}
    # As-is (24 binary values)
    keys["binary"] = [1 if l else 0 for l in lamps]

    # Groups of 4 → 6 values
    keys["nibbles"] = [int(binary_str[i:i+4], 2) for i in range(0, 24, 4)]

    # Groups of 3 → 8 values
    keys["triples"] = [int(binary_str[i:i+3], 2) for i in range(0, 24, 3)]

    # Count lit per row → key digits
    keys["row_counts"] = [
        int(lamps[0]),                                    # seconds
        sum(lamps[1:5]),                                  # 5h row
        sum(lamps[5:9]),                                  # 1h row
        sum(lamps[9:20]),                                 # 5m row
        sum(lamps[20:24]),                                # 1m row
    ]

    # Just the time digits
    return keys


def make_keyword_key(keyword):
    return [ALPH_IDX[c] for c in keyword.upper()]


def main():
    t0 = time_mod.time()
    print("=" * 70)
    print("E-S-122: Berlin Clock Permutation Tests")
    print("=" * 70)

    # Key historical times to test
    times = {
        "23:30 (Wall opening)": (23, 30),
        "19:00 (Schabowski presser)": (19, 0),
        "00:00 (midnight)": (0, 0),
        "11:30 (Wall time 12h)": (11, 30),
        "19:89 (year of fall→19:29?)": (19, 29),
        "07:14 (7×14 grid)": (7, 14),
        "09:07 (97 chars)": (9, 7),
        "06:45 (ENE=67.5°)": (6, 45),
        "12:00 (noon)": (12, 0),
        "19:86 (Egypt year→19:26?)": (19, 26),
        "03:38 (38° latitude)": (3, 38),
        "20:45 (Nov 9 key)": (20, 45),
    }

    # Also test all times that produce interesting lamp counts
    # Times where exactly 7 lamps are lit (width-7 connection)
    seven_lamp_times = []
    for h in range(24):
        for m in range(60):
            lamps = berlin_clock_lamps(h, m)
            if sum(lamps) == 7:
                seven_lamp_times.append((h, m))
    print(f"Found {len(seven_lamp_times)} times with exactly 7 lamps lit")

    # Substitution keywords
    keywords = {
        "KRYPTOS": make_keyword_key("KRYPTOS"),
        "ABSCISSA": make_keyword_key("ABSCISSA"),
        "PALIMPCEST": make_keyword_key("PALIMPCEST"),
        "COORD_MOD26": [v % MOD for v in [38, 57, 6, 5, 77, 8, 44]],
    }

    results = []
    best_overall = 0
    total_tested = 0

    # ── Phase 1: Historical times as permutations ────────────────────────
    print("\n--- Phase 1: Key historical times ---")
    for time_name, (h, m) in times.items():
        lamps = berlin_clock_lamps(h, m)
        n_lit = sum(lamps)
        lamp_str = "".join("█" if l else "░" for l in lamps)
        print(f"\n  {time_name}: {lamp_str} ({n_lit} lit)")

        # Method A: Cyclic permutation (lit first, unlit second)
        perm_a = lamps_to_permutation(lamps, CT_LEN)
        if len(set(perm_a)) == CT_LEN:
            inv_a = invert_perm(perm_a)
            ct_a = apply_perm(CT, inv_a)
            sc_a = score_cribs(ct_a)
            total_tested += 1
            if sc_a > best_overall:
                best_overall = sc_a
            if sc_a > NOISE_FLOOR:
                results.append({"time": time_name, "method": "cyclic_perm", "score": sc_a})
            print(f"    Cyclic perm: {sc_a}/24")

            # With substitution
            for kw_name, kw in keywords.items():
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    pt = decrypt_text(ct_a, kw, variant)
                    sc = score_cribs(pt)
                    total_tested += 1
                    if sc > best_overall:
                        best_overall = sc
                    if sc > NOISE_FLOOR:
                        results.append({
                            "time": time_name, "method": "cyclic_perm",
                            "keyword": kw_name, "variant": variant.value,
                            "score": sc,
                        })

        # Method B: Block permutation (24-char blocks)
        perm_b = lamps_to_block_permutation(lamps, CT_LEN)
        if len(perm_b) == CT_LEN and len(set(perm_b)) == CT_LEN:
            inv_b = invert_perm(perm_b)
            ct_b = apply_perm(CT, inv_b)
            sc_b = score_cribs(ct_b)
            total_tested += 1
            if sc_b > best_overall:
                best_overall = sc_b
            if sc_b > NOISE_FLOOR:
                results.append({"time": time_name, "method": "block_perm", "score": sc_b})
            print(f"    Block perm: {sc_b}/24")

            for kw_name, kw in keywords.items():
                for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                    pt = decrypt_text(ct_b, kw, variant)
                    sc = score_cribs(pt)
                    total_tested += 1
                    if sc > best_overall:
                        best_overall = sc
                    if sc > NOISE_FLOOR:
                        results.append({
                            "time": time_name, "method": "block_perm",
                            "keyword": kw_name, "variant": variant.value,
                            "score": sc,
                        })

        # Method C: Lamp counts as numeric key
        num_keys = lamps_to_numeric_key(lamps)
        for nk_name, nk in num_keys.items():
            nk_mod = [v % MOD for v in nk]
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(CT, nk_mod, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > best_overall:
                    best_overall = sc
                if sc > NOISE_FLOOR:
                    results.append({
                        "time": time_name, "method": f"numeric_{nk_name}",
                        "variant": variant.value, "score": sc,
                    })

        # Method D: Time digits as key
        time_digits = [int(d) for d in f"{h:02d}{m:02d}"]
        for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
            pt = decrypt_text(CT, time_digits, variant)
            sc = score_cribs(pt)
            total_tested += 1
            if sc > best_overall:
                best_overall = sc
            if sc > NOISE_FLOOR:
                results.append({
                    "time": time_name, "method": "time_digits",
                    "key": time_digits, "variant": variant.value, "score": sc,
                })

    # ── Phase 2: 7-lamp times ────────────────────────────────────────────
    print(f"\n--- Phase 2: Times with exactly 7 lamps lit ({len(seven_lamp_times)} times) ---")
    phase2_best = 0

    for h, m in seven_lamp_times:
        lamps = berlin_clock_lamps(h, m)

        # Only test cyclic permutation (most promising method)
        perm = lamps_to_permutation(lamps, CT_LEN)
        if len(set(perm)) != CT_LEN:
            continue
        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        sc = score_cribs(ct_untrans)
        total_tested += 1
        if sc > phase2_best:
            phase2_best = sc

        # With substitution
        for kw_name, kw in keywords.items():
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, kw, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase2_best:
                    phase2_best = sc
                if sc > NOISE_FLOOR:
                    results.append({
                        "time": f"{h:02d}:{m:02d}", "method": "7lamp_cyclic",
                        "keyword": kw_name, "variant": variant.value,
                        "score": sc,
                    })

    if phase2_best > best_overall:
        best_overall = phase2_best
    print(f"  Best from 7-lamp times: {phase2_best}/24")

    # ── Phase 3: Berlin Clock time 23:30 deep dive ──────────────────────
    print("\n--- Phase 3: 23:30 deep dive ---")
    lamps_2330 = berlin_clock_lamps(23, 30)
    print(f"  23:30 pattern: {''.join('█' if l else '░' for l in lamps_2330)}")
    print(f"  Lit positions: {[i for i, l in enumerate(lamps_2330) if l]}")
    print(f"  Unlit positions: {[i for i, l in enumerate(lamps_2330) if not l]}")

    # Try all permutations of the 24-lamp block applied to 97-char text
    # with various extensions to fill 97 from 24
    lit_pos = [i for i, l in enumerate(lamps_2330) if l]
    unlit_pos = [i for i, l in enumerate(lamps_2330) if not l]

    # Try: read CT at lit positions in each 24-block, concatenate
    phase3_best = 0
    # Generate route: within each 24-block, read lit first then unlit
    route = lit_pos + unlit_pos
    for start_offset in range(24):
        rotated_route = [(r + start_offset) % 24 for r in route]
        perm = []
        for block_start in range(0, CT_LEN, 24):
            for r in rotated_route:
                pos = block_start + r
                if pos < CT_LEN:
                    perm.append(pos)
        if len(perm) != CT_LEN or len(set(perm)) != CT_LEN:
            continue

        inv = invert_perm(perm)
        ct_untrans = apply_perm(CT, inv)

        for kw_name, kw in list(keywords.items()) + [("identity", [0])]:
            for variant in [CipherVariant.VIGENERE, CipherVariant.BEAUFORT]:
                pt = decrypt_text(ct_untrans, kw, variant)
                sc = score_cribs(pt)
                total_tested += 1
                if sc > phase3_best:
                    phase3_best = sc
                if sc > NOISE_FLOOR:
                    results.append({
                        "time": "23:30_rotated", "offset": start_offset,
                        "keyword": kw_name, "variant": variant.value,
                        "score": sc,
                    })

    if phase3_best > best_overall:
        best_overall = phase3_best
    print(f"  23:30 deep dive best: {phase3_best}/24")

    # ── Summary ──────────────────────────────────────────────────────────
    elapsed = time_mod.time() - t0
    print(f"\n{'=' * 70}")
    print(f"SUMMARY (elapsed: {elapsed:.1f}s)")
    print(f"{'=' * 70}")
    print(f"Total configs tested: {total_tested}")
    print(f"Global best score: {best_overall}/24")
    print(f"Results above noise: {len(results)}")

    if results:
        print("\nTop results:")
        for r in sorted(results, key=lambda x: -x["score"])[:10]:
            print(f"  score={r['score']}/24 {r}")

    verdict = "SIGNAL" if best_overall >= 18 else ("STORE" if best_overall > NOISE_FLOOR else "NOISE")
    print(f"\nVERDICT: {verdict}")

    artifact = {
        "experiment_id": "e_s_122",
        "stage": 4,
        "hypothesis": "Berlin Clock lamp patterns generate K4 transposition",
        "parameters_source": "K4 plaintext (BERLINCLOCK) + historical events",
        "total_tested": total_tested,
        "best_score": best_overall,
        "above_noise": results[:50],
        "seven_lamp_times_count": len(seven_lamp_times),
        "verdict": verdict,
        "runtime_seconds": elapsed,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_122_berlin_clock_perm.py",
    }

    out_path = "artifacts/progressive_solve/stage4/berlin_clock_results.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifacts written to {out_path}")


if __name__ == "__main__":
    main()
