#!/usr/bin/env python3
"""
Cipher: Antipodes analysis
Family: antipodes
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
E-ANTIPODES-05: Gromark/Vimark + Transposition

HYPOTHESIS: K4 uses Gromark or Vimark cipher (quasi-periodic via linear
recurrence) combined with a transposition. These are listed as OPEN in
docs/elimination_tiers.md. The recurrence structure means keystream at crib
positions over-constrains the primer, making algebraic consistency checks
tractable.

WHY ANTIPODES: The confirmed non-periodicity of K4's key is consistent with
Gromark/Vimark. The seamless K3→K4 transition is consistent with moving from
pure-periodic (K3) to quasi-periodic (K4).

METHOD:
1. For each Bean-surviving period p in {8, 13, 16, 19, 20, 23, 24, 26}:
   For each candidate transposition (columnar at Bean-compatible widths):
   - Apply inverse transposition to K4 CT
   - At crib positions, compute implied Vigenère key values
   - Check if implied keys satisfy Vimark recurrence: k[i] = (k[i-p] + k[i-p+1]) mod 26
   - If consistent: extract primer, expand full keystream, decrypt, score
2. Also test Gromark variant (digit-based recurrence)

COST: ~100K transpositions × 8 periods ≈ 800K checks. Under 5 sec.
"""

import json
import os
import sys
import time
import itertools
from typing import List, Dict, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, invert_perm, apply_perm, keyword_to_order, validate_perm,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text,
    vig_recover_key, beau_recover_key, varbeau_recover_key,
)
from kryptos.kernel.scoring.crib_score import score_cribs
from kryptos.kernel.constraints.bean import (
    verify_bean, verify_bean_simple, expand_keystream_vimark,
)

# ── Bean-compatible periods ──────────────────────────────────────────────

BEAN_PERIODS = [8, 13, 16, 19, 20, 23, 24, 26]

KEY_RECOVER = {
    CipherVariant.VIGENERE: vig_recover_key,
    CipherVariant.BEAUFORT: beau_recover_key,
    CipherVariant.VAR_BEAUFORT: varbeau_recover_key,
}


def check_vimark_recurrence(
    key_at_pos: Dict[int, int], period: int,
) -> Tuple[bool, int, int]:
    """Check if known key values satisfy Vimark recurrence.

    Vimark: k[i] = (k[i-p] + k[i-p+1]) mod 26

    Returns (consistent, n_checked, n_satisfied).
    """
    n_checked = 0
    n_satisfied = 0

    positions = sorted(key_at_pos.keys())

    for pos in positions:
        # Check if we can verify the recurrence at this position
        prev1 = pos - period
        prev2 = pos - period + 1

        if prev1 in key_at_pos and prev2 in key_at_pos:
            expected = (key_at_pos[prev1] + key_at_pos[prev2]) % MOD
            n_checked += 1
            if key_at_pos[pos] == expected:
                n_satisfied += 1

    consistent = (n_checked > 0 and n_satisfied == n_checked)
    return consistent, n_checked, n_satisfied


def check_gromark_recurrence(
    key_at_pos: Dict[int, int], period: int,
) -> Tuple[bool, int, int]:
    """Check Gromark recurrence: k[i] = (k[i-p] + k[i-p+1]) mod 10.

    Gromark uses digit-based (mod 10) recurrence applied to key,
    where key values are mapped to digits first.
    """
    n_checked = 0
    n_satisfied = 0

    for pos in sorted(key_at_pos.keys()):
        prev1 = pos - period
        prev2 = pos - period + 1

        if prev1 in key_at_pos and prev2 in key_at_pos:
            # Gromark: digit recurrence mod 10
            d1 = key_at_pos[prev1] % 10
            d2 = key_at_pos[prev2] % 10
            expected_digit = (d1 + d2) % 10
            actual_digit = key_at_pos[pos] % 10
            n_checked += 1
            if actual_digit == expected_digit:
                n_satisfied += 1

    consistent = (n_checked > 0 and n_satisfied == n_checked)
    return consistent, n_checked, n_satisfied


def try_reconstruct_primer(
    key_at_pos: Dict[int, int], period: int, mode: str = "vimark",
) -> Optional[Tuple[int, ...]]:
    """Try to reconstruct the primer from known key values.

    For Vimark with period p, the primer is k[0]..k[p-1].
    We propagate known values backward/forward through the recurrence.
    """
    # Start with what we know
    key = dict(key_at_pos)

    # Forward propagation: k[i] = (k[i-p] + k[i-p+1]) mod M
    mod = MOD if mode == "vimark" else 10
    changed = True
    iterations = 0
    while changed and iterations < 200:
        changed = False
        iterations += 1
        for pos in range(period, CT_LEN):
            prev1 = pos - period
            prev2 = pos - period + 1
            if prev1 in key and prev2 in key and pos not in key:
                if mode == "vimark":
                    key[pos] = (key[prev1] + key[prev2]) % MOD
                else:
                    key[pos] = (key[prev1] % 10 + key[prev2] % 10) % 10
                changed = True

        # Backward: k[i-p] = (k[i] - k[i-p+1]) mod M (from recurrence)
        for pos in range(CT_LEN - 1, period - 1, -1):
            prev1 = pos - period
            prev2 = pos - period + 1
            if pos in key and prev2 in key and prev1 not in key:
                if mode == "vimark":
                    key[prev1] = (key[pos] - key[prev2]) % MOD
                else:
                    key[prev1] = (key[pos] - key[prev2] % 10) % 10
                changed = True
            if pos in key and prev1 in key and prev2 not in key:
                if mode == "vimark":
                    key[prev2] = (key[pos] - key[prev1]) % MOD
                else:
                    key[prev2] = (key[pos] - key[prev1] % 10) % 10
                changed = True

    # Check if we have the full primer
    primer_vals = []
    for i in range(period):
        if i in key:
            primer_vals.append(key[i])
        else:
            return None  # Can't determine full primer

    return tuple(primer_vals)


def generate_column_orderings(width: int, max_orderings: int = 5040):
    if width <= 7:
        yield from itertools.permutations(range(width))
    else:
        seen = set()
        keywords = [
            "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "SANBORN",
            "SCHEIDT", "SHADOW", "ENIGMA", "QUARTZ", "CLOCK",
            "EASTNORTHEAST", "BERLINCLOCK", "CARTER", "EGYPT",
            "CIPHER", "HILL", "COMPASS", "LODESTONE",
        ]
        for kw in keywords:
            order = keyword_to_order(kw, width)
            if order is not None and order not in seen:
                seen.add(order)
                yield order
        import random
        rng = random.Random(42)
        attempts = 0
        while len(seen) < max_orderings and attempts < max_orderings * 5:
            perm_list = list(range(width))
            rng.shuffle(perm_list)
            t = tuple(perm_list)
            if t not in seen:
                seen.add(t)
                yield t
            attempts += 1


def main():
    t0 = time.time()
    print("=" * 70)
    print("E-ANTIPODES-05: Gromark/Vimark + Transposition")
    print("=" * 70)

    best_score = 0
    best_result = None
    total_configs = 0
    vimark_consistent = 0
    gromark_consistent = 0
    above_noise = []

    variants = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

    for period in BEAN_PERIODS:
        print(f"\n--- Period {period} ---")
        p_configs = 0
        p_consistent = 0

        for width in range(6, 14):
            for col_order in generate_column_orderings(width):
                perm = columnar_perm(width, col_order, CT_LEN)
                if not validate_perm(perm, CT_LEN):
                    continue
                inv_p = invert_perm(perm)
                intermediate = apply_perm(CT, inv_p)

                for variant in variants:
                    total_configs += 1
                    p_configs += 1
                    recover_fn = KEY_RECOVER[variant]

                    # Recover key at crib positions
                    key_at_pos = {}
                    for pos, pt_char in CRIB_DICT.items():
                        c = ord(intermediate[pos]) - 65
                        p = ord(pt_char) - 65
                        key_at_pos[pos] = recover_fn(c, p)

                    # Check Vimark recurrence
                    consistent, n_chk, n_sat = check_vimark_recurrence(key_at_pos, period)
                    if consistent and n_chk >= 2:
                        vimark_consistent += 1
                        p_consistent += 1

                        # Try to reconstruct primer
                        primer = try_reconstruct_primer(key_at_pos, period, "vimark")
                        if primer is not None:
                            # Expand and decrypt
                            full_key = expand_keystream_vimark(primer, CT_LEN)
                            pt = decrypt_text(intermediate, full_key, variant)
                            sc = score_cribs(pt)

                            bean_ok = verify_bean_simple(full_key)

                            if sc > best_score:
                                best_score = sc
                                best_result = {
                                    "type": "vimark",
                                    "period": period,
                                    "width": width,
                                    "col_order": list(col_order)[:10],
                                    "variant": variant.value,
                                    "primer": list(primer),
                                    "plaintext": pt,
                                    "crib_score": sc,
                                    "bean_pass": bean_ok,
                                    "recurrence_checks": n_chk,
                                }
                                if sc > NOISE_FLOOR:
                                    print(f"  VIMARK BEST: {sc}/24, p={period}, w={width}, "
                                          f"{variant.value}, bean={'PASS' if bean_ok else 'FAIL'}")
                                    if sc >= STORE_THRESHOLD:
                                        print(f"  PT: {pt}")

                            if sc > NOISE_FLOOR:
                                above_noise.append({
                                    "type": "vimark",
                                    "period": period,
                                    "width": width,
                                    "variant": variant.value,
                                    "crib_score": sc,
                                    "bean_pass": bean_ok,
                                })

                    # Check Gromark recurrence
                    g_consistent, g_chk, g_sat = check_gromark_recurrence(key_at_pos, period)
                    if g_consistent and g_chk >= 2:
                        gromark_consistent += 1

                        primer = try_reconstruct_primer(key_at_pos, period, "gromark")
                        if primer is not None:
                            # Expand Gromark keystream (mod 10 recurrence, but applied mod 26)
                            full_key = list(primer)
                            while len(full_key) < CT_LEN:
                                d1 = full_key[-period] % 10
                                d2 = full_key[-period + 1] % 10
                                full_key.append((d1 + d2) % 10)
                            full_key = full_key[:CT_LEN]

                            pt = decrypt_text(intermediate, full_key, variant)
                            sc = score_cribs(pt)

                            if sc > best_score:
                                best_score = sc
                                best_result = {
                                    "type": "gromark",
                                    "period": period,
                                    "width": width,
                                    "col_order": list(col_order)[:10],
                                    "variant": variant.value,
                                    "primer": list(primer),
                                    "plaintext": pt,
                                    "crib_score": sc,
                                }
                                if sc > NOISE_FLOOR:
                                    print(f"  GROMARK BEST: {sc}/24, p={period}, w={width}, "
                                          f"{variant.value}")

                            if sc > NOISE_FLOOR:
                                above_noise.append({
                                    "type": "gromark",
                                    "period": period,
                                    "width": width,
                                    "variant": variant.value,
                                    "crib_score": sc,
                                })

        print(f"  Period {period}: {p_configs:,} configs, "
              f"{p_consistent} vimark-consistent")

    # ── Also test without transposition (identity perm) ──────────────────
    print("\n--- No transposition (identity) ---")
    for period in BEAN_PERIODS:
        for variant in variants:
            total_configs += 1
            recover_fn = KEY_RECOVER[variant]

            key_at_pos = {}
            for pos, pt_char in CRIB_DICT.items():
                c = ord(CT[pos]) - 65
                p = ord(pt_char) - 65
                key_at_pos[pos] = recover_fn(c, p)

            for mode_name, check_fn, recon_mode in [
                ("vimark", check_vimark_recurrence, "vimark"),
                ("gromark", check_gromark_recurrence, "gromark"),
            ]:
                consistent, n_chk, n_sat = check_fn(key_at_pos, period)
                if consistent and n_chk >= 2:
                    primer = try_reconstruct_primer(key_at_pos, period, recon_mode)
                    if primer is not None:
                        if recon_mode == "vimark":
                            full_key = expand_keystream_vimark(primer, CT_LEN)
                        else:
                            full_key = list(primer)
                            while len(full_key) < CT_LEN:
                                d1 = full_key[-period] % 10
                                d2 = full_key[-period + 1] % 10
                                full_key.append((d1 + d2) % 10)
                            full_key = full_key[:CT_LEN]

                        pt = decrypt_text(CT, full_key, variant)
                        sc = score_cribs(pt)
                        if sc > best_score:
                            best_score = sc
                            best_result = {
                                "type": f"{mode_name}_no_trans",
                                "period": period,
                                "variant": variant.value,
                                "primer": list(primer),
                                "plaintext": pt,
                                "crib_score": sc,
                            }
                            if sc > NOISE_FLOOR:
                                print(f"  {mode_name.upper()} (no trans): {sc}/24, "
                                      f"p={period}, {variant.value}")

    elapsed = time.time() - t0

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total configs tested: {total_configs:,}")
    print(f"Vimark-consistent: {vimark_consistent}")
    print(f"Gromark-consistent: {gromark_consistent}")
    print(f"Best crib score: {best_score}/24")
    if best_result:
        for k, v in best_result.items():
            if k != "plaintext":
                print(f"  {k}: {v}")
        if best_score >= STORE_THRESHOLD:
            print(f"Best plaintext: {best_result.get('plaintext')}")
    print(f"Above-noise results: {len(above_noise)}")
    print(f"Elapsed: {elapsed:.1f}s")

    # ── Write results ─────────────────────────────────────────────────────
    outdir = os.path.join(os.path.dirname(__file__), '..', 'results', 'e_antipodes_05')
    os.makedirs(outdir, exist_ok=True)
    summary = {
        "experiment": "E-ANTIPODES-05",
        "hypothesis": "Gromark/Vimark quasi-periodic cipher + transposition",
        "total_configs": total_configs,
        "vimark_consistent": vimark_consistent,
        "gromark_consistent": gromark_consistent,
        "best_score": best_score,
        "best_result": {k: v for k, v in best_result.items() if k != "plaintext"} if best_result else None,
        "above_noise_count": len(above_noise),
        "periods_tested": BEAN_PERIODS,
        "elapsed_seconds": elapsed,
    }
    with open(os.path.join(outdir, 'summary.json'), 'w') as f:
        json.dump(summary, f, indent=2)
    if above_noise:
        above_noise.sort(key=lambda x: x["crib_score"], reverse=True)
        with open(os.path.join(outdir, 'above_noise.json'), 'w') as f:
            json.dump(above_noise[:100], f, indent=2)

    print(f"\nResults written to {outdir}/")
    if best_score <= NOISE_FLOOR:
        print("\nCONCLUSION: NOISE — Gromark/Vimark + transposition eliminated.")
    else:
        print(f"\nCONCLUSION: Score {best_score}/24 — "
              f"{'investigate!' if best_score >= STORE_THRESHOLD else 'likely noise.'}")


if __name__ == "__main__":
    main()
