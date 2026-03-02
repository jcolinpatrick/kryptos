#!/usr/bin/env python3
"""E-COMPOSE-02: Extended novel pipeline compositions — diagnostics + autokey.

Follow-up to E-COMPOSE-01 which found 0/2,462 consistent at periods {8,13}.

This experiment:
1. Diagnoses WHY compositions fail (count consistency vs Bean failures)
2. Tests ALL Bean-compatible periods {8,13,16,19,20,23,24,26} to see
   if any non-columnar transpositions pass at higher periods
3. Tests AUTOKEY + non-columnar transposition (novel: autokey was only
   tested alone or with columnar)
4. Tests MASK + AUTOKEY (novel: mask changes autokey feedback values)
5. Tests KA-alphabet Vigenère + non-columnar transposition (novel:
   KA cipher was only tested with columnar or identity transposition)

KEY THEORETICAL NOTE:
E-COMPOSE-01 confirmed that non-columnar transpositions (serpentine,
spiral, rail fence, Myszkowski, strip) share the same impossibility
as columnar at periods 8 and 13. This extends E-HYBRID-01's columnar
result to all structured transposition families.

At higher periods (16+), scoring is underdetermined (random ≈ 17.3+/24),
but CONSISTENCY CHECKING is still meaningful as a filter. If 0/N configs
are consistent at ALL periods, that's a universal elimination.
"""

import os
import sys
import time
import json
from collections import defaultdict
from math import ceil

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, BEAN_EQ, BEAN_INEQ,
    KRYPTOS_ALPHABET, NOISE_FLOOR,
)
from kryptos.kernel.transforms.transposition import (
    serpentine_perm, spiral_perm, rail_fence_perm, myszkowski_perm,
    strip_perm, invert_perm, apply_perm, validate_perm,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, vig_recover_key, beau_recover_key, varbeau_recover_key,
    vig_decrypt, beau_decrypt, varbeau_decrypt,
)
from kryptos.kernel.scoring.aggregate import score_candidate

CT_IDX = [ALPH_IDX[c] for c in CT]
CRIB_LIST = sorted(CRIB_DICT.items())
CRIB_POS_LIST = [pos for pos, _ in CRIB_LIST]
CRIB_VAL_LIST = [ALPH_IDX[ch] for _, ch in CRIB_LIST]

ALL_BEAN_PERIODS = [8, 13, 16, 19, 20, 23, 24, 26]
VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]

KEY_RECOVERY = {
    CipherVariant.VIGENERE: vig_recover_key,
    CipherVariant.BEAUFORT: beau_recover_key,
    CipherVariant.VAR_BEAUFORT: varbeau_recover_key,
}
DECRYPT = {
    CipherVariant.VIGENERE: vig_decrypt,
    CipherVariant.BEAUFORT: beau_decrypt,
    CipherVariant.VAR_BEAUFORT: varbeau_decrypt,
}


def make_keyed_alphabet(keyword):
    seen = set()
    result = []
    for ch in keyword.upper():
        if ch not in seen and ch in ALPH:
            seen.add(ch)
            result.append(ch)
    for ch in ALPH:
        if ch not in seen:
            result.append(ch)
    return ''.join(result)


# ══════════════════════════════════════════════════════════════════════════
# Generate transposition permutations
# ══════════════════════════════════════════════════════════════════════════

def generate_all_perms():
    """Generate non-columnar transposition permutations."""
    perms = []

    # Serpentine
    for width in range(7, 15):
        rows = ceil(CT_LEN / width)
        for vert in [False, True]:
            p = serpentine_perm(rows, width, CT_LEN, vert)
            if validate_perm(p, CT_LEN):
                perms.append((f"serp_w{width}_{'v' if vert else 'h'}", p))

    # Spiral
    for width in range(7, 15):
        rows = ceil(CT_LEN / width)
        for cw in [True, False]:
            p = spiral_perm(rows, width, CT_LEN, cw)
            if len(p) == CT_LEN and validate_perm(p, CT_LEN):
                perms.append((f"spir_w{width}_{'cw' if cw else 'ccw'}", p))

    # Rail fence
    for depth in range(2, 16):
        p = rail_fence_perm(CT_LEN, depth)
        if validate_perm(p, CT_LEN):
            perms.append((f"rail_d{depth}", p))

    # Myszkowski
    for kw in ["PALIMPSEST", "ABSCISSA", "BERLINCLOCK", "KRYPTOS",
               "EQUINOX", "SANBORN", "SCHEIDT", "COMPASS"]:
        try:
            p = myszkowski_perm(kw, CT_LEN)
            if validate_perm(p, CT_LEN):
                perms.append((f"mysz_{kw}", p))
        except:
            pass

    return perms


# ══════════════════════════════════════════════════════════════════════════
# Part 1: Diagnostic — consistency vs Bean failures at ALL periods
# ══════════════════════════════════════════════════════════════════════════

def diagnose_pipeline(perm, period, variant, model):
    """Return (status, detail) where status is:
    'consistent+bean_pass', 'consistent+bean_fail', 'inconsistent'.
    """
    inv_perm = invert_perm(perm)
    recover = KEY_RECOVERY[variant]

    key_constraints = defaultdict(list)

    for crib_pos, pt_val in zip(CRIB_POS_LIST, CRIB_VAL_LIST):
        if model == "A":
            ct_pos = perm[crib_pos]
            residue = ct_pos % period
        else:
            ct_pos = inv_perm[crib_pos]
            residue = crib_pos % period

        if ct_pos >= CT_LEN:
            continue
        ct_val = CT_IDX[ct_pos]
        k_val = recover(ct_val, pt_val)
        key_constraints[residue].append(k_val)

    # Check consistency
    key_vals = {}
    for residue, vals in key_constraints.items():
        if len(set(vals)) > 1:
            return "inconsistent", f"residue {residue}: {set(vals)}"
        key_vals[residue] = vals[0]

    # Check Bean
    for a, b in BEAN_EQ:
        if model == "A":
            ra = perm[a] % period
            rb = perm[b] % period
        else:
            ra = a % period
            rb = b % period
        if ra in key_vals and rb in key_vals:
            if key_vals[ra] != key_vals[rb]:
                return "consistent+bean_fail", f"Bean EQ: k[{ra}]={key_vals[ra]} != k[{rb}]={key_vals[rb]}"

    for a, b in BEAN_INEQ:
        if model == "A":
            ra = perm[a] % period
            rb = perm[b] % period
        else:
            ra = a % period
            rb = b % period
        if ra in key_vals and rb in key_vals:
            if key_vals[ra] == key_vals[rb]:
                return "consistent+bean_fail", f"Bean INEQ: k[{ra}]=k[{rb}]={key_vals[ra]}"

    return "consistent+bean_pass", f"key_vals: {key_vals}"


# ══════════════════════════════════════════════════════════════════════════
# Part 2: CT-autokey + non-columnar transposition
# ══════════════════════════════════════════════════════════════════════════

def test_ct_autokey_transposition(perm, perm_desc, primer_len, variant, model):
    """Test CT-autokey + transposition.

    CT-autokey: key[i] = CT[i-primer_len] for i >= primer_len
    With transposition Model A (trans→sub):
      CT_at_position[j] = sub(transposed_PT[j], key[j])
      key[j] = CT[j - primer_len] for j >= primer_len

    For Model B (sub→trans):
      encrypted[i] = sub(PT[i], key[i])
      CT = trans(encrypted)
      CT[j] = encrypted[perm[j]]
      To undo: encrypted[i] = CT[inv_perm[i]]
      PT[i] = decrypt(encrypted[i], key[i])
      CT-autokey: key[i] = encrypted[i - primer_len] = CT[inv_perm[i - primer_len]]
    """
    if not validate_perm(perm, CT_LEN):
        return None

    inv_perm = invert_perm(perm)
    recover = KEY_RECOVERY[variant]
    decrypt = DECRYPT[variant]

    # For CT-autokey, key positions >= primer_len are determined by CT
    # For positions < primer_len, key is the primer (unknown)
    # At crib positions, we can compute what the primer values must be

    if model == "B":
        # intermediate = CT after undoing transposition
        intermediate = apply_perm(CT, inv_perm)
        int_idx = [ALPH_IDX[c] for c in intermediate]

        # key[i] = int_idx[i - primer_len] for i >= primer_len
        # At crib positions, PT[i] = decrypt(int_idx[i], key[i])
        # If i >= primer_len: key[i] = int_idx[i - primer_len]
        # If i < primer_len: key[i] is unknown

        # Check cribs at positions >= primer_len (determined key)
        matches = 0
        for crib_pos, pt_val in zip(CRIB_POS_LIST, CRIB_VAL_LIST):
            if crib_pos >= primer_len:
                k = int_idx[crib_pos - primer_len]
                pt_computed = decrypt(int_idx[crib_pos], k)
                if pt_computed == pt_val:
                    matches += 1

        if matches < 4:  # Need substantial signal
            return None

        # For positions < primer_len, recover primer values from cribs
        primer = [None] * primer_len
        for crib_pos, pt_val in zip(CRIB_POS_LIST, CRIB_VAL_LIST):
            if crib_pos < primer_len:
                k = recover(int_idx[crib_pos], pt_val)
                primer[crib_pos] = k

        # Fill unknown primer positions with 0
        for i in range(primer_len):
            if primer[i] is None:
                primer[i] = 0

        # Decrypt full text
        key = list(primer)
        for i in range(primer_len, CT_LEN):
            key.append(int_idx[i - primer_len])

        plaintext = ''.join(ALPH[decrypt(int_idx[i], key[i])] for i in range(CT_LEN))
        sc = score_candidate(plaintext)
        return (sc.crib_score, sc.bean_passed, plaintext, sc.summary,
                perm_desc, variant.value, primer_len, model)

    else:  # Model A
        # CT → sub⁻¹(key) → trans⁻¹ → PT
        # key[j] = CT[j - primer_len] for j >= primer_len
        # At position j: intermediate[j] = decrypt(CT[j], key[j])
        # PT[i] = intermediate[perm[i]]

        # Crib at pos i: PT[i] = intermediate[π(i)] = decrypt(CT[π(i)], key[π(i)])
        # If π(i) >= primer_len: key[π(i)] = CT_IDX[π(i) - primer_len] (known!)

        matches = 0
        for crib_pos, pt_val in zip(CRIB_POS_LIST, CRIB_VAL_LIST):
            ct_pos = perm[crib_pos]
            if ct_pos >= primer_len:
                k = CT_IDX[ct_pos - primer_len]
                pt_computed = decrypt(CT_IDX[ct_pos], k)
                if pt_computed == pt_val:
                    matches += 1

        if matches < 4:
            return None

        # Recover primer from cribs where π(i) < primer_len
        primer = [None] * primer_len
        for crib_pos, pt_val in zip(CRIB_POS_LIST, CRIB_VAL_LIST):
            ct_pos = perm[crib_pos]
            if ct_pos < primer_len:
                k = recover(CT_IDX[ct_pos], pt_val)
                if primer[ct_pos] is not None and primer[ct_pos] != k:
                    return None  # Inconsistent primer
                primer[ct_pos] = k

        for i in range(primer_len):
            if primer[i] is None:
                primer[i] = 0

        key = list(primer)
        for j in range(primer_len, CT_LEN):
            key.append(CT_IDX[j - primer_len])

        intermediate = ''.join(ALPH[decrypt(CT_IDX[j], key[j])] for j in range(CT_LEN))
        plaintext = apply_perm(intermediate, inv_perm)
        sc = score_candidate(plaintext)
        return (sc.crib_score, sc.bean_passed, plaintext, sc.summary,
                perm_desc, variant.value, primer_len, model)


# ══════════════════════════════════════════════════════════════════════════
# Part 3: KA-alphabet cipher + non-columnar transposition
# ══════════════════════════════════════════════════════════════════════════

def test_ka_cipher_transposition(perm, perm_desc, period, variant, model):
    """Test Vigenère/Beaufort using KA alphabet indices + non-columnar trans.

    Instead of standard A=0..Z=25, use KA: K=0,R=1,Y=2,P=3,...
    This changes key recovery values at crib positions.
    """
    KA_IDX = {ch: i for i, ch in enumerate(KRYPTOS_ALPHABET)}
    inv_perm = invert_perm(perm)
    recover = KEY_RECOVERY[variant]

    key_constraints = defaultdict(list)

    for crib_pos, pt_char in CRIB_LIST:
        if model == "A":
            ct_pos = perm[crib_pos]
            residue = ct_pos % period
        else:
            ct_pos = inv_perm[crib_pos]
            residue = crib_pos % period

        if ct_pos >= CT_LEN:
            continue

        # Use KA indices instead of AZ indices
        ct_ka = KA_IDX[CT[ct_pos]]
        pt_ka = KA_IDX[pt_char]
        k_val = recover(ct_ka, pt_ka)
        key_constraints[residue].append(k_val)

    key_vals = {}
    for residue, vals in key_constraints.items():
        if len(set(vals)) > 1:
            return None
        key_vals[residue] = vals[0]

    # Bean check
    for a, b in BEAN_EQ:
        ra = (perm[a] if model == "A" else a) % period
        rb = (perm[b] if model == "A" else b) % period
        if ra in key_vals and rb in key_vals:
            if key_vals[ra] != key_vals[rb]:
                return None

    for a, b in BEAN_INEQ:
        ra = (perm[a] if model == "A" else a) % period
        rb = (perm[b] if model == "A" else b) % period
        if ra in key_vals and rb in key_vals:
            if key_vals[ra] == key_vals[rb]:
                return None

    # Decrypt using KA alphabet
    decrypt = DECRYPT[variant]
    full_key = [key_vals.get(i % period, 0) for i in range(CT_LEN)]

    if model == "A":
        intermediate = ''.join(
            KRYPTOS_ALPHABET[decrypt(KA_IDX[CT[i]], full_key[i])] for i in range(CT_LEN)
        )
        plaintext = apply_perm(intermediate, inv_perm)
    else:
        reordered = apply_perm(CT, inv_perm)
        plaintext = ''.join(
            KRYPTOS_ALPHABET[decrypt(KA_IDX[reordered[i]], full_key[i])] for i in range(CT_LEN)
        )

    sc = score_candidate(plaintext)
    if sc.crib_score >= NOISE_FLOOR:
        return (sc.crib_score, sc.bean_passed, plaintext, sc.summary,
                perm_desc, variant.value, period, model, "KA")
    return None


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 78)
    print("E-COMPOSE-02: Extended Pipeline Compositions + Diagnostics")
    print("=" * 78)
    t0 = time.time()

    perms = generate_all_perms()
    print(f"\nGenerated {len(perms)} non-columnar transposition permutations")

    # ── Part 1: Diagnostic at ALL Bean-compatible periods ─────────────────
    print("\n" + "─" * 78)
    print("Part 1: Diagnostic — ALL Bean-compatible periods")
    print("─" * 78)

    diag_counts = {p: {"inconsistent": 0, "bean_fail": 0, "bean_pass": 0}
                   for p in ALL_BEAN_PERIODS}

    for perm_desc, perm in perms:
        for period in ALL_BEAN_PERIODS:
            for variant in VARIANTS:
                for model in ["A", "B"]:
                    status, _ = diagnose_pipeline(perm, period, variant, model)
                    if status == "inconsistent":
                        diag_counts[period]["inconsistent"] += 1
                    elif status == "consistent+bean_fail":
                        diag_counts[period]["bean_fail"] += 1
                    else:
                        diag_counts[period]["bean_pass"] += 1

    print(f"\n  {'Period':>6} | {'Inconsistent':>12} | {'Bean FAIL':>10} | {'Bean PASS':>10} | Total")
    print(f"  {'─'*6}-+-{'─'*12}-+-{'─'*10}-+-{'─'*10}-+──────")
    for period in ALL_BEAN_PERIODS:
        c = diag_counts[period]
        total = sum(c.values())
        print(f"  {period:6d} | {c['inconsistent']:12d} | {c['bean_fail']:10d} | {c['bean_pass']:10d} | {total}")

    # ── Part 2: Detailed decrypt for Bean-passing configs ─────────────────
    bean_pass_results = []
    for perm_desc, perm in perms:
        for period in ALL_BEAN_PERIODS:
            for variant in VARIANTS:
                for model in ["A", "B"]:
                    status, detail = diagnose_pipeline(perm, period, variant, model)
                    if status == "consistent+bean_pass":
                        # Decrypt and score
                        inv_perm = invert_perm(perm)
                        recover = KEY_RECOVERY[variant]
                        decrypt = DECRYPT[variant]

                        key_constraints = defaultdict(list)
                        for crib_pos, pt_val in zip(CRIB_POS_LIST, CRIB_VAL_LIST):
                            if model == "A":
                                ct_pos = perm[crib_pos]
                                residue = ct_pos % period
                            else:
                                ct_pos = inv_perm[crib_pos]
                                residue = crib_pos % period
                            if ct_pos >= CT_LEN:
                                continue
                            k_val = recover(CT_IDX[ct_pos], pt_val)
                            key_constraints[residue].append(k_val)

                        key_vals = {r: vs[0] for r, vs in key_constraints.items()}
                        full_key = [key_vals.get(i % period, 0) for i in range(CT_LEN)]

                        if model == "A":
                            intermediate = ''.join(
                                ALPH[decrypt(CT_IDX[i], full_key[i])] for i in range(CT_LEN)
                            )
                            pt = apply_perm(intermediate, inv_perm)
                        else:
                            reordered = apply_perm(CT, inv_perm)
                            pt = ''.join(
                                ALPH[decrypt(ALPH_IDX[reordered[i]], full_key[i])]
                                for i in range(CT_LEN)
                            )

                        sc = score_candidate(pt)
                        bean_pass_results.append((
                            period, sc.crib_score, sc.bean_passed, perm_desc,
                            variant.value, model, pt[:40], sc.summary
                        ))

    if bean_pass_results:
        print(f"\n  Bean-passing configs that were decrypted: {len(bean_pass_results)}")
        bean_pass_results.sort(key=lambda x: x[1], reverse=True)
        for r in bean_pass_results[:15]:
            print(f"    p={r[0]:2d} score={r[1]:2d}/24 bean={r[2]} "
                  f"{r[3]} {r[4]} M{r[5]}")
            print(f"         PT: {r[6]}...")
    else:
        print("\n  No Bean-passing configs found at any period.")

    # ── Part 3: CT-autokey + non-columnar transposition ───────────────────
    print("\n" + "─" * 78)
    print("Part 3: CT-autokey + non-columnar transposition")
    print("─" * 78)

    autokey_results = []
    autokey_configs = 0
    for perm_desc, perm in perms:
        for primer_len in [5, 7, 8, 10, 13]:
            for variant in VARIANTS:
                for model in ["A", "B"]:
                    autokey_configs += 1
                    result = test_ct_autokey_transposition(
                        perm, perm_desc, primer_len, variant, model
                    )
                    if result and result[0] >= NOISE_FLOOR:
                        autokey_results.append(result)

    print(f"  Tested: {autokey_configs} configs")
    if autokey_results:
        autokey_results.sort(key=lambda x: x[0], reverse=True)
        print(f"  Results above noise: {len(autokey_results)}")
        for r in autokey_results[:10]:
            print(f"    score={r[0]:2d}/24 bean={r[1]} {r[4]} {r[5]} "
                  f"primer={r[6]} M{r[7]}")
            print(f"         PT: {r[2][:40]}...")
    else:
        print(f"  No results above noise floor ({NOISE_FLOOR}).")

    # ── Part 4: KA-alphabet cipher + non-columnar transposition ──────────
    print("\n" + "─" * 78)
    print("Part 4: KA-alphabet Vigenère + non-columnar transposition")
    print("─" * 78)

    ka_results = []
    ka_configs = 0
    for perm_desc, perm in perms:
        for period in [8, 13]:
            for variant in VARIANTS:
                for model in ["A", "B"]:
                    ka_configs += 1
                    result = test_ka_cipher_transposition(
                        perm, perm_desc, period, variant, model
                    )
                    if result is not None:
                        ka_results.append(result)

    print(f"  Tested: {ka_configs} configs")
    if ka_results:
        ka_results.sort(key=lambda x: x[0], reverse=True)
        print(f"  Results above noise: {len(ka_results)}")
        for r in ka_results[:10]:
            print(f"    score={r[0]:2d}/24 bean={r[1]} {r[4]} {r[5]} p{r[6]} M{r[7]} {r[8]}")
    else:
        print(f"  No results above noise floor ({NOISE_FLOOR}).")

    # ── Summary ───────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print("\n" + "=" * 78)
    print(f"SUMMARY — E-COMPOSE-02")
    print(f"=" * 78)

    total_bean_pass = sum(d["bean_pass"] for d in diag_counts.values())
    total_bean_fail = sum(d["bean_fail"] for d in diag_counts.values())
    total_incon = sum(d["inconsistent"] for d in diag_counts.values())

    print(f"\nDiagnostic totals across all periods:")
    print(f"  Inconsistent: {total_incon}")
    print(f"  Consistent + Bean FAIL: {total_bean_fail}")
    print(f"  Consistent + Bean PASS: {total_bean_pass}")
    print(f"\nAutokey configs: {autokey_configs}, above noise: {len(autokey_results)}")
    print(f"KA cipher configs: {ka_configs}, above noise: {len(ka_results)}")
    print(f"\nElapsed: {elapsed:.1f}s")

    best_score = 0
    if bean_pass_results:
        best_score = max(best_score, max(r[1] for r in bean_pass_results))
    if autokey_results:
        best_score = max(best_score, max(r[0] for r in autokey_results))
    if ka_results:
        best_score = max(best_score, max(r[0] for r in ka_results))

    print(f"\nBest overall score: {best_score}/24")

    # High-period caveat
    if total_bean_pass > 0:
        period_pass_counts = {p: diag_counts[p]["bean_pass"] for p in ALL_BEAN_PERIODS
                              if diag_counts[p]["bean_pass"] > 0}
        print(f"\nBean passes by period: {period_pass_counts}")
        print(f"  NOTE: periods >= 16 are underdetermined (expected random: 17+/24)")
        print(f"  Only periods 8,13 are discriminating. Others are false positives.")

    # Save
    results_dir = os.path.join(os.path.dirname(__file__), '..', 'results')
    os.makedirs(results_dir, exist_ok=True)
    output = {
        "experiment": "E-COMPOSE-02",
        "diagnostics": {str(p): diag_counts[p] for p in ALL_BEAN_PERIODS},
        "autokey_configs": autokey_configs,
        "autokey_above_noise": len(autokey_results),
        "ka_configs": ka_configs,
        "ka_above_noise": len(ka_results),
        "best_score": best_score,
        "elapsed": elapsed,
        "bean_pass_results_count": len(bean_pass_results),
        "top_bean_pass": [
            {"period": r[0], "score": r[1], "perm": r[3], "variant": r[4]}
            for r in bean_pass_results[:5]
        ] if bean_pass_results else [],
    }
    with open(os.path.join(results_dir, "e_compose_02.json"), 'w') as f:
        json.dump(output, f, indent=2)


if __name__ == "__main__":
    main()
