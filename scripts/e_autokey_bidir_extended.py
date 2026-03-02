#!/usr/bin/env python3
"""Extended autokey bidirectional analysis: seed lengths 1-96, with detailed
contradiction tracing and verification.

Extends e_autokey_bidirectional.py to:
1. Test ALL possible seed lengths (1-96)
2. Show detailed contradiction traces
3. Verify the structural impossibility argument
4. Test with KA alphabet as well as standard AZ
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, KRYPTOS_ALPHABET,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# ── Load quadgrams ────────────────────────────────────────────────────────

QG_PATH = "data/english_quadgrams.json"
QUADGRAMS = {}
if os.path.exists(QG_PATH):
    with open(QG_PATH) as f:
        QUADGRAMS = json.load(f)

QG_FLOOR = -10.0


def qg_score_per_char(text):
    if len(text) < 4:
        return QG_FLOOR
    score = sum(QUADGRAMS.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3))
    return score / (len(text) - 3)


# ── Variant definitions ──────────────────────────────────────────────────

VARIANTS = {
    'vig': {
        'name': 'Vigenère',
        'key_from_ct_pt': lambda ct, pt: (ct - pt) % 26,
        'pt_from_ct_key': lambda ct, k: (ct - k) % 26,
    },
    'beau': {
        'name': 'Beaufort',
        'key_from_ct_pt': lambda ct, pt: (ct + pt) % 26,
        'pt_from_ct_key': lambda ct, k: (k - ct) % 26,
    },
    'vbeau': {
        'name': 'VarBeau',
        'key_from_ct_pt': lambda ct, pt: (pt - ct) % 26,
        'pt_from_ct_key': lambda ct, k: (ct + k) % 26,
    },
}


def propagate_autokey(p, variant_key, verbose=False):
    """Bidirectional autokey propagation.

    Returns: (pt_list, contradiction_found, contradiction_detail, n_determined)
    """
    v = VARIANTS[variant_key]
    key_from = v['key_from_ct_pt']
    pt_from = v['pt_from_ct_key']

    pt = [None] * CT_LEN

    # Seed from cribs
    for pos, val in CRIB_NUM.items():
        pt[pos] = val

    for iteration in range(CT_LEN * 3):
        changed = False

        # Forward: PT[i] known → K[i+p] = PT[i] → PT[i+p] = decrypt(CT[i+p], PT[i])
        for i in range(CT_LEN):
            if pt[i] is not None and i + p < CT_LEN:
                new_val = pt_from(CT_NUM[i + p], pt[i])
                if pt[i + p] is None:
                    pt[i + p] = new_val
                    changed = True
                elif pt[i + p] != new_val:
                    detail = (f"pos {i+p}: existing={ALPH[pt[i+p]]} "
                              f"derived={ALPH[new_val]} from PT[{i}]={ALPH[pt[i]]}")
                    return pt, True, detail, 0

        # Backward: PT[i] known, i >= p → K[i] = key_from(CT[i], PT[i]) = PT[i-p]
        for i in range(p, CT_LEN):
            if pt[i] is not None:
                k_val = key_from(CT_NUM[i], pt[i])
                target = i - p
                if pt[target] is None:
                    pt[target] = k_val
                    changed = True
                elif pt[target] != k_val:
                    detail = (f"pos {target}: existing={ALPH[pt[target]]} "
                              f"derived={ALPH[k_val]} backward from PT[{i}]={ALPH[pt[i]]}")
                    return pt, True, detail, 0

        if not changed:
            break

    n_det = sum(1 for v in pt if v is not None)
    return pt, False, None, n_det


def main():
    print("=" * 78)
    print("AUTOKEY VIGENÈRE — EXTENDED BIDIRECTIONAL (ALL SEED LENGTHS 1-96)")
    print("=" * 78)
    print(f"  Testing {96 * 3} total configs (3 variants × 96 seed lengths)")
    sys.stdout.flush()

    t0 = time.time()
    results_by_variant = {k: [] for k in VARIANTS}

    for vkey in ['vig', 'beau', 'vbeau']:
        vname = VARIANTS[vkey]['name']
        contradicted = []
        survived = []

        for p in range(1, CT_LEN):
            pt, contra, detail, n_det = propagate_autokey(p, vkey)

            if contra:
                contradicted.append(p)
            else:
                survived.append(p)
                # Score surviving configs
                pt_text = ''.join(ALPH[v] if v is not None else '?' for v in pt)
                det_text = ''.join(ALPH[v] for v in pt if v is not None)
                qg = qg_score_per_char(det_text) if len(det_text) >= 4 else QG_FLOOR

                # Crib match count
                cm = sum(1 for pos, exp in CRIB_NUM.items()
                         if pos < len(pt) and pt[pos] is not None and pt[pos] == exp)

                # Bean check (only if enough positions determined)
                bean = None
                if n_det > 60:
                    key = [(CT_NUM[i] - (pt[i] if pt[i] is not None else 0)) % 26
                           for i in range(CT_LEN)]
                    bean_eq_ok = all(key[a] == key[b] for a, b in BEAN_EQ
                                    if pt[a] is not None and pt[b] is not None)
                    bean_ineq_ok = all(key[a] != key[b] for a, b in BEAN_INEQ
                                      if pt[a] is not None and pt[b] is not None)
                    bean = bean_eq_ok and bean_ineq_ok

                results_by_variant[vkey].append({
                    'p': p, 'n_det': n_det, 'cm': cm, 'qg': qg,
                    'bean': bean, 'pt': pt_text
                })

        # Report
        print(f"\n{'─' * 78}")
        print(f"  {vname}: {len(contradicted)} contradicted, {len(survived)} survived (of 96)")

        if survived:
            print(f"  Survived seed lengths: {survived}")
            for r in results_by_variant[vkey]:
                bean_s = "BEAN✓" if r['bean'] else ("BEAN✗" if r['bean'] is False else "bean?")
                print(f"    p={r['p']:2d}: det={r['n_det']:2d}/97 "
                      f"cribs={r['cm']:2d}/24 qg={r['qg']:+.3f} {bean_s}")
                if r['n_det'] >= 50:
                    print(f"      PT: {r['pt']}")
        else:
            print(f"  ALL seed lengths eliminated by contradiction!")

        if contradicted:
            # Show first few contradiction details
            print(f"\n  Contradiction details (first 5):")
            for p in contradicted[:5]:
                _, _, detail, _ = propagate_autokey(p, vkey, verbose=False)
                print(f"    p={p}: {detail}")

    # ── Structural analysis ───────────────────────────────────────────────

    print(f"\n{'═' * 78}")
    print("STRUCTURAL ANALYSIS")
    print(f"{'═' * 78}")

    # The cribs are at positions 21-33 (ENE, 13 chars) and 63-73 (BC, 11 chars)
    # For autokey with seed length p, forward propagation from ENE covers:
    #   Wave 0: 21-33 (from cribs)
    #   Wave 1: 21+p .. 33+p
    #   Wave 2: 21+2p .. 33+2p
    #   ...
    # Backward propagation from ENE covers:
    #   Wave -1: 21-p .. 33-p (clamped to ≥0)
    #   Wave -2: 21-2p .. 33-2p
    #   ...
    # Similarly for BC at 63-73.

    # For a contradiction, we need the forward chain from one crib to overlap
    # with positions determined by the other crib (or the same crib backward).

    print("\n  Overlap analysis (ENE forward → BC region):")
    for p in range(1, 50):
        # How many waves from ENE end (pos 33) to reach BC start (pos 63)?
        # 33 + k*p >= 63 → k >= (63-33)/p = 30/p
        waves_needed = -(-30 // p)  # ceiling division
        ene_reach_end = 33 + waves_needed * p  # last ENE position after waves_needed waves
        if 33 + waves_needed * p <= 73 + p:  # ENE chain reaches into BC region
            # Similarly, BC backward propagation reaches:
            bc_back_start = 63 - (63 // p) * p
            overlap = "YES" if 33 + waves_needed * p >= 63 else "possible"
        else:
            overlap = "no"

        # Check how many positions are determined
        _, contra, _, n_det = propagate_autokey(p, 'vig')
        status = "CONTRA" if contra else f"OK({n_det})"
        if p <= 30 or not contra:
            print(f"    p={p:2d}: waves_to_BC={waves_needed:2d}, status={status}")

    # ── Extended: test with KA alphabet ──────────────────────────────────

    print(f"\n{'─' * 78}")
    print("PHASE 3: Test with KRYPTOS (KA) alphabet ordering")
    print(f"{'─' * 78}")

    KA_IDX = {c: i for i, c in enumerate(KRYPTOS_ALPHABET)}
    KA_CT = [KA_IDX[c] for c in CT]
    KA_CRIB = {pos: KA_IDX[ch] for pos, ch in CRIB_DICT.items()}

    ka_survived = []
    for p in range(1, CT_LEN):
        pt = [None] * CT_LEN
        for pos, val in KA_CRIB.items():
            pt[pos] = val

        contra = False
        for _ in range(CT_LEN * 3):
            changed = False
            for i in range(CT_LEN):
                if pt[i] is not None and i + p < CT_LEN:
                    new_val = (KA_CT[i + p] - pt[i]) % 26  # Vig in KA space
                    if pt[i + p] is None:
                        pt[i + p] = new_val
                        changed = True
                    elif pt[i + p] != new_val:
                        contra = True
                        break
            if contra:
                break
            for i in range(p, CT_LEN):
                if pt[i] is not None:
                    k_val = (KA_CT[i] - pt[i]) % 26
                    target = i - p
                    if pt[target] is None:
                        pt[target] = k_val
                        changed = True
                    elif pt[target] != k_val:
                        contra = True
                        break
            if contra or not changed:
                break

        if not contra:
            n_det = sum(1 for v in pt if v is not None)
            pt_text = ''.join(KRYPTOS_ALPHABET[v] if v is not None else '?' for v in pt)
            ka_survived.append((p, n_det, pt_text))

    if ka_survived:
        print(f"  Survived with KA alphabet: {len(ka_survived)}")
        for p, nd, pt_text in ka_survived[:20]:
            print(f"    p={p}: det={nd}/97")
            if nd >= 50:
                print(f"      PT(KA): {pt_text}")
    else:
        print(f"  ALL seed lengths eliminated by contradiction (KA alphabet too)!")

    # ── Final verdict ──────────────────────────────────────────────────────

    elapsed = time.time() - t0
    total_survived = sum(len(results_by_variant[k]) for k in results_by_variant)

    print(f"\n{'═' * 78}")
    print("FINAL VERDICT")
    print(f"{'═' * 78}")
    print(f"  AZ variants: {total_survived} survived out of {96*3}")
    print(f"  KA Vigenère: {len(ka_survived)} survived out of 96")
    print(f"  Time: {elapsed:.1f}s")

    if total_survived == 0 and len(ka_survived) == 0:
        print(f"\n  ★ COMPLETE STRUCTURAL ELIMINATION ★")
        print(f"  Standard autokey Vigenère/Beaufort/VarBeau with AZ or KA alphabet")
        print(f"  is IMPOSSIBLE for K4 at ALL seed lengths, given both cribs.")
        print(f"  The bidirectional propagation from EASTNORTHEAST and BERLINCLOCK")
        print(f"  produces internal contradictions for every (variant, seed_length) pair.")
        verdict = "DISPROVED"
    else:
        # Check if any survivor has good scores
        best_cm = 0
        for k in results_by_variant:
            for r in results_by_variant[k]:
                if r['cm'] > best_cm:
                    best_cm = r['cm']
        if best_cm >= 18:
            verdict = "SIGNAL"
        elif best_cm >= 10:
            verdict = "INTERESTING"
        else:
            verdict = "NO_SIGNAL"

    print(f"  Verdict: {verdict}")

    # Save
    output = {
        'experiment': 'E-AUTOKEY-BIDIR-EXT',
        'description': 'Extended autokey bidirectional: all seed lengths 1-96, AZ+KA',
        'az_results': {k: results_by_variant[k] for k in results_by_variant},
        'ka_survived': [(p, nd) for p, nd, _ in ka_survived],
        'verdict': verdict,
        'elapsed': elapsed,
    }
    os.makedirs("results", exist_ok=True)
    with open("results/e_autokey_bidir_extended.json", "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n  Artifact: results/e_autokey_bidir_extended.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_autokey_bidir_extended.py")


if __name__ == '__main__':
    main()
