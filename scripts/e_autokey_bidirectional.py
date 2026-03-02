#!/usr/bin/env python3
"""Autokey Vigenère bidirectional back-derivation from BERLINCLOCK crib.

Approach:
  For plaintext-autokey Vigenère, the key sequence is:
    K[i] = seed[i]        for i < p  (seed length)
    K[i] = PT[i - p]      for i >= p

  Encryption: CT[i] = (PT[i] + K[i]) mod 26
  Decryption: PT[i] = (CT[i] - K[i]) mod 26

  Also test Beaufort and Variant Beaufort:
    Beaufort:  CT[i] = (K[i] - PT[i]) mod 26  → PT[i] = (K[i] - CT[i]) mod 26
    VarBeau:   CT[i] = (PT[i] - K[i]) mod 26  → PT[i] = (CT[i] + K[i]) mod 26

Strategy:
  1. Use BERLINCLOCK (positions 63-73) to compute K at those positions.
  2. Since K[i] = PT[i-p] for i >= p, we get PT at positions (63-p) through (73-p).
  3. If (63-p) through (73-p) partially overlaps the seed region (< p),
     we directly derive seed characters.
  4. Propagate bidirectionally until all determinable positions are filled.
  5. Also use EASTNORTHEAST (positions 21-33) the same way.
  6. Check for internal contradictions (two derivations yield different PT at same pos).
  7. Score with quadgram statistics and crib match counts.

Seed lengths: 1 through 15.
All three cipher variants tested.

Prior work: E-06 tested PT-autokey propagation. This script provides a detailed
trace of the back-derivation mechanics and uses the framework's scoring module.
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_WORDS,
    BEAN_EQ, BEAN_INEQ,
)

# ── Setup ──────────────────────────────────────────────────────────────────

CT_NUM = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_NUM = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# Load quadgram data
QG_PATH = "data/english_quadgrams.json"
QUADGRAMS = {}
if os.path.exists(QG_PATH):
    with open(QG_PATH) as f:
        QUADGRAMS = json.load(f)
QG_FLOOR = -10.0  # Floor for unknown quadgrams


def qg_score(text):
    """Quadgram log-probability score (total)."""
    if not QUADGRAMS or len(text) < 4:
        return QG_FLOOR * max(len(text) - 3, 1)
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        score += QUADGRAMS.get(qg, QG_FLOOR)
    return score


def qg_score_per_char(text):
    """Quadgram score normalized per character."""
    if len(text) < 4:
        return QG_FLOOR
    return qg_score(text) / (len(text) - 3)


def count_crib_matches(pt):
    """Count how many crib positions match in a plaintext list."""
    matches = 0
    ene_matches = 0
    bc_matches = 0
    for pos, expected in CRIB_NUM.items():
        if pos < len(pt) and pt[pos] is not None and pt[pos] == expected:
            matches += 1
            if 21 <= pos <= 33:
                ene_matches += 1
            if 63 <= pos <= 73:
                bc_matches += 1
    return matches, ene_matches, bc_matches


def check_bean(pt):
    """Check Bean constraints. Assumes all positions filled (use 0 for unknown)."""
    key = [(CT_NUM[i] - (pt[i] if pt[i] is not None else 0)) % MOD for i in range(CT_LEN)]
    for a, b in BEAN_EQ:
        if pt[a] is not None and pt[b] is not None:
            if key[a] != key[b]:
                return False
    for a, b in BEAN_INEQ:
        if pt[a] is not None and pt[b] is not None:
            if key[a] == key[b]:
                return False
    return True


def pt_to_text(pt):
    """Convert PT num list to string (? for None)."""
    return ''.join(ALPH[v] if v is not None else '?' for v in pt)


# ── Cipher variant definitions ────────────────────────────────────────────

VARIANTS = {
    'vigenere': {
        'name': 'Vigenère',
        # CT = (PT + K) mod 26
        'key_from_ct_pt': lambda ct, pt: (ct - pt) % MOD,
        'pt_from_ct_key': lambda ct, k: (ct - k) % MOD,
    },
    'beaufort': {
        'name': 'Beaufort',
        # CT = (K - PT) mod 26
        'key_from_ct_pt': lambda ct, pt: (ct + pt) % MOD,
        'pt_from_ct_key': lambda ct, k: (k - ct) % MOD,
    },
    'var_beaufort': {
        'name': 'Variant Beaufort',
        # CT = (PT - K) mod 26
        'key_from_ct_pt': lambda ct, pt: (pt - ct) % MOD,
        'pt_from_ct_key': lambda ct, k: (ct + k) % MOD,
    },
}


def autokey_bidirectional(p, variant_key, verbose=False):
    """Attempt autokey decryption with seed length p using bidirectional
    back-derivation from known cribs.

    Returns (pt, contradiction, n_determined, crib_matches, ene_matches, bc_matches)
    """
    variant = VARIANTS[variant_key]
    key_from_ct_pt = variant['key_from_ct_pt']
    pt_from_ct_key = variant['pt_from_ct_key']

    pt = [None] * CT_LEN
    seed = [None] * p  # Track derived seed values

    # Step 1: Seed PT from both known cribs
    for pos, val in CRIB_NUM.items():
        pt[pos] = val

    # Step 2: Back-derive from known PT positions
    # If PT[i] is known and i >= p, then K[i] = key_from_ct_pt(CT[i], PT[i])
    # And K[i] = PT[i-p] (autokey), so PT[i-p] = K[i]
    #
    # If PT[i] is known and i+p < CT_LEN, then K[i+p] = PT[i]
    # So PT[i+p] = pt_from_ct_key(CT[i+p], PT[i])

    # Iterative propagation (bidirectional)
    max_iters = CT_LEN * 2  # Safety limit
    contradiction = False

    for iteration in range(max_iters):
        changed = False

        # Forward propagation: PT[i] known → K[i+p] = PT[i] → PT[i+p]
        for i in range(CT_LEN):
            if pt[i] is not None and i + p < CT_LEN:
                new_val = pt_from_ct_key(CT_NUM[i + p], pt[i])
                if pt[i + p] is None:
                    pt[i + p] = new_val
                    changed = True
                elif pt[i + p] != new_val:
                    contradiction = True
                    if verbose:
                        print(f"  CONTRADICTION at pos {i+p}: "
                              f"existing={ALPH[pt[i+p]]}, "
                              f"derived={ALPH[new_val]} "
                              f"(from PT[{i}]={ALPH[pt[i]]} as K[{i+p}])")
                    return pt, True, 0, 0, 0, 0

        # Backward propagation: PT[i] known, i >= p → K[i] = key_from_ct_pt(CT[i], PT[i]) = PT[i-p]
        for i in range(p, CT_LEN):
            if pt[i] is not None:
                k_val = key_from_ct_pt(CT_NUM[i], pt[i])
                target = i - p
                if target >= 0:
                    if target < p:
                        # This determines a seed character
                        if seed[target] is None:
                            seed[target] = k_val
                        elif seed[target] != k_val:
                            contradiction = True
                            if verbose:
                                print(f"  SEED CONTRADICTION at seed[{target}]: "
                                      f"existing={ALPH[seed[target]]}, "
                                      f"derived={ALPH[k_val]} "
                                      f"(from PT[{i}]={ALPH[pt[i]]})")
                            return pt, True, 0, 0, 0, 0

                    if pt[target] is None:
                        pt[target] = k_val
                        changed = True
                    elif pt[target] != k_val:
                        contradiction = True
                        if verbose:
                            print(f"  CONTRADICTION at pos {target}: "
                                  f"existing={ALPH[pt[target]]}, "
                                  f"derived={ALPH[k_val]} "
                                  f"(backward from PT[{i}]={ALPH[pt[i]]})")
                        return pt, True, 0, 0, 0, 0

        if not changed:
            break

    n_determined = sum(1 for v in pt if v is not None)
    cm, ene_m, bc_m = count_crib_matches(pt)

    return pt, contradiction, n_determined, cm, ene_m, bc_m


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 78)
    print("AUTOKEY VIGENÈRE — BIDIRECTIONAL BACK-DERIVATION FROM BERLINCLOCK")
    print("=" * 78)
    print(f"  CT: {CT}")
    print(f"  CT length: {CT_LEN}")
    print(f"  Cribs: EASTNORTHEAST@21-33, BERLINCLOCK@63-73 ({N_CRIBS} total)")
    print(f"  Quadgrams loaded: {len(QUADGRAMS):,}")
    print(f"  Seed lengths to test: 1-15")
    print(f"  Variants: Vigenère, Beaufort, Variant Beaufort")
    sys.stdout.flush()

    t0 = time.time()
    all_results = []

    for variant_key in ['vigenere', 'beaufort', 'var_beaufort']:
        variant_name = VARIANTS[variant_key]['name']
        print(f"\n{'─' * 78}")
        print(f"  Variant: {variant_name}")
        print(f"{'─' * 78}")
        sys.stdout.flush()

        for p in range(1, 16):
            pt, contradiction, n_det, cm, ene_m, bc_m = autokey_bidirectional(
                p, variant_key, verbose=(p <= 5)
            )

            if contradiction:
                status = "CONTRADICTION"
                qg = QG_FLOOR
                bean = False
            else:
                # Build text from determined positions
                pt_text = pt_to_text(pt)
                # For quadgram scoring, use only contiguous determined regions
                # (avoid penalizing gaps)
                determined_text = ''.join(ALPH[v] for v in pt if v is not None)
                qg = qg_score_per_char(determined_text) if len(determined_text) >= 4 else QG_FLOOR
                bean = check_bean(pt) if n_det > 60 else None
                status = "OK"

            # Derive seed info
            seed_chars = []
            if not contradiction:
                key_from = VARIANTS[variant_key]['key_from_ct_pt']
                for i in range(p, CT_LEN):
                    if pt[i] is not None:
                        k_val = key_from(CT_NUM[i], pt[i])
                        target = i - p
                        if target < p:
                            seed_chars.append((target, ALPH[k_val]))
                seed_chars = sorted(set(seed_chars))

            result = {
                'variant': variant_key,
                'seed_len': p,
                'status': status,
                'n_determined': n_det,
                'crib_matches': cm,
                'ene_matches': ene_m,
                'bc_matches': bc_m,
                'qg_per_char': round(qg, 3) if qg != QG_FLOOR else None,
                'bean': bean,
                'seed_derived': seed_chars,
            }
            all_results.append(result)

            # Print result
            bean_str = "BEAN✓" if bean else ("BEAN✗" if bean is False else "bean?")
            seed_str = ''.join(ch for _, ch in seed_chars) if seed_chars else '?'

            marker = ""
            if contradiction:
                marker = "  ✗ ELIMINATED"
            elif cm == N_CRIBS:
                marker = "  ★ FULL CRIB MATCH"
            elif cm >= 18:
                marker = "  ▶ SIGNAL"
            elif cm >= 10:
                marker = "  ▷ interesting"

            print(f"  p={p:2d}: {status:13s} det={n_det:2d}/{CT_LEN} "
                  f"cribs={cm:2d}/24 (ENE={ene_m:2d} BC={bc_m:2d}) "
                  f"qg={qg:+.3f} {bean_str} seed=[{seed_str}]{marker}")

            # Show full PT for promising results or fully determined
            if not contradiction and (cm >= 18 or n_det >= 90):
                pt_text = pt_to_text(pt)
                print(f"         PT: {pt_text}")

                # Show which positions are determined
                det_mask = ''.join('█' if v is not None else '·' for v in pt)
                print(f"       mask: {det_mask}")

            sys.stdout.flush()

    # ── Summary ────────────────────────────────────────────────────────────

    elapsed = time.time() - t0

    print(f"\n{'═' * 78}")
    print("SUMMARY")
    print(f"{'═' * 78}")

    # Count eliminations
    eliminated = sum(1 for r in all_results if r['status'] == 'CONTRADICTION')
    survived = sum(1 for r in all_results if r['status'] == 'OK')

    print(f"  Total configs: {len(all_results)} (3 variants × 15 seed lengths)")
    print(f"  Eliminated by contradiction: {eliminated}")
    print(f"  Survived: {survived}")
    print(f"  Time: {elapsed:.1f}s")

    # Best by crib matches
    ok_results = [r for r in all_results if r['status'] == 'OK']
    if ok_results:
        best_crib = max(ok_results, key=lambda r: (r['crib_matches'], r.get('qg_per_char') or -99))
        print(f"\n  Best by cribs: {best_crib['variant']} p={best_crib['seed_len']} "
              f"→ {best_crib['crib_matches']}/24 cribs, "
              f"qg={best_crib.get('qg_per_char', '?')}")

        # Best by quadgram (among those with BC cribs matching)
        bc_ok = [r for r in ok_results if r['bc_matches'] == 11]
        if bc_ok:
            best_qg = max(bc_ok, key=lambda r: r.get('qg_per_char') or -99)
            print(f"  Best QG (BC=11): {best_qg['variant']} p={best_qg['seed_len']} "
                  f"→ qg={best_qg.get('qg_per_char', '?')}, "
                  f"cribs={best_qg['crib_matches']}/24")

    # ── Extended analysis: for non-contradicted configs, try all 26^k primers ──
    # for seed positions that are NOT determined by the back-derivation

    print(f"\n{'─' * 78}")
    print("PHASE 2: Exhaustive primer search for non-contradicted configs")
    print(f"{'─' * 78}")
    sys.stdout.flush()

    best_overall = {'score': -999, 'config': None, 'pt': '', 'cribs': 0}

    for r in ok_results:
        p = r['seed_len']
        variant_key = r['variant']
        variant = VARIANTS[variant_key]
        key_from = variant['key_from_ct_pt']
        pt_from = variant['pt_from_ct_key']

        # First, re-derive the PT using only cribs at known positions
        # Collect determined seed positions
        seed_known = {}
        # Re-run propagation to get the partial PT
        pt_base, _, _, _, _, _ = autokey_bidirectional(p, variant_key)

        # Find which seed positions are determined
        for i in range(p, CT_LEN):
            if pt_base[i] is not None:
                k_val = key_from(CT_NUM[i], pt_base[i])
                target = i - p
                if 0 <= target < p:
                    seed_known[target] = k_val

        # How many seed positions are UNdetermined?
        undetermined_seed = [i for i in range(p) if i not in seed_known]
        n_undet = len(undetermined_seed)

        if n_undet == 0:
            # Full seed is determined — just score the result
            determined_text = ''.join(ALPH[v] for v in pt_base if v is not None)
            qg = qg_score_per_char(determined_text) if len(determined_text) >= 4 else QG_FLOOR
            cm, ene_m, bc_m = count_crib_matches(pt_base)
            bean = check_bean(pt_base)

            if cm > best_overall['cribs'] or (cm == best_overall['cribs'] and qg > best_overall['score']):
                best_overall = {
                    'score': qg,
                    'config': f"{variant_key} p={p}",
                    'pt': pt_to_text(pt_base),
                    'cribs': cm,
                    'bean': bean,
                }

            print(f"  {variant_key} p={p}: seed fully determined "
                  f"[{''.join(ALPH[seed_known[i]] for i in range(p))}] "
                  f"cribs={cm}/24 qg={qg:+.3f} {'BEAN✓' if bean else 'BEAN✗'}")
            if cm >= 18:
                print(f"    PT: {pt_to_text(pt_base)}")
            sys.stdout.flush()

        elif n_undet <= 4:
            # Brute-force the undetermined seed positions
            total_combos = 26 ** n_undet
            print(f"  {variant_key} p={p}: {n_undet} undetermined seed positions "
                  f"({undetermined_seed}), testing {total_combos} combos...")
            sys.stdout.flush()

            local_best_cribs = 0
            local_best_qg = QG_FLOOR
            local_best_pt = ''

            for combo_idx in range(total_combos):
                # Decode combo_idx into seed values for undetermined positions
                trial_seed = dict(seed_known)  # copy known
                tmp = combo_idx
                for pos in undetermined_seed:
                    trial_seed[pos] = tmp % 26
                    tmp //= 26

                # Build full plaintext
                pt_trial = [None] * CT_LEN
                seed_list = [trial_seed.get(i, 0) for i in range(p)]

                # Decrypt forward
                for i in range(CT_LEN):
                    if i < p:
                        k = seed_list[i]
                    else:
                        if pt_trial[i - p] is None:
                            break  # Can't continue without prior PT
                        k = pt_trial[i - p]
                    pt_trial[i] = pt_from(CT_NUM[i], k)

                # Check crib matches
                cm_trial, ene_trial, bc_trial = count_crib_matches(pt_trial)

                if cm_trial > local_best_cribs:
                    local_best_cribs = cm_trial
                    pt_text = ''.join(ALPH[v] if v is not None else '?' for v in pt_trial)
                    local_best_pt = pt_text
                    det_text = ''.join(ALPH[v] for v in pt_trial if v is not None)
                    local_best_qg = qg_score_per_char(det_text) if len(det_text) >= 4 else QG_FLOOR

                if cm_trial >= 20:
                    pt_text = ''.join(ALPH[v] if v is not None else '?' for v in pt_trial)
                    det_text = ''.join(ALPH[v] for v in pt_trial if v is not None)
                    qg_val = qg_score_per_char(det_text)
                    bean = check_bean(pt_trial)
                    seed_str = ''.join(ALPH[trial_seed[i]] for i in range(p))
                    print(f"    ★ cribs={cm_trial}/24 seed=[{seed_str}] qg={qg_val:+.3f} "
                          f"{'BEAN✓' if bean else 'BEAN✗'}")
                    print(f"      PT: {pt_text}")

                    if cm_trial > best_overall['cribs'] or \
                       (cm_trial == best_overall['cribs'] and qg_val > best_overall['score']):
                        best_overall = {
                            'score': qg_val,
                            'config': f"{variant_key} p={p} seed={seed_str}",
                            'pt': pt_text,
                            'cribs': cm_trial,
                            'bean': bean,
                        }

            print(f"    best: cribs={local_best_cribs}/24 qg={local_best_qg:+.3f}")
            if local_best_cribs >= 18:
                print(f"    PT: {local_best_pt}")
            sys.stdout.flush()

        else:
            # Too many undetermined positions for brute force
            # Use a smarter approach: fix the forward chain from position 0
            # and only try all 26 values for seed[0..p-1] that aren't determined

            if n_undet > 6:
                print(f"  {variant_key} p={p}: {n_undet} undetermined seed positions — "
                      f"too many for brute force (26^{n_undet} = {26**n_undet:,}), skipping")
                sys.stdout.flush()
                continue

            total_combos = 26 ** n_undet
            print(f"  {variant_key} p={p}: {n_undet} undetermined seed positions "
                  f"({undetermined_seed}), testing {total_combos:,} combos...")
            sys.stdout.flush()

            local_best_cribs = 0

            for combo_idx in range(total_combos):
                trial_seed = dict(seed_known)
                tmp = combo_idx
                for pos in undetermined_seed:
                    trial_seed[pos] = tmp % 26
                    tmp //= 26

                # Build full plaintext forward
                pt_trial = [None] * CT_LEN
                seed_list = [trial_seed.get(i, 0) for i in range(p)]

                for i in range(CT_LEN):
                    if i < p:
                        k = seed_list[i]
                    else:
                        if pt_trial[i - p] is None:
                            break
                        k = pt_trial[i - p]
                    pt_trial[i] = pt_from(CT_NUM[i], k)

                cm_trial, ene_trial, bc_trial = count_crib_matches(pt_trial)

                if cm_trial > local_best_cribs:
                    local_best_cribs = cm_trial

                if cm_trial >= 20:
                    pt_text = ''.join(ALPH[v] if v is not None else '?' for v in pt_trial)
                    det_text = ''.join(ALPH[v] for v in pt_trial if v is not None)
                    qg_val = qg_score_per_char(det_text) if len(det_text) >= 4 else QG_FLOOR
                    bean = check_bean(pt_trial)
                    seed_str = ''.join(ALPH[trial_seed[i]] for i in range(p))
                    print(f"    ★ cribs={cm_trial}/24 seed=[{seed_str}] qg={qg_val:+.3f} "
                          f"{'BEAN✓' if bean else 'BEAN✗'}")
                    print(f"      PT: {pt_text}")

                    if cm_trial > best_overall['cribs'] or \
                       (cm_trial == best_overall['cribs'] and qg_val > best_overall['score']):
                        best_overall = {
                            'score': qg_val,
                            'config': f"{variant_key} p={p} seed={seed_str}",
                            'pt': pt_text,
                            'cribs': cm_trial,
                            'bean': bean,
                        }

            print(f"    best: cribs={local_best_cribs}/24")
            sys.stdout.flush()

    # ── Final summary ──────────────────────────────────────────────────────

    print(f"\n{'═' * 78}")
    print("FINAL VERDICT")
    print(f"{'═' * 78}")
    print(f"  Best overall: {best_overall.get('config', 'none')}")
    print(f"  Cribs: {best_overall.get('cribs', 0)}/24")
    print(f"  QG/char: {best_overall.get('score', QG_FLOOR):+.3f}")
    print(f"  Bean: {best_overall.get('bean', False)}")
    if best_overall.get('pt'):
        print(f"  PT: {best_overall['pt']}")

    total_time = time.time() - t0
    print(f"\n  Total time: {total_time:.1f}s")

    # Classification
    max_cribs = best_overall.get('cribs', 0)
    if max_cribs == 24 and best_overall.get('bean'):
        verdict = "BREAKTHROUGH"
    elif max_cribs >= 18:
        verdict = "SIGNAL"
    elif max_cribs >= 10:
        verdict = "INTERESTING (likely noise at these parameters)"
    else:
        verdict = "NO SIGNAL — autokey at noise floor"

    print(f"  Verdict: {verdict}")

    # Save results
    output = {
        'experiment': 'E-AUTOKEY-BIDIR',
        'description': 'Autokey Vigenere bidirectional back-derivation from BERLINCLOCK',
        'variants_tested': ['vigenere', 'beaufort', 'var_beaufort'],
        'seed_lengths': list(range(1, 16)),
        'total_configs': len(all_results),
        'eliminated': eliminated,
        'survived': survived,
        'best_overall': best_overall,
        'verdict': verdict,
        'elapsed': total_time,
        'all_results': all_results,
    }
    os.makedirs("results", exist_ok=True)
    with open("results/e_autokey_bidirectional.json", "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\n  Artifact: results/e_autokey_bidirectional.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_autokey_bidirectional.py")


if __name__ == '__main__':
    main()
