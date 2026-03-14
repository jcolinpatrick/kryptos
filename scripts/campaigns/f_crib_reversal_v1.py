#!/usr/bin/env python3
"""
Cipher: Crib position reversal — cribs in PT73 space, not CT97 space
Family: campaigns
Status: active
Keyspace: SA optimization of 24-null mask × 6 keywords × 4 cipher types × 2 alphabets
Last run: never
Best score: n/a

CRIB POSITION REVERSAL HYPOTHESIS
===================================
All prior null-mask tests assumed cribs are at positions 21-33 and 63-73 in
the 97-char CARVED text. After removing nulls, crib positions shift based on
how many nulls precede each crib. This means the null mask must carefully
avoid disrupting crib alignment.

THIS TEST reverses that assumption:
  Model: CT97 → remove 24 nulls → CT73 → decrypt → PT73
  Cribs are at FIXED positions 21-33 and 63-73 in PT73 (the 73-char plaintext).
  The null mask is FREE to remove ANY 24 positions — no constraint on crib locations.

This is a major escape hatch because:
  1. The null mask has C(97,24) ≈ 4.5e20 possibilities — far too many to exhaust
  2. Without crib-position constraints on the mask, every prior elimination is invalidated
  3. If correct, the scoring landscape changes completely

Ciphers tested:
  - Simple Vigenere (AZ, KA)
  - Beaufort (AZ, KA)
  - Autokey PT-feedback (AZ, KA) — both vig and beau variants
  - Also: direct on all 97 chars (baseline, known eliminated)

Keywords: KRYPTOS, DEFECTOR, KOMPASS, ABSCISSA, COLOPHON, PALIMPSEST

SA: 30 restarts × 6000 steps each per cipher/keyword combo.
"""

import sys, random, math, time, json
sys.path.insert(0, 'src')

from kryptos.kernel.constants import CT

# ── Constants ────────────────────────────────────────────────────────────────
CT97     = CT
N        = 97
N_NULLS  = 24
N_PT     = 73

ENE_WORD  = "EASTNORTHEAST"   # 13 chars
BCL_WORD  = "BERLINCLOCK"     # 11 chars
# In this model, cribs are at FIXED positions in the 73-char plaintext
ENE_START = 21   # PT73[21:34]
BCL_START = 63   # PT73[63:74]

ALL_POS   = list(range(N))

KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_IDX = {c: i for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ")}

# ── Cipher implementations ──────────────────────────────────────────────────

def vigenere_decrypt(ct_str, keyword, use_ka=False):
    """Decrypt using repeating-key Vigenere. PT = (CT - K) mod 26."""
    if use_ka:
        alpha = KA_STR
        idx = KA_IDX
    else:
        alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        idx = AZ_IDX
    kw_indices = [idx[c] for c in keyword.upper()]
    kw_len = len(kw_indices)
    result = []
    for i, c in enumerate(ct_str):
        ci = idx[c]
        ki = kw_indices[i % kw_len]
        pi = (ci - ki) % 26
        result.append(alpha[pi])
    return ''.join(result)

def beaufort_decrypt(ct_str, keyword, use_ka=False):
    """Decrypt using Beaufort. PT = (K - CT) mod 26."""
    if use_ka:
        alpha = KA_STR
        idx = KA_IDX
    else:
        alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        idx = AZ_IDX
    kw_indices = [idx[c] for c in keyword.upper()]
    kw_len = len(kw_indices)
    result = []
    for i, c in enumerate(ct_str):
        ci = idx[c]
        ki = kw_indices[i % kw_len]
        pi = (ki - ci) % 26
        result.append(alpha[pi])
    return ''.join(result)

def autokey_vig_decrypt(ct_str, keyword, use_ka=False):
    """Autokey Vigenere decrypt. PT-feedback: key = keyword || PT.
    Decrypt: PT[i] = (CT[i] - K[i]) mod 26, K[i] = keyword[i] if i < L else PT[i-L]."""
    if use_ka:
        alpha = KA_STR
        idx = KA_IDX
    else:
        alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        idx = AZ_IDX
    kw_indices = [idx[c] for c in keyword.upper()]
    L = len(kw_indices)
    pt_indices = []
    result = []
    for i, c in enumerate(ct_str):
        ci = idx[c]
        if i < L:
            ki = kw_indices[i]
        else:
            ki = pt_indices[i - L]
        pi = (ci - ki) % 26
        pt_indices.append(pi)
        result.append(alpha[pi])
    return ''.join(result)

def autokey_beau_decrypt(ct_str, keyword, use_ka=False):
    """Autokey Beaufort decrypt. PT-feedback: key = keyword || PT.
    Decrypt: PT[i] = (K[i] - CT[i]) mod 26, K[i] = keyword[i] if i < L else PT[i-L]."""
    if use_ka:
        alpha = KA_STR
        idx = KA_IDX
    else:
        alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        idx = AZ_IDX
    kw_indices = [idx[c] for c in keyword.upper()]
    L = len(kw_indices)
    pt_indices = []
    result = []
    for i, c in enumerate(ct_str):
        ci = idx[c]
        if i < L:
            ki = kw_indices[i]
        else:
            ki = pt_indices[i - L]
        pi = (ki - ci) % 26
        pt_indices.append(pi)
        result.append(alpha[pi])
    return ''.join(result)

# ── Scoring ──────────────────────────────────────────────────────────────────

def count_crib_hits_fixed(pt73, ene_start=ENE_START, bcl_start=BCL_START):
    """Count crib matches at FIXED positions in PT73.
    Default: ENE at 21-33, BCL at 63-73.
    NOTE: Position 73 exceeds PT73 bounds (indices 0-72), so the last char
    of BERLINCLOCK ('K') cannot match when bcl_start=63. Max possible = 23/24.
    We handle this gracefully by bounds-checking each position."""
    n = len(pt73)
    ene = sum(1 for j, c in enumerate(ENE_WORD)
              if ene_start + j < n and pt73[ene_start + j] == c)
    bcl = sum(1 for j, c in enumerate(BCL_WORD)
              if bcl_start + j < n and pt73[bcl_start + j] == c)
    return ene + bcl, ene, bcl

# ── SA core ──────────────────────────────────────────────────────────────────

CIPHER_FNS = {
    'vig':         vigenere_decrypt,
    'beau':        beaufort_decrypt,
    'autokey_vig': autokey_vig_decrypt,
    'autokey_beau':autokey_beau_decrypt,
}

KEYWORDS = ['KRYPTOS', 'DEFECTOR', 'KOMPASS', 'ABSCISSA', 'COLOPHON', 'PALIMPSEST']

def evaluate(null_set_frozen, cipher_fn, keyword, use_ka,
             ene_start=ENE_START, bcl_start=BCL_START):
    """Remove nulls, decrypt 73-char text, score cribs at fixed PT73 positions."""
    ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set_frozen)
    assert len(ct73) == N_PT, f"Expected 73 chars, got {len(ct73)}"
    pt73 = cipher_fn(ct73, keyword, use_ka)
    total, ene, bcl = count_crib_hits_fixed(pt73, ene_start, bcl_start)
    return total, ene, bcl, pt73

def sa_optimize(cipher_fn, keyword, use_ka, n_restarts=30, n_steps=6000,
                seed_base=0, ene_start=ENE_START, bcl_start=BCL_START):
    """Run SA to find best 24-null mask for fixed-position cribs in PT73."""
    global_best_score = 0
    global_best_null = None
    global_best_pt = ""
    global_best_ene = 0
    global_best_bcl = 0

    for restart in range(n_restarts):
        rng = random.Random(seed_base + restart * 137)
        null_set = set(rng.sample(ALL_POS, N_NULLS))
        non_null = set(ALL_POS) - null_set

        score, _, _, _ = evaluate(frozenset(null_set), cipher_fn, keyword, use_ka,
                                  ene_start, bcl_start)
        best_sc = score
        best_null = frozenset(null_set)

        T0 = 0.8
        Tf = 0.003
        for step in range(n_steps):
            T = T0 * (Tf / T0) ** (step / n_steps)
            # Swap one null with one non-null
            out = rng.choice(list(null_set))
            into = rng.choice(list(non_null))
            null_set.discard(out)
            null_set.add(into)
            non_null.discard(into)
            non_null.add(out)

            new_sc, _, _, _ = evaluate(frozenset(null_set), cipher_fn, keyword, use_ka,
                                       ene_start, bcl_start)
            delta = new_sc - score
            if delta > 0 or rng.random() < math.exp(delta / max(T, 1e-10)):
                score = new_sc
                if score > best_sc:
                    best_sc = score
                    best_null = frozenset(null_set)
            else:
                # Revert
                null_set.discard(into)
                null_set.add(out)
                non_null.discard(out)
                non_null.add(into)

        # Evaluate best from this restart
        total, ene, bcl, pt = evaluate(best_null, cipher_fn, keyword, use_ka,
                                       ene_start, bcl_start)
        if total > global_best_score:
            global_best_score = total
            global_best_null = best_null
            global_best_pt = pt
            global_best_ene = ene
            global_best_bcl = bcl

    return global_best_score, global_best_ene, global_best_bcl, global_best_pt, global_best_null

# ── Direct (no nulls) baseline ──────────────────────────────────────────────

def direct_baseline():
    """Test direct decryption of all 97 chars, check positions 21-33 and 63-73.
    This is the known-eliminated baseline for comparison."""
    print("=" * 70)
    print("PHASE 0: DIRECT BASELINE (no null removal, cribs at 21-33/63-73 in PT97)")
    print("=" * 70)
    results = []
    for kw in KEYWORDS:
        for cipher_name, cipher_fn in CIPHER_FNS.items():
            for alpha_name, use_ka in [('AZ', False), ('KA', True)]:
                pt97 = cipher_fn(CT97, kw, use_ka)
                # Check cribs at standard positions in PT97
                ene = sum(1 for j, c in enumerate(ENE_WORD)
                          if ENE_START + j < len(pt97) and pt97[ENE_START + j] == c)
                bcl = sum(1 for j, c in enumerate(BCL_WORD)
                          if BCL_START + j < len(pt97) and pt97[BCL_START + j] == c)
                total = ene + bcl
                label = f"{kw}:{alpha_name}_{cipher_name}"
                results.append((total, ene, bcl, label, pt97))
    results.sort(key=lambda x: -x[0])
    print(f"  Tested {len(results)} configs")
    print(f"  Best: {results[0][0]}/24 (ene={results[0][1]}/13 bcl={results[0][2]}/11) {results[0][3]}")
    for total, ene, bcl, label, pt in results[:5]:
        print(f"    {total:2d}/24 ene={ene:2d}/13 bcl={bcl:2d}/11  {label}")
    print()
    return results

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    t_start = time.time()

    print("=" * 70)
    print("CRIB POSITION REVERSAL ATTACK")
    print("=" * 70)
    print(f"CT97  = {CT97}")
    print(f"Model : CT97 -> remove 24 nulls -> CT73 -> decrypt -> PT73")
    print(f"Key   : Null mask is FREE (any 24 of 97 positions)")
    print(f"SA    : 30 restarts x 6000 steps per config")
    print()
    print("BOUNDARY NOTE: PT73 has indices 0-72. BERLINCLOCK at positions 63-73")
    print("  would need index 73 (out of bounds). So with BCL@63:")
    print("  - Max achievable = 23/24 (last K of BERLINCLOCK unreachable)")
    print("  We also test BCL@62 (shifted -1) where max = 24/24.")
    print()

    # Define crib position variants to test
    CRIB_VARIANTS = [
        (21, 63, "ENE@21,BCL@63 (standard, max=23)"),
        (21, 62, "ENE@21,BCL@62 (shifted BCL, max=24)"),
        (20, 62, "ENE@20,BCL@62 (both shifted -1, max=24)"),
        (21, 60, "ENE@21,BCL@60 (BCL shifted -3, max=24)"),
    ]

    # Phase 0: baseline
    baseline_results = direct_baseline()

    # Phase 1: SA with null removal — cribs at fixed PT73 positions
    all_results = []

    for ene_s, bcl_s, variant_label in CRIB_VARIANTS:
        # Compute max possible score for this variant
        max_ene = sum(1 for j in range(len(ENE_WORD)) if ene_s + j < N_PT)
        max_bcl = sum(1 for j in range(len(BCL_WORD)) if bcl_s + j < N_PT)
        max_possible = max_ene + max_bcl

        print("=" * 70)
        print(f"PHASE 1: NULL MASK SA — {variant_label}")
        print(f"  Max possible score: {max_possible}/24")
        print(f"  Null mask is completely FREE (any 24 of 97)")
        print(f"  Testing: 4 cipher types x 2 alphabets x 6 keywords = 48 configs")
        print("=" * 70)
        print()

        config_count = 0
        total_configs = len(KEYWORDS) * len(CIPHER_FNS) * 2

        for kw in KEYWORDS:
            for cipher_name, cipher_fn in CIPHER_FNS.items():
                for alpha_name, use_ka in [('AZ', False), ('KA', True)]:
                    config_count += 1
                    label = f"{kw}:{alpha_name}_{cipher_name}|{variant_label[:12]}"
                    seed_base = hash(label) % 100000

                    t_cfg = time.time()
                    score, ene, bcl, pt, null_set = sa_optimize(
                        cipher_fn, kw, use_ka,
                        n_restarts=30, n_steps=6000,
                        seed_base=seed_base,
                        ene_start=ene_s, bcl_start=bcl_s,
                    )
                    elapsed_cfg = time.time() - t_cfg

                    all_results.append({
                        'score': score,
                        'ene': ene,
                        'bcl': bcl,
                        'label': label,
                        'pt': pt,
                        'mask': sorted(null_set) if null_set else [],
                        'elapsed': elapsed_cfg,
                        'max_possible': max_possible,
                        'ene_start': ene_s,
                        'bcl_start': bcl_s,
                    })

                    tag = ""
                    if score >= 15:
                        tag = " *** BREAKTHROUGH ***"
                    elif score >= 12:
                        tag = " ** HIGH **"
                    elif score >= 10:
                        tag = " * INTERESTING *"

                    print(f"  [{config_count:2d}/{total_configs}] {label:50s}  "
                          f"{score:2d}/{max_possible} (ene={ene:2d}/{max_ene} bcl={bcl:2d}/{max_bcl})  "
                          f"{elapsed_cfg:5.1f}s{tag}")

                    if score >= 12:
                        print(f"         PT  = {pt}")
                        print(f"         mask= {sorted(null_set)}")
                        ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
                        print(f"         CT73= {ct73}")

                    sys.stdout.flush()

            print()  # Blank line between keywords
        print()

    # Phase 2: Extended SA for any promising results (score >= 12)
    promising = [r for r in all_results if r['score'] >= 12]
    if promising:
        print("=" * 70)
        print(f"PHASE 2: EXTENDED SA FOR {len(promising)} PROMISING CONFIGS (score >= 12)")
        print("  100 restarts x 15000 steps each")
        print("=" * 70)
        print()

        for r in promising:
            label = r['label']
            base_label = label.split('|')[0]
            parts = base_label.split(':')
            kw = parts[0]
            variant = parts[1]
            use_ka = variant.startswith('KA')
            cipher_name = variant.split('_', 1)[1]
            cipher_fn = CIPHER_FNS[cipher_name]

            t_ext = time.time()
            score2, ene2, bcl2, pt2, null2 = sa_optimize(
                cipher_fn, kw, use_ka,
                n_restarts=100, n_steps=15000,
                seed_base=hash(label + "_ext") % 100000,
                ene_start=r['ene_start'], bcl_start=r['bcl_start'],
            )
            elapsed_ext = time.time() - t_ext

            tag = ""
            if score2 >= 18:
                tag = " *** SIGNAL ***"
            elif score2 >= 15:
                tag = " *** HIGH ***"

            print(f"  {label:50s}  {r['score']:2d} -> {score2:2d}/{r['max_possible']} "
                  f"(ene={ene2:2d} bcl={bcl2:2d})  {elapsed_ext:5.1f}s{tag}")
            if score2 >= 12:
                print(f"    PT  = {pt2}")
                print(f"    mask= {sorted(null2)}")

            if score2 > r['score']:
                r['score'] = score2
                r['ene'] = ene2
                r['bcl'] = bcl2
                r['pt'] = pt2
                r['mask'] = sorted(null2)

        print()

    # Phase 3: Random mask baseline — what score does random get?
    print("=" * 70)
    print("PHASE 3: RANDOM BASELINE — Expected score with random null masks")
    print("=" * 70)
    rng_baseline = random.Random(42)
    random_scores = []
    for trial in range(1000):
        null_set = frozenset(rng_baseline.sample(ALL_POS, N_NULLS))
        ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)
        pt73 = vigenere_decrypt(ct73, 'KRYPTOS', False)
        total, _, _ = count_crib_hits_fixed(pt73)
        random_scores.append(total)
    avg_random = sum(random_scores) / len(random_scores)
    max_random = max(random_scores)
    print(f"  1000 random trials (AZ_vig, KRYPTOS): avg={avg_random:.2f}, max={max_random}")
    score_dist = {}
    for s in random_scores:
        score_dist[s] = score_dist.get(s, 0) + 1
    for s in sorted(score_dist.keys()):
        print(f"    score={s}: {score_dist[s]} ({score_dist[s]/10:.1f}%)")
    print()

    # ── Summary ──────────────────────────────────────────────────────────────
    elapsed_total = time.time() - t_start
    all_results.sort(key=lambda x: -x['score'])

    print("=" * 70)
    print(f"SUMMARY — Crib Position Reversal Attack ({elapsed_total:.1f}s total)")
    print("=" * 70)
    print()
    print("Model: CT97 -> remove 24 nulls -> CT73 -> decrypt -> PT73")
    print("Cribs at FIXED positions in PT73 (4 variants tested)")
    print(f"Random baseline: avg={avg_random:.2f}, max={max_random}")
    print()

    print("TOP 20 RESULTS:")
    for i, r in enumerate(all_results[:20]):
        print(f"  {i+1:2d}. {r['score']:2d}/{r['max_possible']} "
              f"(ene={r['ene']:2d} bcl={r['bcl']:2d})  {r['label']}")
        if r['score'] >= 10:
            print(f"      PT  = {r['pt']}")
            print(f"      mask= {r['mask']}")

    # Score distribution across all SA results
    print()
    print("SCORE DISTRIBUTION (all SA configs):")
    sa_dist = {}
    for r in all_results:
        s = r['score']
        sa_dist[s] = sa_dist.get(s, 0) + 1
    for s in sorted(sa_dist.keys(), reverse=True):
        print(f"  score={s:2d}: {sa_dist[s]:3d} configs")

    # Compare to prior model (cribs in CT97 space)
    print()
    best = all_results[0]
    prior_best_direct = baseline_results[0][0] if baseline_results else 0

    if best['score'] >= 18:
        verdict = "SIGNAL — crib reversal produces statistically significant scores"
    elif best['score'] >= 15:
        verdict = "PROMISING — exceeds prior model ceiling, warrants investigation"
    elif best['score'] >= 12:
        verdict = "INCONCLUSIVE — above noise but may be underdetermined"
    else:
        verdict = "NOISE — crib reversal does not improve over random/direct baseline"

    print(f"VERDICT: {verdict}")
    print(f"  Reversal model best : {best['score']}/{best['max_possible']} ({best['label']})")
    print(f"  Direct baseline best: {prior_best_direct}/24")
    print(f"  Random baseline     : avg={avg_random:.2f}, max={max_random}")
    print()

    # JSON verdict
    print("verdict:", json.dumps({
        "verdict_status": "signal" if best['score'] >= 18 else
                         "promising" if best['score'] >= 15 else
                         "inconclusive" if best['score'] >= 12 else "noise",
        "best_score": best['score'],
        "best_config": best['label'],
        "best_ene": best['ene'],
        "best_bcl": best['bcl'],
        "direct_baseline_best": prior_best_direct,
        "random_baseline_avg": round(avg_random, 2),
        "random_baseline_max": max_random,
        "total_configs": len(all_results),
        "summary": f"Crib reversal (cribs at fixed PT73 positions, 4 variants): "
                   f"best {best['score']}/{best['max_possible']} ({best['label']}). "
                   f"Direct baseline: {prior_best_direct}/24. "
                   f"Random: avg {avg_random:.2f}, max {max_random}.",
    }))

if __name__ == '__main__':
    main()
