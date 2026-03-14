#!/usr/bin/env python3
"""Quagmire II autokey cipher with indicator letter sweep + null mask SA.

# Cipher:    Quagmire II autokey (PT-feedback)
# Family:    campaigns
# Status:    active
# Keyspace:  26 indicators × 5 keywords × 3 variants × 20 SA restarts = 7,800 runs
# Last run:  never
# Best score: 0

QUAGMIRE II WITH INDICATOR:
The Kryptos tableau is Quagmire II. The KA (keyword-mixed) alphabet forms the
cipher alphabet. The AZ alphabet is the plain alphabet. An "indicator letter"
determines alignment: it is the KA letter that sits under 'A' in the identity
row.

With indicator letter I:
  indicator_pos = KA.index(I)

  Encryption:
    CT = KA[(AZ.index(key_letter) + KA.index(PT_letter) - indicator_pos) % 26]

  Decryption:
    KA.index(PT) = (KA.index(CT) - AZ.index(key_letter) + indicator_pos) % 26
    PT = KA[(KA.index(CT) - AZ.index(key) + indicator_pos) % 26]

  For Beaufort variant:
    KA.index(PT) = (AZ.index(key_letter) - KA.index(CT) + indicator_pos) % 26
    PT = KA[(AZ.index(key) - KA.index(CT) + indicator_pos) % 26]

  For Variant Beaufort:
    KA.index(PT) = (KA.index(CT) + AZ.index(key_letter) - indicator_pos) % 26
    (= swapped sign on key vs vig)

Autokey PT-feedback: key[i] = AZ.index(PT[i-L]) for i >= L
  where L = keyword length. PT is decoded via KA alphabet → AZ position for feedback.

MODEL: CT97 → remove 24 nulls → CT73 → Q2-indicator autokey decrypt → PT73

PHASE 1: All 26 indicators × 5 keywords × 3 variants × 20 SA restarts (4000 steps)
PHASE 2: Top 10 configs tested with col7 transposition (20 restarts × 6000 steps)
"""

import sys, random, math, time, json
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, CRIB_POSITIONS, KRYPTOS_ALPHABET, ALPH

# ── Constants ─────────────────────────────────────────────────────────────────
CT97      = CT
N         = 97; N_NULLS = 24; N_PT = 73
ENE_WORD  = "EASTNORTHEAST"; BCL_WORD = "BERLINCLOCK"
ENE_START = 21; BCL_START = 63
NON_CRIB  = sorted(i for i in range(N) if i not in CRIB_POSITIONS)
NC_SET    = frozenset(NON_CRIB)
assert len(NON_CRIB) == 73

KA_STR = KRYPTOS_ALPHABET   # "KRYPTOSABCDEFGHIJLMNQUVWXZ"
AZ_STR = ALPH               # "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA_IDX = {c: i for i, c in enumerate(KA_STR)}
AZ_IDX = {c: i for i, c in enumerate(AZ_STR)}

KEYWORDS = ['KRYPTOS', 'DEFECTOR', 'KOMPASS', 'ABSCISSA', 'COLOPHON']
INDICATORS = list(AZ_STR)  # A-Z (26 letters)
VARIANT_NAMES = ['vig', 'beau', 'vbeau']

# ── Columnar transposition ────────────────────────────────────────────────────
def columnar_perm(n, width):
    """Columnar transposition: write row-by-row width-wide, read col-by-col.
    Returns p where transposed[i] = original[p[i]]."""
    n_rows = (n + width - 1) // width
    grid = []
    for row in range(n_rows):
        start = row * width
        grid.append(list(range(start, min(start + width, n))))
    perm = []
    for col in range(width):
        for row in range(n_rows):
            if col < len(grid[row]):
                perm.append(grid[row][col])
    return perm

def reverse_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv

# Pre-compute col7 inverse permutation for Phase 2
COL7_INV = reverse_perm(columnar_perm(N_PT, 7))

def apply_col7(ct73_list):
    """Apply col7 inverse transposition to ct73 list."""
    return [ct73_list[COL7_INV[i]] for i in range(len(ct73_list))]

# ── Q2 Indicator Autokey Decrypt ──────────────────────────────────────────────
def q2_autokey_decrypt(ct73_str, keyword, indicator, variant='vig'):
    """Decrypt ct73 using Quagmire II autokey with indicator letter.

    The Kryptos tableau uses KA as the cipher alphabet.
    - PT alphabet: KA (plaintext letters map through KA)
    - CT alphabet: KA (ciphertext is in KA ordering)
    - Key alphabet: AZ (key letters index via standard alphabet)

    Indicator I means: when key=A, the KA alphabet starts at position KA.index(I).
    Effectively, indicator_pos shifts the relationship.

    Decryption formulas:
      vig:   pt_ka_idx = (ct_ka_idx - az_key_idx + indicator_pos) % 26
      beau:  pt_ka_idx = (az_key_idx - ct_ka_idx + indicator_pos) % 26
      vbeau: pt_ka_idx = (ct_ka_idx + az_key_idx - indicator_pos) % 26

    Autokey PT-feedback: for i >= L, key letter = PT[i-L] looked up via AZ.
    The PT is in KA ordering, so we convert PT char → AZ index for key feedback.
    """
    ind_pos = KA_IDX[indicator]
    kw_az = [AZ_IDX[c] for c in keyword]
    L = len(kw_az)

    pt_chars = []
    # For autokey feedback, we need AZ indices of PT chars
    pt_az_indices = []

    for i, ct_ch in enumerate(ct73_str):
        ct_ka = KA_IDX[ct_ch]

        if i < L:
            key_az = kw_az[i]
        else:
            # Autokey: feedback from plaintext, using AZ index of PT char
            key_az = pt_az_indices[i - L]

        if variant == 'vig':
            pt_ka = (ct_ka - key_az + ind_pos) % 26
        elif variant == 'beau':
            pt_ka = (key_az - ct_ka + ind_pos) % 26
        else:  # vbeau
            pt_ka = (ct_ka + key_az - ind_pos) % 26

        pt_ch = KA_STR[pt_ka]
        pt_chars.append(pt_ch)
        pt_az_indices.append(AZ_IDX[pt_ch])

    return ''.join(pt_chars)

# ── Scoring ───────────────────────────────────────────────────────────────────
def count_crib_hits(pt, ene_s, bcl_s):
    """Count crib character matches at mapped positions."""
    e = sum(1 for j, c in enumerate(ENE_WORD)
            if 0 <= ene_s + j < N_PT and pt[ene_s + j] == c)
    b = sum(1 for j, c in enumerate(BCL_WORD)
            if 0 <= bcl_s + j < N_PT and pt[bcl_s + j] == c)
    return e + b, e, b

def eval_mask(null_set, keyword, indicator, variant, use_col7=False):
    """Evaluate a null mask with given Q2 config. Returns (total, ene, bcl, pt)."""
    ct73 = ''.join(CT97[i] for i in range(N) if i not in null_set)

    if use_col7:
        ct73_list = list(ct73)
        ct73_list = apply_col7(ct73_list)
        ct73 = ''.join(ct73_list)

    n1 = sum(1 for p in null_set if p < ENE_START)
    n2 = sum(1 for p in null_set if p < BCL_START)
    ene_s = ENE_START - n1
    bcl_s = BCL_START - n2

    pt = q2_autokey_decrypt(ct73, keyword, indicator, variant)
    total, e, b = count_crib_hits(pt, ene_s, bcl_s)
    return total, e, b, pt

def score_mask(null_set, keyword, indicator, variant, use_col7=False):
    """Return scalar score for SA."""
    total, e, b, pt = eval_mask(null_set, keyword, indicator, variant, use_col7)
    return float(total)

# ── SA Engine ─────────────────────────────────────────────────────────────────
def sa_run(keyword, indicator, variant, seed, steps=4000, use_col7=False):
    """Single SA restart optimising null mask for given Q2 config."""
    rng = random.Random(seed)
    null_set = set(rng.sample(NON_CRIB, N_NULLS))
    non_null = NC_SET - null_set

    score = score_mask(frozenset(null_set), keyword, indicator, variant, use_col7)
    best_sc = score
    best_null = frozenset(null_set)

    T0 = 0.8; Tf = 0.005
    for step in range(steps):
        T = T0 * (Tf / T0) ** (step / steps)

        out = rng.choice(list(null_set))
        into = rng.choice(list(non_null))

        null_set = (null_set - {out}) | {into}
        non_null = (non_null - {into}) | {out}

        new_sc = score_mask(frozenset(null_set), keyword, indicator, variant, use_col7)
        delta = new_sc - score
        if delta > 0 or rng.random() < math.exp(delta / max(T, 1e-12)):
            score = new_sc
            if score > best_sc:
                best_sc = score
                best_null = frozenset(null_set)
        else:
            null_set = (null_set - {into}) | {out}
            non_null = (non_null - {out}) | {into}

    total, e, b, pt = eval_mask(best_null, keyword, indicator, variant, use_col7)
    return {
        'score': total, 'ene': e, 'bcl': b, 'pt': pt,
        'mask': sorted(best_null), 'keyword': keyword,
        'indicator': indicator, 'variant': variant,
        'col7': use_col7, 'seed': seed,
    }

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    print("=" * 72)
    print("QUAGMIRE II INDICATOR SWEEP: 26 indicators × 5 keywords × 3 variants")
    print("=" * 72)
    print(f"CT97 = {CT97}")
    print(f"KA   = {KA_STR}")
    print(f"AZ   = {AZ_STR}")
    print(f"Keywords:   {KEYWORDS}")
    print(f"Variants:   {VARIANT_NAMES}")
    print(f"Indicators: A-Z (26)")
    print(f"SA: 20 restarts × 4000 steps per config")
    print(f"Total configs: {26 * len(KEYWORDS) * len(VARIANT_NAMES)} = "
          f"{26 * len(KEYWORDS) * len(VARIANT_NAMES)} "
          f"(× 20 restarts = {26 * len(KEYWORDS) * len(VARIANT_NAMES) * 20})")
    print()

    # ── Sanity check: indicator='K' should be equivalent to old KA autokey ──
    # When indicator=K (pos 0 in KA), ind_pos=0, so Q2 reduces to the
    # standard KA-alphabet autokey. Verify:
    print("Sanity check: Q2(indicator=K, vig) vs standard KA autokey...")
    test_ct = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFP"
    test_pt_q2 = q2_autokey_decrypt(test_ct, "KRYPTOS", "K", "vig")
    # Standard KA autokey vig for comparison:
    def _std_ka_autokey(ct_str, kw):
        kw_ka = [KA_IDX[c] for c in kw]
        L = len(kw_ka)
        pt_out = []
        pt_ka_idx = []
        for i, c in enumerate(ct_str):
            ci = KA_IDX[c]
            ki = kw_ka[i] if i < L else pt_ka_idx[i - L]
            pi = (ci - ki) % 26
            pt_ka_idx.append(pi)
            pt_out.append(KA_STR[pi])
        return ''.join(pt_out)
    test_pt_std = _std_ka_autokey(test_ct, "KRYPTOS")
    if test_pt_q2 == test_pt_std:
        print(f"  PASS: Q2(K,vig) == standard KA autokey")
    else:
        print(f"  FAIL: Q2(K,vig) = {test_pt_q2[:30]}")
        print(f"  FAIL: std       = {test_pt_std[:30]}")
    print()

    t0 = time.time()
    all_results = []
    config_bests = {}  # (keyword, indicator, variant) → best result

    # ── PHASE 1: Full sweep ───────────────────────────────────────────────────
    print("=" * 72)
    print("PHASE 1: Full indicator sweep (no transposition)")
    print("=" * 72)

    total_configs = len(KEYWORDS) * len(INDICATORS) * len(VARIANT_NAMES)
    config_count = 0

    for kw in KEYWORDS:
        for indicator in INDICATORS:
            for variant in VARIANT_NAMES:
                config_count += 1
                label = f"{kw}:{variant}:ind={indicator}"

                best_this = None
                for restart in range(20):
                    seed = hash((kw, indicator, variant, restart)) % (2**31)
                    r = sa_run(kw, indicator, variant, seed, steps=4000, use_col7=False)
                    if best_this is None or r['score'] > best_this['score']:
                        best_this = r

                key = (kw, indicator, variant)
                config_bests[key] = best_this
                all_results.append(best_this)

                if best_this['score'] >= 10:
                    elapsed = time.time() - t0
                    print(f"  [{config_count}/{total_configs}] {label}: "
                          f"{best_this['score']}/24 ene={best_this['ene']}/13 "
                          f"bcl={best_this['bcl']}/11  [{elapsed:.0f}s]")
                    print(f"    PT = {best_this['pt'][:60]}...")
                    if best_this['score'] >= 14:
                        print(f"    *** HIGH SCORE {best_this['score']}/24 ***")
                        print(f"    FULL PT = {best_this['pt']}")
                        print(f"    MASK    = {best_this['mask']}")

                # Progress update every 50 configs
                if config_count % 50 == 0:
                    elapsed = time.time() - t0
                    best_so_far = max(all_results, key=lambda x: x['score'])
                    print(f"  ... {config_count}/{total_configs} configs done "
                          f"[{elapsed:.0f}s]. Best so far: "
                          f"{best_so_far['score']}/24 "
                          f"({best_so_far['keyword']}:{best_so_far['variant']}"
                          f":ind={best_so_far['indicator']})")

    # ── Phase 1 Summary ──────────────────────────────────────────────────────
    all_results.sort(key=lambda x: (-x['score'], -x['ene'], -x['bcl']))

    elapsed = time.time() - t0
    print()
    print("=" * 72)
    print(f"PHASE 1 COMPLETE ({elapsed:.0f}s)")
    print("=" * 72)
    print(f"\nTOP 20 RESULTS (Phase 1, no transposition):")
    for i, r in enumerate(all_results[:20]):
        print(f"  {i+1:2d}. {r['score']}/24 ene={r['ene']}/13 bcl={r['bcl']}/11  "
              f"{r['keyword']}:{r['variant']}:ind={r['indicator']}")
        print(f"      PT = {r['pt'][:60]}...")

    # Distribution summary by indicator
    print(f"\nBest score per indicator (across all keywords/variants):")
    ind_bests = {}
    for r in all_results:
        ind = r['indicator']
        if ind not in ind_bests or r['score'] > ind_bests[ind]['score']:
            ind_bests[ind] = r
    for ind in sorted(ind_bests.keys()):
        r = ind_bests[ind]
        flag = " ***" if r['score'] >= 13 else ""
        print(f"  ind={ind}: {r['score']}/24 ({r['keyword']}:{r['variant']}){flag}")

    # Distribution by keyword
    print(f"\nBest score per keyword (across all indicators/variants):")
    kw_bests = {}
    for r in all_results:
        kw = r['keyword']
        if kw not in kw_bests or r['score'] > kw_bests[kw]['score']:
            kw_bests[kw] = r
    for kw in KEYWORDS:
        r = kw_bests[kw]
        print(f"  {kw:10s}: {r['score']}/24 (ind={r['indicator']}, {r['variant']})")

    # ── PHASE 2: Top 10 with col7 ────────────────────────────────────────────
    print()
    print("=" * 72)
    print("PHASE 2: Top 10 configs + col7 transposition")
    print("=" * 72)

    # De-duplicate: unique (keyword, indicator, variant) combos from top results
    seen_keys = set()
    top_configs = []
    for r in all_results:
        key = (r['keyword'], r['indicator'], r['variant'])
        if key not in seen_keys:
            seen_keys.add(key)
            top_configs.append(r)
        if len(top_configs) >= 10:
            break

    phase2_results = []
    for i, cfg in enumerate(top_configs):
        kw = cfg['keyword']; ind = cfg['indicator']; var = cfg['variant']
        label = f"{kw}:{var}:ind={ind}:col7"
        print(f"\n  [{i+1}/10] {label} (Phase 1 baseline: {cfg['score']}/24)")

        best_col7 = None
        for restart in range(20):
            seed = hash((kw, ind, var, 'col7', restart)) % (2**31)
            r = sa_run(kw, ind, var, seed, steps=6000, use_col7=True)
            if best_col7 is None or r['score'] > best_col7['score']:
                best_col7 = r

        phase2_results.append(best_col7)
        elapsed = time.time() - t0
        delta = best_col7['score'] - cfg['score']
        delta_str = f"+{delta}" if delta > 0 else str(delta)
        print(f"    → {best_col7['score']}/24 ene={best_col7['ene']}/13 "
              f"bcl={best_col7['bcl']}/11 ({delta_str} vs Phase 1) [{elapsed:.0f}s]")
        if best_col7['score'] >= 14:
            print(f"    *** HIGH SCORE {best_col7['score']}/24 ***")
            print(f"    PT   = {best_col7['pt']}")
            print(f"    MASK = {best_col7['mask']}")

    # ── Phase 2 Summary ──────────────────────────────────────────────────────
    phase2_results.sort(key=lambda x: (-x['score'], -x['ene'], -x['bcl']))
    print()
    print("=" * 72)
    print("PHASE 2 RESULTS (col7 transposition):")
    print("=" * 72)
    for i, r in enumerate(phase2_results[:10]):
        print(f"  {i+1:2d}. {r['score']}/24 ene={r['ene']}/13 bcl={r['bcl']}/11  "
              f"{r['keyword']}:{r['variant']}:ind={r['indicator']}:col7")
        print(f"      PT = {r['pt'][:60]}...")

    # ── Grand Summary ─────────────────────────────────────────────────────────
    combined = all_results + phase2_results
    combined.sort(key=lambda x: (-x['score'], -x['ene'], -x['bcl']))
    elapsed = time.time() - t0

    print()
    print("=" * 72)
    print(f"GRAND SUMMARY (total elapsed: {elapsed:.0f}s)")
    print("=" * 72)
    print(f"\nTOP 10 OVERALL:")
    for i, r in enumerate(combined[:10]):
        col7_str = "+col7" if r['col7'] else ""
        print(f"  {i+1:2d}. {r['score']}/24 ene={r['ene']}/13 bcl={r['bcl']}/11  "
              f"{r['keyword']}:{r['variant']}:ind={r['indicator']}{col7_str}")
        print(f"      PT   = {r['pt']}")
        print(f"      MASK = {r['mask']}")
        print()

    # ── Comparison: indicator=K should match previous KA autokey results ──
    print("=" * 72)
    print("INDICATOR ANALYSIS:")
    print("=" * 72)
    # Check if any non-K indicator outperforms K
    k_best = None
    non_k_best = None
    for r in combined:
        if r['indicator'] == 'K' and (k_best is None or r['score'] > k_best['score']):
            k_best = r
        if r['indicator'] != 'K' and (non_k_best is None or r['score'] > non_k_best['score']):
            non_k_best = r
    if k_best:
        col7_str = "+col7" if k_best['col7'] else ""
        print(f"  Best with indicator=K: {k_best['score']}/24 "
              f"({k_best['keyword']}:{k_best['variant']}{col7_str})")
    if non_k_best:
        col7_str = "+col7" if non_k_best['col7'] else ""
        print(f"  Best with indicator≠K: {non_k_best['score']}/24 "
              f"({non_k_best['keyword']}:{non_k_best['variant']}"
              f":ind={non_k_best['indicator']}{col7_str})")
    if k_best and non_k_best:
        if non_k_best['score'] > k_best['score']:
            print(f"  >>> NON-K INDICATOR OUTPERFORMS K by "
                  f"{non_k_best['score'] - k_best['score']} points!")
        elif non_k_best['score'] == k_best['score']:
            print(f"  >>> Non-K tied with K at {k_best['score']}/24")
        else:
            print(f"  >>> K indicator is best (no improvement from other indicators)")

    best = combined[0]
    col7_str = "+col7" if best['col7'] else ""
    print()
    print("verdict:", json.dumps({
        "verdict_status": "signal" if best['score'] >= 16 else
                          "promising" if best['score'] >= 14 else "inconclusive",
        "score": best['score'],
        "summary": f"Q2 indicator sweep best {best['score']}/24 "
                   f"(ene={best['ene']}/13 bcl={best['bcl']}/11)",
        "evidence": f"{best['keyword']}:{best['variant']}:ind={best['indicator']}"
                    f"{col7_str}",
        "best_plaintext": best['pt'],
    }))
