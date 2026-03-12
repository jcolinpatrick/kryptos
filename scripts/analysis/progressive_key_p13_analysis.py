"""
Progressive Key Period-13 Analysis
===================================
Campaign rounds 58, 64, 65, 210, 212, 213 all produced 15-16/24 crib hits
with a "progressive key" Beaufort cipher at period 13.

Mechanism: key[i] = (base_key[i%13] + floor(i/13)*step) % 26
- base_key is DERIVED from EASTNORTHEAST crib (pos 21-33) → 13 ENE hits guaranteed
- BERLINCLOCK (pos 63-73) provides 11 independent tests
- 15-16 total = 13 (ENE, by construction) + 2-3 (BC, the real signal)

This script determines:
1. Exactly how many BC hits each (mode, alphabet, step) combo gives
2. The null distribution: how many BC hits you'd expect from random CT
3. Whether 2-3 BC hits is statistically significant
4. What plaintext the best configs produce
"""

import sys
sys.path.insert(0, 'src')

from kryptos.kernel.constants import CT, BEAN_EQ, BEAN_INEQ
from kryptos.kernel.alphabet import AZ, KA

# Crib data
ENE_POS, ENE_PT = 21, 'EASTNORTHEAST'
BC_POS, BC_PT = 63, 'BERLINCLOCK'

CRIB_DICT = {}
for j, ch in enumerate(ENE_PT):
    CRIB_DICT[ENE_POS + j] = ch
for j, ch in enumerate(BC_PT):
    CRIB_DICT[BC_POS + j] = ch

N = len(CT)  # 97

def derive_and_decrypt(ct, alph, mode, step):
    """
    Derive base key from EASTNORTHEAST, decrypt full CT.
    Returns (plaintext, ene_hits, bc_hits, total_hits, base_key).
    mode: 'vig' (K=CT-PT), 'beau' (K=CT+PT), 'vbeau' (K=PT-CT)
    """
    n = len(ct)
    ci = [alph.char_to_idx(c) for c in ct]

    # Derive base key from ENE crib
    base_key = [None] * 13
    for j, ch in enumerate(ENE_PT):
        pos = ENE_POS + j
        row = pos // 13
        residue = pos % 13
        ct_val = ci[pos]
        pt_val = alph.char_to_idx(ch)

        if mode == 'vig':
            raw_k = (ct_val - pt_val) % 26
        elif mode == 'beau':
            raw_k = (ct_val + pt_val) % 26
        else:  # vbeau
            raw_k = (pt_val - ct_val) % 26

        bk = (raw_k - row * step) % 26
        if base_key[residue] is not None and base_key[residue] != bk:
            return None  # Internal conflict in ENE
        base_key[residue] = bk

    if any(v is None for v in base_key):
        return None

    # Decrypt
    pt = []
    for i in range(n):
        row = i // 13
        residue = i % 13
        k = (base_key[residue] + row * step) % 26

        if mode == 'vig':
            p = (ci[i] - k) % 26
        elif mode == 'beau':
            p = (k - ci[i]) % 26
        else:  # vbeau
            p = (ci[i] + k) % 26

        pt.append(alph.idx_to_char(p))

    pt_str = ''.join(pt)

    # Count crib hits
    ene_hits = sum(1 for j, ch in enumerate(ENE_PT) if pt_str[ENE_POS + j] == ch)
    bc_hits = sum(1 for j, ch in enumerate(BC_PT) if BC_POS + j < n and pt_str[BC_POS + j] == ch)
    total = ene_hits + bc_hits

    return pt_str, ene_hits, bc_hits, total, base_key


def structural_analysis():
    """Analyze WHY certain BC positions match — is it structural?"""
    print("=" * 80)
    print("STRUCTURAL ANALYSIS: Row differences between ENE and BC positions")
    print("=" * 80)

    print("\nEASTNORTHEAST positions (source of base key):")
    for j, ch in enumerate(ENE_PT):
        pos = ENE_POS + j
        print(f"  pos {pos:2d}: row {pos//13}, residue {pos%13:2d}  PT={ch}")

    print("\nBERLINCLOCK positions (independent test):")
    for j, ch in enumerate(BC_PT):
        pos = BC_POS + j
        residue = pos % 13
        bc_row = pos // 13
        # Find which ENE position provided this residue's base key
        ene_pos_for_r = ENE_POS + ((residue - ENE_POS % 13) % 13)
        if ene_pos_for_r < ENE_POS:
            ene_pos_for_r += 13
        if ene_pos_for_r > ENE_POS + 12:
            ene_pos_for_r -= 13
        ene_row = ene_pos_for_r // 13
        row_diff = bc_row - ene_row
        print(f"  pos {pos:2d}: row {bc_row}, residue {residue:2d}  PT={ch}  "
              f"(ENE source: pos {ene_pos_for_r}, row {ene_row}, diff={row_diff})")

    # Key insight: for most BC positions, row_diff=3, but pos 73 has row_diff=4
    print("\n→ 10/11 BC positions have row_diff=3, position 73 has row_diff=4")
    print("→ For row_diff=3: constraint is 3*step ≡ target (mod 26)")
    print("→ Since gcd(3,26)=1, each position uniquely determines step")
    print("→ Multiple BC hits ⟹ multiple constraints AGREE on same step")


def exhaustive_search():
    """Test ALL (mode, alphabet, step) combinations."""
    print("\n" + "=" * 80)
    print("EXHAUSTIVE SEARCH: All mode × alphabet × step combinations")
    print("=" * 80)

    results = []
    for alph_name, alph in [('AZ', AZ), ('KA', KA)]:
        for mode in ['vig', 'beau', 'vbeau']:
            for step in range(26):
                r = derive_and_decrypt(CT, alph, mode, step)
                if r is None:
                    continue
                pt_str, ene_hits, bc_hits, total, base_key = r
                results.append({
                    'alph': alph_name, 'mode': mode, 'step': step,
                    'ene': ene_hits, 'bc': bc_hits, 'total': total,
                    'pt': pt_str, 'key': base_key,
                })

    # Sort by total hits descending
    results.sort(key=lambda x: (-x['total'], -x['bc']))

    print(f"\nTotal valid configs: {len(results)}")
    print(f"\nTop results (≥14 total hits):")
    print(f"{'Alph':4s} {'Mode':5s} {'Step':4s} {'ENE':3s} {'BC':3s} {'Tot':3s}  Plaintext[0:30]...")
    print("-" * 80)

    for r in results:
        if r['total'] >= 14:
            print(f"{r['alph']:4s} {r['mode']:5s} {r['step']:4d} {r['ene']:3d} {r['bc']:3d} {r['total']:3d}  "
                  f"{r['pt'][:30]}...")

    print(f"\nDistribution of BC hits:")
    from collections import Counter
    bc_dist = Counter(r['bc'] for r in results)
    for bc_val in sorted(bc_dist.keys(), reverse=True):
        print(f"  BC={bc_val}: {bc_dist[bc_val]} configs")

    return results


def null_distribution(n_trials=10000):
    """What would we expect from random CT?"""
    import random
    print("\n" + "=" * 80)
    print(f"NULL DISTRIBUTION: {n_trials} random CTs, same analysis")
    print("=" * 80)

    max_bc_per_trial = []
    max_total_per_trial = []

    for trial in range(n_trials):
        fake_ct = ''.join(random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ') for _ in range(97))
        best_bc = 0
        best_total = 0
        for alph_name, alph in [('AZ', AZ), ('KA', KA)]:
            for mode in ['vig', 'beau', 'vbeau']:
                for step in range(26):
                    r = derive_and_decrypt(fake_ct, alph, mode, step)
                    if r is None:
                        continue
                    _, ene, bc, total, _ = r
                    if bc > best_bc:
                        best_bc = bc
                    if total > best_total:
                        best_total = total

        max_bc_per_trial.append(best_bc)
        max_total_per_trial.append(best_total)

    from collections import Counter

    print(f"\nMax BC hits per trial (across all {6*26}={6*26} configs):")
    bc_dist = Counter(max_bc_per_trial)
    cumulative = 0
    for bc_val in sorted(bc_dist.keys(), reverse=True):
        cumulative += bc_dist[bc_val]
        pct = 100 * cumulative / n_trials
        print(f"  BC≥{bc_val}: {cumulative:5d}/{n_trials} = {pct:5.1f}%")

    print(f"\nMax total hits per trial:")
    total_dist = Counter(max_total_per_trial)
    cumulative = 0
    for t_val in sorted(total_dist.keys(), reverse=True):
        cumulative += total_dist[t_val]
        pct = 100 * cumulative / n_trials
        print(f"  Total≥{t_val}: {cumulative:5d}/{n_trials} = {pct:5.1f}%")

    # Direct comparison
    actual_results = exhaustive_search_silent()
    actual_max_bc = max(r['bc'] for r in actual_results)
    actual_max_total = max(r['total'] for r in actual_results)

    p_bc = sum(1 for x in max_bc_per_trial if x >= actual_max_bc) / n_trials
    p_total = sum(1 for x in max_total_per_trial if x >= actual_max_total) / n_trials

    print(f"\n*** K4 actual: max BC={actual_max_bc}, max total={actual_max_total} ***")
    print(f"*** p-value (BC≥{actual_max_bc}): {p_bc:.4f} ({100*p_bc:.1f}%) ***")
    print(f"*** p-value (total≥{actual_max_total}): {p_total:.4f} ({100*p_total:.1f}%) ***")

    return max_bc_per_trial, max_total_per_trial


def exhaustive_search_silent():
    """Same as exhaustive_search but without printing."""
    results = []
    for alph_name, alph in [('AZ', AZ), ('KA', KA)]:
        for mode in ['vig', 'beau', 'vbeau']:
            for step in range(26):
                r = derive_and_decrypt(CT, alph, mode, step)
                if r is None:
                    continue
                pt_str, ene_hits, bc_hits, total, base_key = r
                results.append({
                    'alph': alph_name, 'mode': mode, 'step': step,
                    'ene': ene_hits, 'bc': bc_hits, 'total': total,
                    'pt': pt_str, 'key': base_key,
                })
    return results


def show_best_plaintext():
    """Show full plaintext for the best configs."""
    print("\n" + "=" * 80)
    print("BEST PLAINTEXT OUTPUTS")
    print("=" * 80)

    results = exhaustive_search_silent()
    results.sort(key=lambda x: (-x['total'], -x['bc']))

    for r in results[:5]:
        pt = r['pt']
        print(f"\n--- {r['alph']} {r['mode']} step={r['step']} (ENE={r['ene']}, BC={r['bc']}, total={r['total']}) ---")
        print(f"PT: {pt}")
        print(f"Key (base): {r['key']}")
        print(f"Key (alpha): {''.join(chr(k+65) for k in r['key'])}")

        # Highlight crib matches
        markers = [' '] * len(pt)
        for pos, ch in CRIB_DICT.items():
            if pos < len(pt):
                markers[pos] = '✓' if pt[pos] == ch else '✗'
        print(f"     {''.join(markers)}")

        # Check which specific BC positions match
        bc_matches = []
        bc_misses = []
        for j, ch in enumerate(BC_PT):
            pos = BC_POS + j
            if pos < len(pt) and pt[pos] == ch:
                bc_matches.append((pos, ch))
            else:
                bc_misses.append((pos, ch, pt[pos] if pos < len(pt) else '?'))
        print(f"  BC matches: {bc_matches}")
        print(f"  BC misses:  {bc_misses}")

        # Bean check
        if len(pt) >= 74:
            k27 = (ord(CT[27]) - ord(pt[27])) % 26  # simplified
            k65 = (ord(CT[65]) - ord(pt[65])) % 26
            print(f"  Bean eq check (simplified): k[27]={k27}, k[65]={k65}, eq={'PASS' if k27==k65 else 'FAIL'}")


def d13_connection():
    """Show the connection to the d=13 anomaly."""
    print("\n" + "=" * 80)
    print("CONNECTION TO d=13 ANOMALY")
    print("=" * 80)

    # The d=13 anomaly: Beaufort keystream values at positions that are 13 apart
    # collide 7.09× more than expected.
    # Progressive key with period 13 and step s:
    #   k[i] = base[i%13] + (i//13)*s
    #   k[i+13] = base[i%13] + (i//13 + 1)*s = k[i] + s
    # So k[i+13] - k[i] = s (constant!)
    # Bean's d=13 anomaly counts pairs where k[a] = k[b] with |a-b| divisible by 13.
    # Under progressive key: k[a] = k[b] iff (a//13)*s = (b//13)*s mod 26
    # i.e., iff a//13 = b//13 mod (26/gcd(s,26))

    print("""
The d=13 anomaly measures keystream collisions at distance divisible by 13.

Under progressive key cipher:
  k[i] = base[i%13] + floor(i/13) * step  (mod 26)

For two positions a,b with a%13 = b%13 (same residue):
  k[a] = k[b] ⟺ floor(a/13) * step ≡ floor(b/13) * step (mod 26)
  ⟺ (floor(a/13) - floor(b/13)) * step ≡ 0 (mod 26)

This creates STRUCTURED collisions — not random.
The d=13 anomaly could be an artifact of progressive keying.

For step values where gcd(step, 26) > 1 (i.e., step ∈ {2,4,6,8,10,12,13,14,16,18,20,22,24,26}):
  The effective period of the row-shift is 26/gcd(step,26), creating more collisions.
""")

    # Show collision structure for each step
    print("Collision structure by step value:")
    print(f"{'Step':4s} {'gcd(s,26)':9s} {'Effective row period':20s} {'Collision factor':16s}")
    for s in range(1, 26):
        from math import gcd
        g = gcd(s, 26)
        eff_period = 26 // g
        # Number of row groups: ceil(97/13) = 8 rows (0-7)
        # In each residue class, rows 0..7 get keys base[r], base[r]+s, base[r]+2s, ...
        # Collisions: rows a,b collide iff (a-b)*s ≡ 0 mod 26
        # Number of distinct key values per residue = min(8, eff_period)
        distinct = min(8, eff_period)
        # Expected collisions if no structure: each pair has 1/26 chance
        # Actual: pairs in same equivalence class always collide
        rows_per_class = 8 / distinct if distinct > 0 else 8
        collision_factor = rows_per_class  # relative to uniform
        print(f"  {s:2d}    {g:9d}  {eff_period:20d}  {collision_factor:16.2f}×")


if __name__ == '__main__':
    structural_analysis()
    all_results = exhaustive_search()
    show_best_plaintext()
    d13_connection()

    print("\n" + "=" * 80)
    print("Running null distribution (10,000 trials)... this may take a few minutes")
    print("=" * 80)
    null_distribution(n_trials=10000)
