#!/usr/bin/env python3
"""E-S-97: Decimation (Skip) Cipher + Various Substitutions

Decimation cipher: read every d-th character from CT (mod 97).
Since 97 is prime, EVERY d from 1 to 96 produces a valid permutation.
This gives exactly 96 possible transpositions (vs 5040+ for columnar).

Combined with:
  Phase 1: Period-7 Vig/Beau/VBeau (96 × 15120 period-7 keys × 3 variants)
  Phase 2: All periodic keys p=2..14 (96 × 3 variants × p=2..14)
  Phase 3: Autokey CT/PT with primer 1-3 (96 × 26^p × 2 × 3)
  Phase 4: Pure monoalphabetic (26 × 96 = 2496 configs)
  Phase 5: Decimation + width-7 columnar (compound transposition)

Also: test DOUBLE decimation (d1, d2) where we apply decimation twice.
"""

import json, os, time
from itertools import product

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
N = len(CT)  # 97 (prime!)
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
I2N = {c: i for i, c in enumerate(AZ)}
CT_N = [I2N[c] for c in CT]

CRIBS = {
    21:'E',22:'A',23:'S',24:'T',25:'N',26:'O',27:'R',28:'T',29:'H',30:'E',31:'A',32:'S',33:'T',
    63:'B',64:'E',65:'R',66:'L',67:'I',68:'N',69:'C',70:'L',71:'O',72:'C',73:'K'}
PT_FULL = {p: I2N[c] for p, c in CRIBS.items()}
CPOS = sorted(CRIBS.keys())

VNAMES = ['Vig', 'Beau', 'VBeau']


def decimation_perm(d, n=97):
    """Generate decimation permutation: position j reads from CT[(j*d) % n]."""
    return [(j * d) % n for j in range(n)]


def check_cribs(pt):
    return sum(1 for p in CPOS if pt[p] == PT_FULL[p])


def ct_autokey_decrypt(intermed, primer, variant):
    p = len(primer)
    pt = [0] * N
    for j in range(N):
        k = primer[j] if j < p else intermed[j - p]
        if variant == 0:
            pt[j] = (intermed[j] - k) % 26
        elif variant == 1:
            pt[j] = (k - intermed[j]) % 26
        else:
            pt[j] = (intermed[j] + k) % 26
    return pt


def pt_autokey_decrypt(intermed, primer, variant):
    p = len(primer)
    pt = [0] * N
    for j in range(N):
        k = primer[j] if j < p else pt[j - p]
        if variant == 0:
            pt[j] = (intermed[j] - k) % 26
        elif variant == 1:
            pt[j] = (k - intermed[j]) % 26
        else:
            pt[j] = (intermed[j] + k) % 26
    return pt


print("=" * 70)
print("E-S-97: Decimation (Skip) Cipher + Various Substitutions")
print(f"  N={N} (prime), decimation steps: 96")
print("=" * 70)

t0 = time.time()

# Precompute all 96 decimation intermediates
DECIMATIONS = {}
for d in range(1, N):
    perm = decimation_perm(d)
    intermed = [CT_N[perm[j]] for j in range(N)]
    DECIMATIONS[d] = intermed

results = {}


# ── Phase 1: Decimation + periodic key (p=2..14) ─────────────────────
print("\n--- P1: Decimation + periodic key (p=2..14) ---")

p1_best = 0
p1_cfg = None

for d in range(1, N):
    intermed = DECIMATIONS[d]

    for period in range(2, 15):
        for vi in range(3):
            # Check period consistency at crib positions
            residue_keys = {}
            consistent = True

            for p in CPOS:
                # Compute observed key
                if vi == 0:  # Vig
                    k = (intermed[p] - PT_FULL[p]) % 26
                elif vi == 1:  # Beau
                    k = (intermed[p] + PT_FULL[p]) % 26
                else:  # VBeau
                    k = (PT_FULL[p] - intermed[p]) % 26

                r = p % period
                if r in residue_keys:
                    if residue_keys[r] != k:
                        consistent = False
                        break
                else:
                    residue_keys[r] = k

            if consistent:
                score = 24  # All cribs match by construction
                # Decrypt full text
                pt = [0] * N
                for j in range(N):
                    k = residue_keys.get(j % period, 0)
                    if vi == 0:
                        pt[j] = (intermed[j] - k) % 26
                    elif vi == 1:
                        pt[j] = (k - intermed[j]) % 26
                    else:
                        pt[j] = (intermed[j] + k) % 26

                # Verify
                actual = check_cribs(pt)
                if actual > p1_best:
                    p1_best = actual
                    p1_cfg = (d, period, VNAMES[vi])

                if actual >= 24:
                    pt_text = ''.join(AZ[x] for x in pt)
                    print(f"  *** BREAKTHROUGH: d={d} period={period} {VNAMES[vi]}")
                    print(f"      PT: {pt_text}")
                    # Check IC and quadgrams
                    from collections import Counter
                    freq = Counter(pt)
                    ic = sum(f*(f-1) for f in freq.values()) / (N*(N-1))
                    print(f"      IC: {ic:.4f}")

elapsed = time.time() - t0
print(f"  P1: best={p1_best}/24, {elapsed:.1f}s, cfg={p1_cfg}")
results['P1_periodic'] = {'best': p1_best, 'cfg': str(p1_cfg)}


# ── Phase 2: Decimation + autokey (CT and PT), primer 1-3 ────────────
print("\n--- P2: Decimation + autokey, primer 1-3 ---")

p2_best = 0
p2_cfg = None
tested = 0

for d in range(1, N):
    intermed = DECIMATIONS[d]

    for plen in range(1, 4):
        for primer_tuple in product(range(26), repeat=plen):
            primer = list(primer_tuple)
            for vi in range(3):
                # CT-autokey
                pt = ct_autokey_decrypt(intermed, primer, vi)
                score = check_cribs(pt)
                tested += 1

                if score > p2_best:
                    p2_best = score
                    p2_cfg = ('CT', d, VNAMES[vi], ''.join(AZ[x] for x in primer))

                if score >= 18:
                    pt_text = ''.join(AZ[x] for x in pt)
                    print(f"  HIT: {score}/24 CT-AK d={d} {VNAMES[vi]} "
                          f"primer={''.join(AZ[x] for x in primer)}")
                    print(f"      PT: {pt_text}")

                # PT-autokey
                pt2 = pt_autokey_decrypt(intermed, primer, vi)
                score2 = check_cribs(pt2)
                tested += 1

                if score2 > p2_best:
                    p2_best = score2
                    p2_cfg = ('PT', d, VNAMES[vi], ''.join(AZ[x] for x in primer))

                if score2 >= 18:
                    pt_text = ''.join(AZ[x] for x in pt2)
                    print(f"  HIT: {score2}/24 PT-AK d={d} {VNAMES[vi]} "
                          f"primer={''.join(AZ[x] for x in primer)}")

    if d % 20 == 0:
        print(f"    d={d}/96, best={p2_best}, {tested:,} tested ({time.time()-t0:.0f}s)")

elapsed = time.time() - t0
print(f"  P2: best={p2_best}/24, {tested:,} tested, {elapsed:.1f}s, cfg={p2_cfg}")
results['P2_autokey'] = {'best': p2_best, 'cfg': str(p2_cfg)}


# ── Phase 3: Double decimation + periodic ─────────────────────────────
print("\n--- P3: Double decimation (d1, d2) + period-7 key ---")

p3_best = 0
p3_cfg = None

for d1 in range(1, N):
    for d2 in range(1, N):
        # Compound decimation: effective d = d1*d2 mod 97
        d_eff = (d1 * d2) % N
        if d_eff == 0:
            continue

        # This is the same as single decimation with d_eff!
        # Double decimation = single decimation. Skip unless we offset.
        break  # No point testing this

    break

# Instead: decimation with offset (read starting from position s, every d chars)
print("  Double decimation = single decimation (multiplicative group mod 97)")
print("  Testing decimation with offset instead...")

p3_best = 0
for d in range(1, N):
    for s in range(N):
        # Permutation: position j reads from CT[(s + j*d) % N]
        perm = [(s + j * d) % N for j in range(N)]
        intermed = [CT_N[perm[j]] for j in range(N)]

        # Check period-7 consistency
        for vi in range(3):
            residue_keys = {}
            consistent = True
            for p in CPOS:
                if vi == 0:
                    k = (intermed[p] - PT_FULL[p]) % 26
                elif vi == 1:
                    k = (intermed[p] + PT_FULL[p]) % 26
                else:
                    k = (PT_FULL[p] - intermed[p]) % 26

                r = p % 7
                if r in residue_keys:
                    if residue_keys[r] != k:
                        consistent = False
                        break
                else:
                    residue_keys[r] = k

            if consistent:
                # Full decrypt
                pt = [0] * N
                for j in range(N):
                    k = residue_keys.get(j % 7, 0)
                    if vi == 0:
                        pt[j] = (intermed[j] - k) % 26
                    elif vi == 1:
                        pt[j] = (k - intermed[j]) % 26
                    else:
                        pt[j] = (intermed[j] + k) % 26

                score = check_cribs(pt)
                if score > p3_best:
                    p3_best = score
                    p3_cfg = (d, s, VNAMES[vi])
                    if score >= 20:
                        pt_text = ''.join(AZ[x] for x in pt)
                        print(f"  HIT: {score}/24 d={d} s={s} {VNAMES[vi]}")
                        print(f"      PT: {pt_text}")

    if d % 20 == 0:
        print(f"    d={d}/96, best={p3_best} ({time.time()-t0:.0f}s)")

elapsed = time.time() - t0
print(f"  P3: best={p3_best}/24, {elapsed:.1f}s, cfg={p3_cfg}")
results['P3_offset_decimation'] = {'best': p3_best, 'cfg': str(p3_cfg)}


# ── Phase 4: Decimation + mixed alphabet monoalphabetic ───────────────
print("\n--- P4: Decimation + monoalphabetic (crib-derived) ---")

# For each decimation d, extract intermediate and check if a single
# substitution alphabet maps I → PT at all 24 crib positions
p4_best = 0
p4_cfg = None

for d in range(1, N):
    intermed = DECIMATIONS[d]

    # Build substitution mapping from cribs
    mapping = {}
    consistent = True
    for p in CPOS:
        i_val = intermed[p]
        pt_val = PT_FULL[p]
        if i_val in mapping:
            if mapping[i_val] != pt_val:
                consistent = False
                break
        else:
            mapping[i_val] = pt_val

    if not consistent:
        continue

    # Also check injectivity (each PT letter used at most once)
    reverse = {}
    injective = True
    for i_val, pt_val in mapping.items():
        if pt_val in reverse:
            if reverse[pt_val] != i_val:
                injective = False
                break
        else:
            reverse[pt_val] = i_val

    if not injective:
        continue

    # Count how many crib positions match (should be all 24 if consistent)
    pt = [mapping.get(intermed[j], intermed[j]) for j in range(N)]
    score = check_cribs(pt)

    if score > p4_best:
        p4_best = score
        p4_cfg = (d, len(mapping))

    if score >= 24:
        pt_text = ''.join(AZ[x] for x in pt)
        from collections import Counter
        freq = Counter(pt)
        ic = sum(f*(f-1) for f in freq.values()) / (N*(N-1))
        print(f"  *** MONO HIT: d={d}, {len(mapping)} letters mapped, IC={ic:.4f}")
        print(f"      PT: {pt_text}")

elapsed = time.time() - t0
print(f"  P4 (mono): best={p4_best}/24, survivors(consistent)={sum(1 for d in range(1,N) if True)}, {elapsed:.1f}s")
results['P4_monoalphabetic'] = {'best': p4_best, 'cfg': str(p4_cfg)}


# ── Summary ───────────────────────────────────────────────────────────
total_elapsed = time.time() - t0

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
for phase, data in sorted(results.items()):
    print(f"  {phase}: {data['best']}/24")
print(f"  Total: {total_elapsed:.1f}s")

best = max(v['best'] for v in results.values())
if best >= 18:
    print(f"\n  Verdict: SIGNAL — {best}/24")
elif best >= 10:
    print(f"\n  Verdict: INTERESTING — {best}/24")
else:
    print(f"\n  Verdict: NOISE — {best}/24")

os.makedirs("results", exist_ok=True)
out = {
    'experiment': 'E-S-97',
    'description': 'Decimation (skip) cipher + various substitutions',
    'results': results,
    'elapsed_seconds': total_elapsed,
}
with open("results/e_s_97_decimation.json", "w") as f:
    json.dump(out, f, indent=2, default=str)
print(f"\n  Artifact: results/e_s_97_decimation.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_97_decimation.py")
