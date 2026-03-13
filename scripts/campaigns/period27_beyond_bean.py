#!/usr/bin/env python3
"""
CRITICAL TEST: Periods 27-52 on K4 CT.

The Bean proof eliminates periods 1-26 ONLY.
For period p > 26: no two crib positions can share the same residue mod p
IF the max crib-position difference < 2p. Since cribs span 21-73 (diff=52),
periods 27-52 may have NO CRIB CONFLICTS.

For period 27: all 24 crib positions map to DISTINCT residues mod 27!
(No two crib positions differ by 27 or 54)
→ The 24 cribs give 24 independent key constraints — ALWAYS CONSISTENT.
→ 3 key positions are unconstrained (residues 7, 8, 20)
→ 11 CT positions have free PT (those at residues 7, 8, 20)
→ 86 CT positions have DETERMINED PT

This means we can compute 86 determined PT letters and check if they look English!

If the 86 determined positions look like English, K4 uses period-27 cipher.
The 3 free key letters give 26^3 = 17,576 combinations for the 11 free positions.

Also test periods 28-52.
"""
import sys
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT as CT_STR, CRIB_DICT, KRYPTOS_ALPHABET as KA

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CT = [ord(c)-65 for c in CT_STR]
N = len(CT)
ALL_CRIBS = list(CRIB_DICT.items())

def count_cribs(pt_list):
    return sum(1 for pos, ch in ALL_CRIBS if pos < len(pt_list)
               and AZ[pt_list[pos]] == ch)

# For each period and variant, determine crib key and decode
VARIANTS = [
    ('AZ-Vig',   AZ, lambda ct,pt: (AZ.index(ct)-AZ.index(pt))%26,
                     lambda key,ct: AZ[(AZ.index(ct)-key)%26]),
    ('AZ-Beau',  AZ, lambda ct,pt: (AZ.index(ct)+AZ.index(pt))%26,
                     lambda key,ct: AZ[(key-AZ.index(ct))%26]),
    ('AZ-VBeau', AZ, lambda ct,pt: (AZ.index(pt)-AZ.index(ct))%26,
                     lambda key,ct: AZ[(AZ.index(ct)+key)%26]),
    ('KA-Vig',   KA, lambda ct,pt: (KA.index(ct)-KA.index(pt))%26,
                     lambda key,ct: KA[(KA.index(ct)-key)%26]),
    ('KA-Beau',  KA, lambda ct,pt: (KA.index(ct)+KA.index(pt))%26,
                     lambda key,ct: KA[(key-KA.index(ct))%26]),
    ('KA-VBeau', KA, lambda ct,pt: (KA.index(pt)-KA.index(ct))%26,
                     lambda key,ct: KA[(KA.index(ct)+key)%26]),
]

try:
    import quadgram_scorer
    qg = quadgram_scorer.QuadgramScorer()
except:
    qg = None

def ic(pt_list):
    from collections import Counter
    n = len(pt_list)
    if n < 2: return 0
    counts = Counter(pt_list)
    return sum(v*(v-1) for v in counts.values()) / (n*(n-1))

print("Testing periods 27-52 (beyond Bean proof range)")
print("=" * 70)

all_results = []

for period in range(27, 53):
    # Determine which residues mod period are covered by cribs
    crib_residues = {}  # residue → (pos, ch) list
    for pos, ch in CRIB_DICT.items():
        r = pos % period
        if r not in crib_residues:
            crib_residues[r] = []
        crib_residues[r].append((pos, ch))

    for vname, alpha, key_fn, dec_fn in VARIANTS:
        # Derive key from cribs — check for conflicts
        key = [None] * period
        conflict = False

        for r, cribs in crib_residues.items():
            key_vals = set()
            for pos, ch in cribs:
                try:
                    kv = key_fn(CT_STR[pos], ch)
                    key_vals.add(kv)
                except ValueError:
                    conflict = True
                    break
            if len(key_vals) > 1:
                conflict = True
                break
            if not conflict:
                key[r] = list(key_vals)[0]

        if conflict:
            continue

        # Count constrained vs free key positions
        n_known = sum(1 for k in key if k is not None)
        n_free = period - n_known
        free_residues = [r for r in range(period) if key[r] is None]

        # For periods > 26, try to decrypt the determined positions
        # Count how many CT positions are at determined residues
        constrained_positions = [(i, CT_STR[i]) for i in range(N) if key[i % period] is not None]
        free_positions = [(i, CT_STR[i]) for i in range(N) if key[i % period] is None]

        # Decrypt constrained positions
        pt_partial = [None] * N
        for i, ct_ch in constrained_positions:
            pt_partial[i] = dec_fn(key[i % period], ct_ch)

        # Count crib hits at constrained positions
        crib_hits_constrained = sum(1 for pos, ch in ALL_CRIBS
                                     if pt_partial[pos] is not None
                                     and pt_partial[pos] == ch)

        # Compute IC of constrained positions only
        constrained_pt = [AZ.index(c) for c in pt_partial if c is not None]

        key_str = ''.join(AZ[k] if k is not None else '?' for k in key)

        # For small n_free, try all combinations
        if n_free <= 3:
            best_score = -999
            best_pt_str = None
            best_key_combo = None

            from itertools import product
            for combo in product(range(26), repeat=n_free):
                full_key = list(key)
                for idx, r in enumerate(free_residues):
                    full_key[r] = combo[idx]

                pt = [AZ.index(dec_fn(full_key[i % period], CT_STR[i])) for i in range(N)]
                c_hits = count_cribs(pt)

                if c_hits == 24:
                    pt_str = ''.join(AZ[x] for x in pt)
                    if qg:
                        score = qg.score(pt_str) / N
                    else:
                        score = ic(pt)

                    if score > best_score:
                        best_score = score
                        best_pt_str = pt_str
                        best_key_combo = ''.join(AZ[x] for x in combo)

            if best_pt_str is not None:
                all_results.append({
                    'period': period, 'variant': vname, 'key': key_str,
                    'n_free': n_free, 'free_residues': free_residues,
                    'best_score': best_score, 'pt': best_pt_str,
                    'key_combo': best_key_combo
                })

        # Always report if n_known >= N - 15 (almost fully constrained)
        n_constrained = len(constrained_positions)
        if n_constrained >= N - 15 or n_free <= 3:
            print(f"p={period:2d} {vname:<12} key={key_str[:40]:40s} "
                  f"constrained={n_constrained:3d}/{N} free_residues={free_residues}")

print("\n" + "=" * 70)
print("Results with 24/24 crib hits:")
for r in sorted(all_results, key=lambda x: -x['best_score']):
    print(f"\n  p={r['period']} {r['variant']} score={r['best_score']:.4f}")
    print(f"  Key: {r['key'][:40]} | free combo: {r['key_combo']}")
    print(f"  PT: {r['pt']}")

if not all_results:
    print("  None found.")

# ── Also: quick check for all periods 27-96 with AZ-Beau ─────────────────
print("\n\n" + "=" * 70)
print("AZ-Beaufort: checking ALL periods 27-96 for conflict-free consistency")
print("=" * 70)

conflict_free = []
for period in range(27, 97):
    # Check for conflicts
    key_req = {}
    conflict = False
    for pos, ch in CRIB_DICT.items():
        r = pos % period
        kv = (AZ.index(CT_STR[pos]) + AZ.index(ch)) % 26
        if r in key_req and key_req[r] != kv:
            conflict = True
            break
        key_req[r] = kv

    if not conflict:
        n_free = period - len(key_req)
        n_constrained = sum(1 for i in range(N) if (i % period) in key_req)
        conflict_free.append((period, n_free, n_constrained))

print(f"{'Period':>7} {'Free key pos':>12} {'Constrained CT pos':>18}")
for period, n_free, n_con in conflict_free:
    marker = " ◄ INTERESTING!" if n_free <= 3 else ""
    print(f"{period:>7} {n_free:>12} {n_con:>18}/{N}{marker}")

print(f"\nTotal conflict-free periods (AZ-Beau, 27-96): {len(conflict_free)}")

# Same for all 6 variants
print("\n\nSummary: periods 27-52, all variants, number of conflicts")
print(f"{'Period':>6}", end="")
for vname, *_ in VARIANTS:
    print(f" {vname:>12}", end="")
print()

for period in range(27, 53):
    print(f"{period:>6}", end="")
    for vname, alpha, key_fn, _ in VARIANTS:
        key_req = {}
        conflict = False
        for pos, ch in CRIB_DICT.items():
            r = pos % period
            try:
                kv = key_fn(CT_STR[pos], ch)
            except ValueError:
                conflict = True
                break
            if r in key_req and key_req[r] != kv:
                conflict = True
                break
            key_req[r] = kv
        n_free = period - len(key_req) if not conflict else -1
        print(f" {'-CONFLICT-' if conflict else str(n_free)+' free':>12}", end="")
    print()
