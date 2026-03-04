#!/usr/bin/env python3
"""
Cipher: uncategorized
Family: _uncategorized
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-62: Width-7 Model B — Joint SA Attack on Key + Plaintext.

HYPOTHESIS: K4 uses width-7 columnar transposition (Model B: trans→sub)
with non-periodic substitution (possibly a running key from English text).

EVIDENCE:
- Lag-7 autocorrelation: z=3.036, p≈0.002
- Crib alignment at width 7: p=0.021
- K3 uses width-7 columnar transposition
- Model A disfavored (CT[σ(27)]≠CT[σ(65)] for all width-7 combos)
- Joint probability of width-7 coincidences: p ≈ 4×10⁻⁵

APPROACH:
Phase 1: Periodic key consistency (5040 × p2-14 × 4 variants)
         Any hit at p≤7 is essentially impossible by chance (~10⁻²⁴)
Phase 2: Joint SA filter (5040 × Vig/Beau, 5K iters each)
         Score: quadgram(PT) + α×quadgram(key), α=1.0
         Discrimination comes from KEY quality (PT-only gives same result for all orderings)
Phase 3: Deep SA on top 50 (200K iters × 5 restarts)
Phase 4: Report best candidates

Model B decryption:
  intermediate[i] = (CT[i] - key[i]) % 26  [Vig]
  intermediate[i] = (key[i] - CT[i]) % 26  [Beau]
  PT[j] = intermediate[inv_perm[j]]

Key derivation at crib position p (PT pos → CT pos inv_perm[p]):
  key[inv_perm[p]] = (CT[inv_perm[p]] - PT[p]) % 26  [Vig]
  key[inv_perm[p]] = (CT[inv_perm[p]] + PT[p]) % 26  [Beau]

Output: results/e_s_62_width7_sa.json
"""
import json
import time
import sys
import os
import random
import math
from itertools import permutations
from collections import defaultdict

sys.path.insert(0, "src")
from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS,
    KRYPTOS_ALPHABET,
)

CT_IDX = [ALPH_IDX[c] for c in CT]
CRIB_POS = sorted(CRIB_POSITIONS)
PT_AT_CRIB = {p: ALPH_IDX[ch] for p, ch in CRIB_DICT.items()}
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
CT_KA_IDX = [KA_IDX[c] for c in CT]
N = CT_LEN

# ── Load quadgrams into flat lookup table ────────────────────────────────
print("Loading quadgrams...", flush=True)
QG_FLOOR = -10.0
QG_TABLE = [QG_FLOOR] * (26 ** 4)
n_loaded = 0
with open("data/english_quadgrams.json") as f:
    qg_data = json.load(f)
# Handle both flat and nested formats
if isinstance(qg_data, dict) and "logp" in qg_data:
    qg_data = qg_data["logp"]
for gram, logp in qg_data.items():
    if len(gram) == 4 and all(c in ALPH_IDX for c in gram):
        a, b, c, d = (ALPH_IDX[gram[0]], ALPH_IDX[gram[1]],
                       ALPH_IDX[gram[2]], ALPH_IDX[gram[3]])
        QG_TABLE[a * 17576 + b * 676 + c * 26 + d] = logp
        n_loaded += 1
print(f"  {n_loaded} quadgrams loaded", flush=True)


# ── Permutation utilities ────────────────────────────────────────────────

def columnar_perm(order, n):
    """Build columnar transposition permutation (gather convention).

    perm[i] = PT position that goes to intermediate position i.
    So intermediate[i] = PT[perm[i]].
    """
    width = len(order)
    nf = n // width
    extra = n % width
    heights = [nf + (1 if c < extra else 0) for c in range(width)]
    perm = []
    for ri in range(width):
        col = order[ri]
        for row in range(heights[col]):
            perm.append(row * width + col)
    return perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# ── Key derivation ───────────────────────────────────────────────────────

def derive_constraints(inv_perm, variant):
    """Derive constrained key values at intermediate positions from cribs."""
    fixed = {}
    use_ka = variant.startswith("ka_")
    for p in CRIB_POS:
        i = inv_perm[p]
        ct_val = CT_KA_IDX[i] if use_ka else CT_IDX[i]
        pt_val = KA_IDX[CRIB_DICT[p]] if use_ka else PT_AT_CRIB[p]
        if "beau" in variant:
            fixed[i] = (ct_val + pt_val) % MOD
        else:
            fixed[i] = (ct_val - pt_val) % MOD
    return fixed


# ── Periodic consistency check ───────────────────────────────────────────

def check_periodic(fixed, period):
    """Check if all constrained key values are consistent with period p."""
    residues = {}
    for pos, val in fixed.items():
        r = pos % period
        if r in residues:
            if residues[r] != val:
                return False, {}
        else:
            residues[r] = val
    return True, residues


def decrypt_periodic(perm, key_residues, period, variant):
    """Decrypt with a periodic key under Model B."""
    use_ka = variant.startswith("ka_")
    pt = [0] * N
    for i in range(N):
        k = key_residues.get(i % period, 0)
        ct_val = CT_KA_IDX[i] if use_ka else CT_IDX[i]
        if "beau" in variant:
            inter = (k - ct_val) % MOD
        else:
            inter = (ct_val - k) % MOD
        if use_ka:
            pt[perm[i]] = ALPH_IDX[KA[inter]]
        else:
            pt[perm[i]] = inter
    return pt


# ── Simulated Annealing ─────────────────────────────────────────────────

def sa_joint(perm, inv_perm, fixed, variant, n_iters, alpha_key=1.0, seed=42):
    """SA optimizing joint quadgram score of plaintext AND key.

    Score = quadgram(PT) + alpha_key * quadgram(key)

    Critical: with alpha_key=0, all orderings give the same result
    (PT-only SA is ordering-independent). Discrimination requires alpha_key > 0.
    """
    rng = random.Random(seed)
    use_ka = variant.startswith("ka_")

    # Initialize key: fixed positions from cribs, free positions random
    key = [0] * N
    free_pos = []
    for i in range(N):
        if i in fixed:
            key[i] = fixed[i]
        else:
            key[i] = rng.randint(0, 25)
            free_pos.append(i)

    n_free = len(free_pos)
    if n_free == 0:
        return -999.0, "", "", -999.0, -999.0

    # Compute initial intermediate, PT, and scores
    intermediate = [0] * N
    pt = [0] * N
    for i in range(N):
        ct_val = CT_KA_IDX[i] if use_ka else CT_IDX[i]
        if "beau" in variant:
            intermediate[i] = (key[i] - ct_val) % MOD
        else:
            intermediate[i] = (ct_val - key[i]) % MOD
        if use_ka:
            pt[perm[i]] = ALPH_IDX[KA[intermediate[i]]]
        else:
            pt[perm[i]] = intermediate[i]

    # Compute initial scores
    pt_score = 0.0
    for i in range(N - 3):
        pt_score += QG_TABLE[pt[i] * 17576 + pt[i+1] * 676 + pt[i+2] * 26 + pt[i+3]]

    key_score = 0.0
    if alpha_key > 0:
        for i in range(N - 3):
            key_score += QG_TABLE[key[i] * 17576 + key[i+1] * 676 + key[i+2] * 26 + key[i+3]]

    score = pt_score + alpha_key * key_score
    best_score = score
    best_pt = pt[:]
    best_key = key[:]
    best_pt_score = pt_score
    best_key_score = key_score

    # Temperature schedule
    T = 2.0
    T_min = 0.005
    cool = (T_min / T) ** (1.0 / max(1, n_iters))

    for step in range(n_iters):
        # Pick random free position
        i = free_pos[rng.randint(0, n_free - 1)]
        old_kv = key[i]
        new_kv = rng.randint(0, 24)
        if new_kv >= old_kv:
            new_kv += 1

        # Compute new intermediate value
        ct_val = CT_KA_IDX[i] if use_ka else CT_IDX[i]
        if "beau" in variant:
            new_inter = (new_kv - ct_val) % MOD
        else:
            new_inter = (ct_val - new_kv) % MOD

        # Affected PT position
        j = perm[i]
        if use_ka:
            new_pt_val = ALPH_IDX[KA[new_inter]]
        else:
            new_pt_val = new_inter
        old_pt_val = pt[j]

        if new_pt_val == old_pt_val and new_kv == old_kv:
            T *= cool
            continue

        # Compute PT score delta (quadgrams containing position j)
        delta_pt = 0.0
        for s in range(max(0, j - 3), min(N - 3, j + 1)):
            # Old quadgram
            delta_pt -= QG_TABLE[pt[s] * 17576 + pt[s+1] * 676 + pt[s+2] * 26 + pt[s+3]]
            # New quadgram (replace pt[j])
            vals = [pt[s], pt[s+1], pt[s+2], pt[s+3]]
            vals[j - s] = new_pt_val
            delta_pt += QG_TABLE[vals[0] * 17576 + vals[1] * 676 + vals[2] * 26 + vals[3]]

        # Compute key score delta (quadgrams containing position i)
        delta_key = 0.0
        if alpha_key > 0:
            for s in range(max(0, i - 3), min(N - 3, i + 1)):
                delta_key -= QG_TABLE[key[s] * 17576 + key[s+1] * 676 + key[s+2] * 26 + key[s+3]]
                vals = [key[s], key[s+1], key[s+2], key[s+3]]
                vals[i - s] = new_kv
                delta_key += QG_TABLE[vals[0] * 17576 + vals[1] * 676 + vals[2] * 26 + vals[3]]

        delta = delta_pt + alpha_key * delta_key

        # Accept/reject
        if delta > 0 or rng.random() < math.exp(delta / max(T, 1e-10)):
            key[i] = new_kv
            intermediate[i] = new_inter
            pt[j] = new_pt_val
            pt_score += delta_pt
            key_score += delta_key
            score += delta
            if score > best_score:
                best_score = score
                best_pt = pt[:]
                best_key = key[:]
                best_pt_score = pt_score
                best_key_score = key_score

        T *= cool

    n_qg = max(1, N - 3)
    return (best_score / n_qg, ''.join(ALPH[v] for v in best_pt),
            ''.join(ALPH[v] for v in best_key),
            best_pt_score / n_qg, best_key_score / n_qg)


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()
    print("=" * 70, flush=True)
    print("E-S-62: Width-7 Model B — Joint SA Attack", flush=True)
    print("=" * 70, flush=True)
    print(f"CT: {CT}", flush=True)
    print(f"Cribs: {CRIB_POS[0]}-{CRIB_POS[12]} (ENE), {CRIB_POS[13]}-{CRIB_POS[23]} (BC)")
    print(flush=True)

    all_orderings = list(permutations(range(7)))
    variants = ["vig", "beau", "ka_vig", "ka_beau"]

    # ════════════════════════════════════════════════════════════════════
    # Phase 1: Periodic Key Consistency Check
    # ════════════════════════════════════════════════════════════════════
    print("Phase 1: Periodic Key Consistency Check", flush=True)
    print("-" * 50, flush=True)

    periodic_hits = []
    for order in all_orderings:
        order = list(order)
        perm = columnar_perm(order, N)
        inv_perm = invert_perm(perm)

        for variant in variants:
            fixed = derive_constraints(inv_perm, variant)
            for period in range(2, 15):
                ok, residues = check_periodic(fixed, period)
                if ok:
                    periodic_hits.append({
                        "order": order,
                        "variant": variant,
                        "period": period,
                        "residues": residues,
                        "n_populated": len(residues),
                    })

    # Group by period
    by_period = defaultdict(list)
    for h in periodic_hits:
        by_period[h["period"]].append(h)
    print(f"  Total periodic hits: {len(periodic_hits)}", flush=True)
    for p in sorted(by_period):
        n_extra = 24 - by_period[p][0]["n_populated"] if by_period[p] else 0
        p_random = (1.0 / 26) ** max(0, n_extra)
        print(f"  Period {p:2d}: {len(by_period[p]):5d} hits "
              f"(extra constraints: {n_extra}, P(random)≈{p_random:.1e})", flush=True)

    # Score all periodic hits at p ≤ 7
    interesting = []
    for h in periodic_hits:
        if h["period"] > 7:
            continue
        order = h["order"]
        perm = columnar_perm(order, N)
        pt = decrypt_periodic(perm, h["residues"], h["period"], h["variant"])
        qg = 0.0
        for i in range(N - 3):
            qg += QG_TABLE[pt[i] * 17576 + pt[i+1] * 676 + pt[i+2] * 26 + pt[i+3]]
        qg_pc = qg / max(1, N - 3)
        pt_text = ''.join(ALPH[v] for v in pt)
        crib_ok = sum(1 for p in CRIB_POS if pt[p] == PT_AT_CRIB[p])
        h["qg"] = qg_pc
        h["pt"] = pt_text
        h["cribs"] = crib_ok
        if qg_pc > -7.0 or crib_ok >= 20:
            interesting.append(h)

    interesting.sort(key=lambda h: -h.get("qg", -999))
    if interesting:
        print(f"\n  *** INTERESTING PERIODIC HITS (p≤7) ***", flush=True)
        for h in interesting[:30]:
            print(f"    p={h['period']} {h['variant']:8s} order={h['order']} "
                  f"cribs={h['cribs']}/24 qg={h['qg']:.3f} "
                  f"PT={h['pt'][:50]}...", flush=True)
    else:
        print(f"  No interesting periodic hits at p≤7 (expected if key is non-periodic)",
              flush=True)

    phase1_time = time.time() - t0
    print(f"  Phase 1 time: {phase1_time:.1f}s\n", flush=True)

    # ════════════════════════════════════════════════════════════════════
    # Phase 2: Quick Joint SA on All Orderings
    # ════════════════════════════════════════════════════════════════════
    print("Phase 2: Quick Joint SA Filter (5040 orderings × Vig/Beau)", flush=True)
    print(f"  SA: 5K iters, alpha_key=1.0 (joint PT+key scoring)", flush=True)
    print("-" * 50, flush=True)

    quick_results = []
    n_done = 0

    for order in all_orderings:
        order = list(order)
        perm = columnar_perm(order, N)
        inv_perm = invert_perm(perm)

        for variant in ["vig", "beau"]:
            fixed = derive_constraints(inv_perm, variant)
            joint_spc, pt_text, key_text, pt_spc, key_spc = sa_joint(
                perm, inv_perm, fixed, variant,
                n_iters=5000, alpha_key=1.0, seed=42
            )
            quick_results.append({
                "order": order,
                "variant": variant,
                "joint_spc": joint_spc,
                "pt_spc": pt_spc,
                "key_spc": key_spc,
                "pt_preview": pt_text[:50],
                "key_preview": key_text[:50],
            })

        n_done += 1
        if n_done % 500 == 0:
            best_j = max(r["joint_spc"] for r in quick_results)
            best_p = max(r["pt_spc"] for r in quick_results)
            best_k = max(r["key_spc"] for r in quick_results)
            elapsed = time.time() - t0
            print(f"  [{n_done:5d}/5040] best_joint={best_j:.3f} "
                  f"pt={best_p:.3f} key={best_k:.3f} ({elapsed:.0f}s)", flush=True)

    quick_results.sort(key=lambda r: -r["joint_spc"])
    phase2_time = time.time() - t0 - phase1_time

    print(f"\n  Phase 2 done: {len(quick_results)} configs in {phase2_time:.0f}s", flush=True)
    print(f"\n  Top 15 by joint score:", flush=True)
    for i, r in enumerate(quick_results[:15]):
        print(f"    {i+1:3d}. joint={r['joint_spc']:.3f} pt={r['pt_spc']:.3f} "
              f"key={r['key_spc']:.3f} {r['variant']} order={r['order']}", flush=True)

    # Also rank by key score only (important discriminator)
    key_ranked = sorted(quick_results, key=lambda r: -r["key_spc"])
    print(f"\n  Top 15 by KEY score (main discriminator):", flush=True)
    for i, r in enumerate(key_ranked[:15]):
        print(f"    {i+1:3d}. key={r['key_spc']:.3f} pt={r['pt_spc']:.3f} "
              f"joint={r['joint_spc']:.3f} {r['variant']} order={r['order']}", flush=True)

    # ════════════════════════════════════════════════════════════════════
    # Phase 3: Deep Joint SA on Top Candidates
    # ════════════════════════════════════════════════════════════════════
    print(f"\nPhase 3: Deep Joint SA on Top 50 ({time.time()-t0:.0f}s elapsed)", flush=True)
    print("-" * 50, flush=True)

    # Take top 50 unique (order, variant) by joint score
    seen = set()
    top_configs = []
    for r in quick_results:
        cfg = (tuple(r["order"]), r["variant"])
        if cfg not in seen:
            seen.add(cfg)
            top_configs.append((r["order"], r["variant"]))
            if len(top_configs) >= 50:
                break

    # Also include some top-key-ranked configs not already in the list
    for r in key_ranked:
        cfg = (tuple(r["order"]), r["variant"])
        if cfg not in seen:
            seen.add(cfg)
            top_configs.append((r["order"], r["variant"]))
            if len(top_configs) >= 70:
                break

    deep_results = []
    for ci, (order, variant) in enumerate(top_configs):
        perm = columnar_perm(order, N)
        inv_perm = invert_perm(perm)
        fixed = derive_constraints(inv_perm, variant)

        best_joint = -999.0
        best_pt_text = ""
        best_key_text = ""
        best_pt_spc = -999.0
        best_key_spc = -999.0

        for restart in range(5):
            joint_spc, pt_text, key_text, pt_spc, key_spc = sa_joint(
                perm, inv_perm, fixed, variant,
                n_iters=200000, alpha_key=1.0, seed=restart * 7919
            )
            if joint_spc > best_joint:
                best_joint = joint_spc
                best_pt_text = pt_text
                best_key_text = key_text
                best_pt_spc = pt_spc
                best_key_spc = key_spc

        deep_results.append({
            "order": list(order),
            "variant": variant,
            "joint_spc": round(best_joint, 4),
            "pt_spc": round(best_pt_spc, 4),
            "key_spc": round(best_key_spc, 4),
            "pt": best_pt_text,
            "key": best_key_text,
        })

        if (ci + 1) % 10 == 0:
            print(f"  [{ci+1}/{len(top_configs)}] ({time.time()-t0:.0f}s)", flush=True)

    deep_results.sort(key=lambda r: -r["joint_spc"])

    print(f"\n  Deep SA done ({time.time()-t0:.0f}s)", flush=True)
    print(f"\n  Top 20 by joint score:", flush=True)
    for i, r in enumerate(deep_results[:20]):
        pt_idx = [ALPH_IDX[c] for c in r["pt"]]
        cribs = sum(1 for p in CRIB_POS if pt_idx[p] == PT_AT_CRIB[p])
        print(f"  {i+1:3d}. joint={r['joint_spc']:.3f} pt={r['pt_spc']:.3f} "
              f"key={r['key_spc']:.3f} cribs={cribs}/24 "
              f"{r['variant']} order={r['order']}", flush=True)
        print(f"       PT:  {r['pt']}", flush=True)
        print(f"       KEY: {r['key'][:60]}...", flush=True)

    # Also show top by KEY score in deep results
    deep_by_key = sorted(deep_results, key=lambda r: -r["key_spc"])
    print(f"\n  Top 10 by KEY score (deep):", flush=True)
    for i, r in enumerate(deep_by_key[:10]):
        pt_idx = [ALPH_IDX[c] for c in r["pt"]]
        cribs = sum(1 for p in CRIB_POS if pt_idx[p] == PT_AT_CRIB[p])
        print(f"  {i+1:3d}. key={r['key_spc']:.3f} pt={r['pt_spc']:.3f} "
              f"joint={r['joint_spc']:.3f} cribs={cribs}/24 "
              f"{r['variant']} order={r['order']}", flush=True)
        print(f"       PT:  {r['pt']}", flush=True)
        print(f"       KEY: {r['key'][:60]}...", flush=True)

    # ════════════════════════════════════════════════════════════════════
    # Phase 4: Also try PT-only SA + key scoring (different alpha values)
    # ════════════════════════════════════════════════════════════════════
    print(f"\nPhase 4: PT-only SA + Key Scoring on Top 20 ({time.time()-t0:.0f}s)", flush=True)
    print("-" * 50, flush=True)

    # For top 20, also try alpha_key=0 (PT-only) and score the resulting key
    pt_only_results = []
    top20_configs = [(r["order"], r["variant"]) for r in deep_results[:20]]

    for order, variant in top20_configs:
        perm = columnar_perm(order, N)
        inv_perm = invert_perm(perm)
        fixed = derive_constraints(inv_perm, variant)

        best_pt_spc = -999.0
        best_key_spc_from_pt = -999.0
        best_pt_text = ""
        best_key_text = ""

        for restart in range(3):
            _, pt_text, key_text, pt_spc, _ = sa_joint(
                perm, inv_perm, fixed, variant,
                n_iters=200000, alpha_key=0.0, seed=restart * 3571
            )
            # Score the key that falls out from PT-optimized SA
            key_idx = [ALPH_IDX[c] for c in key_text]
            ks = 0.0
            for i in range(N - 3):
                ks += QG_TABLE[key_idx[i] * 17576 + key_idx[i+1] * 676 +
                               key_idx[i+2] * 26 + key_idx[i+3]]
            key_spc = ks / max(1, N - 3)

            if pt_spc > best_pt_spc:
                best_pt_spc = pt_spc
                best_key_spc_from_pt = key_spc
                best_pt_text = pt_text
                best_key_text = key_text

        pt_only_results.append({
            "order": list(order),
            "variant": variant,
            "pt_spc": round(best_pt_spc, 4),
            "key_spc_from_pt": round(best_key_spc_from_pt, 4),
            "pt": best_pt_text,
            "key": best_key_text,
        })

    pt_only_results.sort(key=lambda r: -r["key_spc_from_pt"])
    print(f"  Top 10 (ranked by key quality from PT-only SA):", flush=True)
    for i, r in enumerate(pt_only_results[:10]):
        print(f"    {i+1}. pt={r['pt_spc']:.3f} key_from_pt={r['key_spc_from_pt']:.3f} "
              f"{r['variant']} order={r['order']}", flush=True)
        print(f"       PT:  {r['pt']}", flush=True)
        print(f"       KEY: {r['key'][:60]}...", flush=True)

    # ════════════════════════════════════════════════════════════════════
    # Summary & Save
    # ════════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print(f"\n{'='*70}", flush=True)
    print(f"SUMMARY", flush=True)
    print(f"{'='*70}", flush=True)
    n_periodic_low = sum(len(v) for p, v in by_period.items() if p <= 7)
    print(f"  Periodic hits (p≤7): {n_periodic_low}", flush=True)
    print(f"  Interesting periodic (p≤7): {len(interesting)}", flush=True)
    if quick_results:
        print(f"  Quick SA best joint: {quick_results[0]['joint_spc']:.3f}", flush=True)
    if deep_results:
        print(f"  Deep SA best joint: {deep_results[0]['joint_spc']:.3f}", flush=True)
        print(f"  Deep SA best key: {deep_by_key[0]['key_spc']:.3f}", flush=True)
        print(f"  Deep SA best PT: {max(r['pt_spc'] for r in deep_results):.3f}", flush=True)
    print(f"  Total time: {elapsed:.0f}s", flush=True)

    # Verdict
    best_deep_joint = deep_results[0]["joint_spc"] if deep_results else -999
    if best_deep_joint > -4.5:
        verdict = "SIGNAL — joint score suggests real English PT+key"
    elif best_deep_joint > -5.5:
        verdict = "MARGINAL — investigate further"
    else:
        verdict = "NO SIGNAL — no ordering produces coherent English PT+key"
    print(f"  Verdict: {verdict}", flush=True)

    # Save artifact
    artifact = {
        "experiment": "E-S-62",
        "description": "Width-7 Model B joint SA attack (PT + key scoring)",
        "elapsed_seconds": round(elapsed, 1),
        "periodic_hits_total": len(periodic_hits),
        "periodic_by_period": {str(p): len(v) for p, v in by_period.items()},
        "interesting_periodic": [
            {"period": h["period"], "variant": h["variant"], "order": h["order"],
             "qg": round(h.get("qg", -999), 3), "cribs": h.get("cribs", 0),
             "pt": h.get("pt", "")}
            for h in interesting[:50]
        ],
        "quick_sa_top30": [
            {"joint": round(r["joint_spc"], 3), "pt": round(r["pt_spc"], 3),
             "key": round(r["key_spc"], 3), "order": r["order"], "variant": r["variant"]}
            for r in quick_results[:30]
        ],
        "deep_sa_top30": [r for r in deep_results[:30]],
        "pt_only_sa": pt_only_results,
        "verdict": verdict,
    }

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_62_width7_sa.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_s_62_width7_sa.json", flush=True)
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_62_width7_sa.py", flush=True)


if __name__ == "__main__":
    main()
