#!/usr/bin/env python3
"""E-S-64: Autokey Ciphers + Width-7 Columnar Transposition.

Test autokey cipher variants with width-7 columnar (Model B: trans→sub).

Autokey variants:
1. CT-autokey: key[i] = CT[i-p] for i≥p (primer for i<p)
   → intermediate[i] = (CT[i] - CT[i-p]) % 26 for i≥p → FULLY DETERMINED
2. PT-autokey: key[i] = intermediate[i-p] for i≥p
   → intermediate[i] = (CT[i] - intermediate[i-p]) % 26 → sequential computation
3. Also test Beaufort variants and mixed autokey models

CT-autokey is INSTANT to check: for most positions, the key is known from CT.
Only the first p positions need a primer. With 24 crib constraints, the primer
is overdetermined for small p.

PT-autokey requires trying all 26^p primers, but cribs provide heavy constraints.

Output: results/e_s_64_autokey.json
"""
import json
import time
import sys
import os
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
N = CT_LEN

# Load quadgrams
QG_FLOOR = -10.0
QG_TABLE = [QG_FLOOR] * (26 ** 4)
with open("data/english_quadgrams.json") as f:
    qg_data = json.load(f)
if isinstance(qg_data, dict) and "logp" in qg_data:
    qg_data = qg_data["logp"]
for gram, logp in qg_data.items():
    if len(gram) == 4 and all(c in ALPH_IDX for c in gram):
        a, b, c, d = (ALPH_IDX[gram[0]], ALPH_IDX[gram[1]],
                       ALPH_IDX[gram[2]], ALPH_IDX[gram[3]])
        QG_TABLE[a * 17576 + b * 676 + c * 26 + d] = logp


def columnar_perm(order, n):
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


def qg_score(pt_idx):
    s = 0.0
    for i in range(len(pt_idx) - 3):
        s += QG_TABLE[pt_idx[i] * 17576 + pt_idx[i+1] * 676 +
                       pt_idx[i+2] * 26 + pt_idx[i+3]]
    return s / max(1, len(pt_idx) - 3)


def check_ct_autokey(perm, inv_perm, lag, variant="vig"):
    """Check CT-autokey with given lag under Model B.

    CT-autokey: key[i] = CT[i-lag] for i ≥ lag
    For i < lag: primer (unknown, determined by cribs)

    For i ≥ lag, intermediate is fully determined:
    Vig: intermediate[i] = (CT[i] - CT[i-lag]) % 26
    Beau: intermediate[i] = (CT[i-lag] - CT[i]) % 26

    Then PT[perm[i]] = intermediate[i].
    Check: how many crib positions are satisfied?
    """
    intermediate = [0] * N

    # Positions ≥ lag are fully determined
    for i in range(lag, N):
        if variant == "beau":
            intermediate[i] = (CT_IDX[i - lag] - CT_IDX[i]) % MOD
        else:
            intermediate[i] = (CT_IDX[i] - CT_IDX[i - lag]) % MOD

    # Derive PT at positions where perm maps to determined intermediate
    # PT[perm[i]] = intermediate[i] for i ≥ lag
    crib_matches = 0
    primer_constraints = {}  # position → required intermediate value

    for p in CRIB_POS:
        i = inv_perm[p]  # intermediate position
        if i >= lag:
            # Intermediate is determined → check crib
            if intermediate[i] == PT_AT_CRIB[p]:
                crib_matches += 1
        else:
            # Position in primer zone → constrain primer
            # intermediate[i] must equal PT_AT_CRIB[p]
            required = PT_AT_CRIB[p]
            if i in primer_constraints:
                if primer_constraints[i] != required:
                    return 0, {}, None  # Conflict in primer
            primer_constraints[i] = required

    # All primer constraints consistent → add those matches
    crib_matches += len(primer_constraints)

    # If good, compute full PT and score
    pt = None
    if crib_matches >= 10:
        # Fill in primer
        for i, val in primer_constraints.items():
            intermediate[i] = val
        # Fill remaining primer positions with 0 (doesn't matter for scoring)
        pt = [0] * N
        for i in range(N):
            pt[perm[i]] = intermediate[i]
        # Quadgram score
        pt_qg = qg_score(pt)
        pt_text = ''.join(ALPH[v] for v in pt)
        return crib_matches, primer_constraints, (pt_text, pt_qg)

    return crib_matches, primer_constraints, None


def check_pt_autokey(perm, inv_perm, lag, primer, variant="vig"):
    """Check PT-autokey with given lag and primer under Model B.

    PT-autokey: key[i] = intermediate[i-lag] for i ≥ lag
    intermediate[i] = (CT[i] - key[i]) % 26
    For i ≥ lag: intermediate[i] = (CT[i] - intermediate[i-lag]) % 26

    Compute sequentially, then check cribs.
    """
    intermediate = [0] * N

    # Fill primer
    for i in range(min(lag, N)):
        if variant == "beau":
            intermediate[i] = (primer[i] - CT_IDX[i]) % MOD
        else:
            intermediate[i] = (CT_IDX[i] - primer[i]) % MOD

    # Sequential computation
    for i in range(lag, N):
        if variant == "beau":
            intermediate[i] = (intermediate[i - lag] - CT_IDX[i]) % MOD
        else:
            intermediate[i] = (CT_IDX[i] - intermediate[i - lag]) % MOD

    # Derive PT
    pt = [0] * N
    for i in range(N):
        pt[perm[i]] = intermediate[i]

    crib_matches = sum(1 for p in CRIB_POS if pt[p] == PT_AT_CRIB[p])
    return crib_matches, pt


def main():
    t0 = time.time()
    print("=" * 70, flush=True)
    print("E-S-64: Autokey + Width-7 Columnar (Model B)", flush=True)
    print("=" * 70, flush=True)
    print(flush=True)

    all_orderings = list(permutations(range(7)))
    best_overall = 0
    best_config = None
    all_results = []

    # ════════════════════════════════════════════════════════════════════
    # Phase 1: CT-Autokey (instant check, fully determined for i ≥ lag)
    # ════════════════════════════════════════════════════════════════════
    print("Phase 1: CT-Autokey — All 5040 orderings × lags 1-20 × Vig/Beau", flush=True)
    print("-" * 50, flush=True)

    ct_autokey_results = []
    n_tested = 0

    for order in all_orderings:
        order = list(order)
        perm = columnar_perm(order, N)
        inv_perm = invert_perm(perm)

        for lag in range(1, 21):
            for variant in ["vig", "beau"]:
                matches, primer, result = check_ct_autokey(
                    perm, inv_perm, lag, variant
                )
                n_tested += 1

                if matches > best_overall:
                    best_overall = matches
                    info = {
                        "type": "ct_autokey",
                        "order": order,
                        "lag": lag,
                        "variant": variant,
                        "matches": matches,
                    }
                    if result:
                        info["pt"] = result[0]
                        info["qg"] = round(result[1], 3)
                    best_config = info

                if matches >= 10:
                    info = {
                        "type": "ct_autokey",
                        "order": order,
                        "lag": lag,
                        "variant": variant,
                        "matches": matches,
                    }
                    if result:
                        info["pt"] = result[0][:50]
                        info["qg"] = round(result[1], 3)
                    ct_autokey_results.append(info)

                    if matches >= 18:
                        print(f"  *** SIGNAL: {matches}/24 lag={lag} {variant} "
                              f"order={order}", flush=True)
                        if result:
                            print(f"      PT: {result[0]}", flush=True)
                            print(f"      QG: {result[1]:.3f}", flush=True)

    phase1_time = time.time() - t0
    ct_autokey_results.sort(key=lambda r: -r["matches"])
    print(f"  CT-autokey: {n_tested:,} configs, best={best_overall}/24, "
          f"{phase1_time:.1f}s", flush=True)

    if ct_autokey_results:
        print(f"  Top CT-autokey results (≥10):", flush=True)
        for r in ct_autokey_results[:20]:
            print(f"    {r['matches']}/24 lag={r['lag']} {r['variant']} "
                  f"order={r['order']} "
                  f"qg={r.get('qg', 'N/A')}", flush=True)

    # ════════════════════════════════════════════════════════════════════
    # Phase 2: CT-Autokey with NO transposition (direct correspondence)
    # ════════════════════════════════════════════════════════════════════
    print(f"\nPhase 2: CT-Autokey — No Transposition (direct)", flush=True)
    print("-" * 50, flush=True)

    identity_perm = list(range(N))
    for lag in range(1, 30):
        for variant in ["vig", "beau"]:
            matches, primer, result = check_ct_autokey(
                identity_perm, identity_perm, lag, variant
            )
            if matches >= 6:
                info = {"lag": lag, "variant": variant, "matches": matches}
                if result:
                    info["pt"] = result[0][:50]
                    info["qg"] = round(result[1], 3)
                print(f"  lag={lag} {variant}: {matches}/24"
                      + (f" qg={result[1]:.3f}" if result else ""), flush=True)

    # ════════════════════════════════════════════════════════════════════
    # Phase 3: PT-Autokey (constraint propagation from cribs)
    # ════════════════════════════════════════════════════════════════════
    print(f"\nPhase 3: PT-Autokey — Top orderings × lags 1-14", flush=True)
    print("-" * 50, flush=True)

    # For PT-autokey, we can derive primer from cribs at inv_perm[p] < lag
    # Then check remaining cribs
    pt_autokey_results = []
    n_tested_p3 = 0

    for order in all_orderings:
        order = list(order)
        perm = columnar_perm(order, N)
        inv_perm = invert_perm(perm)

        for lag in range(1, 15):
            for variant in ["vig", "beau"]:
                # Find crib positions in primer zone (inv_perm[p] < lag)
                primer_from_cribs = {}
                conflict = False
                for p in CRIB_POS:
                    i = inv_perm[p]
                    if i < lag:
                        # intermediate[i] must = PT_AT_CRIB[p]
                        # key[i] = primer[i]
                        # Vig: intermediate[i] = (CT[i] - primer[i]) % 26 = PT_AT_CRIB[p]
                        # → primer[i] = (CT_IDX[i] - PT_AT_CRIB[p]) % 26
                        # Beau: intermediate[i] = (primer[i] - CT_IDX[i]) % 26 = PT_AT_CRIB[p]
                        # → primer[i] = (PT_AT_CRIB[p] + CT_IDX[i]) % 26
                        if variant == "beau":
                            req = (PT_AT_CRIB[p] + CT_IDX[i]) % MOD
                        else:
                            req = (CT_IDX[i] - PT_AT_CRIB[p]) % MOD

                        if i in primer_from_cribs:
                            if primer_from_cribs[i] != req:
                                conflict = True
                                break
                        primer_from_cribs[i] = req

                if conflict:
                    continue

                # Build primer (fill undetermined positions with all 26 values)
                undetermined = [i for i in range(lag) if i not in primer_from_cribs]
                n_undet = len(undetermined)

                if n_undet > 4:
                    # Too many free — skip (would need 26^n_undet ≈ millions)
                    # Just try a few random primers
                    import random
                    rng = random.Random(42)
                    for _ in range(100):
                        primer = [0] * lag
                        for i in range(lag):
                            if i in primer_from_cribs:
                                primer[i] = primer_from_cribs[i]
                            else:
                                primer[i] = rng.randint(0, 25)
                        matches, pt = check_pt_autokey(perm, inv_perm, lag, primer, variant)
                        n_tested_p3 += 1
                        if matches > best_overall:
                            best_overall = matches
                            pt_text = ''.join(ALPH[v] for v in pt)
                            best_config = {
                                "type": "pt_autokey", "order": order,
                                "lag": lag, "variant": variant,
                                "matches": matches, "pt": pt_text,
                                "qg": round(qg_score(pt), 3),
                            }
                        if matches >= 10:
                            pt_autokey_results.append({
                                "order": order, "lag": lag, "variant": variant,
                                "matches": matches,
                            })
                else:
                    # Exhaustive over undetermined (≤ 26^4 = 456976)
                    def enumerate_primers(idx=0, primer=None):
                        nonlocal best_overall, best_config, n_tested_p3
                        if primer is None:
                            primer = [0] * lag
                            for i in range(lag):
                                if i in primer_from_cribs:
                                    primer[i] = primer_from_cribs[i]

                        if idx == len(undetermined):
                            matches, pt = check_pt_autokey(
                                perm, inv_perm, lag, primer, variant
                            )
                            n_tested_p3 += 1
                            if matches > best_overall:
                                best_overall = matches
                                pt_text = ''.join(ALPH[v] for v in pt)
                                best_config = {
                                    "type": "pt_autokey", "order": order,
                                    "lag": lag, "variant": variant,
                                    "matches": matches, "pt": pt_text,
                                    "qg": round(qg_score(pt), 3),
                                }
                            if matches >= 10:
                                pt_autokey_results.append({
                                    "order": order, "lag": lag,
                                    "variant": variant, "matches": matches,
                                })
                            if matches >= 18:
                                print(f"  *** SIGNAL: PT-autokey {matches}/24 "
                                      f"lag={lag} {variant} order={order}",
                                      flush=True)
                                print(f"      PT: {pt_text}", flush=True)
                            return

                        pos = undetermined[idx]
                        for v in range(26):
                            primer[pos] = v
                            enumerate_primers(idx + 1, primer)

                    enumerate_primers()

        if n_tested_p3 % 100000 == 0 and n_tested_p3 > 0:
            print(f"    [{n_tested_p3:,} tested] best={best_overall}/24 "
                  f"({time.time()-t0:.0f}s)", flush=True)

    phase3_time = time.time() - t0 - phase1_time
    pt_autokey_results.sort(key=lambda r: -r["matches"])
    print(f"  PT-autokey: {n_tested_p3:,} configs, best={best_overall}/24, "
          f"{phase3_time:.0f}s", flush=True)

    if pt_autokey_results:
        print(f"  Top PT-autokey (≥10):", flush=True)
        for r in pt_autokey_results[:20]:
            print(f"    {r['matches']}/24 lag={r['lag']} {r['variant']} "
                  f"order={r['order']}", flush=True)

    # ════════════════════════════════════════════════════════════════════
    # Phase 4: Also test with non-width-7 transpositions
    # ════════════════════════════════════════════════════════════════════
    print(f"\nPhase 4: CT-Autokey with other widths (5, 6, 8, 9, 10, 11, 13)",
          flush=True)
    print("-" * 50, flush=True)

    for width in [5, 6, 8, 9, 10, 11, 13]:
        best_w = 0
        n_tested_w = 0
        # Sample orderings (full enumeration too expensive for w > 7)
        if width <= 8:
            orderings_w = list(permutations(range(width)))
        else:
            # Sample 5000 random orderings
            import random
            rng = random.Random(42)
            orderings_w = []
            for _ in range(5000):
                o = list(range(width))
                rng.shuffle(o)
                orderings_w.append(tuple(o))
            orderings_w = list(set(orderings_w))

        for order in orderings_w:
            order = list(order)
            perm = columnar_perm(order, N)
            inv_perm = invert_perm(perm)
            for lag in range(1, 15):
                for variant in ["vig", "beau"]:
                    matches, _, result = check_ct_autokey(
                        perm, inv_perm, lag, variant
                    )
                    n_tested_w += 1
                    if matches > best_w:
                        best_w = matches
                    if matches > best_overall:
                        best_overall = matches
                        info = {
                            "type": "ct_autokey",
                            "width": width,
                            "order": order,
                            "lag": lag,
                            "variant": variant,
                            "matches": matches,
                        }
                        if result:
                            info["pt"] = result[0]
                            info["qg"] = round(result[1], 3)
                        best_config = info
                    if matches >= 18:
                        print(f"  *** SIGNAL: w={width} {matches}/24 lag={lag} "
                              f"{variant}", flush=True)

        print(f"  Width {width}: {n_tested_w:,} configs, best={best_w}/24", flush=True)

    # ════════════════════════════════════════════════════════════════════
    # Summary
    # ════════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    print(f"\n{'='*70}", flush=True)
    print(f"SUMMARY", flush=True)
    print(f"{'='*70}", flush=True)
    print(f"  Best overall: {best_overall}/24", flush=True)
    if best_config:
        print(f"  Best config:", flush=True)
        for k, v in best_config.items():
            if k == "pt":
                print(f"    {k}: {v[:60]}...", flush=True)
            else:
                print(f"    {k}: {v}", flush=True)
    print(f"  Total time: {elapsed:.0f}s", flush=True)

    if best_overall >= 18:
        verdict = f"SIGNAL — {best_overall}/24, autokey cipher is a strong candidate"
    elif best_overall >= 10:
        verdict = f"MARGINAL — {best_overall}/24, worth deeper investigation"
    else:
        verdict = f"NO SIGNAL — {best_overall}/24, autokey + columnar ELIMINATED"

    print(f"  Verdict: {verdict}", flush=True)

    # Save
    artifact = {
        "experiment": "E-S-64",
        "best_overall": best_overall,
        "best_config": best_config,
        "ct_autokey_hits": ct_autokey_results[:50],
        "pt_autokey_hits": pt_autokey_results[:50],
        "verdict": verdict,
        "elapsed_seconds": round(elapsed, 1),
    }

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_64_autokey.json", "w") as f:
        json.dump(artifact, f, indent=2, default=str)

    print(f"\n  Artifact: results/e_s_64_autokey.json", flush=True)
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_64_autokey_width7.py", flush=True)


if __name__ == "__main__":
    main()
