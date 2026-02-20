#!/usr/bin/env python3
"""E-S-63: K3 Method Variants — Systematic Search.

K3 was solved with: Vigenère(keyword=PALIMPSEST) → Columnar(keyword=KRYPTOS)
This is Model B (trans→sub) with width-7 columnar + period-10 Vigenère.

K4 has a "change in methodology" (Scheidt). Test variants:
1. Same structure, different keywords for transposition and/or substitution
2. Beaufort instead of Vigenère
3. Keyword-mixed alphabet (KRYPTOS alphabet) instead of standard
4. Different transposition widths with keyword-derived orderings
5. Keywords from thematic sources (Kryptos, CIA, Berlin, Egypt, etc.)

This is a DIRECT ATTACK: for each (trans_keyword, sub_keyword, variant),
fully decrypt and check all 24 cribs. No SA needed.

Output: results/e_s_63_k3_variants.json
"""
import json
import time
import sys
import os
from itertools import product

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


def keyword_to_order(keyword):
    """Convert keyword to column reading order for columnar transposition."""
    w = len(keyword)
    indexed = sorted(range(w), key=lambda i: (keyword[i], i))
    # indexed[rank] = column → read column indexed[0] first, etc.
    return indexed


def keyword_to_mixed_alphabet(keyword):
    """Generate a keyword-mixed alphabet (remove duplicates, append remaining)."""
    seen = set()
    mixed = []
    for c in keyword.upper():
        if c in ALPH_IDX and c not in seen:
            seen.add(c)
            mixed.append(c)
    for c in ALPH:
        if c not in seen:
            mixed.append(c)
    return ''.join(mixed)


def columnar_perm(order, n):
    """Columnar transposition permutation (gather convention)."""
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


def decrypt_model_b(perm, sub_key_indices, variant, mixed_alph=None):
    """Decrypt under Model B: CT → inv_sub → intermediate → inv_trans → PT.

    sub_key_indices: list of 97 key values (0-25), applied periodically or as given.
    variant: 'vig' or 'beau'
    mixed_alph: if provided, use this alphabet instead of standard A-Z.
    """
    if mixed_alph:
        ma_idx = {c: i for i, c in enumerate(mixed_alph)}
        ct_vals = [ma_idx[c] for c in CT]
    else:
        ct_vals = CT_IDX

    intermediate = [0] * N
    for i in range(N):
        k = sub_key_indices[i % len(sub_key_indices)] if len(sub_key_indices) < N else sub_key_indices[i]
        if variant == "beau":
            intermediate[i] = (k - ct_vals[i]) % MOD
        else:
            intermediate[i] = (ct_vals[i] - k) % MOD

    # Inverse transposition: PT[perm[i]] = intermediate[i]
    pt = [0] * N
    for i in range(N):
        if mixed_alph:
            pt[perm[i]] = ALPH_IDX[mixed_alph[intermediate[i]]]
        else:
            pt[perm[i]] = intermediate[i]

    return pt


def score_pt(pt):
    """Crib matches + quadgram score."""
    cribs = sum(1 for p in CRIB_POS if pt[p] == PT_AT_CRIB[p])
    qg = 0.0
    for i in range(N - 3):
        qg += QG_TABLE[pt[i] * 17576 + pt[i+1] * 676 + pt[i+2] * 26 + pt[i+3]]
    return cribs, qg / max(1, N - 3)


# ── Keyword lists ────────────────────────────────────────────────────────

TRANS_KEYWORDS = [
    # K3 keyword
    "KRYPTOS",
    # Thematic (CIA, Kryptos sculpture)
    "PALIMPSEST", "ABSCISSA", "SHADOW", "SANBORN", "SCHEIDT",
    "LANGLEY", "IQLUSION", "LUCID", "CIPHER", "SECRET",
    # Berlin / Cold War
    "BERLIN", "CHECKPOINT", "WALL", "COLDWAR", "FREEDOM",
    # Egypt
    "EGYPT", "NILE", "PHARAOH", "PYRAMID", "CARTER",
    "TUTANKHAMUN", "HIEROGLYPH", "SPHINX", "LUXOR", "THEBES",
    # From Sanborn's 2025 open letter
    "WHATSTHEPOINT", "MESSAGE", "DELIVER", "POINT",
    # CIA related
    "INTELLIGENCE", "AGENCY", "CENTRAL", "DIRECTOR",
    "COVERT", "CLASSI", "CLASSIFIED",
    # Coordinates / locations
    "NORTH", "SOUTH", "EAST", "WEST", "COMPASS",
    "LATITUDE", "LONGITUDE", "DEGREES",
    # Numbers as words
    "SEVEN", "NINETY", "NINETYSEVEN", "PRIME",
    # Misc Kryptos-related
    "BETWEEN", "SUBTLE", "SHADING", "UNDERGROUND",
    "PASSAGE", "SLOWLY", "DESPERATELY", "DARKNESS",
    "TOTALLY", "INVISIBLE",
]

# For substitution, test these as periodic Vigenère/Beaufort keys
SUB_KEYWORDS = TRANS_KEYWORDS[:]

# Mixed alphabets to test
MIXED_ALPHABETS = {
    "standard": ALPH,
    "KRYPTOS": keyword_to_mixed_alphabet("KRYPTOS"),
    "PALIMPSEST": keyword_to_mixed_alphabet("PALIMPSEST"),
    "ABSCISSA": keyword_to_mixed_alphabet("ABSCISSA"),
    "SANBORN": keyword_to_mixed_alphabet("SANBORN"),
    "SCHEIDT": keyword_to_mixed_alphabet("SCHEIDT"),
    "BERLIN": keyword_to_mixed_alphabet("BERLIN"),
    "SHADOW": keyword_to_mixed_alphabet("SHADOW"),
    "CIPHER": keyword_to_mixed_alphabet("CIPHER"),
    "SECRET": keyword_to_mixed_alphabet("SECRET"),
}


def main():
    t0 = time.time()
    print("=" * 70, flush=True)
    print("E-S-63: K3 Method Variants — Systematic Search", flush=True)
    print("=" * 70, flush=True)
    print(f"Trans keywords: {len(TRANS_KEYWORDS)}", flush=True)
    print(f"Sub keywords: {len(SUB_KEYWORDS)}", flush=True)
    print(f"Mixed alphabets: {len(MIXED_ALPHABETS)}", flush=True)
    print(f"Variants: vig, beau", flush=True)
    print(flush=True)

    best_overall = 0
    best_config = None
    all_results = []
    n_tested = 0
    n_signal = 0

    # ── Phase 1: Standard Alphabet Tests ────────────────────────────────
    print("Phase 1: Standard Alphabet — All Keyword Pairs × Vig/Beau", flush=True)
    print("-" * 50, flush=True)

    for trans_kw in TRANS_KEYWORDS:
        # Compute transposition (use keyword length as width)
        width = len(set(trans_kw))  # unique chars determine width
        if width < 3 or width > 20:
            continue
        # But for columnar, width = len(keyword)
        order = keyword_to_order(trans_kw)
        perm = columnar_perm(order, N)

        for sub_kw in SUB_KEYWORDS:
            sub_key = [ALPH_IDX[sub_kw[i % len(sub_kw)]] for i in range(N)]

            for variant in ["vig", "beau"]:
                pt = decrypt_model_b(perm, sub_key, variant)
                cribs, qg = score_pt(pt)
                n_tested += 1

                if cribs > best_overall:
                    best_overall = cribs
                    pt_text = ''.join(ALPH[v] for v in pt)
                    best_config = {
                        "trans_kw": trans_kw, "sub_kw": sub_kw,
                        "variant": variant, "alphabet": "standard",
                        "cribs": cribs, "qg": round(qg, 3),
                        "pt": pt_text,
                    }

                if cribs >= 10:
                    n_signal += 1
                    pt_text = ''.join(ALPH[v] for v in pt)
                    all_results.append({
                        "trans_kw": trans_kw, "sub_kw": sub_kw,
                        "variant": variant, "alphabet": "standard",
                        "cribs": cribs, "qg": round(qg, 3),
                        "pt": pt_text[:50],
                    })
                    if cribs >= 18:
                        print(f"  *** SIGNAL: cribs={cribs}/24 qg={qg:.3f} "
                              f"trans={trans_kw} sub={sub_kw} {variant}", flush=True)
                        print(f"      PT: {pt_text}", flush=True)

        if n_tested % 5000 == 0:
            print(f"    [{n_tested:,} tested] best={best_overall}/24 signals={n_signal} "
                  f"({time.time()-t0:.0f}s)", flush=True)

    phase1_time = time.time() - t0
    print(f"  Phase 1: {n_tested:,} configs, best={best_overall}/24, "
          f"signals(≥10)={n_signal}, {phase1_time:.0f}s", flush=True)

    # ── Phase 2: Mixed Alphabet Tests ───────────────────────────────────
    print(f"\nPhase 2: Mixed Alphabets × All Keyword Pairs × Vig/Beau", flush=True)
    print("-" * 50, flush=True)

    n_tested_p2 = 0
    for alph_name, mixed_alph in MIXED_ALPHABETS.items():
        if alph_name == "standard":
            continue  # Already tested in Phase 1

        for trans_kw in TRANS_KEYWORDS:
            order = keyword_to_order(trans_kw)
            perm = columnar_perm(order, N)

            for sub_kw in SUB_KEYWORDS:
                ma_idx = {c: i for i, c in enumerate(mixed_alph)}
                sub_key = [ma_idx.get(sub_kw[i % len(sub_kw)], 0) for i in range(N)]

                for variant in ["vig", "beau"]:
                    pt = decrypt_model_b(perm, sub_key, variant, mixed_alph)
                    cribs, qg = score_pt(pt)
                    n_tested += 1
                    n_tested_p2 += 1

                    if cribs > best_overall:
                        best_overall = cribs
                        pt_text = ''.join(ALPH[v] for v in pt)
                        best_config = {
                            "trans_kw": trans_kw, "sub_kw": sub_kw,
                            "variant": variant, "alphabet": alph_name,
                            "cribs": cribs, "qg": round(qg, 3),
                            "pt": pt_text,
                        }

                    if cribs >= 10:
                        n_signal += 1
                        pt_text = ''.join(ALPH[v] for v in pt)
                        all_results.append({
                            "trans_kw": trans_kw, "sub_kw": sub_kw,
                            "variant": variant, "alphabet": alph_name,
                            "cribs": cribs, "qg": round(qg, 3),
                            "pt": pt_text[:50],
                        })
                        if cribs >= 18:
                            print(f"  *** SIGNAL: cribs={cribs}/24 qg={qg:.3f} "
                                  f"trans={trans_kw} sub={sub_kw} {variant} "
                                  f"alph={alph_name}", flush=True)
                            print(f"      PT: {pt_text}", flush=True)

            if n_tested_p2 % 10000 == 0:
                print(f"    [{n_tested_p2:,} tested] best={best_overall}/24 "
                      f"({time.time()-t0:.0f}s)", flush=True)

    phase2_time = time.time() - t0 - phase1_time
    print(f"  Phase 2: {n_tested_p2:,} configs, best={best_overall}/24, "
          f"{phase2_time:.0f}s", flush=True)

    # ── Phase 3: Model A variant (sub→trans) ────────────────────────────
    print(f"\nPhase 3: Model A (sub→trans) — Key Keyword Pairs", flush=True)
    print("-" * 50, flush=True)

    n_tested_p3 = 0
    for trans_kw in TRANS_KEYWORDS:
        order = keyword_to_order(trans_kw)
        perm = columnar_perm(order, N)
        inv_perm = invert_perm(perm)

        for sub_kw in SUB_KEYWORDS:
            sub_key = [ALPH_IDX[sub_kw[i % len(sub_kw)]] for i in range(N)]

            for variant in ["vig", "beau"]:
                # Model A: Sub first, then Trans
                # CT = Trans(Sub(PT, key))
                # Decrypt: Sub_inv(Trans_inv(CT)) = PT
                # Trans_inv: intermediate[perm[i]] = CT[i] → intermediate[j] = CT[inv_perm[j]]
                intermediate = [0] * N
                for j in range(N):
                    intermediate[j] = CT_IDX[inv_perm[j]]

                # Sub_inv: PT[j] = intermediate[j] - key[j] (Vig) or key[j] - intermediate[j] (Beau)
                pt = [0] * N
                for j in range(N):
                    k = sub_key[j]
                    if variant == "beau":
                        pt[j] = (k - intermediate[j]) % MOD
                    else:
                        pt[j] = (intermediate[j] - k) % MOD

                cribs, qg = score_pt(pt)
                n_tested += 1
                n_tested_p3 += 1

                if cribs > best_overall:
                    best_overall = cribs
                    pt_text = ''.join(ALPH[v] for v in pt)
                    best_config = {
                        "trans_kw": trans_kw, "sub_kw": sub_kw,
                        "variant": variant, "alphabet": "standard",
                        "model": "A",
                        "cribs": cribs, "qg": round(qg, 3),
                        "pt": pt_text,
                    }

                if cribs >= 10:
                    n_signal += 1
                    pt_text = ''.join(ALPH[v] for v in pt)
                    all_results.append({
                        "trans_kw": trans_kw, "sub_kw": sub_kw,
                        "variant": variant, "alphabet": "standard",
                        "model": "A",
                        "cribs": cribs, "qg": round(qg, 3),
                        "pt": pt_text[:50],
                    })
                    if cribs >= 18:
                        print(f"  *** SIGNAL: Model A cribs={cribs}/24 "
                              f"trans={trans_kw} sub={sub_kw} {variant}", flush=True)

        if n_tested_p3 % 5000 == 0:
            print(f"    [{n_tested_p3:,} tested] ({time.time()-t0:.0f}s)", flush=True)

    phase3_time = time.time() - t0 - phase1_time - phase2_time
    print(f"  Phase 3: {n_tested_p3:,} configs, best={best_overall}/24, "
          f"{phase3_time:.0f}s", flush=True)

    # ── Summary ─────────────────────────────────────────────────────────
    elapsed = time.time() - t0

    all_results.sort(key=lambda r: (-r["cribs"], -r["qg"]))

    print(f"\n{'='*70}", flush=True)
    print(f"SUMMARY", flush=True)
    print(f"{'='*70}", flush=True)
    print(f"  Total configs tested: {n_tested:,}", flush=True)
    print(f"  Best crib matches: {best_overall}/24", flush=True)
    print(f"  Configs scoring ≥10: {n_signal}", flush=True)
    print(f"  Total time: {elapsed:.0f}s", flush=True)

    if best_config:
        print(f"\n  Best config:", flush=True)
        for k, v in best_config.items():
            print(f"    {k}: {v}", flush=True)

    if all_results:
        print(f"\n  Top 20 results:", flush=True)
        for i, r in enumerate(all_results[:20]):
            print(f"    {i+1:3d}. cribs={r['cribs']}/24 qg={r['qg']:.3f} "
                  f"trans={r.get('trans_kw','')} sub={r.get('sub_kw','')} "
                  f"{r['variant']} alph={r.get('alphabet','')} "
                  f"model={r.get('model','B')}", flush=True)

    if best_overall >= 18:
        verdict = f"SIGNAL — {best_overall}/24 cribs match, investigate"
    elif best_overall >= 10:
        verdict = f"MARGINAL — best {best_overall}/24"
    else:
        verdict = f"NO SIGNAL — best {best_overall}/24, all at noise"

    print(f"\n  Verdict: {verdict}", flush=True)

    # Save
    artifact = {
        "experiment": "E-S-63",
        "total_tested": n_tested,
        "best_cribs": best_overall,
        "best_config": best_config,
        "verdict": verdict,
        "elapsed_seconds": round(elapsed, 1),
        "top_results": all_results[:100],
    }

    os.makedirs("results", exist_ok=True)
    with open("results/e_s_63_k3_variants.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_s_63_k3_variants.json", flush=True)
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_63_k3_variants.py", flush=True)


if __name__ == "__main__":
    main()
