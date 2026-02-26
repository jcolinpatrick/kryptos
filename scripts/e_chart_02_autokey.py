#!/usr/bin/env python3
"""E-CHART-02: Autokey Cipher Variants Through KA Tableau

Tests autokey ciphers (non-periodic key via plaintext/ciphertext feedback)
under both standard AZ and KA (Kryptos-keyed) alphabets.

Theory: K4 uses the visible KA tableau as a coding chart, with an autokey
mechanism producing the proven non-periodic keystream. Only a short primer
is needed to start decryption.

Autokey mechanics:
  PT-autokey (Vig):  KEY[i] = PT[i-m] for i>=m; PT[i] = (CT[i] - KEY[i]) % 26
  CT-autokey (Vig):  KEY[i] = CT[i-m] for i>=m; PT[i] = (CT[i] - KEY[i]) % 26
  PT-autokey (Beau): KEY[i] = PT[i-m]; PT[i] = (KEY[i] - CT[i]) % 26
  CT-autokey (Beau): KEY[i] = CT[i-m]; PT[i] = (KEY[i] - CT[i]) % 26
  PT-autokey (VB):   KEY[i] = PT[i-m]; PT[i] = (CT[i] + KEY[i]) % 26
  CT-autokey (VB):   KEY[i] = CT[i-m]; PT[i] = (CT[i] + KEY[i]) % 26

KA variant: Letters mapped to positions via KRYPTOSABCDEFGHIJLMNQUVWXZ
(K=0,R=1,...,Z=25) instead of standard A=0..Z=25.

Phases:
  1. Direct correspondence (no transposition) - all primers x 6 variants x 2 alphabets
  2. Columnar transposition at width 8 on top-10 configs (40,320 orderings each)
  3. Summary + artifact output

Primers: 26 single letters + thematic words from the Kryptos domain.
"""

import json
import os
import sys
import time
from itertools import permutations

# Import from kernel (PYTHONPATH=src required)
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, CRIB_ENTRIES, N_CRIBS,
    ALPH, ALPH_IDX, KRYPTOS_ALPHABET,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean

# ── Alphabet setups ──────────────────────────────────────────────────────────

AZ = ALPH
AZ_IDX = ALPH_IDX
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
MOD = 26

CT_AZ = [AZ_IDX[c] for c in CT]
CT_KA = [KA_IDX[c] for c in CT]

CRIB_POS = sorted(CRIB_DICT.keys())
CRIB_AZ = {p: AZ_IDX[c] for p, c in CRIB_DICT.items()}
CRIB_KA = {p: KA_IDX[c] for p, c in CRIB_DICT.items()}

N = CT_LEN

# ── Primers ──────────────────────────────────────────────────────────────────

SINGLE_LETTERS = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
WORD_PRIMERS = [
    "YAR", "DYAR", "RAY", "YARD", "YARDBIRD",
    "KRYPTOS", "PALIMPSEST", "ABSCISSA",
    "LAYERTWO", "GOLD", "STOPWATCH", "BERLIN", "CLOCK", "BERLINCLOCK",
    "EASTNORTHEAST",
    "WW", "T", "TT",
    "HILL", "LIMA",
    "SHADOW", "LUCID", "INVISIBLE",
    "CHARLIE", "CHECKPOINT",
]

ALL_PRIMERS = SINGLE_LETTERS + WORD_PRIMERS

# Variant names
VARIANT_NAMES = ["vig", "beau", "var_beau"]
FEEDBACK_NAMES = ["ct_autokey", "pt_autokey"]
ALPHABET_NAMES = ["AZ", "KA"]


# ── Autokey decryption functions ─────────────────────────────────────────────

def decrypt_ct_autokey(ct_num, primer_num, variant, alph_idx_map, alph_str):
    """CT-autokey: key feeds back from ciphertext.

    For i < len(primer): KEY[i] = primer[i]
    For i >= len(primer): KEY[i] = ct_num[i - len(primer)]

    Returns plaintext as string.
    """
    m = len(primer_num)
    pt = []
    for i in range(N):
        k = primer_num[i] if i < m else ct_num[i - m]
        if variant == "vig":
            p = (ct_num[i] - k) % MOD
        elif variant == "beau":
            p = (k - ct_num[i]) % MOD
        else:  # var_beau
            p = (ct_num[i] + k) % MOD
        pt.append(p)
    return "".join(alph_str[v] for v in pt)


def decrypt_pt_autokey(ct_num, primer_num, variant, alph_idx_map, alph_str):
    """PT-autokey: key feeds back from plaintext.

    For i < len(primer): KEY[i] = primer[i]
    For i >= len(primer): KEY[i] = pt_num[i - len(primer)]

    Returns plaintext as string.
    """
    m = len(primer_num)
    pt_num = []
    for i in range(N):
        k = primer_num[i] if i < m else pt_num[i - m]
        if variant == "vig":
            p = (ct_num[i] - k) % MOD
        elif variant == "beau":
            p = (k - ct_num[i]) % MOD
        else:  # var_beau
            p = (ct_num[i] + k) % MOD
        pt_num.append(p)
    return "".join(alph_str[v] for v in pt_num)


def primer_to_nums(primer_str, idx_map):
    """Convert primer string to numeric values under given alphabet."""
    return [idx_map[c] for c in primer_str]


def count_crib_matches(pt_str):
    """Count how many crib positions match in plaintext string."""
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(pt_str) and pt_str[pos] == ch)


def derive_keystream(ct_str, pt_str, variant, alph_idx_map):
    """Derive keystream from CT and PT under given variant and alphabet."""
    ct_n = [alph_idx_map[c] for c in ct_str]
    pt_n = [alph_idx_map[c] for c in pt_str]
    ks = []
    for i in range(len(ct_str)):
        if variant == "vig":
            ks.append((ct_n[i] - pt_n[i]) % MOD)
        elif variant == "beau":
            ks.append((ct_n[i] + pt_n[i]) % MOD)
        else:  # var_beau
            ks.append((pt_n[i] - ct_n[i]) % MOD)
    return ks


# ── Columnar transposition ───────────────────────────────────────────────────

def build_columnar_perm(order, width, n):
    """Build gather permutation for columnar transposition.

    output[i] = input[perm[i]]

    The columnar cipher writes plaintext row-by-row into a grid of given width,
    then reads off column-by-column in the given order.
    So CT position j corresponds to a specific PT position.
    """
    nrows = n // width
    nextra = n % width
    col_lengths = [nrows + 1 if c < nextra else nrows for c in range(width)]

    perm = []
    for rank in range(width):
        col = order[rank]
        clen = col_lengths[col]
        for row in range(clen):
            pt_pos = row * width + col
            perm.append(pt_pos)
    return perm


def apply_inv_transposition(text, perm):
    """Apply inverse columnar transposition.

    If CT was produced by columnar transposition of PT, then:
    CT[j] came from PT[perm[j]], so PT[perm[j]] = decrypt(CT[j]).
    To get PT in order: PT[perm[j]] = text[j] => need inverse.
    """
    n = len(text)
    pt = ['?'] * n
    for j in range(n):
        pt[perm[j]] = text[j]
    return "".join(pt)


# ── Phase 1: Direct correspondence ──────────────────────────────────────────

print("=" * 70)
print("E-CHART-02: Autokey Cipher Variants Through KA Tableau")
print("=" * 70)
print(f"  CT: {CT[:50]}...")
print(f"  CT length: {N}")
print(f"  Primers: {len(ALL_PRIMERS)} ({len(SINGLE_LETTERS)} single + {len(WORD_PRIMERS)} words)")
print(f"  Variants: {VARIANT_NAMES}")
print(f"  Feedback: {FEEDBACK_NAMES}")
print(f"  Alphabets: {ALPHABET_NAMES}")
print(f"  Total Phase 1 configs: {len(ALL_PRIMERS)} × 3 × 2 × 2 = "
      f"{len(ALL_PRIMERS) * 3 * 2 * 2}")

t0 = time.time()

# Store all results for sorting
phase1_results = []
best_score = 0
best_config = None
best_pt = ""

n_tested = 0

for alph_name in ALPHABET_NAMES:
    if alph_name == "AZ":
        ct_num = CT_AZ
        idx_map = AZ_IDX
        alph_str = AZ
    else:
        ct_num = CT_KA
        idx_map = KA_IDX
        alph_str = KA

    for feedback in FEEDBACK_NAMES:
        for variant in VARIANT_NAMES:
            for primer_str in ALL_PRIMERS:
                primer_num = primer_to_nums(primer_str, idx_map)

                if feedback == "ct_autokey":
                    pt = decrypt_ct_autokey(ct_num, primer_num, variant, idx_map, alph_str)
                else:
                    pt = decrypt_pt_autokey(ct_num, primer_num, variant, idx_map, alph_str)

                cribs = count_crib_matches(pt)
                n_tested += 1

                config = {
                    "alphabet": alph_name,
                    "feedback": feedback,
                    "variant": variant,
                    "primer": primer_str,
                    "crib_score": cribs,
                    "pt_preview": pt[:40],
                }

                phase1_results.append(config)

                if cribs > best_score:
                    best_score = cribs
                    best_config = config.copy()
                    best_pt = pt

                if cribs > NOISE_FLOOR:
                    # Also compute full scoring for interesting results
                    sb = score_candidate(pt)
                    ks = derive_keystream(CT, pt, variant, idx_map)
                    bean = verify_bean(ks)
                    config["bean_passed"] = bean.passed
                    config["ic"] = sb.ic_value
                    config["full_pt"] = pt
                    print(f"  ABOVE NOISE: cribs={cribs}/24 | {alph_name} {feedback} "
                          f"{variant} primer={primer_str!r} | bean={'PASS' if bean.passed else 'FAIL'} "
                          f"| IC={sb.ic_value:.4f}")
                    print(f"    PT: {pt[:60]}...")

elapsed_p1 = time.time() - t0
print(f"\nPhase 1 complete: {n_tested} configs in {elapsed_p1:.1f}s")
print(f"Best: cribs={best_score}/24 | {best_config}")
if best_pt:
    print(f"  PT: {best_pt[:70]}...")

# Sort by crib score descending
phase1_results.sort(key=lambda x: -x["crib_score"])

print(f"\nTop 20 Phase 1 results:")
for i, r in enumerate(phase1_results[:20]):
    print(f"  {i+1:2d}. cribs={r['crib_score']:2d}/24 | {r['alphabet']} {r['feedback']} "
          f"{r['variant']} primer={r['primer']!r}")

# ── Phase 2: Top-10 configs + columnar transposition at width 8 ─────────────

print("\n" + "=" * 70)
print("Phase 2: Top-10 Phase 1 configs + width-8 columnar transposition")
print("  (40,320 orderings per config = up to 403,200 total)")
print("=" * 70)

WIDTH = 8
all_orders_w8 = list(permutations(range(WIDTH)))
print(f"  Width-8 orderings: {len(all_orders_w8)}")

t1 = time.time()

# Take top 10 distinct configs by crib score (dedup by config tuple)
seen = set()
top10_configs = []
for r in phase1_results:
    key = (r["alphabet"], r["feedback"], r["variant"], r["primer"])
    if key not in seen:
        seen.add(key)
        top10_configs.append(r)
    if len(top10_configs) >= 10:
        break

phase2_best_score = 0
phase2_best_config = None
phase2_best_pt = ""
phase2_results = []

for cfg_idx, cfg in enumerate(top10_configs):
    alph_name = cfg["alphabet"]
    feedback = cfg["feedback"]
    variant = cfg["variant"]
    primer_str = cfg["primer"]

    if alph_name == "AZ":
        ct_num = CT_AZ
        idx_map = AZ_IDX
        alph_str = AZ
    else:
        ct_num = CT_KA
        idx_map = KA_IDX
        alph_str = KA

    primer_num = primer_to_nums(primer_str, idx_map)

    # First decrypt without transposition to get the intermediate text
    if feedback == "ct_autokey":
        raw_pt = decrypt_ct_autokey(ct_num, primer_num, variant, idx_map, alph_str)
    else:
        raw_pt = decrypt_pt_autokey(ct_num, primer_num, variant, idx_map, alph_str)

    cfg_best = 0

    for order in all_orders_w8:
        order_list = list(order)
        perm = build_columnar_perm(order_list, WIDTH, N)

        # Apply inverse transposition: CT was columnar-transposed, so undo it
        # Two models:
        # Model A: transposition BEFORE autokey (transpose CT, then autokey)
        # Model B: autokey THEN transposition (autokey produces intermediate, transpose that)

        # Model B: the raw_pt from autokey is the intermediate; apply inverse transposition
        pt_b = apply_inv_transposition(raw_pt, perm)
        cribs_b = count_crib_matches(pt_b)

        if cribs_b > cfg_best:
            cfg_best = cribs_b

        if cribs_b > phase2_best_score:
            phase2_best_score = cribs_b
            phase2_best_config = {
                "alphabet": alph_name, "feedback": feedback,
                "variant": variant, "primer": primer_str,
                "order": order_list, "width": WIDTH,
                "model": "B_autokey_then_transpose",
                "crib_score": cribs_b,
            }
            phase2_best_pt = pt_b

        if cribs_b > NOISE_FLOOR:
            sb = score_candidate(pt_b)
            phase2_results.append({
                "alphabet": alph_name, "feedback": feedback,
                "variant": variant, "primer": primer_str,
                "order": order_list, "width": WIDTH,
                "model": "B",
                "crib_score": cribs_b,
                "ic": sb.ic_value,
                "pt_preview": pt_b[:50],
            })

        # Model A: transpose CT first, then autokey
        # Rearrange CT under inverse perm, then autokey the rearranged CT
        ct_rearranged_str = apply_inv_transposition(CT, perm)
        ct_rearranged_num = [idx_map[c] for c in ct_rearranged_str]

        if feedback == "ct_autokey":
            pt_a = decrypt_ct_autokey(ct_rearranged_num, primer_num, variant, idx_map, alph_str)
        else:
            pt_a = decrypt_pt_autokey(ct_rearranged_num, primer_num, variant, idx_map, alph_str)

        cribs_a = count_crib_matches(pt_a)

        if cribs_a > cfg_best:
            cfg_best = cribs_a

        if cribs_a > phase2_best_score:
            phase2_best_score = cribs_a
            phase2_best_config = {
                "alphabet": alph_name, "feedback": feedback,
                "variant": variant, "primer": primer_str,
                "order": order_list, "width": WIDTH,
                "model": "A_transpose_then_autokey",
                "crib_score": cribs_a,
            }
            phase2_best_pt = pt_a

        if cribs_a > NOISE_FLOOR:
            sb = score_candidate(pt_a)
            phase2_results.append({
                "alphabet": alph_name, "feedback": feedback,
                "variant": variant, "primer": primer_str,
                "order": order_list, "width": WIDTH,
                "model": "A",
                "crib_score": cribs_a,
                "ic": sb.ic_value,
                "pt_preview": pt_a[:50],
            })

    elapsed_cfg = time.time() - t1
    print(f"  Config {cfg_idx+1}/10: {alph_name} {feedback} {variant} "
          f"primer={primer_str!r} => best w8 cribs={cfg_best} "
          f"[{elapsed_cfg:.1f}s]")

elapsed_p2 = time.time() - t1
print(f"\nPhase 2 complete in {elapsed_p2:.1f}s")
print(f"Best Phase 2: cribs={phase2_best_score}/24")
if phase2_best_config:
    print(f"  Config: {phase2_best_config}")
if phase2_best_pt:
    print(f"  PT: {phase2_best_pt[:70]}...")

if phase2_results:
    phase2_results.sort(key=lambda x: -x["crib_score"])
    print(f"\nPhase 2 above-noise results ({len(phase2_results)}):")
    for i, r in enumerate(phase2_results[:20]):
        print(f"  {i+1:2d}. cribs={r['crib_score']:2d}/24 | {r['alphabet']} {r['feedback']} "
              f"{r['variant']} primer={r['primer']!r} order={r['order']} model={r['model']}")


# ── Phase 3: Exhaustive single-letter primers with width-8 transposition ────
# (Phase 2 only tests top-10 from Phase 1. But the best direct-correspondence
#  primer may not be the best after transposition. So test all 26 single-letter
#  primers across all orderings for the most promising variant/feedback/alphabet.)

print("\n" + "=" * 70)
print("Phase 3: All 26 single-letter primers × width-8 columnar × best variant combos")
print("=" * 70)

# Test all 6 variant combos (3 variants × 2 feedbacks) for each alphabet
# But limit to KA alphabet if Phase 1/2 showed no KA signal, to save time.
# For safety, test both alphabets but limit orderings to random sample if too slow.

t2 = time.time()

phase3_best_score = 0
phase3_best_config = None
phase3_best_pt = ""
phase3_above_noise = []

combos_to_test = []
for alph_name in ALPHABET_NAMES:
    for feedback in FEEDBACK_NAMES:
        for variant in VARIANT_NAMES:
            combos_to_test.append((alph_name, feedback, variant))

print(f"  Combos: {len(combos_to_test)} × 26 letters × {len(all_orders_w8)} orderings")
print(f"  = {len(combos_to_test) * 26 * len(all_orders_w8) * 2:,} total (×2 models)")

for combo_idx, (alph_name, feedback, variant) in enumerate(combos_to_test):
    if alph_name == "AZ":
        ct_num = CT_AZ
        idx_map = AZ_IDX
        alph_str = AZ
    else:
        ct_num = CT_KA
        idx_map = KA_IDX
        alph_str = KA

    combo_best = 0

    for letter in SINGLE_LETTERS:
        primer_num = [idx_map[letter]]

        # Decrypt under autokey (no transposition)
        if feedback == "ct_autokey":
            raw_pt = decrypt_ct_autokey(ct_num, primer_num, variant, idx_map, alph_str)
        else:
            raw_pt = decrypt_pt_autokey(ct_num, primer_num, variant, idx_map, alph_str)

        for order in all_orders_w8:
            order_list = list(order)
            perm = build_columnar_perm(order_list, WIDTH, N)

            # Model B: autokey then transpose
            pt_b = apply_inv_transposition(raw_pt, perm)
            cribs_b = count_crib_matches(pt_b)

            if cribs_b > combo_best:
                combo_best = cribs_b

            if cribs_b > phase3_best_score:
                phase3_best_score = cribs_b
                phase3_best_config = {
                    "alphabet": alph_name, "feedback": feedback,
                    "variant": variant, "primer": letter,
                    "order": order_list, "width": WIDTH,
                    "model": "B", "crib_score": cribs_b,
                }
                phase3_best_pt = pt_b

            if cribs_b > NOISE_FLOOR:
                phase3_above_noise.append({
                    "alphabet": alph_name, "feedback": feedback,
                    "variant": variant, "primer": letter,
                    "order": order_list, "model": "B",
                    "crib_score": cribs_b,
                })

            # Model A: transpose then autokey
            ct_rearranged_str = apply_inv_transposition(CT, perm)
            ct_rearranged_num = [idx_map[c] for c in ct_rearranged_str]

            if feedback == "ct_autokey":
                pt_a = decrypt_ct_autokey(ct_rearranged_num, primer_num, variant, idx_map, alph_str)
            else:
                pt_a = decrypt_pt_autokey(ct_rearranged_num, primer_num, variant, idx_map, alph_str)

            cribs_a = count_crib_matches(pt_a)

            if cribs_a > combo_best:
                combo_best = cribs_a

            if cribs_a > phase3_best_score:
                phase3_best_score = cribs_a
                phase3_best_config = {
                    "alphabet": alph_name, "feedback": feedback,
                    "variant": variant, "primer": letter,
                    "order": order_list, "width": WIDTH,
                    "model": "A", "crib_score": cribs_a,
                }
                phase3_best_pt = pt_a

            if cribs_a > NOISE_FLOOR:
                phase3_above_noise.append({
                    "alphabet": alph_name, "feedback": feedback,
                    "variant": variant, "primer": letter,
                    "order": order_list, "model": "A",
                    "crib_score": cribs_a,
                })

    elapsed_combo = time.time() - t2
    print(f"  Combo {combo_idx+1}/{len(combos_to_test)}: {alph_name} {feedback} {variant} "
          f"=> best={combo_best} [{elapsed_combo:.1f}s]")

elapsed_p3 = time.time() - t2
print(f"\nPhase 3 complete in {elapsed_p3:.1f}s")
print(f"Best Phase 3: cribs={phase3_best_score}/24")
if phase3_best_config:
    print(f"  Config: {phase3_best_config}")
if phase3_best_pt:
    print(f"  PT: {phase3_best_pt[:70]}...")

print(f"Phase 3 above-noise count: {len(phase3_above_noise)}")
if phase3_above_noise:
    phase3_above_noise.sort(key=lambda x: -x["crib_score"])
    for i, r in enumerate(phase3_above_noise[:15]):
        print(f"  {i+1:2d}. cribs={r['crib_score']:2d}/24 | {r['alphabet']} {r['feedback']} "
              f"{r['variant']} primer={r['primer']!r} order={r['order']} model={r['model']}")


# ── Summary ──────────────────────────────────────────────────────────────────

total_elapsed = time.time() - t0

overall_best = max(best_score, phase2_best_score, phase3_best_score)

print("\n" + "=" * 70)
print("SUMMARY — E-CHART-02")
print("=" * 70)
print(f"  Phase 1 (direct, no transposition): best cribs = {best_score}/24")
print(f"  Phase 2 (top-10 + w8 columnar):     best cribs = {phase2_best_score}/24")
print(f"  Phase 3 (all letters + w8 columnar): best cribs = {phase3_best_score}/24")
print(f"  Overall best: {overall_best}/24")
print(f"  Total time: {total_elapsed:.1f}s")

if overall_best >= 18:
    verdict = f"SIGNAL — {overall_best}/24 cribs, investigate further"
elif overall_best >= 10:
    verdict = f"INTERESTING — {overall_best}/24 cribs, check false positive rate"
elif overall_best > NOISE_FLOOR:
    verdict = f"MARGINAL — {overall_best}/24 cribs, above noise but not significant"
else:
    verdict = f"NO SIGNAL — best {overall_best}/24 cribs, at noise level. Autokey through KA tableau ELIMINATED for tested configs."

print(f"\n  VERDICT: {verdict}")

# ── Save artifact ────────────────────────────────────────────────────────────

os.makedirs("results", exist_ok=True)
output = {
    "experiment": "E-CHART-02",
    "description": "Autokey cipher variants through KA tableau (AZ + KA alphabets)",
    "total_configs_phase1": n_tested,
    "phase1_best": {
        "crib_score": best_score,
        "config": best_config,
    },
    "phase2_best": {
        "crib_score": phase2_best_score,
        "config": phase2_best_config,
        "pt": phase2_best_pt[:80] if phase2_best_pt else None,
    },
    "phase3_best": {
        "crib_score": phase3_best_score,
        "config": phase3_best_config,
        "pt": phase3_best_pt[:80] if phase3_best_pt else None,
    },
    "phase2_above_noise": phase2_results[:20],
    "phase3_above_noise_count": len(phase3_above_noise),
    "phase3_above_noise_top": phase3_above_noise[:20],
    "overall_best": overall_best,
    "verdict": verdict,
    "total_elapsed_seconds": total_elapsed,
    "primers_tested": ALL_PRIMERS,
    "repro": "PYTHONPATH=src python3 -u scripts/e_chart_02_autokey.py",
}

with open("results/e_chart_02_autokey.json", "w") as f:
    json.dump(output, f, indent=2, default=str)

print(f"\n  Artifact: results/e_chart_02_autokey.json")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_chart_02_autokey.py")
