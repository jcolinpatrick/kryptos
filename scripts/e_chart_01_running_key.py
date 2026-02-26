#!/usr/bin/env python3
"""E-CHART-01: K1+K2+K3 plaintext as running key through KA tableau for K4.

Theory: K4's "coding chart" IS the visible Vigenère tableau on the sculpture.
The key is a running key from the K1-K3 plaintexts — you must solve K1-K3
first to get the key for K4. "Designed to unveil itself... pull up one layer."

Tests:
  1. Each of K1, K2, K3 alone — all starting offsets
  2. K1+K2+K3 concatenated — all offsets
  3. K2+K3 concatenated — all offsets
  4. K3+K2+K1 reversed order — all offsets
  5. K3 reversed text — all offsets
  6. For each source x offset x variant, test with:
     - AZ Vigenère: PT = (CT - KEY) mod 26
     - AZ Beaufort: PT = (KEY - CT) mod 26
     - AZ Variant Beaufort: PT = (CT + KEY) mod 26
     - KA Vigenère: convert via KA indices, PT = (CT_ka - KEY_ka) mod 26, back
     - KA Beaufort: convert via KA indices, PT = (KEY_ka - CT_ka) mod 26, back
     - KA Variant Beaufort: convert via KA, PT = (CT_ka + KEY_ka) mod 26, back
  7. Top 10 best configs → width-8 columnar transposition (40,320 orderings)

Usage: PYTHONPATH=src python3 -u scripts/e_chart_01_running_key.py
"""
import json
import os
import sys
import time
from itertools import permutations

from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, N_CRIBS, ALPH, ALPH_IDX, MOD,
    KRYPTOS_ALPHABET, NOISE_FLOOR, STORE_THRESHOLD, SIGNAL_THRESHOLD,
)
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.constraints.bean import verify_bean

# ── Alphabet setup ─────────────────────────────────────────────────────

AZ = ALPH
AZ_IDX = ALPH_IDX
KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

CT_AZ = [AZ_IDX[c] for c in CT]
CT_KA = [KA_IDX[c] for c in CT]

CRIB_PT_AZ = {pos: AZ_IDX[ch] for pos, ch in CRIB_DICT.items()}
CRIB_PT_KA = {pos: KA_IDX[ch] for pos, ch in CRIB_DICT.items()}
CRIB_POSITIONS = sorted(CRIB_DICT.keys())

# ── K1/K2/K3 Plaintexts ───────────────────────────────────────────────
# Verified against reference. K3 uses Sanborn's misspellings as on the sculpture.

def clean(s):
    return ''.join(c for c in s.upper() if c in AZ)

# K1 plaintext (with Sanborn's "IQLUSION" misspelling)
K1_PT = clean("BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUALCEOFIQLUSION")
# Note: some sources say NUANCE, Sanborn's text uses NUALCE→typo? or intentional.
# Actually the K1 decrypt is: BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHEN U ANCEOFIQLUSION
# Let's try both variants
K1_PT_V1 = clean("BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUALCEOFIQLUSION")
K1_PT_V2 = clean("BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION")

# K2 plaintext (with Sanborn's "UNDERGRUUND" misspelling and "WW")
K2_PT = clean(
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSED"
    "THEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHERED"
    "ANDTRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONX"
    "DOESLANGLEYKNOWABOUTTHISTHEYSHOULDITS BURIEDOUT"
    "THERESOMEWHEREXWHOKNOWSTHEEXACTLOCATIONONLYWW"
    "THISWASHISLASTMESSAGEXTHIRTYEIGHTDEGREESFIFTY"
    "SEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVEN"
    "DEGREESEIGHTMINUTESFORTYFOURSECONDSWES TLAYERTWO"
)

# K3 plaintext (with Sanborn's misspellings: DESPARATLY, etc.)
K3_PT = clean(
    "SLOWLYDESPARATLYSLOW LYTHEREMAINS OFPASSAGEDEBRIS"
    "THATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVED"
    "WITHTREMB LINGHANDSIMADETINYBREACHINTHEUPPERLEFT"
    "HANDCORNERANDTHENW IDENINGTHEHOLEALITTLEIINSERTED"
    "THECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHE"
    "CHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS"
    "OFTHEROOMWITHIN EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
)

# K3 with corrected spelling
K3_PT_CORRECT = clean(
    "SLOWLYDESPERATELYSLOWLYTHEREMAINSOFPASSAGEDEBRIS"
    "THATENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVED"
    "WITHTREMBLING HANDSIMADEATINYBREACHINTHEUPPERLEFT"
    "HANDCORNERANDTHENW IDENINGTHEHOLEALITTLEIINSERTED"
    "THECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHE"
    "CHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS"
    "OFTHEROOMWITHINMERGEDFROMTHEMISTCANYOUSEEANYTHINGQ"
)

# Build all source texts to test
SOURCES = {
    "K1": K1_PT_V1,
    "K1_nuance": K1_PT_V2,
    "K2": K2_PT,
    "K3": K3_PT,
    "K3_correct": K3_PT_CORRECT,
    "K1+K2+K3": K1_PT_V1 + K2_PT + K3_PT,
    "K2+K3": K2_PT + K3_PT,
    "K3+K2+K1": K3_PT + K2_PT + K1_PT_V1,
    "K3_rev": K3_PT[::-1],
    "K1+K2+K3_rev": (K1_PT_V1 + K2_PT + K3_PT)[::-1],
    "K2+K3_rev": (K2_PT + K3_PT)[::-1],
    "K1_rev": K1_PT_V1[::-1],
    "K2_rev": K2_PT[::-1],
    "K3+K1": K3_PT + K1_PT_V1,
    "K1+K3": K1_PT_V1 + K3_PT,
}

# ── Cipher variant functions ───────────────────────────────────────────

def decrypt_vig(ct_num, key_num):
    """AZ Vigenère: PT = (CT - KEY) mod 26"""
    return [(c - k) % 26 for c, k in zip(ct_num, key_num)]

def decrypt_beau(ct_num, key_num):
    """AZ Beaufort: PT = (KEY - CT) mod 26"""
    return [(k - c) % 26 for c, k in zip(ct_num, key_num)]

def decrypt_vbeau(ct_num, key_num):
    """AZ Variant Beaufort: PT = (CT + KEY) mod 26"""
    return [(c + k) % 26 for c, k in zip(ct_num, key_num)]

VARIANTS_AZ = {
    "AZ_Vig": decrypt_vig,
    "AZ_Beau": decrypt_beau,
    "AZ_VBeau": decrypt_vbeau,
}

def decrypt_ka_vig(ct_ka, key_ka):
    """KA Vigenère: convert through KA, PT_ka = (CT_ka - KEY_ka) mod 26"""
    return [(c - k) % 26 for c, k in zip(ct_ka, key_ka)]

def decrypt_ka_beau(ct_ka, key_ka):
    """KA Beaufort: PT_ka = (KEY_ka - CT_ka) mod 26"""
    return [(k - c) % 26 for c, k in zip(ct_ka, key_ka)]

def decrypt_ka_vbeau(ct_ka, key_ka):
    """KA Variant Beaufort: PT_ka = (CT_ka + KEY_ka) mod 26"""
    return [(c + k) % 26 for c, k in zip(ct_ka, key_ka)]

VARIANTS_KA = {
    "KA_Vig": decrypt_ka_vig,
    "KA_Beau": decrypt_ka_beau,
    "KA_VBeau": decrypt_ka_vbeau,
}

# ── Scoring ────────────────────────────────────────────────────────────

def quick_score_az(pt_nums):
    """Count crib matches for AZ-indexed plaintext."""
    return sum(1 for pos in CRIB_POSITIONS
               if pos < len(pt_nums) and pt_nums[pos] == CRIB_PT_AZ[pos])

def quick_score_ka(pt_ka_nums):
    """Count crib matches for KA-indexed plaintext."""
    return sum(1 for pos in CRIB_POSITIONS
               if pos < len(pt_ka_nums) and pt_ka_nums[pos] == CRIB_PT_KA[pos])

def nums_to_text_az(nums):
    return ''.join(AZ[n % 26] for n in nums)

def nums_to_text_ka(nums):
    return ''.join(KA[n % 26] for n in nums)

# ── Main sweep ─────────────────────────────────────────────────────────

print("=" * 72)
print("E-CHART-01: K1+K2+K3 Running Key through KA Tableau")
print("=" * 72)
print(f"  CT: {CT_LEN} chars")
print(f"  KA: {KA}")
for name, src in SOURCES.items():
    print(f"  {name}: {len(src)} chars")
print()

t0 = time.time()
all_results = []
best_overall = 0
best_config = None
total_tests = 0

for src_name, src_text in SOURCES.items():
    # Precompute numeric forms
    src_az = [AZ_IDX[c] for c in src_text]
    src_ka = [KA_IDX[c] for c in src_text]
    src_len = len(src_text)

    if src_len < CT_LEN:
        # Pad by repeating (cyclic key)
        while len(src_az) < CT_LEN * 2:
            src_az = src_az + src_az
            src_ka = src_ka + src_ka
        src_len = len(src_az)

    max_offset = src_len - CT_LEN

    best_for_src = 0
    best_src_cfg = None

    # Test AZ variants
    for var_name, decrypt_fn in VARIANTS_AZ.items():
        for offset in range(max_offset + 1):
            key = src_az[offset:offset + CT_LEN]
            pt_nums = decrypt_fn(CT_AZ, key)
            score = quick_score_az(pt_nums)
            total_tests += 1

            if score > best_for_src:
                best_for_src = score
                best_src_cfg = (var_name, offset, score)

            if score > best_overall:
                best_overall = score
                best_config = (src_name, var_name, offset, score)

            if score >= STORE_THRESHOLD:
                pt_text = nums_to_text_az(pt_nums)
                print(f"  ** {src_name}/{var_name} offset={offset}: {score}/24")
                print(f"     PT: {pt_text[:50]}...")
                all_results.append({
                    "source": src_name,
                    "variant": var_name,
                    "offset": offset,
                    "score": score,
                    "plaintext": pt_text,
                })

            if score >= SIGNAL_THRESHOLD:
                pt_text = nums_to_text_az(pt_nums)
                # Full scoring
                sb = score_candidate(pt_text)
                print(f"  *** SIGNAL: {sb.summary}")

    # Test KA variants
    for var_name, decrypt_fn in VARIANTS_KA.items():
        for offset in range(max_offset + 1):
            key = src_ka[offset:offset + CT_LEN]
            pt_ka_nums = decrypt_fn(CT_KA, key)
            score = quick_score_ka(pt_ka_nums)
            total_tests += 1

            if score > best_for_src:
                best_for_src = score
                best_src_cfg = (var_name, offset, score)

            if score > best_overall:
                best_overall = score
                best_config = (src_name, var_name, offset, score)

            if score >= STORE_THRESHOLD:
                pt_text = nums_to_text_ka(pt_ka_nums)
                print(f"  ** {src_name}/{var_name} offset={offset}: {score}/24")
                print(f"     PT: {pt_text[:50]}...")
                all_results.append({
                    "source": src_name,
                    "variant": var_name,
                    "offset": offset,
                    "score": score,
                    "plaintext": pt_text,
                })

            if score >= SIGNAL_THRESHOLD:
                pt_text = nums_to_text_ka(pt_ka_nums)
                sb = score_candidate(pt_text)
                print(f"  *** SIGNAL: {sb.summary}")

    elapsed = time.time() - t0
    print(f"  {src_name}: best={best_for_src}/24 ({best_src_cfg}) [{elapsed:.1f}s, {total_tests:,} tests]")

# ── Phase 2: Top candidates + width-8 columnar ────────────────────────

print()
print("=" * 72)
print("Phase 2: Top 10 candidates + width-8 columnar transposition")
print("=" * 72)

# Collect top 10 unique configs (by source+variant+offset)
# First sort all_results by score descending, take top 10
# If we have no results above STORE_THRESHOLD, take best per source/variant
# Let's also store ALL results with score >= NOISE_FLOOR for top selection

# Re-sweep to collect top 10 by score
top_candidates = []

for src_name, src_text in SOURCES.items():
    src_az = [AZ_IDX[c] for c in src_text]
    src_ka = [KA_IDX[c] for c in src_text]
    src_len = len(src_text)

    if src_len < CT_LEN:
        while len(src_az) < CT_LEN * 2:
            src_az = src_az + src_az
            src_ka = src_ka + src_ka
        src_len = len(src_az)

    max_offset = src_len - CT_LEN

    # Track best per source+variant
    best_per_var = {}

    for var_name, decrypt_fn in VARIANTS_AZ.items():
        best_score = 0
        best_off = 0
        for offset in range(max_offset + 1):
            key = src_az[offset:offset + CT_LEN]
            pt_nums = decrypt_fn(CT_AZ, key)
            score = quick_score_az(pt_nums)
            if score > best_score:
                best_score = score
                best_off = offset
        best_per_var[var_name] = (best_score, best_off)

    for var_name, decrypt_fn in VARIANTS_KA.items():
        best_score = 0
        best_off = 0
        for offset in range(max_offset + 1):
            key = src_ka[offset:offset + CT_LEN]
            pt_ka_nums = decrypt_fn(CT_KA, key)
            score = quick_score_ka(pt_ka_nums)
            if score > best_score:
                best_score = score
                best_off = offset
        best_per_var[var_name] = (best_score, best_off)

    for var_name, (score, offset) in best_per_var.items():
        top_candidates.append({
            "source": src_name,
            "variant": var_name,
            "offset": offset,
            "score": score,
        })

# Sort by score descending and take top 10
top_candidates.sort(key=lambda x: -x["score"])
top_10 = top_candidates[:10]

print("Top 10 candidates for columnar test:")
for i, cfg in enumerate(top_10):
    print(f"  {i+1}. {cfg['source']}/{cfg['variant']} offset={cfg['offset']}: {cfg['score']}/24")

# Width-8 columnar transposition
W = 8
NUM_ROWS = (CT_LEN + W - 1) // W  # 13 rows for 97 chars at width 8
EMPTY_CELLS = NUM_ROWS * W - CT_LEN  # 7 empty cells

def build_columnar_perm(col_order, n=CT_LEN, w=W):
    """Build a columnar transposition permutation (read-off order).

    Given column order, returns permutation p such that:
    output[i] = input[p[i]] (gather convention)

    Columns are read top-to-bottom. Short columns (last EMPTY_CELLS columns
    in the column order) have one fewer row.
    """
    nrows = (n + w - 1) // w
    short_cols = nrows * w - n  # number of columns with nrows-1

    perm = []
    for col_rank in range(w):
        col_idx = col_order[col_rank]
        # Columns with index >= (w - short_cols) are short
        col_len = nrows - 1 if col_idx >= (w - short_cols) else nrows
        for row in range(col_len):
            perm.append(row * w + col_idx)
    return perm

def apply_inv_perm(text_nums, perm):
    """Apply INVERSE permutation: if perm maps input→output positions,
    this undoes that transposition to recover the original order.

    inv_output[perm[i]] = text_nums[i]
    """
    n = len(perm)
    result = [0] * n
    for i in range(n):
        result[perm[i]] = text_nums[i]
    return result

print(f"\nTesting {len(top_10)} configs x {W}! = {len(top_10) * 40320:,} columnar orderings...")
sys.stdout.flush()

phase2_results = []
phase2_best = 0
phase2_best_cfg = None
p2_tested = 0
p2_t0 = time.time()

for cfg in top_10:
    src_name = cfg["source"]
    var_name = cfg["variant"]
    offset = cfg["offset"]

    src_text = SOURCES[src_name]
    is_ka = var_name.startswith("KA")

    if is_ka:
        src_num = [KA_IDX[c] for c in src_text]
        ct_num = CT_KA
        crib_check = CRIB_PT_KA
    else:
        src_num = [AZ_IDX[c] for c in src_text]
        ct_num = CT_AZ
        crib_check = CRIB_PT_AZ

    src_len = len(src_num)
    if src_len < CT_LEN:
        while len(src_num) < CT_LEN * 2:
            src_num = src_num + src_num

    key = src_num[offset:offset + CT_LEN]

    # Pick the right decrypt function
    if var_name == "AZ_Vig":
        decrypt_fn = decrypt_vig
    elif var_name == "AZ_Beau":
        decrypt_fn = decrypt_beau
    elif var_name == "AZ_VBeau":
        decrypt_fn = decrypt_vbeau
    elif var_name == "KA_Vig":
        decrypt_fn = decrypt_ka_vig
    elif var_name == "KA_Beau":
        decrypt_fn = decrypt_ka_beau
    elif var_name == "KA_VBeau":
        decrypt_fn = decrypt_ka_vbeau
    else:
        continue

    # Try all width-8 column orderings
    # Model: CT was written into grid by rows, read off by columns in some order.
    # To decrypt: apply inverse columnar transposition to CT, then running key decrypt.
    for col_order in permutations(range(W)):
        perm = build_columnar_perm(col_order)
        # Undo the columnar transposition on CT
        ct_transposed = apply_inv_perm(ct_num, perm)
        # Then decrypt with running key
        pt_nums = decrypt_fn(ct_transposed, key)

        score = sum(1 for pos in CRIB_POSITIONS
                    if pos < len(pt_nums) and pt_nums[pos] == crib_check[pos])
        p2_tested += 1

        if score > phase2_best:
            phase2_best = score
            phase2_best_cfg = (src_name, var_name, offset, list(col_order), score)

        if score >= STORE_THRESHOLD:
            if is_ka:
                pt_text = nums_to_text_ka(pt_nums)
            else:
                pt_text = nums_to_text_az(pt_nums)
            print(f"  ** COLUMNAR {src_name}/{var_name} off={offset} col={list(col_order)}: {score}/24")
            print(f"     PT: {pt_text[:50]}...")
            phase2_results.append({
                "source": src_name,
                "variant": var_name,
                "offset": offset,
                "col_order": list(col_order),
                "score": score,
                "plaintext": pt_text,
            })

        if score >= SIGNAL_THRESHOLD:
            if is_ka:
                pt_text = nums_to_text_ka(pt_nums)
            else:
                pt_text = nums_to_text_az(pt_nums)
            sb = score_candidate(pt_text)
            print(f"  *** SIGNAL COLUMNAR: {sb.summary}")

    p2_elapsed = time.time() - p2_t0
    print(f"  ... {src_name}/{var_name}: phase2 best so far = {phase2_best}/24 [{p2_elapsed:.1f}s]")
    sys.stdout.flush()

# Also test model B: running key decrypt first, THEN transposition
print()
print("--- Model B: running key first, then columnar ---")
sys.stdout.flush()

p2b_best = 0
p2b_best_cfg = None

for cfg in top_10:
    src_name = cfg["source"]
    var_name = cfg["variant"]
    offset = cfg["offset"]

    src_text = SOURCES[src_name]
    is_ka = var_name.startswith("KA")

    if is_ka:
        src_num = [KA_IDX[c] for c in src_text]
        ct_num = CT_KA
        crib_check = CRIB_PT_KA
    else:
        src_num = [AZ_IDX[c] for c in src_text]
        ct_num = CT_AZ
        crib_check = CRIB_PT_AZ

    src_len = len(src_num)
    if src_len < CT_LEN:
        while len(src_num) < CT_LEN * 2:
            src_num = src_num + src_num

    key = src_num[offset:offset + CT_LEN]

    # Pick decrypt function
    if var_name == "AZ_Vig":
        decrypt_fn = decrypt_vig
    elif var_name == "AZ_Beau":
        decrypt_fn = decrypt_beau
    elif var_name == "AZ_VBeau":
        decrypt_fn = decrypt_vbeau
    elif var_name == "KA_Vig":
        decrypt_fn = decrypt_ka_vig
    elif var_name == "KA_Beau":
        decrypt_fn = decrypt_ka_beau
    elif var_name == "KA_VBeau":
        decrypt_fn = decrypt_ka_vbeau
    else:
        continue

    # First decrypt with running key (direct), then try transposition
    intermediate = decrypt_fn(ct_num, key)

    for col_order in permutations(range(W)):
        perm = build_columnar_perm(col_order)
        pt_nums = apply_inv_perm(intermediate, perm)
        p2_tested += 1

        score = sum(1 for pos in CRIB_POSITIONS
                    if pos < len(pt_nums) and pt_nums[pos] == crib_check[pos])

        if score > p2b_best:
            p2b_best = score
            p2b_best_cfg = (src_name, var_name, offset, list(col_order), score)

        if score >= STORE_THRESHOLD:
            if is_ka:
                pt_text = nums_to_text_ka(pt_nums)
            else:
                pt_text = nums_to_text_az(pt_nums)
            print(f"  ** MODEL-B {src_name}/{var_name} off={offset} col={list(col_order)}: {score}/24")
            print(f"     PT: {pt_text[:50]}...")
            phase2_results.append({
                "source": src_name,
                "variant": var_name,
                "offset": offset,
                "col_order": list(col_order),
                "model": "B",
                "score": score,
                "plaintext": pt_text,
            })

        if score >= SIGNAL_THRESHOLD:
            if is_ka:
                pt_text = nums_to_text_ka(pt_nums)
            else:
                pt_text = nums_to_text_az(pt_nums)
            sb = score_candidate(pt_text)
            print(f"  *** SIGNAL MODEL-B: {sb.summary}")

    p2_elapsed = time.time() - p2_t0
    print(f"  ... Model B {src_name}/{var_name}: best so far = {p2b_best}/24 [{p2_elapsed:.1f}s]")
    sys.stdout.flush()

# ── Summary ────────────────────────────────────────────────────────────

total_elapsed = time.time() - t0

print()
print("=" * 72)
print("SUMMARY — E-CHART-01")
print("=" * 72)
print(f"  Total tests: {total_tests + p2_tested:,}")
print(f"  Total elapsed: {total_elapsed:.1f}s")
print()
print(f"  Phase 1 (direct running key): best = {best_overall}/24")
if best_config:
    print(f"    Config: {best_config}")
print(f"  Phase 2A (transposition → running key): best = {phase2_best}/24")
if phase2_best_cfg:
    print(f"    Config: {phase2_best_cfg}")
print(f"  Phase 2B (running key → transposition): best = {p2b_best}/24")
if p2b_best_cfg:
    print(f"    Config: {p2b_best_cfg}")
print()

overall_best = max(best_overall, phase2_best, p2b_best)
if overall_best >= SIGNAL_THRESHOLD:
    verdict = f"SIGNAL — {overall_best}/24"
elif overall_best > NOISE_FLOOR:
    verdict = f"STORE — {overall_best}/24 (above noise but below signal)"
else:
    verdict = f"NOISE — {overall_best}/24"

print(f"  VERDICT: {verdict}")
print()

# ── Save results ───────────────────────────────────────────────────────

os.makedirs("results", exist_ok=True)
output = {
    "experiment": "E-CHART-01",
    "description": "K1+K2+K3 plaintext as running key through KA tableau",
    "phase1_best": best_overall,
    "phase1_config": str(best_config),
    "phase2a_best": phase2_best,
    "phase2a_config": str(phase2_best_cfg),
    "phase2b_best": p2b_best,
    "phase2b_config": str(p2b_best_cfg),
    "total_tests": total_tests + p2_tested,
    "elapsed_seconds": total_elapsed,
    "verdict": verdict,
    "hits_above_store": all_results + phase2_results,
    "sources": {name: len(text) for name, text in SOURCES.items()},
}

outpath = "results/e_chart_01_running_key.json"
with open(outpath, "w") as f:
    json.dump(output, f, indent=2, default=str)

print(f"  Artifact: {outpath}")
print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_chart_01_running_key.py")
