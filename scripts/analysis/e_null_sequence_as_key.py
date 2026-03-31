#!/usr/bin/env python3
"""
E-NULL-SEQ-KEY: Test null value sequence OBKOGBOWWKWIWGZIG as key material.

Hypothesis: The 17-char null value sequence (IC=0.1103, only 7 distinct letters)
might BE key material for decrypting K4.

Phases:
  1. Direct running key on CT97 (cycling period-17)
  2. Running key on CT73 (null-extracted, cycling + partial)
  3. Derived keys (cumsum, pairwise diff, KA indexing)
  4. Null sequence as keyword for mixed alphabet + common keyword decryption
  5. Null values interleaved back as key at null positions + keyword elsewhere
  6. Self-encryption keystream analysis at null positions

Status: active
Family: analysis
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md


import sys, os, json, datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CONSENSUS_NULL_POSITIONS, CRIB_POSITIONS
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free
from kryptos.kernel.alphabet import AZ, KA, keyword_mixed_alphabet
from kryptos.kernel.transforms.vigenere import decrypt_text, CipherVariant

# ── Constants ──────────────────────────────────────────────────────────────

NULL_POS_SORTED = sorted(CONSENSUS_NULL_POSITIONS)
NULL_SEQ = "".join(CT[i] for i in NULL_POS_SORTED)  # OBKOGBOWWKWIWGZIG
NULL_SEQ_REV = NULL_SEQ[::-1]
DEDUP_SEQ = ""
seen = set()
for c in NULL_SEQ:
    if c not in seen:
        DEDUP_SEQ += c
        seen.add(c)
# DEDUP_SEQ = "OBKGWIZ"

VARIANTS = [CipherVariant.VIGENERE, CipherVariant.BEAUFORT, CipherVariant.VAR_BEAUFORT]
VARIANT_NAMES = ["vig", "beau", "varbeau"]
KEYWORDS = ["KRYPTOS", "DEFECTOR", "PALIMPSEST", "ABSCISSA", "SHADOW", "BERLIN", "SCHEIDT"]

# Extract CT73 (non-null chars)
NON_NULL_POS = sorted(set(range(97)) - CONSENSUS_NULL_POSITIONS)
CT73 = "".join(CT[i] for i in NON_NULL_POS)

REPORT_THRESHOLD = 6  # report anything >= 6/24


def encode_text(text, alpha):
    """Convert text to numeric values using given alphabet."""
    return alpha.encode(text)


def cycle_key(key_nums, length):
    """Cycle a numeric key to fill `length` positions."""
    return [key_nums[i % len(key_nums)] for i in range(length)]


def score_both(pt, label):
    """Score with both anchored and free scoring. Return dict with scores."""
    anchored = score_candidate(pt)
    free = score_candidate_free(pt)
    return {
        "label": label,
        "pt_snippet": pt[:40],
        "anchored_crib": anchored.crib_score,
        "free_crib": free.crib_score,
        "bean_pass": anchored.bean_passed,
        "ic": round(anchored.ic_value, 4) if anchored.ic_value else None,
    }


def score_free_only(pt, label):
    """Score with free scoring only (for CT73 where positions shift)."""
    free = score_candidate_free(pt)
    return {
        "label": label,
        "pt_snippet": pt[:40],
        "free_crib": free.crib_score,
        "ic": round(free.ic_value, 4) if free.ic_value else None,
    }


# ── Collection ─────────────────────────────────────────────────────────────

all_results = []
phase_summaries = {}
config_count = 0


def record(result):
    global config_count
    config_count += 1
    all_results.append(result)
    cs = result.get("anchored_crib", 0) or 0
    fs = result.get("free_crib", 0) or 0
    best = max(cs, fs)
    if best >= REPORT_THRESHOLD:
        print(f"  *** HIT {best}/24: {result['label']} -> {result['pt_snippet']}")


# ══════════════════════════════════════════════════════════════════════════
# PHASE 1: Direct running key on CT97
# ══════════════════════════════════════════════════════════════════════════
print("=" * 70)
print("PHASE 1: Direct running key on CT97 (cycling period-17)")
print("=" * 70)

p1_best = 0
for seq, seq_name in [(NULL_SEQ, "nullseq"), (NULL_SEQ_REV, "nullseq_rev")]:
    key_nums = encode_text(seq, AZ)
    key_full = cycle_key(key_nums, 97)
    for vi, variant in enumerate(VARIANTS):
        pt = decrypt_text(CT, key_full, variant)
        r = score_both(pt, f"P1_{seq_name}_{VARIANT_NAMES[vi]}_CT97")
        record(r)
        p1_best = max(p1_best, r["anchored_crib"] or 0, r["free_crib"] or 0)

    # Also try on KA alphabet
    key_nums_ka = encode_text(seq, KA)
    key_full_ka = cycle_key(key_nums_ka, 97)
    for vi, variant in enumerate(VARIANTS):
        pt = decrypt_text(CT, key_full_ka, variant)
        r = score_both(pt, f"P1_{seq_name}_KA_{VARIANT_NAMES[vi]}_CT97")
        record(r)
        p1_best = max(p1_best, r["anchored_crib"] or 0, r["free_crib"] or 0)

phase_summaries["phase1"] = {"configs": config_count, "best_score": p1_best}
print(f"Phase 1: {config_count} configs, best {p1_best}/24")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 2: Running key on CT73 (null-extracted)
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("PHASE 2: Running key on CT73 (null-extracted)")
print("=" * 70)

p2_start = config_count
p2_best = 0

for seq, seq_name in [(NULL_SEQ, "nullseq"), (NULL_SEQ_REV, "nullseq_rev")]:
    key_nums = encode_text(seq, AZ)

    # Cycling over full CT73
    key_full = cycle_key(key_nums, 73)
    for vi, variant in enumerate(VARIANTS):
        pt = decrypt_text(CT73, key_full, variant)
        r = score_free_only(pt, f"P2_{seq_name}_{VARIANT_NAMES[vi]}_CT73_cycle")
        record(r)
        p2_best = max(p2_best, r["free_crib"] or 0)

    # Partial: first 17, 34, 51 chars only
    for partial_len in [17, 34, 51]:
        key_partial = key_nums[:min(partial_len, 17)] * (partial_len // 17 + 1)
        key_partial = key_partial[:partial_len]
        # Decrypt only first partial_len chars, leave rest as-is
        pt_partial = decrypt_text(CT73[:partial_len], key_partial[:partial_len], CipherVariant.BEAUFORT)
        pt_full = pt_partial + CT73[partial_len:]
        r = score_free_only(pt_full, f"P2_{seq_name}_beau_CT73_first{partial_len}")
        record(r)
        p2_best = max(p2_best, r["free_crib"] or 0)

    # KA alphabet
    key_nums_ka = encode_text(seq, KA)
    key_full_ka = cycle_key(key_nums_ka, 73)
    for vi, variant in enumerate(VARIANTS):
        pt = decrypt_text(CT73, key_full_ka, variant)
        r = score_free_only(pt, f"P2_{seq_name}_KA_{VARIANT_NAMES[vi]}_CT73_cycle")
        record(r)
        p2_best = max(p2_best, r["free_crib"] or 0)

p2_configs = config_count - p2_start
phase_summaries["phase2"] = {"configs": p2_configs, "best_score": p2_best}
print(f"Phase 2: {p2_configs} configs, best {p2_best}/24")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 3: Derived keys from null sequence
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("PHASE 3: Key derived from null sequence")
print("=" * 70)

p3_start = config_count
p3_best = 0

for alpha, alpha_name in [(AZ, "AZ"), (KA, "KA")]:
    base_nums = encode_text(NULL_SEQ, alpha)

    # Cumulative sum mod 26
    cumsum = []
    s = 0
    for n in base_nums:
        s = (s + n) % 26
        cumsum.append(s)

    # Pairwise differences (16 values)
    pairwise = [(base_nums[i + 1] - base_nums[i]) % 26 for i in range(len(base_nums) - 1)]

    derived_keys = {
        "cumsum": cumsum,
        "pairwise_diff": pairwise,
    }

    for dk_name, dk_vals in derived_keys.items():
        key_cyc_97 = cycle_key(dk_vals, 97)
        key_cyc_73 = cycle_key(dk_vals, 73)
        for vi, variant in enumerate(VARIANTS):
            # CT97
            pt = decrypt_text(CT, key_cyc_97, variant)
            r = score_both(pt, f"P3_{dk_name}_{alpha_name}_{VARIANT_NAMES[vi]}_CT97")
            record(r)
            p3_best = max(p3_best, r["anchored_crib"] or 0, r["free_crib"] or 0)

            # CT73
            pt73 = decrypt_text(CT73, key_cyc_73, variant)
            r = score_free_only(pt73, f"P3_{dk_name}_{alpha_name}_{VARIANT_NAMES[vi]}_CT73")
            record(r)
            p3_best = max(p3_best, r["free_crib"] or 0)

p3_configs = config_count - p3_start
phase_summaries["phase3"] = {"configs": p3_configs, "best_score": p3_best}
print(f"Phase 3: {p3_configs} configs, best {p3_best}/24")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 4: Null sequence as keyword for mixed alphabet
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("PHASE 4: Null sequence as keyword for mixed alphabet")
print("=" * 70)

p4_start = config_count
p4_best = 0

# Create mixed alphabet from deduplicated null sequence
null_mixed = keyword_mixed_alphabet(DEDUP_SEQ)
print(f"  Mixed alphabet from '{DEDUP_SEQ}': {null_mixed}")

for kw in KEYWORDS:
    kw_nums_az = encode_text(kw, AZ)

    for vi, variant in enumerate(VARIANTS):
        # Map CT through null_mixed alphabet, decrypt with AZ keyword, map back
        ct_nums = [null_mixed.index(c) for c in CT]
        key_cyc = cycle_key(kw_nums_az, 97)

        if variant == CipherVariant.VIGENERE:
            pt_nums = [(ct_nums[i] - key_cyc[i]) % 26 for i in range(97)]
        elif variant == CipherVariant.BEAUFORT:
            pt_nums = [(key_cyc[i] - ct_nums[i]) % 26 for i in range(97)]
        else:  # VAR_BEAUFORT
            pt_nums = [(ct_nums[i] + key_cyc[i]) % 26 for i in range(97)]

        # Map back through mixed alphabet
        pt = "".join(null_mixed[n] for n in pt_nums)
        r = score_both(pt, f"P4_nullmixed_{kw}_{VARIANT_NAMES[vi]}")
        record(r)
        p4_best = max(p4_best, r["anchored_crib"] or 0, r["free_crib"] or 0)

        # Also try: standard alphabet for CT, mixed alphabet for key
        kw_nums_in_mixed = [null_mixed.index(c) for c in kw]
        key_cyc_m = cycle_key(kw_nums_in_mixed, 97)
        pt2 = decrypt_text(CT, key_cyc_m, variant)
        r2 = score_both(pt2, f"P4_mixedkey_{kw}_{VARIANT_NAMES[vi]}")
        record(r2)
        p4_best = max(p4_best, r2["anchored_crib"] or 0, r2["free_crib"] or 0)

p4_configs = config_count - p4_start
phase_summaries["phase4"] = {"configs": p4_configs, "best_score": p4_best}
print(f"Phase 4: {p4_configs} configs, best {p4_best}/24")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 5: Null values interleaved back as key at null positions
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("PHASE 5: Null values as key at null positions + keyword elsewhere")
print("=" * 70)

p5_start = config_count
p5_best = 0

null_val_map = {pos: AZ.char_to_idx(CT[pos]) for pos in NULL_POS_SORTED}

for kw in KEYWORDS:
    kw_nums = encode_text(kw, AZ)

    for vi, variant in enumerate(VARIANTS):
        # Build 97-char key: null_value at null positions, keyword cycling elsewhere
        full_key = []
        kw_idx = 0
        for i in range(97):
            if i in CONSENSUS_NULL_POSITIONS:
                full_key.append(null_val_map[i])
            else:
                full_key.append(kw_nums[kw_idx % len(kw_nums)])
                kw_idx += 1

        pt = decrypt_text(CT, full_key, variant)
        r = score_both(pt, f"P5_interleave_{kw}_{VARIANT_NAMES[vi]}")
        record(r)
        p5_best = max(p5_best, r["anchored_crib"] or 0, r["free_crib"] or 0)

        # Also try: keyword cycling globally (not just non-null positions)
        full_key2 = []
        for i in range(97):
            if i in CONSENSUS_NULL_POSITIONS:
                full_key2.append(null_val_map[i])
            else:
                full_key2.append(kw_nums[i % len(kw_nums)])

        pt2 = decrypt_text(CT, full_key2, variant)
        r2 = score_both(pt2, f"P5_interleave_global_{kw}_{VARIANT_NAMES[vi]}")
        record(r2)
        p5_best = max(p5_best, r2["anchored_crib"] or 0, r2["free_crib"] or 0)

p5_configs = config_count - p5_start
phase_summaries["phase5"] = {"configs": p5_configs, "best_score": p5_best}
print(f"Phase 5: {p5_configs} configs, best {p5_best}/24")

# ══════════════════════════════════════════════════════════════════════════
# PHASE 6: Self-encryption keystream analysis
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("PHASE 6: Null sequence as Beaufort self-key analysis")
print("=" * 70)

p6_start = config_count
p6_best = 0

# If nulls encrypt to themselves under Beaufort: PT[i] = CT[i]
# Then key[i] = (CT[i] + PT[i]) mod 26 = 2*CT[i] mod 26
self_key_values = {}
print("\n  Self-encryption keystream at null positions:")
print(f"  {'Pos':>4} {'CT':>3} {'CT_val':>6} {'key=2CT%26':>10}")
for pos in NULL_POS_SORTED:
    ct_val = AZ.char_to_idx(CT[pos])
    key_val = (2 * ct_val) % 26
    self_key_values[pos] = key_val
    print(f"  {pos:4d}   {CT[pos]}   {ct_val:5d}   {key_val:9d} ({chr(65 + key_val)})")

# Check periodicity of self-key values
self_key_list = [self_key_values[p] for p in NULL_POS_SORTED]
print(f"\n  Self-key sequence: {''.join(chr(65 + v) for v in self_key_list)}")

# Check if these values are consistent with any period
for period in range(1, 18):
    residues = {}
    consistent = True
    for idx, pos in enumerate(NULL_POS_SORTED):
        r = pos % period
        expected = self_key_values[pos]
        if r in residues:
            if residues[r] != expected:
                consistent = False
                break
        else:
            residues[r] = expected
    if consistent:
        print(f"  Period {period}: CONSISTENT (but only {len(NULL_POS_SORTED)} points)")

# What if we interpolate the self-key at null positions to get a full 97-char key?
# Just fill gaps with the nearest null key value
full_self_key = [0] * 97
for i in range(97):
    nearest = min(NULL_POS_SORTED, key=lambda p: abs(p - i))
    full_self_key[i] = self_key_values[nearest]

for vi, variant in enumerate(VARIANTS):
    pt = decrypt_text(CT, full_self_key, variant)
    r = score_both(pt, f"P6_selfkey_nearest_{VARIANT_NAMES[vi]}")
    record(r)
    p6_best = max(p6_best, r["anchored_crib"] or 0, r["free_crib"] or 0)

# Try cycling the 17 self-key values as a period-17 key
self_key_cycling = cycle_key(self_key_list, 97)
for vi, variant in enumerate(VARIANTS):
    pt = decrypt_text(CT, self_key_cycling, variant)
    r = score_both(pt, f"P6_selfkey_cycle17_{VARIANT_NAMES[vi]}")
    record(r)
    p6_best = max(p6_best, r["anchored_crib"] or 0, r["free_crib"] or 0)

p6_configs = config_count - p6_start
phase_summaries["phase6"] = {"configs": p6_configs, "best_score": p6_best}
print(f"Phase 6: {p6_configs} configs, best {p6_best}/24")

# ══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)

overall_best = 0
best_result = None
for r in all_results:
    cs = r.get("anchored_crib", 0) or 0
    fs = r.get("free_crib", 0) or 0
    best = max(cs, fs)
    if best > overall_best:
        overall_best = best
        best_result = r

print(f"Total configurations tested: {config_count}")
print(f"Overall best score: {overall_best}/24")
if best_result:
    print(f"Best result: {best_result['label']}")
    print(f"  PT snippet: {best_result['pt_snippet']}")
print()
for phase, summary in sorted(phase_summaries.items()):
    print(f"  {phase}: {summary['configs']} configs, best {summary['best_score']}/24")

hits = [r for r in all_results if max(r.get("anchored_crib", 0) or 0, r.get("free_crib", 0) or 0) >= REPORT_THRESHOLD]
if hits:
    print(f"\nHits >= {REPORT_THRESHOLD}/24: {len(hits)}")
    for h in hits:
        print(f"  {h['label']}: anchored={h.get('anchored_crib')}, free={h.get('free_crib')}")
else:
    print(f"\nNo hits >= {REPORT_THRESHOLD}/24")

verdict = "NOISE" if overall_best < 10 else ("INTERESTING" if overall_best < 18 else "SIGNAL")
print(f"\nVerdict: {verdict}")

# ── Save results ───────────────────────────────────────────────────────────

output = {
    "experiment": "E-NULL-SEQ-KEY",
    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "hypothesis": "Null value sequence OBKOGBOWWKWIWGZIG used as key material for K4 decryption",
    "null_sequence": NULL_SEQ,
    "null_positions": NULL_POS_SORTED,
    "total_configs": config_count,
    "overall_best_score": overall_best,
    "best_result": best_result,
    "phase_summaries": phase_summaries,
    "hits_above_threshold": hits,
    "verdict": verdict,
    "all_results_count": len(all_results),
    "score_distribution": {
        str(s): sum(1 for r in all_results
                    if max(r.get("anchored_crib", 0) or 0, r.get("free_crib", 0) or 0) == s)
        for s in range(25)
    },
}

out_path = os.path.join(_ROOT, "results", "null_sequence_as_key.json")
with open(out_path, "w") as f:
    json.dump(output, f, indent=2, default=str)

print(f"\nResults saved to {out_path}")
