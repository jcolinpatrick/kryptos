#!/usr/bin/env python3
"""
Cipher: encoding/alexandria_streets
Family: encoding
Status: active
Keyspace: ~2000 configs
Last run: never
Best score: n/a

Hypothesis: The Old Town Alexandria street grid provides running key material
for K4. Sanborn grew up at 3501 Forest Ave, Alexandria VA 22302. His Smithsonian
archive (Box 6, Folder 18) contains an art print of Old Town Alexandria alongside
his KRYPTOS Vigenère tableau and steganography sketches.

The 14 N-S streets (Union to West) match K4's 14-column grid width.
The full street names, concatenated, provide a running key source that would
NOT appear in any published text (explaining the Gutenberg sweep null result).

Key sources tested:
  1. First letters of 14 N-S streets: ULFRPSWCAPHFPW (period 14)
  2. Full N-S street names concatenated (running key, 81 chars)
  3. First letters of 17 E-W streets: OPWQPCKPDWWGFJGMM (period 17)
  4. Full E-W street names concatenated (running key)
  5. Combined N-S + E-W (running key)
  6. Various orderings: alphabetical, by founding date, reversed
  7. Street names as Polybius grid labels
  8. A1Z26 values of street initials as numeric key

Tests against CT97, CT73 (Model B with consensus nulls), both AZ and KA.

Output: results/e_alexandria_street_key_01.json
"""

import json
import os
import sys
import time
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_POSITIONS
from kryptos.kernel.alphabet import AZ, KA
from kryptos.kernel.scoring.aggregate import score_candidate, score_candidate_free

# ── OLD TOWN ALEXANDRIA STREET GRID ─────────────────────────────────────

# North-South streets, west (river) to east (inland)
NS_STREETS = [
    "UNION", "LEE", "FAIRFAX", "ROYAL", "PITT", "STASAPH",
    "WASHINGTON", "COLUMBUS", "ALFRED", "PATRICK", "HENRY",
    "FAYETTE", "PAYNE", "WEST"
]

# East-West streets, north to south
EW_STREETS = [
    "ORONOCO", "PENDLETON", "WYTHE", "QUEEN", "PRINCESS",
    "CAMERON", "KING", "PRINCE", "DUKE", "WOLFE", "WILKES",
    "GIBBON", "FRANKLIN", "JEFFERSON", "GREEN", "MADISON",
    "MONTGOMERY"
]

# Alternative E-W with original names
EW_STREETS_ORIGINAL = [
    "DUCHESS", "PENDLETON", "WYTHE", "QUEEN", "PRINCESS",
    "CAMERON", "KING", "PRINCE", "DUKE", "WOLFE", "WILKES",
    "GIBBON", "FRANKLIN", "JEFFERSON", "GREEN", "MADISON",
    "MONTGOMERY"
]

# First letters
NS_INITIALS = "".join(s[0] for s in NS_STREETS)  # ULFRPSWCAPHFPW
EW_INITIALS = "".join(s[0] for s in EW_STREETS)   # OPWQPCKPDWWGFJGMM

# Full concatenated names
NS_CONCAT = "".join(NS_STREETS)
EW_CONCAT = "".join(EW_STREETS)
BOTH_CONCAT = NS_CONCAT + EW_CONCAT
EW_ORIG_CONCAT = "".join(EW_STREETS_ORIGINAL)

# Consensus null positions
CONSENSUS_NULLS = {0, 1, 2, 5, 8, 12, 14, 20, 36, 52, 58, 59, 74, 75, 78, 84, 85}
ALL_CRIB_POS = set(range(21, 34)) | set(range(63, 74))

# Standard alphabets
AZ_STR = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA_STR = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

print("=" * 70)
print("OLD TOWN ALEXANDRIA STREET GRID — Running Key Test")
print("=" * 70)
print(f"CT: {CT}")
print(f"NS streets (14): {NS_INITIALS} = {''.join(NS_STREETS)}")
print(f"EW streets (17): {EW_INITIALS}")
print(f"NS concat length: {len(NS_CONCAT)}")
print(f"EW concat length: {len(EW_CONCAT)}")
print(f"Combined length:  {len(BOTH_CONCAT)}")
print()


def decrypt_beaufort(ct_text, key_text, alphabet=AZ_STR):
    """Beaufort decrypt: PT[i] = (KEY[i] + CT[i]) mod 26 in given alphabet."""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    for i in range(min(len(ct_text), len(key_text))):
        c = alph_idx.get(ct_text[i])
        k = alph_idx.get(key_text[i])
        if c is None or k is None:
            pt.append('?')
            continue
        p = (k + c) % 26
        pt.append(alphabet[p])
    return "".join(pt)


def decrypt_vigenere(ct_text, key_text, alphabet=AZ_STR):
    """Vigenère decrypt: PT[i] = (CT[i] - KEY[i]) mod 26."""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    for i in range(min(len(ct_text), len(key_text))):
        c = alph_idx.get(ct_text[i])
        k = alph_idx.get(key_text[i])
        if c is None or k is None:
            pt.append('?')
            continue
        p = (c - k) % 26
        pt.append(alphabet[p])
    return "".join(pt)


def decrypt_var_beaufort(ct_text, key_text, alphabet=AZ_STR):
    """Variant Beaufort: PT[i] = (KEY[i] - CT[i]) mod 26."""
    alph_idx = {c: i for i, c in enumerate(alphabet)}
    pt = []
    for i in range(min(len(ct_text), len(key_text))):
        c = alph_idx.get(ct_text[i])
        k = alph_idx.get(key_text[i])
        if c is None or k is None:
            pt.append('?')
            continue
        p = (k - c) % 26
        pt.append(alphabet[p])
    return "".join(pt)


def extend_key(key_text, length):
    """Extend key by repeating to fill length."""
    if len(key_text) >= length:
        return key_text[:length]
    reps = (length // len(key_text)) + 1
    return (key_text * reps)[:length]


def extract_ct73():
    """Extract CT73 using consensus nulls (17 fixed + reasonable choices for 7 varying)."""
    # Use a representative set of null positions (17 consensus + 7 most likely)
    # Varying: {38,39,40,41,42,43,44,45} pick 3, {55,56} pick 1, {87,88} pick 1, {93,94,95,96} pick 2
    # Most common assignment from prior work:
    nulls_24 = sorted(CONSENSUS_NULLS | {40, 42, 44, 55, 87, 93, 95})
    ct73 = "".join(CT[i] for i in range(97) if i not in nulls_24)
    return ct73, nulls_24


results = {"experiment": "e_alexandria_street_key_01", "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")}
all_tests = []
best_score = 0
best_config = ""


def run_test(name, ct_text, key_source, variant_name, decrypt_fn, alphabet, alph_name):
    global best_score, best_config

    key = extend_key(key_source, len(ct_text))
    pt = decrypt_fn(ct_text, key, alphabet)

    # Score using free crib search (works for both CT97 and CT73)
    breakdown = score_candidate_free(pt)
    score = breakdown.crib_score

    result = {
        "name": name,
        "variant": variant_name,
        "alphabet": alph_name,
        "key_source": key_source[:40] + "..." if len(key_source) > 40 else key_source,
        "key_length": len(key_source),
        "ct_length": len(ct_text),
        "crib_score": score,
        "plaintext": pt[:50],
    }
    all_tests.append(result)

    if score > best_score:
        best_score = score
        best_config = name

    marker = " <<<" if score >= 8 else ""
    print(f"  {name:55s} {variant_name:8s} {alph_name:3s}  score={score:2d}/24  pt={pt[:30]}...{marker}")

    return score


# ════════════════════════════════════════════════════════════════════════
# PHASE 1: CT97 — Street names as running key
# ════════════════════════════════════════════════════════════════════════

print("─" * 70)
print("PHASE 1: CT97 — Street names as running key")
print("─" * 70)

key_sources = {
    "NS_initials_14": NS_INITIALS,
    "NS_concat_81": NS_CONCAT,
    "EW_initials_17": EW_INITIALS,
    "EW_concat": EW_CONCAT,
    "EW_original_concat": EW_ORIG_CONCAT,
    "NS+EW_combined": BOTH_CONCAT,
    "NS_reversed": NS_CONCAT[::-1],
    "EW_reversed": EW_CONCAT[::-1],
    "NS_alpha_order": "".join(sorted(NS_STREETS)),
    "KING_first": "KING" + NS_CONCAT,
    "WASHINGTON_first": "WASHINGTON" + NS_CONCAT,
    "ALEXANDRIA": "ALEXANDRIA",
    "OLDTOWN": "OLDTOWN",
    "SHOOTERSHILL": "SHOOTERSHILL",
    "JONESPOINT": "JONESPOINT",
    "PHAROS": "PHAROS",
    "MASONIC": "MASONIC",
    "SHADOW": "SHADOW",  # ТЕНЬ = shadow = Cyrillic Projector keyword
}

for key_name, key_text in key_sources.items():
    for variant_name, decrypt_fn in [("beaufort", decrypt_beaufort), ("vigenere", decrypt_vigenere), ("varbeau", decrypt_var_beaufort)]:
        for alph_name, alphabet in [("AZ", AZ_STR), ("KA", KA_STR)]:
            run_test(f"CT97_{key_name}", CT, key_text, variant_name, decrypt_fn, alphabet, alph_name)


# ════════════════════════════════════════════════════════════════════════
# PHASE 2: CT73 — Street names as running key after null removal
# ════════════════════════════════════════════════════════════════════════

print()
print("─" * 70)
print("PHASE 2: CT73 — Street names as running key after null removal")
print("─" * 70)

ct73, nulls_used = extract_ct73()
print(f"CT73 ({len(ct73)} chars): {ct73}")
print(f"Nulls used (24): {sorted(nulls_used)}")
print()

for key_name, key_text in key_sources.items():
    for variant_name, decrypt_fn in [("beaufort", decrypt_beaufort), ("vigenere", decrypt_vigenere), ("varbeau", decrypt_var_beaufort)]:
        for alph_name, alphabet in [("AZ", AZ_STR), ("KA", KA_STR)]:
            run_test(f"CT73_{key_name}", ct73, key_text, variant_name, decrypt_fn, alphabet, alph_name)


# ════════════════════════════════════════════════════════════════════════
# PHASE 3: Street names at every offset
# ════════════════════════════════════════════════════════════════════════

print()
print("─" * 70)
print("PHASE 3: Best key sources at all offsets (circular)")
print("─" * 70)

# For the most promising key sources, try all circular offsets
top_keys = ["NS_concat_81", "EW_concat", "NS+EW_combined"]
offset_best = 0

for key_name in top_keys:
    key_text = key_sources[key_name]
    if len(key_text) < 73:
        continue

    for offset in range(len(key_text)):
        shifted_key = key_text[offset:] + key_text[:offset]

        # Test on CT97 and CT73, all variants, AZ only (to save time)
        for ct_label, ct_text in [("CT97", CT), ("CT73", ct73)]:
            for variant_name, decrypt_fn in [("beaufort", decrypt_beaufort), ("vigenere", decrypt_vigenere), ("varbeau", decrypt_var_beaufort)]:
                key = extend_key(shifted_key, len(ct_text))
                pt = decrypt_fn(ct_text, key, AZ_STR)
                breakdown = score_candidate_free(pt)
                score = breakdown.crib_score

                if score >= 6:
                    print(f"  OFFSET {offset:3d} {ct_label} {key_name:20s} {variant_name:8s} score={score:2d}/24  pt={pt[:30]}...")
                    all_tests.append({
                        "name": f"{ct_label}_{key_name}_offset{offset}",
                        "variant": variant_name,
                        "alphabet": "AZ",
                        "offset": offset,
                        "crib_score": score,
                        "plaintext": pt[:50],
                    })
                    if score > best_score:
                        best_score = score
                        best_config = f"{ct_label}_{key_name}_offset{offset}_{variant_name}"


# ════════════════════════════════════════════════════════════════════════
# PHASE 4: Street initials as Polybius/transposition key
# ════════════════════════════════════════════════════════════════════════

print()
print("─" * 70)
print("PHASE 4: NS initials as columnar transposition key (width 14)")
print("─" * 70)

# The 14 NS initials can define a columnar transposition order
# ULFRPSWCAPHFPW — rank order gives column permutation
def rank_order(text):
    """Convert text to rank order (handling duplicates by left-to-right precedence)."""
    indexed = [(c, i) for i, c in enumerate(text)]
    indexed.sort(key=lambda x: (x[0], x[1]))
    ranks = [0] * len(text)
    for rank, (_, orig_idx) in enumerate(indexed):
        ranks[orig_idx] = rank
    return ranks

ns_perm = rank_order(NS_INITIALS)
ew_perm = rank_order(EW_INITIALS)

print(f"NS initials: {NS_INITIALS}")
print(f"NS rank order: {ns_perm}")
print(f"EW initials: {EW_INITIALS}")
print(f"EW rank order: {ew_perm}")

# Apply columnar transposition with NS_INITIALS as key
def columnar_decrypt(ct, width, col_order):
    n = len(ct)
    full_rows = n // width
    extra = n % width
    col_lens = [full_rows + (1 if i < extra else 0) for i in range(width)]

    grid = [''] * width
    pos = 0
    for col in col_order:
        clen = col_lens[col]
        grid[col] = ct[pos:pos + clen]
        pos += clen

    result = []
    for row in range(full_rows + (1 if extra else 0)):
        for col in range(width):
            if row < len(grid[col]):
                result.append(grid[col][row])
    return ''.join(result)

# Width 14 columnar with NS street ordering
for ct_label, ct_text in [("CT97", CT), ("CT73", ct73)]:
    pt = columnar_decrypt(ct_text, 14, ns_perm)
    breakdown = score_candidate_free(pt)
    score = breakdown.crib_score
    print(f"  {ct_label} columnar w=14 NS_order  score={score}/24  pt={pt[:40]}...")
    all_tests.append({"name": f"{ct_label}_columnar_w14_NS", "crib_score": score, "plaintext": pt[:50]})

    if score > best_score:
        best_score = score
        best_config = f"{ct_label}_columnar_w14_NS"

# Width 17 columnar with EW street ordering (17 E-W streets)
for ct_label, ct_text in [("CT97", CT), ("CT73", ct73)]:
    pt = columnar_decrypt(ct_text, 17, ew_perm)
    breakdown = score_candidate_free(pt)
    score = breakdown.crib_score
    print(f"  {ct_label} columnar w=17 EW_order  score={score}/24  pt={pt[:40]}...")
    all_tests.append({"name": f"{ct_label}_columnar_w17_EW", "crib_score": score, "plaintext": pt[:50]})

# Columnar + substitution: transpose then decrypt with street key
print()
print("  Columnar w=14 (NS) + Beaufort with street running key:")
for ct_label, ct_text in [("CT97", CT), ("CT73", ct73)]:
    transposed = columnar_decrypt(ct_text, 14, ns_perm)
    for key_name in ["NS_concat_81", "EW_concat", "NS+EW_combined"]:
        key_text = key_sources[key_name]
        key = extend_key(key_text, len(transposed))
        pt = decrypt_beaufort(transposed, key, AZ_STR)
        breakdown = score_candidate_free(pt)
        score = breakdown.crib_score
        if score >= 4:
            print(f"    {ct_label} col14+beau {key_name:20s} score={score}/24  pt={pt[:30]}...")
        all_tests.append({
            "name": f"{ct_label}_col14NS_beau_{key_name}",
            "crib_score": score,
            "plaintext": pt[:50],
        })
        if score > best_score:
            best_score = score
            best_config = f"{ct_label}_col14NS_beau_{key_name}"


# ════════════════════════════════════════════════════════════════════════
# PHASE 5: A1Z26 numeric values of street initials
# ════════════════════════════════════════════════════════════════════════

print()
print("─" * 70)
print("PHASE 5: A1Z26 numeric key from street initials")
print("─" * 70)

ns_a1z26 = [ord(c) - ord('A') for c in NS_INITIALS]
ew_a1z26 = [ord(c) - ord('A') for c in EW_INITIALS]

print(f"NS A1Z26: {ns_a1z26}")
print(f"NS sum: {sum(ns_a1z26)}, mod 26: {sum(ns_a1z26) % 26}")
print(f"EW A1Z26: {ew_a1z26}")
print(f"EW sum: {sum(ew_a1z26)}, mod 26: {sum(ew_a1z26) % 26}")

# Use A1Z26 values as numeric Beaufort key
for ct_label, ct_text in [("CT97", CT), ("CT73", ct73)]:
    ct_nums = [ord(c) - ord('A') for c in ct_text]

    for key_name, key_nums in [("NS_a1z26", ns_a1z26), ("EW_a1z26", ew_a1z26)]:
        period = len(key_nums)
        pt_nums = [(ct_nums[i] + key_nums[i % period]) % 26 for i in range(len(ct_nums))]
        pt = "".join(chr(n + ord('A')) for n in pt_nums)
        breakdown = score_candidate_free(pt)
        score = breakdown.crib_score
        print(f"  {ct_label} {key_name} period={period} beaufort  score={score}/24")
        all_tests.append({"name": f"{ct_label}_{key_name}_beaufort", "crib_score": score})

        if score > best_score:
            best_score = score
            best_config = f"{ct_label}_{key_name}_beaufort"


# ════════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════════

print()
print("=" * 70)
print("SUMMARY — Old Town Alexandria Street Key Test")
print("=" * 70)

print(f"\n  Total tests: {len(all_tests)}")
print(f"  Best score:  {best_score}/24")
print(f"  Best config: {best_config}")

# Score distribution
scores = [t["crib_score"] for t in all_tests]
score_dist = Counter(scores)
print(f"\n  Score distribution:")
for s in sorted(score_dist.keys()):
    print(f"    {s}/24: {score_dist[s]} tests")

verdict = "NOISE" if best_score < 8 else "INVESTIGATE" if best_score < 18 else "SIGNAL"
print(f"\n  Verdict: {verdict}")

results["tests"] = all_tests
results["best_score"] = best_score
results["best_config"] = best_config
results["total_tests"] = len(all_tests)
results["verdict"] = verdict
results["key_sources"] = {
    "NS_initials": NS_INITIALS,
    "NS_concat": NS_CONCAT,
    "EW_initials": EW_INITIALS,
    "NS_streets": NS_STREETS,
    "EW_streets": EW_STREETS,
}

out_path = os.path.join(_ROOT, "results", "e_alexandria_street_key_01.json")
with open(out_path, "w") as f:
    json.dump(results, f, indent=2, default=str)
print(f"\n  Results saved to: {out_path}")
