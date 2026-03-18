#!/usr/bin/env python3 -u
"""
=================================================================
VIC GAP-CLOSING TEST v1 — Three Untested VIC Angles
=================================================================
Cipher:     VIC cipher variants
Family:     campaigns
Status:     active

Tests three genuinely untested VIC angles to close the gap:

1. VIC on CT73 (after null removal) — all prior tests used VIC as
   the 73→97 expansion. What if nulls are stripped FIRST, then VIC
   decrypts the 73-char result?

2. KA tableau as straddling checkerboard — the 26-row Kryptos
   tableau reinterpreted as a checkerboard with KRYPTOS-derived
   row labels.

3. Historical Häyhänen VIC parameters — the ACTUAL 1953 defection
   case parameters as a deliberate Sanborn reference.
=================================================================
"""

import sys
import os
import json
import time
from itertools import permutations
from collections import Counter

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, KRYPTOS_ALPHABET,
)

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}

# ── Consensus null mask ────────────────────────────────────────────────

CONSENSUS_NULLS = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})
REF_VARYING = [38, 39, 40, 55, 87, 93, 94]
ALL_NULLS = CONSENSUS_NULLS | set(REF_VARYING)
NONNULL = sorted(set(range(CT_LEN)) - ALL_NULLS)
CT73 = "".join(CT[i] for i in NONNULL)

CRIB_POS_97 = sorted(CRIB_DICT.keys())
CRIB_CT73_IDX = [NONNULL.index(p) for p in CRIB_POS_97]

# ── VIC primitives (from e_full_vic_pipeline_k4.py) ───────────────────

def rank10(items, is_letters=False):
    assert len(items) == 10
    if is_letters:
        indexed = [(items[i], i) for i in range(10)]
    else:
        indexed = [(items[i] if items[i] != 0 else 10, i) for i in range(10)]
    ranked = sorted(indexed, key=lambda x: (x[0], x[1]))
    result = [0] * 10
    for rank_idx, (_, orig_pos) in enumerate(ranked):
        result[orig_pos] = (rank_idx + 1) % 10
    return result


def chain_add(digits, target_len):
    result = list(digits)
    while len(result) < target_len:
        result.append((result[-2] + result[-1]) % 10)
    return result[:target_len]


def mod10_sub(a, b):
    return [(a[i] - b[i]) % 10 for i in range(len(a))]


def mod10_add(a, b):
    return [(a[i] + b[i]) % 10 for i in range(min(len(a), len(b)))]


def generate_full_vic_keys(phrase, date_5, personal_number):
    """Generate VIC keys from phrase (20 chars), date (5 digits), PN (int)."""
    p = phrase.upper()[:20]
    if len(p) < 20:
        return None

    e1 = rank10(list(p[:10]), is_letters=True)
    e2 = rank10(list(p[10:20]), is_letters=True)

    results = []
    # Try all 100K keygroups (5-digit)
    # Too many — sample strategically
    for kg in range(100000):
        kg_digits = [(kg // 10000) % 10, (kg // 1000) % 10,
                     (kg // 100) % 10, (kg // 10) % 10, kg % 10]

        c = mod10_sub(kg_digits, date_5)
        f1 = chain_add(c, 10)
        g = mod10_add(e1, f1)

        h = []
        for d in g:
            h.append(e2[(d - 1) % 10])

        j = rank10(h, is_letters=False)
        chain_60 = chain_add(h, 60)

        # Get a, b from last two unequal digits of line P
        p_line = chain_60[50:60]
        last_two = []
        for d in reversed(p_line):
            if not last_two:
                last_two.append(d)
            elif d != last_two[0]:
                last_two.insert(0, d)
                break
        if len(last_two) < 2:
            continue

        a = (last_two[0] if last_two[0] != 0 else 10) + personal_number
        b = (last_two[1] if last_two[1] != 0 else 10) + personal_number

        if a < 3 or a > 25 or b < 3 or b > 25:
            continue

        # Checkerboard header from J
        # Top row positions: where J has values a and b
        # In standard VIC, the two "blank" columns are determined by a,b
        # But for K4 we need the digit sequence, not the checkerboard itself

        # The additive keystream: chain from line K onward
        keystream = chain_60[10:10 + 97]  # up to 97 digits
        if len(keystream) < 73:
            keystream = chain_add(h, 73 + 10)[10:]

        results.append({
            'kg': kg,
            'keystream': keystream[:97],
            'a': a,
            'b': b,
            'j': j,
        })

        if len(results) >= 5000:  # sample limit per (phrase, date, PN)
            break

    return results


# ── Straddling checkerboard ────────────────────────────────────────────

def build_checkerboard(alphabet, blank_pos1, blank_pos2):
    """Build a straddling checkerboard from a 26-letter alphabet.
    blank_pos1 and blank_pos2 (0-9) are the two columns without a top-row letter.
    Returns encode_dict: letter -> digit string, decode_dict: digit string -> letter.
    """
    top_row_cols = [i for i in range(10) if i not in (blank_pos1, blank_pos2)]
    assert len(top_row_cols) == 8

    encode = {}
    idx = 0

    # Top row: 8 most frequent letters get single digits
    for col in top_row_cols:
        if idx < len(alphabet):
            encode[alphabet[idx]] = str(col)
            idx += 1

    # Second row (prefix = blank_pos1): 10 letters
    for col in range(10):
        if idx < len(alphabet):
            encode[alphabet[idx]] = str(blank_pos1) + str(col)
            idx += 1

    # Third row (prefix = blank_pos2): remaining letters
    for col in range(10):
        if idx < len(alphabet):
            encode[alphabet[idx]] = str(blank_pos2) + str(col)
            idx += 1

    decode = {v: k for k, v in encode.items()}
    return encode, decode


def checkerboard_decode_digits(digits, decode_dict, prefix1, prefix2):
    """Decode a digit sequence using straddling checkerboard."""
    result = []
    i = 0
    while i < len(digits):
        d = digits[i]
        if d == prefix1 or d == prefix2:
            if i + 1 < len(digits):
                pair = str(d) + str(digits[i + 1])
                if pair in decode_dict:
                    result.append(decode_dict[pair])
                i += 2
            else:
                break
        else:
            key = str(d)
            if key in decode_dict:
                result.append(decode_dict[key])
            i += 1
    return "".join(result)


# ── Scoring ────────────────────────────────────────────────────────────

def score_against_cribs_ct73(plaintext):
    """Score plaintext against cribs mapped to CT73 positions."""
    matches = 0
    for i, crib_pos in enumerate(CRIB_POS_97):
        ct73_idx = CRIB_CT73_IDX[i]
        if ct73_idx < len(plaintext) and plaintext[ct73_idx] == CRIB_DICT[crib_pos]:
            matches += 1
    return matches


def score_against_cribs_ct97(plaintext):
    """Score plaintext against cribs at CT97 positions."""
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(plaintext) and plaintext[pos] == ch:
            matches += 1
    return matches


# ── TEST 1: VIC on CT73 ───────────────────────────────────────────────

def test1_vic_on_ct73():
    """Apply VIC decryption to CT73 (null-stripped first)."""
    print("\n  TEST 1: VIC cipher on CT73 (after null removal)")
    print(f"  CT73: {CT73}")

    # Convert CT73 to digits via multiple mapping strategies
    ct73_digits_maps = {}

    # Map A: sequential (A=0, B=1, ... Z=5 with wrapping)
    ct73_digits_maps["sequential"] = [ALPH_IDX[c] % 10 for c in CT73]

    # Map B: KA-indexed mod 10
    ct73_digits_maps["ka_mod10"] = [KA_IDX[c] % 10 for c in CT73]

    # Map C: AZ-indexed mod 10 (same as sequential but explicit)
    ct73_digits_maps["az_mod10"] = [ALPH_IDX[c] % 10 for c in CT73]

    # Phrases to test
    phrases = [
        "THESNOWSOFYESTERYEAR",  # Close to actual Häyhänen phrase
        "THEIDEAOFANEWSOCIETY",  # Alternate VIC phrase variant
        "KRYPTOSABCDEFGHIJLMN",  # KA first 20
        "BETWEENSUBTLESHADING",  # K1 PT first 20
        "ITWASTOTALLYINVISIBL",  # K2 PT first 20
        "SLOWLYDESPARATLYSLOW",  # K3 PT first 20
        "PALABORAANDTHEBUSHED",  # Sanborn phrase variant
        "BERLINCLOCKATWORLDTI",  # Berlin thematic
        "DEFECTORHAYHAHNENSPY",  # DEFECTOR thematic
        "ALEXANDERPLATZPROTEST", # Berlin Wall thematic
    ]

    dates = [
        [1, 3, 0, 7, 5],  # 13/07/53 — Häyhänen defection 1953
        [0, 9, 1, 1, 8],  # 09/11/89 — Berlin Wall fall
        [1, 1, 0, 9, 8],  # 11/09/89 — alt format
        [0, 4, 1, 1, 8],  # 04/11/89 — Alexanderplatz demo
        [0, 3, 1, 1, 9],  # 03/11/90 — Kryptos dedication
        [1, 9, 9, 0, 0],  # 1990 + 0
    ]

    personal_numbers = [3, 5, 6, 7, 8]

    best_score = 0
    best_result = None
    total_configs = 0

    for phrase in phrases:
        for date in dates:
            for pn in personal_numbers:
                vic_keys_list = generate_full_vic_keys(phrase, date, pn)
                if not vic_keys_list:
                    continue

                for vk in vic_keys_list[:1000]:  # limit per combo
                    ks = vk['keystream'][:73]
                    if len(ks) < 73:
                        continue

                    for map_name, ct_digits in ct73_digits_maps.items():
                        # Subtract keystream from CT digits mod 10
                        plain_digits = [(ct_digits[i] - ks[i]) % 10 for i in range(73)]

                        # Try to decode via checkerboard
                        for bp1 in range(10):
                            for bp2 in range(bp1 + 1, 10):
                                # Build checkerboard with ETAONIRSH as top row
                                # (standard English frequency order)
                                freq_order = "ETAONIRSHLDCUPFMWYBGVKJXQZ"
                                _, decode = build_checkerboard(freq_order, bp1, bp2)

                                pt = checkerboard_decode_digits(plain_digits, decode, bp1, bp2)
                                if len(pt) >= 24:
                                    sc = score_against_cribs_ct73(pt)
                                    total_configs += 1

                                    if sc > best_score:
                                        best_score = sc
                                        best_result = {
                                            "phrase": phrase, "date": date, "pn": pn,
                                            "map": map_name, "blanks": (bp1, bp2),
                                            "score": sc, "pt": pt[:50],
                                        }

                    # Also: direct digit subtraction then digit→letter (no checkerboard)
                    for map_name, ct_digits in ct73_digits_maps.items():
                        plain_digits = [(ct_digits[i] - ks[i]) % 10 for i in range(73)]
                        # Convert digits back to letters: digit d → ALPH[d] (wrapping)
                        pt = "".join(ALPH[d] for d in plain_digits)
                        sc = score_against_cribs_ct73(pt)
                        total_configs += 1
                        if sc > best_score:
                            best_score = sc
                            best_result = {
                                "phrase": phrase, "date": date, "pn": pn,
                                "map": map_name, "blanks": "none",
                                "score": sc, "pt": pt[:50],
                            }

    print(f"  Tested {total_configs:,} configs")
    print(f"  Best score: {best_score}/24")
    if best_result:
        print(f"  Best: {best_result}")
    return best_score, best_result


# ── TEST 2: KA Tableau as Checkerboard ─────────────────────────────────

def test2_ka_checkerboard():
    """Use the KA alphabet ordering as the checkerboard alphabet."""
    print("\n  TEST 2: KA tableau as straddling checkerboard")

    # KA = KRYPTOSABCDEFGHIJLMNQUVWXZ
    # Use KA ordering for the checkerboard (instead of frequency order)
    # This means K,R,Y,P,T,O,S,A are the 8 top-row (monome) letters
    # B,C,D,E,F,G,H,I,J,L are prefix-row-1 (dinome)
    # M,N,Q,U,V,W,X,Z are prefix-row-2 (dinome, only 8 letters)

    best_score = 0
    best_result = None
    total_configs = 0

    for bp1 in range(10):
        for bp2 in range(bp1 + 1, 10):
            _, decode = build_checkerboard(KA, bp1, bp2)

            # Convert CT97 to digits via KA index mod 10
            ct_digits = [KA_IDX[c] % 10 for c in CT]

            # Try with no keystream (pure checkerboard)
            pt = checkerboard_decode_digits(ct_digits, decode, bp1, bp2)
            if len(pt) >= 24:
                sc = score_against_cribs_ct97(pt)
                total_configs += 1
                if sc > best_score:
                    best_score = sc
                    best_result = {"blanks": (bp1, bp2), "score": sc,
                                   "pt": pt[:50], "method": "pure_cb"}

            # Also try on CT73
            ct73_digits = [KA_IDX[c] % 10 for c in CT73]
            pt73 = checkerboard_decode_digits(ct73_digits, decode, bp1, bp2)
            if len(pt73) >= 24:
                sc73 = score_against_cribs_ct73(pt73)
                total_configs += 1
                if sc73 > best_score:
                    best_score = sc73
                    best_result = {"blanks": (bp1, bp2), "score": sc73,
                                   "pt": pt73[:50], "method": "pure_cb_ct73"}

    print(f"  Tested {total_configs:,} configs (pure checkerboard)")
    print(f"  Best: {best_score}/24")
    if best_result:
        print(f"  Best: {best_result}")
    return best_score, best_result


# ── TEST 3: Historical Häyhänen VIC Parameters ─────────────────────────

def test3_hayhanen():
    """Test the actual historical Häyhänen VIC parameters."""
    print("\n  TEST 3: Historical Häyhänen VIC parameters")

    # Häyhänen's known parameters (from declassified sources):
    # Phrase: variations of Russian poem, transliterated
    # The actual phrase used was from a Russian song/poem
    # Common reconstruction: "SNOWSOFWINTERMELTEDLO" or similar
    # Date: related to 1953 events
    # Personal number: reportedly 6 or 3

    hayhanen_phrases = [
        "THESNOWSOFYESTERYEAR",
        "SNOWFALLSOFTHELASTWI",  # "Snowfalls of the last winter"
        "THELASTSNOWOFWINTERS",  # "The last snow of winter"
        "ИДУТБЕЛЫЕСНЕГИИДУТБЕ",  # Russian (won't work with A-Z)
        "WHENTHESNOWMELTSAWAY",
        "SNOWOFWINTERMELTSINT",
        "THEWHITESNOWISFALLEN",
        "SNOWWHITEANDTHEROSES",
    ]
    # Filter to valid A-Z only, 20 chars
    hayhanen_phrases = [p for p in hayhanen_phrases if len(p) >= 20 and p.isalpha()]

    # Häyhänen defected June 1957, was active 1952-1957
    hayhanen_dates = [
        [2, 0, 0, 6, 5],  # 20/06/53 (Häyhänen arrived US)
        [1, 5, 1, 1, 5],  # 15/11/52 (possible activation)
        [2, 2, 0, 6, 5],  # 22/06/53
        [0, 4, 0, 5, 5],  # 04/05/53 (hollow nickel found)
        [0, 9, 1, 1, 8],  # 09/11/89 (Berlin Wall - Sanborn reference)
        [0, 3, 1, 1, 9],  # 03/11/90 (Kryptos dedication)
    ]

    personal_numbers = [3, 6, 5, 7, 8]

    best_score_97 = 0
    best_score_73 = 0
    best_result = None
    total = 0

    for phrase in hayhanen_phrases:
        for date in hayhanen_dates:
            for pn in personal_numbers:
                keys_list = generate_full_vic_keys(phrase, date, pn)
                if not keys_list:
                    continue

                for vk in keys_list[:2000]:
                    ks = vk['keystream']

                    # Test on CT97: subtract keystream digits from CT digit representation
                    for ct_str, target_len, scorer, label in [
                        (CT, 97, score_against_cribs_ct97, "CT97"),
                        (CT73, 73, score_against_cribs_ct73, "CT73"),
                    ]:
                        ct_digits = [ALPH_IDX[c] % 10 for c in ct_str]
                        ks_slice = ks[:target_len]
                        if len(ks_slice) < target_len:
                            continue

                        plain_digits = [(ct_digits[i] - ks_slice[i]) % 10 for i in range(target_len)]
                        pt = "".join(ALPH[d] for d in plain_digits)
                        sc = scorer(pt)
                        total += 1

                        if sc > max(best_score_97, best_score_73):
                            best_result = {
                                "phrase": phrase[:20], "date": date, "pn": pn,
                                "target": label, "score": sc, "pt": pt[:50],
                            }
                        if label == "CT97" and sc > best_score_97:
                            best_score_97 = sc
                        if label == "CT73" and sc > best_score_73:
                            best_score_73 = sc

    print(f"  Tested {total:,} configs")
    print(f"  Best CT97: {best_score_97}/24, Best CT73: {best_score_73}/24")
    if best_result:
        print(f"  Best: {best_result}")
    return max(best_score_97, best_score_73), best_result


# ── Main ───────────────────────────────────────────────────────────────

def main():
    t_start = time.time()
    print("=" * 70)
    print("VIC GAP-CLOSING TEST v1")
    print("=" * 70)

    results = {}

    s1, r1 = test1_vic_on_ct73()
    results["test1_vic_ct73"] = {"score": s1, "detail": r1}

    s2, r2 = test2_ka_checkerboard()
    results["test2_ka_checkerboard"] = {"score": s2, "detail": r2}

    s3, r3 = test3_hayhanen()
    results["test3_hayhanen"] = {"score": s3, "detail": r3}

    elapsed = time.time() - t_start
    max_score = max(s1, s2, s3)

    print(f"\n{'='*70}")
    print(f"SUMMARY ({elapsed:.1f}s)")
    print(f"{'='*70}")
    print(f"  Test 1 (VIC on CT73):        {s1}/24")
    print(f"  Test 2 (KA checkerboard):    {s2}/24")
    print(f"  Test 3 (Häyhänen params):    {s3}/24")
    print(f"  Overall best: {max_score}/24")

    if max_score >= 10:
        print(f"\n  ** SIGNAL: {max_score}/24 — investigate! **")
    else:
        print(f"\n  All noise. VIC is comprehensively ELIMINATED.")

    output_path = os.path.join(_ROOT, "results", "f_vic_gap_close_v1.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump({
            "experiment": "vic_gap_close_v1",
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "elapsed": elapsed,
            "results": {k: {"score": v["score"]} for k, v in results.items()},
            "max_score": max_score,
        }, f, indent=2)
    print(f"  Results: {output_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
