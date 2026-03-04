#!/usr/bin/env python3
"""
Cipher: Vigenere/Beaufort
Family: _uncategorized
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-13: Keyword-derived transposition + Vigenère/Beaufort period consistency.

Instead of testing random permutations (97! is astronomical), this tests
transpositions derived from MEANINGFUL keywords associated with Kryptos:
- Columnar transposition with keyword-derived column order
- Myszkowski transposition (handles repeated letters)
- Double columnar (keyword pair, both directions)

Keywords sourced from: sculpture text, known plaintexts, Sanborn clues,
CIA/intelligence terms, Egypt/Berlin references.

For each (transposition, period), checks how many crib positions produce
consistent Vigenère/Beaufort key values.
"""

import json
import os
import sys
import time
from collections import Counter, defaultdict
from itertools import product

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import CT, CT_LEN, CRIB_ENTRIES, MOD

# ═══ Setup ════════════════════════════════════════════════════════════════

CT_INT = [ord(c) - 65 for c in CT]

_sorted = sorted(CRIB_ENTRIES, key=lambda x: x[0])
CRIB_POS = [p for p, _ in _sorted]
CRIB_DICT = {p: c for p, c in _sorted}
PT_INT = {p: ord(c) - 65 for p, c in _sorted}
N_CRIBS = len(CRIB_POS)

NOISE_FLOORS = {
    3: 5.0, 4: 5.8, 5: 6.5, 6: 7.2, 7: 8.2, 8: 9.2,
    9: 10.0, 10: 11.0, 11: 12.0, 12: 13.0, 13: 13.5,
}

# ═══ Keywords ══════════════════════════════════════════════════════════════

KEYWORDS = [
    # Sculpture / artwork
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "FORCES",
    "LUCID", "MEMORY", "IQLUSION", "ILLUSION", "VIRTUALLY",
    "INVISIBLE", "UNDERGRUUND", "DIGETAL", "INTERPRETATIT",
    # Known plaintext fragments
    "EASTNORTHEAST", "BERLINCLOCK", "BETWEEN", "SUBTLE", "SHADING",
    "NUANCE", "DESPERATLY", "REMAINS", "PASSAGE", "DEBRIS",
    # Sanborn 2025 clues
    "BERLIN", "CLOCK", "EGYPT", "CAIRO", "GIZA", "PYRAMIDS",
    "PHARAOH", "TUTANKHAMUN", "CARTER", "TOMB", "CANDLE",
    "WONDERFUL", "THINGS", "MESSAGE", "DELIVERING",
    "WHATSTHEPOINT", "THEPOINT", "POINT",
    # CIA / Intelligence
    "LANGLEY", "AGENCY", "CENTRAL", "INTELLIGENCE",
    "CIPHER", "DECIPHER", "ENCODE", "DECODE", "SECRET",
    "CLASSIFIED", "COVERT", "STEALTH",
    # Sanborn / Scheidt
    "SANBORN", "SCHEIDT", "WEBSTER", "SCULPTOR",
    # Historical
    "BERLINWALL", "NOVEMBER", "NINETEEN", "EIGHTYNINE",
    "COLDWAR", "REUNIFICATION",
    # K3 method clue
    "KEYHOLE", "MATRIX", "TABLEAU",
    # Numbers as words/dates
    "NINETEENEIGHTYSIX", "NINETEENEIGHTYNINE",
    # Misc thematic
    "COORDINATE", "LATITUDE", "LONGITUDE",
    "MAGNETIC", "FIELD", "COMPASS", "NORTH",
    "BURIED", "SOMEWHERE", "LOCATION", "UNKNOWN",
    # Short keys often used
    "KEY", "CODE", "PASS", "WORD", "OPEN",
    # Combined / compound
    "KRYPTOSPALIMPSEST", "KRYPTOSABSCISSA",
    "EASTBERLIN", "WESTBERLIN",
]

# Remove duplicates, keep order
seen = set()
KEYWORDS_UNIQUE = []
for kw in KEYWORDS:
    kw_upper = kw.upper()
    if kw_upper not in seen:
        seen.add(kw_upper)
        KEYWORDS_UNIQUE.append(kw_upper)


# ═══ Transposition builders ═══════════════════════════════════════════════

def keyword_to_col_order(keyword):
    """Convert a keyword to column ordering (alphabetic order of letters).
    Ties broken by position (standard columnar convention).
    """
    indexed = [(c, i) for i, c in enumerate(keyword)]
    indexed.sort(key=lambda x: (x[0], x[1]))
    order = [0] * len(keyword)
    for rank, (_, orig_idx) in enumerate(indexed):
        order[orig_idx] = rank
    return order


def columnar_encrypt_perm(keyword, length):
    """Build the permutation for columnar transposition encryption.
    Encrypt = write in rows by keyword width, read off by column order.
    perm[i] = position in input that maps to output position i.
    """
    width = len(keyword)
    col_order = keyword_to_col_order(keyword)
    n_rows = (length + width - 1) // width

    # Build: output position for each input position
    # Input is written row by row. Read by columns in col_order.
    perm = []
    # Read columns in order 0,1,2,...
    # Column ranked 'r' is the original column where col_order[orig_col] == r
    rank_to_orig = [0] * width
    for orig, rank in enumerate(col_order):
        rank_to_orig[rank] = orig

    for rank in range(width):
        orig_col = rank_to_orig[rank]
        for row in range(n_rows):
            pos = row * width + orig_col
            if pos < length:
                perm.append(pos)

    return perm


def columnar_decrypt_perm(keyword, length):
    """Build permutation for columnar transposition decryption.
    decrypt_perm[i] = position in CT that maps to PT position i.
    """
    enc_perm = columnar_encrypt_perm(keyword, length)
    # Invert: if enc_perm[out] = in, then dec_perm[in] = out
    dec_perm = [0] * length
    for out_pos, in_pos in enumerate(enc_perm):
        dec_perm[in_pos] = out_pos
    return dec_perm


def myszkowski_encrypt_perm(keyword, length):
    """Myszkowski transposition: repeated letters share the same column number,
    and their positions are read left-to-right across rows.
    """
    width = len(keyword)
    n_rows = (length + width - 1) // width

    # Group columns by letter
    col_groups = defaultdict(list)
    for i, c in enumerate(keyword):
        col_groups[c].append(i)

    # Sort groups by letter
    sorted_letters = sorted(col_groups.keys())

    perm = []
    for letter in sorted_letters:
        cols = col_groups[letter]
        if len(cols) == 1:
            # Single column: read top to bottom
            col = cols[0]
            for row in range(n_rows):
                pos = row * width + col
                if pos < length:
                    perm.append(pos)
        else:
            # Multiple columns: read row by row, left to right across these columns
            for row in range(n_rows):
                for col in cols:
                    pos = row * width + col
                    if pos < length:
                        perm.append(pos)

    return perm


def myszkowski_decrypt_perm(keyword, length):
    """Decrypt permutation for Myszkowski."""
    enc_perm = myszkowski_encrypt_perm(keyword, length)
    dec_perm = [0] * length
    for out_pos, in_pos in enumerate(enc_perm):
        dec_perm[in_pos] = out_pos
    return dec_perm


def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# ═══ Scoring ═════════════════════════════════════════════════════════════

def score_transposition(perm, direction='decrypt'):
    """Score a transposition + periodic Vigenère.

    If direction='decrypt': apply perm as decryption (perm maps CT→intermediate),
    then check periodic Vig consistency on intermediate text.

    Key at crib position p: k[p] = (intermediate[p] - PT[p]) mod 26

    Two models:
    A) CT was produced by: PT → Vig encrypt → transpose encrypt
       Decrypt: CT → transpose decrypt → Vig decrypt
       intermediate = transpose_decrypt(CT)
       intermediate[p] = CT[perm[p]] (gather convention)

    B) CT was produced by: PT → transpose encrypt → Vig encrypt
       Decrypt: CT → Vig decrypt → transpose decrypt
       This means CT[i] = Vig(transposed_PT[i], key[i])
       key[i] = (CT[i] - transposed_PT[i]) mod 26
       transposed_PT = transpose_encrypt(PT)
       At crib position p in original PT: transposed position = enc_perm[p]
       So key[enc_perm[p]] = (CT[enc_perm[p]] - PT[p]) mod 26

    We test Model A here (transpose layer is outermost).
    """
    results = {}

    for variant in ['vigenere', 'beaufort']:
        for period in range(3, 14):
            groups = defaultdict(list)
            for p in CRIB_POS:
                if p < len(perm):
                    ct_val = CT_INT[perm[p]]
                    pt_val = PT_INT[p]
                    if variant == 'vigenere':
                        key_val = (ct_val - pt_val) % 26
                    else:
                        key_val = (ct_val + pt_val) % 26
                    groups[p % period].append(key_val)

            score = 0
            for vals in groups.values():
                if vals:
                    score += Counter(vals).most_common(1)[0][1]

            noise = NOISE_FLOORS.get(period, 8)
            key = f"{variant}_p{period}"
            results[key] = {"score": score, "noise": noise, "excess": score - noise}

    return results


def score_model_b(enc_perm):
    """Model B: CT = Vig(transpose(PT), key).
    key[enc_perm[p]] = (CT[enc_perm[p]] - PT[p]) mod 26
    Check if these scattered key positions are periodic.
    """
    results = {}

    for variant in ['vigenere', 'beaufort']:
        for period in range(3, 14):
            groups = defaultdict(list)
            for p in CRIB_POS:
                q = enc_perm[p]  # position in transposed text
                ct_val = CT_INT[q]
                pt_val = PT_INT[p]
                if variant == 'vigenere':
                    key_val = (ct_val - pt_val) % 26
                else:
                    key_val = (ct_val + pt_val) % 26
                groups[q % period].append(key_val)

            score = 0
            for vals in groups.values():
                if vals:
                    score += Counter(vals).most_common(1)[0][1]

            noise = NOISE_FLOORS.get(period, 8)
            key = f"{variant}_p{period}"
            results[key] = {"score": score, "noise": noise, "excess": score - noise}

    return results


def best_result(results):
    """Find the best result by excess over noise."""
    best_key = max(results, key=lambda k: results[k]["excess"])
    return best_key, results[best_key]


def main():
    t0 = time.time()

    print("=" * 60)
    print("E-S-13: Keyword-Derived Transposition + Period Consistency")
    print("=" * 60)
    print(f"Keywords: {len(KEYWORDS_UNIQUE)}")
    print(f"Transposition types: columnar, Myszkowski, double columnar")
    print(f"Models: A (trans outer), B (trans inner)")
    print(f"Variants: Vigenère, Beaufort × periods 3-13")
    print()

    all_results = []
    global_best = {"score": 0, "excess": -99}
    n_tested = 0

    # ═══ Single transposition ══════════════════════════════════════════════
    print("Phase 1: Single keyword transposition")
    print("-" * 40)

    for kw in KEYWORDS_UNIQUE:
        if len(kw) < 3 or len(kw) > 20:
            continue

        # Columnar
        dec_perm = columnar_decrypt_perm(kw, CT_LEN)
        enc_perm = columnar_encrypt_perm(kw, CT_LEN)

        # Model A
        res_a = score_transposition(dec_perm)
        bk_a, br_a = best_result(res_a)
        n_tested += 1

        # Model B
        res_b = score_model_b(enc_perm)
        bk_b, br_b = best_result(res_b)
        n_tested += 1

        for tag, bk, br in [("col_A", bk_a, br_a), ("col_B", bk_b, br_b)]:
            entry = {
                "keyword": kw, "type": f"columnar_{tag}",
                "best_config": bk, "score": br["score"],
                "excess": round(br["excess"], 1),
            }
            all_results.append(entry)
            if br["score"] > global_best["score"] or (
                br["score"] == global_best["score"] and br["excess"] > global_best["excess"]):
                global_best = entry

        # Myszkowski (only useful if keyword has repeated letters)
        if len(set(kw)) < len(kw):
            dec_perm_m = myszkowski_decrypt_perm(kw, CT_LEN)
            enc_perm_m = myszkowski_encrypt_perm(kw, CT_LEN)

            res_a_m = score_transposition(dec_perm_m)
            bk_a_m, br_a_m = best_result(res_a_m)
            n_tested += 1

            res_b_m = score_model_b(enc_perm_m)
            bk_b_m, br_b_m = best_result(res_b_m)
            n_tested += 1

            for tag, bk, br in [("mysz_A", bk_a_m, br_a_m), ("mysz_B", bk_b_m, br_b_m)]:
                entry = {
                    "keyword": kw, "type": f"myszkowski_{tag}",
                    "best_config": bk, "score": br["score"],
                    "excess": round(br["excess"], 1),
                }
                all_results.append(entry)
                if br["score"] > global_best["score"] or (
                    br["score"] == global_best["score"] and br["excess"] > global_best["excess"]):
                    global_best = entry

    print(f"  Single transposition: {n_tested} configs tested")
    print(f"  Best so far: {global_best['score']}/24 excess={global_best['excess']} "
          f"({global_best.get('keyword', '?')} {global_best.get('type', '?')})")

    # ═══ Double columnar transposition ═════════════════════════════════════
    print("\nPhase 2: Double columnar (keyword pairs)")
    print("-" * 40)

    # Use top keywords (short ones for tractability)
    short_kws = [kw for kw in KEYWORDS_UNIQUE if 4 <= len(kw) <= 10]
    n_pairs = 0
    n_double = 0

    for kw1 in short_kws:
        for kw2 in short_kws:
            if kw1 == kw2:
                continue

            # Double columnar: encrypt with kw1, then encrypt with kw2
            # Decrypt: decrypt kw2, then decrypt kw1
            enc1 = columnar_encrypt_perm(kw1, CT_LEN)
            enc2 = columnar_encrypt_perm(kw2, CT_LEN)

            # Combined encryption: compose enc2(enc1(x))
            # combined_enc[i] = enc2[enc1[i]] -- NO, permutation composition
            # If PT → enc1 → intermediate → enc2 → CT
            # Then CT[enc2[j]] = intermediate[j] = PT[enc1_inv[j]]
            # Wait, need to be careful with gather/scatter convention.

            # enc_perm: output[i] = input[enc_perm[i]]? No.
            # Our enc_perm: perm[out_pos] = in_pos (gather for output)
            # So intermediate[i] = PT[enc1_inv[i]] ... actually:
            # enc1 maps: reading input row-by-row, output column-by-column
            # enc1[out] = in: output[out] = input[enc1[out]]? No.
            # Let me re-check: columnar_encrypt_perm returns perm where
            # perm[i] is the input position read at output position i.
            # So output[i] = input[perm[i]], which is gather convention.

            # For double: output1 = input[enc1], output2 = output1[enc2]
            # output2[i] = output1[enc2[i]] = input[enc1[enc2[i]]]
            # So combined_perm[i] = enc1[enc2[i]]

            combined_enc = [enc1[enc2[i]] for i in range(CT_LEN)]
            combined_dec = invert_perm(combined_enc)

            # Model A: CT was encrypted by combined, decrypt by inverse
            res_a = score_transposition(combined_dec)
            bk_a, br_a = best_result(res_a)

            # Model B
            res_b = score_model_b(combined_enc)
            bk_b, br_b = best_result(res_b)

            n_double += 2

            for tag, bk, br in [("dbl_A", bk_a, br_a), ("dbl_B", bk_b, br_b)]:
                entry = {
                    "keyword": f"{kw1}+{kw2}", "type": f"double_col_{tag}",
                    "best_config": bk, "score": br["score"],
                    "excess": round(br["excess"], 1),
                }
                all_results.append(entry)
                if br["score"] > global_best["score"] or (
                    br["score"] == global_best["score"] and br["excess"] > global_best["excess"]):
                    global_best = entry

            n_pairs += 1
            if n_pairs % 500 == 0:
                print(f"  [{n_pairs:>6}] pairs  best={global_best['score']}/24  "
                      f"({global_best.get('keyword', '?')})")
                sys.stdout.flush()

    print(f"  Double columnar: {n_double} configs from {n_pairs} pairs")
    print(f"  Best: {global_best['score']}/24 excess={global_best['excess']} "
          f"({global_best.get('keyword', '?')} {global_best.get('type', '?')})")

    # ═══ Summary ═══════════════════════════════════════════════════════════
    elapsed = time.time() - t0

    all_results.sort(key=lambda x: (-x["score"], -x["excess"]))

    print(f"\n{'=' * 60}")
    print(f"  TOP 20 RESULTS")
    print(f"{'=' * 60}")
    for i, r in enumerate(all_results[:20]):
        print(f"  {i+1:>2}. {r['keyword']:<30s} {r['type']:<15s} "
              f"score={r['score']}/24 excess={r['excess']:+.1f} "
              f"@ {r['best_config']}")

    # Period 7 specific
    p7_results = []
    for r in all_results:
        # re-extract p7 info from the full results
        p7_results.append(r)

    # Noise analysis
    scores = [r["score"] for r in all_results]
    score_dist = Counter(scores)
    print(f"\n  Score distribution: {dict(sorted(score_dist.items(), reverse=True))}")

    n_total = n_tested + n_double
    if global_best["score"] >= 18:
        verdict = "SIGNAL"
    elif global_best["score"] >= 14:
        verdict = "INVESTIGATE"
    else:
        verdict = "NOISE"

    print(f"\n  Total configs: {n_total}")
    print(f"  Time: {elapsed:.1f}s")
    print(f"  VERDICT: {verdict}")

    # Write results
    os.makedirs("results", exist_ok=True)
    outpath = "results/e_s_13_keyword_transposition.json"
    with open(outpath, "w") as f:
        json.dump({
            "experiment": "E-S-13",
            "hypothesis": "Keyword-derived transposition reveals periodic key",
            "total_time_s": round(elapsed, 1),
            "verdict": verdict,
            "n_configs": n_total,
            "n_keywords": len(KEYWORDS_UNIQUE),
            "global_best": global_best,
            "top_20": all_results[:20],
            "score_distribution": dict(sorted(score_dist.items(), reverse=True)),
        }, f, indent=2, default=str)

    print(f"\n  Artifacts: {outpath}")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_13_keyword_transposition.py")
    print(f"\nRESULT: best={global_best['score']}/24 verdict={verdict}")


if __name__ == "__main__":
    main()
