#!/usr/bin/env python3
"""
E-CHART-03: Misspelling-Modified Tableau Variants for K4

Theory: The deliberate misspellings in K1-K3 are INSTRUCTIONS for modifying
the visible KA Vigenere tableau to create K4's coding chart.

Misspelling substitutions (correct -> wrong):
  S->C, L->Q, O->U, E->A, I->E

The KA alphabet: KRYPTOSABCDEFGHIJLMNQUVWXZ (26 letters, keyword KRYPTOS first)

Modifications tested:
  1. ROW SWAPS (independent and chained)
  2. COLUMN SWAPS (independent and chained)
  3. BOTH row + column swaps
  4. LETTER REPLACEMENT in tableau
  5. ROW PERMUTATION by misspelling offsets (cyclic)
  6. KEYWORD from misspelling letters (CQUAE, SLOEI, EQUAL, etc.)

Each modified tableau is tested with multiple keywords and cipher variants.
Top configs also tested with width-8 columnar transposition.

Output: results/e_chart_03_misspelling.json
Repro:  PYTHONPATH=src python3 -u scripts/e_chart_03_misspelling_tableau.py
"""

import json
import os
import sys
import time
from itertools import permutations
from copy import deepcopy

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import (
    CT, CT_LEN, CRIB_DICT, ALPH_IDX, MOD, KRYPTOS_ALPHABET, N_CRIBS,
)
from kryptos.kernel.scoring.crib_score import score_cribs, score_cribs_detailed
from kryptos.kernel.constraints.bean import verify_bean, verify_bean_simple

# ── Constants ──────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET  # KRYPTOSABCDEFGHIJLMNQUVWXZ
KA_IDX = {c: i for i, c in enumerate(KA)}
CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN

# Misspelling pairs: correct -> wrong
MISSPELLINGS = [
    ('S', 'C'),  # DESPARATLY: S->C wrong; correct: DESPERATELY has S at that spot... actually S->C
    ('L', 'Q'),
    ('O', 'U'),
    ('E', 'A'),
    ('I', 'E'),
]

# Misspelling shifts in standard alphabet
# S(18)->C(2) = -16 mod 26 = 10
# L(11)->Q(16) = +5
# O(14)->U(20) = +6
# E(4)->A(0) = -4 mod 26 = 22
# I(8)->E(4) = -4 mod 26 = 22
MISSPELLING_OFFSETS = [10, 5, 6, 22, 22]

# Keywords to test
KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "LAYERTWO", "YAR",
    "STOPWATCH", "CQUAE", "SLOEI", "EQUAL", "EAUQC", "IEOLS",
    "LAUQE", "BERLINCLOCK", "EASTNORTHEAST",
]

# K3 plaintext as running key source
K3_PT = "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBABORHHRISWASOIFRRRISCOVEREDLEADINGTOKING"
# K1+K2+K3 concatenated
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
K2_PT = "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHEEARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDANDTRANSMITTEDUNDERGRUABORHNDIREWMYLVYFHLAYCEPSMKYWFVDHWIOKNCLSZQSCQHNRETYJPRJKWLBHVAKQSXOGNIFEAYFRO"

RUNNING_KEYS = {
    "K3_PT": K3_PT,
    "K1_PT": K1_PT,
    "K2_PT": K2_PT,
    "K1K2K3": K1_PT + K2_PT + K3_PT,
}


def build_ka_tableau():
    """Build the standard KA Vigenere tableau: 26 rows, each shifted."""
    tableau = []
    for i in range(26):
        row = KA[i:] + KA[:i]
        tableau.append(list(row))
    return tableau


def tableau_encrypt(pt_char, key_char, tableau):
    """Encrypt: row = KA position of key, col = KA position of pt."""
    row = KA_IDX[key_char]
    col = KA_IDX[pt_char]
    return tableau[row][col]


def tableau_decrypt_vig(ct_char, key_char, tableau):
    """Decrypt Vigenere-style: find ct_char in row[key], return column letter."""
    row_idx = KA_IDX[key_char]
    row = tableau[row_idx]
    try:
        col = row.index(ct_char)
    except ValueError:
        return None
    return KA[col]


def tableau_decrypt_beau(ct_char, pt_char_guess, tableau):
    """Decrypt Beaufort-style: find ct_char in column[pt], return row letter."""
    col = KA_IDX[pt_char_guess]
    for row_idx in range(26):
        if tableau[row_idx][col] == ct_char:
            return KA[row_idx]
    return None


def decrypt_with_tableau(ct_str, key_str, tableau, variant="vigenere"):
    """Decrypt full CT with a key through a (possibly modified) tableau.

    variant: 'vigenere', 'beaufort', 'variant_beaufort'
    For Vigenere: PT[i] = col where tableau[key_row][col] == CT[i]
    For Beaufort: PT[i] = col where tableau[ct_row][col] == key[i]
                  (equivalently, find key in column of pt)
    For Variant Beaufort: same as Vigenere but inverted
    """
    pt = []
    for i in range(len(ct_str)):
        ct_c = ct_str[i]
        key_c = key_str[i % len(key_str)]

        if variant == "vigenere":
            # Find ct_c in the row indexed by key_c, return col as KA letter
            row_idx = KA_IDX[key_c]
            row = tableau[row_idx]
            try:
                col = row.index(ct_c)
            except ValueError:
                pt.append('?')
                continue
            pt.append(KA[col])
        elif variant == "beaufort":
            # Find ct_c in the row indexed by pt_c... but we don't know pt_c.
            # Beaufort: CT = tableau[PT][KEY], so find row where tableau[row][key_col] == ct_c
            key_col = KA_IDX[key_c]
            found = False
            for row_idx in range(26):
                if tableau[row_idx][key_col] == ct_c:
                    pt.append(KA[row_idx])
                    found = True
                    break
            if not found:
                pt.append('?')
        elif variant == "variant_beaufort":
            # CT = tableau[KEY][PT], solve for PT: same as Vigenere but with
            # the lookup reversed. Actually for variant Beaufort:
            # CT[i] = (KEY - PT) mod 26 in standard; in tableau terms:
            # Find ct_c in column indexed by key_c, return row as KA letter
            key_col = KA_IDX[key_c]
            found = False
            for row_idx in range(26):
                if tableau[row_idx][key_col] == ct_c:
                    pt.append(KA[row_idx])
                    found = True
                    break
            if not found:
                pt.append('?')
        else:
            pt.append('?')
    return ''.join(pt)


def apply_row_swaps_independent(tableau, pairs):
    """Swap rows based on misspelling pairs (independent, not chained)."""
    t = deepcopy(tableau)
    for correct, wrong in pairs:
        r1 = KA_IDX[correct]
        r2 = KA_IDX[wrong]
        t[r1], t[r2] = t[r2], t[r1]
    return t


def apply_row_swaps_chained(tableau, pairs):
    """Swap rows based on misspelling pairs (chained, sequential).
    Each swap modifies the tableau before the next swap is applied."""
    t = deepcopy(tableau)
    for correct, wrong in pairs:
        r1 = KA_IDX[correct]
        r2 = KA_IDX[wrong]
        t[r1], t[r2] = t[r2], t[r1]
    return t  # Note: chaining matters when E is involved in both (E->A, I->E)


def apply_col_swaps_independent(tableau, pairs):
    """Swap columns based on misspelling pairs (independent)."""
    t = deepcopy(tableau)
    for correct, wrong in pairs:
        c1 = KA_IDX[correct]
        c2 = KA_IDX[wrong]
        for row in t:
            row[c1], row[c2] = row[c2], row[c1]
    return t


def apply_col_swaps_chained(tableau, pairs):
    """Swap columns based on misspelling pairs (chained/sequential)."""
    t = deepcopy(tableau)
    for correct, wrong in pairs:
        c1 = KA_IDX[correct]
        c2 = KA_IDX[wrong]
        for row in t:
            row[c1], row[c2] = row[c2], row[c1]
    return t


def apply_both_swaps(tableau, pairs, chained=False):
    """Apply row swaps then column swaps."""
    if chained:
        t = apply_row_swaps_chained(tableau, pairs)
        return apply_col_swaps_chained(t, pairs)
    else:
        t = apply_row_swaps_independent(tableau, pairs)
        return apply_col_swaps_independent(t, pairs)


def apply_letter_replacement(tableau):
    """Replace every instance of correct letter with wrong letter.
    S->C, L->Q, O->U, E->A, I->E.

    WARNING: This makes the tableau non-bijective (C, Q, U, A, E appear twice;
    S, L, O, original-E, I disappear). Decryption may be ambiguous.
    """
    t = deepcopy(tableau)
    replacements = {p[0]: p[1] for p in MISSPELLINGS}
    for r in range(26):
        for c in range(26):
            if t[r][c] in replacements:
                t[r][c] = replacements[t[r][c]]
    return t


def apply_row_offset_cyclic(tableau, offsets):
    """At each position i, use row (original_key_row + offsets[i % len(offsets)]) mod 26.
    This doesn't modify the tableau itself but changes which row is used during decryption.
    We implement this by returning a function that maps key index to effective row.

    Instead, we return a modified key function.
    """
    # We'll handle this differently in the main loop
    return offsets


def columnar_perm(col_order, width, length):
    """Generate columnar transposition permutation (gather convention).
    output[i] = input[perm[i]]
    """
    n_rows = (length + width - 1) // width
    n_long = length % width
    if n_long == 0:
        n_long = width
    sigma = [0] * length
    ct_pos = 0
    for col in col_order:
        col_len = n_rows if col < n_long else n_rows - 1
        for row in range(col_len):
            inter_pos = row * width + col
            if inter_pos < length:
                sigma[inter_pos] = ct_pos
                ct_pos += 1
    return sigma


def apply_transposition(text, perm):
    """Apply a transposition permutation (gather convention)."""
    return ''.join(text[perm[i]] for i in range(len(text)))


def invert_perm(perm):
    """Invert a permutation."""
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


def score_plaintext(pt):
    """Score a plaintext candidate using the canonical crib scoring."""
    detail = score_cribs_detailed(pt)
    return detail


def keyword_to_key(keyword, length):
    """Repeat keyword to cover the required length."""
    return (keyword * ((length // len(keyword)) + 1))[:length]


def running_key_to_ka_key(text, length):
    """Convert running key text to KA-indexed key characters."""
    # The running key text is in standard alphabet; we just use the letters
    key = text[:length]
    if len(key) < length:
        # Repeat if needed
        key = (text * ((length // len(text)) + 1))[:length]
    return key.upper()


def main():
    print("=" * 70)
    print("E-CHART-03: Misspelling-Modified Tableau Variants for K4")
    print("=" * 70)
    t0 = time.time()

    base_tableau = build_ka_tableau()

    # Verify base tableau
    print(f"  KA alphabet: {KA}")
    print(f"  Base tableau row 0: {''.join(base_tableau[0])}")
    print(f"  Base tableau row 1: {''.join(base_tableau[1])}")

    # ── Build all modified tableaux ──

    modified_tableaux = {}

    # 1. Row swaps
    modified_tableaux["row_swap_independent"] = apply_row_swaps_independent(base_tableau, MISSPELLINGS)
    modified_tableaux["row_swap_chained"] = apply_row_swaps_chained(base_tableau, MISSPELLINGS)

    # For chaining to matter, we need to handle E carefully:
    # Independent: swap(S,C), swap(L,Q), swap(O,U), swap(E,A), swap(I,E)
    # Chained: swap(S,C) first, then swap(L,Q), then swap(O,U), then swap(E,A),
    #   then swap(I,E) — but at this point E's row has already been swapped with A's row
    # Let's also test reverse order
    modified_tableaux["row_swap_chained_rev"] = apply_row_swaps_chained(
        base_tableau, list(reversed(MISSPELLINGS)))

    # 2. Column swaps
    modified_tableaux["col_swap_independent"] = apply_col_swaps_independent(base_tableau, MISSPELLINGS)
    modified_tableaux["col_swap_chained"] = apply_col_swaps_chained(base_tableau, MISSPELLINGS)
    modified_tableaux["col_swap_chained_rev"] = apply_col_swaps_chained(
        base_tableau, list(reversed(MISSPELLINGS)))

    # 3. Both row + column swaps
    modified_tableaux["both_swap_independent"] = apply_both_swaps(base_tableau, MISSPELLINGS, chained=False)
    modified_tableaux["both_swap_chained"] = apply_both_swaps(base_tableau, MISSPELLINGS, chained=True)
    modified_tableaux["both_swap_chained_rev"] = apply_both_swaps(
        base_tableau, list(reversed(MISSPELLINGS)), chained=True)

    # 4. Letter replacement
    modified_tableaux["letter_replacement"] = apply_letter_replacement(base_tableau)

    # 5. Also test the unmodified tableau as baseline
    modified_tableaux["unmodified_ka"] = deepcopy(base_tableau)

    # Additional swap variants: only the E-involved pairs (E->A, I->E)
    e_pairs = [('E', 'A'), ('I', 'E')]
    modified_tableaux["row_swap_E_only"] = apply_row_swaps_chained(base_tableau, e_pairs)
    modified_tableaux["col_swap_E_only"] = apply_col_swaps_chained(base_tableau, e_pairs)

    # Only consonant pairs (S->C, L->Q, O->U)
    consonant_pairs = [('S', 'C'), ('L', 'Q'), ('O', 'U')]
    modified_tableaux["row_swap_consonants"] = apply_row_swaps_chained(base_tableau, consonant_pairs)
    modified_tableaux["col_swap_consonants"] = apply_col_swaps_chained(base_tableau, consonant_pairs)

    print(f"\n  Modified tableaux generated: {len(modified_tableaux)}")

    # ── Test each modified tableau ──

    all_results = []
    configs_tested = 0

    variants = ["vigenere", "beaufort", "variant_beaufort"]

    for tab_name, tableau in modified_tableaux.items():
        # Check if tableau is bijective per row (needed for Vigenere decryption)
        bijective = all(len(set(row)) == 26 for row in tableau)

        for variant in variants:
            # Skip non-bijective tableau for Vigenere (ambiguous decryption)
            if not bijective and variant == "vigenere":
                continue

            # Test with keyword keys
            for kw in KEYWORDS:
                key = keyword_to_key(kw, N)
                pt = decrypt_with_tableau(CT, key, tableau, variant)

                if '?' in pt:
                    continue  # Skip failed decryptions

                configs_tested += 1
                detail = score_plaintext(pt)
                score = detail["score"]

                if score > 4:  # Log anything above trivial
                    all_results.append({
                        "tableau": tab_name,
                        "variant": variant,
                        "key_type": "keyword",
                        "key": kw,
                        "score": score,
                        "ene": detail["ene_score"],
                        "bc": detail["bc_score"],
                        "classification": detail["classification"],
                        "pt_snippet": pt[:40],
                    })

            # Test with running keys
            for rk_name, rk_text in RUNNING_KEYS.items():
                if len(rk_text) < N:
                    continue
                key = rk_text[:N]
                pt = decrypt_with_tableau(CT, key, tableau, variant)

                if '?' in pt:
                    continue

                configs_tested += 1
                detail = score_plaintext(pt)
                score = detail["score"]

                if score > 4:
                    all_results.append({
                        "tableau": tab_name,
                        "variant": variant,
                        "key_type": "running_key",
                        "key": rk_name,
                        "score": score,
                        "ene": detail["ene_score"],
                        "bc": detail["bc_score"],
                        "classification": detail["classification"],
                        "pt_snippet": pt[:40],
                    })

    print(f"  Phase 1 (direct keys): {configs_tested} configs tested ({time.time()-t0:.1f}s)")

    # ── Modification 5: Row offset cyclic ──
    # At position i, use row (key_row + MISSPELLING_OFFSETS[i % 5]) mod 26

    print(f"\n  Phase 2: Cyclic row offset model...")
    offset_configs = 0

    for variant in variants:
        for kw in KEYWORDS:
            key = keyword_to_key(kw, N)
            pt = []
            valid = True

            for i in range(N):
                key_c = key[i]
                ct_c = CT[i]
                offset = MISSPELLING_OFFSETS[i % 5]
                effective_row = (KA_IDX[key_c] + offset) % 26

                if variant == "vigenere":
                    row = base_tableau[effective_row]
                    try:
                        col = row.index(ct_c)
                    except ValueError:
                        valid = False
                        break
                    pt.append(KA[col])
                elif variant in ("beaufort", "variant_beaufort"):
                    key_col = KA_IDX[key_c]
                    found = False
                    for row_idx in range(26):
                        eff = (row_idx + offset) % 26
                        if base_tableau[eff][key_col] == ct_c:
                            pt.append(KA[row_idx])
                            found = True
                            break
                    if not found:
                        valid = False
                        break

            if not valid:
                continue

            pt_str = ''.join(pt)
            offset_configs += 1
            detail = score_plaintext(pt_str)
            score = detail["score"]

            if score > 4:
                all_results.append({
                    "tableau": "cyclic_row_offset",
                    "variant": variant,
                    "key_type": "keyword",
                    "key": kw,
                    "score": score,
                    "ene": detail["ene_score"],
                    "bc": detail["bc_score"],
                    "classification": detail["classification"],
                    "pt_snippet": pt_str[:40],
                })

        # Running keys with cyclic offset
        for rk_name, rk_text in RUNNING_KEYS.items():
            if len(rk_text) < N:
                continue
            key = rk_text[:N]
            pt = []
            valid = True

            for i in range(N):
                key_c = key[i]
                ct_c = CT[i]
                offset = MISSPELLING_OFFSETS[i % 5]
                effective_row = (KA_IDX[key_c] + offset) % 26

                if variant == "vigenere":
                    row = base_tableau[effective_row]
                    try:
                        col = row.index(ct_c)
                    except ValueError:
                        valid = False
                        break
                    pt.append(KA[col])
                elif variant in ("beaufort", "variant_beaufort"):
                    key_col = KA_IDX[key_c]
                    found = False
                    for row_idx in range(26):
                        eff = (row_idx + offset) % 26
                        if base_tableau[eff][key_col] == ct_c:
                            pt.append(KA[row_idx])
                            found = True
                            break
                    if not found:
                        valid = False
                        break

            if not valid:
                continue

            pt_str = ''.join(pt)
            offset_configs += 1
            detail = score_plaintext(pt_str)
            score = detail["score"]

            if score > 4:
                all_results.append({
                    "tableau": "cyclic_row_offset",
                    "variant": variant,
                    "key_type": "running_key",
                    "key": rk_name,
                    "score": score,
                    "ene": detail["ene_score"],
                    "bc": detail["bc_score"],
                    "classification": detail["classification"],
                    "pt_snippet": pt_str[:40],
                })

    configs_tested += offset_configs
    print(f"  Phase 2 (cyclic offset): {offset_configs} configs ({time.time()-t0:.1f}s)")

    # ── Phase 3: Also test standard alphabet tableau with same modifications ──

    print(f"\n  Phase 3: Standard alphabet tableau with misspelling mods...")

    ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

    def build_std_tableau():
        tableau = []
        for i in range(26):
            row = ALPH[i:] + ALPH[:i]
            tableau.append(list(row))
        return tableau

    std_tableau = build_std_tableau()
    std_idx = {c: i for i, c in enumerate(ALPH)}

    # Apply misspelling modifications to standard tableau
    std_modified = {}
    std_modified["std_row_swap"] = apply_row_swaps_independent(std_tableau,
        [(c, w) for c, w in MISSPELLINGS])
    std_modified["std_col_swap"] = apply_col_swaps_independent(std_tableau,
        [(c, w) for c, w in MISSPELLINGS])
    std_modified["std_both_swap"] = apply_both_swaps(std_tableau, MISSPELLINGS, chained=False)

    # For standard tableau, use standard ALPH_IDX for row/col lookup
    std_phase_configs = 0
    for tab_name, tableau in std_modified.items():
        for variant in variants:
            for kw in KEYWORDS:
                key = keyword_to_key(kw, N)
                pt = []
                valid = True
                for i in range(N):
                    ct_c = CT[i]
                    key_c = key[i]
                    if key_c not in std_idx:
                        valid = False
                        break

                    if variant == "vigenere":
                        row_idx = std_idx[key_c]
                        row = tableau[row_idx]
                        try:
                            col = row.index(ct_c)
                        except ValueError:
                            valid = False
                            break
                        pt.append(ALPH[col])
                    elif variant in ("beaufort", "variant_beaufort"):
                        key_col = std_idx[key_c]
                        found = False
                        for row_idx in range(26):
                            if tableau[row_idx][key_col] == ct_c:
                                pt.append(ALPH[row_idx])
                                found = True
                                break
                        if not found:
                            valid = False
                            break

                if not valid:
                    continue

                pt_str = ''.join(pt)
                std_phase_configs += 1
                detail = score_plaintext(pt_str)
                score = detail["score"]

                if score > 4:
                    all_results.append({
                        "tableau": tab_name,
                        "variant": variant,
                        "key_type": "keyword",
                        "key": kw,
                        "score": score,
                        "ene": detail["ene_score"],
                        "bc": detail["bc_score"],
                        "classification": detail["classification"],
                        "pt_snippet": pt_str[:40],
                    })

    configs_tested += std_phase_configs
    print(f"  Phase 3 (std tableau mods): {std_phase_configs} configs ({time.time()-t0:.1f}s)")

    # ── Phase 4: Width-8 columnar transposition on top configs ──

    # Sort all results, pick top 5 unique tableau+variant+key combos
    all_results.sort(key=lambda r: -r["score"])

    # Also include all configs that scored > 0 for transposition testing
    top_configs = []
    seen = set()
    for r in all_results:
        key_id = (r["tableau"], r["variant"], r["key_type"], r["key"])
        if key_id not in seen:
            seen.add(key_id)
            top_configs.append(r)
        if len(top_configs) >= 10:
            break

    # If we have fewer than 5 results, also add some 0-score configs
    if len(top_configs) < 5:
        # Add some from the main tableau modifications
        for tab_name in ["row_swap_independent", "col_swap_independent", "both_swap_independent",
                         "letter_replacement", "unmodified_ka"]:
            if tab_name in modified_tableaux:
                for kw in ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]:
                    key_id = (tab_name, "vigenere", "keyword", kw)
                    if key_id not in seen:
                        seen.add(key_id)
                        top_configs.append({
                            "tableau": tab_name,
                            "variant": "vigenere",
                            "key_type": "keyword",
                            "key": kw,
                            "score": 0,
                        })
                    if len(top_configs) >= 10:
                        break
            if len(top_configs) >= 10:
                break

    print(f"\n  Phase 4: Width-8 columnar transposition on top {len(top_configs)} configs...")
    trans_configs = 0
    trans_results = []

    width = 8
    n_perms = 1
    for i in range(1, width + 1):
        n_perms *= i
    print(f"  Testing {n_perms} orderings per config (width={width})")

    for cfg in top_configs:
        tab_name = cfg["tableau"]
        variant = cfg["variant"]
        key_type = cfg["key_type"]
        key_val = cfg["key"]

        # Get the appropriate tableau
        if tab_name in modified_tableaux:
            tableau = modified_tableaux[tab_name]
            idx_map = KA_IDX
            alpha = KA
        elif tab_name in std_modified:
            tableau = std_modified[tab_name]
            idx_map = std_idx
            alpha = ALPH
        elif tab_name == "cyclic_row_offset":
            # Handle cyclic offset separately below
            continue
        else:
            continue

        # Build the key string
        if key_type == "keyword":
            key = keyword_to_key(key_val, N)
        else:
            rk_text = RUNNING_KEYS.get(key_val, "")
            if len(rk_text) < N:
                continue
            key = rk_text[:N]

        # First decrypt without transposition to get intermediate text
        # Then apply transposition BEFORE decryption:
        # The model is: encrypt = substitute then transpose
        # So decrypt = un-transpose then un-substitute
        # CT_untransposed[i] = CT[perm[i]]

        for order_tuple in permutations(range(width)):
            order = list(order_tuple)
            perm = columnar_perm(order, width, N)

            # Un-transpose: CT_untrans[i] = CT[perm[i]]
            ct_untrans = ''.join(CT[perm[i]] for i in range(N))

            # Decrypt through tableau
            pt = decrypt_with_tableau(ct_untrans, key, tableau, variant)

            if '?' in pt:
                continue

            trans_configs += 1
            detail = score_plaintext(pt)
            score = detail["score"]

            if score > 6:  # Only log above noise floor
                trans_results.append({
                    "tableau": tab_name,
                    "variant": variant,
                    "key_type": key_type,
                    "key": key_val,
                    "width": width,
                    "col_order": order,
                    "score": score,
                    "ene": detail["ene_score"],
                    "bc": detail["bc_score"],
                    "classification": detail["classification"],
                    "pt_snippet": pt[:40],
                })

        if trans_configs % 100000 == 0 and trans_configs > 0:
            print(f"    ... {trans_configs:,} transposition configs tested ({time.time()-t0:.1f}s)",
                  flush=True)

    configs_tested += trans_configs
    print(f"  Phase 4 (transposition): {trans_configs:,} configs ({time.time()-t0:.1f}s)")

    # ── Combine all results ──

    all_results.extend(trans_results)
    all_results.sort(key=lambda r: -r["score"])

    # ── Summary ──

    elapsed = time.time() - t0
    best_score = all_results[0]["score"] if all_results else 0

    print(f"\n{'='*70}")
    print(f"RESULTS SUMMARY")
    print(f"{'='*70}")
    print(f"  Total configs tested: {configs_tested:,}")
    print(f"  Results above threshold: {len(all_results)}")
    print(f"  Best score: {best_score}/24")
    print(f"  Elapsed: {elapsed:.1f}s")

    if all_results:
        print(f"\n  TOP 20 RESULTS:")
        for i, r in enumerate(all_results[:20]):
            trans_info = f" w={r.get('width','-')} order={r.get('col_order','-')}" if 'width' in r else ""
            print(f"  {i+1:3d}. score={r['score']:2d}/24 ENE={r['ene']:2d} BC={r['bc']:2d}"
                  f" [{r['classification']:12s}] {r['tableau']:25s} {r['variant']:18s}"
                  f" {r['key_type']:11s} key={r['key']}{trans_info}")
            print(f"       PT: {r['pt_snippet']}")

    # Score distribution
    score_dist = {}
    for r in all_results:
        s = r["score"]
        score_dist[s] = score_dist.get(s, 0) + 1
    if score_dist:
        print(f"\n  SCORE DISTRIBUTION:")
        for s in sorted(score_dist.keys(), reverse=True):
            print(f"    score {s:2d}: {score_dist[s]:5d} configs")

    # Verdict
    if best_score >= 18:
        verdict = "SIGNAL"
    elif best_score >= 10:
        verdict = "INTERESTING"
    else:
        verdict = "NOISE"

    print(f"\n  VERDICT: {verdict}")

    # Check if any transposition results are significant
    # Only meaningful at period <= 7, but width-8 columnar is period 8
    # which is at the edge of meaningful discrimination
    if trans_results:
        best_trans = max(trans_results, key=lambda r: r["score"])
        print(f"\n  Best transposition score: {best_trans['score']}/24"
              f" (width-8 columnar, at edge of meaningful discrimination)")
        if best_trans["score"] >= 10:
            print(f"  WARNING: Width-8 scores may have elevated false positive rate")

    # ── Save results ──

    os.makedirs("results", exist_ok=True)
    output = {
        "experiment": "E-CHART-03",
        "description": "Misspelling-modified tableau variants for K4",
        "misspellings": [f"{c}->{w}" for c, w in MISSPELLINGS],
        "misspelling_offsets": MISSPELLING_OFFSETS,
        "tableaux_tested": list(modified_tableaux.keys()) + list(std_modified.keys()) + ["cyclic_row_offset"],
        "keywords_tested": KEYWORDS,
        "running_keys_tested": list(RUNNING_KEYS.keys()),
        "variants_tested": variants,
        "total_configs": configs_tested,
        "best_score": best_score,
        "verdict": verdict,
        "elapsed_seconds": round(elapsed, 1),
        "top_50": all_results[:50],
        "score_distribution": score_dist,
        "transposition_results_count": len(trans_results),
    }

    with open("results/e_chart_03_misspelling.json", "w") as f:
        json.dump(output, f, indent=2)

    print(f"\n  Artifact: results/e_chart_03_misspelling.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_chart_03_misspelling_tableau.py")


if __name__ == "__main__":
    main()
