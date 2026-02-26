#!/usr/bin/env python3
"""E-BESPOKE-01: Test ciphertext modifications derived from Kryptos misspellings.

Theory: The deliberate misspellings on the Kryptos sculpture may be instructions
for modifying the K4 ciphertext before standard decryption.

Misspelling rules tested:
  IQLUSION:   Q -> L  (positions 25, 26, 38, 41 in K4 CT)
  DIGETAL:    I -> E  (positions 16, 56, 59, 84 in K4 CT)
  DESPARATLY: E -> A  (positions 44, 92 in K4 CT)

Also tests: modified alphabet / reduced tableau hypothesis.
"""
from __future__ import annotations

import math
from collections import Counter
from itertools import product
from typing import Dict, List, Optional, Tuple

from kryptos.kernel.constants import (
    ALPH,
    ALPH_IDX,
    CT,
    CT_LEN,
    CRIB_DICT,
    CRIB_WORDS,
    MOD,
    VIGENERE_KEY_ENE,
    VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE,
    BEAUFORT_KEY_BC,
)

# ── Helpers ──────────────────────────────────────────────────────────────────

def char_to_num(c: str) -> int:
    return ord(c) - 65

def num_to_char(n: int) -> str:
    return chr((n % 26) + 65)

def vig_key(c: int, p: int) -> int:
    """Vigenere key recovery: K = (C - P) mod 26."""
    return (c - p) % MOD

def beau_key(c: int, p: int) -> int:
    """Beaufort key recovery: K = (C + P) mod 26."""
    return (c + p) % MOD

def varbeau_key(c: int, p: int) -> int:
    """Variant Beaufort key recovery: K = (P - C) mod 26."""
    return (p - c) % MOD

def vig_decrypt(c: int, k: int) -> int:
    return (c - k) % MOD

def beau_decrypt(c: int, k: int) -> int:
    return (k - c) % MOD

def varbeau_decrypt(c: int, k: int) -> int:
    return (c + k) % MOD


def compute_keystream(ct_str: str, crib_dict: Dict[int, str], key_fn) -> Dict[int, int]:
    """Recover keystream values at crib positions given a key recovery function."""
    result = {}
    for pos, pt_ch in sorted(crib_dict.items()):
        if pos < len(ct_str):
            c = char_to_num(ct_str[pos])
            p = char_to_num(pt_ch)
            result[pos] = key_fn(c, p)
    return result


def keystream_to_letters(ks: Dict[int, int]) -> str:
    """Convert keystream dict to letter string (sorted by position)."""
    return "".join(num_to_char(ks[pos]) for pos in sorted(ks.keys()))


def check_periodicity(ks: Dict[int, int], max_period: int = 30) -> List[Tuple[int, int, float]]:
    """Check autocorrelation of keystream at crib positions.
    Returns list of (period, matches, fraction) for periods with any matches."""
    positions = sorted(ks.keys())
    results = []
    for period in range(1, max_period + 1):
        matches = 0
        comparisons = 0
        for i, p1 in enumerate(positions):
            for p2 in positions[i+1:]:
                if (p2 - p1) % period == 0:
                    comparisons += 1
                    if ks[p1] == ks[p2]:
                        matches += 1
        if comparisons > 0:
            frac = matches / comparisons
            if matches > 0:
                results.append((period, matches, frac))
    return results


def entropy_bits(ks_values: List[int]) -> float:
    """Shannon entropy of keystream values in bits."""
    n = len(ks_values)
    if n == 0:
        return 0.0
    counts = Counter(ks_values)
    h = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            h -= p * math.log2(p)
    return h


def find_fragments(letters: str) -> List[str]:
    """Look for common English fragments (2+ chars) in a letter string."""
    # Common bigrams and trigrams to look for
    common = [
        "TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND",
        "TI", "ES", "OR", "TE", "OF", "ED", "IS", "IT", "AL", "AR",
        "ST", "TO", "NT", "NG", "SE", "HA", "AS", "OU", "IO", "LE",
        "THE", "AND", "ING", "ENT", "ION", "TIO", "FOR", "HER", "ATE",
        "HIS", "HAS", "NOT", "ARE", "WAS", "ALL", "BUT", "OUT", "ONE",
        "KEY", "PAD", "SPY", "CIA", "NSA", "WAR", "RUN", "CODE",
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK", "EAST",
    ]
    found = []
    upper = letters.upper()
    for frag in common:
        if frag in upper:
            found.append(frag)
    return found


def apply_modification(ct_str: str, rule_name: str, rules: Dict[str, str]) -> str:
    """Apply a set of character replacement rules to ciphertext.
    rules: dict mapping from_char -> to_char, applied simultaneously."""
    result = []
    for ch in ct_str:
        result.append(rules.get(ch, ch))
    return "".join(result)


def diff_positions(original: str, modified: str) -> List[Tuple[int, str, str]]:
    """Return positions where two strings differ."""
    diffs = []
    for i, (a, b) in enumerate(zip(original, modified)):
        if a != b:
            diffs.append((i, a, b))
    return diffs


# ── Modification definitions ──────────────────────────────────────────────

MODIFICATIONS = {
    "ORIGINAL": {},
    "IQLUSION (Q->L)": {"Q": "L"},
    "DIGETAL (I->E)": {"I": "E"},
    "DESPARATLY (E->A)": {"E": "A"},
    "Q->L + I->E": {"Q": "L", "I": "E"},
    "Q->L + E->A": {"Q": "L", "E": "A"},
    "I->E + E->A": {"I": "E", "E": "A"},  # simultaneous: I->E and E->A independently
    "Q->L + I->E + E->A (simultaneous)": {"Q": "L", "I": "E", "E": "A"},
}

# Sequential application: I->E first, then E->A (new E's from I also become A)
SEQUENTIAL_MODS = {
    "I->E then E->A (sequential)": [{"I": "E"}, {"E": "A"}],
    "Q->L + I->E then E->A (sequential)": [{"Q": "L", "I": "E"}, {"E": "A"}],
}

# Reverse direction: what if the misspellings encode the REVERSE transformation?
REVERSE_MODIFICATIONS = {
    "REVERSE: L->Q": {"L": "Q"},
    "REVERSE: E->I": {"E": "I"},
    "REVERSE: A->E": {"A": "E"},
    "REVERSE: L->Q + E->I": {"L": "Q", "E": "I"},
    "REVERSE: L->Q + A->E": {"L": "Q", "A": "E"},
    "REVERSE: L->Q + E->I + A->E (simultaneous)": {"L": "Q", "E": "I", "A": "E"},
}

KEY_RECOVERY_FNS = {
    "Vigenere": vig_key,
    "Beaufort": beau_key,
    "Variant Beaufort": varbeau_key,
}


def analyze_variant(name: str, ct_mod: str) -> None:
    """Run full analysis on a modified ciphertext variant."""
    diffs = diff_positions(CT, ct_mod)

    print(f"\n{'='*78}")
    print(f"  {name}")
    print(f"{'='*78}")
    print(f"  Modified CT: {ct_mod}")

    if diffs:
        print(f"  Changes ({len(diffs)}):")
        for pos, orig, new in diffs:
            crib_note = f" [CRIB: PT={CRIB_DICT[pos]}]" if pos in CRIB_DICT else ""
            print(f"    pos {pos:2d}: {orig}->{new}{crib_note}")
    else:
        print("  (No changes)")

    # Check if modifications hit crib positions
    crib_hits = [(pos, orig, new) for pos, orig, new in diffs if pos in CRIB_DICT]
    if crib_hits:
        print(f"\n  ** WARNING: {len(crib_hits)} modification(s) hit crib positions! **")
        for pos, orig, new in crib_hits:
            print(f"     pos {pos}: CT {orig}->{new}, PT={CRIB_DICT[pos]}")

    for variant_name, key_fn in KEY_RECOVERY_FNS.items():
        ks = compute_keystream(ct_mod, CRIB_DICT, key_fn)
        ks_letters = keystream_to_letters(ks)
        ks_values = [ks[p] for p in sorted(ks.keys())]

        # Split into ENE and BC segments
        ene_keys = [ks[p] for p in range(21, 34)]
        bc_keys = [ks[p] for p in range(63, 74)]
        ene_letters = "".join(num_to_char(k) for k in ene_keys)
        bc_letters = "".join(num_to_char(k) for k in bc_keys)

        ent = entropy_bits(ks_values)
        ene_ent = entropy_bits(ene_keys)
        bc_ent = entropy_bits(bc_keys)

        fragments = find_fragments(ks_letters)
        ene_fragments = find_fragments(ene_letters)
        bc_fragments = find_fragments(bc_letters)

        print(f"\n  --- {variant_name} ---")
        print(f"  ENE keystream (pos 21-33): {ene_letters}  nums={ene_keys}")
        print(f"  BC  keystream (pos 63-73): {bc_letters}  nums={bc_keys}")
        print(f"  Full keystream letters:    {ks_letters}")
        print(f"  Entropy: full={ent:.2f} bits, ENE={ene_ent:.2f}, BC={bc_ent:.2f}")

        # Check for repeated values
        ene_counter = Counter(ene_keys)
        bc_counter = Counter(bc_keys)
        ene_repeats = {num_to_char(k): v for k, v in ene_counter.items() if v > 1}
        bc_repeats = {num_to_char(k): v for k, v in bc_counter.items() if v > 1}
        if ene_repeats:
            print(f"  ENE repeated values: {ene_repeats}")
        if bc_repeats:
            print(f"  BC  repeated values: {bc_repeats}")

        # Check for arithmetic progressions in keystream
        for start_idx in range(len(ene_keys) - 2):
            d = ene_keys[start_idx + 1] - ene_keys[start_idx]
            run = 2
            for j in range(start_idx + 2, len(ene_keys)):
                if ene_keys[j] - ene_keys[j-1] == d:
                    run += 1
                else:
                    break
            if run >= 3:
                print(f"  ENE arithmetic run at index {start_idx}: length {run}, diff={d}")

        for start_idx in range(len(bc_keys) - 2):
            d = bc_keys[start_idx + 1] - bc_keys[start_idx]
            run = 2
            for j in range(start_idx + 2, len(bc_keys)):
                if bc_keys[j] - bc_keys[j-1] == d:
                    run += 1
                else:
                    break
            if run >= 3:
                print(f"  BC  arithmetic run at index {start_idx}: length {run}, diff={d}")

        all_frags = fragments + ene_fragments + bc_fragments
        if all_frags:
            print(f"  Fragments found: {sorted(set(all_frags))}")

        # Periodicity check
        periods = check_periodicity(ks, max_period=26)
        best_periods = sorted(periods, key=lambda x: -x[2])[:5]
        if best_periods:
            print(f"  Top periodicities:")
            for per, matches, frac in best_periods:
                print(f"    period={per:2d}: {matches} matches ({frac:.3f})")

        # Check Bean equality: k[27] == k[65]?
        if 27 in ks and 65 in ks:
            bean_eq = ks[27] == ks[65]
            print(f"  Bean EQ k[27]={ks[27]}({num_to_char(ks[27])}) vs k[65]={ks[65]}({num_to_char(ks[65])}): {'PASS' if bean_eq else 'FAIL'}")


def analyze_modified_alphabet():
    """Test the hypothesis that misspellings define a modified alphabet/tableau.

    If Q->L, I->E, E->A are letter merges:
      - Q maps to L (Q is "same as" L)
      - I maps to E (I is "same as" E)
      - E maps to A (E is "same as" A)

    This creates equivalence classes, effectively reducing the alphabet.
    """
    print(f"\n{'='*78}")
    print(f"  MODIFIED ALPHABET / REDUCED TABLEAU ANALYSIS")
    print(f"{'='*78}")

    # Define the merge map
    merges = {"Q": "L", "I": "E", "E": "A"}

    # Build transitive closure: I->E->A means I also maps to A
    def resolve(ch, merge_map, depth=0):
        if depth > 26:
            return ch  # prevent infinite loops
        if ch in merge_map:
            return resolve(merge_map[ch], merge_map, depth + 1)
        return ch

    # Build full resolved mapping
    full_map = {}
    for c in ALPH:
        resolved = resolve(c, merges)
        full_map[c] = resolved

    print(f"\n  Merge rules: {merges}")
    print(f"  Transitive closure:")
    changed = {c: r for c, r in full_map.items() if c != r}
    for c, r in sorted(changed.items()):
        print(f"    {c} -> {r}")

    # What letters remain in the reduced alphabet?
    remaining = sorted(set(full_map.values()))
    print(f"\n  Reduced alphabet ({len(remaining)} letters): {''.join(remaining)}")
    eliminated = sorted(set(ALPH) - set(remaining))
    print(f"  Eliminated letters: {''.join(eliminated)}")

    # Apply to CT
    ct_mapped = "".join(full_map[c] for c in CT)
    print(f"\n  Original CT:  {CT}")
    print(f"  Mapped CT:    {ct_mapped}")
    diffs = diff_positions(CT, ct_mapped)
    print(f"  Changes: {len(diffs)} positions")

    # Compute keystream under mapped CT
    for variant_name, key_fn in KEY_RECOVERY_FNS.items():
        ks = compute_keystream(ct_mapped, CRIB_DICT, key_fn)
        ks_letters = keystream_to_letters(ks)
        ene_keys = [ks[p] for p in range(21, 34)]
        bc_keys = [ks[p] for p in range(63, 74)]
        ene_letters = "".join(num_to_char(k) for k in ene_keys)
        bc_letters = "".join(num_to_char(k) for k in bc_keys)
        print(f"\n  --- {variant_name} (mapped CT) ---")
        print(f"  ENE keys: {ene_letters}  {ene_keys}")
        print(f"  BC  keys: {bc_letters}  {bc_keys}")

        fragments = find_fragments(ene_letters) + find_fragments(bc_letters)
        if fragments:
            print(f"  Fragments: {sorted(set(fragments))}")

    # Also test: what if the reduced alphabet defines a custom Vigenere tableau?
    # In a 23-letter tableau, positions shift. Test if key becomes periodic.
    print(f"\n  --- Reduced alphabet Vigenere (23-letter mod) ---")
    remaining_idx = {c: i for i, c in enumerate(remaining)}
    mod_r = len(remaining)

    # Map CT and PT to reduced alphabet indices
    for variant_name in ["Reduced-Vig", "Reduced-Beau"]:
        ks_reduced = {}
        valid = True
        for pos, pt_ch in sorted(CRIB_DICT.items()):
            ct_ch = ct_mapped[pos]  # already mapped
            pt_mapped = full_map.get(pt_ch, pt_ch)
            if ct_ch in remaining_idx and pt_mapped in remaining_idx:
                c_idx = remaining_idx[ct_ch]
                p_idx = remaining_idx[pt_mapped]
                if variant_name == "Reduced-Vig":
                    k = (c_idx - p_idx) % mod_r
                else:
                    k = (c_idx + p_idx) % mod_r
                ks_reduced[pos] = k
            else:
                valid = False
                break

        if valid:
            ks_vals = [ks_reduced[p] for p in sorted(ks_reduced.keys())]
            ks_chars = "".join(remaining[k] if k < len(remaining) else "?" for k in ks_vals)
            ene_vals = [ks_reduced[p] for p in range(21, 34)]
            bc_vals = [ks_reduced[p] for p in range(63, 74)]
            print(f"  {variant_name} (mod {mod_r}):")
            print(f"    ENE keys: {ene_vals}")
            print(f"    BC  keys: {bc_vals}")
            print(f"    Letters:  {ks_chars}")

            # Check periodicity
            periods = check_periodicity(ks_reduced, max_period=26)
            best = sorted(periods, key=lambda x: -x[2])[:3]
            if best:
                print(f"    Top periodicities: {best}")
        else:
            print(f"  {variant_name}: mapping failed (letter not in reduced alphabet)")

    # Test KRYPTOS alphabet version: apply merges within KRYPTOS ordering
    print(f"\n  --- KRYPTOS alphabet with merges ---")
    from kryptos.kernel.constants import KRYPTOS_ALPHABET
    ka_map = {}
    for c in KRYPTOS_ALPHABET:
        ka_map[c] = full_map.get(c, c)
    ka_mapped_ct = "".join(ka_map[c] for c in CT)
    ka_remaining = sorted(set(ka_map.values()))
    print(f"  KA reduced alphabet ({len(ka_remaining)} letters): {''.join(ka_remaining)}")

    for variant_name, key_fn in [("Vig", vig_key), ("Beau", beau_key)]:
        ks = compute_keystream(ka_mapped_ct, CRIB_DICT, key_fn)
        ks_letters = keystream_to_letters(ks)
        print(f"  KA-{variant_name} keystream: {ks_letters}")


def analyze_position_specific_rules():
    """Test: what if the misspelling positions on K4 CT indicate which positions
    to swap/modify, and the misspelling letter tells you what to change TO?

    i.e., the misspellings are position markers within K4 itself."""

    print(f"\n{'='*78}")
    print(f"  POSITION-SPECIFIC ANALYSIS")
    print(f"{'='*78}")

    # Find all Q, I, E positions in original CT
    q_pos = [i for i, c in enumerate(CT) if c == "Q"]
    i_pos = [i for i, c in enumerate(CT) if c == "I"]
    e_pos = [i for i, c in enumerate(CT) if c == "E"]

    print(f"  Q positions in CT: {q_pos}")
    print(f"  I positions in CT: {i_pos}")
    print(f"  E positions in CT: {e_pos}")

    # What are the position numbers mod 26 (as letters)?
    print(f"\n  Position numbers as letters (mod 26):")
    print(f"    Q positions: {[num_to_char(p % 26) for p in q_pos]} = {[p % 26 for p in q_pos]}")
    print(f"    I positions: {[num_to_char(p % 26) for p in i_pos]} = {[p % 26 for p in i_pos]}")
    print(f"    E positions: {[num_to_char(p % 26) for p in e_pos]} = {[p % 26 for p in e_pos]}")

    # Look at spacing between same-letter positions
    print(f"\n  Spacings:")
    for name, positions in [("Q", q_pos), ("I", i_pos), ("E", e_pos)]:
        if len(positions) > 1:
            spacings = [positions[i+1] - positions[i] for i in range(len(positions) - 1)]
            print(f"    {name}: positions={positions}, spacings={spacings}")

    # What if Q positions mark key-repeat boundaries?
    print(f"\n  Q positions as key boundaries: segments of length {[q_pos[i+1]-q_pos[i] for i in range(len(q_pos)-1)]}")

    # What if the number of each letter is significant?
    print(f"\n  Letter counts: Q={len(q_pos)}, I={len(i_pos)}, E={len(e_pos)}")
    print(f"  Total modified positions: {len(q_pos) + len(i_pos) + len(e_pos)}")


def analyze_selective_decrypt():
    """What if only the MODIFIED positions use a different cipher variant?
    e.g., Q positions use Beaufort while everything else uses Vigenere."""

    print(f"\n{'='*78}")
    print(f"  SELECTIVE VARIANT ANALYSIS (mixed cipher at modified positions)")
    print(f"{'='*78}")

    q_pos_set = {i for i, c in enumerate(CT) if c == "Q"}
    i_pos_set = {i for i, c in enumerate(CT) if c == "I"}
    e_pos_set = {i for i, c in enumerate(CT) if c == "E"}

    # For each crib position, determine which variant to use
    for mod_set, mod_name in [(q_pos_set, "Q"), (i_pos_set, "I"), (e_pos_set, "E"),
                               (q_pos_set | i_pos_set | e_pos_set, "Q+I+E")]:
        for primary, alt in [("Vig", "Beau"), ("Beau", "Vig"), ("Vig", "VarBeau")]:
            primary_fn = {"Vig": vig_key, "Beau": beau_key, "VarBeau": varbeau_key}[primary]
            alt_fn = {"Vig": vig_key, "Beau": beau_key, "VarBeau": varbeau_key}[alt]

            ks = {}
            for pos, pt_ch in sorted(CRIB_DICT.items()):
                c = char_to_num(CT[pos])
                p = char_to_num(pt_ch)
                if pos in mod_set:
                    ks[pos] = alt_fn(c, p)
                else:
                    ks[pos] = primary_fn(c, p)

            ks_letters = keystream_to_letters(ks)
            ene_letters = "".join(num_to_char(ks[p]) for p in range(21, 34))
            bc_letters = "".join(num_to_char(ks[p]) for p in range(63, 74))

            # Only report if we find fragments or notable patterns
            fragments = find_fragments(ks_letters)
            ene_ent = entropy_bits([ks[p] for p in range(21, 34)])
            bc_ent = entropy_bits([ks[p] for p in range(63, 74)])

            # Report if entropy is notably low or fragments found
            if fragments or ene_ent < 3.0 or bc_ent < 2.5:
                print(f"\n  {mod_name} positions use {alt}, rest use {primary}:")
                print(f"    ENE: {ene_letters}  BC: {bc_letters}")
                print(f"    Entropy: ENE={ene_ent:.2f}, BC={bc_ent:.2f}")
                if fragments:
                    print(f"    Fragments: {fragments}")

    # Also check: no hits case
    print(f"\n  (Only variants with low entropy or fragments shown above)")


def analyze_null_hypothesis():
    """Compute expected number of fragments and entropy for random 24-char keystreams."""
    import random
    random.seed(42)

    print(f"\n{'='*78}")
    print(f"  NULL HYPOTHESIS: Random keystream baseline")
    print(f"{'='*78}")

    n_trials = 10000
    frag_counts = []
    entropies = []

    for _ in range(n_trials):
        ks = [random.randint(0, 25) for _ in range(24)]
        letters = "".join(num_to_char(k) for k in ks)
        frags = find_fragments(letters)
        frag_counts.append(len(frags))
        entropies.append(entropy_bits(ks))

    avg_frags = sum(frag_counts) / n_trials
    avg_ent = sum(entropies) / n_trials
    pct_with_frags = sum(1 for f in frag_counts if f > 0) / n_trials * 100

    print(f"  {n_trials} random 24-char keystreams:")
    print(f"    Avg fragments found: {avg_frags:.2f}")
    print(f"    % with any fragment: {pct_with_frags:.1f}%")
    print(f"    Avg entropy: {avg_ent:.2f} bits")
    print(f"    Min entropy seen: {min(entropies):.2f} bits")


def main():
    print("=" * 78)
    print("  E-BESPOKE-01: Misspelling-derived CT modifications")
    print("=" * 78)
    print(f"  Original CT: {CT}")
    print(f"  CT length: {CT_LEN}")
    print(f"  Cribs: {CRIB_WORDS}")

    # Verify position data
    print(f"\n  Verification of affected positions:")
    for ch in "QIE":
        positions = [i for i, c in enumerate(CT) if c == ch]
        print(f"    '{ch}' at positions: {positions} (count: {len(positions)})")

    # ── Phase 1: Direct character replacements (simultaneous) ──
    print(f"\n{'#'*78}")
    print(f"  PHASE 1: SIMULTANEOUS CHARACTER REPLACEMENTS")
    print(f"{'#'*78}")

    for name, rules in MODIFICATIONS.items():
        ct_mod = apply_modification(CT, name, rules)
        analyze_variant(name, ct_mod)

    # ── Phase 2: Sequential replacements ──
    print(f"\n{'#'*78}")
    print(f"  PHASE 2: SEQUENTIAL CHARACTER REPLACEMENTS")
    print(f"{'#'*78}")

    for name, rule_list in SEQUENTIAL_MODS.items():
        ct_mod = CT
        for rules in rule_list:
            ct_mod = apply_modification(ct_mod, name, rules)
        analyze_variant(name, ct_mod)

    # ── Phase 3: Reverse direction replacements ──
    print(f"\n{'#'*78}")
    print(f"  PHASE 3: REVERSE DIRECTION REPLACEMENTS")
    print(f"{'#'*78}")

    for name, rules in REVERSE_MODIFICATIONS.items():
        ct_mod = apply_modification(CT, name, rules)
        analyze_variant(name, ct_mod)

    # ── Phase 4: Modified alphabet / reduced tableau ──
    print(f"\n{'#'*78}")
    print(f"  PHASE 4: MODIFIED ALPHABET / REDUCED TABLEAU")
    print(f"{'#'*78}")

    analyze_modified_alphabet()

    # ── Phase 5: Position-specific analysis ──
    print(f"\n{'#'*78}")
    print(f"  PHASE 5: POSITION-SPECIFIC ANALYSIS")
    print(f"{'#'*78}")

    analyze_position_specific_rules()

    # ── Phase 6: Mixed cipher variant at modified positions ──
    print(f"\n{'#'*78}")
    print(f"  PHASE 6: SELECTIVE VARIANT (mixed cipher)")
    print(f"{'#'*78}")

    analyze_selective_decrypt()

    # ── Phase 7: Null hypothesis baseline ──
    print(f"\n{'#'*78}")
    print(f"  PHASE 7: NULL HYPOTHESIS BASELINE")
    print(f"{'#'*78}")

    analyze_null_hypothesis()

    # ── Summary ──
    print(f"\n{'#'*78}")
    print(f"  SUMMARY")
    print(f"{'#'*78}")

    # Collect all variants and their best metrics
    print(f"\n  Comparing keystream entropy across all modifications (lower = more structured):")
    print(f"  {'Variant':<45s} {'Cipher':<12s} {'ENE ent':>8s} {'BC ent':>8s} {'Full ent':>8s} {'Bean EQ':>8s}")
    print(f"  {'-'*93}")

    all_variants = list(MODIFICATIONS.items()) + [(n, None) for n in SEQUENTIAL_MODS]

    for name, rules in MODIFICATIONS.items():
        if rules is not None:
            ct_mod = apply_modification(CT, name, rules)
        else:
            ct_mod = CT
        for vname, key_fn in KEY_RECOVERY_FNS.items():
            ks = compute_keystream(ct_mod, CRIB_DICT, key_fn)
            ene_keys = [ks[p] for p in range(21, 34)]
            bc_keys = [ks[p] for p in range(63, 74)]
            all_keys = [ks[p] for p in sorted(ks.keys())]
            ene_ent = entropy_bits(ene_keys)
            bc_ent = entropy_bits(bc_keys)
            full_ent = entropy_bits(all_keys)
            bean = "PASS" if ks.get(27) == ks.get(65) else "FAIL"
            print(f"  {name:<45s} {vname:<12s} {ene_ent:>8.2f} {bc_ent:>8.2f} {full_ent:>8.2f} {bean:>8s}")

    for name, rule_list in SEQUENTIAL_MODS.items():
        ct_mod = CT
        for rules in rule_list:
            ct_mod = apply_modification(ct_mod, name, rules)
        for vname, key_fn in KEY_RECOVERY_FNS.items():
            ks = compute_keystream(ct_mod, CRIB_DICT, key_fn)
            ene_keys = [ks[p] for p in range(21, 34)]
            bc_keys = [ks[p] for p in range(63, 74)]
            all_keys = [ks[p] for p in sorted(ks.keys())]
            ene_ent = entropy_bits(ene_keys)
            bc_ent = entropy_bits(bc_keys)
            full_ent = entropy_bits(all_keys)
            bean = "PASS" if ks.get(27) == ks.get(65) else "FAIL"
            print(f"  {name:<45s} {vname:<12s} {ene_ent:>8.2f} {bc_ent:>8.2f} {full_ent:>8.2f} {bean:>8s}")

    for name, rules in REVERSE_MODIFICATIONS.items():
        ct_mod = apply_modification(CT, name, rules)
        for vname, key_fn in KEY_RECOVERY_FNS.items():
            ks = compute_keystream(ct_mod, CRIB_DICT, key_fn)
            ene_keys = [ks[p] for p in range(21, 34)]
            bc_keys = [ks[p] for p in range(63, 74)]
            all_keys = [ks[p] for p in sorted(ks.keys())]
            ene_ent = entropy_bits(ene_keys)
            bc_ent = entropy_bits(bc_keys)
            full_ent = entropy_bits(all_keys)
            bean = "PASS" if ks.get(27) == ks.get(65) else "FAIL"
            print(f"  {name:<45s} {vname:<12s} {ene_ent:>8.2f} {bc_ent:>8.2f} {full_ent:>8.2f} {bean:>8s}")

    print(f"\n  Random 24-char baseline entropy: ~4.2 bits")
    print(f"\n  Done.")


if __name__ == "__main__":
    main()
