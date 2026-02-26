#!/usr/bin/env python3
"""E-AUDIT-03: Weltzeituhr-Driven Finite-State Cipher.

[HYPOTHESIS] The Weltzeituhr (World Clock at Alexanderplatz, Berlin) is a
hand-operated state machine:
- 24 cities on its ring → 24 keyed substitution alphabets
- Start pointer at BERLIN
- Encipher each plaintext letter using the current city's alphabet
- Advance pointer by a deterministic rule (previous CT/PT letter, fixed offset,
  or city distance)
- WITHOUT-REPLACEMENT scheduling: each city/alphabet is consumed once before
  reset, creating non-periodic, anti-clustered output

Historical anchor: Sanborn confirmed BERLINCLOCK = Weltzeituhr (2025).
"Who says it is even a math solution?" (Sanborn, Nov 2025)

This is hand-executable, non-periodic, and not equivalent to standard periodic
Vigenere, autokey, or progressive-key models because the state evolution is
constrained by without-replacement scheduling.

Uses position-FREE crib scoring.
"""
import json
import os
import sys
import time
from collections import Counter
from itertools import permutations, product
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from kryptos.kernel.constants import CT, CT_LEN, ALPH, MOD
from kryptos.kernel.scoring.free_crib import score_free, score_free_fast, CRIB_ENE, CRIB_BC
from kryptos.kernel.scoring.ic import ic


# ── Weltzeituhr city data ────────────────────────────────────────────────

# The 24 cities on the Weltzeituhr, in order around the ring.
# UTC offsets as of 1989 (pre-EU timezone standardization).
# The ring reads clockwise from 12 o'clock.
WELTZEITUHR_CITIES = [
    ("ACCRA", 0),
    ("ALGIERS", 1),
    ("CAIRO", 2),
    ("MOSCOW", 3),
    ("TASHKENT", 5),
    ("DACCA", 6),        # now Dhaka
    ("BANGKOK", 7),
    ("HONGKONG", 8),     # now one word
    ("TOKYO", 9),
    ("SYDNEY", 10),
    ("NOUMEA", 11),
    ("WELLINGTON", 12),
    ("SAMOA", -11),      # west of date line
    ("ANCHORAGE", -9),
    ("VANCOUVER", -8),
    ("DENVER", -7),
    ("MEXICO", -6),      # Mexico City
    ("NEWYORK", -5),     # on the clock face
    ("CARACAS", -4),
    ("RIODEJANEIRO", -3),
    ("SOUTHGEORGIA", -2),
    ("REYKJAVIK", 0),    # shares UTC+0 with Accra
    ("LONDON", 0),
    ("BERLIN", 1),       # shares UTC+1 with Algiers
]

CITY_NAMES = [c[0] for c in WELTZEITUHR_CITIES]
CITY_OFFSETS = [c[1] for c in WELTZEITUHR_CITIES]
N_CITIES = len(CITY_NAMES)

# Find BERLIN's position
BERLIN_IDX = CITY_NAMES.index("BERLIN")


# ── Alphabet generation ──────────────────────────────────────────────────

def keyed_alphabet(keyword: str) -> str:
    """Generate a keyed alphabet from a keyword."""
    seen = set()
    result = []
    for ch in keyword.upper():
        if ch in ALPH and ch not in seen:
            result.append(ch)
            seen.add(ch)
    for ch in ALPH:
        if ch not in seen:
            result.append(ch)
            seen.add(ch)
    return ''.join(result)


def shifted_alphabet(shift: int) -> str:
    """Generate a Caesar-shifted alphabet."""
    return ALPH[shift % 26:] + ALPH[:shift % 26]


def city_alphabets_keyword() -> List[str]:
    """Generate one keyed alphabet per city using city name as keyword."""
    return [keyed_alphabet(city) for city in CITY_NAMES]


def city_alphabets_offset() -> List[str]:
    """Generate one Caesar-shifted alphabet per city using UTC offset."""
    return [shifted_alphabet(offset) for offset in CITY_OFFSETS]


def city_alphabets_combined() -> List[str]:
    """Keyed alphabet from city name, then shift by UTC offset."""
    result = []
    for city, offset in WELTZEITUHR_CITIES:
        ka = keyed_alphabet(city)
        # Apply additional shift
        shift = offset % 26
        result.append(ka[shift:] + ka[:shift])
    return result


# ── FSM cipher engine ────────────────────────────────────────────────────

def encrypt_fsm(plaintext: str, alphabets: List[str], start_city: int,
                advance_rule: str, reset_after: int = N_CITIES) -> str:
    """Encrypt using Weltzeituhr FSM.

    Args:
        plaintext: uppercase A-Z
        alphabets: one alphabet per city
        start_city: initial pointer index
        advance_rule: how to advance the pointer
            "fixed_N" — advance by N each step
            "ct_mod" — advance by (ciphertext letter index) mod N_CITIES
            "pt_mod" — advance by (plaintext letter index) mod N_CITIES
            "offset_delta" — advance by UTC offset delta to next city
            "sequential" — advance by 1 each step (simple sequential)
        reset_after: how many cities before resetting the pool (default: 24)

    Returns: ciphertext string
    """
    result = []
    pointer = start_city
    used = set()  # for without-replacement scheduling
    step = 0

    for ch in plaintext.upper():
        if not ch.isalpha():
            continue

        # Current city's alphabet
        city_idx = pointer % N_CITIES
        alph = alphabets[city_idx]

        # Encipher: plaintext letter → cipher alphabet position
        pt_idx = ALPH.index(ch)
        ct_ch = alph[pt_idx]
        result.append(ct_ch)

        # Track usage for without-replacement
        used.add(city_idx)

        # Advance pointer
        if advance_rule.startswith("fixed_"):
            delta = int(advance_rule.split("_")[1])
            pointer = (pointer + delta) % N_CITIES
        elif advance_rule == "ct_mod":
            pointer = (pointer + (ord(ct_ch) - 65)) % N_CITIES
        elif advance_rule == "pt_mod":
            pointer = (pointer + pt_idx) % N_CITIES
        elif advance_rule == "offset_delta":
            # Move to the next city whose offset differs
            next_ptr = (pointer + 1) % N_CITIES
            delta = abs(CITY_OFFSETS[next_ptr] - CITY_OFFSETS[city_idx])
            pointer = (pointer + max(delta, 1)) % N_CITIES
        elif advance_rule == "sequential":
            pointer = (pointer + 1) % N_CITIES

        # Without-replacement reset
        if len(used) >= reset_after:
            used.clear()

        step += 1

    return ''.join(result)


def decrypt_fsm(ciphertext: str, alphabets: List[str], start_city: int,
                advance_rule: str, reset_after: int = N_CITIES) -> str:
    """Decrypt using Weltzeituhr FSM (inverse of encrypt_fsm)."""
    result = []
    pointer = start_city
    used = set()
    step = 0

    for ch in ciphertext.upper():
        if not ch.isalpha():
            continue

        city_idx = pointer % N_CITIES
        alph = alphabets[city_idx]

        # Decipher: find ciphertext letter in cipher alphabet → plaintext position
        ct_idx = alph.index(ch)
        pt_ch = ALPH[ct_idx]
        result.append(pt_ch)

        used.add(city_idx)

        # Advance pointer (must match encrypt exactly)
        if advance_rule.startswith("fixed_"):
            delta = int(advance_rule.split("_")[1])
            pointer = (pointer + delta) % N_CITIES
        elif advance_rule == "ct_mod":
            pointer = (pointer + (ord(ch) - 65)) % N_CITIES
        elif advance_rule == "pt_mod":
            pointer = (pointer + ct_idx) % N_CITIES  # Note: ct_idx = pt_idx in decrypt
        elif advance_rule == "offset_delta":
            next_ptr = (pointer + 1) % N_CITIES
            delta = abs(CITY_OFFSETS[next_ptr] - CITY_OFFSETS[city_idx])
            pointer = (pointer + max(delta, 1)) % N_CITIES
        elif advance_rule == "sequential":
            pointer = (pointer + 1) % N_CITIES

        if len(used) >= reset_after:
            used.clear()

        step += 1

    return ''.join(result)


# ── Main search ──────────────────────────────────────────────────────────

def run_weltzeituhr():
    print("=" * 72)
    print("E-AUDIT-03: Weltzeituhr Finite-State Cipher Experiment")
    print("=" * 72)
    print()

    # Alphabet generation strategies
    alphabet_strategies = {
        "city_keyword": city_alphabets_keyword(),
        "utc_offset": city_alphabets_offset(),
        "combined": city_alphabets_combined(),
    }

    # Advance rules
    advance_rules = [
        "sequential",
        "fixed_2", "fixed_3", "fixed_5", "fixed_7", "fixed_11", "fixed_13",
        "ct_mod", "pt_mod", "offset_delta",
    ]

    # Starting cities
    start_cities = list(range(N_CITIES))

    # Reset intervals (without-replacement pool size)
    reset_intervals = [N_CITIES, 12, 6, 8, 13, 26]

    print(f"Alphabet strategies: {len(alphabet_strategies)}")
    print(f"Advance rules: {len(advance_rules)}")
    print(f"Starting cities: {N_CITIES}")
    print(f"Reset intervals: {len(reset_intervals)}")
    total_configs = (len(alphabet_strategies) * len(advance_rules)
                    * N_CITIES * len(reset_intervals))
    print(f"Total configs: {total_configs:,}")
    print()

    best_score = 0
    best_results = []
    configs_tested = 0
    t0 = time.time()

    for strat_name, alphabets in alphabet_strategies.items():
        for rule in advance_rules:
            for start_city in start_cities:
                for reset_n in reset_intervals:
                    configs_tested += 1

                    try:
                        plaintext = decrypt_fsm(CT, alphabets, start_city,
                                               rule, reset_n)
                    except (ValueError, IndexError):
                        continue

                    if len(plaintext) != CT_LEN:
                        continue

                    fscore = score_free_fast(plaintext)

                    if fscore > 0:
                        result = score_free(plaintext)
                        ic_val = ic(plaintext)
                        entry = {
                            "strategy": strat_name,
                            "rule": rule,
                            "start_city": CITY_NAMES[start_city],
                            "reset_n": reset_n,
                            "score": fscore,
                            "ic": ic_val,
                            "text_sample": plaintext[:50] + "...",
                        }
                        best_results.append(entry)
                        if fscore > best_score:
                            best_score = fscore
                            print(f"  NEW BEST: score={fscore}/24 | "
                                  f"{strat_name}/{rule}/start={CITY_NAMES[start_city]}/"
                                  f"reset={reset_n}")
                            print(f"    PT: {plaintext[:60]}...")
                            if result.ene_found:
                                print(f"    ENE at: {result.ene_offsets}")
                            if result.bc_found:
                                print(f"    BC at: {result.bc_offsets}")

    elapsed = time.time() - t0

    # Phase 2: Extended search with permuted city orderings
    # The order of cities on the ring may not be the canonical one
    print()
    print("Phase 2: Rotated city ring (different starting reference)")
    print("-" * 48)

    phase2_tested = 0
    phase2_best = 0

    # Try all rotations of the city ring
    for rotation in range(N_CITIES):
        rotated_cities = CITY_NAMES[rotation:] + CITY_NAMES[:rotation]
        rotated_offsets = CITY_OFFSETS[rotation:] + CITY_OFFSETS[:rotation]

        # Generate keyword alphabets from rotated order
        rotated_alphs = [keyed_alphabet(city) for city in rotated_cities]

        for rule in ["sequential", "fixed_2", "fixed_5", "ct_mod"]:
            for reset_n in [N_CITIES, 13, 26]:
                phase2_tested += 1
                try:
                    plaintext = decrypt_fsm(CT, rotated_alphs, 0, rule, reset_n)
                except (ValueError, IndexError):
                    continue

                if len(plaintext) != CT_LEN:
                    continue

                fscore = score_free_fast(plaintext)
                if fscore > 0:
                    result = score_free(plaintext)
                    if fscore > phase2_best:
                        phase2_best = fscore
                        print(f"  HIT: score={fscore}/24 | rotation={rotation} "
                              f"({rotated_cities[0]}...) / {rule} / reset={reset_n}")

    # Phase 3: Kryptos-alphabet variants
    # Instead of city-name alphabets, use KA permutations
    print()
    print("Phase 3: KA-shifted alphabets (Kryptos alphabet as base)")
    print("-" * 48)

    KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
    phase3_tested = 0
    phase3_best = 0

    for shift_base in range(26):
        # Each city gets KA shifted by (city_index * shift_base) mod 26
        ka_alphabets = []
        for i in range(N_CITIES):
            shift = (i * shift_base) % 26
            ka_alphabets.append(KA[shift:] + KA[:shift])

        for rule in advance_rules:
            for start_city in [BERLIN_IDX, 0]:
                for reset_n in [N_CITIES, 13, 26]:
                    phase3_tested += 1
                    try:
                        plaintext = decrypt_fsm(CT, ka_alphabets, start_city,
                                               rule, reset_n)
                    except (ValueError, IndexError):
                        continue

                    if len(plaintext) != CT_LEN:
                        continue

                    fscore = score_free_fast(plaintext)
                    if fscore > 0:
                        if fscore > phase3_best:
                            phase3_best = fscore
                            print(f"  HIT: score={fscore}/24 | shift_base={shift_base} "
                                  f"/ {rule} / start={CITY_NAMES[start_city]}")

    # IC distribution analysis
    print()
    print("Phase 4: IC distribution under Weltzeituhr FSM")
    print("-" * 48)

    ic_values = []
    sample_count = min(1000, configs_tested)
    sample_idx = 0

    for strat_name, alphabets in alphabet_strategies.items():
        for rule in advance_rules[:4]:
            for start_city in start_cities:
                for reset_n in [N_CITIES, 13]:
                    try:
                        pt = decrypt_fsm(CT, alphabets, start_city, rule, reset_n)
                        if len(pt) == CT_LEN:
                            ic_values.append(ic(pt))
                            sample_idx += 1
                    except (ValueError, IndexError):
                        continue
                    if sample_idx >= sample_count:
                        break
                if sample_idx >= sample_count:
                    break
            if sample_idx >= sample_count:
                break
        if sample_idx >= sample_count:
            break

    if ic_values:
        mean_ic = sum(ic_values) / len(ic_values)
        min_ic = min(ic_values)
        max_ic = max(ic_values)
        print(f"  IC distribution over {len(ic_values)} samples:")
        print(f"    Mean: {mean_ic:.4f}")
        print(f"    Min:  {min_ic:.4f}")
        print(f"    Max:  {max_ic:.4f}")
        print(f"    K4 observed: 0.0361")
        below_k4 = sum(1 for v in ic_values if v <= 0.0361)
        print(f"    Samples ≤ K4 IC: {below_k4}/{len(ic_values)} "
              f"({100*below_k4/len(ic_values):.1f}%)")

    # Summary
    total_tested = configs_tested + phase2_tested + phase3_tested
    overall_best = max(best_score, phase2_best, phase3_best)

    print()
    print("=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"Total configurations tested: {total_tested:,}")
    print(f"Phase 1 (direct): {configs_tested:,} configs, best={best_score}/24")
    print(f"Phase 2 (rotated ring): {phase2_tested:,} configs, best={phase2_best}/24")
    print(f"Phase 3 (KA-shifted): {phase3_tested:,} configs, best={phase3_best}/24")
    print(f"Overall best free score: {overall_best}/24")
    print(f"Elapsed: {time.time()-t0:.1f}s")
    print()

    if overall_best >= 24:
        print("*** BREAKTHROUGH: Both cribs found! ***")
    elif overall_best >= 13:
        print("*** SIGNAL: One full crib found. ***")
    elif overall_best >= 11:
        print("INTERESTING: Partial crib match.")
    else:
        print("NOISE: No crib content found under Weltzeituhr FSM model.")
        print("This does NOT eliminate the family — only the tested parameter space.")
        print("Remaining open: arbitrary pointer rules, non-standard city orderings,")
        print("city-specific non-keyword alphabets.")

    # Save
    os.makedirs("results/audit", exist_ok=True)
    output = {
        "experiment": "E-AUDIT-03",
        "description": "Weltzeituhr finite-state cipher",
        "total_configs": total_tested,
        "best_score": overall_best,
        "phase1_configs": configs_tested,
        "phase1_best": best_score,
        "phase2_configs": phase2_tested,
        "phase2_best": phase2_best,
        "phase3_configs": phase3_tested,
        "phase3_best": phase3_best,
        "ic_mean": mean_ic if ic_values else None,
        "hits": best_results[:20],
    }
    with open("results/audit/e_audit_03_weltzeituhr_fsm.json", "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved to results/audit/e_audit_03_weltzeituhr_fsm.json")


if __name__ == "__main__":
    run_weltzeituhr()
