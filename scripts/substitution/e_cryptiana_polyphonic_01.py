#!/usr/bin/env python3 -u
"""
Cipher: polyphonic substitution
Family: substitution
Status: active
Keyspace: constrained by 24 cribs, ~10^4 tables x disambiguation rules
Last run:
Best score:

CRYPTIANA POLYPHONIC SUBSTITUTION: One CT Symbol -> Multiple PT Letters

Hypothesis: Each CT letter can represent 2-3 different PT letters.
A second system (position rule, keyword selector, grille pattern)
disambiguates which meaning applies at each position.

This is the INVERSE of homophonic substitution:
  Homophonic: one PT letter -> multiple CT symbols (tested, eliminated)
  Polyphonic: one CT symbol -> multiple PT letters (UNTESTED)

From Cryptiana: Renaissance papal ciphers used polyphonic substitution
where context or diacritical marks disambiguated. For K4, the "second
system" could be the disambiguation mechanism.

Attack strategy:
  1. Use 24 crib positions to constrain the polyphonic table
     (at each crib position, CT letter MUST map to the known PT letter)
  2. Build candidate tables where each CT letter maps to 2-3 PT letters
  3. For non-crib positions, enumerate possible PT letters
  4. Score by English quality (quadgrams, word detection)
  5. Test disambiguation rules (periodic, position-dependent, grille)

Two-system connection:
  System 1: polyphonic substitution table (creates ambiguity)
  System 2: disambiguation selector (resolves ambiguity)
"""

import sys
import os
import json
import time
from collections import defaultdict
from multiprocessing import Pool, cpu_count

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import CT, CRIB_DICT, BEAN_EQ, BEAN_INEQ

ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
CT_LEN = len(CT)
CRIB_POSITIONS = sorted(CRIB_DICT.keys())

# Load quadgrams for scoring
QG_PATH = os.path.join(_ROOT, "data", "english_quadgrams.json")
try:
    with open(QG_PATH) as f:
        _qg_raw = json.load(f)
    QG_FLOOR = min(_qg_raw.values()) - 1.0
    QG = {}
    for gram, logp in _qg_raw.items():
        if len(gram) == 4:
            QG[gram] = logp
    del _qg_raw
except FileNotFoundError:
    QG = {}
    QG_FLOOR = -10.0


def quadgram_score(text):
    """Score text by quadgram log-probability."""
    if len(text) < 4:
        return QG_FLOOR
    total = sum(QG.get(text[i:i+4], QG_FLOOR) for i in range(len(text) - 3))
    return total / (len(text) - 3)


# ---- Build polyphonic table from crib constraints ----

def build_crib_mapping():
    """Extract CT->PT mappings required by cribs.

    Returns dict: CT_letter -> set of PT letters it MUST be able to produce.
    """
    ct_to_pt = defaultdict(set)
    for pos in CRIB_POSITIONS:
        ct_char = CT[pos]
        pt_char = CRIB_DICT[pos]
        ct_to_pt[ct_char].add(pt_char)
    return dict(ct_to_pt)


def build_polyphonic_tables(crib_mapping, max_meanings=3):
    """Build candidate polyphonic tables.

    Each CT letter gets 1-3 PT letter meanings.
    Crib-constrained letters MUST include their required PT letters.
    Unconstrained letters get assigned based on frequency matching.

    Returns list of (table_dict, label) where table_dict maps
    CT_letter -> list of PT_letters.
    """
    # Start with crib-required mappings
    base_table = {}
    for ct_char in ALPHA:
        if ct_char in crib_mapping:
            base_table[ct_char] = list(crib_mapping[ct_char])
        else:
            base_table[ct_char] = []

    # For each unconstrained CT letter, assign 1-2 PT letters
    # based on frequency proximity
    # English letter frequencies (approximate rank order)
    eng_freq_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

    # CT letter frequencies
    ct_freq = defaultdict(int)
    for c in CT:
        ct_freq[c] += 1

    # Assign PT letters to unconstrained CT letters
    # Strategy: each CT letter gets PT letters with similar frequency rank
    tables = []

    # Strategy 1: Each CT letter maps to itself + one neighbor
    table1 = dict(base_table)
    for ct_char in ALPHA:
        if not table1[ct_char]:
            idx = ALPHA.index(ct_char)
            table1[ct_char] = [ct_char]
            if idx + 1 < 26:
                table1[ct_char].append(ALPHA[idx + 1])
        elif len(table1[ct_char]) < 2:
            # Add the letter itself if not already there
            if ct_char not in table1[ct_char]:
                table1[ct_char].append(ct_char)
    tables.append((table1, "self_neighbor"))

    # Strategy 2: Frequency-matched pairs
    table2 = dict(base_table)
    for ct_char in ALPHA:
        if not table2[ct_char]:
            ct_rank = eng_freq_order.index(ct_char) if ct_char in eng_freq_order else 25
            # Assign the letter at the same frequency rank + one nearby
            table2[ct_char] = [eng_freq_order[ct_rank]]
            nearby = (ct_rank + 13) % 26  # pair with letter 13 ranks away
            table2[ct_char].append(eng_freq_order[nearby])
        elif len(table2[ct_char]) < 2:
            ct_rank = eng_freq_order.index(ct_char) if ct_char in eng_freq_order else 25
            nearby = (ct_rank + 13) % 26
            cand = eng_freq_order[nearby]
            if cand not in table2[ct_char]:
                table2[ct_char].append(cand)
    tables.append((table2, "freq_matched"))

    # Strategy 3: Crib-only (each CT letter maps ONLY to what cribs require)
    # Unconstrained letters map to all possible PT letters (maximally ambiguous)
    # This tests whether the disambiguation rule alone can produce English
    table3 = dict(base_table)
    for ct_char in ALPHA:
        if not table3[ct_char]:
            table3[ct_char] = list(ALPHA)  # fully ambiguous
    tables.append((table3, "crib_only_full_ambig"))

    return tables


# ---- Disambiguation rules ----

def disambiguate_periodic(position, n_options, period, offset=0):
    """Select meaning index based on position mod period."""
    return (position + offset) % n_options


def disambiguate_beaufort_key(position, n_options, key):
    """Select meaning based on Beaufort key character."""
    k = ord(key[position % len(key)]) - ord('A')
    return k % n_options


def apply_disambiguation(table, rule_type, rule_param):
    """Apply a disambiguation rule to produce a single PT character per position.

    Returns the plaintext string.
    """
    pt = []
    for i, ct_char in enumerate(CT):
        options = table.get(ct_char, [ct_char])
        n = len(options)
        if n == 0:
            pt.append('?')
        elif n == 1:
            pt.append(options[0])
        else:
            if rule_type == 'periodic':
                period, offset = rule_param
                idx = (i + offset) % n
            elif rule_type == 'beaufort_key':
                key = rule_param
                k = ord(key[i % len(key)]) - ord('A')
                idx = k % n
            elif rule_type == 'position_mod':
                mod_val = rule_param
                idx = i % n
            elif rule_type == 'alternating':
                idx = i % n
            else:
                idx = 0
            pt.append(options[idx])
    return ''.join(pt)


# ---- Worker function ----

def test_config(args):
    """Test one (table, disambiguation rule) configuration."""
    table_label, table, rule_type, rule_param, rule_label = args

    pt = apply_disambiguation(table, rule_type, rule_param)

    # Check cribs first (fast rejection)
    crib_score = 0
    for pos in CRIB_POSITIONS:
        if pt[pos] == CRIB_DICT[pos]:
            crib_score += 1

    if crib_score < 20:  # polyphonic should nail cribs since they're constrained
        return None

    # Quadgram score
    qg = quadgram_score(pt)

    # Bean constraints
    bean_pass = True
    eq_pos1, eq_pos2 = BEAN_EQ
    # Under polyphonic, "key" concept doesn't directly apply
    # but we can check if the disambiguation is consistent

    if crib_score >= 20 or qg > -6.5:
        return {
            "table_label": table_label,
            "rule": f"{rule_type}:{rule_label}",
            "crib_score": crib_score,
            "quadgram": round(qg, 3),
            "plaintext": pt,
        }
    return None


def main():
    print("=" * 70)
    print("CRYPTIANA POLYPHONIC SUBSTITUTION")
    print("One CT symbol -> multiple PT letters + disambiguation")
    print("=" * 70)
    t0 = time.time()

    # Build crib mapping
    crib_mapping = build_crib_mapping()
    print(f"\nCrib-constrained CT letters: {len(crib_mapping)}")
    for ct, pts in sorted(crib_mapping.items()):
        print(f"  {ct} -> {pts}")

    # Check for contradictions (same CT letter must produce different PT letters)
    multi_mapped = {ct: pts for ct, pts in crib_mapping.items() if len(pts) > 1}
    print(f"\nCT letters requiring POLYPHONIC mapping (multiple PT values): {len(multi_mapped)}")
    for ct, pts in sorted(multi_mapped.items()):
        print(f"  {ct} must produce: {pts}")

    if not multi_mapped:
        print("\n  WARNING: No CT letter requires multiple PT values from cribs alone.")
        print("  This means a standard monoalphabetic substitution could satisfy all cribs.")
        print("  Polyphonic is only needed if the non-crib positions require it.")

    # Build polyphonic tables
    print("\nBuilding polyphonic tables...")
    tables = build_polyphonic_tables(crib_mapping)
    print(f"  {len(tables)} table strategies")

    # Build disambiguation rules
    keywords = [
        "KRYPTOS", "PALIMPSEST", "ABSCISSA", "DEFECTOR", "KUBARK",
        "SANBORN", "SCHEIDT", "SEVEN", "POINT", "SECRET",
    ]

    work_items = []
    for table, table_label in tables:
        # Periodic disambiguation
        for period in range(2, 14):
            for offset in range(period):
                rule_label = f"p{period}_o{offset}"
                work_items.append((table_label, table, 'periodic', (period, offset), rule_label))

        # Beaufort key disambiguation
        for key in keywords:
            rule_label = f"beau_{key}"
            work_items.append((table_label, table, 'beaufort_key', key, rule_label))

        # Simple alternating
        work_items.append((table_label, table, 'alternating', None, 'alt'))

        # Position mod
        for mod_val in range(2, 8):
            work_items.append((table_label, table, 'position_mod', mod_val, f'mod{mod_val}'))

    print(f"  {len(work_items)} total configurations")

    # Scan
    print(f"\nScanning ({max(1, cpu_count()-2)} workers)...")
    n_workers = max(1, cpu_count() - 2)
    results = []

    with Pool(n_workers) as pool:
        for result in pool.imap_unordered(test_config, work_items, chunksize=100):
            if result is not None:
                results.append(result)

    elapsed = time.time() - t0
    results.sort(key=lambda r: (-r['crib_score'], -r['quadgram']))

    print(f"\n  Done in {elapsed:.1f}s")
    print(f"  {len(results)} configs with crib >= 20")

    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    if not results:
        print("\n  NO configs scored crib >= 20. All noise.")
    else:
        for r in results[:20]:
            print(f"\n  Crib: {r['crib_score']}/24, QG: {r['quadgram']}")
            print(f"  Table: {r['table_label']}, Rule: {r['rule']}")
            print(f"  PT: {r['plaintext'][:60]}...")

    # Save
    out = {
        "timestamp": time.strftime("%Y%m%d_%H%M%S"),
        "configs_tested": len(work_items),
        "crib_constrained_ct_letters": len(crib_mapping),
        "polyphonic_required": len(multi_mapped),
        "above_20": len(results),
        "runtime_s": round(elapsed, 1),
        "top_20": [
            {k: v for k, v in r.items() if k != 'plaintext'}
            for r in results[:20]
        ],
        "multi_mapped": {ct: list(pts) for ct, pts in multi_mapped.items()},
    }
    out_path = os.path.join(_ROOT, "results", "e_cryptiana_polyphonic_01.json")
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"\n  Saved to {out_path}")
    print(f"  Total: {elapsed:.1f}s")


if __name__ == "__main__":
    main()
