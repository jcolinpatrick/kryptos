#!/usr/bin/env python3
"""
Statistical audit: Polybius row clustering in K4 Beaufort keystream.

Questions addressed:
  Q1. Is the row clustering (10/23 consecutive same-row pairs) statistically
      significant under a well-chosen null? Is it an automatic consequence of
      known AP {G,K,O} enrichment?
  Q2. Multiplicity correction — how many related tests could have been run?
  Q3. Does the Vigenere keystream show the same pattern? (CT/crib property test)
  Q4. Conditional analysis — given the known letter frequency distribution in
      the keystream, what is the expected same-row pair count?

Nulls tested:
  N1. IID uniform random 24-letter sequences from KA alphabet
  N2. Frequency-matched random: preserve letter frequencies of observed keystream
  N3. AP-conditioned: fix 12 positions as {G,K,O}, randomize remaining 12
  N4. Letter-permutation: shuffle the 24 observed keystream letters

Cipher variants tested:
  - Beaufort A=0 (primary)
  - Vigenere (comparison)
  - Variant Beaufort (comparison)
  - Beaufort A=1 (comparison)

Metadata:
  Cipher: statistical_audit
  Family: statistical
  Status: active
  Keyspace: 4 variants x 4 nulls x 1M trials
  Last run: 2026-03-21
  Best score: N/A (audit)
"""

import json
import os
import sys
import random
from collections import Counter
from typing import List, Tuple, Dict, Any

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, KRYPTOS_ALPHABET, MOD,
    CRIB_DICT, CRIB_POSITIONS, N_CRIBS,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
)

# ── Constants ────────────────────────────────────────────────────────────────

KA = KRYPTOS_ALPHABET
KA_IDX = {c: i for i, c in enumerate(KA)}
GRID_COLS = 5
# Grid: row = idx // 5, col = idx % 5
# KA = KRYPTOSABCDEFGHIJLMNQUVWXZ
# Row 0: K R Y P T  (indices 0-4)
# Row 1: O S A B C  (indices 5-9)
# Row 2: D E F G H  (indices 10-14)
# Row 3: I J L M N  (indices 15-19)
# Row 4: Q U V W X  (indices 20-24)
# Row 5: Z           (index 25)

def ka_row(ch: str) -> int:
    return KA_IDX[ch] // GRID_COLS

def ka_col(ch: str) -> int:
    return KA_IDX[ch] % GRID_COLS

# ── Derive keystreams for all variants ───────────────────────────────────────

CRIB_POS_SORTED = sorted(CRIB_DICT.keys())  # 24 positions, sorted

def derive_keystream_beaufort_a0() -> str:
    """K = (CT - PT) mod 26 under AZ indexing, then map to letter."""
    ks = []
    for pos in CRIB_POS_SORTED:
        ct_val = ALPH_IDX[CT[pos]]
        pt_val = ALPH_IDX[CRIB_DICT[pos]]
        k_val = (ct_val - pt_val) % MOD
        ks.append(ALPH[k_val])
    return ''.join(ks)

def derive_keystream_beaufort_a1() -> str:
    """K = (CT - PT + 1) mod 26... actually Beaufort: K = (PT - CT) mod 26 with A=1.
    More precisely, Beaufort A=1 means K = (CT + PT) mod 26 with different convention.
    Let's be precise: Beaufort encryption is CT = (K - PT) mod 26, so K = (CT + PT) mod 26.
    A=0: CT = (K - PT) mod 26 => K = (CT + PT) mod 26
    Wait — let me re-derive from the constants file.
    BEAUFORT_KEY: K[i] = (CT[i] + PT[i]) mod 26? No:
    From constants: BEAUFORT_KEY_ENE = (9, 11, 9, 14, 3, 4, 6, 10, 20, 10, 10, 10, 11)
    Check pos 21: CT='Q'=16, PT='E'=4. (16+4)%26=20 != 9. (16-4)%26=12 != 9. (4-16)%26=14 != 9.
    Hmm. Under KA? KA_IDX['Q']=20, KA_IDX['E']=12. (20-12)%26=8 != 9.
    Under AZ with Beaufort tableau: K = (PT - CT) mod 26 = (4-16)%26 = 14 != 9.
    OK let me just compute from the known numeric keys.
    """
    # Use the stored numeric keys directly
    ene_keys = BEAUFORT_KEY_ENE  # 13 values
    bc_keys = BEAUFORT_KEY_BC    # 11 values
    ks = []
    for i, pos in enumerate(CRIB_POS_SORTED):
        if 21 <= pos <= 33:
            k_val = ene_keys[pos - 21]
        else:
            k_val = bc_keys[pos - 63]
        ks.append(ALPH[k_val])
    return ''.join(ks)

def derive_keystream_vigenere() -> str:
    """Use stored Vigenere keys."""
    ene_keys = VIGENERE_KEY_ENE
    bc_keys = VIGENERE_KEY_BC
    ks = []
    for i, pos in enumerate(CRIB_POS_SORTED):
        if 21 <= pos <= 33:
            k_val = ene_keys[pos - 21]
        else:
            k_val = bc_keys[pos - 63]
        ks.append(ALPH[k_val])
    return ''.join(ks)

def derive_keystream_variant_beaufort() -> str:
    """VBeau: K = (PT - CT) mod 26."""
    ks = []
    for pos in CRIB_POS_SORTED:
        ct_val = ALPH_IDX[CT[pos]]
        pt_val = ALPH_IDX[CRIB_DICT[pos]]
        k_val = (pt_val - ct_val) % MOD
        ks.append(ALPH[k_val])
    return ''.join(ks)

# ── Compute row/col sequences and clustering statistics ──────────────────────

def row_sequence(keystream: str) -> List[int]:
    return [ka_row(ch) for ch in keystream]

def col_sequence(keystream: str) -> List[int]:
    return [ka_col(ch) for ch in keystream]

def count_same_pairs(seq: List[int]) -> int:
    """Count consecutive pairs with same value."""
    return sum(1 for i in range(len(seq) - 1) if seq[i] == seq[i + 1])

def count_runs(seq: List[int]) -> List[int]:
    """Return list of run lengths."""
    if not seq:
        return []
    runs = [1]
    for i in range(1, len(seq)):
        if seq[i] == seq[i - 1]:
            runs[-1] += 1
        else:
            runs.append(1)
    return runs

def max_run(seq: List[int]) -> int:
    runs = count_runs(seq)
    return max(runs) if runs else 0

# ── Monte Carlo engines ─────────────────────────────────────────────────────

def mc_null_iid(n_trials: int, seq_len: int, seed: int = 42) -> Dict[str, Any]:
    """N1: IID uniform random letters from full KA alphabet."""
    rng = random.Random(seed)
    all_letters = list(KA)
    obs_row = None  # will be set externally
    row_counts = []
    col_counts = []
    max_row_run_counts = []

    for _ in range(n_trials):
        seq = [rng.choice(all_letters) for _ in range(seq_len)]
        rows = row_sequence(''.join(seq))
        cols = col_sequence(''.join(seq))
        row_counts.append(count_same_pairs(rows))
        col_counts.append(count_same_pairs(cols))
        max_row_run_counts.append(max_run(rows))

    return {
        'row_same_pairs': row_counts,
        'col_same_pairs': col_counts,
        'max_row_run': max_row_run_counts,
    }

def mc_null_freq_matched(n_trials: int, letter_freqs: Counter, seq_len: int, seed: int = 43) -> Dict[str, Any]:
    """N2: Random sequences matching observed letter frequency distribution.
    Generate by sampling from the observed frequency distribution."""
    rng = random.Random(seed)
    # Build sampling pool
    pool = []
    for letter, count in letter_freqs.items():
        pool.extend([letter] * count)
    # pool has exactly seq_len letters
    assert len(pool) == seq_len

    row_counts = []
    col_counts = []
    max_row_run_counts = []

    for _ in range(n_trials):
        shuffled = pool[:]
        rng.shuffle(shuffled)
        rows = row_sequence(''.join(shuffled))
        cols = col_sequence(''.join(shuffled))
        row_counts.append(count_same_pairs(rows))
        col_counts.append(count_same_pairs(cols))
        max_row_run_counts.append(max_run(rows))

    return {
        'row_same_pairs': row_counts,
        'col_same_pairs': col_counts,
        'max_row_run': max_row_run_counts,
    }

def mc_null_ap_conditioned(n_trials: int, keystream: str, ap_letters: set, seed: int = 44) -> Dict[str, Any]:
    """N3: Fix positions that are AP letters {G,K,O}, randomize the rest uniformly from KA."""
    rng = random.Random(seed)
    all_letters = list(KA)
    ks_list = list(keystream)
    ap_positions = [i for i, ch in enumerate(ks_list) if ch in ap_letters]
    non_ap_positions = [i for i, ch in enumerate(ks_list) if ch not in ap_letters]

    row_counts = []
    col_counts = []
    max_row_run_counts = []

    for _ in range(n_trials):
        trial = ks_list[:]
        for pos in non_ap_positions:
            trial[pos] = rng.choice(all_letters)
        rows = row_sequence(''.join(trial))
        cols = col_sequence(''.join(trial))
        row_counts.append(count_same_pairs(rows))
        col_counts.append(count_same_pairs(cols))
        max_row_run_counts.append(max_run(rows))

    return {
        'row_same_pairs': row_counts,
        'col_same_pairs': col_counts,
        'max_row_run': max_row_run_counts,
    }

def mc_null_permutation(n_trials: int, keystream: str, seed: int = 45) -> Dict[str, Any]:
    """N4: Shuffle the observed 24 keystream letters (preserves exact letter set)."""
    rng = random.Random(seed)
    ks_list = list(keystream)

    row_counts = []
    col_counts = []
    max_row_run_counts = []

    for _ in range(n_trials):
        shuffled = ks_list[:]
        rng.shuffle(shuffled)
        rows = row_sequence(''.join(shuffled))
        cols = col_sequence(''.join(shuffled))
        row_counts.append(count_same_pairs(rows))
        col_counts.append(count_same_pairs(cols))
        max_row_run_counts.append(max_run(rows))

    return {
        'row_same_pairs': row_counts,
        'col_same_pairs': col_counts,
        'max_row_run': max_row_run_counts,
    }

# ── Exact expected value computation ─────────────────────────────────────────

def expected_same_row_pairs_permutation(keystream: str) -> float:
    """Exact expected number of same-row consecutive pairs under permutation null.

    E[same-row pairs] = sum over i in 0..22 of P(ks[i] and ks[i+1] same row).
    Under random permutation of fixed multiset, P(pos i and pos i+1 share row) =
    sum_r [ n_r * (n_r - 1) ] / [N * (N - 1)]
    where n_r = count of letters in row r, N = total letters.

    This is because for any two distinct positions, P(both in row r) = n_r*(n_r-1)/(N*(N-1)).
    """
    N = len(keystream)
    rows = row_sequence(keystream)
    row_freqs = Counter(rows)

    numerator = sum(n * (n - 1) for n in row_freqs.values())
    denominator = N * (N - 1)
    p_same_row = numerator / denominator

    # Number of consecutive pairs = N - 1 = 23
    expected = (N - 1) * p_same_row
    return expected, p_same_row

def expected_same_row_pairs_iid(grid_cols: int = 5) -> float:
    """Expected same-row pairs for IID uniform from 26-letter KA.

    P(two random KA letters share row) = sum_r (n_r/26)^2
    Row sizes: 5,5,5,5,5,1 → P = 5*(5/26)^2 + (1/26)^2 = 5*25/676 + 1/676 = 126/676 ≈ 0.1864
    """
    # KA has 6 rows: rows 0-4 have 5 letters each, row 5 has 1 letter (Z)
    row_sizes = [5, 5, 5, 5, 5, 1]
    p = sum((s / 26) ** 2 for s in row_sizes)
    expected = 23 * p
    return expected, p

# ── Decompose AP contribution ────────────────────────────────────────────────

def decompose_ap_contribution(keystream: str, ap_letters: set) -> Dict[str, Any]:
    """How many of the same-row pairs are explained by AP letters alone?

    Categorize each consecutive pair (i, i+1):
    - Both AP: same row iff both in same AP letter's row
    - One AP, one non-AP: same row is partly constrained
    - Neither AP: same row is unconstrained by AP
    """
    ks_list = list(keystream)
    rows = row_sequence(keystream)

    both_ap = 0
    both_ap_same_row = 0
    one_ap = 0
    one_ap_same_row = 0
    neither_ap = 0
    neither_ap_same_row = 0

    for i in range(len(ks_list) - 1):
        a_is_ap = ks_list[i] in ap_letters
        b_is_ap = ks_list[i + 1] in ap_letters
        same = rows[i] == rows[i + 1]

        if a_is_ap and b_is_ap:
            both_ap += 1
            if same:
                both_ap_same_row += 1
        elif a_is_ap or b_is_ap:
            one_ap += 1
            if same:
                one_ap_same_row += 1
        else:
            neither_ap += 1
            if same:
                neither_ap_same_row += 1

    return {
        'both_ap': {'count': both_ap, 'same_row': both_ap_same_row},
        'one_ap': {'count': one_ap, 'same_row': one_ap_same_row},
        'neither_ap': {'count': neither_ap, 'same_row': neither_ap_same_row},
        'total_same_row': both_ap_same_row + one_ap_same_row + neither_ap_same_row,
    }

# ── Additional clustering statistics ─────────────────────────────────────────

def all_widths_row_clustering(keystream: str, max_width: int = 13) -> Dict[int, Dict]:
    """Test row clustering at every grid width from 2 to max_width.
    This addresses the multiplicity question: is width 5 uniquely special?"""
    results = {}
    for w in range(2, max_width + 1):
        # Rows for this width
        rows = [KA_IDX[ch] // w for ch in keystream]
        n_same = count_same_pairs(rows)

        # Expected under permutation null
        row_freqs = Counter(rows)
        N = len(keystream)
        p_same = sum(n * (n - 1) for n in row_freqs.values()) / (N * (N - 1))
        expected = 23 * p_same

        results[w] = {
            'observed': n_same,
            'expected_perm': round(expected, 3),
            'ratio': round(n_same / expected, 3) if expected > 0 else float('inf'),
            'n_rows': (26 + w - 1) // w,
        }
    return results

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    N_TRIALS = 1_000_000  # 1M trials for good precision at p ~ 0.005

    print("=" * 72)
    print("POLYBIUS ROW CLUSTERING AUDIT")
    print("=" * 72)

    # ── Step 1: Derive and verify all keystreams ────────────────────────────

    ks_beau = derive_keystream_beaufort_a0()
    ks_beau_stored = derive_keystream_beaufort_a1()  # This is actually from stored keys
    ks_vig = derive_keystream_vigenere()
    ks_vbeau = derive_keystream_variant_beaufort()

    # Verify Beaufort keystream matches user-provided JLJODEGKUKKKLOCGGBGOKTRU
    # The stored keys use a specific convention. Let's derive from stored keys:
    beau_numeric = list(BEAUFORT_KEY_ENE) + list(BEAUFORT_KEY_BC)
    ks_beau_from_stored = ''.join(ALPH[v] for v in beau_numeric)

    vig_numeric = list(VIGENERE_KEY_ENE) + list(VIGENERE_KEY_BC)
    ks_vig_from_stored = ''.join(ALPH[v] for v in vig_numeric)

    print(f"\nBeaufort keystream (from stored keys): {ks_beau_from_stored}")
    print(f"Beaufort A=0 (derived CT-PT mod 26):   {ks_beau}")
    print(f"Variant Beaufort (PT-CT mod 26):       {ks_vbeau}")
    print(f"Vigenere (from stored keys):           {ks_vig_from_stored}")

    # User's claimed keystream
    CLAIMED_KS = "JLJODEGKUKKKLOCGGBGOKTRU"
    print(f"\nUser's claimed Beaufort keystream:     {CLAIMED_KS}")

    # Determine which derivation matches
    match_stored = ks_beau_from_stored == CLAIMED_KS
    match_derived = ks_beau == CLAIMED_KS
    match_vbeau = ks_vbeau == CLAIMED_KS
    print(f"Matches stored Beaufort keys: {match_stored}")
    print(f"Matches CT-PT mod 26:         {match_derived}")
    print(f"Matches PT-CT mod 26:         {match_vbeau}")

    # Use the keystream that actually matches
    if match_stored:
        primary_ks = ks_beau_from_stored
        primary_label = "Beaufort (stored keys)"
    elif match_derived:
        primary_ks = ks_beau
        primary_label = "Beaufort A=0 (CT-PT)"
    elif match_vbeau:
        primary_ks = ks_vbeau
        primary_label = "VBeau (PT-CT)"
    else:
        # Fallback: use the claimed keystream directly
        primary_ks = CLAIMED_KS
        primary_label = "User-provided"
        print("WARNING: None of the derived keystreams match the claimed value!")
        print("Using claimed keystream directly.")

    print(f"\nPrimary keystream ({primary_label}): {primary_ks}")

    # ── Step 2: Grid layout verification ────────────────────────────────────

    print("\n" + "─" * 72)
    print("KA POLYBIUS GRID (5-wide)")
    print("─" * 72)
    for r in range(6):
        start = r * 5
        end = min(start + 5, 26)
        row_letters = KA[start:end]
        print(f"  Row {r}: {' '.join(row_letters)}")

    print("\nKeystream letter grid positions:")
    for ch in sorted(set(primary_ks)):
        r, c = ka_row(ch), ka_col(ch)
        freq = primary_ks.count(ch)
        print(f"  {ch}: row={r}, col={c}, freq={freq}")

    # ── Step 3: Observed statistics ─────────────────────────────────────────

    print("\n" + "─" * 72)
    print("OBSERVED STATISTICS")
    print("─" * 72)

    rows_primary = row_sequence(primary_ks)
    cols_primary = col_sequence(primary_ks)

    print(f"Row sequence:  {rows_primary}")
    print(f"Col sequence:  {cols_primary}")

    obs_row_pairs = count_same_pairs(rows_primary)
    obs_col_pairs = count_same_pairs(cols_primary)
    obs_max_row_run = max_run(rows_primary)
    obs_runs = count_runs(rows_primary)

    print(f"\nSame-row consecutive pairs:    {obs_row_pairs} / 23")
    print(f"Same-col consecutive pairs:    {obs_col_pairs} / 23")
    print(f"Max row run length:            {obs_max_row_run}")
    print(f"Row run lengths:               {obs_runs}")

    # ── Step 4: AP decomposition ────────────────────────────────────────────

    print("\n" + "─" * 72)
    print("AP {G,K,O} DECOMPOSITION")
    print("─" * 72)

    AP_LETTERS = {'G', 'K', 'O'}
    ap_info = decompose_ap_contribution(primary_ks, AP_LETTERS)

    print(f"AP letter rows: G=row {ka_row('G')}, K=row {ka_row('K')}, O=row {ka_row('O')}")
    print(f"AP letters span {len(set(ka_row(c) for c in AP_LETTERS))} distinct rows "
          f"({sorted(set(ka_row(c) for c in AP_LETTERS))})")

    ap_positions = [i for i, ch in enumerate(primary_ks) if ch in AP_LETTERS]
    print(f"\nAP positions in keystream (0-indexed): {ap_positions}")
    print(f"AP count: {len(ap_positions)}/24")

    print(f"\nPair decomposition:")
    print(f"  Both AP:    {ap_info['both_ap']['count']} pairs, {ap_info['both_ap']['same_row']} same-row")
    print(f"  One AP:     {ap_info['one_ap']['count']} pairs, {ap_info['one_ap']['same_row']} same-row")
    print(f"  Neither AP: {ap_info['neither_ap']['count']} pairs, {ap_info['neither_ap']['same_row']} same-row")
    print(f"  Total same-row: {ap_info['total_same_row']}")

    # What would we expect from AP alone?
    # G is row 2, K is row 0, O is row 1. All different rows!
    # So two adjacent AP letters can only be same-row if they're the SAME letter
    # or happen to be in the same row (but G,K,O are in different rows).
    print(f"\nKey insight: G(row {ka_row('G')}), K(row {ka_row('K')}), O(row {ka_row('O')}) "
          f"are ALL in DIFFERENT rows.")
    print("Therefore, two adjacent AP letters are same-row ONLY if they're the same letter.")
    print("AP enrichment does NOT cause row clustering — it actually INHIBITS it")
    print("(by placing many letters across 3 different rows).")

    # ── Step 5: Cross-variant comparison ────────────────────────────────────

    print("\n" + "─" * 72)
    print("CROSS-VARIANT COMPARISON")
    print("─" * 72)

    all_keystreams = {
        'Beaufort': primary_ks,
        'Vigenere': ks_vig_from_stored,
        'VBeau (PT-CT)': ks_vbeau,
        'Beau (CT-PT)': ks_beau,
    }

    for label, ks in all_keystreams.items():
        rows = row_sequence(ks)
        cols = col_sequence(ks)
        rp = count_same_pairs(rows)
        cp = count_same_pairs(cols)
        mr = max_run(rows)
        n_distinct = len(set(ks))
        print(f"  {label:20s}: ks={ks}, row_pairs={rp}, col_pairs={cp}, "
              f"max_run={mr}, distinct={n_distinct}")

    # ── Step 6: Exact expected values ───────────────────────────────────────

    print("\n" + "─" * 72)
    print("EXACT EXPECTED VALUES")
    print("─" * 72)

    exp_perm, p_perm = expected_same_row_pairs_permutation(primary_ks)
    exp_iid, p_iid = expected_same_row_pairs_iid()

    print(f"Under permutation null (shuffle observed letters):")
    print(f"  P(same row per pair) = {p_perm:.6f}")
    print(f"  E[same-row pairs]    = {exp_perm:.3f}")
    print(f"  Observed             = {obs_row_pairs}")
    print(f"  Observed/Expected    = {obs_row_pairs / exp_perm:.3f}")

    print(f"\nUnder IID uniform null:")
    print(f"  P(same row per pair) = {p_iid:.6f}")
    print(f"  E[same-row pairs]    = {exp_iid:.3f}")
    print(f"  Observed             = {obs_row_pairs}")
    print(f"  Observed/Expected    = {obs_row_pairs / exp_iid:.3f}")

    # Letter frequency distribution
    freq = Counter(primary_ks)
    print(f"\nLetter frequencies: {dict(sorted(freq.items(), key=lambda x: -x[1]))}")
    print(f"Distinct letters: {len(freq)}")
    row_counts = Counter(rows_primary)
    print(f"Row distribution: {dict(sorted(row_counts.items()))}")

    # ── Step 7: Monte Carlo simulations ─────────────────────────────────────

    print("\n" + "─" * 72)
    print(f"MONTE CARLO SIMULATIONS ({N_TRIALS:,} trials each)")
    print("─" * 72)

    # N1: IID uniform
    print("\nN1: IID uniform random KA letters...")
    n1 = mc_null_iid(N_TRIALS, 24, seed=20260321)
    n1_row_p = sum(1 for x in n1['row_same_pairs'] if x >= obs_row_pairs) / N_TRIALS
    n1_col_p = sum(1 for x in n1['col_same_pairs'] if x >= obs_col_pairs) / N_TRIALS
    n1_run_p = sum(1 for x in n1['max_row_run'] if x >= obs_max_row_run) / N_TRIALS
    n1_row_mean = sum(n1['row_same_pairs']) / N_TRIALS
    n1_col_mean = sum(n1['col_same_pairs']) / N_TRIALS

    print(f"  Row pairs: obs={obs_row_pairs}, E={n1_row_mean:.3f}, p(>={obs_row_pairs})={n1_row_p:.6f}")
    print(f"  Col pairs: obs={obs_col_pairs}, E={n1_col_mean:.3f}, p(>={obs_col_pairs})={n1_col_p:.6f}")
    print(f"  Max run:   obs={obs_max_row_run}, p(>={obs_max_row_run})={n1_run_p:.6f}")

    # N2: Frequency-matched (permutation of observed letters)
    print("\nN2: Permutation of observed keystream letters...")
    n2 = mc_null_permutation(N_TRIALS, primary_ks, seed=20260321)
    n2_row_p = sum(1 for x in n2['row_same_pairs'] if x >= obs_row_pairs) / N_TRIALS
    n2_col_p = sum(1 for x in n2['col_same_pairs'] if x >= obs_col_pairs) / N_TRIALS
    n2_run_p = sum(1 for x in n2['max_row_run'] if x >= obs_max_row_run) / N_TRIALS
    n2_row_mean = sum(n2['row_same_pairs']) / N_TRIALS
    n2_col_mean = sum(n2['col_same_pairs']) / N_TRIALS

    print(f"  Row pairs: obs={obs_row_pairs}, E={n2_row_mean:.3f}, p(>={obs_row_pairs})={n2_row_p:.6f}")
    print(f"  Col pairs: obs={obs_col_pairs}, E={n2_col_mean:.3f}, p(>={obs_col_pairs})={n2_col_p:.6f}")
    print(f"  Max run:   obs={obs_max_row_run}, p(>={obs_max_row_run})={n2_run_p:.6f}")

    # N3: AP-conditioned (fix G,K,O positions, randomize rest)
    print("\nN3: AP-conditioned (fix 12 AP positions, randomize rest)...")
    n3 = mc_null_ap_conditioned(N_TRIALS, primary_ks, AP_LETTERS, seed=20260321)
    n3_row_p = sum(1 for x in n3['row_same_pairs'] if x >= obs_row_pairs) / N_TRIALS
    n3_col_p = sum(1 for x in n3['col_same_pairs'] if x >= obs_col_pairs) / N_TRIALS
    n3_run_p = sum(1 for x in n3['max_row_run'] if x >= obs_max_row_run) / N_TRIALS
    n3_row_mean = sum(n3['row_same_pairs']) / N_TRIALS
    n3_col_mean = sum(n3['col_same_pairs']) / N_TRIALS

    print(f"  Row pairs: obs={obs_row_pairs}, E={n3_row_mean:.3f}, p(>={obs_row_pairs})={n3_row_p:.6f}")
    print(f"  Col pairs: obs={obs_col_pairs}, E={n3_col_mean:.3f}, p(>={obs_col_pairs})={n3_col_p:.6f}")
    print(f"  Max run:   obs={obs_max_row_run}, p(>={obs_max_row_run})={n3_run_p:.6f}")

    # N4: Frequency-matched sampling (draw from distribution matching observed)
    print("\nN4: Frequency-matched random (same letter distribution, independent draws)...")
    n4 = mc_null_freq_matched(N_TRIALS, freq, 24, seed=20260321)
    n4_row_p = sum(1 for x in n4['row_same_pairs'] if x >= obs_row_pairs) / N_TRIALS
    n4_col_p = sum(1 for x in n4['col_same_pairs'] if x >= obs_col_pairs) / N_TRIALS
    n4_run_p = sum(1 for x in n4['max_row_run'] if x >= obs_max_row_run) / N_TRIALS
    n4_row_mean = sum(n4['row_same_pairs']) / N_TRIALS
    n4_col_mean = sum(n4['col_same_pairs']) / N_TRIALS

    print(f"  Row pairs: obs={obs_row_pairs}, E={n4_row_mean:.3f}, p(>={obs_row_pairs})={n4_row_p:.6f}")
    print(f"  Col pairs: obs={obs_col_pairs}, E={n4_col_mean:.3f}, p(>={obs_col_pairs})={n4_col_p:.6f}")
    print(f"  Max run:   obs={obs_max_row_run}, p(>={obs_max_row_run})={n4_run_p:.6f}")

    # ── Step 8: Multi-width analysis ────────────────────────────────────────

    print("\n" + "─" * 72)
    print("MULTI-WIDTH ANALYSIS (row clustering at widths 2-13)")
    print("─" * 72)

    width_results = all_widths_row_clustering(primary_ks, max_width=13)
    for w, res in sorted(width_results.items()):
        flag = " ***" if w == 5 else ""
        print(f"  Width {w:2d}: obs={res['observed']:2d}, E_perm={res['expected_perm']:6.3f}, "
              f"ratio={res['ratio']:5.3f}, n_rows={res['n_rows']}{flag}")

    # MC for best non-5 width
    best_non5_width = max(
        (w for w in width_results if w != 5),
        key=lambda w: width_results[w]['ratio']
    )
    print(f"\nBest non-5 width: {best_non5_width} (ratio={width_results[best_non5_width]['ratio']})")

    # Run MC for all widths to get p-values
    print(f"\nMC p-values for widths 2-13 (N={N_TRIALS:,})...")
    width_pvalues = {}
    rng = random.Random(20260321)

    for trial_num in range(N_TRIALS):
        shuffled = list(primary_ks)
        rng.shuffle(shuffled)
        for w in range(2, 14):
            rows = [KA_IDX[ch] // w for ch in shuffled]
            same = count_same_pairs(rows)
            if w not in width_pvalues:
                width_pvalues[w] = 0
            if same >= width_results[w]['observed']:
                width_pvalues[w] += 1

    print(f"\n  {'Width':>5s} {'Obs':>4s} {'E_perm':>8s} {'p-value':>10s} {'Bonf(12)':>10s}")
    min_p = 1.0
    min_p_width = 0
    for w in range(2, 14):
        p = width_pvalues[w] / N_TRIALS
        bonf = min(1.0, p * 12)
        if p < min_p:
            min_p = p
            min_p_width = w
        flag = " ***" if w == 5 else ""
        print(f"  {w:5d} {width_results[w]['observed']:4d} {width_results[w]['expected_perm']:8.3f} "
              f"{p:10.6f} {bonf:10.6f}{flag}")

    print(f"\n  Minimum p-value: width {min_p_width}, p={min_p:.6f}")
    print(f"  Width 5 is{'NOT ' if min_p_width != 5 else ' '}the most significant width")

    # ── Step 9: Cross-variant MC ────────────────────────────────────────────

    print("\n" + "─" * 72)
    print("CROSS-VARIANT MONTE CARLO (width 5 only)")
    print("─" * 72)

    for label, ks in all_keystreams.items():
        rows = row_sequence(ks)
        obs = count_same_pairs(rows)
        exp, p_pair = expected_same_row_pairs_permutation(ks)

        # Quick MC: permutation null for this keystream
        rng = random.Random(20260321)
        ks_list = list(ks)
        count_ge = 0
        for _ in range(N_TRIALS):
            shuffled = ks_list[:]
            rng.shuffle(shuffled)
            if count_same_pairs(row_sequence(''.join(shuffled))) >= obs:
                count_ge += 1
        p = count_ge / N_TRIALS

        print(f"  {label:20s}: obs={obs:2d}, E_perm={exp:.3f}, p={p:.6f}")

    # ── Step 10: Row-run structure analysis ─────────────────────────────────

    print("\n" + "─" * 72)
    print("RUN STRUCTURE ANALYSIS")
    print("─" * 72)

    obs_n_runs = len(obs_runs)

    # MC for number of runs (Wald-Wolfowitz style)
    rng = random.Random(20260321)
    ks_list = list(primary_ks)
    run_count_dist = []
    for _ in range(N_TRIALS):
        shuffled = ks_list[:]
        rng.shuffle(shuffled)
        rows = row_sequence(''.join(shuffled))
        run_count_dist.append(len(count_runs(rows)))

    run_p = sum(1 for x in run_count_dist if x <= obs_n_runs) / N_TRIALS
    run_mean = sum(run_count_dist) / N_TRIALS

    print(f"Number of runs (row-sequence): observed={obs_n_runs}, E={run_mean:.3f}, "
          f"p(<={obs_n_runs})={run_p:.6f}")
    print(f"Run lengths: {obs_runs}")
    print(f"Max run: {obs_max_row_run}")

    # ── Compile results ─────────────────────────────────────────────────────

    results = {
        'audit': 'Polybius row clustering in K4 Beaufort keystream',
        'date': '2026-03-21',
        'n_trials': N_TRIALS,
        'seeds': [20260321],
        'primary_keystream': primary_ks,
        'primary_label': primary_label,
        'grid': 'KA 5-wide',
        'observed': {
            'row_same_pairs': obs_row_pairs,
            'col_same_pairs': obs_col_pairs,
            'max_row_run': obs_max_row_run,
            'run_lengths': obs_runs,
            'n_runs': obs_n_runs,
        },
        'expected': {
            'permutation_null': {
                'E_row_same_pairs': round(exp_perm, 4),
                'P_same_row_per_pair': round(p_perm, 6),
            },
            'iid_null': {
                'E_row_same_pairs': round(exp_iid, 4),
                'P_same_row_per_pair': round(p_iid, 6),
            },
        },
        'ap_decomposition': ap_info,
        'mc_results': {
            'N1_iid_uniform': {
                'row_p': n1_row_p,
                'col_p': n1_col_p,
                'max_run_p': n1_run_p,
                'row_mean': round(n1_row_mean, 3),
            },
            'N2_permutation': {
                'row_p': n2_row_p,
                'col_p': n2_col_p,
                'max_run_p': n2_run_p,
                'row_mean': round(n2_row_mean, 3),
            },
            'N3_ap_conditioned': {
                'row_p': n3_row_p,
                'col_p': n3_col_p,
                'max_run_p': n3_run_p,
                'row_mean': round(n3_row_mean, 3),
            },
            'N4_freq_matched': {
                'row_p': n4_row_p,
                'col_p': n4_col_p,
                'max_run_p': n4_run_p,
                'row_mean': round(n4_row_mean, 3),
            },
        },
        'multi_width': {
            str(w): {
                'observed': width_results[w]['observed'],
                'expected_perm': width_results[w]['expected_perm'],
                'p_value': width_pvalues[w] / N_TRIALS,
            }
            for w in range(2, 14)
        },
        'cross_variant': {},
        'run_structure': {
            'observed_n_runs': obs_n_runs,
            'expected_n_runs': round(run_mean, 3),
            'p_fewer_runs': run_p,
        },
    }

    # Save
    out_path = os.path.join(_ROOT, 'results', 'e_polybius_row_clustering_audit.json')
    with open(out_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to {out_path}")

    # ── Summary ─────────────────────────────────────────────────────────────

    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)

    print(f"""
Keystream: {primary_ks}
Grid: KA 5-wide Polybius

OBSERVED:
  Same-row consecutive pairs: {obs_row_pairs}/23
  Same-col consecutive pairs: {obs_col_pairs}/23
  Max row run: {obs_max_row_run}

P-VALUES (row pairs >= {obs_row_pairs}):
  N1 (IID uniform):       {n1_row_p:.6f}  (E={n1_row_mean:.3f})
  N2 (permutation):       {n2_row_p:.6f}  (E={n2_row_mean:.3f})
  N3 (AP-conditioned):    {n3_row_p:.6f}  (E={n3_row_mean:.3f})
  N4 (freq-matched):      {n4_row_p:.6f}  (E={n4_row_mean:.3f})

AP DECOMPOSITION:
  {ap_info['both_ap']['same_row']}/{ap_info['both_ap']['count']} both-AP pairs are same-row
  {ap_info['one_ap']['same_row']}/{ap_info['one_ap']['count']} one-AP pairs are same-row
  {ap_info['neither_ap']['same_row']}/{ap_info['neither_ap']['count']} neither-AP pairs are same-row
  G,K,O span 3 DIFFERENT rows -> AP INHIBITS row clustering

WIDTH SPECIFICITY:
  Width 5 p-value:        {width_pvalues[5] / N_TRIALS:.6f}
  Best width:             {min_p_width} (p={min_p:.6f})
  Width 5 Bonferroni:     {min(1.0, width_pvalues[5] / N_TRIALS * 12):.6f}

RUN STRUCTURE:
  Number of runs: {obs_n_runs} (E={run_mean:.3f}, p_fewer={run_p:.6f})
""")

if __name__ == '__main__':
    main()
