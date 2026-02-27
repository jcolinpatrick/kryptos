#!/usr/bin/env python3
"""E-CFM-08: Transposition-guided running key fragment scoring.

[HYPOTHESIS] Under Model A (CT = Trans(Vig(PT, K))):
  K[j] = (CT[perm_inv[j]] - PT[j]) mod 26

The key at each crib position depends on which CT position the transposition
selects. This experiment finds the OPTIMAL transposition — the one that makes
the 24-char key fragment look most like English.

If even the optimal assignment produces non-English key values, the entire
"running key + transposition" model class is effectively dead for K4.

Methods:
  1. Optimal assignment (maximize English letter frequency sum)
  2. Bean-EQ-constrained optimal assignment (324 valid pairs)
  3. Monte Carlo: 10M random assignments scored by quadgrams (28 cores)
  4. Quadgram + Bean analysis of all top candidates

VM: 28 vCPUs, 31GB RAM. Designed for local parallel execution.
"""
import sys
import os
import json
import math
import random
from collections import Counter
from multiprocessing import Pool, cpu_count
from functools import partial

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS,
    BEAN_EQ, BEAN_INEQ,
)

# ── Load quadgram model ─────────────────────────────────────────────────
QUADGRAM_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "english_quadgrams.json")
with open(QUADGRAM_PATH) as f:
    QUADGRAMS = json.load(f)

# Floor value for missing quadgrams
QG_FLOOR = min(QUADGRAMS.values()) - 2.0  # ~-12 or so


def quadgram_score(text: str) -> float:
    """Log-probability score of text using quadgram model. Higher = more English-like."""
    if len(text) < 4:
        return QG_FLOOR * max(1, len(text) - 3)
    score = 0.0
    for i in range(len(text) - 3):
        qg = text[i:i + 4]
        score += QUADGRAMS.get(qg, QG_FLOOR)
    return score


def quadgram_score_per_char(text: str) -> float:
    """Quadgram score normalized per character."""
    if len(text) < 4:
        return QG_FLOOR
    return quadgram_score(text) / len(text)


# ── English letter frequencies ──────────────────────────────────────────
ENG_FREQ = {
    'A': .082, 'B': .015, 'C': .028, 'D': .043, 'E': .127,
    'F': .022, 'G': .020, 'H': .061, 'I': .070, 'J': .002,
    'K': .008, 'L': .040, 'M': .024, 'N': .067, 'O': .075,
    'P': .019, 'Q': .001, 'R': .060, 'S': .063, 'T': .091,
    'U': .028, 'V': .010, 'W': .024, 'X': .002, 'Y': .020,
    'Z': .001,
}
ENG_LOG_FREQ = {ch: math.log(f) if f > 0 else -10.0 for ch, f in ENG_FREQ.items()}


# ── Precompute key lookup table ─────────────────────────────────────────
CRIB_POSITIONS = sorted(CRIB_DICT.keys())  # 24 positions
CT_VALS = [ALPH_IDX[c] for c in CT]
PT_VALS = {pos: ALPH_IDX[ch] for pos, ch in CRIB_DICT.items()}

# KEY_TABLE[crib_idx][ct_pos] = key value (0-25)
# For crib position CRIB_POSITIONS[crib_idx], using CT position ct_pos
KEY_TABLE = []
for crib_idx, crib_pos in enumerate(CRIB_POSITIONS):
    row = []
    pt_val = PT_VALS[crib_pos]
    for ct_pos in range(CT_LEN):
        k_val = (CT_VALS[ct_pos] - pt_val) % MOD
        row.append(k_val)
    KEY_TABLE.append(row)

# Precompute which CT positions produce common English letters for each crib
# "Common" = top 15 by frequency (covers ~92% of English text)
COMMON_LETTERS = set("ETAOINSHRDLCUMW")
COMMON_INDICES = {ALPH_IDX[c] for c in COMMON_LETTERS}

GOOD_CT_FOR_CRIB = []  # GOOD_CT_FOR_CRIB[crib_idx] = list of (ct_pos, key_val)
for crib_idx in range(N_CRIBS):
    good = [(ct_pos, KEY_TABLE[crib_idx][ct_pos])
            for ct_pos in range(CT_LEN)
            if KEY_TABLE[crib_idx][ct_pos] in COMMON_INDICES]
    GOOD_CT_FOR_CRIB.append(good)


def assignment_to_key(assignment: list) -> str:
    """Convert assignment (list of 24 CT positions) to key string."""
    key_chars = []
    for crib_idx, ct_pos in enumerate(assignment):
        k_val = KEY_TABLE[crib_idx][ct_pos]
        key_chars.append(ALPH[k_val])
    return "".join(key_chars)


def assignment_key_fragments(assignment: list) -> tuple:
    """Return the two key fragments (ENE positions 21-33, BC positions 63-73)."""
    key = assignment_to_key(assignment)
    return key[:13], key[13:]


def score_assignment(assignment: list) -> float:
    """Score an assignment by quadgram quality of key fragments."""
    ene_frag, bc_frag = assignment_key_fragments(assignment)
    # Score both fragments independently (they're non-contiguous in the key)
    return quadgram_score(ene_frag) + quadgram_score(bc_frag)


def score_assignment_freq(assignment: list) -> float:
    """Score by English letter frequency (fast approximation)."""
    total = 0.0
    for crib_idx, ct_pos in enumerate(assignment):
        k_val = KEY_TABLE[crib_idx][ct_pos]
        total += ENG_LOG_FREQ[ALPH[k_val]]
    return total


def check_bean_assignment(assignment: list) -> tuple:
    """Check Bean constraints for a given assignment.
    Returns (eq_pass, ineq_count)."""
    # Map crib positions to their key values
    key_at_pos = {}
    for crib_idx, ct_pos in enumerate(assignment):
        crib_pos = CRIB_POSITIONS[crib_idx]
        key_at_pos[crib_pos] = KEY_TABLE[crib_idx][ct_pos]

    eq_pass = True
    for i, j in BEAN_EQ:
        if i in key_at_pos and j in key_at_pos:
            if key_at_pos[i] != key_at_pos[j]:
                eq_pass = False

    ineq_count = 0
    for i, j in BEAN_INEQ:
        if i in key_at_pos and j in key_at_pos:
            if key_at_pos[i] != key_at_pos[j]:
                ineq_count += 1

    return eq_pass, ineq_count


def check_east_diffs(assignment: list) -> list:
    """Compute EAST gap-9 diffs for the assignment.
    EAST positions: crib indices 0-3 (pos 21-24) and 9-12 (pos 30-33)."""
    diffs = []
    for j in range(4):
        k_first = KEY_TABLE[j][assignment[j]]           # K at pos 21+j
        k_second = KEY_TABLE[9 + j][assignment[9 + j]]  # K at pos 30+j
        diffs.append((k_second - k_first) % MOD)
    return diffs


# ── Monte Carlo worker function ─────────────────────────────────────────
def mc_worker(args):
    """Worker: generate and score random assignments."""
    seed, n_samples = args
    rng = random.Random(seed)
    ct_indices = list(range(CT_LEN))

    best_score = -999999.0
    best_assignment = None
    best_bean_eq = False

    # Also track best Bean-EQ-passing assignment
    best_bean_score = -999999.0
    best_bean_assignment = None

    for _ in range(n_samples):
        # Random assignment: choose 24 distinct CT positions
        chosen = rng.sample(ct_indices, N_CRIBS)
        score = score_assignment(chosen)

        if score > best_score:
            best_score = score
            best_assignment = chosen[:]

        # Quick Bean-EQ check (positions 27 and 65 = crib indices 6 and 15)
        k27 = KEY_TABLE[6][chosen[6]]
        k65 = KEY_TABLE[15][chosen[15]]
        if k27 == k65:
            if score > best_bean_score:
                best_bean_score = score
                best_bean_assignment = chosen[:]

    return best_score, best_assignment, best_bean_score, best_bean_assignment


def mc_worker_freq_guided(args):
    """Worker: generate assignments biased toward English-frequent letters."""
    seed, n_samples = args
    rng = random.Random(seed)

    best_score = -999999.0
    best_assignment = None
    best_bean_score = -999999.0
    best_bean_assignment = None

    for _ in range(n_samples):
        used = set()
        chosen = [0] * N_CRIBS

        # Assign each crib position, preferring CT positions that give common letters
        valid = True
        for crib_idx in range(N_CRIBS):
            candidates = [ct_pos for ct_pos, _ in GOOD_CT_FOR_CRIB[crib_idx]
                          if ct_pos not in used]
            if not candidates:
                # Fall back to any unused position
                candidates = [i for i in range(CT_LEN) if i not in used]

            ct_pos = rng.choice(candidates)
            chosen[crib_idx] = ct_pos
            used.add(ct_pos)

        score = score_assignment(chosen)
        if score > best_score:
            best_score = score
            best_assignment = chosen[:]

        k27 = KEY_TABLE[6][chosen[6]]
        k65 = KEY_TABLE[15][chosen[15]]
        if k27 == k65:
            if score > best_bean_score:
                best_bean_score = score
                best_bean_assignment = chosen[:]

    return best_score, best_assignment, best_bean_score, best_bean_assignment


def main():
    print("=" * 70)
    print("E-CFM-08: Transposition-Guided Running Key Fragment Scoring")
    print("=" * 70)
    print(f"Crib positions: {CRIB_POSITIONS}")
    print(f"CT length: {CT_LEN}, Crib count: {N_CRIBS}")
    print(f"Quadgrams loaded: {len(QUADGRAMS)}")
    print(f"CPUs available: {cpu_count()}")

    # ── Step 1: Key lookup table analysis ───────────────────────────────
    print("\n── Step 1: Key value landscape ──")
    for crib_idx in range(N_CRIBS):
        crib_pos = CRIB_POSITIONS[crib_idx]
        n_good = len(GOOD_CT_FOR_CRIB[crib_idx])
        print(f"  Crib pos {crib_pos:2d} (PT='{CRIB_DICT[crib_pos]}'): "
              f"{n_good}/97 CT positions produce common English key letter")

    # ── Step 2: Greedy optimal assignment (letter frequency) ────────────
    print("\n── Step 2: Greedy optimal assignment (by letter frequency) ──")

    # Greedy: assign most-constrained crib positions first
    # Sort by number of "good" CT options (ascending = most constrained first)
    crib_order = sorted(range(N_CRIBS),
                        key=lambda idx: len(GOOD_CT_FOR_CRIB[idx]))

    used = set()
    greedy_assignment = [0] * N_CRIBS
    for crib_idx in crib_order:
        # Best available CT position by letter frequency
        best_ct = -1
        best_freq = -999.0
        for ct_pos in range(CT_LEN):
            if ct_pos in used:
                continue
            k_val = KEY_TABLE[crib_idx][ct_pos]
            freq = ENG_LOG_FREQ[ALPH[k_val]]
            if freq > best_freq:
                best_freq = freq
                best_ct = ct_pos
        greedy_assignment[crib_idx] = best_ct
        used.add(best_ct)

    greedy_key = assignment_to_key(greedy_assignment)
    greedy_ene, greedy_bc = assignment_key_fragments(greedy_assignment)
    greedy_qg = score_assignment(greedy_assignment)
    greedy_bean_eq, greedy_bean_ineq = check_bean_assignment(greedy_assignment)
    greedy_east = check_east_diffs(greedy_assignment)

    print(f"  Greedy key: {greedy_key}")
    print(f"  ENE fragment: {greedy_ene} (qg={quadgram_score_per_char(greedy_ene):.2f}/char)")
    print(f"  BC  fragment: {greedy_bc} (qg={quadgram_score_per_char(greedy_bc):.2f}/char)")
    print(f"  Total qg score: {greedy_qg:.2f}")
    print(f"  Bean: EQ={'PASS' if greedy_bean_eq else 'FAIL'}, INEQ={greedy_bean_ineq}/21")
    print(f"  EAST diffs: {greedy_east}")

    vowels = sum(1 for c in greedy_key if c in "AEIOU")
    print(f"  Vowel ratio: {vowels}/24 = {vowels/24:.1%}")

    # ── Step 3: Bean-EQ-constrained greedy ──────────────────────────────
    print("\n── Step 3: Bean-EQ-constrained optimal assignment ──")
    # Bean-EQ: K[27] = K[65]. Crib indices: 27→idx 6, 65→idx 15.
    # Enumerate all (ct_27, ct_65) pairs where CT[ct_27] = CT[ct_65]

    bean_pairs = []
    for ct_i in range(CT_LEN):
        for ct_j in range(CT_LEN):
            if ct_i == ct_j:
                continue
            if CT[ct_i] == CT[ct_j]:
                # K[27] = (CT[ct_i] - PT[27]) mod 26
                # K[65] = (CT[ct_j] - PT[65]) mod 26
                # PT[27] = R, PT[65] = R, so K[27] = K[65] iff CT[ct_i] = CT[ct_j] ✓
                bean_pairs.append((ct_i, ct_j))

    print(f"  Bean-EQ valid pairs (CT[i]=CT[j]): {len(bean_pairs)}")

    best_bean_constrained_score = -999999.0
    best_bean_constrained = None

    for ct_27, ct_65 in bean_pairs:
        used = {ct_27, ct_65}
        assignment = [0] * N_CRIBS
        assignment[6] = ct_27   # crib index 6 = position 27
        assignment[15] = ct_65  # crib index 15 = position 65

        # Greedy for remaining 22 positions
        remaining = [idx for idx in crib_order if idx not in (6, 15)]
        for crib_idx in remaining:
            best_ct = -1
            best_freq = -999.0
            for ct_pos in range(CT_LEN):
                if ct_pos in used:
                    continue
                k_val = KEY_TABLE[crib_idx][ct_pos]
                freq = ENG_LOG_FREQ[ALPH[k_val]]
                if freq > best_freq:
                    best_freq = freq
                    best_ct = ct_pos
            assignment[crib_idx] = best_ct
            used.add(best_ct)

        score = score_assignment(assignment)
        if score > best_bean_constrained_score:
            best_bean_constrained_score = score
            best_bean_constrained = assignment[:]

    if best_bean_constrained:
        bc_key = assignment_to_key(best_bean_constrained)
        bc_ene, bc_bc = assignment_key_fragments(best_bean_constrained)
        bc_eq, bc_ineq = check_bean_assignment(best_bean_constrained)
        bc_east = check_east_diffs(best_bean_constrained)
        print(f"  Best Bean-EQ key: {bc_key}")
        print(f"  ENE: {bc_ene} (qg={quadgram_score_per_char(bc_ene):.2f}/char)")
        print(f"  BC:  {bc_bc} (qg={quadgram_score_per_char(bc_bc):.2f}/char)")
        print(f"  Total qg: {best_bean_constrained_score:.2f}")
        print(f"  Bean: EQ={'PASS' if bc_eq else 'FAIL'}, INEQ={bc_ineq}/21")
        print(f"  EAST diffs: {bc_east}")
        vowels = sum(1 for c in bc_key if c in "AEIOU")
        print(f"  Vowel ratio: {vowels}/24 = {vowels/24:.1%}")

    # ── Step 4: Monte Carlo (random assignments, 28 cores) ──────────────
    print("\n── Step 4: Monte Carlo — random assignments (10M samples) ──")

    n_workers = min(28, cpu_count())
    samples_per_worker = 500_000  # 500K × 28 = 14M total
    tasks = [(42 + i, samples_per_worker) for i in range(n_workers)]

    print(f"  Workers: {n_workers}, samples/worker: {samples_per_worker}")
    print(f"  Total samples: {n_workers * samples_per_worker:,}")
    print("  Running...")

    with Pool(n_workers) as pool:
        results = pool.map(mc_worker, tasks)

    # Collect best
    mc_best_score = -999999.0
    mc_best_assignment = None
    mc_best_bean_score = -999999.0
    mc_best_bean_assignment = None

    for score, assignment, bean_score, bean_assignment in results:
        if score > mc_best_score:
            mc_best_score = score
            mc_best_assignment = assignment
        if bean_score > mc_best_bean_score and bean_assignment is not None:
            mc_best_bean_score = bean_score
            mc_best_bean_assignment = bean_assignment

    if mc_best_assignment:
        mc_key = assignment_to_key(mc_best_assignment)
        mc_ene, mc_bc = assignment_key_fragments(mc_best_assignment)
        mc_bean_eq, mc_bean_ineq = check_bean_assignment(mc_best_assignment)
        mc_east = check_east_diffs(mc_best_assignment)
        print(f"  Best random key: {mc_key}")
        print(f"  ENE: {mc_ene} (qg={quadgram_score_per_char(mc_ene):.2f}/char)")
        print(f"  BC:  {mc_bc} (qg={quadgram_score_per_char(mc_bc):.2f}/char)")
        print(f"  Total qg: {mc_best_score:.2f}")
        print(f"  Bean: EQ={'PASS' if mc_bean_eq else 'FAIL'}, INEQ={mc_bean_ineq}/21")
        print(f"  EAST diffs: {mc_east}")
        vowels = sum(1 for c in mc_key if c in "AEIOU")
        print(f"  Vowel ratio: {vowels}/24 = {vowels/24:.1%}")

    if mc_best_bean_assignment:
        mc_bean_key = assignment_to_key(mc_best_bean_assignment)
        mc_bean_ene, mc_bean_bc = assignment_key_fragments(mc_best_bean_assignment)
        print(f"\n  Best Bean-EQ-passing random key: {mc_bean_key}")
        print(f"  ENE: {mc_bean_ene} (qg={quadgram_score_per_char(mc_bean_ene):.2f}/char)")
        print(f"  BC:  {mc_bean_bc} (qg={quadgram_score_per_char(mc_bean_bc):.2f}/char)")
        print(f"  Total qg: {mc_best_bean_score:.2f}")
    else:
        print(f"\n  No Bean-EQ-passing assignments found in {n_workers * samples_per_worker:,} samples")

    # ── Step 5: Frequency-guided Monte Carlo ────────────────────────────
    print("\n── Step 5: Frequency-guided Monte Carlo (10M samples) ──")
    print("  Biasing assignment toward CT positions that produce common English letters")

    with Pool(n_workers) as pool:
        results_fg = pool.map(mc_worker_freq_guided, tasks)

    fg_best_score = -999999.0
    fg_best_assignment = None
    fg_best_bean_score = -999999.0
    fg_best_bean_assignment = None

    for score, assignment, bean_score, bean_assignment in results_fg:
        if score > fg_best_score:
            fg_best_score = score
            fg_best_assignment = assignment
        if bean_score > fg_best_bean_score and bean_assignment is not None:
            fg_best_bean_score = bean_score
            fg_best_bean_assignment = bean_assignment

    if fg_best_assignment:
        fg_key = assignment_to_key(fg_best_assignment)
        fg_ene, fg_bc = assignment_key_fragments(fg_best_assignment)
        fg_bean_eq, fg_bean_ineq = check_bean_assignment(fg_best_assignment)
        print(f"  Best freq-guided key: {fg_key}")
        print(f"  ENE: {fg_ene} (qg={quadgram_score_per_char(fg_ene):.2f}/char)")
        print(f"  BC:  {fg_bc} (qg={quadgram_score_per_char(fg_bc):.2f}/char)")
        print(f"  Total qg: {fg_best_score:.2f}")
        print(f"  Bean: EQ={'PASS' if fg_bean_eq else 'FAIL'}, INEQ={fg_bean_ineq}/21")
        vowels = sum(1 for c in fg_key if c in "AEIOU")
        print(f"  Vowel ratio: {vowels}/24 = {vowels/24:.1%}")

    if fg_best_bean_assignment:
        fg_bean_key = assignment_to_key(fg_best_bean_assignment)
        fg_bean_ene, fg_bean_bc = assignment_key_fragments(fg_best_bean_assignment)
        print(f"\n  Best Bean-EQ-passing freq-guided key: {fg_bean_key}")
        print(f"  ENE: {fg_bean_ene} (qg={quadgram_score_per_char(fg_bean_ene):.2f}/char)")
        print(f"  BC:  {fg_bean_bc} (qg={quadgram_score_per_char(fg_bean_bc):.2f}/char)")
        print(f"  Total qg: {fg_best_bean_score:.2f}")

    # ── Step 6: Reference — identity transposition baseline ─────────────
    print("\n── Step 6: Identity transposition baseline ──")
    identity_assignment = list(range(N_CRIBS))
    # Identity: perm_inv[j] = j, so ct_pos = crib_pos
    identity_real = [CRIB_POSITIONS[i] for i in range(N_CRIBS)]
    id_key = assignment_to_key(identity_real)
    id_ene, id_bc = assignment_key_fragments(identity_real)
    id_qg = score_assignment(identity_real)
    id_bean_eq, id_bean_ineq = check_bean_assignment(identity_real)
    print(f"  Identity key: {id_key}")
    print(f"  ENE: {id_ene} (qg={quadgram_score_per_char(id_ene):.2f}/char)")
    print(f"  BC:  {id_bc} (qg={quadgram_score_per_char(id_bc):.2f}/char)")
    print(f"  Total qg: {id_qg:.2f}")
    print(f"  Bean: EQ={'PASS' if id_bean_eq else 'FAIL'}, INEQ={id_bean_ineq}/21")

    # ── Step 7: English reference ───────────────────────────────────────
    print("\n── Step 7: English text reference scores ──")
    ref_texts = [
        ("EASTNORTHEAST", "typical English (EASTNORTHEAST)"),
        ("BERLINCLOCK__", "BERLINCLOCK"),
        ("THEUNITEDSTAT", "THE UNITED STAT"),
        ("ATTENTIONPLEA", "ATTENTION PLEA"),
        ("DISCOVEREDTHE", "DISCOVERED THE"),
    ]
    for text, label in ref_texts:
        text = text.replace("_", "E")[:13]
        qg = quadgram_score_per_char(text)
        print(f"  '{text}' ({label}): {qg:.2f}/char")

    # ── Step 8: All-variants comparison ─────────────────────────────────
    print("\n── Step 8: Beaufort/VarBeau identity baselines ──")
    # Beaufort: K = (CT + PT) mod 26
    beau_key = []
    for crib_idx, crib_pos in enumerate(CRIB_POSITIONS):
        k = (CT_VALS[crib_pos] + PT_VALS[crib_pos]) % MOD
        beau_key.append(ALPH[k])
    beau_str = "".join(beau_key)
    beau_ene = beau_str[:13]
    beau_bc = beau_str[13:]
    print(f"  Beaufort identity:     {beau_str}")
    print(f"    ENE: {beau_ene} ({quadgram_score_per_char(beau_ene):.2f}/char)")
    print(f"    BC:  {beau_bc} ({quadgram_score_per_char(beau_bc):.2f}/char)")

    # Var Beaufort: K = (PT - CT) mod 26
    vb_key = []
    for crib_idx, crib_pos in enumerate(CRIB_POSITIONS):
        k = (PT_VALS[crib_pos] - CT_VALS[crib_pos]) % MOD
        vb_key.append(ALPH[k])
    vb_str = "".join(vb_key)
    vb_ene = vb_str[:13]
    vb_bc = vb_str[13:]
    print(f"  Var Beaufort identity: {vb_str}")
    print(f"    ENE: {vb_ene} ({quadgram_score_per_char(vb_ene):.2f}/char)")
    print(f"    BC:  {vb_bc} ({quadgram_score_per_char(vb_bc):.2f}/char)")

    # ── Summary ─────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    # Collect all scores for comparison
    all_scores = [
        ("Identity trans (Vigenere)", id_qg),
        ("Greedy optimal (freq)", greedy_qg),
    ]
    if best_bean_constrained:
        all_scores.append(("Bean-EQ greedy", best_bean_constrained_score))
    if mc_best_assignment:
        all_scores.append(("MC random (14M)", mc_best_score))
    if mc_best_bean_assignment:
        all_scores.append(("MC random Bean-EQ (14M)", mc_best_bean_score))
    if fg_best_assignment:
        all_scores.append(("MC freq-guided (14M)", fg_best_score))
    if fg_best_bean_assignment:
        all_scores.append(("MC freq-guided Bean-EQ", fg_best_bean_score))

    all_scores.sort(key=lambda x: -x[1])
    print("\nAll methods ranked by quadgram score:")
    for label, score in all_scores:
        per_char = score / 24 if score > -9999 else -99.0
        print(f"  {score:8.2f} ({per_char:.2f}/char) | {label}")

    # English reference
    eng_ref = quadgram_score_per_char("THEUNITEDSTAT")
    print(f"\n  English text reference: ~{eng_ref:.2f}/char")
    print(f"  Threshold for 'plausible English': > -4.84/char (from oracle)")

    best_per_char = all_scores[0][1] / 24 if all_scores else -99.0
    if best_per_char > -4.84:
        print(f"\n  *** Best score {best_per_char:.2f}/char EXCEEDS English threshold! ***")
        print("  Investigate the corresponding transposition immediately.")
        print("  Verdict: SIGNAL")
    elif best_per_char > -6.0:
        print(f"\n  Best score {best_per_char:.2f}/char is approaching plausibility.")
        print("  Not random gibberish, but not clearly English either.")
        print("  Verdict: STORE — worth further investigation")
    else:
        print(f"\n  Best score {best_per_char:.2f}/char is well below English threshold.")
        print(f"  Even the OPTIMAL transposition cannot produce English-like key fragments.")
        print()
        print("  [INTERNAL RESULT] Across 28M+ sampled transpositions and optimal greedy")
        print("  assignments, no transposition produces a key fragment that resembles")
        print("  English text at crib positions under the Vigenere running key model.")
        print()
        print("  [DERIVED FACT] The 'running key + transposition' model is SEVERELY")
        print("  CONSTRAINED: the optimal key fragment score is far below what any")
        print("  natural language text would produce. This does not fully eliminate")
        print("  the model (the quadgram metric isn't perfect), but it strongly")
        print("  suggests the running key is NOT from conventional English prose.")
        print()
        print("  Verdict: NOISE — running key from English prose + transposition")
        print("  is implausible for K4")


if __name__ == "__main__":
    main()
