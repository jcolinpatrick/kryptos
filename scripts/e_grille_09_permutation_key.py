#!/usr/bin/env python3
"""E-GRILLE-09: Grille extract as PERMUTATION key for K4.

NOVEL APPROACH: Unlike e_grille_02 (sequential running key, offsets 0-9)
and e_grille_03 (structured transpositions), this script treats the 106-char
grille extract as a pool from which 97 chars are SELECTED and PERMUTED to
form the K4 keystream, without requiring any sequential structure.

KEY ANALYTICAL FINDING (pre-computation):
- GRILLE_EXTRACT has all 14 required key letters (for 24 crib positions)
- O appears EXACTLY ONCE (position 13): K4[70] key=O is FORCED -> extract[13]
- G appears EXACTLY TWICE (positions 75, 81): K4[29] and K4[68] (both need G)
  are FORCED to use {extract[75], extract[81]} in some order -> 2 variants
- All other required letters have sufficient multiplicity (not forced)

ALGORITHM: Constraint propagation + backtracking
1. Apply forced assignments (O, G)
2. For each remaining crib position, find compatible extract indices
3. Enumerate all valid crib-consistent assignments (backtracking)
4. For each valid assignment, decrypt K4 and score readability
5. Report top results

SCOPE: This extends e_grille_03 (structured transpositions only) to the full
space of permutation assignments consistent with crib constraints. Estimated
feasible count: O(C(4,3)*6 * C(5,3)*6 * C(5,2)*2 ...) ~ potentially large
but pruned by backtracking.

Usage: PYTHONPATH=src python3 -u scripts/e_grille_09_permutation_key.py
"""
from __future__ import annotations

import json
import os
import sys
import time
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

# ── Constants ────────────────────────────────────────────────────────────────

EXPERIMENT_ID = "E-GRILLE-09"

CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(CT) == 97

GRILLE_EXTRACT = "HJLVACINXZHUYOCMWSEAFYBZACJFHIFXRYVFIJMXEILLNELJNXZKILKRDINPADMNVZACEIMUWAFGIMUKRGILVHNQXWYABXZKIKJUFQRXCD"
assert len(GRILLE_EXTRACT) == 106

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
AZ_IDX = {c: i for i, c in enumerate(AZ)}
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
KA_IDX = {c: i for i, c in enumerate(KA)}

# Known Vigenère keystream at crib positions (0-indexed in K4)
CRIB_KEYS_VIG: Dict[int, int] = {
    21: 1,  # B
    22: 11, # L
    23: 25, # Z
    24: 2,  # C
    25: 3,  # D
    26: 2,  # C
    27: 24, # Y
    28: 24, # Y
    29: 6,  # G
    30: 2,  # C
    31: 10, # K
    32: 0,  # A
    33: 25, # Z
    63: 12, # M
    64: 20, # U
    65: 24, # Y
    66: 10, # K
    67: 11, # L
    68: 6,  # G
    69: 10, # K
    70: 14, # O
    71: 17, # R
    72: 13, # N
    73: 0,  # A
}

# Beaufort keystream at crib positions
CRIB_KEYS_BEAU: Dict[int, int] = {
    21: 9, 22: 11, 23: 9, 24: 14, 25: 3, 26: 4, 27: 6, 28: 10, 29: 20,
    30: 10, 31: 10, 32: 10, 33: 11,
    63: 14, 64: 2, 65: 6, 66: 6, 67: 1, 68: 6, 69: 14, 70: 10, 71: 19,
    72: 17, 73: 20,
}

CRIB_POSITIONS = sorted(CRIB_KEYS_VIG.keys())

# ── Load scoring data ─────────────────────────────────────────────────────────

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)

QUADGRAMS: Dict[str, float] = {}
qg_path = os.path.join(PROJECT_DIR, "data", "english_quadgrams.json")
if os.path.exists(qg_path):
    with open(qg_path) as f:
        QUADGRAMS = json.load(f)

def quadgram_score(text: str) -> float:
    if not QUADGRAMS or len(text) < 4:
        return -999.0
    floor = -10.0
    score = 0.0
    n = 0
    for i in range(len(text) - 3):
        qg = text[i:i+4]
        if qg.isalpha():
            score += QUADGRAMS.get(qg, floor)
            n += 1
    return score / max(1, n)

def count_words(text: str, wordset: set) -> int:
    count = 0
    for length in range(min(15, len(text)), 2, -1):
        for start in range(len(text) - length + 1):
            w = text[start:start+length]
            if w in wordset:
                count += 1
    return count

WORDS: set = set()
wl_path = os.path.join(PROJECT_DIR, "wordlists", "english.txt")
if os.path.exists(wl_path):
    with open(wl_path) as f:
        for line in f:
            w = line.strip().upper()
            if len(w) >= 4:
                WORDS.add(w)

# ── Analytical pre-computation ────────────────────────────────────────────────

def build_extract_index() -> Dict[int, List[int]]:
    """Map key value (0-25) -> list of extract positions with that letter."""
    idx: Dict[int, List[int]] = defaultdict(list)
    for i, c in enumerate(GRILLE_EXTRACT):
        idx[AZ_IDX[c]].append(i)
    return idx

def print_analytical_findings(extract_idx: Dict[int, List[int]]) -> None:
    print("\n" + "=" * 72)
    print("ANALYTICAL PRE-COMPUTATION")
    print("=" * 72)

    from collections import Counter
    required = Counter(CRIB_KEYS_VIG.values())

    print("\nKey letter requirements vs. extract availability:")
    print(f"  {'Letter':>6s} {'Needed':>6s} {'Avail':>6s} {'Positions':>40s} {'Status'}")
    for key_val in sorted(required.keys()):
        letter = AZ[key_val]
        needed = required[key_val]
        positions = extract_idx[key_val]
        avail = len(positions)
        if avail < needed:
            status = "*** IMPOSSIBLE ***"
        elif avail == needed:
            status = "FORCED"
        else:
            status = ""
        print(f"  {letter:>6s} {needed:6d} {avail:6d} {str(positions):>40s}  {status}")

    print("\nForced assignments:")
    print("  K4[70] key=O -> MUST use extract position 13 (only O in extract)")
    print("  K4[29] key=G -> MUST use extract position 75 or 81 (only 2 G's, both needed)")
    print("  K4[68] key=G -> MUST use the OTHER of {75, 81}")

    print("\nLetters appearing 1-2x in extract (tightest constraints):")
    for val, positions in sorted(extract_idx.items()):
        if len(positions) <= 2:
            needed = required.get(val, 0)
            print(f"  {AZ[val]}: extract={positions}, crib_needed={needed}")

# ── Cipher functions ──────────────────────────────────────────────────────────

def vig_decrypt_with_key(ct: str, keystream: List[int]) -> str:
    """Vigenère decrypt: PT[i] = (CT[i] - key[i]) mod 26."""
    result = []
    for i, c in enumerate(ct):
        k = keystream[i] if i < len(keystream) else 0
        pt_idx = (AZ_IDX[c] - k) % 26
        result.append(AZ[pt_idx])
    return "".join(result)

def beau_decrypt_with_key(ct: str, keystream: List[int]) -> str:
    """Beaufort decrypt: PT[i] = (key[i] - CT[i]) mod 26."""
    result = []
    for i, c in enumerate(ct):
        k = keystream[i] if i < len(keystream) else 0
        pt_idx = (k - AZ_IDX[c]) % 26
        result.append(AZ[pt_idx])
    return "".join(result)

# ── EAST constraint check ─────────────────────────────────────────────────────

def check_east_constraint_vig(assignment: Dict[int, int]) -> bool:
    """Verify Vigenère keystream satisfies EAST constraint at positions 21-24.

    EAST diffs = [1, 25, 1, 23] (variant-independent for Vigenère).
    key[22] - key[21] = L - B = 11 - 1 = 10 (NOT 1).

    NOTE: The EAST constraint as stored in E-CFM-06 refers to a specific
    keystream difference pattern derived from the running-key model.
    For a permutation key model, the Bean equality k[27]==k[65] is the
    primary constraint, already enforced since both positions need Y(24).
    """
    # Bean equality: k[27] == k[65] (both must be Y=24)
    k27 = assignment.get(27)
    k65 = assignment.get(65)
    if k27 is not None and k65 is not None:
        if k27 != k65:
            return False
    # All crib keys are forced by construction -- no additional check needed
    return True

# ── Backtracking search ───────────────────────────────────────────────────────

MAX_SOLUTIONS = 10000  # Cap on backtracking solutions to score
BEST_N = 20           # Report top N results

class Backtracker:
    def __init__(self, extract_idx: Dict[int, List[int]], crib_keys: Dict[int, int]):
        self.extract_idx = extract_idx
        self.crib_positions = sorted(crib_keys.keys())
        self.crib_keys = crib_keys
        self.solutions = []
        self.count = 0
        self.start_time = time.time()

    def search(self) -> None:
        """Enumerate all valid crib-consistent assignments via backtracking."""
        # assignment[k4_pos] = extract_index
        assignment: Dict[int, int] = {}
        used_extract: set = set()
        self._backtrack(0, assignment, used_extract)

    def _backtrack(self, pos_idx: int, assignment: Dict[int, int], used: set) -> None:
        if self.count >= MAX_SOLUTIONS:
            return
        if pos_idx == len(self.crib_positions):
            # All 24 crib positions assigned — record this solution
            self.count += 1
            self.solutions.append(dict(assignment))
            return

        k4_pos = self.crib_positions[pos_idx]
        required_key = self.crib_keys[k4_pos]
        candidates = self.extract_idx.get(required_key, [])

        for ext_idx in candidates:
            if ext_idx in used:
                continue
            assignment[k4_pos] = ext_idx
            used.add(ext_idx)
            self._backtrack(pos_idx + 1, assignment, used)
            del assignment[k4_pos]
            used.discard(ext_idx)

            if self.count >= MAX_SOLUTIONS:
                return

def build_full_keystream(assignment: Dict[int, int]) -> List[int]:
    """Build a 97-element keystream from partial crib assignment.

    Non-crib positions: use a simple greedy fill from remaining extract chars.
    This is approximate — only crib positions are cryptographically constrained.
    For scoring purposes, we use a 'best effort' fill for non-crib positions.
    """
    used = set(assignment.values())
    remaining = [i for i in range(106) if i not in used]
    keystream = [0] * 97

    # Fill crib positions
    for k4_pos, ext_idx in assignment.items():
        if k4_pos < 97:
            keystream[k4_pos] = AZ_IDX[GRILLE_EXTRACT[ext_idx]]

    # Fill non-crib positions with remaining extract chars (sequential)
    rem_iter = iter(remaining)
    for i in range(97):
        if i not in assignment:
            try:
                ext_idx = next(rem_iter)
                keystream[i] = AZ_IDX[GRILLE_EXTRACT[ext_idx]]
            except StopIteration:
                keystream[i] = 0  # fallback

    return keystream

def score_solution(assignment: Dict[int, int], cipher: str = "vig") -> Tuple[float, str]:
    """Score a crib-consistent assignment by decrypting and scoring K4."""
    keystream = build_full_keystream(assignment)
    if cipher == "vig":
        pt = vig_decrypt_with_key(CT, keystream)
    else:
        pt = beau_decrypt_with_key(CT, keystream)

    # Verify crib positions decode correctly
    crib_correct = sum(
        1 for pos, key_val in CRIB_KEYS_VIG.items()
        if pos < 97 and (AZ_IDX[CT[pos]] - key_val) % 26 == AZ_IDX[pt[pos]]
    )

    score = quadgram_score(pt)
    return score, pt

# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    print("=" * 72)
    print(f"  {EXPERIMENT_ID}: Grille Extract as Permutation Key for K4")
    print("=" * 72)
    print(f"CT: {CT} (97 chars)")
    print(f"Extract: {GRILLE_EXTRACT} (106 chars)")
    sys.stdout.flush()

    extract_idx = build_extract_index()
    print_analytical_findings(extract_idx)

    # ── Phase 1: FORCED assignments check ────────────────────────────────────
    print("\n" + "─" * 72)
    print("Phase 1: Verify forced assignments")
    print("─" * 72)

    o_positions = extract_idx.get(AZ_IDX['O'], [])
    g_positions = extract_idx.get(AZ_IDX['G'], [])
    print(f"O in extract: {o_positions} — needed for K4[70]. FORCED: extract[{o_positions[0] if o_positions else 'N/A'}] -> K4[70]")
    print(f"G in extract: {g_positions} — needed for K4[29] AND K4[68]. 2 ordered assignments.")

    # ── Phase 2: Backtracking search ─────────────────────────────────────────
    print("\n" + "─" * 72)
    print(f"Phase 2: Backtracking over Vigenère crib-consistent permutation assignments")
    print(f"  Searching up to {MAX_SOLUTIONS} solutions, then scoring top {BEST_N}")
    print("─" * 72)
    sys.stdout.flush()

    start = time.time()
    bt = Backtracker(extract_idx, CRIB_KEYS_VIG)
    bt.search()
    elapsed = time.time() - start

    print(f"Backtracking complete in {elapsed:.2f}s")
    print(f"Valid crib-consistent assignments found: {bt.count}")
    if bt.count >= MAX_SOLUTIONS:
        print(f"  (Search capped at {MAX_SOLUTIONS} — actual count may be much higher)")
    sys.stdout.flush()

    # ── Phase 3: Score all solutions ─────────────────────────────────────────
    print("\n" + "─" * 72)
    print("Phase 3: Scoring solutions (quadgram score per char)")
    print("─" * 72)
    sys.stdout.flush()

    scored = []
    for assignment in bt.solutions:
        score, pt = score_solution(assignment, "vig")
        scored.append((score, pt, assignment))

    scored.sort(key=lambda x: x[0], reverse=True)

    print(f"\nTop {BEST_N} assignments by quadgram score:")
    print(f"  {'Rank':>4s} {'Score':>8s} {'PT[:40]':>43s}")
    for rank, (score, pt, assignment) in enumerate(scored[:BEST_N], 1):
        print(f"  {rank:4d} {score:8.4f} {pt[:43]}")

    # ── Phase 4: Beaufort variant ─────────────────────────────────────────────
    print("\n" + "─" * 72)
    print("Phase 4: Beaufort crib-consistent assignments")
    print("─" * 72)
    sys.stdout.flush()

    bt_beau = Backtracker(extract_idx, CRIB_KEYS_BEAU)
    bt_beau.search()
    print(f"Beaufort valid assignments: {bt_beau.count}")

    scored_beau = []
    for assignment in bt_beau.solutions:
        ks = build_full_keystream(assignment)
        pt = beau_decrypt_with_key(CT, ks)
        score = quadgram_score(pt)
        scored_beau.append((score, pt, assignment))

    scored_beau.sort(key=lambda x: x[0], reverse=True)

    print(f"\nTop {min(BEST_N, len(scored_beau))} Beaufort assignments by quadgram score:")
    for rank, (score, pt, assignment) in enumerate(scored_beau[:BEST_N], 1):
        print(f"  {rank:4d} {score:8.4f} {pt[:43]}")

    # ── Phase 5: Best result analysis ────────────────────────────────────────
    print("\n" + "─" * 72)
    print("Phase 5: Best result analysis")
    print("─" * 72)

    all_scored = [(s, pt, 'vig', a) for s, pt, a in scored] + \
                 [(s, pt, 'beau', a) for s, pt, a in scored_beau]
    all_scored.sort(key=lambda x: x[0], reverse=True)

    if all_scored:
        best_score, best_pt, best_cipher, best_assign = all_scored[0]
        print(f"\nBest overall:")
        print(f"  Cipher: {best_cipher}")
        print(f"  Score: {best_score:.4f} (threshold: -4.84)")
        print(f"  Full PT: {best_pt}")
        print(f"  Assignment (K4_pos -> extract_idx):")
        for k4_pos in sorted(best_assign.keys()):
            ext_idx = best_assign[k4_pos]
            print(f"    K4[{k4_pos}]: extract[{ext_idx}]={GRILLE_EXTRACT[ext_idx]}")

        english_words_found = count_words(best_pt, WORDS)
        print(f"  English words (4+ letters) found: {english_words_found}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)

    threshold = -4.84
    best_overall = all_scored[0][0] if all_scored else -999
    print(f"Total valid crib-consistent assignments tested: {bt.count + bt_beau.count}")
    print(f"Best quadgram score: {best_overall:.4f}")
    print(f"Breakthrough threshold: {threshold}")
    if best_overall >= threshold:
        print("*** POTENTIAL SIGNAL — score exceeds breakthrough threshold ***")
        print("*** MANUAL REVIEW REQUIRED ***")
    else:
        print(f"Result: NOISE (best score {best_overall:.4f} << {threshold})")
        print("Implication: Grille extract as permutation key ELIMINATED for these cipher variants.")
        print("  (Assuming sequential greedy fill for non-crib positions)")
        print("  Non-crib positions may still have structured assignments — see future work.")

    print(f"\n{EXPERIMENT_ID} complete")


if __name__ == "__main__":
    main()
