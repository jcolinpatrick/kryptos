#!/usr/bin/env python3
"""
Cipher: K4
Family: grille
Status: active
Keyspace: permutation_SA_abscissa_kryptos_constraints
Last run: 2026-03-05
Best score: TBD

Targeted K4 cryptanalysis under the paradigm:
  PT -> Vigenere(key) -> real_CT -> SCRAMBLE(sigma) -> K4_carved

Uses ABSCISSA/AZ and KRYPTOS/KA Vigenere constraints from known cribs
(EASTNORTHEAST at PT[21:34], BERLINCLOCK at PT[63:74]) plus self-encrypting
positions (K4[32]=PT[32]=S, K4[73]=PT[73]=K) to constrain the scrambling
permutation sigma.

Runs:
  Part 1 - Constraint-based permutation analysis
  Part 2 - SA on permutation with ABSCISSA/AZ Vigenere
  Part 3 - SA on permutation with KRYPTOS/KA Vigenere
  Part 4 - K1-rotation grille test (K4 pairs with K1 under 180deg rotation)
  Part 5 - Self-encrypting position exhaustive test over all key/cipher combos
"""

import json
import math
import random
import sys
import time
from collections import defaultdict
from pathlib import Path

# ─── Constants ───────────────────────────────────────────────────────────────

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
assert len(KA) == 26 and len(set(KA)) == 26

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4) == 97

# Cribs: PT[21:34]=EASTNORTHEAST (positions 21-33 inclusive, 13 chars)
#        PT[63:74]=BERLINCLOCK (positions 63-73 inclusive, 11 chars)
PT_KNOWN = {}
for i, ch in enumerate("EASTNORTHEAST"):
    PT_KNOWN[21 + i] = ch
for i, ch in enumerate("BERLINCLOCK"):
    PT_KNOWN[63 + i] = ch
# Self-encrypting: PT[32]=S, PT[73]=K (both are K4 positions too)
PT_KNOWN[32] = 'S'
PT_KNOWN[73] = 'K'
# Verify crib consistency
assert PT_KNOWN[32] == 'S'   # EASTNORTHEAST[11] == 'S'
assert PT_KNOWN[73] == 'K'   # BERLINCLOCK[10] == 'K'

# Build AZ->KA permutation cycles
def build_cycles():
    visited = set()
    cycles = []
    for start in AZ:
        if start in visited:
            continue
        cycle = []
        c = start
        while c not in visited:
            visited.add(c)
            cycle.append(c)
            c = AZ[AZ.index(c)]  # next in AZ is itself — wrong, use AZ->KA
            # Actually: AZ->KA perm maps AZ[i] -> KA[i]
            # so next = KA[AZ.index(prev)]
            break
        # Restart correctly
        cycle = []
        c = start
        while c not in visited:
            visited.add(c)
            cycle.append(c)
            c = KA[AZ.index(c)]
        cycles.append(cycle)
    return cycles

def build_az_ka_cycles():
    """AZ->KA permutation: letter L maps to KA[AZ.index(L)]."""
    visited = set()
    cycles = []
    for start in AZ:
        if start in visited:
            continue
        cycle = []
        c = start
        while c not in visited:
            visited.add(c)
            cycle.append(c)
            c = KA[AZ.index(c)]
        cycles.append(cycle)
    return cycles

ALL_CYCLES = build_az_ka_cycles()
C17 = set()
C8 = set()
C1 = set()
for cyc in ALL_CYCLES:
    if len(cyc) == 17:
        C17 = set(cyc)
    elif len(cyc) == 8:
        C8 = set(cyc)
    elif len(cyc) == 1:
        C1 = set(cyc)

assert len(C17) == 17, f"C17 len={len(C17)}"
assert len(C8) == 8, f"C8 len={len(C8)}"
assert 'Z' in C1

print("=" * 70)
print("K4 TARGETED PERMUTATION ANALYSIS — blitz_wildcard_grille2.py")
print("=" * 70)
print(f"K4 ({len(K4)} chars): {K4}")
print(f"C17: {sorted(C17)}")
print(f"C8:  {sorted(C8)}")
print(f"C1:  {sorted(C1)}")
print(f"Known PT positions: {sorted(PT_KNOWN.keys())} ({len(PT_KNOWN)} total)")

# ─── Quadgram scorer ─────────────────────────────────────────────────────────

def load_quadgrams(path=None):
    if path is None:
        path = str(Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json")
    with open(path) as f:
        raw = json.load(f)
    if all(v <= 0 for v in list(raw.values())[:10]):
        floor = min(raw.values()) - 1.0
        return raw, floor
    total = sum(raw.values())
    log_probs = {k: math.log10(v / total) for k, v in raw.items()}
    floor = math.log10(0.01 / total)
    return log_probs, floor

print("\nLoading quadgrams...")
QG, QG_FLOOR = load_quadgrams()
print(f"Loaded {len(QG)} quadgrams, floor={QG_FLOOR:.3f}")

def qscore(text):
    """Quadgram score per character."""
    t = ''.join(c for c in text.upper() if c in AZ)
    if len(t) < 4:
        return -10.0
    s = sum(QG.get(t[i:i+4], QG_FLOOR) for i in range(len(t) - 3))
    return s / max(1, len(t) - 3)

# English baseline
ENGLISH_SAMPLE = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
ENG_SCORE = qscore(ENGLISH_SAMPLE)
print(f"English baseline score: {qscore('YESNOWONDERFULTHINGS'):.3f}")

SCORE_INTERESTING = -5.0
SCORE_STRONG = -4.5

# ─── Vigenere cipher functions ───────────────────────────────────────────────

def az_vig_encrypt(pt, key):
    """AZ Vigenere encrypt: CT[i] = AZ[(AZ.index(PT[i]) + AZ.index(key[i%k])) % 26]"""
    result = []
    ki = 0
    for c in pt:
        if c not in AZ:
            result.append(c)
            continue
        shift = AZ.index(key[ki % len(key)])
        result.append(AZ[(AZ.index(c) + shift) % 26])
        ki += 1
    return ''.join(result)

def az_vig_decrypt(ct, key):
    """AZ Vigenere decrypt."""
    result = []
    ki = 0
    for c in ct:
        if c not in AZ:
            result.append(c)
            continue
        shift = AZ.index(key[ki % len(key)])
        result.append(AZ[(AZ.index(c) - shift) % 26])
        ki += 1
    return ''.join(result)

def az_beau_decrypt(ct, key):
    """AZ Beaufort decrypt: PT = (KEY - CT) % 26."""
    result = []
    ki = 0
    for c in ct:
        if c not in AZ:
            result.append(c)
            continue
        k_idx = AZ.index(key[ki % len(key)])
        result.append(AZ[(k_idx - AZ.index(c)) % 26])
        ki += 1
    return ''.join(result)

def ka_vig_encrypt(pt, key):
    """KA Vigenere encrypt: CT[i] = KA[(KA.index(PT[i]) + KA.index(key[i%k])) % 26]"""
    result = []
    ki = 0
    for c in pt:
        if c not in AZ and c not in KA:
            result.append(c)
            continue
        c_idx = KA.index(c) if c in KA else AZ.index(c)
        k_letter = key[ki % len(key)]
        k_idx = KA.index(k_letter) if k_letter in KA else AZ.index(k_letter)
        result.append(KA[(c_idx + k_idx) % 26])
        ki += 1
    return ''.join(result)

def ka_vig_decrypt(ct, key):
    """KA Vigenere decrypt."""
    result = []
    ki = 0
    for c in ct:
        if c not in KA and c not in AZ:
            result.append(c)
            continue
        c_idx = KA.index(c) if c in KA else AZ.index(c)
        k_letter = key[ki % len(key)]
        k_idx = KA.index(k_letter) if k_letter in KA else AZ.index(k_letter)
        result.append(KA[(c_idx - k_idx) % 26])
        ki += 1
    return ''.join(result)

# ─── Part 5 (done first — fast exhaustive check) ──────────────────────────────

print("\n" + "=" * 70)
print("PART 5: Self-Encrypting Position Exhaustive Test")
print("=" * 70)
print("Testing all (key, cipher) combinations for consistency with:")
print("  sigma(32)=32  (K4[32]=S=real_CT[32]  => PT[32]=S encrypted gives S)")
print("  tau(67)=73    (K4[73]=K=real_CT[67]   => PT[67]=I encrypted gives K)")
print()

# PT[32]=S, key position 32 mod keylen, K4[32]=S
# PT[67]=I (BERLINCLOCK[4]='I'), K4[73]=K

KEYS_TO_TEST = ["KRYPTOS", "ABSCISSA", "PALIMPSEST", "SHADOW", "BERLIN", "CLOCK"]
CIPHER_FUNS = [
    ("AZ-Vig-E",   lambda pt, key: az_vig_encrypt(pt, key)),
    ("AZ-Vig-D",   lambda pt, key: az_vig_decrypt(pt, key)),
    ("AZ-Beau-D",  lambda pt, key: az_beau_decrypt(pt, key)),
    ("KA-Vig-E",   lambda pt, key: ka_vig_encrypt(pt, key)),
    ("KA-Vig-D",   lambda pt, key: ka_vig_decrypt(pt, key)),
]

constraint_matches = []

for key in KEYS_TO_TEST:
    for fn_name, fn in CIPHER_FUNS:
        # Check sigma(32)=32: encrypt PT[32]='S' at position 32, result should = K4[32]='S'
        s_single = fn('S', key[32 % len(key)])[0] if len(fn('S', key[32 % len(key)])) > 0 else '?'
        # Actually: apply fn to single char 'S' using key shifted to position 32
        # Build single-char string and apply with position offset

        # We need encrypt at position 32, so the key letter is key[32 % len(key)]
        # Simulate by prepending 32 null chars... or just do it directly:
        key_letter_32 = key[32 % len(key)]
        key_letter_67 = key[67 % len(key)]

        # For AZ-Vig: real_CT[i] = AZ[(AZ.index(PT[i]) + AZ.index(key[i%k])) % 26]
        if 'AZ-Vig-E' in fn_name:
            real_ct_32 = AZ[(AZ.index('S') + AZ.index(key_letter_32)) % 26]
            real_ct_67 = AZ[(AZ.index('I') + AZ.index(key_letter_67)) % 26]
        elif 'AZ-Vig-D' in fn_name:
            real_ct_32 = AZ[(AZ.index('S') - AZ.index(key_letter_32)) % 26]
            real_ct_67 = AZ[(AZ.index('I') - AZ.index(key_letter_67)) % 26]
        elif 'AZ-Beau' in fn_name:
            real_ct_32 = AZ[(AZ.index(key_letter_32) - AZ.index('S')) % 26]
            real_ct_67 = AZ[(AZ.index(key_letter_67) - AZ.index('I')) % 26]
        elif 'KA-Vig-E' in fn_name:
            real_ct_32 = KA[(KA.index('S') + KA.index(key_letter_32)) % 26]
            real_ct_67 = KA[(KA.index('I') + KA.index(key_letter_67)) % 26]
        elif 'KA-Vig-D' in fn_name:
            real_ct_32 = KA[(KA.index('S') - KA.index(key_letter_32)) % 26]
            real_ct_67 = KA[(KA.index('I') - KA.index(key_letter_67)) % 26]
        else:
            continue

        # Check constraint 1: real_CT[32] == K4[32] = 'S'  =>  sigma(32)=32
        c1_ok = (real_ct_32 == K4[32])  # K4[32]='S'
        # Check constraint 2: real_CT[67] == K4[73] = 'K'  =>  tau(67)=73
        c2_ok = (real_ct_67 == K4[73])  # K4[73]='K'

        status = ""
        if c1_ok and c2_ok:
            status = "*** BOTH MATCH ***"
        elif c1_ok:
            status = "C1 match (sigma(32)=32)"
        elif c2_ok:
            status = "C2 match (tau(67)=73)"

        print(f"  key={key:12s} cipher={fn_name:12s}  "
              f"real_CT[32]={real_ct_32} (need S: {'OK' if c1_ok else '--'})  "
              f"real_CT[67]={real_ct_67} (need K: {'OK' if c2_ok else '--'})  "
              f"{status}")

        if c1_ok or c2_ok:
            constraint_matches.append({
                'key': key, 'cipher': fn_name,
                'c1_ok': c1_ok, 'c2_ok': c2_ok,
                'real_ct_32': real_ct_32, 'real_ct_67': real_ct_67,
            })

print(f"\nTotal partial/full constraint matches: {len(constraint_matches)}")
both_matches = [m for m in constraint_matches if m['c1_ok'] and m['c2_ok']]
print(f"BOTH constraints satisfied: {len(both_matches)}")
for m in both_matches:
    print(f"  *** CONSTRAINT MATCH for key={m['key']}, cipher={m['cipher']}: sigma(32)=32, tau(67)=73 ***")

# ─── Part 1: Constraint-based Permutation Analysis (ABSCISSA/AZ) ─────────────

print("\n" + "=" * 70)
print("PART 1: Constraint-Based Permutation Analysis")
print("ABSCISSA / AZ Vigenere")
print("=" * 70)
print()
print("Paradigm: real_CT[i] = AZ[(AZ.index(PT[i]) + AZ.index(ABSCISSA[i%8])) % 26]")
print("tau = sigma^{-1}: K4[tau(i)] = real_CT[i]")
print()

ABSCISSA = "ABSCISSA"

# Compute real_CT for all known PT positions under ABSCISSA/AZ Vigenere
real_ct_abscissa = {}
for pos, pt_ch in PT_KNOWN.items():
    key_ch = ABSCISSA[pos % 8]
    shift = AZ.index(key_ch)
    rct = AZ[(AZ.index(pt_ch) + shift) % 26]
    real_ct_abscissa[pos] = rct

print("Known PT -> real_CT (ABSCISSA/AZ Vigenere):")
print(f"  {'pos':>4}  {'PT':>2}  {'key_ch':>6}  {'shift':>5}  {'real_CT':>7}  K4 positions with that letter")

k4_pos_by_letter = defaultdict(list)
for i, c in enumerate(K4):
    k4_pos_by_letter[c].append(i)

total_combos = 1
constraint_info = {}
for pos in sorted(real_ct_abscissa.keys()):
    rct = real_ct_abscissa[pos]
    key_ch = ABSCISSA[pos % 8]
    pt_ch = PT_KNOWN[pos]
    possible_tau = k4_pos_by_letter[rct]
    n = len(possible_tau)
    total_combos *= n
    constraint_info[pos] = {'pt': pt_ch, 'key_ch': key_ch, 'rct': rct, 'possible_tau': possible_tau}
    print(f"  {pos:>4}  {pt_ch:>2}  {key_ch:>6}  {AZ.index(key_ch):>5}  {rct:>7}  {possible_tau} ({n} options)")

print(f"\nTotal naive combinations (product of options): {total_combos:,}")
print("(Actual assignments are constrained by bijectivity of tau)")

# Verify the two derived fixed points:
print("\nFixed point checks:")
print(f"  sigma(32)=32: real_CT[32]={real_ct_abscissa[32]}, K4[32]={K4[32]}, match={real_ct_abscissa[32]==K4[32]}")
print(f"  tau(67)=73  : real_CT[67]={real_ct_abscissa[67]}, K4[73]={K4[73]}, match={real_ct_abscissa[67]==K4[73]}")

# Compute real_CT for BERLINCLOCK + EASTNORTHEAST for display
print("\nreal_CT for EASTNORTHEAST (positions 21-33):")
east_rct = [real_ct_abscissa[i] for i in range(21, 34)]
print(f"  {''.join(east_rct)}")
print("\nreal_CT for BERLINCLOCK (positions 63-73):")
berlin_rct = [real_ct_abscissa[i] for i in range(63, 74)]
print(f"  {''.join(berlin_rct)}")

# ─── Part 1 continued: KRYPTOS/KA ────────────────────────────────────────────

print("\n" + "-" * 50)
print("KRYPTOS / KA Vigenere constraints")
print("-" * 50)
print()
print("Paradigm: real_CT[i] = KA[(KA.index(PT[i]) + KA.index(KRYPTOS[i%7])) % 26]")
print()

KRYPTOS = "KRYPTOS"

real_ct_kryptos = {}
for pos, pt_ch in PT_KNOWN.items():
    key_ch = KRYPTOS[pos % 7]
    if pt_ch not in KA:
        pt_idx = AZ.index(pt_ch) if pt_ch in AZ else 0
    else:
        pt_idx = KA.index(pt_ch)
    if key_ch not in KA:
        k_idx = AZ.index(key_ch) if key_ch in AZ else 0
    else:
        k_idx = KA.index(key_ch)
    rct = KA[(pt_idx + k_idx) % 26]
    real_ct_kryptos[pos] = rct

print("Known PT -> real_CT (KRYPTOS/KA Vigenere):")
print(f"  {'pos':>4}  {'PT':>2}  {'key_ch':>6}  {'real_CT':>7}  K4 positions with that letter")

total_combos_ka = 1
constraint_info_ka = {}
for pos in sorted(real_ct_kryptos.keys()):
    rct = real_ct_kryptos[pos]
    key_ch = KRYPTOS[pos % 7]
    pt_ch = PT_KNOWN[pos]
    possible_tau = k4_pos_by_letter[rct]
    n = len(possible_tau)
    total_combos_ka *= n
    constraint_info_ka[pos] = {'pt': pt_ch, 'key_ch': key_ch, 'rct': rct, 'possible_tau': possible_tau}
    print(f"  {pos:>4}  {pt_ch:>2}  {key_ch:>6}          {rct:>7}  {possible_tau} ({n} options)")

print(f"\nTotal naive combinations (KRYPTOS/KA): {total_combos_ka:,}")
print(f"  real_CT[32]={real_ct_kryptos[32]}, K4[32]={K4[32]}, match={real_ct_kryptos[32]==K4[32]}")
print(f"  real_CT[67]={real_ct_kryptos[67]}, K4[73]={K4[73]}, match={real_ct_kryptos[67]==K4[73]}")

print("\nreal_CT for EASTNORTHEAST (KRYPTOS/KA, positions 21-33):")
east_rct_ka = [real_ct_kryptos[i] for i in range(21, 34)]
print(f"  {''.join(east_rct_ka)}")
print("real_CT for BERLINCLOCK (KRYPTOS/KA, positions 63-73):")
berlin_rct_ka = [real_ct_kryptos[i] for i in range(63, 74)]
print(f"  {''.join(berlin_rct_ka)}")

# ─── SA Helper ───────────────────────────────────────────────────────────────

def make_initial_tau(constraint_info_map, n=97):
    """
    Build a valid permutation tau (list of length n, injective)
    satisfying:
      tau[pos] must be in constraint_info_map[pos]['possible_tau']
    Returns tau or None if infeasible.
    """
    tau = [-1] * n
    used = set()

    # First pass: handle fixed points and very constrained positions
    # Sort by number of options (most constrained first)
    positions = sorted(constraint_info_map.keys(), key=lambda p: len(constraint_info_map[p]['possible_tau']))

    for pos in positions:
        options = [v for v in constraint_info_map[pos]['possible_tau'] if v not in used]
        if not options:
            return None  # infeasible
        choice = random.choice(options)
        tau[pos] = choice
        used.add(choice)

    # Fill remaining free positions with unused K4 indices
    all_k4_indices = list(range(n))
    available = [i for i in all_k4_indices if i not in used]
    random.shuffle(available)
    avail_iter = iter(available)

    for pos in range(n):
        if tau[pos] == -1:
            tau[pos] = next(avail_iter)

    assert len(set(tau)) == n, "tau not injective!"
    assert all(0 <= v < n for v in tau), "tau out of range!"
    return tau

def reorder_by_tau(tau):
    """Given tau, return real_CT where real_CT[i] = K4[tau[i]]."""
    return ''.join(K4[tau[i]] for i in range(97))

def verify_tau_constraints(tau, constraint_info_map):
    """Return number of violated constraints."""
    violations = 0
    for pos, info in constraint_info_map.items():
        if tau[pos] not in info['possible_tau']:
            violations += 1
    return violations

def run_sa(constraint_info_map, decrypt_fn, label, n_iters=200000, n_restarts=20, progress_every=10000):
    """
    Simulated annealing on permutation tau.
    Fixed constraints: tau[pos] must map to positions where K4 has the right letter.
    Free positions: SA-optimized.

    decrypt_fn: function(real_ct_string) -> plaintext_string
    """
    print(f"\n  Running SA: {label}")
    print(f"  n_iters={n_iters}, n_restarts={n_restarts}")

    n = 97
    constrained_positions = set(constraint_info_map.keys())
    free_positions = [i for i in range(n) if i not in constrained_positions]

    best_global_score = -999
    best_global_tau = None
    best_global_pt = ""

    for restart in range(n_restarts):
        tau = make_initial_tau(constraint_info_map, n)
        if tau is None:
            print(f"    Restart {restart+1}: INFEASIBLE (constraint conflict)")
            continue

        # Verify
        viols = verify_tau_constraints(tau, constraint_info_map)
        if viols > 0:
            print(f"    Restart {restart+1}: {viols} constraint violations in initial tau!")
            continue

        real_ct = reorder_by_tau(tau)
        pt = decrypt_fn(real_ct)
        current_score = qscore(pt)

        best_score = current_score
        best_tau = tau[:]
        best_pt = pt

        T = 5.0
        T_min = 0.01
        cooling = (T_min / T) ** (1.0 / n_iters)

        for iteration in range(n_iters):
            T *= cooling

            # Pick two free positions to swap in tau
            if len(free_positions) < 2:
                break
            i, j = random.sample(free_positions, 2)

            # Swap
            tau[i], tau[j] = tau[j], tau[i]

            # Score
            real_ct_new = reorder_by_tau(tau)
            pt_new = decrypt_fn(real_ct_new)
            new_score = qscore(pt_new)

            delta = new_score - current_score
            if delta > 0 or random.random() < math.exp(delta / T):
                current_score = new_score
                pt = pt_new
                if new_score > best_score:
                    best_score = new_score
                    best_tau = tau[:]
                    best_pt = pt_new
            else:
                # Revert
                tau[i], tau[j] = tau[j], tau[i]

            if (iteration + 1) % progress_every == 0:
                flag = ""
                if best_score > SCORE_STRONG:
                    flag = " *** STRONG ***"
                elif best_score > SCORE_INTERESTING:
                    flag = " ** INTERESTING **"
                print(f"    Restart {restart+1:2d} iter {iteration+1:7d}  T={T:.4f}  "
                      f"cur={current_score:.4f}  best={best_score:.4f}{flag}")
                print(f"      best_pt: {best_pt[:60]!r}")

        if best_score > best_global_score:
            best_global_score = best_score
            best_global_tau = best_tau[:]
            best_global_pt = best_pt

        flag = ""
        if best_score > SCORE_STRONG:
            flag = " *** STRONG ***"
        elif best_score > SCORE_INTERESTING:
            flag = " ** INTERESTING **"
        print(f"    Restart {restart+1:2d} DONE: best={best_score:.4f}{flag}  pt={best_pt[:50]!r}")

    print(f"\n  {label} GLOBAL BEST: {best_global_score:.4f}")
    print(f"  PT: {best_global_pt!r}")
    if best_global_score > SCORE_INTERESTING:
        print(f"  *** INTERESTING: score={best_global_score:.4f} > {SCORE_INTERESTING} ***")
    return best_global_score, best_global_tau, best_global_pt

# ─── Part 2: SA with ABSCISSA/AZ ─────────────────────────────────────────────

print("\n" + "=" * 70)
print("PART 2: SA on Permutation — ABSCISSA / AZ Vigenere")
print("=" * 70)

def abscissa_decrypt(real_ct):
    """AZ Vigenere decrypt with ABSCISSA key."""
    return az_vig_decrypt(real_ct, ABSCISSA)

# Check feasibility: for each constrained position, there must be
# at least one valid K4 position not used by any other constrained position
# requiring the same letter uniquely.
print("\nFeasibility check for ABSCISSA/AZ constraints:")
letter_demand = defaultdict(list)
# constraint_info was built in Part 1
for pos, info in constraint_info.items():
    letter_demand[info['rct']].append(pos)

for letter, positions in sorted(letter_demand.items()):
    available = k4_pos_by_letter[letter]
    print(f"  real_CT letter {letter}: needed by {len(positions)} positions "
          f"({positions}), available K4 positions: {len(available)} ({available})")
    if len(available) < len(positions):
        print(f"  *** INFEASIBLE: {letter} needed {len(positions)} times but only {len(available)} in K4 ***")

score2, tau2, pt2 = run_sa(
    constraint_info,
    abscissa_decrypt,
    "ABSCISSA/AZ Vigenere SA",
    n_iters=150000,
    n_restarts=20,
    progress_every=25000,
)

# ─── Part 3: SA with KRYPTOS/KA ──────────────────────────────────────────────

print("\n" + "=" * 70)
print("PART 3: SA on Permutation — KRYPTOS / KA Vigenere")
print("=" * 70)

def kryptos_decrypt(real_ct):
    """KA Vigenere decrypt with KRYPTOS key."""
    return ka_vig_decrypt(real_ct, KRYPTOS)

print("\nFeasibility check for KRYPTOS/KA constraints:")
letter_demand_ka = defaultdict(list)
for pos, info in constraint_info_ka.items():
    letter_demand_ka[info['rct']].append(pos)

for letter, positions in sorted(letter_demand_ka.items()):
    available = k4_pos_by_letter[letter]
    print(f"  real_CT letter {letter}: needed by {len(positions)} positions "
          f"({positions}), available K4 positions: {len(available)} ({available})")
    if len(available) < len(positions):
        print(f"  *** INFEASIBLE: {letter} needed {len(positions)} times but only {len(available)} in K4 ***")

score3, tau3, pt3 = run_sa(
    constraint_info_ka,
    kryptos_decrypt,
    "KRYPTOS/KA Vigenere SA",
    n_iters=150000,
    n_restarts=20,
    progress_every=25000,
)

# ─── Part 4: K1-Rotation Grille Test ─────────────────────────────────────────

print("\n" + "=" * 70)
print("PART 4: K1-Rotation Grille Test")
print("=" * 70)
print()
print("K4 occupies rows 24-27 (starting at col 27 for row 24).")
print("Under 180deg rotation: (r,c) -> (27-r, 30-c).")
print("K4 position (r,c) rotates to K1/K2 region.")
print("Grille rule: hole at K4 position (r,c) if rotated cipher char in C17 (or C8).")
print()

# Reproduce the 28x31 cipher grid
CIPHER_RAW = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",   # row 0
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",  # row 1 (32 chars — trim)
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNC",   # row 2
    "EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",  # row 3
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",   # row 4
    "QZGZLECGYUXUEENJTBJLBQCETBJDFHR",   # row 5
    "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT",   # row 6
    "IHHDDDUVH?DWKBFUFPWNTDFIYCUQZER",   # row 7
    "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI",   # row 8
    "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK",   # row 9
    "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",   # row 10
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",   # row 11
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",   # row 12
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",   # row 13
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",   # row 14
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",   # row 15
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",   # row 16
    "WMTWNDITEENRAHCTENEUDRETNHAEOET",   # row 17
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",   # row 18
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT",   # row 19
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI",   # row 20
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",   # row 21
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",   # row 22
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",   # row 23
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",   # row 24
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",   # row 25
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",   # row 26
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",   # row 27
]

CIPHER = []
for i, row in enumerate(CIPHER_RAW):
    r = row[:31]
    if len(r) < 31:
        r = r + '?' * (31 - len(r))
    CIPHER.append(r)

assert len(CIPHER) == 28
assert all(len(r) == 31 for r in CIPHER)

# K4 positions in the grid
K4_POSITIONS = []
for c in range(27, 31):
    K4_POSITIONS.append((24, c))
for r in range(25, 28):
    for c in range(31):
        K4_POSITIONS.append((r, c))
assert len(K4_POSITIONS) == 97

# Verify K4 chars
k4_from_grid = ''.join(CIPHER[r][c] for r, c in K4_POSITIONS)
assert k4_from_grid == K4, f"Grid mismatch!\n{k4_from_grid}\n{K4}"
print("Grid K4 verification: OK")

# For each K4 position (r,c), get the 180deg rotated partner
# K4 index i -> grid (r,c) = K4_POSITIONS[i]
# Rotated: (27-r, 30-c)
print("\nK4 position rotation analysis:")
print(f"  {'k4_idx':>7}  {'K4_pos':>10}  {'rotated_pos':>12}  {'K4_char':>7}  {'rot_char':>8}  {'in_C17':>6}  {'in_C8':>5}")

for i in range(min(20, 97)):
    r, c = K4_POSITIONS[i]
    r2, c2 = 27 - r, 30 - c
    k4_ch = K4[i]
    rot_ch = CIPHER[r2][c2] if 0 <= r2 < 28 and 0 <= c2 < 31 else '?'
    in_c17 = rot_ch in C17
    in_c8 = rot_ch in C8
    print(f"  {i:>7}  ({r:2d},{c:2d})     ({r2:2d},{c2:2d})       {k4_ch:>7}  {rot_ch:>8}  {str(in_c17):>6}  {str(in_c8):>5}")
print("  ...")

# Build grille masks for K4 reordering
def k4_rotation_grille(cycle_set, label):
    """
    For each K4 position, look at the rotated cipher char.
    If that char is in cycle_set => this is a 'hole'.
    Holes go first (in k4 order), non-holes go second.
    Return the reordered K4 string.
    """
    holes = []
    non_holes = []
    for i, (r, c) in enumerate(K4_POSITIONS):
        r2, c2 = 27 - r, 30 - c
        if 0 <= r2 < 28 and 0 <= c2 < 31:
            rot_ch = CIPHER[r2][c2]
            if rot_ch in cycle_set:
                holes.append(i)
            else:
                non_holes.append(i)
        else:
            non_holes.append(i)

    reordered = ''.join(K4[i] for i in holes) + ''.join(K4[i] for i in non_holes)
    hole_k4_chars = ''.join(K4[i] for i in holes)
    non_k4_chars = ''.join(K4[i] for i in non_holes)

    print(f"\n  [{label}] holes={len(holes)}, non-holes={len(non_holes)}")
    print(f"    hole K4 chars:     {hole_k4_chars}")
    print(f"    non-hole K4 chars: {non_k4_chars}")
    print(f"    reordered (97):    {reordered}")

    results = []
    # Score raw
    sc_raw = qscore(reordered)
    print(f"    raw score:    {sc_raw:.4f}")
    results.append((sc_raw, label, 'raw', 'none', reordered))

    # Test various decryptions
    for key in ["ABSCISSA", "KRYPTOS", "PALIMPSEST", "SHADOW"]:
        for dec_fn, dec_name in [
            (az_vig_decrypt, "AZ-Vig"),
            (az_beau_decrypt, "AZ-Beau"),
            (ka_vig_decrypt, "KA-Vig"),
        ]:
            pt = dec_fn(reordered, key)
            sc = qscore(pt)
            if sc > SCORE_INTERESTING:
                flag = " *** STRONG ***" if sc > SCORE_STRONG else " ** INTERESTING **"
                print(f"    {dec_name}({key}): score={sc:.4f}{flag}  pt={pt[:50]!r}")
                results.append((sc, label, dec_name, key, pt))

    # Also test holes-only and non-holes-only
    for subset_chars, subset_name in [(hole_k4_chars, 'holes_only'), (non_k4_chars, 'nonholes_only')]:
        sc = qscore(subset_chars)
        if sc > SCORE_INTERESTING:
            print(f"    {subset_name} raw: score={sc:.4f}")
            results.append((sc, label, subset_name + '_raw', 'none', subset_chars))
        for key in ["ABSCISSA", "KRYPTOS"]:
            for dec_fn, dec_name in [(az_vig_decrypt, "AZ-Vig"), (ka_vig_decrypt, "KA-Vig")]:
                pt = dec_fn(subset_chars, key)
                sc = qscore(pt)
                if sc > SCORE_INTERESTING:
                    flag = " *** STRONG ***" if sc > SCORE_STRONG else " ** INTERESTING **"
                    print(f"    {subset_name} {dec_name}({key}): score={sc:.4f}{flag}  pt={pt[:50]!r}")
                    results.append((sc, label, subset_name + '_' + dec_name, key, pt))

    return results

print("\nTest 1: hole if rotated cipher char IN C17")
results_p4_c17 = k4_rotation_grille(C17, "P4_rot180_C17hole")

print("\nTest 2: hole if rotated cipher char IN C8")
results_p4_c8 = k4_rotation_grille(C8, "P4_rot180_C8hole")

print("\nTest 3: hole if rotated cipher char NOT IN C17 (complement)")
results_p4_notc17 = k4_rotation_grille(set(AZ) - C17, "P4_rot180_notC17hole")

print("\nTest 4: hole if rotated cipher char NOT IN C8 (complement)")
results_p4_notc8 = k4_rotation_grille(set(AZ) - C8, "P4_rot180_notC8hole")

# Also: ABSCISSA decrypt applied directly to rotation-reordered K4
print("\nDirect ABSCISSA decrypt tests on rotation results:")
for results_set, set_name in [
    (results_p4_c17, "C17"),
    (results_p4_c8, "C8"),
]:
    if results_set:
        best = max(results_set, key=lambda x: x[0])
        if best[0] > SCORE_INTERESTING:
            print(f"  {set_name}: BEST={best[0]:.4f}  {best[2]}({best[3]})  {best[4][:50]!r}")

# All Part 4 results
all_p4 = results_p4_c17 + results_p4_c8 + results_p4_notc17 + results_p4_notc8
p4_best = max(all_p4, key=lambda x: x[0]) if all_p4 else None
if p4_best:
    print(f"\nPart 4 global best: score={p4_best[0]:.4f}  [{p4_best[1]}] {p4_best[2]}({p4_best[3]})")
    print(f"  PT: {p4_best[4][:70]!r}")

# ─── Additional: Tau analysis using ABSCISSA derivation ──────────────────────

print("\n" + "=" * 70)
print("ADDITIONAL: Direct tau constraint satisfaction check")
print("=" * 70)
print()
print("For ABSCISSA/AZ: verifying all 24 constraint positions are satisfiable.")
print()

# Build the constraint: tau[pos] must be in k4_pos_by_letter[real_ct_abscissa[pos]]
# Count how many ways each constraint can be satisfied
total_feasible = 1
any_infeasible = False

# Group by real_CT letter to find letter-demand clashes
letter_to_needed = defaultdict(set)
for pos in sorted(constraint_info.keys()):
    info = constraint_info[pos]
    letter_to_needed[info['rct']].add(pos)

print("Letter demand vs supply:")
for letter in sorted(letter_to_needed.keys()):
    needed_positions = sorted(letter_to_needed[letter])
    supply = k4_pos_by_letter[letter]
    n_needed = len(needed_positions)
    n_supply = len(supply)
    feasible = n_supply >= n_needed
    status = "OK" if feasible else "*** INFEASIBLE ***"
    if not feasible:
        any_infeasible = True
    print(f"  {letter}: needed by {n_needed} positions {needed_positions}, "
          f"supply={n_supply} {supply}  [{status}]")

if any_infeasible:
    print("\n*** OVERALL: ABSCISSA/AZ CONSTRAINTS ARE INFEASIBLE ***")
    print("The ABSCISSA key + AZ Vigenere cannot work with the given cribs.")
else:
    print("\nOVERALL: ABSCISSA/AZ constraints are feasible (sufficient supply for all letters).")

# Same for KRYPTOS/KA
print()
letter_to_needed_ka = defaultdict(set)
for pos in sorted(constraint_info_ka.keys()):
    info = constraint_info_ka[pos]
    letter_to_needed_ka[info['rct']].add(pos)

print("Letter demand vs supply (KRYPTOS/KA):")
any_infeasible_ka = False
for letter in sorted(letter_to_needed_ka.keys()):
    needed_positions = sorted(letter_to_needed_ka[letter])
    supply = k4_pos_by_letter[letter]
    n_needed = len(needed_positions)
    n_supply = len(supply)
    feasible = n_supply >= n_needed
    status = "OK" if feasible else "*** INFEASIBLE ***"
    if not feasible:
        any_infeasible_ka = True
    print(f"  {letter}: needed by {n_needed} positions {needed_positions}, "
          f"supply={n_supply} {supply}  [{status}]")

if any_infeasible_ka:
    print("\n*** OVERALL: KRYPTOS/KA CONSTRAINTS ARE INFEASIBLE ***")
else:
    print("\nOVERALL: KRYPTOS/KA constraints are feasible.")

# ─── Summary ─────────────────────────────────────────────────────────────────

print("\n" + "=" * 70)
print("FINAL SUMMARY")
print("=" * 70)
print()

all_scores = []
if pt2:
    all_scores.append((score2, "Part2 ABSCISSA/AZ SA", pt2))
if pt3:
    all_scores.append((score3, "Part3 KRYPTOS/KA SA", pt3))
if p4_best:
    all_scores.append((p4_best[0], f"Part4 {p4_best[1]} {p4_best[2]}({p4_best[3]})", p4_best[4]))

all_scores.sort(reverse=True)

print(f"Best scores across all methods:")
for sc, method, pt in all_scores:
    flag = ""
    if sc > SCORE_STRONG:
        flag = " *** STRONG ***"
    elif sc > SCORE_INTERESTING:
        flag = " ** INTERESTING **"
    print(f"  {sc:.4f}  [{method}]{flag}")
    print(f"    PT: {pt[:70]!r}")

if all_scores:
    best_sc, best_method, best_pt = all_scores[0]
    print(f"\n*** BEST OVERALL: {best_sc:.4f} via {best_method} ***")
    print(f"PT: {best_pt!r}")
    if best_sc > SCORE_STRONG:
        print("*** STRONG CANDIDATE — INVESTIGATE FURTHER ***")
    elif best_sc > SCORE_INTERESTING:
        print("** INTERESTING — WORTH EXPLORING **")
    else:
        print("(Below interesting threshold)")

print("\n" + "=" * 70)
print("DONE")
print("=" * 70)
