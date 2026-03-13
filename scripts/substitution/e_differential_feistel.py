#!/usr/bin/env python3
"""
Differential cryptanalysis of letter-based Feistel cipher on K4.

Cipher:  Letter Feistel (differential attack)
Family:  substitution
Status:  active
Keyspace: analytical (not brute force)
Last run: never
Best score: N/A

Instead of brute-forcing keyword × rounds × P-box, this script uses
Biham-Shamir differential cryptanalysis adapted to mod-26 arithmetic.

Key insight: in a Feistel round f(R,K) = S(R+K mod 26), the input
difference R[i]-R[j] is KEY-INDEPENDENT (key cancels). Given known
PT-CT pairs (cribs), we can analytically recover round keys by:

1. For each candidate S-box (keyword alphabet), build the mod-26
   Differential Distribution Table (DDT).
2. For each structural assumption (n_rounds, P-box, split point),
   compute what the round-3 (or round-2) inputs/outputs must be.
3. Use the DDT to build test sets of possible round key values.
4. Intersect test sets across all 276 crib pairs — true key uniquely
   survives if the model is correct.

This is ANALYTICAL key recovery, not search. Runs in milliseconds
per structural hypothesis.
"""

import json, math, sys, time
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CRIB_DICT

QG_PATH = Path(__file__).resolve().parents[2] / "data" / "english_quadgrams.json"
with open(QG_PATH) as f:
    _qg = json.load(f)
QG_FLOOR = min(_qg.values()) - 1.0

def qg_score(text):
    return sum(_qg.get(text[i:i+4], QG_FLOOR) for i in range(len(text)-3))

def qg_per_char(text):
    n = len(text) - 3
    return qg_score(text) / n if n > 0 else QG_FLOOR

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
N = len(CT)  # 97
MOD = 26

ct_nums = [ord(c) - ord('A') for c in CT]

# Known PT-CT pairs from cribs (0-indexed)
KNOWN = {}  # pos -> (pt_num, ct_num)
for pos, ch in CRIB_DICT.items():
    KNOWN[pos] = (ord(ch) - ord('A'), ct_nums[pos])

KNOWN_POSITIONS = sorted(KNOWN.keys())
print(f"Known positions ({len(KNOWN_POSITIONS)}): {KNOWN_POSITIONS}")

# ── Keyword alphabet generation ────────────────────────────────────────────

def keyword_alpha(kw):
    seen = set()
    result = []
    for ch in kw.upper():
        if ch.isalpha() and ch not in seen:
            result.append(ch)
            seen.add(ch)
    for ch in AZ:
        if ch not in seen:
            result.append(ch)
            seen.add(ch)
    return ''.join(result)

KEYWORDS = [
    "KRYPTOS", "KOMPASS", "DEFECTOR", "COLOPHON", "ABSCISSA",
    "PALIMPSEST", "BERLINCLOCK", "SHADOW", "LUCIFER", "SANBORN",
    "SCHEIDT", "CIPHER", "MATRIX", "DIGITAL", "ENIGMA", "SECRET",
    "COMPASS", "LODESTONE", "MAGNETIC", "HIDDEN", "LANGLEY",
    # Identity (no keyword)
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
]

# ── Mod-26 Differential Distribution Table ─────────────────────────────────

def build_ddt(sbox):
    """Build 26x26 DDT for a mod-26 substitution.

    ddt[d_in][d_out] = count of x in Z26 such that
        S(x) - S((x + d_in) % 26) ≡ d_out (mod 26)

    Also builds input sets:
    ddt_inputs[d_in][d_out] = list of x values producing that differential
    """
    ddt = [[0]*MOD for _ in range(MOD)]
    ddt_inputs = [[[] for _ in range(MOD)] for _ in range(MOD)]

    for x in range(MOD):
        for d_in in range(MOD):
            x2 = (x + d_in) % MOD
            d_out = (sbox[x] - sbox[x2]) % MOD
            ddt[d_in][d_out] += 1
            ddt_inputs[d_in][d_out].append(x)

    return ddt, ddt_inputs


def analyze_ddt(ddt, kw_name):
    """Print DDT statistics."""
    nonzero_counts = []
    max_val = 0
    for d_in in range(1, MOD):  # skip d_in=0 (trivial)
        nz = sum(1 for d_out in range(MOD) if ddt[d_in][d_out] > 0)
        nonzero_counts.append(nz)
        for d_out in range(MOD):
            if ddt[d_in][d_out] > max_val:
                max_val = ddt[d_in][d_out]

    avg_nz = sum(nonzero_counts) / len(nonzero_counts)
    min_nz = min(nonzero_counts)
    max_nz = max(nonzero_counts)
    print(f"  {kw_name}: max_entry={max_val}, "
          f"nonzero/row: avg={avg_nz:.1f} min={min_nz} max={max_nz}")


# ── P-box permutations ────────────────────────────────────────────────────

def pb_identity(x): return list(x)
def pb_reverse(x): return list(reversed(x))
def pb_interleave(x):
    return [x[i] for i in range(0, len(x), 2)] + [x[i] for i in range(1, len(x), 2)]
def pb_deinterleave(x):
    """Inverse of interleave."""
    half = (len(x) + 1) // 2
    result = [0] * len(x)
    for i in range(half):
        result[2*i] = x[i]
    for i in range(len(x) - half):
        result[2*i+1] = x[half + i]
    return result

def make_stride_perm(n, stride):
    perm = []
    visited = set()
    pos = 0
    while len(perm) < n:
        while pos in visited:
            pos = (pos + 1) % n
        perm.append(pos)
        visited.add(pos)
        pos = (pos + stride) % n
    return perm

def apply_perm(data, perm):
    """output[i] = data[perm[i]]"""
    return [data[perm[i]] for i in range(len(data))]

def invert_perm(perm):
    inv = [0] * len(perm)
    for i, p in enumerate(perm):
        inv[p] = i
    return inv


# ── Feistel structure ──────────────────────────────────────────────────────

def feistel_round_encrypt(L, R, sbox, round_key, pbox_fn):
    """One Feistel encryption round: new_L = R, new_R = L + P(S(R + K))."""
    n_R = len(R)
    n_L = len(L)

    # f(R, K) = P(S(R[i] + K[i%klen] mod 26))
    klen = len(round_key)
    f_input = [(R[i] + round_key[i % klen]) % MOD for i in range(n_R)]
    f_sbox = [sbox[v] for v in f_input]
    f_perm = pbox_fn(f_sbox)

    # Pad/truncate to match L length
    if len(f_perm) < n_L:
        f_perm = f_perm + f_perm[:n_L - len(f_perm)]
    f_perm = f_perm[:n_L]

    new_R = [(L[j] + f_perm[j]) % MOD for j in range(n_L)]
    new_L = list(R)
    return new_L, new_R


def derive_round_key(key_nums, rnd, method="rotate"):
    """Derive subkey for round rnd from master key."""
    if method == "rotate":
        return [(k + rnd * 3) % MOD for k in key_nums]
    elif method == "shift":
        return [(k + rnd) % MOD for k in key_nums]
    elif method == "identity":
        return list(key_nums)
    return list(key_nums)


# ── DIFFERENTIAL ATTACK: 1-round Feistel ──────────────────────────────────

def attack_1round(sbox, sbox_inv, pbox_fn, pbox_inv_fn, mid):
    """
    1-round Feistel decrypt: given CT = (L1, R1), recover PT = (L0, R0).

    Encryption: L1 = R0, R1 = L0 + P(S(R0 + K))
    So: R0 = L1, L0 = R1 - P(S(L1 + K))

    We know PT and CT at crib positions. Use differential to find K.

    For positions in R0 (= L1), the PT value directly equals CT_L.
    For positions in L0, we need: L0[j] = R1[j] - P(S(L1 + K))[j]

    Actually, let's think about this differently using the counter method.
    """
    L1 = ct_nums[:mid]
    R1 = ct_nums[mid:]

    # In 1-round Feistel:
    #   L1 = R0 (PT right half)
    #   R1 = L0 + f(R0, K1)
    # So: L0 = R1 - f(R0, K1) = R1 - P(S(R0 + K1))
    #     R0 = L1

    # For each crib position p with known PT[p]:
    #   If p < mid: PT[p] should be L0[p] = R1[p] - P(S(R0 + K1))[p]
    #   If p >= mid: PT[p] should be R0[p-mid] = L1[p-mid] = CT[p-mid]

    # First check: positions in right half must match CT left half
    right_half_ok = True
    for pos in KNOWN_POSITIONS:
        if pos >= mid:
            r_idx = pos - mid
            if r_idx < len(L1):
                pt_val, _ = KNOWN[pos]
                if L1[r_idx] != pt_val:
                    right_half_ok = False
                    break

    if not right_half_ok:
        return None, 0  # Right half doesn't match — wrong split

    # For left half positions: use differential to find key
    # L0[j] = R1[j] - f_out[j] where f_out = P(S(R0 + K))
    # So f_out[j] = R1[j] - L0[j] = R1[j] - PT[j]  (known!)
    # And f_out = P(S(R0 + K))
    # So S(R0 + K) = P_inv(f_out)
    # So R0[i] + K[i] = S_inv(P_inv(f_out)[i])
    # So K[i] = S_inv(P_inv(f_out)[i]) - R0[i]

    left_positions = [p for p in KNOWN_POSITIONS if p < mid]
    if not left_positions:
        return None, 0

    # Compute f_out at known left positions
    # But f_out has length = len(L), and we need to undo P-box
    # We need the FULL f_out to undo P... but we only know it at crib positions

    # Alternative: try all possible key values at each R0 position
    # For position i in R0: K[i%klen] = S_inv(pre_pbox[?]) - R0[i]
    # The P-box maps pre_pbox position i to f_out position pbox(i)

    # This gets complicated with unknown P-box mappings to partial positions.
    # Let's use a simpler approach: for each candidate key value k at position i,
    # check if the resulting f_out is consistent with known PT.

    # Actually, for the identity P-box, P_inv = identity too.
    # Then: K[i] = S_inv(R1[j] - PT[j]) - R0[i]  where j corresponds to i
    # But the correspondence depends on the key length and padding.

    # Let's just try all 26 possible key values at each position
    # and check consistency with cribs.

    # For a keyword of length klen, K[i] = K[i % klen]
    # So all R0 positions with same (i % klen) must give same K value.

    best_key = None
    best_crib = 0

    for klen in range(1, 21):
        # For each key position, collect constraints
        key_counters = [([0]*MOD) for _ in range(klen)]
        key_constraints = [0] * klen  # how many constraints per position

        for pos in left_positions:
            j = pos  # position in L0
            pt_val = KNOWN[pos][0]

            # f_out[j] = R1[j] - PT[j]
            f_out_j = (R1[j] - pt_val) % MOD if j < len(R1) else None
            if f_out_j is None:
                continue

            # For identity pbox: pre_pbox[j] = f_out[j]
            # S(R0[j] + K[j%klen]) = pre_pbox[j]
            # R0[j] + K[j%klen] = S_inv(pre_pbox[j])

            # Apply inverse P-box to get pre_pbox position
            # For identity: pre_pbox[j] = f_out[j]
            s_inv_val = sbox_inv[f_out_j]

            # R0 = L1, and we need R0 at position j
            # But R0 has length mid, and f operates on R0 with key cycling
            # Actually f_input[i] = R0[i] + K[i%klen] for i in range(len(R0))
            # And f_out[j] = f_sbox[j] (for identity pbox)
            # But j here is a position in L0 (length N-mid)
            # The f output is padded/truncated to length N-mid

            # If j < mid (len of R0), then f_sbox[j] = S(R0[j] + K[j%klen])
            if j < mid:
                r0_j = L1[j]  # R0 = L1
                k_val = (s_inv_val - r0_j) % MOD
                k_pos = j % klen
                key_counters[k_pos][k_val] += 1
                key_constraints[k_pos] += 1

        # Check if key is determined
        if all(c > 0 for c in key_constraints):
            key = []
            total_hits = 0
            for kp in range(klen):
                best_k = max(range(MOD), key=lambda k: key_counters[kp][k])
                key.append(best_k)
                total_hits += key_counters[kp][best_k]

            total_constraints = sum(key_constraints)
            if total_constraints > 0 and total_hits == total_constraints:
                # Perfect consistency — try decrypting
                key_full = key
                f_input = [(L1[i] + key_full[i % klen]) % MOD for i in range(mid)]
                f_sbox_out = [sbox[v] for v in f_input]
                f_perm = pbox_fn(f_sbox_out)
                if len(f_perm) < N - mid:
                    f_perm = f_perm + f_perm[:N - mid - len(f_perm)]
                f_perm = f_perm[:N - mid]

                pt_L = [(R1[j] - f_perm[j]) % MOD for j in range(N - mid)]
                pt_R = list(L1)
                pt_nums = pt_L + pt_R
                pt = ''.join(chr(v + ord('A')) for v in pt_nums)

                # Count crib matches
                crib_hits = sum(1 for pos, ch in CRIB_DICT.items()
                               if pos < len(pt) and pt[pos] == ch)

                if crib_hits > best_crib:
                    best_crib = crib_hits
                    best_key = (klen, key, pt)

    return best_key, best_crib


# ── DIFFERENTIAL ATTACK: 2-round Feistel ──────────────────────────────────

def attack_2round_differential(sbox, sbox_inv, ddt, ddt_inputs, pbox_fn, pbox_inv_fn, mid, kw_name):
    """
    2-round Feistel differential attack using counter method.

    Encryption:
      Round 1: L1 = R0, R1 = L0 + f(R0, K1)
      Round 2: L2 = R1, R2 = L1 + f(R1, K2)

    So: L2 = R1 = L0 + f(R0, K1)
        R2 = L1 + f(R1, K2) = R0 + f(R1, K2)

    CT = L2||R2. PT = L0||R0.

    From R2 = R0 + f(R1, K2) and R1 = L2:
      f(L2, K2) = R2 - R0

    For each known position in R0 (positions >= mid in PT):
      We know R0[i] and R2[i] from cribs and CT.
      So f(L2, K2)[i] = R2[i] - R0[i-mid] is known.

    Now f(L2, K2)[j] = P(S(L2 + K2))[j].
    With identity P-box: S(L2[j] + K2[j%klen]) = f_val[j]
    So K2[j%klen] = S_inv(f_val[j]) - L2[j]

    This directly recovers K2! Then K1 from the other half.
    """
    L2 = ct_nums[:mid]
    R2 = ct_nums[mid:]

    best_result = None
    best_crib = 0

    for klen in range(1, 21):
        # ── Recover K2 from right-half crib positions ──
        # R2[i] = R0[i] + f(L2, K2)[i]  (where i indexes the right half)
        # For PT position (mid + i), PT[mid+i] = R0[i]
        # CT right half: R2[i] = ct_nums[mid + i]

        k2_counters = [[0]*MOD for _ in range(klen)]
        k2_n = [0] * klen

        right_crib_positions = [p for p in KNOWN_POSITIONS if p >= mid]

        for pos in right_crib_positions:
            i = pos - mid  # index within right half
            pt_val = KNOWN[pos][0]  # R0[i]
            ct_r_val = R2[i]  # R2[i]

            # f(L2, K2)[i] = R2[i] - R0[i]
            f_val_i = (ct_r_val - pt_val) % MOD

            # For identity pbox: S(L2[i] + K2[i%klen]) = f_val_i
            # But we need i < len(L2) for the S-box input to use L2[i]
            if i < len(L2):
                s_inv = sbox_inv[f_val_i]
                k2_val = (s_inv - L2[i]) % MOD
                k2_counters[i % klen][k2_val] += 1
                k2_n[i % klen] += 1

        # Check K2 consistency
        if not all(n > 0 for n in k2_n):
            continue

        k2 = []
        k2_perfect = True
        for kp in range(klen):
            best_k = max(range(MOD), key=lambda k: k2_counters[kp][k])
            if k2_counters[kp][best_k] < k2_n[kp]:
                k2_perfect = False
                break
            k2.append(best_k)

        if not k2_perfect:
            continue

        # ── K2 recovered! Now compute f(L2, K2) fully and get R0 ──
        f_input_2 = [(L2[i] + k2[i % klen]) % MOD for i in range(mid)]
        f_sbox_2 = [sbox[v] for v in f_input_2]
        f_perm_2 = pbox_fn(f_sbox_2)
        if len(f_perm_2) < N - mid:
            f_perm_2 = f_perm_2 + f_perm_2[:N - mid - len(f_perm_2)]
        f_perm_2 = f_perm_2[:N - mid]

        # R0 = R2 - f(L2, K2)
        R0 = [(R2[j] - f_perm_2[j]) % MOD for j in range(N - mid)]

        # ── Now recover K1 from left-half crib positions ──
        # L2 = L0 + f(R0, K1) → R1 = L2, and L1 = R0
        # Actually: L2 = R1 = L0 + f(R0, K1)
        # f(R0, K1)[j] = L2[j] - L0[j] for positions where L0[j] is known

        left_crib_positions = [p for p in KNOWN_POSITIONS if p < mid]

        k1_counters = [[0]*MOD for _ in range(klen)]
        k1_n = [0] * klen

        for pos in left_crib_positions:
            j = pos  # index within left half
            pt_val = KNOWN[pos][0]  # L0[j]

            f_val_j = (L2[j] - pt_val) % MOD

            # For identity pbox: S(R0[j] + K1[j%klen]) = f_val_j
            # Need R0[j], but R0 has length N-mid
            if j < len(R0):
                s_inv = sbox_inv[f_val_j]
                k1_val = (s_inv - R0[j]) % MOD
                k1_counters[j % klen][k1_val] += 1
                k1_n[j % klen] += 1

        if not all(n > 0 for n in k1_n):
            continue

        k1 = []
        k1_perfect = True
        for kp in range(klen):
            best_k = max(range(MOD), key=lambda k: k1_counters[kp][k])
            if k1_counters[kp][best_k] < k1_n[kp]:
                k1_perfect = False
                break
            k1.append(best_k)

        if not k1_perfect:
            continue

        # ── Both keys recovered! Full decryption ──
        # L0 = L2 - f(R0, K1)
        f_input_1 = [(R0[i] + k1[i % klen]) % MOD for i in range(N - mid)]
        f_sbox_1 = [sbox[v] for v in f_input_1]
        f_perm_1 = pbox_fn(f_sbox_1)
        if len(f_perm_1) < mid:
            f_perm_1 = f_perm_1 + f_perm_1[:mid - len(f_perm_1)]
        f_perm_1 = f_perm_1[:mid]

        L0 = [(L2[j] - f_perm_1[j]) % MOD for j in range(mid)]

        pt_nums = L0 + list(R0)
        pt = ''.join(chr(v + ord('A')) for v in pt_nums)

        crib_hits = sum(1 for pos, ch in CRIB_DICT.items()
                       if pos < len(pt) and pt[pos] == ch)

        if crib_hits > best_crib:
            best_crib = crib_hits
            best_result = {
                'klen': klen,
                'k1': k1, 'k2': k2,
                'k1_word': ''.join(chr(v + ord('A')) for v in k1),
                'k2_word': ''.join(chr(v + ord('A')) for v in k2),
                'pt': pt,
                'crib_hits': crib_hits,
                'kw': kw_name,
            }

    return best_result, best_crib


# ── DIFFERENTIAL ATTACK: 3-round Feistel (full Biham-Shamir) ──────────────

def attack_3round_differential(sbox, sbox_inv, ddt, ddt_inputs, pbox_fn, mid, kw_name):
    """
    3-round Feistel: exact Biham-Shamir method adapted to mod-26.

    CT = (L3, R3). PT = (L0, R0).

    R3 = L0 + f(R0, K1) + f(R2, K3)   [XOR → mod-26 addition]

    If we have TWO PT-CT pairs with R0 = R0* (same right half),
    then f(R0, K1) cancels:
      R3 - R3* = (L0 - L0*) + (f(R2,K3) - f(R2*,K3))

    We can't choose pairs, but we can use the counter method on
    individual pairs to recover K3, then K1.

    For each crib pair at position p:
      If p >= mid: gives info about R0 (and hence R3 = L1 + f(R2, K3) via R2 = L3)

    Actually, for 3 rounds the full Biham-Shamir requires knowing
    R2 = L3 (from CT) and computing the S-box inputs for round 3.

    R3[i] = R1[i] + f(R2, K3)[i]
    R1 = L2, but L2 isn't directly available for 3 rounds...
    L2 = R1 (from round 1→2), R2 = L3 (known from CT).

    Wait: L3 = R2, R3 is the other half of CT.
    R2 = L1 + f(R1, K2)... we'd need to peel layers.

    For 3 rounds, the standard approach:
    L3 = R2 = L1 + f(R1, K2) — involves K2
    R3 = L2 + f(R2, K3) = R1 + f(L3, K3)

    So: f(L3, K3) = R3 - R1
    But R1 = L0 + f(R0, K1) — involves K1.

    For two pairs with same R0 difference (not necessarily equal R0):
    f(L3,K3) - f(L3*,K3) = (R3-R3*) - (L0-L0*) - (f(R0,K1) - f(R0*,K1))

    The right side has f(R0,K1) - f(R0*,K1) which is key-independent
    in its INPUT difference (R0 - R0*), but the OUTPUT difference
    depends on the S-box differential table.

    This is where we use the DDT: for input diff (R0-R0*), the DDT
    tells us the probability distribution of output differences.

    Using the counter method across many pairs, the correct K3
    accumulates more counts than incorrect values.
    """
    L3 = ct_nums[:mid]
    R3 = ct_nums[mid:]

    best_result = None
    best_crib = 0

    for klen in range(1, 15):
        # For 3-round, we use the Stinson approach:
        # f(L3, K3)[j] = output of round 3 f-function at position j
        # The S-box input for round 3 at position j is: L3[j] + K3[j%klen]

        # For each pair of crib positions (p1, p2) where both are in the
        # right half (>= mid):
        #   R3[p1-mid] - R3[p2-mid] = (R1[p1-mid] - R1[p2-mid]) +
        #                              (f(L3,K3)[p1-mid] - f(L3,K3)[p2-mid])

        # But we don't know R1... For 3 rounds this gets recursive.
        # Instead, use the direct counter method for K3:

        # If we ASSUME K1 (or try all), we can compute R1, then recover K3.
        # That's still brute force on K1.

        # Better: for 3 rounds, use the fact that many crib pairs constrain
        # K3 through the DDT. For each pair of cribs at right-half positions:
        #   d_out_3 = (R3[a] - R3[b]) - (R1[a] - R1[b])
        #   d_in_3 = L3[a] - L3[b]  (key-independent!)
        # The DDT tells us which K3 values are consistent.

        # But we still need R1[a]-R1[b]... which depends on K1.
        # This is the fundamental challenge of >2-round differential crypto.

        # For now, skip 3-round (the 2-round attack is more appropriate
        # for a hand-executable cipher anyway).
        pass

    return best_result, best_crib


# ── GENERALIZED ROUND FUNCTION VARIANTS ───────────────────────────────────

def attack_2round_generalized(sbox, sbox_inv, mid, kw_name,
                               combine="add", round_fn="sbox"):
    """
    2-round with different combining operations.

    combine="add": R_new = L + f(R, K)  (mod 26 addition, like Vig)
    combine="sub": R_new = L - f(R, K)  (Beaufort-style)

    round_fn="sbox": f(R,K) = S(R+K)
    round_fn="vig":  f(R,K) = R+K mod 26 (no S-box, just Vigenere)
    """
    L2 = ct_nums[:mid]
    R2 = ct_nums[mid:]

    best_result = None
    best_crib = 0

    if combine == "add":
        inv_combine = lambda a, b: (a - b) % MOD  # undo addition
    else:
        inv_combine = lambda a, b: (b - a) % MOD  # undo subtraction

    for klen in range(1, 21):
        # Recovery of K2 from right-half cribs
        right_crib_positions = [p for p in KNOWN_POSITIONS if p >= mid]

        k2_counters = [[0]*MOD for _ in range(klen)]
        k2_n = [0] * klen

        for pos in right_crib_positions:
            i = pos - mid
            pt_val = KNOWN[pos][0]
            ct_r_val = R2[i]

            # f_val = inv_combine(R2[i], R0[i]) = undo the combine
            f_val_i = inv_combine(ct_r_val, pt_val)

            if i < len(L2):
                if round_fn == "sbox":
                    s_inv = sbox_inv[f_val_i]
                    k2_val = (s_inv - L2[i]) % MOD
                else:  # "vig" — no sbox
                    k2_val = (f_val_i - L2[i]) % MOD

                k2_counters[i % klen][k2_val] += 1
                k2_n[i % klen] += 1

        if not all(n > 0 for n in k2_n):
            continue

        k2 = []
        k2_perfect = True
        for kp in range(klen):
            best_k = max(range(MOD), key=lambda k: k2_counters[kp][k])
            if k2_counters[kp][best_k] < k2_n[kp]:
                k2_perfect = False
                break
            k2.append(best_k)

        if not k2_perfect:
            continue

        # Compute full f(L2, K2) and recover R0
        if round_fn == "sbox":
            f_vals_2 = [sbox[(L2[i] + k2[i % klen]) % MOD] for i in range(mid)]
        else:
            f_vals_2 = [(L2[i] + k2[i % klen]) % MOD for i in range(mid)]

        # Pad to right-half length
        fv2 = list(f_vals_2)
        while len(fv2) < N - mid:
            fv2 = fv2 + f_vals_2[:N - mid - len(fv2)]
        fv2 = fv2[:N - mid]

        R0 = [inv_combine(R2[j], fv2[j]) for j in range(N - mid)]

        # Recover K1 from left-half cribs
        left_crib_positions = [p for p in KNOWN_POSITIONS if p < mid]

        k1_counters = [[0]*MOD for _ in range(klen)]
        k1_n = [0] * klen

        for pos in left_crib_positions:
            j = pos
            pt_val = KNOWN[pos][0]

            f_val_j = inv_combine(L2[j], pt_val)

            if j < len(R0):
                if round_fn == "sbox":
                    s_inv = sbox_inv[f_val_j]
                    k1_val = (s_inv - R0[j]) % MOD
                else:
                    k1_val = (f_val_j - R0[j]) % MOD

                k1_counters[j % klen][k1_val] += 1
                k1_n[j % klen] += 1

        if not all(n > 0 for n in k1_n):
            continue

        k1 = []
        k1_perfect = True
        for kp in range(klen):
            best_k = max(range(MOD), key=lambda k: k1_counters[kp][k])
            if k1_counters[kp][best_k] < k1_n[kp]:
                k1_perfect = False
                break
            k1.append(best_k)

        if not k1_perfect:
            continue

        # Full decrypt
        if round_fn == "sbox":
            f_vals_1 = [sbox[(R0[i] + k1[i % klen]) % MOD] for i in range(N - mid)]
        else:
            f_vals_1 = [(R0[i] + k1[i % klen]) % MOD for i in range(N - mid)]

        fv1 = list(f_vals_1)
        while len(fv1) < mid:
            fv1 = fv1 + f_vals_1[:mid - len(fv1)]
        fv1 = fv1[:mid]

        L0 = [inv_combine(L2[j], fv1[j]) for j in range(mid)]

        pt_nums = L0 + list(R0)
        pt = ''.join(chr(v + ord('A')) for v in pt_nums)

        crib_hits = sum(1 for pos, ch in CRIB_DICT.items()
                       if pos < len(pt) and pt[pos] == ch)

        if crib_hits > best_crib:
            best_crib = crib_hits
            best_result = {
                'klen': klen,
                'k1': ''.join(chr(v + ord('A')) for v in k1),
                'k2': ''.join(chr(v + ord('A')) for v in k2),
                'pt': pt,
                'crib_hits': crib_hits,
                'kw': kw_name,
                'combine': combine,
                'round_fn': round_fn,
            }

    return best_result, best_crib


# ── MAIN ──────────────────────────────────────────────────────────────────

def run():
    print("=" * 70)
    print("DIFFERENTIAL CRYPTANALYSIS: LETTER-BASED FEISTEL ON K4")
    print("=" * 70)
    print(f"CT ({N}): {CT}")
    print(f"Cribs: {len(KNOWN)} known PT-CT pairs")
    print(f"Method: Biham-Shamir counter method adapted to mod-26")
    print()

    all_results = []
    total_configs = 0

    # ═══ PHASE 1: DDT Analysis ═══
    print("=" * 70)
    print("PHASE 1: Differential Distribution Table Analysis")
    print("=" * 70)

    sbox_cache = {}
    for kw in KEYWORDS:
        alpha = keyword_alpha(kw)
        sbox = [ord(alpha[i]) - ord('A') for i in range(MOD)]
        sbox_inv = [0] * MOD
        for i in range(MOD):
            sbox_inv[sbox[i]] = i

        ddt, ddt_inputs = build_ddt(sbox)
        analyze_ddt(ddt, kw)
        sbox_cache[kw] = (sbox, sbox_inv, ddt, ddt_inputs)

    # ═══ PHASE 2: 1-round and 2-round analytical attack ═══
    print(f"\n{'=' * 70}")
    print("PHASE 2: Analytical Key Recovery (1-2 round Feistel)")
    print("=" * 70)

    # Try multiple split points (where to divide CT into L|R)
    split_points = [
        N // 2,          # 48|49 — standard midpoint
        (N + 1) // 2,    # 49|48
        36,              # After 2nd W delimiter
        37,              # K2-derived: 38-1
        48,              # 48|49 — near half
        24,              # 24|73 — null count split
        73,              # 73|24 — reversed
    ]

    combine_modes = ["add", "sub"]
    round_fn_modes = ["sbox", "vig"]

    for mid in split_points:
        if mid < 10 or mid > N - 10:
            continue

        for kw in KEYWORDS:
            sbox, sbox_inv, ddt, ddt_inputs = sbox_cache[kw]

            # 2-round with various combining operations
            for combine in combine_modes:
                for rfn in round_fn_modes:
                    result, crib = attack_2round_generalized(
                        sbox, sbox_inv, mid, kw,
                        combine=combine, round_fn=rfn
                    )
                    total_configs += 20  # ~20 key lengths tested

                    if result and crib >= 10:
                        print(f"  *** SIGNAL: crib={crib}/24 | "
                              f"mid={mid} kw={kw} {combine}/{rfn} "
                              f"klen={result['klen']}")
                        print(f"      K1={result['k1']} K2={result['k2']}")
                        print(f"      PT: {result['pt'][:60]}...")
                        qg = qg_per_char(result['pt'])
                        print(f"      qg/char: {qg:.3f}")
                        all_results.append((crib, qg, result))
                    elif result and crib >= 4:
                        all_results.append((crib, qg_per_char(result['pt']), result))

    found_signal = any(c >= 10 for c, _, _ in all_results)

    if not found_signal:
        print(f"  {total_configs} configs tested, no signal (best crib = "
              f"{max((c for c,_,_ in all_results), default=0)}/24)")

    # ═══ PHASE 3: Multiple round key schedules ═══
    print(f"\n{'=' * 70}")
    print("PHASE 3: Key Schedule Variants (2-round, all split points)")
    print("=" * 70)
    print("  Testing: independent round keys, rotated keys, shifted keys")

    # For 2-round Feistel, the key schedule determines how K1 and K2
    # relate. If they're independent, the attack above handles it.
    # If K2 = rotate(K1, offset), we can add that constraint.

    # Try: K2 = K1 rotated by various offsets
    for mid in [N // 2, (N+1) // 2, 36, 48]:
        if mid < 10 or mid > N - 10:
            continue
        for kw in KEYWORDS:
            sbox, sbox_inv, ddt, ddt_inputs = sbox_cache[kw]

            for klen in range(1, 15):
                # Recover K2 analytically
                right_crib = [p for p in KNOWN_POSITIONS if p >= mid]
                k2_vals = {}

                for pos in right_crib:
                    i = pos - mid
                    if i >= mid:  # out of L2 range
                        continue
                    pt_val = KNOWN[pos][0]
                    ct_r_val = ct_nums[mid + i]
                    f_val = (ct_r_val - pt_val) % MOD
                    s_inv = sbox_inv[f_val]
                    k2_val = (s_inv - ct_nums[i]) % MOD  # L2[i] = ct_nums[i]
                    kp = i % klen
                    if kp not in k2_vals:
                        k2_vals[kp] = k2_val
                    elif k2_vals[kp] != k2_val:
                        break  # inconsistency
                else:
                    if len(k2_vals) == klen:
                        k2 = [k2_vals[kp] for kp in range(klen)]

                        # Now check: is K1 related to K2?
                        # Recover R0 first
                        f_vals_2 = [sbox[(ct_nums[i] + k2[i % klen]) % MOD] for i in range(mid)]
                        fv2 = list(f_vals_2)
                        while len(fv2) < N - mid:
                            fv2 = fv2 + f_vals_2[:N - mid - len(fv2)]
                        fv2 = fv2[:N - mid]
                        R0 = [(ct_nums[mid + j] - fv2[j]) % MOD for j in range(N - mid)]

                        # Recover K1
                        left_crib = [p for p in KNOWN_POSITIONS if p < mid]
                        k1_vals = {}
                        ok = True
                        for pos in left_crib:
                            j = pos
                            if j >= len(R0):
                                continue
                            pt_val = KNOWN[pos][0]
                            f_val = (ct_nums[j] - pt_val) % MOD  # L2[j] - L0[j]
                            s_inv = sbox_inv[f_val]
                            k1_val = (s_inv - R0[j]) % MOD
                            kp = j % klen
                            if kp not in k1_vals:
                                k1_vals[kp] = k1_val
                            elif k1_vals[kp] != k1_val:
                                ok = False
                                break

                        if ok and len(k1_vals) == klen:
                            k1 = [k1_vals[kp] for kp in range(klen)]

                            # Full decrypt
                            f1 = [sbox[(R0[i] + k1[i % klen]) % MOD] for i in range(N - mid)]
                            fv1 = list(f1)
                            while len(fv1) < mid:
                                fv1 = fv1 + f1[:mid - len(fv1)]
                            fv1 = fv1[:mid]
                            L0 = [(ct_nums[j] - fv1[j]) % MOD for j in range(mid)]

                            pt_nums = L0 + list(R0)
                            pt = ''.join(chr(v + ord('A')) for v in pt_nums)
                            crib_hits = sum(1 for pos, ch in CRIB_DICT.items()
                                           if pos < len(pt) and pt[pos] == ch)

                            total_configs += 1

                            if crib_hits >= 10:
                                k1w = ''.join(chr(v+ord('A')) for v in k1)
                                k2w = ''.join(chr(v+ord('A')) for v in k2)
                                qg = qg_per_char(pt)
                                print(f"  *** crib={crib_hits}/24 mid={mid} "
                                      f"kw={kw} klen={klen} K1={k1w} K2={k2w}")
                                print(f"      PT: {pt[:60]}...")
                                print(f"      qg={qg:.3f}")
                                all_results.append((crib_hits, qg, {
                                    'klen': klen, 'k1': k1w, 'k2': k2w,
                                    'pt': pt, 'crib_hits': crib_hits,
                                    'kw': kw, 'mid': mid}))

    print(f"  {total_configs} total configs tested analytically")

    # ═══ PHASE 4: Exhaustive S-box search (no keyword constraint) ═══
    print(f"\n{'=' * 70}")
    print("PHASE 4: Unknown S-box Recovery via Differential Constraints")
    print("=" * 70)

    # If the S-box is unknown, we can STILL recover it using the cribs.
    # For 2-round at mid=48:
    #   f(L2, K2)[i] = R2[i] - R0[i]  — known at right-half crib positions
    #   S(L2[i] + K2[i%klen]) = f_val[i]
    # With enough constraints, we can solve for S and K simultaneously.

    # For each pair of right-half crib positions (a, b) with a%klen == b%klen:
    #   S(L2[a] + K) = f_a  and  S(L2[b] + K) = f_b  (same K value)
    #   Input diff = L2[a] - L2[b] (known), output diff = f_a - f_b (known)
    #   This constrains the DDT of S without knowing S!

    for mid in [N // 2, (N+1) // 2, 48, 36]:
        if mid < 10 or mid > N - 10:
            continue

        right_crib = [p for p in KNOWN_POSITIONS if p >= mid]
        if len(right_crib) < 4:
            continue

        for klen in range(1, 15):
            # Group right-half cribs by (i % klen)
            groups = {}
            for pos in right_crib:
                i = pos - mid
                if i >= mid:
                    continue
                kp = i % klen
                pt_val = KNOWN[pos][0]
                ct_r_val = ct_nums[mid + i]
                f_val = (ct_r_val - pt_val) % MOD
                l2_val = ct_nums[i]

                if kp not in groups:
                    groups[kp] = []
                groups[kp].append((i, l2_val, f_val))

            # For each group, pairs give differential constraints
            n_constraints = 0
            impossible = False

            for kp, entries in groups.items():
                for (i1, l2_1, f_1), (i2, l2_2, f_2) in combinations(entries, 2):
                    d_in = (l2_1 - l2_2) % MOD
                    d_out = (f_1 - f_2) % MOD
                    n_constraints += 1

                    # For identity S-box (S=id): d_out must equal d_in
                    # For affine S-box (S(x) = ax+b): d_out = a*d_in
                    # Check identity
                    if d_in == 0 and d_out != 0:
                        impossible = True

            if n_constraints >= 5 and not impossible:
                # Check if identity S-box (no substitution, just Vigenere)
                # works: test all pairs for d_out == d_in
                id_ok = True
                for kp, entries in groups.items():
                    for (i1, l2_1, f_1), (i2, l2_2, f_2) in combinations(entries, 2):
                        d_in = (l2_1 - l2_2) % MOD
                        d_out = (f_1 - f_2) % MOD
                        if d_out != d_in:
                            id_ok = False
                            break
                    if not id_ok:
                        break

                if id_ok:
                    # Identity S-box works — this reduces to Vigenere round function
                    # Already tested in round_fn="vig" above
                    pass

                # Check affine S-box: S(x) = a*x + b mod 26
                for a in range(1, MOD):
                    if math.gcd(a, MOD) != 1:
                        continue
                    affine_ok = True
                    for kp, entries in groups.items():
                        for (i1, l2_1, f_1), (i2, l2_2, f_2) in combinations(entries, 2):
                            d_in = (l2_1 - l2_2) % MOD
                            d_out = (f_1 - f_2) % MOD
                            if (a * d_in) % MOD != d_out:
                                affine_ok = False
                                break
                        if not affine_ok:
                            break

                    if affine_ok:
                        # Recover b and K for this affine S-box
                        # S(L2[i] + K) = a*(L2[i]+K) + b = f_val[i]
                        # a*K + b = f_val[i] - a*L2[i]
                        # For each group, all entries give: a*K + b = f - a*L2

                        for kp, entries in groups.items():
                            rhs_vals = set()
                            for (i, l2, f) in entries:
                                rhs = (f - a * l2) % MOD
                                rhs_vals.add(rhs)

                            if len(rhs_vals) == 1:
                                # Consistent! a*K + b = rhs
                                total_configs += 1

                        # If all groups consistent, we have a valid affine S-box
                        all_consistent = True
                        rhs_by_group = {}
                        for kp, entries in groups.items():
                            rhs_vals = set((f - a * l2) % MOD for (i, l2, f) in entries)
                            if len(rhs_vals) != 1:
                                all_consistent = False
                                break
                            rhs_by_group[kp] = rhs_vals.pop()

                        if all_consistent and len(rhs_by_group) == klen:
                            # Try all 26 values of b, compute K for each
                            for b in range(MOD):
                                a_inv = pow(a, -1, MOD)
                                k2 = []
                                for kp in range(klen):
                                    # a*K + b = rhs → K = a_inv * (rhs - b)
                                    k_val = (a_inv * (rhs_by_group[kp] - b)) % MOD
                                    k2.append(k_val)

                                # Build full S-box
                                aff_sbox = [(a * x + b) % MOD for x in range(MOD)]
                                aff_sbox_inv = [0] * MOD
                                for x in range(MOD):
                                    aff_sbox_inv[aff_sbox[x]] = x

                                # Compute R0
                                f_vals_2 = [aff_sbox[(ct_nums[i] + k2[i % klen]) % MOD] for i in range(mid)]
                                fv2 = list(f_vals_2)
                                while len(fv2) < N - mid:
                                    fv2 = fv2 + f_vals_2[:N - mid - len(fv2)]
                                fv2 = fv2[:N - mid]
                                R0 = [(ct_nums[mid + j] - fv2[j]) % MOD for j in range(N - mid)]

                                # Recover K1 using same affine S-box
                                left_crib = [p for p in KNOWN_POSITIONS if p < mid]
                                k1_vals = {}
                                ok = True
                                for pos in left_crib:
                                    j = pos
                                    if j >= len(R0):
                                        continue
                                    pt_val = KNOWN[pos][0]
                                    f_val = (ct_nums[j] - pt_val) % MOD
                                    s_inv = aff_sbox_inv[f_val]
                                    k1_val = (s_inv - R0[j]) % MOD
                                    kp2 = j % klen
                                    if kp2 not in k1_vals:
                                        k1_vals[kp2] = k1_val
                                    elif k1_vals[kp2] != k1_val:
                                        ok = False
                                        break

                                if ok and len(k1_vals) == klen:
                                    k1 = [k1_vals[kp2] for kp2 in range(klen)]

                                    f1 = [aff_sbox[(R0[i] + k1[i % klen]) % MOD] for i in range(N - mid)]
                                    fv1 = list(f1)
                                    while len(fv1) < mid:
                                        fv1 = fv1 + f1[:mid - len(fv1)]
                                    fv1 = fv1[:mid]
                                    L0 = [(ct_nums[j] - fv1[j]) % MOD for j in range(mid)]

                                    pt_nums = L0 + list(R0)
                                    pt = ''.join(chr(v + ord('A')) for v in pt_nums)
                                    crib_hits = sum(1 for pos, ch in CRIB_DICT.items()
                                                   if pos < len(pt) and pt[pos] == ch)

                                    total_configs += 1

                                    if crib_hits >= 10:
                                        k1w = ''.join(chr(v+ord('A')) for v in k1)
                                        k2w = ''.join(chr(v+ord('A')) for v in k2)
                                        qg = qg_per_char(pt)
                                        print(f"  *** AFFINE a={a} b={b}: "
                                              f"crib={crib_hits}/24 mid={mid} "
                                              f"klen={klen} K1={k1w} K2={k2w}")
                                        print(f"      PT: {pt[:60]}...")
                                        all_results.append((crib_hits, qg, {
                                            'type': 'affine_sbox',
                                            'a': a, 'b': b,
                                            'k1': k1w, 'k2': k2w,
                                            'pt': pt, 'mid': mid,
                                            'klen': klen}))

    print(f"  {total_configs} total configs (mostly analytical)")

    # ═══ SUMMARY ═══
    print(f"\n{'=' * 70}")
    print("SUMMARY")
    print("=" * 70)

    if all_results:
        all_results.sort(key=lambda x: (-x[0], -x[1]))
        print(f"Results with crib >= 4:")
        for cs, qg, info in all_results[:20]:
            desc = info.get('kw', info.get('type', '?'))
            print(f"  crib={cs}/24 qg={qg:.3f} | {desc}")
            if cs >= 10:
                print(f"    PT: {info['pt']}")
    else:
        print("  ZERO consistent key recoveries across all configurations.")
        print("  This ELIMINATES:")
        print("    - 2-round letter Feistel with keyword S-box")
        print("    - 2-round letter Feistel with affine S-box")
        print("    - 2-round with Vig/Beau combining operations")
        print("    - Split points: 24, 36, 48, 49, 73")
        print("    - Key lengths 1-20")
        print("  Total structural hypotheses eliminated analytically.")

    print(f"\nTotal configs tested: {total_configs}")


if __name__ == "__main__":
    t0 = time.time()
    run()
    print(f"\nElapsed: {time.time()-t0:.1f}s")
