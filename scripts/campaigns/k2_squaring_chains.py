#!/usr/bin/env python3
"""
Cipher: Mod-73 squaring chain as key stream / null mask
Family: campaigns
Status: active
Keyspace: ~600 configs

K2 encodes K4 constants: 44²≡38 (mod 73), 38²≡57 (mod 73).
These K2 numbers (38,57,6,5,77,8,44) are linked by squaring mod 73.

Novel hypothesis: the squaring chain generates the KEYSTREAM (not a transposition).
Chain(x) = x, x², x⁴, x⁸, ... (mod 73), then mod 26 as cipher key.

Also tests: chain as null-position selector.
"""
import sys
sys.path.insert(0, "src")
from kryptos.kernel.constants import CT, CRIB_DICT, CRIB_POSITIONS, N_CRIBS, ALPH, ALPH_IDX

def squaring_chain(start: int, modulus: int, length: int) -> list[int]:
    """Generate squaring chain: x, x², x⁴, ... (mod modulus) up to `length` terms."""
    result, x = [], start % modulus
    if x == 0:
        return [0] * length
    for _ in range(length):
        result.append(x)
        x = (x * x) % modulus
        if len(result) > 4 and x == result[0]:  # detected full period
            # Fill remaining by wrapping
            break
    # Detect period for wrapping
    seen, period_start = {}, -1
    chain2 = []
    x = start % modulus
    for i in range(200):
        if x in seen:
            period_start = seen[x]
            break
        seen[x] = i
        chain2.append(x)
        x = (x * x) % modulus
    # Build extended chain
    if period_start == -1:
        # No cycle found within 200 steps - use direct
        return (chain2 * ((length // len(chain2)) + 1))[:length]
    prefix = chain2[:period_start]
    cycle = chain2[period_start:]
    extended = prefix + (cycle * ((length // max(len(cycle), 1)) + 2))
    return extended[:length]

def crib_score(pt: str) -> int:
    return sum(1 for pos, ch in CRIB_DICT.items() if pos < len(pt) and pt[pos] == ch)

def vig_decrypt(ct: str, key: list[int]) -> str:
    n = len(key)
    return "".join(ALPH[(ALPH_IDX[c] - key[i % n]) % 26] for i, c in enumerate(ct))

def beau_decrypt(ct: str, key: list[int]) -> str:
    n = len(key)
    return "".join(ALPH[(key[i % n] - ALPH_IDX[c]) % 26] for i, c in enumerate(ct))

def vbeau_decrypt(ct: str, key: list[int]) -> str:
    n = len(key)
    return "".join(ALPH[(ALPH_IDX[c] + key[i % n]) % 26] for i, c in enumerate(ct))

# K2 numbers: 38°57'6.5"N 77°8'44"W
K2_NUMS = [38, 57, 6, 5, 77, 8, 44]

# Generate squaring chains mod 73 and mod 97 starting from each K2 number
print("=" * 70)
print("K2 SQUARING CHAINS — KEY STREAM ATTACK")
print("=" * 70)
print(f"CT: {CT}")
print()

results = []

for modulus in [73, 97]:
    for start in K2_NUMS + [3, 8, 11, 13, 24]:
        chain = squaring_chain(start, modulus, 97)
        chain_mod26 = [v % 26 for v in chain]

        # Detect non-trivial key (not all zeros, not trivially repeating)
        if len(set(chain_mod26[:20])) < 3:
            continue  # degenerate key

        label_base = f"sq_chain(start={start}, mod={modulus})"

        # Test as full-length key stream (non-repeating)
        for cipher, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", vbeau_decrypt)]:
            pt = fn(CT, chain_mod26)
            sc = crib_score(pt)
            results.append((sc, f"{label_base} {cipher} full", pt))

        # Test as period-k key (first k unique values before cycle)
        for period in range(2, 16):
            key = chain_mod26[:period]
            if len(set(key)) < 2:
                continue
            for cipher, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", vbeau_decrypt)]:
                pt = fn(CT, key)
                sc = crib_score(pt)
                results.append((sc, f"{label_base} {cipher} p={period}", pt))

print(f"Sub-only configs tested: {len(results)}")

# === Part 2: Chain as null-position generator ===
print()
print("--- Squaring chain as null-position mask + substitution ---")
print()

def extract_73(ct: str, null_positions: set) -> str:
    """Remove null positions to get 73-char text."""
    return "".join(c for i, c in enumerate(ct) if i not in null_positions)

def crib_score_shifted(pt73: str, null_positions: set) -> int:
    """Score 73-char PT against cribs, accounting for null removal."""
    # Build mapping: original position → position in 73-char text
    pos73 = 0
    orig_to_73 = {}
    for i in range(97):
        if i not in null_positions:
            orig_to_73[i] = pos73
            pos73 += 1

    score = 0
    for orig_pos, ch in CRIB_DICT.items():
        if orig_pos not in null_positions and orig_pos in orig_to_73:
            new_pos = orig_to_73[orig_pos]
            if new_pos < len(pt73) and pt73[new_pos] == ch:
                score += 1
    return score

# Build null mask from union of squaring chains (mod 73)
# Exclude crib positions: 21-33, 63-73
CRIB_SET = set(CRIB_POSITIONS)

null_candidates = set()
for start in K2_NUMS + [3, 8]:
    chain = squaring_chain(start, 73, 50)
    for v in chain:
        if v < 97 and v not in CRIB_SET:
            null_candidates.add(v)

print(f"Null candidates from all chains (mod 73): {sorted(null_candidates)}")
print(f"Count: {len(null_candidates)}")

# Try using exactly 24 from these candidates
# Prioritize: chains from 44 (most direct K2 connection)
chain44 = squaring_chain(44, 73, 24)
null_mask_44 = set()
for v in chain44:
    if len(null_mask_44) == 24:
        break
    if v < 97 and v not in CRIB_SET:
        null_mask_44.add(v)

if len(null_mask_44) >= 20:
    # Pad to 24 if needed
    for v in sorted(null_candidates):
        if len(null_mask_44) == 24:
            break
        if v not in null_mask_44 and v not in CRIB_SET:
            null_mask_44.add(v)

    if len(null_mask_44) == 24:
        ct73 = extract_73(CT, null_mask_44)
        print(f"\nNull mask from chain(44) mod 73: {sorted(null_mask_44)}")
        print(f"73-char CT: {ct73}")

        # Try simple substitution on 73-char text
        for period in range(1, 16):
            for cipher, fn in [("Vig", vig_decrypt), ("Beau", beau_decrypt), ("VBeau", vbeau_decrypt)]:
                for start_k in K2_NUMS + [3, 8, 11, 13, 24]:
                    key = squaring_chain(start_k, 73, period)
                    key_mod26 = [v % 26 for v in key]
                    if len(set(key_mod26)) < 2:
                        continue
                    pt73 = fn(ct73, key_mod26)
                    sc = crib_score_shifted(pt73, null_mask_44)
                    results.append((sc, f"null44+{cipher}_sq(start={start_k},mod=73,p={period})", pt73))

# === Summary ===
results.sort(key=lambda x: -x[0])
above_noise = [(s, l, p) for s, l, p in results if s > 6]
print(f"\nTotal configs tested: {len(results)}")
print(f"Above noise (>6): {len(above_noise)}")
print()

if above_noise:
    print("ALL ABOVE-NOISE RESULTS:")
    for sc, label, pt in above_noise[:20]:
        matches = [(pos, CRIB_DICT[pos]) for pos in sorted(CRIB_POSITIONS)
                   if pos < len(pt) and pt[pos] == CRIB_DICT[pos]]
        print(f"  Score {sc:2d}/24: {label}")
        print(f"    PT: {pt[:60]}")
        print(f"    Matches: {matches}")
        print()

print("Top 10 results:")
for sc, label, pt in results[:10]:
    print(f"  {sc:2d}/24: {label}")
    print(f"    {pt[:50]}")
print()
print("DONE")
