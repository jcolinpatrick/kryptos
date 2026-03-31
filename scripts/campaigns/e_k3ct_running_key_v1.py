#!/usr/bin/env python3
"""Test K3 CT (carved ciphertext) as running key for K4.

Prior testing used K3 PLAINTEXT and K1K2K3 PT concatenation.
K3 CT itself (the carved Kryptos sculpture text for section 3)
was NOT in the 38-text reference set. This fills that gap.

Also tests: K3 CT reversed, K1/K2 CT, combined CTs, KA vs AZ indexing.

Key fingerprint (Beaufort A=0, crib positions):
  pos 21-33: J L J O D E G K U K K K L
  pos 63-73: O C G G B G O K T R U
"""
# DEPRECATED: This script is retained as a historical artifact.
# Superseded by newer analysis. Do not cite results as current.
# See docs/SCRIPT_RIGOR_STANDARD.md

import sys
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT as K4_CT, CRIB_WORDS, CRIB_DICT

CRIBS = CRIB_WORDS
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"

# K3 CT (336 chars) from sculpture rows 14-24 of 28x31 grid
K3_CT = ("ENDYAHROHNLSRHEOCPTEOIBIDYSHNAIACHTNREYULDSLLSLLNOHSNOSMRWXMNET"
         "PRNGATIHNRARPESLNNELEBLPIIACAEWMTWNDITEENRAHCTENEUDRETNHAEOETFOL"
         "SEDTIWENHAEIOYTEYQHEENCTAYCREIFTBRSPAMHHEWENATAMATEGYEERLBTEEFO"
         "ASFIOTUETUAEOTOARMAEERTNRTIBSEDDNIAAHTTMSTEWPIEROAGRIEWFEBAECTDD"
         "HILCEIHSITEGOEAOSDDRYDLORITRKLMLEHAGTDHARDPNEOHMGFMFEUHEECDMRIP"
         "FEIMEHNLSSTTRTVDOHW")

# K1 CT (63 chars)
K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"[:63]

# K2 CT (369 chars, stripped of ?)
K2_RAW = ("VFPJUDEEHZWETZYVGWHKKQETGFQJNCEGGWHKKDQMCPFQZDQMMIAGPFXHQRLG"
          "TMJLTEVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFVVJKTUJNMOUVJJRKOUYGJJ"
          "VUUQPJLIIFHGQHLTTKMUJJLIHQUVTTCLJUJTPPKOGHVNHHJKJUQTMKKYRDMFD"
          "DUVHJJJMMLLORDTJDOHSUYGJJUUQPJLLVUUTTCLJUTPPKOGHVNHHJKJUQTMKK"
          "YRDMFXXXTJOFDTOFMRJEAIWFMGWDMFPZJXZSFVRNHIYVFLQHIZBGJQGLJMFQL"
          "BVIJMBBQLIMKNFMFMQFBQMFKFQVPMFUIFBFVGZXFBNHBFVGMFBQMFKFQVPMF"
          "UIFBFVGZXFBNHBFVG")[:369]

# Compute known Beaufort key at crib positions
CRIB_KEY = {}
for (start, word) in CRIBS:
    for j, ch in enumerate(word):
        pos = start + j
        ct_ch = K4_CT[pos]
        pt_val = AZ.index(ch)
        ct_val = AZ.index(ct_ch)
        key_val = (pt_val + ct_val) % 26
        CRIB_KEY[pos] = key_val  # AZ index of key letter

CRIB_POSITIONS = sorted(CRIB_KEY.keys())
N_CRIBS = len(CRIB_POSITIONS)

print(f"Testing K3/K2/K1 CT as running key for K4")
print(f"Known key fingerprint: {N_CRIBS} positions")
key_str = ''.join(AZ[CRIB_KEY[p]] for p in CRIB_POSITIONS)
print(f"  Positions {CRIB_POSITIONS[0]}-{CRIB_POSITIONS[12]}: {key_str[:13]}")
print(f"  Positions {CRIB_POSITIONS[13]}-{CRIB_POSITIONS[23]}: {key_str[13:]}")
print()

def score_source(source, label, alpha=AZ):
    """Test source text as Beaufort running key at all circular offsets."""
    src_len = len(source)
    if src_len < 97:
        # Too short - only try if long enough to cover crib positions
        if src_len <= max(CRIB_POSITIONS):
            print(f"  {label}: too short ({src_len} chars), skipping")
            return

    best = 0
    best_offset = -1
    results = []

    for o in range(src_len):
        score = 0
        for pos, expected_key_val in CRIB_KEY.items():
            src_idx = (pos + o) % src_len  # align: source[pos+o] = key[pos]
            ch = source[src_idx]
            if ch not in alpha:
                continue
            key_val = alpha.index(ch)
            if key_val == expected_key_val:
                score += 1
        if score > best:
            best = score
            best_offset = o
            if score >= 8:
                results.append((o, score))

    if best >= 6:
        print(f"  {label}: best={best}/{N_CRIBS} at offset={best_offset} "
              f"(src[{(21+best_offset)%src_len}:{(33+best_offset)%src_len+1}]="
              f"{''.join(source[(pos+best_offset)%src_len] for pos in CRIB_POSITIONS[:5])}...)")
        for o, sc in sorted(results, key=lambda x: -x[1])[:5]:
            print(f"    offset={o}: score={sc}/{N_CRIBS}")
    else:
        print(f"  {label}: best={best}/{N_CRIBS} (noise)")
    return best

# Build K1K2K3 combined CTs
K1K2K3_CT = K1_CT + K2_RAW + K3_CT  # 63+369+336=768
K1K3_CT = K1_CT + K3_CT              # 63+336=399

print("=== Testing K-series CTs as running keys (AZ alphabet) ===")
score_source(K3_CT, "K3 CT (336 chars, AZ)", AZ)
score_source(K3_CT[::-1], "K3 CT reversed (AZ)", AZ)
score_source(K1K2K3_CT, "K1+K2+K3 CT concat (AZ)", AZ)
score_source(K1K2K3_CT[::-1], "K1+K2+K3 CT reversed (AZ)", AZ)
score_source(K1_CT, "K1 CT (63 chars, AZ)", AZ)
score_source(K2_RAW, "K2 CT (369 chars, AZ)", AZ)
score_source(K4_CT, "K4 CT self (97 chars, AZ)", AZ)  # self-referential

print()
print("=== Testing K3 CT with KA alphabet ===")
score_source(K3_CT, "K3 CT (KA alphabet)", KA)
score_source(K1K2K3_CT, "K1+K2+K3 CT (KA alphabet)", KA)

print()
print("=== Testing K4 CT variants ===")
# K4 CT shifted by various amounts (self-referential key at offset d)
best_self = 0
best_d = -1
for d in range(1, 97):
    score = 0
    for pos, expected_key_val in CRIB_KEY.items():
        key_char = K4_CT[(pos + d) % 97]
        if AZ.index(key_char) == expected_key_val:
            score += 1
    if score > best_self:
        best_self = score
        best_d = d
print(f"  K4 CT self-shift: best={best_self}/{N_CRIBS} at shift d={best_d}")

# K4 CT XOR-style: key[i] = CT[(i+d) % 97] + delta mod 26
if best_self >= 6:
    # Try AZ shift
    for delta in range(26):
        score = 0
        for pos, expected_key_val in CRIB_KEY.items():
            key_char = K4_CT[(pos + best_d) % 97]
            key_val = (AZ.index(key_char) + delta) % 26
            if key_val == expected_key_val:
                score += 1
        if score >= 8:
            print(f"    K4 self-shift d={best_d}, delta={delta}: {score}/{N_CRIBS}")

print()
print("=== Complete Period Impossibility Proof ===")
# Prove no periodic key of any period 1-97 works
# Key fingerprint known at 24 positions
key_vals = {pos: CRIB_KEY[pos] for pos in CRIB_POSITIONS}

impossible_count = 0
for period in range(1, 98):
    # For a period-P key: key[a] = key[b] iff a ≡ b (mod P)
    # Check: do any pairs (a,b) with same key value have a difference NOT divisible by P?
    # More precisely: do any pairs (a,b) with different key values have difference divisible by P?
    contradiction = False
    for i, pos_a in enumerate(CRIB_POSITIONS):
        for pos_b in CRIB_POSITIONS[i+1:]:
            if (pos_b - pos_a) % period == 0:  # same residue mod P
                if key_vals[pos_a] != key_vals[pos_b]:
                    contradiction = True
                    break
        if contradiction:
            break

    if contradiction:
        impossible_count += 1
    else:
        # Not contradicted - needs further analysis
        print(f"  Period {period}: NOT ruled out by crib key constraints!")

print(f"Periods 1-97 with contradictions: {impossible_count}/97")
if impossible_count == 97:
    print("  COMPLETE PROOF: No periodic key of any period 1-97 can produce K4 cribs.")
    print("  The K4 cipher MUST use a non-periodic key (running key or one-time pad).")
else:
    print(f"  {97 - impossible_count} periods survived - need further analysis")

print("\nDone.")
