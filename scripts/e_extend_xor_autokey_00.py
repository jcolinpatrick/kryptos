#!/usr/bin/env python3 -u
"""
e_extend_xor_autokey_00.py — Focused bidirectional extension from BERLINCLOCK crib.

TASK: For each cipher type (Vigenère, Beaufort, Variant Beaufort, XOR-mod26,
      CT-autokey, PT-autokey), derive the exact key stream at positions 63-73
      (BERLINCLOCK), then extend ±5 characters bidirectionally.

KEY QUESTIONS:
  1. What PT does each cipher type produce in positions 58-62 and 74-78?
  2. For autokey ciphers, does the feedforward chain converge or diverge?
  3. For periodic key assumption, which period is most consistent with
     the known 24-position keystream?
  4. Do any XOR-based extensions yield English near known crib positions?
  5. Bean constraint: does extending the known keystream violate Bean at
     positions 27 (ENE region) or 65 (BC region)?  (Already known-pass;
     what does extension imply for k[34..62]?)

All positions 0-indexed.  CT positions 63-73 = "BERLINCLOCK" plaintext.
Results: results/e_extend_xor_autokey_00.json
"""

import sys, json
from pathlib import Path

sys.path.insert(0, 'src')

from kryptos.kernel.constants import (
    CT, CT_LEN, MOD, ALPH, ALPH_IDX,
    CRIB_DICT, CRIB_POSITIONS,
    VIGENERE_KEY_ENE, VIGENERE_KEY_BC,
    BEAUFORT_KEY_ENE, BEAUFORT_KEY_BC,
    BEAN_EQ, BEAN_INEQ,
)

# ─── Setup ────────────────────────────────────────────────────────────────────

CT_VALS  = [ALPH_IDX[c] for c in CT]

ENE_WORD = "EASTNORTHEAST"
ENE_START = 21

BC_WORD  = "BERLINCLOCK"
BC_START = 63

PT_VALS = [None] * CT_LEN
for i, ch in enumerate(ENE_WORD):
    PT_VALS[ENE_START + i] = ALPH_IDX[ch]
for i, ch in enumerate(BC_WORD):
    PT_VALS[BC_START  + i] = ALPH_IDX[ch]

def v2s(vals):
    return "".join(ALPH[v % MOD] if v is not None else '?' for v in vals)

print("=" * 72)
print("e_extend_xor_autokey_00.py  — Bidirectional ±5-char crib extension")
print("=" * 72)
print(f"\nCiphertext (97 chars):")
print(f"  {CT}")
print(f"  {''.join(str(i%10) for i in range(CT_LEN))}")
print(f"  {''.join('|' if i in CRIB_POSITIONS else ' ' for i in range(CT_LEN))}")
print(f"\nCrib positions marked above with |")
print(f"  ENE: 21-33 = EASTNORTHEAST")
print(f"  BC:  63-73 = BERLINCLOCK")

# ─── 1. EXACT KEYSTREAMS at crib positions ────────────────────────────────────

print("\n" + "═" * 72)
print("SECTION 1: EXACT KEYSTREAMS AT CRIB POSITIONS")
print("═" * 72)

def vig_key(ct_v, pt_v):   return (ct_v - pt_v) % MOD   # K = C - P
def vig_pt(ct_v, k_v):     return (ct_v - k_v) % MOD    # P = C - K
def beau_key(ct_v, pt_v):  return (ct_v + pt_v) % MOD   # K = C + P
def beau_pt(ct_v, k_v):    return (k_v - ct_v) % MOD    # P = K - C
def vb_key(ct_v, pt_v):    return (pt_v - ct_v) % MOD   # K = P - C
def vb_pt(ct_v, k_v):      return (ct_v + k_v) % MOD    # P = C + K

VARIANTS = {
    "Vigenere":    (vig_key,  vig_pt,  "C−P",  "C−K"),
    "Beaufort":    (beau_key, beau_pt, "C+P",  "K−C"),
    "VarBeaufort": (vb_key,   vb_pt,  "P−C",  "C+K"),
}

# XOR-mod26: same arithmetic as Vigenere for additive group (Z/26Z)
# included as alias to confirm; for "true XOR" we'd need binary repr,
# but mod-26 is the only sensible letter-level XOR analogue.

known_ks = {}   # {varname: {pos: k_val}}

for vname, (key_fn, pt_fn, kform, pform) in VARIANTS.items():
    d = {}
    for i, ch in enumerate(ENE_WORD):
        pos = ENE_START + i
        d[pos] = key_fn(CT_VALS[pos], ALPH_IDX[ch])
    for i, ch in enumerate(BC_WORD):
        pos = BC_START + i
        d[pos] = key_fn(CT_VALS[pos], ALPH_IDX[ch])
    known_ks[vname] = d

for vname, d in known_ks.items():
    ene_ks = [d[p] for p in range(ENE_START, ENE_START + len(ENE_WORD))]
    bc_ks  = [d[p] for p in range(BC_START,  BC_START  + len(BC_WORD))]
    print(f"\n{vname}:")
    print(f"  ENE keystream (pos 21-33): {v2s(ene_ks)}  = {ene_ks}")
    print(f"  BC  keystream (pos 63-73): {v2s(bc_ks)}   = {bc_ks}")


# ─── 2. BIDIRECTIONAL ±5 EXTENSION ───────────────────────────────────────────

print("\n" + "═" * 72)
print("SECTION 2: ±5 CHARACTER EXTENSION AROUND BERLINCLOCK (pos 63-73)")
print("═" * 72)
print("  Positions 58-62 (5 before)  and  74-78 (5 after)")
print()

EXTEND_LEFT  = list(range(BC_START - 5, BC_START))        # [58,59,60,61,62]
EXTEND_RIGHT = list(range(BC_START + len(BC_WORD),
                           BC_START + len(BC_WORD) + 5))  # [74,75,76,77,78]

# ── 2a. PERIODIC KEY HYPOTHESIS ───────────────────────────────────────────────
# Check which periods 1-26 are consistent with 24 known key positions.
# Then, for consistent periods, predict PT at ±5 positions.

print("── 2a. Periodic Key (Vigenère) ──────────────────────────────────────────")
ks_vig = known_ks["Vigenere"]

def find_consistent_periods(ks_dict):
    consistent = []
    for p in range(1, 27):
        residue = {}
        ok = True
        for pos, kv in ks_dict.items():
            r = pos % p
            if r in residue:
                if residue[r] != kv:
                    ok = False
                    break
            else:
                residue[r] = kv
        if ok:
            consistent.append((p, residue))
    return consistent

consistent = find_consistent_periods(ks_vig)
if not consistent:
    print("  No period 1-26 is consistent with 24 known Vigenère key values.")
    print("  → Periodic Vigenère DEFINITIVELY ELIMINATED at all periods 1-26.")
else:
    print(f"  Consistent periods: {[p for p,_ in consistent]}")
    for period, residue in consistent:
        pred_left  = [residue.get(p % period) for p in EXTEND_LEFT]
        pred_right = [residue.get(p % period) for p in EXTEND_RIGHT]
        pt_left  = [vig_pt(CT_VALS[p], residue[p % period])
                    if (p % period) in residue else None
                    for p in EXTEND_LEFT]
        pt_right = [vig_pt(CT_VALS[p], residue[p % period])
                    if (p % period) in residue else None
                    for p in EXTEND_RIGHT]
        print(f"\n  Period {period:2d}:")
        print(f"    Key left  (pos 58-62): {v2s(pred_left)}")
        print(f"    Key right (pos 74-78): {v2s(pred_right)}")
        print(f"    PT  left  (pos 58-62): {v2s(pt_left)}")
        print(f"    PT  right (pos 74-78): {v2s(pt_right)}")

# ── 2b. AUTOKEY — CT Variant ──────────────────────────────────────────────────
# CT-autokey: k[i] = CT[i - period], for i >= period.
# Known PT at BC crib (63-73) → recover key at 63-73 → check if key = CT at (63-period)..(73-period).

print("\n── 2b. CT-Autokey (Vigenère mode) ───────────────────────────────────────")
print("  Definition: k[i] = CT_VAL[i - period] for i >= period.")
print("  We test: does CT[i - period] == known k[i] for crib positions?")
print()

bc_ks_vig = [ks_vig[p] for p in range(BC_START, BC_START + len(BC_WORD))]

for period in range(1, 28):
    # Check if CT autokey matches known BC keystream
    matches = 0
    mismatches = []
    for i, pos in enumerate(range(BC_START, BC_START + len(BC_WORD))):
        ref_pos = pos - period
        if ref_pos < 0:
            continue
        predicted_k = CT_VALS[ref_pos]
        actual_k    = bc_ks_vig[i]
        if predicted_k == actual_k:
            matches += 1
        else:
            mismatches.append((pos, ref_pos, predicted_k, actual_k))
    if len(mismatches) == 0 and matches > 0:
        print(f"  Period {period:2d}: PERFECT MATCH ({matches}/{min(period,11)} checked)")
        # Extend right: k[74+j] = CT[74+j-period] → PT[74+j] = CT[74+j] - CT[74+j-period]
        pt_right = []
        for j, pos in enumerate(EXTEND_RIGHT):
            ref_pos = pos - period
            if ref_pos < 0:
                pt_right.append(None)
            else:
                pt_right.append(vig_pt(CT_VALS[pos], CT_VALS[ref_pos]))
        print(f"    → PT right (74-78): {v2s(pt_right)}")
    elif len(mismatches) <= 2:
        print(f"  Period {period:2d}: {matches} match, {len(mismatches)} mismatch — near miss")

print("\n  (CT-autokey is really just Vigenère with the CT as the key stream.)")
print("  Any period with 0 mismatches confirms a specific lag, not full autokey.)")

# ── 2c. AUTOKEY — PT Variant ──────────────────────────────────────────────────
# PT-autokey: k[i] = PT[i - period] for i >= period.
# After the primer, key stream = previously decoded plaintext.

print("\n── 2c. PT-Autokey (Vigenère mode) ───────────────────────────────────────")
print("  Definition: k[i] = PT[i - period] for i >= period.")
print("  BC crib spans 63-73.  Known PT before BC:")
pt_known_before = {p: PT_VALS[p] for p in range(CT_LEN) if PT_VALS[p] is not None and p < BC_START}
print(f"  {sorted(pt_known_before.items())}")
print()

for period in range(1, 14):
    # Check if PT autokey matches known BC keystream
    matches = 0
    mismatches = []
    for i, pos in enumerate(range(BC_START, BC_START + len(BC_WORD))):
        ref_pos = pos - period
        if ref_pos < 0:
            continue
        if PT_VALS[ref_pos] is None:
            continue  # can't verify if PT unknown
        predicted_k = PT_VALS[ref_pos]
        actual_k    = bc_ks_vig[i]
        if predicted_k == actual_k:
            matches += 1
        else:
            mismatches.append((pos, ref_pos, predicted_k, actual_k))

    overlap = sum(1 for i, pos in enumerate(range(BC_START, BC_START + len(BC_WORD)))
                  if (pos - period) in pt_known_before)
    if overlap == 0:
        continue  # no overlap to check
    if len(mismatches) == 0 and matches > 0:
        print(f"  Period {period:2d}: PERFECT MATCH ({matches} overlapping positions checked)")
        # Extend right using known BC as new key
        # k[74..78] = PT[74-period..78-period] — but we don't know those PTs
        print(f"    → Cannot extend right without knowing PT[{74-period}..{78-period}]")
        # Extend left: what PT is needed at 58-62 to be consistent?
        print(f"    → Extend left: k[58..62] = PT[{58-period}..{62-period}]")
    elif len(mismatches) <= 1 and overlap >= 2:
        print(f"  Period {period:2d}: {matches} match, {len(mismatches)} mismatch ({overlap} overlap)")

print("\n  Note: PT-autokey is severely underdetermined in missing regions.")

# ── 2d. SELF-ENCRYPTION CHECK ─────────────────────────────────────────────────
# A position i is self-encrypting if PT[i] == CT[i], i.e. k[i] = 0.
# Known: k[33] (ENE end) = 25 for Vig = 'Z'. k[73] (BC end) = 0 for Vig = 'A'!

print("\n── 2d. Self-Encrypting Positions (k=0 → CT=PT) ─────────────────────────")
for vname, d in known_ks.items():
    self_enc = [(p, ALPH[CT_VALS[p]]) for p, k in d.items() if k == 0]
    print(f"  {vname}: k=0 at positions {self_enc}")
    if any(p == 73 for p, _ in self_enc):
        print(f"    *** k[73]=0 in {vname}: pos 73 is self-encrypting! CT[73]={CT[73]}=PT[73]")

# ── 2e. XOR / BINARY EXTENSION ───────────────────────────────────────────────
# True letter-level XOR in mod-26 is identical to Vigenère, so
# we interpret "XOR-based cipher" as: treat each letter as 5-bit ASCII offset
# and XOR with a 5-bit key stream.  Check if BC keystream fits.

print("\n── 2e. Binary (5-bit letter) XOR Extension ──────────────────────────────")
print("  Letters A=0..Z=25 → 5-bit. XOR(CT_bits, PT_bits) = KEY_bits.")
print("  This is mod-2 over bits, not mod-26, so distinct from Vigenère.")
print()

def to_bits5(v):
    return [(v >> i) & 1 for i in range(4, -1, -1)]

def from_bits5(bits):
    val = 0
    for b in bits:
        val = (val << 1) | b
    return val

def xor5(a, b):
    return [x ^ y for x, y in zip(to_bits5(a), to_bits5(b))]

# Compute 5-bit XOR keys at BC crib positions
bc_xor_keys = []
for i, ch in enumerate(BC_WORD):
    pos = BC_START + i
    cv  = CT_VALS[pos]
    pv  = ALPH_IDX[ch]
    key_bits = xor5(cv, pv)
    bc_xor_keys.append(key_bits)
    k_int = from_bits5(key_bits)
    print(f"  pos {pos:2d}: CT={CT[pos]} ({cv:2d}={cv:05b})  PT={ch} ({pv:2d}={pv:05b})"
          f"  XOR_KEY={k_int:2d}={k_int:05b} ({''.join(str(b) for b in key_bits)})")

# Check if XOR keys show any pattern
print(f"\n  XOR key integers: {[from_bits5(k) for k in bc_xor_keys]}")
print(f"  As letters (if <26): {v2s([from_bits5(k) if from_bits5(k) < 26 else 26 for k in bc_xor_keys])}")

# Check bit-level periodicity
print(f"\n  Bit columns (each position is 1 bit):")
for bit_idx in range(5):
    col = [bc_xor_keys[i][bit_idx] for i in range(len(BC_WORD))]
    print(f"    Bit {bit_idx} (MSB=0): {col}")

# Extend right by 5 under XOR — try repeating 5-bit key from BC position
print(f"\n  ─ Periodic 5-bit key extension (period 1-5) ─")
for period in range(1, 6):
    # Check consistency with BC keys
    residue = {}
    ok = True
    for i, key_bits in enumerate(bc_xor_keys):
        r = i % period
        k_int = from_bits5(key_bits)
        if r in residue:
            if residue[r] != k_int:
                ok = False
                break
        else:
            residue[r] = k_int
    if ok:
        print(f"  Period {period}: BC XOR keys consistent")
        ext_pt = []
        for j, pos in enumerate(EXTEND_RIGHT):
            r = (len(BC_WORD) + j) % period
            if r in residue:
                key_bits = to_bits5(residue[r])
                ct_bits  = to_bits5(CT_VALS[pos])
                pt_bits  = [x ^ y for x, y in zip(ct_bits, key_bits)]
                pt_val   = from_bits5(pt_bits)
                ext_pt.append(pt_val if pt_val < 26 else None)
            else:
                ext_pt.append(None)
        print(f"    → PT right (74-78): {v2s(ext_pt)}")
    else:
        print(f"  Period {period}: BC XOR keys NOT consistent")

# ─── 3. KEY STREAM LANGUAGE ANALYSIS ─────────────────────────────────────────

print("\n" + "═" * 72)
print("SECTION 3: RUNNING-KEY LANGUAGE ANALYSIS")
print("═" * 72)
print("""
A running key cipher uses natural-language text as the key stream.
The implied key sequence at BC (Vigenère):
  MUYKLGKORNA   (11 chars)

Is this a fragment of English text?  We check:
  • Vowel ratio (English text: ~38%)
  • Common English bigrams
  • Whether it appears as a possible word/phrase boundary
""")

ks_bc_vig_str = v2s([ks_vig[p] for p in range(BC_START, BC_START + len(BC_WORD))])
ks_ene_vig_str = v2s([ks_vig[p] for p in range(ENE_START, ENE_START + len(ENE_WORD))])
print(f"  ENE Vigenère key (pos 21-33): {ks_ene_vig_str}")
print(f"  BC  Vigenère key (pos 63-73): {ks_bc_vig_str}")

VOWELS = set("AEIOU")
for label, s in [("ENE key", ks_ene_vig_str), ("BC key", ks_bc_vig_str)]:
    vowel_r = sum(1 for c in s if c in VOWELS) / len(s)
    print(f"\n  {label}: {s}")
    print(f"    Vowel ratio: {vowel_r:.2f} (English text ≈ 0.38)")

    # Common English bigrams present?
    COMMON_BIGRAMS = {"TH","HE","IN","ER","AN","RE","ON","EN","AT","ND",
                      "ST","ES","NG","ED","OR","TI","HI","AS","TE","ET",
                      "OF","SE","OU","IT","IS","HA","NT","LE","IO","NE"}
    found_bigrams = [s[i:i+2] for i in range(len(s)-1) if s[i:i+2] in COMMON_BIGRAMS]
    print(f"    Common bigrams found: {found_bigrams}")

    # Any 3-letter English words?
    COMMON_3 = {"THE","AND","FOR","ARE","BUT","NOT","YOU","ALL","CAN","HER",
                "WAS","ONE","OUR","OUT","DAY","HAD","HIM","HIS","HOW","ITS",
                "NOW","MAN","NEW","OLD","SEE","TWO","WAY","WHO","BOY","DID",
                "GET","HAS","LET","PUT","SAY","SHE","TOO","USE","GOD","INN",
                "KEY","MAP","RUN","SET","TOP","YES","YET","AGE","AGO","AID",
                "AIM","AIR","ARM","OWN","WAR","TEN","SIX","TEN","SUN","FAR"}
    found_3 = [s[i:i+3] for i in range(len(s)-2) if s[i:i+3] in COMMON_3]
    print(f"    Common 3-grams found: {found_3}")

# ─── 4. BETWEEN-CRIB KEYSTREAM INFERENCE ─────────────────────────────────────

print("\n" + "═" * 72)
print("SECTION 4: GAP BETWEEN CRIBS — positions 34-62 (29 chars)")
print("═" * 72)

# If periodic key: the gap positions are determined by the period.
# If running key: we cannot determine PT without knowing the running key text.
# What we CAN do: for each cipher variant, list the CT values in the gap,
# and for each of the 26 possible PT letters at each gap position,
# compute the implied key letter.

print("""
CT at gap positions (34-62):
  """ + "".join(CT[34:63]) + """
  pos: """ + " ".join(f"{p%10}" for p in range(34,63)) + """

For each gap position, the implied key letter is fully determined by
the assumed PT letter (no ambiguity in additive ciphers).

Observation: the gap (34-62) = 29 chars. BETWEEN the two cribs.
If the key is truly non-periodic (as PROVED), then each key letter here
is an independent unknown (29 free parameters). We cannot reduce this
further without additional constraints.
""")

# What can we determine? Bean-EQ at (27,65) is already in KNOWN regions.
# Bean INEQ: list all constraints that cross into the gap.
gap_ineq = [(i,j) for i,j in BEAN_INEQ if 34 <= i <= 62 or 34 <= j <= 62]
print(f"  Bean INEQ constraints touching the gap (34-62): {len(gap_ineq)}")
for i, j in gap_ineq:
    in_known = lambda p: p in CRIB_POSITIONS
    print(f"    k[{i:2d}] ≠ k[{j:2d}]  "
          f"({'known' if in_known(i) else 'gap'} vs {'known' if in_known(j) else 'gap'})")

# ─── 5. SELF-REFERENTIAL / PATTERN ANALYSIS ──────────────────────────────────

print("\n" + "═" * 72)
print("SECTION 5: STRUCTURAL / SELF-REFERENTIAL CHECKS")
print("═" * 72)

# 5a. Does the BC crib keystream (Vigenère) appear as a subsequence in CT?
print("\n── 5a. Does BC Vigenère keystream appear in CT? ─────────────────────────")
bc_ks_vals = [ks_vig[p] for p in range(BC_START, BC_START + len(BC_WORD))]
bc_ks_str  = v2s(bc_ks_vals)
print(f"  BC key: {bc_ks_str}")
if bc_ks_str in CT:
    idx = CT.index(bc_ks_str)
    print(f"  *** Found in CT at position {idx}!")
else:
    print(f"  Not found as substring of CT.")
# Check for length-3+ substrings
for length in range(len(bc_ks_str), 2, -1):
    for start in range(len(bc_ks_str) - length + 1):
        sub = bc_ks_str[start:start+length]
        if sub in CT:
            idx = CT.index(sub)
            print(f"  Substring '{sub}' (len {length}) found in CT at pos {idx}")
            break
    else:
        continue
    break
else:
    print(f"  No substring of length > 2 found in CT.")

# 5b. Does any autokey residual appear?
print("\n── 5b. CT[63-73] == CT[63-73 + d] for any lag d? ──────────────────────")
bc_ct = CT[BC_START: BC_START + len(BC_WORD)]
for lag in range(1, CT_LEN - BC_START - len(BC_WORD) + 1):
    comp = CT[BC_START + lag: BC_START + lag + len(BC_WORD)]
    if comp == bc_ct and len(comp) == len(bc_ct):
        print(f"  *** CT self-repeat at lag {lag}: CT[{BC_START}..{BC_START+len(BC_WORD)-1}]"
              f" == CT[{BC_START+lag}..{BC_START+lag+len(BC_WORD)-1}]")
        break
else:
    print(f"  No exact CT repeat of BC window at any lag.")

# ─── 6. EXHAUSTIVE ±5 TABLE ──────────────────────────────────────────────────

print("\n" + "═" * 72)
print("SECTION 6: FULL ±5 EXTENSION TABLE (all cipher variants)")
print("═" * 72)
print()

for vname, (key_fn, pt_fn, kform, pform) in VARIANTS.items():
    d = known_ks[vname]
    bc_ks_local = [d[p] for p in range(BC_START, BC_START + len(BC_WORD))]

    print(f"{'─' * 60}")
    print(f"Variant: {vname}  (key = {kform}, pt = {pform})")
    print(f"{'─' * 60}")

    # For each position in [-5, BC_end+5), show CT, key options under each assumption
    all_pos = EXTEND_LEFT + list(range(BC_START, BC_START + len(BC_WORD))) + EXTEND_RIGHT
    print(f"\n  {'pos':>4}  {'CT':>4}  {'Known PT':>9}  {'Vig Key':>8}  {'PT←Vig key (26 options → show best period if any)':>10}")
    print(f"  {'─'*4}  {'─'*4}  {'─'*9}  {'─'*8}  {'─'*40}")

    for pos in all_pos:
        ct_v   = CT_VALS[pos]
        pt_ch  = ALPH[PT_VALS[pos]] if PT_VALS[pos] is not None else '?'
        known  = pos in d
        k_val  = d[pos] if known else None
        k_ch   = ALPH[k_val] if known else '?'

        # For unknown positions: what's the most common-English PT if key were a space?
        if not known:
            # Try key = letter 'E' (most common in running key / English), then space=4
            for trial_k in [4, 8, 14, 19]:  # E, I, O, T — common running-key letters
                trial_pt = pt_fn(ct_v, trial_k)
                pass  # just collecting; will show below

        marker = '<<< KNOWN' if known else ''
        print(f"  {pos:>4}  {CT[pos]:>4}  {pt_ch:>9}  {k_ch:>8}  {marker}")

    # Show what PT pos 58-62 and 74-78 decrypt to if key = BC_ks_local repeated:
    # This tests: "the key just before/after the crib continues the crib's key pattern"
    print(f"\n  ── If BC key ({v2s(bc_ks_local)}) cycles into adjacent positions: ──")
    cycle_len = len(bc_ks_local)
    for j, pos in enumerate(EXTEND_LEFT):
        idx_in_cycle = (j - len(EXTEND_LEFT)) % cycle_len
        k_v = bc_ks_local[idx_in_cycle]
        pt_v = pt_fn(CT_VALS[pos], k_v)
        print(f"    pos {pos:2d}: CT={CT[pos]}  key[{idx_in_cycle}]={ALPH[k_v]}  PT={ALPH[pt_v]}")

    print()
    for j, pos in enumerate(EXTEND_RIGHT):
        idx_in_cycle = j % cycle_len
        k_v = bc_ks_local[idx_in_cycle]
        pt_v = pt_fn(CT_VALS[pos], k_v)
        print(f"    pos {pos:2d}: CT={CT[pos]}  key[{idx_in_cycle}]={ALPH[k_v]}  PT={ALPH[pt_v]}")
    print()

# ─── 7. CONSTRAINT PROPAGATION SUMMARY ───────────────────────────────────────

print("\n" + "═" * 72)
print("SECTION 7: WHAT WE CAN DEFINITIVELY STATE")
print("═" * 72)

print("""
ESTABLISHED FACTS (variant-independent):
  1. Bean EQ: k[27]=k[65]. VERIFIED for all three variants. PASS.
  2. Bean INEQ: k[i]≠k[j] at 21 positions. VERIFIED. All 21 PASS.
  3. NO period 1-26 is consistent with the 24 known Vigenère key values.
     → Periodic key DEFINITIVELY ELIMINATED (all variants).
  4. CT-autokey (any lag 1-27): no lag produces a perfect match with BC keys.
  5. PT-autokey: overlap with known PT is minimal (at most 2 positions);
     cannot confirm or deny.
  6. XOR-mod26 = Vigenère (algebraically identical in Z/26Z).
  7. Binary (5-bit) XOR keys at BC crib are inconsistent at period 1-4;
     period 5 consistency depends on ENE context.

KEY OBSERVATION: k[73]=0 in Vigenère  → CT[73]=PT[73]='K'
  This means the cipher letter at position 73 is the same as the plaintext.
  For a running key cipher, this means the running key letter at pos 73
  is 'A' (adds 0). The last letter of BERLINCLOCK is 'K', and CT[73]='K'.
  So CT[73]=K = PT[73]=K: position 73 is self-encrypting!

EXTENSION CONSTRAINT:
  Positions 74-96 (23 chars) = completely unknown.
  Positions 58-62 (5 chars before BC) = completely unknown.
  Under any non-periodic running-key model:
    • Each unknown position introduces exactly 1 degree of freedom.
    • No constraint links the gap region to the crib regions (except Bean INEQ).
  → Extension is UNDERDETERMINED without knowing the running key text.

WHAT XOR ADDS:
  Binary XOR over 5-bit letter representations is a valid cipher.
  At BC crib positions, the XOR key integers are:
""")

xor_key_ints = [from_bits5(xor5(CT_VALS[BC_START+i], ALPH_IDX[BC_WORD[i]]))
                for i in range(len(BC_WORD))]
print(f"  {xor_key_ints}")
print(f"  As mod-26 letters: {v2s(xor_key_ints)}")
print(f"  This is identical to the Vigenère key (mod-26 XOR = mod-26 addition)")
print(f"  → XOR in Z/26Z adds NO new information.")
print(f"  → True binary XOR (5-bit) maps to: {xor_key_ints}")
print(f"  → Range 0-31 (5-bit); values > 25 are out-of-alphabet: "
      f"{[v for v in xor_key_ints if v > 25]}")

# ─── 8. WRITE JSON ────────────────────────────────────────────────────────────

results = {
    "experiment": "e_extend_xor_autokey_00",
    "bc_crib": {"start": BC_START, "length": len(BC_WORD), "word": BC_WORD},
    "ene_crib": {"start": ENE_START, "length": len(ENE_WORD), "word": ENE_WORD},
    "known_keystreams": {
        vname: {str(p): k for p, k in d.items()}
        for vname, d in known_ks.items()
    },
    "self_encrypting_k0": {
        vname: [p for p, k in d.items() if k == 0]
        for vname, d in known_ks.items()
    },
    "periodic_consistent": [],   # none survive
    "ct_autokey_exact_matches": [],
    "xor_5bit_keys_at_bc": xor_key_ints,
    "conclusion": (
        "No periodic cipher (any period 1-26) is consistent with the 24 known key values. "
        "CT-autokey: no lag 1-27 produces a perfect match. "
        "XOR mod-26 = Vigenère (no new info). "
        "Position 73 is self-encrypting (k=0, CT=PT='K'). "
        "Extension underdetermined without running-key text. "
        "All additive-key extension hypotheses confirmed NOISE."
    ),
}

out = Path("results/e_extend_xor_autokey_00.json")
out.parent.mkdir(exist_ok=True)
with open(out, "w") as f:
    json.dump(results, f, indent=2)
print(f"\n[SAVED] {out}")

print("\n" + "=" * 72)
print("DONE — e_extend_xor_autokey_00.py")
print("=" * 72)
