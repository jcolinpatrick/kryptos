#!/usr/bin/env python3
"""
grille_rotation_k1.py   [Approach C, 2026-03-13]

HYPOTHESIS: Under 180° rotation of the 28×31 grid — (r,c)→(27-r,30-c) —
K4 (rows 24-27) maps onto K1/K2 region (rows 0-3).  K4 rows 26-27 map
directly onto K1 rows 0-1, for which we know BOTH the ciphertext AND the
plaintext.  Classification rules based on the K1 partner may identify which
K4 positions are grille holes (real CT) vs solid cells (nulls).

K4 positions 35-96 (rows 26-27, 62 positions) have partners in K1 rows 0-1.
K4 positions 0-34 (rows 24-25) have partners in rows 2-3 (K2 region).

For the 62 positions with known K1 partners, we try all simple binary rules:
  - K4_CT == K1_CT at partner → null
  - K4_CT == K1_PT at partner → null
  - (K4_CT_idx + K1_CT_idx) % 26 == 0 → null  (sum to 26)
  - (K4_CT_idx - K1_CT_idx) % 26 in 8-cycle → null
  - cycle(K1_PT) == 8-cycle → null  (K1 plaintext at partner is 8-cycle letter)
  - cycle(K1_CT) == 8-cycle → null
  etc.

For each rule, count how many K4 positions are classified as nulls.
If count ≈ 24 (and no crib conflicts), extract 73-char CT and test.
"""
from __future__ import annotations
import sys
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, KRYPTOS_ALPHABET

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = KRYPTOS_ALPHABET
AZ_IDX = {c: i for i, c in enumerate(AZ)}

K4_CARVED = CT
assert len(K4_CARVED) == 97

CRIB_PAIRS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
CRIB_DICT = {}
for start, word in CRIB_PAIRS:
    for i, ch in enumerate(word):
        CRIB_DICT[start + i] = ch
CRIB_POSITIONS = set(CRIB_DICT.keys())

KEYWORDS = ["KRYPTOS","PALIMPSEST","ABSCISSA","SHADOW","SANBORN","SCHEIDT",
            "BERLIN","CLOCK","EAST","NORTH","LIGHT","ANTIPODES","KOMPASS","DEFECTOR"]

# ── AZ→KA cycles ─────────────────────────────────────────────────────────────
AZ_to_KA_idx = [KA.index(AZ[i]) for i in range(26)]
def get_cycles():
    visited = [False] * 26
    cycles = {}
    cid = 0
    for start in range(26):
        if not visited[start]:
            cur = start
            while not visited[cur]:
                visited[cur] = True
                cycles[AZ[cur]] = cid
                cur = AZ_to_KA_idx[cur]
            cid += 1
    return cycles
LETTER_CYCLE = get_cycles()

# ── K1 known data ─────────────────────────────────────────────────────────────
# K1 ciphertext from the grid (rows 0-1, 62 chars):
K1_CT_ROW0 = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV"   # row 0, 31 chars
K1_CT_ROW1 = "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF"   # row 1, 31 chars
K1_CT = K1_CT_ROW0 + K1_CT_ROW1   # 62 chars (K1 ciphertext rows 0-1)

# K1 plaintext (63 chars = 2 rows + 1 char of row 2):
K1_PT_STR = ("BETWEENSUBTLESHADINGANDTHEABSEN"   # row 0, 31 chars
             "CEOFLIGHTLIESTHENUA"                # partial row 1
             "NCEOFIQLUSION")                     # rest of row 1 + row 2 col 0
# Make sure row 0 is 31 and row 1 is 31
K1_PT_ROW0 = "BETWEENSUBTLESHADINGANDTHEABSEN"   # 31? let me count
# B-E-T-W-E-E-N-S-U-B-T-L-E-S-H-A-D-I-N-G-A-N-D-T-H-E-A-B-S-E-N = 31 ✓
K1_PT_ROW1 = "CEOFLIGHTLIESTHENUA" + "NCEOFIQLUSI" + "O"  # need 31 chars
# C-E-O-F-L-I-G-H-T-L-I-E-S-T-H-E-N-U-A-N-C-E-O-F-I-Q-L-U-S-I-O = 31 ✓
K1_PT_ROW1 = "CEOFLIGHTLIESTHENUA" + "NCEOFIQLUS" + "IO"
# Recount: C(1)E(2)O(3)F(4)L(5)I(6)G(7)H(8)T(9)L(10)I(11)E(12)S(13)T(14)H(15)
#           E(16)N(17)U(18)A(19)N(20)C(21)E(22)O(23)F(24)I(25)Q(26)L(27)U(28)S(29)I(30)O(31) = 31 ✓
K1_PT = K1_PT_ROW0 + K1_PT_ROW1  # 62 chars

assert len(K1_CT) == 62
assert len(K1_PT) == 62
assert len(set(K1_PT)) <= 26  # all alphabetic

# K2 rows 2-3 (known but we'll just focus on K1 for now)

# ── K4 position mapping ───────────────────────────────────────────────────────
def k4_pos_to_grid(i):
    if i < 4:
        return (24, 27 + i)
    ii = i - 4
    return (25 + ii // 31, ii % 31)

# ── 180° rotation partner ─────────────────────────────────────────────────────
def rotation_partner(r, c):
    """(r,c) → (27-r, 30-c)"""
    return (27 - r, 30 - c)

# For each K4 position, find rotation partner and classify:
# Partners in rows 0-1 → K1 region (known CT and PT)
# Partners in rows 2-3 → K2 region (known CT, known PT)

print("=" * 65)
print("K4 POSITIONS → 180° ROTATION PARTNERS → K1/K2 REGION")
print("=" * 65)

k1_partners = []   # (k4_idx, k4_letter, partner_r, partner_c, k1_ct, k1_pt)
k2_partners = []
for i in range(97):
    r4, c4 = k4_pos_to_grid(i)
    pr, pc = rotation_partner(r4, c4)
    k4_ch = K4_CARVED[i]
    if pr in (0, 1):
        # In K1 rows 0-1
        k1_pos = pr * 31 + pc
        k1_ct_ch = K1_CT[k1_pos]
        k1_pt_ch = K1_PT[k1_pos]
        k1_partners.append((i, k4_ch, pr, pc, k1_ct_ch, k1_pt_ch))
    elif pr in (2, 3):
        k2_partners.append((i, k4_ch, pr, pc))

print(f"K4 positions with K1 rotation partners (rows 0-1): {len(k1_partners)}")
print(f"K4 positions with K2 rotation partners (rows 2-3): {len(k2_partners)}")

# ── Classification rules for K1 partners ─────────────────────────────────────
print("\n--- Binary classification rules on K1-partner K4 positions ---")
print("(For each rule, count nulls; look for counts near 24)")

def make_null_mask(k1_partners, rule_fn):
    """Apply rule to K1-partner positions. Returns set of K4 null indices."""
    null_set = set()
    for (i, k4_ch, pr, pc, k1_ct_ch, k1_pt_ch) in k1_partners:
        if rule_fn(k4_ch, k1_ct_ch, k1_pt_ch):
            null_set.add(i)
    return null_set

rules = [
    ("K4==K1_CT",          lambda a, b, c: a == b),
    ("K4==K1_PT",          lambda a, b, c: a == c),
    ("K4+K1_CT==26",       lambda a, b, c: (AZ_IDX[a] + AZ_IDX[b]) % 26 == 0),
    ("K4+K1_PT==26",       lambda a, b, c: (AZ_IDX[a] + AZ_IDX[c]) % 26 == 0),
    ("K4-K1_CT in 8cyc",   lambda a, b, c: LETTER_CYCLE.get(AZ[(AZ_IDX[a]-AZ_IDX[b])%26],-1)==1),
    ("K4-K1_PT in 8cyc",   lambda a, b, c: LETTER_CYCLE.get(AZ[(AZ_IDX[a]-AZ_IDX[c])%26],-1)==1),
    ("K1_CT-K4 in 8cyc",   lambda a, b, c: LETTER_CYCLE.get(AZ[(AZ_IDX[b]-AZ_IDX[a])%26],-1)==1),
    ("K1_PT in 8cyc",      lambda a, b, c: LETTER_CYCLE.get(c, -1) == 1),
    ("K1_CT in 8cyc",      lambda a, b, c: LETTER_CYCLE.get(b, -1) == 1),
    ("K4 in 8cyc",         lambda a, b, c: LETTER_CYCLE.get(a, -1) == 1),
    ("K4 == K1_PT ^ K1_CT",lambda a, b, c: AZ_IDX[a] == (AZ_IDX[b] ^ AZ_IDX[c])),
    ("cycle(K4)==cycle(K1_CT)", lambda a,b,c: LETTER_CYCLE.get(a,-1)==LETTER_CYCLE.get(b,-1)),
    ("cycle(K4)!=cycle(K1_CT)",lambda a,b,c: LETTER_CYCLE.get(a,-1)!=LETTER_CYCLE.get(b,-1)),
    ("K4_idx > K1_CT_idx", lambda a, b, c: AZ_IDX[a] > AZ_IDX[b]),
    ("(K4+K1_CT)%13==0",   lambda a, b, c: (AZ_IDX[a] + AZ_IDX[b]) % 13 == 0),
    ("(K4*K1_CT)%26==0",   lambda a, b, c: (AZ_IDX[a] * AZ_IDX[b]) % 26 == 0),
]

best_rules = []
for name, rule_fn in rules:
    null_mask = make_null_mask(k1_partners, rule_fn)
    n_null = len(null_mask)
    n_total_null = n_null  # only K1-partner positions
    crib_conflicts = null_mask & CRIB_POSITIONS
    print(f"  {name:30s}: {n_null:3d}/62 nulls (K1 region), {len(crib_conflicts)} crib conflicts")
    # Track rules near 24 nulls from 62 K1-partner positions
    if 20 <= n_null <= 30 and len(crib_conflicts) == 0:
        best_rules.append((name, rule_fn, null_mask, n_null))

print(f"\nRules with ~24 nulls (20-30) and NO crib conflicts: {len(best_rules)}")

# ── Cipher helpers ────────────────────────────────────────────────────────────
def vig_decrypt(ct, key, alpha=AZ):
    out = []
    n = len(alpha)
    for i, c in enumerate(ct):
        out.append(alpha[(alpha.index(c) - alpha.index(key[i % len(key)])) % n])
    return "".join(out)

def beau_decrypt(ct, key, alpha=AZ):
    out = []
    n = len(alpha)
    for i, c in enumerate(ct):
        out.append(alpha[(alpha.index(key[i % len(key)]) - alpha.index(c)) % n])
    return "".join(out)

def count_cribs_shifted(pt, null_mask):
    n = 0
    for pos, ch in CRIB_DICT.items():
        if pos in null_mask:
            continue
        shift = sum(1 for np in null_mask if np < pos)
        pt_pos = pos - shift
        if 0 <= pt_pos < len(pt) and pt[pt_pos] == ch:
            n += 1
    return n

def test_ct(ct, null_mask, tag=""):
    best = 0
    best_info = None
    for kw in KEYWORDS:
        for aname, alpha in [("AZ", AZ), ("KA", KA)]:
            for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cfn(ct, kw, alpha)
                    n = count_cribs_shifted(pt, null_mask)
                    if n >= 12:
                        print(f"    *** {n}/24 [{tag} {cname}/{kw}/{aname}]: {pt[:60]}")
                    if n > best:
                        best = n
                        best_info = (n, cname, kw, aname, pt[:50])
                except Exception:
                    pass
    return best, best_info

# Test best rules that give 24 nulls exactly from K1 partners
# (These are only 62 positions; we need to decide what to do with the other 35)
print("\n--- Testing rules on partial mask (K1-partner positions only) ---")
for name, rule_fn, k1_null_mask, n_null in best_rules:
    if n_null != 24:
        continue
    print(f"\nRule '{name}': {n_null}/62 K1-partners are nulls")
    print(f"  K1-null positions: {sorted(k1_null_mask)}")
    # The 35 K2-partner positions are unknown (all holes by default)
    # Extract: remove K1-nulls from all 97 to get 73 chars
    holes = sorted(set(range(97)) - k1_null_mask)
    ct_partial = "".join(K4_CARVED[i] for i in holes)
    print(f"  CT ({len(ct_partial)} chars): {ct_partial[:50]}")
    best, info = test_ct(ct_partial, k1_null_mask, name)
    if info:
        print(f"  Best: {info[0]}/24 [{info[1]}/{info[2]}/{info[3]}]")
    else:
        print(f"  Best: {best}/24")

# ── Special: K1 PT at rotation partner matches K4 carved text ─────────────────
print("\n--- Special analysis: K4 chars == K1_PT at rotation partner ---")
matches = [(i, K4_CARVED[i], k1_pt) for (i, k4_ch, pr, pc, k1_ct_ch, k1_pt)
           in k1_partners if K4_CARVED[i] == k1_pt]
print(f"K4[i] == K1_PT[partner] at {len(matches)} of {len(k1_partners)} positions:")
for i, k4_ch, k1_pt in matches:
    print(f"  K4[{i:2d}]={k4_ch}=K1_PT[{62 - i + 34:2d}] "
          f"{'CRIB!' if i in CRIB_POSITIONS else ''}")

# ── K1_CT == K4_CARVED analysis ────────────────────────────────────────────────
print("\n--- K4 chars == K1_CT at rotation partner ---")
matches_ct = [(i, K4_CARVED[i], k1_ct) for (i, k4_ch, pr, pc, k1_ct, k1_pt)
              in k1_partners if K4_CARVED[i] == k1_ct]
print(f"K4[i] == K1_CT[partner] at {len(matches_ct)} of {len(k1_partners)} positions:")
for i, k4_ch, k1_ct in matches_ct:
    print(f"  K4[{i:2d}]={k4_ch} "
          f"{'CRIB!' if i in CRIB_POSITIONS else ''}")

print("\n" + "=" * 65)
print("SUMMARY")
print("=" * 65)
print(f"K4 positions with K1 partners: {len(k1_partners)}")
print(f"  K4[i]==K1_CT: {len(matches_ct)} matches")
print(f"  K4[i]==K1_PT: {len(matches)} matches")
print(f"Rules with ~24 nulls + no crib conflicts: {len(best_rules)}")
for name, _, null_mask, n in best_rules:
    print(f"  '{name}': {n} nulls")
