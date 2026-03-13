#!/usr/bin/env python3
"""
grille_cipher_eq_tableau.py   [Approach A+B, 2026-03-13]

HYPOTHESIS: Positions where cipher[r][c] == tableau[r][c] are SOLID cells
(nulls) in the Cardan grille.  K3 CALIBRATION: the same rule must give
ZERO nulls in K3 (all K3 positions are real CT).

Steps:
  1. Build 28x31 cipher grid & KA tableau
  2. K3 calibration: count cipher==tableau in K3 region (expect ~0)
  3. K4 check: count cipher==tableau in K4 region (hope for exactly 24)
  4. If count == 24 (or another small number), extract 73-char CT and test
  5. Also test inverse: cipher!=tableau as holes (different count)
"""
from __future__ import annotations
import sys
sys.path.insert(0, 'src')
from kryptos.kernel.constants import CT, KRYPTOS_ALPHABET

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = KRYPTOS_ALPHABET

K4_CARVED = CT
assert len(K4_CARVED) == 97

CRIB_PAIRS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
CRIB_DICT = {}
for start, word in CRIB_PAIRS:
    for i, ch in enumerate(word):
        CRIB_DICT[start + i] = ch

KEYWORDS = ["KRYPTOS","PALIMPSEST","ABSCISSA","SHADOW","SANBORN","SCHEIDT",
            "BERLIN","CLOCK","EAST","NORTH","LIGHT","ANTIPODES","KOMPASS","DEFECTOR"]

# ── Grid ─────────────────────────────────────────────────────────────────────
CIPHER_ROWS_RAW = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNCE",
    "EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",
    "QZGZLECGYUXUEENJTBJLBQCETBJDFHR",
    "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT",
    "IHHDDDUVH?DWKBFUFPWNTDFIYCUQZER",
    "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI",
    "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK",
    "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",
    "WMTWNDITEENRAHCTENEUDRETNHAEOET",
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT",
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI",
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",
]

def build_grid():
    grid = []
    for row in CIPHER_ROWS_RAW:
        r = list(row[:31])
        while len(r) < 31:
            r.append('?')
        grid.append(r)
    return grid

GRID = build_grid()

# ── Tableau ───────────────────────────────────────────────────────────────────
AZ_to_KA_idx = [KA.index(AZ[i]) for i in range(26)]

def tableau_cell(r, c):
    """Tableau letter at grid (r, c)."""
    if c == 0:
        return AZ[r - 1] if 1 <= r <= 26 else ' '
    elif r == 0 or r == 27:
        return AZ[(c - 1) % 26]
    else:
        key_pos = AZ_to_KA_idx[r - 1]
        body_col = c - 1
        return KA[(key_pos + body_col) % 26]

# ── Position helpers ──────────────────────────────────────────────────────────
def k3_pos_to_grid(i):
    if i < 310:
        return (14 + i // 31, i % 31)
    return (24, i - 310)

def k4_pos_to_grid(i):
    if i < 4:
        return (24, 27 + i)
    ii = i - 4
    return (25 + ii // 31, ii % 31)

# ── K3 extraction ─────────────────────────────────────────────────────────────
def extract_k3_ct():
    ct = []
    for r in range(14, 24):
        for c in range(31):
            ch = GRID[r][c]
            if ch != '?':
                ct.append(ch)
    for c in range(26):
        ch = GRID[24][c]
        if ch != '?':
            ct.append(ch)
    return "".join(ct)

K3_CT = extract_k3_ct()
assert len(K3_CT) == 336

# ── Crib test ─────────────────────────────────────────────────────────────────
def count_cribs_at_carved(pt97):
    """Count crib matches at ORIGINAL carved positions (Model B)."""
    n = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(pt97) and pt97[pos] == ch:
            n += 1
    return n

def count_cribs_in_73(pt73, null_mask):
    """Count crib matches in 73-char PT, with crib positions SHIFTED by null removal."""
    # For each crib position in the carved text, compute its 73-char equivalent
    n = 0
    for carved_pos, ch in CRIB_DICT.items():
        if carved_pos in null_mask:
            continue  # this crib position is a null - can't match
        # Number of nulls strictly before this carved position
        shift = sum(1 for np in null_mask if np < carved_pos)
        pt73_pos = carved_pos - shift
        if 0 <= pt73_pos < len(pt73) and pt73[pt73_pos] == ch:
            n += 1
    return n

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

def test_73(ct73, null_mask, tag=""):
    """Try all keywords/alphabets/ciphers on the 73-char CT."""
    best_n = 0
    best_info = None
    for kw in KEYWORDS:
        for aname, alpha in [("AZ", AZ), ("KA", KA)]:
            for cname, cfn in [("vig", vig_decrypt), ("beau", beau_decrypt)]:
                try:
                    pt = cfn(ct73, kw, alpha)
                    n = count_cribs_in_73(pt, null_mask)
                    if n >= 18:
                        print(f"  *** SIGNAL [{tag}] {cname}/{kw}/{aname}: {n}/24 cribs")
                        print(f"      PT73: {pt}")
                    if n > best_n:
                        best_n = n
                        best_info = (n, cname, kw, aname, pt[:60])
                except Exception:
                    pass
    return best_n, best_info

# ── MAIN ─────────────────────────────────────────────────────────────────────
print("=" * 70)
print("CIPHER == TABLEAU NULL MASK — K3 CALIBRATION + K4 TEST")
print("=" * 70)

# 1. Full grid: where does cipher == tableau?
print("\n--- Full 28x31 grid: cipher == tableau positions ---")
eq_positions = []
for r in range(28):
    for c in range(31):
        cell = GRID[r][c]
        if cell == '?':
            continue
        tab = tableau_cell(r, c)
        if cell == tab:
            eq_positions.append((r, c, cell))

print(f"Total cipher==tableau positions in full grid: {len(eq_positions)}")

# 2. K3 calibration
k3_eq = []
for i in range(336):
    r, c = k3_pos_to_grid(i)
    cell = K3_CT[i]
    tab = tableau_cell(r, c)
    if cell == tab:
        k3_eq.append(i)
print(f"\nK3 calibration: {len(k3_eq)}/336 positions have cipher==tableau")
if k3_eq:
    print(f"  Positions: {k3_eq[:20]}...")
    print("  NOTE: Non-zero K3 matches FAIL K3 calibration for this rule")
else:
    print("  PERFECT: zero K3 matches — K3 calibration PASSED")

# 3. K4 check
k4_eq_mask = set()
k4_neq_mask = set()
for i in range(97):
    r, c = k4_pos_to_grid(i)
    cell = K4_CARVED[i]
    tab = tableau_cell(r, c)
    if cell == tab:
        k4_eq_mask.add(i)
    else:
        k4_neq_mask.add(i)

print(f"\nK4 check: {len(k4_eq_mask)}/97 positions have cipher==tableau (= potential nulls)")
print(f"  Null positions: {sorted(k4_eq_mask)}")
print(f"  Crib positions in null set: {sorted(k4_eq_mask & set(CRIB_DICT.keys()))}")

# 4. Test as null mask (cipher==tableau → null, i.e., cipher!=tableau → holes)
for mask_name, null_mask in [
    ("cipher==tableau (nulls)", k4_eq_mask),
    ("cipher!=tableau (nulls)", k4_neq_mask),
]:
    n_nulls = len(null_mask)
    n_holes = 97 - n_nulls
    crib_conflicts = null_mask & set(CRIB_DICT.keys())
    print(f"\n--- Test: {mask_name} ---")
    print(f"  Nulls: {n_nulls}, Holes: {n_holes}")
    print(f"  Crib positions in null set: {sorted(crib_conflicts)}")

    if n_holes < 10:
        print("  Skipping: too few holes")
        continue

    # Extract CT from holes
    holes = sorted(set(range(97)) - null_mask)
    ct73 = "".join(K4_CARVED[i] for i in holes)

    if n_holes == 73:
        print(f"  Holes = 73 exactly! Testing...")
    else:
        print(f"  Holes = {n_holes} (not 73). Testing anyway...")

    # Also test Model B (all 97 chars, ignore null mask for cipher scoring)
    print(f"  CT (first 40): {ct73[:40]}")
    best_n, best_info = test_73(ct73, null_mask, f"cipher_eq_tab/{mask_name}")
    if best_info:
        print(f"  Best: {best_info[0]}/24 cribs [{best_info[1]}/{best_info[2]}/{best_info[3]}]")
        print(f"        {best_info[4]}")
    else:
        print(f"  Best: {best_n}/24 cribs")

# 5. Show the 39-position claim from memory
print(f"\n--- Detail: all {len(eq_positions)} cipher==tableau positions ---")
k4_region = {(k4_pos_to_grid(i)[0], k4_pos_to_grid(i)[1]) for i in range(97)}
k4_eq_detailed = [(r, c, ch) for r, c, ch in eq_positions if (r, c) in k4_region]
other_eq = [(r, c, ch) for r, c, ch in eq_positions if (r, c) not in k4_region]
print(f"  In K4 region: {len(k4_eq_detailed)} positions")
for r, c, ch in k4_eq_detailed:
    ki = [i for i in range(97) if k4_pos_to_grid(i) == (r, c)][0]
    print(f"    K4[{ki:2d}] grid({r},{c}) cipher=tableau={ch} "
          f"{'CRIB!' if ki in CRIB_DICT else ''}")
print(f"  Outside K4 region: {len(other_eq)} positions")

print("\n" + "=" * 70)
print("DONE")
print("=" * 70)
