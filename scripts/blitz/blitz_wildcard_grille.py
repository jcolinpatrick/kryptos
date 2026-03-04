#!/usr/bin/env python3
"""
Cipher: Cardan grille
Family: blitz
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_wildcard_grille.py — Novel Cardan Grille Approaches for K4 (2026-03-04)

PARADIGM: PT → Cipher(key) → real_CT → SCRAMBLE(σ) → K4_CARVED
σ[j] = K4_CARVED position for real_CT[j]

NEW APPROACHES:
  A. KA cycle partition (17+8+1) — use cycle membership as binary grille mask
  B. "8 Lines 73" — literal 8-row × ~9-hole grille over K4+context rows
  C. Prime/Fibonacci/modular — position-based mask patterns (enhanced)
  D. KRYPTOS/ABSCISSA period-7/8 — keyword period masks
  E. K4 self-referential — K4 letter's KA index determines its own sigma pos
  F. T-diagonal — "T IS YOUR POSITION" in KA tableau; T-positions as grille
  G. AZ→KA permutation directly as σ — cycle-structured sigma variants
  H. Forced-constraint feasibility — 24 crib positions filter kw×cipher×alpha
  I. YES WONDERFUL THINGS — new crib at K4_PT[0:18], feasibility filter
  J. 434-char double rotation — K3+?+K4 combined, K4 extracted as tail

Run: cd /home/cpatrick/kryptos && PYTHONPATH=src python3 -u scripts/blitz_wildcard_grille.py
"""

import sys, os, json, math
from collections import Counter, defaultdict
from itertools import permutations

sys.path.insert(0, os.path.dirname(__file__))

# ─── CONSTANTS ────────────────────────────────────────────────────────────────

AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
assert len(KA) == 26 and len(set(KA)) == 26

K4 = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
assert len(K4) == 97

KEYWORDS = ["KRYPTOS","PALIMPSEST","ABSCISSA","SHADOW","SANBORN",
            "SCHEIDT","BERLIN","CLOCK","EAST","NORTH","LIGHT",
            "ANTIPODES","MEDUSA","ENIGMA","BERLINCLOCK","EASTNORTHEAST"]

ALPHAS = [("AZ", AZ), ("KA", KA)]

# Known K4 plaintext positions (0-indexed)
CRIBS = [(21, "EASTNORTHEAST"), (63, "BERLINCLOCK")]
K4_PT_KNOWN = [None] * 97
for start, crib in CRIBS:
    for i, ch in enumerate(crib):
        K4_PT_KNOWN[start + i] = ch
# Note: K4_PT[32]='S' and K4_PT[73]='K' are already covered by the cribs above.
KNOWN = [(j, K4_PT_KNOWN[j]) for j in range(97) if K4_PT_KNOWN[j] is not None]
assert len(KNOWN) == 24

# YES WONDERFUL THINGS crib (K3 ends "CAN YOU SEE ANYTHING?"; Carter replied "Yes, wonderful things!")
YWT = "YESWONDERFULTHINGS"   # 18 chars, K4_PT[0:18] hypothesis
assert len(YWT) == 18

# Extended known positions with YES WONDERFUL THINGS hypothesis (positions 0-17)
KNOWN_YWT = [(j, YWT[j]) for j in range(18)] + KNOWN  # 42 positions total

# K4 letter → list of K4_CARVED positions
L2P = defaultdict(list)
for i, ch in enumerate(K4):
    L2P[ch].append(i)
K4_FREQ = Counter(K4)

# 28×31 cipher grid
GRID_ROWS = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNC",
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
assert len(GRID_ROWS) == 28

# K4 (row,col) positions in grid
K4_RC = [(24, c) for c in range(27, 31)] + \
        [(r, c) for r in range(25, 28) for c in range(31)]
assert len(K4_RC) == 97, f"Expected 97 K4 positions, got {len(K4_RC)}"

# KA Vigenère tableau (28×31)
def make_tableau():
    tab = []
    for r in range(28):
        key = AZ[r % 26]
        # body[c-1] = KA[(r + c - 1) % 26] for c in 1..30
        body = ''.join(KA[(r + c - 1) % 26] for c in range(1, 31))
        tab.append(key + body)  # 31 chars
    return tab

TAB = make_tableau()
assert all(len(row) == 31 for row in TAB)

# ─── QUADGRAM SCORING ─────────────────────────────────────────────────────────
QG = None
for p in ["data/english_quadgrams.json", "../data/english_quadgrams.json",
          os.path.join(os.path.dirname(__file__), "..", "data", "english_quadgrams.json")]:
    if os.path.exists(p):
        with open(p) as f:
            QG = json.load(f)
        break

def qscore(text):
    if QG is None: return -9.9
    t = ''.join(c for c in text.upper() if c in AZ)
    n = len(t) - 3
    if n <= 0: return -9.9
    return sum(QG.get(t[i:i+4], -10.0) for i in range(n)) / n

def crib_count(pt):
    return sum(1 for s, c in CRIBS for i, ch in enumerate(c)
               if s + i < len(pt) and pt[s + i] == ch)

# ─── CIPHER FUNCTIONS ─────────────────────────────────────────────────────────
def vig_e(pt, kw, a=AZ):
    ai = {c: i for i, c in enumerate(a)}
    return ''.join(a[(ai[pt[j]] + ai[kw[j % len(kw)]]) % 26] for j in range(len(pt)))

def vig_d(ct, kw, a=AZ):
    ai = {c: i for i, c in enumerate(a)}
    return ''.join(a[(ai[ct[j]] - ai[kw[j % len(kw)]]) % 26] for j in range(len(ct)))

def beau_d(ct, kw, a=AZ):  # Beaufort is symmetric
    ai = {c: i for i, c in enumerate(a)}
    return ''.join(a[(ai[kw[j % len(kw)]] - ai[ct[j]]) % 26] for j in range(len(ct)))

def beau_e(pt, kw, a=AZ):
    return beau_d(pt, kw, a)

CIPHER_FUNCS = [("vig", vig_d, vig_e), ("beau", beau_d, beau_e)]

# ─── SIGMA TESTER ─────────────────────────────────────────────────────────────
BEST_SCORE = -9.9
CRIB_HITS = []
TESTED = 0

def test_sigma(sigma, label, verbose=False):
    """Test permutation sigma[j] = K4_CARVED position for real_CT[j]."""
    global BEST_SCORE, TESTED
    if len(sigma) != 97 or sorted(sigma) != list(range(97)):
        return None
    TESTED += 1
    rct = ''.join(K4[sigma[j]] for j in range(97))
    best = (-9.9, "", "", "", "", 0)

    for kw in KEYWORDS:
        for an, a in ALPHAS:
            for cn, df, _ in CIPHER_FUNCS:
                try:
                    pt = df(rct, kw, a)
                except Exception:
                    continue
                sc = qscore(pt)
                ene = pt.find("EASTNORTHEAST")
                bc = pt.find("BERLINCLOCK")
                if ene >= 0 or bc >= 0:
                    msg = (f"\n{'!'*60}\n*** CRIB HIT: {label}\n"
                           f"    ENE@{ene}  BC@{bc}  score={sc:.3f}\n"
                           f"    PT: {pt}\n    {kw}/{cn}/{an}\n{'!'*60}")
                    print(msg)
                    CRIB_HITS.append({"label": label, "pt": pt, "ene": ene,
                                      "bc": bc, "score": sc, "kw": kw,
                                      "cipher": cn, "alpha": an})
                    return CRIB_HITS[-1]
                cc = crib_count(pt)
                if sc > best[0]:
                    best = (sc, pt, kw, cn, an, cc)

    if best[0] > BEST_SCORE:
        BEST_SCORE = best[0]
        print(f"  NEW BEST [{label}]: {best[0]:.3f}/char  "
              f"key={best[2]}/{best[3]}/{best[4]}  cribs={best[5]}/24")
        if best[0] > -6.5:
            print(f"    PT: {best[1]}")
    elif verbose:
        print(f"  [{label}] score={best[0]:.3f}  key={best[2]}/{best[3]}/{best[4]}  cribs={best[5]}/24")
    return {"label": label, "score": best[0], "pt": best[1],
            "kw": best[2], "cipher": best[3], "alpha": best[4]}


# ─── AZ→KA CYCLE ANALYSIS ─────────────────────────────────────────────────────
print("=" * 70)
print("AZ→KA CYCLE STRUCTURE")
print("=" * 70)

# AZ→KA permutation: maps AZ letter to KA letter at the same index position
# φ: AZ[i] → KA[i]
# As a permutation on indices: φ_idx(i) = AZ.index(KA[i]) — where does KA[i] land in AZ?
phi_idx = [AZ.index(KA[i]) for i in range(26)]  # index permutation: position i → position φ_idx(i)
# The cycle structure: applying φ starting from each position
def find_cycles_idx(perm):
    visited = [False] * len(perm)
    cycles = []
    for start in range(len(perm)):
        if not visited[start]:
            cycle, cur = [], start
            while not visited[cur]:
                visited[cur] = True
                cycle.append(cur)
                cur = perm[cur]
            cycles.append(cycle)
    return cycles

phi_cycles = find_cycles_idx(phi_idx)
print(f"AZ→KA permutation: φ_idx = {phi_idx[:8]}...")
print(f"Cycles: {[len(c) for c in phi_cycles]} (expect 17+8+1)")

# Identify cycle membership for each AZ letter
CYCLE_SIZE = {}  # letter → cycle size
CYCLE_ID = {}    # letter → cycle id
for cid, cycle in enumerate(phi_cycles):
    for idx in cycle:
        CYCLE_SIZE[AZ[idx]] = len(cycle)
        CYCLE_ID[AZ[idx]] = cid

CYCLE17 = set(ch for ch in AZ if CYCLE_SIZE[ch] == 17)
CYCLE8  = set(ch for ch in AZ if CYCLE_SIZE[ch] == 8)
CYCLE1  = set(ch for ch in AZ if CYCLE_SIZE[ch] == 1)
print(f"17-cycle: {sorted(CYCLE17)}")
print(f"8-cycle:  {sorted(CYCLE8)}")
print(f"Fixed:    {sorted(CYCLE1)}")

# Also compute the LETTER CYCLE (which letter maps to which under φ)
phi_letter = {AZ[i]: KA[i] for i in range(26)}   # AZ letter → KA letter
print(f"\n17-cycle letter orbit: A→{phi_letter['A']}→{phi_letter[phi_letter['A']]}→...")
orbit17 = []
cur = 'A'
for _ in range(17):
    orbit17.append(cur)
    cur = phi_letter[cur]
print(f"  {orbit17}")
orbit8 = []
cur = 'C'
for _ in range(8):
    orbit8.append(cur)
    cur = phi_letter[cur]
print(f"8-cycle orbit: {orbit8}")
print()

# K4 letter cycle membership
k4_cycle_membership = [CYCLE_SIZE.get(K4[i], -1) for i in range(97)]
k4_cycle17_count = sum(1 for x in k4_cycle_membership if x == 17)
k4_cycle8_count  = sum(1 for x in k4_cycle_membership if x == 8)
k4_cycle1_count  = sum(1 for x in k4_cycle_membership if x == 1)
print(f"K4 letter cycle membership: 17-cycle={k4_cycle17_count}, 8-cycle={k4_cycle8_count}, fixed={k4_cycle1_count}")
print(f"(Expected roughly: 17/26*97≈63, 8/26*97≈30, 1/26*97≈4)")
print()

# ─── SECTION A: KA CYCLE MEMBERSHIP MASKS ─────────────────────────────────────
print("=" * 70)
print("APPROACH A: KA Cycle Membership as Grille Mask")
print("=" * 70)

# A.1: Holes = positions where K4[i] ∈ 17-cycle, read in order → real_CT[0..]
# A.2: Holes = positions where K4[i] ∈ 8-cycle
# A.3: Holes = positions where K4[i] ∈ 8-cycle + fixed
# A.4: Use tableau letter cycle membership instead of K4 letter

for approach, label, hole_set in [
    ("A.1", "17-cycle letters", CYCLE17),
    ("A.2", "8-cycle letters", CYCLE8),
    ("A.3", "8-cycle+fixed", CYCLE8 | CYCLE1),
    ("A.4", "NOT-17-cycle", CYCLE8 | CYCLE1),  # complement of 17-cycle
]:
    holes = [i for i in range(97) if K4[i] in hole_set]
    solids = [i for i in range(97) if K4[i] not in hole_set]
    print(f"  {approach} ({label}): {len(holes)} holes, {len(solids)} solids")

    if len(holes) == 0 or len(holes) == 97:
        continue

    # Reading order: holes first (natural order), then solids (natural order)
    sigma_fwd = holes + solids
    test_sigma(sigma_fwd, f"A-{approach}-holes-fwd", verbose=True)

    # Reverse: solids first, then holes
    sigma_rev = solids + holes
    test_sigma(sigma_rev, f"A-{approach}-solids-fwd", verbose=True)

    # Alternating: interleave holes and solids
    # (like a 2-position grille: position 1 reads holes, position 2 reads solids)
    # Position 1: reading order is holes sorted ascending
    # Position 2 (180° flip): reading order is solids sorted DESCENDING (reversed)
    sigma_flip = holes + solids[::-1]
    test_sigma(sigma_flip, f"A-{approach}-holes+solidrev", verbose=True)

    sigma_flip2 = holes[::-1] + solids
    test_sigma(sigma_flip2, f"A-{approach}-holesrev+solids", verbose=True)

# A.5: Use TABLEAU letter cycle membership (TAB[r][c] cycle) instead of K4 letter
print("\n  A.5: Using tableau letter cycle membership at K4 positions")
for hole_set, label in [(CYCLE17, "tab-17cycle"), (CYCLE8, "tab-8cycle"),
                        (CYCLE8 | CYCLE1, "tab-8+1cycle")]:
    holes = [i for i, (r, c) in enumerate(K4_RC)
             if TAB[r][c] in AZ and CYCLE_SIZE.get(TAB[r][c], -1) == (17 if 'tab-17' in label else (8 if 'tab-8c' in label else 99))]
    # Fix: just use set membership
    holes = [i for i, (r, c) in enumerate(K4_RC)
             if TAB[r][c] in hole_set]
    solids = [i for i in range(97) if i not in set(holes)]
    print(f"    {label}: {len(holes)} holes")
    if 5 <= len(holes) <= 92:
        test_sigma(holes + solids, f"A.5-{label}-fwd", verbose=True)
        test_sigma(solids + holes, f"A.5-{label}-rev", verbose=True)

print()

# ─── SECTION F: T-DIAGONAL ───────────────────────────────────────────────────
print("=" * 70)
print("APPROACH F: T-Diagonal ('T IS YOUR POSITION')")
print("=" * 70)

# TAB[r][c] = KA[(r + c - 1) % 26] for c in 1..30
# T is KA[4]. T-diagonal: r + c - 1 ≡ 4 (mod 26) → r + c ≡ 5 (mod 26)
# For each row r: c = (5 - r) % 26, if in 1..30, add; also c+26 if ≤ 30

T_POS_FULL = []  # T positions in full 28×31 tableau (r, c)
for r in range(28):
    c1 = (5 - r) % 26
    for c in [c1, c1 + 26]:
        if 1 <= c <= 30:
            T_POS_FULL.append((r, c))

T_POS_SET = set(T_POS_FULL)
print(f"T positions in full 28×31 tableau body: {len(T_POS_FULL)}")
print(f"T positions per row: {[(r, [c for rr, c in T_POS_FULL if rr == r]) for r in range(28) if any(rr == r for rr, _ in T_POS_FULL)][:10]}...")

# T positions in K4 region specifically
T_IN_K4 = [i for i, (r, c) in enumerate(K4_RC) if (r, c) in T_POS_SET]
print(f"\nT positions in K4 region ({len(T_IN_K4)} found):")
for idx in T_IN_K4:
    r, c = K4_RC[idx]
    print(f"  K4[{idx}] = '{K4[idx]}' at row {r}, col {c}; TAB={TAB[r][c]}")

# T-diagonal based sigma:
# F.1: holes = T positions, solids = rest
# F.2: reading order starts at T-position and proceeds in natural order
# F.3: T-position in each row marks the "offset" for that row's reading

if T_IN_K4:
    non_T = [i for i in range(97) if i not in T_IN_K4]
    # F.1: T positions first
    test_sigma(T_IN_K4 + non_T, "F.1-T-first", verbose=True)
    test_sigma(non_T + T_IN_K4, "F.1-nonT-first", verbose=True)

# F.2: For K4 rows, read starting from T-diagonal position within each row
# Row 25: T at col 6 (K4 index 10); Row 26: T at col 5 (K4 index 40);
# Row 27: T at cols 4,30 (K4 indices 70, 96)
# Read each row starting from its T position, going right, then wrap around
print("\n  F.2: Row-by-row reading starting from T-diagonal")
K4_ROWS_RC = {
    24: list(range(0, 4)),    # K4_RC indices for row 24 (cols 27-30)
    25: list(range(4, 35)),   # K4_RC indices for row 25 (cols 0-30)
    26: list(range(35, 66)),  # K4_RC indices for row 26
    27: list(range(66, 97)),  # K4_RC indices for row 27
}

def t_start_row(row):
    """Return the T-diagonal column position in this row, if in K4 range."""
    t_cols = [(5 - row) % 26, (5 - row) % 26 + 26]
    if row == 24:
        # K4 cols 27-30 only
        return [c for c in t_cols if 27 <= c <= 30]
    else:
        return [c for c in t_cols if 0 <= c <= 30]

sigma_t_start = []
for row in [24, 25, 26, 27]:
    row_indices = K4_ROWS_RC[row]
    t_cols = t_start_row(row)
    if not t_cols:
        sigma_t_start.extend(row_indices)  # No T in this row, read normally
        continue
    # Start from first T column in this row
    t_start_c = t_cols[0]
    if row == 24:
        start_pos = t_start_c - 27  # col 27 is index 0 in this row
    else:
        start_pos = t_start_c       # col c is index c in rows 25-27
    # Rotate row reading order to start at T position
    shifted = row_indices[start_pos:] + row_indices[:start_pos]
    sigma_t_start.extend(shifted)
    print(f"  Row {row}: T at col {t_start_c}, start_pos={start_pos}, "
          f"K4 letters at T: {[K4[i] for i in row_indices if K4_RC[i][1] in t_cols]}")

if len(sigma_t_start) == 97 and sorted(sigma_t_start) == list(range(97)):
    test_sigma(sigma_t_start, "F.2-T-start-each-row", verbose=True)
else:
    print(f"  F.2: sigma has {len(sigma_t_start)} elements, {len(set(sigma_t_start))} unique — not valid")

print()

# ─── SECTION H: FORCED CONSTRAINT ANALYSIS ────────────────────────────────────
print("=" * 70)
print("APPROACH H: Forced-Constraint Feasibility (24 crib positions)")
print("=" * 70)
print("For each (kw, cipher, alpha): compute required K4_CARVED letters")
print("at all 24 known PT positions. Check multiset feasibility.\n")

# Rare letters in K4 (frequency ≤ 2)
RARE = {ch: positions for ch, positions in L2P.items() if len(positions) <= 2}
print(f"Rare letters in K4 (≤2 occurrences): {dict(sorted((k, len(v)) for k,v in RARE.items()))}")
print()

feasible_combos = []  # (kw, cipher, an, forced_count, forced_map)

for kw in KEYWORDS:
    for an, a in ALPHAS:
        for cn, _, enc_fn in CIPHER_FUNCS:
            # Compute required real_CT letter at each known PT position
            required = {}  # sigma_pos → required K4_CARVED letter
            ai = {c: i for i, c in enumerate(a)}
            for j, pt_ch in KNOWN:
                ki = ai[kw[j % len(kw)]]
                pi = ai[pt_ch]
                if cn == 'vig':
                    ri = (pi + ki) % 26
                else:  # beau
                    ri = (ki - pi) % 26
                required[j] = a[ri]

            # Check feasibility: multiset of required letters ⊆ K4_FREQ
            req_counts = Counter(required.values())
            feasible = all(K4_FREQ[ch] >= cnt for ch, cnt in req_counts.items())
            if not feasible:
                # Find which letters are infeasible
                infeasible = {ch: (cnt, K4_FREQ[ch]) for ch, cnt in req_counts.items()
                              if K4_FREQ[ch] < cnt}
                continue  # skip infeasible combos

            # Find forced sigma values (required letter appears exactly once in K4)
            forced = {}
            for j, ch in required.items():
                if len(L2P[ch]) == 1:
                    forced[j] = L2P[ch][0]

            # Check forced map for self-consistency
            if len(set(forced.values())) < len(forced):
                continue  # Two different sigma positions forced to same K4 pos → infeasible

            feasible_combos.append((kw, cn, an, len(forced), forced, required))

print(f"Feasible combos (24 crib positions): {len(feasible_combos)} / {len(KEYWORDS)*4}")
print("\nTop combos by forced sigma count:")
feasible_combos.sort(key=lambda x: -x[3])
for kw, cn, an, fc, forced, required in feasible_combos[:15]:
    print(f"  {kw:15s}/{cn}/{an}: {fc} forced, "
          f"highly_constrained={sum(1 for ch in required.values() if K4_FREQ[ch] <= 2)}")
    if fc >= 2:
        for j, k4pos in forced.items():
            print(f"    sigma[{j}]={k4pos} (K4[{k4pos}]='{K4[k4pos]}' ← "
                  f"req letter '{required[j]}' appears {K4_FREQ[required[j]]} time(s))")
print()

# ─── SECTION I: YES WONDERFUL THINGS FEASIBILITY ──────────────────────────────
print("=" * 70)
print("APPROACH I: 'YES WONDERFUL THINGS' — K4_PT[0:18] feasibility")
print("=" * 70)
print(f"Hypothesis: K4_PT[0:18] = '{YWT}'")
print(f"Combined known positions: 18 + 24 = 42 (positions 0-17 + cribs)\n")

yesno_combos = []

for kw in KEYWORDS:
    for an, a in ALPHAS:
        for cn, _, enc_fn in CIPHER_FUNCS:
            ai = {c: i for i, c in enumerate(a)}
            required_ywt = {}
            for j, pt_ch in KNOWN_YWT:
                ki = ai[kw[j % len(kw)]]
                pi = ai[pt_ch]
                if cn == 'vig':
                    ri = (pi + ki) % 26
                else:  # beau
                    ri = (ki - pi) % 26
                required_ywt[j] = a[ri]

            # Check feasibility
            req_counts = Counter(required_ywt.values())
            feasible = all(K4_FREQ[ch] >= cnt for ch, cnt in req_counts.items())
            if not feasible:
                infeasible_letters = {ch: (cnt, K4_FREQ[ch])
                                      for ch, cnt in req_counts.items()
                                      if K4_FREQ[ch] < cnt}
                continue

            # Find forced sigma values
            forced_ywt = {}
            for j, ch in required_ywt.items():
                if len(L2P[ch]) == 1:
                    forced_ywt[j] = L2P[ch][0]
            if len(set(forced_ywt.values())) < len(forced_ywt):
                continue

            yesno_combos.append((kw, cn, an, len(forced_ywt), forced_ywt, required_ywt))

print(f"Combos compatible with YES WONDERFUL THINGS: {len(yesno_combos)}")
yesno_combos.sort(key=lambda x: -x[3])
for kw, cn, an, fc, forced_ywt, req_ywt in yesno_combos[:20]:
    n_constrained = sum(1 for ch in req_ywt.values() if K4_FREQ[ch] <= 2)
    print(f"  {kw:15s}/{cn}/{an}: {fc} forced, {n_constrained} doubly-constrained positions")
    if fc >= 1:
        for j, k4pos in forced_ywt.items():
            print(f"    sigma[{j}]={k4pos} "
                  f"(PT[{j}]='{KNOWN_YWT[j][1] if j < len(KNOWN_YWT) else '?'}' "
                  f"→ req='{req_ywt[j]}' @ K4[{k4pos}])")

print()

# Test direct decryption with YES WONDERFUL THINGS as crib check
# For each keyword/cipher/alpha, check if direct vig_decrypt gives anything near YWT at start
print("Direct decryption check (identity sigma) against YES WONDERFUL THINGS:")
for kw in KEYWORDS[:8]:  # Top keywords
    for an, a in ALPHAS:
        pt_direct = vig_d(K4, kw, a)
        # How many chars of YWT match at position 0?
        ywt_match = sum(1 for i in range(min(18, len(YWT))) if pt_direct[i] == YWT[i])
        if ywt_match >= 5:
            print(f"  {kw}/{an} YWT match: {ywt_match}/18 at pos 0: PT={pt_direct[:20]}")
        # Also check if YWT appears anywhere
        if YWT[:6] in pt_direct:
            print(f"  {kw}/{an} YWT prefix in PT: pos={pt_direct.find(YWT[:6])}, "
                  f"PT={pt_direct[:20]}")
print()

# ─── SECTION G: AZ→KA PERMUTATION AS SIGMA ────────────────────────────────────
print("=" * 70)
print("APPROACH G: AZ→KA Permutation Directly as σ")
print("=" * 70)

# φ_idx(i) = AZ.index(KA[i]) — permutation on {0..25}
# Extension to 97: sigma(j) = phi_idx(j%26) + 26*(j//26) — but this may overflow
# Fix: for j//26 == 3 (j in 78-96, 19 elements), keep values in 0-96
# phi_idx maps each residue j%26 to another residue phi_idx(j%26)
# so phi_idx(j%26) + 26*(j//26) is in: [0..25+0, 0..25+26, 0..25+52, 0..18+78]
# For j//26=3: values up to 18+78=96 ✓ (since j%26 ≤ 18 when j≤96)
# BUT: phi_idx maps {0..18} to a SUBSET of {0..25}, so some values in
#      {0..25}+78={78..103} which exceeds 96!
# Need to handle this carefully.

print("Computing phi_idx extended to 97 positions:")
# Check which values phi_idx(j%26)+26*(j//26) would produce for j in 78..96
block3_vals = [phi_idx[j % 26] + 26 * (j // 26) for j in range(78, 97)]
print(f"  phi_idx block 3 (j=78..96): {block3_vals}")
is_valid = len(set(block3_vals)) == len(block3_vals) and max(block3_vals) < 97
print(f"  Block 3 all unique: {len(set(block3_vals)) == len(block3_vals)}")
print(f"  Block 3 max: {max(block3_vals)}")

# G.1: Try phi_idx extended naively (may not be bijection)
sigma_phi_naive = [phi_idx[j % 26] + 26 * (j // 26) for j in range(97)]
if sorted(sigma_phi_naive) == list(range(97)):
    print("  G.1: Naive extension IS a valid bijection!")
    test_sigma(sigma_phi_naive, "G.1-phi-naive", verbose=True)
else:
    collisions = Counter(sigma_phi_naive)
    print(f"  G.1: NOT a bijection. Collisions: {[v for v,c in collisions.items() if c>1][:5]}")

# G.2: Cyclic rotation approach — apply phi_letter cyclically to K4 letters
# Use the cycle structure to define a reading order:
# Read positions where K4[i] is at step 0 in their cycle, then step 1, etc.
print("\n  G.2: Reading by cycle-position order")
# For each letter, find its step in the 17-cycle or 8-cycle
def cycle_step(ch):
    """Return (cycle_size, step_in_cycle) for letter ch."""
    if ch in CYCLE1:
        return (1, 0)
    if ch in CYCLE17:
        cur = 'A'  # 17-cycle starts at A (arbitrary starting point)
        # Actually use orbit17 computed earlier
        if ch in orbit17:
            return (17, orbit17.index(ch))
        return (17, -1)
    if ch in CYCLE8:
        if ch in orbit8:
            return (8, orbit8.index(ch))
        return (8, -1)
    return (-1, -1)

# Sort K4 positions by (cycle_size, cycle_step) of K4[i]
key_for_sort = [(CYCLE_SIZE.get(K4[i], 0), orbit17.index(K4[i]) if K4[i] in orbit17
                 else (orbit8.index(K4[i]) if K4[i] in orbit8 else 0), i)
                for i in range(97)]
sigma_cycle_order = sorted(range(97), key=lambda i: key_for_sort[i])
test_sigma(sigma_cycle_order, "G.2-cycle-order-asc", verbose=True)
test_sigma(sigma_cycle_order[::-1], "G.2-cycle-order-desc", verbose=True)

# G.3: phi_idx applied k times to each K4 position mod 97
# phi_idx has order lcm(17,8,1)=136. For each position j in 0..96:
# sigma(j) = ?
# Interpretation: use KA index of K4[j] as "position in alphabet", apply phi_idx
for k in [1, 2, 3, 4, 7, 8, 9, 17]:
    # phi_idx^k on AZ index of K4[j]
    def apply_phi_k(ch, k):
        idx = AZ.index(ch)
        for _ in range(k):
            idx = phi_idx[idx]
        return idx

    vals = [apply_phi_k(K4[j], k) * 97 // 26 for j in range(97)]  # scale 0..25 → 0..96 approx
    # This won't be bijection. Try a different mapping.
    # sigma(j) = position j where K4[j]'s AZ index after k phi applications
    # Use as ordering key
    sigma_phi_k = sorted(range(97), key=lambda j: (apply_phi_k(K4[j], k), j))
    test_sigma(sigma_phi_k, f"G.3-phi^{k}-order", verbose=False)

# G.4: KA-index as reading order
# Sort K4 positions by KA.index(K4[i]) — reading order based on KA position
sigma_ka_idx = sorted(range(97), key=lambda i: (KA.index(K4[i]) if K4[i] in KA else 26, i))
test_sigma(sigma_ka_idx, "G.4-KA-index-sort-asc", verbose=True)
test_sigma(sigma_ka_idx[::-1], "G.4-KA-index-sort-desc", verbose=True)

# G.5: AZ-index as reading order
sigma_az_idx = sorted(range(97), key=lambda i: (AZ.index(K4[i]) if K4[i] in AZ else 26, i))
test_sigma(sigma_az_idx, "G.5-AZ-index-sort-asc", verbose=True)
test_sigma(sigma_az_idx[::-1], "G.5-AZ-index-sort-desc", verbose=True)

print()

# ─── SECTION B: "8 LINES 73" LITERAL ─────────────────────────────────────────
print("=" * 70)
print("APPROACH B: '8 Lines 73' Literal Interpretation")
print("=" * 70)
print("'8 Lines' = 8 rows with holes; '73' = total hole count")
print("K4 spans rows 24-27 (4 rows). '8 Lines' might extend to rows 20-27.\n")

# B.1: 73 holes interpretation — these are NON-crib positions
crib_pos_set = set()
for s, c in CRIBS:
    crib_pos_set.update(range(s, s + len(c)))
non_crib = sorted(set(range(97)) - crib_pos_set)
assert len(non_crib) == 73
print(f"B.1: 73 non-crib positions: {non_crib[:10]}... + {non_crib[-5:]}")
print(f"     24 crib positions: {sorted(crib_pos_set)[:5]}... + {sorted(crib_pos_set)[-5:]}")

# 73-hole sigma: holes = non-crib positions, solids = crib positions
# Reading: holes first (real_CT[0..72] at non-crib carved positions), then cribs
sigma_73 = non_crib + sorted(crib_pos_set)
test_sigma(sigma_73, "B.1-73holes=non-crib", verbose=True)
# Also try: solids first
sigma_73_rev = sorted(crib_pos_set) + non_crib
test_sigma(sigma_73_rev, "B.1-cribs-first", verbose=True)

# B.2: "8 Lines" = 8 rows of cipher grid with holes
# Which 8 rows? If rows 20-27: those include K3 tail + K4
rows_20_27 = [(r, c) for r in range(20, 28) for c in range(31)]
# Find which of these rows contain K4 positions
k4_rc_set = set(K4_RC)
k4_in_rows_20_27 = [(r, c) for r, c in rows_20_27 if (r, c) in k4_rc_set]
print(f"\nB.2: Rows 20-27 contain {len(k4_in_rows_20_27)} K4 positions")

# If 73 holes are distributed among 8 rows, average ~9 per row
# Try: for each row, use every 4th column (creating ~8 holes/row in 31-col row)
# Then select 73 total
print("B.2: Testing various 8-row, 73-hole patterns:")
for start_col in [0, 1, 2, 3]:
    # Holes at every 4th column in K4, starting at start_col
    holes_4th = [i for i, (r, c) in enumerate(K4_RC) if c % 4 == start_col]
    if len(holes_4th) >= 20:
        solids_4th = [i for i in range(97) if i not in holes_4th]
        test_sigma(holes_4th + solids_4th, f"B.2-every4th-col-start{start_col}",
                   verbose=False)

# B.3: Period 8 structure (ABSCISSA, length 8)
print("\nB.3: Period-8 sigma (ABSCISSA key structure)")
for offset in range(8):
    # holes = positions where i % 8 == offset
    holes_p8 = [i for i in range(97) if i % 8 == offset]  # 12 or 13 holes
    solids_p8 = [i for i in range(97) if i % 8 != offset]
    # Hmm, this doesn't give 73 holes. Try combinations.
    pass

# Test period-8 full permutation: arrange K4 in 8 groups, interleave
for base_period in [7, 8, 13, 14, 31]:
    if 97 % base_period == 0:
        # Clean division
        n_groups = base_period
        group_size = 97 // base_period
        # Read: group 0 (positions 0, p, 2p, ...), group 1 (1, 1+p, ...), etc.
        # This is a columnar transposition with width=p, rows=97/p
        for read_order in [list(range(n_groups)), list(reversed(range(n_groups)))]:
            sigma_period = []
            for g in read_order:
                sigma_period.extend(range(g, 97, n_groups))
            if sorted(sigma_period) == list(range(97)):
                test_sigma(sigma_period,
                           f"B.3-period{base_period}-groups{'fwd' if read_order[0]==0 else 'rev'}",
                           verbose=False)

# Test with ABSCISSA (period 8) as column ordering key
ABSCISSA = "ABSCISSA"
# Alphabetical column order: A=0,B=1,C=2,I=3,S=4 (deduplicated by first occurrence)
print("\nB.4: Keyword columnar transpositions")
for kw in ["KRYPTOS", "ABSCISSA", "SHADOW", "BERLINCLOCK", "EASTNORTHEAST"]:
    L = len(kw)
    if L > 20:
        continue
    # Standard keyword columnar: sort columns by letter rank
    col_order = sorted(range(L), key=lambda i: (kw[i], i))
    sigma_col = []
    nrows_col = (97 + L - 1) // L
    for col in col_order:
        for row in range(nrows_col):
            pos = row * L + col
            if pos < 97:
                sigma_col.append(pos)
    if sorted(sigma_col) == list(range(97)):
        test_sigma(sigma_col, f"B.4-kc-{kw}", verbose=True)
        # Also inverse
        inv_col = [0] * 97
        for i, v in enumerate(sigma_col):
            inv_col[v] = i
        test_sigma(inv_col, f"B.4-kc-{kw}-inv", verbose=True)

print()

# ─── SECTION J: 434-CHAR DOUBLE ROTATION ──────────────────────────────────────
print("=" * 70)
print("APPROACH J: 434-Char Double Rotation (K3+?+K4 Combined = 14×31)")
print("=" * 70)

# K3 known data
K3_START_FLAT = 434   # row 14, col 0
K3_END_FLAT   = 770   # end of K3
K3_CARVED = ''.join(GRID_ROWS[r][c] if GRID_ROWS[r][c] != '?' else '?'
                    for r in range(14, 25) for c in range(31)
                    if r < 24 or c < 27)  # rows 14-24 col 0..26

K3_CARVED = ''.join(GRID_ROWS[r][c] for r in range(14, 25)
                    for c in range(31)
                    if r < 24 or c < 27)
K3_CARVED = K3_CARVED[:336]  # Exactly 336 chars (rows 14..23 = 10 rows × 31 + row24 cols 0..25)
# Actually: rows 14..23 = 10 rows, row 24 cols 0..25 = 26 chars
# 10*31 + 26 = 310 + 26 = 336 ✓

# K3 plaintext (verified)
def k3_ct_to_pt(i):
    a = i // 24; b = i % 24
    inter = 14 * b + 13 - a
    c = inter // 8; d = inter % 8
    return 42 * d + 41 - c

K3_PERM = [k3_ct_to_pt(i) for i in range(336)]
assert sorted(K3_PERM) == list(range(336))
K3_PT_LIST = [''] * 336
for i in range(336):
    K3_PT_LIST[K3_PERM[i]] = K3_CARVED[i]
K3_PT = ''.join(K3_PT_LIST)
print(f"K3_PT[:30]: {K3_PT[:30]}")
print(f"K3_CARVED[:30]: {K3_CARVED[:30]}")

# 434 = 14×31 = K3(336) + ?(1) + K4(97)
# Combined carved: K3_CARVED + '?' + K4 = 434 chars
COMBINED = K3_CARVED + '?' + K4
assert len(COMBINED) == 434

# Double rotation on 434 chars with dimensions (14,31):
# Grid 1: write 434 chars into 14 rows × 31 cols, row by row
# Rotate CW: get 31 rows × 14 cols (intermediate)
# Grid 2: write into 31 rows × 14 cols
# Rotate CW: get 14 rows × 31 cols (output)
def double_rotation(n, r1, c1):
    """Returns permutation perm where perm[output_pos] = input_pos."""
    assert r1 * c1 == n
    # Grid 1: r1 rows × c1 cols, fill row by row
    # Rotate CW: new[c1_new][r1-1-r] = grid[r][c1_new] → dims c1 × r1
    r2, c2 = c1, r1  # After first CW rotation: c1 rows × r1 cols
    # Intermediate position of input[i]:
    # Input at position i = (i//c1, i%c1) in grid1
    # After CW rotation: (col_old, r1-1-row_old) = (i%c1, r1-1-i//c1) in grid2
    # Position in grid2 (read row-by-row): (i%c1) * r1 + (r1-1-i//c1)
    def input_to_inter(i):
        r, c = i // c1, i % c1
        return c * r1 + (r1 - 1 - r)  # intermediate position

    # Grid 2: r2 rows × c2 cols (= c1 rows × r1 cols), intermediate written in
    # Rotate CW: new[c2_new][r2-1-r] = grid2[r][c2_new] → dims c2 × r2 = r1 × c1
    r3, c3 = c2, r2  # = r1, c1
    def inter_to_output(inter):
        r, c = inter // c2, inter % c2
        return c * r2 + (r2 - 1 - r)  # output position

    perm = [inter_to_output(input_to_inter(i)) for i in range(n)]
    return perm

perm_434 = double_rotation(434, 14, 31)
assert sorted(perm_434) == list(range(434)), "perm_434 is not a bijection!"

# Apply to K3+?+K4: perm_434[output_pos] = input_pos
# So: OUTPUT[output_pos] = COMBINED[perm_434[output_pos]]
# PT[perm_434[i]] = COMBINED[i] i.e. perm_434 maps carved→PT position
output_434 = ['?'] * 434
for i in range(434):
    j = perm_434[i]
    output_434[j] = COMBINED[i]
output_str = ''.join(output_434)

print(f"\n14×31 double rotation output[:40]: {output_str[:40]}")
print(f"K3_PT match: {output_str[:336] == K3_PT}")
k3_match = sum(1 for a, b in zip(output_str[:336], K3_PT) if a == b)
print(f"K3_PT partial match: {k3_match}/336")

# K4 PT candidate from this rotation
k4_pt_candidate_434 = output_str[337:434]  # positions 337-433 (after the ?)
k4_pt_candidate_434_clean = ''.join(c for c in k4_pt_candidate_434 if c.isalpha())
print(f"K4_PT candidate (pos 337-433): '{k4_pt_candidate_434}'")
print(f"K4_PT candidate (letters only, {len(k4_pt_candidate_434_clean)}): '{k4_pt_candidate_434_clean}'")

# If K3 matches, this is very significant!
if k3_match == 336:
    print("*** K3 PERFECT MATCH! K4 candidate:")
    if len(k4_pt_candidate_434_clean) >= 4:
        sc = qscore(k4_pt_candidate_434_clean)
        print(f"  Score: {sc:.3f}/char")
        print(f"  ENE: {k4_pt_candidate_434_clean.find('EASTNORTHEAST')}")
        print(f"  BC: {k4_pt_candidate_434_clean.find('BERLINCLOCK')}")

# Also try 434 double rotation in the OTHER direction (31×14 then 14×31)
perm_434_alt = double_rotation(434, 31, 14)
assert sorted(perm_434_alt) == list(range(434))
output_434_alt = ['?'] * 434
for i in range(434):
    output_434_alt[perm_434_alt[i]] = COMBINED[i]
output_str_alt = ''.join(output_434_alt)
k3_match_alt = sum(1 for a, b in zip(output_str_alt[:336], K3_PT) if a == b)
print(f"\n31×14 rotation K3 match: {k3_match_alt}/336")
print(f"  Output[:40]: {output_str_alt[:40]}")

# J.2: Use the 434-char rotation to DEFINE sigma for K4
# If the combined perm maps K4 carved positions → K4 PT positions,
# then sigma(j) tells us which K4_CARVED position has real_CT[j]
# where real_CT = cipher_encrypt(K4_PT, key)
# BUT: if K4_PT from rotation doesn't match cribs, try as sigma directly
print("\nJ.2: 434 rotation → K4 sigma (positions 337-433)")
# perm_434[i] = PT position for combined_carved[i]
# For K4 (carved positions 337-433 = K4 chars 0-96):
# perm_434[337+j] = PT position in combined (337-433 range, minus 337 = K4_PT position)
k4_from_434_sigma = []
for j in range(97):
    carved_pos_in_combined = 336 + 1 + j  # position in combined (after K3 + ?)
    pt_pos_in_combined = perm_434[carved_pos_in_combined]
    k4_pt_pos = pt_pos_in_combined - 337  # relative to K4 PT
    if 0 <= k4_pt_pos < 97:
        k4_from_434_sigma.append(k4_pt_pos)
    else:
        k4_from_434_sigma = None
        break

if k4_from_434_sigma and sorted(k4_from_434_sigma) == list(range(97)):
    print(f"  434-rotation gives valid K4 sigma: {k4_from_434_sigma[:10]}...")
    # This sigma maps K4_PT position j → K4_CARVED position sigma[j]
    # Invert it: sigma_inv[k4_pt_pos] = k4_carved_pos
    sigma_434_inv = [0] * 97
    for j, pt_pos in enumerate(k4_from_434_sigma):
        sigma_434_inv[pt_pos] = j
    test_sigma(sigma_434_inv, "J.2-434-rotation-sigma", verbose=True)
else:
    print(f"  434-rotation K4 sigma is not a bijection (PT positions out of range)")
    if k4_from_434_sigma:
        oob = [x for x in k4_from_434_sigma if not (0 <= x < 97)]
        print(f"  Out-of-bounds positions: {oob[:5]}")

print()

# ─── SECTION C: ENHANCED PRIME/FIBONACCI/MODULAR ─────────────────────────────
print("=" * 70)
print("APPROACH C: Prime/Fibonacci/Modular Position Masks (Enhanced)")
print("=" * 70)

def sieve(n):
    is_prime = [True] * (n + 1)
    is_prime[0] = is_prime[1] = False
    for i in range(2, int(n**0.5) + 1):
        if is_prime[i]:
            for j in range(i*i, n+1, i):
                is_prime[j] = False
    return [i for i in range(n+1) if is_prime[i]]

primes97 = [p for p in sieve(96) if p < 97]  # Primes < 97
prime_set = set(primes97)
# Fibonacci numbers ≤ 97
fibs = set()
a, b = 1, 1
while a <= 97:
    fibs.add(a); a, b = b, a + b

# C.1: Positions at primes
holes_prime = sorted(p for p in primes97)
solids_prime = [i for i in range(97) if i not in prime_set]
test_sigma(holes_prime + solids_prime, "C.1-prime-first", verbose=True)
test_sigma(solids_prime + holes_prime, "C.1-prime-last", verbose=True)

# C.2: Positions at Fibonacci
holes_fib = sorted(f - 1 for f in fibs if 1 <= f <= 97)  # 0-indexed
holes_fib1 = sorted(f for f in fibs if f < 97)            # 1-indexed as 0-indexed
for holes, label in [(holes_fib, "C.2-fib-0idx"), (holes_fib1, "C.2-fib-1idx")]:
    solids = [i for i in range(97) if i not in set(holes)]
    test_sigma(holes + solids, label + "-first", verbose=True)

# C.3: Positions where i is a multiple of key length
for period in [7, 8, 13, 14, 17]:
    holes_period = [i for i in range(97) if i % period == 0]
    solids_period = [i for i in range(97) if i % period != 0]
    test_sigma(holes_period + solids_period, f"C.3-mult{period}-first", verbose=False)
    # Also: positions NOT multiples
    test_sigma(solids_period + holes_period, f"C.3-not-mult{period}-first", verbose=False)

# C.4: 180° rotation (reverse ordering of K4)
sigma_180 = list(range(96, -1, -1))
test_sigma(sigma_180, "C.4-180deg-reverse", verbose=True)

# C.5: Identity + partial shifts
# sigma(j) = (j + k) % 97 for each k
for k in [1, 7, 8, 13, 17, 24, 48, 49, 73, 96]:
    if math.gcd(k, 97) == 1 or k == 0:
        sigma_shift = [(j + k) % 97 for j in range(97)]
        test_sigma(sigma_shift, f"C.5-shift{k}", verbose=False)

# C.6: Affine permutations mod 97: sigma(j) = (a*j + b) % 97
for a_coeff in [2, 3, 5, 7, 8, 13, 17, 24, 48, 73]:
    if math.gcd(a_coeff, 97) == 1:  # 97 is prime, gcd=1 for all a_coeff != 0
        for b_offset in [0, 1, 7, 8]:
            sigma_affine = [(a_coeff * j + b_offset) % 97 for j in range(97)]
            test_sigma(sigma_affine, f"C.6-affine-a{a_coeff}-b{b_offset}", verbose=False)

print()

# ─── SECTION D: K4 SELF-REFERENTIAL & TABLEAU ALIGNMENT ──────────────────────
print("=" * 70)
print("APPROACH D/E: Self-Referential and Tableau-Aligned Masks")
print("=" * 70)

# D.1: Positions where cipher[r][c] == tableau[r][c] in K4 region
same_ct = [i for i, (r, c) in enumerate(K4_RC)
           if GRID_ROWS[r][c].isalpha() and GRID_ROWS[r][c] == TAB[r][c]]
diff_ct = [i for i in range(97) if i not in same_ct]
print(f"D.1: Positions where cipher==tableau in K4: {len(same_ct)}")
if same_ct:
    test_sigma(same_ct + diff_ct, "D.1-same-CT-first", verbose=True)
    test_sigma(diff_ct + same_ct, "D.1-diff-CT-first", verbose=True)

# D.2: Positions where K4[i] is in 17-cycle AND at KA index < 8 (KRYPTOS part of KA)
# KA = KRYPTOSABCDE... → positions 0-6 are KRYPTOS letters
KRYPTOS_LETTERS = set("KRYPTOS")  # K,R,Y,P,T,O,S
kryptos_holes = [i for i in range(97) if K4[i] in KRYPTOS_LETTERS]
kryptos_solids = [i for i in range(97) if K4[i] not in KRYPTOS_LETTERS]
print(f"D.2: K4 letters in KRYPTOS set: {len(kryptos_holes)}")
test_sigma(kryptos_holes + kryptos_solids, "D.2-KRYPTOS-letters-first", verbose=True)
test_sigma(kryptos_solids + kryptos_holes, "D.2-non-KRYPTOS-first", verbose=True)

# D.3: KA index threshold masks
for thresh in [7, 13, 15, 17, 20]:
    holes_thresh = [i for i in range(97) if K4[i] in KA and KA.index(K4[i]) < thresh]
    solids_thresh = [i for i in range(97) if i not in set(holes_thresh)]
    if 15 <= len(holes_thresh) <= 82:
        test_sigma(holes_thresh + solids_thresh,
                   f"D.3-KA-idx<{thresh}({len(holes_thresh)}h)", verbose=False)

# D.4: Tableau key letter threshold — row key AZ[r%26] determines hole
# K4 spans rows 24-27: key letters are AZ[24%26]=Y, AZ[25%26]=Z, AZ[26%26]=Z, AZ[27%26]=A
# Wait: AZ[24]='Y', AZ[25]='Z', AZ[0]='A' (but AZ[26] wraps to AZ[0])
# Keys for K4 rows: row24=Y, row25=Z, row26=A, row27=B (AZ[0%26..27%26])
# Wait: AZ[r%26] for r=24..27: Y, Z, A, B
key_letters_k4_rows = {24: 'Y', 25: 'Z', 26: 'A', 27: 'B'}
for key_letter, label in [('Y', 'rowY'), ('Z', 'rowZ'), ('A', 'rowA'), ('B', 'rowB')]:
    holes_key = [i for i, (r, c) in enumerate(K4_RC) if AZ[r % 26] == key_letter]
    solids_key = [i for i in range(97) if i not in holes_key]
    if holes_key:
        test_sigma(holes_key + solids_key, f"D.4-row-key-{label}({len(holes_key)}h)",
                   verbose=False)

print()

# ─── SECTION SPECIAL: COMBINED APPROACHES ─────────────────────────────────────
print("=" * 70)
print("SPECIAL: Combining Forced Constraints with Sigma Guesses")
print("=" * 70)

# For the most-forced feasible combos from APPROACH H,
# test their sigma with some of the patterns above
print("Testing feasible combos' forced values with random completions...")

if feasible_combos:
    # Take the top combo (most forced positions)
    top_kw, top_cn, top_an, top_fc, top_forced, top_req = feasible_combos[0]
    print(f"Top forced combo: {top_kw}/{top_cn}/{top_an}, {top_fc} forced positions")
    print(f"Forced: {top_forced}")

    # Build a partial sigma consistent with forced values
    # Fill remaining positions with natural order
    partial = list(range(97))  # start with identity
    # Apply forced positions
    for j, k4pos in top_forced.items():
        partial[j] = k4pos
    # Check if this is consistent (no collisions with forced values)
    forced_vals = set(top_forced.values())
    forced_keys = set(top_forced.keys())
    free_pos = sorted(set(range(97)) - forced_keys)
    free_vals = sorted(set(range(97)) - forced_vals)

    # Try: fill free positions with natural order
    free_val_idx = 0
    for j in free_pos:
        while free_val_idx < len(free_vals) and free_vals[free_val_idx] in forced_vals:
            free_val_idx += 1
        if free_val_idx < len(free_vals):
            partial[j] = free_vals[free_val_idx]
            free_val_idx += 1

    if sorted(partial) == list(range(97)):
        test_sigma(partial, f"SPEC.1-forced-{top_kw[:6]}-natural-fill", verbose=True)

    # Also: for each YWT-compatible combo, test forced sigma with cycle-based filling
    if yesno_combos:
        top_ywt = yesno_combos[0]
        kw, cn, an, fc, forced_ywt, req_ywt = top_ywt
        print(f"\nTop YWT combo: {kw}/{cn}/{an}, {fc} forced, testing cycle-based fill...")
        # Build sigma from forced values + cycle-order for free positions
        partial_ywt = list(range(97))
        for j, k4pos in forced_ywt.items():
            partial_ywt[j] = k4pos
        forced_vals_ywt = set(forced_ywt.values())
        free_pos_ywt = sorted(set(range(97)) - set(forced_ywt.keys()))
        free_vals_ywt = sorted(set(range(97)) - forced_vals_ywt,
                                key=lambda v: (KA.index(K4[v]) if K4[v] in KA else 26, v))
        for k, j in enumerate(free_pos_ywt):
            if k < len(free_vals_ywt):
                partial_ywt[j] = free_vals_ywt[k]
        if sorted(partial_ywt) == list(range(97)):
            test_sigma(partial_ywt, f"SPEC.2-YWT-{kw[:6]}-cycle-fill", verbose=True)

# ─── SECTION: TABLEAU STRUCTURAL CLUES ────────────────────────────────────────
print()
print("=" * 70)
print("SPECIAL: Extra-L at Row N / Tableau Structural Clues")
print("=" * 70)

# Row 14 (key=N) has ANOMALOUS extra L (32 chars instead of 31).
# Row 22 (key=V) has extra T.
# V - N = T - L = 8 (period-8 signal)
# These anomalies are at rows 14 and 22.

# What if these mark "hole rows" in the grille?
# K4 is in rows 24-27. Distance from row 14: 10, 11, 12, 13. From row 22: 2, 3, 4, 5.
# Mod 8: row 24 % 8 = 0, row 25 % 8 = 1, row 26 % 8 = 2, row 27 % 8 = 3
# Row 14 % 8 = 6, Row 22 % 8 = 6 as well? 22%8=6. And 14%8=6.
# Both anomaly rows have r%8 == 6!
print(f"Row 14 % 8 = {14%8}, Row 22 % 8 = {22%8} — both = 6!")
print(f"K4 rows mod 8: {[(r, r%8) for r in range(24,28)]}")

# Test: holes at K4 positions where (r+c) % 8 == 6 (mod-8 pattern matching anomaly rows)
for target_mod in range(8):
    holes_mod8 = [i for i, (r, c) in enumerate(K4_RC) if (r + c) % 8 == target_mod]
    solids_mod8 = [i for i in range(97) if i not in holes_mod8]
    if 5 <= len(holes_mod8) <= 92:
        test_sigma(holes_mod8 + solids_mod8, f"TAB.1-(r+c)%8={target_mod}({len(holes_mod8)}h)",
                   verbose=False)

# The V-N=8 pattern: maybe reading starts at col offset +8 per row
# Row 25 starts at col 0; if shifted by +8: col 8
# Row 26 starts at col 0; shifted by +8: col 16
# Row 27 starts at col 0; shifted by +8: col 24
print("\nTAB.2: Row-shifted reading (offset +8 per row from row 25 start)")
sigma_shifted = []
for r, row_start, row_len in [(24, 0, 4), (25, 4, 31), (26, 35, 31), (27, 66, 31)]:
    row_indices = list(range(row_start, row_start + row_len))
    row_number = r - 24  # 0, 1, 2, 3
    shift = row_number * 8 % row_len
    rotated = row_indices[shift:] + row_indices[:shift]
    sigma_shifted.extend(rotated)

if sorted(sigma_shifted) == list(range(97)):
    test_sigma(sigma_shifted, "TAB.2-row-shift-8-per-row", verbose=True)

print()

# ─── SECTION: DIRECT PLAINTEXT HYPOTHESIS TESTS ─────────────────────────────-
print("=" * 70)
print("SPECIAL: Direct Plaintext Search (What does K4 say?)")
print("=" * 70)

# What if K4_PT starts with "YESWONDERFULTHINGS" AND includes "EASTNORTHEAST" AND "BERLINCLOCK"?
# The ENTIRE 97-char K4 PT can be (partially) assembled from:
# - K4_PT[0:18] = YESWONDERFULTHINGS (hypothesis)
# - K4_PT[21:34] = EASTNORTHEAST (known)
# - K4_PT[63:74] = BERLINCLOCK (known)
# = 18 + 13 + 11 = 42 chars known (no overlap: 0-17, 21-33, 63-73)
# Remaining unknown: 18-20 (3 chars), 34-62 (29 chars), 74-96 (23 chars) = 55 chars

# If we assemble the known 42 chars, the full PT might be something like:
# "YESWONDERFULTHINGS??EASTNORTHEAST[29 unknown]BERLINCLOCK[23 unknown]"
known_pt = ['?'] * 97
for j, ch in KNOWN_YWT:
    known_pt[j] = ch

pt_str = ''.join(known_pt)
print(f"Known PT (42 positions filled): {pt_str}")
print(f"Positions 18-20: {pt_str[18:21]} (3 unknown chars between YWT and ENE start gap)")
print(f"Position 19: should be part of transition from 'YESWONDERFULTHINGS' to 'EASTNORTHEAST'")
# K4_PT[18]='?', K4_PT[19]='?', K4_PT[20]='?' — these 3 chars + YWT + ENE should flow

# What text might go between YESWONDERFULTHINGS and EASTNORTHEAST?
# Carter's quote: "Yes, wonderful things!" Then later described going through the wall
# "EAST NORTHEAST" might be a compass direction to the location
# Try some plausible 3-char bridges
bridges = ["ITS", "AND", "YES", "NOW", "BUT", "ARE", "THE", "YOU"]
for br in bridges:
    candidate = YWT + br + "EASTNORTHEAST"  # positions 0-33 (34 chars)
    # Check: does this fit a known key? For each kw/cipher/alpha, compute required
    # real_CT[0:34] and check against K4 frequency
    for kw in ["KRYPTOS", "ABSCISSA", "SHADOW", "BERLINCLOCK"]:
        for an, a in ALPHAS:
            ai = {c: i for i, c in enumerate(a)}
            req34 = []
            feasible34 = True
            for j, ch in enumerate(candidate):
                if ch not in a:
                    feasible34 = False; break
                ki = ai[kw[j % len(kw)]]
                pi = ai[ch]
                req34.append(a[(pi + ki) % 26])  # vig_enc

            if not feasible34:
                continue
            # Check multiset feasibility with K4_FREQ
            req_counts = Counter(req34)
            if all(K4_FREQ[ch] >= cnt for ch, cnt in req_counts.items()):
                print(f"  Feasible bridge '{br}': {kw}/{an}/vig for positions 0-33")

print()

# ─── SUMMARY ─────────────────────────────────────────────────────────────────
print("=" * 70)
print("FINAL SUMMARY")
print("=" * 70)
print(f"Total permutations tested: {TESTED}")
print(f"Best score seen: {BEST_SCORE:.3f}/char  (random ≈ -9.9, English ≈ -4.2)")
print(f"Crib hits: {len(CRIB_HITS)}")

if CRIB_HITS:
    for h in CRIB_HITS:
        print(f"\n  *** HIT: {h['label']}")
        print(f"      PT: {h['pt']}")
        print(f"      Key: {h['kw']}/{h['cipher']}/{h['alpha']}")
        print(f"      ENE@{h.get('ene','?')}  BC@{h.get('bc','?')}  score={h['score']:.3f}")
else:
    print("  No crib hits.")

print(f"\nKey findings:")
print(f"  AZ→KA cycle: 17={sorted(CYCLE17)[:5]}..., 8={sorted(CYCLE8)[:5]}..., Z=fixed")
print(f"  K4 cycle distribution: 17-cycle={k4_cycle17_count}, 8-cycle={k4_cycle8_count}, Z={k4_cycle1_count}")
print(f"  T-diagonal K4 positions: {T_IN_K4} (letters: {[K4[i] for i in T_IN_K4]})")
print(f"  Feasible combos (24 cribs): {len(feasible_combos)}")
print(f"  Feasible combos (42 cribs+YWT): {len(yesno_combos)}")
print(f"  Top YWT-compatible: {yesno_combos[0][:3] if yesno_combos else 'none'}")
print(f"  434-char rotation K3 match: {k3_match}/336")
print(f"  Row 14 and Row 22 both have r%8=6 (period-8 anomaly signal)")
