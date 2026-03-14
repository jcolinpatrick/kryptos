#!/usr/bin/env python3
"""
Quagmire cross-alphabet analysis for K4.

Cipher:  quagmire_cross
Family:  campaigns
Status:  active
Keyspace: see implementation
Last run:
Best score:

Tests UNTESTED cross-alphabet cipher variants (Elonka Dunin's insight):
The Kryptos sculpture has a Quagmire II tableau (KA body, AZ edges),
but K1-K3 used Quagmire III (KA everywhere). The tableau may be for K4.

Cross-alphabet key recovery formulas (Vigenere variant):
  Q2 (sculpture): key = (KA[CT] - AZ[PT]) % 26   ← CT in KA body, PT in AZ header
  Q1 (reversed):  key = (AZ[CT] - KA[PT]) % 26   ← CT in AZ, PT in KA header

These produce DIFFERENT key values than same-alphabet modes (AZ,AZ) or (KA,KA).
Same-alphabet modes have been tested; cross-alphabet modes have NOT.

Phase 1: Bean inequality analysis for all 12 modes
Phase 2: Periodic consistency on raw 97
Phase 3: Null-mask + Q2/Q1 autokey with SA
Phase 4: Null-mask + Q2/Q1 autokey + col7 transposition
"""

import sys, time, random, itertools, json
from pathlib import Path
from collections import Counter

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from kryptos.kernel.constants import CT, CRIB_DICT, BEAN_EQ, BEAN_INEQ, CT_LEN

t0 = time.time()
random.seed(42)

# ── Constants ──────────────────────────────────────────────────────────────
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
KA = "KRYPTOSABCDEFGHIJLMNQUVWXZ"
MOD = 26
N = len(CT)

AZ_IDX = {ch: i for i, ch in enumerate(AZ)}
KA_IDX = {ch: i for i, ch in enumerate(KA)}

PT_AT = dict(CRIB_DICT)
CRIB_POS = sorted(PT_AT.keys())

ENE_PT = "EASTNORTHEAST"
BC_PT = "BERLINCLOCK"
ENE_START, BC_START = 21, 63

print("=" * 80)
print("QUAGMIRE CROSS-ALPHABET ANALYSIS FOR K4")
print("=" * 80)
print(f"CT: {CT} ({N} chars)")
print(f"KA: {KA}")
print(f"Crib positions: {len(CRIB_POS)}")
print()

# ── Key recovery for any (ct_alphabet, pt_alphabet, variant) ──────────────

IDX = {"AZ": AZ_IDX, "KA": KA_IDX}
ALPHA = {"AZ": AZ, "KA": KA}

def key_val(ct_ch, pt_ch, ct_a, pt_a, var):
    c = IDX[ct_a][ct_ch]
    p = IDX[pt_a][pt_ch]
    if var == "vig":
        return (c - p) % MOD
    elif var == "beau":
        return (c + p) % MOD
    else:  # vbeau
        return (p - c) % MOD

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1: Bean inequality analysis
# ═══════════════════════════════════════════════════════════════════════════
print("=" * 80)
print("PHASE 1: Bean inequality analysis (all C(24,2)=276 crib pairs)")
print("=" * 80)

all_pairs = list(itertools.combinations(CRIB_POS, 2))
assert len(all_pairs) == 276

ALPH_PAIRS = [("AZ", "AZ"), ("KA", "KA"), ("KA", "AZ"), ("AZ", "KA")]
PAIR_NAMES = {"AZ_AZ": "Standard", "KA_KA": "Q3 (K1-K2 method)",
              "KA_AZ": "Q2 (SCULPTURE TABLEAU)", "AZ_KA": "Q1 (reversed cross)"}
VARIANTS = ["vig", "beau", "vbeau"]

for ct_a, pt_a in ALPH_PAIRS:
    pair_key = f"{ct_a}_{pt_a}"
    name = PAIR_NAMES[pair_key]
    cross = " *** UNTESTED ***" if ct_a != pt_a else " (already tested)"

    # Per-variant inequality counts
    var_ineqs = {}
    for var in VARIANTS:
        n_ineq = 0
        for a, b in all_pairs:
            ka = key_val(CT[a], PT_AT[a], ct_a, pt_a, var)
            kb = key_val(CT[b], PT_AT[b], ct_a, pt_a, var)
            if ka != kb:
                n_ineq += 1
        var_ineqs[var] = n_ineq

    # Variant-independent count
    vi = 0
    for a, b in all_pairs:
        all_diff = True
        for var in VARIANTS:
            ka = key_val(CT[a], PT_AT[a], ct_a, pt_a, var)
            kb = key_val(CT[b], PT_AT[b], ct_a, pt_a, var)
            if ka == kb:
                all_diff = False
                break
        if all_diff:
            vi += 1

    # Bean EQ check
    k27 = key_val(CT[27], PT_AT[27], ct_a, pt_a, "vig")
    k65 = key_val(CT[65], PT_AT[65], ct_a, pt_a, "vig")
    bean_eq = "PASS" if k27 == k65 else "FAIL"

    print(f"\n{name}{cross}")
    print(f"  ct_alphabet={ct_a}, pt_alphabet={pt_a}")
    print(f"  Bean EQ (k[27]=k[65]): {k27}={k65} → {bean_eq}")
    for var in VARIANTS:
        print(f"  {var:8s}: {var_ineqs[var]}/276 inequalities ({276-var_ineqs[var]} equalities)")
    print(f"  Variant-independent: {vi}/276")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: Periodic consistency for all 12 modes, periods 1-26
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 2: Periodic consistency (periods 1-26, raw 97)")
print("=" * 80)

def check_periodic(ct_a, pt_a, var, period):
    """Check if key values at crib positions are consistent with period-P key."""
    residues = {}
    for pos in CRIB_POS:
        r = pos % period
        k = key_val(CT[pos], PT_AT[pos], ct_a, pt_a, var)
        if r not in residues:
            residues[r] = k
        elif residues[r] != k:
            return False
    return True

def count_consistent(ct_a, pt_a, var, period):
    """Count how many crib positions are consistent with best periodic key."""
    residues = {}
    for pos in CRIB_POS:
        r = pos % period
        k = key_val(CT[pos], PT_AT[pos], ct_a, pt_a, var)
        if r not in residues:
            residues[r] = Counter()
        residues[r][k] += 1
    return sum(c.most_common(1)[0][1] for c in residues.values())

print(f"\n{'Mode':<40s} | Survivors (fully consistent periods)")
print("-" * 80)

for ct_a, pt_a in ALPH_PAIRS:
    pair_key = f"{ct_a}_{pt_a}"
    name = PAIR_NAMES[pair_key]
    for var in VARIANTS:
        survivors = []
        best_score, best_p = 0, 0
        for p in range(1, 27):
            if check_periodic(ct_a, pt_a, var, p):
                sc = count_consistent(ct_a, pt_a, var, p)
                survivors.append((p, sc))
            sc = count_consistent(ct_a, pt_a, var, p)
            if sc > best_score:
                best_score, best_p = sc, p

        label = f"{name} {var}"
        if survivors:
            surv_str = ", ".join(f"p={p}({s}/24)" for p, s in survivors)
            print(f"  {label:<38s} | *** {surv_str} ***")
        else:
            print(f"  {label:<38s} | ALL ELIMINATED (best {best_score}/24 at p={best_p})")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3: Null-mask + Q2/Q1 autokey with SA
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 3: Null-mask + cross-alphabet autokey (SA optimization)")
print("Q2 = sculpture tableau: CT looked up in KA, PT from KA header, key in AZ")
print("Q1 = reversed: CT in AZ, PT from KA, key in AZ")
print("=" * 80)


def cross_autokey_decrypt(ct_chars, keyword, ct_a, pt_a, var):
    """Decrypt with cross-alphabet autokey (PT-feedback).

    Tableau semantics:
      Encrypt: CT = CT_ALPHA[(KEY_NUM + PT_ALPHA.index(PT)) % 26]
      where KEY_NUM = left_column_index(key_letter) = AZ.index(key_letter)

    Decrypt for Vig variant:
      PT_ALPHA.index(PT) = (CT_ALPHA.index(CT) - KEY_NUM) % 26
      PT = PT_ALPHA[(...)]

    Wait — the header row IS the PT alphabet. So for Q2:
      PT_ALPHA = KA (the header), CT_ALPHA = KA (body rows share same alphabet)
      But the KEY is from AZ left column.

    Actually, re-deriving from first principles:
      The Kryptos Q2 tableau cell at (key_row, col):
        Row for key K: KA shifted left by AZ.index(K) positions
        CT = KA[(AZ.index(key) + col) % 26]
        where col = position of PT in header = KA.index(PT)

      So: CT = KA[(AZ.index(key) + KA.index(PT)) % 26]
      Decrypt: KA.index(PT) = (KA.index(CT) - AZ.index(key)) % 26
               PT = KA[(KA.index(CT) - AZ.index(key)) % 26]

    For Q2 autokey (PT feedback):
      key_num[i] = AZ.index(PT[i-L])   (key column is AZ)

    For Q1 tableau:
      CT = AZ[(AZ.index(key) + KA.index(PT)) % 26]
      Decrypt: KA.index(PT) = (AZ.index(CT) - AZ.index(key)) % 26
               PT = KA[(AZ.index(CT) - AZ.index(key)) % 26]
    """
    ct_idx_table = IDX[ct_a]
    pt_alpha = ALPHA[pt_a]  # For Q2: KA. For Q1: KA.
    # Actually for Q2, the decrypt formula gives PT = KA[...] regardless.
    # For Q1, CT = AZ[...] and PT = KA[...].
    # In both cases, PT comes from KA (the header alphabet).
    # Wait, that's not right for standard modes...

    # Let me use a general formulation:
    # CT = ct_alpha[(key_num + pt_alpha.index(PT)) % 26]
    # Decrypt: pt_alpha.index(PT) = (ct_alpha.index(CT) - key_num) % 26  [vig]
    # PT = pt_alpha[(ct_alpha.index(CT) - key_num) % 26]

    # For Beaufort: CT = ct_alpha[(key_num - pt_alpha.index(PT)) % 26]
    # Decrypt: pt_alpha.index(PT) = (key_num - ct_alpha.index(CT)) % 26
    # PT = pt_alpha[(key_num - ct_alpha.index(CT)) % 26]

    # For VBeau: CT = ct_alpha[(pt_alpha.index(PT) - key_num) % 26]
    # Decrypt: pt_alpha.index(PT) = (ct_alpha.index(CT) + key_num) % 26
    # PT = pt_alpha[(ct_alpha.index(CT) + key_num) % 26]

    n = len(ct_chars)
    L = len(keyword)
    kw_nums = [AZ_IDX[c] for c in keyword]  # Key column is always AZ

    pt_chars = []
    for i in range(n):
        c_val = ct_idx_table[ct_chars[i]]

        if i < L:
            key_num = kw_nums[i]
        else:
            # PT feedback: key = AZ.index(previous PT letter)
            key_num = AZ_IDX[pt_chars[i - L]]

        if var == "vig":
            pt_idx = (c_val - key_num) % MOD
        elif var == "beau":
            pt_idx = (key_num - c_val) % MOD
        else:  # vbeau
            pt_idx = (c_val + key_num) % MOD

        # PT comes from the pt_alphabet
        # For Q2: pt_alpha = KA (header row is KA)
        # For Q1: pt_alpha = KA (header row is KA)
        # Hmm wait, for Q1 the header is KA? Let me re-check.
        #
        # Q1: keyword-mixed PT alphabet = KA, standard CT alphabet = AZ
        # Header = KA (the PT lookup alphabet)
        # Body rows = AZ shifted
        #
        # Q2: standard PT alphabet = AZ, keyword-mixed CT alphabet = KA
        # Wait, Gillogly says Q2 = "plaintext alphabet straight A-Z, cipher rows keyed"
        # So the HEADER (plaintext) is AZ, and the BODY (cipher) is KA rows.
        #
        # But on the actual Kryptos sculpture, the HEADER is KA!
        # The sculpture doesn't match the standard Q2 definition exactly.
        #
        # On the sculpture:
        # - Top row: K R Y P T O S A B C D E F G H I J L M N Q U V W X Z (= KA)
        # - Left column: A B C D E F ... Z (= AZ)
        # - Body: shifted KA rows
        #
        # Gillogly says this is Q2. But Q2's definition says "straight A-Z" plaintext.
        # The discrepancy: Gillogly may consider the KA header as part of the
        # cipher alphabet system, not the plaintext alphabet.
        #
        # In Q2, you LOOK UP the plaintext letter in the header to find the column.
        # The header IS the KA alphabet. So you find 'E' at KA position 11.
        # Then you go to the key row and read the ciphertext.
        #
        # The "standard plaintext alphabet" in Q2's definition means the
        # plaintext letters aren't re-encoded — 'E' means 'E'. The header
        # just tells you which column to use. It's the COLUMN INDEX that
        # comes from KA ordering, not the plaintext letter itself.
        #
        # So for Q2 on the Kryptos tableau:
        #   column = KA.index(PT)    (find PT in KA header)
        #   row = AZ.index(key)      (find key in AZ left column)
        #   CT = body_row[column]    (shifted KA)
        #   body_row = KA shifted by AZ.index(key)
        #   CT = KA[(AZ.index(key) + KA.index(PT)) % 26]
        #
        # So PT is indexed in KA for column lookup!
        # Decrypt: KA.index(PT) = (KA.index(CT) - AZ.index(key)) % 26
        #          PT = KA[(KA.index(CT) - AZ.index(key)) % 26]
        #
        # The output PT is a KA letter (read from header).
        # But since KA contains all 26 letters, PT is just a regular letter.

        # For the Kryptos sculpture specifically:
        # Both Q2 and Q1 produce PT from the KA alphabet (header row).
        # The CT alphabet differs: Q2 uses KA body, Q1 would use AZ body.
        # But wait, Q1 on the sculpture doesn't exist — the sculpture only
        # has ONE tableau (Q2). Q1 would be a hypothetical reversed tableau.

        # For generality, let's say PT comes from pt_alpha:
        pt_chars.append(pt_alpha[pt_idx])

    return pt_chars


def score_with_mask(ct97, null_mask, keyword, ct_a, pt_a, var):
    """Remove nulls, decrypt, score against cribs at mapped positions."""
    ct73 = [ct97[i] for i in range(len(ct97)) if i not in null_mask]
    if len(ct73) != 73:
        return 0, 0, 0, ""

    pt73 = cross_autokey_decrypt(ct73, keyword, ct_a, pt_a, var)
    pt_str = "".join(pt73)

    # Map 97-positions to 73-positions
    pos_map = {}
    j = 0
    for i in range(len(ct97)):
        if i not in null_mask:
            pos_map[i] = j
            j += 1

    ene_score = 0
    for k, ch in enumerate(ENE_PT):
        p97 = ENE_START + k
        if p97 in pos_map and pos_map[p97] < len(pt73):
            if pt73[pos_map[p97]] == ch:
                ene_score += 1

    bc_score = 0
    for k, ch in enumerate(BC_PT):
        p97 = BC_START + k
        if p97 in pos_map and pos_map[p97] < len(pt73):
            if pt73[pos_map[p97]] == ch:
                bc_score += 1

    return ene_score + bc_score, ene_score, bc_score, pt_str


def sa_optimize(keyword, ct_a, pt_a, var, n_restarts=50, n_steps=8000):
    """SA to find best 24-position null mask."""
    best_g = 0
    best_g_ene = best_g_bc = 0
    best_g_mask = None
    best_g_pt = ""

    all_pos = list(range(N))

    for _ in range(n_restarts):
        random.shuffle(all_pos)
        mask = set(all_pos[:24])

        score, ene, bc, pt = score_with_mask(CT, mask, keyword, ct_a, pt_a, var)
        cur_score = score
        cur_mask = set(mask)

        temp = 3.0
        for step in range(n_steps):
            nulls = list(cur_mask)
            non_nulls = [p for p in range(N) if p not in cur_mask]
            rm = random.choice(nulls)
            add = random.choice(non_nulls)

            cur_mask.discard(rm)
            cur_mask.add(add)

            ns, ne, nb, npt = score_with_mask(CT, cur_mask, keyword, ct_a, pt_a, var)

            if ns >= cur_score or (temp > 0.01 and random.random() < 2.718 ** ((ns - cur_score) / temp)):
                cur_score = ns
                if ns > best_g:
                    best_g = ns
                    best_g_ene = ne
                    best_g_bc = nb
                    best_g_mask = set(cur_mask)
                    best_g_pt = npt
            else:
                cur_mask.discard(add)
                cur_mask.add(rm)

            temp *= 0.9995

    return best_g, best_g_ene, best_g_bc, best_g_mask, best_g_pt


KEYWORDS = ["KRYPTOS", "DEFECTOR", "KOMPASS", "ABSCISSA", "COLOPHON",
            "PALIMPSEST", "BERLIN", "SHADOW", "CIPHER"]

# ── Q2: The sculpture tableau ──
print("\nQ2 autokey (sculpture tableau): CT=KA body, PT=KA header, Key=AZ column")
print("-" * 80)

q2_results = []
for kw in KEYWORDS:
    for var in VARIANTS:
        score, ene, bc, mask, pt = sa_optimize(kw, "KA", "KA", var)
        # Wait — Q2 on the actual sculpture: CT alphabet is KA, and
        # PT is looked up in the KA header. But the KEY is from AZ column.
        # In our general decrypt function, ct_a="KA" and pt_a refers to
        # the output alphabet (KA header). The key is always AZ.
        # So ct_a="KA", pt_a="KA" with key in AZ — this is what we want.
        #
        # But this is the SAME as KA_vig/KA_beau with AZ-indexed key!
        # The key difference from standard KA_vig is the autokey feedback:
        # key[i] = AZ.index(PT[i-L]) instead of KA.index(PT[i-L])
        #
        # In our cross_autokey_decrypt function, the key feedback always
        # uses AZ.index. So this IS the Q2 variant even though ct_a=pt_a=KA.

        marker = " ***" if score >= 13 else ""
        print(f"  {kw}:{var} → {score}/24 (ene={ene}/13 bc={bc}/11){marker}")
        if score >= 13:
            print(f"    Nulls: {sorted(mask)}")
            print(f"    PT: {pt[:60]}...")
        q2_results.append((kw, var, score, ene, bc))

# ── Also test with ct_a="KA", pt_a="AZ" (the cross-index key derivation) ──
print("\nQ2-cross autokey (CT indexed in KA, PT indexed in AZ): distinct key derivation")
print("-" * 80)

for kw in KEYWORDS:
    for var in VARIANTS:
        score, ene, bc, mask, pt = sa_optimize(kw, "KA", "AZ", var)
        marker = " ***" if score >= 13 else ""
        print(f"  {kw}:{var} → {score}/24 (ene={ene}/13 bc={bc}/11){marker}")
        if score >= 13:
            print(f"    Nulls: {sorted(mask)}")
            print(f"    PT: {pt[:60]}...")

# ── Q1: Reversed cross ──
print("\nQ1 autokey (reversed cross: CT=AZ, PT=KA, Key=AZ)")
print("-" * 80)

for kw in KEYWORDS:
    for var in VARIANTS:
        score, ene, bc, mask, pt = sa_optimize(kw, "AZ", "KA", var)
        marker = " ***" if score >= 13 else ""
        print(f"  {kw}:{var} → {score}/24 (ene={ene}/13 bc={bc}/11){marker}")
        if score >= 13:
            print(f"    Nulls: {sorted(mask)}")
            print(f"    PT: {pt[:60]}...")

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4: Best configs + col7 transposition
# ═══════════════════════════════════════════════════════════════════════════
print("\n" + "=" * 80)
print("PHASE 4: Cross-alphabet autokey + col7 transposition")
print("=" * 80)


def columnar_untranspose(text, width):
    """Undo columnar transposition: reverse of reading column-by-column."""
    n = len(text)
    if n == 0 or width <= 0:
        return text

    n_full_rows = n // width
    n_extra = n % width

    # Columns: first n_extra columns have (n_full_rows+1) chars,
    # remaining have n_full_rows chars
    grid = []
    pos = 0
    for c in range(width):
        col_len = n_full_rows + (1 if c < n_extra else 0)
        grid.append(list(text[pos:pos + col_len]))
        pos += col_len

    # Read row by row
    result = []
    max_rows = n_full_rows + (1 if n_extra > 0 else 0)
    for r in range(max_rows):
        for c in range(width):
            if r < len(grid[c]):
                result.append(grid[c][r])

    return "".join(result)


def score_with_mask_and_trans(ct97, null_mask, keyword, ct_a, pt_a, var, col_width):
    """Remove nulls, undo columnar transposition, decrypt, score (free crib)."""
    ct73 = [ct97[i] for i in range(len(ct97)) if i not in null_mask]
    if len(ct73) != 73:
        return 0, 0, 0, ""

    ct73_str = "".join(ct73)
    ct73_untrans = columnar_untranspose(ct73_str, col_width)

    pt73 = cross_autokey_decrypt(list(ct73_untrans), keyword, ct_a, pt_a, var)
    pt_str = "".join(pt73)

    # Free crib search (positions may have shifted after transposition)
    ene_best = 0
    for s in range(max(0, len(pt_str) - len(ENE_PT) + 1)):
        m = sum(1 for k, ch in enumerate(ENE_PT) if s + k < len(pt_str) and pt_str[s + k] == ch)
        ene_best = max(ene_best, m)

    bc_best = 0
    for s in range(max(0, len(pt_str) - len(BC_PT) + 1)):
        m = sum(1 for k, ch in enumerate(BC_PT) if s + k < len(pt_str) and pt_str[s + k] == ch)
        bc_best = max(bc_best, m)

    return ene_best + bc_best, ene_best, bc_best, pt_str


def sa_optimize_trans(keyword, ct_a, pt_a, var, col_width, n_restarts=30, n_steps=5000):
    """SA for null mask with transposition."""
    best_g = 0
    best_g_ene = best_g_bc = 0
    best_g_mask = None
    best_g_pt = ""
    all_pos = list(range(N))

    for _ in range(n_restarts):
        random.shuffle(all_pos)
        mask = set(all_pos[:24])
        cur_score, _, _, _ = score_with_mask_and_trans(CT, mask, keyword, ct_a, pt_a, var, col_width)
        cur_mask = set(mask)
        temp = 3.0

        for step in range(n_steps):
            nulls = list(cur_mask)
            non_nulls = [p for p in range(N) if p not in cur_mask]
            rm = random.choice(nulls)
            add = random.choice(non_nulls)
            cur_mask.discard(rm)
            cur_mask.add(add)

            ns, ne, nb, npt = score_with_mask_and_trans(CT, cur_mask, keyword, ct_a, pt_a, var, col_width)
            if ns >= cur_score or (temp > 0.01 and random.random() < 2.718 ** ((ns - cur_score) / temp)):
                cur_score = ns
                if ns > best_g:
                    best_g, best_g_ene, best_g_bc = ns, ne, nb
                    best_g_mask = set(cur_mask)
                    best_g_pt = npt
            else:
                cur_mask.discard(add)
                cur_mask.add(rm)
            temp *= 0.9995

    return best_g, best_g_ene, best_g_bc, best_g_mask, best_g_pt


TOP_KW = ["KRYPTOS", "DEFECTOR", "KOMPASS", "ABSCISSA", "COLOPHON"]

for ct_a, pt_a, mode_name in [("KA", "KA", "Q2-tableau"), ("KA", "AZ", "Q2-cross"),
                               ("AZ", "KA", "Q1-reversed")]:
    print(f"\n{mode_name} + col7:")
    print("-" * 60)
    for kw in TOP_KW:
        for var in VARIANTS:
            score, ene, bc, mask, pt = sa_optimize_trans(kw, ct_a, pt_a, var, 7,
                                                          n_restarts=20, n_steps=4000)
            marker = " ***" if score >= 13 else ""
            print(f"  {kw}:{var} → {score}/24 (ene={ene}/13 bc={bc}/11){marker}")
            if score >= 15:
                print(f"    Nulls: {sorted(mask)}")
                print(f"    PT: {pt[:60]}...")

# ═══════════════════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
elapsed = time.time() - t0
print("\n" + "=" * 80)
print(f"COMPLETE in {elapsed:.1f}s")
print("=" * 80)
print("""
KEY FINDINGS:
- Phase 1: Bean inequality counts for cross-alphabet modes
- Phase 2: Whether periodic elimination holds for Q1/Q2
- Phase 3: Q2/Q1 autokey scores (compare to KA_vig=13/24, AZ_beau=12/24)
- Phase 4: Q2/Q1 + col7 scores (compare to DEFECTOR:AZ_beau+col7=15/24)

The sculpture's Quagmire II tableau was NOT used for K1-K3 (which used Q3).
Elonka Dunin (2010): "Why would Sanborn have placed this entire tableau if
it couldn't be used to decrypt any of the ciphertext on the other side?"
Sanborn (WSJ): "The most obvious key to the sculpture, nobody has picked up on."
""")
