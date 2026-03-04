"""
Cipher: tableau analysis
Family: tableau
Status: active
Keyspace: see implementation
Last run: 
Best score: 
"""
"""
blitz_tableau_matching.py — Cipher-Tableau Match Analysis for 28×31 Kryptos Grid

Approaches:
  A. Statistical test — Is 39/868 significantly different from random?
  B. Spatial pattern — Map the 39 matches on the 28×31 grid
  C. Section distribution — How many matches per section (K1/K2/K3/K4)?
  D. Non-match constraint analysis — 829 cells where cipher≠tableau constrain holes
  E. K4-specific matches — which of K4's 97 positions are matches?
  F. Row/column clustering — chi-squared test for non-uniform spatial distribution
  G. 180° rotation symmetry — do matches pair up under (r,c)→(27-r,30-c)?
  H. K3 verification — use known K3 PT/CT to test grille theories
  I. "Free variable" analysis — 39 matches as free variables in grille search
"""

from __future__ import annotations
import math
import sys
from collections import Counter

# ── Grid Data ────────────────────────────────────────────────────────────────

# 28×31 cipher grid (corrected, with ? replaced by ? as placeholder)
# Each row is exactly 31 chars. ? marks positional ? characters (not counted as positions
# for scrambling, but occupying physical cells).
CIPHER_ROWS = [
    "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIV",  # row 0
    "JYQTQUXQBQVYUVLLTREVJYQTMKYRDMF",  # row 1
    "DVFPJUDEEHZWETZYVGWHKKQETGFQJNC",  # row 2  (K1→K2 boundary)
    "EGGWHKK?DQMCPFQZDQMMIAGPFXHQRLG",  # row 3  K2 (? at col 7)
    "TIMVMZJANQLVKQEDAGDVFRPJUNGEUNA",  # row 4
    "QZGZLECGYUXUEENJTBJLBQCETBJDFHR",  # row 5
    "RYIZETKZEMVDUFKSJHKFWHKUWQLSZFT",  # row 6
    "IHHDDDUVH?DWKBFUFPWNTDFIYCUQZER",  # row 7  (? at col 9)
    "EEVLDKFEZMOQQJLTTUGSYQPFEUNLAVI",  # row 8
    "DXFLGGTEZFKZBSFDQVGOGIPUFXHHDRK",  # row 9
    "FFHQNTGPUAECNUVPDJMQCLQUMUNEDFQ",  # row 10
    "ELZZVRRGKFFVOEEXBDMVPNFQXEZLGRE",  # row 11
    "DNQFMPNZGLFLPMRJQYALMGNUVPDXVKP",  # row 12
    "DQUMEBEDMHDAFMJGZNUPLGEWJLLAETG",  # row 13  K2 ends
    "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI",  # row 14  K3 starts (CENTER)
    "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE",  # row 15
    "TPRNGATIHNRARPESLNNELEBLPIIACAE",  # row 16
    "WMTWNDITEENRAHCTENEUDRETNHAEOET",  # row 17
    "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR",  # row 18
    "EIFTBRSPAMHHEWENATAMATEGYEERLBT",  # row 19
    "EEFOASFIOTUETUAEOTOARMAEERTNRTI",  # row 20
    "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB",  # row 21
    "AECTDDHILCEIHSITEGOEAOSDDRYDLOR",  # row 22
    "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE",  # row 23
    "ECDMRIPFEIMEHNLSSTTRTVDOHW?OBKR",  # row 24  K4 starts col 27 (? at col 26)
    "UOXOGHULBSOLIFBBWFLRVQQPRNGKSSO",  # row 25
    "TWTQSJQSSEKZZWATJKLUDIAWINFBNYP",  # row 26
    "VTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR",  # row 27  K4 ends
]

# KA Vigenère Tableau (28 rows × 31 cols)
# Row structure: key_letter (col 0) + 30 body chars
# We store the FULL 31-char row as it physically appears
KA_TABLEAU_ROWS = [
    "AABCDEFGHIJLMNQUVWXZKRYPTOSABCD",  # row 0, key=A
    "BBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",  # row 1, key=B
    "CCDEFGHIJLMNQUVWXZKRYPTOSABCDEF",  # row 2, key=C
    "DDEFGHIJLMNQUVWXZKRYPTOSABCDEFG",  # row 3, key=D
    "EEFGHIJLMNQUVWXZKRYPTOSABCDEFGH",  # row 4, key=E
    "FFGHIJLMNQUVWXZKRYPTOSABCDEFGHI",  # row 5, key=F
    "GGHIJLMNQUVWXZKRYPTOSABCDEFGHIJ",  # row 6, key=G
    "HHIJLMNQUVWXZKRYPTOSABCDEFGHIJL",  # row 7, key=H
    "IIJLMNQUVWXZKRYPTOSABCDEFGHIJLM",  # row 8, key=I
    "JJLMNQUVWXZKRYPTOSABCDEFGHIJLMN",  # row 9, key=J
    "KKRYPTOSABCDEFGHIJLMNQUVWXZKRYP",  # row 10, key=K
    "LLMNQUVWXZKRYPTOSABCDEFGHIJLMNQ",  # row 11, key=L
    "MMNQUVWXZKRYPTOSABCDEFGHIJLMNQU",  # row 12, key=M
    "NNQUVWXZKRYPTOSABCDEFGHIJLMNQUV",  # row 13, key=N  (extra L anomaly in body)
    "OOSABCDEFGHIJLMNQUVWXZKRYPTOSAB",  # row 14, key=O
    "PPTOSABCDEFGHIJLMNQUVWXZKRYPTOS",  # row 15, key=P
    "QQUVWXZKRYPTOSABCDEFGHIJLMNQUVW",  # row 16, key=Q
    "RRYPTOSABCDEFGHIJLMNQUVWXZKRYPT",  # row 17, key=R
    "SSABCDEFGHIJLMNQUVWXZKRYPTOSABC",  # row 18, key=S
    "TTOSABCDEFGHIJLMNQUVWXZKRYPTOSA",  # row 19, key=T
    "UUVWXZKRYPTOSABCDEFGHIJLMNQUVWX",  # row 20, key=U
    "VVWXZKRYPTOSABCDEFGHIJLMNQUVWXZ",  # row 21, key=V
    "WWXZKRYPTOSABCDEFGHIJLMNQUVWXZK",  # row 22, key=W  (extra T anomaly in body)
    "XXZKRYPTOSABCDEFGHIJLMNQUVWXZKR",  # row 23, key=X
    "YYPTOSABCDEFGHIJLMNQUVWXZKRYPTO",  # row 24, key=Y
    "ZZKRYPTOSABCDEFGHIJLMNQUVWXZKRY",  # row 25, key=Z
    # Rows 26-27: tableau only has 26 key rows (A-Z), so the cipher grid rows 26-27
    # physically sit BELOW the tableau. We treat them as repeating the tableau cycle.
    # Row 26 (key=A again), Row 27 (key=B again)
    "AABCDEFGHIJLMNQUVWXZKRYPTOSABCD",  # row 26 (tableau wraps: key=A again)
    "BBCDEFGHIJLMNQUVWXZKRYPTOSABCDE",  # row 27 (tableau wraps: key=B again)
]

# Section boundaries in the flat cipher grid (0-indexed positions after removing ?s)
# K1: rows 0-2 partial + row 3 partial = positions 0..62 (63 chars)
# K2: rest of row 3 through row 13 = positions 63..431 (369 chars)
# K3: rows 14-23 partial + row 24 partial = positions 432..767 (336 chars)
# K4: end of row 24 through row 27 = positions 768..864 (97 chars)
# ? marks: row 3 col 7, row 7 col 9, row 24 col 26 = 3 positional ? chars

# ── Build flat arrays, tracking grid position and section ─────────────────────

def build_grid():
    """Build list of (row, col, cipher_char, tableau_char, section, flat_pos) tuples.

    Skips ? characters (they are not letter positions).
    Returns:
        cells: list of dicts
        grid_cipher: 2D array [row][col]
        grid_tableau: 2D array [row][col]
    """
    cells = []
    flat_pos = 0

    for r, (crow, trow) in enumerate(zip(CIPHER_ROWS, KA_TABLEAU_ROWS)):
        assert len(crow) == 31, f"Row {r} cipher has {len(crow)} chars, expected 31"
        assert len(trow) == 31, f"Row {r} tableau has {len(trow)} chars, expected 31"

        for c in range(31):
            cc = crow[c]
            tc = trow[c]

            # Determine section
            if flat_pos < 63:
                section = "K1"
            elif flat_pos < 432:
                section = "K2"
            elif flat_pos < 768:
                section = "K3"
            else:
                section = "K4"

            if cc == '?':
                # Positional ? — skip for letter count, but track position
                cells.append({
                    'row': r, 'col': c,
                    'cipher': '?', 'tableau': tc,
                    'section': section,
                    'flat_pos': None,  # not a letter position
                    'is_match': False,
                    'is_question': True,
                })
            else:
                is_match = (cc == tc)
                cells.append({
                    'row': r, 'col': c,
                    'cipher': cc, 'tableau': tc,
                    'section': section,
                    'flat_pos': flat_pos,
                    'is_match': is_match,
                    'is_question': False,
                })
                flat_pos += 1

    return cells, flat_pos


def print_header(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


def main():
    print("CIPHER-TABLEAU MATCH ANALYSIS — 28×31 Kryptos Grid")
    print("="*70)

    cells, total_letters = build_grid()

    # Filter to letter cells only
    letter_cells = [c for c in cells if not c['is_question']]
    match_cells = [c for c in letter_cells if c['is_match']]
    nonmatch_cells = [c for c in letter_cells if not c['is_match']]
    question_cells = [c for c in cells if c['is_question']]

    print(f"\nTotal grid cells: 28×31 = 868")
    print(f"Positional ? characters: {len(question_cells)}")
    print(f"Letter cells: {total_letters}")
    print(f"Expected: 868 - 3 = 865 letters")
    print(f"Confirmed: {total_letters} == 865? {total_letters == 865}")

    # ── APPROACH A: Statistical Test ──────────────────────────────────────────
    print_header("A. STATISTICAL TEST — Is 39/868 matches significant?")

    n_cells = total_letters
    n_matches = len(match_cells)
    expected = n_cells / 26.0

    # Under null hypothesis (uniform random cipher assignment):
    # Each cell matches with probability 1/26
    # Expected matches = n_cells/26
    # Std dev = sqrt(n * p * (1-p))
    p = 1.0 / 26.0
    expected_mean = n_cells * p
    expected_std = math.sqrt(n_cells * p * (1 - p))
    z_score = (n_matches - expected_mean) / expected_std

    print(f"\nTotal letter cells: {n_cells}")
    print(f"Observed matches: {n_matches}")
    print(f"Expected under random (n/26): {expected_mean:.2f}")
    print(f"Std dev: {expected_std:.2f}")
    print(f"Z-score: {z_score:.3f}")
    print(f"Interpretation: ", end="")
    if abs(z_score) < 1.0:
        print("NOT significant (|z| < 1.0) — consistent with random")
    elif abs(z_score) < 1.96:
        print(f"Marginal (1.0 < |z| < 1.96, p ~ {2*(1-0.84):.2f})")
    elif abs(z_score) < 2.576:
        print(f"Significant at p<0.05 (|z|={abs(z_score):.2f})")
    else:
        print(f"HIGHLY significant at p<0.01 (|z|={abs(z_score):.2f})")

    # ── APPROACH B: Spatial Pattern ───────────────────────────────────────────
    print_header("B. SPATIAL PATTERN — Row and column distribution")

    # Build match grid
    match_grid = [[' '] * 31 for _ in range(28)]
    for c in letter_cells:
        r, col = c['row'], c['col']
        if c['is_match']:
            match_grid[r][col] = 'X'
        else:
            match_grid[r][col] = '.'
    for c in question_cells:
        match_grid[c['row']][c['col']] = '?'

    print("\nMatch map (X=match, .=no match, ?=question mark):")
    print("     " + "".join(str(i % 10) for i in range(31)))
    for r in range(28):
        row_matches = sum(1 for col in range(31) if match_grid[r][col] == 'X')
        section = "K1" if r < 3 else ("K2" if r < 14 else ("K3" if r < 25 else "K4"))
        print(f"r{r:02d}: {''.join(match_grid[r])}  [{row_matches:2d} matches] {section}")

    # Row distribution statistics
    print("\nRow match counts:")
    row_counts = []
    for r in range(28):
        rc = sum(1 for c in match_cells if c['row'] == r)
        row_counts.append(rc)
        print(f"  Row {r:2d}: {rc} matches", end="")
        if rc >= 3:
            cols = sorted(c['col'] for c in match_cells if c['row'] == r)
            print(f"  [cols {cols}]", end="")
        print()

    # Column distribution
    print("\nColumn match counts (col 0-30):")
    col_counts = []
    for col in range(31):
        cc = sum(1 for c in match_cells if c['col'] == col)
        col_counts.append(cc)
    print("  " + " ".join(f"{c:2d}" for c in col_counts))
    print("  Cols: " + " ".join(f"{i:2d}" for i in range(31)))

    # Chi-squared test for uniform row distribution
    expected_per_row = n_matches / 28.0
    chi2_row = sum((r - expected_per_row)**2 / expected_per_row for r in row_counts)
    print(f"\nChi-squared (rows, df=27): {chi2_row:.3f}")
    print(f"  Expected per row: {expected_per_row:.2f}")
    print(f"  Note: chi2 > 40.1 → p < 0.05; chi2 > 46.9 → p < 0.01")

    # ── APPROACH C: Section Distribution ──────────────────────────────────────
    print_header("C. SECTION DISTRIBUTION — K1/K2/K3/K4")

    section_lens = {"K1": 63, "K2": 369, "K3": 336, "K4": 97}
    section_counts = Counter(c['section'] for c in match_cells)

    print(f"\n{'Section':<8} {'Length':>8} {'Matches':>8} {'Expected':>10} {'Obs/Exp':>8} {'Z-score':>8}")
    print("-" * 60)
    for sec, length in section_lens.items():
        obs = section_counts.get(sec, 0)
        exp = length / 26.0
        std = math.sqrt(length * (1/26) * (25/26))
        z = (obs - exp) / std if std > 0 else 0
        print(f"{sec:<8} {length:>8} {obs:>8} {exp:>10.2f} {obs/exp:>8.3f} {z:>8.3f}")

    # ── APPROACH D: Non-match Constraint Analysis ─────────────────────────────
    print_header("D. NON-MATCH CONSTRAINTS — 829 cells where cipher≠tableau")

    print(f"\nNon-match cells: {len(nonmatch_cells)}")
    print("At non-match positions:")
    print("  - If HOLE: output = tableau char")
    print("  - If SOLID: output = cipher char")
    print("  → Each non-match cell is a 1-bit constraint on the grille mask")
    print(f"\nMatch cells: {n_matches}")
    print("At match positions:")
    print("  - If HOLE or SOLID: output = same char")
    print("  → Match cells are FREE VARIABLES in grille design")
    print(f"\nEffective degrees of freedom in grille = {n_matches} (match cells)")
    print(f"Constrained cells = {len(nonmatch_cells)}")

    # What fraction of K4 cells are free?
    k4_cells = [c for c in letter_cells if c['section'] == 'K4']
    k4_matches = [c for c in k4_cells if c['is_match']]
    k4_nonmatches = [c for c in k4_cells if not c['is_match']]

    print(f"\nK4-specific free/constrained:")
    print(f"  K4 letter cells: {len(k4_cells)}")
    print(f"  K4 match (free): {len(k4_matches)}")
    print(f"  K4 non-match (constrained): {len(k4_nonmatches)}")

    # ── APPROACH E: K4 Matches ────────────────────────────────────────────────
    print_header("E. K4 MATCHES — Details of each matching position")

    print(f"\nK4 carved text: OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR")
    print(f"\nK4 positions with cipher==tableau (flat pos 0-96 within K4):")
    print(f"{'K4pos':>6} {'Grid(r,c)':>10} {'Cipher':>8} {'Tableau':>8} {'Section':>8}")
    print("-" * 50)

    k4_match_positions = []
    for c in k4_cells:
        k4_local_pos = c['flat_pos'] - 768  # 0-indexed within K4
        if c['is_match']:
            k4_match_positions.append(k4_local_pos)
            print(f"{k4_local_pos:>6} ({c['row']:2d},{c['col']:2d})     {c['cipher']:>8} {c['tableau']:>8}")

    print(f"\nTotal K4 matches: {len(k4_match_positions)}")
    print(f"K4 match positions (0-indexed in K4): {sorted(k4_match_positions)}")

    # Check if any crib positions are matches
    CRIB_POSITIONS_ENE = list(range(21, 34))   # EASTNORTHEAST
    CRIB_POSITIONS_BC  = list(range(63, 74))   # BERLINCLOCK
    crib_matches = [p for p in k4_match_positions if p in CRIB_POSITIONS_ENE + CRIB_POSITIONS_BC]
    print(f"\nCrib positions that are matches: {crib_matches}")
    if crib_matches:
        print("  → These crib positions can be HOLE or SOLID without changing cipher char")
        print("  → They don't distinguish between grille orientations at those positions")

    # Show match letter frequencies in K4
    k4_match_letters = [c['cipher'] for c in k4_cells if c['is_match']]
    print(f"\nK4 match letters: {''.join(sorted(k4_match_letters))}")
    print(f"Letter distribution: {dict(Counter(k4_match_letters))}")

    # ── APPROACH F: 180° Rotation Symmetry ───────────────────────────────────
    print_header("F. 180° ROTATION SYMMETRY — Do matches pair under (r,c)→(27-r,30-c)?")

    # Build lookup: (r,c) → match status
    match_lookup = {}
    for c in letter_cells:
        match_lookup[(c['row'], c['col'])] = c['is_match']

    symmetric_pairs = 0
    antisymmetric_pairs = 0
    both_match = 0
    neither_match = 0
    one_match = 0

    visited = set()
    for c in letter_cells:
        r, col = c['row'], c['col']
        rp = 27 - r
        cp = 30 - col

        if (rp, cp) in visited or (r, col) in visited:
            continue

        # Handle center (14, 15) if grid were odd — 28×31 has no exact center cell
        # for a pair, so all cells have distinct 180° partners
        visited.add((r, col))
        visited.add((rp, cp))

        m1 = match_lookup.get((r, col), False)
        m2 = match_lookup.get((rp, cp), False)

        if (rp, cp) == (r, col):
            # Self-paired (impossible in 28×31)
            continue

        if m1 and m2:
            both_match += 1
            symmetric_pairs += 1
        elif not m1 and not m2:
            neither_match += 1
        else:
            one_match += 1
            antisymmetric_pairs += 1

    print(f"\n180° rotation analysis (pairing (r,c) with (27-r,30-c)):")
    print(f"  Both positions match: {both_match} pairs")
    print(f"  Neither position matches: {neither_match} pairs")
    print(f"  Exactly one matches: {one_match} pairs")

    # Under random, P(both match) = (1/26)^2, P(one matches) = 2*(1/26)*(25/26)
    total_pairs = both_match + neither_match + one_match
    expected_both = total_pairs * (1/26)**2
    expected_one = total_pairs * 2 * (1/26) * (25/26)
    print(f"\n  Expected both match (random): {expected_both:.2f}")
    print(f"  Expected one match (random): {expected_one:.2f}")
    print(f"  Observed both: {both_match}")
    print(f"  Observed one: {one_match}")

    # Z-test for "both match" count
    std_both = math.sqrt(total_pairs * (1/26)**2 * (1 - (1/26)**2))
    z_both = (both_match - expected_both) / std_both if std_both > 0 else 0
    print(f"  Z-score for 'both match' excess: {z_both:.3f}")

    # ── APPROACH G: Row/Column Clustering ─────────────────────────────────────
    print_header("G. ROW/COLUMN CLUSTERING — Chi-squared test")

    # Expected matches per row (letters per row varies due to ? placements)
    letters_per_row = []
    for r in range(28):
        lpr = sum(1 for c in letter_cells if c['row'] == r)
        letters_per_row.append(lpr)

    print("\nRow: letters | matches | expected | chi2-contribution")
    chi2_row2 = 0.0
    for r in range(28):
        lpr = letters_per_row[r]
        exp = lpr / 26.0
        obs = row_counts[r]
        contrib = (obs - exp)**2 / exp if exp > 0 else 0
        chi2_row2 += contrib
        print(f"  Row {r:2d}: {lpr:2d} letters | {obs} matches | {exp:.2f} expected | {contrib:.3f}")

    print(f"\nChi-squared total (rows): {chi2_row2:.3f}")

    # ── APPROACH H: K3 Verification ───────────────────────────────────────────
    print_header("H. K3 VERIFICATION — Known PT/CT match analysis")

    # K3 carved text (rows 14-23 full + row 24 partial, 336 chars)
    K3_CARVED = (
        "ENDYAHROHNLSRHEOCPTEOIBIDYSHNAI"  # row 14
        "ACHTNREYULDSLLSLLNOHSNOSMRWXMNE"  # row 15
        "TPRNGATIHNRARPESLNNELEBLPIIACAE"  # row 16 (30 chars!)
        "WMTWNDITEENRAHCTENEUDRETNHAEOET"  # row 17
        "FOLSEDTIWENHAEIOYTEYQHEENCTAYCR"  # row 18
        "EIFTBRSPAMHHEWENATAMATEGYEERLBT"  # row 19
        "EEFOASFIOTUETUAEOTOARMAEERTNRTI"  # row 20
        "BSEDDNIAAHTTMSTEWPIEROAGRIEWFEB"  # row 21
        "AECTDDHILCEIHSITEGOEAOSDDRYDLOR"  # row 22
        "ITRKLMLEHAGTDHARDPNEOHMGFMFEUHE"  # row 23
        "ECDMRIPFEIMEHNLSSTTRTVDOHW"       # row 24 cols 0-26 (before ?)
    )

    K3_PT = (
        "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHAT"
        "ENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITH"
        "TREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFTHAND"
        "CORNERANDTHENWIDDENINGTHEHOLEALITTLEIINSERTEDTHE"
        "CANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSED"
        "THEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIN"
        "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
    )

    # K3 is 336 chars but the above may have counting issues, let's just use what we know
    # K3 flat positions are 432..767
    k3_cells = [c for c in letter_cells if c['section'] == 'K3']
    k3_matches = [c for c in k3_cells if c['is_match']]

    print(f"\nK3 cells: {len(k3_cells)}")
    print(f"K3 matches: {len(k3_matches)}")
    print(f"Expected K3 matches (random): {len(k3_cells)/26:.2f}")

    # For K3 matches: at these positions, grille hole assignment is ambiguous
    # But K3 PT is KNOWN — so we can check: what does the tableau say at K3 match positions?
    print(f"\nK3 match positions (tableau letter = cipher letter):")
    for c in k3_matches[:20]:  # show first 20
        k3_local = c['flat_pos'] - 432
        k3_pt_char = K3_PT[k3_local] if k3_local < len(K3_PT) else '?'
        print(f"  flat={c['flat_pos']:3d} (K3 pos {k3_local:3d}): "
              f"cipher={c['cipher']} tableau={c['tableau']} "
              f"PT={k3_pt_char} "
              f"match_PT_CT={'YES' if k3_pt_char == c['cipher'] else 'NO'}")

    # ── APPROACH I: Letter Analysis at Match Positions ────────────────────────
    print_header("I. LETTER ANALYSIS — Which letters appear at match positions?")

    match_letters = Counter(c['cipher'] for c in match_cells)
    total_letters_dist = Counter(c['cipher'] for c in letter_cells if c['cipher'] != '?')

    print(f"\nLetter frequencies in cipher grid vs at match positions:")
    print(f"{'Letter':<8} {'Total':>6} {'Matches':>8} {'Match%':>8} {'Expected%':>10}")
    print("-" * 50)
    for letter in sorted(match_letters.keys()):
        tot = total_letters_dist.get(letter, 0)
        obs = match_letters.get(letter, 0)
        exp_pct = 100.0 / 26.0
        obs_pct = 100.0 * obs / tot if tot > 0 else 0
        print(f"{letter:<8} {tot:>6} {obs:>8} {obs_pct:>8.1f}% {exp_pct:>9.1f}%")

    # Letters with ZERO matches
    zero_match = [l for l in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if match_letters.get(l, 0) == 0]
    print(f"\nLetters with ZERO matches (cipher==tableau never occurs): {zero_match}")
    print(f"  → These letters have FULLY CONSTRAINED grille assignment at their positions")

    # ── SUMMARY ───────────────────────────────────────────────────────────────
    print_header("SUMMARY")

    print(f"""
KEY FINDINGS:
─────────────────────────────────────────────────────────────────────
Total grid:       868 cells (28×31)
Letter cells:     {total_letters} (865 after removing 3 positional ?s)
Matches (cipher==tableau): {n_matches}
Expected (random):         {expected_mean:.1f}
Z-score:                   {z_score:.3f}

Section breakdown:
  K1 ({section_lens['K1']} chars): {section_counts.get('K1',0)} matches (exp {section_lens['K1']/26:.1f})
  K2 ({section_lens['K2']} chars): {section_counts.get('K2',0)} matches (exp {section_lens['K2']/26:.1f})
  K3 ({section_lens['K3']} chars): {section_counts.get('K3',0)} matches (exp {section_lens['K3']/26:.1f})
  K4 ({section_lens['K4']} chars):  {section_counts.get('K4',0)} matches (exp {section_lens['K4']/26:.1f})

K4 free positions (match positions where grille assignment is ambiguous): {len(k4_matches)}
K4 constrained positions: {len(k4_nonmatches)}

180° rotation pairs:
  Both match:    {both_match} (exp {expected_both:.2f})
  One match:     {one_match} (exp {expected_one:.2f})
  Neither match: {neither_match}

Letters with zero matches: {zero_match}
─────────────────────────────────────────────────────────────────────
""")

    # ── DIAGNOSTIC: Print all match cells ────────────────────────────────────
    print_header("DIAGNOSTIC: All match cells")
    print(f"\n{'flat_pos':>8} {'K4-pos':>8} {'row':>5} {'col':>5} {'letter':>7} {'section':>8}")
    print("-" * 55)
    for c in match_cells:
        k4pos = (c['flat_pos'] - 768) if c['section'] == 'K4' else '-'
        print(f"{c['flat_pos']:>8} {str(k4pos):>8} {c['row']:>5} {c['col']:>5} {c['cipher']:>7} {c['section']:>8}")

    print(f"\nTotal matches: {len(match_cells)}")

    return {
        'n_matches': n_matches,
        'expected_mean': expected_mean,
        'z_score': z_score,
        'section_counts': dict(section_counts),
        'k4_matches': len(k4_matches),
        'k4_match_positions': sorted(k4_match_positions),
        'both_match_180': both_match,
        'zero_match_letters': zero_match,
    }


if __name__ == "__main__":
    results = main()
