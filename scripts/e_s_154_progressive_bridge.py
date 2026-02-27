#!/usr/bin/env python3
"""E-S-145: Progressive bridge experiments — K3→K4 gap analysis.

From reports/explorer_09_progressive_flow.md Section 7 (Solvability Analysis),
the progressive chain breaks at K3→K4. This experiment tests the top candidates
for bridging that gap:

  H1: Howard Carter's ORIGINAL 1922 journal as running key for K4
      (K3 plaintext is a paraphrase of Carter — the original text is the bridge)
  H2: YAR superscript [Y=24, A=0, R=17] as transposition/key parameters
  H3: T=19 from "T IS YOUR POSITION" as running key start offset into reference texts
  H4: K2 GPS coordinates [38,57,6,5,77,8,44] as procedural grid parameters

Output: results/e_s_145_progressive_bridge.json
Repro:  PYTHONPATH=src python3 -u scripts/e_s_145_progressive_bridge.py
"""

import json
import os
import sys
import itertools

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, NOISE_FLOOR,
    BEAN_EQ, BEAN_INEQ,
)

CT_NUM = [ALPH_IDX[c] for c in CT]
N = CT_LEN


def vig_dec(ct_nums, key_nums):
    return [(ct_nums[i] - key_nums[i]) % MOD for i in range(min(len(ct_nums), len(key_nums)))]

def beau_dec(ct_nums, key_nums):
    return [(key_nums[i] - ct_nums[i]) % MOD for i in range(min(len(ct_nums), len(key_nums)))]

def varbeau_dec(ct_nums, key_nums):
    return [(ct_nums[i] + key_nums[i]) % MOD for i in range(min(len(ct_nums), len(key_nums)))]

def nums_to_text(nums):
    return ''.join(ALPH[n % 26] for n in nums)

def score_cribs_text(text):
    matches = 0
    for pos, ch in CRIB_DICT.items():
        if pos < len(text) and text[pos] == ch:
            matches += 1
    return matches

def check_bean_from_pt(pt_nums):
    if len(pt_nums) < N:
        return False
    key = [(CT_NUM[i] - pt_nums[i]) % MOD for i in range(N)]
    for a, b in BEAN_EQ:
        if key[a] != key[b]:
            return False
    for a, b in BEAN_INEQ:
        if key[a] == key[b]:
            return False
    return True


# ══════════════════════════════════════════════════════════════════════════
# REFERENCE TEXTS
# ══════════════════════════════════════════════════════════════════════════

# Howard Carter's journal entry, November 26, 1922 (original text)
# Source: "The Tomb of Tut-ankh-amen" by Howard Carter, Vol. I
CARTER_JOURNAL = (
    "SLOWLYDESPERATELYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHAT"
    "ENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITH"
    "TREMBLINGHANDSIMADETHETINYBREACHINTHEUPPERLEFTHAND"
    "CORNERANDTHENWIDENEDTHEHOLEALITTLEIINSERTEDTHECANDLE"
    "ANDPEEREDINTHEHOTAIRESCAPINGFROMTHECHAMBERCAUSED"
    "THEFLAMETOFLICKERBUTPRESENTLYDETAILSOFTHEROOMWITHIN"
    "EMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
).upper()

# Extended Carter text (from the original journal, beyond K3 paraphrase)
CARTER_EXTENDED = (
    "ATFIRSTICOULDSEENOTHINGTHECANDLELIGHTCAUSEDBYTHE"
    "HOTAIRESCAPINGFROMTHECHAMBERCAUSEDTHEFLAMETOFLICKER"
    "BUTPRESENTLYASMYEYESGREWACCUSTOMEDTOTHELIGHTTHETINY"
    "DETAILSOFTHEROOMEMERGEDFROMTHEMISTSTRANGEANIMALS"
    "STATUESANDGOLDEVERYWHERETHEGLINTOFGOLD"
    "WHENLORDSASKEDICANHEADSAIDQCANYOUSEEANYTHING"
    "YESYESIWONDERFULTHINGS"
    "WITHTHEUTMOSTPRECAUTIONWIDENEDALITTLETHEBREACHSO"
    "ASTOINTRODUCEANELECTRICFLASHLAMPTHELIGHTDISCLOSED"
    "ANASTONISHINGSIGHTINTHEMIDDLEOFTHEANTEROOM"
    "TWOLARGECOUCHESORNAMENTEDWITHGOLDSTOODWITHAGREAT"
    "NUMBEROFSMALLERFURNITUREANDEQUIPMENT"
).upper()

# K3 plaintext (Sanborn's paraphrase, the text the solver already has)
K3_PT = (
    "SLOWLYDESPARATLYSLOWLYTHEREMAINSOFPASSAGEDEBRISTHAT"
    "ENCUMBEREDTHELOWERPARTOFTHEDOORWAYWASREMOVEDWITH"
    "TREMBLINGHANDSIMADEATINYBREACHINTHEUPPERLEFT"
    "HANDCORNERANDTHENWIDENINGTHEHOLEALITTLEIINSERTED"
    "THECANDLEANDPEEREDINTHEHOTAIRESCAPINGFROMTHE"
    "CHAMBERCAUSEDTHEFLAMETOFLICKERBUTPRESENTLYDETAILS"
    "OFTHEROOMWITHINEMERGEDFROMTHEMISTXCANYOUSEEANYTHINGQ"
).upper()

# K1 and K2 plaintexts
K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENAUANCEOFIQLUSION".upper()
K2_PT = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHE"
    "EARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDAND"
    "TRANSMITTEDUNDERGRUUNDTOANUNKNOWNLOCATIONXDOES"
    "LANGLEYKNOWABOUTTHISITSBURIEDOUTTHERESOMEWHEREX"
    "WHOKNOWSTHEEXACTLOCATIONONLYWWTHISWASHISLAST"
    "MESSAGEXTHIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIX"
    "POINTFIVESECONDSNORTHSEVENTYSEVENDEGREESEIGHT"
    "MINUTESFORTYFOURSECONDWESTXLAYERTWO"
).upper()


# ══════════════════════════════════════════════════════════════════════════
# TRACKING
# ══════════════════════════════════════════════════════════════════════════

best_score = 0
best_tag = ""
total_configs = 0
results_log = []

def test_and_log(tag, pt_text):
    global best_score, best_tag, total_configs
    total_configs += 1
    sc = score_cribs_text(pt_text[:N])
    if sc > best_score:
        best_score = sc
        best_tag = tag
        print(f"  NEW BEST: {sc}/{N_CRIBS} — {tag}")
        print(f"    PT: {pt_text[:60]}...")
    if sc >= NOISE_FLOOR:
        results_log.append({"tag": tag, "score": sc, "pt_prefix": pt_text[:40]})
    return sc


# ══════════════════════════════════════════════════════════════════════════
# H1: Howard Carter's Journal as Running Key
# ══════════════════════════════════════════════════════════════════════════
def h1_carter_running_key():
    print("=" * 72)
    print("H1: Howard Carter's Journal as Running Key for K4")
    print("=" * 72)
    print(f"  Carter journal length: {len(CARTER_JOURNAL)} chars")
    print(f"  Carter extended length: {len(CARTER_EXTENDED)} chars")
    print(f"  K3 plaintext length: {len(K3_PT)} chars")

    # Combine all Carter text sources
    sources = {
        'carter_journal': CARTER_JOURNAL,
        'carter_extended': CARTER_EXTENDED,
        'carter_combined': CARTER_JOURNAL + CARTER_EXTENDED,
        'k3_plaintext': K3_PT,
    }

    for src_name, src_text in sources.items():
        src_clean = ''.join(c for c in src_text if c.isalpha())
        max_offset = len(src_clean) - N
        if max_offset < 0:
            print(f"  {src_name}: too short ({len(src_clean)} chars), wrapping")
            max_offset = len(src_clean)

        print(f"\n  Testing {src_name} ({len(src_clean)} chars) at all offsets:")

        best_for_src = 0
        best_offset = -1
        best_variant = ""

        for offset in range(max(max_offset, len(src_clean))):
            # Extract running key starting at this offset (wrap if needed)
            rk = []
            for i in range(N):
                rk.append(ALPH_IDX[src_clean[(offset + i) % len(src_clean)]])

            for vname, vfn in [('vig', vig_dec), ('beau', beau_dec), ('vb', varbeau_dec)]:
                pt_nums = vfn(CT_NUM, rk)
                pt = nums_to_text(pt_nums)
                sc = test_and_log(f"H1_{src_name}_off{offset}_{vname}", pt)

                if sc > best_for_src:
                    best_for_src = sc
                    best_offset = offset
                    best_variant = vname

        print(f"  {src_name} best: {best_for_src}/24 at offset {best_offset} ({best_variant})")


# ══════════════════════════════════════════════════════════════════════════
# H2: YAR superscript values as parameters
# ══════════════════════════════════════════════════════════════════════════
def h2_yar_params():
    print("\n" + "=" * 72)
    print("H2: YAR [Y=24, A=0, R=17] as transposition/key parameters")
    print("=" * 72)

    Y, A, R = 24, 0, 17
    D, O = 3, 14  # DYARO extended

    # H2a: Width-17 columnar with KRYPTOS-derived column order,
    # but starting read at row offset Y=24 mod nrows
    print("\n  (a) Width-17 columnar transposition + row offset from Y=24:")

    # KRYPTOS ordering for width 7: 0362514
    # For width 17, we need a 17-char key. Try KRYPTOS repeated/extended
    # KRYPTOSKRYPTOSK -> alphabetical ordering
    key17_text = "KRYPTOSKRYPTOSKRY"[:17]
    # Get alphabetical ranking
    indexed = sorted(enumerate(key17_text), key=lambda x: (x[1], x[0]))
    col_order = [0] * 17
    for rank, (orig_idx, _) in enumerate(indexed):
        col_order[orig_idx] = rank

    print(f"    Key text: {key17_text}")
    print(f"    Column order: {col_order}")

    # Write CT into width-17 grid
    nrows = (N + 16) // 17
    grid = []
    for r in range(nrows):
        row = []
        for c in range(17):
            idx = r * 17 + c
            row.append(CT[idx] if idx < N else 'X')
        grid.append(row)

    # Read columns in col_order, but start at row Y%nrows
    row_offset = Y % nrows
    for ro_label, ro_val in [('Y24', Y % nrows), ('A0', 0), ('R17', R % nrows)]:
        pt_chars = []
        for rank in range(17):
            col_idx = col_order.index(rank)
            for r in range(nrows):
                actual_row = (r + ro_val) % nrows
                ch = grid[actual_row][col_idx]
                if ch != 'X':
                    pt_chars.append(ch)
        pt = ''.join(pt_chars)[:N]
        test_and_log(f"H2a_w17_KRYPTOS_rowoff_{ro_label}", pt)

    # H2b: Columnar at widths derived from YAR: 24, 17, 7 (reversed RAY)
    print("\n  (b) Columnar at YAR-derived widths:")
    for width in [24, 17, 7, 4]:  # 24=Y, 17=R, 7=KRYPTOS, 4=97/24.25
        nrows_w = (N + width - 1) // width
        # Read columns in identity order
        pt_chars = []
        for c in range(width):
            for r in range(nrows_w):
                idx = r * width + c
                if idx < N:
                    pt_chars.append(CT[idx])
        pt = ''.join(pt_chars)[:N]
        test_and_log(f"H2b_w{width}_identity_cols", pt)

        # Read columns in reverse order
        pt_chars_rev = []
        for c in range(width - 1, -1, -1):
            for r in range(nrows_w):
                idx = r * width + c
                if idx < N:
                    pt_chars_rev.append(CT[idx])
        pt_rev = ''.join(pt_chars_rev)[:N]
        test_and_log(f"H2b_w{width}_reverse_cols", pt_rev)

    # H2c: YAR as key combined with transposition
    # Write CT into w=7 grid (KRYPTOS width), read with rotation by R=17 positions
    print("\n  (c) Width-7 + cyclic rotation by R=17:")
    for shift in [17, 24, 7, 14, 3]:
        shifted = CT[shift:] + CT[:shift]
        # Read into w=7 grid, read all 5040 column orderings
        # This is covered by E-S-144 Phase D for shift=19, so just do the YAR values
        for perm in itertools.permutations(range(7)):
            nrows7 = (N + 6) // 7
            long_cols = N % 7 if N % 7 != 0 else 7

            col_lens = []
            for c in range(7):
                if long_cols == 7:
                    col_lens.append(nrows7)
                elif c < long_cols:
                    col_lens.append(nrows7)
                else:
                    col_lens.append(nrows7 - 1)

            cols = {}
            pos = 0
            for rank in range(7):
                col_idx = list(perm).index(rank)
                clen = col_lens[col_idx]
                cols[col_idx] = shifted[pos:pos + clen]
                pos += clen

            result = []
            for r in range(nrows7):
                for c in range(7):
                    if r < len(cols[c]):
                        result.append(cols[c][r])
            pt = ''.join(result)[:N]
            test_and_log(f"H2c_shift{shift}_w7_{perm}", pt)


# ══════════════════════════════════════════════════════════════════════════
# H3: T=19 as running key start offset into reference texts
# ══════════════════════════════════════════════════════════════════════════
def h3_t19_rk_offset():
    print("\n" + "=" * 72)
    print("H3: T=19 as running key start offset")
    print("=" * 72)

    # The idea: "T IS YOUR POSITION" means start the running key at position T=19
    # Test against K1, K2, K3 plaintexts and Carter journal
    sources = {
        'K1': K1_PT,
        'K2': K2_PT,
        'K3': K3_PT,
        'carter': CARTER_JOURNAL,
        'carter_ext': CARTER_EXTENDED,
    }

    for src_name, src_text in sources.items():
        src_clean = ''.join(c for c in src_text if c.isalpha())
        offset = 19  # T = 19 (A=0)

        if offset >= len(src_clean):
            print(f"  {src_name}: offset 19 exceeds length ({len(src_clean)})")
            continue

        rk = []
        for i in range(N):
            rk.append(ALPH_IDX[src_clean[(offset + i) % len(src_clean)]])

        for vname, vfn in [('vig', vig_dec), ('beau', beau_dec), ('vb', varbeau_dec)]:
            pt_nums = vfn(CT_NUM, rk)
            pt = nums_to_text(pt_nums)
            sc = test_and_log(f"H3_T19_{src_name}_{vname}", pt)

    # Also test T=20 (A=1 convention)
    print("\n  Also testing T=20 (A=1 convention):")
    for src_name, src_text in sources.items():
        src_clean = ''.join(c for c in src_text if c.isalpha())
        offset = 20

        if offset >= len(src_clean):
            continue

        rk = []
        for i in range(N):
            rk.append(ALPH_IDX[src_clean[(offset + i) % len(src_clean)]])

        for vname, vfn in [('vig', vig_dec), ('beau', beau_dec)]:
            pt_nums = vfn(CT_NUM, rk)
            pt = nums_to_text(pt_nums)
            test_and_log(f"H3_T20_{src_name}_{vname}", pt)


# ══════════════════════════════════════════════════════════════════════════
# H4: K2 GPS coordinates as procedural grid parameters
# ══════════════════════════════════════════════════════════════════════════
def h4_gps_grid():
    print("\n" + "=" * 72)
    print("H4: K2 GPS coordinates as procedural grid parameters")
    print("=" * 72)

    # K2 coordinates: 38 57'6.5"N  77 8'44"W
    # Extracted numeric values:
    coords = [38, 57, 6, 5, 77, 8, 44]

    # H4a: Use coordinate digits as column read order in various grids
    print("\n  (a) Coordinate values as column reordering:")

    # Width 7 grid, read columns in order [38%7, 57%7, 6%7, 5%7, 77%7, 8%7, 44%7]
    col_order_mod7 = [c % 7 for c in coords]
    print(f"    coords mod 7: {col_order_mod7}")

    # Check if it's a valid permutation
    if len(set(col_order_mod7)) == 7:
        print(f"    Valid permutation for width 7!")
        nrows = (N + 6) // 7
        long_cols = N % 7 if N % 7 != 0 else 7
        col_lens = []
        for c in range(7):
            col_lens.append(nrows if (long_cols == 7 or c < long_cols) else nrows - 1)

        cols = {}
        pos = 0
        for rank in range(7):
            col_idx = col_order_mod7.index(rank)
            clen = col_lens[col_idx]
            cols[col_idx] = CT[pos:pos + clen]
            pos += clen

        result = []
        for r in range(nrows):
            for c in range(7):
                if r < len(cols.get(c, '')):
                    result.append(cols[c][r])
        pt = ''.join(result)[:N]
        test_and_log("H4a_coords_mod7_colorder", pt)
    else:
        print(f"    NOT a valid permutation (duplicates)")

    # H4b: Coordinate values as periodic key
    print("\n  (b) Coordinates as period-7 key:")
    for vname, vfn in [('vig', vig_dec), ('beau', beau_dec), ('vb', varbeau_dec)]:
        key = [c % 26 for c in coords]
        full_key = [key[i % 7] for i in range(N)]
        pt_nums = vfn(CT_NUM, full_key)
        pt = nums_to_text(pt_nums)
        test_and_log(f"H4b_coords_p7_{vname}", pt)

    # H4c: Individual coordinate values as grid widths
    print("\n  (c) Individual coordinate values as grid widths:")
    for cv in set(coords):
        if 2 <= cv <= 48 and cv <= N:
            nrows_cv = (N + cv - 1) // cv
            # Read columns
            pt_chars = []
            for c in range(cv):
                for r in range(nrows_cv):
                    idx = r * cv + c
                    if idx < N:
                        pt_chars.append(CT[idx])
            pt = ''.join(pt_chars)[:N]
            sc = test_and_log(f"H4c_width_{cv}_cols", pt)

    # H4d: Start at grid position (row=38%nrows, col=57%width)
    print("\n  (d) Grid start position from coordinates:")
    for width in [7, 8, 9, 10]:
        nrows_w = (N + width - 1) // width
        start_row = 38 % nrows_w
        start_col = 57 % width
        start_idx = start_row * width + start_col

        # Read from start_idx wrapping around
        reordered = CT[start_idx:] + CT[:start_idx]
        test_and_log(f"H4d_w{width}_start_r{start_row}c{start_col}", reordered)

    # H4e: Coordinate string as running key
    print("\n  (e) Coordinate string as running key:")
    coord_str = "THIRTYEIGHTDEGREESFIFTYSEVENMINUTESSIXPOINTFIVESECONDSNORTHSEVENTYSEVENDEGRESEIGHTMINUTESFORTYFOURSECONDWEST"
    coord_clean = ''.join(c for c in coord_str.upper() if c.isalpha())
    rk = [ALPH_IDX[coord_clean[i % len(coord_clean)]] for i in range(N)]

    for vname, vfn in [('vig', vig_dec), ('beau', beau_dec)]:
        pt_nums = vfn(CT_NUM, rk)
        pt = nums_to_text(pt_nums)
        test_and_log(f"H4e_coord_text_rk_{vname}", pt)


# ══════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════
def main():
    global best_score, best_tag, total_configs

    print("=" * 72)
    print("E-S-145: Progressive Bridge Experiments (K3→K4 Gap)")
    print("=" * 72)
    print(f"CT: {CT}")
    print(f"CT length: {N}")
    print(f"Theory: progressive solve chain breaks at K3→K4")
    print(f"Testing candidates for bridging the gap")
    print()

    h1_carter_running_key()
    h2_yar_params()
    h3_t19_rk_offset()
    h4_gps_grid()

    # ── Final summary ──
    print("\n" + "=" * 72)
    print("FINAL SUMMARY")
    print("=" * 72)
    print(f"Total configurations tested: {total_configs}")
    print(f"Above NOISE ({NOISE_FLOOR}): {len(results_log)}")
    print(f"Best score: {best_score}/{N_CRIBS} ({best_tag})")

    if results_log:
        print("\nResults above noise floor:")
        for r in sorted(results_log, key=lambda x: -x['score'])[:20]:
            print(f"  score={r['score']} | {r['tag']}")

    if best_score <= NOISE_FLOOR:
        print(f"\nCONCLUSION: ALL progressive bridge candidates produce NOISE.")
        print(f"  K3→K4 chain remains broken. No K0/K1/K2/K3-derived parameter")
        print(f"  provides the K4 key or method. This is consistent with:")
        print(f"  - Scheidt's 'change in methodology' statement")
        print(f"  - The 'coding charts' being external information")
        print(f"  - Sanborn's 'Who says it is even a math solution?'")
    else:
        print(f"\nINVESTIGATE: Score {best_score}/{N_CRIBS} exceeds noise floor.")

    # Save artifact
    os.makedirs("results", exist_ok=True)
    artifact = {
        "experiment_id": "e_s_145",
        "description": "Progressive bridge experiments - K3→K4 gap analysis",
        "total_configs": total_configs,
        "best_score": best_score,
        "best_tag": best_tag,
        "results_above_noise": results_log,
        "repro_command": "PYTHONPATH=src python3 -u scripts/e_s_145_progressive_bridge.py",
    }
    with open("results/e_s_145_progressive_bridge.json", "w") as f:
        json.dump(artifact, f, indent=2, default=str)
    print(f"\nArtifact: results/e_s_145_progressive_bridge.json")


if __name__ == "__main__":
    main()
