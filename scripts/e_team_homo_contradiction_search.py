#!/usr/bin/env python3
"""E-TEAM-HOMO-CONTRADICTION: Systematic search for transpositions that
resolve all homophonic substitution contradictions.

Under homophonic DECRYPTION (each CT letter → exactly one PT letter),
9 of the 14 CT letters at crib positions map to 2+ different PT letters.
A transposition applied BEFORE substitution changes which CT chars land
at crib positions, potentially resolving all contradictions.

We search structured transpositions (columnar, rail fence, serpentine,
spiral, keyword-based, block reverse) plus large random samples to find
ANY permutation that resolves all 9 contradictions.

This is fast: each check is O(24) — just verify consistency of CT→PT
mapping at the 24 crib positions after transposition.
"""
import sys, os, json, time, random, itertools
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS, CRIB_WORDS,
)
from kryptos.kernel.transforms.transposition import (
    apply_perm, invert_perm, columnar_perm, keyword_to_order,
    spiral_perm, serpentine_perm, rail_fence_perm,
)

# ── Step 1: Identify contradictions under identity transposition ──

def count_contradictions(perm):
    """Count number of CT letters that map to multiple PT letters
    at crib positions after applying transposition perm.

    Model: intermediate[i] = CT[perm[i]], then sub(intermediate[i]) = PT[i]
    Contradiction: same intermediate letter at different crib positions → different PT.
    """
    # Map: intermediate_letter → set of PT letters it must decrypt to
    letter_to_pts = {}
    for pos in sorted(CRIB_DICT.keys()):
        # After transposition, position pos gets CT[perm[pos]]
        intermediate_letter = CT[perm[pos]]
        pt_letter = CRIB_DICT[pos]
        if intermediate_letter not in letter_to_pts:
            letter_to_pts[intermediate_letter] = set()
        letter_to_pts[intermediate_letter].add(pt_letter)

    contradictions = sum(1 for pts in letter_to_pts.values() if len(pts) > 1)
    return contradictions, letter_to_pts

# Verify identity case matches E-CFM-04's count of 9
identity_perm = list(range(CT_LEN))
id_contradictions, id_mapping = count_contradictions(identity_perm)
print(f"Identity transposition: {id_contradictions} contradictions")
for letter, pts in sorted(id_mapping.items()):
    if len(pts) > 1:
        print(f"  {letter} → {sorted(pts)}")
print()

# ── Step 2: Generate structured transpositions ──

structured_perms = []

# 2a: Columnar transpositions with numeric order
for width in range(5, 16):
    n_cols = width
    for col_order_tuple in itertools.permutations(range(min(n_cols, 6))):
        # For widths > 6, only test first few column orders (too many otherwise)
        if width > 6:
            break
        order = list(col_order_tuple) + list(range(len(col_order_tuple), n_cols))
        try:
            perm = columnar_perm(width, tuple(order), CT_LEN)
            structured_perms.append((f"columnar_w{width}_order{''.join(map(str,order[:6]))}", perm))
        except:
            pass

    # Also just the standard columnar (identity column order)
    std_order = tuple(range(n_cols))
    try:
        perm = columnar_perm(width, std_order, CT_LEN)
        structured_perms.append((f"columnar_w{width}_std", perm))
    except:
        pass

# 2b: Keyword-based columnar
keywords = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "BERLIN", "CLOCK",
    "SHADOW", "IQLUSION", "LAYERTWO", "IDBYROWS", "SANBORN",
    "SCHEIDT", "WEBSTER", "EGYPT", "CARTER", "PHARAOH",
    "WELTZEITUHR", "ANTIPODES", "EASTNORTHEAST", "BERLINCLOCK",
    "DESPARATLY", "ALEXANDERPLATZ", "SMITHSONIAN", "HIRSHHORN",
    "DRUSILLA", "WHATSTHEPOINT", "NORTHEASTEAST", "TUTANKHAMUN",
]

for kw in keywords:
    width = len(kw)
    if 3 <= width <= 20:
        try:
            order = keyword_to_order(kw, width)
            perm = columnar_perm(width, order, CT_LEN)
            structured_perms.append((f"kw_{kw}_w{width}", perm))
            # Also try inverse
            inv = invert_perm(perm)
            structured_perms.append((f"kw_{kw}_w{width}_inv", inv))
        except:
            pass

# 2c: Rail fence
for depth in range(2, 15):
    try:
        perm = rail_fence_perm(CT_LEN, depth)
        structured_perms.append((f"railfence_d{depth}", perm))
        inv = invert_perm(perm)
        structured_perms.append((f"railfence_d{depth}_inv", inv))
    except:
        pass

# 2d: Spiral and serpentine for various grid dimensions
for rows in range(4, 20):
    for cols in range(4, 30):
        if abs(rows * cols - CT_LEN) <= cols:  # grid can hold 97 chars
            try:
                for cw in [True, False]:
                    perm = spiral_perm(rows, cols, CT_LEN, clockwise=cw)
                    d = "CW" if cw else "CCW"
                    structured_perms.append((f"spiral_{d}_{rows}x{cols}", perm))
                    inv = invert_perm(perm)
                    structured_perms.append((f"spiral_{d}_{rows}x{cols}_inv", inv))
            except:
                pass
            try:
                for vert in [False, True]:
                    perm = serpentine_perm(rows, cols, CT_LEN, vertical=vert)
                    d = "V" if vert else "H"
                    structured_perms.append((f"serpentine_{d}_{rows}x{cols}", perm))
                    inv = invert_perm(perm)
                    structured_perms.append((f"serpentine_{d}_{rows}x{cols}_inv", inv))
            except:
                pass

# 2e: Even/odd interleave variations
evens = list(range(0, CT_LEN, 2))
odds = list(range(1, CT_LEN, 2))
structured_perms.append(("interleave_evens_first", evens + odds))
structured_perms.append(("interleave_odds_first", odds + evens))
# Reverse interleave
structured_perms.append(("interleave_evens_rev", evens[::-1] + odds[::-1]))
structured_perms.append(("interleave_odds_rev", odds[::-1] + evens[::-1]))
# Alternating from both halves
alt = []
for i in range(max(len(evens), len(odds))):
    if i < len(evens): alt.append(evens[i])
    if i < len(odds): alt.append(odds[i])
structured_perms.append(("interleave_alternating", alt[:CT_LEN]))

# 2f: Reverse, rotation
structured_perms.append(("reverse", list(range(CT_LEN-1, -1, -1))))
for rot in range(1, CT_LEN):
    perm = [(i + rot) % CT_LEN for i in range(CT_LEN)]
    structured_perms.append((f"rotate_{rot}", perm))

# 2g: Block reversal
for block_size in [4, 5, 7, 8, 9, 10, 11, 12, 13, 24]:
    perm = []
    for start in range(0, CT_LEN, block_size):
        end = min(start + block_size, CT_LEN)
        perm.extend(range(end-1, start-1, -1))
    structured_perms.append((f"block_rev_{block_size}", perm[:CT_LEN]))

# 2h: Skip/stride patterns
for stride in range(2, 20):
    perm = []
    for offset in range(stride):
        perm.extend(range(offset, CT_LEN, stride))
    if len(perm) == CT_LEN:
        structured_perms.append((f"skip_{stride}", perm))
        structured_perms.append((f"skip_{stride}_inv", invert_perm(perm)))

# 2i: Diagonal reading of grids
for width in range(7, 14):
    rows = (CT_LEN + width - 1) // width
    # Top-left to bottom-right diagonals
    perm = []
    for d in range(rows + width - 1):
        for r in range(rows):
            c = d - r
            if 0 <= c < width:
                idx = r * width + c
                if idx < CT_LEN:
                    perm.append(idx)
    if len(perm) == CT_LEN:
        structured_perms.append((f"diagonal_tlbr_w{width}", perm))
        structured_perms.append((f"diagonal_tlbr_w{width}_inv", invert_perm(perm)))

    # Top-right to bottom-left diagonals
    perm2 = []
    for d in range(rows + width - 1):
        for r in range(rows):
            c = r - (d - (width-1))
            if 0 <= c < width:
                idx = r * width + c
                if idx < CT_LEN:
                    perm2.append(idx)
    if len(perm2) == CT_LEN:
        structured_perms.append((f"diagonal_trbl_w{width}", perm2))
        structured_perms.append((f"diagonal_trbl_w{width}_inv", invert_perm(perm2)))

print(f"Generated {len(structured_perms)} structured transpositions")

# ── Step 3: Test all structured transpositions ──

start_time = time.time()
hits = []
best_contradictions = id_contradictions
best_structured = []
contradiction_dist = {}

for name, perm in structured_perms:
    # Validate permutation
    if len(perm) != CT_LEN or set(perm) != set(range(CT_LEN)):
        continue

    c, mapping = count_contradictions(perm)
    contradiction_dist[c] = contradiction_dist.get(c, 0) + 1

    if c == 0:
        hits.append({
            "name": name,
            "type": "structured",
            "contradictions": 0,
            "mapping": {k: sorted(v) for k, v in sorted(mapping.items())},
            "perm_sample": perm[:20],
        })
        print(f"*** ZERO CONTRADICTIONS: {name} ***")
        # Show the implied substitution table
        for letter, pts in sorted(mapping.items()):
            print(f"  {letter} → {pts}")

    if c < best_contradictions:
        best_contradictions = c
        best_structured = [(name, c, mapping)]
    elif c == best_contradictions:
        best_structured.append((name, c, mapping))

elapsed_structured = time.time() - start_time
valid_count = sum(contradiction_dist.values())
print(f"\nTested {valid_count} valid structured perms in {elapsed_structured:.1f}s")
print(f"Best: {best_contradictions} contradictions")
print(f"Distribution: {dict(sorted(contradiction_dist.items()))}")
if best_structured:
    print(f"Best examples ({min(5, len(best_structured))}):")
    for name, c, _ in best_structured[:5]:
        print(f"  {name}: {c} contradictions")
print()

# ── Step 4: Exhaustive columnar search (widths 5-15, all column orders) ──

print("=" * 60)
print("Phase 2: Exhaustive columnar (widths 5-8, all column orders)")
print("=" * 60)

columnar_hits = []
columnar_best = id_contradictions
columnar_tested = 0

for width in range(5, 9):  # 5!=120, 6!=720, 7!=5040, 8!=40320
    n_perms = 1
    for i in range(2, width+1):
        n_perms *= i
    print(f"  Width {width}: testing {n_perms} column orders...")

    for col_order in itertools.permutations(range(width)):
        try:
            perm = columnar_perm(width, col_order, CT_LEN)
            c, mapping = count_contradictions(perm)
            columnar_tested += 1

            if c == 0:
                columnar_hits.append({
                    "width": width,
                    "col_order": list(col_order),
                    "contradictions": 0,
                    "mapping": {k: sorted(v) for k, v in sorted(mapping.items())},
                })
                print(f"  *** ZERO CONTRADICTIONS: width={width} order={col_order} ***")

            if c < columnar_best:
                columnar_best = c

            # Also try inverse
            inv = invert_perm(perm)
            c2, mapping2 = count_contradictions(inv)
            columnar_tested += 1

            if c2 == 0:
                columnar_hits.append({
                    "width": width,
                    "col_order": list(col_order),
                    "direction": "inverse",
                    "contradictions": 0,
                    "mapping": {k: sorted(v) for k, v in sorted(mapping2.items())},
                })
                print(f"  *** ZERO CONTRADICTIONS (inv): width={width} order={col_order} ***")

            if c2 < columnar_best:
                columnar_best = c2

        except Exception:
            pass

print(f"Columnar exhaustive: tested {columnar_tested}, best {columnar_best} contradictions, {len(columnar_hits)} zero-contradiction hits")
print()

# ── Step 5: Wider columnar (widths 9-13, sampled orders) ──

print("=" * 60)
print("Phase 3: Sampled columnar (widths 9-13, 50K random orders each)")
print("=" * 60)

sampled_tested = 0
sampled_best = id_contradictions
sampled_hits = []

for width in range(9, 14):
    print(f"  Width {width}: sampling 50K random column orders...")
    for _ in range(50000):
        col_order = list(range(width))
        random.shuffle(col_order)
        try:
            perm = columnar_perm(width, tuple(col_order), CT_LEN)
            c, mapping = count_contradictions(perm)
            sampled_tested += 1

            if c == 0:
                sampled_hits.append({
                    "width": width,
                    "col_order": col_order,
                    "contradictions": 0,
                })
                print(f"  *** ZERO: width={width} order={col_order} ***")

            if c < sampled_best:
                sampled_best = c

            inv = invert_perm(perm)
            c2, _ = count_contradictions(inv)
            sampled_tested += 1

            if c2 == 0:
                sampled_hits.append({
                    "width": width,
                    "col_order": col_order,
                    "direction": "inverse",
                    "contradictions": 0,
                })
                print(f"  *** ZERO (inv): width={width} order={col_order} ***")

            if c2 < sampled_best:
                sampled_best = c2

        except Exception:
            pass

print(f"Sampled columnar: tested {sampled_tested}, best {sampled_best} contradictions, {len(sampled_hits)} hits")
print()

# ── Step 6: Random transpositions (1M samples) ──

print("=" * 60)
print("Phase 4: Random full transpositions (1M samples)")
print("=" * 60)

random_tested = 0
random_hits = []
random_best = id_contradictions
random_dist = {}

base = list(range(CT_LEN))
for i in range(1000000):
    perm = base.copy()
    random.shuffle(perm)
    c, mapping = count_contradictions(perm)
    random_tested += 1
    random_dist[c] = random_dist.get(c, 0) + 1

    if c == 0:
        random_hits.append({
            "index": i,
            "contradictions": 0,
            "perm": perm[:20],
            "mapping": {k: sorted(v) for k, v in sorted(mapping.items())},
        })
        print(f"  *** ZERO CONTRADICTIONS at sample {i} ***")

    if c < random_best:
        random_best = c

    if (i + 1) % 200000 == 0:
        print(f"  Progress: {i+1}/1M, best so far: {random_best}")

elapsed_total = time.time() - start_time
print(f"\nRandom: tested {random_tested}, best {random_best} contradictions, {len(random_hits)} hits")
print(f"Distribution: {dict(sorted(random_dist.items()))}")
print()

# ── Step 7: If any hits found, verify and try decryption ──

all_hits = hits + columnar_hits + sampled_hits + random_hits
print(f"Total zero-contradiction transpositions found: {len(all_hits)}")

if all_hits:
    from kryptos.kernel.transforms.vigenere import CipherVariant, decrypt_text
    from kryptos.kernel.scoring.aggregate import score_candidate
    from kryptos.kernel.constraints.bean import verify_bean

    print("\n" + "=" * 60)
    print("VERIFYING HITS — trying all substitution variants")
    print("=" * 60)

    for hit in all_hits[:50]:  # limit to first 50 hits
        perm = hit.get("perm_sample") or hit.get("perm")
        if perm and len(perm) < CT_LEN:
            # Can't reconstruct full perm from sample
            print(f"  Skipping {hit.get('name', 'unknown')} — incomplete perm")
            continue

        # If we have the full perm, test it
        # For columnar hits, reconstruct the perm
        if "col_order" in hit:
            perm = columnar_perm(hit["width"], tuple(hit["col_order"]), CT_LEN)
            if hit.get("direction") == "inverse":
                perm = invert_perm(perm)

        if perm is None or len(perm) != CT_LEN:
            continue

        # Apply transposition (undo direction)
        intermediate = apply_perm(CT, invert_perm(perm))

        # Build the mono substitution from crib constraints
        mapping = hit.get("mapping", {})
        sub_table = {}
        for letter, pts in mapping.items():
            if len(pts) == 1:
                sub_table[letter] = pts[0]

        # Apply known substitution to intermediate
        pt = ""
        for ch in intermediate:
            if ch in sub_table:
                pt += sub_table[ch]
            else:
                pt += "?"

        known_pct = sum(1 for c in pt if c != "?")
        label = hit.get('name', 'w%s_order' % hit.get('width', '?'))
        print(f"  Hit: {label} — {known_pct}/97 chars known")
        print(f"    PT: {pt[:50]}...")

        # Score what we have
        sc = score_candidate(pt.replace("?", "X"))
        print(f"    Score: {sc.crib_score}/24, Bean: {sc.bean_passed}")

# ── Save results ──

results = {
    "experiment": "E-TEAM-HOMO-CONTRADICTION-SEARCH",
    "description": "Systematic search for transpositions resolving all 9 homophonic contradictions",
    "identity_contradictions": id_contradictions,
    "identity_mapping": {k: sorted(v) for k, v in sorted(id_mapping.items()) if len(v) > 1},
    "structured": {
        "tested": valid_count,
        "best_contradictions": best_contradictions,
        "zero_hits": len(hits),
    },
    "columnar_exhaustive": {
        "tested": columnar_tested,
        "best_contradictions": columnar_best,
        "zero_hits": len(columnar_hits),
        "widths": "5-8",
    },
    "columnar_sampled": {
        "tested": sampled_tested,
        "best_contradictions": sampled_best,
        "zero_hits": len(sampled_hits),
        "widths": "9-13",
    },
    "random": {
        "tested": random_tested,
        "best_contradictions": random_best,
        "zero_hits": len(random_hits),
        "distribution": {str(k): v for k, v in sorted(random_dist.items())},
    },
    "total_zero_hits": len(all_hits),
    "elapsed_seconds": elapsed_total,
    "verdict": "SIGNAL" if all_hits else "NOISE",
    "all_hits": all_hits[:100],  # save first 100 hits
}

os.makedirs("results", exist_ok=True)
with open("results/e_team_homo_contradiction_search.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"\nTotal elapsed: {elapsed_total:.1f}s")
print(f"Results saved to results/e_team_homo_contradiction_search.json")
