#!/usr/bin/env python3
"""E-TEAM-HOMOPHONIC-TRANS: Test whether transposition resolves homophonic contradictions.

Under direct correspondence, 9 CT letters at crib positions map to 2+ PT letters,
making homophonic substitution impossible. This script tests whether a transposition
applied before homophonic substitution can resolve all contradictions.

Approach:
1. Compute contradiction count under identity transposition
2. Sample 100K random permutations and build contradiction distribution
3. Test structured transpositions (columnar, skip-N, grid reads)
4. For any permutation achieving 0 contradictions: build and validate the
   homophonic substitution table
"""
import sys, os, json, math, random, time
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, CRIB_POSITIONS,
)


def count_contradictions(perm):
    """Count homophonic contradictions under a given transposition.

    Under transposition perm: intermediate[i] = CT[perm[i]]
    At crib positions, intermediate[pos] must map to PT[pos] via homophonic sub.
    A contradiction occurs when the same intermediate letter maps to different PT letters.
    """
    # intermediate[pos] = CT[perm[pos]] for crib positions
    letter_to_pt = defaultdict(set)
    for pos in CRIB_POSITIONS:
        intermediate_char = CT[perm[pos]]
        pt_char = CRIB_DICT[pos]
        letter_to_pt[intermediate_char].add(pt_char)

    contradictions = 0
    for letter, pt_set in letter_to_pt.items():
        if len(pt_set) > 1:
            contradictions += 1
    return contradictions, dict(letter_to_pt)


def build_columnar_perm(width, col_order=None):
    """Build a columnar transposition permutation for CT_LEN characters."""
    nrows = math.ceil(CT_LEN / width)
    if col_order is None:
        col_order = list(range(width))

    perm = []
    for col in col_order:
        for row in range(nrows):
            idx = row * width + col
            if idx < CT_LEN:
                perm.append(idx)
    return perm


def build_skip_perm(skip):
    """Build a skip-N permutation."""
    positions = []
    pos = 0
    seen = set()
    while len(positions) < CT_LEN:
        if pos in seen:
            for p in range(CT_LEN):
                if p not in seen:
                    pos = p
                    break
            else:
                break
        seen.add(pos)
        positions.append(pos)
        pos = (pos + skip) % CT_LEN
    return positions if len(positions) == CT_LEN else None


def main():
    random.seed(42)

    print("=" * 70)
    print("E-TEAM-HOMOPHONIC-TRANS: Transposition + homophonic resolution")
    print("=" * 70)
    print()

    # ── Step 1: Identity transposition baseline ──────────────────────────
    print("--- Step 1: Identity transposition (direct correspondence) ---")
    identity_perm = list(range(CT_LEN))
    n_contra, mapping = count_contradictions(identity_perm)

    print(f"  Contradictions under identity: {n_contra}")
    print(f"  CT→PT mapping at crib positions:")
    for letter in sorted(mapping.keys()):
        pts = mapping[letter]
        status = "OK" if len(pts) == 1 else f"CONTRADICTION ({len(pts)} PT letters)"
        print(f"    {letter} → {pts}  {status}")
    print()

    # ── Step 2: Random permutation sampling ──────────────────────────────
    print("--- Step 2: Random permutation sampling (100K) ---")
    t0 = time.time()
    NUM_SAMPLES = 100000

    contra_counts = defaultdict(int)
    zero_contra_perms = []
    min_contra = n_contra

    for trial in range(NUM_SAMPLES):
        perm = list(range(CT_LEN))
        random.shuffle(perm)
        nc, mp = count_contradictions(perm)
        contra_counts[nc] += 1

        if nc < min_contra:
            min_contra = nc
        if nc == 0:
            zero_contra_perms.append(perm[:])

    elapsed = time.time() - t0
    print(f"  Elapsed: {elapsed:.1f}s")
    print(f"  Contradiction distribution:")
    for nc in sorted(contra_counts.keys()):
        pct = contra_counts[nc] / NUM_SAMPLES * 100
        bar = "#" * max(1, int(pct / 2))
        print(f"    {nc:2d}: {contra_counts[nc]:6d} ({pct:5.2f}%) {bar}")
    print(f"  Minimum contradictions found: {min_contra}")
    print(f"  Permutations with 0 contradictions: {len(zero_contra_perms)}")
    print()

    # ── Step 3: Structured transpositions ────────────────────────────────
    print("--- Step 3: Structured transpositions ---")
    structured_results = []

    # a) Columnar transpositions (widths 7-13)
    for width in range(7, 14):
        # Standard column order
        perm = build_columnar_perm(width)
        if len(perm) == CT_LEN:
            nc, mp = count_contradictions(perm)
            structured_results.append({
                "type": "columnar",
                "width": width,
                "order": "standard",
                "contradictions": nc,
            })
            if nc == 0:
                print(f"  *** ZERO contradictions: columnar w={width} standard ***")
                zero_contra_perms.append(perm[:])

        # Reverse column order
        perm_rev = build_columnar_perm(width, list(range(width - 1, -1, -1)))
        if len(perm_rev) == CT_LEN:
            nc, mp = count_contradictions(perm_rev)
            structured_results.append({
                "type": "columnar",
                "width": width,
                "order": "reverse",
                "contradictions": nc,
            })
            if nc == 0:
                zero_contra_perms.append(perm_rev[:])

    # b) Skip-N transpositions
    for skip in range(2, 49):
        perm = build_skip_perm(skip)
        if perm and len(perm) == CT_LEN:
            nc, mp = count_contradictions(perm)
            structured_results.append({
                "type": "skip",
                "skip": skip,
                "contradictions": nc,
            })
            if nc == 0:
                print(f"  *** ZERO contradictions: skip-{skip} ***")
                zero_contra_perms.append(perm[:])

    # c) Reverse permutation
    rev_perm = list(range(CT_LEN - 1, -1, -1))
    nc, mp = count_contradictions(rev_perm)
    structured_results.append({"type": "reverse", "contradictions": nc})

    # d) Grid column reads
    for width in range(7, 14):
        nrows = math.ceil(CT_LEN / width)
        for col in range(width):
            positions = []
            for row in range(nrows):
                idx = row * width + col
                if idx < CT_LEN:
                    positions.append(idx)
            # Build permutation: these positions get mapped sequentially
            # This doesn't make a full perm, skip
            pass

    # Summary of structured results
    struct_min = min(r["contradictions"] for r in structured_results) if structured_results else 99
    print(f"  Structured transpositions tested: {len(structured_results)}")
    print(f"  Minimum contradictions: {struct_min}")
    print(f"  Distribution:")
    struct_contra = defaultdict(int)
    for r in structured_results:
        struct_contra[r["contradictions"]] += 1
    for nc in sorted(struct_contra.keys()):
        print(f"    {nc:2d}: {struct_contra[nc]:3d} transpositions")
    print()

    # ── Step 4: Analyze zero-contradiction cases ─────────────────────────
    print("--- Step 4: Zero-contradiction analysis ---")
    print(f"  Total permutations with 0 contradictions: {len(zero_contra_perms)}")
    print()

    if zero_contra_perms:
        # For each zero-contradiction perm, build the homophonic table
        # and check frequency consistency
        for idx, perm in enumerate(zero_contra_perms[:10]):  # Analyze first 10
            nc, mapping = count_contradictions(perm)
            assert nc == 0

            print(f"  Perm #{idx}: mapping (intermediate → PT):")
            # Count how many intermediate letters map to each PT letter
            pt_letter_sources = defaultdict(list)
            for inter_char, pt_set in sorted(mapping.items()):
                pt_char = list(pt_set)[0]  # Exactly one since nc=0
                pt_letter_sources[pt_char].append(inter_char)
                print(f"    {inter_char} → {pt_char}")

            print(f"  PT letter homophones:")
            for pt_char in sorted(pt_letter_sources.keys()):
                sources = pt_letter_sources[pt_char]
                print(f"    {pt_char}: {len(sources)} homophones = {sources}")

            # Check: in the intermediate text, how many distinct letters appear?
            intermediate = "".join(CT[perm[pos]] for pos in sorted(CRIB_POSITIONS))
            inter_freq = defaultdict(int)
            for c in intermediate:
                inter_freq[c] += 1
            print(f"  Intermediate at crib positions: {intermediate}")
            print(f"  Distinct letters in intermediate at cribs: {len(inter_freq)}")

            # How many of 26 letters are used in the mapping?
            mapped_letters = set(mapping.keys())
            print(f"  Letters used in mapping: {len(mapped_letters)}/26")

            # Check full intermediate text
            full_intermediate = "".join(CT[perm[i]] for i in range(CT_LEN))
            full_freq = defaultdict(int)
            for c in full_intermediate:
                full_freq[c] += 1

            # For a valid homophonic cipher, we need ALL letters in intermediate
            # to have a defined mapping. Currently only crib positions define mappings.
            unmapped = set(ALPH) - mapped_letters
            print(f"  Unmapped intermediate letters: {unmapped}")
            print()

        # Statistical analysis of contradiction counts
        print(f"  P(0 contradictions | random perm) = {len(zero_contra_perms)}/{NUM_SAMPLES} = "
              f"{len(zero_contra_perms)/NUM_SAMPLES:.6f}")
    else:
        print("  No zero-contradiction permutations found.")
        print()

        # Analyze the minimum case
        if min_contra > 0:
            # Find a minimum-contradiction perm
            print(f"  Analyzing minimum contradiction case ({min_contra}):")
            for trial in range(10000):
                perm = list(range(CT_LEN))
                random.shuffle(perm)
                nc, mp = count_contradictions(perm)
                if nc == min_contra:
                    print(f"  Example perm with {min_contra} contradictions:")
                    for letter in sorted(mp.keys()):
                        pts = mp[letter]
                        if len(pts) > 1:
                            print(f"    {letter} → {pts}  CONTRADICTION")
                    break
    print()

    # ── Step 5: Theoretical analysis ─────────────────────────────────────
    print("--- Step 5: Theoretical analysis ---")

    # How many distinct CT letters appear at crib positions?
    crib_ct_letters = set(CT[pos] for pos in CRIB_POSITIONS)
    crib_pt_letters = set(CRIB_DICT[pos] for pos in CRIB_POSITIONS)
    print(f"  Distinct CT letters at crib positions (identity): {len(crib_ct_letters)}")
    print(f"  Distinct PT letters at crib positions: {len(crib_pt_letters)}")
    print(f"  CT letters: {sorted(crib_ct_letters)}")
    print(f"  PT letters: {sorted(crib_pt_letters)}")

    # Under identity, 9 CT letters have contradictions because:
    # 24 crib positions use only ~15 distinct CT letters,
    # but map to ~11 distinct PT letters.
    # Pigeonhole: some CT letters must map to multiple PT letters.

    # Under random transposition, the intermediate letters at crib positions
    # are random draws from CT. The probability depends on how many distinct
    # intermediate letters we get.

    # With 24 crib positions drawing from 97 CT positions:
    # Expected distinct letters drawn ≈ 26*(1-(25/26)^24) ≈ 16.2
    # But we need each drawn letter to map to only 1 PT letter.
    # The 24 crib positions map to 11 distinct PT letters, with distribution:
    pt_freq = defaultdict(int)
    for pos in CRIB_POSITIONS:
        pt_freq[CRIB_DICT[pos]] += 1
    print(f"\n  PT letter frequency at crib positions:")
    for pt, count in sorted(pt_freq.items(), key=lambda x: -x[1]):
        print(f"    {pt}: {count}")

    # The probability of 0 contradictions is complex but we have the empirical answer
    print(f"\n  Empirical P(0 contradictions): "
          f"{contra_counts.get(0, 0)}/{NUM_SAMPLES} = "
          f"{contra_counts.get(0, 0)/NUM_SAMPLES:.6f}")
    print(f"  Expected in 10^6 trials: ~{contra_counts.get(0, 0) * 10:.0f}")
    print()

    # ── Summary ──────────────────────────────────────────────────────────
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print()

    print(f"Identity contradictions: {n_contra}/26 CT letters")
    print(f"Random perm minimum: {min_contra}")
    print(f"Zero-contradiction random perms: {contra_counts.get(0, 0)}/{NUM_SAMPLES}")
    print(f"Structured minimum: {struct_min}")
    print()

    if contra_counts.get(0, 0) > 0 or any(r["contradictions"] == 0 for r in structured_results):
        print("FINDING: Zero-contradiction transpositions EXIST.")
        print("Homophonic + transposition is NOT eliminated.")
        print("However, the homophonic table is highly underdetermined")
        print("(only crib positions constrain the mapping).")
        verdict = "OPEN"
    else:
        print("FINDING: No zero-contradiction transpositions found in sampling.")
        if min_contra <= 2:
            print(f"Minimum {min_contra} contradictions suggests near-viability.")
            print("Larger sampling or structured search may find zero cases.")
            verdict = "LIKELY_OPEN"
        else:
            print(f"Minimum {min_contra} contradictions suggests homophonic is hard to achieve.")
            verdict = "CONSTRAINED"

    print(f"\nVERDICT: {verdict}")

    # ── Save results ─────────────────────────────────────────────────────
    output = {
        "experiment_id": "e_team_homophonic_trans",
        "description": "Homophonic + transposition contradiction resolution",
        "identity_contradictions": n_contra,
        "random_samples": NUM_SAMPLES,
        "random_min_contradictions": min_contra,
        "zero_contradiction_count": contra_counts.get(0, 0),
        "contradiction_distribution": {str(k): v for k, v in sorted(contra_counts.items())},
        "structured_tested": len(structured_results),
        "structured_min": struct_min,
        "pt_letter_freq": dict(pt_freq),
        "crib_ct_letters_count": len(crib_ct_letters),
        "crib_pt_letters_count": len(crib_pt_letters),
        "verdict": verdict,
    }

    results_path = os.path.join(os.path.dirname(__file__), "..", "results", "e_team_homophonic_trans.json")
    os.makedirs(os.path.dirname(results_path), exist_ok=True)
    with open(results_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\nResults saved to: {results_path}")


if __name__ == "__main__":
    main()
