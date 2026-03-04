#!/usr/bin/env python3
"""
Cipher: columnar transposition
Family: transposition/columnar
Status: exhausted
Keyspace: see implementation
Last run: 
Best score: 
"""
"""E-S-53: Keyword Columnar + Myszkowski Transposition + Polyalphabetic Sweep.

Tests columnar transpositions derived from ~120 thematic keywords at ALL widths
(not just 5-10 tested previously). For each keyword:
  - Derive standard columnar ordering
  - Also test Myszkowski variant (tied columns)
  - Apply transposition both directions (encrypt/decrypt)
  - Test Vigenère/Beaufort/VarBeau at periods 2-14
  - Check crib matches and Bean constraint

Prior work eliminated widths 5-10 with EXHAUSTIVE orderings (E-NSA-01, Session 4).
This test uses KEYWORD-derived orderings at ALL widths including 3-4, 11-20+.

Expected: ~120 keywords × 2 types × 2 dirs × 3 variants × 13 periods ≈ 18,720 configs.
"""

import json
import time
import sys

sys.path.insert(0, "src")

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD,
    CRIB_DICT, N_CRIBS, CRIB_POSITIONS,
    BEAN_EQ, BEAN_INEQ,
    NOISE_FLOOR, STORE_THRESHOLD,
)
from kryptos.kernel.transforms.transposition import (
    columnar_perm, myszkowski_perm, keyword_to_order,
    invert_perm, apply_perm, validate_perm,
)

# ── Thematic keywords ───────────────────────────────────────────────
# Sources: Kryptos sculpture, Sanborn's statements, CIA history,
# Egypt/Berlin thematic, Carter's book, Scheidt consultation

KEYWORDS = [
    # Kryptos / sculpture
    "KRYPTOS", "PALIMPSEST", "ABSCISSA", "SHADOW", "FORCES",
    "VIRTUALLY", "INVISIBLE", "IQLUSION", "ILLUSION",
    "KRYPTOSABCDEFGHIJLMNQUVWXZ",  # full KA alphabet as keyword
    "BETWEEN", "SUBTLE", "SHADING",
    # CIA / intelligence
    "CIA", "LANGLEY", "INTELLIGENCE", "SECRET", "AGENCY",
    "COVERT", "CLASSIFIED", "CLEARANCE", "DIRECTOR",
    "OPERATION", "ENCRYPTION", "DECRYPTION",
    # Berlin / Cold War
    "BERLIN", "WALL", "CLOCK", "BERLINCLOCK", "CHECKPOINT",
    "CHARLIE", "NOVEMBER", "ALEXANDERPLATZ", "URANIA",
    "WELTZEITUHR", "FREEDOM", "REUNIFICATION",
    # Egypt / Carter
    "EGYPT", "CAIRO", "TUTANKHAMUN", "CARTER", "HOWARD",
    "PHARAOH", "TOMB", "PYRAMID", "SPHINX", "VALLEY",
    "KINGS", "EXCAVATION", "DISCOVERY", "ARCHAEOLOGY",
    "CARNARVON", "LUXOR", "THEBES", "NILE",
    # Cryptography
    "CIPHER", "CODE", "KEY", "VIGENERE", "BEAUFORT",
    "ENIGMA", "TRANSPOSITION", "SUBSTITUTION", "POLYALPHABETIC",
    "SCHEIDT", "SANBORN", "ELONKA",
    # Sanborn clues
    "POINT", "WHATSTHEPOINT", "DELIVERINGAMESSAGE",
    "MESSAGE", "DELIVERING",
    # Sculpture features
    "COMPASS", "LODESTONE", "QUARTZ", "PETRIFIED",
    "COPPER", "MORSE", "COORDINATES",
    # Dates / numbers as words
    "NINETEENEIGHTYSIX", "NINETEENEIGHTYNINE",
    "NOVEMBER", "NINTH",
    # NSA / government
    "NSA", "FORTMEADE", "PENTAGON", "WHITEHOUSE",
    "CENTRAL", "HEADQUARTERS",
    # Military / espionage
    "DEAD", "DROP", "DEADDROP", "HANDLER", "MOLE",
    "AGENT", "DOUBLE", "MISSION", "BRIEFING",
    # Miscellaneous thematic
    "DIGETAL", "INTERPRETATU", "DESPERATELY",  # K3 misspellings
    "SLOWLY", "MATERIAL", "REMAINS", "UNDERGROUND",
    "LIGHT", "DARKNESS", "TRUTH", "HIDDEN",
    "NORTHWEST", "SOUTHEAST", "NORTHEAST",
    # Short keywords (widths 3-4, not tested before)
    "KEY", "MAP", "CIA", "SPY", "WAR",
    "CODE", "LOCK", "OPEN", "HIDE",
    "EAST", "WEST", "NORTH", "SOUTH",
    # Long keywords (widths 11-20)
    "SOUTHEASTERN", "NORTHWESTERN", "CRYPTANALYSIS",
    "NORTHEASTERLY", "ARCHAEOLOGICAL", "COUNTERINTELLIGENCE",
    "ALEXANDERPLATZ", "TUTANKHAMUN",
]

# Deduplicate (case-insensitive)
seen = set()
UNIQUE_KEYWORDS = []
for kw in KEYWORDS:
    kw_upper = kw.upper()
    if kw_upper not in seen and len(kw_upper) >= 3:
        seen.add(kw_upper)
        UNIQUE_KEYWORDS.append(kw_upper)

CT_IDX = [ALPH_IDX[c] for c in CT]


def derive_key_at_crib(ct_idx, pt_idx, variant):
    """Derive key value from CT and PT indices under given cipher variant."""
    if variant == "vig":
        return (ct_idx - pt_idx) % MOD
    elif variant == "beau":
        return (ct_idx + pt_idx) % MOD
    elif variant == "varbeau":
        return (pt_idx - ct_idx) % MOD
    else:
        raise ValueError(f"Unknown variant: {variant}")


def check_period_consistency(key_vals, period):
    """Check how many crib-derived key values are consistent with given period."""
    residue_vals = {}
    matches = 0
    for pos, kv in key_vals:
        r = pos % period
        if r in residue_vals:
            if residue_vals[r] == kv:
                matches += 1
            # Don't increment matches for first occurrence
        else:
            residue_vals[r] = kv
            matches += 1
    return matches


def check_bean(key_vals_dict, variant):
    """Check Bean equality and inequalities."""
    # Bean equality: k[27] == k[65]
    if 27 in key_vals_dict and 65 in key_vals_dict:
        if key_vals_dict[27] != key_vals_dict[65]:
            return False
    # Bean inequalities
    for p1, p2 in BEAN_INEQ:
        if p1 in key_vals_dict and p2 in key_vals_dict:
            if key_vals_dict[p1] == key_vals_dict[p2]:
                return False
    return True


def test_transposition(perm, label, results):
    """Test a transposition permutation with all cipher variants and periods.

    Model: CT[i] = Transpose(SubEncrypt(PT))[i]
    So to reverse: SubEncrypt(PT) = InverseTranspose(CT)
    Then: INTER[j] = CT[perm[j]] (apply perm to CT to undo transposition)
    Then: KEY[j] = INTER[j] - PT[j] (Vigenère) at crib positions

    Wait — need to be careful with directions.

    Convention: perm is the encryption permutation.
    Encrypt: CT[perm[i]] = INTER[i], or equivalently CT = apply_perm(INTER, inv_perm)
    Decrypt: INTER[i] = CT[inv_perm[i]], or equivalently INTER = apply_perm(CT, perm)

    Actually, with our convention output[i] = input[perm[i]]:
    If transposition perm maps PT positions to CT positions:
      CT[i] = INTER[perm[i]]  -- "gather" from INTER
      So INTER[j] = CT[inv_perm[j]]

    Direction 1 (Sub then Trans):
      INTER = SubEncrypt(PT)  -> INTER[j] = PT[j] + KEY[j]
      CT[i] = INTER[perm[i]]
      So CT[i] = PT[perm[i]] + KEY[perm[i]]
      To check at crib: for crib pos p (in PT space):
        Need CT position i such that perm[i] = p, i.e., i = inv_perm[p]
        CT[inv_perm[p]] = PT[p] + KEY[p]
        KEY[p] = CT[inv_perm[p]] - PT[p]

    Direction 2 (Trans then Sub):
      INTER[i] = PT[perm[i]]  -- transpose PT first
      CT[i] = INTER[i] + KEY[i] = PT[perm[i]] + KEY[i]
      At crib pos p: we know PT[p], and CT appears at position inv_perm[p]
      Wait, no. We know PT[p] for crib positions p.
      CT[i] = PT[perm[i]] + KEY[i]
      For each i, if perm[i] is a crib position:
        KEY[i] = CT[i] - PT[perm[i]]
      So the key is in CT-space, and we test its periodicity there.
    """
    inv_perm = invert_perm(perm)

    for direction in [1, 2]:
        for variant in ["vig", "beau", "varbeau"]:
            # Derive key values at crib positions
            key_vals = []  # list of (position_in_key_space, key_value)
            key_dict = {}

            if direction == 1:
                # Sub then Trans: KEY[p] = derive(CT[inv_perm[p]], PT[p])
                for p, pt_ch in CRIB_DICT.items():
                    ct_pos = inv_perm[p]
                    ct_val = CT_IDX[ct_pos]
                    pt_val = ALPH_IDX[pt_ch]
                    kv = derive_key_at_crib(ct_val, pt_val, variant)
                    key_vals.append((p, kv))
                    key_dict[p] = kv
            else:
                # Trans then Sub: KEY[i] = derive(CT[i], PT[perm[i]])
                for i in range(CT_LEN):
                    pt_pos = perm[i]
                    if pt_pos in CRIB_DICT:
                        pt_val = ALPH_IDX[CRIB_DICT[pt_pos]]
                        ct_val = CT_IDX[i]
                        kv = derive_key_at_crib(ct_val, pt_val, variant)
                        key_vals.append((i, kv))
                        key_dict[i] = kv

            # Test period consistency for periods 2-14
            for period in range(2, 15):
                score = check_period_consistency(key_vals, period)

                if score >= STORE_THRESHOLD:
                    bean_ok = check_bean(key_dict, variant)
                    results.append({
                        "keyword": label,
                        "type": "columnar" if "col:" in label else "myszkowski" if "mysz:" in label else label.split(":")[0],
                        "direction": direction,
                        "variant": variant,
                        "period": period,
                        "score": score,
                        "bean": bean_ok,
                    })


def main():
    print("=" * 70)
    print("E-S-53: Keyword Columnar + Myszkowski Transposition + Poly Sweep")
    print("=" * 70)
    print(f"Keywords: {len(UNIQUE_KEYWORDS)}")
    print(f"Width range: {min(len(k) for k in UNIQUE_KEYWORDS)}-{max(len(k) for k in UNIQUE_KEYWORDS)}")
    print()

    t0 = time.time()
    results = []
    total_configs = 0
    best_score = 0
    best_config = None

    for ki, kw in enumerate(UNIQUE_KEYWORDS):
        width = len(kw)

        # Standard columnar
        order = keyword_to_order(kw, width)
        if order is not None:
            perm = columnar_perm(width, order, CT_LEN)
            if validate_perm(perm, CT_LEN):
                test_transposition(perm, f"col:{kw}", results)
                total_configs += 2 * 3 * 13  # 2 dirs × 3 variants × 13 periods

        # Myszkowski (only different from columnar if keyword has repeated letters)
        has_repeats = len(set(kw)) < len(kw)
        if has_repeats:
            perm_m = myszkowski_perm(kw, CT_LEN)
            if validate_perm(perm_m, CT_LEN):
                test_transposition(perm_m, f"mysz:{kw}", results)
                total_configs += 2 * 3 * 13

        if (ki + 1) % 20 == 0:
            cur_best = max((r["score"] for r in results), default=0)
            print(f"  Keyword {ki+1}/{len(UNIQUE_KEYWORDS)}: configs={total_configs} "
                  f"hits(≥{STORE_THRESHOLD})={len(results)} best={cur_best}/24 [{time.time()-t0:.1f}s]")

    elapsed = time.time() - t0

    # Sort results by score descending
    results.sort(key=lambda r: (-r["score"], -r["bean"]))

    # Summary
    print()
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"  Keywords: {len(UNIQUE_KEYWORDS)}")
    print(f"  Total configs: {total_configs}")
    print(f"  Hits ≥{STORE_THRESHOLD}: {len(results)}")
    print(f"  Time: {elapsed:.1f}s")
    print()

    if results:
        print(f"  Top 10 results:")
        for r in results[:10]:
            bean_str = "BEAN_OK" if r["bean"] else "bean_fail"
            print(f"    {r['score']}/24 p={r['period']} d={r['direction']} "
                  f"{r['variant']} {r['keyword']} {bean_str}")
        best_config = results[0]
        best_score = best_config["score"]
    else:
        print("  No results above threshold!")
        best_score = 0

    # Expected random baseline
    # For period p with 24 crib positions: expected matches ≈ 24 - (24 - num_residues) * (1 - 1/26)
    # At period 7: ~8.2/24 expected
    print()
    print(f"  Best score: {best_score}/24")

    if best_score <= NOISE_FLOOR:
        verdict = "ELIMINATED — all at noise floor"
    elif best_score <= 14:
        verdict = f"WEAK — best {best_score}/24, likely noise"
    else:
        verdict = f"INVESTIGATE — best {best_score}/24"

    print(f"  Verdict: {verdict}")

    # Width distribution of hits
    if results:
        from collections import Counter
        width_dist = Counter()
        period_dist = Counter()
        for r in results:
            kw = r["keyword"].split(":", 1)[1] if ":" in r["keyword"] else r["keyword"]
            width_dist[len(kw)] += 1
            period_dist[r["period"]] += 1
        print()
        print(f"  Width distribution of hits: {dict(sorted(width_dist.items()))}")
        print(f"  Period distribution of hits: {dict(sorted(period_dist.items()))}")

    # Save artifact
    artifact = {
        "experiment": "E-S-53",
        "n_keywords": len(UNIQUE_KEYWORDS),
        "total_configs": total_configs,
        "n_hits": len(results),
        "best_score": best_score,
        "best_config": best_config,
        "verdict": verdict,
        "elapsed_seconds": elapsed,
        "top_20": results[:20],
    }

    with open("results/e_s_53_keyword_columnar.json", "w") as f:
        json.dump(artifact, f, indent=2)

    print(f"\n  Artifact: results/e_s_53_keyword_columnar.json")
    print(f"  Repro: PYTHONPATH=src python3 -u scripts/e_s_53_keyword_columnar_sweep.py")


if __name__ == "__main__":
    main()
