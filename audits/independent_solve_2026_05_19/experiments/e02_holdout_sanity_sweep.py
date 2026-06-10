"""Phase 3b: holdout-verified sanity sweep of direct-positional Vigenere /
Beaufort / Variant Beaufort with Kryptos-context keywords.

For each (cipher variant) × (AZ or KA alphabet) × (curated K4-context
keyword), we:

- Decrypt CT.
- Score against the **non-held-out crib only**.
- Read the predicted plaintext at the held-out crib positions.
- A "pass" means the held-out crib characters are predicted exactly.

This is a sanity check: the documented Tier 1 elimination of all periodic
polyalphabetic under direct positional crib mapping predicts ZERO passes.
Running it from independent code confirms that prediction *for this
keyword pool* rather than trusting the kernel's exhaustion log.
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.dirname(ROOT))

from independent_solve_2026_05_19.src.alphabets import AZ, KA, mixed_alphabet
from independent_solve_2026_05_19.src.ciphers.vigenere import decrypt as vig_decrypt
from independent_solve_2026_05_19.src.ciphers.beaufort import (
    beaufort_decrypt, variant_beaufort_decrypt,
)
from independent_solve_2026_05_19.src.scoring import crib_score, holdout_predictions


CT = "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"

KEYWORDS = [
    "KRYPTOS", "PALIMPSEST", "ABSCISSA",
    "BERLIN", "CLOCK", "BERLINCLOCK",
    "EAST", "NORTHEAST", "EASTNORTHEAST",
    "WORLD", "WORLDCLOCK", "LANGLEY", "WEBSTER",
    "CARTER", "HOWARDCARTER", "TUTANKHAMUN", "LAYERTWO",
    "INVISIBLE", "IQLUSION", "SHADOW", "FORCES",
    "ATBASH", "ALEXANDERPLATZ",
]

VARIANTS = [
    ("vig",   vig_decrypt),
    ("beau",  beaufort_decrypt),
    ("vbeau", variant_beaufort_decrypt),
]

ALPHABETS = [
    ("AZ", AZ),
    ("KA", KA),
]


def main():
    rows = []
    for vname, fn in VARIANTS:
        for aname, alpha in ALPHABETS:
            for kw in KEYWORDS:
                pt = fn(CT, kw, alpha)
                # Withhold BCL (index 1), see how many of EAST/NORTHEAST hit
                hits_E, total_E, _ = crib_score(pt, withheld_crib_index=1)
                # Withhold EAST (index 0), see how many of BERLINCLOCK hit
                hits_B, total_B, _ = crib_score(pt, withheld_crib_index=0)
                holdout_E = holdout_predictions(pt, withheld_crib_index=0)
                holdout_B = holdout_predictions(pt, withheld_crib_index=1)
                rows.append({
                    "variant": vname, "alpha": aname, "key": kw,
                    "EAST_hits_held_in":     hits_E,
                    "BCL_hits_held_in":      hits_B,
                    "EAST_holdout_predicted": holdout_E["predicted"],
                    "EAST_holdout_hits":      holdout_E["hits"],
                    "BCL_holdout_predicted":  holdout_B["predicted"],
                    "BCL_holdout_hits":       holdout_B["hits"],
                    "holdout_passes": holdout_E["passes"] or holdout_B["passes"],
                    "fully_passes":   holdout_E["passes"] and holdout_B["passes"],
                })

    passes = [r for r in rows if r["holdout_passes"]]
    full_passes = [r for r in rows if r["fully_passes"]]
    best_E = max(rows, key=lambda r: r["EAST_holdout_hits"])
    best_B = max(rows, key=lambda r: r["BCL_holdout_hits"])
    best_total = max(rows, key=lambda r: r["EAST_holdout_hits"] + r["BCL_holdout_hits"])

    out = {
        "experiment": "e02_holdout_sanity_sweep",
        "n_configs": len(rows),
        "holdout_partial_pass_count": len(passes),
        "holdout_full_pass_count": len(full_passes),
        "best_EAST_holdout": best_E,
        "best_BCL_holdout":  best_B,
        "best_combined_holdout": best_total,
        "all_rows": rows,
    }
    out_path = os.path.join(ROOT, "results", "e02_holdout_sweep.json")
    with open(out_path, "w") as f:
        json.dump(out, f, indent=2)

    print(f"e02: {len(rows)} configs ({len(VARIANTS)} variants × {len(ALPHABETS)} alphabets × {len(KEYWORDS)} keywords)")
    print(f"  Holdout-PARTIAL passes (one crib predicts the other exactly): {len(passes)}")
    print(f"  Holdout-FULL passes    (each crib predicts the other exactly): {len(full_passes)}")
    print(f"  Best EAST-holdout : {best_E['EAST_holdout_hits']:>2}/13 -- {best_E['variant']}/{best_E['alpha']} key={best_E['key']!r:<20s} predicted={best_E['EAST_holdout_predicted']!r}")
    print(f"  Best BCL-holdout  : {best_B['BCL_holdout_hits']:>2}/11 -- {best_B['variant']}/{best_B['alpha']} key={best_B['key']!r:<20s} predicted={best_B['BCL_holdout_predicted']!r}")
    print(f"  Best combined     : {best_total['EAST_holdout_hits'] + best_total['BCL_holdout_hits']:>2}/24 -- {best_total['variant']}/{best_total['alpha']} key={best_total['key']!r}")


if __name__ == "__main__":
    main()
