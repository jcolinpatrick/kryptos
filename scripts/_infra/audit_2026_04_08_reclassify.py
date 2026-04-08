#!/usr/bin/env python3
"""Audit 2026-04-08: reclassify 18 INTERESTING/SIGNAL results as ELIMINATED.

Rationale documented per item. Preserves the prior verdict in `verdict_previous`
so the change is reversible. See conversation log for the audit methodology.
"""
import json
import sys
from pathlib import Path

RESULTS = Path(__file__).resolve().parents[2] / "results"
STAMP = "ELIMINATED (audit 2026-04-08)"

# name -> one-line rationale
RECLASSIFY = {
    "e_combined_ptct_autokey":
        "autokey structurally impossible (all 4 variants); 11/24 is in-family noise",
    "e_s_10_additive_grid_key":
        "self-reports NO SIGNAL; all widths produce contradictions",
    "e_s_54_pre_ene":
        "surface IC on 21-char fragment; not cipher evidence",
    "e_s_59_width7_nonperiodic":
        "self-reports NO SIGNAL; composite metric not on 0-24 crib scale",
    "e_s_61_noncolumnar_width7":
        "18/24 at period 12-14 is the underdetermination false-positive regime "
        "(random ~18-19/24 at period>=num_cribs/constraints_per_residue); no Bean pass",
    "e_s_77_hill_anomaly":
        "mislabeled SIGNAL; max 5/24 is deep noise",
    "e_sanborn_error_beaufort_sensitivity":
        "65K mutations, max 6/24, uniform near-noise distribution",
    "f_fleissner_q2_autokey_v1":
        "doubly invalidated: retired consensus_17 null palette + autokey (impossible)",
    "f_vic_nonstandard_keyschedule_v1":
        "VIC family is DO NOT TEST (52M+ configs noise); 10/24 below SIGNAL",
    "full_vic_pipeline_k4":
        "full VIC pipeline is DO NOT TEST per MEMORY.md; 10/24 below SIGNAL",
    "inclinare_stacked_null_mask":
        "directly uses retired {B,G,I,K,O,W,Z} palette; April 2026 retirement",
    "k2_numberword_keywords":
        "doubly invalidated: AZ_beau_autokey (impossible) + col7 retired palette",
    "letter_shape_null_correlation":
        "feature-correlation analysis built on retired null palette; April 2026 retirement",
    "vic_lineh_k2_direct":
        "VIC family DO NOT TEST; 10/24 below SIGNAL",
    "vic_ndyar_keygroup":
        "VIC family DO NOT TEST; free 12/24 below SIGNAL under multiple-testing",
    "e_opgold_berlin_tunnel_v2":
        "all 14/24 top hits from col7_null_sa phase using retired consensus mask",
    "e_s_60_coordinate_date_keys":
        "source script marked DEPRECATED at line 10; not palette-dependent but retired",
    "k2_checkerboard_decode":
        "free=11 with fixed=2 is random 2-letter substring matching in 81-char decode; "
        "checkerboard family in DO NOT TEST scope",
    "straddling_checkerboard_k4":
        "checkerboard family in DO NOT TEST scope; free=10 / fixed=7 below SIGNAL",
}


def main():
    updated = 0
    missing = []
    for name, reason in RECLASSIFY.items():
        path = RESULTS / f"{name}.json"
        if not path.exists():
            missing.append(name)
            continue
        with path.open() as f:
            d = json.load(f)
        prior = d.get("verdict")
        if prior and isinstance(prior, str) and prior.startswith("ELIMINATED"):
            print(f"  skip (already eliminated): {name}")
            continue
        d["verdict_previous"] = prior
        d["verdict"] = f"{STAMP}: {reason}"
        with path.open("w") as f:
            json.dump(d, f, indent=2)
        updated += 1
        print(f"  updated: {name}")
    print()
    print(f"Updated {updated}/{len(RECLASSIFY)} result files")
    if missing:
        print(f"Missing: {missing}")
        sys.exit(1)


if __name__ == "__main__":
    main()
