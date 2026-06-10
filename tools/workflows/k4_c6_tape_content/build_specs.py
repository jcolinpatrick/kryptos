"""Build, validate, and admissibility-check the C6 tape-content sweep specs.

Two specs, split by inner-tape ALPHABET (AZ vs KA), each holding the same
boustrophedon outer (widths {7,14,21,24} x both verticals) and the key_tape
inner with the swept tape axis = 8 public corpus tapes for that alphabet,
variant in {vigenere, beaufort, var_beaufort}.

Per-spec cardinality = (4 widths * 2 verticals) * (8 tapes * 3 variants)
                      = 8 * 24 = 192.
Total across 2 specs = 384 (<= 400).

NOTE on outer-layer alphabet: route_boustrophedon is a pure permutation of CT
positions; its `alphabet` field is irrelevant to the permutation. We keep AZ on
the outer layer in BOTH specs (matching the h35 reference); only the INNER
key_tape alphabet differs between the two specs.
"""

from __future__ import annotations

import json
import os
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, _REPO)
sys.path.insert(0, os.path.join(_REPO, "src"))

from kryptosbot.hypothesis_dsl import validate_hypothesis_spec  # noqa: E402
from kryptosbot.job_dispatcher import check_admissibility  # noqa: E402

_TS = "20260528T232903Z"
_OUT = os.path.join(_REPO, "results", "workflows", "k4_c6_tape_content", _TS)
_SPEC_DIR = os.path.join(_OUT, "specs")

WIDTHS = [7, 14, 21, 24]          # h35 best width 7 + 3 others
VERTICALS = [False, True]
VARIANTS = ["vigenere", "beaufort", "var_beaufort"]


def _load_tapes() -> list[dict]:
    with open(os.path.join(_OUT, "tapes.json")) as fh:
        return json.load(fh)


def _build_spec(spec_id: str, alphabet: str, tapes: list[dict]) -> dict:
    tape_values = [t["values"] for t in tapes]
    return {
        "hypothesis_id": spec_id,
        "family": "key_tape",
        "pipeline": [
            {
                "kind": "route_boustrophedon",
                "alphabet": "AZ",
                "params": [
                    {"name": "width", "values": WIDTHS},
                    {"name": "vertical", "values": VERTICALS},
                ],
            },
            {
                "kind": "key_tape",
                "alphabet": alphabet,
                "params": [
                    {"name": "tape", "values": tape_values},
                    {"name": "variant", "values": VARIANTS},
                ],
            },
        ],
        "crib_alignment": "post_transposition",
        "scoring": "composite",
        "compute_budget_cpu_minutes": 10,
        "assumption_bundle": [
            "outer_boustrophedon_serpentine_route",
            "inner_nonperiodic_finite_public_tape",
            "tape_content_swept_axis",
            "public_source_provenance_only",
            "geometric_alignment_not_ct_extraction",
            "not_H1_direct_positional",
            "bean_inapplicable_by_construction",
        ],
        "notes": (
            f"C6 tape-content sweep; inner alphabet={alphabet}; tapes from "
            f"public K1/K2/K3 PT+CT, K1K2K3 concat, KRYPTOS tableau row-major. "
            f"Tapes derived programmatically by tools/workflows/k4_c6_tape_content/"
            f"gen_tapes.py. Tape ids: {[t['tape_id'] for t in tapes]}"
        ),
    }


def main() -> None:
    os.makedirs(_SPEC_DIR, exist_ok=True)
    tapes = _load_tapes()
    az = [t for t in tapes if t["alphabet"] == "AZ"]
    ka = [t for t in tapes if t["alphabet"] == "KA"]
    assert len(az) == 8 and len(ka) == 8, (len(az), len(ka))

    specs = [
        ("c6tc_az", _build_spec("c6tc_az", "AZ", az)),
        ("c6tc_ka", _build_spec("c6tc_ka", "KA", ka)),
    ]

    total = 0
    for spec_id, spec in specs:
        pr = validate_hypothesis_spec(spec)
        if not pr.is_valid:
            print(f"[INVALID] {spec_id}: {pr.errors}")
            sys.exit(1)
        card = pr.value.expected_cardinality()
        shash = pr.value.spec_hash
        total += card
        # dry admissibility (real-K4: no bench_mode)
        try:
            admissible, reasons = check_admissibility(pr.value)
        except Exception as e:  # noqa: BLE001
            admissible, reasons = None, [f"ERROR: {e!r}"]
        print(f"[OK] {spec_id}: cardinality={card} spec_hash={shash} "
              f"admissible={admissible} reasons={reasons}")
        out_path = os.path.join(_SPEC_DIR, f"spec_{spec_id}.json")
        with open(out_path, "w") as fh:
            json.dump(spec, fh, indent=2)
        print(f"     wrote {out_path}")

    print(f"TOTAL CARDINALITY across {len(specs)} specs = {total} (cap 400)")
    assert total <= 400, total


if __name__ == "__main__":
    main()
