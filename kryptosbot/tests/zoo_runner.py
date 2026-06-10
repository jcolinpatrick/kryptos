"""Suite-assurance Task C — zoo subprocess runner.

Executed as a CHILD process with ``KRYPTOS_CT_OVERRIDE`` +
``KRYPTOS_CRIB_DICT_OVERRIDE`` already present in the environment (set by
the parent BEFORE this interpreter starts, so kernel constants are frozen
to the synthetic fixture at import). Runs the fixture's HypothesisSpec
through the REAL dispatcher (`execute_from_json`) and the REAL contract
boundary (`job_result_to_worker_contract`), then prints an observation
JSON to stdout (single line, prefixed ZOO_RESULT:).

Usage: python zoo_runner.py <fixture_payload.json>
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path


def main() -> int:
    payload = json.loads(Path(sys.argv[1]).read_text())

    # Hard guard: the parent must have installed the overrides; running
    # this against the real kernel would score fixtures against real K4.
    if os.environ.get("KRYPTOS_CT_OVERRIDE") != payload["carved_ct"]:
        print("ZOO_ERROR: KRYPTOS_CT_OVERRIDE missing or mismatched",
              file=sys.stderr)
        return 2

    from kryptos.kernel.constants import CT, CRIB_DICT
    assert CT == payload["carved_ct"]
    assert {str(k): v for k, v in CRIB_DICT.items()} == payload["crib_dict"]

    from kryptosbot.job_dispatcher import (
        execute_from_json, job_result_to_worker_contract,
    )

    result = execute_from_json(
        payload["spec"],
        exhaustion_log={},
        parallel=False,
        artifact_root=Path(tempfile.mkdtemp(prefix="zoo_")),
    )
    contract = job_result_to_worker_contract(result)

    best = result.best_candidate or {}
    obs = {
        "fixture_id": payload["fixture_id"],
        "admissibility_verdict": result.admissibility_verdict,
        "total_tested": result.total_tested,
        "best": {
            "crib_score": best.get("crib_score"),
            "bean_passed": best.get("bean_passed"),
            "bean_variant": best.get("bean_variant"),
            "scoring_mode": best.get("scoring_mode"),
            "canonical_positions": best.get("canonical_positions"),
            "pt_matches_planted": best.get("candidate_pt") == payload["plaintext"],
        },
        "best_config_bindings": result.best_config_bindings,
        "contract": {
            "status": contract.status.value,
            "crib_score": contract.crib_score,
            "bean_passed": contract.bean_passed,
            "bean_variant": contract.bean_variant,
            "fields_overwritten": contract.fields_overwritten,
            "verification_error": contract.verification_error,
        },
    }
    print("ZOO_RESULT:" + json.dumps(obs, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
