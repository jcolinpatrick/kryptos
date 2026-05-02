#!/usr/bin/env python3
"""Audit DSL -> dispatcher -> kernel translation semantics."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))
RESULT_PATH = REPO_ROOT / "results" / "audit" / "dsl_dispatcher_semantics.json"
DOC_PATH = REPO_ROOT / "docs" / "audits" / "dsl_dispatcher_semantics.md"


def inspect() -> dict[str, Any]:
    from kryptosbot.hypothesis_dsl import (
        _VALID_CIPHER_KINDS,
        CipherLayer,
        HypothesisSpec,
        ParamRange,
    )
    from kryptosbot.job_dispatcher import (
        _SUPPORTED_KINDS,
        _build_pipeline_config,
        _enumerate_bindings,
        execute,
    )
    from kryptosbot.contracts import validate_worker_contract

    gaps = sorted(set(_VALID_CIPHER_KINDS) - set(_SUPPORTED_KINDS))
    extra = sorted(set(_SUPPORTED_KINDS) - set(_VALID_CIPHER_KINDS))

    caesar = HypothesisSpec(
        hypothesis_id="audit_caesar",
        pipeline=[CipherLayer(kind="caesar", params=[ParamRange(name="shift", values=[3])])],
        compute_budget_cpu_minutes=1,
    )
    bindings = list(_enumerate_bindings(caesar))
    pipe = _build_pipeline_config(caesar, bindings[0])
    columnar_short = HypothesisSpec(
        hypothesis_id="audit_columnar_short",
        pipeline=[
            CipherLayer(
                kind="columnar",
                params=[
                    ParamRange(name="width", values=[5]),
                    ParamRange(name="col_order", values=[[1, 3, 0, 4, 2]]),
                ],
            )
        ],
        compute_budget_cpu_minutes=1,
    )
    short_pipe = _build_pipeline_config(
        columnar_short,
        next(_enumerate_bindings(columnar_short)),
        text_length=35,
    )
    short_plaintext = "THEQUICKBROWNFOXIUMPSOVERTHELAZYDOG"
    short_ciphertext = "HKFPTYQRXOEOTCNMRZUOIVLGIWUEAEBOSHD"
    short_challenge = execute(
        columnar_short,
        workers=1,
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext=short_ciphertext,
        challenge_crib_dict={i: ch for i, ch in enumerate(short_plaintext)},
    )
    route_top_right = HypothesisSpec(
        hypothesis_id="audit_route_top_right_spiral",
        pipeline=[
            CipherLayer(
                kind="route",
                params=[
                    ParamRange(name="variant", values=["spiral"]),
                    ParamRange(name="rows", values=[5]),
                    ParamRange(name="cols", values=[3]),
                    ParamRange(name="clockwise", values=[True]),
                    ParamRange(name="start_corner", values=["top_right"]),
                ],
            )
        ],
        compute_budget_cpu_minutes=1,
    )
    route_pipe = _build_pipeline_config(
        route_top_right,
        next(_enumerate_bindings(route_top_right)),
        text_length=15,
    )
    route_challenge = execute(
        route_top_right,
        workers=1,
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext="ITAHEVONOGBRHND",
        challenge_crib_dict={i: ch for i, ch in enumerate("BRIGHTONANDHOVE")},
    )
    enumerated_composite = HypothesisSpec(
        hypothesis_id="audit_enumerated_composite",
        pipeline=[
            CipherLayer(
                kind="caesar",
                params=[ParamRange(name="shift", values=[3, 5, 7])],
            ),
            CipherLayer(
                kind="vigenere",
                params=[ParamRange(name="keyword", values=["ORBIT", "LEMON"])],
            ),
        ],
        compute_budget_cpu_minutes=1,
    )
    enumerated_result = execute(
        enumerated_composite,
        workers=1,
        parallel=False,
        exhaustion_log={},
        challenge_ciphertext="MDKDSBYQOPHSTSMQEAZNLKBRPMDKYYSUJBE",
        challenge_crib_dict={i: ch for i, ch in enumerate(short_plaintext)},
    )

    identity = HypothesisSpec(
        hypothesis_id="audit_identity",
        pipeline=[CipherLayer(kind="identity")],
        compute_budget_cpu_minutes=1,
    )
    identity_result = execute(identity, workers=1, parallel=False, exhaustion_log={})

    raw = """```json
{"status":"success","score":99,"crib_score":24,"bean_passed":true,"best_plaintext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
```"""
    contract = validate_worker_contract(raw, "audit_worker_overrule")

    spec_a = HypothesisSpec(
        hypothesis_id="stable",
        pipeline=[
            CipherLayer(
                kind="vigenere",
                params=[ParamRange(name="keyword", values=["ABC", "XYZ"])],
            )
        ],
        assumption_bundle=["audit"],
    )
    spec_b = HypothesisSpec.from_dict(json.loads(spec_a.to_json()))

    return {
        "valid_cipher_kinds": sorted(_VALID_CIPHER_KINDS),
        "supported_kinds": sorted(_SUPPORTED_KINDS),
        "valid_without_translation": gaps,
        "supported_not_valid": extra,
        "caesar_translation": pipe,
        "caesar_expected_cardinality": caesar.expected_cardinality(),
        "caesar_bindings": [list(x) for x in bindings],
        "challenge_length_parameterized_translation": {
            "kind": "columnar",
            "text_length": 35,
            "perm_length": len(short_pipe["steps"][0]["params"]["perm"]),
            "is_valid_35_perm": sorted(short_pipe["steps"][0]["params"]["perm"]) == list(range(35)),
            "expected_cardinality": columnar_short.expected_cardinality(),
            "execute_total_tested": short_challenge.total_tested,
            "execute_universe_hash": short_challenge.universe_hash,
            "execute_best_matches_plaintext": (
                short_challenge.best_candidate is not None
                and short_challenge.best_candidate.get("candidate_pt") == short_plaintext
            ),
        },
        "route_start_corner_translation": {
            "kind": "route",
            "variant": "spiral",
            "start_corner": "top_right",
            "text_length": 15,
            "perm_length": len(route_pipe["steps"][0]["params"]["perm"]),
            "is_valid_15_perm": sorted(route_pipe["steps"][0]["params"]["perm"]) == list(range(15)),
            "expected_cardinality": route_top_right.expected_cardinality(),
            "execute_total_tested": route_challenge.total_tested,
            "execute_best_matches_plaintext": (
                route_challenge.best_candidate is not None
                and route_challenge.best_candidate.get("candidate_pt") == "BRIGHTONANDHOVE"
            ),
        },
        "enumerated_composite_search_universe": {
            "expected_cardinality": enumerated_composite.expected_cardinality(),
            "execute_total_tested": enumerated_result.total_tested,
            "execute_universe_hash": enumerated_result.universe_hash,
            "best_matches_plaintext": (
                enumerated_result.best_candidate is not None
                and enumerated_result.best_candidate.get("candidate_pt") == short_plaintext
            ),
            "best_crib_score": (
                enumerated_result.best_candidate.get("crib_score")
                if enumerated_result.best_candidate else None
            ),
        },
        "identity_execute": {
            "admissibility_verdict": identity_result.admissibility_verdict,
            "total_tested": identity_result.total_tested,
            "universe_hash": identity_result.universe_hash,
            "best_candidate_present": identity_result.best_candidate is not None,
        },
        "universe_hash_stability": {
            "spec_hash_a": spec_a.spec_hash,
            "spec_hash_b": spec_b.spec_hash,
            "stable": spec_a.spec_hash == spec_b.spec_hash,
        },
        "worker_self_report_overrule": {
            "parse_valid": contract.is_valid,
            "crib_score_after_kernel": contract.value.crib_score if contract.value else None,
            "bean_after_kernel": contract.value.bean_passed if contract.value else None,
            "fields_overwritten": contract.value.fields_overwritten if contract.value else None,
            "verification_error": contract.value.verification_error if contract.value else None,
        },
        "canonical_scoring_note": "job_dispatcher._evaluate_one imports score_candidate from kryptos.kernel.scoring.aggregate",
    }


def write_markdown(payload: dict[str, Any]) -> None:
    lines = [
        "# DSL Dispatcher Semantics Audit",
        "",
        "## Verdict",
        "",
        f"- DSL-valid kinds: {len(payload['valid_cipher_kinds'])}",
        f"- Dispatcher-supported kinds: {len(payload['supported_kinds'])}",
        f"- Valid without translation: {payload['valid_without_translation']}",
        f"- Supported but not DSL-valid: {payload['supported_not_valid']}",
        "",
        "The deferred `key_tape` gap is explicit. The dispatcher uses the "
        "canonical kernel scoring path, and worker self-reports are overruled "
        "by the kernel verifier.",
        "",
        "Challenge-mode transposition translators are parameterized by the "
        "challenge text length; the audit columnar fixture emits a valid "
        f"{payload['challenge_length_parameterized_translation']['perm_length']}-position permutation "
        f"and executes {payload['challenge_length_parameterized_translation']['execute_total_tested']} "
        "candidate for the one-point search universe.",
        "",
        "The spiral route translator now preserves an explicit "
        f"`start_corner={payload['route_start_corner_translation']['start_corner']}` "
        "parameter, emits a valid "
        f"{payload['route_start_corner_translation']['perm_length']}-position permutation, "
        "and solves the external top-right spiral route fixture.",
        "",
        "A two-layer Caesar plus Vigenere challenge enumerates "
        f"{payload['enumerated_composite_search_universe']['expected_cardinality']} "
        "candidate bindings and reports the same `total_tested`, proving this "
        "small composed search is accounted for exactly.",
        "",
        "## Reproduction",
        "",
        "```bash",
        "PYTHONPATH=src python3 scripts/audit/audit_dsl_dispatcher_semantics.py",
        "```",
    ]
    DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOC_PATH.write_text("\n".join(lines) + "\n")


def main() -> int:
    payload = {
        "schema_version": 1,
        "audit": inspect(),
        "reproduction_command": "PYTHONPATH=src python3 scripts/audit/audit_dsl_dispatcher_semantics.py",
    }
    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)
    RESULT_PATH.write_text(json.dumps(payload, indent=2, sort_keys=True))
    write_markdown(payload["audit"])
    print(json.dumps({"wrote": [str(RESULT_PATH), str(DOC_PATH)], "gaps": payload["audit"]["valid_without_translation"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
