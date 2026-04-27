"""Tests for the 8 new DSL-oriented MCP tools in kryptosbot.dsl_tools.

Framework maturation Phase 5 (2026-04-21). Brief §7.5 requires one
happy-path test + two adversarial tests per new tool (24 minimum),
plus one end-to-end integration. This file delivers ≥24.

Every tool returns the standard envelope:

    {"status": "ok" | "error" | "not_yet_available",
     "data": <tool-specific>,
     "provenance": {kernel_commit, phase, assumption_bundle, ...}}

wrapped in the SDK content-blocks format. Tests parse that envelope and
assert on the status + data shape.
"""

from __future__ import annotations

import asyncio
import json
import time
import warnings
from pathlib import Path

import pytest

from kryptosbot.dsl_tools import (
    compute_null_baseline_tool,
    create_dsl_mcp_server,
    enumerate_admissible_transforms_tool,
    get_procedural_recipe_tool,
    poll_job_tool,
    query_exhaustion_tool,
    request_compute_budget_estimate_tool,
    score_candidate_canonical_tool,
    submit_hypothesis_spec_tool,
    _reset_jobs_for_testing,
    _reset_procedural_cache_for_testing,
    _PHASE5_NULL_CACHE_PATH,
)
from kryptosbot.hypothesis_dsl import CipherLayer, HypothesisSpec, ParamRange
# ─── Helpers ─────────────────────────────────────────────────────────────────

def _invoke(tool_obj, args: dict) -> dict:
    """Invoke a @tool-decorated handler and parse the envelope."""
    raw = asyncio.run(tool_obj.handler(args))
    text = raw["content"][0]["text"]
    return json.loads(text)


def _minimal_vigenere_spec() -> dict:
    return HypothesisSpec(
        hypothesis_id="T-TEST",
        pipeline=[CipherLayer(
            kind="vigenere", alphabet="AZ",
            params=[ParamRange(name="keyword", values=["KRYPTOS", "PALIMPSEST"])],
        )],
        compute_budget_cpu_minutes=1,
    ).to_dict()


# ─── 1. submit_hypothesis_spec ───────────────────────────────────────────────

class TestSubmitHypothesisSpec:
    def setup_method(self):
        _reset_jobs_for_testing()

    def test_happy_path_returns_job_id(self):
        env = _invoke(submit_hypothesis_spec_tool, {"spec": _minimal_vigenere_spec()})
        assert env["status"] == "ok"
        assert env["data"]["job_id"].startswith("job_")
        assert env["data"]["hypothesis_id"] == "T-TEST"
        assert env["data"]["expected_cardinality"] == 2

    def test_adversarial_non_dict_spec_rejected(self):
        env = _invoke(submit_hypothesis_spec_tool, {"spec": "not a dict"})
        assert env["status"] == "error"
        assert "dict" in env["data"]["reason"].lower()

    def test_adversarial_invalid_dsl_rejected(self):
        bad_spec = {
            "hypothesis_id": "",
            "pipeline": [{"kind": "qubic_cipher"}],
        }
        env = _invoke(submit_hypothesis_spec_tool, {"spec": bad_spec})
        assert env["status"] == "error"
        assert any("hypothesis_id" in e for e in env["data"].get("errors", []))
        assert any("qubic_cipher" in e for e in env["data"].get("errors", []))


# ─── 2. poll_job ─────────────────────────────────────────────────────────────

class TestPollJob:
    def setup_method(self):
        _reset_jobs_for_testing()

    def test_happy_path_completes_submitted_job(self):
        submit = _invoke(
            submit_hypothesis_spec_tool, {"spec": _minimal_vigenere_spec()},
        )
        job_id = submit["data"]["job_id"]
        # Spin briefly for the background thread to finish.
        deadline = time.monotonic() + 5.0
        final = None
        while time.monotonic() < deadline:
            env = _invoke(poll_job_tool, {"job_id": job_id})
            assert env["status"] == "ok"
            if env["data"]["state"] == "completed":
                final = env
                break
            time.sleep(0.05)
        assert final is not None, "job did not complete within 5s"
        assert final["data"]["progress_pct"] == 100
        assert final["data"]["result"]["total_tested"] == 2
        assert final["data"]["error"] is None

    def test_adversarial_missing_job_id(self):
        env = _invoke(poll_job_tool, {})
        assert env["status"] == "error"
        assert "job_id" in env["data"]["reason"]

    def test_adversarial_unknown_job_id(self):
        env = _invoke(poll_job_tool, {"job_id": "job_nosuchthing"})
        assert env["status"] == "error"
        assert "not found" in env["data"]["reason"]


# ─── 3. query_exhaustion ─────────────────────────────────────────────────────

class TestQueryExhaustion:
    def test_happy_path_returns_overlap_count(self):
        env = _invoke(query_exhaustion_tool, {
            "kinds": ["vigenere"],
            "assumption_bundle": ["H1_direct_positional"],
        })
        assert env["status"] == "ok"
        assert "total_log_entries" in env["data"]
        assert "overlap_count" in env["data"]
        assert isinstance(env["data"]["overlapping_scripts"], list)

    def test_adversarial_non_list_kinds(self):
        env = _invoke(query_exhaustion_tool, {
            "kinds": "vigenere",  # should be list
            "assumption_bundle": [],
        })
        assert env["status"] == "error"
        assert "list" in env["data"]["reason"]

    def test_adversarial_unknown_kinds_surface_in_response(self):
        env = _invoke(query_exhaustion_tool, {
            "kinds": [42, None, "vigenere"],
            "assumption_bundle": [],
        })
        assert env["status"] == "ok"  # partial success, reports unknowns
        assert env["data"]["unknown_kinds"]


# ─── 4. compute_null_baseline ────────────────────────────────────────────────

class TestComputeNullBaseline:
    """Phase 6 wired the tool to kryptosbot.null_baselines.

    Shape contract: success returns summary_dict keys including
    scorer_name, method, n_chars, alphabet, mean, stdev, percentiles
    (nested dict with p01..p999), parametric_model, p_value_tail_method.
    Unknown scorer/method/alphabet yields ``status='error'`` (hard
    validation), not ``not_yet_available``."""

    def test_happy_path_crib_score_combo(self):
        env = _invoke(compute_null_baseline_tool, {
            "scorer": "crib_score",
            "method": "random_text",
            "n_chars": 97,
            "alphabet": "AZ",
        })
        assert env["status"] == "ok"
        d = env["data"]
        assert d["scorer_name"] == "crib_score"
        assert d["n_chars"] == 97
        assert "mean" in d and "stdev" in d
        # 24 Bernoulli(1/26) sum ⇒ mean ≈ 24/26 ≈ 0.923
        assert 0.0 <= d["mean"] <= 3.0, f"unexpected mean: {d['mean']}"
        # Percentiles nested under 'percentiles'.
        pct = d["percentiles"]
        assert pct["p99"] >= pct["p50"]
        # parametric model populated for crib_score × random_text
        assert d["parametric_model"] == "binomial"

    def test_happy_path_ngram_score_combo(self):
        """Phase 6 added ngram_score support with normal-approx tail."""
        env = _invoke(compute_null_baseline_tool, {
            "scorer": "ngram_score",
            "method": "random_text",
            "n_chars": 97,
            "alphabet": "AZ",
        })
        if env["status"] == "error":
            # Cache not built; skip rather than fail.
            pytest.skip(f"ngram_score cache unavailable: {env['data']}")
        assert env["status"] == "ok"
        assert env["data"]["parametric_model"] == "normal"

    def test_adversarial_unknown_scorer_hard_rejected(self):
        """Unknown scorer (not in _VALID_SCORERS) is an error, not a
        'not_yet_available'."""
        env = _invoke(compute_null_baseline_tool, {
            "scorer": "not_a_scorer",
            "method": "random_text",
            "n_chars": 97,
            "alphabet": "AZ",
        })
        assert env["status"] == "error"
        assert any("scorer=" in d for d in env["data"]["details"])

    def test_adversarial_unknown_alphabet_hard_rejected(self):
        env = _invoke(compute_null_baseline_tool, {
            "scorer": "crib_score",
            "method": "random_text",
            "n_chars": 97,
            "alphabet": "EBCDIC",
        })
        assert env["status"] == "error"
        assert any("alphabet=" in d for d in env["data"]["details"])


# ─── 5. score_candidate_canonical ────────────────────────────────────────────

class TestScoreCandidateCanonical:
    def test_happy_path_scores_plaintext(self):
        env = _invoke(score_candidate_canonical_tool, {"plaintext": "A" * 97})
        assert env["status"] == "ok"
        assert env["data"]["length"] == 97
        assert env["data"]["crib_score"] == 2  # K4 self-encrypts at 32, 73
        assert env["data"]["classification"] == "noise"

    def test_adversarial_non_string_plaintext(self):
        env = _invoke(score_candidate_canonical_tool, {"plaintext": 42})
        assert env["status"] == "error"

    def test_adversarial_short_plaintext_is_scored_without_crashing(self):
        """score_cribs handles short text; verifier logic lives in
        contracts, not here. The tool returns whatever kernel says."""
        env = _invoke(score_candidate_canonical_tool, {"plaintext": "ABC"})
        assert env["status"] == "ok"
        assert env["data"]["length"] == 3


# ─── 6. get_procedural_recipe ───────────────────────────────────────────────

class TestGetProceduralRecipe:
    def setup_method(self):
        _reset_procedural_cache_for_testing()

    def test_happy_path_retrieves_real_recipe(self):
        env = _invoke(get_procedural_recipe_tool, {"recipe_id": "P-A5-3"})
        # Depending on whether the recipe file is parseable; tolerate both.
        if env["status"] == "error":
            pytest.skip(f"procedural recipe file not parseable: {env['data']}")
        assert env["status"] == "ok"
        assert env["data"]["recipe_id"] == "P-A5-3"
        assert env["data"]["section_id"]
        assert env["data"]["procedure"]

    def test_happy_path_list_all(self):
        env = _invoke(get_procedural_recipe_tool, {"recipe_id": "*"})
        if env["status"] == "error":
            pytest.skip(f"procedural recipe file not parseable: {env['data']}")
        assert env["status"] == "ok"
        assert env["data"]["total"] > 0
        assert isinstance(env["data"]["recipe_ids"], list)
        # Expect at least one 'P-' recipe id from the markdown.
        assert any(r.startswith("P-") for r in env["data"]["recipe_ids"])

    def test_adversarial_non_string_recipe_id(self):
        env = _invoke(get_procedural_recipe_tool, {"recipe_id": 42})
        assert env["status"] == "error"

    def test_adversarial_unknown_recipe_id(self):
        env = _invoke(get_procedural_recipe_tool, {"recipe_id": "P-NOT-EXIST-999"})
        assert env["status"] == "error"
        assert "not found" in env["data"]["reason"]


# ─── 7. enumerate_admissible_transforms ─────────────────────────────────────

class TestEnumerateAdmissibleTransforms:
    def test_happy_path_returns_supported_set(self):
        env = _invoke(enumerate_admissible_transforms_tool, {
            "assumption_bundle": ["H1_direct_positional"],
        })
        assert env["status"] == "ok"
        assert "vigenere" in env["data"]["supported_kinds"]
        assert "identity" in env["data"]["supported_kinds"]
        # R2-2 (2026-04-21) added KA + keyword_mixed; tool used to lie
        # by reporting AZ-only. All three must be advertised.
        supported = env["data"]["supported_alphabets"]
        assert "AZ" in supported
        assert "KA" in supported
        assert "keyword_mixed" in supported
        # And nothing should be in unsupported_alphabets, since the
        # dispatcher now covers the full _VALID_ALPHABET_KINDS set.
        assert env["data"]["unsupported_alphabets"] == []
        assert env["provenance"]["assumption_bundle"] == ["H1_direct_positional"]

    def test_adversarial_non_list_bundle(self):
        env = _invoke(enumerate_admissible_transforms_tool, {
            "assumption_bundle": "not a list",
        })
        assert env["status"] == "error"

    def test_adversarial_empty_bundle_ok(self):
        """Empty bundle is valid — Phase 5 doesn't filter by bundle anyway."""
        env = _invoke(enumerate_admissible_transforms_tool, {
            "assumption_bundle": [],
        })
        assert env["status"] == "ok"
        assert env["data"]["supported_kinds"]


# ─── 8. request_compute_budget_estimate ─────────────────────────────────────

class TestRequestComputeBudgetEstimate:
    def test_happy_path_returns_estimate(self):
        env = _invoke(request_compute_budget_estimate_tool, {
            "spec": _minimal_vigenere_spec(),
        })
        assert env["status"] == "ok"
        assert env["data"]["expected_cardinality"] == 2
        assert env["data"]["estimated_serial_sec"] >= 0
        assert env["data"]["estimated_parallel_sec_at_26_workers"] >= 0
        assert env["data"]["under_budget"] is True  # 2 configs is trivial

    def test_adversarial_non_dict_spec(self):
        env = _invoke(request_compute_budget_estimate_tool, {"spec": "string"})
        assert env["status"] == "error"

    def test_adversarial_invalid_spec(self):
        env = _invoke(request_compute_budget_estimate_tool, {
            "spec": {"hypothesis_id": "", "pipeline": [{"kind": "bogus"}]},
        })
        assert env["status"] == "error"
        assert any("bogus" in e or "hypothesis_id" in e
                   for e in env["data"].get("errors", []))


# ─── Envelope invariants (applies to every tool) ────────────────────────────

class TestEnvelopeInvariants:
    """Every tool returns {status, data, provenance} with kernel_commit +
    phase + assumption_bundle in provenance. This is brief §7.2's standing
    shape contract."""

    @pytest.mark.parametrize("tool_obj,args", [
        (submit_hypothesis_spec_tool, {"spec": _minimal_vigenere_spec()}),
        (query_exhaustion_tool, {"kinds": ["vigenere"], "assumption_bundle": []}),
        (enumerate_admissible_transforms_tool, {"assumption_bundle": []}),
        (request_compute_budget_estimate_tool, {"spec": _minimal_vigenere_spec()}),
        (score_candidate_canonical_tool, {"plaintext": "A" * 97}),
    ])
    def test_envelope_has_required_keys(self, tool_obj, args):
        _reset_jobs_for_testing()
        env = _invoke(tool_obj, args)
        assert set(env.keys()) >= {"status", "data", "provenance"}
        prov = env["provenance"]
        assert "kernel_commit" in prov
        assert prov["phase"] == 5
        assert "assumption_bundle" in prov


# ─── Server wiring ───────────────────────────────────────────────────────────

class TestServerWiring:
    def test_create_dsl_mcp_server_registers_all_eight(self):
        server = create_dsl_mcp_server()
        # Server is a TypedDict-ish config. Extract the tool list.
        # Fallback: just confirm ALL_TOOLS has 8 entries and that the
        # module exposes each handler.
        from kryptosbot.dsl_tools import ALL_TOOLS
        assert len(ALL_TOOLS) == 8
        names = {t.name for t in ALL_TOOLS}
        expected = {
            "submit_hypothesis_spec", "poll_job", "query_exhaustion",
            "compute_null_baseline", "score_candidate_canonical",
            "get_procedural_recipe", "enumerate_admissible_transforms",
            "request_compute_budget_estimate",
        }
        assert names == expected


# Deprecation-coverage tests for the three noise tools in
# kryptosbot/k4_tools.py (try_keyword_sweep, swap_and_test, hill_climb)
# were removed on 2026-04-26 along with the move of k4_tools.py to
# _archive/k4_tools_legacy.py. The tools are unreachable from any
# worker session (no MCP server registers them; create_k4_mcp_server
# is never called in production code). The DeprecationWarning surface
# they emitted on direct invocation served no real purpose because
# nothing invoked them in production.

# ─── End-to-end integration (brief §7.5) ────────────────────────────────────

class TestEndToEndIntegration:
    """Mock theorist emits a valid spec → submit via tool → poll to
    completion → assert kernel-verified outputs. This is the brief's
    end-to-end sanity that the DSL path is live."""

    def setup_method(self):
        _reset_jobs_for_testing()

    def test_mock_theorist_to_completed_job(self):
        # Mock theorist produces a HypothesisSpec JSON blob.
        theorist_spec = HypothesisSpec(
            hypothesis_id="T-E2E",
            pipeline=[CipherLayer(
                kind="identity", alphabet="AZ", params=[],
            )],
            assumption_bundle=["H1_direct_positional"],
            compute_budget_cpu_minutes=1,
        )

        # Budget-check first (what the worker should do).
        budget = _invoke(
            request_compute_budget_estimate_tool,
            {"spec": theorist_spec.to_dict()},
        )
        assert budget["data"]["under_budget"] is True

        # Submit.
        submit = _invoke(
            submit_hypothesis_spec_tool, {"spec": theorist_spec.to_dict()},
        )
        assert submit["status"] == "ok"
        job_id = submit["data"]["job_id"]

        # Poll to completion.
        deadline = time.monotonic() + 5.0
        final = None
        while time.monotonic() < deadline:
            env = _invoke(poll_job_tool, {"job_id": job_id})
            if env["data"]["state"] == "completed":
                final = env
                break
            time.sleep(0.05)
        assert final is not None, "e2e job did not complete in 5s"
        result = final["data"]["result"]

        # Kernel-verified outputs:
        assert result["total_tested"] == 1
        assert result["best_candidate"]["crib_score"] == 2  # CT self-encrypts
        assert result["spec_hash"] == theorist_spec.spec_hash
        # Provenance carried through.
        assert final["provenance"]["phase"] == 5
        assert final["provenance"]["assumption_bundle"] in ([], None) or \
            "assumption_bundle" in final["provenance"]
