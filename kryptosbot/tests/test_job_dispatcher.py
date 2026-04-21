"""Tests for kryptosbot.job_dispatcher.

Framework maturation Phase 4 (2026-04-21). Exercises:
- Admissibility pre-flight (budget, translation gap, exhaustion overlap)
- Layer translation (identity, vigenere, columnar, atbash, unsupported)
- Universe enumeration (cartesian product, empty pipeline, multi-layer)
- End-to-end execute on trivial spec (kernel-verified)
- Deterministic universe_hash across runs
- Deterministic config_id format
- Failing specs short-circuit before touching the pool
- JobResult shape and serialization
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from kryptosbot.hypothesis_dsl import (
    CipherLayer,
    HypothesisSpec,
    ParamRange,
    validate_hypothesis_spec,
)
from kryptosbot.job_dispatcher import (
    DispatcherError,
    JobResult,
    _SUPPORTED_KINDS,
    _enumerate_bindings,
    _translate_layer,
    _universe_hash,
    check_admissibility,
    execute,
    execute_from_json,
    job_result_to_worker_contract,
)
from kryptosbot.models import WorkerStatus


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _tmp_artifact_root(tmp_path: Path) -> Path:
    (tmp_path / "results" / "dsl_jobs").mkdir(parents=True, exist_ok=True)
    return tmp_path / "results" / "dsl_jobs"


def _identity_spec() -> HypothesisSpec:
    return HypothesisSpec(
        hypothesis_id="T-IDENT",
        pipeline=[CipherLayer(kind="identity")],
        compute_budget_cpu_minutes=1,
    )


def _vigenere_spec(keywords=("PALIMPSEST", "ABSCISSA")) -> HypothesisSpec:
    return HypothesisSpec(
        hypothesis_id="T-VIG",
        pipeline=[CipherLayer(
            kind="vigenere", alphabet="AZ",
            params=[ParamRange(name="keyword", values=list(keywords))],
        )],
        compute_budget_cpu_minutes=1,
    )


# ─── Admissibility ───────────────────────────────────────────────────────────

class TestAdmissibility:
    def test_valid_identity_spec_admissible(self):
        admissible, reasons = check_admissibility(_identity_spec(), exhaustion_log={})
        assert admissible is True
        assert reasons == []

    def test_valid_vigenere_spec_admissible(self):
        admissible, reasons = check_admissibility(_vigenere_spec(), exhaustion_log={})
        assert admissible is True
        assert reasons == []

    def test_dsl_validation_errors_surface_as_admissibility_reasons(self):
        spec = HypothesisSpec(hypothesis_id="")  # invalid
        admissible, reasons = check_admissibility(spec, exhaustion_log={})
        assert admissible is False
        assert any("hypothesis_id" in r for r in reasons)

    def test_unsupported_kind_rejected_with_pointer(self):
        """A DSL-valid but dispatcher-unsupported kind must fail
        admissibility with a clear pointer. Pre-R3-0.5 used polybius
        as the exemplar; R3-0.5-3 wired polybius so this test now
        uses rail_fence — still in the DSL literal, still lacking a
        translator. Any kind in _VALID_CIPHER_KINDS but not in
        _SUPPORTED_KINDS is a valid exemplar here."""
        spec = HypothesisSpec(
            hypothesis_id="T", pipeline=[CipherLayer(kind="rail_fence")],
            compute_budget_cpu_minutes=1,
        )
        admissible, reasons = check_admissibility(spec, exhaustion_log={})
        assert admissible is False
        assert any(
            "rail_fence" in r and "no dispatcher translation" in r
            for r in reasons
        )

    def test_cardinality_over_budget_rejected(self):
        """Spec with 10M configs × 1 min budget should be rejected."""
        spec = HypothesisSpec(
            hypothesis_id="T",
            pipeline=[CipherLayer(
                kind="vigenere",
                params=[ParamRange(name="keyword", values=["K"])],
            )],
            compute_budget_cpu_minutes=1,
        )
        # Force cardinality past the budget by overriding the values.
        spec.pipeline[0].params[0].values = ["K"] * 500_000
        spec.pipeline[0].params[0].cardinality_cap = 1_000_000  # allow DSL validation
        admissible, reasons = check_admissibility(spec, exhaustion_log={})
        assert admissible is False
        assert any("exceeds budget" in r for r in reasons)

    def test_exhaustion_overlap_surfaces_advisory(self):
        """A vigenere spec overlaps with exhausted entries tagged 'vigenere'."""
        spec = _vigenere_spec()
        log = {
            "some_old_script": {
                "family": "polyalphabetic/vigenere",
                "status": "exhausted",
                "audit_reason": "no signal",
                "description": "old vig scan",
            }
        }
        admissible, reasons = check_admissibility(spec, exhaustion_log=log)
        # Overlap is advisory; the spec remains non-admissible so the
        # caller surfaces the overlap explicitly.
        assert admissible is False
        assert any("exhaustion overlap" in r for r in reasons)

    def test_empty_exhaustion_log_no_false_overlap(self):
        spec = _vigenere_spec()
        admissible, reasons = check_admissibility(spec, exhaustion_log={})
        assert admissible is True


# ─── Layer translation ──────────────────────────────────────────────────────

class TestLayerTranslation:
    def test_identity_layer_translates(self):
        step = _translate_layer(CipherLayer(kind="identity"), {})
        assert step["type"] == "identity"
        assert step["params"] == {}

    def test_vigenere_requires_keyword(self):
        with pytest.raises(DispatcherError, match="'keyword' parameter"):
            _translate_layer(CipherLayer(kind="vigenere"), {})

    def test_vigenere_keyword_maps_to_az_indices(self):
        step = _translate_layer(
            CipherLayer(kind="vigenere", alphabet="AZ"),
            {"keyword": "ABC"},
        )
        assert step["type"] == "vigenere"
        assert step["params"]["key"] == [0, 1, 2]
        assert step["params"]["direction"] == "decrypt"

    def test_vigenere_ka_alphabet_translates_after_r2_2(self):
        """R2-2 (2026-04-21) added KA alphabet support. The keyword's
        key-indices are resolved in KA's ordering, not AZ's. 'K' in KA
        has index 0; 'R' has index 1; 'A' has index 7 (first letter
        after KRYPTOS)."""
        step = _translate_layer(
            CipherLayer(kind="vigenere", alphabet="KA"),
            {"keyword": "KRA"},
        )
        assert step["type"] == "vigenere"
        # K -> 0, R -> 1, A -> 7 in KRYPTOSABCD...
        assert step["params"]["key"] == [0, 1, 7]
        assert step["params"]["alphabet_sequence"] == (
            "KRYPTOSABCDEFGHIJLMNQUVWXZ"
        )
        assert step["params"]["alphabet_label"] == "KA"

    def test_beaufort_and_variant_beaufort_translate(self):
        for kind in ("beaufort", "variant_beaufort"):
            step = _translate_layer(
                CipherLayer(kind=kind, alphabet="AZ"),
                {"keyword": "KEY"},
            )
            assert step["type"] in ("beaufort", "var_beaufort")
            assert step["params"]["key"] == [10, 4, 24]

    def test_columnar_translates_with_perm(self):
        step = _translate_layer(
            CipherLayer(kind="columnar"),
            {"width": 5, "col_order": [2, 0, 4, 1, 3]},
        )
        assert step["type"] == "transposition_full"
        assert step["params"]["direction"] == "undo"
        # perm should have length 97 (CT_LEN)
        assert len(step["params"]["perm"]) == 97

    def test_columnar_rejects_non_permutation(self):
        with pytest.raises(DispatcherError, match="not a permutation"):
            _translate_layer(
                CipherLayer(kind="columnar"),
                {"width": 5, "col_order": [0, 0, 1, 2, 3]},
            )

    def test_atbash_translates_to_beaufort_with_fixed_key(self):
        step = _translate_layer(CipherLayer(kind="atbash"), {})
        assert step["type"] == "beaufort"
        assert step["params"]["key"] == [25]


# ─── Universe enumeration ───────────────────────────────────────────────────

class TestUniverseEnumeration:
    def test_empty_pipeline_yields_one_empty_binding(self):
        spec = HypothesisSpec(hypothesis_id="T")
        bindings = list(_enumerate_bindings(spec))
        assert bindings == [()]

    def test_identity_pipeline_yields_one_empty_binding(self):
        bindings = list(_enumerate_bindings(_identity_spec()))
        assert bindings == [()]

    def test_single_param_enumeration(self):
        spec = _vigenere_spec(keywords=("A", "B", "C"))
        bindings = list(_enumerate_bindings(spec))
        assert len(bindings) == 3
        assert ("layer0.keyword", "A") in bindings[0]

    def test_cartesian_across_layers(self):
        """Two layers with 2 and 3 params respectively → 6 bindings."""
        spec = HypothesisSpec(
            hypothesis_id="T",
            pipeline=[
                CipherLayer(
                    kind="columnar",
                    params=[ParamRange(name="width", start=5, stop=7)],  # 2
                ),
                CipherLayer(
                    kind="vigenere",
                    params=[ParamRange(name="keyword", values=["X", "Y", "Z"])],  # 3
                ),
            ],
        )
        bindings = list(_enumerate_bindings(spec))
        assert len(bindings) == 2 * 3
        # First binding should touch both layers.
        b0_keys = {k for k, v in bindings[0]}
        assert "layer0.width" in b0_keys
        assert "layer1.keyword" in b0_keys

    def test_universe_hash_is_deterministic(self):
        ids = [f"cfg_{i}" for i in range(10)]
        h1 = _universe_hash("abcd1234", ids)
        h2 = _universe_hash("abcd1234", ids[::-1])  # reverse order
        assert h1 == h2, "universe_hash must not depend on input order"

    def test_universe_hash_changes_on_material_change(self):
        h1 = _universe_hash("abcd1234", ["a", "b", "c"])
        h2 = _universe_hash("abcd1234", ["a", "b", "d"])
        assert h1 != h2


# ─── End-to-end execute ──────────────────────────────────────────────────────

class TestExecuteEndToEnd:
    def test_identity_spec_runs_and_scores(self, tmp_path: Path):
        """Pipeline is identity → candidate == CT → score_candidate returns
        the CT's own crib match count (2 from self-encrypting positions)."""
        spec = _identity_spec()
        result = execute(
            spec,
            artifact_root=_tmp_artifact_root(tmp_path),
            parallel=False,
            exhaustion_log={},
        )
        assert result.admissibility_verdict == "ok"
        assert result.total_tested == 1
        assert result.best_score == 2.0  # K4 self-encrypts at positions 32, 73
        assert result.best_candidate is not None
        assert result.best_candidate["crib_score"] == 2
        assert result.universe_hash  # non-empty deterministic hash
        assert Path(result.artifact_path).exists()

    def test_vigenere_spec_enumerates_all_keywords(self, tmp_path: Path):
        keywords = ["KRYPTOS", "PALIMPSEST", "ABSCISSA"]
        spec = _vigenere_spec(keywords=tuple(keywords))
        result = execute(
            spec,
            artifact_root=_tmp_artifact_root(tmp_path),
            parallel=False,
            exhaustion_log={},
        )
        assert result.admissibility_verdict == "ok"
        assert result.total_tested == len(keywords)
        assert result.universe_hash
        # Artifact contains the full per-config result set.
        artifact = json.loads(Path(result.artifact_path).read_text())
        assert len(artifact["all_results"]) == len(keywords)
        returned_cids = {r["config_id"] for r in artifact["all_results"]}
        for kw in keywords:
            assert any(kw in cid for cid in returned_cids), (
                f"no config id for keyword {kw!r}"
            )

    def test_rerun_produces_same_universe_hash(self, tmp_path: Path):
        """Same spec → same universe_hash across independent runs
        (deterministic enumeration)."""
        spec = _vigenere_spec()
        r1 = execute(spec, artifact_root=_tmp_artifact_root(tmp_path), parallel=False, exhaustion_log={})
        r2 = execute(spec, artifact_root=_tmp_artifact_root(tmp_path), parallel=False, exhaustion_log={})
        assert r1.universe_hash == r2.universe_hash
        assert r1.spec_hash == r2.spec_hash

    def test_completed_run_with_no_signal_sets_eliminated_claim(self, tmp_path: Path):
        spec = _vigenere_spec(keywords=("NOKNOK", "XYZZX", "WOWOW"))
        result = execute(
            spec, artifact_root=_tmp_artifact_root(tmp_path),
            parallel=False, exhaustion_log={},
        )
        assert result.total_tested == 3
        assert result.total_stored == 0
        assert result.eliminated_claim is not None
        assert spec.hypothesis_id in result.eliminated_claim
        assert "STORE_THRESHOLD" in result.eliminated_claim

    def test_admissibility_rejection_short_circuits(self, tmp_path: Path):
        """Rejected spec returns early — total_tested stays 0.

        Uses rail_fence (still unsupported as of R3-0.5-3) rather than
        polybius (now supported); see test_unsupported_kind_rejected_with_pointer
        for the history.
        """
        spec = HypothesisSpec(
            hypothesis_id="T", pipeline=[CipherLayer(kind="rail_fence")],
            compute_budget_cpu_minutes=1,
        )
        result = execute(
            spec, artifact_root=_tmp_artifact_root(tmp_path),
            parallel=False, exhaustion_log={},
        )
        assert result.admissibility_verdict == "rejected"
        assert result.total_tested == 0
        assert result.best_candidate is None
        assert any("no dispatcher translation" in r for r in result.admissibility_reasons)

    def test_kernel_overrules_worker_score(self, tmp_path: Path):
        """All scoring comes from score_candidate (kernel). Workers
        don't self-report; there's no field for them to lie in."""
        spec = _vigenere_spec()
        result = execute(
            spec, artifact_root=_tmp_artifact_root(tmp_path),
            parallel=False, exhaustion_log={},
        )
        assert result.best_candidate is not None
        artifact = json.loads(Path(result.artifact_path).read_text())
        # Every stored result contains kernel-sourced crib_score + bean_passed.
        for r in artifact["all_results"]:
            if "error" in r:
                continue
            assert isinstance(r["crib_score"], int)
            assert isinstance(r["bean_passed"], bool)
            assert "candidate_pt" in r


# ─── execute_from_json wrapper ──────────────────────────────────────────────

class TestExecuteFromJson:
    def test_valid_json_runs(self, tmp_path: Path):
        spec = _identity_spec()
        result = execute_from_json(
            spec.to_dict(),
            artifact_root=_tmp_artifact_root(tmp_path),
            parallel=False,
            exhaustion_log={},
        )
        assert result.admissibility_verdict == "ok"
        assert result.total_tested == 1

    def test_malformed_json_returns_rejected_result(self, tmp_path: Path):
        result = execute_from_json(
            "{not valid",
            artifact_root=_tmp_artifact_root(tmp_path),
            parallel=False,
            exhaustion_log={},
        )
        assert result.admissibility_verdict == "rejected"
        assert any("JSON parse error" in r for r in result.admissibility_reasons)


# ─── JobResult serialization ────────────────────────────────────────────────

class TestJobResultShape:
    def test_to_dict_roundtrip(self):
        r = JobResult(
            hypothesis_id="T", spec_hash="abc", universe_hash="def",
            total_tested=5, total_stored=1, best_score=18.0,
        )
        d = r.to_dict()
        assert d["hypothesis_id"] == "T"
        assert d["total_stored"] == 1
        assert d["best_score"] == 18.0

    def test_json_serializes(self):
        r = JobResult(hypothesis_id="T", spec_hash="abc", universe_hash="def")
        raw = r.to_json()
        parsed = json.loads(raw)
        assert parsed["hypothesis_id"] == "T"


# ─── JobResult → WorkerContract conversion ─────────────────────────────────

class TestJobResultToWorkerContract:
    """Brief §6.3 minimal controller integration: verify the dispatcher can
    emit a WorkerContract that the Phase 3 kernel verifier will accept.

    Default controller dispatch flow is NOT wired to use this helper in
    Phase 4 (brief §6.6 backward-compat). The helper is exposed so a
    future session can wire it in without modifying the dispatcher."""

    def test_eliminated_spec_becomes_disproved_contract(self, tmp_path: Path):
        spec = _vigenere_spec(keywords=("NOKNOK", "XYZZX", "WOWOW"))
        result = execute(
            spec, artifact_root=_tmp_artifact_root(tmp_path),
            parallel=False, exhaustion_log={},
        )
        contract = job_result_to_worker_contract(result)
        assert contract.status == WorkerStatus.DISPROVED
        assert contract.worker_role == "dsl_dispatcher"
        assert contract.hypothesis_id == spec.hypothesis_id
        assert contract.raw_artifacts["spec_hash"] == spec.spec_hash
        assert contract.disproof_evidence, "expected eliminated_claim in disproof_evidence"
        assert spec.hypothesis_id in contract.disproof_evidence[0]

    def test_admissibility_rejection_becomes_inconclusive(self, tmp_path: Path):
        spec = HypothesisSpec(
            hypothesis_id="T", pipeline=[CipherLayer(kind="polybius")],
            compute_budget_cpu_minutes=1,
        )
        result = execute(
            spec, artifact_root=_tmp_artifact_root(tmp_path),
            parallel=False, exhaustion_log={},
        )
        contract = job_result_to_worker_contract(result)
        assert contract.status == WorkerStatus.INCONCLUSIVE
        assert any("ADMISSIBILITY" in e for e in contract.disproof_evidence)

    def test_contract_fields_are_kernel_verified(self, tmp_path: Path):
        """Kernel verifier runs on the emitted contract; bean_variant
        populated when best_plaintext is CT97-shaped (Phase 3 guarantee)."""
        spec = _identity_spec()
        result = execute(
            spec, artifact_root=_tmp_artifact_root(tmp_path),
            parallel=False, exhaustion_log={},
        )
        contract = job_result_to_worker_contract(result)
        # best_plaintext is K4 CT itself (identity pipeline); 97 chars, verifiable.
        assert len(contract.best_plaintext) == 97
        assert contract.crib_score == 2  # K4 self-encrypts at 32, 73
        # fields_overwritten may or may not trip depending on whether the
        # JobResult reports matching values. The kernel verifier always
        # overwrites to ground truth either way.
        assert contract.verification_error == ""


# ─── Support-kinds coverage ─────────────────────────────────────────────────

class TestSupportedKinds:
    def test_supported_subset_of_valid(self):
        """Every dispatcher-supported kind must also be a valid DSL kind."""
        from kryptosbot.hypothesis_dsl import _VALID_CIPHER_KINDS
        assert _SUPPORTED_KINDS.issubset(_VALID_CIPHER_KINDS)

    def test_phase4_expected_kinds_are_supported(self):
        """The kinds the brief's worked examples use must be supported."""
        for expected in ("identity", "vigenere", "beaufort", "variant_beaufort",
                         "columnar", "atbash"):
            assert expected in _SUPPORTED_KINDS, (
                f"expected {expected!r} in _SUPPORTED_KINDS for Phase 4"
            )
