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

    def test_unsupported_kind_rejected_with_pointer(self, monkeypatch):
        """A DSL-valid but dispatcher-unsupported kind must fail
        admissibility with a clear pointer.

        key_tape was the last deferred kind; its translator landed in
        Task 9 (2026-05-03) so the gap is now empty. This test simulates
        the pre-translation state by temporarily removing key_tape from
        _SUPPORTED_KINDS via monkeypatch, keeping the mechanism test
        meaningful without requiring a real unsupported kind.
        """
        import kryptosbot.job_dispatcher as _disp
        monkeypatch.setattr(
            _disp,
            "_SUPPORTED_KINDS",
            _disp._SUPPORTED_KINDS - {"key_tape"},
        )
        spec = HypothesisSpec(
            hypothesis_id="T", pipeline=[CipherLayer(kind="key_tape")],
            compute_budget_cpu_minutes=1,
        )
        admissible, reasons = check_admissibility(spec, exhaustion_log={})
        assert admissible is False
        assert any(
            "key_tape" in r and "no dispatcher translation" in r
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


# ─── B-DSL-expanded translators (2026-04-22) ─────────────────────────────────

class TestRailFenceTranslation:
    def test_rail_fence_translates_to_transposition_with_perm(self):
        step = _translate_layer(CipherLayer(kind="rail_fence"), {"depth": 3})
        assert step["type"] == "transposition_full"
        assert step["params"]["direction"] == "undo"
        assert len(step["params"]["perm"]) == 97
        # Perm must be a valid permutation of [0, 97).
        assert sorted(step["params"]["perm"]) == list(range(97))

    def test_rail_fence_rejects_missing_depth(self):
        with pytest.raises(DispatcherError, match="depth"):
            _translate_layer(CipherLayer(kind="rail_fence"), {})

    def test_rail_fence_rejects_depth_below_2(self):
        with pytest.raises(DispatcherError, match="depth"):
            _translate_layer(CipherLayer(kind="rail_fence"), {"depth": 1})

    def test_rail_fence_rejects_depth_at_or_above_ct_len(self):
        with pytest.raises(DispatcherError, match="depth"):
            _translate_layer(CipherLayer(kind="rail_fence"), {"depth": 97})


class TestMyszkowskiTranslation:
    def test_myszkowski_translates_to_transposition_with_perm(self):
        step = _translate_layer(
            CipherLayer(kind="myszkowski"), {"keyword": "TOMATO"},
        )
        assert step["type"] == "transposition_full"
        assert len(step["params"]["perm"]) == 97
        assert sorted(step["params"]["perm"]) == list(range(97))

    def test_myszkowski_rejects_short_keyword(self):
        with pytest.raises(DispatcherError, match="keyword"):
            _translate_layer(CipherLayer(kind="myszkowski"), {"keyword": "A"})

    def test_myszkowski_rejects_non_string_keyword(self):
        with pytest.raises(DispatcherError, match="keyword"):
            _translate_layer(
                CipherLayer(kind="myszkowski"), {"keyword": 12345},
            )

    def test_myszkowski_keyword_case_insensitive(self):
        upper = _translate_layer(
            CipherLayer(kind="myszkowski"), {"keyword": "TOMATO"},
        )
        lower = _translate_layer(
            CipherLayer(kind="myszkowski"), {"keyword": "tomato"},
        )
        assert upper["params"]["perm"] == lower["params"]["perm"]


class TestRouteTranslation:
    def test_serpentine_variant_translates(self):
        step = _translate_layer(
            CipherLayer(kind="route"),
            {"variant": "serpentine", "rows": 10, "cols": 10},
        )
        assert step["type"] == "transposition_full"
        assert len(step["params"]["perm"]) == 97
        assert sorted(step["params"]["perm"]) == list(range(97))

    def test_spiral_variant_translates(self):
        step = _translate_layer(
            CipherLayer(kind="route"),
            {"variant": "spiral", "rows": 10, "cols": 10},
        )
        assert step["type"] == "transposition_full"
        assert len(step["params"]["perm"]) == 97
        assert sorted(step["params"]["perm"]) == list(range(97))

    def test_route_rejects_unknown_variant(self):
        with pytest.raises(DispatcherError, match="variant"):
            _translate_layer(
                CipherLayer(kind="route"),
                {"variant": "diagonal", "rows": 10, "cols": 10},
            )

    def test_route_rejects_grid_too_small(self):
        with pytest.raises(DispatcherError, match="CT_LEN"):
            _translate_layer(
                CipherLayer(kind="route"),
                {"variant": "serpentine", "rows": 5, "cols": 5},
            )

    def test_serpentine_horizontal_vs_vertical_differ(self):
        h = _translate_layer(
            CipherLayer(kind="route"),
            {"variant": "serpentine", "rows": 10, "cols": 10, "vertical": False},
        )
        v = _translate_layer(
            CipherLayer(kind="route"),
            {"variant": "serpentine", "rows": 10, "cols": 10, "vertical": True},
        )
        assert h["params"]["perm"] != v["params"]["perm"]


class TestQuagmireTranslation:
    def _k1_binding(self):
        # The K1/K2 calling convention (see kernel quagmire docstring).
        return {
            "variant": "quagmire_iii",
            "period_keyword": "PALIMPSEST",
            "ct_alphabet_keyword": "KRYPTOS",
            "pt_alphabet_keyword": "KRYPTOS",
            "indicator": "K",
        }

    def test_quagmire_iii_translates_with_correct_params(self):
        step = _translate_layer(CipherLayer(kind="quagmire"), self._k1_binding())
        assert step["type"] == "quagmire"
        assert step["params"]["period_keyword"] == "PALIMPSEST"
        assert step["params"]["ct_alphabet_keyword"] == "KRYPTOS"
        assert step["params"]["pt_alphabet_keyword"] == "KRYPTOS"
        assert step["params"]["indicator"] == "K"
        assert step["params"]["direction"] == "decrypt"

    def test_quagmire_rejects_missing_ct_alphabet_keyword(self):
        # The f_w10 footgun: calling the kernel with only ct_alphabet_keyword
        # set (or neither) silently implements a different mechanism. The
        # translator must reject instead.
        bad = self._k1_binding()
        del bad["ct_alphabet_keyword"]
        with pytest.raises(DispatcherError, match="ct_alphabet_keyword"):
            _translate_layer(CipherLayer(kind="quagmire"), bad)

    def test_quagmire_rejects_missing_pt_alphabet_keyword(self):
        bad = self._k1_binding()
        del bad["pt_alphabet_keyword"]
        with pytest.raises(DispatcherError, match="pt_alphabet_keyword"):
            _translate_layer(CipherLayer(kind="quagmire"), bad)

    def test_quagmire_iii_rejects_mismatched_keywords(self):
        bad = self._k1_binding()
        bad["pt_alphabet_keyword"] = "DIFFERENT"
        with pytest.raises(DispatcherError, match="quagmire_iii requires"):
            _translate_layer(CipherLayer(kind="quagmire"), bad)

    def test_quagmire_iv_requires_distinct_keywords(self):
        bad = self._k1_binding()
        bad["variant"] = "quagmire_iv"
        # Same keyword for both — quagmire_iv requires distinct.
        with pytest.raises(DispatcherError, match="distinct"):
            _translate_layer(CipherLayer(kind="quagmire"), bad)

    def test_quagmire_rejects_missing_indicator(self):
        bad = self._k1_binding()
        del bad["indicator"]
        with pytest.raises(DispatcherError, match="indicator"):
            _translate_layer(CipherLayer(kind="quagmire"), bad)

    def test_quagmire_rejects_multi_char_indicator(self):
        bad = self._k1_binding()
        bad["indicator"] = "KR"
        with pytest.raises(DispatcherError, match="indicator"):
            _translate_layer(CipherLayer(kind="quagmire"), bad)

    def test_quagmire_k1_roundtrip_through_kernel(self):
        """End-to-end: the translator produces params that the kernel
        quagmire_decrypt accepts, and decrypting K1 CT with PALIMPSEST /
        KRYPTOS / KRYPTOS / 'K' reproduces the K1 plaintext prefix.
        This is the hard guard against the f_w10 convention footgun —
        anything that breaks the K1 discovery path fails here first."""
        from kryptos.kernel.transforms.quagmire import quagmire_decrypt
        step = _translate_layer(CipherLayer(kind="quagmire"), self._k1_binding())
        params = step["params"]
        K1_CT = (
            "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJ"
            "YQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
        )
        pt = quagmire_decrypt(
            K1_CT,
            period_keyword=params["period_keyword"],
            indicator=params["indicator"],
            ct_alphabet_keyword=params["ct_alphabet_keyword"],
            pt_alphabet_keyword=params["pt_alphabet_keyword"],
        )
        # K1 starts with BETWEEN... — the first word is the regression
        # anchor the kernel docstring calls out.
        assert pt.startswith("BETWEEN"), (
            f"K1/K2 convention regression: translator-produced params "
            f"should decrypt K1 CT to plaintext starting with 'BETWEEN'. "
            f"Got {pt[:20]!r}."
        )


class TestKeyTapeTranslation:
    """Regression tests for the 2026-05-07 layer-level alphabet bug.

    The key_tape DSL puts ``alphabet`` at the CipherLayer level (a
    sibling of ``params``), not inside the enumerated param bindings.
    Pre-fix the translator passed only the binding to the validator,
    which then rejected every real-world spec with ``alphabet None
    must be 'AZ' or 'KA'``. The fix folds layer.alphabet into the
    binding before validation.
    """

    def _binding_for(self, tape, variant="vigenere", **extra):
        return {"tape": list(tape), "variant": variant, **extra}

    def test_key_tape_uses_layer_level_alphabet(self):
        """Layer-level alphabet must reach the kernel param dict."""
        layer = CipherLayer(kind="key_tape", alphabet="KA")
        binding = self._binding_for(tuple(range(26)))
        step = _translate_layer(layer, binding)
        assert step["type"] == "key_tape"
        assert step["params"]["alphabet"] == "KA"

    def test_key_tape_defaults_alphabet_to_az(self):
        """Default CipherLayer.alphabet is 'AZ'; translator forwards it."""
        layer = CipherLayer(kind="key_tape")  # default alphabet="AZ"
        binding = self._binding_for(tuple(range(26)))
        step = _translate_layer(layer, binding)
        assert step["params"]["alphabet"] == "AZ"

    def test_key_tape_explicit_binding_alphabet_wins(self):
        """If a future ParamRange names 'alphabet' explicitly, the
        binding-level value wins over the layer-level default — same
        precedence rule as ``dict.setdefault``."""
        layer = CipherLayer(kind="key_tape", alphabet="AZ")
        binding = self._binding_for(tuple(range(26)))
        binding["alphabet"] = "KA"
        step = _translate_layer(layer, binding)
        assert step["params"]["alphabet"] == "KA"

    def test_key_tape_rejects_invalid_alphabet(self):
        """A bogus layer-level alphabet still trips the validator
        rather than silently falling back to AZ."""
        layer = CipherLayer(kind="key_tape", alphabet="NONSENSE")
        binding = self._binding_for(tuple(range(26)))
        # CipherLayer.validate() catches the alphabet at layer level;
        # _translate_layer's validator is the second line of defense.
        # A bogus alphabet on the layer means the spec was constructed
        # bypassing CipherLayer.validate, which is exactly the
        # threat model the dispatcher's per-kind validation guards.
        with pytest.raises(ValueError, match="alphabet"):
            _translate_layer(layer, binding)

    def test_key_tape_real_world_spec_executes(self):
        """End-to-end smoke: a spec the LLM theorist actually emits
        (alphabet at layer level, params Cartesian-multiplied) must
        translate without raising. Pre-fix this whole pipeline_config
        build raised ValueError because the layer-level alphabet
        was not folded into the binding."""
        from kryptosbot.job_dispatcher import _build_pipeline_config
        layer = CipherLayer(
            kind="key_tape",
            alphabet="AZ",
            params=[
                ParamRange(name="tape", values=[[i % 26 for i in range(97)]]),
                ParamRange(name="variant", values=["vigenere"]),
            ],
        )
        spec = HypothesisSpec(hypothesis_id="t-keytape-smoke", pipeline=[layer])
        bindings_iter = _enumerate_bindings(spec)
        bindings = next(bindings_iter)
        # _build_pipeline_config is the same call site execute() uses
        # (job_dispatcher.py:1937); re-using it pins the real production
        # path, not just the unit-level _translate_layer call.
        pipeline_dict = _build_pipeline_config(spec, bindings)
        assert len(pipeline_dict["steps"]) == 1
        step = pipeline_dict["steps"][0]
        assert step["type"] == "key_tape"
        assert step["params"]["alphabet"] == "AZ"
        assert step["params"]["variant"] == "vigenere"
        assert len(step["params"]["tape"]) == 97


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

    def test_admissibility_rejection_short_circuits(self, tmp_path: Path, monkeypatch):
        """Rejected spec returns early — total_tested stays 0.

        key_tape was the last deferred kind; its translator landed in
        Task 9 (2026-05-03). Monkeypatch removes key_tape from
        _SUPPORTED_KINDS to simulate the rejection path and confirm
        execute() short-circuits on admissibility failure without running
        any workers.
        """
        import kryptosbot.job_dispatcher as _disp
        monkeypatch.setattr(
            _disp,
            "_SUPPORTED_KINDS",
            _disp._SUPPORTED_KINDS - {"key_tape"},
        )
        spec = HypothesisSpec(
            hypothesis_id="T", pipeline=[CipherLayer(kind="key_tape")],
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

    def test_admissibility_rejection_becomes_rejected_admissibility(self, tmp_path: Path):
        """R3-2: admissibility-rejected specs now produce
        WorkerStatus.REJECTED_ADMISSIBILITY (previously INCONCLUSIVE).
        Uses rail_fence since polybius was wired in R3-0.5-3."""
        spec = HypothesisSpec(
            hypothesis_id="T", pipeline=[CipherLayer(kind="rail_fence")],
            compute_budget_cpu_minutes=1,
        )
        result = execute(
            spec, artifact_root=_tmp_artifact_root(tmp_path),
            parallel=False, exhaustion_log={},
        )
        contract = job_result_to_worker_contract(result)
        assert contract.status == WorkerStatus.REJECTED_ADMISSIBILITY
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


# Module-level so it is picklable by multiprocessing.Pool. Hangs for the
# duration the work_item asks for; used by TestPoolPerTaskTimeout to verify
# that a single hung worker can no longer deadlock the pool dispatch.
def _hang_for_test(work_item: dict) -> dict:
    import time as _time
    _time.sleep(work_item["secs"])
    return {"completed_after": work_item["secs"], "config_id": work_item.get("config_id", "")}


def _normal_for_test(work_item: dict) -> dict:
    return {"crib_score": 0, "ngram_score": -7.0, "config_id": work_item.get("config_id", "")}


class TestPoolPerTaskTimeout:
    """Regression coverage for feedback_pool_worker_no_per_task_timeout.

    Before the fix, ``Pool.imap_unordered`` had no per-task timeout and a
    single hung evaluator deadlocked the controller indefinitely (cycle
    245, 2026-05-06; Quagmire III BEARING). The fix replaces the
    imap_unordered call with apply_async + per-future timeout via the
    ``_dispatch_pool`` helper.
    """

    def test_hung_worker_does_not_deadlock_pool(self):
        """A worker that exceeds per_task_timeout_sec must yield control."""
        import time
        from kryptosbot.job_dispatcher import _dispatch_pool

        items = [{"config_id": "cfg-A", "secs": 30}]  # well past the timeout
        t0 = time.monotonic()
        results = _dispatch_pool(
            items,
            workers=2,
            per_task_timeout_sec=1.0,
            evaluator=_hang_for_test,
        )
        elapsed = time.monotonic() - t0

        # Bound generously so flakiness on a busy CI host does not bite.
        assert elapsed < 8.0, f"timeout did not fire promptly: elapsed={elapsed:.2f}s"
        assert len(results) == 1
        assert results[0].get("error") == "per_task_timeout"
        assert results[0].get("config_id") == "cfg-A"

    def test_mixed_normal_and_hung_workers(self):
        """Healthy workers' results survive alongside a hung worker's timeout."""
        import time
        from kryptosbot.job_dispatcher import _dispatch_pool

        items = [
            {"config_id": "cfg-A", "secs": 0.0},
            {"config_id": "cfg-B", "secs": 30.0},
            {"config_id": "cfg-C", "secs": 0.0},
        ]
        t0 = time.monotonic()
        results = _dispatch_pool(
            items,
            workers=3,
            per_task_timeout_sec=1.0,
            evaluator=_hang_for_test,
        )
        elapsed = time.monotonic() - t0

        assert elapsed < 8.0, f"slowest path exceeded budget: elapsed={elapsed:.2f}s"
        assert len(results) == 3
        # Order must match input order so the aggregator can correlate
        # with config_ids if needed.
        assert results[0].get("config_id") == "cfg-A"
        assert results[1].get("error") == "per_task_timeout"
        assert results[1].get("config_id") == "cfg-B"
        assert results[2].get("config_id") == "cfg-C"

    def test_normal_path_unaffected_by_timeout_parameter(self):
        """When no worker hangs, results pass through unchanged."""
        from kryptosbot.job_dispatcher import _dispatch_pool

        items = [
            {"config_id": "cfg-A"},
            {"config_id": "cfg-B"},
        ]
        results = _dispatch_pool(
            items,
            workers=2,
            per_task_timeout_sec=10.0,
            evaluator=_normal_for_test,
        )
        assert len(results) == 2
        assert all("error" not in r for r in results)
        assert {r["config_id"] for r in results} == {"cfg-A", "cfg-B"}

    def test_default_evaluator_is_evaluate_one(self):
        """When evaluator is None, the helper uses production _evaluate_one."""
        from kryptosbot.job_dispatcher import _dispatch_pool, _evaluate_one
        # Inspect the default rather than executing — _evaluate_one needs
        # a fully-built pipeline_dict and CT, which is overkill for this
        # contract test.
        import inspect
        sig = inspect.signature(_dispatch_pool)
        assert "evaluator" in sig.parameters
        # Default of None resolves to _evaluate_one inside the helper;
        # see the helper's body. We assert the default sentinel.
        assert sig.parameters["evaluator"].default is None

    def test_total_budget_caps_many_hung_workers(self):
        """A dispatch where every config hangs cannot run longer than the
        total budget, regardless of how large the per-task timeout is.

        This is the second arm of the deadlock-fix: per-task timeout
        bounds individual hangs, but a 500-config dispatch with all hung
        configs would sequentially time out 500 × 60s = 8 hours under
        per-task alone. The total budget cuts that off.
        """
        import time
        from kryptosbot.job_dispatcher import _dispatch_pool

        # 30 hung configs × 30s per-task would be 900s without the total
        # budget; 5s total budget bounds it tightly.
        items = [{"config_id": f"cfg-{i}", "secs": 30} for i in range(30)]
        t0 = time.monotonic()
        results = _dispatch_pool(
            items,
            workers=2,
            per_task_timeout_sec=30.0,
            evaluator=_hang_for_test,
            total_budget_sec=5.0,
        )
        elapsed = time.monotonic() - t0

        # Budget=5s, per-task=30s. The first 1-2 futures will hit per-task
        # timeout (each ~5s actually because we min(per_task, remaining)),
        # then the rest get total_dispatch_budget_exhausted instantly.
        assert elapsed < 12.0, f"total budget did not cap dispatch: elapsed={elapsed:.2f}s"
        assert len(results) == 30
        budget_exhausted = sum(
            1 for r in results
            if r.get("error") == "total_dispatch_budget_exhausted"
        )
        per_task_timeouts = sum(
            1 for r in results if r.get("error") == "per_task_timeout"
        )
        # Most results should be budget-exhausted; at most a handful are
        # per-task timeouts (one per worker that started before the budget
        # ran out).
        assert budget_exhausted >= 20, (
            f"expected most futures abandoned via total budget; "
            f"got budget_exhausted={budget_exhausted}, "
            f"per_task_timeouts={per_task_timeouts}"
        )

    def test_total_budget_does_not_fire_for_fast_workers(self):
        """When workers complete quickly, total budget is never consulted."""
        from kryptosbot.job_dispatcher import _dispatch_pool

        items = [{"config_id": f"cfg-{i}"} for i in range(10)]
        results = _dispatch_pool(
            items,
            workers=2,
            per_task_timeout_sec=10.0,
            evaluator=_normal_for_test,
            total_budget_sec=30.0,
        )
        assert len(results) == 10
        assert all("error" not in r for r in results)

    def test_default_total_budget_is_clamped(self):
        """The auto-computed default total budget is bounded between 5
        and 30 minutes regardless of input size."""
        from kryptosbot.job_dispatcher import _compute_total_budget_sec

        # Tiny dispatch: floor of 5 minutes
        tiny = _compute_total_budget_sec(n_items=1, workers=8, per_task_timeout_sec=60.0)
        assert tiny >= 300.0
        assert tiny <= 1800.0

        # Huge dispatch: ceiling of 30 minutes
        huge = _compute_total_budget_sec(n_items=10000, workers=8, per_task_timeout_sec=60.0)
        assert huge <= 1800.0
