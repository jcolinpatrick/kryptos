"""R2-1 verification: DSL + dispatcher support for double columnar (K3 class).

Two separate responsibilities under test:

  1. The self-test strategy generator (_columnar_double_candidates +
     _ordered_recipe_pairs) discovers K3 in bounded cycles. This is the
     falsification target of R2-1.

  2. The DSL dispatcher's layer-translation path
     (_translate_layer + _build_pipeline_config) can express a two-layer
     columnar spec whose pipeline, when executed over the K3 CT via
     ct_override, produces the K3 known plaintext. Full execute() with
     kernel scoring is deferred to R2-5 (PanelCribs).

Per maturation brief round 2, this file exists at phase R2-1 and must
remain green through R2-2..R2-6. The K3 kernel-sanity path is the
'heartbeat' of the Sanborn-as-sculptor doctrine's closest analog; its
regression would block any K4 attempt.
"""
from __future__ import annotations

import pytest

from kryptos.kernel.transforms.compose import (
    PipelineConfig, TransformConfig, TransformType, build_pipeline,
)
from kryptosbot.hypothesis_dsl import CipherLayer, HypothesisSpec, ParamRange
from kryptosbot.job_dispatcher import _build_pipeline_config, _translate_layer
from kryptosbot.self_test import (
    _K3,
    _columnar_double_candidates,
    _ordered_recipe_pairs,
    _score_panel_candidate,
    ct_override,
    run_panel_dryrun,
    verify_known_answer_contained,
)


# ─── K3 panel integrity ──────────────────────────────────────────────────────

class TestK3PanelIntegrity:
    """R2-1 repaired the K3 panel from 281 to 336 chars. These guards
    prevent silent regression to the Phase-7 truncation bug.
    """

    def test_k3_ciphertext_length_is_336(self):
        assert len(_K3.ciphertext) == 336, (
            "K3 canonical ciphertext is 336 chars (7 rows × 48 cols). A "
            "prior Phase-7 bug truncated this to 281 chars; R2-1 repaired "
            "it. If this fails, the K3 CT was reverted."
        )

    def test_k3_plaintext_matches_ciphertext_length(self):
        assert len(_K3.known_plaintext) == len(_K3.ciphertext), (
            f"PT len {len(_K3.known_plaintext)} != CT len "
            f"{len(_K3.ciphertext)} — pure transposition requires equal lens"
        )

    def test_k3_ct_pt_are_multiset_equal(self):
        from collections import Counter
        assert Counter(_K3.ciphertext) == Counter(_K3.known_plaintext), (
            "K3 is a pure transposition; CT and PT must be anagrams"
        )


# ─── Kernel-sanity (the "heartbeat") ─────────────────────────────────────────

class TestK3KernelSanity:
    """verify_known_answer_contained must actually decrypt K3 under the
    documented (width=14, reversed) ∘ (width=42, reversed) decomposition,
    not short-circuit to 'note: skipped' as Phase 7 did.
    """

    def test_verify_actually_decrypts_k3(self):
        v = verify_known_answer_contained(_K3)
        assert v["direct_kernel_decrypt_works"] is True, (
            f"K3 kernel-sanity failed: {v}"
        )

    def test_verify_reports_decomposition(self):
        v = verify_known_answer_contained(_K3)
        assert "decomposition" in v, (
            "verify_known_answer_contained should document the K3 "
            "decomposition it used, for operator transparency"
        )
        assert "14" in v["decomposition"] and "42" in v["decomposition"]


# ─── Strategy coverage ───────────────────────────────────────────────────────

class TestColumnarDoubleStrategy:
    """The _columnar_double_candidates generator must include K3's
    true decomposition early enough in its enumeration that K3 discovers
    in bounded cycles.
    """

    def test_recipe_pairs_start_with_motivated(self):
        pairs = _ordered_recipe_pairs()
        assert len(pairs) > 0
        # First 9 pairs should all be (identity|reversed|reversed_halves) ×
        # (identity|reversed|reversed_halves) — the motivated × motivated tier.
        motivated_names = {"identity", "reversed", "reversed_halves"}
        for i in range(9):
            o_name, _, i_name, _ = pairs[i]
            assert o_name in motivated_names, (
                f"pair index {i}: outer recipe {o_name!r} should be motivated"
            )
            assert i_name in motivated_names, (
                f"pair index {i}: inner recipe {i_name!r} should be motivated"
            )

    def test_reversed_reversed_pair_appears_in_tier0(self):
        """Explicit guard: (reversed, reversed) must appear within the
        first 9 pairs (the 3×3 motivated × motivated block)."""
        pairs = _ordered_recipe_pairs()
        for i, (o_name, _, i_name, _) in enumerate(pairs[:9]):
            if o_name == "reversed" and i_name == "reversed":
                return
        pytest.fail(
            "(reversed, reversed) not in tier 0. Without it, K3 falls into "
            "tier 2+ and discovery cardinality balloons past bounded cycles."
        )

    def test_k3_discovers_in_bounded_cycles(self):
        """The single most important R2-1 guard: full discovery in
        bounded cycles. Caps at 20_000 — R2-1 empirically observed
        discovery at ~9345."""
        result = run_panel_dryrun(_K3, max_cycles=20_000)
        assert result.discovered is True, (
            f"K3 not discovered in 20K cycles. peak={result.peak_score}/20"
        )
        assert result.peak_score == result.pseudo_crib_total
        assert result.discovered_via == "columnar_double"
        assert result.cycles_to_discovery is not None
        assert result.cycles_to_discovery <= 15_000, (
            f"K3 discovered but took {result.cycles_to_discovery} cycles — "
            f"schedule regression (R2-1 observed ~9345)"
        )

    def test_k3_candidate_schedule_does_not_hardcode_widths(self):
        """The schedule must contain K3's widths (14, 42) via generic
        enumeration, not via a hardcoded (14, 42) pair. A simple
        regression check: the schedule also produces distinct widths
        1-2 away that are NOT 14 or 42."""
        pairs = _ordered_recipe_pairs()
        widths_seen_outer = set()
        widths_seen_inner = set()
        # Walk the first 500 candidates of the K3 strategy; harvest widths.
        count = 0
        for cand in _columnar_double_candidates(_K3):
            widths_seen_outer.add(cand["outer_width"])
            widths_seen_inner.add(cand["inner_width"])
            count += 1
            if count >= 500:
                break
        # Widths other than 14/42 must have been emitted — else we're
        # secretly hardcoding them.
        other_widths_outer = widths_seen_outer - {14, 42}
        other_widths_inner = widths_seen_inner - {14, 42}
        assert len(other_widths_outer) >= 5, (
            f"only {len(other_widths_outer)} outer widths other than "
            f"14/42 in first 500 candidates — suspicious"
        )
        assert len(other_widths_inner) >= 5


# ─── DSL dispatcher path ─────────────────────────────────────────────────────

class TestDispatcherColumnarDouble:
    """The DSL dispatcher's Phase 4 support for columnar layers must
    compose two layers correctly. R2-1 verifies the translation +
    pipeline-execution path against K3 under ct_override; full execute()
    with kernel scoring is deferred to R2-5.
    """

    def _build_k3_two_layer_spec(self) -> HypothesisSpec:
        """A two-layer columnar spec that decrypts K3 when applied via
        ct_override(K3)."""
        order_14_rev = list(range(13, -1, -1))
        order_42_rev = list(range(41, -1, -1))
        return HypothesisSpec(
            hypothesis_id="T-K3-R2-1",
            pipeline=[
                CipherLayer(
                    kind="columnar",
                    alphabet="AZ",
                    params=[
                        ParamRange(name="width", values=[14]),
                        ParamRange(name="col_order", values=[order_14_rev]),
                    ],
                ),
                CipherLayer(
                    kind="columnar",
                    alphabet="AZ",
                    params=[
                        ParamRange(name="width", values=[42]),
                        ParamRange(name="col_order", values=[order_42_rev]),
                    ],
                ),
            ],
            notes="R2-1 dispatcher-path verification on K3 panel.",
        )

    def test_spec_validates(self):
        """The two-layer columnar spec must pass DSL validation.

        HypothesisSpec.validate() returns a list of error strings;
        empty list means valid.
        """
        spec = self._build_k3_two_layer_spec()
        errors = spec.validate()
        assert errors == [], f"validation failed: {errors}"

    def test_translate_layer_columnar_produces_full_perm(self):
        """Under ct_override(K3), _translate_layer on a columnar layer
        must produce a transposition_full step whose perm has length 336."""
        with ct_override(_K3):
            step = _translate_layer(
                CipherLayer(kind="columnar"),
                {"width": 14, "col_order": list(range(13, -1, -1))},
            )
            assert step["type"] == "transposition_full"
            assert "perm" in step["params"]
            assert len(step["params"]["perm"]) == 336, (
                f"perm length {len(step['params']['perm'])} != 336 — "
                "ct_override did not propagate to CT_LEN"
            )
            # The direction should be 'undo' (the dispatcher decrypts;
            # columnar_perm builds the encryption perm, so undo inverts it).
            assert step["params"]["direction"] == "undo"

    def test_build_pipeline_config_two_layer(self):
        """The pipeline builder must emit exactly two transposition_full
        steps, in the order the spec declared them."""
        spec = self._build_k3_two_layer_spec()
        # One binding pulls the single value out of each ParamRange.
        order_14_rev = list(range(13, -1, -1))
        order_42_rev = list(range(41, -1, -1))
        bindings = (
            ("layer0.width", 14),
            ("layer0.col_order", order_14_rev),
            ("layer1.width", 42),
            ("layer1.col_order", order_42_rev),
        )
        with ct_override(_K3):
            pipeline_dict = _build_pipeline_config(spec, bindings)
            assert len(pipeline_dict["steps"]) == 2
            for step in pipeline_dict["steps"]:
                assert step["type"] == "transposition_full"
                assert len(step["params"]["perm"]) == 336

    def test_dispatcher_pipeline_decrypts_k3(self):
        """End-to-end: build the two-layer pipeline via the dispatcher's
        _build_pipeline_config + kernel's build_pipeline, apply to K3 CT,
        verify it produces K3 PT. This is the brief §2.4 check, modulo
        scoring (which is R2-5 work)."""
        spec = self._build_k3_two_layer_spec()
        order_14_rev = list(range(13, -1, -1))
        order_42_rev = list(range(41, -1, -1))
        bindings = (
            ("layer0.width", 14),
            ("layer0.col_order", order_14_rev),
            ("layer1.width", 42),
            ("layer1.col_order", order_42_rev),
        )
        with ct_override(_K3):
            pipeline_dict = _build_pipeline_config(spec, bindings)
            steps = tuple(
                TransformConfig(
                    transform_type=TransformType(s["type"]),
                    params=dict(s.get("params", {})),
                    description=s.get("description", ""),
                )
                for s in pipeline_dict["steps"]
            )
            pipeline = PipelineConfig(
                name="R2-1-k3-verify",
                steps=steps,
                direction="decrypt",
            )
            fn = build_pipeline(pipeline)
            recovered = fn(_K3.ciphertext)
            assert recovered == _K3.known_plaintext, (
                "DSL dispatcher's two-layer columnar pipeline did NOT "
                "decrypt K3.\n"
                f"  got:      {recovered[:60]}...\n"
                f"  expected: {_K3.known_plaintext[:60]}..."
            )
            # Also: pseudo-crib score on K3 panel is full.
            assert _score_panel_candidate(_K3, recovered) == 20
