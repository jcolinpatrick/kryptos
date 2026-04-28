"""Tests for LESSON-011 — modular skip / step / stride route
transposition capability.

Pinned properties:

  1. ``LessonRegistry`` seeds LESSON-011 with the trigger
     vocabulary, default step set, and parameter knobs the user
     mandated. Drift test: runtime constants in
     ``hand_cipher_core`` honor the lesson's parameters.
  2. The DSL accepts a ``skip_route`` cipher kind with ``step``
     and ``offset`` parameters; the dispatcher translates it to a
     ``transposition_full`` perm such that ``output[i] =
     input[(offset + i*step) mod CT_LEN]`` (the kernel inverts the
     supplied perm under direction='undo'). Non-coprime steps are
     rejected with a clear error.
  3. The CoverageVector dataclass exposes ``route_mode``, ``step``,
     and ``offset`` fields. Legacy specs leave them at safe empty
     defaults; dict round-trip preserves them.
  4. Trigger detection: a clue text containing any of the
     LESSON-011 trigger tokens flips ``_detect_skip_route_trigger``.
     Without a trigger the historical catalog is bit-identical (no
     skip_route specs emitted).
  5. The user-mandated synthetic toy clue
     ``"walk every fifth step through the tunnel, offset three,
     mirror then fence"`` causes HCC to emit
     skip_route(step=5, offset=3) combined with Beaufort and
     rail_fence before any LLM call.
  6. Permutation validity: every emitted skip_route perm is a
     valid bijection of [0, CT_LEN) — no missing or repeated
     positions. Replayability: dispatching the same spec twice
     produces the same perm.
  7. All major two-layer and three-layer orderings are present in
     the catalog (skip_route + sub in both orders; sub + skip +
     rail_fence in 4 orderings; etc.).
  8. Real-K4 mode unchanged: ``_collect_hcc_seeds`` returns ``[]``
     in real-K4 mode, so the family generators never auto-emit;
     LESSON-011 entry IS in the registry as a generalized tactic.
"""
from __future__ import annotations

import math
from pathlib import Path
import sys

import pytest

from kryptosbot.solver_capabilities import _default_lessons, LessonRegistry
from kryptosbot.hand_cipher_core import (
    AlphabetMode,
    CoverageVector,
    _DEFAULT_SKIP_ROUTE_OFFSETS,
    _DEFAULT_SKIP_ROUTE_STEPS,
    _SKIP_ROUTE_TRIGGER_TOKENS,
    _detect_skip_route_trigger,
    _gen_skip_route_alone_family,
    _gen_skip_route_atbash_family,
    _gen_skip_route_caesar_family,
    _gen_skip_route_rail_fence_family,
    _gen_skip_route_substitution_family,
    _gen_skip_route_three_layer_family,
    _skip_route_layer,
    _skip_route_pairs_for_payload,
    _skip_route_steps_for_payload,
    _skip_route_offsets_for_payload,
    generate_layered_specs,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]
_K4B006_PATH = _REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-006.json"

# Toy clue keyword set unrelated to any K4Bench challenge.
_ABC = ["ALPHA", "BRAVO", "CHARLIE"]


# ---------------------------------------------------------------------------
# (1) LessonRegistry
# ---------------------------------------------------------------------------


class TestLessonRegistry:
    def test_lesson_011_present(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        assert "LESSON-011" in lessons
        l = lessons["LESSON-011"]
        assert l.tactic_kind == "skip_step_route_enumeration"
        assert l.generates_specs is True

    def test_lesson_011_has_required_trigger_vocabulary(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-011"]
        triggers = set(l.tactic_parameters.get("trigger_tokens", []))
        required = {
            "skip", "skipped",
            "step", "stepped",
            "stride",
            "every",
            "nth",
            "offset",
            "route", "path",
            "tunnel", "passage",
            "layer",
            "hide", "hides", "hidden",
            "read", "reads",
            "walk", "walks",
            "margin", "margins",
        }
        missing = required - triggers
        assert not missing, f"LESSON-011 trigger_tokens missing: {missing}"

    def test_lesson_011_default_steps_and_coprimality(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-011"]
        steps = list(l.tactic_parameters.get("default_steps", []))
        # Default set: covers small primes and a couple of useful
        # composites; every step must be a positive int
        assert all(isinstance(s, int) and s >= 2 for s in steps)
        # Coprimality required is part of the lesson contract
        assert l.tactic_parameters.get("coprimality_required") is True

    def test_lesson_011_lists_substitution_partners(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-011"]
        partners = set(l.tactic_parameters.get(
            "applies_to_substitution_kinds", [],
        ))
        assert {
            "vigenere", "beaufort", "variant_beaufort",
            "caesar", "atbash",
        } <= partners

    def test_lesson_011_runtime_drift(self):
        """Drift test: runtime trigger tokens and default step set
        match the registry entry."""
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-011"]
        assert set(l.tactic_parameters["trigger_tokens"]) == set(
            _SKIP_ROUTE_TRIGGER_TOKENS
        )
        assert tuple(l.tactic_parameters["default_steps"]) == (
            _DEFAULT_SKIP_ROUTE_STEPS
        )

    def test_lesson_registry_round_trip(self, tmp_path):
        path = tmp_path / "lessons.json"
        reg1 = LessonRegistry(path=path, seed_defaults=True)
        ids1 = {l.lesson_id for l in reg1.all()}
        assert "LESSON-011" in ids1
        reg2 = LessonRegistry(path=path, seed_defaults=True)
        ids2 = {l.lesson_id for l in reg2.all()}
        assert "LESSON-011" in ids2


# ---------------------------------------------------------------------------
# (2) DSL + dispatcher accept skip_route
# ---------------------------------------------------------------------------


class TestDslAndDispatcher:
    def test_dsl_validates_skip_route_layer(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "skip_route", "alphabet": "AZ",
                "params": [
                    {"name": "step", "values": [5]},
                    {"name": "offset", "values": [3]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        assert parsed.is_valid

    def test_dispatcher_supported_kinds_includes_skip_route(self):
        from kryptosbot.job_dispatcher import (
            _SUPPORTED_KINDS, _kind_has_translation,
        )
        assert "skip_route" in _SUPPORTED_KINDS
        assert _kind_has_translation("skip_route")

    def test_translator_emits_decoded_perm(self):
        """The kernel inverts the supplied perm under direction='undo',
        so ``output[i] = input[inv[i]]``. We emit perm such that
        ``inv[i] = (offset + i*step) mod CT_LEN`` — the decryption
        map. Verify by checking a specific (step, offset) produces
        the inverse-of-decode perm.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        from kryptos.kernel.constants import CT_LEN
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "skip_route", "alphabet": "AZ",
                "params": [
                    {"name": "step", "values": [5]},
                    {"name": "offset", "values": [3]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        out = _translate_layer(
            parsed.value.pipeline[0],
            {"step": 5, "offset": 3},
        )
        assert out["type"] == "transposition_full"
        perm = out["params"]["perm"]
        assert len(perm) == CT_LEN
        # Verify perm is the inverse of the decode map:
        # inv[i] = (3 + 5*i) mod CT_LEN should equal perm-1[i]
        # i.e. for every i, perm[(3 + 5*i) % CT_LEN] should == i
        for i in range(CT_LEN):
            decode_pos = (3 + 5 * i) % CT_LEN
            assert perm[decode_pos] == i, (
                f"perm inverse mismatch at i={i}: "
                f"perm[{decode_pos}]={perm[decode_pos]}, expected {i}"
            )

    def test_translator_rejects_non_coprime_step(self):
        """Non-coprime steps would skip positions and the modular
        inverse wouldn't exist. The translator must reject these.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import (
            _translate_layer, DispatcherError,
        )
        from kryptos.kernel.constants import CT_LEN
        # Pick a step value > 1 that shares a factor with CT_LEN.
        # CT_LEN=97 is prime so every step in [1, 96] is coprime;
        # we test with CT_LEN's multiples (which are 0 modular —
        # excluded) or use a step >= CT_LEN.
        # Use step == CT_LEN - 0 == CT_LEN to fail the bound check
        # OR test gcd directly via patching CT_LEN... here we test
        # the bounds branch which fires before gcd:
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "skip_route", "alphabet": "AZ",
                "params": [
                    {"name": "step", "values": [CT_LEN]},
                    {"name": "offset", "values": [0]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        with pytest.raises(DispatcherError, match="step"):
            _translate_layer(
                parsed.value.pipeline[0],
                {"step": CT_LEN, "offset": 0},
            )

    def test_translator_rejects_invalid_offset(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import (
            _translate_layer, DispatcherError,
        )
        from kryptos.kernel.constants import CT_LEN
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "skip_route", "alphabet": "AZ",
                "params": [
                    {"name": "step", "values": [5]},
                    {"name": "offset", "values": [CT_LEN]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        with pytest.raises(DispatcherError, match="offset"):
            _translate_layer(
                parsed.value.pipeline[0],
                {"step": 5, "offset": CT_LEN},
            )

    def test_perm_is_valid_bijection(self):
        """Every (step, offset) pair where gcd(step, CT_LEN)==1
        produces a perm that is a complete bijection of
        [0, CT_LEN).
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        from kryptos.kernel.constants import CT_LEN
        for step in [2, 3, 5, 7, 11, 13, 17, 23]:
            if math.gcd(step, CT_LEN) != 1:
                continue
            for offset in [0, 1, 5, 10]:
                spec = {
                    "hypothesis_id": "t",
                    "pipeline": [{
                        "kind": "skip_route", "alphabet": "AZ",
                        "params": [
                            {"name": "step", "values": [step]},
                            {"name": "offset", "values": [offset]},
                        ],
                    }],
                    "crib_alignment": "post_transposition",
                    "scoring": "crib_plus_bean",
                    "compute_budget_cpu_minutes": 1,
                }
                parsed = validate_hypothesis_spec(spec)
                out = _translate_layer(
                    parsed.value.pipeline[0],
                    {"step": step, "offset": offset},
                )
                perm = out["params"]["perm"]
                assert len(perm) == CT_LEN
                assert sorted(perm) == list(range(CT_LEN)), (
                    f"step={step} offset={offset} perm not a "
                    f"bijection of [0, {CT_LEN})"
                )

    def test_perm_replayability_deterministic(self):
        """Translating the same spec twice produces the same perm.
        This is the foundational replayability invariant for
        attempt artifact reconstruction.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "skip_route", "alphabet": "AZ",
                "params": [
                    {"name": "step", "values": [7]},
                    {"name": "offset", "values": [4]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        out1 = _translate_layer(
            parsed.value.pipeline[0],
            {"step": 7, "offset": 4},
        )
        out2 = _translate_layer(
            parsed.value.pipeline[0],
            {"step": 7, "offset": 4},
        )
        assert out1["params"]["perm"] == out2["params"]["perm"]


# ---------------------------------------------------------------------------
# (3) Trigger detection
# ---------------------------------------------------------------------------


class TestTriggerDetection:
    @pytest.mark.parametrize("text,expected", [
        ("walk every fifth step through the tunnel", True),
        ("offset three, stride seven", True),
        ("read the route in skip order", True),
        ("the margins show the path", True),
        ("hidden in the passage layer", True),
        ("ROUTE BEGINNING THREE STEPS", True),
        ("ordinary cipher", False),
        ("apply Polybius and a tableau", False),
        ("", False),
    ])
    def test_detect_skip_route_trigger(self, text, expected):
        assert _detect_skip_route_trigger(text) is expected

    def test_word_boundary_negative(self):
        """'step' inside 'stepwise' DOES trigger because 'step' is
        the prefix at a word boundary; 'walk' inside 'walkway' does
        NOT trigger because 'walk' is followed by an alphanumeric.
        """
        assert _detect_skip_route_trigger("the walkway opens") is False


# ---------------------------------------------------------------------------
# (4) Parameter extraction
# ---------------------------------------------------------------------------


class TestParameterExtraction:
    def test_steps_from_clue_numerals_and_defaults(self):
        steps = _skip_route_steps_for_payload(
            "step five and step seven", ct_length=97,
        )
        # Clue-derived steps appear first
        clue_steps = [s for s, src in steps if src == "clue_numeral"]
        defaults = [s for s, src in steps if src == "default_set"]
        assert 5 in clue_steps
        assert 7 in clue_steps
        # Defaults absent from the clue still appear
        assert 3 in defaults

    def test_steps_filter_non_coprime(self):
        """For ct_length=10, only coprime steps survive."""
        steps = _skip_route_steps_for_payload(
            "ordinary clue", ct_length=10,
        )
        for s, _ in steps:
            assert math.gcd(s, 10) == 1

    def test_offsets_for_step(self):
        offsets = _skip_route_offsets_for_payload(
            "offset three", step=5,
        )
        offsets_only = [o for o, _ in offsets]
        # Clue-derived offset 3 appears
        assert 3 in offsets_only
        # Default window 0..min(step-1, 5) covers 0..4
        for d in (0, 1, 2, 3, 4):
            assert d in offsets_only

    def test_pairs_provenance(self):
        pairs = _skip_route_pairs_for_payload(
            "step five and offset three", cap=8,
        )
        # (5, 3) should be flagged as clue_numeral (both clue-derived)
        match = [src for s, o, src in pairs if s == 5 and o == 3]
        assert match == ["clue_numeral"]

    def test_pairs_cap_respected(self):
        pairs = _skip_route_pairs_for_payload(
            "ordinary clue", cap=4,
        )
        assert len(pairs) <= 4


# ---------------------------------------------------------------------------
# (5) User-mandated synthetic toy clue
# ---------------------------------------------------------------------------


class TestSyntheticToyClue:
    """The user-mandated synthetic clue:
    ``"walk every fifth step through the tunnel, offset three,
    mirror then fence"``
    must cause HCC to emit skip_route(step=5, offset=3) combined
    with Beaufort and rail_fence before any LLM call. The test
    drives ``generate_layered_specs`` directly with no LLM in the
    loop.
    """

    _TOY_CLUE = (
        "walk every fifth step through the tunnel, offset three, "
        "mirror then fence"
    )

    def test_skip_route_5_3_alone_emitted(self):
        specs = generate_layered_specs(
            ["MIRROR", "TUNNEL", "FENCE"], bench_slug="toy",
            clue_text=self._TOY_CLUE, max_specs=20000,
        )
        match = [
            s for s in specs
            if s.coverage.layer_family == "skip_route"
            and s.coverage.step == 5 and s.coverage.offset == 3
        ]
        assert match, (
            "skip_route(step=5, offset=3) alone NOT emitted from "
            "the toy clue"
        )

    @pytest.mark.parametrize("sub_kind,family", [
        ("vigenere", "skip_route_vigenere"),
        ("beaufort", "skip_route_beaufort"),
        ("variant_beaufort", "skip_route_variant_beaufort"),
    ])
    def test_skip_route_5_3_paired_with_substitution(self, sub_kind, family):
        specs = generate_layered_specs(
            ["MIRROR", "TUNNEL", "FENCE"], bench_slug="toy",
            clue_text=self._TOY_CLUE, max_specs=20000,
        )
        match = [
            s for s in specs
            if s.coverage.layer_family == family
            and s.coverage.step == 5 and s.coverage.offset == 3
        ]
        assert match, (
            f"skip_route(step=5, offset=3) paired with {sub_kind} "
            "NOT emitted from the toy clue"
        )
        # Both layer orders present
        orders = {s.coverage.layer_order for s in match}
        assert (sub_kind, "skip_route") in orders
        assert ("skip_route", sub_kind) in orders

    def test_skip_route_5_3_paired_with_rail_fence(self):
        specs = generate_layered_specs(
            ["MIRROR", "TUNNEL", "FENCE"], bench_slug="toy",
            clue_text=self._TOY_CLUE, max_specs=20000,
        )
        match = [
            s for s in specs
            if s.coverage.layer_family == "skip_route_rail_fence"
            and s.coverage.step == 5 and s.coverage.offset == 3
        ]
        assert match, (
            "skip_route(5, 3) + rail_fence NOT emitted from toy clue"
        )
        # Both layer orders
        orders = {s.coverage.layer_order for s in match}
        assert ("rail_fence", "skip_route") in orders
        assert ("skip_route", "rail_fence") in orders

    def test_three_layer_beaufort_skip_rail_fence_present(self):
        """The user-mandated combination beaufort + skip_route(5,3) +
        rail_fence in three-layer form."""
        specs = generate_layered_specs(
            ["MIRROR", "TUNNEL", "FENCE"], bench_slug="toy",
            clue_text=self._TOY_CLUE, max_specs=20000,
        )
        match = [
            s for s in specs
            if s.coverage.layer_family == "beaufort_skip_route_rail_fence"
            and s.coverage.step == 5 and s.coverage.offset == 3
        ]
        assert match, (
            "beaufort + skip_route(5,3) + rail_fence three-layer "
            "NOT emitted from toy clue"
        )

    def test_no_llm_required_for_emission(self):
        """The catalog is generated entirely from the clue text and
        clue keywords. ``generate_layered_specs`` is pure-Python
        and invokes no SDK / LLM — this test simply confirms the
        function runs to completion with deterministic output for
        the toy clue.
        """
        specs = generate_layered_specs(
            ["MIRROR", "TUNNEL", "FENCE"], bench_slug="toy",
            clue_text=self._TOY_CLUE, max_specs=20000,
        )
        # The catalog is non-empty; at least the skip_route family
        # fired
        skip_families = {
            s.coverage.layer_family for s in specs
            if s.coverage.layer_family.startswith("skip_route")
            or "_skip_route_" in s.coverage.layer_family
        }
        assert skip_families, "no skip_route family fired"


# ---------------------------------------------------------------------------
# (6) Layer-order coverage
# ---------------------------------------------------------------------------


class TestLayerOrderCoverage:
    def _toy_specs(self):
        return generate_layered_specs(
            _ABC, bench_slug="t",
            clue_text="walk every step through the route",
            max_specs=20000,
        )

    @pytest.mark.parametrize("partner,family", [
        ("vigenere", "skip_route_vigenere"),
        ("beaufort", "skip_route_beaufort"),
        ("variant_beaufort", "skip_route_variant_beaufort"),
    ])
    def test_two_layer_both_orders(self, partner, family):
        specs = self._toy_specs()
        fam = [s for s in specs if s.coverage.layer_family == family]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert (partner, "skip_route") in orders
        assert ("skip_route", partner) in orders

    def test_skip_route_atbash_both_orders(self):
        specs = self._toy_specs()
        fam = [s for s in specs if s.coverage.layer_family == "skip_route_atbash"]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert ("atbash", "skip_route") in orders
        assert ("skip_route", "atbash") in orders

    def test_skip_route_caesar_both_orders(self):
        specs = self._toy_specs()
        fam = [s for s in specs if s.coverage.layer_family == "skip_route_caesar"]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert ("caesar", "skip_route") in orders
        assert ("skip_route", "caesar") in orders

    def test_skip_route_rail_fence_both_orders(self):
        specs = self._toy_specs()
        fam = [s for s in specs if s.coverage.layer_family == "skip_route_rail_fence"]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert ("rail_fence", "skip_route") in orders
        assert ("skip_route", "rail_fence") in orders

    def test_three_layer_rail_fence_four_orderings(self):
        specs = self._toy_specs()
        fam = [
            s for s in specs
            if s.coverage.layer_family == "vigenere_skip_route_rail_fence"
        ]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        # All four orderings the generator emits
        assert ("vigenere", "skip_route", "rail_fence") in orders
        assert ("rail_fence", "skip_route", "vigenere") in orders
        assert ("skip_route", "vigenere", "rail_fence") in orders
        assert ("rail_fence", "vigenere", "skip_route") in orders


# ---------------------------------------------------------------------------
# (7) Coverage vector new fields
# ---------------------------------------------------------------------------


class TestCoverageVectorRouteFields:
    def test_alone_family_carries_route_metadata(self):
        out = _gen_skip_route_alone_family(
            bench_slug="t",
            pairs=[(5, 3, "clue_numeral"), (7, 0, "default_set")],
        )
        for s in out:
            assert s.coverage.route_mode == "skip_route"
            assert s.coverage.step in (5, 7)
            assert s.coverage.offset in (0, 3)
            assert s.coverage.operation_source in (
                "clue_numeral", "default_set",
            )

    def test_legacy_specs_keep_empty_route_fields(self):
        specs = generate_layered_specs(
            ["FOO", "BAR"], bench_slug="t",
            clue_text="ordinary problem", max_specs=200,
            include_three_layer=False,
        )
        non_skip = [
            s for s in specs
            if "skip_route" not in s.coverage.layer_family
        ]
        assert non_skip
        for s in non_skip:
            assert s.coverage.route_mode == ""
            assert s.coverage.step is None
            assert s.coverage.offset is None

    def test_dict_round_trip(self):
        cv = CoverageVector(
            layer_family="skip_route",
            layer_order=("skip_route",),
            role_assignment=(),
            alphabet="AZ", n_layers=1,
            route_mode="skip_route", step=5, offset=3,
            operation_source="clue_numeral",
        )
        d = cv.to_dict()
        assert d["route_mode"] == "skip_route"
        assert d["step"] == 5
        assert d["offset"] == 3
        cv2 = CoverageVector.from_dict(d)
        assert cv2.route_mode == "skip_route"
        assert cv2.step == 5
        assert cv2.offset == 3


# ---------------------------------------------------------------------------
# (8) Real-K4 mode unchanged
# ---------------------------------------------------------------------------


class TestRealK4Unchanged:
    def test_real_k4_collect_hcc_seeds_returns_empty(self, tmp_path):
        from kryptosbot.controller import (
            ControllerConfig, ResearchController,
        )
        cfg = ControllerConfig(
            project_root=tmp_path,
            ledger_db_path=tmp_path / "real_k4_ledger.sqlite",
            max_cycles=1, theories_per_cycle=5, dry_run=True,
        )
        controller = ResearchController(cfg)
        controller.state = controller.ledger.load_controller_state()
        controller._snapshot_session_baseline()
        seeds = controller._collect_hcc_seeds()
        assert seeds == []

    def test_lesson_011_in_registry_for_real_k4(self, tmp_path):
        reg = LessonRegistry(
            path=tmp_path / "lessons.json", seed_defaults=True,
        )
        ids = {l.lesson_id for l in reg.all()}
        assert "LESSON-011" in ids

    def test_no_skip_route_emission_without_trigger(self):
        """A clue without skip_route triggers MUST NOT emit
        skip_route specs (regression guard for 'historical catalog
        unchanged' contract).
        """
        specs = generate_layered_specs(
            ["FOO", "BAR"], bench_slug="t",
            clue_text="just an ordinary cipher problem",
            max_specs=2000,
        )
        skip_specs = [
            s for s in specs
            if "skip_route" in s.coverage.layer_family
        ]
        assert skip_specs == [], (
            f"unexpected skip_route specs without trigger: "
            f"{[s.coverage.layer_family for s in skip_specs[:3]]}"
        )


# ---------------------------------------------------------------------------
# (9) Internal helpers
# ---------------------------------------------------------------------------


class TestInternalHelpers:
    def test_skip_route_layer_rejects_invalid(self):
        with pytest.raises(ValueError):
            _skip_route_layer(0, 0)
        with pytest.raises(ValueError):
            _skip_route_layer(5, -1)

    def test_default_set_excludes_step_one(self):
        """Step=1 + offset=0 is identity; step=1 with offset>0 is a
        cyclic shift (still useful, but the default set deliberately
        starts at 2 to avoid trivial identity-only specs)."""
        assert 1 not in _DEFAULT_SKIP_ROUTE_STEPS

    def test_default_offsets_include_zero(self):
        assert 0 in _DEFAULT_SKIP_ROUTE_OFFSETS


# ---------------------------------------------------------------------------
# (10) K4B-006 canary
# ---------------------------------------------------------------------------


class TestK4B006Canary:
    """K4B-006 canary: confirms the LESSON-011 catalog includes the
    clue-driven (step=5, offset=3) candidate and that the spec is
    dispatchable. The canary does NOT hard-code the K4B-006
    plaintext; the kernel verifies dispatch.

    K4B-006 is silver difficulty and may require additional
    composition beyond skip_route alone. A non-24 result here does
    NOT invalidate the LESSON-011 capability — the synthetic toy
    test above is the binding correctness check. This canary
    confirms attempt artifacts surface explicit
    (step, offset, route_mode) telemetry.
    """

    def test_k4b006_skip_route_5_3_in_catalog(self):
        if not _K4B006_PATH.exists():
            pytest.skip(f"K4B-006 fixture not on disk at {_K4B006_PATH}")
        from kryptosbot.bench_loader import load_k4bench_challenge
        from kryptosbot.bench_fallback import hand_cipher_core_fallback
        ch = load_k4bench_challenge(_K4B006_PATH)
        ch.install_kernel_overrides()
        seeds = hand_cipher_core_fallback(ch.canonical_facts(), n_target=5)
        match = [
            s for s in seeds
            if s.minimal_test_spec.get("coverage_vector", {}).get("step") == 5
            and s.minimal_test_spec.get("coverage_vector", {}).get("offset") == 3
            and s.minimal_test_spec.get("coverage_vector", {}).get("route_mode")
            == "skip_route"
        ]
        assert match, (
            "K4B-006 HCC catalog must contain at least one "
            "skip_route(step=5, offset=3) seed"
        )

    def test_k4b006_seeds_carry_explicit_telemetry(self):
        if not _K4B006_PATH.exists():
            pytest.skip(f"K4B-006 fixture not on disk at {_K4B006_PATH}")
        from kryptosbot.bench_loader import load_k4bench_challenge
        from kryptosbot.bench_fallback import hand_cipher_core_fallback
        ch = load_k4bench_challenge(_K4B006_PATH)
        ch.install_kernel_overrides()
        seeds = hand_cipher_core_fallback(ch.canonical_facts(), n_target=5)
        skip_seeds = [
            s for s in seeds
            if "skip_route" in s.minimal_test_spec.get(
                "coverage_vector", {}
            ).get("layer_family", "")
        ]
        assert skip_seeds, "K4B-006 catalog has no skip_route seeds"
        # Every skip_route seed must surface route_mode + step + offset
        for s in skip_seeds:
            cv = s.minimal_test_spec["coverage_vector"]
            assert cv.get("route_mode") == "skip_route", (
                f"missing route_mode in seed {s.hypothesis_id}"
            )
            assert isinstance(cv.get("step"), int), (
                f"missing step in seed {s.hypothesis_id}"
            )
            assert isinstance(cv.get("offset"), int), (
                f"missing offset in seed {s.hypothesis_id}"
            )
            assert cv.get("operation_source") in (
                "clue_numeral", "default_set", "mixed",
            )
