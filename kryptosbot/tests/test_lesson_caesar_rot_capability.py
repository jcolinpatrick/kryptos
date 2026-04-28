"""Tests for LESSON-009 — canonical Caesar / ROT composition with
keyed transpositions and Atbash, plus the cost-control hardening
that landed alongside it.

Pinned properties:

  1. ``LessonRegistry`` seeds LESSON-009 with the trigger vocabulary
     (shift, shifted, offset, rotate, rotated, rotation, step,
     caesar, rot, additive, subtractive) and parameter knobs the
     user mandated. The runtime constants in ``hand_cipher_core``
     match the registry entry (drift test).
  2. The DSL accepts a ``caesar`` cipher kind with a ``shift``
     parameter; the dispatcher translates it to the kernel's
     Vigenere transform with a single-element key, but coverage_
     vector and attempt artifact layers continue to show the
     canonical caesar layer (not collapsed to vigenere).
  3. Trigger detection: a clue text containing any of the lesson's
     trigger tokens flips ``_detect_caesar_trigger``. Without a
     trigger the historical catalog is bit-identical (no caesar*
     families emitted).
  4. Trigger-driven generation: when triggered,
     ``generate_layered_specs`` emits Caesar alone + Caesar paired
     with each keyed transposition (columnar, myszkowski, rail_
     fence, route) in BOTH layer orders + Caesar paired with
     Atbash + the four three-layer Caesar/transposition/Atbash
     orderings.
  5. Coverage vectors carry ``shift_value`` and ``operation_source``
     whenever a Caesar layer is in the pipeline. Legacy specs leave
     them at their safe empty defaults.
  6. Real-K4 mode unchanged: ``_collect_hcc_seeds`` returns ``[]``
     in real-K4 mode, so the family generators never auto-emit. The
     LESSON-009 entry is still in the registry as a generalized
     tactic the LLM theorist can read.
  7. Cost-control: ``--bench-fast`` implies skip-synthesis +
     skip-lead-pursuit + skip-stat-audit + deterministic-critic +
     redteam-min-crib=1. A non-dry-run HCC-only bench-fast
     subprocess with API keys stripped runs to completion without
     any LLM call.
"""
from __future__ import annotations

from pathlib import Path
import sys

import pytest

from kryptosbot.solver_capabilities import _default_lessons
from kryptosbot.hand_cipher_core import (
    AlphabetMode,
    CoverageVector,
    _CAESAR_TRIGGER_TOKENS,
    _DEFAULT_CAESAR_SHIFTS,
    _caesar_layer,
    _caesar_shifts_for_payload,
    _detect_caesar_trigger,
    _gen_caesar_alone_family,
    _gen_caesar_atbash_family,
    _gen_caesar_keyword_transposition_family,
    _gen_caesar_keywordless_transposition_family,
    _gen_caesar_three_layer_family,
    generate_layered_specs,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]
_K4B003_PATH = _REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-003.json"


# ---------------------------------------------------------------------------
# (1) LessonRegistry contains LESSON-009
# ---------------------------------------------------------------------------


class TestLessonRegistry:
    def test_lesson_009_present_in_defaults(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        assert "LESSON-009" in lessons
        l = lessons["LESSON-009"]
        assert l.tactic_kind == "caesar_rot_composition"
        assert l.generates_specs is True

    def test_lesson_009_has_required_trigger_vocabulary(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-009"]
        triggers = set(l.tactic_parameters.get("trigger_tokens", []))
        required = {
            "shift", "shifted", "offset",
            "rotate", "rotated", "rotation",
            "step",
            "caesar",
            "rot",
            "additive", "subtractive",
        }
        missing = required - triggers
        assert not missing, (
            f"LESSON-009 trigger_tokens missing: {missing}"
        )

    def test_lesson_009_lists_default_shifts(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-009"]
        shifts = l.tactic_parameters.get("default_shifts", [])
        # Default shift set: common hand-cipher shifts including ROT13
        assert 13 in shifts, "ROT13 must be in default_shifts"
        for s in shifts:
            assert 0 < s < 26, f"shift {s} out of [1,25]"

    def test_lesson_009_lists_partner_kinds(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-009"]
        trans = set(l.tactic_parameters.get(
            "applies_to_transposition_kinds", [],
        ))
        assert trans == {
            "columnar", "myszkowski", "rail_fence", "route",
        }
        sub_partners = set(l.tactic_parameters.get(
            "applies_to_substitution_partners", [],
        ))
        assert sub_partners == {"atbash"}

    def test_lesson_009_runtime_drift(self):
        """Drift: registry trigger_tokens must equal the runtime
        ``_CAESAR_TRIGGER_TOKENS`` constant."""
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-009"]
        assert set(l.tactic_parameters["trigger_tokens"]) == set(
            _CAESAR_TRIGGER_TOKENS
        ), "runtime _CAESAR_TRIGGER_TOKENS != lesson trigger_tokens"
        assert tuple(l.tactic_parameters["default_shifts"]) == (
            _DEFAULT_CAESAR_SHIFTS
        ), "runtime _DEFAULT_CAESAR_SHIFTS != lesson default_shifts"


# ---------------------------------------------------------------------------
# (2) DSL + dispatcher accept canonical caesar
# ---------------------------------------------------------------------------


class TestDslAndDispatcher:
    def test_dsl_validates_caesar_layer(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        spec = {
            "hypothesis_id": "test-c",
            "pipeline": [{
                "kind": "caesar", "alphabet": "AZ",
                "params": [{"name": "shift", "values": [8]}],
            }],
            "crib_alignment": "direct_positional",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        assert parsed.is_valid, parsed.errors

    def test_dispatcher_supported_kinds_includes_caesar(self):
        from kryptosbot.job_dispatcher import (
            _SUPPORTED_KINDS, _kind_has_translation,
        )
        assert "caesar" in _SUPPORTED_KINDS
        assert _kind_has_translation("caesar")

    def test_translator_emits_vigenere_with_single_key(self):
        """The kernel arithmetic for Caesar is identical to Vigenere
        with key=[shift]; the translator emits that, but the surface
        kind on the spec stays "caesar" so coverage_vector is honest.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "caesar", "alphabet": "AZ",
                "params": [{"name": "shift", "values": [8]}],
            }],
            "crib_alignment": "direct_positional",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        out = _translate_layer(parsed.value.pipeline[0], {"shift": 8})
        assert out["type"] == "vigenere"
        assert out["params"]["key"] == [8]
        assert out["params"]["direction"] == "decrypt"

    def test_translator_rejects_invalid_shift(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer, DispatcherError
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "caesar", "alphabet": "AZ",
                "params": [{"name": "shift", "values": [26]}],
            }],
            "crib_alignment": "direct_positional",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        with pytest.raises(DispatcherError):
            _translate_layer(parsed.value.pipeline[0], {"shift": 26})

    def test_translator_rejects_non_az_alphabet(self):
        """Caesar is by definition over the canonical alphabet; a
        non-AZ alphabet would silently become a 1-letter Vigenere
        over a different tableau and mislead telemetry. The
        translator must reject it.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer, DispatcherError
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "caesar", "alphabet": "KA",
                "params": [{"name": "shift", "values": [3]}],
            }],
            "crib_alignment": "direct_positional",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        with pytest.raises(DispatcherError, match="caesar"):
            _translate_layer(parsed.value.pipeline[0], {"shift": 3})


# ---------------------------------------------------------------------------
# (3) Trigger detection
# ---------------------------------------------------------------------------


class TestTriggerDetection:
    @pytest.mark.parametrize("text,expected", [
        ("stamped shift eight, reverse the panel, rivet column", True),
        ("ROTATE the disc by three", True),
        ("Apply a CAESAR shift", True),
        ("Step the alphabet by one", True),
        ("subtractive arrow", True),
        ("additive operation", True),
        ("ROT13 reference", True),
        ("normal vigenere problem", False),
        ("apply Polybius and a tableau", False),
        ("", False),
    ])
    def test_detect_caesar_trigger(self, text, expected):
        assert _detect_caesar_trigger(text) is expected

    def test_word_boundary_negative(self):
        """'shift' inside 'shifty' or 'gearshift' or 'shiftless' must
        NOT trigger. The single-word 'shift' DOES trigger."""
        assert _detect_caesar_trigger("a shifty character") is False
        assert _detect_caesar_trigger("the shiftless chap") is False
        assert _detect_caesar_trigger("apply a shift here") is True


# ---------------------------------------------------------------------------
# (4) Trigger-driven generation
# ---------------------------------------------------------------------------


class TestTriggerDrivenGeneration:
    def test_no_trigger_no_caesar_families(self):
        specs = generate_layered_specs(
            ["RIVET", "BRASS"], bench_slug="t",
            clue_text="ordinary cipher problem", max_specs=3000,
        )
        caesar_specs = [
            s for s in specs
            if s.coverage.layer_family == "caesar"
            or s.coverage.layer_family.startswith("caesar_")
        ]
        assert caesar_specs == [], (
            f"unexpected caesar specs without trigger: "
            f"{[s.coverage.layer_family for s in caesar_specs[:3]]}"
        )

    def test_caesar_alone_emitted_when_triggered(self):
        clue = "stamped shift eight, reverse the panel, rivet column"
        specs = generate_layered_specs(
            ["RIVET", "BRASS"], bench_slug="t",
            clue_text=clue, max_specs=4000,
        )
        alone = [
            s for s in specs if s.coverage.layer_family == "caesar"
        ]
        assert alone, "caesar alone family did not fire"
        # Shifts include the clue-derived 8 with EITHER the LESSON-012
        # phrase-bound source ("shift eight" anchor) OR the legacy
        # clue_numeral source. Both are valid provenance for shift=8.
        shifts = {(s.coverage.shift_value, s.coverage.operation_source)
                  for s in alone}
        assert (
            (8, "phrase_bound_shift_value") in shifts
            or (8, "clue_numeral") in shifts
        ), f"shift=8 not present with clue-derived provenance; shifts={shifts}"

    def test_caesar_columnar_both_layer_orders(self):
        clue = "stamped shift eight, reverse the panel, rivet column"
        specs = generate_layered_specs(
            ["RIVET", "BRASS"], bench_slug="t",
            clue_text=clue, max_specs=4000,
        )
        fam = [
            s for s in specs
            if s.coverage.layer_family == "caesar_columnar"
        ]
        assert fam, "caesar_columnar family did not fire"
        orders = {s.coverage.layer_order for s in fam}
        assert ("caesar", "columnar") in orders
        assert ("columnar", "caesar") in orders

    def test_caesar_myszkowski_both_layer_orders(self):
        clue = "stamped shift eight, reverse the panel, rivet column"
        specs = generate_layered_specs(
            ["RIVET", "BRASS"], bench_slug="t",
            clue_text=clue, max_specs=4000,
        )
        fam = [
            s for s in specs
            if s.coverage.layer_family == "caesar_myszkowski"
        ]
        assert fam, "caesar_myszkowski family did not fire"
        orders = {s.coverage.layer_order for s in fam}
        assert ("caesar", "myszkowski") in orders
        assert ("myszkowski", "caesar") in orders

    def test_caesar_rail_fence_both_layer_orders(self):
        clue = "stamped shift eight, reverse the panel, rivet column"
        specs = generate_layered_specs(
            ["RIVET", "BRASS"], bench_slug="t",
            clue_text=clue, max_specs=4000,
        )
        fam = [
            s for s in specs
            if s.coverage.layer_family == "caesar_rail_fence"
        ]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert ("caesar", "rail_fence") in orders
        assert ("rail_fence", "caesar") in orders

    def test_caesar_route_both_layer_orders(self):
        clue = "stamped shift eight, reverse the panel, rivet column"
        specs = generate_layered_specs(
            ["RIVET", "BRASS"], bench_slug="t",
            clue_text=clue, max_specs=4000,
        )
        fam = [
            s for s in specs
            if s.coverage.layer_family == "caesar_route"
        ]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert ("caesar", "route") in orders
        assert ("route", "caesar") in orders

    def test_caesar_atbash_both_layer_orders(self):
        clue = "rotate the disc, atbash strip, shift three"
        specs = generate_layered_specs(
            ["KEY", "BRASS"], bench_slug="t",
            clue_text=clue, max_specs=4000,
        )
        fam = [
            s for s in specs
            if s.coverage.layer_family == "caesar_atbash"
        ]
        assert fam
        orders = {s.coverage.layer_order for s in fam}
        assert ("caesar", "atbash") in orders
        assert ("atbash", "caesar") in orders

    def test_three_layer_orderings_all_present(self):
        """All four orderings: caesar/trans/atbash, atbash/trans/caesar,
        trans/caesar/atbash, atbash/caesar/trans must be present."""
        clue = "stamped shift eight, reverse the panel, rivet column"
        specs = generate_layered_specs(
            ["RIVET", "BRASS"], bench_slug="t",
            clue_text=clue, max_specs=4000,
        )
        fam = [
            s for s in specs
            if s.coverage.layer_family == "caesar_columnar_atbash"
        ]
        assert fam, "caesar_columnar_atbash did not fire"
        orders = {s.coverage.layer_order for s in fam}
        assert ("caesar", "columnar", "atbash") in orders
        assert ("atbash", "columnar", "caesar") in orders
        assert ("columnar", "caesar", "atbash") in orders
        assert ("atbash", "caesar", "columnar") in orders

    def test_three_layer_includes_other_transpositions(self):
        clue = "stamped shift eight, reverse the panel, rivet column"
        specs = generate_layered_specs(
            ["RIVET", "BRASS"], bench_slug="t",
            clue_text=clue, max_specs=5000,
        )
        labels = {s.coverage.layer_family for s in specs}
        assert "caesar_myszkowski_atbash" in labels
        assert "caesar_rail_fence_atbash" in labels
        assert "caesar_route_atbash" in labels

    def test_clue_derived_shift_value_present(self):
        """The clue 'shift eight' must contribute shift=8. Under
        LESSON-012 the "shift" BEFORE-anchor binds 8 to shift_value
        with provenance 'phrase_bound_shift_value'. The pre-LESSON-012
        path produced 'clue_numeral'; either is acceptable."""
        sizes = _caesar_shifts_for_payload("stamped shift eight")
        eights = [s for s, src in sizes if s == 8]
        assert eights == [8]
        sources = [src for s, src in sizes if s == 8]
        assert sources[0] in (
            "phrase_bound_shift_value", "clue_numeral",
        )

    def test_synthetic_clue_emits_caesar_columnar_and_atbash(self):
        """User-mandated synthetic test: the clue 'stamped shift eight,
        reverse the panel, rivet column' MUST emit Caesar(8), keyed
        columnar with RIVET as the keyword, and Atbash compositions.
        """
        clue = "stamped shift eight, reverse the panel, rivet column"
        specs = generate_layered_specs(
            ["RIVET", "BRASS"], bench_slug="t",
            clue_text=clue, max_specs=5000,
        )
        # Caesar(8) alone
        eights = [
            s for s in specs
            if s.coverage.layer_family == "caesar"
            and s.coverage.shift_value == 8
        ]
        assert eights, "Caesar(8) alone NOT emitted"
        # Caesar + columnar(RIVET) (in some order)
        cc = [
            s for s in specs
            if s.coverage.layer_family == "caesar_columnar"
            and s.coverage.shift_value == 8
            and any(
                k == "columnar" and v == "RIVET"
                for k, v in s.coverage.role_assignment
            )
        ]
        assert cc, "Caesar(8) + columnar(RIVET) NOT emitted"
        # Caesar + Atbash composition
        ca = [
            s for s in specs
            if s.coverage.layer_family == "caesar_atbash"
        ]
        assert ca, "Caesar + Atbash NOT emitted"


# ---------------------------------------------------------------------------
# (5) Coverage vector new field
# ---------------------------------------------------------------------------


class TestCoverageVectorShiftField:
    def test_alone_family_carries_shift_value_and_op_source(self):
        out = _gen_caesar_alone_family(
            bench_slug="t",
            shifts=[(8, "clue_numeral"), (3, "default_set")],
        )
        for s in out:
            assert s.coverage.shift_value in (3, 8)
            assert s.coverage.operation_source in (
                "clue_numeral", "default_set",
            )

    def test_legacy_specs_keep_empty_shift(self):
        """Specs without a caesar layer must leave ``shift_value`` at
        None — the legacy catalog must not gain spurious metadata.
        """
        specs = generate_layered_specs(
            ["CEDAR", "LANTERN"], bench_slug="t",
            clue_text="ordinary cipher", max_specs=200,
            include_three_layer=False,
        )
        non_caesar = [
            s for s in specs if "caesar" not in s.coverage.layer_family
        ]
        assert non_caesar
        for s in non_caesar:
            assert s.coverage.shift_value is None

    def test_coverage_vector_dict_round_trip(self):
        cv = CoverageVector(
            layer_family="caesar",
            layer_order=("caesar",),
            role_assignment=(("caesar_shift", "8"),),
            alphabet="AZ", n_layers=1,
            shift_value=8, operation_source="clue_numeral",
        )
        d = cv.to_dict()
        assert d["shift_value"] == 8
        assert d["operation_source"] == "clue_numeral"
        cv2 = CoverageVector.from_dict(d)
        assert cv2.shift_value == 8
        assert cv2.operation_source == "clue_numeral"


# ---------------------------------------------------------------------------
# (6) Real-K4 mode unchanged
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
        assert seeds == [], (
            f"real-K4 HCC seeds must be empty; got {len(seeds)} seeds"
        )

    def test_real_k4_lesson_registry_includes_lesson_009(self, tmp_path):
        from kryptosbot.solver_capabilities import LessonRegistry
        reg = LessonRegistry(
            path=tmp_path / "lessons.json", seed_defaults=True,
        )
        ids = {l.lesson_id for l in reg.all()}
        assert "LESSON-009" in ids


# ---------------------------------------------------------------------------
# (7) K4B-003 canary
# ---------------------------------------------------------------------------
#
# Cost-control test classes that previously lived here moved to
# tests/test_bench_fast_cost_control.py alongside the bench-fast
# orchestrator tests. This file stays focused on the LESSON-009
# capability: registry, DSL, dispatcher, trigger detection, family
# generators, coverage_vector, real-K4 isolation, and the K4B-003
# canary that confirms the generalized capability scores 24/24.


class TestK4B003Canary:
    """LESSON-009 must include a spec that scores 24/24 on K4B-003 so
    the bench-fast HCC-only run finds the answer deterministically.
    Runs in a subprocess so the kernel constants module loads with
    the K4B-003 CT/cribs override.
    """

    def test_k4b003_caesar_columnar_atbash_hits_24(self):
        if not _K4B003_PATH.exists():
            pytest.skip(f"K4B-003 fixture not on disk at {_K4B003_PATH}")
        import os
        import subprocess
        env = {**os.environ}
        env["PYTHONPATH"] = (
            str(_REPO_ROOT / "src") + ":" + env.get("PYTHONPATH", "")
        )
        code = (
            "import json, sys\n"
            f"sys.path.insert(0, {str(_REPO_ROOT)!r})\n"
            "from kryptosbot.bench_loader import load_k4bench_challenge\n"
            f"ch = load_k4bench_challenge({str(_K4B003_PATH)!r})\n"
            "ch.install_kernel_overrides()\n"
            "from kryptosbot.bench_fallback import hand_cipher_core_fallback\n"
            "from kryptosbot.hypothesis_dsl import validate_hypothesis_spec\n"
            "from kryptosbot.job_dispatcher import execute\n"
            "seeds = hand_cipher_core_fallback(ch.canonical_facts(), n_target=5)\n"
            "cands = [s for s in seeds\n"
            "         if s.minimal_test_spec.get('coverage_vector', {}).get('layer_family') "
            "== 'caesar_columnar_atbash']\n"
            "best = 0.0\n"
            "best_meta = None\n"
            "for s in cands:\n"
            "    parsed = validate_hypothesis_spec(s.dsl_spec)\n"
            "    if not parsed.is_valid:\n"
            "        continue\n"
            "    r = execute(parsed.value, workers=1, parallel=False, bench_mode=True)\n"
            "    if r.best_score > best:\n"
            "        best = r.best_score\n"
            "        cv = s.minimal_test_spec.get('coverage_vector', {})\n"
            "        best_meta = {\n"
            "            'shift_value': cv.get('shift_value'),\n"
            "            'operation_source': cv.get('operation_source'),\n"
            "            'layer_order': cv.get('layer_order'),\n"
            "            'role_assignment': cv.get('role_assignment'),\n"
            "        }\n"
            "print(json.dumps({'best': best, 'cand_count': len(cands), "
            "'meta': best_meta}))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            env=env, capture_output=True, text=True,
            cwd=str(_REPO_ROOT), timeout=600,
        )
        assert result.returncode == 0, (
            f"subprocess failed:\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
        import json
        last = next(
            (ln for ln in reversed(result.stdout.strip().splitlines())
             if ln.startswith("{")),
            "",
        )
        assert last
        payload = json.loads(last)
        assert payload["cand_count"] > 0
        assert payload["best"] == 24.0, (
            f"K4B-003 expected crib_score 24 from caesar_columnar_atbash; "
            f"got {payload['best']}"
        )
        # Also confirm the coverage_vector explicitly reports the
        # generalized fields (not a 1-letter Vigenere artifact).
        meta = payload["meta"]
        assert meta is not None
        assert meta["shift_value"] is not None
        assert meta["operation_source"] in (
            "phrase_bound_shift_value", "clue_numeral", "default_set",
        )


# ---------------------------------------------------------------------------
# (10) Internal helpers
# ---------------------------------------------------------------------------


class TestInternalHelpers:
    def test_caesar_layer_rejects_invalid(self):
        with pytest.raises(ValueError):
            _caesar_layer(-1)
        with pytest.raises(ValueError):
            _caesar_layer(26)

    def test_caesar_shifts_for_payload_orders(self):
        sizes = _caesar_shifts_for_payload("apply shift eight, then shift three")
        # Under LESSON-012 the "shift" anchor binds both numerals to
        # shift_value with phrase_bound_shift_value provenance. Pre-
        # LESSON-012 they appeared as clue_numeral. Either is the
        # "non-default" bucket the legacy test was checking.
        clue = [
            s for s, src in sizes
            if src in ("clue_numeral", "phrase_bound_shift_value")
        ]
        defaults = [s for s, src in sizes if src == "default_set"]
        assert {3, 8} <= set(clue)
        assert set(defaults).isdisjoint(set(clue))
