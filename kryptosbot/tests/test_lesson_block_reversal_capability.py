"""Tests for LESSON-008 — fixed-size block / chunk reversal.

Pinned properties:

  1. ``LessonRegistry`` seeds LESSON-008 with the trigger vocabulary
     and parameter knobs the user mandated. The runtime constants
     in ``hand_cipher_core`` match the registry entry (drift test).
  2. The DSL accepts a ``reverse_blocks`` cipher kind with
     ``block_size`` and ``block_mode`` parameters; the dispatcher
     translates it to a ``transposition_full`` perm that reverses
     each block of size N.
  3. Trigger detection: a clue text containing any of the lesson's
     trigger tokens (single-word or multi-word phrase) flips the
     ``_detect_block_reversal_trigger`` switch. A clue without
     triggers leaves it OFF — the historical catalog stays bit-
     identical.
  4. Trigger-driven generation: when triggered, ``generate_layered_
     specs`` emits the full reverse_blocks family matrix
     (``reverse_blocks`` alone + 2-layer pairings with vigenere /
     beaufort / variant_beaufort / caesar / atbash in BOTH layer
     orders). Three-layer Atbash / Caesar sandwiches fire only when
     a shift trigger is also present.
  5. Coverage vectors carry ``block_size``, ``block_mode``, and
     ``operation_source`` whenever a reverse_blocks layer is in
     the pipeline; legacy specs leave the new fields at their safe
     empty defaults so older catalogue analysis still works.
  6. Real-K4 mode is unchanged: the lesson is registered (so the
     LLM theorist can read it as a tactic) but ``_collect_hcc_seeds``
     returns ``[]``, so the family generators never fire automatically.
  7. K4B-004 canary: the K4B-004 challenge's clue text triggers the
     lesson, the catalog includes the variant_beaufort + reverse_
     blocks(5) spec, and dispatching that spec hits crib_score 24.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from kryptosbot.solver_capabilities import (
    LessonRegistry,
    _default_lessons,
)
from kryptosbot.hand_cipher_core import (
    AlphabetMode,
    CoverageVector,
    _BLOCK_REVERSAL_TRIGGER_TOKENS,
    _DEFAULT_BLOCK_SIZES,
    _DEFAULT_CAESAR_SHIFTS,
    _SHIFT_TRIGGER_TOKENS,
    _block_sizes_for_payload,
    _detect_block_reversal_trigger,
    _detect_shift_trigger,
    _gen_reverse_blocks_alone_family,
    _gen_reverse_blocks_atbash_family,
    _gen_reverse_blocks_caesar_family,
    _gen_reverse_blocks_substitution_family,
    _gen_reverse_blocks_three_layer_family,
    _reverse_blocks_layer,
    _shift_to_keyword,
    generate_layered_specs,
)


_REPO_ROOT = Path(__file__).resolve().parents[2]
_K4B004_PATH = _REPO_ROOT / "bench" / "k4bench" / "challenges" / "K4B-004.json"


# ---------------------------------------------------------------------------
# (1) LessonRegistry contains LESSON-008 with the mandated vocabulary
# ---------------------------------------------------------------------------


class TestLessonRegistry:
    def test_lesson_008_present_in_defaults(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        assert "LESSON-008" in lessons
        l = lessons["LESSON-008"]
        assert l.tactic_kind == "block_reversal_enumeration"
        assert l.generates_specs is True

    def test_lesson_008_has_required_trigger_vocabulary(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-008"]
        triggers = set(l.tactic_parameters.get("trigger_tokens", []))
        # The user-mandated vocabulary
        required = {
            "block", "blocks",
            "chunk", "chunks",
            "group", "groups",
            "small group",
            "backward", "backwards",
            "reverse", "reversed", "reversal",
            "turn",
            "clockwise", "counterclockwise", "clock",
            "route before",
            "read first", "read last",
            "before key", "after key",
        }
        missing = required - triggers
        assert not missing, (
            f"LESSON-008 trigger_tokens missing: {missing}"
        )

    def test_lesson_008_has_default_block_sizes(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-008"]
        sizes = list(l.tactic_parameters.get("default_block_sizes", []))
        assert sizes == [2, 3, 4, 5, 6, 7, 8, 10]

    def test_lesson_008_has_block_modes(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-008"]
        modes = set(l.tactic_parameters.get("block_modes", []))
        assert modes == {"reverse_partial", "truncate"}

    def test_lesson_008_lists_substitution_partners(self):
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-008"]
        partners = set(l.tactic_parameters.get(
            "applies_to_substitution_kinds", [],
        ))
        assert partners == {
            "vigenere", "beaufort", "variant_beaufort",
            "caesar", "atbash",
        }

    def test_lesson_008_runtime_drift_against_registry(self):
        """Drift test: the runtime constants in hand_cipher_core
        must match the lesson registry's tactic_parameters. A
        change to one without the other indicates a refactor that
        broke the contract."""
        lessons = {l.lesson_id: l for l in _default_lessons()}
        l = lessons["LESSON-008"]
        params = l.tactic_parameters
        assert set(params["trigger_tokens"]) == set(
            _BLOCK_REVERSAL_TRIGGER_TOKENS
        ), "runtime _BLOCK_REVERSAL_TRIGGER_TOKENS != lesson trigger_tokens"
        assert tuple(params["default_block_sizes"]) == _DEFAULT_BLOCK_SIZES, (
            "runtime _DEFAULT_BLOCK_SIZES != lesson default_block_sizes"
        )
        assert set(params["shift_trigger_tokens"]) == set(
            _SHIFT_TRIGGER_TOKENS
        ), "runtime _SHIFT_TRIGGER_TOKENS != lesson shift_trigger_tokens"

    def test_registry_persists_lesson_008(self, tmp_path):
        """LessonRegistry round-trip: write defaults, reload, confirm
        LESSON-008 survives. Guards against the persistence layer
        silently dropping the new lesson.
        """
        path = tmp_path / "lessons.json"
        reg1 = LessonRegistry(path=path, seed_defaults=True)
        ids1 = {l.lesson_id for l in reg1.all()}
        assert "LESSON-008" in ids1
        # Reload from the on-disk file
        reg2 = LessonRegistry(path=path, seed_defaults=True)
        ids2 = {l.lesson_id for l in reg2.all()}
        assert "LESSON-008" in ids2


# ---------------------------------------------------------------------------
# (2) DSL + dispatcher accept reverse_blocks
# ---------------------------------------------------------------------------


class TestDslAndDispatcher:
    def test_dsl_validates_reverse_blocks_layer(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        spec = {
            "hypothesis_id": "test-rb",
            "pipeline": [{
                "kind": "reverse_blocks",
                "alphabet": "AZ",
                "params": [
                    {"name": "block_size", "values": [5]},
                    {"name": "block_mode", "values": ["reverse_partial"]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        assert parsed.is_valid, f"errors={parsed.errors}"

    def test_dispatcher_supported_kinds_includes_reverse_blocks(self):
        from kryptosbot.job_dispatcher import (
            _SUPPORTED_KINDS, _kind_has_translation,
        )
        assert "reverse_blocks" in _SUPPORTED_KINDS
        assert _kind_has_translation("reverse_blocks")

    def test_translator_emits_reversal_perm_partial(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "reverse_blocks",
                "alphabet": "AZ",
                "params": [
                    {"name": "block_size", "values": [5]},
                    {"name": "block_mode", "values": ["reverse_partial"]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        out = _translate_layer(
            parsed.value.pipeline[0],
            {"block_size": 5, "block_mode": "reverse_partial"},
        )
        assert out["type"] == "transposition_full"
        perm = out["params"]["perm"]
        # First block 0..4 reversed → [4, 3, 2, 1, 0]
        assert perm[:5] == [4, 3, 2, 1, 0]
        # Second block 5..9 reversed → [9, 8, 7, 6, 5]
        assert perm[5:10] == [9, 8, 7, 6, 5]
        # Length matches CT_LEN
        from kryptos.kernel.constants import CT_LEN
        assert len(perm) == CT_LEN
        # Trailing partial block (97 % 5 == 2 positions) IS reversed
        # under reverse_partial: positions 95..96 swap
        assert perm[95:97] == [96, 95]

    def test_translator_truncate_mode_keeps_tail_identity(self):
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        spec = {
            "hypothesis_id": "t",
            "pipeline": [{
                "kind": "reverse_blocks",
                "alphabet": "AZ",
                "params": [
                    {"name": "block_size", "values": [5]},
                    {"name": "block_mode", "values": ["truncate"]},
                ],
            }],
            "crib_alignment": "post_transposition",
            "scoring": "crib_plus_bean",
            "compute_budget_cpu_minutes": 1,
        }
        parsed = validate_hypothesis_spec(spec)
        out = _translate_layer(
            parsed.value.pipeline[0],
            {"block_size": 5, "block_mode": "truncate"},
        )
        perm = out["params"]["perm"]
        # Trailing partial block under truncate mode is identity
        # (positions 95, 96 unchanged)
        assert perm[95:97] == [95, 96]

    def test_reverse_blocks_self_inverse(self):
        """Block reversal is its own inverse: applying the perm twice
        is identity. Sanity check that confirms the dispatcher's
        ``direction='undo'`` works correctly for this primitive.
        """
        from kryptosbot.hypothesis_dsl import validate_hypothesis_spec
        from kryptosbot.job_dispatcher import _translate_layer
        for size, mode in [(3, "reverse_partial"), (7, "reverse_partial"),
                           (4, "truncate"), (10, "truncate")]:
            spec = {
                "hypothesis_id": "t",
                "pipeline": [{
                    "kind": "reverse_blocks",
                    "alphabet": "AZ",
                    "params": [
                        {"name": "block_size", "values": [size]},
                        {"name": "block_mode", "values": [mode]},
                    ],
                }],
                "crib_alignment": "post_transposition",
                "scoring": "crib_plus_bean",
                "compute_budget_cpu_minutes": 1,
            }
            parsed = validate_hypothesis_spec(spec)
            perm = _translate_layer(
                parsed.value.pipeline[0],
                {"block_size": size, "block_mode": mode},
            )["params"]["perm"]
            # Apply twice
            twice = [perm[perm[i]] for i in range(len(perm))]
            assert twice == list(range(len(perm))), (
                f"reverse_blocks size={size} mode={mode} not self-inverse"
            )


# ---------------------------------------------------------------------------
# (3) Trigger detection
# ---------------------------------------------------------------------------


class TestTriggerDetection:
    @pytest.mark.parametrize("text,expected", [
        ("small clock note, backward steps, reverse blocks before the key", True),
        ("Read first the chunk, read last the group", True),
        ("Reversal of small group is required", True),
        ("CHUNKS need to be turned clockwise", True),
        ("compass rose has five tick groups", True),
        ("after key alignment", True),
        ("route before the wall", True),
        ("normal vigenere problem", False),
        ("apply Polybius and a tableau", False),
        ("", False),
    ])
    def test_detect_block_reversal_trigger(self, text, expected):
        assert _detect_block_reversal_trigger(text) is expected, (
            f"text={text!r} expected={expected}"
        )

    def test_substring_no_false_positive(self):
        """Trigger tokens must respect word boundaries: 'block' inside
        'unblocking' or 'blockchain' does NOT fire; 'clock' inside
        'clockwork' does NOT fire (the 'k' next to 'w' breaks the
        word boundary). The trigger 'clockwise' IS in the list as a
        whole word and DOES fire on its own."""
        assert _detect_block_reversal_trigger("we are unblocking now") is False
        assert _detect_block_reversal_trigger("clockwork project") is False
        # The 'clockwise' trigger token is in the lexicon and matches
        # standalone.
        assert _detect_block_reversal_trigger("turn clockwise") is True

    @pytest.mark.parametrize("text,expected", [
        ("clockwise turn", True),
        ("rotate the disc", True),
        ("normal substitution", False),
    ])
    def test_detect_shift_trigger(self, text, expected):
        assert _detect_shift_trigger(text) is expected


# ---------------------------------------------------------------------------
# (4) Trigger-driven generation
# ---------------------------------------------------------------------------


class TestTriggerDrivenGeneration:
    def test_no_trigger_no_reverse_blocks(self):
        """A clue without triggers must NOT emit any reverse_blocks
        family. This is the regression guard for the "historical
        catalog unchanged" contract.
        """
        specs = generate_layered_specs(
            ["CEDAR", "LANTERN"], bench_slug="t",
            clue_text="ordinary cipher problem", max_specs=2000,
        )
        rb_specs = [
            s for s in specs
            if "reverse_blocks" in s.coverage.layer_family
        ]
        assert rb_specs == [], (
            f"unexpected reverse_blocks specs without trigger: "
            f"{[s.coverage.layer_family for s in rb_specs[:3]]}"
        )

    def test_block_trigger_emits_alone_family(self):
        clue = "small clock note, backward steps, reverse blocks before the key"
        specs = generate_layered_specs(
            ["CEDAR", "LANTERN"], bench_slug="t",
            clue_text=clue, max_specs=2000,
        )
        alone = [
            s for s in specs
            if s.coverage.layer_family == "reverse_blocks"
        ]
        assert len(alone) > 0, "reverse_blocks alone family did not fire"
        # Block sizes include both clue-derived and defaults
        sizes = {s.coverage.block_size for s in alone}
        assert _DEFAULT_BLOCK_SIZES[0] in sizes  # default 2
        # Both modes emitted in the alone family
        modes = {s.coverage.block_mode for s in alone}
        assert {"reverse_partial", "truncate"} <= modes

    def test_block_trigger_emits_pairings_with_each_substitution(self):
        clue = "small clock note, backward steps, reverse blocks before the key"
        specs = generate_layered_specs(
            ["CEDAR", "LANTERN"], bench_slug="t",
            clue_text=clue, max_specs=3000,
        )
        # Each substitution pairing must produce specs in BOTH layer
        # orders.
        for sub_kind, label in [
            ("vigenere", "reverse_blocks_vigenere"),
            ("beaufort", "reverse_blocks_beaufort"),
            ("variant_beaufort", "reverse_blocks_variant_beaufort"),
        ]:
            fam = [s for s in specs if s.coverage.layer_family == label]
            assert fam, f"family {label} produced no specs"
            orders = {s.coverage.layer_order for s in fam}
            assert (sub_kind, "reverse_blocks") in orders, (
                f"{label} missing sub-first layer order"
            )
            assert ("reverse_blocks", sub_kind) in orders, (
                f"{label} missing trans-first layer order"
            )

    def test_block_trigger_emits_caesar_pairing(self):
        clue = "small clock note, reverse blocks before the key"
        specs = generate_layered_specs(
            ["CEDAR", "LANTERN"], bench_slug="t",
            clue_text=clue, max_specs=3000,
        )
        caesar = [
            s for s in specs
            if s.coverage.layer_family == "reverse_blocks_caesar"
        ]
        assert caesar, "reverse_blocks_caesar produced no specs"
        # Caesar shifts coverage
        shifts = {
            v for s in caesar for k, v in s.coverage.extras
            if k == "caesar_shift"
        }
        assert _DEFAULT_CAESAR_SHIFTS[0] in shifts
        # Both layer orders present
        orders = {s.coverage.layer_order for s in caesar}
        assert ("caesar", "reverse_blocks") in orders
        assert ("reverse_blocks", "caesar") in orders

    def test_block_trigger_emits_atbash_pairing(self):
        clue = "small clock note, reverse blocks before the key"
        specs = generate_layered_specs(
            ["CEDAR", "LANTERN"], bench_slug="t",
            clue_text=clue, max_specs=3000,
        )
        atbash = [
            s for s in specs
            if s.coverage.layer_family == "reverse_blocks_atbash"
        ]
        assert atbash, "reverse_blocks_atbash produced no specs"
        orders = {s.coverage.layer_order for s in atbash}
        assert ("atbash", "reverse_blocks") in orders
        assert ("reverse_blocks", "atbash") in orders

    def test_three_layer_sandwiches_only_with_shift_trigger(self):
        """Three-layer Atbash / Caesar sandwiches require BOTH a
        block-reversal trigger AND a shift / rotation trigger.
        """
        # Block trigger only — no sandwiches
        specs_block = generate_layered_specs(
            ["CEDAR", "LANTERN"], bench_slug="t",
            clue_text="reverse the small groups", max_specs=3000,
        )
        sandwiches = [
            s for s in specs_block
            if s.coverage.layer_family.endswith("_atbash")
            and "_reverse_blocks_" in s.coverage.layer_family
        ]
        assert sandwiches == [], (
            f"three-layer sandwich fired without shift trigger: "
            f"{[s.coverage.layer_family for s in sandwiches[:3]]}"
        )
        # Both triggers — sandwiches fire
        specs_both = generate_layered_specs(
            ["CEDAR", "LANTERN"], bench_slug="t",
            clue_text="reverse the small groups, clockwise turn",
            max_specs=4000,
        )
        sandwich_labels = {
            s.coverage.layer_family for s in specs_both
            if "_reverse_blocks_" in s.coverage.layer_family
        }
        # Must include each sub × {atbash, caesar} pairing
        for sub in ("vigenere", "beaufort", "variant_beaufort"):
            for partner in ("atbash", "caesar"):
                label = f"{sub}_reverse_blocks_{partner}"
                assert label in sandwich_labels, (
                    f"sandwich {label} did not fire with both triggers"
                )

    def test_block_size_from_clue_numeral(self):
        """The clue text 'five tick groups' must contribute block_size=5
        with operation_source='clue_numeral'.
        """
        clue = "compass rose has five tick groups"
        sizes = _block_sizes_for_payload(clue)
        sources_for_5 = [
            src for n, src in sizes if n == 5
        ]
        assert sources_for_5 == ["clue_numeral"], (
            f"expected block_size 5 sourced from clue numeral; got {sizes}"
        )
        # Defaults still present after the clue size
        size_set = {n for n, _ in sizes}
        assert {2, 3, 4, 5, 6, 7, 8, 10} <= size_set


# ---------------------------------------------------------------------------
# (5) Coverage vector new fields
# ---------------------------------------------------------------------------


class TestCoverageVectorFields:
    def test_reverse_blocks_alone_carries_block_metadata(self):
        out = _gen_reverse_blocks_alone_family(
            bench_slug="t",
            block_sizes=[(5, "clue_numeral"), (3, "default_set")],
        )
        # Each spec carries non-empty block fields
        for s in out:
            assert s.coverage.block_size in (3, 5)
            assert s.coverage.block_mode in (
                "reverse_partial", "truncate",
            )
            assert s.coverage.operation_source in (
                "clue_numeral", "default_set",
            )

    def test_legacy_specs_keep_empty_block_fields(self):
        """Specs that don't include reverse_blocks must leave the new
        coverage fields at their safe empty defaults — the legacy
        catalog must not gain spurious metadata.
        """
        # Ordinary columnar+vigenere spec. ``include_three_layer=False``
        # keeps the universe small.
        specs = generate_layered_specs(
            ["CEDAR", "LANTERN"], bench_slug="t",
            clue_text="ordinary cipher", max_specs=200,
            include_three_layer=False,
        )
        non_rb = [
            s for s in specs
            if "reverse_blocks" not in s.coverage.layer_family
        ]
        assert non_rb, "expected non-reverse_blocks specs"
        for s in non_rb:
            assert s.coverage.block_size is None
            assert s.coverage.block_mode == ""
            assert s.coverage.operation_source == ""

    def test_coverage_vector_dict_round_trip(self):
        cv = CoverageVector(
            layer_family="reverse_blocks",
            layer_order=("reverse_blocks",),
            role_assignment=(),
            alphabet="AZ", n_layers=1,
            block_size=5, block_mode="reverse_partial",
            operation_source="clue_numeral",
        )
        d = cv.to_dict()
        assert d["block_size"] == 5
        assert d["block_mode"] == "reverse_partial"
        assert d["operation_source"] == "clue_numeral"
        cv2 = CoverageVector.from_dict(d)
        assert cv2.block_size == 5
        assert cv2.block_mode == "reverse_partial"
        assert cv2.operation_source == "clue_numeral"


# ---------------------------------------------------------------------------
# (6) Real-K4 mode unchanged
# ---------------------------------------------------------------------------


class TestRealK4Unchanged:
    def test_real_k4_collect_hcc_seeds_returns_empty(self, tmp_path):
        """The HCC fallback never fires in real-K4 mode regardless of
        what the lesson registry contains. The lesson is registered
        as a generalized tactic the LLM theorist can read, but the
        controller's deterministic HCC seed list is empty.
        """
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

    def test_real_k4_lesson_registry_still_includes_lesson_008(self):
        """Real K4 mode does not consume HCC seeds, but the LESSON-008
        entry MUST still be in the registry — that is how the LLM
        theorist gets the tactic at prompt-build time.
        """
        from kryptosbot.solver_capabilities import LessonRegistry
        # Use a fresh in-memory registry so test does not depend on
        # the on-disk state of db/solver_capabilities/lessons.json.
        reg = LessonRegistry(path=Path("/tmp/never-exists-test.json"),
                             seed_defaults=True)
        ids = {l.lesson_id for l in reg.all()}
        assert "LESSON-008" in ids


# ---------------------------------------------------------------------------
# (7) K4B-004 canary
# ---------------------------------------------------------------------------


class TestK4B004Canary:
    """K4B-004 canary: the LESSON-008 capability must include a spec
    that scores 24/24 on the K4B-004 challenge so the next bench-fast
    run finds the answer deterministically.
    """

    def _hcc_seeds_for_k4b004(self):
        if not _K4B004_PATH.exists():
            pytest.skip(f"K4B-004 fixture not on disk at {_K4B004_PATH}")
        from kryptosbot.bench_loader import load_k4bench_challenge
        from kryptosbot.bench_fallback import hand_cipher_core_fallback
        ch = load_k4bench_challenge(_K4B004_PATH)
        ch.install_kernel_overrides()
        return ch, hand_cipher_core_fallback(
            ch.canonical_facts(), n_target=5,
        )

    def test_k4b004_seeds_include_reverse_blocks_family(self):
        ch, seeds = self._hcc_seeds_for_k4b004()
        rb_seeds = [
            s for s in seeds
            if "reverse_blocks" in s.minimal_test_spec.get(
                "coverage_vector", {}
            ).get("layer_family", "")
        ]
        assert len(rb_seeds) > 0, (
            "K4B-004 HCC catalog must contain reverse_blocks seeds; "
            "the clue text 'five tick groups' triggers LESSON-008"
        )

    def test_k4b004_seeds_include_block_size_5(self):
        """The clue text 'five tick groups' MUST contribute block_size=5
        with operation_source='clue_numeral' to at least one seed.
        """
        _, seeds = self._hcc_seeds_for_k4b004()
        size5 = [
            s for s in seeds
            if s.minimal_test_spec.get(
                "coverage_vector", {}
            ).get("block_size") == 5
            and s.minimal_test_spec.get(
                "coverage_vector", {}
            ).get("operation_source") == "clue_numeral"
        ]
        assert size5, (
            "K4B-004 HCC catalog must contain block_size=5 seeds "
            "sourced from the 'five tick groups' clue numeral"
        )

    def test_k4b004_variant_beaufort_reverse_blocks_5_hits_24(self):
        """End-to-end: dispatch the variant_beaufort + reverse_blocks(5)
        spec on K4B-004 and confirm it hits crib_score 24. This is
        the deterministic-coverage proof that LESSON-008 closes the
        K4B-004 miss.

        Runs in a fresh subprocess so the kernel constants module
        loads with the K4B-004 CT/cribs override; an in-process call
        would fail if any earlier test had already imported the
        kernel against real K4 (the kernel reads override env vars
        at first import only).
        """
        if not _K4B004_PATH.exists():
            pytest.skip(f"K4B-004 fixture not on disk at {_K4B004_PATH}")
        import subprocess
        import sys
        env = {**__import__("os").environ}
        env["PYTHONPATH"] = (
            str(_REPO_ROOT / "src") + ":" + env.get("PYTHONPATH", "")
        )
        code = (
            "import json, sys\n"
            "from pathlib import Path\n"
            "sys.path.insert(0, str(Path(__file__).resolve().parent if False else "
            f"{str(_REPO_ROOT)!r}))\n"
            "from kryptosbot.bench_loader import load_k4bench_challenge\n"
            f"ch = load_k4bench_challenge({str(_K4B004_PATH)!r})\n"
            "ch.install_kernel_overrides()\n"
            "from kryptosbot.bench_fallback import hand_cipher_core_fallback\n"
            "from kryptosbot.hypothesis_dsl import validate_hypothesis_spec\n"
            "from kryptosbot.job_dispatcher import execute\n"
            "seeds = hand_cipher_core_fallback(ch.canonical_facts(), n_target=5)\n"
            "cands = [s for s in seeds\n"
            "         if s.minimal_test_spec.get('coverage_vector', {}).get('layer_family') "
            "== 'reverse_blocks_variant_beaufort'\n"
            "         and s.minimal_test_spec.get('coverage_vector', {}).get('block_size') == 5]\n"
            "best = 0.0\n"
            "for s in cands:\n"
            "    parsed = validate_hypothesis_spec(s.dsl_spec)\n"
            "    if not parsed.is_valid:\n"
            "        continue\n"
            "    r = execute(parsed.value, workers=1, parallel=False, bench_mode=True)\n"
            "    if r.best_score > best:\n"
            "        best = r.best_score\n"
            "print(json.dumps({'best': best, 'cand_count': len(cands)}))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            env=env,
            capture_output=True,
            text=True,
            cwd=str(_REPO_ROOT),
            timeout=300,
        )
        assert result.returncode == 0, (
            f"subprocess failed: rc={result.returncode}\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
        # Last JSON line of stdout
        import json as _json
        last_json_line = next(
            (ln for ln in reversed(result.stdout.strip().splitlines())
             if ln.startswith("{")),
            "",
        )
        assert last_json_line, (
            f"no JSON line found in subprocess stdout:\n{result.stdout}"
        )
        payload = _json.loads(last_json_line)
        assert payload["cand_count"] > 0, (
            "no variant_beaufort + reverse_blocks(5) candidate found"
        )
        assert payload["best"] == 24.0, (
            f"K4B-004 expected crib_score 24 from variant_beaufort + "
            f"reverse_blocks(5); got {payload['best']}. The "
            "deterministic block-reversal capability is incorrect "
            "or incomplete."
        )


# ---------------------------------------------------------------------------
# (8) Helpers — internal sanity
# ---------------------------------------------------------------------------


class TestInternalHelpers:
    def test_shift_to_keyword_round_trip(self):
        for k in range(1, 26):
            assert _shift_to_keyword(k) == chr(ord("A") + k)

    def test_shift_zero_is_rejected(self):
        with pytest.raises(ValueError):
            _shift_to_keyword(0)

    def test_reverse_blocks_layer_rejects_invalid_size(self):
        with pytest.raises(ValueError):
            _reverse_blocks_layer(1)
        with pytest.raises(ValueError):
            _reverse_blocks_layer(5, block_mode="bogus")

    def test_block_sizes_for_payload_orders_clue_numerals_first(self):
        sizes = _block_sizes_for_payload("five tick groups, three rows")
        # Clue numerals 5 and 3 come first
        clue_nums = [n for n, src in sizes if src == "clue_numeral"]
        assert clue_nums[0] in (3, 5)
        # Defaults appear after, with no overlap
        defaults = [n for n, src in sizes if src == "default_set"]
        assert set(defaults).isdisjoint(set(clue_nums))
