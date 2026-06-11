"""Tests for kryptosbot.pantheon.resolve_model_for_phase.

Pins the phase -> (model, fallback) routing policy so future model bumps and
phase-routing changes are intentional, not accidental. Added 2026-05-29
alongside the Opus 4.8 migration; updated 2026-06-10 for the Fable 5
migration, which routes every frontier-tier phase (frontmatter "opus" token
plus the worker phase) to claude-fable-5 with Sonnet fallback. Prior to this
file the routing function had no direct test coverage.
"""

import ast
import pathlib

import pytest

from kryptosbot.pantheon import (
    AgentSpec,
    resolve_model_for_phase,
    _SDK_FABLE,
    _SDK_OPUS,
    _SDK_SONNET,
    _SDK_HAIKU,
)


def _spec(model):
    """Minimal AgentSpec carrying only the frontmatter model declaration."""
    return AgentSpec(name="t", description="d", body="b", model=model)


class TestModelConstants:
    def test_fable_is_5(self):
        # The Fable 5 migration target (2026-06-10). If this changes, it must
        # be a deliberate model bump, not an accident.
        assert _SDK_FABLE == "claude-fable-5"

    def test_opus_is_4_8(self):
        # Retained for the thinking gate and historical pricing paths.
        assert _SDK_OPUS == "claude-opus-4-8"

    def test_sonnet_and_haiku_unchanged(self):
        # Sonnet 4.6 / Haiku 4.5 are the newest in their tiers.
        assert _SDK_SONNET == "claude-sonnet-4-6"
        assert _SDK_HAIKU == "claude-haiku-4-5"


class TestFrontmatterHonoringPhases:
    """theorist / red_team / stat_audit respect the persona frontmatter.

    The abstract frontmatter token "opus" means "frontier tier", not a
    concrete model id — since 2026-06-10 it routes to Fable 5.
    """

    def test_opus_persona_routes_to_fable(self):
        for phase in ("theorist", "red_team", "stat_audit"):
            assert resolve_model_for_phase(_spec("opus"), phase) == (
                _SDK_FABLE, _SDK_SONNET,
            ), phase

    def test_sonnet_persona_routes_to_sonnet(self):
        for phase in ("theorist", "red_team", "stat_audit"):
            assert resolve_model_for_phase(_spec("sonnet"), phase) == (
                _SDK_SONNET, _SDK_HAIKU,
            ), phase

    def test_haiku_persona_routes_to_haiku(self):
        assert resolve_model_for_phase(_spec("haiku"), "theorist") == (
            _SDK_HAIKU, _SDK_HAIKU,
        )

    def test_no_declared_model_defaults_to_sonnet(self):
        for phase in ("theorist", "red_team", "stat_audit"):
            assert resolve_model_for_phase(_spec(None), phase) == (
                _SDK_SONNET, _SDK_HAIKU,
            ), phase

    def test_phase_name_is_case_insensitive(self):
        assert resolve_model_for_phase(_spec("opus"), "THEORIST") == (
            _SDK_FABLE, _SDK_SONNET,
        )


class TestWorkerPhaseAlwaysFrontier:
    """Worker runs the frontier-tier model regardless of frontmatter.

    2026-05-29: worker upgraded Sonnet/Haiku -> Opus/Sonnet. 2026-06-10:
    Opus -> Fable 5. The worker translates an approved theory into a
    kernel-executable DSL HypothesisSpec under a strict fenced-JSON contract;
    a mis-translated spec wastes a whole bounded campaign or causes a false
    elimination, so it is routed to the frontier model regardless of
    frontmatter, with Sonnet (not Haiku) as the capable fallback. A
    regression here would silently downgrade the worker.
    """

    def test_worker_ignores_frontmatter_and_uses_fable(self):
        for declared in ("opus", "sonnet", "haiku", None):
            assert resolve_model_for_phase(_spec(declared), "worker") == (
                _SDK_FABLE, _SDK_SONNET,
            ), declared

    def test_worker_fallback_is_not_haiku(self):
        # The deliberate-frontier-for-correctness phase must not silently
        # degrade to the weakest tier on fallback.
        _, fallback = resolve_model_for_phase(_spec(None), "worker")
        assert fallback == _SDK_SONNET
        assert fallback != _SDK_HAIKU

    def test_worker_fallback_is_not_opus_4_8(self):
        # Deliberate: the thinking option is computed from the PRIMARY model
        # (None for Fable 5 — see thinking_config_for_model). An opus-4-8
        # fallback would then run WITHOUT the disabled-thinking gate and
        # reintroduce the GOTCHA2 long-session 400 crash. Sonnet is the safe
        # fallback tier.
        _, fallback = resolve_model_for_phase(_spec(None), "worker")
        assert fallback != _SDK_OPUS


class TestForcedSonnetPhases:
    """synthesis / pursuit stay Sonnet regardless of frontmatter.

    Short, bounded structured-verdict calls (pursuit is passive and cannot
    dispatch compute), so Opus headroom is deliberately not spent here.
    """

    def test_synthesis_always_sonnet(self):
        for declared in ("opus", "sonnet", None):
            assert resolve_model_for_phase(_spec(declared), "synthesis") == (
                _SDK_SONNET, _SDK_HAIKU,
            ), declared

    def test_pursuit_always_sonnet(self):
        for declared in ("opus", "sonnet", None):
            assert resolve_model_for_phase(_spec(declared), "pursuit") == (
                _SDK_SONNET, _SDK_HAIKU,
            ), declared


class TestThinkingGate:
    """thinking_config_for_model: disabled-dict for opus-4-8, None for Fable.

    Two distinct constraints meet here:
    - opus-4-8: long multi-turn Agent-SDK sessions 400 with "thinking blocks
      in the latest assistant message" once thinking blocks stop
      round-tripping in API-required order (GOTCHA2, 2026-05-31). The gate
      returns {"type": "disabled"}.
    - Fable 5: an EXPLICIT {"type": "disabled"} returns a 400 on
      claude-fable-5 (the thinking param must be omitted entirely). The gate
      must therefore return None for Fable — extending the opus-4-8
      disabled-dict to Fable would break every Fable session at the first
      API call.
    """

    def test_opus_4_8_disables_thinking(self):
        from kryptosbot.pantheon import thinking_config_for_model
        assert thinking_config_for_model("claude-opus-4-8") == {"type": "disabled"}

    def test_opus_4_8_1m_variant_disabled(self):
        # The 1M-context variant id must also be gated.
        from kryptosbot.pantheon import thinking_config_for_model
        assert thinking_config_for_model("claude-opus-4-8[1m]") == {"type": "disabled"}

    def test_fable_is_none_never_disabled_dict(self):
        # Fable 5 rejects an explicit disabled dict with a 400; the only safe
        # value is None (param omitted).
        from kryptosbot.pantheon import thinking_config_for_model
        assert thinking_config_for_model(_SDK_FABLE) is None

    def test_fable_1m_variant_is_none(self):
        from kryptosbot.pantheon import thinking_config_for_model
        assert thinking_config_for_model("claude-fable-5[1m]") is None

    def test_sonnet_is_none(self):
        from kryptosbot.pantheon import thinking_config_for_model
        assert thinking_config_for_model(_SDK_SONNET) is None

    def test_haiku_is_none(self):
        from kryptosbot.pantheon import thinking_config_for_model
        assert thinking_config_for_model(_SDK_HAIKU) is None

    def test_none_is_none(self):
        from kryptosbot.pantheon import thinking_config_for_model
        assert thinking_config_for_model(None) is None

    def test_resolved_worker_phase_routes_fable_and_omits_thinking(self):
        # End-to-end with the router: worker phase -> Fable 5 -> thinking
        # omitted (NOT the opus disabled-dict, which would 400 on Fable).
        from kryptosbot.pantheon import thinking_config_for_model
        model, _ = resolve_model_for_phase(_spec("opus"), "worker")
        assert model == _SDK_FABLE
        assert thinking_config_for_model(model) is None


class TestSdkThinkingFieldContract:
    """Pin that the installed claude_agent_sdk accepts our thinking value.

    Catches an SDK upgrade that renames/removes the field (the gate would
    then silently stop working).
    """

    def test_claude_agent_options_accepts_thinking_disabled(self):
        from claude_agent_sdk import ClaudeAgentOptions
        opts = ClaudeAgentOptions(thinking={"type": "disabled"})
        assert opts.thinking == {"type": "disabled"}


def _claude_agent_options_calls(tree):
    """Yield ast.Call nodes constructing ClaudeAgentOptions."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        name = fn.id if isinstance(fn, ast.Name) else (
            fn.attr if isinstance(fn, ast.Attribute) else None
        )
        if name == "ClaudeAgentOptions":
            yield node


class TestThinkingGateWiredEverywhere:
    """Drift guard: every model-bearing SDK session must set the gate.

    Direct-keyword sites (theorist, red-team, stat-audit, pursuit, synthesis)
    are checked structurally. The worker site builds ClaudeAgentOptions(**kwargs)
    so it carries neither keyword directly; it is covered by asserting the gate
    helper is referenced in each file.
    """

    _ROOT = pathlib.Path(__file__).resolve().parents[1]

    @pytest.mark.parametrize("relpath", ["controller.py", "pantheon_siblings.py"])
    def test_direct_model_options_set_thinking(self, relpath):
        src = (self._ROOT / relpath).read_text()
        tree = ast.parse(src)
        offenders = []
        for call in _claude_agent_options_calls(tree):
            kws = {kw.arg for kw in call.keywords if kw.arg is not None}
            if "model" in kws and "thinking" not in kws:
                offenders.append(call.lineno)
        assert not offenders, (
            f"{relpath}: ClaudeAgentOptions sets model= but not thinking= at "
            f"lines {offenders} — wire thinking_config_for_model(model)"
        )

    @pytest.mark.parametrize("relpath", ["controller.py", "pantheon_siblings.py"])
    def test_gate_helper_referenced(self, relpath):
        src = (self._ROOT / relpath).read_text()
        assert "thinking_config_for_model" in src, (
            f"{relpath}: gate helper not referenced — worker/**kwargs sites "
            f"could silently miss the thinking gate"
        )
