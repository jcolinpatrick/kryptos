"""Tests for kryptosbot.pantheon.resolve_model_for_phase.

Pins the phase -> (model, fallback) routing policy so future model bumps and
phase-routing changes are intentional, not accidental. Added 2026-05-29
alongside the Opus 4.8 migration, which (a) bumped _SDK_OPUS to
claude-opus-4-8 and (b) upgraded the worker phase from Sonnet/Haiku to
Opus/Sonnet. Prior to this file the routing function had no direct test
coverage.
"""

from kryptosbot.pantheon import (
    AgentSpec,
    resolve_model_for_phase,
    _SDK_OPUS,
    _SDK_SONNET,
    _SDK_HAIKU,
)


def _spec(model):
    """Minimal AgentSpec carrying only the frontmatter model declaration."""
    return AgentSpec(name="t", description="d", body="b", model=model)


class TestModelConstants:
    def test_opus_is_4_8(self):
        # The Opus 4.8 migration target. If this changes, it must be a
        # deliberate model bump, not an accident.
        assert _SDK_OPUS == "claude-opus-4-8"

    def test_sonnet_and_haiku_unchanged(self):
        # Sonnet 4.6 / Haiku 4.5 are the newest in their tiers.
        assert _SDK_SONNET == "claude-sonnet-4-6"
        assert _SDK_HAIKU == "claude-haiku-4-5"


class TestFrontmatterHonoringPhases:
    """theorist / red_team / stat_audit respect the persona frontmatter."""

    def test_opus_persona_routes_to_opus(self):
        for phase in ("theorist", "red_team", "stat_audit"):
            assert resolve_model_for_phase(_spec("opus"), phase) == (
                _SDK_OPUS, _SDK_SONNET,
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
            _SDK_OPUS, _SDK_SONNET,
        )


class TestWorkerPhaseAlwaysOpus:
    """2026-05-29 policy change: worker upgraded Sonnet/Haiku -> Opus/Sonnet.

    The worker translates an approved theory into a kernel-executable DSL
    HypothesisSpec under a strict fenced-JSON contract; a mis-translated spec
    wastes a whole bounded campaign or causes a false elimination, so it is
    routed to Opus regardless of frontmatter, with Sonnet (not Haiku) as the
    capable fallback. A regression here would silently downgrade the worker.
    """

    def test_worker_ignores_frontmatter_and_uses_opus(self):
        for declared in ("opus", "sonnet", "haiku", None):
            assert resolve_model_for_phase(_spec(declared), "worker") == (
                _SDK_OPUS, _SDK_SONNET,
            ), declared

    def test_worker_fallback_is_not_haiku(self):
        # The deliberate-Opus-for-correctness phase must not silently degrade
        # to the weakest tier on fallback.
        _, fallback = resolve_model_for_phase(_spec(None), "worker")
        assert fallback == _SDK_SONNET
        assert fallback != _SDK_HAIKU


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
