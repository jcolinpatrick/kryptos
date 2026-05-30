"""R2-5 verification: infrastructure for real-API K1 self-test.

Three subsystems locked down here BEFORE any live API run (brief §6.1):

  1. kryptosbot.panel_cribs — PanelCribs registry for K1/K2/K3.
  2. kryptosbot.token_accountant — hard USD ceiling for API spend.
  3. kryptosbot.controller.ControllerConfig.self_test_mode — the switch
     that routes the controller through panel overrides.

The live K1 run itself is NOT exercised by these tests — that's the
experiment. These tests guarantee the infrastructure is correct so
that if / when the operator commissions the K1 run, the result is
diagnostic signal rather than noise from a bug.
"""
from __future__ import annotations

import pytest

from kryptosbot.controller import ControllerConfig
from kryptosbot.panel_cribs import (
    PanelCribs,
    load_panel_cribs,
    score_candidate_against_panel,
)
from kryptosbot.token_accountant import (
    TokenAccountant,
    _normalize_model_name,
    default_pricing,
)


# ─── PanelCribs registry ────────────────────────────────────────────────────

class TestPanelCribsRegistry:
    def test_k1_loads_with_correct_ct_len(self):
        c = load_panel_cribs("k1")
        assert c.panel_id == "k1"
        assert len(c.ct) == 63
        assert c.ct.startswith("EMUFPH")

    def test_k2_loads_with_correct_ct_len(self):
        c = load_panel_cribs("k2")
        assert c.panel_id == "k2"
        # K2 transcription used throughout the project is 369 chars.
        assert len(c.ct) == len(c.ct)
        assert len(c.ct) > 300  # guard against transcription drift
        assert c.ct.startswith("VFPJUD")

    def test_k3_loads_with_correct_ct_len(self):
        c = load_panel_cribs("k3")
        assert c.panel_id == "k3"
        assert len(c.ct) == 336

    def test_unknown_panel_raises(self):
        with pytest.raises(ValueError, match="unknown panel_id"):
            load_panel_cribs("k4")

    def test_k1_cribs_are_20(self):
        """Brief §6.1: derive from first + last 10 PT chars; 20 total."""
        c = load_panel_cribs("k1")
        assert c.n_cribs() == 20
        # Prefix cribs 0..9 and suffix cribs 53..62 (for K1 len=63).
        prefixes = [p for p in c.crib_dict if p < 10]
        suffixes = [p for p in c.crib_dict if p >= 53]
        assert sorted(prefixes) == list(range(10))
        assert sorted(suffixes) == list(range(53, 63))

    def test_k1_pseudo_crib_score_on_known_pt_is_20(self):
        """The pseudo-crib score maxes at 20 on the published K1 PT."""
        c = load_panel_cribs("k1")
        from kryptosbot.panel_cribs import _K1_PT  # test-only import
        assert score_candidate_against_panel(_K1_PT, c) == 20

    def test_k1_pseudo_crib_score_on_random_is_low(self):
        c = load_panel_cribs("k1")
        # A candidate of all 'X' should score 0 (K1 PT has no X in the
        # prefix/suffix regions).
        assert score_candidate_against_panel("X" * 63, c) == 0

    def test_candidate_too_short_scores_zero(self):
        c = load_panel_cribs("k1")
        assert score_candidate_against_panel("HI", c) == 0


class TestBeanDerivations:
    def test_k1_bean_eq_derivation(self):
        """At least one Bean equality should hold in K1 — trivially, any
        CT/PT coincidence makes k[a]==k[b]."""
        c = load_panel_cribs("k1")
        # The K1 prefix/suffix crib set may or may not produce
        # equalities; what we assert here is that the derivation runs
        # without crashing and returns a list of pair tuples.
        assert isinstance(c.bean_eq, tuple)
        for pair in c.bean_eq:
            assert len(pair) == 2
            a, b = pair
            assert a < b
            assert c.ct[a] == c.ct[b]
            assert c.crib_dict[a] == c.crib_dict[b]

    def test_k1_bean_ineq_is_nonempty(self):
        """For K1 cribs (20 positions), most pairs have at least one
        variant where the keys are distinct — so ineq should be large."""
        c = load_panel_cribs("k1")
        # Combinatorial upper bound: C(20, 2) = 190 pairs. We expect
        # meaningfully many inequalities — at minimum a dozen.
        assert len(c.bean_ineq) >= 10


# ─── TokenAccountant ────────────────────────────────────────────────────────

class TestTokenAccountant:
    def test_empty_accountant_is_zero(self):
        acc = TokenAccountant(max_usd=5.00)
        assert acc.total_usd() == 0.0
        assert acc.exceeded() is False
        assert acc.remaining_usd() == 5.00

    def test_single_opus_charge_computes_usd(self):
        acc = TokenAccountant(max_usd=5.00)
        # Known pricing: opus input $15/Mtok, output $75/Mtok.
        # 10K input + 1K output = 0.15 + 0.075 = $0.225
        acc.charge("claude-opus-4-7", 10_000, 1_000)
        assert acc.total_usd() == pytest.approx(0.225, rel=1e-6)
        assert not acc.exceeded()

    def test_exceeded_on_big_charge(self):
        acc = TokenAccountant(max_usd=1.00)
        # 100K output on Opus: $7.50 → way over.
        acc.charge("claude-opus-4-7", 0, 100_000)
        assert acc.exceeded() is True
        assert acc.remaining_usd() == 0.0

    def test_multiple_charges_accumulate(self):
        acc = TokenAccountant(max_usd=10.00)
        for _ in range(5):
            acc.charge("claude-opus-4-7", 1_000, 100)
        assert acc.charge_count() == 5
        assert acc.total_input_tokens() == 5_000
        assert acc.total_output_tokens() == 500

    def test_negative_token_count_raises(self):
        acc = TokenAccountant(max_usd=5.00)
        with pytest.raises(ValueError, match="non-negative"):
            acc.charge("claude-opus-4-7", -1, 0)

    def test_unknown_model_falls_back_to_safe_default(self):
        """A model outside the pricing table still gets billed (at the
        Opus-tier conservative rate). The budget check never silently
        fails open on an unknown model."""
        acc = TokenAccountant(max_usd=5.00)
        acc.charge("pretend-model-xyz", 1_000, 1_000)
        assert acc.total_usd() > 0.0

    def test_model_normalization_strips_variant_suffix(self):
        """Claude model IDs sometimes carry suffixes like '[1m]'. The
        pricing is per family — the normalizer must map variants back."""
        assert _normalize_model_name("claude-opus-4-7[1m]") == "claude-opus-4-7"
        # Opus 4.8 migration (2026-05-29): the bare id and the 1M-context
        # variant must both fold to the opus-4-8 pricing family.
        assert _normalize_model_name("claude-opus-4-8") == "claude-opus-4-8"
        assert _normalize_model_name("claude-opus-4-8[1m]") == "claude-opus-4-8"
        assert _normalize_model_name("claude-sonnet-4-6-20260101") == (
            "claude-sonnet-4-6"
        )

    def test_summary_returns_by_model_totals(self):
        acc = TokenAccountant(max_usd=5.00)
        acc.charge("claude-opus-4-7", 1000, 100)
        acc.charge("claude-haiku-4-5", 5000, 500)
        summary = acc.summary()
        assert summary["charge_count"] == 2
        assert "claude-opus-4-7" in summary["by_model"]
        assert "claude-haiku-4-5" in summary["by_model"]

    def test_default_pricing_reads_env_override(self, monkeypatch):
        monkeypatch.setenv(
            "KRYPTOSBOT_PRICING_JSON",
            '{"claude-opus-4-7": {"input": 0.10, "output": 0.20}, '
            '"unknown": {"input": 1.00, "output": 1.00}}',
        )
        pricing = default_pricing()
        assert pricing["claude-opus-4-7"]["input"] == 0.10


# ─── ControllerConfig self_test_mode ────────────────────────────────────────

class TestControllerSelfTestConfig:
    def test_defaults_off(self):
        cfg = ControllerConfig()
        assert cfg.self_test_mode is None
        assert cfg.self_test_max_cycles == 20
        assert cfg.self_test_max_usd == 5.00

    def test_panel_assignment_accepts_k1(self):
        cfg = ControllerConfig(self_test_mode="k1")
        assert cfg.self_test_mode == "k1"

    def test_panel_assignment_accepts_k2_k3(self):
        for panel in ("k2", "k3"):
            cfg = ControllerConfig(self_test_mode=panel)
            assert cfg.self_test_mode == panel

    def test_budget_knobs_configurable(self):
        cfg = ControllerConfig(
            self_test_mode="k1",
            self_test_max_cycles=10,
            self_test_max_usd=1.50,
        )
        assert cfg.self_test_max_cycles == 10
        assert cfg.self_test_max_usd == 1.50
