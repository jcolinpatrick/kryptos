"""Synthetic-signal alert-path test harness (R3 maturation).

Closes the live-untested arm of the matched-null alert pipeline that
Campaign A left open (see K4_CAMPAIGN_A_POSTMORTEM.md §7.2). Drives
fabricated SIGNAL/BREAKTHROUGH outcomes through the live
classify_outcome / process_alerts / _check_cycle_hardening_halts chain
under each p_value_status bucket: ok_matched_family, ok_gated,
matched_null_miss, cache_miss.

Scope: exercise existing code; never modify production; use only the
4 calibrated families already in null_baselines/manifest.json. Covers
Criterion 1' (matched-family consultation on beaufort / variant_beaufort,
the families outside DSL_SPEC_CONTRACT worked examples).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from kryptosbot.alerts import (
    AlertEvent, AlertLevel, classify_outcome, process_alerts,
    _matched_null_family_from_contract,
)
from kryptosbot.controller import (
    ControllerConfig, ResearchController,
    FALLBACK_HALT_STREAK, D_ZERO_HALT_STREAK,
)
from kryptosbot.models import (
    TheoryRecord, TheoryStatus, WorkerContract, WorkerStatus,
)
from kryptosbot import alerts as alerts_mod
from kryptosbot import null_baselines as nb_mod


# Real English-like plaintext (K2 solve excerpt), length 97, sufficient
# to clear BREAKTHROUGH_NGRAM_FLOOR when the kernel ngram scorer runs.
_ENGLISH_97 = (
    "ITWASTOTALLYINVISIBLEHOWSTHATPOSSIBLETHEYUSEDTHE"
    "EARTHSMAGNETICFIELDXTHEINFORMATIONWASGATHEREDAND"
    "T"
)
assert len(_ENGLISH_97) == 97


def _fab(pipeline_kinds=None, crib_score=18, bean_passed=False,
         hypothesis_id="SYN-TEST", plaintext=_ENGLISH_97):
    """Build a WorkerContract whose raw_artifacts['dsl_pipeline_kinds']
    drives _matched_null_family_from_contract."""
    return WorkerContract(
        hypothesis_id=hypothesis_id,
        worker_role="dsl_dispatcher",
        status=WorkerStatus.SUCCESS,
        score=float(crib_score),
        crib_score=int(crib_score),
        bean_passed=bean_passed,
        best_plaintext=plaintext,
        raw_artifacts={"dsl_pipeline_kinds": list(pipeline_kinds or [])},
    )


def _controller(tmp_path):
    config = ControllerConfig(
        project_root=tmp_path,
        ledger_db_path=tmp_path / "ledger.sqlite",
        alert_threshold="signal",
    )
    return ResearchController(config)


def _theory_for(contract, family="test"):
    return TheoryRecord(
        hypothesis_id=contract.hypothesis_id,
        title=f"Synthetic theory for {contract.hypothesis_id}",
        core_claim="synthetic test fabrication",
        mechanism="synthetic", family=family,
        status=TheoryStatus.APPROVED,
    )


def _redirect_cache(tmp_path, monkeypatch, *, keep_random_text=False, family=""):
    """Redirect nb_mod._FULL_CACHE_DIR to a fresh tmp dir.

    ``keep_random_text`` copies the real random_text distribution over
    so caller hits the matched_null_miss path (family cache missing,
    fallback cache present). Without it, every lookup misses →
    cache_miss path.
    """
    d = tmp_path / "nulls"
    d.mkdir()
    if keep_random_text:
        real = nb_mod.get_cached("crib_score", "random_text", 97, "AZ")
        assert real is not None, "precondition: random_text cache required"
        # Also verify the family we'd otherwise hit actually exists in
        # production, so this test exercises the miss path rather than a
        # pre-existing environment hole.
        if family:
            assert nb_mod.get_cached(
                "crib_score", "matched_variant_family", 97, "AZ", family=family,
            ) is not None, (
                f"precondition: matched-family cache for {family!r} "
                f"must exist in real env for this miss test to be meaningful"
            )
    monkeypatch.setattr(nb_mod, "_FULL_CACHE_DIR", d)
    if keep_random_text:
        nb_mod.save_to_cache(real)
    return d


# ---------------------------------------------------------------------------
# Scenario A — happy-path matched-null consultation, one per calibrated family
# ---------------------------------------------------------------------------

class TestScenarioA_MatchedNullHappyPath:
    """Real cache hit on every R2-4 calibrated family.

    Originally this class documented a production defect: at the R2-4
    calibration of 50K samples per family, ``ok_matched_family`` was
    structurally unreachable because the empirical floor (2e-4)
    exceeded the configured 1e-6 gate. Every real matched-family alert
    would have landed in ``matched_family_ungated`` (suppressed).

    Resolution (follow-up brief): null cache recalibrated to 10M
    samples AND ``null_baselines.effective_gate`` now widens the gate
    to the empirical floor when calibration can't support the
    configured gate. With both fixes, matched-family alerts at
    SIGNAL-level crib scores now produce ``ok_matched_family`` under
    the real configured gate, not a monkeypatched one.

    These tests no longer require the gate monkeypatch."""

    @pytest.mark.parametrize(
        "pipeline_kinds, expected_family",
        [
            (["beaufort"], "beaufort"),
            (["variant_beaufort"], "variant_beaufort"),
            (["columnar"], "columnar_single"),
            (["columnar", "columnar"], "columnar_double"),
        ],
    )
    def test_matched_family_consulted_at_signal(
        self, pipeline_kinds, expected_family, monkeypatch,
    ):
        # Sanity: the real manifest must have this family cached, else
        # the test is measuring an environmental hole, not the code path.
        assert nb_mod.get_cached(
            "crib_score", "matched_variant_family", 97, "AZ",
            family=expected_family,
        ) is not None, (
            f"precondition: calibrated cache missing for {expected_family!r}"
        )

        # Spy on p_value_for_alert to confirm the family argument flows
        # through from contract → _matched_null_family_from_contract →
        # _p_value_gate_passes → p_value_for_alert.
        calls: list[str] = []
        real_pvfa = nb_mod.p_value_for_alert

        def spy(plaintext, crib_score_value, family=""):
            calls.append(family)
            return real_pvfa(plaintext, crib_score_value, family=family)

        monkeypatch.setattr(nb_mod, "p_value_for_alert", spy)

        contract = _fab(pipeline_kinds=pipeline_kinds, crib_score=18)
        assert _matched_null_family_from_contract(contract) == expected_family, (
            "precondition: kind list must resolve to expected family"
        )

        level, status = classify_outcome(contract, AlertLevel.SIGNAL)
        assert level == AlertLevel.SIGNAL
        assert status == "ok_matched_family", (
            f"expected ok_matched_family; got {status!r}"
        )
        assert expected_family in calls, (
            f"p_value_for_alert should have been called with "
            f"family={expected_family!r}; got call list {calls}"
        )

    def test_production_matched_family_alert_clearable_post_fix(self):
        """Post-fix behaviour check: under the real configured gate
        (no monkeypatch), a matched-family alert at SIGNAL-level crib
        score now produces ``ok_matched_family`` — not
        ``matched_family_ungated``.

        Fails loudly if either fix regresses:
          (1) null cache recalibration at n_samples >= 10M (the
              empirical floor ``10/n_samples`` must be ≤ configured gate)
          (2) ``null_baselines.effective_gate`` must widen the gate to
              the empirical floor when calibration can't support it

        A fail here means signal-level matched-family alerts are being
        silently suppressed again — the exact defect this work closed."""
        contract = _fab(pipeline_kinds=["beaufort"], crib_score=18)
        level, status = classify_outcome(contract, AlertLevel.SIGNAL)
        assert level == AlertLevel.SIGNAL, (
            f"post-fix: matched-family alert at crib=18 must clear the "
            f"effective gate. Got level={level!r}. Check (a) n_samples in "
            f"null_baselines/manifest.json and (b) effective_gate wiring."
        )
        assert status == "ok_matched_family", (
            f"post-fix: expected ok_matched_family; got {status!r}"
        )


# ---------------------------------------------------------------------------
# Scenario B — not-calibrated family path (random_text fallback, not a miss)
# ---------------------------------------------------------------------------

class TestScenarioB_NotCalibratedFallback:
    """A contract whose pipeline kinds don't resolve to any calibrated
    family must NOT produce ``matched_null_miss`` — it produces
    ``ok_gated`` (the legacy Phase 6 random_text path). ``matched_null_miss``
    specifically means "caller requested a family that we couldn't serve";
    not requesting anything is a different bucket."""

    @pytest.mark.parametrize("pipeline_kinds", [
        ["grille"],                  # single-layer non-calibrated
        ["vigenere", "columnar"],    # multi-layer not matching columnar_double
        [],                          # empty kinds
    ])
    def test_resolves_to_empty_family_and_ok_gated(self, pipeline_kinds):
        contract = _fab(pipeline_kinds=pipeline_kinds, crib_score=18)
        assert _matched_null_family_from_contract(contract) == ""
        level, status = classify_outcome(contract, AlertLevel.SIGNAL)
        assert level == AlertLevel.SIGNAL
        # random_text exists; p(X>=18) ≈ 3.7e-21 ≪ 1e-6 gate → ok_gated.
        assert status == "ok_gated"


# ---------------------------------------------------------------------------
# Scenario C — matched_null_miss + halt condition
# ---------------------------------------------------------------------------

class TestScenarioC_MatchedNullMiss:
    """Caller requests a calibrated family but that cache entry is gone.
    The gate returns ``matched_null_miss`` and — combined with a
    BREAKTHROUGH-level contract — the halt condition fires."""

    def test_matched_null_miss_bubbles_to_status(self, tmp_path, monkeypatch):
        _redirect_cache(tmp_path, monkeypatch, keep_random_text=True, family="beaufort")
        contract = _fab(pipeline_kinds=["beaufort"], crib_score=18)
        level, status = classify_outcome(contract, AlertLevel.SIGNAL)
        assert level == AlertLevel.SIGNAL
        assert status == "matched_null_miss"

    def test_breakthrough_plus_matched_null_miss_triggers_halt(
        self, tmp_path, monkeypatch,
    ):
        _redirect_cache(tmp_path, monkeypatch, keep_random_text=True, family="beaufort")
        monkeypatch.setattr(alerts_mod, "_ngram_per_char_safe", lambda _pt: -3.0)

        contract = _fab(
            pipeline_kinds=["beaufort"], crib_score=24,
            bean_passed=True, hypothesis_id="SYN-BK-MISS",
        )
        level, status = classify_outcome(contract, AlertLevel.BREAKTHROUGH)
        assert level == AlertLevel.BREAKTHROUGH
        assert status == "matched_null_miss"

        events = process_alerts(
            outcomes=[contract], threshold=AlertLevel.BREAKTHROUGH,
            cycle_number=1, results_dir=tmp_path / "breakthroughs",
        )
        assert len(events) == 1
        assert events[0].p_value_status == "matched_null_miss"
        assert events[0].level == "breakthrough"

        ctrl = _controller(tmp_path)
        reason = ctrl._check_cycle_hardening_halts(
            candidates=[_theory_for(contract)],
            outcomes=[contract],
            triggered_alerts=events,
        )
        assert reason is not None, "halt should fire on BREAKTHROUGH + matched_null_miss"
        assert "null cache" in reason.lower() or "calibrate" in reason.lower()
        assert ctrl.state.halt_reason_hardening == reason


# ---------------------------------------------------------------------------
# Scenario D — cache_miss path (no null cache at all) + halt
# ---------------------------------------------------------------------------

class TestScenarioD_CacheMiss:
    """No null cache anywhere — even random_text is gone. Gate fails
    open (legacy behaviour) but flags status=cache_miss so the halt
    condition can fire on BREAKTHROUGH."""

    def test_cache_miss_on_empty_cache_dir(self, tmp_path, monkeypatch):
        _redirect_cache(tmp_path, monkeypatch)
        contract = _fab(pipeline_kinds=["beaufort"], crib_score=18)
        level, status = classify_outcome(contract, AlertLevel.SIGNAL)
        # Gate fails open on cache_miss (legacy) — SIGNAL still fires.
        assert level == AlertLevel.SIGNAL
        assert status == "cache_miss"

    def test_breakthrough_plus_cache_miss_triggers_halt(self, tmp_path, monkeypatch):
        _redirect_cache(tmp_path, monkeypatch)
        monkeypatch.setattr(alerts_mod, "_ngram_per_char_safe", lambda _pt: -3.0)

        contract = _fab(
            pipeline_kinds=["beaufort"], crib_score=24,
            bean_passed=True, hypothesis_id="SYN-BK-CM",
        )
        events = process_alerts(
            outcomes=[contract], threshold=AlertLevel.BREAKTHROUGH,
            cycle_number=1, results_dir=tmp_path / "breakthroughs",
        )
        assert len(events) == 1
        assert events[0].p_value_status == "cache_miss"
        assert events[0].level == "breakthrough"

        ctrl = _controller(tmp_path)
        reason = ctrl._check_cycle_hardening_halts(
            candidates=[_theory_for(contract)],
            outcomes=[contract], triggered_alerts=events,
        )
        assert reason is not None
        assert "null cache" in reason.lower() or "calibrate" in reason.lower()


# ---------------------------------------------------------------------------
# Scenario E — Criterion 1' closure (the specific unobserved criterion)
# ---------------------------------------------------------------------------

class TestScenarioE_CriterionOnePrimeClosure:
    """Criterion 1' in ``docs/maturation/round3/K4_CAMPAIGN_A_PREREG.md``
    §3 required an ``ok_matched_family`` alert on a family OUTSIDE the
    DSL_SPEC_CONTRACT worked examples. The only non-worked-example
    families in the R2-4 calibrated set are ``beaufort`` and
    ``variant_beaufort``.

    Campaign A did not observe this because no signal fired at all.
    This test synthesizes that observation to prove the infrastructure
    behaves correctly when signal does fire. It closes the postmortem's
    §7.2 largest-remaining-gap item."""

    @pytest.mark.parametrize(
        "non_worked_example_family", ["beaufort", "variant_beaufort"],
    )
    def test_matched_family_null_on_family_outside_worked_examples(
        self, non_worked_example_family,
    ):
        # Post-fix: the gate monkeypatch is no longer required —
        # effective_gate widens to the empirical floor when the cache
        # can't support the configured gate, and the 10M recalibration
        # brings the floor down to meet the gate exactly.
        contract = _fab(
            pipeline_kinds=[non_worked_example_family],
            crib_score=18,
            hypothesis_id=f"SYN-CRIT1P-{non_worked_example_family}",
        )
        derived_family = _matched_null_family_from_contract(contract)
        assert derived_family == non_worked_example_family, (
            f"pipeline_kinds=[{non_worked_example_family!r}] should derive "
            f"to family={non_worked_example_family!r}; got {derived_family!r}"
        )
        level, status = classify_outcome(contract, AlertLevel.SIGNAL)
        assert level == AlertLevel.SIGNAL
        assert status == "ok_matched_family", (
            "Criterion 1' closure: a signal-level alert on a "
            f"{non_worked_example_family!r}-family contract must consult "
            f"the matched-family null cache. Got status={status!r}."
        )


# ---------------------------------------------------------------------------
# Scenario F — full integration via _run_alerts
# ---------------------------------------------------------------------------

class TestScenarioF_EndToEndIntegration:
    """Drive a synthetic contract through the live controller surface
    (``_run_alerts`` + ``_check_cycle_hardening_halts``) the same way a
    real cycle does. If any glue between classify_outcome → AlertEvent
    → controller state is broken, this is the canary."""

    def test_ok_matched_family_end_to_end_no_halt(self, tmp_path):
        # Post-fix: real configured gate — no monkeypatch needed.
        ctrl = _controller(tmp_path)
        ctrl._begin_cycle_phase_state()
        ctrl.state.cycle_number = 1

        contract = _fab(pipeline_kinds=["beaufort"], crib_score=18,
                        hypothesis_id="SYN-F-HAPPY")
        theory = _theory_for(contract, family="beaufort")
        ctrl._run_alerts([theory], [contract])

        assert len(ctrl._cycle_alert_events) == 1
        ev = ctrl._cycle_alert_events[0]
        assert ev.level == "signal"
        assert ev.p_value_status == "ok_matched_family"

        reason = ctrl._check_cycle_hardening_halts(
            candidates=[theory], outcomes=[contract],
            triggered_alerts=ctrl._cycle_alert_events,
        )
        assert reason is None
        assert ctrl.state.halt_reason_hardening == ""

    def test_breakthrough_matched_null_miss_end_to_end_halts(self, tmp_path, monkeypatch):
        _redirect_cache(tmp_path, monkeypatch, keep_random_text=True, family="beaufort")
        monkeypatch.setattr(alerts_mod, "_ngram_per_char_safe", lambda _pt: -3.0)

        ctrl = _controller(tmp_path)
        ctrl._begin_cycle_phase_state()
        ctrl.state.cycle_number = 1

        contract = _fab(pipeline_kinds=["beaufort"], crib_score=24,
                        bean_passed=True, hypothesis_id="SYN-F-HALT")
        theory = _theory_for(contract, family="beaufort")
        ctrl._run_alerts([theory], [contract])

        assert len(ctrl._cycle_alert_events) == 1
        ev = ctrl._cycle_alert_events[0]
        assert ev.level == "breakthrough"
        assert ev.p_value_status == "matched_null_miss"

        reason = ctrl._check_cycle_hardening_halts(
            candidates=[theory], outcomes=[contract],
            triggered_alerts=ctrl._cycle_alert_events,
        )
        assert reason is not None
        assert ctrl.state.halt_reason_hardening == reason
        # Immediate-halt condition — counters untouched, not a streak.
        assert ctrl.state.consecutive_fallback_cycles == 0


def test_module_constants_match_production():
    """Guard against the harness silently testing a divergent copy of
    the halt-streak constants."""
    assert isinstance(FALLBACK_HALT_STREAK, int) and FALLBACK_HALT_STREAK >= 1
    assert isinstance(D_ZERO_HALT_STREAK, int) and D_ZERO_HALT_STREAK >= 1


# ---------------------------------------------------------------------------
# Gate parameterization invariant — effective_gate(null) widens configured
# gate to the empirical floor when calibration can't support it.
# ---------------------------------------------------------------------------

class TestGateParameterization:
    """``null_baselines.effective_gate`` enforces the invariant that
    ``alert gate >= 10 / n_samples`` so a undersampled null cache can
    never silently suppress matched-family alerts."""

    def test_gate_parameterization_logs_warning_below_floor(self, caplog):
        import logging
        from kryptosbot.null_baselines import (
            NullDistribution, effective_gate, _warned_floor_mismatches,
        )

        # Synthetic null with n_samples=10K → empirical floor = 1e-3,
        # well above the 1e-6 configured gate → widens + warns.
        null = NullDistribution(
            scorer_name="crib_score",
            method="matched_variant_family",
            n_chars=97, alphabet="AZ",
            n_samples=10_000, seed=42,
            kernel_commit="test-synthetic",
            sorted_scores=[0.0] * 10_000,
            mean=0.0, stdev=0.0,
            family="beaufort_lowsample_test",
        )

        # Ensure a fresh warning (the module-level dedup set is per-session).
        _warned_floor_mismatches.discard((null.family, _pid()))

        with caplog.at_level(logging.WARNING, logger="kryptosbot.null_baselines"):
            gate = effective_gate(null, 1e-6)

        assert gate == pytest.approx(1e-3), (
            f"expected gate widened to empirical floor 1e-3; got {gate!r}"
        )
        warning_msgs = [r.message for r in caplog.records if "empirical floor" in r.message]
        assert warning_msgs, (
            "expected a warning when gate < empirical floor; none logged"
        )
        # Second call must NOT re-warn (dedup by (family, session)).
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="kryptosbot.null_baselines"):
            gate2 = effective_gate(null, 1e-6)
        assert gate2 == gate
        assert not [r for r in caplog.records if "empirical floor" in r.message], (
            "effective_gate must dedup warnings per (family, session)"
        )

    def test_effective_gate_respects_configured_when_cache_is_sufficient(self):
        from kryptosbot.null_baselines import NullDistribution, effective_gate

        # Synthetic null with n_samples=10M → empirical floor = 1e-6 = configured
        # → returns configured gate unchanged, no warning.
        null = NullDistribution(
            scorer_name="crib_score",
            method="matched_variant_family",
            n_chars=97, alphabet="AZ",
            n_samples=10_000_000, seed=42,
            kernel_commit="test",
            sorted_scores=[],
            mean=0.0, stdev=0.0,
            family="sufficient_test",
        )
        assert effective_gate(null, 1e-6) == pytest.approx(1e-6)
        # A much tighter gate (1e-8) would be below the floor at 10M.
        # Widens to 1e-6 (the floor).
        assert effective_gate(null, 1e-8) == pytest.approx(1e-6)

    def test_effective_gate_handles_none_or_zero_samples_defensively(self):
        from kryptosbot.null_baselines import NullDistribution, effective_gate
        # None null → passes configured through unchanged.
        assert effective_gate(None, 1e-6) == pytest.approx(1e-6)
        # Zero n_samples (shouldn't happen in practice) → pass through.
        null = NullDistribution(
            scorer_name="crib_score",
            method="matched_variant_family",
            n_chars=97, alphabet="AZ",
            n_samples=0, seed=42,
            kernel_commit="test",
            sorted_scores=[],
            mean=0.0, stdev=0.0,
            family="zero_samples_test",
        )
        assert effective_gate(null, 1e-6) == pytest.approx(1e-6)


def _pid() -> int:
    import os
    return os.getpid()
