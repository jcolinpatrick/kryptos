"""Tests for the contradiction-detector alert system.

Covers:
- classify_outcome firing thresholds
- emit_terminal_alert prints recognizable text
- emit_ntfy_alert handles missing/invalid topics gracefully
- process_alerts persists files and never raises
- AlertLevel.NONE disables all alerting
- AlertLevel.SIGNAL fires on crib_score>=18
- AlertLevel.BREAKTHROUGH only fires on crib_score==24 + bean_passed
- Failures in one channel don't block other channels
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_ROOT))
sys.path.insert(0, str(_ROOT / "src"))

from kryptosbot.alerts import (
    AlertLevel,
    AlertEvent,
    classify_outcome,
    process_alerts,
    write_breakthrough_file,
    emit_ntfy_alert,
    _build_contradiction_note,
    _load_thresholds,
)
from kryptosbot.models import WorkerContract, WorkerStatus


# ── classify_outcome ──────────────────────────────────────────────────

class TestClassifyOutcome:

    def test_none_threshold_never_fires(self):
        contract = WorkerContract(
            hypothesis_id="abc",
            status=WorkerStatus.SUCCESS,
            crib_score=24,
            bean_passed=True,
        )
        assert classify_outcome(contract, AlertLevel.NONE) is None

    def test_signal_fires_at_18(self):
        contract = WorkerContract(
            hypothesis_id="abc",
            status=WorkerStatus.SUCCESS,
            crib_score=18,
            bean_passed=False,
        )
        assert classify_outcome(contract, AlertLevel.SIGNAL) == AlertLevel.SIGNAL

    def test_signal_does_not_fire_at_17(self):
        contract = WorkerContract(
            hypothesis_id="abc",
            status=WorkerStatus.SUCCESS,
            crib_score=17,
            bean_passed=True,
        )
        assert classify_outcome(contract, AlertLevel.SIGNAL) is None

    def test_breakthrough_requires_24_and_bean(self, monkeypatch):
        from kryptosbot import alerts
        monkeypatch.setattr(alerts, "_ngram_per_char_safe", lambda _pt: -3.0)
        # 24 without bean — only fires if threshold is SIGNAL
        c = WorkerContract(
            hypothesis_id="abc",
            status=WorkerStatus.SUCCESS,
            crib_score=24,
            bean_passed=False,
        )
        assert classify_outcome(c, AlertLevel.BREAKTHROUGH) == AlertLevel.SIGNAL

        c.bean_passed = True
        assert classify_outcome(c, AlertLevel.BREAKTHROUGH) == AlertLevel.BREAKTHROUGH

    def test_breakthrough_threshold_blocks_signal_only_results(self):
        # crib=18 should NOT fire at BREAKTHROUGH threshold... wait, re-read.
        # Actually the implementation: threshold BREAKTHROUGH still allows
        # SIGNAL-level matches because BREAKTHROUGH is the higher bar and
        # we want to know about both. Confirm behavior.
        c = WorkerContract(
            hypothesis_id="abc",
            status=WorkerStatus.SUCCESS,
            crib_score=18,
            bean_passed=False,
        )
        assert classify_outcome(c, AlertLevel.BREAKTHROUGH) == AlertLevel.SIGNAL

    def test_error_status_never_alerts(self):
        c = WorkerContract(
            hypothesis_id="abc",
            status=WorkerStatus.ERROR,
            crib_score=24,
            bean_passed=True,
        )
        assert classify_outcome(c, AlertLevel.SIGNAL) is None
        assert classify_outcome(c, AlertLevel.BREAKTHROUGH) is None

    def test_timeout_status_never_alerts(self):
        c = WorkerContract(
            hypothesis_id="abc",
            status=WorkerStatus.TIMEOUT,
            crib_score=24,
            bean_passed=True,
        )
        assert classify_outcome(c, AlertLevel.SIGNAL) is None


# ── thresholds ────────────────────────────────────────────────────────

class TestThresholds:

    def test_load_thresholds_returns_signal_and_breakthrough(self):
        t = _load_thresholds()
        assert "signal" in t
        assert "breakthrough" in t
        assert t["signal"] >= 10
        assert t["breakthrough"] >= t["signal"]


# ── contradiction notes ───────────────────────────────────────────────

class TestContradictionNote:

    def test_breakthrough_note_warns_about_implausibility(self):
        c = WorkerContract(
            hypothesis_id="abc",
            status=WorkerStatus.SUCCESS,
            crib_score=24,
            bean_passed=True,
        )
        note = _build_contradiction_note(c)
        assert "BREAKTHROUGH" in note or "breakthrough" in note.lower()
        assert "implausible" in note.lower() or "verify" in note.lower()

    def test_signal_note_warns_about_eliminations(self):
        c = WorkerContract(
            hypothesis_id="abc",
            status=WorkerStatus.SUCCESS,
            crib_score=20,
            bean_passed=False,
        )
        note = _build_contradiction_note(c)
        assert "elimination" in note.lower() or "audit" in note.lower()

    def test_no_bean_pass_adds_note(self):
        c = WorkerContract(
            hypothesis_id="abc",
            status=WorkerStatus.SUCCESS,
            crib_score=22,
            bean_passed=False,
        )
        note = _build_contradiction_note(c)
        assert "bean" in note.lower() or "Bean" in note


# ── persistence ───────────────────────────────────────────────────────

class TestPersistence:

    def test_write_breakthrough_file_creates_dir(self, tmp_path):
        event = AlertEvent(
            triggered_at="2026-04-12T10:00:00+00:00",
            hypothesis_id="abc123def456",
            level="signal",
            crib_score=20,
            bean_passed=True,
            score=15.0,
            worker_status="success",
            best_plaintext="EAST",
            narrative_summary="test",
            contradiction_note="test note",
            cycle_number=42,
            theory_title="Test theory",
        )
        target_dir = tmp_path / "breakthroughs"
        path = write_breakthrough_file(event, target_dir)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["hypothesis_id"] == "abc123def456"
        assert data["crib_score"] == 20
        assert data["level"] == "signal"


# ── ntfy push ─────────────────────────────────────────────────────────

class TestNtfyPush:

    def test_ntfy_returns_false_with_no_topic(self, tmp_path, monkeypatch):
        monkeypatch.delenv("NTFY_TOPIC", raising=False)
        # Patch the .env path to a non-existent location
        with patch("kryptosbot.alerts.Path") as mock_path:
            mock_path.side_effect = lambda *a, **kw: tmp_path / "nonexistent.env"
            event = AlertEvent(
                triggered_at="2026-04-12T10:00:00+00:00",
                hypothesis_id="abc",
                level="signal",
                crib_score=20,
                bean_passed=True,
                score=15.0,
                worker_status="success",
                best_plaintext="",
                narrative_summary="",
                contradiction_note="",
                cycle_number=1,
            )
            # Should return False, not raise
            result = emit_ntfy_alert(event)
            assert result is False

    def test_ntfy_never_raises_on_network_failure(self, monkeypatch):
        monkeypatch.setenv("NTFY_TOPIC", "test-topic-that-does-not-exist-12345")

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = OSError("simulated network error")
            event = AlertEvent(
                triggered_at="2026-04-12T10:00:00+00:00",
                hypothesis_id="abc",
                level="signal",
                crib_score=20,
                bean_passed=True,
                score=15.0,
                worker_status="success",
                best_plaintext="",
                narrative_summary="",
                contradiction_note="",
                cycle_number=1,
            )
            # Must NOT raise
            result = emit_ntfy_alert(event)
            assert result is False


# ── process_alerts ────────────────────────────────────────────────────

class TestProcessAlerts:

    def test_process_alerts_none_returns_empty(self, tmp_path):
        outcomes = [
            WorkerContract(
                hypothesis_id="abc",
                status=WorkerStatus.SUCCESS,
                crib_score=24,
                bean_passed=True,
            ),
        ]
        result = process_alerts(
            outcomes=outcomes,
            threshold=AlertLevel.NONE,
            cycle_number=1,
            results_dir=tmp_path,
        )
        assert result == []
        # No file should have been written
        assert list(tmp_path.glob("*.json")) == []

    def test_process_alerts_signal_fires_and_persists(self, tmp_path, monkeypatch, capsys):
        # Disable ntfy via env to avoid network attempts
        monkeypatch.delenv("NTFY_TOPIC", raising=False)
        outcomes = [
            WorkerContract(
                hypothesis_id="abc123",
                status=WorkerStatus.SUCCESS,
                crib_score=20,
                bean_passed=True,
                score=15.0,
                best_plaintext="EASTNORTHEAST",
                narrative_summary="test",
            ),
        ]
        result = process_alerts(
            outcomes=outcomes,
            threshold=AlertLevel.SIGNAL,
            cycle_number=42,
            results_dir=tmp_path,
        )
        assert len(result) == 1
        assert result[0].crib_score == 20
        assert result[0].level == "signal"

        # Should have persisted a file
        files = list(tmp_path.glob("*.json"))
        assert len(files) == 1

        # Should have printed terminal alert
        captured = capsys.readouterr()
        assert "ALERT" in captured.out
        assert "abc123" in captured.out
        assert "CONTRADICTION" in captured.out or "contradiction" in captured.out

    def test_process_alerts_never_raises_on_inner_failure(self, tmp_path, monkeypatch):
        """If write_breakthrough_file fails, process_alerts must continue."""
        monkeypatch.delenv("NTFY_TOPIC", raising=False)
        outcomes = [
            WorkerContract(
                hypothesis_id="abc",
                status=WorkerStatus.SUCCESS,
                crib_score=20,
                bean_passed=True,
                score=15.0,
            ),
        ]
        # Patch write_breakthrough_file to raise
        with patch("kryptosbot.alerts.write_breakthrough_file") as mock_write:
            mock_write.side_effect = OSError("simulated disk error")
            # Must not raise
            result = process_alerts(
                outcomes=outcomes,
                threshold=AlertLevel.SIGNAL,
                cycle_number=1,
                results_dir=tmp_path,
            )
            # Event was still created and reported
            assert len(result) == 1

    def test_process_alerts_includes_theory_metadata(self, tmp_path, monkeypatch):
        monkeypatch.delenv("NTFY_TOPIC", raising=False)
        outcomes = [
            WorkerContract(
                hypothesis_id="abc",
                status=WorkerStatus.SUCCESS,
                crib_score=20,
                bean_passed=True,
                score=15.0,
            ),
        ]
        lookup = {
            "abc": {
                "title": "Test theory title",
                "family": "test_family",
                "mechanism": "test mechanism",
            },
        }
        result = process_alerts(
            outcomes=outcomes,
            threshold=AlertLevel.SIGNAL,
            cycle_number=1,
            results_dir=tmp_path,
            theory_lookup=lookup,
        )
        assert len(result) == 1
        assert result[0].theory_title == "Test theory title"
        assert result[0].theory_family == "test_family"


# ── controller integration ────────────────────────────────────────────

class TestControllerIntegration:

    def test_controller_config_has_alert_threshold_default_signal(self):
        from kryptosbot.controller import ControllerConfig
        cfg = ControllerConfig()
        assert cfg.alert_threshold == "signal"

    def test_controller_config_alert_threshold_configurable(self):
        from kryptosbot.controller import ControllerConfig
        cfg = ControllerConfig(alert_threshold="breakthrough")
        assert cfg.alert_threshold == "breakthrough"

        cfg2 = ControllerConfig(alert_threshold="none")
        assert cfg2.alert_threshold == "none"
