"""Unit tests for kryptosbot.transport_preflight.

Covers both probes plus the combined verdict. Real network is mocked
throughout — no subprocess spawn, no claude CLI, no Anthropic SDK
call leaves these tests. This is by design: the module is a boundary
between the controller and two flaky-in-practice transports, and the
tests exist to pin behavior at that boundary, not to exercise the
transports themselves.
"""

from __future__ import annotations

import asyncio
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from kryptosbot.transport_preflight import (
    verify_direct_api_k1,
    verify_subscription_sdk,
    verify_transport,
)


# ---------------------------------------------------------------------------
# verify_direct_api_k1
# ---------------------------------------------------------------------------


class TestVerifyDirectApiK1:

    def _fake_completed_process(
        self, *, returncode: int, stdout: str = "", stderr: str = "",
    ) -> MagicMock:
        proc = MagicMock()
        proc.returncode = returncode
        proc.stdout = stdout
        proc.stderr = stderr
        return proc

    def test_returns_ok_on_discovered_true(self):
        stdout = (
            "R2-5 real-API self-test: panel=k1\n"
            "api_call_ok        : True\n"
            "discovered           : True\n"
            "usd_spent            : $0.0263\n"
        )
        proc = self._fake_completed_process(returncode=0, stdout=stdout)
        with patch("subprocess.run", return_value=proc):
            ok, msg = verify_direct_api_k1()
        assert ok is True
        assert "ok" in msg.lower()

    def test_returns_fail_on_nonzero_exit_code(self):
        proc = self._fake_completed_process(
            returncode=2,
            stderr="anthropic.APIStatusError: rate limit exceeded",
        )
        with patch("subprocess.run", return_value=proc):
            ok, msg = verify_direct_api_k1()
        assert ok is False
        assert "failed" in msg
        assert "rc=2" in msg
        assert "rate limit" in msg

    def test_returns_fail_on_non_discovery(self):
        stdout = (
            "api_call_ok        : True\n"
            "discovered           : False\n"
        )
        proc = self._fake_completed_process(returncode=0, stdout=stdout)
        with patch("subprocess.run", return_value=proc):
            ok, msg = verify_direct_api_k1()
        assert ok is False
        assert "non-discovery" in msg

    def test_returns_fail_on_timeout(self):
        err = subprocess.TimeoutExpired(cmd=["python"], timeout=30)
        with patch("subprocess.run", side_effect=err):
            ok, msg = verify_direct_api_k1(timeout_sec=30)
        assert ok is False
        assert "timed out" in msg
        assert "30s" in msg

    def test_returns_fail_on_spawn_error(self):
        with patch("subprocess.run", side_effect=FileNotFoundError("no python")):
            ok, msg = verify_direct_api_k1()
        assert ok is False
        assert "could not spawn" in msg


# ---------------------------------------------------------------------------
# verify_subscription_sdk
# ---------------------------------------------------------------------------


class TestVerifySubscriptionSdk:

    def test_returns_ok_when_preflight_passes(self):
        mock = AsyncMock(return_value=(True, "OK"))
        with patch("kryptosbot.sdk_wrapper.preflight_check", mock):
            ok, msg = asyncio.run(verify_subscription_sdk())
        assert ok is True
        assert "ok" in msg.lower()

    def test_returns_fail_when_preflight_reports_failure(self):
        mock = AsyncMock(return_value=(False, "auth error"))
        with patch("kryptosbot.sdk_wrapper.preflight_check", mock):
            ok, msg = asyncio.run(verify_subscription_sdk())
        assert ok is False
        assert "auth error" in msg

    def test_returns_fail_on_timeout(self):
        # Simulate a hung preflight by having it sleep longer than the
        # probe's timeout budget.
        async def _hang(*args, **kwargs):
            await asyncio.sleep(10)
            return True, "late"

        with patch("kryptosbot.sdk_wrapper.preflight_check", _hang):
            ok, msg = asyncio.run(verify_subscription_sdk(timeout_sec=1))
        assert ok is False
        assert "timed out" in msg

    def test_returns_fail_on_unexpected_exception(self):
        mock = AsyncMock(side_effect=RuntimeError("weird transport error"))
        with patch("kryptosbot.sdk_wrapper.preflight_check", mock):
            ok, msg = asyncio.run(verify_subscription_sdk())
        assert ok is False
        assert "weird transport error" in msg


# ---------------------------------------------------------------------------
# verify_transport (combined verdict)
# ---------------------------------------------------------------------------


class TestVerifyTransportCombined:

    def test_proceed_verdict_when_both_probes_ok(self):
        with patch(
            "kryptosbot.transport_preflight.verify_direct_api_k1",
            return_value=(True, "api ok in 4.1s"),
        ), patch(
            "kryptosbot.transport_preflight.verify_subscription_sdk",
            AsyncMock(return_value=(True, "sdk ok in 0.8s")),
        ):
            ok, summary = verify_transport()
        assert ok is True
        assert "PROCEED" in summary
        assert "direct-api:        OK" in summary
        assert "subscription-sdk:  OK" in summary

    def test_halt_verdict_when_direct_api_fails(self):
        with patch(
            "kryptosbot.transport_preflight.verify_direct_api_k1",
            return_value=(False, "api key missing"),
        ), patch(
            "kryptosbot.transport_preflight.verify_subscription_sdk",
            AsyncMock(return_value=(True, "sdk ok")),
        ):
            ok, summary = verify_transport()
        assert ok is False
        assert "HALT" in summary
        assert "direct-api:        FAIL" in summary
        assert "api key missing" in summary
        # Sub probe still reported, not short-circuited — we want to
        # see both diagnostics so the operator knows which layer is
        # broken.
        assert "subscription-sdk:  OK" in summary

    def test_halt_verdict_when_subscription_sdk_fails(self):
        with patch(
            "kryptosbot.transport_preflight.verify_direct_api_k1",
            return_value=(True, "api ok"),
        ), patch(
            "kryptosbot.transport_preflight.verify_subscription_sdk",
            AsyncMock(return_value=(False, "claude CLI missing")),
        ):
            ok, summary = verify_transport()
        assert ok is False
        assert "HALT" in summary
        assert "subscription-sdk:  FAIL" in summary
        assert "claude CLI missing" in summary

    def test_halt_verdict_when_both_fail(self):
        with patch(
            "kryptosbot.transport_preflight.verify_direct_api_k1",
            return_value=(False, "api fail"),
        ), patch(
            "kryptosbot.transport_preflight.verify_subscription_sdk",
            AsyncMock(return_value=(False, "sdk fail")),
        ):
            ok, summary = verify_transport()
        assert ok is False
        assert "HALT" in summary


# ---------------------------------------------------------------------------
# CLI wiring: --verify-transport flag parses cleanly on run_controller.
# Integration smoke only — full launch gating is exercised by end-to-end
# runs, not by a unit test that would require mocking asyncio entrypoints.
# ---------------------------------------------------------------------------


class TestVerifyTransportCliFlag:

    def _parse(self, monkeypatch, argv_tail):
        import sys as _sys
        from kryptosbot import run_controller
        monkeypatch.setattr(_sys, "argv", ["run_controller.py", *argv_tail])
        return run_controller.parse_args()

    def test_default_is_false(self, monkeypatch):
        args = self._parse(monkeypatch, [])
        assert args.verify_transport is False
        assert args.verify_transport_timeout == 60

    def test_flag_parses_true_when_set(self, monkeypatch):
        args = self._parse(monkeypatch, ["--verify-transport"])
        assert args.verify_transport is True

    def test_timeout_overridable(self, monkeypatch):
        args = self._parse(
            monkeypatch,
            ["--verify-transport", "--verify-transport-timeout", "120"],
        )
        assert args.verify_transport is True
        assert args.verify_transport_timeout == 120
