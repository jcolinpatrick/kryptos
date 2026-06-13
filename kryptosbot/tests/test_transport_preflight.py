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
    verify_transport_async,
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
        # Real spacing from self_test_real_api.py:424 — 9 spaces between
        # "discovered" and the colon. The previous fixture used 11 spaces
        # which silently encoded a matcher bug; the real self-test would
        # have failed this probe in production.
        stdout = (
            "R2-5 real-API self-test: panel=k1\n"
            "api_call_ok        : True\n"
            "discovered         : True\n"
            "usd_spent          : $0.0263\n"
        )
        proc = self._fake_completed_process(returncode=0, stdout=stdout)
        with patch("subprocess.run", return_value=proc):
            ok, msg = verify_direct_api_k1()
        assert ok is True
        assert "ok" in msg.lower()

    def test_returns_ok_on_alternate_spacing(self):
        # Whitespace-tolerant regex must accept any column-padding the
        # self-test format chooses. Three spacings, all valid.
        for label_pad in ("", "   ", "           "):
            stdout = f"discovered{label_pad} : True\n"
            proc = self._fake_completed_process(returncode=0, stdout=stdout)
            with patch("subprocess.run", return_value=proc):
                ok, _ = verify_direct_api_k1()
            assert ok is True, f"matcher rejected spacing {label_pad!r}"

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
            "discovered         : False\n"
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
# preflight_check model pinning (2026-06-10)
# ---------------------------------------------------------------------------


class TestPreflightCheckExplicitModel:
    """preflight_check must pass the routed model id explicitly to query().

    Discovered 2026-06-10 launching the first Fable 5 campaign: the probe
    passed NO model, so the SDK's bundled CLI (2.1.112, older than the PATH
    CLI) fell through to the user-settings default model ALIAS, which it could
    not resolve — exit 1, campaign HALT at the transport gate. Meanwhile every
    real controller session passes an explicit model id, which the same
    bundled CLI accepts fine. The probe must therefore exercise the exact
    model id the campaign will run, both for representativeness and to be
    independent of user-level settings.

    2026-06-13: the frontier-tier routing default is Opus 4.8 (Fable 5 was
    restricted). The probe pins claude-opus-4-8 and must carry the matching
    thinking gate — {"type": "disabled"} — so it exercises the exact request
    shape the campaign's frontier sessions send.
    """

    def test_probe_query_pins_routing_default_model(self):
        from types import SimpleNamespace

        import kryptosbot.sdk_wrapper as sw
        from kryptosbot.pantheon import _SDK_OPUS

        captured: dict = {}

        async def _fake_query(*, prompt, options, **kwargs):
            captured["options"] = options
            yield SimpleNamespace(result="OK")

        with patch.object(sw, "query", _fake_query):
            ok, msg = asyncio.run(sw.preflight_check())

        assert ok is True
        opts = captured["options"]
        assert opts.model == _SDK_OPUS, (
            "preflight_check must pin the routing-default model id; an "
            "unset model inherits the user-settings alias, which the SDK's "
            "bundled CLI may not resolve"
        )
        # Opus 4.8 disables extended thinking (GOTCHA2 long-session gate); the
        # probe must send the same disabled-dict the campaign sessions send.
        assert getattr(opts, "thinking", None) == {"type": "disabled"}


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

    def test_sync_wrapper_refuses_running_loop_before_coroutine_created(self, monkeypatch):
        calls = 0

        def _should_not_construct_coroutine(timeout_sec=60):
            nonlocal calls
            calls += 1

            async def _unused():
                return True, "unused"

            return _unused()

        monkeypatch.setattr(
            "kryptosbot.transport_preflight.verify_transport_async",
            _should_not_construct_coroutine,
        )

        async def _scenario():
            with pytest.raises(RuntimeError, match="verify_transport_async"):
                verify_transport()

        asyncio.run(_scenario())
        assert calls == 0


# ---------------------------------------------------------------------------
# verify_transport_async (async variant — used by run_controller.main)
#
# Regression: the sync verify_transport used to call asyncio.run() on the
# subscription-SDK probe, which fails with "asyncio.run() cannot be called
# from a running event loop" when invoked from run_controller's async main.
# These tests pin the async path so a future refactor can't silently
# reintroduce the nested-loop bug.
# ---------------------------------------------------------------------------


class TestVerifyTransportAsync:

    def test_proceed_verdict_when_both_probes_ok(self):
        with patch(
            "kryptosbot.transport_preflight.verify_direct_api_k1",
            return_value=(True, "api ok"),
        ), patch(
            "kryptosbot.transport_preflight.verify_subscription_sdk",
            AsyncMock(return_value=(True, "sdk ok")),
        ):
            ok, summary = asyncio.run(verify_transport_async())
        assert ok is True
        assert "PROCEED" in summary

    def test_runs_inside_existing_event_loop(self):
        # The original bug: verify_transport called asyncio.run() internally,
        # which crashed when called from another async context. The async
        # variant must work when awaited from inside a running loop.
        async def _scenario():
            with patch(
                "kryptosbot.transport_preflight.verify_direct_api_k1",
                return_value=(True, "api ok"),
            ), patch(
                "kryptosbot.transport_preflight.verify_subscription_sdk",
                AsyncMock(return_value=(True, "sdk ok")),
            ):
                return await verify_transport_async()

        ok, summary = asyncio.run(_scenario())
        assert ok is True
        assert "PROCEED" in summary


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
