"""Pre-flight transport verification for Campaign launches.

Campaign C attempt 1 (2026-04-24) hung for ~3 hours on a subscription-SDK
transport throttle that was not verified before launch. The brief's
pre-flight checklist (step 4: "Fresh subscription window confirmed")
was skipped, and the run silently wasted wall time instead of failing
fast.

This module makes that check machine-executable. `verify_transport()`
runs two probes:

1. Direct-API probe: invokes ``self_test_real_api.py --panel k1``.
   Exercises the Anthropic Python SDK path that direct workers use.
   Expected cost ~$0.02-0.03, expected wall time ~5s.
2. Subscription-SDK probe: invokes
   ``kryptosbot.sdk_wrapper.preflight_check``. Spawns a minimal
   ``claude`` CLI subprocess and confirms it can answer "Reply with
   exactly: OK". Exercises the Agent SDK transport that controller
   workers use.

If either probe fails (or times out), ``verify_transport()`` returns
``(False, summary)``. Callers should halt instead of launching. The
``--verify-transport`` flag on ``run_controller.py`` wires this in
as a launch-time gate.

Scope: this module verifies the two transports are *alive*. It does
not verify throughput, rate-limit state, or the presence of a fresh
subscription window. A probe that passes does not guarantee a 2-hour
campaign run will complete without rate-limiting — that is a
different operational concern.
"""

from __future__ import annotations

import asyncio
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

logger = logging.getLogger(__name__)


DEFAULT_PROBE_TIMEOUT_SEC = 60
_REPO_ROOT = Path(__file__).resolve().parent.parent


def verify_direct_api_k1(
    timeout_sec: int = DEFAULT_PROBE_TIMEOUT_SEC,
) -> tuple[bool, str]:
    """Run the Anthropic-SDK direct-API probe against K1.

    Invokes ``kryptosbot/self_test_real_api.py --panel k1`` as a
    subprocess so this module does not import the anthropic SDK
    at controller-launch time.

    Returns ``(ok, message)``. ``ok=True`` requires: exit 0, stdout
    contains ``discovered           : True``.
    """
    script = Path(__file__).resolve().parent / "self_test_real_api.py"
    env = {**os.environ, "PYTHONPATH": str(_REPO_ROOT / "src")}
    t0 = time.monotonic()
    try:
        result = subprocess.run(
            [sys.executable, "-u", str(script), "--panel", "k1"],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            cwd=str(_REPO_ROOT),
            env=env,
        )
    except subprocess.TimeoutExpired:
        return False, f"direct-api probe timed out after {timeout_sec}s"
    except FileNotFoundError as exc:
        return False, f"direct-api probe could not spawn: {exc}"

    elapsed = time.monotonic() - t0
    if result.returncode != 0:
        stderr_excerpt = (result.stderr or "")[-300:]
        return False, (
            f"direct-api probe failed (rc={result.returncode}): "
            f"{stderr_excerpt}"
        )
    if "discovered           : True" not in (result.stdout or ""):
        tail = (result.stdout or "")[-300:]
        return False, f"direct-api probe returned non-discovery: {tail}"
    return True, f"direct-api probe ok in {elapsed:.1f}s"


async def verify_subscription_sdk(
    timeout_sec: int = DEFAULT_PROBE_TIMEOUT_SEC,
) -> tuple[bool, str]:
    """Run the Agent-SDK subscription-transport probe.

    Calls ``kryptosbot.sdk_wrapper.preflight_check`` which spawns a
    ``claude`` CLI subprocess and asks it to reply "OK". Catches
    timeouts explicitly so a hung transport is reported rather than
    silently waited on.
    """
    from kryptosbot.sdk_wrapper import preflight_check

    t0 = time.monotonic()
    try:
        ok, msg = await asyncio.wait_for(
            preflight_check(), timeout=timeout_sec,
        )
    except asyncio.TimeoutError:
        return False, f"subscription-sdk probe timed out after {timeout_sec}s"
    except Exception as exc:  # noqa: BLE001 — probe is a boundary
        return False, f"subscription-sdk probe raised: {exc!r}"

    elapsed = time.monotonic() - t0
    if not ok:
        return False, f"subscription-sdk probe failed: {msg}"
    return True, (
        f"subscription-sdk probe ok in {elapsed:.1f}s "
        f"(response: {msg!r})"
    )


async def verify_transport_async(
    timeout_sec: int = DEFAULT_PROBE_TIMEOUT_SEC,
) -> tuple[bool, str]:
    """Async variant of :func:`verify_transport`.

    Use this from coroutines (e.g. ``run_controller.main``) so the
    subscription-SDK probe can be awaited inside the caller's existing
    event loop instead of trying to spin up a nested one.
    """
    logger.info("transport-verify: running direct-api probe")
    api_ok, api_msg = verify_direct_api_k1(timeout_sec=timeout_sec)
    logger.info(
        "transport-verify: direct-api %s: %s",
        "OK" if api_ok else "FAIL", api_msg,
    )

    logger.info("transport-verify: running subscription-sdk probe")
    sdk_ok, sdk_msg = await verify_subscription_sdk(timeout_sec=timeout_sec)
    logger.info(
        "transport-verify: subscription-sdk %s: %s",
        "OK" if sdk_ok else "FAIL", sdk_msg,
    )

    overall_ok = api_ok and sdk_ok
    summary_lines = [
        f"direct-api:        {'OK' if api_ok else 'FAIL'} — {api_msg}",
        f"subscription-sdk:  {'OK' if sdk_ok else 'FAIL'} — {sdk_msg}",
        f"verdict:           {'PROCEED' if overall_ok else 'HALT'}",
    ]
    return overall_ok, "\n".join(summary_lines)


def verify_transport(
    timeout_sec: int = DEFAULT_PROBE_TIMEOUT_SEC,
) -> tuple[bool, str]:
    """Run both probes and produce a combined verdict (sync wrapper).

    Runs sequentially (not in parallel) so a hung probe can't starve
    the other. Each probe has its own ``timeout_sec`` budget.

    Returns ``(overall_ok, multiline_summary)``. ``overall_ok=True``
    requires both probes to succeed. Async callers should use
    :func:`verify_transport_async` instead — calling this from inside
    a running event loop will fail.
    """
    return asyncio.run(verify_transport_async(timeout_sec=timeout_sec))
