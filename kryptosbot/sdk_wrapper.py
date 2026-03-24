"""
Wrapper for the Claude Agent SDK query() function.

The SDK (as of early 2026) has a cleanup bug: when the async generator
from query() finishes or is exited early, anyio raises:

    RuntimeError: Attempted to exit cancel scope in a different task
    than it was entered in

This is a teardown issue in the SDK's internal use of anyio task groups.
The actual query completes successfully — all messages are received — but
the generator's __aexit__ path fails.

This module provides safe_query() which wraps the generator, suppresses
the known cleanup error, and yields messages normally.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import warnings
from typing import Any, AsyncIterator

from claude_agent_sdk import ClaudeAgentOptions, query

logger = logging.getLogger("kryptosbot.sdk_wrapper")


# ---------------------------------------------------------------------------
# Error classification — map stderr/error strings to human-readable causes
# ---------------------------------------------------------------------------

_ERROR_PATTERNS: list[tuple[str, str, str]] = [
    # (substring to match, short label, user-facing explanation)
    ("rate limit", "RATE_LIMIT",
     "API rate limit reached. Wait a few minutes or reduce --workers."),
    ("rate_limit", "RATE_LIMIT",
     "API rate limit reached. Wait a few minutes or reduce --workers."),
    ("429", "RATE_LIMIT",
     "HTTP 429 — API rate limit. Wait a few minutes or reduce --workers."),
    ("token limit", "TOKEN_LIMIT",
     "Token/usage limit reached for your API plan."),
    ("quota", "QUOTA_EXCEEDED",
     "API quota exceeded. Check your Anthropic plan usage at console.anthropic.com."),
    ("credit balance is too low", "CREDITS_EXHAUSTED",
     "API key has no credits. Either top up at console.anthropic.com, "
     "or remove ANTHROPIC_API_KEY from .env to use your Claude subscription."),
    ("billing", "BILLING",
     "Billing issue with your API key. Check console.anthropic.com."),
    ("insufficient", "QUOTA_EXCEEDED",
     "Insufficient quota/credits. Check your Anthropic plan."),
    ("entitlement", "ENTITLEMENT",
     "API entitlement issue. Your plan may not include this feature."),
    ("unauthorized", "AUTH_FAILURE",
     "API key is invalid or expired. Check ANTHROPIC_API_KEY."),
    ("401", "AUTH_FAILURE",
     "HTTP 401 — unauthorized. Check your ANTHROPIC_API_KEY."),
    ("403", "AUTH_FORBIDDEN",
     "HTTP 403 — forbidden. Your API key may lack required permissions."),
    ("authentication", "AUTH_FAILURE",
     "Authentication failed. Verify ANTHROPIC_API_KEY is valid."),
    ("invalid api key", "AUTH_FAILURE",
     "Invalid API key. Get a new one from console.anthropic.com."),
    ("invalid_api_key", "AUTH_FAILURE",
     "Invalid API key. Get a new one from console.anthropic.com."),
    ("cannot be launched inside another", "NESTED_SESSION",
     "Claude Code refuses to run inside another Claude Code session. "
     "The CLAUDECODE env var is leaking. Run from a plain terminal."),
    ("overloaded", "OVERLOADED",
     "API is overloaded. Try again in a few minutes."),
    ("529", "OVERLOADED",
     "HTTP 529 — API overloaded. Try again shortly."),
    ("503", "SERVICE_UNAVAILABLE",
     "HTTP 503 — service temporarily unavailable."),
    ("timeout", "TIMEOUT",
     "Connection timed out reaching the API."),
    ("connection refused", "CONNECTION",
     "Cannot connect to the API. Check your network."),
    ("fatal error in message reader", "PROTOCOL_MISMATCH",
     "CLI failed to parse SDK messages. Version mismatch between "
     "claude-agent-sdk and claude CLI. Run: pip install --upgrade claude-agent-sdk"),
]


def classify_error(error_text: str) -> tuple[str, str]:
    """
    Classify an error string into (label, explanation).

    Returns ("UNKNOWN", <raw text>) if no pattern matches.
    """
    lower = error_text.lower()
    for pattern, label, explanation in _ERROR_PATTERNS:
        if pattern in lower:
            return label, explanation
    return "UNKNOWN", error_text[:500]


async def safe_query(
    prompt: str,
    options: ClaudeAgentOptions | None = None,
    **kwargs: Any,
) -> AsyncIterator[Any]:
    """
    Wrapper around claude_agent_sdk.query() that handles the anyio
    cancel scope cleanup bug.

    Usage is identical to query():

        async for message in safe_query(prompt="...", options=opts):
            process(message)
    """
    try:
        async for message in query(prompt=prompt, options=options, **kwargs):
            yield message
    except GeneratorExit:
        # Normal when caller breaks out of the loop early.
        # The SDK will try to close its internal task group and may fail.
        pass
    except RuntimeError as exc:
        if "cancel scope" in str(exc) or "Event loop is closed" in str(exc):
            # Known SDK cleanup bug — the query already completed successfully.
            logger.debug("Suppressed SDK cleanup error: %s", exc)
        else:
            raise


async def collect_query(
    prompt: str,
    options: ClaudeAgentOptions | None = None,
    **kwargs: Any,
) -> list[Any]:
    """
    Run a query and collect ALL messages into a list.

    This avoids the generator cleanup issue entirely by fully consuming
    the stream before returning. Use for short queries where you don't
    need streaming output.
    """
    messages: list[Any] = []
    try:
        async for message in query(prompt=prompt, options=options, **kwargs):
            messages.append(message)
    except RuntimeError as exc:
        if "cancel scope" in str(exc) or "Event loop is closed" in str(exc):
            logger.debug("Suppressed SDK cleanup error: %s", exc)
        else:
            raise
    return messages


async def test_sdk_auth() -> str:
    """
    Quick auth test. Returns the model's response text or raises on failure.

    Handles the cleanup error so callers get a clean result.
    """
    result_text = ""
    try:
        async for msg in query(
            prompt="Reply with exactly: OK",
            options=ClaudeAgentOptions(allowed_tools=[], env={"CLAUDECODE": ""}),
        ):
            if hasattr(msg, "result"):
                result_text = str(msg.result)
            elif hasattr(msg, "content"):
                result_text = str(msg.content)
    except RuntimeError as exc:
        if "cancel scope" not in str(exc) and "Event loop is closed" not in str(exc):
            raise

    # Suppress the deferred cleanup errors that fire after the loop
    # by giving the event loop a moment to flush them
    await asyncio.sleep(0.1)

    return result_text.strip() if result_text else "No response received"


async def preflight_check() -> tuple[bool, str]:
    """
    Verify that the Claude Agent SDK can spawn a working session.

    Checks (in order):
    1. `claude` CLI is on PATH
    2. CLI version is compatible with SDK
    3. A minimal query succeeds (auth + API connectivity)

    Returns (ok: bool, message: str). On failure, message contains the
    classified error with actionable advice.
    """
    import claude_agent_sdk._internal.transport.subprocess_cli as transport_mod

    # 1. CLI exists
    cli_path = shutil.which("claude")
    if not cli_path:
        return False, (
            "PREFLIGHT FAIL [CLI_NOT_FOUND]: `claude` not found on PATH.\n"
            "Install with: npm install -g @anthropic-ai/claude-code"
        )

    # 2. CLI version
    try:
        result = subprocess.run(
            [cli_path, "--version"],
            capture_output=True, text=True, timeout=5,
            env={**__import__("os").environ, "CLAUDECODE": ""},
        )
        version_str = result.stdout.strip().split()[0] if result.stdout else "unknown"
        min_version = getattr(transport_mod, "MINIMUM_CLAUDE_CODE_VERSION", "2.0.0")

        # Simple semver compare
        try:
            ver_parts = [int(x) for x in version_str.split(".")[:3]]
            min_parts = [int(x) for x in min_version.split(".")[:3]]
            if ver_parts < min_parts:
                return False, (
                    f"PREFLIGHT FAIL [CLI_VERSION]: claude {version_str} < "
                    f"minimum {min_version}.\n"
                    "Update with: npm update -g @anthropic-ai/claude-code"
                )
        except ValueError:
            pass  # Can't parse version — continue anyway

        from claude_agent_sdk._version import __version__ as sdk_version
        logger.info(
            "Preflight: claude CLI %s, SDK %s, min required %s",
            version_str, sdk_version, min_version,
        )
    except Exception as exc:
        return False, f"PREFLIGHT FAIL [CLI_CHECK]: Could not run `claude --version`: {exc}"

    # 3. Minimal query — catches auth, rate limit, entitlement, protocol issues
    stderr_lines: list[str] = []

    def _capture(line: str) -> None:
        stderr_lines.append(line)

    # Build env: clear CLAUDECODE for nesting, clear ANTHROPIC_API_KEY
    # so the CLI uses the user's subscription (not a potentially-exhausted
    # .env API key)
    preflight_env: dict[str, str] = {"CLAUDECODE": ""}
    if os.environ.get("ANTHROPIC_API_KEY"):
        preflight_env["ANTHROPIC_API_KEY"] = ""

    try:
        got_response = False
        async for msg in query(
            prompt="Reply with exactly: OK",
            options=ClaudeAgentOptions(
                allowed_tools=[],
                env=preflight_env,
                max_turns=1,
                stderr=_capture,
            ),
        ):
            if hasattr(msg, "result") or hasattr(msg, "content"):
                got_response = True

        if not got_response:
            stderr_text = "\n".join(stderr_lines)
            label, explanation = classify_error(stderr_text)
            return False, (
                f"PREFLIGHT FAIL [{label}]: SDK session produced no response.\n"
                f"  {explanation}\n"
                f"  stderr: {stderr_text[:300]}"
            )

    except RuntimeError as exc:
        if "cancel scope" in str(exc) or "Event loop is closed" in str(exc):
            pass  # Known cleanup bug — query actually succeeded
        else:
            stderr_text = "\n".join(stderr_lines)
            combined = f"{exc}\n{stderr_text}"
            label, explanation = classify_error(combined)
            return False, (
                f"PREFLIGHT FAIL [{label}]: {explanation}\n"
                f"  raw error: {exc}\n"
                f"  stderr: {stderr_text[:300]}"
            )
    except Exception as exc:
        stderr_text = "\n".join(stderr_lines)
        combined = f"{exc}\n{stderr_text}"
        label, explanation = classify_error(combined)
        return False, (
            f"PREFLIGHT FAIL [{label}]: {explanation}\n"
            f"  raw error: {exc}\n"
            f"  stderr: {stderr_text[:300]}"
        )

    await asyncio.sleep(0.1)  # Flush deferred cleanup errors
    logger.info("Preflight: SDK auth check PASSED")
    return True, "OK"
