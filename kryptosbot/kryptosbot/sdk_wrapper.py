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
import warnings
from typing import Any, AsyncIterator

from claude_agent_sdk import ClaudeAgentOptions, query

logger = logging.getLogger("kryptosbot.sdk_wrapper")


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
            options=ClaudeAgentOptions(allowed_tools=[]),
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
