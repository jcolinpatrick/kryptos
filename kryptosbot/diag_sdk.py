#!/usr/bin/env python3
"""Minimal SDK diagnostic — 1 agent, full stderr capture."""
import asyncio
import os
import sys

# Clear nested-session guard
os.environ.pop("CLAUDECODE", None)

from claude_agent_sdk import ClaudeAgentOptions, query


async def main():
    print("=== SDK Diagnostic ===")
    print(f"claude CLI: {os.popen('which claude').read().strip()}")
    print(f"claude version: {os.popen('claude --version 2>&1').read().strip()}")
    print(f"CLAUDECODE env: {os.environ.get('CLAUDECODE', '<unset>')}")
    print()

    stderr_lines = []

    def capture_stderr(line: str):
        stderr_lines.append(line)
        print(f"  [stderr] {line.rstrip()}", file=sys.stderr)

    options = ClaudeAgentOptions(
        allowed_tools=[],
        permission_mode="bypassPermissions",
        cwd=os.path.dirname(os.path.abspath(__file__)),
        env={"CLAUDECODE": ""},
        stderr=capture_stderr,
    )

    print("Sending prompt: 'Reply with exactly: OK'")
    print()

    try:
        async for msg in query(prompt="Reply with exactly: OK", options=options):
            msg_type = type(msg).__name__
            if hasattr(msg, "subtype"):
                print(f"  [{msg_type}] subtype={msg.subtype}")
            if hasattr(msg, "content"):
                print(f"  [{msg_type}] content={msg.content!r:.200}")
            if hasattr(msg, "result"):
                print(f"  [{msg_type}] result={msg.result!r:.200}")
            if hasattr(msg, "error"):
                print(f"  [{msg_type}] error={msg.error!r}")
    except Exception as e:
        print(f"\nERROR: {type(e).__name__}: {e}")
        if stderr_lines:
            print(f"\n=== Captured stderr ({len(stderr_lines)} lines) ===")
            for line in stderr_lines[-20:]:
                print(f"  {line.rstrip()}")
        return 1

    print("\nSUCCESS")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
