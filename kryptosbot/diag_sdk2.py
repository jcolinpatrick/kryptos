#!/usr/bin/env python3
"""Test with exact worker options to isolate the failure."""
import asyncio
import os
import sys

os.environ.pop("CLAUDECODE", None)

from claude_agent_sdk import ClaudeAgentOptions, query


async def main():
    stderr_lines = []

    def capture_stderr(line: str):
        stderr_lines.append(line)
        sys.stderr.write(f"  [stderr] {line}")

    # Exact options from worker.py
    options = ClaudeAgentOptions(
        allowed_tools=["Read", "Write", "Edit", "Bash", "Glob", "Grep"],
        permission_mode="bypassPermissions",
        system_prompt="You are a test agent. Reply with OK.",
        cwd="/home/cpatrick/kryptos",
        max_buffer_size=10_485_760,
        env={"CLAUDECODE": ""},
        stderr=capture_stderr,
    )

    print("Testing with worker-identical options (1 agent)...")
    try:
        async for msg in query(prompt="Reply with exactly: OK", options=options):
            msg_type = type(msg).__name__
            if hasattr(msg, "subtype"):
                print(f"  [{msg_type}] subtype={msg.subtype}")
            if hasattr(msg, "content"):
                content = str(msg.content)[:200]
                print(f"  [{msg_type}] content={content}")
            if hasattr(msg, "result"):
                print(f"  [{msg_type}] result={str(msg.result)[:200]}")
    except Exception as e:
        print(f"\nERROR: {type(e).__name__}: {e}")
        if stderr_lines:
            print(f"\n=== Captured stderr ({len(stderr_lines)} lines) ===")
            for line in stderr_lines[-30:]:
                print(f"  {line.rstrip()}")
        return 1

    print("\nSUCCESS — single worker options work fine")

    # Now test 3 concurrent
    print("\n=== Testing 3 concurrent agents ===")

    async def run_one(i):
        opts = ClaudeAgentOptions(
            allowed_tools=[],
            permission_mode="bypassPermissions",
            cwd="/home/cpatrick/kryptos",
            env={"CLAUDECODE": ""},
            stderr=capture_stderr,
        )
        result = ""
        try:
            async for msg in query(prompt=f"Reply with exactly: AGENT{i}", options=opts):
                if hasattr(msg, "result"):
                    result = str(msg.result)
            print(f"  Agent {i}: {result[:80]}")
        except Exception as e:
            print(f"  Agent {i} FAILED: {type(e).__name__}: {e}")
            if stderr_lines:
                for line in stderr_lines[-5:]:
                    print(f"    stderr: {line.rstrip()}")

    await asyncio.gather(run_one(1), run_one(2), run_one(3))
    print("\nDone")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
