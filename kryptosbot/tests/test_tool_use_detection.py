"""Tool-use block detection.

claude-agent-sdk 0.1.61 delivers tool calls as ``ToolUseBlock`` dataclasses
with fields (id, name, input) and NO ``type`` attribute. The legacy detector
``hasattr(block, "type") and block.type == "tool_use"`` is therefore always
False, so every "N tools" telemetry counter in the controller silently read 0
even when agents called tools. These tests pin a robust detector and guard the
buggy pattern from returning.
"""

import pathlib

from claude_agent_sdk import TextBlock, ThinkingBlock, ToolUseBlock

from kryptosbot.sdk_wrapper import is_tool_use_block

_ROOT = pathlib.Path(__file__).resolve().parents[1]


def test_detects_real_tooluseblock_instance():
    block = ToolUseBlock(id="t1", name="mcp__dsl_tools__query_exhaustion", input={})
    assert is_tool_use_block(block) is True


def test_text_and_thinking_blocks_are_not_tool_use():
    assert is_tool_use_block(TextBlock(text="hello")) is False
    assert is_tool_use_block(ThinkingBlock(thinking="...", signature="s")) is False


def test_dict_shaped_blocks():
    assert is_tool_use_block({"type": "tool_use", "name": "x"}) is True
    assert is_tool_use_block({"type": "text", "text": "x"}) is False


def test_legacy_buggy_pattern_is_gone_from_controller_and_siblings():
    # The `.type == "tool_use"` attribute check never matches a 0.1.61
    # ToolUseBlock; it must not be used for tool counting anywhere.
    for rel in ("controller.py", "pantheon_siblings.py"):
        src = (_ROOT / rel).read_text()
        assert 'block.type == "tool_use"' not in src, (
            f"{rel} still uses the broken block.type=='tool_use' tool detector"
        )
        assert "is_tool_use_block" in src, f"{rel} must use is_tool_use_block"
