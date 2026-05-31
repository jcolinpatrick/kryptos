"""Read-only MCP tool palette: activation + safety guards.

The in-process MCP servers (dsl_tools, research_tools) were built and tested
but never mounted into any ClaudeAgentOptions, so LLM agents could not call the
kernel / exhaustion / ledger query tools and had to shell out via Bash. This
palette mounts ONLY the read-only / query tools.

SAFETY INVARIANTS pinned here:
  * tools that dispatch compute (submit_hypothesis_spec) or mutate the ledger
    (register_hypothesis, update_hypothesis_status, record_experiment_result)
    are NEVER exposed — they would bypass the R3 critic gate / deterministic
    Category-A worker invariant.
  * every real tool is classified (read-only XOR excluded) so a newly added
    tool can't silently leak into the agent palette.
"""

import asyncio
import dataclasses
import pathlib
import re

import pytest

_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _real_tool_names(all_tools):
    return {t.name for t in all_tools}


def test_excluded_set_lists_the_dangerous_tools():
    from kryptosbot.mcp_palette import EXCLUDED_TOOLS

    assert {
        "submit_hypothesis_spec",
        "register_hypothesis",
        "update_hypothesis_status",
        "record_experiment_result",
    } <= set(EXCLUDED_TOOLS)


def test_palette_never_exposes_excluded_tools():
    from kryptosbot.mcp_palette import readonly_allowed_tool_names, EXCLUDED_TOOLS

    names = readonly_allowed_tool_names()
    for full in names:
        suffix = full.rsplit("__", 1)[-1]
        assert suffix not in EXCLUDED_TOOLS, f"palette leaks excluded tool {full}"


def test_every_real_tool_is_classified_readonly_xor_excluded():
    # Drift guard: a new @tool added to either server must be deliberately
    # placed into the read-only palette or the excluded set, never neither.
    from kryptosbot import dsl_tools, research_tools
    from kryptosbot.mcp_palette import (
        READONLY_DSL_TOOLS,
        READONLY_RESEARCH_TOOLS,
        EXCLUDED_TOOLS,
    )

    dsl_real = _real_tool_names(dsl_tools.ALL_TOOLS)
    research_real = _real_tool_names(research_tools.ALL_RESEARCH_TOOLS)

    assert set(READONLY_DSL_TOOLS) | (EXCLUDED_TOOLS & dsl_real) == dsl_real
    assert set(READONLY_RESEARCH_TOOLS) | (EXCLUDED_TOOLS & research_real) == research_real
    # read-only and excluded must be disjoint
    assert not (set(READONLY_DSL_TOOLS) & EXCLUDED_TOOLS)
    assert not (set(READONLY_RESEARCH_TOOLS) & EXCLUDED_TOOLS)


def test_build_mount_shape():
    from kryptosbot.mcp_palette import build_readonly_mcp_mount, DSL_SERVER, RESEARCH_SERVER

    mcp_servers, allowed = build_readonly_mcp_mount()
    assert set(mcp_servers) == {DSL_SERVER, RESEARCH_SERVER}
    assert mcp_servers[DSL_SERVER]["name"] == DSL_SERVER
    assert mcp_servers[RESEARCH_SERVER]["name"] == RESEARCH_SERVER
    # allowlist prefixes resolve against the server keys
    assert all(n.startswith("mcp__") for n in allowed)
    assert any(n.startswith(f"mcp__{DSL_SERVER}__") for n in allowed)
    assert any(n.startswith(f"mcp__{RESEARCH_SERVER}__") for n in allowed)


def test_config_default_off():
    from kryptosbot.controller import ControllerConfig

    fields = {f.name: f for f in dataclasses.fields(ControllerConfig)}
    assert "enable_mcp_tools" in fields
    assert fields["enable_mcp_tools"].default is False


def test_controller_wires_mount_at_llm_sites_only():
    src = (_ROOT / "controller.py").read_text()
    assert "enable_mcp_tools" in src
    assert "build_readonly_mcp_mount" in src
    assert "mcp_servers" in src


def test_mounted_readonly_tool_actually_runs():
    # De-risks live enablement: prove a mounted read-only handler executes
    # in-process without error (the layer was previously never exercised live).
    from kryptosbot import dsl_tools

    res = asyncio.run(dsl_tools.enumerate_admissible_transforms_tool.handler({}))
    assert "content" in res


# --------------------------------------------------------------------------
# Theorist tool-usage nudge: mounting the palette is necessary but not
# sufficient; the theorist must be told the tools exist or it won't use them.
# --------------------------------------------------------------------------

def test_theorist_tool_guidance_references_only_mounted_tools():
    from kryptosbot.mcp_palette import theorist_tool_guidance, readonly_allowed_tool_names

    text = theorist_tool_guidance()
    assert text.strip()
    # Names it nudges toward are a subset of what is actually mounted, so it
    # never points the agent at a tool that isn't in allowed_tools.
    mounted = set(readonly_allowed_tool_names())
    referenced = set(re.findall(r"mcp__[a-z_]+__[a-z_]+", text))
    assert referenced, "guidance must name concrete mcp__ tools"
    assert referenced <= mounted, f"guidance references unmounted tools: {referenced - mounted}"
    # The high-value pre-proposal checks must be present.
    for must in ("query_exhaustion", "request_compute_budget_estimate", "enumerate_admissible_transforms"):
        assert must in text


def test_theorist_tool_guidance_is_prompt_lint_clean():
    from kryptosbot.mcp_palette import theorist_tool_guidance

    low = theorist_tool_guidance().lower()
    # No Task/Agent subagent-delegation language (controller-routed agent rule).
    for bad in ("agent tool", "task tool", "launch subagent", "launch agent", "commission"):
        assert bad not in low, f"guidance contains delegation language: {bad!r}"
    # No promotion / sycophancy vocabulary.
    for bad in ("breakthrough", "signal", "promising", "elegant", "proves", "confirms", "explains everything"):
        assert bad not in low, f"guidance contains promotion vocabulary: {bad!r}"


def test_controller_appends_guidance_only_when_mcp_enabled():
    src = (_ROOT / "controller.py").read_text()
    assert "theorist_tool_guidance" in src
    # The CALL site (last occurrence; the first is the import) must live in the
    # enable_mcp_tools-gated theorist block — the tools only exist when mounted.
    idx = src.rindex("theorist_tool_guidance")
    window = src[max(0, idx - 600):idx]
    assert "enable_mcp_tools" in window
