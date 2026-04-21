"""K4 cycle-1 hygiene tests.

Regression tests for the SDK-message-to-text serialization bug found
during the first post-R3 K4 run (2026-04-21, commit 48b78d0, cycle 1
halted by operator). See docs/maturation/round3/K4_RUN_CYCLE1_DIAGNOSTIC.md.

The bug: controller.py stringified ``AssistantMessage.content`` (a
list of ContentBlock dataclasses) with plain ``str()``, yielding a
Python repr that ``extract_json_block`` cannot parse. Result: the
controller silently fell back to ``_programmatic_fallback`` even when
the theorist produced a well-formed JSON array. These tests freeze
that failure mode so it cannot silently return.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from kryptosbot.contracts import validate_theory_proposals
from kryptosbot.controller import _extract_message_text


# ─── Synthetic ContentBlock fakes mirroring claude_agent_sdk shapes ─────────


@dataclass
class FakeTextBlock:
    text: str
    type: str = "text"
    citations: object = None


@dataclass
class FakeThinkingBlock:
    thinking: str
    type: str = "thinking"
    signature: str = ""
    # Include text attr to mimic SDK variance; real ThinkingBlock does
    # NOT have .text but we test the "text takes precedence" path.


@dataclass
class FakeToolUseBlock:
    name: str
    input: dict
    type: str = "tool_use"
    id: str = ""


# ─── _extract_message_text ──────────────────────────────────────────────────


def test_extract_text_from_single_textblock_list():
    """The happy path: a list containing one TextBlock returns its text."""
    content = [FakeTextBlock(text='[{"hello": "world"}]')]
    result = _extract_message_text(content)
    assert result == '[{"hello": "world"}]'


def test_extract_text_skips_thinking_blocks():
    """ThinkingBlocks must NOT contribute to the extracted text. Their
    content is the model's private reasoning and can contain JSON-like
    fragments that would pollute the downstream parser."""
    content = [
        FakeThinkingBlock(thinking='[{"private": "thought"}]'),
        FakeTextBlock(text='[{"public": "result"}]'),
    ]
    result = _extract_message_text(content)
    assert result == '[{"public": "result"}]'
    assert "private" not in result


def test_extract_text_concatenates_multiple_textblocks():
    """Multiple TextBlocks (rare but possible in streaming) are joined
    with newline separators."""
    content = [
        FakeTextBlock(text="part 1"),
        FakeTextBlock(text="part 2"),
    ]
    result = _extract_message_text(content)
    assert "part 1" in result
    assert "part 2" in result


def test_extract_text_empty_list_returns_empty_string():
    assert _extract_message_text([]) == ""


def test_extract_text_non_list_content_passthrough():
    """Plain string (legacy SDK shape) is returned verbatim as str()."""
    assert _extract_message_text("already a string") == "already a string"
    assert _extract_message_text("") == ""


def test_extract_text_unknown_block_type_with_text_attr_included():
    """Forward-compat: blocks with .text but unrecognized .type still
    contribute text. Prefer inclusion over silent drop to avoid losing
    content if the SDK adds new block types."""

    @dataclass
    class _UnknownBlock:
        text: str
        type: str = "mystery"

    content = [_UnknownBlock(text="useful content")]
    assert _extract_message_text(content) == "useful content"


def test_extract_text_tool_use_block_skipped():
    """ToolUseBlock has no .text attribute; should be skipped silently."""
    content = [
        FakeTextBlock(text="before tool"),
        FakeToolUseBlock(name="Read", input={}),
        FakeTextBlock(text="after tool"),
    ]
    result = _extract_message_text(content)
    assert "before tool" in result
    assert "after tool" in result
    assert "Read" not in result  # tool_use is not text


# ─── End-to-end: the cycle-1 failure mode CANNOT silently return ────────────


def test_validate_theory_proposals_sees_textblock_content():
    """The cycle-1 regression. A list containing a TextBlock whose text
    is a well-formed theory array MUST parse to the embedded theories,
    not get mangled into Python repr and fall through to the fallback
    path.

    Before the fix: controller.py did str(list_of_blocks) yielding
    "[TextBlock(text='[{...}]', ...)]"; extract_json_block skipped the
    outer [TextBlock, then hit single-quoted strings it couldn't track,
    and returned NONE. report.valid was always 0.

    After the fix: _extract_message_text extracts the TextBlock.text
    directly; the downstream validator sees clean JSON and parses it."""
    theorist_json = (
        '[{"title": "T", "core_claim": "c", "mechanism": "m", '
        '"family": "geometry", "dsl_spec": null}]'
    )
    sdk_content = [FakeTextBlock(text=theorist_json)]

    # Simulate the controller's new assembly step.
    text = _extract_message_text(sdk_content)
    report = validate_theory_proposals(text)

    assert report.valid, (
        "cycle-1 regression: a TextBlock-wrapped theorist response "
        "must parse; if it falls through to invalid/empty here, the "
        "controller will fall back to programmatic stubs and burn "
        "compute cycles on template theories."
    )
    assert len(report.valid) == 1
    assert report.valid[0].family == "geometry"


def test_replay_cycle1_textblock_path():
    """Replay test: load the actual 2026-04-21 cycle-1 theorist output
    from disk, wrap it in a synthetic TextBlock list, and run it
    through the fix. Proves the SDK-mangling bug is closed end-to-end
    against real production text.

    Expected after commit 1 (this commit): at least 1 theory parses
    (the 'CT perturbation' theory whose anomalies_exploited list
    contains only the canonical id 'ct_perturbation').

    The other 4 theories fail the anomaly-id canonical-match check in
    this commit because they embed free-form commentary like
    'aaa_compass_cipher (tie to physical sculpture geometry
    specifically)' instead of the bare canonical id. That is the
    secondary bug that commit 2 addresses via _normalize_anomaly_id;
    this test's assertion will strengthen from '>= 1' to '== 5' in
    that commit.
    """
    from pathlib import Path
    raw_path = Path(__file__).resolve().parent / "fixtures" / "theorist_cycle1_raw.txt"
    assert raw_path.exists(), (
        f"tracked fixture missing at {raw_path} — commit it or the "
        "replay regression test loses its teeth"
    )
    raw_text = raw_path.read_text()
    assert len(raw_text) > 10_000, (
        "fixture integrity: the 2026-04-21 cycle-1 response was "
        "~18.5k chars; something truncated the file on disk"
    )

    # Wrap in the same SDK shape that caused the production failure.
    sdk_content = [FakeTextBlock(text=raw_text)]

    # Buggy path: str() on the list of blocks — should still fail.
    buggy = str(sdk_content)
    buggy_report = validate_theory_proposals(buggy)
    assert not buggy_report.valid, (
        "regression fence: the pre-fix SDK-repr-stringification path "
        "must continue to fail; if it starts passing, either "
        "extract_json_block was hardened (hygiene fix may be redundant) "
        "or the fixture has drifted from production shape"
    )

    # Fixed path: _extract_message_text → validator.
    fixed = _extract_message_text(sdk_content)
    assert fixed.startswith("[") and fixed.rstrip().endswith("]"), (
        "fixed text should be the raw JSON array verbatim, not wrapped"
    )
    fixed_report = validate_theory_proposals(fixed)
    assert len(fixed_report.valid) >= 1, (
        f"SDK-mangling fix must surface at least one valid theory; "
        f"got valid={len(fixed_report.valid)} invalid={len(fixed_report.valid)} "
        f"errors={fixed_report.errors}"
    )
    # Document the exact current yield — this number will change in
    # commit 2 from 1 → 5 as _normalize_anomaly_id lands.
    assert len(fixed_report.valid) == 1, (
        f"commit 1 expected exactly 1 valid theory (the 'CT perturbation' "
        f"theory, the only one with a bare canonical anomaly_id); the "
        f"rest fail anomaly-id exact match. Commit 2's "
        f"_normalize_anomaly_id raises this to 5. Got "
        f"valid={len(fixed_report.valid)} — if this increased, commit 2 "
        f"has already landed or the canonical anomaly set has grown."
    )


def test_cycle1_bug_shape_explicitly_documented():
    """Pinning the bug's failure mode using a realistic multi-theory
    response (production cycle 1 produced 18K chars across 5 theories
    with indented JSON). The simpler single-theory stub happened to
    parse-by-accident from the Python-repr form; the indented multi-
    theory form does not, which is what the production bug hit.

    If this ever starts passing against str(sdk_content), either
    extract_json_block got smarter (hygiene fix may be redundant —
    investigate) or the fixture drifted and no longer mimics
    production (update fixture)."""
    theorist_json = """[
  {
    "title": "Theory one",
    "core_claim": "claim one",
    "mechanism": "mechanism one",
    "family": "novel"
  },
  {
    "title": "Theory two",
    "core_claim": "claim two",
    "mechanism": "mechanism two",
    "family": "geometry",
    "dsl_spec": null
  }
]"""
    sdk_content = [FakeTextBlock(text=theorist_json)]

    # Buggy path: str() on list of blocks.
    buggy = str(sdk_content)
    assert buggy.startswith("[FakeTextBlock("), (
        "fixture must mimic the Python-repr-of-dataclass-list shape"
    )
    buggy_report = validate_theory_proposals(buggy)
    assert not buggy_report.valid, (
        "the multi-theory Python-repr form must NOT parse to valid "
        "theories. If this fails, investigate — either extract_json_block "
        "has been extended to handle Python repr (hygiene fix may be "
        "redundant) or the fixture no longer reproduces production."
    )

    # Fixed path: _extract_message_text first.
    fixed = _extract_message_text(sdk_content)
    fixed_report = validate_theory_proposals(fixed)
    assert len(fixed_report.valid) == 2, (
        f"post-fix: both theories must parse; got "
        f"valid={len(fixed_report.valid)}, "
        f"invalid={len(fixed_report.invalid)}, "
        f"errors={fixed_report.errors}"
    )
