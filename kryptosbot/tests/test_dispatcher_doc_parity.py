"""Repo-integrity smoke tests for dispatcher / DSL-tool / doc parity.

The kryptosbot DSL has three independent surfaces that must agree on
which cipher kinds and alphabets are supported:

1. ``hypothesis_dsl._VALID_CIPHER_KINDS`` / ``_VALID_ALPHABET_KINDS`` —
   what the DSL parser accepts.
2. ``job_dispatcher._SUPPORTED_KINDS`` / ``_SUPPORTED_ALPHABETS`` —
   what the dispatcher can actually translate into kernel transforms.
3. ``dsl_tools.enumerate_admissible_transforms_tool`` — what agents are
   told they can use.

Drift between any pair is silently dangerous: an agent told an alphabet
is unsupported avoids it (false elimination of search space), and an
agent told a kind is supported but the dispatcher disagrees produces a
worker crash mid-cycle. These tests pin the contracts.

Also covers:

- ORIENT.md does not contain known-stale failure strings whose underlying
  bugs are fixed (e.g. the pre-R2-2 "alphabet 'KA' not supported in
  Phase 4 dispatcher" hint).
- ``transport_preflight`` parses ``self_test_real_api`` output robustly
  against label-spacing changes.

Background: an external review on 2026-04-26 flagged that
``dsl_tools`` hard-coded ``supported_alphabets = ["AZ"]`` even though
``job_dispatcher`` had supported KA + keyword_mixed since R2-2, and
that ``transport_preflight`` matched a hard-coded 11-space variant of
``discovered : True`` while the self-test prints 9 spaces. Both bugs
were silent because their tests encoded the same incorrect strings.
This file exists so the next such drift surfaces immediately.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from kryptosbot.hypothesis_dsl import (
    _VALID_ALPHABET_KINDS,
    _VALID_CIPHER_KINDS,
)
from kryptosbot.job_dispatcher import (
    _SUPPORTED_ALPHABETS,
    _SUPPORTED_KINDS,
)


_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_KRYPTOSBOT = _REPO_ROOT / "kryptosbot"


# ---------------------------------------------------------------------------
# Cipher-kind parity
# ---------------------------------------------------------------------------


def test_all_dsl_kinds_have_translator():
    """Every DSL-valid kind has a dispatcher translation.

    key_tape was the last deferred kind (finite tape + null insertion);
    its translator landed in Task 9 (2026-05-03). The gap is now empty.
    If a kind was added to the DSL without a translator, it will appear
    here. Wire a translator into job_dispatcher._SUPPORTED_KINDS and
    _translate_layer before merging.
    """
    gap = _VALID_CIPHER_KINDS - _SUPPORTED_KINDS
    assert gap == set(), (
        f"DSL-valid kinds that lack a dispatcher translator: "
        f"{sorted(gap)}. Wire a translator for each missing kind into "
        f"job_dispatcher._SUPPORTED_KINDS and _translate_layer."
    )


def test_dispatcher_kinds_are_dsl_valid():
    """The dispatcher must not advertise translation for kinds the DSL rejects."""
    extra = _SUPPORTED_KINDS - _VALID_CIPHER_KINDS
    assert extra == set(), (
        f"_SUPPORTED_KINDS contains kinds not in _VALID_CIPHER_KINDS: "
        f"{sorted(extra)}. Either remove them from the dispatcher or "
        f"add them to the DSL."
    )


# ---------------------------------------------------------------------------
# Alphabet parity
# ---------------------------------------------------------------------------


def test_dispatcher_supports_full_dsl_alphabet_set():
    """Currently the dispatcher covers every alphabet the DSL accepts.

    If a new alphabet is added to the DSL without a dispatcher branch,
    this test fires. (The reverse — dispatcher adds an alphabet the DSL
    rejects — is caught by ``test_dispatcher_alphabets_are_dsl_valid``.)
    """
    gap = _VALID_ALPHABET_KINDS - _SUPPORTED_ALPHABETS
    assert gap == set(), (
        f"DSL accepts alphabets the dispatcher cannot translate: "
        f"{sorted(gap)}. Wire them into "
        f"job_dispatcher._resolve_alphabet_sequence and "
        f"_SUPPORTED_ALPHABETS."
    )


def test_dispatcher_alphabets_are_dsl_valid():
    extra = _SUPPORTED_ALPHABETS - _VALID_ALPHABET_KINDS
    assert extra == set(), (
        f"_SUPPORTED_ALPHABETS contains alphabets not in "
        f"_VALID_ALPHABET_KINDS: {sorted(extra)}."
    )


# ---------------------------------------------------------------------------
# DSL tool / dispatcher agreement
# ---------------------------------------------------------------------------


def _invoke_enumerate(assumption_bundle=None):
    """Execute enumerate_admissible_transforms_tool synchronously.

    The @tool decorator wraps the function in an SdkMcpTool object whose
    underlying coroutine is exposed as .handler — same pattern the
    existing test_dsl_tools.py uses.
    """
    import asyncio
    from kryptosbot.dsl_tools import enumerate_admissible_transforms_tool

    return asyncio.run(
        enumerate_admissible_transforms_tool.handler(
            {"assumption_bundle": list(assumption_bundle or [])},
        ),
    )


def _envelope_data(tool_response):
    blocks = tool_response["content"]
    text = blocks[0]["text"]
    return json.loads(text)["data"]


def test_dsl_tool_matches_dispatcher_supported_kinds():
    data = _envelope_data(_invoke_enumerate())
    assert set(data["supported_kinds"]) == set(_SUPPORTED_KINDS), (
        f"enumerate_admissible_transforms_tool reports kinds "
        f"{sorted(data['supported_kinds'])} but dispatcher actually "
        f"supports {sorted(_SUPPORTED_KINDS)}. Agents will be misled."
    )


def test_dsl_tool_matches_dispatcher_supported_alphabets():
    data = _envelope_data(_invoke_enumerate())
    assert set(data["supported_alphabets"]) == set(_SUPPORTED_ALPHABETS), (
        f"enumerate_admissible_transforms_tool reports alphabets "
        f"{sorted(data['supported_alphabets'])} but dispatcher actually "
        f"supports {sorted(_SUPPORTED_ALPHABETS)}. Agents will avoid "
        f"valid search space."
    )


def test_dsl_tool_unsupported_alphabets_match_dsl_gap():
    data = _envelope_data(_invoke_enumerate())
    expected_gap = sorted(_VALID_ALPHABET_KINDS - _SUPPORTED_ALPHABETS)
    assert sorted(data["unsupported_alphabets"]) == expected_gap


# ---------------------------------------------------------------------------
# ORIENT.md staleness checks
# ---------------------------------------------------------------------------

# Strings whose underlying bugs are fixed. If they reappear in ORIENT.md,
# the doc has regressed (likely a bad merge or a hand-edit that revived
# old text).
_FORBIDDEN_ORIENT_STRINGS = (
    # Pre-R2-2 KA-failure hint; KA support landed 2026-04-21.
    "alphabet 'KA' not supported in Phase 4 dispatcher",
    # Pre-R2-2 narrative claim — superseded by §5.4 historical-note form.
    "Phase 4 DSL dispatcher only handles AZ alphabet",
)


def test_orient_md_has_no_stale_failure_strings():
    orient_path = _KRYPTOSBOT / "ORIENT.md"
    assert orient_path.exists(), f"ORIENT.md missing at {orient_path}"
    text = orient_path.read_text(encoding="utf-8")
    # Allow the strings inside historical / "if you still see" framing
    # by matching them as standalone hint sentences (not all occurrences).
    # Practically: bare appearance is fine if it's inside a sentence
    # that explicitly marks the failure as historical. The simplest way
    # to enforce that is to require any occurrence to also have one of
    # ("Historical", "older than R2-2", "pre-R2-2") on the same line or
    # the line immediately before.
    lines = text.splitlines()
    for forbidden in _FORBIDDEN_ORIENT_STRINGS:
        for i, line in enumerate(lines):
            if forbidden in line:
                window = " ".join(lines[max(0, i - 2): i + 1]).lower()
                assert any(
                    marker in window
                    for marker in ("historical", "older than r2-2",
                                   "pre-r2-2")
                ), (
                    f"ORIENT.md line {i + 1} mentions a fixed failure "
                    f"({forbidden!r}) without flagging it as historical."
                )


# ---------------------------------------------------------------------------
# Transport preflight robustness
# ---------------------------------------------------------------------------


def test_preflight_regex_matches_real_self_test_format():
    """The preflight matcher must accept what self_test_real_api actually prints.

    Regression for the 11-vs-9-space mismatch: the preflight used to
    hard-code 11 spaces between "discovered" and the colon, but the
    self-test prints 9 spaces, so a successful test was misclassified
    as a transport failure.
    """
    from kryptosbot.transport_preflight import _DISCOVERED_TRUE_RE

    real_format_line = "discovered         : True"
    assert _DISCOVERED_TRUE_RE.search(real_format_line), (
        "transport_preflight regex no longer matches the real "
        "self_test_real_api column-padded format."
    )

    # Spot-check tolerance against several plausible label-paddings.
    for padding in (0, 1, 3, 5, 9, 11, 15):
        line = "discovered" + (" " * padding) + ": True"
        assert _DISCOVERED_TRUE_RE.search(line), (
            f"regex rejected padding={padding}"
        )


def test_preflight_regex_actually_used_self_test_print_format():
    """The matcher must align with the format string in self_test_real_api.

    Reads the literal print statement at self_test_real_api.py:424 (or
    wherever it has moved to) and asserts the matcher accepts the
    rendered text. This is the contract: if the self-test changes its
    print format, this test fires before production breaks.
    """
    from kryptosbot.transport_preflight import _DISCOVERED_TRUE_RE

    self_test_path = _KRYPTOSBOT / "self_test_real_api.py"
    text = self_test_path.read_text(encoding="utf-8")

    # Find the f-string that produces the discovered line. The current
    # form is:  print(f"discovered         : {result.discovered}")
    pattern = re.compile(
        r'print\(f"(discovered\s*:\s*)\{[^}]*\}"\)',
    )
    match = pattern.search(text)
    assert match is not None, (
        "Could not find the 'discovered : ...' print statement in "
        "self_test_real_api.py. Either the format changed or the "
        "matcher in this test needs updating to find it."
    )

    label_prefix = match.group(1)
    rendered = f"{label_prefix}True"
    assert _DISCOVERED_TRUE_RE.search(rendered), (
        f"transport_preflight regex does not match the actual "
        f"self_test print rendering: {rendered!r}. Update the regex "
        f"or revisit the print format."
    )
