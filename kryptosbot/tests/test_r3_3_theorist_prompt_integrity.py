"""R3-3 theorist-prompt integrity test.

Verifies the DSL_SPEC CONTRACT section is correctly embedded in the
theorist prompt. A static-analysis guard against prompt drift:
catches the failure mode where a future edit removes the example
block or the supported-kinds list, which would tank the live spec-
production rate silently.

This test complements (not replaces) the real-theorist --dry-run
measurement documented in the R3-3 phase report. Both are required:
this test proves the prompt is structurally correct; the dry-run
proves the structure actually induces valid spec output from real
theorists.
"""
from __future__ import annotations

import pytest

import inspect

from kryptosbot.controller import ResearchController


def _get_prompt(tmp_path=None) -> str:
    """Extract the theorist prompt template as source text.

    Avoids running _assess_landscape (which needs heavy controller
    state to execute) and _build_theorist_prompt (which pulls config
    fields that change). Inspecting the source directly is sufficient
    to verify the prompt contract's literal contents — the precise
    strings the theorist reads.
    """
    return inspect.getsource(ResearchController._build_theorist_prompt)


def test_theorist_prompt_includes_dsl_spec_contract(tmp_path):
    prompt = _get_prompt(tmp_path)
    assert "DSL_SPEC CONTRACT" in prompt, (
        "theorist prompt must declare the DSL_SPEC CONTRACT section "
        "so theorists understand the requirement"
    )


def test_theorist_prompt_lists_supported_kinds(tmp_path):
    prompt = _get_prompt(tmp_path)
    # All 13 B-DSL-expanded supported kinds must appear in the prompt.
    # Regression target 2026-04-22: prompt previously listed only the
    # original 9 kinds, so the theorist never saw "route", "rail_fence",
    # "myszkowski", or "quagmire" and fell back to kind="procedural"
    # with invented recipe names, triggering dsl_untranslatable.
    for kind in ("identity", "vigenere", "beaufort", "variant_beaufort",
                 "columnar", "atbash", "procedural", "grille", "polybius",
                 "rail_fence", "myszkowski", "route", "quagmire"):
        assert kind in prompt, (
            f"theorist prompt missing supported kind {kind!r}; "
            "DSL coverage won't be accurately conveyed"
        )


def test_theorist_prompt_disambiguates_procedural_paradigm_from_dsl_kind(tmp_path):
    """The "procedural paradigm" philosophical section and the DSL's
    literal ``kind="procedural"`` (recipe_id only) are two different
    things. Conflating them produces dsl_untranslatable rejections on
    every non-registered procedural hypothesis.

    Added 2026-04-22 after Campaign B theorist produced serpentine /
    ragbaby / Alberti-disk proposals all tagged kind="procedural" with
    ad-hoc recipe strings; the prompt now must explicitly separate the
    two concepts and point theorists at the specific cipher kinds."""
    prompt = _get_prompt(tmp_path)
    # The disambiguation section MUST appear and must direct serpentine
    # specifically to kind='route' + variant='serpentine'.
    lowered = prompt.lower()
    assert "kind=\"route\"" in lowered or "kind='route'" in lowered or "route" in lowered, (
        "prompt must reference route kind so theorists know how to "
        "encode serpentine/spiral hypotheses"
    )
    assert "serpentine" in lowered
    # The prompt must warn theorists that kind="procedural" with an
    # invented recipe name gets rejected.
    assert "dsl_untranslatable" in lowered
    # And must distinguish the DSL kind from the paradigm philosophy.
    assert any(tok in prompt for tok in (
        "DSL kind",
        "literal",
        "DISAMBIGUATION",
        "procedural paradigm",
    )), (
        "prompt must explicitly disambiguate DSL 'procedural' kind from "
        "philosophical 'procedural paradigm' preference"
    )


def test_theorist_prompt_lists_untranslatable_kinds(tmp_path):
    prompt = _get_prompt(tmp_path)
    # After key_tape DSL build Task 9 (2026-05-03), ALL DSL-valid kinds have
    # dispatcher translators — the untranslatable list is now empty. The
    # prompt must still declare the "Untranslatable kinds" header (so the
    # section doesn't vanish silently), but it must explicitly state that no
    # kinds are deferred. No kinds must appear on the deferred list.
    import re
    untranslatable_section = re.search(
        r"Untranslatable kinds.*?:\s*\n\s*([^\n]+)", prompt, re.DOTALL,
    )
    assert untranslatable_section, (
        "theorist prompt must declare an 'Untranslatable kinds' section"
    )
    # All previously-deferred kinds must be absent from the section.
    for kind in ("rail_fence", "route", "myszkowski", "quagmire", "key_tape"):
        assert kind not in untranslatable_section.group(1), (
            f"{kind!r} is now supported and must not appear on the "
            f"untranslatable-kinds listing"
        )


def test_theorist_prompt_enumerates_dsl_enum_domains(tmp_path):
    prompt = _get_prompt(tmp_path)
    for token in (
        "direct_positional",
        "post_transposition",
        "free",
        "crib_only",
        "crib_plus_bean",
        "ngram_vs_null",
        "composite",
        "random_text",
        "shuffled_ct",
        "matched_variant_family",
        "monte_carlo_cached",
        "AZ",
        "KA",
        "keyword_mixed",
    ):
        assert token in prompt, (
            f"theorist prompt must enumerate DSL token {token!r} "
            "to reduce enum invention drift"
        )


def test_theorist_prompt_calls_out_invalid_free_search_alias(tmp_path):
    prompt = _get_prompt(tmp_path)
    assert "free_search" in prompt
    assert 'only free-alignment enum value is "free"' in prompt


def test_theorist_prompt_canonicalizes_quagmire_variant_field(tmp_path):
    """Quagmire variant naming canonicalization (2026-04-24).

    Theorists across Campaigns A, B, and C proposed quagmire layers
    with ``variant='III'`` (matching the cipher's common roman-numeral
    label) but the translator only accepts ``'quagmire_iii'`` /
    ``'quagmire_iv'``. 15 theories total across three campaigns were
    lost to admissibility translation errors with this exact shape.

    The prompt must explicitly disambiguate by specifying the canonical
    form AND the exact rejected form so the theorist learns to write
    ``quagmire_iii`` instead of ``III``.
    """
    prompt = _get_prompt(tmp_path)
    # Canonical form explicitly enumerated so theorists can lift it
    # directly.
    assert "quagmire_iii" in prompt, (
        "theorist prompt must show the canonical variant "
        "'quagmire_iii' so proposals don't use the roman-numeral form"
    )
    assert "quagmire_iv" in prompt, (
        "theorist prompt must show 'quagmire_iv' (the other canonical "
        "variant) alongside quagmire_iii"
    )
    # Anti-example: the rejected shape must also appear, explicitly
    # flagged as wrong. Without this, a future prompt edit that drops
    # the disambiguation would silently revive the translation-error
    # class observed in Campaigns A/B/C.
    assert '"III"' in prompt, (
        "theorist prompt must call out the rejected roman-numeral form "
        "'III' as the anti-example so the contrast is explicit"
    )
    # Cross-check: the rejection mode (dsl_untranslatable) must be
    # named in the vicinity of the anti-example so the theorist knows
    # the *consequence* of emitting the wrong form, not just that one
    # form is preferred.
    assert "dsl_untranslatable" in prompt


def test_theorist_prompt_includes_three_worked_examples(tmp_path):
    prompt = _get_prompt(tmp_path)
    # The three examples have distinct headers. Verify all three appear.
    for header in ("Example A", "Example B", "Example C"):
        assert header in prompt, (
            f"theorist prompt must include {header} from DSL_CUTOVER_CONTRACT §1.3"
        )


def test_theorist_prompt_names_non_dsl_families(tmp_path):
    prompt = _get_prompt(tmp_path)
    # NON_DSL_FAMILIES members must appear verbatim so theorists know
    # which families are exempt from the Category-A requirement.
    for family in ("geometry", "k2_coords", "geodetic", "antipodes",
                   "archive_evidence", "crib_analysis", "k3_continuity"):
        assert family in prompt, (
            f"theorist prompt must list NON_DSL_FAMILIES member {family!r} "
            "so theorists know Category B doesn't need a spec"
        )


def test_theorist_prompt_discourages_fabrication(tmp_path):
    """Brief §1 principle: theorists must not fabricate specs to
    satisfy the DSL requirement. The prompt's language must include
    an explicit discourage-fabrication clause."""
    prompt = _get_prompt(tmp_path)
    # The prompt says: "DO NOT fabricate one. Set dsl_spec=null and
    # accept rejection"
    assert "DO NOT fabricate" in prompt or "not fabricate" in prompt, (
        "theorist prompt must explicitly discourage spec fabrication; "
        "this is the scope-discipline clause"
    )
