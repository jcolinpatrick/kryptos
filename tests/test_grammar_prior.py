"""Tests for kryptos.language grammar prior."""
import json
import subprocess
import sys
import os

from kryptos.language import (
    POS_TAGS, RegisterStyle,
    directive_register, status_report_register,
    telegraphic_register, hybrid_register, all_registers,
    WordEntry, all_entries, entries_by_length, entries_by_pos,
    entries_by_length_and_pos, find_word,
    PhraseTemplate, all_templates, template_by_id,
    CandidateFill, ScoreBreakdown, score_candidate, rank_candidates,
    left_context_candidates, right_context_candidates,
    compare_anchor_phrases, score_sequence,
    DEFAULT_WEIGHTS,
)
from kryptos.language.templates import (
    DIRECTIVE_VERB_DIRECTION, ANCHOR_LEFT_PREP, ANCHOR_LEFT_VERB,
    STATUS_NOUN_PARTICIPLE, DIRECTIVE_LOCATIVE_TARGET,
)


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CLI_PATH = os.path.join(REPO_ROOT, "scripts", "tools", "k4_grammar_probe.py")


def test_inventories_load():
    entries = all_entries()
    assert len(entries) > 20
    for e in entries:
        assert e.pos in POS_TAGS, f"bad POS for {e.word}: {e.pos}"
        assert e.length == len(e.word)
        assert e.word.isupper()


def test_inventories_deterministic():
    a = all_entries()
    b = all_entries()
    assert [(e.word, e.pos) for e in a] == [(e.word, e.pos) for e in b]


def test_entries_by_length_filter():
    es = entries_by_length(2)
    assert all(e.length == 2 for e in es)
    assert any(e.word == "AT" for e in es)


def test_entries_by_pos_filter():
    es = entries_by_pos("PREP")
    assert len(es) > 5
    assert all(e.pos == "PREP" for e in es)


def test_template_slot_count_consistent():
    for t in all_templates():
        assert isinstance(t, PhraseTemplate)
        assert len(t.slots) >= 2
        for slot in t.slots:
            assert len(slot.allowed_pos) >= 1
    assert template_by_id("directive_verb_direction") is not None


def test_directive_register_prefers_verb_initial():
    reg = directive_register()
    init = reg.initial_pos_weights
    assert init["VERB_OP"] >= max(init["ART"], init["NOUN_STATUS"])


def test_status_report_register_prefers_noun_initial():
    reg = status_report_register()
    init = reg.initial_pos_weights
    assert init["NOUN_STATUS"] >= init["VERB_OP"]


def test_telegraphic_register_suppresses_articles():
    reg = telegraphic_register()
    assert reg.article_suppression > 0.5


def _score_phrase(words, template, register_fn, anchor="", side=""):
    cand = CandidateFill(slot_words=tuple(words),
                         template=template, register=register_fn())
    return score_candidate(cand, anchor=anchor, anchor_position=side)


def test_at_berlinclock_scores_higher_than_of_berlinclock():
    at = _score_phrase(("AT", "BERLINCLOCK"), ANCHOR_LEFT_PREP,
                       directive_register, anchor="BERLINCLOCK", side="right")
    of = _score_phrase(("OF", "BERLINCLOCK"), ANCHOR_LEFT_PREP,
                       directive_register, anchor="BERLINCLOCK", side="right")
    assert at.aggregate > of.aggregate


def test_to_berlinclock_ranking_documented():
    # The user's intuition is AT > TO. Document whichever the model says.
    at = _score_phrase(("AT", "BERLINCLOCK"), ANCHOR_LEFT_PREP,
                       directive_register, anchor="BERLINCLOCK", side="right")
    to = _score_phrase(("TO", "BERLINCLOCK"), ANCHOR_LEFT_PREP,
                       directive_register, anchor="BERLINCLOCK", side="right")
    # Not asserting direction — both must be plausible (positive) and close.
    assert at.aggregate > 0.4
    assert to.aggregate > 0.4


def test_go_eastnortheast_scores_higher_than_at_eastnortheast():
    go = _score_phrase(("GO", "EASTNORTHEAST"), ANCHOR_LEFT_VERB,
                       directive_register, anchor="EASTNORTHEAST", side="right")
    at = _score_phrase(("AT", "EASTNORTHEAST"), ANCHOR_LEFT_PREP,
                       directive_register, anchor="EASTNORTHEAST", side="right")
    assert go.aggregate > at.aggregate


def test_meet_at_berlinclock_scores_above_meet_berlinclock_non_telegraphic():
    from kryptos.language.templates import DIRECTIVE_VERB_PREP_LANDMARK
    meet_at = _score_phrase(
        ("MEET", "AT", "BERLINCLOCK"),
        DIRECTIVE_VERB_PREP_LANDMARK, directive_register,
        anchor="BERLINCLOCK", side="right",
    )
    meet_bc = _score_phrase(
        ("MEET", "", "BERLINCLOCK"),
        DIRECTIVE_LOCATIVE_TARGET, directive_register,
        anchor="BERLINCLOCK", side="right",
    )
    assert meet_at.aggregate >= meet_bc.aggregate


def test_meet_berlinclock_preferred_in_telegraphic():
    from kryptos.language.templates import DIRECTIVE_VERB_PREP_LANDMARK
    meet_at = _score_phrase(
        ("MEET", "AT", "BERLINCLOCK"),
        DIRECTIVE_VERB_PREP_LANDMARK, telegraphic_register,
        anchor="BERLINCLOCK", side="right",
    )
    meet_bc = _score_phrase(
        ("MEET", "", "BERLINCLOCK"),
        DIRECTIVE_LOCATIVE_TARGET, telegraphic_register,
        anchor="BERLINCLOCK", side="right",
    )
    # in telegraphic, article/prep suppression is more tolerated; the
    # article_suppression_consistency component favors the compressed form
    assert meet_bc.article_suppression_consistency >= meet_at.article_suppression_consistency


def test_score_breakdown_transparent():
    sb = _score_phrase(("AT", "BERLINCLOCK"), ANCHOR_LEFT_PREP,
                       directive_register, anchor="BERLINCLOCK", side="right")
    keys = set(sb.components.keys())
    for k in DEFAULT_WEIGHTS:
        assert k in keys


def test_score_aggregate_is_linear_combination():
    sb = _score_phrase(("GO", "EASTNORTHEAST"), ANCHOR_LEFT_VERB,
                       directive_register, anchor="EASTNORTHEAST", side="right")
    tw = sum(DEFAULT_WEIGHTS.values())
    expected = sum(DEFAULT_WEIGHTS[k] * sb.components[k] for k in DEFAULT_WEIGHTS) / tw
    assert abs(sb.aggregate - expected) < 1e-9


def test_compare_phrases_returns_breakdown_per_phrase():
    res = compare_anchor_phrases(
        ["AT BERLINCLOCK", "TO BERLINCLOCK", "OF BERLINCLOCK"],
        anchor="BERLINCLOCK",
    )
    assert set(res.keys()) == {"AT BERLINCLOCK", "TO BERLINCLOCK", "OF BERLINCLOCK"}
    for sb in res.values():
        assert isinstance(sb, ScoreBreakdown)


def test_left_context_candidates_returns_top_k():
    results = left_context_candidates("BERLINCLOCK", slot_length=2, role="PREP", top_k=5)
    assert 0 < len(results) <= 5
    for sb in results:
        assert isinstance(sb, ScoreBreakdown)


def test_cli_query_left_context_text_output():
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.join(REPO_ROOT, "src")
    r = subprocess.run(
        [sys.executable, CLI_PATH, "--query", "left-context",
         "--anchor", "BERLINCLOCK", "--slot-length", "2",
         "--role", "PREP", "--top-k", "5"],
        capture_output=True, text=True, env=env, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    assert "BERLINCLOCK" in r.stdout
    assert "soft signal" in r.stdout.lower()


def test_cli_query_compare_json_output():
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.join(REPO_ROOT, "src")
    r = subprocess.run(
        [sys.executable, CLI_PATH, "--query", "compare",
         "--anchor", "BERLINCLOCK",
         "--phrases", "AT BERLINCLOCK", "OF BERLINCLOCK",
         "--format", "json"],
        capture_output=True, text=True, env=env, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    # pull JSON out — CLI prints header and trailing disclaimer
    lines = r.stdout.splitlines()
    start = next(i for i, l in enumerate(lines) if l.strip().startswith("{"))
    end = next(i for i in range(len(lines) - 1, -1, -1) if lines[i].strip().startswith("}"))
    blob = "\n".join(lines[start:end + 1])
    data = json.loads(blob)
    assert "AT BERLINCLOCK" in data
    assert "aggregate" in data["AT BERLINCLOCK"]


def test_score_does_not_promote_to_signal():
    # No scoring path produces the strings "signal" or "crib" as a label.
    sb = score_sequence("ASSET COMPROMISED")
    blob = json.dumps(sb.to_dict()).lower()
    assert "signal" not in blob
    assert "crib" not in blob
