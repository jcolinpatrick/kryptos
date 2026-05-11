"""Tests for swing_k1_structure (channels S1..S4)."""
import pytest


def test_s1_finds_exact_substring_in_tier_a():
    """If the keystream IS a 24-char substring of a Tier A source text, S1 fires."""
    from kryptosbot.swing_k1_structure import scan_source_text, _str_to_idx_seq
    # Fake corpus with a known 24-char run.
    plant = "ABCDEFGHIJKLMNOPQRSTUVWX"
    fake_corpus_text = "JUNK" + plant + "MOREJUNK"
    fake_entries = [type("E", (), {"id": "fake", "text": lambda self=None: fake_corpus_text})()]
    keystream_idx = _str_to_idx_seq(plant)
    hit = scan_source_text(keystream_idx, fake_entries)
    assert hit is not None
    assert hit.source_id == "fake"
    assert hit.offset == 4
    assert hit.match_len == 24


def test_s1_returns_none_when_no_match():
    from kryptosbot.swing_k1_structure import scan_source_text, _str_to_idx_seq
    fake_entries = [type("E", (), {"id": "fake", "text": lambda self=None: "ENGLISHTEXTWITHNORANDOMKEYSEQUENCE"})()]
    random_ks = _str_to_idx_seq("ZZQXJVQXJVQXJVQXJVQXJVQX")  # unlikely substring
    hit = scan_source_text(random_ks, fake_entries)
    assert hit is None


def test_s1_partial_match_below_threshold_does_not_promote():
    """Partial matches at len < 24 are recorded but not promotion-eligible."""
    from kryptosbot.swing_k1_structure import scan_source_text, _str_to_idx_seq
    fake_entries = [type("E", (), {"id": "fake", "text": lambda self=None: "ABCDEFGHIJKLMNOPQRSTUVWZ" * 2})()]
    # Plant a 23-char match; expect None at 24-length threshold
    ks24 = _str_to_idx_seq("ABCDEFGHIJKLMNOPQRSTUVWX")
    hit = scan_source_text(ks24, fake_entries, threshold_len=24)
    assert hit is None  # exact 24 not present


def test_s1_prepared_finds_substring():
    """scan_source_text_prepared returns same hit as scan_source_text on same input."""
    from kryptosbot.swing_k1_structure import (
        prepare_corpus, scan_source_text, scan_source_text_prepared, _str_to_idx_seq,
    )
    plant = "ABCDEFGHIJKLMNOPQRSTUVWX"
    fake_text = "JUNK" + plant + "MOREJUNK"
    fake_entries = [type("E", (), {"id": "fake", "text": lambda self=None: fake_text})()]
    prepared = prepare_corpus(fake_entries)
    keystream_idx = _str_to_idx_seq(plant)
    legacy_hit = scan_source_text(keystream_idx, fake_entries)
    prepared_hit = scan_source_text_prepared(keystream_idx, prepared)
    assert legacy_hit is not None and prepared_hit is not None
    assert legacy_hit.source_id == prepared_hit.source_id == "fake"
    assert legacy_hit.offset == prepared_hit.offset == 4
    assert legacy_hit.match_len == prepared_hit.match_len == 24


def test_s1_prepared_returns_none_when_no_match():
    from kryptosbot.swing_k1_structure import prepare_corpus, scan_source_text_prepared, _str_to_idx_seq
    fake_entries = [type("E", (), {"id": "fake", "text": lambda self=None: "ENGLISHTEXTWITHNORANDOMKEYSEQUENCE"})()]
    prepared = prepare_corpus(fake_entries)
    random_ks = _str_to_idx_seq("ZZQXJVQXJVQXJVQXJVQXJVQX")
    hit = scan_source_text_prepared(random_ks, prepared)
    assert hit is None
