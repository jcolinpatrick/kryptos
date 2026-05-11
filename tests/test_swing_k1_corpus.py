"""Tests for swing_k1_corpus."""
from pathlib import Path

import pytest


def test_load_tier_a_returns_entries():
    from kryptosbot.swing_k1_corpus import load_tier_a
    corpus = load_tier_a()
    assert len(corpus.entries) >= 3  # at least K1, K2, K3 inline
    ids = {e.id for e in corpus.entries}
    assert "k1_plaintext" in ids
    assert "k2_plaintext" in ids
    assert "k3_plaintext" in ids


def test_inline_plaintext_hashes_resolved():
    from kryptosbot.swing_k1_corpus import load_tier_a
    corpus = load_tier_a()
    k1 = next(e for e in corpus.entries if e.id == "k1_plaintext")
    # Hash is computed at load, not the placeholder string.
    assert k1.sha256 != "COMPUTE_AT_LOAD_TIME"
    assert len(k1.sha256) == 64
    assert all(c in "0123456789abcdef" for c in k1.sha256)


def test_file_entry_hash_matches_disk():
    import hashlib
    from kryptosbot.swing_k1_corpus import load_tier_a
    REPO_ROOT = Path(__file__).resolve().parent.parent  # tests/.. = repo root
    corpus = load_tier_a()
    for entry in corpus.entries:
        if entry.kind == "file":
            with open(REPO_ROOT / entry.path, "rb") as f:
                expected = hashlib.sha256(f.read()).hexdigest()
            assert entry.sha256 == expected, f"hash mismatch for {entry.path}"


def test_corpus_hash_stable():
    from kryptosbot.swing_k1_corpus import load_tier_a
    a1 = load_tier_a()
    a2 = load_tier_a()
    assert a1.manifest_hash == a2.manifest_hash


def test_tier_b_empty_in_phase_a():
    from kryptosbot.swing_k1_corpus import load_tier_b
    corpus = load_tier_b()
    assert list(corpus.entries) == []


def test_uppercase_normalized_text():
    """All entries expose .text() as uppercase A..Z only, for slide-scan."""
    from kryptosbot.swing_k1_corpus import load_tier_a
    for entry in load_tier_a().entries:
        t = entry.text()
        assert isinstance(t, str)
        assert all(c.isalpha() and c == c.upper() for c in t)
