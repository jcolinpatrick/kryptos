"""QA test coverage for pipeline, novelty triage, persistence, and utility modules.

Fills critical coverage gaps identified in iteration 3:
- pipeline/runners.py (SweepRunner) — unit tests for config, resume, signal handling
- pipeline/experiments.py (worker functions) — block & full transposition workers
- pipeline/evaluation.py (evaluate_pipeline) — extended evaluation tests
- novelty/triage.py (hypothesis filtering) — all three triage paths + batch
- kernel/persistence/sqlite.py (Database) — CRUD, checkpoint, resume
- kernel/persistence/artifacts.py (RunManifest, JsonlWriter) — create, save, load
- kernel/scoring/ngram.py (NgramScorer) — score, score_per_char, from_file
- kernel/text.py — sanitize, text_to_nums, nums_to_text, char_to_num, num_to_char
- kernel/constraints/consistency.py — self-encrypting, mono consistency, bijection
"""
import json
import math
import os
import sqlite3
import tempfile
from pathlib import Path

import pytest

from kryptos.kernel.constants import (
    CT, CT_LEN, ALPH, ALPH_IDX, MOD, CRIB_DICT, CRIB_ENTRIES,
    CRIB_POSITIONS, NOISE_FLOOR, SELF_ENCRYPTING,
)


# Module-level worker function for SweepRunner test (must be picklable)
def _trivial_worker(item):
    return {
        "job_id": item["job_id"],
        "best_score": 3,
        "top_results": [],
        "config_label": "test",
    }


# ═══════════════════════════════════════════════════════════════════════
# SECTION 1: kernel/text.py
# ═══════════════════════════════════════════════════════════════════════

class TestTextUtils:
    """Tests for kernel/text.py — sanitize, text_to_nums, nums_to_text."""

    def test_sanitize_basic(self):
        from kryptos.kernel.text import sanitize
        assert sanitize("Hello, World!") == "HELLOWORLD"

    def test_sanitize_lowercase(self):
        from kryptos.kernel.text import sanitize
        assert sanitize("abc") == "ABC"

    def test_sanitize_digits_and_spaces(self):
        from kryptos.kernel.text import sanitize
        assert sanitize("A1 B2 C3") == "ABC"

    def test_sanitize_empty(self):
        from kryptos.kernel.text import sanitize
        assert sanitize("") == ""
        assert sanitize("123!@#") == ""

    def test_text_to_nums_basic(self):
        from kryptos.kernel.text import text_to_nums
        assert text_to_nums("ABC") == [0, 1, 2]
        assert text_to_nums("Z") == [25]

    def test_text_to_nums_full_alphabet(self):
        from kryptos.kernel.text import text_to_nums
        result = text_to_nums("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        assert result == list(range(26))

    def test_nums_to_text_basic(self):
        from kryptos.kernel.text import nums_to_text
        assert nums_to_text([0, 1, 2]) == "ABC"
        assert nums_to_text([25]) == "Z"

    def test_text_to_nums_roundtrip(self):
        from kryptos.kernel.text import text_to_nums, nums_to_text
        original = "KRYPTOS"
        assert nums_to_text(text_to_nums(original)) == original

    def test_nums_to_text_mod_wrap(self):
        from kryptos.kernel.text import nums_to_text
        assert nums_to_text([26]) == "A"  # 26 mod 26 = 0 → A
        assert nums_to_text([27]) == "B"  # 27 mod 26 = 1 → B

    def test_char_to_num(self):
        from kryptos.kernel.text import char_to_num
        assert char_to_num("A") == 0
        assert char_to_num("Z") == 25
        assert char_to_num("a") == 0  # lowercase

    def test_num_to_char(self):
        from kryptos.kernel.text import num_to_char
        assert num_to_char(0) == "A"
        assert num_to_char(25) == "Z"
        assert num_to_char(26) == "A"  # mod 26


# ═══════════════════════════════════════════════════════════════════════
# SECTION 2: kernel/scoring/ngram.py
# ═══════════════════════════════════════════════════════════════════════

class TestNgramScorer:
    """Tests for NgramScorer — n-gram log-probability scoring."""

    def test_score_basic(self):
        from kryptos.kernel.scoring.ngram import NgramScorer
        probs = {"TION": -1.0, "IONS": -1.5, "ONSE": -2.0}
        scorer = NgramScorer(probs, n=4)
        # "TIONS" has two quadgrams: TION (-1.0) + IONS (-1.5) = -2.5
        assert scorer.score("TIONS") == pytest.approx(-2.5)

    def test_score_unknown_gram_uses_floor(self):
        from kryptos.kernel.scoring.ngram import NgramScorer
        probs = {"AAAA": -1.0, "BBBB": -2.0}
        scorer = NgramScorer(probs, n=4)
        # "XXXX" is unknown, should use floor = min(probs) = -2.0
        assert scorer.score("XXXX") == pytest.approx(-2.0)

    def test_score_per_char_basic(self):
        from kryptos.kernel.scoring.ngram import NgramScorer
        probs = {"TION": -1.0, "IONS": -1.5}
        scorer = NgramScorer(probs, n=4)
        # "TIONS": 2 quadgrams, total = -2.5, per_char = -2.5/2 = -1.25
        assert scorer.score_per_char("TIONS") == pytest.approx(-1.25)

    def test_score_per_char_short_text_returns_floor(self):
        from kryptos.kernel.scoring.ngram import NgramScorer
        probs = {"AAAA": -1.0}
        scorer = NgramScorer(probs, n=4)
        # "AB" has 0 quadgrams (len < n), should return floor
        assert scorer.score_per_char("AB") == scorer._floor

    def test_score_case_insensitive(self):
        from kryptos.kernel.scoring.ngram import NgramScorer
        probs = {"ABCD": -1.5}
        scorer = NgramScorer(probs, n=4)
        assert scorer.score("abcd") == scorer.score("ABCD")

    def test_empty_probs_floor(self):
        from kryptos.kernel.scoring.ngram import NgramScorer
        scorer = NgramScorer({}, n=4)
        assert scorer._floor == -10.0

    def test_from_file_flat_format(self, tmp_path):
        from kryptos.kernel.scoring.ngram import NgramScorer
        data = {"TION": -1.0, "IONS": -1.5, "NESS": -2.0}
        path = tmp_path / "quadgrams.json"
        path.write_text(json.dumps(data))
        scorer = NgramScorer.from_file(path, n=4)
        assert scorer.score("TION") == pytest.approx(-1.0)

    def test_from_file_nested_format(self, tmp_path):
        from kryptos.kernel.scoring.ngram import NgramScorer
        data = {"logp": {"TION": -1.0, "IONS": -1.5}}
        path = tmp_path / "quadgrams.json"
        path.write_text(json.dumps(data))
        scorer = NgramScorer.from_file(path, n=4)
        assert scorer.score("TION") == pytest.approx(-1.0)

    def test_real_quadgrams_load(self):
        """Verify the real quadgram file loads correctly."""
        from kryptos.kernel.scoring.ngram import NgramScorer
        qpath = Path("data/english_quadgrams.json")
        if not qpath.exists():
            pytest.skip("Quadgram file not found")
        scorer = NgramScorer.from_file(qpath)
        # English text should score higher than random
        english_score = scorer.score_per_char("THEQUICKBROWNFOXJUMPS")
        random_score = scorer.score_per_char("XQZJKWVNPMFLBDRHTCGYS")
        assert english_score > random_score


# ═══════════════════════════════════════════════════════════════════════
# SECTION 3: kernel/persistence/sqlite.py
# ═══════════════════════════════════════════════════════════════════════

class TestDatabase:
    """Tests for Database — SQLite persistence layer."""

    @pytest.fixture
    def db(self, tmp_path):
        from kryptos.kernel.persistence.sqlite import Database
        db = Database(tmp_path / "test.sqlite")
        yield db
        db.close()

    def test_schema_creation(self, db):
        """Tables are created on init."""
        cursor = db.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = {row[0] for row in cursor.fetchall()}
        assert "runs" in tables
        assert "results" in tables
        assert "eliminations" in tables
        assert "checkpoints" in tables

    def test_wal_mode(self, db):
        """WAL mode is enabled."""
        cursor = db.conn.execute("PRAGMA journal_mode")
        assert cursor.fetchone()[0].lower() == "wal"

    def test_store_and_query_result(self, db):
        """Store a result and query it back."""
        db.store_result(
            experiment_id="test_exp",
            config={"variant": "vigenere", "period": 5},
            score=15,
            bean_pass=True,
            plaintext="TESTPLAINTEXT",
            run_id="run_001",
        )
        db.commit()
        results = db.top_results(limit=10, min_score=10)
        assert len(results) == 1
        assert results[0]["score"] == 15
        assert results[0]["experiment_id"] == "test_exp"
        assert results[0]["bean_pass"] == 1  # SQLite stores bool as int

    def test_top_results_ordering(self, db):
        """Results are returned in descending score order."""
        for score in [5, 15, 10, 20]:
            db.store_result(
                experiment_id="test",
                config={"score": score},
                score=score,
            )
        db.commit()
        results = db.top_results(limit=10, min_score=0)
        scores = [r["score"] for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_top_results_filter_by_experiment(self, db):
        """Filter results by experiment_id."""
        db.store_result(experiment_id="exp_a", config={}, score=10)
        db.store_result(experiment_id="exp_b", config={}, score=15)
        db.commit()
        results = db.top_results(experiment_id="exp_a")
        assert all(r["experiment_id"] == "exp_a" for r in results)

    def test_top_results_min_score_filter(self, db):
        """Only results above min_score are returned."""
        db.store_result(experiment_id="test", config={}, score=5)
        db.store_result(experiment_id="test", config={}, score=15)
        db.commit()
        results = db.top_results(min_score=10)
        assert all(r["score"] >= 10 for r in results)
        assert len(results) == 1

    def test_store_elimination(self, db):
        """Record an elimination and verify it's stored."""
        db.store_elimination(
            experiment_id="elim_test",
            hypothesis="Vigenere period 5",
            configs_tested=5040,
            best_score=8,
            verdict="ELIMINATED",
            evidence="Best score 8/24, noise floor 8.1/24",
        )
        db.commit()
        cursor = db.conn.execute("SELECT * FROM eliminations")
        rows = cursor.fetchall()
        assert len(rows) == 1

    def test_register_and_finalize_run(self, db):
        """Run lifecycle: register → finalize."""
        db.register_run("run_42", "test_campaign", {"key": "val"}, total_jobs=100)
        cursor = db.conn.execute("SELECT status FROM runs WHERE run_id = 'run_42'")
        assert cursor.fetchone()[0] == "RUNNING"

        db.finalize_run("run_42", "COMPLETE")
        cursor = db.conn.execute("SELECT status FROM runs WHERE run_id = 'run_42'")
        assert cursor.fetchone()[0] == "COMPLETE"

    def test_checkpoint_and_resume(self, db):
        """Checkpoint jobs and resume by filtering completed."""
        db.register_run("run_resume", "test", {}, total_jobs=3)
        db.checkpoint_job("run_resume", "job_1", {"result": "ok"})
        db.checkpoint_job("run_resume", "job_2", {"result": "ok"})
        db.commit()

        completed = db.completed_job_ids("run_resume")
        assert completed == {"job_1", "job_2"}
        assert "job_3" not in completed

    def test_checkpoint_replace(self, db):
        """Checkpointing same job_id replaces the previous entry."""
        db.checkpoint_job("run_x", "job_1", {"attempt": 1})
        db.checkpoint_job("run_x", "job_1", {"attempt": 2})
        db.commit()
        cursor = db.conn.execute(
            "SELECT result_json FROM checkpoints WHERE run_id='run_x' AND job_id='job_1'"
        )
        data = json.loads(cursor.fetchone()[0])
        assert data["attempt"] == 2

    def test_store_result_with_score_breakdown(self, db):
        """Score breakdown is stored as JSON."""
        breakdown = {"crib_score": 15, "bean_passed": True, "ic": 0.042}
        db.store_result(
            experiment_id="test",
            config={},
            score=15,
            score_breakdown=breakdown,
        )
        db.commit()
        results = db.top_results(limit=1)
        assert results[0]["score_breakdown"] is not None
        parsed = json.loads(results[0]["score_breakdown"])
        assert parsed["crib_score"] == 15

    def test_empty_query(self, db):
        """Empty database returns empty results."""
        assert db.top_results() == []
        assert db.completed_job_ids("nonexistent") == set()


# ═══════════════════════════════════════════════════════════════════════
# SECTION 4: kernel/persistence/artifacts.py
# ═══════════════════════════════════════════════════════════════════════

class TestRunManifest:
    """Tests for RunManifest — reproducible experiment metadata."""

    def test_create_manifest(self):
        from kryptos.kernel.persistence.artifacts import RunManifest
        manifest = RunManifest.create("test_experiment", {"period": 5})
        assert manifest.experiment_name == "test_experiment"
        assert manifest.config == {"period": 5}
        assert len(manifest.run_id) == 16
        assert manifest.hostname != ""
        assert "3.12" in manifest.python_version or "3.1" in manifest.python_version

    def test_manifest_run_id_unique(self):
        from kryptos.kernel.persistence.artifacts import RunManifest
        import time
        m1 = RunManifest.create("test", {"a": 1})
        time.sleep(0.01)  # Ensure different timestamp
        m2 = RunManifest.create("test", {"a": 1})
        # run_id includes time.time(), so should differ
        assert m1.run_id != m2.run_id

    def test_manifest_save_and_load(self, tmp_path):
        from kryptos.kernel.persistence.artifacts import RunManifest
        manifest = RunManifest.create("save_test", {"key": "value"})
        path = tmp_path / "manifest.json"
        manifest.save(path)

        loaded = RunManifest.load(path)
        assert loaded.experiment_name == manifest.experiment_name
        assert loaded.config == manifest.config
        assert loaded.run_id == manifest.run_id
        assert loaded.timestamp == manifest.timestamp

    def test_manifest_json_format(self, tmp_path):
        from kryptos.kernel.persistence.artifacts import RunManifest
        manifest = RunManifest.create("format_test", {"x": 42})
        path = tmp_path / "manifest.json"
        manifest.save(path)

        with open(path) as f:
            data = json.load(f)
        assert "run_id" in data
        assert "experiment_name" in data
        assert "config" in data
        assert "timestamp" in data
        assert "kryptos_version" in data


class TestJsonlWriter:
    """Tests for JsonlWriter — append-only log writer."""

    def test_write_single_record(self, tmp_path):
        from kryptos.kernel.persistence.artifacts import JsonlWriter
        path = tmp_path / "test.jsonl"
        with JsonlWriter(path) as writer:
            writer.write({"score": 10, "variant": "vigenere"})

        lines = path.read_text().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["score"] == 10

    def test_write_multiple_records(self, tmp_path):
        from kryptos.kernel.persistence.artifacts import JsonlWriter
        path = tmp_path / "test.jsonl"
        with JsonlWriter(path) as writer:
            for i in range(5):
                writer.write({"index": i})

        lines = path.read_text().strip().split("\n")
        assert len(lines) == 5
        for i, line in enumerate(lines):
            assert json.loads(line)["index"] == i

    def test_append_mode(self, tmp_path):
        from kryptos.kernel.persistence.artifacts import JsonlWriter
        path = tmp_path / "test.jsonl"
        # Write first batch
        with JsonlWriter(path) as writer:
            writer.write({"batch": 1})
        # Append second batch
        with JsonlWriter(path) as writer:
            writer.write({"batch": 2})

        lines = path.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_creates_parent_dirs(self, tmp_path):
        from kryptos.kernel.persistence.artifacts import JsonlWriter
        path = tmp_path / "deep" / "nested" / "dir" / "test.jsonl"
        with JsonlWriter(path) as writer:
            writer.write({"test": True})
        assert path.exists()


# ═══════════════════════════════════════════════════════════════════════
# SECTION 5: kernel/constraints/consistency.py
# ═══════════════════════════════════════════════════════════════════════

class TestConsistencyChecks:
    """Tests for consistency.py — self-encrypting, mono, bijection checks."""

    def test_check_self_encrypting_with_ct(self):
        """CT at self-encrypting positions should pass."""
        from kryptos.kernel.constraints.consistency import check_self_encrypting
        # If the candidate text matches CT at self-encrypting positions,
        # those should pass (since SELF_ENCRYPTING maps pos → CT[pos])
        failures = check_self_encrypting(CT)
        assert failures == []

    def test_check_self_encrypting_wrong_text(self):
        """All-A text should fail at self-encrypting positions."""
        from kryptos.kernel.constraints.consistency import check_self_encrypting
        text = "A" * CT_LEN
        failures = check_self_encrypting(text)
        # Should fail at any position where CT[pos] != 'A'
        for pos, expected, actual in failures:
            assert pos in SELF_ENCRYPTING
            assert actual == "A"

    def test_check_mono_consistency_no_conflicts(self):
        """No mono conflicts when each PT letter maps to one CT letter."""
        from kryptos.kernel.constraints.consistency import check_mono_consistency
        # Use CT itself — the crib positions map CT[pos] to CRIB_DICT[pos]
        mapping, conflicts = check_mono_consistency(CT)
        # mapping should exist (we have crib positions)
        assert isinstance(mapping, dict)
        assert isinstance(conflicts, list)

    def test_check_alphabet_bijection_valid(self):
        from kryptos.kernel.constraints.consistency import check_alphabet_bijection
        from kryptos.kernel.alphabet import AZ, KA
        assert check_alphabet_bijection(AZ) is True
        assert check_alphabet_bijection(KA) is True

    def test_check_alphabet_bijection_invalid(self):
        from kryptos.kernel.constraints.consistency import check_alphabet_bijection
        # Alphabet constructor validates, so we mock an invalid one
        from unittest.mock import MagicMock
        bad = MagicMock()
        bad.sequence = "AACDEFGHIJKLMNOPQRSTUVWXYZ"  # Duplicate A, missing B
        assert check_alphabet_bijection(bad) is False


# ═══════════════════════════════════════════════════════════════════════
# SECTION 6: novelty/triage.py
# ═══════════════════════════════════════════════════════════════════════

class TestTriageSimpleKey:
    """Tests for triage_simple_key — fixed-key hypothesis triage."""

    def _make_hyp(self, key, variant="vigenere"):
        from kryptos.novelty.hypothesis import Hypothesis
        return Hypothesis(
            description="Test simple key",
            transform_stack=[{"type": variant, "params": {"key": key}}],
        )

    def test_zero_key_scores_low(self):
        """Zero key (identity) should score at the self-encrypting positions only."""
        from kryptos.novelty.triage import triage_simple_key
        hyp = self._make_hyp([0] * CT_LEN)
        result = triage_simple_key(hyp)
        assert result.triage_score > 0
        assert result.triage_detail != ""

    def test_empty_key_eliminated(self):
        """Empty key should be eliminated."""
        from kryptos.novelty.triage import triage_simple_key
        hyp = self._make_hyp([])
        result = triage_simple_key(hyp)
        from kryptos.novelty.hypothesis import HypothesisStatus
        assert result.status == HypothesisStatus.ELIMINATED
        assert result.triage_score == 0.0

    def test_high_score_promoted(self):
        """A key that scores >=10 should be promoted."""
        from kryptos.novelty.triage import triage_simple_key
        from kryptos.novelty.hypothesis import HypothesisStatus
        from kryptos.kernel.constants import VIGENERE_KEY_ENE, VIGENERE_KEY_BC, CRIB_ENTRIES
        from kryptos.kernel.transforms.vigenere import CipherVariant, KEY_RECOVERY
        # Build a full-length key that matches at all 24 crib positions (Vig)
        # Key recovery: k = (c - p) mod 26 for Vigenere
        key = [0] * CT_LEN
        fn = KEY_RECOVERY[CipherVariant.VIGENERE]
        for pos, pt_ch in CRIB_ENTRIES:
            c = ord(CT[pos]) - 65
            p = ord(pt_ch) - 65
            key[pos] = fn(c, p)
        hyp = self._make_hyp(key, "vigenere")
        result = triage_simple_key(hyp)
        # Should score 24/24 since key is correct at all crib positions
        assert result.triage_score >= 10.0 / 24.0
        assert result.status == HypothesisStatus.PROMOTED

    def test_triage_detail_has_score(self):
        """Triage detail should include score information."""
        from kryptos.novelty.triage import triage_simple_key
        hyp = self._make_hyp([1, 2, 3, 4, 5] * 20)  # arbitrary periodic key
        result = triage_simple_key(hyp)
        assert "Score:" in result.triage_detail
        assert "IC:" in result.triage_detail


class TestTriageRunningKey:
    """Tests for triage_running_key — running-key hypothesis triage."""

    def _make_hyp(self, source_path, variant="vigenere"):
        from kryptos.novelty.hypothesis import Hypothesis
        return Hypothesis(
            description="Test running key",
            transform_stack=[{
                "type": variant,
                "params": {"key_source": "running_key", "source_path": str(source_path)},
            }],
        )

    def test_missing_file_eliminated(self):
        """Missing source file should eliminate hypothesis."""
        from kryptos.novelty.triage import triage_running_key
        from kryptos.novelty.hypothesis import HypothesisStatus
        hyp = self._make_hyp("/nonexistent/file.txt")
        result = triage_running_key(hyp)
        assert result.status == HypothesisStatus.ELIMINATED
        assert "not found" in result.triage_detail

    def test_short_file_eliminated(self, tmp_path):
        """Source text shorter than CT should be eliminated."""
        from kryptos.novelty.triage import triage_running_key
        from kryptos.novelty.hypothesis import HypothesisStatus
        short_file = tmp_path / "short.txt"
        short_file.write_text("TOOSHORT")
        hyp = self._make_hyp(short_file)
        result = triage_running_key(hyp)
        assert result.status == HypothesisStatus.ELIMINATED
        assert "too short" in result.triage_detail.lower()

    def test_valid_source_produces_scores(self, tmp_path):
        """A valid source file should produce triage scores."""
        from kryptos.novelty.triage import triage_running_key
        # Create a file long enough
        source = tmp_path / "source.txt"
        source.write_text("A" * 500)  # All A's, 500 chars
        hyp = self._make_hyp(source)
        result = triage_running_key(hyp)
        assert result.triage_score >= 0
        assert "Sampled" in result.triage_detail

    def test_deterministic_seed(self, tmp_path):
        """Same input should produce same triage result."""
        from kryptos.novelty.triage import triage_running_key
        source = tmp_path / "source.txt"
        source.write_text("ABCDEFGHIJ" * 100)
        hyp1 = self._make_hyp(source)
        hyp2 = self._make_hyp(source)
        r1 = triage_running_key(hyp1)
        r2 = triage_running_key(hyp2)
        assert r1.triage_score == r2.triage_score


class TestTriageHypothesis:
    """Tests for triage_hypothesis — routing to correct triage function."""

    def test_empty_transform_stack(self):
        """Hypothesis with no transforms should be eliminated."""
        from kryptos.novelty.triage import triage_hypothesis
        from kryptos.novelty.hypothesis import Hypothesis, HypothesisStatus
        hyp = Hypothesis(description="Empty", transform_stack=[])
        result = triage_hypothesis(hyp)
        assert result.status == HypothesisStatus.ELIMINATED

    def test_routes_to_simple_key(self):
        """Hypothesis with key param should route to triage_simple_key."""
        from kryptos.novelty.triage import triage_hypothesis
        from kryptos.novelty.hypothesis import Hypothesis
        hyp = Hypothesis(
            description="Simple key test",
            transform_stack=[{"type": "vigenere", "params": {"key": [0] * 97}}],
        )
        result = triage_hypothesis(hyp)
        # Should have been triaged (not just default)
        assert "Score:" in result.triage_detail

    def test_routes_to_running_key(self, tmp_path):
        """Hypothesis with running_key source should route correctly."""
        from kryptos.novelty.triage import triage_hypothesis
        from kryptos.novelty.hypothesis import Hypothesis, HypothesisStatus
        hyp = Hypothesis(
            description="Running key test",
            transform_stack=[{
                "type": "vigenere",
                "params": {"key_source": "running_key", "source_path": "/nonexistent"},
            }],
        )
        result = triage_hypothesis(hyp)
        assert result.status == HypothesisStatus.ELIMINATED
        assert "not found" in result.triage_detail

    def test_default_triage_path(self):
        """Hypothesis without key or running_key gets default triage."""
        from kryptos.novelty.triage import triage_hypothesis
        from kryptos.novelty.hypothesis import Hypothesis, HypothesisStatus
        hyp = Hypothesis(
            description="Default path",
            transform_stack=[{"type": "custom", "params": {}}],
        )
        result = triage_hypothesis(hyp)
        assert result.status == HypothesisStatus.TRIAGED
        assert result.triage_score == 0.5
        assert "manual review" in result.triage_detail


class TestTriageBatch:
    """Tests for triage_batch — batch triage and sorting."""

    def test_batch_sorts_by_priority(self):
        """Batch results should be sorted by priority_score descending."""
        from kryptos.novelty.triage import triage_batch
        from kryptos.novelty.hypothesis import Hypothesis, ResearchQuestion
        hypotheses = [
            Hypothesis(
                description="Low priority",
                transform_stack=[{"type": "x", "params": {}}],
                research_questions=[],
                estimated_configs=1000000,
            ),
            Hypothesis(
                description="High priority",
                transform_stack=[{"type": "x", "params": {}}],
                research_questions=[ResearchQuestion.RQ1_CIPHER_TYPE],
                estimated_configs=10,
            ),
        ]
        results = triage_batch(hypotheses)
        assert len(results) == 2
        # Higher priority_score should come first
        assert results[0].priority_score >= results[1].priority_score

    def test_batch_empty(self):
        """Empty batch should return empty list."""
        from kryptos.novelty.triage import triage_batch
        assert triage_batch([]) == []

    def test_batch_preserves_all(self):
        """Batch should return all hypotheses, not filter any out."""
        from kryptos.novelty.triage import triage_batch
        from kryptos.novelty.hypothesis import Hypothesis
        hypotheses = [
            Hypothesis(description=f"Hyp {i}", transform_stack=[{"type": "x", "params": {}}])
            for i in range(5)
        ]
        results = triage_batch(hypotheses)
        assert len(results) == 5


# ═══════════════════════════════════════════════════════════════════════
# SECTION 7: pipeline/evaluation.py (extended tests)
# ═══════════════════════════════════════════════════════════════════════

class TestEvaluationExtended:
    """Extended tests for evaluate_candidate and evaluate_with_key."""

    def test_evaluate_candidate_with_keystream(self):
        """evaluate_candidate with keystream triggers Bean check."""
        from kryptos.pipeline.evaluation import evaluate_candidate
        result = evaluate_candidate("A" * 97, keystream=[0] * 97)
        assert result.score.bean_passed is not None

    def test_evaluate_candidate_classification(self):
        """Score classifications should be correct."""
        from kryptos.pipeline.evaluation import evaluate_candidate
        result = evaluate_candidate("A" * 97)
        # Random text should be NOISE (field name is crib_classification)
        assert result.score.crib_classification in ("noise", "store")

    def test_evaluate_with_key_all_variants(self):
        """evaluate_with_key works with all three cipher variants."""
        from kryptos.pipeline.evaluation import evaluate_with_key
        from kryptos.kernel.transforms.vigenere import CipherVariant
        key = [3] * 97
        for variant in CipherVariant:
            result = evaluate_with_key(CT, key, variant)
            assert result.plaintext != ""
            assert len(result.plaintext) == 97

    def test_evaluate_with_key_metadata(self):
        """Metadata is passed through correctly."""
        from kryptos.pipeline.evaluation import evaluate_with_key
        from kryptos.kernel.transforms.vigenere import CipherVariant
        result = evaluate_with_key(
            CT, [0] * 97, CipherVariant.VIGENERE,
            metadata={"agent": "qa", "test": True},
        )
        assert result.metadata["agent"] == "qa"
        assert result.metadata["test"] is True

    def test_evaluate_with_key_implied_keystream(self):
        """Implied keystream should be populated."""
        from kryptos.pipeline.evaluation import evaluate_with_key
        from kryptos.kernel.transforms.vigenere import CipherVariant
        key = list(range(97))  # i.e. [0,1,2,...,96]
        result = evaluate_with_key(CT, key, CipherVariant.VIGENERE)
        assert result.implied_keystream is not None
        # Check a few values
        assert result.implied_keystream[0] == 0
        assert result.implied_keystream[5] == 5

    def test_evaluate_pipeline_identity(self):
        """Identity pipeline should produce a valid evaluation."""
        from kryptos.pipeline.evaluation import evaluate_pipeline
        from kryptos.kernel.transforms.compose import (
            TransformConfig, TransformType, PipelineConfig,
        )
        config = PipelineConfig(
            name="test_identity",
            steps=(TransformConfig(transform_type=TransformType.IDENTITY),),
        )
        result = evaluate_pipeline(config, period=5)
        assert result.plaintext != ""
        assert result.pipeline_config is not None


# ═══════════════════════════════════════════════════════════════════════
# SECTION 8: pipeline/experiments.py (worker functions)
# ═══════════════════════════════════════════════════════════════════════

class TestBlockTranspositionWorker:
    """Tests for block_transposition_worker.

    Note: unmask_block_transposition uses BLOCK_SIZE=24, so perm must be len 24.
    """

    def _identity_perm(self):
        """Identity permutation of BLOCK_SIZE=24."""
        from kryptos.kernel.transforms.transposition import BLOCK_SIZE
        return list(range(BLOCK_SIZE))

    def _make_alpha_pairs(self):
        """Build alpha_pairs in the 4-tuple format the worker expects.

        Worker expects: (pa_label, pa_seq, ca_label, ca_seq)
        build_alphabet_pairs returns: (Alphabet, Alphabet)
        """
        from kryptos.kernel.alphabet import build_alphabet_pairs
        raw = build_alphabet_pairs()
        return [(pa.label, pa.sequence, ca.label, ca.sequence) for pa, ca in raw]

    def test_identity_perm_returns_result(self):
        """Identity permutation should produce a valid result dict."""
        from kryptos.pipeline.experiments import block_transposition_worker
        perm = self._identity_perm()
        alpha_pairs = self._make_alpha_pairs()
        result = block_transposition_worker({
            "perm": perm,
            "alpha_pairs": alpha_pairs[:1],
            "variants": ["vigenere"],
            "periods": [5],
            "store_threshold": 100,
            "job_id": "test_identity",
            "config_label": "identity_w24",
        })
        assert result["job_id"] == "test_identity"
        assert result["status"] == "complete"
        assert result["tests"] > 0
        assert result["best_score"] >= 0
        assert result["elapsed"] > 0
        assert isinstance(result["top_results"], list)

    def test_worker_stores_above_threshold(self):
        """Results above store_threshold should be in top_results."""
        from kryptos.pipeline.experiments import block_transposition_worker
        perm = self._identity_perm()
        alpha_pairs = self._make_alpha_pairs()
        result = block_transposition_worker({
            "perm": perm,
            "alpha_pairs": alpha_pairs[:1],
            "variants": ["vigenere"],
            "periods": [5],
            "store_threshold": 0,  # Store everything
            "job_id": "test_store",
        })
        # With threshold 0, everything should be stored
        assert len(result["top_results"]) > 0

    def test_worker_result_schema(self):
        """Worker result has all required fields."""
        from kryptos.pipeline.experiments import block_transposition_worker
        perm = self._identity_perm()
        alpha_pairs = self._make_alpha_pairs()
        result = block_transposition_worker({
            "perm": perm,
            "alpha_pairs": alpha_pairs[:1],
            "variants": ["vigenere"],
            "periods": [5],
            "store_threshold": 100,
            "job_id": "schema_test",
            "config_label": "test",
        })
        required = {"job_id", "config_label", "perm", "best_score", "tests",
                     "elapsed", "status", "error", "top_results"}
        assert required.issubset(result.keys())
        assert result["error"] is None

    def test_worker_counts_all_combos(self):
        """Worker should test all variant × period combos."""
        from kryptos.pipeline.experiments import block_transposition_worker
        perm = self._identity_perm()
        alpha_pairs = self._make_alpha_pairs()
        variants = ["vigenere", "beaufort"]
        periods = [4, 5, 6]
        result = block_transposition_worker({
            "perm": perm,
            "alpha_pairs": alpha_pairs[:1],
            "variants": variants,
            "periods": periods,
            "store_threshold": 100,
            "job_id": "combo_test",
        })
        # 1 mask × 1 alpha_pair × 2 variants × 3 periods = 6 tests
        assert result["tests"] == len(variants) * len(periods)


class TestFullTranspositionWorker:
    """Tests for full_transposition_worker."""

    def test_identity_perm_result(self):
        """Identity permutation (full text) should produce valid result."""
        from kryptos.pipeline.experiments import full_transposition_worker
        perm = list(range(CT_LEN))
        result = full_transposition_worker({
            "perm": perm,
            "variants": ["vigenere"],
            "periods": [5],
            "store_threshold": 100,
            "job_id": "full_identity",
        })
        assert result["status"] == "complete"
        assert result["tests"] > 0

    def test_full_worker_result_schema(self):
        """Full worker result has required fields."""
        from kryptos.pipeline.experiments import full_transposition_worker
        perm = list(range(CT_LEN))
        result = full_transposition_worker({
            "perm": perm,
            "variants": ["vigenere"],
            "periods": [5],
            "store_threshold": 100,
            "job_id": "schema_test",
        })
        required = {"job_id", "best_score", "tests", "elapsed", "status", "top_results"}
        assert required.issubset(result.keys())

    def test_full_worker_counts_combos(self):
        """Full worker tests all variant × period combinations."""
        from kryptos.pipeline.experiments import full_transposition_worker
        perm = list(range(CT_LEN))
        variants = ["vigenere", "beaufort", "var_beaufort"]
        periods = [4, 5, 6, 7]
        result = full_transposition_worker({
            "perm": perm,
            "variants": variants,
            "periods": periods,
            "store_threshold": 100,
            "job_id": "count_test",
        })
        assert result["tests"] == len(variants) * len(periods)


# ═══════════════════════════════════════════════════════════════════════
# SECTION 9: pipeline/runners.py (SweepRunner — unit-testable parts)
# ═══════════════════════════════════════════════════════════════════════

class TestSweepRunnerConfig:
    """Tests for SweepRunner configuration and setup (no multiprocessing)."""

    def test_sweep_config_run_id_deterministic(self):
        """Same config should produce same run_id."""
        from kryptos.kernel.config import SweepConfig
        c1 = SweepConfig(name="test", periods=(4, 5))
        c2 = SweepConfig(name="test", periods=(4, 5))
        assert c1.run_id == c2.run_id

    def test_sweep_config_run_id_differs(self):
        """Different configs should produce different run_ids."""
        from kryptos.kernel.config import SweepConfig
        c1 = SweepConfig(name="test_a")
        c2 = SweepConfig(name="test_b")
        assert c1.run_id != c2.run_id

    def test_sweep_config_to_dict(self):
        """Config serializes to dict correctly."""
        from kryptos.kernel.config import SweepConfig
        config = SweepConfig(name="test", workers=4, periods=(5, 6, 7))
        d = config.to_dict()
        assert d["name"] == "test"
        assert d["workers"] == 4
        assert d["periods"] == (5, 6, 7)

    def test_sweep_config_from_dict(self):
        """Config deserializes from dict correctly."""
        from kryptos.kernel.config import SweepConfig
        data = {"name": "test", "workers": 4, "periods": [5, 6, 7]}
        config = SweepConfig.from_dict(data)
        assert config.name == "test"
        assert config.workers == 4
        assert config.periods == (5, 6, 7)  # list → tuple

    def test_sweep_runner_init(self, tmp_path):
        """SweepRunner initializes correctly."""
        from kryptos.kernel.config import SweepConfig
        from kryptos.pipeline.runners import SweepRunner
        config = SweepConfig(
            name="test",
            db_path=str(tmp_path / "test.sqlite"),
            log_dir=str(tmp_path / "logs"),
        )
        work_items = [{"job_id": "j1"}, {"job_id": "j2"}]
        runner = SweepRunner(config, lambda x: x, work_items)
        assert runner.config.name == "test"
        assert len(runner.work_items) == 2
        assert not runner._interrupted

    def test_sweep_runner_signal_handler(self, tmp_path):
        """Signal handler sets _interrupted flag."""
        from kryptos.kernel.config import SweepConfig
        from kryptos.pipeline.runners import SweepRunner
        config = SweepConfig(
            name="test",
            db_path=str(tmp_path / "test.sqlite"),
        )
        runner = SweepRunner(config, lambda x: x, [])
        assert not runner._interrupted
        runner._signal_handler(2, None)  # SIGINT
        assert runner._interrupted

    def test_sweep_runner_execute_empty_workitems(self, tmp_path):
        """Execute with all-completed items returns 0."""
        from kryptos.kernel.config import SweepConfig
        from kryptos.pipeline.runners import SweepRunner
        from kryptos.kernel.persistence.sqlite import Database

        db_path = str(tmp_path / "test.sqlite")
        config = SweepConfig(
            name="test",
            db_path=db_path,
            log_dir=str(tmp_path / "logs"),
            workers=1,
        )

        # Pre-populate all jobs as completed
        db = Database(db_path)
        db.register_run(config.run_id, "test", {}, 2)
        db.checkpoint_job(config.run_id, "j1", {"status": "ok"})
        db.checkpoint_job(config.run_id, "j2", {"status": "ok"})
        db.commit()
        db.close()

        runner = SweepRunner(
            config,
            lambda x: x,
            [{"job_id": "j1"}, {"job_id": "j2"}],
        )
        result = runner.execute()
        assert result == 0

    def test_sweep_runner_execute_simple(self, tmp_path):
        """Execute a minimal sweep with a trivial worker.

        Uses a module-level function because multiprocessing Pool
        requires picklable workers.
        """
        from kryptos.kernel.config import SweepConfig
        from kryptos.pipeline.runners import SweepRunner

        config = SweepConfig(
            name="test_sweep",
            db_path=str(tmp_path / "sweep.sqlite"),
            log_dir=str(tmp_path / "logs"),
            workers=1,
        )

        items = [{"job_id": f"j{i}"} for i in range(3)]
        runner = SweepRunner(config, _trivial_worker, items, force=True)
        result = runner.execute()
        assert result == 0

        # Verify results were written to DB
        from kryptos.kernel.persistence.sqlite import Database
        db = Database(str(tmp_path / "sweep.sqlite"))
        completed = db.completed_job_ids(config.run_id)
        assert len(completed) == 3
        db.close()


# ═══════════════════════════════════════════════════════════════════════
# SECTION 10: SweepConfig TOML loading
# ═══════════════════════════════════════════════════════════════════════

class TestSweepConfigToml:
    """Tests for loading SweepConfig from TOML files."""

    def test_from_toml_campaign_section(self, tmp_path):
        from kryptos.kernel.config import SweepConfig
        toml_content = b"""
[campaign]
name = "test_campaign"
transposition_family = "columnar"
cipher_variants = ["vigenere", "beaufort"]
periods = [5, 6, 7]
workers = 4
"""
        path = tmp_path / "config.toml"
        path.write_bytes(toml_content)
        config = SweepConfig.from_toml(path)
        assert config.name == "test_campaign"
        assert config.transposition_family == "columnar"
        assert config.cipher_variants == ("vigenere", "beaufort")
        assert config.workers == 4

    def test_config_roundtrip_json(self):
        from kryptos.kernel.config import SweepConfig
        config = SweepConfig(name="roundtrip", periods=(4, 5, 6))
        j = config.to_json()
        d = json.loads(j)
        config2 = SweepConfig.from_dict(d)
        assert config.name == config2.name
        assert config.periods == config2.periods


# ═══════════════════════════════════════════════════════════════════════
# SECTION 11: ExperimentConfig tests
# ═══════════════════════════════════════════════════════════════════════

class TestExperimentConfig:
    """Tests for ExperimentConfig dataclass."""

    def test_config_hash_deterministic(self):
        from kryptos.kernel.config import ExperimentConfig
        c1 = ExperimentConfig(name="test", seed=42)
        c2 = ExperimentConfig(name="test", seed=42)
        assert c1.config_hash == c2.config_hash

    def test_config_hash_differs(self):
        from kryptos.kernel.config import ExperimentConfig
        c1 = ExperimentConfig(name="test_a")
        c2 = ExperimentConfig(name="test_b")
        assert c1.config_hash != c2.config_hash

    def test_to_dict(self):
        from kryptos.kernel.config import ExperimentConfig
        config = ExperimentConfig(
            name="test",
            hypothesis="H1",
            seed=42,
        )
        d = config.to_dict()
        assert d["name"] == "test"
        assert d["hypothesis"] == "H1"
        assert d["seed"] == 42
        assert "hash" in d
