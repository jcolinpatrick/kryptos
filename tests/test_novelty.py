"""Tests for the novelty engine."""
import pytest
import tempfile
import os

from kryptos.novelty.hypothesis import (
    Hypothesis, HypothesisStatus, ResearchQuestion, RQ_WEIGHTS,
)
from kryptos.novelty.ledger import NoveltyLedger
from kryptos.novelty.generators import date_derived_keys, pre_ene_segment_hypotheses


class TestHypothesis:
    def test_hypothesis_id_deterministic(self):
        h1 = Hypothesis(description="test", transform_stack=[{"type": "vig"}])
        h2 = Hypothesis(description="test", transform_stack=[{"type": "vig"}])
        assert h1.hypothesis_id == h2.hypothesis_id

    def test_hypothesis_id_differs(self):
        h1 = Hypothesis(description="test1")
        h2 = Hypothesis(description="test2")
        assert h1.hypothesis_id != h2.hypothesis_id

    def test_priority_score(self):
        h = Hypothesis(
            description="test",
            research_questions=[ResearchQuestion.RQ1_CIPHER_TYPE],
            triage_score=0.5,
            estimated_configs=100,
        )
        assert h.priority_score > 0

    def test_high_rq_weight_higher_priority(self):
        h_high = Hypothesis(
            description="high",
            research_questions=[ResearchQuestion.RQ1_CIPHER_TYPE],  # weight 10
            triage_score=0.5,
            estimated_configs=100,
        )
        h_low = Hypothesis(
            description="low",
            research_questions=[ResearchQuestion.RQ9_K5],  # weight 1
            triage_score=0.5,
            estimated_configs=100,
        )
        assert h_high.priority_score > h_low.priority_score

    def test_to_dict_roundtrip(self):
        h = Hypothesis(
            description="test",
            research_questions=[ResearchQuestion.RQ1_CIPHER_TYPE],
            status=HypothesisStatus.PROPOSED,
        )
        d = h.to_dict()
        h2 = Hypothesis.from_dict(d)
        assert h2.description == h.description


class TestLedger:
    def test_record_and_retrieve(self):
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name

        try:
            with NoveltyLedger(path) as ledger:
                h = Hypothesis(description="test hypothesis")
                ledger.record(h)
                ledger.conn.commit()
                assert not ledger.already_tested(h.hypothesis_id)  # Still proposed

                h.status = HypothesisStatus.ELIMINATED
                ledger.record(h)
                ledger.conn.commit()
                assert ledger.already_tested(h.hypothesis_id)
        finally:
            os.unlink(path)

    def test_summary(self):
        with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
            path = f.name

        try:
            with NoveltyLedger(path) as ledger:
                for i in range(5):
                    h = Hypothesis(description=f"test {i}")
                    h.status = HypothesisStatus.PROPOSED if i < 3 else HypothesisStatus.ELIMINATED
                    ledger.record(h)
                ledger.conn.commit()

                summary = ledger.summary()
                assert summary.get("proposed", 0) == 3
                assert summary.get("eliminated", 0) == 2
        finally:
            os.unlink(path)


class TestGenerators:
    def test_date_keys_generate(self):
        hyps = list(date_derived_keys())
        assert len(hyps) > 0
        for h in hyps:
            assert h.description
            assert len(h.research_questions) > 0

    def test_pre_ene_generate(self):
        hyps = list(pre_ene_segment_hypotheses())
        assert len(hyps) > 0
        for h in hyps:
            assert ResearchQuestion.RQ7_PRE_ENE in h.research_questions
