"""Tests for the evaluation pipeline — smoke tests."""
import pytest

from kryptos.kernel.constants import CT
from kryptos.kernel.transforms.vigenere import CipherVariant
from kryptos.pipeline.evaluation import (
    evaluate_candidate, evaluate_with_key, EvaluationResult,
)


class TestEvaluation:
    def test_evaluate_candidate_basic(self):
        result = evaluate_candidate("A" * 97)
        assert isinstance(result, EvaluationResult)
        assert not result.is_breakthrough

    def test_evaluate_with_key(self):
        key = [0] * 97  # Identity key
        result = evaluate_with_key(CT, key, CipherVariant.VIGENERE)
        assert isinstance(result, EvaluationResult)
        # Identity key means PT == CT, so crib score should match
        # self-encrypting positions (32: S, 73: K)
        assert result.score.crib_score >= 2

    def test_evaluate_preserves_metadata(self):
        result = evaluate_candidate(
            "A" * 97,
            metadata={"test": True},
        )
        assert result.metadata.get("test") is True


class TestCompose:
    def test_identity_pipeline(self):
        from kryptos.kernel.transforms.compose import (
            TransformConfig, TransformType, PipelineConfig, build_pipeline,
        )
        config = PipelineConfig(
            name="test_identity",
            steps=(
                TransformConfig(transform_type=TransformType.IDENTITY),
            ),
        )
        fn = build_pipeline(config)
        assert fn(CT) == CT

    def test_pipeline_hash_deterministic(self):
        from kryptos.kernel.transforms.compose import (
            TransformConfig, TransformType, PipelineConfig,
        )
        config1 = PipelineConfig(
            name="test",
            steps=(TransformConfig(transform_type=TransformType.IDENTITY),),
        )
        config2 = PipelineConfig(
            name="test",
            steps=(TransformConfig(transform_type=TransformType.IDENTITY),),
        )
        assert config1.pipeline_hash == config2.pipeline_hash
