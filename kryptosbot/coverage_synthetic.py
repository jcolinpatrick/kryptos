"""Synthetic-CT generator for coverage recovery (PR 3).

Generates a synthetic ciphertext from a profile's closing_spec by reusing
the dispatcher's spec->pipeline translation in ENCRYPT direction, applied
to a fixed canonical plaintext. Because the SAME translation produces the
decrypt pipeline that execute() runs, encrypt and decrypt are true
inverses: dispatching the closing_spec against the generated CT recovers
the canonical plaintext, so crib_score reaches 24 (>= SIGNAL).

The real K4 ciphertext is never used: the CT is produced from
CANONICAL_PLAINTEXT via the mechanism. Crib positions reuse the kernel's
canonical CRIB_POSITIONS (integer indices only - not the real CT).
"""

from __future__ import annotations

from typing import Any

# A fixed 97-letter A-Z plaintext. The exact text is irrelevant; the
# invariant (97 uppercase letters) is enforced by tests. The mechanism,
# not the plaintext, is what varies per profile.
CANONICAL_PLAINTEXT = (
    "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    "THEQUICKBROWNFOXJUMPSOVERTH"
)  # 35 + 35 + 27 = 97


def generate_synthetic_challenge(
    closing_spec: dict[str, Any],
) -> tuple[str, dict[int, str]]:
    """Return (synthetic_ct, crib_dict) for a single-layer closing_spec.

    Reuses the dispatcher translation in encrypt direction. Raises
    ValueError for multi-layer specs (out of scope; recovery targets are
    single-layer).
    """
    from kryptos.kernel.constants import CRIB_POSITIONS
    from kryptos.kernel.transforms.compose import (
        PipelineConfig,
        TransformConfig,
        TransformType,
        build_pipeline,
    )
    from kryptosbot import job_dispatcher
    from kryptosbot.hypothesis_dsl import HypothesisSpec

    spec = HypothesisSpec.from_dict(closing_spec)
    spec = job_dispatcher._expand_procedural_layers(spec)
    if len(spec.pipeline) != 1:
        raise ValueError(
            f"generate_synthetic_challenge supports single-layer specs only; "
            f"got {len(spec.pipeline)} layers (multi-layer encrypt-order is "
            f"out of scope for PR3)"
        )

    bindings_list = list(job_dispatcher._enumerate_bindings(spec))
    if len(bindings_list) != 1:
        raise ValueError(
            f"closing_spec must pin a single config; got "
            f"{len(bindings_list)} bindings"
        )
    pipeline_dict = job_dispatcher._build_pipeline_config(
        spec, bindings_list[0], text_length=len(CANONICAL_PLAINTEXT),
    )

    # build_pipeline ignores PipelineConfig.direction; the encrypt branch
    # is selected per-step via params["direction"]="encrypt" (non-"undo"
    # for transposition, non-"decrypt" for vigenere/quagmire/bifid).
    # NOTE: this TransformConfig/PipelineConfig reconstruction mirrors the
    # dispatcher's per-config worker (job_dispatcher._evaluate_one); keep the
    # two in sync if the step-dict shape changes. The round-trip test guards drift.
    steps = []
    for s in pipeline_dict["steps"]:
        params = dict(s.get("params", {}))
        params["direction"] = "encrypt"
        steps.append(
            TransformConfig(
                transform_type=TransformType(s["type"]),
                params=params,
                description=s.get("description", ""),
            )
        )
    pipeline = PipelineConfig(
        name=pipeline_dict["name"] + "__encrypt",
        steps=tuple(steps),
        direction="encrypt",
    )
    fn = build_pipeline(pipeline)
    ct = fn(CANONICAL_PLAINTEXT)
    if len(ct) != len(CANONICAL_PLAINTEXT):
        raise ValueError(
            f"synthetic CT length {len(ct)} != PT length "
            f"{len(CANONICAL_PLAINTEXT)}"
        )

    crib_dict = {pos: CANONICAL_PLAINTEXT[pos] for pos in CRIB_POSITIONS}
    return (ct, crib_dict)


__all__ = ["CANONICAL_PLAINTEXT", "generate_synthetic_challenge"]
