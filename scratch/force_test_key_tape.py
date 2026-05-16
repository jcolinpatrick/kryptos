"""Force-test the key_tape DSL→dispatcher→kernel→scoring pipeline on real K4.

Bypasses theorist generation, critic, and red-team. Constructs a clean
key_tape spec with deliberately non-retired-hypothesis derivation, runs
it through:

    1. validate_layer_for_kind  (DSL validation)
    2. _translate_layer         (dispatcher translation)
    3. build_pipeline           (compose integration)
    4. apply_key_tape           (kernel transform)
    5. score_candidate          (anchored crib + Bean + ngram scoring)

…and reports the outcome for each (variant × alphabet) combination.

Goal: prove the integration works end-to-end on real K4 with a clean
hypothesis. The expected outcome is noise — the *capability test*
succeeds if every combination produces a valid score breakdown without
exception.

Tape derivation (deliberate, no retired-hypothesis lineage):

    Tape values are taken from the K1 plaintext repeated to 97 chars.
    K1 plaintext is a [PUBLIC FACT] from 1998-1999 community solve;
    not derived from CONSENSUS_NULL_POSITIONS, the retired palette
    family, or any quarantined hypothesis. Length L = 97 = CT length,
    no nulls — matches the "PT length is open" doctrine without
    asserting any null model.

Run: PYTHONPATH=src python3 scratch/force_test_key_tape.py
"""
import sys

from kryptos.kernel.alphabet import AZ, KA
from kryptos.kernel.constants import CT
from kryptos.kernel.scoring.aggregate import score_candidate
from kryptos.kernel.transforms.compose import (
    PipelineConfig,
    TransformConfig,
    TransformType,
    build_pipeline,
)
from kryptos.kernel.transforms.key_tape import apply_key_tape
from kryptos.kernel.transforms.vigenere import CipherVariant
from kryptosbot.hypothesis_dsl import validate_layer_for_kind
from kryptosbot.job_dispatcher import _kind_has_translation, _translate_layer

# K1 plaintext (1998-1999 community solve, PUBLIC FACT).
# "BETWEEN SUBTLE SHADING AND THE ABSENCE OF LIGHT LIES THE NUANCE OF IQLUSION"
K1_PLAINTEXT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"
assert len(K1_PLAINTEXT) == 63, f"K1 PT length unexpected: {len(K1_PLAINTEXT)}"

# Tile to 97 chars, convert to int tape.
TAPE_SOURCE = (K1_PLAINTEXT * 2)[:97]  # 97 chars, K1 PT repeated
assert len(TAPE_SOURCE) == 97
TAPE = tuple(ord(c) - ord("A") for c in TAPE_SOURCE)

# Sanity check tape values
assert all(0 <= v <= 25 for v in TAPE), "tape values out of range"


def banner(title: str) -> None:
    print()
    print("=" * 72)
    print(f"  {title}")
    print("=" * 72)


def report_layer_5(variant_str: str, alphabet_str: str) -> None:
    """Run all 5 layers for one (variant × alphabet) combination."""
    print(f"\n--- variant={variant_str:14s}  alphabet={alphabet_str} ---")

    layer_params = {
        "tape": TAPE,
        "variant": variant_str,
        "direction": "decrypt",
        "null_positions": (),
        "null_rule": "skip",
        "alphabet": alphabet_str,
    }

    # Layer 1: DSL validation
    errors = validate_layer_for_kind("key_tape", layer_params)
    if errors:
        print(f"  [DSL]      FAIL: {errors}")
        return
    print(f"  [DSL]      pass — 9 validation rules cleared")

    # Layer 2: dispatcher translation
    if not _kind_has_translation("key_tape"):
        print("  [DISPATCH] FAIL: _kind_has_translation('key_tape') is False")
        return

    class _Layer:
        kind = "key_tape"
        params = []

    cfg_dict = _translate_layer(_Layer(), binding=layer_params, text_length=97)
    if cfg_dict.get("type") != "key_tape":
        print(f"  [DISPATCH] FAIL: type mismatch {cfg_dict!r}")
        return
    print(f"  [DISPATCH] pass — emits TransformConfig dict, type=key_tape")

    # Layer 3: compose integration
    cfg = TransformConfig(
        transform_type=TransformType.KEY_TAPE,
        params=cfg_dict["params"],
    )
    pipeline = build_pipeline(PipelineConfig(name="key_tape_force_test", steps=(cfg,)))
    print(f"  [COMPOSE]  pass — pipeline built")

    # Layer 4: kernel transform via the pipeline
    pt_via_pipeline = pipeline(CT)
    if len(pt_via_pipeline) != 97:
        print(f"  [KERNEL]   FAIL: pipeline produced {len(pt_via_pipeline)} chars, expected 97")
        return

    # Cross-check: direct apply_key_tape call should match
    variant_enum = CipherVariant(variant_str)
    alphabet = AZ if alphabet_str == "AZ" else KA
    pt_direct = apply_key_tape(
        CT,
        tape=TAPE,
        variant=variant_enum,
        direction="decrypt",
        null_positions=frozenset(),
        null_rule="skip",
        alphabet=alphabet,
    )
    if pt_via_pipeline != pt_direct:
        print(f"  [KERNEL]   FAIL: pipeline output != direct apply_key_tape output")
        print(f"             pipeline: {pt_via_pipeline}")
        print(f"             direct:   {pt_direct}")
        return
    print(f"  [KERNEL]   pass — pipeline matches direct apply_key_tape (97 chars)")

    # Layer 5: scoring
    try:
        breakdown = score_candidate(pt_via_pipeline)
    except Exception as e:
        print(f"  [SCORING]  FAIL: {e!r}")
        return

    # Pull the canonical fields
    crib_score = breakdown.crib_score
    bean_passed = breakdown.bean_passed
    ic_value = getattr(breakdown, "ic_value", None)
    ngram = getattr(breakdown, "ngram_score", None)
    classification = getattr(breakdown, "crib_classification", "unknown")

    print(
        f"  [SCORING]  pass — crib={crib_score}/24  bean={bean_passed}  "
        f"ic={ic_value:.4f}" if ic_value is not None else f"  [SCORING]  pass — crib={crib_score}/24"
    )

    # PT preview at crib regions
    print(f"             pt[21:34] = {pt_via_pipeline[21:34]}  (crib expects EASTNORTHEAST)")
    print(f"             pt[63:74] = {pt_via_pipeline[63:74]}  (crib expects BERLINCLOCK)")
    print(f"             classification: {classification}")

    if crib_score >= 18:
        print(f"             ⚡⚡⚡ SIGNAL HIT: crib_score >= 18 ⚡⚡⚡")
    elif crib_score >= 10:
        print(f"             interesting (≥10) — worth logging")


def main() -> int:
    banner("KEY_TAPE FORCE-TEST: full DSL→dispatcher→kernel→scoring pipeline")
    print(f"  CT (97 chars):      {CT}")
    print(f"  Tape source:        K1 plaintext tiled to 97 chars (PUBLIC FACT)")
    print(f"  Tape preview:       {TAPE[:10]} ...")
    print(f"  Length L:           97 (no nulls; null hypothesis baseline)")
    print(f"  Derivation:         K1 PT, no CONSENSUS_NULL_POSITIONS lineage")
    print(f"  Direction:          decrypt (CT→PT)")

    banner("Per-combination layer-by-layer")
    for variant_str in ["vigenere", "beaufort", "var_beaufort"]:
        for alphabet_str in ["AZ", "KA"]:
            report_layer_5(variant_str, alphabet_str)

    banner("Summary")
    print("If every combination above shows pass on all 5 layers (DSL,")
    print("DISPATCH, COMPOSE, KERNEL, SCORING), the new key_tape integration")
    print("is end-to-end working on real K4. Score outcomes are expected to")
    print("be noise — the test is for plumbing, not for solve.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
