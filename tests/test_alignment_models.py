from kryptos.alignment_models import (
    ALIGNMENT_MODELS, ALIGNMENT_MODEL_KEYS,
    DIRECT_CARVING_MODELS, NON_DIRECT_MODELS,
)


def test_six_models_exact_keys():
    assert [k for k, _ in ALIGNMENT_MODELS] == [
        "direct_ct_pt", "fixed_len_97", "ct73_null_extracted",
        "arbitrary_null_mask", "non_direct_alignment", "joint_mask_mechanism",
    ]


def test_every_model_has_a_description():
    assert all(isinstance(d, str) and d for _, d in ALIGNMENT_MODELS)


def test_direct_and_non_direct_partition_the_keys():
    assert DIRECT_CARVING_MODELS == {"direct_ct_pt", "fixed_len_97"}
    assert NON_DIRECT_MODELS == ALIGNMENT_MODEL_KEYS - DIRECT_CARVING_MODELS
    assert DIRECT_CARVING_MODELS | NON_DIRECT_MODELS == ALIGNMENT_MODEL_KEYS
    assert DIRECT_CARVING_MODELS & NON_DIRECT_MODELS == set()


def test_session_briefing_uses_canonical_taxonomy():
    import importlib.util
    import sys
    from pathlib import Path
    from kryptos.alignment_models import ALIGNMENT_MODELS
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "session_briefing", root / "scripts" / "_infra" / "session_briefing.py")
    mod = importlib.util.module_from_spec(spec)
    # Register in sys.modules before exec so @dataclass with string annotations
    # (from __future__ import annotations) can resolve the module namespace.
    sys.modules.setdefault("session_briefing", mod)
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.modules.pop("session_briefing", None)
    assert mod.ALIGNMENT_MODELS is ALIGNMENT_MODELS
