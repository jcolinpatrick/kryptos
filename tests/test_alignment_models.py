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
