"""Tests for stateful / architecture-specific transforms.

Covers:
- Band offset encrypt/decrypt roundtrip
- Polarity switching roundtrip
- Progressive key stream generation and roundtrip
- State alphabet roundtrip
- Band polarity roundtrip
- Compass offset roundtrip
- Composition framework integration (registry, serialization, campaign)
"""
import pytest

from kryptos.kernel.constants import CT, CT_LEN, ALPH_IDX
from kryptos.kernel.transforms.stateful import (
    band_offset_encrypt, band_offset_decrypt,
    polarity_switch_encrypt, polarity_switch_decrypt,
    progressive_key_stream, progressive_key_encrypt, progressive_key_decrypt,
    state_alphabet_encrypt, state_alphabet_decrypt,
    band_polarity_encrypt, band_polarity_decrypt,
    compass_offset_encrypt, compass_offset_decrypt,
    position_to_band_97,
    ALL_BANDS, BAND_SIZES,
)
from kryptos.composition.models import LayerFamily, CompositionStack, PeelOrder
from kryptos.composition.registry import (
    build_transforms, generate_params, make_instance, registered_families,
)


# ══════════════════════════════════════════════════════════════════════════
# Band structure
# ══════════════════════════════════════════════════════════════════════════

class TestBandStructure:
    def test_band_sizes(self):
        assert BAND_SIZES == (1, 4, 4, 11, 4)
        assert sum(BAND_SIZES) == 24

    def test_position_to_band(self):
        assert position_to_band_97(0) == 0   # Band A
        assert position_to_band_97(1) == 1   # Band B
        assert position_to_band_97(4) == 1
        assert position_to_band_97(5) == 2   # Band C
        assert position_to_band_97(9) == 3   # Band D
        assert position_to_band_97(19) == 3
        assert position_to_band_97(20) == 4  # Band E
        assert position_to_band_97(23) == 4
        # Second block
        assert position_to_band_97(24) == 0
        assert position_to_band_97(25) == 1


# ══════════════════════════════════════════════════════════════════════════
# Transform roundtrips
# ══════════════════════════════════════════════════════════════════════════

class TestBandOffset:
    def test_roundtrip_nontrivial(self):
        offsets = [0, 3, 7, 13, 19]
        enc = band_offset_encrypt(CT, offsets)
        dec = band_offset_decrypt(enc, offsets)
        assert dec == CT
        assert enc != CT

    def test_zero_offsets_identity(self):
        offsets = [0, 0, 0, 0, 0]
        assert band_offset_encrypt(CT, offsets) == CT

    def test_roundtrip_various(self):
        for offsets in [[1, 0, 0, 0, 0], [0, 25, 13, 7, 1], [5, 5, 5, 5, 5]]:
            enc = band_offset_encrypt(CT, offsets)
            assert band_offset_decrypt(enc, offsets) == CT


class TestPolaritySwitch:
    def test_roundtrip(self):
        key = [ALPH_IDX[c] for c in "KRYPTOS"]
        schedule = [0, 1, 0, 0, 1, 1, 0]  # Vig/Beau mix
        enc = polarity_switch_encrypt(CT, key, schedule)
        dec = polarity_switch_decrypt(enc, key, schedule)
        assert dec == CT

    def test_all_vig_matches_standard(self):
        key = [ALPH_IDX[c] for c in "TEST"]
        schedule = [0, 0, 0, 0]  # All Vigenere
        from kryptos.kernel.transforms.vigenere import encrypt_text, CipherVariant
        expected = encrypt_text(CT, key, CipherVariant.VIGENERE)
        got = polarity_switch_encrypt(CT, key, schedule)
        assert got == expected

    def test_all_beau_matches_standard(self):
        key = [ALPH_IDX[c] for c in "TEST"]
        schedule = [1, 1, 1, 1]  # All Beaufort
        from kryptos.kernel.transforms.vigenere import encrypt_text, CipherVariant
        expected = encrypt_text(CT, key, CipherVariant.BEAUFORT)
        got = polarity_switch_encrypt(CT, key, schedule)
        assert got == expected


class TestProgressiveKey:
    def test_stream_fibonacci(self):
        stream = progressive_key_stream([1, 1], 8)
        assert stream == [1, 1, 2, 3, 5, 8, 13, 21]

    def test_stream_mod26(self):
        stream = progressive_key_stream([20, 20], 5)
        # 20, 20, 14(=40%26), 8(=34%26), 22(=22%26)
        assert stream == [20, 20, 14, 8, 22]

    def test_roundtrip(self):
        seed = [ALPH_IDX[c] for c in "KRYPTOS"]
        enc = progressive_key_encrypt(CT, seed)
        dec = progressive_key_decrypt(enc, seed)
        assert dec == CT
        assert enc != CT


class TestStateAlphabet:
    def test_roundtrip(self):
        key = [ALPH_IDX[c] for c in "KRYPTOS"]
        offsets = [0, 7, 13]
        schedule = [0, 1, 2]
        enc = state_alphabet_encrypt(CT, key, offsets, schedule)
        dec = state_alphabet_decrypt(enc, key, offsets, schedule)
        assert dec == CT

    def test_zero_state_matches_plain_vig(self):
        key = [ALPH_IDX[c] for c in "TEST"]
        offsets = [0]
        schedule = [0]
        from kryptos.kernel.transforms.vigenere import encrypt_text, CipherVariant
        expected = encrypt_text(CT, key, CipherVariant.VIGENERE)
        got = state_alphabet_encrypt(CT, key, offsets, schedule)
        assert got == expected


class TestBandPolarity:
    def test_roundtrip(self):
        key = [ALPH_IDX[c] for c in "KRYPTOS"]
        band_variants = [0, 1, 0, 1, 2]
        enc = band_polarity_encrypt(CT, key, band_variants)
        dec = band_polarity_decrypt(enc, key, band_variants)
        assert dec == CT


class TestCompassOffset:
    def test_roundtrip(self):
        bo = [0, 3, 7, 11, 13, 17, 19, 23]
        enc = compass_offset_encrypt(CT, "KRYPTOS", bo)
        dec = compass_offset_decrypt(enc, "KRYPTOS", bo)
        assert dec == CT

    def test_zero_offsets_identity(self):
        bo = [0] * 8
        assert compass_offset_encrypt(CT, "KRYPTOS", bo) == CT


# ══════════════════════════════════════════════════════════════════════════
# Registry integration
# ══════════════════════════════════════════════════════════════════════════

class TestStatefulRegistry:
    def test_families_registered(self):
        families = registered_families()
        assert LayerFamily.BAND_OFFSET in families
        assert LayerFamily.POLARITY_SWITCH in families
        assert LayerFamily.PROGRESSIVE_KEY in families
        assert LayerFamily.STATE_ALPHABET in families
        assert LayerFamily.BAND_POLARITY in families
        assert LayerFamily.COMPASS_OFFSET in families

    def test_band_offset_roundtrip_via_registry(self):
        inst = make_instance(LayerFamily.BAND_OFFSET, {"band_offsets": [0, 3, 7, 13, 19]})
        fwd, inv = build_transforms(inst)
        assert inv(fwd(CT)) == CT

    def test_progressive_key_roundtrip_via_registry(self):
        inst = make_instance(LayerFamily.PROGRESSIVE_KEY, {"keyword": "KRYPTOS"})
        fwd, inv = build_transforms(inst)
        assert inv(fwd(CT)) == CT

    def test_polarity_switch_roundtrip_via_registry(self):
        inst = make_instance(LayerFamily.POLARITY_SWITCH,
                             {"keyword": "TEST", "schedule": [0, 1]})
        fwd, inv = build_transforms(inst)
        assert inv(fwd(CT)) == CT

    def test_state_alphabet_roundtrip_via_registry(self):
        inst = make_instance(LayerFamily.STATE_ALPHABET,
                             {"keyword": "KRYPTOS", "state_offsets": [0, 7],
                              "state_schedule": [0, 1]})
        fwd, inv = build_transforms(inst)
        assert inv(fwd(CT)) == CT

    def test_band_polarity_roundtrip_via_registry(self):
        inst = make_instance(LayerFamily.BAND_POLARITY,
                             {"keyword": "KRYPTOS", "band_variants": [0, 1, 0, 1, 2]})
        fwd, inv = build_transforms(inst)
        assert inv(fwd(CT)) == CT

    def test_compass_offset_roundtrip_via_registry(self):
        inst = make_instance(LayerFamily.COMPASS_OFFSET,
                             {"keyword": "KRYPTOS", "bearing_offsets": [0, 3, 7, 11, 13, 17, 19, 23]})
        fwd, inv = build_transforms(inst)
        assert inv(fwd(CT)) == CT

    def test_param_gen_progressive_key(self):
        params = generate_params(LayerFamily.PROGRESSIVE_KEY, keywords=["A", "B"])
        assert len(params) == 2

    def test_param_gen_polarity_switch(self):
        params = generate_params(LayerFamily.POLARITY_SWITCH,
                                 keywords=["A"], schedules=[[0, 1], [1, 0]])
        assert len(params) == 2

    def test_serialization_roundtrip(self):
        inst = make_instance(LayerFamily.PROGRESSIVE_KEY, {"keyword": "KRYPTOS"})
        d = inst.to_dict()
        from kryptos.composition.models import LayerInstance
        restored = LayerInstance.from_dict(d)
        assert restored.family == inst.family
        assert restored.params == inst.params
