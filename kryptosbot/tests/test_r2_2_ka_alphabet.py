"""R2-2 verification: KA and keyword_mixed alphabet support in the
dispatcher for vigenere / beaufort / variant_beaufort layers.

The Phase 4 dispatcher was AZ-only on substitution layers. R2-2 extends
_resolve_alphabet_sequence + _translate_layer + _keyword_to_key_ints
to support KA (the Kryptos tableau) and keyword_mixed (arbitrary
theorist-supplied keyword). The kernel's decrypt_text / encrypt_text
gained an optional `alphabet` parameter; the compose.py VIGENERE path
propagates through `alphabet_sequence` and `alphabet_label` params.

The highest-value integration test below is
``test_k1_reduces_to_vigenere_on_KA``: it verifies the published
Quagmire III decomposition of Kryptos K1 (keyword PALIMPSEST, indicator
K, PA=CA=KRYPTOS) reduces to a plain Vigenère-on-KA layer the DSL
dispatcher can now express. This unblocks R2-5's real-API K1 test.
"""
from __future__ import annotations

import pytest

from kryptos.kernel.alphabet import KA, keyword_mixed_alphabet
from kryptos.kernel.transforms.compose import (
    PipelineConfig, TransformConfig, TransformType, build_pipeline,
)
from kryptos.kernel.transforms.vigenere import (
    CipherVariant, decrypt_text, encrypt_text,
)
from kryptosbot.hypothesis_dsl import CipherLayer, HypothesisSpec, ParamRange
from kryptosbot.job_dispatcher import (
    DispatcherError,
    _build_pipeline_config,
    _keyword_to_key_ints,
    _resolve_alphabet_sequence,
    _translate_layer,
)


# ─── Kernel alphabet support (the low-level extension) ───────────────────────

class TestKernelDecryptTextAcceptsAlphabet:
    """decrypt_text gained an optional alphabet param in R2-2. These
    tests lock the contract: AZ-default behavior unchanged; KA produces
    KA-indexed output; encrypt/decrypt round-trip."""

    def test_az_default_unchanged(self):
        """ROT-3 encryption/decryption round-trips on AZ without
        touching the new alphabet param."""
        ct = encrypt_text("HELLOWORLD", [3], CipherVariant.VIGENERE)
        pt = decrypt_text(ct, [3], CipherVariant.VIGENERE)
        assert pt == "HELLOWORLD"

    def test_ka_roundtrip_vigenere(self):
        """A plaintext encrypted with KA-Vigenère and decrypted with
        KA-Vigenère round-trips to the original."""
        # Key indices in KA: 'P' -> KA.char_to_idx('P') == 3 (K-R-Y-P...)
        key = [KA.char_to_idx('P')]
        ct = encrypt_text("HELLOWORLD", key, CipherVariant.VIGENERE, alphabet=KA)
        pt = decrypt_text(ct, key, CipherVariant.VIGENERE, alphabet=KA)
        assert pt == "HELLOWORLD"
        # Round trip on AZ-default path produces a different CT than the
        # KA path (structural check that KA is being used, not ignored).
        ct_az = encrypt_text("HELLOWORLD", key, CipherVariant.VIGENERE)
        assert ct != ct_az, (
            "KA and AZ paths produced identical CT — alphabet param ignored?"
        )

    def test_ka_roundtrip_beaufort(self):
        key = [KA.char_to_idx('S')]  # S is KA index 6
        ct = encrypt_text("THEEAGLEFLEW", key, CipherVariant.BEAUFORT, alphabet=KA)
        pt = decrypt_text(ct, key, CipherVariant.BEAUFORT, alphabet=KA)
        assert pt == "THEEAGLEFLEW"

    def test_ka_roundtrip_var_beaufort(self):
        key = [KA.char_to_idx('Z')]
        ct = encrypt_text("HELLOKRYPTOS", key, CipherVariant.VAR_BEAUFORT, alphabet=KA)
        pt = decrypt_text(ct, key, CipherVariant.VAR_BEAUFORT, alphabet=KA)
        assert pt == "HELLOKRYPTOS"


# ─── Dispatcher: alphabet resolution ─────────────────────────────────────────

class TestResolveAlphabetSequence:
    def test_az_returns_none(self):
        """AZ uses the kernel's AZ fast path; the resolver returns None."""
        assert _resolve_alphabet_sequence("AZ", {}) is None

    def test_ka_returns_kryptos_alphabet(self):
        seq = _resolve_alphabet_sequence("KA", {})
        assert seq == "KRYPTOSABCDEFGHIJLMNQUVWXZ"
        assert len(seq) == 26
        assert set(seq) == set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    def test_keyword_mixed_returns_constructed_alphabet(self):
        seq = _resolve_alphabet_sequence(
            "keyword_mixed", {"alphabet_keyword": "PALIMPSEST"},
        )
        # PALIMPSEST -> unique letters P, A, L, I, M, S, E, T then remainder.
        assert seq.startswith("PALIMSET")
        assert len(seq) == 26
        assert set(seq) == set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    def test_keyword_mixed_missing_keyword_raises(self):
        with pytest.raises(DispatcherError, match="alphabet_keyword"):
            _resolve_alphabet_sequence("keyword_mixed", {})

    def test_keyword_mixed_empty_keyword_raises(self):
        with pytest.raises(DispatcherError, match="alphabet_keyword"):
            _resolve_alphabet_sequence(
                "keyword_mixed", {"alphabet_keyword": ""},
            )

    def test_keyword_mixed_non_alpha_keyword_raises(self):
        with pytest.raises(DispatcherError, match="only A-Z letters"):
            _resolve_alphabet_sequence(
                "keyword_mixed", {"alphabet_keyword": "A1C"},
            )

    def test_unknown_alphabet_raises(self):
        with pytest.raises(DispatcherError, match="not supported"):
            _resolve_alphabet_sequence("ROT-13", {})


# ─── Dispatcher: layer translation ───────────────────────────────────────────

class TestKAAlphabetAllThreeVariants:
    """Happy-path across vigenere / beaufort / variant_beaufort."""

    @pytest.mark.parametrize("kind,expected_type", [
        ("vigenere", "vigenere"),
        ("beaufort", "beaufort"),
        ("variant_beaufort", "var_beaufort"),
    ])
    def test_ka_translates(self, kind, expected_type):
        step = _translate_layer(
            CipherLayer(kind=kind, alphabet="KA"),
            {"keyword": "PALIMPSEST"},
        )
        assert step["type"] == expected_type
        assert step["params"]["alphabet_sequence"] == KA.sequence
        assert step["params"]["alphabet_label"] == "KA"
        # PALIMPSEST indexed in KA (KRYPTOSABCDEFGHIJLMNQUVWXZ):
        # P=3, A=7, L=17, I=15, M=18, P=3, S=6, E=11, S=6, T=4
        assert step["params"]["key"] == [3, 7, 17, 15, 18, 3, 6, 11, 6, 4]

    @pytest.mark.parametrize("kind", ["vigenere", "beaufort", "variant_beaufort"])
    def test_keyword_mixed_translates(self, kind):
        layer = CipherLayer(
            kind=kind,
            alphabet="keyword_mixed",
            params=[ParamRange(name="alphabet_keyword", values=["ABSCISSA"])],
        )
        step = _translate_layer(
            layer,
            {"keyword": "ABCD", "alphabet_keyword": "ABSCISSA"},
        )
        assert step["params"]["alphabet_sequence"] == (
            keyword_mixed_alphabet("ABSCISSA")
        )
        assert step["params"]["alphabet_label"] == "keyword_mixed"


class TestAdversarial:
    def test_az_still_omits_alphabet_params(self):
        """The AZ fast path must not leak alphabet_sequence into params —
        otherwise compose.py would construct a needless Alphabet object
        for every Phase-4 spec."""
        step = _translate_layer(
            CipherLayer(kind="vigenere", alphabet="AZ"),
            {"keyword": "ABC"},
        )
        assert "alphabet_sequence" not in step["params"]
        assert "alphabet_label" not in step["params"]

    def test_keyword_mixed_without_alphabet_keyword_raises_at_translate(self):
        """A 'keyword_mixed' layer whose binding lacks 'alphabet_keyword'
        fails closed at _translate_layer, not silently at pipeline
        execution."""
        with pytest.raises(DispatcherError, match="alphabet_keyword"):
            _translate_layer(
                CipherLayer(kind="vigenere", alphabet="keyword_mixed"),
                {"keyword": "ABC"},  # missing alphabet_keyword
            )


# ─── Integration: Quagmire III K1 reduction ──────────────────────────────────

class TestK1QuagmireReduction:
    """The payoff test: Kryptos K1 is Quagmire III with keyword
    PALIMPSEST, indicator K, PA=CA=KRYPTOS. That reduces to
    Vigenère-on-KA with a specific key derivation.

    Indicator 'K' in KA has index 0, so the effective key after
    indicator adjustment is just KA.encode('PALIMPSEST'). The
    dispatcher's KA path must produce the published K1 plaintext when
    fed the K1 ciphertext.

    This is the single most important R2-2 integration test: it proves
    the DSL dispatcher can now express K1's cipher, which is the
    precondition for R2-5's real-API self-test.
    """
    K1_CT = "EMUFPHZLRFAXYUSDJKZLDKRNSHGNFIVJYQTQUXQBQVYUVLLTREVJYQTMKYRDMFD"
    K1_PT = "BETWEENSUBTLESHADINGANDTHEABSENCEOFLIGHTLIESTHENUANCEOFIQLUSION"

    def test_k1_reduces_to_vigenere_on_ka(self):
        """Build a one-layer Vigenère-on-KA spec matching K1's Quagmire III
        decomposition and run it through the dispatcher's pipeline
        construction path. The kernel-executed pipeline must produce K1 PT."""
        spec = HypothesisSpec(
            hypothesis_id="T-K1-R2-2",
            pipeline=[
                CipherLayer(
                    kind="vigenere",
                    alphabet="KA",
                    params=[ParamRange(name="keyword", values=["PALIMPSEST"])],
                ),
            ],
            notes="R2-2 verification: K1 Quagmire III as Vigenère on KA.",
        )
        errors = spec.validate()
        assert errors == [], f"spec did not validate: {errors}"

        bindings = (("layer0.keyword", "PALIMPSEST"),)

        # Patch CT_LEN so the dispatcher doesn't reject the 63-char K1 CT.
        import kryptos.kernel.constants as kc
        saved_CT_LEN = kc.CT_LEN
        try:
            kc.CT_LEN = len(self.K1_CT)
            pipeline_dict = _build_pipeline_config(spec, bindings)
            assert len(pipeline_dict["steps"]) == 1
            step = pipeline_dict["steps"][0]
            assert step["type"] == "vigenere"
            assert step["params"]["alphabet_sequence"] == KA.sequence

            steps = tuple(
                TransformConfig(
                    transform_type=TransformType(s["type"]),
                    params=dict(s.get("params", {})),
                    description=s.get("description", ""),
                )
                for s in pipeline_dict["steps"]
            )
            pipeline = PipelineConfig(
                name="R2-2-k1-verify",
                steps=steps,
                direction="decrypt",
            )
            fn = build_pipeline(pipeline)
            recovered = fn(self.K1_CT)
            assert recovered == self.K1_PT, (
                "Vigenère-on-KA pipeline failed to recover K1 plaintext.\n"
                f"  got:      {recovered[:60]}\n"
                f"  expected: {self.K1_PT[:60]}"
            )
        finally:
            kc.CT_LEN = saved_CT_LEN
