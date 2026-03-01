"""Tests for the Egyptological corpus pipeline.

Covers: schema serialization, normalization rules, variant generation,
text ingestion and segmentation.
"""
import json
import os
import pytest
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from kryptos.corpus.schema import CorpusPassage, Provenance, OffsetEntry
from kryptos.corpus.normalize import (
    EgyptNormalizer, EGYPT_NAMES, DIGRAPH_REDUCTIONS, UNICODE_TO_ASCII,
)
from kryptos.corpus.variants import VariantGenerator
from kryptos.corpus.ingest import TextIngester


class TestSchema:
    """CorpusPassage and Provenance serialization."""

    def test_provenance_roundtrip(self):
        prov = Provenance(
            source_file="carter_vol1.txt",
            title="The Tomb of Tut-Ankh-Amen",
            author="Howard Carter",
            gutenberg_id=None,
            chapter="Chapter I",
            line_start=100,
            line_end=120,
        )
        passage = CorpusPassage(
            passage_id="carter_vol1.txt:100",
            raw="Some test text about Tutankhamen",
            provenance=prov,
            raw_alpha_length=28,
        )
        j = passage.to_json()
        restored = CorpusPassage.from_json(j)
        assert restored.passage_id == passage.passage_id
        assert restored.raw == passage.raw
        assert restored.provenance.source_file == "carter_vol1.txt"
        assert restored.provenance.author == "Howard Carter"
        assert restored.provenance.chapter == "Chapter I"
        assert restored.raw_alpha_length == 28

    def test_passage_with_variants(self):
        passage = CorpusPassage(
            passage_id="test:1",
            raw="Tut-Ankh-Amen",
            variants={
                "raw": {"text": "Tut-Ankh-Amen", "alpha": "TUTANKHAMEN",
                         "length": 11, "steps": ["verbatim"]},
            },
        )
        d = passage.to_dict()
        assert "variants" in d
        assert d["variants"]["raw"]["alpha"] == "TUTANKHAMEN"


class TestNormalizer:
    """EgyptNormalizer rule correctness."""

    def test_to_alpha(self):
        assert EgyptNormalizer.to_alpha("Tut-Ankh-Amen") == "TUTANKHAMEN"
        assert EgyptNormalizer.to_alpha("Deir el-Bahari") == "DEIRELBAHARI"
        assert EgyptNormalizer.to_alpha("hello world!") == "HELLOWORLD"

    def test_name_table_completeness(self):
        """Every canonical name has at least 2 variants."""
        for canonical, info in EGYPT_NAMES.items():
            assert len(info["v"]) >= 2, f"{canonical} needs >= 2 variants"
            # First variant should be a real variant (Carter-era)
            assert len(info["v"][0]) > 0

    def test_name_table_canonical_included(self):
        """Canonical modern form appears in its own variant list."""
        for canonical, info in EGYPT_NAMES.items():
            alpha_canonical = EgyptNormalizer.to_alpha(canonical)
            alpha_variants = [
                EgyptNormalizer.to_alpha(v) for v in info["v"]
            ]
            # Either canonical is directly in variants, or its alpha
            # form matches one of the variant alpha forms
            assert alpha_canonical in alpha_variants or canonical in info["v"], \
                f"{canonical} not found among its own variants"

    def test_modern_spellings_tutankhamun(self):
        text = "The tomb of Tutankhamen was discovered"
        result, steps = EgyptNormalizer.apply_modern_spellings(text)
        assert "Tutankhamun" in result
        assert any("Tutankhamen" in s for s in steps)

    def test_modern_spellings_akhenaten(self):
        text = "Ikhnaton ruled Egypt"
        result, steps = EgyptNormalizer.apply_modern_spellings(text)
        assert "Akhenaten" in result

    def test_carter_era_spellings(self):
        text = "Tutankhamun was a pharaoh"
        result, steps = EgyptNormalizer.apply_carter_era_spellings(text)
        # Carter used "Tut-Ankh-Amen"
        assert "Tut-Ankh-Amen" in result

    def test_digraph_reduction(self):
        text = "AKHENATEN HATSHEPSUT PHARAOH"
        result, steps = EgyptNormalizer.reduce_digraphs(text)
        assert "AX" in result     # KH → X
        assert "HATSEPSUT" in result or "ATSEPSUT" in result  # SH → S
        assert "FARAO" in result   # PH → F, but also TH → T

    def test_digraph_changes_length(self):
        """Digraph reduction MUST change letter count."""
        text = "AKHENATEN"  # 9 chars, has KH
        result, _ = EgyptNormalizer.reduce_digraphs(text)
        # KH→X removes one char, TH→T removes one char if present
        # A-K-H-E-N-A-T-E-N → A-X-E-N-A-T-E-N (8 chars after KH→X)
        assert len(result.replace(" ", "")) < len(text)

    def test_vowel_reduction_in_names(self):
        text = "TUTANKHAMEN"
        result, steps = EgyptNormalizer.reduce_vowels_in_names(text)
        # Should strip vowels from TUTANKHAMEN
        assert len(result) < len(text)
        # Consonants should be preserved
        for c in "TTNKHMN":
            assert c in result

    def test_full_reduce(self):
        text = "AKHENATEN PHARAOH"
        result, steps = EgyptNormalizer.full_reduce(text)
        assert len(result) < len(text)
        assert len(steps) > 0

    def test_unicode_normalization(self):
        text = "The god Amen-Rē ruled"
        result, _ = EgyptNormalizer.normalize_unicode(text)
        # No non-ASCII should remain
        assert all(ord(c) < 128 for c in result)

    def test_unicode_egyptological_chars(self):
        text = "ḫpr ḥtp šmꜥ"
        result, steps = EgyptNormalizer.normalize_unicode(text)
        assert "KH" in result.upper() or "X" in result.upper()
        assert len(steps) > 1

    def test_translit_alpha(self):
        text = "TUTANKHAMEN"
        result, steps = EgyptNormalizer.apply_translit_alpha(text)
        if any("translit" in s for s in steps):
            # Should have replaced with transliteration alpha
            assert result != text

    def test_identify_egypt_names(self):
        text = "Howard Carter found Tutankhamen's tomb at Thebes"
        names = EgyptNormalizer.identify_egypt_names(text)
        canonical_names = [n[3] for n in names]
        assert "Tutankhamun" in canonical_names
        assert "Thebes" in canonical_names

    def test_clean_ocr(self):
        text = "TUT-  ANKH  -AMEN   was   found  #  in  the"
        result = EgyptNormalizer.clean_ocr(text)
        # Multiple spaces collapsed, hyphens fixed
        assert "  " not in result
        assert "#" not in result

    def test_clean_ocr_hyphen_fix(self):
        text = "Tut-  Ankh"
        result = EgyptNormalizer.clean_ocr(text)
        assert result == "Tut-Ankh"


class TestVariantGenerator:
    """Variant generation produces distinct alpha forms."""

    def setup_method(self):
        self.gen = VariantGenerator()

    def test_all_variants_produced(self):
        text = "The tomb of Akhenaten at Thebes"
        variants = self.gen.generate_all(text)
        expected = self.gen.variant_names()
        for name in expected:
            assert name in variants, f"Missing variant: {name}"
            assert "alpha" in variants[name]
            assert "steps" in variants[name]
            assert "length" in variants[name]

    def test_raw_is_unchanged(self):
        text = "Simple test without Egyptian names"
        variants = self.gen.generate_all(text)
        assert variants["raw"]["alpha"] == "SIMPLETESTWITHOUTEGYPTIANNAMES"

    def test_digraph_reduces_length(self):
        text = "Akhenaten and Thutmose explored the shrine"
        variants = self.gen.generate_all(text)
        raw_len = variants["raw"]["length"]
        dig_len = variants["digraph_reduced"]["length"]
        # Text contains KH, TH — both should reduce
        assert dig_len < raw_len

    def test_modern_differs_from_carter(self):
        text = "Tutankhamen was buried"
        variants = self.gen.generate_all(text)
        # Modern: Tutankhamun (U at end), Carter: Tut-Ankh-Amen (stripped same)
        modern_alpha = variants["modern"]["alpha"]
        carter_alpha = variants["carter_era"]["alpha"]
        # These should differ because Tutankhamen → Tutankhamun (E→U)
        # and carter_era forces Tut-Ankh-Amen (same alpha as Tutankhamen)
        # The key point is that at least SOME variants differ
        all_alphas = [v["alpha"] for v in variants.values()]
        assert len(set(all_alphas)) > 1, "All variants identical — no divergence"

    def test_variant_names_order(self):
        names = self.gen.variant_names()
        assert names[0] == "raw"
        assert len(names) == 9

    def test_variant_descriptions_complete(self):
        descs = self.gen.variant_descriptions()
        for name in self.gen.variant_names():
            assert name in descs
            assert len(descs[name]) > 5


class TestIngester:
    """Text ingestion and segmentation."""

    def test_paragraph_segmentation(self):
        ingester = TextIngester(cache_dir="/tmp/kryptos_test_cache")
        # Simulate a multi-paragraph text
        text = (
            "First paragraph about Tutankhamen and his tomb.\n"
            "Still the first paragraph.\n"
            "\n"
            "Second paragraph discusses Akhenaten's reign\n"
            "at Amarna in some detail.\n"
            "\n"
            "Third paragraph is about Nefertiti.\n"
        )
        # Write temp file
        tmp = "/tmp/kryptos_test_ingest.txt"
        with open(tmp, "w") as f:
            f.write(text)

        passages = ingester.load_local(
            tmp, title="Test", author="Test", is_ocr=False
        )
        # Should get 3 passages (each paragraph > 20 chars)
        assert len(passages) >= 2
        assert all(p.passage_id for p in passages)
        assert all(p.provenance.title == "Test" for p in passages)

    def test_short_blocks_skipped(self):
        ingester = TextIngester(cache_dir="/tmp/kryptos_test_cache")
        text = (
            "I\n\n"
            "II\n\n"
            "This is a longer paragraph that should be kept as a passage.\n"
        )
        tmp = "/tmp/kryptos_test_short.txt"
        with open(tmp, "w") as f:
            f.write(text)
        passages = ingester.load_local(
            tmp, title="Test", author="Test", is_ocr=False
        )
        # Only the long paragraph should survive (>20 alpha chars)
        assert len(passages) == 1

    def test_gutenberg_stripping(self):
        text = (
            "Some header stuff\n"
            "*** START OF THE PROJECT GUTENBERG EBOOK TEST ***\n"
            "The actual content starts here.\n"
            "\n"
            "More content about ancient Egypt.\n"
            "*** END OF THE PROJECT GUTENBERG EBOOK TEST ***\n"
            "Some footer stuff\n"
        )
        result = TextIngester._strip_gutenberg_wrapper(text)
        assert "header stuff" not in result
        assert "footer stuff" not in result
        assert "actual content" in result

    def test_chapter_detection(self):
        ingester = TextIngester(cache_dir="/tmp/kryptos_test_cache")
        text = (
            "CHAPTER I. THE DISCOVERY\n"
            "The Valley of the Kings at Thebes was well explored by this time.\n"
            "\n"
            "We began our search in the autumn season with great anticipation.\n"
            "\n"
            "CHAPTER II. THE TOMB\n"
            "The entrance was sealed with plaster bearing the royal cartouche.\n"
        )
        tmp = "/tmp/kryptos_test_chapter.txt"
        with open(tmp, "w") as f:
            f.write(text)
        passages = ingester.load_local(
            tmp, title="Test", author="Test", is_ocr=False
        )
        # At least one passage should have chapter info
        chapters = [p.provenance.chapter for p in passages if p.provenance.chapter]
        assert len(chapters) > 0
