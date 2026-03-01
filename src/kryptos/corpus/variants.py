"""Controlled variant expansion for Egyptological text.

Generates a family of parallel A-Z representations from each source passage.
Each variant produces a DIFFERENT alpha string (different letters and/or
different letter count), making each cryptanalytically distinct for
running-key testing.

Variant types and why they matter for K4:

    raw             — direct test of source text as printed
    modern          — catches modern spelling of names (E vs U in Tutankhamen/un)
    carter_era      — forces Carter's own hyphenated forms
    digraph_reduced — KH→X etc. CHANGES LETTER COUNT, shifts alignment
    vowel_reduced   — consonantal skeleton of Egyptian names
    full_reduced    — digraph + vowel combined
    translit_approx — transliteration-derived alpha (maximal reduction)
    unicode_norm    — diacritics → ASCII (relevant for non-English sources)
    modern_digraph  — modern spellings + digraph reduction
"""
from __future__ import annotations

import re
from typing import Dict, List

from kryptos.corpus.normalize import EgyptNormalizer


class VariantGenerator:
    """Generates all variant forms of a text passage."""

    def __init__(self) -> None:
        self.normalizer = EgyptNormalizer()

    def generate_all(self, text: str) -> Dict[str, Dict]:
        """Produce all variant forms from source text.

        Returns dict of variant_name → {
            "text": str,    # variant with formatting (or A-Z for derived)
            "alpha": str,   # A-Z uppercase only
            "length": int,  # len(alpha)
            "steps": list,  # normalization steps applied
        }
        """
        n = self.normalizer
        variants: Dict[str, Dict] = {}

        # ── 1. Raw ───────────────────────────────────────────────────
        alpha_raw = n.to_alpha(text)
        variants["raw"] = {
            "text": text,
            "alpha": alpha_raw,
            "length": len(alpha_raw),
            "steps": ["source text verbatim"],
        }

        # ── 2. Unicode normalized ────────────────────────────────────
        uni_text, uni_steps = n.normalize_unicode(text)
        alpha_uni = n.to_alpha(uni_text)
        variants["unicode_norm"] = {
            "text": uni_text,
            "alpha": alpha_uni,
            "length": len(alpha_uni),
            "steps": uni_steps,
        }

        # ── 3. Modern spellings ──────────────────────────────────────
        mod_text, mod_steps = n.apply_modern_spellings(text)
        alpha_mod = n.to_alpha(mod_text)
        variants["modern"] = {
            "text": mod_text,
            "alpha": alpha_mod,
            "length": len(alpha_mod),
            "steps": mod_steps,
        }

        # ── 4. Carter-era spellings ──────────────────────────────────
        carter_text, carter_steps = n.apply_carter_era_spellings(text)
        alpha_carter = n.to_alpha(carter_text)
        variants["carter_era"] = {
            "text": carter_text,
            "alpha": alpha_carter,
            "length": len(alpha_carter),
            "steps": carter_steps,
        }

        # ── 5. Digraph reduced (from raw alpha) ─────────────────────
        dig_text, dig_steps = n.reduce_digraphs(alpha_raw)
        alpha_dig = re.sub(r"[^A-Z]", "", dig_text)
        variants["digraph_reduced"] = {
            "text": dig_text,
            "alpha": alpha_dig,
            "length": len(alpha_dig),
            "steps": dig_steps,
        }

        # ── 6. Vowel reduced (from raw alpha, Egyptian names) ───────
        vow_text, vow_steps = n.reduce_vowels_in_names(alpha_raw)
        alpha_vow = re.sub(r"[^A-Z]", "", vow_text)
        variants["vowel_reduced"] = {
            "text": vow_text,
            "alpha": alpha_vow,
            "length": len(alpha_vow),
            "steps": vow_steps,
        }

        # ── 7. Full reduced (digraph + vowel) ───────────────────────
        full_text, full_steps = n.full_reduce(alpha_raw)
        alpha_full = re.sub(r"[^A-Z]", "", full_text)
        variants["full_reduced"] = {
            "text": full_text,
            "alpha": alpha_full,
            "length": len(alpha_full),
            "steps": full_steps,
        }

        # ── 8. Transliteration approximation ────────────────────────
        translit_text, translit_steps = n.apply_translit_alpha(alpha_raw)
        alpha_translit = re.sub(r"[^A-Z]", "", translit_text)
        variants["translit_approx"] = {
            "text": translit_text,
            "alpha": alpha_translit,
            "length": len(alpha_translit),
            "steps": translit_steps,
        }

        # ── 9. Modern + digraph combined ────────────────────────────
        mod_dig_text, mod_dig_steps = n.reduce_digraphs(alpha_mod)
        alpha_mod_dig = re.sub(r"[^A-Z]", "", mod_dig_text)
        variants["modern_digraph"] = {
            "text": mod_dig_text,
            "alpha": alpha_mod_dig,
            "length": len(alpha_mod_dig),
            "steps": mod_steps + mod_dig_steps,
        }

        return variants

    def variant_names(self) -> List[str]:
        """Return ordered list of variant type names."""
        return [
            "raw", "unicode_norm", "modern", "carter_era",
            "digraph_reduced", "vowel_reduced", "full_reduced",
            "translit_approx", "modern_digraph",
        ]

    def variant_descriptions(self) -> Dict[str, str]:
        """Human-readable descriptions for each variant type."""
        return {
            "raw": "Source text verbatim, alpha-stripped",
            "unicode_norm": "Unicode diacritics → ASCII equivalents",
            "modern": "Modern canonical spellings substituted",
            "carter_era": "Carter-era / legacy spellings forced",
            "digraph_reduced": "KH→X, SH→S, PH→F, TH→T, DJ→J, CH→X",
            "vowel_reduced": "Vowels removed from Egyptian names",
            "full_reduced": "Digraph + vowel reduction combined",
            "translit_approx": "Transliteration-derived A-Z approximation",
            "modern_digraph": "Modern spellings + digraph reduction",
        }
