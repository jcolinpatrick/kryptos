"""Egyptological text normalization rules.

Transforms text through a family of normalization layers for controlled
variant expansion.  This is NOT exact linguistic reconstruction — it is
cryptanalytic coverage of plausible Latin-script renderings.

Layers produced:
    raw             — source text verbatim
    modern          — modern canonical spellings substituted
    carter_era      — Carter-era / legacy spellings forced
    digraph_reduced — KH→X, SH→S, PH→F, TH→T, DJ→J, CH→X
    vowel_reduced   — vowels stripped from identified Egyptian names
    full_reduced    — digraph + vowel reduction combined
    translit_approx — transliteration-derived alpha approximation
    unicode_norm    — diacritics stripped, ligatures expanded
"""
from __future__ import annotations

import re
import unicodedata
from typing import Dict, List, Tuple

# ── Egyptian name variant table ──────────────────────────────────────────
#
# Format: canonical_modern → {
#     "v": [spelling variants],          — all known Latin renderings
#     "t": "transliteration",            — Egyptological transliteration
#     "ta": "TRANSLITALPHA",             — A-Z approximation of transliteration
# }
#
# Carter-era spelling is ALWAYS the first entry in "v".
# Variants are case-insensitive for matching.

EGYPT_NAMES: Dict[str, Dict] = {
    # ── Pharaohs ─────────────────────────────────────────────────────
    "Tutankhamun": {
        "v": [
            "Tut-Ankh-Amen", "Tutankhamen", "Tutankhamun",
            "Tut-ankh-Amen", "Tut-Ankh-Amun", "Tutankhamon",
            "Touatankhamanou", "Toutankhamon", "Tutenchamun",
        ],
        "t": "twt-ꜥnḫ-jmn",
        "ta": "TWTANXIMN",
    },
    "Akhenaten": {
        "v": [
            "Akh-en-Aten", "Akhenaton", "Akhenaten", "Ikhnaton",
            "Ikhnaten", "Khu-en-Aten", "Khuenaten", "Akhnaton",
            "Akhnaten",
        ],
        "t": "3ḫ-n-jtn",
        "ta": "AXNITN",
    },
    "Amenhotep": {
        "v": [
            "Amenhetep", "Amen-hetep", "Amenhotep", "Amen-hotep",
            "Amenophis", "Amenothes",
        ],
        "t": "jmn-ḥtp",
        "ta": "IMNHTP",
    },
    "Thutmose": {
        "v": [
            "Thothmes", "Thoutmosis", "Thutmose", "Thutmosis",
            "Tuthmosis", "Thotmes", "Totmes", "Djehutymes",
        ],
        "t": "ḏḥwtj-ms",
        "ta": "JHWTIMS",
    },
    "Hatshepsut": {
        "v": [
            "Hat-shep-sut", "Hatshepsut", "Hatshepset", "Hatasu",
            "Hatsheput", "Hatshopsitu",
        ],
        "t": "ḥ3t-šps.wt",
        "ta": "HATSPSWT",
    },
    "Horemheb": {
        "v": ["Horemheb", "Haremhab", "Horemhab", "Harmhabi"],
        "t": "ḥr-m-ḥb",
        "ta": "HRMHB",
    },
    "Seti": {
        "v": ["Seti", "Sethos", "Sety", "Sethi"],
        "t": "stẖ",
        "ta": "STX",
    },
    "Ramesses": {
        "v": ["Rameses", "Ramses", "Ramesses", "Ramessu", "Ramesse"],
        "t": "rꜥ-ms-sw",
        "ta": "RAMSSW",
    },
    "Nefertiti": {
        "v": [
            "Nefertiti", "Nefret-ete", "Nefert-iti", "Nofretete",
            "Nefretiti",
        ],
        "t": "nfr.t-jj.tj",
        "ta": "NFRTITI",
    },
    "Nefertari": {
        "v": ["Nefertari", "Nefert-ari", "Nofretari"],
        "t": "nfr.t-jrj",
        "ta": "NFRTIRI",
    },
    "Ay": {
        "v": ["Ay", "Aye", "Ai", "Aiy"],
        "t": "jy",
        "ta": "IY",
    },
    "Smenkhkare": {
        "v": ["Smenkhkare", "Sakere", "Smenkhare", "Smenkh-ka-Re"],
        "t": "s-mnḫ-k3-rꜥ",
        "ta": "SMNXKARA",
    },
    "Merenptah": {
        "v": ["Merenptah", "Merneptah", "Merenpteh", "Mineptah"],
        "t": "mr-n-ptḥ",
        "ta": "MRNPTH",
    },
    "Senusret": {
        "v": ["Senusret", "Sesostris", "Usertsen", "Usertesen"],
        "t": "s-n-wsrt",
        "ta": "SNWSRT",
    },
    "Khufu": {
        "v": ["Khufu", "Cheops", "Kheops"],
        "t": "ḫwfw",
        "ta": "XWFW",
    },
    "Khafre": {
        "v": ["Khafre", "Chephren", "Khafra", "Khefren"],
        "t": "ḫꜥ.f-rꜥ",
        "ta": "XAFRA",
    },
    "Menkaure": {
        "v": ["Menkaure", "Mycerinus", "Mykerinos", "Menkara"],
        "t": "mn-k3w-rꜥ",
        "ta": "MNKAWRA",
    },
    "Sneferu": {
        "v": ["Sneferu", "Snefru", "Snofru"],
        "t": "snfrw",
        "ta": "SNFRW",
    },
    "Djoser": {
        "v": ["Djoser", "Zoser", "Djeser", "Tcheser"],
        "t": "ḏsr",
        "ta": "JSR",
    },
    "Narmer": {
        "v": ["Narmer", "Nar-mer"],
        "t": "nꜥr-mr",
        "ta": "NARMR",
    },

    # ── Deities ──────────────────────────────────────────────────────
    "Amun": {
        "v": ["Amen", "Amun", "Amon", "Ammon", "Ammun"],
        "t": "jmn",
        "ta": "IMN",
    },
    "Osiris": {
        "v": ["Osiris", "Usire", "Asar", "Wesir"],
        "t": "wsjr",
        "ta": "WSIR",
    },
    "Anubis": {
        "v": ["Anubis", "Anpu", "Inpu", "Inpw"],
        "t": "jnpw",
        "ta": "INPW",
    },
    "Thoth": {
        "v": ["Thoth", "Thout", "Tehuti", "Djehuti", "Djehuty"],
        "t": "ḏḥwtj",
        "ta": "JHWTI",
    },
    "Hathor": {
        "v": ["Hathor", "Hathr", "Het-Hert", "Het-heru"],
        "t": "ḥwt-ḥr",
        "ta": "HWTHR",
    },
    "Horus": {
        "v": ["Horus", "Hor", "Heru", "Hr"],
        "t": "ḥr",
        "ta": "HR",
    },
    "Isis": {
        "v": ["Isis", "Aset", "Ast", "Iset"],
        "t": "3st",
        "ta": "AST",
    },
    "Nephthys": {
        "v": ["Nephthys", "Nebt-het", "Nebthet"],
        "t": "nbt-ḥwt",
        "ta": "NBTHWT",
    },
    "Ptah": {
        "v": ["Ptah", "Peteh", "Phthah"],
        "t": "ptḥ",
        "ta": "PTH",
    },
    "Sekhmet": {
        "v": ["Sekhmet", "Sekhet", "Sachmis", "Sachmet"],
        "t": "sḫmt",
        "ta": "SXMT",
    },
    "Bastet": {
        "v": ["Bastet", "Bast", "Pasht", "Ubaste"],
        "t": "b3stt",
        "ta": "BASTT",
    },
    "Sobek": {
        "v": ["Sobek", "Sebek", "Suchos", "Sobk"],
        "t": "sbk",
        "ta": "SBK",
    },
    "Khnum": {
        "v": ["Khnum", "Khnemu", "Chnoumis", "Knum"],
        "t": "ḫnmw",
        "ta": "XNMW",
    },
    "Aten": {
        "v": ["Aten", "Aton", "Adon"],
        "t": "jtn",
        "ta": "ITN",
    },
    "Maat": {
        "v": ["Maat", "Mayet", "Maet"],
        "t": "m3ꜥt",
        "ta": "MAAT",
    },
    "Ra": {
        "v": ["Ra", "Re"],
        "t": "rꜥ",
        "ta": "RA",
    },
    "Seth": {
        "v": ["Seth", "Set", "Sutekh", "Setesh"],
        "t": "stẖ",
        "ta": "STX",
    },

    # ── Places ───────────────────────────────────────────────────────
    "Amarna": {
        "v": [
            "Tell el-Amarna", "Tel el-Amarna", "Amarna", "El-Amarna",
            "Tell el Amarna", "el-Amarna",
        ],
        "t": "3ḫt-jtn",
        "ta": "AXITN",
    },
    "Deir el-Bahari": {
        "v": [
            "Deir el-Bahari", "Deir el Bahari", "Deir-el-Bahari",
            "Der el Bahri", "Dair el Bahri",
        ],
        "t": "",
        "ta": "",
    },
    "Thebes": {
        "v": ["Thebes", "Waset", "Wase", "Diospolis"],
        "t": "w3st",
        "ta": "WAST",
    },
    "Memphis": {
        "v": ["Memphis", "Men-nefer", "Mennefer", "Moph"],
        "t": "mn-nfr",
        "ta": "MNNFR",
    },
    "Karnak": {
        "v": ["Karnak", "Carnac", "Ipet-isut"],
        "t": "jpt-swt",
        "ta": "IPTSWT",
    },
    "Luxor": {
        "v": ["Luxor", "Louxor", "Luksor"],
        "t": "jpt-rst",
        "ta": "IPTRST",
    },
    "Heliopolis": {
        "v": ["Heliopolis", "Iunu", "On", "Annu"],
        "t": "jwnw",
        "ta": "IWNW",
    },
    "Abydos": {
        "v": ["Abydos", "Abdu", "Abedjou"],
        "t": "3bḏw",
        "ta": "ABJW",
    },
    "Saqqara": {
        "v": ["Saqqara", "Sakkara", "Sakkarah", "Saccara"],
        "t": "",
        "ta": "",
    },
    "Giza": {
        "v": ["Giza", "Gizeh", "Ghizeh", "Geeza"],
        "t": "",
        "ta": "",
    },
    "Aswan": {
        "v": ["Aswan", "Assuan", "Assouan", "Syene"],
        "t": "swnw",
        "ta": "SWNW",
    },
    "Edfu": {
        "v": ["Edfu", "Idfu", "Behdet"],
        "t": "bḥdt",
        "ta": "BHDT",
    },
    "Dendera": {
        "v": ["Dendera", "Denderah", "Tentyra"],
        "t": "jwnt",
        "ta": "IWNT",
    },

    # ── Archaeological / cultural terms ──────────────────────────────
    "ushabti": {
        "v": ["ushabti", "ushebti", "shabti", "shawabti", "shawabty",
               "ushabty"],
        "t": "wšbtj",
        "ta": "WSBTI",
    },
    "canopic": {
        "v": ["canopic", "kanopic"],
        "t": "", "ta": "",
    },
    "sarcophagus": {
        "v": ["sarcophagus", "sarkophag"],
        "t": "", "ta": "",
    },
    "scarab": {
        "v": ["scarab", "scarabaeus", "scarabeus"],
        "t": "ḫprr",
        "ta": "XPRR",
    },
    "cartouche": {
        "v": ["cartouche", "cartouch"],
        "t": "šnw",
        "ta": "SNW",
    },
    "mastaba": {
        "v": ["mastaba", "mastabah", "mastabet"],
        "t": "", "ta": "",
    },
    "stela": {
        "v": ["stela", "stele", "stelae"],
        "t": "wḏ",
        "ta": "WJ",
    },
    "vizier": {
        "v": ["vizier", "vizir", "wazir"],
        "t": "t3tj",
        "ta": "TATI",
    },
    "pylon": {
        "v": ["pylon", "propylon"],
        "t": "bḫnt",
        "ta": "BXNT",
    },
    "obelisk": {
        "v": ["obelisk", "obelisque"],
        "t": "tḫn",
        "ta": "TXN",
    },
    "papyrus": {
        "v": ["papyrus", "papyri"],
        "t": "ṯꜥ",
        "ta": "TA",
    },
    "pharaoh": {
        "v": ["pharaoh", "pharao", "phiroun"],
        "t": "pr-ꜥ3",
        "ta": "PRAA",
    },
    "necropolis": {
        "v": ["necropolis", "nekropolis"],
        "t": "", "ta": "",
    },
}


# ── Digraph reduction rules ─────────────────────────────────────────────
# Applied to A-Z text.  These CHANGE letter count, shifting positions.
# Order matters: apply longest digraphs first to avoid partial matches.

DIGRAPH_REDUCTIONS: List[Tuple[str, str]] = [
    ("KH", "X"),    # Akhenaten → Axenaten (Egyptological ḫ)
    ("SH", "S"),    # Hatshepsut → Hatsepsut (Egyptological š)
    ("PH", "F"),    # Pharaoh → Faraoh (Greek-derived)
    ("DJ", "J"),    # Djehuty → Jehuty (Egyptological ḏ)
    ("TH", "T"),    # Thothmes → Totmes (careful: affects English "the")
    ("CH", "X"),    # Cheops → Xeops (variant rendering of ḫ)
]


# ── Unicode → ASCII mapping ─────────────────────────────────────────────
# Covers Egyptological transliteration characters + common diacritics.

UNICODE_TO_ASCII: Dict[str, str] = {
    # Egyptological transliteration
    "ꜣ": "A",  "ꜥ": "A",  "š": "SH", "ḫ": "KH",
    "ḥ": "H",  "ẖ": "KH", "ḏ": "DJ", "ṯ": "TJ",
    "ḳ": "Q",  "ṡ": "S",  "ṣ": "S",  "ẓ": "Z",
    "ṭ": "T",  "ṇ": "N",
    # European diacritics
    "ü": "UE", "ö": "OE", "ä": "AE", "ß": "SS",
    "é": "E",  "è": "E",  "ê": "E",  "ë": "E",
    "à": "A",  "â": "A",  "î": "I",  "ï": "I",
    "ô": "O",  "ù": "U",  "û": "U",  "ç": "C",
    "ñ": "N",  "æ": "AE", "œ": "OE",
}

VOWELS = frozenset("AEIOU")

# ── Compiled regex for name matching ─────────────────────────────────────
# Built at module load.  Patterns sorted longest-first for greedy matching.

_NAME_PATTERNS: List[Tuple[re.Pattern, str, str]] = []


def _build_patterns() -> None:
    """Build compiled regex patterns for all name variants."""
    entries = []
    for canonical, info in EGYPT_NAMES.items():
        for variant in info["v"]:
            # Escape for regex, allow flexible whitespace around hyphens
            escaped = re.escape(variant)
            # "Tut-Ankh-Amen" should match "Tut - Ankh - Amen" etc.
            escaped = escaped.replace(r"\-", r"\s*-\s*")
            entries.append((len(variant), escaped, canonical, variant))
    # Sort longest first so greedy matching works
    entries.sort(key=lambda x: x[0], reverse=True)
    for _, pattern_str, canonical, original in entries:
        _NAME_PATTERNS.append(
            (re.compile(pattern_str, re.IGNORECASE), canonical, original)
        )


_build_patterns()


class EgyptNormalizer:
    """Applies Egyptological normalization rules to text.

    All methods return (result_text, list_of_steps) tuples for provenance.
    """

    @staticmethod
    def to_alpha(text: str) -> str:
        """Strip to A-Z uppercase only."""
        return re.sub(r"[^A-Z]", "", text.upper())

    @staticmethod
    def normalize_unicode(text: str) -> Tuple[str, List[str]]:
        """Replace Unicode Egyptological characters with ASCII equivalents."""
        result = text
        steps = []
        for uni, ascii_eq in UNICODE_TO_ASCII.items():
            if uni in result:
                result = result.replace(uni, ascii_eq)
                steps.append(f"U+{ord(uni):04X} → {ascii_eq}")
            upper_uni = uni.upper()
            if upper_uni != uni and len(upper_uni) == 1 and upper_uni in result:
                result = result.replace(upper_uni, ascii_eq.upper())
                steps.append(f"U+{ord(upper_uni):04X} → {ascii_eq.upper()}")
        # Fallback: strip remaining combining characters
        nfkd = unicodedata.normalize("NFKD", result)
        stripped = "".join(c for c in nfkd if not unicodedata.combining(c))
        if stripped != result:
            steps.append("residual combining marks stripped")
        return stripped, steps or ["no unicode changes"]

    @staticmethod
    def apply_modern_spellings(text: str) -> Tuple[str, List[str]]:
        """Replace historical spellings with modern canonical forms."""
        result = text
        changes = []
        for pattern, canonical, original in _NAME_PATTERNS:
            if original == canonical:
                continue
            match = pattern.search(result)
            if match:
                result = pattern.sub(canonical, result)
                changes.append(f"{original} → {canonical}")
        return result, changes or ["no name changes"]

    @staticmethod
    def apply_carter_era_spellings(text: str) -> Tuple[str, List[str]]:
        """Force Carter-era spellings (first variant in each group)."""
        result = text
        changes = []
        for canonical, info in EGYPT_NAMES.items():
            carter_form = info["v"][0]
            for variant in info["v"][1:]:
                pat = re.compile(re.escape(variant), re.IGNORECASE)
                if pat.search(result):
                    result = pat.sub(carter_form, result)
                    changes.append(f"{variant} → {carter_form}")
            if canonical != carter_form:
                pat = re.compile(re.escape(canonical), re.IGNORECASE)
                if pat.search(result):
                    result = pat.sub(carter_form, result)
                    changes.append(f"{canonical} → {carter_form}")
        return result, changes or ["no carter-era changes"]

    @staticmethod
    def reduce_digraphs(text: str) -> Tuple[str, List[str]]:
        """Reduce Egyptological digraphs (KH→X, SH→S, etc.).

        WARNING: changes letter count, shifting all subsequent positions.
        Operates on uppercase text.
        """
        result = text.upper()
        reductions = []
        for digraph, replacement in DIGRAPH_REDUCTIONS:
            count = result.count(digraph)
            if count:
                result = result.replace(digraph, replacement)
                reductions.append(f"{digraph}→{replacement} (x{count})")
        return result, reductions or ["no digraph changes"]

    @staticmethod
    def reduce_vowels_in_names(text: str) -> Tuple[str, List[str]]:
        """Remove vowels from identified Egyptian names only.

        Surrounding (non-name) text is preserved as-is.
        Operates on A-Z uppercase text.
        """
        upper = text.upper()
        changes = []
        # Build replacement map: find all name occurrences, strip vowels
        for canonical, info in EGYPT_NAMES.items():
            for variant in info["v"]:
                alpha_form = re.sub(r"[^A-Z]", "", variant.upper())
                if not alpha_form or alpha_form not in upper:
                    continue
                consonants = "".join(c for c in alpha_form if c not in VOWELS)
                if consonants and consonants != alpha_form:
                    upper = upper.replace(alpha_form, consonants, 1)
                    changes.append(f"{alpha_form} → {consonants}")
        return upper, changes or ["no vowel changes"]

    @staticmethod
    def apply_translit_alpha(text: str) -> Tuple[str, List[str]]:
        """Replace known names with transliteration-derived A-Z forms.

        Uses the 'ta' field from EGYPT_NAMES.  Only applies where the
        transliteration alpha form is available and non-empty.
        """
        upper = text.upper()
        changes = []
        for canonical, info in EGYPT_NAMES.items():
            ta = info.get("ta", "")
            if not ta:
                continue
            for variant in info["v"]:
                alpha_form = re.sub(r"[^A-Z]", "", variant.upper())
                if alpha_form and alpha_form in upper:
                    upper = upper.replace(alpha_form, ta, 1)
                    changes.append(f"{alpha_form} → {ta} (translit)")
                    break  # one replacement per canonical name
        return upper, changes or ["no translit changes"]

    @staticmethod
    def full_reduce(text: str) -> Tuple[str, List[str]]:
        """Apply digraph reduction + vowel reduction."""
        t1, c1 = EgyptNormalizer.reduce_digraphs(text)
        t2, c2 = EgyptNormalizer.reduce_vowels_in_names(t1)
        return t2, c1 + c2

    @staticmethod
    def clean_ocr(text: str) -> str:
        """Clean common OCR artifacts from PDF-extracted text."""
        result = text
        # Remove stray # and • markers FIRST (before space collapse)
        result = re.sub(r"[#•>]", "", result)
        # Fix line-break hyphens with spaces: "TUT-  ANKH" → "TUT-ANKH"
        result = re.sub(r"-\s+", "-", result)
        result = re.sub(r"\s+-", "-", result)
        # Collapse multiple spaces (after marker removal)
        result = re.sub(r"  +", " ", result)
        # Collapse multiple newlines
        result = re.sub(r"\n{3,}", "\n\n", result)
        return result.strip()

    @staticmethod
    def identify_egypt_names(text: str) -> List[Tuple[int, int, str, str]]:
        """Find Egyptian name occurrences in text.

        Returns [(match_start, match_end, matched_text, canonical_name)].
        """
        found = []
        for pattern, canonical, _ in _NAME_PATTERNS:
            for m in pattern.finditer(text):
                found.append((m.start(), m.end(), m.group(), canonical))
        # De-duplicate overlaps: keep longest match at each position
        found.sort(key=lambda x: (x[0], -(x[1] - x[0])))
        result = []
        last_end = -1
        for start, end, matched, canonical in found:
            if start >= last_end:
                result.append((start, end, matched, canonical))
                last_end = end
        return result
