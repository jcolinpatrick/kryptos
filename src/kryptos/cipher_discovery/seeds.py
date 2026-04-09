"""Curated seed list for cipher discovery.

Seeds are organized by priority tier and category.
Each seed includes synonyms and contextual metadata.

[POLICY] This is not an exhaustive list. The discovery pipeline expands from these.
[PUBLIC FACT] Sanborn's handwritten notes reference: Beaufort Cipher, Compass Cipher,
    Morse Code, Alphabet Code. "Compass Cipher" and "Alphabet Code" are ambiguous.
[PUBLIC FACT] Ed Scheidt suggested K4 may use a method not in standard literature.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Seed:
    """A seed term for cipher discovery."""
    term: str
    priority: int  # 1=highest, 3=lowest
    category: str
    synonyms: list[str] = field(default_factory=list)
    notes: str = ""
    sanborn_referenced: bool = False


# =============================================================================
# TIER 1: Directly referenced by Sanborn/Scheidt or strongly K4-relevant
# =============================================================================

TIER_1_SEEDS = [
    Seed("compass cipher", 1, "spatial",
         synonyms=["compass code", "bearing cipher", "direction cipher",
                    "cardinal cipher", "azimuth cipher", "compass rose cipher",
                    "compass point cipher"],
         notes="Sanborn handwritten notes. Ambiguous - may be nonstandard.",
         sanborn_referenced=True),
    Seed("alphabet code", 1, "substitution",
         synonyms=["alphabet cipher", "alphabetical code", "letter code",
                    "ABC cipher", "alphabet substitution"],
         notes="Sanborn handwritten notes. Ambiguous - could be many things.",
         sanborn_referenced=True),
    Seed("Beaufort cipher", 1, "polyalphabetic",
         synonyms=["Beaufort tableau", "Beaufort square", "Beaufort table",
                    "reciprocal cipher"],
         notes="Sanborn handwritten notes. K1-K3 confirmed Vigenere family.",
         sanborn_referenced=True),
    Seed("Morse code cipher", 1, "encoding",
         synonyms=["Morse fractionation", "Morse cipher", "Morse substitution",
                    "Pollux cipher", "Morbit cipher"],
         notes="Sanborn handwritten notes. Fractionation via Morse is a known technique.",
         sanborn_referenced=True),
    Seed("turning grille", 1, "grille",
         synonyms=["Fleissner grille", "Cardano grille", "rotating grille",
                    "grille cipher", "Cardano grill", "revolving grille",
                    "Fleissner grid"],
         notes="Tested extensively. Open as one layer of multi-layer."),
    Seed("running key cipher", 1, "polyalphabetic",
         synonyms=["running key", "book key cipher", "long key cipher",
                    "running key Vigenere", "running key Beaufort"],
         notes="Open attack surface. Model survives Bean."),
    Seed("chart-based cipher", 1, "bespoke",
         synonyms=["coding chart", "cipher chart", "code breaker overlay",
                    "overlay cipher", "transparency cipher"],
         notes="Archive shows 'Code Breaker' overlay. Bespoke mechanism."),
]

# =============================================================================
# TIER 2: Known hand ciphers with K4-relevant properties
# =============================================================================

TIER_2_SEEDS = [
    # Transposition family
    Seed("columnar transposition", 2, "transposition",
         synonyms=["columnar cipher", "column transposition",
                    "keyed columnar", "incomplete columnar"]),
    Seed("double transposition", 2, "transposition",
         synonyms=["double columnar", "two-pass transposition",
                    "WWII double transposition"]),
    Seed("route cipher", 2, "transposition",
         synonyms=["route transposition", "path cipher", "spiral cipher",
                    "diagonal cipher", "serpentine cipher", "boustrophedon cipher"]),
    Seed("Myszkowski transposition", 2, "transposition",
         synonyms=["Myszkowski cipher", "Myszkowski"]),
    Seed("AMSCO cipher", 2, "transposition",
         synonyms=["AMSCO transposition", "alternating mono-digraphic"]),
    Seed("rail fence cipher", 2, "transposition",
         synonyms=["zigzag cipher", "zigzag transposition", "rail fence"]),

    # Fractionation family
    Seed("Polybius square", 2, "fractionation",
         synonyms=["Polybius cipher", "Polybius checkerboard", "5x5 grid cipher"]),
    Seed("straddling checkerboard", 2, "fractionation",
         synonyms=["straddle cipher", "straddling board", "CT-35 checkerboard"]),
    Seed("ADFGVX cipher", 2, "fractionation",
         synonyms=["ADFGX cipher", "ADFGVX", "German WWI cipher",
                    "Nebel cipher"]),
    Seed("Delastelle cipher", 2, "fractionation",
         synonyms=["bifid cipher", "trifid cipher", "four-square cipher",
                    "Delastelle bifid", "Delastelle trifid"]),
    Seed("Pollux cipher", 2, "fractionation",
         synonyms=["Pollux", "Morse fractionation cipher"]),

    # Polyalphabetic family
    Seed("Nihilist cipher", 2, "polyalphabetic",
         synonyms=["Nihilist substitution", "Russian Nihilist cipher",
                    "Nihilist transposition"]),
    Seed("VIC cipher", 2, "polyalphabetic",
         synonyms=["VIC", "Kingdom cipher", "Soviet spy cipher",
                    "Hayhanen cipher"]),
    Seed("interrupted key cipher", 2, "polyalphabetic",
         synonyms=["interrupted key", "interrupted keyword",
                    "broken key cipher", "segmented key"]),
    Seed("Porta cipher", 2, "polyalphabetic",
         synonyms=["Porta", "Giambattista della Porta cipher",
                    "Porta reciprocal cipher"]),
    Seed("Gronsfeld cipher", 2, "polyalphabetic",
         synonyms=["Gronsfeld", "numeric Vigenere"]),
    Seed("Quagmire cipher", 2, "polyalphabetic",
         synonyms=["Quagmire I", "Quagmire II", "Quagmire III",
                    "Quagmire IV", "mixed-alphabet Vigenere"]),

    # Mechanical/device ciphers done by hand
    Seed("Wheatstone cipher", 2, "mechanical",
         synonyms=["Wheatstone Cryptograph", "Playfair wheel",
                    "Wheatstone device"]),
    Seed("Hagelin cipher", 2, "mechanical",
         synonyms=["Hagelin machine", "C-35", "M-209", "CX-52",
                    "pin-and-lug cipher"]),
    Seed("Chaocipher", 2, "mechanical",
         synonyms=["Chaocipher", "Byrne cipher machine"]),
    Seed("Bazeries cylinder", 2, "mechanical",
         synonyms=["Bazeries cipher", "Jefferson wheel",
                    "cipher cylinder", "wheel cipher", "strip cipher",
                    "M-94", "M-138"]),

    # Book/text ciphers
    Seed("book cipher", 2, "substitution",
         synonyms=["book code", "Beale cipher", "Beale code",
                    "dictionary cipher", "page-line-word cipher"]),
    Seed("null cipher", 2, "steganographic",
         synonyms=["null code", "open code", "concealment cipher",
                    "first-letter cipher", "acrostic cipher"]),

    # Military/historical
    Seed("TICOM cipher", 2, "military",
         synonyms=["TICOM", "Target Intelligence Committee",
                    "German field cipher", "Wehrmacht cipher"]),
    Seed("NSA historical cipher", 2, "military",
         synonyms=["NSA cipher history", "COMINT cipher",
                    "SIGINT historical cipher"]),
    Seed("field cipher manual", 2, "military",
         synonyms=["army cipher manual", "military field cipher",
                    "tactical cipher", "combat cipher"]),
    Seed("one-time pad variant", 2, "substitution",
         synonyms=["one-time pad", "OTP", "Vernam cipher",
                    "additive cipher", "key tape cipher"]),

    # Playfair variants
    Seed("Playfair cipher", 2, "fractionation",
         synonyms=["Playfair", "Playfair square", "Wheatstone-Playfair"]),
    Seed("two-square cipher", 2, "fractionation",
         synonyms=["double Playfair", "two-square",
                    "Playfair variant"]),
    Seed("four-square cipher", 2, "fractionation",
         synonyms=["four-square", "Delastelle four-square"]),

    # Misc well-known
    Seed("Gromark cipher", 2, "polyalphabetic",
         synonyms=["Gromark", "grille-marked cipher",
                    "Fibonacci key cipher"]),
    Seed("Slidefair cipher", 2, "fractionation",
         synonyms=["Slidefair", "sliding Playfair"]),
]

# =============================================================================
# TIER 3: Obscure, edge-case, or poorly-indexed systems
# =============================================================================

TIER_3_SEEDS = [
    # Obscure historical
    Seed("Trithemius cipher", 3, "polyalphabetic",
         synonyms=["Trithemius tableau", "Ave Maria cipher",
                    "Steganographia cipher", "progressive key"]),
    Seed("Alberti cipher disk", 3, "mechanical",
         synonyms=["Alberti disk", "Alberti cipher", "cipher disk",
                    "cipher wheel"]),
    Seed("Vatsyayana cipher", 3, "substitution",
         synonyms=["Kama Sutra cipher", "Mlecchita Vikalpa",
                    "secret writing India"]),
    Seed("Scytale cipher", 3, "transposition",
         synonyms=["Scytale", "Spartan cipher", "staff cipher",
                    "rod cipher"]),
    Seed("Pigpen cipher", 3, "substitution",
         synonyms=["Freemason cipher", "Masonic cipher",
                    "pigpen", "tic-tac-toe cipher",
                    "Knights Templar cipher"]),
    Seed("Solitaire cipher", 3, "substitution",
         synonyms=["Pontifex cipher", "Schneier Solitaire",
                    "playing card cipher"]),
    Seed("Nihilist transposition", 3, "transposition",
         synonyms=["Russian Nihilist transposition",
                    "Nihilist columnar"]),
    Seed("tap code", 3, "signaling",
         synonyms=["prison tap code", "Polybius tap",
                    "knock code", "POW tap code"]),
    Seed("clock cipher", 3, "spatial",
         synonyms=["clock code", "clock position cipher",
                    "time cipher", "dial cipher",
                    "Berlin clock cipher"],
         notes="Berlin Clock is a known Kryptos theme."),
    Seed("grid cipher", 3, "spatial",
         synonyms=["grid code", "coordinate cipher",
                    "map grid cipher", "grid reference cipher"]),
    Seed("semaphore cipher", 3, "signaling",
         synonyms=["flag semaphore code", "semaphore alphabet",
                    "visual signaling cipher"]),
    Seed("heliograph cipher", 3, "signaling",
         synonyms=["heliograph code", "mirror signal cipher",
                    "sun telegraph cipher"]),

    # Scout/amateur ciphers
    Seed("Boy Scout cipher", 3, "educational",
         synonyms=["Scout code", "Baden-Powell cipher",
                    "camping cipher"]),
    Seed("dancing men cipher", 3, "substitution",
         synonyms=["dancing men", "Sherlock Holmes cipher",
                    "stick figure cipher"]),

    # Bespoke/artistic
    Seed("steganographic cipher", 3, "steganographic",
         synonyms=["visual steganography cipher", "hidden message cipher",
                    "concealment cipher art"]),
    Seed("coordinate cipher", 3, "spatial",
         synonyms=["latitude longitude cipher", "geographic cipher",
                    "geodetic cipher", "map coordinate cipher"]),
    Seed("musical cipher", 3, "symbolic",
         synonyms=["music cipher", "note cipher", "Elgar cipher",
                    "Dorabella cipher"]),

    # Less common variants
    Seed("Monome-Dinome cipher", 3, "fractionation",
         synonyms=["monome dinome", "mono-dinome",
                    "variable-length substitution"]),
    Seed("homophonic cipher", 3, "substitution",
         synonyms=["homophonic substitution", "multiple-equivalent cipher",
                    "nomenclator cipher"]),
    Seed("nomenclator", 3, "substitution",
         synonyms=["nomenclator cipher", "Renaissance cipher",
                    "diplomatic cipher code", "Great Cipher"]),
    Seed("tomographic cipher", 3, "fractionation",
         synonyms=["tomographic", "layer cipher",
                    "fractionation by layer"]),
    Seed("stencil cipher", 3, "grille",
         synonyms=["mask cipher", "template cipher",
                    "Richelieu cipher", "window cipher"]),
    Seed("Rasterschlussel 44", 3, "grille",
         synonyms=["RS44", "Rasterschlussel", "German grid cipher",
                    "WWII grid mask cipher"]),
    Seed("transposition key phrase", 3, "transposition",
         synonyms=["keyword transposition", "phrase transposition",
                    "disrupted transposition", "irregular transposition"]),
    Seed("BATCO cipher", 3, "military",
         synonyms=["BATCO", "British Army tactical code",
                    "SLIDEX", "tactical battlefield cipher"]),
    Seed("M-94 cipher device", 3, "mechanical",
         synonyms=["M-94", "Army strip cipher",
                    "cylinder cipher device"]),
    Seed("Ubchi cipher", 3, "transposition",
         synonyms=["Ubchi", "German WWI transposition",
                    "double columnar German"]),
    Seed("ADFGX hand cipher", 3, "fractionation",
         synonyms=["ADFGX", "Fritz Nebel cipher",
                    "polybius transposition hybrid"]),
    Seed("Phillips cipher", 3, "substitution",
         synonyms=["Phillips", "progressive Playfair",
                    "Phillips classical cipher"]),
    Seed("Grandpre cipher", 3, "substitution",
         synonyms=["Grandpre", "Grand Pre", "digit substitution",
                    "10x10 cipher table"]),
    Seed("Cadenus cipher", 3, "transposition",
         synonyms=["Cadenus", "keyed period transposition"]),
    Seed("Swagman cipher", 3, "transposition",
         synonyms=["Swagman", "Australian cipher"]),
    Seed("Redefence cipher", 3, "transposition",
         synonyms=["Redefence", "redefence transposition",
                    "keyed rail fence"]),
    Seed("Tri-square cipher", 3, "fractionation",
         synonyms=["tri-square", "three-square", "trisquare"]),
    Seed("conjugated matrix bifid", 3, "fractionation",
         synonyms=["CM bifid", "conjugated bifid",
                    "seriated bifid"]),
    Seed("periodic Beaufort", 3, "polyalphabetic",
         synonyms=["Beaufort variant", "mixed Beaufort",
                    "Beaufort with keyword alphabet"]),
    Seed("Grille-masked cipher", 3, "grille",
         synonyms=["mask then encipher", "grille masking",
                    "null insertion grille"]),
    Seed("progressive cipher", 3, "polyalphabetic",
         synonyms=["progressive key", "progressive substitution",
                    "Trithemius progression"]),
    Seed("checkerboard cipher", 3, "fractionation",
         synonyms=["polybius variant", "numbered checkerboard",
                    "Russian checkerboard"]),

    # Navigation/direction themed (K4-specific interest)
    Seed("bearing cipher", 3, "spatial",
         synonyms=["bearing code", "azimuth code",
                    "navigation cipher", "heading cipher"]),
    Seed("sundial cipher", 3, "spatial",
         synonyms=["sundial code", "gnomon cipher",
                    "shadow cipher"]),
    Seed("astrolabe cipher", 3, "spatial",
         synonyms=["astrolabe code", "celestial cipher",
                    "star chart cipher"]),
]


def get_all_seeds() -> list[Seed]:
    """Return all seeds sorted by priority."""
    return sorted(
        TIER_1_SEEDS + TIER_2_SEEDS + TIER_3_SEEDS,
        key=lambda s: s.priority
    )


def get_seeds_by_tier(tier: int) -> list[Seed]:
    """Return seeds for a specific priority tier."""
    mapping = {1: TIER_1_SEEDS, 2: TIER_2_SEEDS, 3: TIER_3_SEEDS}
    return mapping.get(tier, [])


def get_synonym_map() -> dict[str, list[str]]:
    """Return a mapping of canonical term -> all synonyms."""
    result = {}
    for seed in get_all_seeds():
        key = seed.term.lower()
        result[key] = [s.lower() for s in seed.synonyms]
    return result


def get_all_terms() -> set[str]:
    """Return all unique terms (seeds + synonyms) lowercased."""
    terms = set()
    for seed in get_all_seeds():
        terms.add(seed.term.lower())
        for syn in seed.synonyms:
            terms.add(syn.lower())
    return terms
