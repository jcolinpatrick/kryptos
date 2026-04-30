"""Real-K4 project-safe clue registry (v2: provenance-tiered).

Purpose
-------
Source of clue keywords and clue text for the real-K4 HCC audit
(``--real-k4-hcc-audit``). Every entry is grounded in PUBLIC,
PROJECT-SAFE Kryptos K4 material (disclosed cribs, K1/K2/K3 plaintexts,
the public Sanborn/Scheidt/CIA installation record, K2-derived
geodetic vocabulary, generic cipher mechanics).

The registry contains NO K4Bench challenge data, NO K4Bench plaintexts,
NO synthetic clue packs, NO retired-hypothesis anchors.

v2 schema (2026-04-28)
----------------------
v1 was a 9-entry uppercase-string list with provenance labels. v2
restructures around five tiers that group entries by privilege and
expected use, and adds explicit role flags so the audit can keep
trigger-only tokens out of substitution / alphabet / transposition
keyword pools.

Tiers (in priority order):

  1. ``core_public_cribs``         — disclosed K4 crib content
                                     (EAST, NORTHEAST, EASTNORTHEAST,
                                     BERLIN, CLOCK, BERLINCLOCK, ENE)
                                     and obvious public splits/
                                     compounds. Strongest tier; every
                                     entry is usable as substitution /
                                     alphabet / transposition keyword.
  2. ``kryptos_plaintext_legacy``  — distinctive K1/K2/K3 plaintext
                                     words plus the K1/K2 cipher
                                     keywords (PALIMPSEST, ABSCISSA)
                                     and Sanborn's deliberate
                                     misspellings (IQLUSION,
                                     UNDERGRUUND, DESPARATLY).
                                     Public, well-documented;
                                     usable as keywords.
  3. ``sculpture_context``         — installation / creator vocabulary
                                     (KRYPTOS, SANBORN, SCHEIDT, CIA,
                                     COURTYARD, COPPER, STONE,
                                     COMPASS, MORSE, LODESTONE).
                                     Public installation record.
  4. ``geodetic_coordinate``       — public K2 coordinate vocabulary
                                     (LATITUDE, LONGITUDE, DEGREES,
                                     MINUTES, SECONDS, NORTH, WEST).
                                     The K2 plaintext encodes specific
                                     coordinates; this tier holds the
                                     associated geodetic terminology.
  5. ``procedural_terms``          — generic cipher-mechanical
                                     vocabulary (ROUTE, READ, LAYER,
                                     MASK, NULL, GRID, COLUMN, ROW,
                                     FOLD, MIRROR, REVERSE). Used
                                     primarily as TRIGGER text rather
                                     than privileged key guesses;
                                     ``trigger_only=True`` on most.

Role flags per entry:

  * ``use_as_substitution`` — eligible to be the keyword for
                              vigenere / beaufort / variant_beaufort
                              substitution layers
  * ``use_as_alphabet``     — eligible as the keyword_mixed alphabet
                              keyword (Quagmire-style)
  * ``use_as_transposition``— eligible as the keyword for columnar /
                              myszkowski transposition layers
  * ``trigger_only``        — token appears in the audit clue text
                              for trigger-detection purposes only;
                              never enters any keyword pool

Module separation contract
--------------------------
This module imports nothing from ``kryptosbot.bench_loader``,
``kryptosbot.bench_fallback``, ``kryptosbot.bench_attempts``, or
``bench/k4bench/`` data files. The audit subsystem treats this
firewall as a load-time invariant; a regression that adds a bench
import here will fail the firewall test in
``tests/test_real_k4_hcc_audit.py``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Sequence


# ---------------------------------------------------------------------------
# Tier names (ordered by priority — core first → procedural last)
# ---------------------------------------------------------------------------

TIER_CORE_PUBLIC_CRIBS: str = "core_public_cribs"
TIER_KRYPTOS_PLAINTEXT_LEGACY: str = "kryptos_plaintext_legacy"
TIER_SCULPTURE_CONTEXT: str = "sculpture_context"
TIER_GEODETIC_COORDINATE: str = "geodetic_coordinate"
TIER_PROCEDURAL_TERMS: str = "procedural_terms"

CLUE_TIERS_IN_ORDER: tuple[str, ...] = (
    TIER_CORE_PUBLIC_CRIBS,
    TIER_KRYPTOS_PLAINTEXT_LEGACY,
    TIER_SCULPTURE_CONTEXT,
    TIER_GEODETIC_COORDINATE,
    TIER_PROCEDURAL_TERMS,
)

_VALID_TIERS: frozenset[str] = frozenset(CLUE_TIERS_IN_ORDER)


# Tier preset shortcuts. Each preset maps to a tuple of tier names in
# priority order. Presets give the CLI a small set of well-named
# configurations without forcing operators to remember the full tier
# list.
TIER_PRESETS: dict[str, tuple[str, ...]] = {
    "core": (TIER_CORE_PUBLIC_CRIBS,),
    "core_legacy": (
        TIER_CORE_PUBLIC_CRIBS,
        TIER_KRYPTOS_PLAINTEXT_LEGACY,
    ),
    "core_legacy_sculpture": (
        TIER_CORE_PUBLIC_CRIBS,
        TIER_KRYPTOS_PLAINTEXT_LEGACY,
        TIER_SCULPTURE_CONTEXT,
    ),
    "full": CLUE_TIERS_IN_ORDER,
}


# ---------------------------------------------------------------------------
# ClueWordEntry dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClueWordEntry:
    """One project-safe clue keyword with full provenance + role
    metadata.

    Frozen + hashable so the registry can deduplicate entries by
    ``normalized`` token.

    Fields:
      token         — display form (uppercase A-Z)
      normalized    — uppercase A-Z; deduplication key. Usually equal
                      to ``token`` but distinct when the token has a
                      decorative form (e.g. EASTNORTHEAST as compound
                      vs a normalized base of EAST).
      tier          — one of the CLUE_TIERS_IN_ORDER values
      provenance    — short string identifying the source ("public_crib_split",
                      "k1_plaintext_word", "k2_plaintext_word",
                      "k3_plaintext_word", "kryptos_misspelling",
                      "k1_k2_keyword", "sanborn_creator",
                      "scheidt_creator", "cia_courtyard",
                      "sculpture_material", "k2_coordinate",
                      "compass_direction", "cipher_mechanic_trigger")
      use_as_substitution  — eligible as Vig/Beau/varBeau keyword
      use_as_alphabet      — eligible as keyword_mixed alphabet
      use_as_transposition — eligible as columnar/myszkowski keyword
      trigger_only         — appears in clue text for trigger
                              detection; never enters keyword pool
      derived_forms        — additional A-Z compounds / reversals /
                              abbreviations / splits that the audit
                              MAY enumerate alongside ``token`` when
                              ``include_derived=True`` is requested.
                              Always uppercase A-Z.
    """
    token: str
    normalized: str
    tier: str
    provenance: str
    use_as_substitution: bool = True
    use_as_alphabet: bool = True
    use_as_transposition: bool = True
    trigger_only: bool = False
    derived_forms: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.token.isalpha() or not self.token.isupper():
            raise ValueError(
                f"ClueWordEntry token must be uppercase A-Z; got {self.token!r}"
            )
        if not self.normalized.isalpha() or not self.normalized.isupper():
            raise ValueError(
                f"ClueWordEntry normalized must be uppercase A-Z; "
                f"got {self.normalized!r}"
            )
        if self.tier not in _VALID_TIERS:
            raise ValueError(
                f"ClueWordEntry tier {self.tier!r} not in {sorted(_VALID_TIERS)}"
            )
        if self.trigger_only and (
            self.use_as_substitution
            or self.use_as_alphabet
            or self.use_as_transposition
        ):
            raise ValueError(
                f"ClueWordEntry {self.token!r}: trigger_only=True is "
                "incompatible with use_as_* flags being True; trigger-"
                "only tokens never enter keyword pools."
            )
        for derived in self.derived_forms:
            if not derived.isalpha() or not derived.isupper():
                raise ValueError(
                    f"ClueWordEntry {self.token!r}: derived_form "
                    f"{derived!r} must be uppercase A-Z"
                )

    def to_dict(self) -> dict:
        return {
            "token": self.token,
            "normalized": self.normalized,
            "tier": self.tier,
            "provenance": self.provenance,
            "use_as_substitution": self.use_as_substitution,
            "use_as_alphabet": self.use_as_alphabet,
            "use_as_transposition": self.use_as_transposition,
            "trigger_only": self.trigger_only,
            "derived_forms": list(self.derived_forms),
        }


# ---------------------------------------------------------------------------
# Registry contents
# ---------------------------------------------------------------------------
#
# IMPORTANT: every entry below carries an explicit ``provenance`` label
# pointing at a public, project-safe source. The entries are listed in
# tier order so a reviewer can audit each tier's contents in one
# section.

_REGISTRY_V2: tuple[ClueWordEntry, ...] = (
    # ---------------------------------------------------------------
    # Tier 1: core_public_cribs
    # ---------------------------------------------------------------
    # Disclosed K4 cribs (PUBLIC FACT — Sanborn 2010/2014/2020):
    #   positions 21-33 = "EASTNORTHEAST"
    #   positions 63-73 = "BERLINCLOCK"
    # Each crib is split into its semantic components and exposed as
    # both the split form and the full compound. ENE is the standard
    # compass abbreviation for east-northeast, included as a
    # short-keyword candidate.
    ClueWordEntry(
        token="EAST", normalized="EAST",
        tier=TIER_CORE_PUBLIC_CRIBS,
        provenance="public_crib_split",
        derived_forms=("E",),
    ),
    ClueWordEntry(
        token="NORTHEAST", normalized="NORTHEAST",
        tier=TIER_CORE_PUBLIC_CRIBS,
        provenance="public_crib_split",
        derived_forms=("NE",),
    ),
    ClueWordEntry(
        token="EASTNORTHEAST", normalized="EASTNORTHEAST",
        tier=TIER_CORE_PUBLIC_CRIBS,
        provenance="public_crib_full",
    ),
    ClueWordEntry(
        token="BERLIN", normalized="BERLIN",
        tier=TIER_CORE_PUBLIC_CRIBS,
        provenance="public_crib_split",
    ),
    ClueWordEntry(
        token="CLOCK", normalized="CLOCK",
        tier=TIER_CORE_PUBLIC_CRIBS,
        provenance="public_crib_split",
    ),
    ClueWordEntry(
        token="BERLINCLOCK", normalized="BERLINCLOCK",
        tier=TIER_CORE_PUBLIC_CRIBS,
        provenance="public_crib_full",
    ),
    ClueWordEntry(
        token="ENE", normalized="ENE",
        tier=TIER_CORE_PUBLIC_CRIBS,
        provenance="public_crib_compass_abbreviation",
    ),

    # ---------------------------------------------------------------
    # Tier 2: kryptos_plaintext_legacy
    # ---------------------------------------------------------------
    # K1 plaintext distinctive words and the deliberate misspelling.
    ClueWordEntry(
        token="IQLUSION", normalized="IQLUSION",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="kryptos_misspelling_k1",
    ),
    ClueWordEntry(
        token="ABSENCE", normalized="ABSENCE",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="k1_plaintext_word",
    ),
    ClueWordEntry(
        token="SHADING", normalized="SHADING",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="k1_plaintext_word",
    ),
    ClueWordEntry(
        token="SUBTLE", normalized="SUBTLE",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="k1_plaintext_word",
    ),
    ClueWordEntry(
        token="NUANCE", normalized="NUANCE",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="k1_plaintext_word",
    ),
    # K2 plaintext distinctive words and the K2 deliberate misspelling.
    # K2 plaintext is a classified-document-style narrative about a
    # buried object; the words below are publicly disclosed.
    ClueWordEntry(
        token="INVISIBLE", normalized="INVISIBLE",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="k2_plaintext_word",
    ),
    ClueWordEntry(
        token="MAGNETIC", normalized="MAGNETIC",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="k2_plaintext_word",
    ),
    ClueWordEntry(
        token="FIELD", normalized="FIELD",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="k2_plaintext_word",
    ),
    ClueWordEntry(
        token="LANGLEY", normalized="LANGLEY",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="k2_plaintext_word",
    ),
    ClueWordEntry(
        token="UNDERGRUUND", normalized="UNDERGRUUND",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="kryptos_misspelling_k2",
    ),
    ClueWordEntry(
        token="DESPARATLY", normalized="DESPARATLY",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="kryptos_misspelling_k2",
    ),
    # K3 plaintext distinctive words. K3 paraphrases Howard Carter's
    # Tutankhamun tomb account; PASSAGE / BURIED are part of that
    # narrative.
    ClueWordEntry(
        token="PASSAGE", normalized="PASSAGE",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="k3_plaintext_word",
    ),
    ClueWordEntry(
        token="BURIED", normalized="BURIED",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="k3_plaintext_word",
    ),
    ClueWordEntry(
        token="DEBRIS", normalized="DEBRIS",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="k3_plaintext_word",
    ),
    ClueWordEntry(
        token="CHAMBER", normalized="CHAMBER",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="k3_plaintext_word",
    ),
    # K1/K2 cipher KEYWORDS (the actual cipher keys used to encrypt
    # K1 and K2 — public, well-documented).
    ClueWordEntry(
        token="PALIMPSEST", normalized="PALIMPSEST",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="k1_cipher_keyword",
    ),
    ClueWordEntry(
        token="ABSCISSA", normalized="ABSCISSA",
        tier=TIER_KRYPTOS_PLAINTEXT_LEGACY,
        provenance="k2_cipher_keyword",
    ),

    # ---------------------------------------------------------------
    # Tier 3: sculpture_context
    # ---------------------------------------------------------------
    # The sculpture name itself, its creators, and public installation
    # vocabulary. Every entry is well-documented in the public record
    # (CIA press releases, Sanborn artist statements, news coverage).
    ClueWordEntry(
        token="KRYPTOS", normalized="KRYPTOS",
        tier=TIER_SCULPTURE_CONTEXT,
        provenance="sculpture_name",
    ),
    ClueWordEntry(
        token="SANBORN", normalized="SANBORN",
        tier=TIER_SCULPTURE_CONTEXT,
        provenance="sanborn_creator",
    ),
    ClueWordEntry(
        token="SCHEIDT", normalized="SCHEIDT",
        tier=TIER_SCULPTURE_CONTEXT,
        provenance="scheidt_creator",
    ),
    ClueWordEntry(
        token="CIA", normalized="CIA",
        tier=TIER_SCULPTURE_CONTEXT,
        provenance="cia_courtyard",
    ),
    ClueWordEntry(
        token="COURTYARD", normalized="COURTYARD",
        tier=TIER_SCULPTURE_CONTEXT,
        provenance="cia_courtyard",
    ),
    ClueWordEntry(
        token="COPPER", normalized="COPPER",
        tier=TIER_SCULPTURE_CONTEXT,
        provenance="sculpture_material",
    ),
    ClueWordEntry(
        token="STONE", normalized="STONE",
        tier=TIER_SCULPTURE_CONTEXT,
        provenance="sculpture_material",
    ),
    ClueWordEntry(
        token="COMPASS", normalized="COMPASS",
        tier=TIER_SCULPTURE_CONTEXT,
        provenance="sculpture_companion_artwork",
    ),
    ClueWordEntry(
        token="MORSE", normalized="MORSE",
        tier=TIER_SCULPTURE_CONTEXT,
        provenance="sculpture_morse_code",
    ),
    ClueWordEntry(
        token="LODESTONE", normalized="LODESTONE",
        tier=TIER_SCULPTURE_CONTEXT,
        provenance="sculpture_companion_artwork",
    ),

    # ---------------------------------------------------------------
    # Tier 4: geodetic_coordinate
    # ---------------------------------------------------------------
    # K2 plaintext encodes coordinates near CIA HQ (38°57′6.5″ N
    # 77°8′44″ W). The vocabulary below derives from that public
    # K2 disclosure.
    ClueWordEntry(
        token="LATITUDE", normalized="LATITUDE",
        tier=TIER_GEODETIC_COORDINATE,
        provenance="k2_coordinate_axis",
    ),
    ClueWordEntry(
        token="LONGITUDE", normalized="LONGITUDE",
        tier=TIER_GEODETIC_COORDINATE,
        provenance="k2_coordinate_axis",
    ),
    ClueWordEntry(
        token="DEGREES", normalized="DEGREES",
        tier=TIER_GEODETIC_COORDINATE,
        provenance="coordinate_unit",
    ),
    ClueWordEntry(
        token="MINUTES", normalized="MINUTES",
        tier=TIER_GEODETIC_COORDINATE,
        provenance="coordinate_unit",
    ),
    ClueWordEntry(
        token="SECONDS", normalized="SECONDS",
        tier=TIER_GEODETIC_COORDINATE,
        provenance="coordinate_unit",
    ),
    ClueWordEntry(
        token="NORTH", normalized="NORTH",
        tier=TIER_GEODETIC_COORDINATE,
        provenance="compass_direction",
    ),
    ClueWordEntry(
        token="WEST", normalized="WEST",
        tier=TIER_GEODETIC_COORDINATE,
        provenance="compass_direction",
    ),

    # ---------------------------------------------------------------
    # Tier 5: procedural_terms
    # ---------------------------------------------------------------
    # Generic cipher-mechanical vocabulary. Every entry is
    # ``trigger_only=True`` — these tokens drive trigger-detection in
    # the audit clue text but never become substitution / alphabet /
    # transposition keys, because they are too generic to function as
    # privileged key guesses on K4.
    ClueWordEntry(
        token="ROUTE", normalized="ROUTE",
        tier=TIER_PROCEDURAL_TERMS,
        provenance="cipher_mechanic_trigger",
        use_as_substitution=False,
        use_as_alphabet=False,
        use_as_transposition=False,
        trigger_only=True,
    ),
    ClueWordEntry(
        token="READ", normalized="READ",
        tier=TIER_PROCEDURAL_TERMS,
        provenance="cipher_mechanic_trigger",
        use_as_substitution=False,
        use_as_alphabet=False,
        use_as_transposition=False,
        trigger_only=True,
    ),
    ClueWordEntry(
        token="LAYER", normalized="LAYER",
        tier=TIER_PROCEDURAL_TERMS,
        provenance="cipher_mechanic_trigger",
        use_as_substitution=False,
        use_as_alphabet=False,
        use_as_transposition=False,
        trigger_only=True,
    ),
    ClueWordEntry(
        token="MASK", normalized="MASK",
        tier=TIER_PROCEDURAL_TERMS,
        provenance="cipher_mechanic_trigger",
        use_as_substitution=False,
        use_as_alphabet=False,
        use_as_transposition=False,
        trigger_only=True,
    ),
    ClueWordEntry(
        token="GRID", normalized="GRID",
        tier=TIER_PROCEDURAL_TERMS,
        provenance="cipher_mechanic_trigger",
        use_as_substitution=False,
        use_as_alphabet=False,
        use_as_transposition=False,
        trigger_only=True,
    ),
    ClueWordEntry(
        token="COLUMN", normalized="COLUMN",
        tier=TIER_PROCEDURAL_TERMS,
        provenance="cipher_mechanic_trigger",
        use_as_substitution=False,
        use_as_alphabet=False,
        use_as_transposition=False,
        trigger_only=True,
    ),
    ClueWordEntry(
        token="ROW", normalized="ROW",
        tier=TIER_PROCEDURAL_TERMS,
        provenance="cipher_mechanic_trigger",
        use_as_substitution=False,
        use_as_alphabet=False,
        use_as_transposition=False,
        trigger_only=True,
    ),
    ClueWordEntry(
        token="FOLD", normalized="FOLD",
        tier=TIER_PROCEDURAL_TERMS,
        provenance="cipher_mechanic_trigger",
        use_as_substitution=False,
        use_as_alphabet=False,
        use_as_transposition=False,
        trigger_only=True,
    ),
    ClueWordEntry(
        token="REVERSE", normalized="REVERSE",
        tier=TIER_PROCEDURAL_TERMS,
        provenance="cipher_mechanic_trigger",
        use_as_substitution=False,
        use_as_alphabet=False,
        use_as_transposition=False,
        trigger_only=True,
    ),
)


# ---------------------------------------------------------------------------
# Registry accessors
# ---------------------------------------------------------------------------


def all_entries() -> list[ClueWordEntry]:
    """Return every registry entry in canonical order (tier-priority,
    document order within tier)."""
    return list(_REGISTRY_V2)


def entries_by_tier(tier: str) -> list[ClueWordEntry]:
    if tier not in _VALID_TIERS:
        raise ValueError(
            f"unknown tier {tier!r}; valid tiers: "
            f"{sorted(_VALID_TIERS)}"
        )
    return [e for e in _REGISTRY_V2 if e.tier == tier]


def resolve_tier_selector(
    selector: Optional[str | Sequence[str]],
) -> tuple[str, ...]:
    """Resolve a tier selector to a canonical tier-list.

    ``selector`` may be:
      * None or "" → all tiers (CLUE_TIERS_IN_ORDER)
      * a preset name in TIER_PRESETS ("core" / "core_legacy" /
        "core_legacy_sculpture" / "full")
      * a comma-separated list of tier names
      * a sequence of tier names

    Returns a tuple of tier names in canonical priority order.
    Unknown tier names raise ValueError.
    """
    if selector is None or selector == "":
        return CLUE_TIERS_IN_ORDER
    if isinstance(selector, str):
        if selector in TIER_PRESETS:
            return TIER_PRESETS[selector]
        # Comma-separated list.
        names = [s.strip() for s in selector.split(",") if s.strip()]
    else:
        names = [str(s).strip() for s in selector if str(s).strip()]
    out: list[str] = []
    seen: set[str] = set()
    for name in names:
        if name not in _VALID_TIERS:
            raise ValueError(
                f"unknown tier name {name!r}; valid tiers: "
                f"{sorted(_VALID_TIERS)} or preset names: "
                f"{sorted(TIER_PRESETS)}"
            )
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
    # Sort into canonical priority order.
    return tuple(t for t in CLUE_TIERS_IN_ORDER if t in seen)


def real_k4_clue_keywords(
    *,
    tiers: Optional[str | Sequence[str]] = None,
    keyword_role: Optional[str] = None,
    include_derived: bool = False,
    max_keywords: int = 60,
) -> list[str]:
    """Return clue keywords filtered by tier and role.

    Args:
      tiers: tier selector (None = all, preset name, comma-list, or
        sequence). See ``resolve_tier_selector``.
      keyword_role: filter to entries whose ``use_as_<role>=True``.
        One of "substitution", "alphabet", "transposition", or None
        (no role filter — but ``trigger_only=True`` entries are
        always excluded since they are not keyword candidates).
      include_derived: also include derived forms (compounds,
        reversals, abbreviations, splits) after the base tokens.
      max_keywords: hard cap on the returned list. The cap is
        applied AFTER tier/role filtering and BEFORE derived-form
        expansion if ``include_derived=True``. The HCC catalog
        consumes only the first 3-15 keywords meaningfully (role-
        permutation + standalone family); the cap prevents the
        registry from exploding the dispatch universe.

    Returns: a list of uppercase A-Z tokens in tier-priority order,
    deduplicated by ``normalized`` field.
    """
    valid_roles = ("substitution", "alphabet", "transposition")
    if keyword_role is not None and keyword_role not in valid_roles:
        raise ValueError(
            f"keyword_role must be in {valid_roles} or None; "
            f"got {keyword_role!r}"
        )
    selected_tiers = set(resolve_tier_selector(tiers))
    out: list[str] = []
    seen: set[str] = set()
    for entry in _REGISTRY_V2:
        if entry.tier not in selected_tiers:
            continue
        if entry.trigger_only:
            continue
        if keyword_role == "substitution" and not entry.use_as_substitution:
            continue
        if keyword_role == "alphabet" and not entry.use_as_alphabet:
            continue
        if keyword_role == "transposition" and not entry.use_as_transposition:
            continue
        if entry.normalized in seen:
            continue
        seen.add(entry.normalized)
        out.append(entry.token)
        if len(out) >= max_keywords:
            break
    if include_derived:
        for entry in _REGISTRY_V2:
            if entry.tier not in selected_tiers:
                continue
            if entry.trigger_only:
                continue
            for derived in entry.derived_forms:
                if derived in seen:
                    continue
                seen.add(derived)
                out.append(derived)
                if len(out) >= max_keywords:
                    return out
    return out


def real_k4_clue_words_with_provenance(
    *,
    tiers: Optional[str | Sequence[str]] = None,
) -> list[ClueWordEntry]:
    """Return the filtered ClueWordEntry list (full metadata) in
    canonical order.

    Used by the audit artifact to record each emitted keyword's full
    provenance + role flags so an auditor can trace contamination if
    any.
    """
    selected_tiers = set(resolve_tier_selector(tiers))
    return [e for e in _REGISTRY_V2 if e.tier in selected_tiers]


def authorized_normalized_tokens() -> frozenset[str]:
    """Return every normalized token authorized by the registry,
    including derived forms. Used by the audit firewall to allow-list
    explicitly-authorized tokens that might also appear in the
    K4Bench corpus.
    """
    out: set[str] = set()
    for entry in _REGISTRY_V2:
        out.add(entry.normalized)
        out.update(entry.derived_forms)
    return frozenset(out)


def tier_for_token(token: str) -> Optional[str]:
    """Return the tier of a token (matched against ``normalized``),
    or None if the token is not in the registry.
    """
    upper = token.upper().strip()
    for entry in _REGISTRY_V2:
        if entry.normalized == upper:
            return entry.tier
        if upper in entry.derived_forms:
            return entry.tier
    return None


def provenance_for_token(token: str) -> Optional[str]:
    """Return the provenance label of a token, or None if absent."""
    upper = token.upper().strip()
    for entry in _REGISTRY_V2:
        if entry.normalized == upper:
            return entry.provenance
        if upper in entry.derived_forms:
            return f"{entry.provenance}/derived"
    return None


# ---------------------------------------------------------------------------
# Audit clue text
# ---------------------------------------------------------------------------
#
# Single canonical clue text used by the audit when no tier-specific
# variant is needed. Generic cipher-mechanical vocabulary fires the
# LESSON-007..-015 trigger detectors. Project-safe: every token
# is either generic cipher mechanic, public K4 vocabulary, or already
# authorized in the v2 registry.

_AUDIT_CLUE_TEXT: str = (
    "Kryptos K4 capability audit (real-K4, no benchmark data). "
    "Public ciphertext is 97 characters; public cribs disclose "
    "EASTNORTHEAST at positions 21-33 and BERLINCLOCK at positions "
    "63-73. The audit exercises every learned hand-cipher capability "
    "without assuming which one is required. "
    "Test all alphabet variants including the KRYPTOS-keyed and "
    "reversed alphabet tableaux. Allow Caesar shift composition with "
    "shift values 1, 3, 5, 7, 13, and 17. Allow block reversal at "
    "block sizes 5 and 7. Allow skip-step route transposition with "
    "every other and stride patterns. Allow ragged boustrophedon "
    "grids with the rows reading down and up alternately, every "
    "column counted as a route. Allow folded reversal of alternate "
    "rows on a width-5 line and width-7 line. "
    "Allow rail-fence depth 3 and depth 5, columnar widths from 3 "
    "to 7, and Myszkowski transposition. Combine substitution layers "
    "with route, columnar, and row reversal in both layer orders."
)


def real_k4_audit_clue_text() -> str:
    """Return the canonical audit clue text. Always the same string —
    deterministic so the audit artifact is reproducible.
    """
    return _AUDIT_CLUE_TEXT


# ---------------------------------------------------------------------------
# Forbidden / allowed firewall declarations
# ---------------------------------------------------------------------------

_FORBIDDEN_BENCH_ID_PREFIX: str = "K4B-"

# Documented K4Bench-specific keyword tokens. Tokens here that ALSO
# appear in the v2 registry (as authorized public-K4 vocabulary) are
# allowed; the firewall test in tests/test_real_k4_hcc_audit.py
# subtracts ``authorized_normalized_tokens()`` from this set before
# checking.
_DOCUMENTED_BENCH_KEYWORDS: frozenset[str] = frozenset({
    "CEDAR", "LANTERN",
    "ARCHIVE", "ARTIFACT",
    "SHADOW",
    "TUNNEL", "MIRROR",
    "PANEL", "WALL",
})

_RETIRED_HYPOTHESIS_TOKENS: frozenset[str] = frozenset({
    "BCL_PALETTE",
})


def forbidden_bench_keywords() -> frozenset[str]:
    """Return the documented K4Bench-specific keywords that the
    firewall will flag IF they are not also in the v2 registry's
    ``authorized_normalized_tokens``.
    """
    return _DOCUMENTED_BENCH_KEYWORDS


def retired_hypothesis_tokens() -> frozenset[str]:
    return _RETIRED_HYPOTHESIS_TOKENS


def forbidden_bench_id_prefix() -> str:
    return _FORBIDDEN_BENCH_ID_PREFIX


# ---------------------------------------------------------------------------
# Backward-compat exports
# ---------------------------------------------------------------------------
#
# v1 callers used a ``ProjectSafeClueWord`` dataclass with (word,
# provenance). We retain a thin wrapper to keep any pre-v2 caller
# working unchanged. Internal callers should migrate to ClueWordEntry.


@dataclass(frozen=True)
class ProjectSafeClueWord:
    """v1-compatible clue word + provenance. Retained for backward
    compatibility; new code should use ClueWordEntry from v2.
    """
    word: str
    provenance: str

    def __post_init__(self) -> None:
        if not self.word.isalpha() or not self.word.isupper():
            raise ValueError(
                f"ProjectSafeClueWord {self.word!r}: must be uppercase A-Z"
            )


__all__ = [
    "CLUE_TIERS_IN_ORDER",
    "TIER_CORE_PUBLIC_CRIBS",
    "TIER_KRYPTOS_PLAINTEXT_LEGACY",
    "TIER_SCULPTURE_CONTEXT",
    "TIER_GEODETIC_COORDINATE",
    "TIER_PROCEDURAL_TERMS",
    "TIER_PRESETS",
    "ClueWordEntry",
    "ProjectSafeClueWord",
    "all_entries",
    "entries_by_tier",
    "resolve_tier_selector",
    "real_k4_clue_keywords",
    "real_k4_clue_words_with_provenance",
    "real_k4_audit_clue_text",
    "authorized_normalized_tokens",
    "tier_for_token",
    "provenance_for_token",
    "forbidden_bench_keywords",
    "retired_hypothesis_tokens",
    "forbidden_bench_id_prefix",
]
