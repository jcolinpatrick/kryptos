"""Historical elimination registry — single source of truth for the major
project findings that pre-date the campaign manifest system.

This file is the input to scripts/_infra/backfill_historical_manifests.py,
which generates JSON manifests at results/campaign_manifests/historical/.
The internalcontroller reads those manifests at bootstrap and updates
its family registry, so the controller's candidate generator stops proposing theories
for already-eliminated families.

DISCIPLINE
----------
Every entry below was hand-curated against docs/elimination_tiers.md.
Do not edit an entry without re-reading the source row in that doc.
Do not add new entries without explicit hand-verification of the source.
Do not collapse entries that have meaningfully different scope.
Do not relax the H1 caveat on Bean-based items.
Do not change e_frac_54 from OPEN.

The H1 caveat string is defined once and reused — do not paraphrase it
on a per-entry basis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .manifest import CampaignVerdict


# The exact H1 caveat string. Reused across all Bean-based entries.
# Do NOT paraphrase this on a per-entry basis.
H1_CAVEAT = (
    "H1 conditional: assumes direct positional crib mapping on the "
    "carved 97-char CT under an additive cipher class. Mechanisms that "
    "break H1 (outer transposition before the analyzed step, "
    "position-dependent selectors, physical-overlay remaps, non-additive "
    "ciphers) are NOT eliminated by this result."
)


@dataclass(frozen=True)
class HistoricalElimination:
    """A single historical project finding ready for manifest generation."""
    canonical_id: str
    name: str
    source_row_id: str
    source_doc_pointer: str
    verdict: CampaignVerdict
    verdict_summary: str
    family_updates: dict[str, dict[str, Any]] = field(default_factory=dict)
    scope_caveats: list[str] = field(default_factory=list)
    scope_does_not_cover: list[str] = field(default_factory=list)
    quantitative_summary: str = ""
    notes: str = ""


_SRC = "docs/elimination_tiers.md"


HISTORICAL_ELIMINATIONS: list[HistoricalElimination] = [
    # =================================================================
    # Tier 1 — Algebraic / structural proofs
    # =================================================================

    HistoricalElimination(
        canonical_id="e_frac_21",
        name="Fractionation family structural elimination (bifid/trifid/ADFGVX/straddling checkerboard)",
        source_row_id="E-FRAC-21",
        source_doc_pointer=f"{_SRC} (Tier 1 row, E-FRAC-21)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "E-FRAC-21 establishes structural impossibility of the classical "
            "fractionation family on the carved 97-char K4 CT. Bifid 5x5 "
            "requires a 25-letter alphabet (I/J merge); K4 uses all 26. "
            "Bifid/trifid/ADFGVX/straddling-checkerboard outputs are always "
            "an even multiple of letters after fractionation, but K4 is 97 "
            "(odd). These are alphabet- and digit-count proofs; they hold "
            "regardless of keying, period, or cipher-class composition."
        ),
        family_updates={
            "bifid": {"tier": 1, "evidence": "E-FRAC-21: bifid 5x5 requires 25-letter alphabet (I/J merge); K4 uses all 26."},
            "fractionation": {"tier": 1, "evidence": "E-FRAC-21: classical fractionation outputs have parity/digit-count mismatch with K4's 97-char carved CT."},
            "adfgvx": {"tier": 1, "name": "ADFGVX", "evidence": "E-FRAC-21: fractionation output length parity incompatible with K4=97."},
            "straddling_checkerboard": {"tier": 1, "name": "Straddling Checkerboard", "evidence": "E-FRAC-21: output length and alphabet structure incompatible with K4=97."},
            "trifid": {"tier": 1, "name": "Trifid", "evidence": "E-FRAC-21: trifid requires 27-letter alphabet and produces length-3N outputs; incompatible with K4=97."},
        },
        scope_caveats=[
            "Structural/universal proof: holds regardless of cipher class.",
            "Applies to the carved 97-char CT directly.",
        ],
        scope_does_not_cover=[
            "Fractionation applied to a subset of K4 identified by an independent mechanism (e.g., null mask).",
            "Non-standard fractionation variants with non-uniform group sizes.",
        ],
        notes="Structural/universal proof. NO H1 caveat — holds regardless of cipher class.",
    ),

    HistoricalElimination(
        canonical_id="e_frac_26_w5",
        name="Columnar width-5 Bean impossibility (full 120 orderings x 3 variants)",
        source_row_id="E-FRAC-26",
        source_doc_pointer=f"{_SRC} (Tier 1 row, E-FRAC-26)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "E-FRAC-26: exhaustive enumeration of all 120 column orderings at "
            "width 5 across all three additive variants (Vigenere, Beaufort, "
            "Variant Beaufort) admits ZERO Bean-consistent keystreams. Width 5 "
            "is eliminated as a single columnar transposition step under "
            "additive keying at the analyzed scope."
        ),
        family_updates={
            "columnar_single": {"tier": 2, "evidence": "E-FRAC-26: width 5 exhausted (120 orderings x 3 variants, 0 Bean passes)."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Columnar w=5 composed with a non-additive inner cipher.",
            "Columnar w=5 as an inner layer under an outer transformation.",
        ],
        quantitative_summary="120 orderings x 3 variants = 360 (ordering,variant) pairs; 0 Bean passes.",
    ),

    HistoricalElimination(
        canonical_id="e_frac_27_w7",
        name="Columnar width-7 Bean impossibility (full 5,040 orderings x 3 variants)",
        source_row_id="E-FRAC-27",
        source_doc_pointer=f"{_SRC} (Tier 1 row, E-FRAC-27)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "E-FRAC-27: exhaustive enumeration of all 5,040 column orderings "
            "at width 7 across Vigenere, Beaufort, and Variant Beaufort "
            "admits ZERO Bean-consistent keystreams. Width 7 is eliminated "
            "as a single columnar transposition step under additive keying."
        ),
        family_updates={
            "columnar_single": {"tier": 2, "evidence": "E-FRAC-27: width 7 exhausted (5,040 orderings x 3 variants, 0 Bean passes)."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Columnar w=7 composed with a non-additive inner cipher.",
            "Columnar w=7 as an inner layer under an outer transformation.",
        ],
        quantitative_summary="5,040 orderings x 3 variants = 15,120 pairs; 0 Bean passes.",
    ),

    HistoricalElimination(
        canonical_id="e_frac_35_universal",
        name="Universal Bean impossibility: periodic substitution + ANY transposition",
        source_row_id="E-FRAC-35",
        source_doc_pointer=f"{_SRC} (Tier 1 row, E-FRAC-35 universal proof)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "E-FRAC-35 universal Bean impossibility proof: for periodic "
            "substitution at the discriminating periods p in {2,3,4,5,6,7,8,"
            "9,10,11,12,14,15,17,18,21,22,25} combined with ANY transposition "
            "over all 97! permutations, no additive keystream can satisfy the "
            "full Bean constraint set. This eliminates Vigenere, Beaufort, "
            "Variant Beaufort, Gronsfeld, and Porta as inner layers of any "
            "transposition at those periods, for any outer transposition "
            "whatsoever, under additive keying."
        ),
        family_updates={
            "vigenere": {"tier": 1, "evidence": "E-FRAC-35 universal: eliminated as inner layer under any transposition at discriminating periods, by universal Bean impossibility for ALL 97! permutations."},
            "beaufort": {"tier": 1, "evidence": "E-FRAC-35 universal: eliminated as inner layer under any transposition at discriminating periods, by universal Bean impossibility for ALL 97! permutations."},
            "variant_beaufort": {"tier": 1, "evidence": "E-FRAC-35 universal: eliminated as inner layer under any transposition at discriminating periods, by universal Bean impossibility for ALL 97! permutations."},
            "gronsfeld": {"tier": 1, "evidence": "E-FRAC-35 universal: eliminated as inner layer under any transposition at discriminating periods, by universal Bean impossibility for ALL 97! permutations."},
            "porta": {"tier": 1, "evidence": "E-FRAC-35 universal: eliminated as inner layer under any transposition at discriminating periods, by universal Bean impossibility for ALL 97! permutations."},
            "periodic_substitution": {"tier": 1, "evidence": "E-FRAC-35 universal: periodic substitution as inner layer under any transposition at discriminating periods, by universal Bean impossibility for ALL 97! permutations."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Bean-surviving periods {8, 13, 16} where the proof is underdetermined (covered by E-FRAC-55).",
            "Non-additive keystreams (e.g., non-linear key schedules).",
            "Position-dependent selectors that break periodicity.",
        ],
    ),

    HistoricalElimination(
        canonical_id="e_frac_37_autokey",
        name="Autokey structural elimination (PT/CT x Vig/Beau)",
        source_row_id="E-FRAC-37",
        source_doc_pointer=f"{_SRC} (Tier 1 row, E-FRAC-37)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "E-FRAC-37: standard autokey variants (PT-autokey and CT-autokey "
            "over Vigenere and Beaufort arithmetic) cannot reach 24/24 crib "
            "match on K4. PT-autokey maxes at 16/24; CT-autokey maxes at "
            "21/24. The crib feedback contradiction at positions 27/65 is "
            "structural under the standard primer/update rules."
        ),
        family_updates={
            "autokey_vigenere": {"tier": 1, "evidence": "E-FRAC-37: PT-autokey Vigenere max 16/24, structural crib feedback contradiction."},
            "autokey_beaufort": {"tier": 1, "evidence": "E-FRAC-37: PT-autokey Beaufort max 16/24, structural crib feedback contradiction."},
            "ct_autokey_vigenere": {"tier": 1, "evidence": "E-FRAC-37: CT-autokey Vigenere max 21/24, structural crib feedback contradiction."},
            "ct_autokey_beaufort": {"tier": 1, "evidence": "E-FRAC-37: CT-autokey Beaufort max 21/24, structural crib feedback contradiction."},
            "quagmire_ii_autokey": {"tier": 1, "evidence": "E-FRAC-37: same structural crib feedback contradiction as autokey Vigenere/Beaufort."},
        },
        scope_caveats=[
            H1_CAVEAT,
            "Standard autokey primer/update rules. Non-standard autokey variants (e.g., skipping primer, CT+PT fused updates) are not covered by this proof.",
        ],
        scope_does_not_cover=[
            "Autokey variants with non-standard update rules.",
            "Autokey as inner layer under an outer transposition.",
        ],
    ),

    HistoricalElimination(
        canonical_id="e_frac_38_structured_keys",
        name="Structured-key Bean elimination (progressive, quadratic, Fibonacci)",
        source_row_id="E-FRAC-38",
        source_doc_pointer=f"{_SRC} (Tier 1 row, E-FRAC-38)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "E-FRAC-38: structured additive keystreams — progressive keys "
            "k[i]=k[0]+i*delta, quadratic k[i]=a*i^2+b*i+c, and Fibonacci-"
            "recurrence keys — are Bean-eliminated at the 24 crib positions "
            "under the additive-key model. The only progressive survivors "
            "are delta=0 (monoalphabetic, trivially eliminated) and delta=13 "
            "(period-2, eliminated by E-FRAC-35)."
        ),
        family_updates={
            "progressive_key": {"tier": 1, "name": "Progressive Key (Additive)", "evidence": "E-FRAC-38: k[i]=k[0]+i*delta Bean-eliminated at 24 crib positions except delta in {0,13}, both otherwise eliminated."},
            "quadratic_key": {"tier": 1, "name": "Quadratic Additive Key", "evidence": "E-FRAC-38: k[i]=a*i^2+b*i+c Bean-eliminated at 24 crib positions under additive keying."},
            "fibonacci_key": {"tier": 1, "name": "Fibonacci-Recurrence Key", "evidence": "E-FRAC-38: k[i]=k[i-1]+k[i-2] (and linear recurrences) Bean-eliminated at 24 crib positions under additive keying."},
        },
        scope_caveats=[
            H1_CAVEAT,
            "Under the additive-key model. delta=0 (mono trivial) and delta=13 (period-2, Bean-eliminated by E-FRAC-35) are the only progressive survivors and are independently eliminated.",
        ],
        scope_does_not_cover=[
            "Non-additive structured keystreams.",
            "Structured keys as inner layer under an outer transposition.",
        ],
    ),

    HistoricalElimination(
        canonical_id="hill_2x2_3x3",
        name="Hill cipher 2x2 and 3x3 algebraic elimination",
        source_row_id="HILL-2x2-3x3",
        source_doc_pointer=f"{_SRC} (Tier 1 row, Hill 2x2 / 3x3)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "Hill cipher at block sizes 2x2 and 3x3 is algebraically "
            "eliminated on K4 under direct positional crib mapping. The "
            "crib constraints over-determine the linear system; no "
            "invertible key matrix in Z_26 satisfies them simultaneously."
        ),
        family_updates={
            "hill": {"tier": 1, "name": "Hill Cipher (2x2, 3x3)", "evidence": "Hill 2x2 and 3x3 algebraically eliminated under direct positional crib mapping; over-determined linear system has no valid invertible key matrix in Z_26."},
        },
        scope_caveats=[
            H1_CAVEAT,
            "Algebraically eliminated under direct positional crib mapping. Hill 4x4+ untested. Hill as inner layer of multi-layer composition untested.",
        ],
        scope_does_not_cover=[
            "Hill 4x4 and larger blocks.",
            "Hill as inner layer under an outer transposition or substitution.",
        ],
    ),

    HistoricalElimination(
        canonical_id="vimark_p5",
        name="Vimark period-5 algebraic incompatibility",
        source_row_id="VIMARK-P5",
        source_doc_pointer=f"{_SRC} (Tier 1 row, Vimark period 5)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "Vimark at period 5 is algebraically incompatible with the K4 "
            "crib constraints under additive keying. Linked to the E-FRAC-35 "
            "universal Bean impossibility: period 5 is among the "
            "discriminating periods that admit no consistent keystream."
        ),
        family_updates={
            "gromark": {"tier": 2, "evidence": "Vimark (Gromark variant) at period 5 Bean-eliminated, linked to E-FRAC-35 universal proof at p=5."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Vimark at non-5 periods with non-additive schedule overlays.",
        ],
    ),

    HistoricalElimination(
        canonical_id="e_d13_columnar",
        name="Columnar x period-13 substitution structural impossibility",
        source_row_id="E-D13-COLUMNAR",
        source_doc_pointer=f"{_SRC} (Tier 1 row, d=13 columnar + periodic)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "Columnar transposition composed with period-13 periodic "
            "substitution: across widths 2-48 a total of 61.5M configurations "
            "were tested, ZERO hits. The probability that all 11 mod-13 "
            "residues simultaneously match the crib constraint is "
            "approximately 2.5e-16, making this combination structurally "
            "impossible within the tested width range."
        ),
        family_updates={
            "columnar_single": {"tier": 2, "evidence": "E-D13-COLUMNAR: columnar x period-13 substitution structurally eliminated across widths 2-48 (61.5M configs, 0 hits, p~2.5e-16)."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Columnar widths above 48.",
            "Non-period-13 substitutions composed with columnar (covered elsewhere).",
        ],
        quantitative_summary="Widths 2-48, 61.5M configurations, 0 hits. P(all 11 mod-13 residues match) ~ 2.5e-16.",
    ),

    HistoricalElimination(
        canonical_id="e_nullmask_periodic",
        name="Null mask + periodic substitution (periods 1-23) algebraic elimination",
        source_row_id="E-NULLMASK-PERIODIC",
        source_doc_pointer=f"{_SRC} (Tier 1 row, null mask + periodic sub)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "For any choice of 24 null positions combined with periodic "
            "substitution at periods p in [1, 23], a closed-form algebraic "
            "proof over crib-segment null counts (n1, n2, n3) shows no "
            "configuration admits the crib constraints. 550,000 random mask "
            "samples confirm the algebraic result. Only periods p in "
            "{24, 25, 26} survive the analysis, where the constraint system "
            "is underdetermined rather than satisfiable."
        ),
        family_updates={
            "periodic_substitution": {"tier": 1, "evidence": "E-NULLMASK-PERIODIC: null mask (any 24 positions) + periodic substitution at p in [1,23] algebraically eliminated; p in {24,25,26} underdetermined, not satisfied."},
        },
        scope_caveats=[
            H1_CAVEAT,
            "Period 24-26 cases are underdetermined, not proved satisfiable.",
        ],
        scope_does_not_cover=[
            "Null masks combined with non-periodic ciphers.",
            "Nulls identified by a non-statistical mechanism combined with larger-period ciphers.",
        ],
    ),

    HistoricalElimination(
        canonical_id="e_nullmask_beaufort_admissibility",
        name="Null mask + periodic Beaufort sliding-window formal UNSAT",
        source_row_id="E-NULLMASK-BEAU",
        source_doc_pointer=f"{_SRC} (Tier 1 row, null mask + periodic Beaufort)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "Formal UNSAT result: null mask combined with periodic Beaufort "
            "at periods p in [1, 8] over sliding crib windows yields no "
            "satisfying assignment across 44,400 constructed CSPs."
        ),
        family_updates={
            "beaufort": {"tier": 2, "evidence": "E-NULLMASK-BEAU: null mask + periodic Beaufort p in [1,8] formally UNSAT over 44,400 CSPs."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Periods above 8.",
            "Beaufort variants with non-standard keying.",
        ],
        quantitative_summary="44,400 CSPs, all UNSAT.",
    ),

    HistoricalElimination(
        canonical_id="e_bean_01",
        name="Columnar widths {4,6,8,9} + additive variants full Bean elimination",
        source_row_id="E-BEAN-01",
        source_doc_pointer=f"{_SRC} (Tier 1 row, Bean columnar widths {4,6,8,9})",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "E-BEAN-01: for columnar transposition at widths {4, 6, 8, 9} "
            "composed with additive variants (Vigenere, Beaufort, Variant "
            "Beaufort), the full 242-inequality Bean constraint set admits "
            "ZERO Bean-consistent keystreams across 1,211,832 (ordering, "
            "variant) pairs. Running-key-source-independent within the "
            "analyzed additive-keystream class."
        ),
        family_updates={
            "columnar_single": {"tier": 2, "evidence": "E-BEAN-01: columnar widths {4,6,8,9} x 3 additive variants exhaustively Bean-eliminated (1,211,832 pairs, 0 passes)."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Composed ciphers with an outer layer preceding columnar.",
            "Non-additive keystreams at these widths.",
            "Widths outside {4, 6, 8, 9}.",
        ],
        quantitative_summary="1,211,832 (ordering, variant) pairs; 0 Bean passes.",
    ),

    HistoricalElimination(
        canonical_id="e_frac_46_double_columnar",
        name="Double columnar Bean-compatible width pairs empirical null",
        source_row_id="E-FRAC-46",
        source_doc_pointer=f"{_SRC} (Tier 2 row, E-FRAC-46 double columnar)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "E-FRAC-46: double columnar across 9 Bean-compatible width "
            "pairs (w6xw6 through w9xw9) enumerated 2,958,400 compositions. "
            "Maximum crib score 15/24 — matches random expectation. Empirically "
            "saturated within the specific width-pair ranges tested under the "
            "additive-keystream class."
        ),
        family_updates={
            "double_columnar": {"tier": 2, "evidence": "E-FRAC-46: 9 width pairs in {6,7,8,9}^2, 2,958,400 compositions, max 15/24, matches random. Empirically saturated within tested ranges."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Double columnar with widths outside {6,7,8,9}.",
            "Double columnar composed with a non-additive inner cipher.",
        ],
        quantitative_summary="9 width pairs, 2,958,400 compositions, max 15/24.",
    ),

    HistoricalElimination(
        canonical_id="e_frac_47_myszkowski",
        name="Myszkowski transposition w5-13 empirical null",
        source_row_id="E-FRAC-47",
        source_doc_pointer=f"{_SRC} (Tier 2 row, E-FRAC-47 Myszkowski)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "E-FRAC-47: Myszkowski transposition at widths 5-13 with "
            "periodic substitution enumerated 226,390 unique permutations; "
            "maximum crib score 15/24. No positive signal within the "
            "parameterized search space."
        ),
        family_updates={
            "myszkowski": {"tier": 2, "name": "Myszkowski Transposition", "evidence": "E-FRAC-47: widths 5-13 + periodic sub, 226,390 unique perms, max 15/24. No positive signal within tested parameter ranges."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Myszkowski at widths >13.",
            "Myszkowski composed with non-additive inner cipher.",
        ],
        quantitative_summary="226,390 unique perms, max 15/24.",
    ),

    HistoricalElimination(
        canonical_id="e_frac_48_amsco_nihilist",
        name="AMSCO / Nihilist / Swapped columnar w8-13 Bean UNSAT",
        source_row_id="E-FRAC-48",
        source_doc_pointer=f"{_SRC} (Tier 1 row, E-FRAC-48 AMSCO/Nihilist/Swapped)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "E-FRAC-48: AMSCO, Nihilist transposition, and swapped columnar "
            "at widths 8-13 enumerated 361,280 permutations; ZERO Bean "
            "passes. Eliminated as single-step transpositions under additive "
            "keying within the tested width range."
        ),
        family_updates={
            "nihilist": {"tier": 1, "evidence": "E-FRAC-48: nihilist transposition w8-13, 361,280 perms, 0 Bean passes."},
            "amsco": {"tier": 1, "name": "AMSCO Transposition", "evidence": "E-FRAC-48: AMSCO w8-13, 361,280 perms shared across families, 0 Bean passes."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Widths outside 8-13.",
            "As inner layer of a multi-layer composition.",
        ],
        quantitative_summary="361,280 perms, 0 Bean passes.",
    ),

    # =================================================================
    # Tier 2 — Empirical sweeps (BOUNDED_NULL, no universal language)
    # =================================================================

    HistoricalElimination(
        canonical_id="e_frac_29_30_columnar_widths",
        name="Columnar widths 6/8/9 exhaustive, 10-15 sampled empirical null",
        source_row_id="E-FRAC-29/30",
        source_doc_pointer=f"{_SRC} (Tier 2 row, E-FRAC-29/30 columnar widths)",
        verdict=CampaignVerdict.BOUNDED_NULL,
        verdict_summary=(
            "E-FRAC-29/30: columnar widths 6, 8, 9 exhaustively enumerated "
            "plus widths 10-15 sampled. All runs report max crib score <=14/24, "
            "underperforming the random expectation of ~14/24. No positive "
            "signal in any tested configuration within scope. Empirically "
            "saturated within the specific parameter ranges tested."
        ),
        family_updates={
            "columnar_single": {"tier": 2, "evidence": "E-FRAC-29/30: widths 6/8/9 exhaustive + 10-15 sampled, max <=14/24, no positive signal in tested configurations."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Columnar at widths >15.",
            "Columnar as inner layer under an outer transformation.",
        ],
    ),

    HistoricalElimination(
        canonical_id="e_frac_32_simple_transpositions",
        name="Simple transposition families (cyclic/reverse/affine/rail/swaps) empirical null",
        source_row_id="E-FRAC-32",
        source_doc_pointer=f"{_SRC} (Tier 2 row, E-FRAC-32 simple transpositions)",
        verdict=CampaignVerdict.BOUNDED_NULL,
        verdict_summary=(
            "E-FRAC-32: simple transposition families (cyclic shifts, "
            "reverse, affine, block reversal, rail fence, single swaps) "
            "enumerated 14,035 permutations. Maximum 13/24 — BELOW the "
            "random baseline of 14/24. No positive signal in any tested "
            "configuration within scope. Empirically saturated within the "
            "specific parameter ranges tested."
        ),
        family_updates={
            "rail_fence": {"tier": 2, "evidence": "E-FRAC-32: rail fence family exhaustively tested as part of 14,035 simple-transposition perms; max 13/24 (below random)."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Simple transpositions composed with a non-additive inner cipher.",
            "Simple transpositions as inner layer under an outer transformation.",
        ],
        quantitative_summary="14,035 perms, max 13/24 (below random baseline 14/24).",
    ),

    HistoricalElimination(
        canonical_id="e_frac_55_bean_surviving_periods",
        name="Bean-surviving periods {8,13,16} on columnar w6/8/9 empirical null",
        source_row_id="E-FRAC-55",
        source_doc_pointer=f"{_SRC} (Tier 2 row, E-FRAC-55 Bean-surviving periods)",
        verdict=CampaignVerdict.BOUNDED_NULL,
        verdict_summary=(
            "E-FRAC-55: Bean-surviving periods (8, 13, 16) composed with "
            "columnar transposition at widths 6/8/9. 154,000 consistency "
            "checks; zero 24/24 matches at p=8. Periods 13 and 16 max "
            "18/20 reflecting underdetermination rather than signal. Closes "
            "the Bean-surviving period gap left open by E-FRAC-35: "
            "empirically saturated within the tested width range."
        ),
        family_updates={
            "columnar_single": {"tier": 2, "evidence": "E-FRAC-55: closes Bean-surviving period gap at p in {8,13,16} for w in {6,8,9} (154K checks, 0 24/24 at p=8)."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Widths outside {6,8,9}.",
            "Periods outside {8,13,16}.",
        ],
        quantitative_summary="154,000 checks; 0 24/24 matches at p=8; p=13,16 max 18/20 (underdetermined).",
    ),

    HistoricalElimination(
        canonical_id="e_frac_52_three_layer_sub_trans_sub",
        name="Three-layer Sub+Trans+Sub at columnar w6/8/9 empirical null",
        source_row_id="E-FRAC-52",
        source_doc_pointer=f"{_SRC} (Tier 2 row, E-FRAC-52 three-layer)",
        verdict=CampaignVerdict.BOUNDED_NULL,
        verdict_summary=(
            "E-FRAC-52: three-layer Sub+Trans+Sub composition with columnar "
            "transposition at widths 6/8/9 and inner periods p1*p2 <= 50. "
            "Across 1.53M consistency checks, zero candidates were produced. "
            "No positive signal in 1.53M tested configurations within scope. "
            "Empirically saturated within the specific parameterized space."
        ),
        family_updates={
            "multi_layer": {"tier": 3, "evidence": "E-FRAC-52: three-layer Sub+Trans+Sub at columnar w6/8/9, p1*p2<=50 empirically saturated over 1.53M consistency checks, 0 candidates. Three-layer with non-columnar middle remains untested."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Three-layer with non-columnar middle transposition.",
            "Three-layer with p1*p2 > 50.",
            "Deeper (4+) layer compositions.",
        ],
        quantitative_summary="1.53M consistency checks, 0 candidates.",
    ),

    HistoricalElimination(
        canonical_id="e_frac_53_mono_trans_periodic",
        name="Mono+Trans+Periodic at columnar w6/8/9 empirical null",
        source_row_id="E-FRAC-53",
        source_doc_pointer=f"{_SRC} (Tier 2 row, E-FRAC-53 Mono+Trans+Periodic)",
        verdict=CampaignVerdict.BOUNDED_NULL,
        verdict_summary=(
            "E-FRAC-53: monoalphabetic + columnar transposition (w6/8/9) + "
            "periodic substitution at periods 3-12. Zero candidates at "
            "periods 3-7 (bipartite consistency stringent enough to saturate "
            "the search). Only 34 candidates at period 12, all gibberish, "
            "best Q=-6.33. No positive signal in the tested configurations "
            "within scope. Empirically saturated within the parameterized space."
        ),
        family_updates={
            "multi_layer": {"tier": 3, "evidence": "E-FRAC-53: Mono+Trans+Periodic at columnar w6/8/9, periods 3-12: empirically saturated. 0 candidates p3-7; 34 gibberish candidates p12 (best Q=-6.33)."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Monoalphabetic + non-columnar transposition + periodic sub.",
            "Periods outside 3-12.",
        ],
    ),

    HistoricalElimination(
        canonical_id="e_frac_49_50_51_running_key",
        name="Running key (K1/K2/K3 PT, Carter, Kahn, 73 Gutenberg, generic English) + columnar empirical null",
        source_row_id="E-FRAC-49/50/51",
        source_doc_pointer=f"{_SRC} (Tier 2 row, E-FRAC-49/50/51 running-key)",
        verdict=CampaignVerdict.BOUNDED_NULL,
        verdict_summary=(
            "E-FRAC-49/50/51: running-key sources K1/K2/K3 PT, Carter Vol 1, "
            "Kahn's The Codebreakers, 73 Gutenberg books, plus an 'unknown "
            "English text' generic class, each composed with columnar "
            "transposition. 17+ billion checks total, zero 24/24 matches. "
            "No positive signal across the tested corpus within scope. "
            "Empirically saturated for known reference texts and generic "
            "English running keys under the H1 + additive-keystream class."
        ),
        family_updates={
            "running_key": {"tier": 3, "evidence": "E-FRAC-49/50/51: empirically saturated across K1/K2/K3 PT, Carter, Kahn, 73 Gutenberg books, + generic English x columnar (17B+ checks, 0 matches) under H1 + additive."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Non-English running keys.",
            "Running keys combined with monoalphabetic preprocessing (E-FRAC-54 underdetermined).",
            "Running keys combined with non-columnar transpositions.",
        ],
        quantitative_summary="17+ billion checks, 0 24/24 matches.",
    ),

    HistoricalElimination(
        canonical_id="e_jts_08_11_vimark_linear",
        name="Vimark/Gromark linear-algebra primer elimination (orders 1-8)",
        source_row_id="E-JTS-08/11",
        source_doc_pointer=f"{_SRC} (Tier 1 row, E-JTS-08/11 Vimark/Gromark linear)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "E-JTS-08/11: Vimark/Gromark with linear-recurrence primers "
            "at orders 1-8 solved as a linear-algebra problem. No "
            "consistent primer exists for columnar widths 6-9 or strip "
            "transposition widths 7-13 under the crib constraints. "
            "Structural via linear algebra over Z_26."
        ),
        family_updates={
            "gromark": {"tier": 2, "evidence": "E-JTS-08/11: linear-algebra elimination for orders 1-8 over columnar w6-9 and strip w7-13; 0 consistent primers."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Non-linear primer update rules.",
            "Primer orders above 8.",
            "Transpositions outside columnar w6-9 / strip w7-13.",
        ],
    ),

    HistoricalElimination(
        canonical_id="e_jts_12_k123_running_key",
        name="K1/K2/K3 plaintext as running key for K4 empirical null",
        source_row_id="E-JTS-12",
        source_doc_pointer=f"{_SRC} (Tier 2 row, E-JTS-12 K1/K2/K3 running-key)",
        verdict=CampaignVerdict.BOUNDED_NULL,
        verdict_summary=(
            "E-JTS-12: K1/K2/K3 plaintext as running key for K4 "
            "enumerated across 694,000 transpositions. Zero 24/24 matches. "
            "No positive signal in the tested transposition space within scope."
        ),
        family_updates={
            "running_key": {"tier": 3, "evidence": "E-JTS-12: K1/K2/K3 PT running-key x 694K transpositions, 0 24/24 matches."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "K1/K2/K3 PT used with a non-columnar transposition outside the tested set.",
            "K1/K2/K3 PT combined with a monoalphabetic preprocessing (E-FRAC-54 underdetermined).",
        ],
        quantitative_summary="694,000 transpositions, 0 24/24 matches.",
    ),

    HistoricalElimination(
        canonical_id="e_jts_09_10_strip_transposition",
        name="Strip transposition w7-13 + periodic Vig/Beau + 7 reference texts empirical null",
        source_row_id="E-JTS-09/10",
        source_doc_pointer=f"{_SRC} (Tier 2 row, E-JTS-09/10 strip transposition)",
        verdict=CampaignVerdict.BOUNDED_NULL,
        verdict_summary=(
            "E-JTS-09/10: strip transposition at widths 7-13 composed with "
            "periodic Vigenere/Beaufort across 7 reference texts as running "
            "keys. Zero matches. No positive signal in the tested "
            "configurations within scope."
        ),
        family_updates={
            "running_key": {"tier": 3, "evidence": "E-JTS-09/10: strip transposition w7-13 + periodic Vig/Beau x 7 reference texts, 0 matches."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Strip widths outside 7-13.",
            "Reference texts outside the 7 tested.",
        ],
    ),

    HistoricalElimination(
        canonical_id="e_colmask_series",
        name="Colmask experiments (4 variants) on 73-char extract empirical null",
        source_row_id="E-COLMASK",
        source_doc_pointer=f"{_SRC} (Tier 2 row, colmask 73-char series)",
        verdict=CampaignVerdict.BOUNDED_NULL,
        verdict_summary=(
            "Four colmask experiments (autokey, MITM trans x sub, grid "
            "coordinate, native grid reading) executed on the 73-char "
            "extract. All runs produced noise indistinguishable from random "
            "baseline. Bounded negative within the parameterized search "
            "space on the colmask-derived 73-char frame."
        ),
        family_updates={
            "grille": {"tier": 3, "evidence": "E-COLMASK series: 4 experiments on 73-char colmask extract (autokey, MITM, grid coord, native grid reading) all noise."},
        },
        scope_caveats=[
            H1_CAVEAT,
            "The 73-char extract uses a column mask + shifted crib positions. This is a different experimental frame from the carved 97-char CT; the caveat is conditional on that mask being the correct extraction.",
        ],
        scope_does_not_cover=[
            "Alternative colmask extractions.",
            "The carved 97-char CT under the same experimental frame.",
        ],
    ),

    HistoricalElimination(
        canonical_id="composition_framework_v1_v2_v3",
        name="Composition framework v1+v2+v3 (additive x trans, trans x periodic, stateful) empirical null",
        source_row_id="COMPOSITION-v1-v2-v3",
        source_doc_pointer=f"{_SRC} (Tier 2 row, composition framework)",
        verdict=CampaignVerdict.BOUNDED_NULL,
        verdict_summary=(
            "Composition framework v1+v2+v3 (additive x transposition, "
            "transposition x periodic, stateful v3) across 52 family+peel "
            "campaigns enumerated 105,692 composition branches. Zero Bean "
            "passes. Score distribution matches binomial(24, 1/26). "
            "Empirically saturated within the specific parameterized "
            "two-layer search space the framework expresses."
        ),
        family_updates={
            "multi_layer": {"tier": 3, "evidence": "Composition framework v1+v2+v3: 105,692 branches across 52 campaigns, 0 Bean passes, score distribution matches random. Empirically saturated within parameterized two-layer search space."},
        },
        scope_caveats=[H1_CAVEAT],
        scope_does_not_cover=[
            "Compositions outside the v1/v2/v3 framework's expressive scope.",
            "Deeper (3+) layer compositions.",
            "Non-additive keystream inner/outer layers.",
        ],
        quantitative_summary="105,692 branches across 52 family+peel campaigns, 0 Bean passes.",
    ),

    # =================================================================
    # OPEN — genuine algebraic frontier, NOT eliminated
    # =================================================================

    HistoricalElimination(
        canonical_id="e_frac_54_mono_trans_running_key",
        name="Mono + Trans + Running-key UNDERDETERMINED (E-FRAC-54)",
        source_row_id="E-FRAC-54",
        source_doc_pointer=f"{_SRC} (OPEN frontier, E-FRAC-54 Mono+Trans+Running-key)",
        verdict=CampaignVerdict.OPEN,
        verdict_summary=(
            "E-FRAC-54: Monoalphabetic preprocessing + transposition + "
            "running-key decryption is UNDERDETERMINED, NOT eliminated. "
            "The 13 monoalphabetic degrees of freedom saturate quadgram "
            "discrimination at n=97, so the fragment-analysis scoring path "
            "cannot distinguish real English running keys from gibberish "
            "when a monoalphabetic preprocessing layer is present. Requires "
            "a scoring path that beats FM-1 at n=97 to test. This is the "
            "project's only legitimate algebraic-class open frontier; "
            "it remains OPEN."
        ),
        family_updates={},  # MUST BE EMPTY — no family is eliminated by this entry.
        scope_caveats=[
            "Detection-limited, not search-limited. The genuine algebraic open frontier.",
            "The 13 monoalphabetic DOF saturate fragment discrimination at n=97.",
        ],
        scope_does_not_cover=[
            "Nothing is eliminated by this entry — it is an OPEN marker.",
        ],
        notes="E-FRAC-54 must remain OPEN. The 13-DOF saturation is detection-limited, not search-limited.",
    ),

    # =================================================================
    # Statistical negative results (not cipher-family eliminations)
    # =================================================================

    HistoricalElimination(
        canonical_id="e_frac_13_19_ic_not_significant",
        name="K4 IC anomaly statistically insignificant (Bonferroni-corrected)",
        source_row_id="E-FRAC-13/19",
        source_doc_pointer=f"{_SRC} (Tier 1 row, E-FRAC-13/19 IC not significant)",
        verdict=CampaignVerdict.STRONG_ELIMINATION,
        verdict_summary=(
            "E-FRAC-13/19: K4's overall IC approx 0.0361 is BELOW the random "
            "expectation 0.0385. Bonferroni-corrected p=1.0. The pre-ENE "
            "high-IC sub-segment is also Bonferroni p=1.0. This eliminates "
            "the claim that IC is a useful discriminator for K4, NOT any "
            "cipher family. The result is a property of the carved CT "
            "statistic, not a cipher claim."
        ),
        family_updates={},  # No cipher family is eliminated by this statistical null.
        scope_caveats=[
            "Statistical/universal result. No H1 caveat needed — property of the carved CT length and alphabet distribution, not a cipher-class claim.",
        ],
        scope_does_not_cover=[
            "Any cipher family (this is a scoring/discriminator claim, not a cipher-family claim).",
        ],
        notes="Negative result — eliminates the IC anomaly as a discriminator, NOT as an elimination of any cipher family.",
    ),
]
