"""
Bootstrap registries for families, anomalies, and canonical facts.

Loads structured data from existing repo sources (exhaustion_log.json,
docs/anomaly_registry.md, docs/elimination_tiers.md) and populates the
theory ledger at startup. Idempotent — safe to run repeatedly.
"""

from __future__ import annotations

import json
import logging
import re
import hashlib
from pathlib import Path
from typing import Any

from .models import (
    AnomalyRecord, AnomalyStatus,
    FamilyRecord, FamilyStatus,
    ExperimentRecord, WorkerContract, WorkerStatus,
    TheoryStatus,
)
from .theory_ledger import TheoryLedger

logger = logging.getLogger("kryptosbot.registries")


# ---------------------------------------------------------------------------
# Known cipher families with elimination tiers
# ---------------------------------------------------------------------------

# Tier mapping: 1=proven impossible, 2=exhaustive search (single-layer),
#               3=partial, 4=bespoke/untested
KNOWN_FAMILIES: list[dict[str, Any]] = [
    # Tier 1: Proven impossible (structural)
    {"family_id": "caesar", "name": "Caesar / ROT-N", "tier": 1,
     "evidence": "Only 25 keys, all produce noise"},
    {"family_id": "affine", "name": "Affine", "tier": 1,
     "evidence": "312 keys exhausted, best score 3/24"},
    {"family_id": "atbash", "name": "Atbash", "tier": 1,
     "evidence": "Single fixed key, 0/24"},
    {"family_id": "bifid", "name": "Bifid", "tier": 1,
     "evidence": "Requires 25-letter alphabet; K4 uses all 26"},
    {"family_id": "autokey_vigenere", "name": "Autokey Vigenère", "tier": 1,
     "evidence": "Crib feedback contradiction at positions 27/65"},
    {"family_id": "autokey_beaufort", "name": "Autokey Beaufort", "tier": 1,
     "evidence": "Same structural proof as autokey Vigenère"},
    {"family_id": "ct_autokey_vigenere", "name": "CT-Autokey Vigenère", "tier": 1,
     "evidence": "Same structural proof as autokey variants"},
    {"family_id": "ct_autokey_beaufort", "name": "CT-Autokey Beaufort", "tier": 1,
     "evidence": "Same structural proof as autokey variants"},
    {"family_id": "quagmire_ii_autokey", "name": "Quagmire II Autokey", "tier": 1,
     "evidence": "Same crib feedback contradictions"},
    {"family_id": "periodic_substitution", "name": "Periodic Substitution (single-layer)", "tier": 1,
     "evidence": "All periods 1-26 eliminated by Bean 242-ineq on raw 97-char CT"},

    # Tier 2: Exhaustive search completed (single-layer)
    {"family_id": "vigenere", "name": "Vigenère (periodic)", "tier": 2,
     "evidence": "All periods tested, Bean constraints eliminate all"},
    {"family_id": "beaufort", "name": "Beaufort (periodic)", "tier": 2,
     "evidence": "All periods tested, Bean constraints eliminate all"},
    {"family_id": "variant_beaufort", "name": "Variant Beaufort (periodic)", "tier": 2,
     "evidence": "All periods tested, Bean constraints eliminate all"},
    {"family_id": "gronsfeld", "name": "Gronsfeld", "tier": 2,
     "evidence": "Subset of Vigenère, eliminated with it"},
    {"family_id": "porta", "name": "Porta", "tier": 2,
     "evidence": "13 reciprocal alphabets, all periods exhausted"},
    {"family_id": "four_square", "name": "Four-Square", "tier": 2,
     "evidence": "Single-layer reached 23/24 ceiling (overfit), inner 5/24 max"},
    {"family_id": "gromark", "name": "Gromark", "tier": 2,
     "evidence": "73-char exhaustive, all seeds tested"},
    {"family_id": "columnar_single", "name": "Columnar (single)", "tier": 2,
     "evidence": "All widths 2-48 exhausted"},
    {"family_id": "rail_fence", "name": "Rail Fence", "tier": 2,
     "evidence": "All depths 2-48 exhausted"},

    # Tier 3: Partially explored
    {"family_id": "running_key", "name": "Running-Key", "tier": 3,
     "evidence": "Major corpus sources tested, exotic sources remain"},
    {"family_id": "double_columnar", "name": "Double Columnar", "tier": 3,
     "evidence": "Common widths tested, full space too large"},
    {"family_id": "grille", "name": "Grille / Cardan", "tier": 3,
     "evidence": "Geometry-based subsets tested, full space open"},
    {"family_id": "multi_layer", "name": "Multi-Layer Composite", "tier": 3,
     "evidence": "Specific combos tested, combinatorial space open"},
    {"family_id": "route_cipher", "name": "Route Cipher", "tier": 3,
     "evidence": "Common routes tested, bespoke routes open"},
    {"family_id": "nihilist", "name": "Nihilist", "tier": 3,
     "evidence": "Partial testing, some parameter combos remain"},

    # Tier 3 (upgraded from 4): Bridged from external campaigns 2026-04-12
    {"family_id": "stego_layer", "name": "Steganographic Layer", "tier": 3,
     "evidence": "f_two_layer_stego_cipher_v1 full-cartesian null over 206,448 "
                 "profiles (552 outer x 374 inner) within the parameterized "
                 "mask/projection outer x near-identity inner architectural "
                 "slice (2026-04-12). Bounded negative within tested slice. "
                 "DOES NOT cover strongly-mixing inner ciphers, substitution-as-outer, "
                 "three-layer compositions, or procedural mechanisms. "
                 "See docs/two_systems_landscape.md and the frozen artifact at "
                 "results/null_reports/two_layer_full_cartesian_*.json"},

    # Tier 4: Genuinely bespoke / untested
    {"family_id": "physical_overlay", "name": "Physical Overlay / Installation", "tier": 4,
     "evidence": "Environmental puzzle mechanics untested computationally. "
                 "Procedural recipes exist in docs/procedural_anomaly_recipes.md "
                 "but not yet at campaign-grade enumeration."},
    {"family_id": "key_tape", "name": "Finite Key Tape (OTP-like)", "tier": 4,
     "evidence": "Tape consumption models under investigation"},
    {"family_id": "novel", "name": "Novel / Unclassified", "tier": 4,
     "evidence": "Catch-all for bespoke methods"},
    {"family_id": "procedural", "name": "Procedural / Anomaly-Derived", "tier": 4,
     "evidence": "Hand-executable procedures derived from physical anomalies. "
                 "See docs/procedural_anomaly_recipes.md for concrete recipes."},

    # Tier 3 (new): W-delimiter null framework, NARROW_RESIDUAL verdict
    {"family_id": "w_delimiter", "name": "W-Delimiter Null Framework", "tier": 3,
     "evidence": "f_w_delimiter_null_v1 multi-population null elimination test "
                 "(2026-04-12). 453,177 records evaluated across 4 populations "
                 "x 3 cipher variants. Verdict: NARROW_RESIDUAL — 633 "
                 "grammatical candidates hit multi-channel joint-tail criterion "
                 "but none clear multiplicity-corrected curated bar. AT+NEAR "
                 "specifically tagged not-signal across all variants. Cheap "
                 "self-encrypting criterion fully explained by combinatorics. "
                 "Hypothesis class is not strictly eliminated but produces no "
                 "positive evidence under additive variants + H1 alignment."},
]


# Family IDs that should be EXCLUDED from the underexplored display because
# they have external campaign or kernel-level evidence the controller's
# theorist would otherwise re-propose. This list is the bridge between the
# controller's ledger and external work.
EXTERNALLY_EVIDENCED_FAMILIES: frozenset[str] = frozenset({
    # Tier 1/2 — algebraically eliminated, see elimination_tiers.md
    "vigenere", "beaufort", "variant_beaufort", "gronsfeld", "porta",
    "four_square", "gromark", "columnar_single", "rail_fence",
    "caesar", "affine", "atbash", "bifid",
    "autokey_vigenere", "autokey_beaufort",
    "ct_autokey_vigenere", "ct_autokey_beaufort",
    "quagmire_ii_autokey", "periodic_substitution",
    # Tier 3 — externally tested (campaigns or E-FRAC series)
    "running_key",        # E-FRAC-49/50/51, JTS-12, exhaustively tested
    "double_columnar",    # E-FRAC-46
    "nihilist",           # E-FRAC-48
    "stego_layer",        # f_two_layer_stego_cipher_v1 (2026-04-12)
    "w_delimiter",        # f_w_delimiter_null_v1 (2026-04-12)
    "multi_layer",        # composition framework v1+v2+v3, 105K branches
    "fractionation",      # E-FRAC-21 structural eliminations
})


# ---------------------------------------------------------------------------
# Known anomalies
# ---------------------------------------------------------------------------

# Standing constraints — permanent structural facts about K4.
# These INFORM theory generation but are not "open tickets" to close.
# They appear in the landscape as context, not as anomalies to investigate.
STANDING_CONSTRAINTS: list[dict[str, str]] = [
    {
        "id": "bean_eq_27_65",
        "fact": "k[27]=k[65] under all variants (CT[27]=CT[65]='P', PT[27]=PT[65]='R')",
        "implication": "Any valid cipher must produce equal keystream at positions 27 and 65.",
    },
    {
        "id": "624_valid_keystreams",
        "fact": "Bean eq + 242 ineq + 101 linear constraints → exactly 624 valid keystreams at 24 crib positions",
        "implication": "Any proposed keystream can be instantly checked against 624 survivors.",
    },
    {
        "id": "self_encrypting_32_73",
        "fact": "CT[32]='S'=PT[32], CT[73]='K'=PT[73] — key value is 0 at these positions",
        "implication": "Keystream must be 0 mod 26 at positions 32 and 73.",
    },
    {
        "id": "ic_below_random",
        "fact": "IC ≈ 0.0361 (below random 0.0385). Not statistically significant for 97 chars.",
        "implication": "IC is uninformative at this length. Do not use IC alone as a discriminator.",
    },
    {
        "id": "k2_coordinates",
        "fact": "K2 plaintext contains the coordinates 38°57'6.5\"N, 77°8'44\"W as carved. "
                "Per aaa_coordinate_lie, primary-source photographs of Sanborn's own notebook "
                "show these coordinates alongside a different coordinate set with the words "
                "'He lied' circled between them. The primary fact is that Sanborn wrote down "
                "two coordinate sets and marked the discrepancy explicitly; whether one should "
                "be treated as the definitive 'true' coordinate is an interpretation, not a "
                "standing constraint.",
        "implication": "Coordinate digits may serve as key material, but the theorist should "
                        "consider that the carved sequence differs from another coordinate "
                        "sequence in Sanborn's notes. The carved string, the alternate string, "
                        "and the delta between them are testable candidates. See "
                        "aaa_coordinate_lie.",
    },
]

# Investigable anomalies — patterns that could be signal or noise,
# worth testing but resolvable. These are the "open anomalies" in the landscape.
#
# NOTE (2026-04-11): Palette-based anomalies (bcl_beaufort_palette_enrichment,
# null_palette_diversity, ka_mod5_column_structure) REMOVED — the entire palette
# family {B,G,I,K,O,W,Z} was retired 2026-04-01 and is on the do-not-revive
# list in MEMORY.md §5. See docs/a1_score_conditioned_null_report.md.
#
# Procedural recipe anomalies added from docs/procedural_anomaly_recipes.md.
# These treat physical anomalies as INSTRUCTIONS (escape-room paradigm), not
# just patterns to explain.
#
# PRIORITY RANKING (1=highest):
#   Priority reflects how CONSPICUOUS the anomaly is (physically obvious,
#   statistically strong, or creator-confirmed) and how likely it is to
#   constrain or reveal the procedural method. The controller should
#   preferentially generate theories targeting higher-priority anomalies.
#
#   Tier S: Physically unmissable or statistically very strong (p<1/1000)
#   Tier A: Statistically strong (p<1/500) or creator behavior is suspicious
#   Tier B: Moderate signal, worth testing
#   Tier C: Weak or disputed signal
#
# TRIAGE POLICY (2026-04-12, audit by request of Colin Patrick):
#
# Every entry in this list is loaded verbatim into the theorist prompt every
# cycle. A weak or hearsay-anchored entry will spin the theorist off a ledge —
# it will burn compute on speculative chains and exhaust the Opus context
# window on hypotheses whose underlying evidence is gossip.
#
# Evidence tiers (applied on 2026-04-12 audit, refined after Wikipedia
# cross-reference):
#   PRIMARY   First-hand physical observation or a published facsimile of
#             primary-source material. Includes:
#               - Sculpture features measured/photographed directly by Colin
#                 or a named investigator (Dunin, Bean, Gillogly).
#               - Rubbings of the carved copper.
#               - Photographs Colin took at Archives of American Art (AAA).
#               - PUBLISHED FACSIMILES of Sanborn's own handwriting from
#                 reputable outlets: e.g. NYT 2010 published scans of
#                 Sanborn's original coding charts ('Original Decoding
#                 Charts for Kryptos', NYT 2010), Wikipedia-aggregated
#                 primary-source citations. These are NOT hearsay even
#                 though a third party published them — the evidence is
#                 the handwriting, not the publisher's commentary.
#               - The canonical K1/K2/K3/K4 ciphertext strings as
#                 transcribed from the sculpture, and the canonical
#                 K1/K2/K3 plaintext strings (K1-K3 are publicly solved).
#   DERIVED   Computational result reproducible from the canonical CT in
#             this repo, or from a published paper with a stated method.
#   HEARSAY   Sanborn spoken statements ("Sanborn said", "reportedly",
#             "in an interview"), community speculation, Dunin/others'
#             testimony about what Sanborn told them verbally in private.
#             Must NOT appear as the sole anchor of a K4 anomaly. Sanborn
#             has been throwing researchers off for decades; only his
#             handwriting is trusted.
#
# DISAMBIGUATION: The difference between PRIMARY and HEARSAY is NOT about
# who published the evidence — it's about what the evidence IS. A NYT
# article that publishes a scan of Sanborn's handwritten coding chart
# contains PRIMARY evidence (the scan). The same NYT article that quotes
# Sanborn saying "the answers contain clues to the fourth passage" contains
# HEARSAY (the quote). Both can appear in the same article; only the
# handwriting-anchored fact is usable as an anomaly anchor.
#
# LOCATION DISCIPLINE (added 2026-04-12 after ENDYAHR / panel-separation errors):
# Every entry that references a location on the sculpture must state WHICH
# SECTION (K0/K1/K2/K3/K4) and WHICH PANEL (cipher panel / tableau panel /
# entrance slabs / other) the feature is on. Section boundaries are not
# interchangeable labels: "near the K3/K4 boundary" means something very
# different from "at the start of K3" even when the physical distance is
# small. Before citing a sculpture feature, verify the section assignment
# against the canonical CT strings. Example: ENDYAHROHNLSR... is the first
# line of K3 CT, so any feature inside ENDYAHR is K3-internal, not a
# boundary marker.
#
# Every entry below must have PRIMARY or DERIVED evidence as its anchor.
# Interpretations and speculative recipes are permitted but must be clearly
# labeled and must NOT appear in the anchor line. Entries removed by the
# 2026-04-12 audit are listed in RETIRED_ANOMALY_IDS below with reason.
#
KNOWN_ANOMALIES: list[dict[str, Any]] = [
    # ── Tier S: Unmissable ───────────────────────────────────────────────
    {
        "anomaly_id": "yar_superscript",
        "title": "YAR — the ONLY superscript characters on the sculpture, inside ENDYAHR (K3 CT line 1)",
        "description": "PRIMARY EVIDENCE: The Wikipedia article on Kryptos (cited to direct "
                        "sources) states that three letters — Y, A, R — near the beginning of the "
                        "bottom half of the left side are the ONLY characters on the sculpture in "
                        "superscript. Elonka Dunin confirmed this with physical rubbings in October "
                        "2002. The raised letters are directly measurable on the sculpture itself "
                        "and on the rubbings. "
                        "UNIQUENESS CONSTRAINT: no other characters anywhere on the sculpture are "
                        "superscript. Not in K1, not in K2, not in K4, not in the tableau panel, "
                        "not in any other carved text. Any theory that invokes other raised letters "
                        "as additional evidence is false. "
                        "CANONICAL LOCATION: the raised Y, A, R are inside the sequence ENDYAHR, "
                        "which is the FIRST LINE of the K3 ciphertext ('ENDYAHROHNLSRHEOCPTEO"
                        "IBIDYSHNAIA...'). K3 CT beginning with ENDYAHR is canon (directly "
                        "verifiable from the Wikipedia-published CT dump and from any K3 solve "
                        "reproduction in this repo). The raised letters are the Y, A, and R of the "
                        "word ENDYAHR — positions 3, 4, and 6 of K3 CT (0-indexed), with the "
                        "intervening H (position 5) NOT raised. YAR is therefore a K3-INTERNAL "
                        "physical feature at the very start of K3, NOT at the K3/K4 boundary. "
                        "DYARO FRAMING REJECTED: some community sources (solvingkryptos.com) have "
                        "suggested 'DYARO' — five letters — may all be misaligned. Wikipedia "
                        "(which aggregates cited primary sources) only reports YAR as three "
                        "letters. This registry uses the three-letter reading as the anchor. "
                        "IMPLICATIONS FOR K4 THEORIES: any hypothesis that treats YAR as a K4 "
                        "marker must account for the fact that YAR is physically inside K3 "
                        "ciphertext, not adjacent to K4. A K4 connection — if any — must run "
                        "through a procedural rule that reads across section boundaries, not "
                        "through physical adjacency. "
                        "TESTING HISTORY: ~50 scripts have tested YAR as algebraic parameters "
                        "(key primer, shift values, period markers) with no signal. "
                        "UNTESTED: YAR as a physical alignment mark for a cross-section overlay; "
                        "YAR as an instruction that the K4 procedure begins inside K3 and reads "
                        "forward; the asymmetry that the start of K3 is physically marked while "
                        "the start of K4 is not.",
        "source": "Elonka Dunin rubbings (Oct 2002); Wikipedia Kryptos article (primary-source cited); canonical K3 CT",
        "priority": 1,
        "status": "open",
    },
    {
        "anomaly_id": "bean_minor_diffs",
        "title": "KRYPTOS-set PT letters have near-identity CT (mean dist 2.1, p≈1/5520)",
        "description": "At 24 known PT positions, the 10 where PT ∈ {K,R,Y,P,T,O,S} have CT letters very close "
                        "in the standard alphabet (sum of distances=21, mean=2.1). Monte Carlo p ≈ 1/5,520. "
                        "STRONGEST GLOBAL SIGNAL in Bean 2021. This is consistent with a one-to-one substitution with a cipher "
                        "alphabet 'near' AZ and could constrain a procedural method to produce near-identity shifts "
                        "for keyword letters. Could reveal a physical alignment where KRYPTOS letters on the "
                        "tableau nearly align with their cipher-panel counterparts. "
                        "Recipe P-E0b-1: test near-AZ alphabets (Hamming distance 3-8 from standard AZ).",
        "source": "Bean 2021 Section 2.4 (Materna 2020) — Bean-reported, not project-rerun; auto-hedged via provenance layer",
        "priority": 1,
        "status": "open",
    },
    {
        "anomaly_id": "width21_vertical_bigrams",
        "title": "Width-21 gives 11 repeated vertical bigrams (p≈1/6750)",
        "description": "Writing K4 at width 21 produces 11 repeated vertical bigrams out of 76. "
                        "Expected for random: ~3.2. Expected for English at width 21: ~9.7. "
                        "STRONGEST POSITIONAL SIGNAL in K4. Width 21 is a Fibonacci number (F₈). "
                        "Consistent with a physical grid of 21 columns — could be the grid Sanborn used "
                        "to lay out the ciphertext before carving. A physical procedure at width 21 "
                        "(route reading, overlay, fold) would produce exactly this kind of columnar structure. "
                        "Recipe P-E0e-2: test non-standard-modulus Fibonacci (mod 10, mod 21) at width 21. "
                        "INDEPENDENTLY VERIFIED 2026-04-12: 100K MC permutations of K4 confirm z=4.47, "
                        "p≈0.0002. Repeats: AZ BS IT KK LS LW PK QZ SN WA ZT. "
                        "CRITICAL UPDATE 2026-04-17 [DERIVED FACT]: removing the 5 W characters from K4 "
                        "yields a 92-char text with ZERO repeated vertical bigrams at width 21. The entire "
                        "width-21 anomaly is attributable to W placement. This implies the 5 W's (positions "
                        "20,36,48,58,74 in 0-indexed CT97) are structural delimiters, not ciphertext. "
                        "See anomaly w_delimiter_segments.",
        "source": "Hannon (2010), LaTurner (2016), Bean 2021 Section 2.1",
        "priority": 1,
        "status": "open",
    },
    {
        "anomaly_id": "w_delimiter_segments",
        "title": "5 W's divide K4 into 6 segments (20,15,11,9,15,22); removing W's kills the width-21 bigram anomaly",
        "description": "[DERIVED FACT — computed 2026-04-17 from CT by python3 analysis] "
                        "K4 contains exactly 5 W characters at 0-indexed positions [20, 36, 48, 58, 74]. "
                        "Removing all 5 W's from CT97 yields a 92-character string with ZERO repeated "
                        "vertical bigrams at width 21 (vs 11 in CT97, p≈1/6750). The width-21 bigram "
                        "anomaly is entirely explained by the W positions — it is not a property of the "
                        "underlying 92-char text. "
                        "The 5 W's divide K4 into 6 variable-length segments: "
                        "seg0=20 chars (pos 0-19), seg1=15 (pos 21-35), seg2=11 (pos 37-47), "
                        "seg3=9 (pos 49-57), seg4=15 (pos 59-73), seg5=22 (pos 75-96). "
                        "Segment lengths: [20, 15, 11, 9, 15, 22], sum=92. "
                        "FIRST INTERPRETATION: W's are physical row-end delimiters — Sanborn wrote the "
                        "ciphertext in 6 rows of irregular length on graph paper or a stencil, using W "
                        "to mark end-of-row before carving. The underlying cipher operates on the "
                        "92 non-W characters; the W positions are a layout artifact. "
                        "SECOND INTERPRETATION: W's are null insertions placed at positions that generate "
                        "the width-21 bigram anomaly as a structural signature. "
                        "CRIB WARNING — DO NOT RE-INDEX: Sanborn has confirmed the cribs map 1:1 "
                        "to the carved CT97. EASTNORTHEAST is at positions 21-33 and BERLINCLOCK "
                        "at positions 63-73 (0-indexed) in the full 97-character text. These positions "
                        "are FIXED. Any cipher test must honour CT97 crib positions regardless of "
                        "whether W's are treated as delimiters or nulls. Stripping W's and shifting "
                        "cribs to CT92 positions silently invalidates the only confirmed ground truth. "
                        "The W-delimiter hypothesis is about LAYOUT and CONSTRUCTION of the cipher, "
                        "not about what text the cipher operates on. "
                        "KEY TEST: what layout procedure operating on a 6-segment variable-width "
                        "physical grid (segments 20,15,11,9,15,22) with W as row-end marker produces "
                        "a ciphertext that, when read linearly as CT97, decrypts to known cribs at "
                        "their fixed positions? "
                        "NOTE: the 5 W positions are distinct from the CONSENSUS_NULL_POSITIONS "
                        "(retracted palette-era construct); this finding is independent. "
                        "NOTE: CT73 (consensus-null-stripped) also shows p=0.247 at width 21, "
                        "confirming the anomaly is in the null/delimiter layer, not the cipher layer.",
        "source": "[DERIVED FACT] python3 in-session analysis 2026-04-17; "
                  "cross-check: CT73 result from red-team cycle 81 (2026-04-17)",
        "priority": 1,
        "status": "open",
    },
    {
        "anomaly_id": "structural_nulls_hypothesis",
        "title": "K4 may contain null/filler characters identified by a physical-procedural mechanism",
        "description": "HYPOTHESIS CLASS — not a fact. K4 may contain null (filler) characters whose "
                        "positions are identified by a non-statistical, physically-executable rule. "
                        "PRIMARY-FACT ANCHORS (no spoken sources): "
                        "(1) CT length = 97 characters (directly countable on the sculpture); "
                        "(2) 24 of those are constrained by the published plaintext cribs (EASTNORTHEAST "
                        "positions 21-33, BERLINCLOCK positions 63-73, both 0-indexed); "
                        "(3) the cipher panel contains exactly four '?' characters, with the K3 CT "
                        "ending in one of them ('...TRTVDOHW?'). K4 contains ZERO question marks. "
                        "K1 contains ZERO question marks. The remaining three '?'s are embedded "
                        "inside K2 ciphertext. See aaa_question_mark_j_stencil for the full "
                        "distribution and Wikipedia-verified positions. Prior versions of this "
                        "entry claimed a '?' sits 'between K3 and K4' — that was factually wrong; "
                        "the K3-trailing '?' is inside K3, not at a section boundary. "
                        "(4) 25-26 extra 'E' letters appear in the K0 entrance-slab Morse code (the "
                        "exact count depends on whether DIGETAL is counted — see morse_26e_grille_mask). "
                        "The hypothesis is only interesting if an INDEPENDENT physical-procedural rule "
                        "can identify which K4 positions are nulls. Once that rule is specified, the "
                        "remaining text becomes a smaller cipher problem. "
                        "RETIRED: The palette {B,G,I,K,O,W,Z} as a statistical null set is on the "
                        "do-not-revive list (MEMORY.md §5). The Tier 1 algebraic proof eliminates "
                        "'null mask + periodic substitution at periods 1-23' but not 'null mask + "
                        "non-periodic cipher' or 'null mask derived from a physical procedure'. "
                        "OPEN hypothesis sub-classes: (a) nulls identified by Morse E-position "
                        "projection onto the cipher panel; (b) nulls identified by a Cardan grille "
                        "overlay derived from a physical sculpture anomaly; (c) nulls identified by "
                        "the positions of other registered anomalies (YAR, extra-L). "
                        "DO NOT propose any statistical-frequency-based null identification. "
                        "DO NOT cite Scheidt or Sanborn spoken statements as justification.",
        "source": "physical sculpture features only (CT length, crib spans, ? mark, Morse E count)",
        "priority": 3,
        "status": "open",
    },

    # ── Tier A: Strong signal or creator silence ─────────────────────────
    {
        "anomaly_id": "desparatly_misspelling",
        "title": "DESPARATLY misspelling in K3 plaintext — E→A at position 5, E deleted at position 9",
        "description": "PRIMARY EVIDENCE: The K3 decrypted plaintext contains 'DESPARATLY' (10 "
                        "letters) in place of 'DESPERATELY' (11 letters). Relative to the correct "
                        "spelling, the changes are: "
                        "(a) the letter at word-position 5 of DESPERATELY is E, but is A in "
                        "DESPARATLY; "
                        "(b) the letter at word-position 9 of DESPERATELY is E, and is deleted "
                        "entirely in DESPARATLY (so position 9 of DESPARATLY is L, which was "
                        "position 10 in DESPERATELY). "
                        "Letter-by-letter: DESPERATELY = D(1) E(2) S(3) P(4) E(5) R(6) A(7) T(8) "
                        "E(9) L(10) Y(11); DESPARATLY = D(1) E(2) S(3) P(4) A(5) R(6) A(7) T(8) "
                        "L(9) Y(10). Both changes are directly readable from the K3 decryption "
                        "that the repo verifies against the cribs. "
                        "TESTING NOTE: standard columnar transposition at width 5 is "
                        "Bean-eliminated. "
                        "UNTESTED: positions 5 and 9 (of the misspelled word) as extraction "
                        "parameters for a non-columnar procedure — e.g. read-every-9-starting-at-"
                        "offset-5, or a stride rule referencing both positions on the K4 carved "
                        "positions. Also untested: whether the E→A substitution (A = E shifted "
                        "by -4) encodes the cipher operation itself. See "
                        "docs/procedural_anomaly_recipes.md P-A4-1, P-A4-4. "
                        "NOTE: Prior versions of this entry cited Sanborn's reported 'refusal to "
                        "answer' about the misspelling as evidence of significance. That framing "
                        "has been stripped — it is hearsay testimony about interview behavior, "
                        "not a physical fact. Only the physical misspelling is the anchor. "
                        "Prior versions also stated the deleted E was at position 8; that was an "
                        "off-by-one error corrected after the Wikipedia cross-reference.",
        "source": "K3 plaintext (directly verifiable from CT + KRYPTOS/PALIMPSEST/ABSCISSA keywords); Wikipedia-confirmed misspelling",
        "priority": 3,
        "status": "open",
    },
    {
        "anomaly_id": "stehle_delta5_lag4",
        "title": "Stehle constant-difference Δ5 at lag 4 (positions 55-63) — cipher fingerprint",
        "description": "Every 4th character in carved positions 55-63 (DIAWINFBN) differs by exactly 5 mod 26. "
                        "Corrected for 712 spacing × difference tests, p ~ 1/642. First noted by Stehle (2000). "
                        "This is a LOCAL REGULARITY — a fingerprint of whatever key generation or substitution "
                        "rule operates in this segment. A physical procedure that uses a step of 5 (e.g., "
                        "a grid with 5 columns, a 5-position offset, or a mod-5 key component) would produce "
                        "exactly this pattern. Combined with width-21 (21 = 4×5 + 1), this may reveal the "
                        "grid dimensions of the procedure. This anomaly is a WEAKNESS to exploit, not just "
                        "a pattern to observe.",
        "source": "Bean 2021 Section 2.3, citing Stehle (2000)",
        "priority": 2,
        "status": "open",
    },
    {
        "anomaly_id": "tableau_l_row_n_extra",
        "title": "Tableau panel: one row has an extra L, producing 'HILL' reading DOWN the rightmost column",
        "description": "PRIMARY EVIDENCE: The Vigenere tableau carved on the tableau panel (the "
                        "RIGHT-hand panel of the sculpture) has 867 total letters. One line of the "
                        "tableau has an extra 'L' character, making it one character too long "
                        "relative to the other lines. Per Wikipedia (citing Bauer, Link, and "
                        "Molle, Cryptologia 2016): with the extra L, the letters H-I-L-L appear "
                        "consecutively DOWN THE RIGHTMOST COLUMN of the tableau — not across a "
                        "row. This is a physical carving fact on the tableau panel. "
                        "PANEL SEPARATION: the extra L is on the TABLEAU PANEL. The YAR "
                        "superscript (see yar_superscript) is on the CIPHER PANEL. These are "
                        "physically DIFFERENT PANELS — they do not share a horizontal band. Any "
                        "co-location claim is incorrect. "
                        "DIRECTION CORRECTION (2026-04-12 Wikipedia cross-reference): prior "
                        "versions of this entry said 'H-I-L-L read consecutively when scanning "
                        "that row', implying a horizontal reading. The correct reading per the "
                        "published Bauer/Link/Molle analysis is that HILL appears DOWN THE "
                        "RIGHTMOST COLUMN of the tableau. The direction matters — it means the "
                        "extra L is specifically creating a vertical letter sequence, not a "
                        "horizontal one, and the mechanism (if any) would involve reading the "
                        "rightmost column of the tableau as a key source. "
                        "SANBORN BEHAVIOR NOTE (context, not anchor): Per Wikipedia, Sanborn "
                        "omitted the extra L from the small Kryptos models he sold. This is a "
                        "reported fact about the models, not directly verifiable from the main "
                        "sculpture alone. "
                        "COMMUNITY INTERPRETATION (not anchor): Bauer/Link/Molle suggest the "
                        "'HILL' reading references the Hill cipher as a K4 method. The Hill "
                        "cipher is algebraically eliminated for n=2,3,4 under direct positional "
                        "correspondence (elimination_tiers.md Tier 1), so this interpretation "
                        "requires a non-direct mechanism (e.g. Hill as one layer of a multi-layer "
                        "construction) to remain viable. "
                        "SPECULATIVE RECIPE: read the rightmost column of the tableau (26 "
                        "letters + the extra L = 27) as a running key under Vigenere/Beaufort "
                        "against K4. The extra L introduces a one-position shift midway through "
                        "the column, which is testable.",
        "source": "Wikipedia Kryptos article (citing Bauer/Link/Molle 2016); physical tableau panel",
        "priority": 3,
        "status": "open",
    },

    # ── Tier B: Moderate signal, worth testing ───────────────────────────
    # NOTE: comsec_composite REMOVED in 2026-04-12 triage audit — it chained
    # three hearsay-dependent readings ('T IS YOUR POSITION' Morse interpretation,
    # compass deflection, YAR-as-auth-trigraph) into a single speculative
    # procedure with no primary-evidence anchor. See RETIRED_ANOMALY_IDS.
    {
        "anomaly_id": "morse_26e_grille_mask",
        "title": "Morse E's (25-26 extras) as possible grille-mask source",
        "description": "PRIMARY EVIDENCE: The K0 Morse code on the entrance slabs contains approximately "
                        "25-26 extra 'E' letters beyond what the underlying English phrases require. "
                        "The exact count depends on whether the DIGETAL misspelling is counted as an "
                        "extra E (which brings the count to 26). The count '25-26' is from community "
                        "enumeration of the Morse text, which is directly countable from the physical "
                        "slabs. E in Morse is a single dit, the shortest possible character. "
                        "SPECULATIVE RECIPE (P-C1-1 in docs/procedural_anomaly_recipes.md): map the "
                        "E positions to physical line positions on the entrance slabs, project onto "
                        "the cipher panel via a stated spatial correspondence, and use as a grille "
                        "mask to extract K4 characters. The recipe requires FIRST establishing a "
                        "physically meaningful Morse-to-cipher-panel positional correspondence — "
                        "without that, any projection is arbitrary and will produce noise. "
                        "HAZARD: '26 = alphabet size' is numerology unless tied to a mechanism.",
        "source": "physical Morse on K0 entrance slabs, docs/anomaly_registry.md C1",
        "priority": 3,
        "status": "open",
    },
    {
        "anomaly_id": "ct_perturbation",
        "title": "CT perturbation evidence: transcription errors provable from published coding charts",
        "description": "PRIMARY EVIDENCE (two anchor classes): "
                        "(A) SCULPTURE CARVINGS directly readable on the copper: "
                        "  - IQLUSION (K1 plaintext): ILLUSION → IQLUSION. The L→Q change is at "
                        "    the 2nd letter of the word (0-indexed position 1). "
                        "  - UNDERGRUUND (K2 plaintext): UNDERGROUND → UNDERGRUUND. The O→U "
                        "    change is at the 8th letter of the word (0-indexed position 7). "
                        "  - DESPARATLY (K3 plaintext): two changes detailed in "
                        "    desparatly_misspelling (E→A at position 5, E deleted at position 9). "
                        "  - DIGETAL (K0 Morse code): DIGITAL → DIGETAL. The I→E change is at "
                        "    the 4th letter of the word (0-indexed position 3). "
                        "All four carvings are physical facts directly readable on the sculpture. "
                        "POSITION CONVENTION: all letter positions above are 1-indexed within "
                        "the affected word (e.g. 2nd letter = counting 1,2,...). The parenthetical "
                        "0-indexed positions are given for code-facing reference. Prior versions "
                        "of this entry had off-by-one errors on all three of these positional "
                        "claims; corrected 2026-04-13 during the anomaly hardening pass. "
                        "(B) PUBLISHED CODING CHARTS: in November 2010, the New York Times "
                        "published scans of Sanborn's own handwritten coding charts ('Original "
                        "Decoding Charts for Kryptos', NYT 2010 — Wikipedia reference [29]). "
                        "These are primary-source facsimiles of Sanborn's handwriting, not "
                        "testimony. They establish which errors are transcription errors (chart "
                        "correct, sculpture wrong) vs design-phase errors (chart itself has the "
                        "error). Specifically: "
                        "  - UNDERGRUUND: the coding chart spells UNDERGROUND correctly with the "
                        "ABSCISSA keyword also correctly spelled, and the chart's ciphertext "
                        "letter is E. On the sculpture, that letter was carved as R instead. "
                        "Decoding R with the correct ABSCISSA keyword column produces U instead "
                        "of O, yielding UNDERGRUUND. This is a PROVEN transcription-phase error: "
                        "the chart is right, the carving is wrong. "
                        "  - IQLUSION: the coding chart contains the keyword misspelled as "
                        "PALIMPCEST (C instead of S) at one position, while the plaintext "
                        "ILLUSION is correct. The combination produces the ciphertext letter K "
                        "that appears on the sculpture. Decoding K with the correctly-spelled "
                        "PALIMPSEST keyword produces Q instead of L, yielding IQLUSION. This is "
                        "a design-phase error in the keyword, not a transcription error. "
                        "HYPOTHESIS: if the sculptor demonstrably introduced a transcription-"
                        "phase character change in K2 (UNDERGRUUND), he may have introduced 1-N "
                        "such changes in K4. The carved K4 CT may therefore differ from the "
                        "'clean' CT produced by the cipher procedure — but only by character "
                        "changes, not by length changes (the 97-char length is fixed by the "
                        "carved panel). "
                        "SPECULATIVE RECIPE (P-A3-2): systematic single-character substitution "
                        "sweep of all 97 K4 positions × 25 alternatives = 2,425 CT variants, "
                        "each tested against the cribs and Bean constraints. "
                        "HAZARD: the hypothesis is symmetric — any failure of a K4 decryption "
                        "attempt can be rescued by invoking one CT perturbation. A valid "
                        "implementation must pre-register the perturbation budget and penalize "
                        "each used perturbation against the score. "
                        "UPGRADE NOTE: the 'published coding charts' evidence class was "
                        "incorrectly classified as hearsay in the 2026-04-12 audit and stripped "
                        "from this entry. That was an error — NYT 2010 published actual "
                        "facsimiles of Sanborn's handwriting, which is primary source equivalent "
                        "to the AAA archive photographs. The evidence has been restored and the "
                        "triage policy above has been updated to clarify this class.",
        "source": "sculpture carvings (direct) + NYT 2010 published coding chart facsimiles (Wikipedia ref [29])",
        "priority": 3,
        "status": "open",
    },

    # ── Archive-derived (AAA visit 2026-03-27) ──────────────────────────
    # PRIMARY SOURCE: photographs Colin Patrick took first-hand at the
    # Smithsonian Archives of American Art on 2026-03-27 from the "Jim
    # Sanborn papers, circa 1950-2023" collection. These entries anchor on
    # SANBORN'S HANDWRITING ONLY — not on interviews, not on testimony, not
    # on what Sanborn told anyone verbally. Handwriting on archival working
    # papers is the only Sanborn-sourced evidence class this project trusts.
    # See memory/archive_aaa_findings.md and docs/archive_aaa_doctrine.md.
    #
    # The 2026-04-12 triage audit REMOVED aaa_three_keywords and
    # aaa_normandy_keyword — both were interpretive extrapolations from a
    # single notebook phrase and risked spinning the theorist on speculative
    # keyword sweeps with no grounded mechanism. See RETIRED_ANOMALY_IDS.
    {
        "anomaly_id": "aaa_coordinate_lie",
        "title": "'He lied' — two coordinate sets in Sanborn's hand, circled annotation (IMG_1381-1389)",
        "description": "PRIMARY EVIDENCE: photographs of Sanborn notebook pages (IMG_1381-1389) taken "
                        "first-hand at Archives of American Art 2026-03-27 show two coordinate sets "
                        "written in Sanborn's own hand, one above the other, differing in one digit "
                        "of the latitude component. Between the two sets, circled, are the words "
                        "'He lied'. The handwriting is unambiguous; the primary-source fact is that "
                        "Sanborn explicitly marked a discrepancy between the carved K2 coordinates and "
                        "a second coordinate set on the same page. "
                        "INTERPRETATION (separately hedged, not anchor): the modified coordinate is a "
                        "deliberate one-digit deception. This could indicate the sculpture uses a controlled "
                        "distortion of a known reference, which is a general design principle — not a "
                        "specific K4 cipher recipe. "
                        "SPECULATIVE RECIPES (test but do not overweight): "
                        "(1) use HELIED as a candidate keyword across polyalphabetic families; "
                        "(2) use the numeric delta between the two coordinate strings as a Gromark "
                        "seed or shift sequence; "
                        "(3) derive a running-key from either the carved or alternate coordinate "
                        "expressed as a digit string. "
                        "DO NOT extrapolate the coordinates to city names (e.g. 'Fredericksburg', "
                        "'Langley') unless the extrapolation is explicitly justified — the page "
                        "shows coordinates, not city names.",
        "source": "IMG_1381-1389 (Colin Patrick first-hand photographs, AAA 2026-03-27)",
        "priority": 2,
        "status": "open",
    },
    {
        "anomaly_id": "aaa_compass_cipher",
        "title": "Sanborn's handwritten phrase 'compass cipher' + the physical compass rose slab",
        "description": "PRIMARY EVIDENCE (three anchor classes): "
                        "(A) HANDWRITING: photograph IMG_1569 taken first-hand at Archives of "
                        "American Art 2026-03-27 shows a handwritten list in Sanborn's notebook: "
                        "'Beaufort cipher / Compass cipher / Morse code / Alphabet code / "
                        "Cryptotyms', with 'Overload' (underlined) lower on the same page. "
                        "'Compass cipher' appears in Sanborn's own hand alongside three other "
                        "cipher terms that are independently attested elsewhere in Kryptos "
                        "(Beaufort is the K3 system; Morse is on the K0 entrance slabs). The "
                        "list context upgrades 'compass cipher' from "
                        "an isolated phrase to a deliberately enumerated design-period method. "
                        "(B) LODESTONE/METEORITE PAIRING: photograph IMG_1581 shows handwritten "
                        "notes 'Balance between Lodestone / meteorite' (both words underlined) "
                        "and 'meteorites \"messages\" / coded \"when it landed\"'. Sanborn "
                        "explicitly frames meteorites as carriers of coded messages and pairs "
                        "the physical lodestone (on the compass rose slab) with the meteorite "
                        "motif. This is primary evidence that the compass-rose-pointing-at-"
                        "lodestone installation is load-bearing for Sanborn's cipher concept, "
                        "not incidental landscape decoration. "
                        "(C) PHYSICAL INSTALLATION: per Wikipedia (primary-source cited, "
                        "references [1] and [4]), 'one of the stone slabs has an engraving of a "
                        "compass rose pointing to a lodestone'. This is a confirmed physical "
                        "feature of the Kryptos installation — not on the main cipher/tableau "
                        "panels, but on a granite slab outside the New Headquarters Building "
                        "entrance as part of Sanborn's broader installation. The compass rose + "
                        "lodestone combination is a physically directional object: the compass "
                        "points AT the lodestone. "
                        "CRYPTOGRAPHIC CONTEXT: no standard cryptographic cipher is called a "
                        "'compass cipher' in the public literature. The phrase is therefore "
                        "either (a) a Scheidt-original name for a bearing-based construction not "
                        "otherwise published, or (b) Sanborn's own informal name for something "
                        "he had been taught or had invented. The physical compass-rose-pointing-"
                        "at-lodestone object is consistent with 'compass cipher' being a real "
                        "design element, not a discarded note. "
                        "CROSS-REFERENCE WARNING: the Wikipedia article and community sources "
                        "discuss a separate 'compass deflection' anomaly (the compass rose on "
                        "the sculpture allegedly shows a bearing that deviates from true "
                        "direction by a magnetically plausible amount for 1990 Virginia). That "
                        "is a DIFFERENT observation from the handwritten phrase 'compass cipher' "
                        "and from the compass-rose-pointing-at-lodestone. Do not conflate the "
                        "three. "
                        "SPECULATIVE RECIPES (no primary evidence for any specific construction): "
                        "(1) test the physical bearing from the compass rose to the lodestone as "
                        "a numeric parameter (shift value, column index, starting offset) for a "
                        "K4 decryption; "
                        "(2) treat compass bearings (N, NNE, NE, ENE, E, ...) as a 16-element "
                        "alphabet and test as shift indices for a period-16 polyalphabetic; "
                        "(3) search the repo for any 'compass' cipher construction already "
                        "documented (see scripts/mirror_ka, scripts/geometry, scripts/geodetic) "
                        "before proposing new implementations.",
        "source": "IMG_1569 (cipher list including 'Compass cipher'), IMG_1581 (Lodestone/meteorite pairing) — Colin Patrick first-hand photographs, AAA 2026-03-27; Wikipedia Kryptos article on compass rose slab",
        "priority": 2,
        "status": "open",
    },
    {
        "anomaly_id": "aaa_abscissa_tableau_xaxis",
        "title": "Sanborn starred 'Definition of ABSCISSA' on a to-do list (IMG_1340)",
        "description": "PRIMARY EVIDENCE: photograph IMG_1340 taken first-hand at Archives of "
                        "American Art 2026-03-27 shows a handwritten to-do list in Sanborn's hand "
                        "with the starred item 'Definition of ABSCISSA'. The handwriting and the "
                        "star marking are unambiguous. "
                        "CONTEXT (derived fact): ABSCISSA is the keyword used in K2 (publicly "
                        "known from the K2 solve). ABSCISSA is also the mathematical term for the "
                        "x-coordinate in Cartesian geometry. The to-do note shows Sanborn did not "
                        "know the definition offhand during the design period and explicitly "
                        "needed to look it up — which is consistent with ABSCISSA being a "
                        "technical term supplied to him by Scheidt rather than a word he chose "
                        "for thematic reasons. "
                        "INTERPRETATION (not anchor): if Sanborn had to be taught what ABSCISSA "
                        "means, it was likely cipher-technical in his usage. The word may therefore "
                        "correspond to a column-index operation (x-axis) on a grid or tableau, "
                        "distinct from a row-index (ORDINATE / y-axis) operation. The project has "
                        "no primary-source evidence that ABSCISSA appears in a K4-specific "
                        "working paper — only that Sanborn looked up the word in the general "
                        "Kryptos-era notes. "
                        "SPECULATIVE RECIPES: "
                        "(1) test column-indexed KA tableau lookup as an alternative to the "
                        "row-indexed Vigenere operation used for K1-K3; "
                        "(2) test ABSCISSA as a period-8 polyalphabetic keyword against K4; "
                        "(3) search the archive image set for pages where ABSCISSA appears "
                        "alongside K4-related content specifically.",
        "source": "IMG_1340 (Colin Patrick first-hand photographs, AAA 2026-03-27)",
        "priority": 2,
        "status": "open",
    },
    {
        "anomaly_id": "aaa_question_mark_j_stencil",
        "title": "Stencil template shows a J hand-drawn over a ? character (IMG_1531-1532)",
        "description": "PRIMARY EVIDENCE: photographs IMG_1531-1532 taken first-hand at Archives "
                        "of American Art 2026-03-27 show a fabrication-era stencil template for "
                        "the Kryptos punctuation characters. The bottom-row question mark has a "
                        "J shape drawn in pencil overlaid on it, with the J curve sharing the "
                        "lower dot of the ?. "
                        "QUESTION-MARK LOCATIONS ON THE SCULPTURE (corrected 2026-04-12 after "
                        "Wikipedia cross-reference): the cipher panel contains exactly four '?' "
                        "characters among 869 total (865 letters + 4 question marks). Their "
                        "locations, verifiable from the canonical CT published by Wikipedia, "
                        "are NOT at section boundaries: "
                        "  - THREE question marks are embedded inside K2 ciphertext: "
                        "'GGWHKK?DQMC', 'HHDDDUVH?DWK', 'FLGGTEZ?FKZB'. "
                        "  - ONE question mark is at the end of K3 ciphertext: "
                        "'...TRTVDOHW?'. "
                        "  - K1 has ZERO question marks. K4 has ZERO question marks. "
                        "This means the 'section boundary markers' framing is wrong. The "
                        "distribution is: all four '?'s lie in K2 or at the end of K3. Three of "
                        "them are mid-K2, which is significant — they cannot be section "
                        "separators if they're inside a single section. "
                        "COMPETING INTERPRETATIONS: "
                        "(A) Sanborn mentally associated ? with J at the fabrication stage, "
                        "implying the K2 and end-of-K3 question marks secretly encode the "
                        "letter J. In this reading, K2 contains 3 hidden J's at the ?-positions "
                        "and K3 ends with a hidden J. Note that the K2 plaintext has already "
                        "been fully decoded using ABSCISSA — adding J's at the ?-positions would "
                        "either break the existing K2 decryption or imply those positions are "
                        "treated specially by the K2 decoder. Neither is consistent with the "
                        "published K2 solve, which reduces the plausibility of interpretation A. "
                        "(B) Workshop testing: the stencil fabricator was checking whether the "
                        "J character could be produced by modifying the existing ? template — a "
                        "purely mechanical fit-check unrelated to any cipher meaning. "
                        "CURRENT ASSESSMENT: interpretation B is more consistent with the K2 "
                        "solve; interpretation A would require a mechanism that selectively "
                        "ignores the J-substitution during K2 decryption but applies it elsewhere. "
                        "Neither is proven. The archive photograph itself is a physical fact "
                        "(Sanborn drew a J over a ? on a stencil); the cipher-significance "
                        "interpretation is speculative. "
                        "SPECULATIVE RECIPE (budget-limited, low priority): treat the K3 "
                        "end-of-section ? as a candidate hidden J and check whether appending J "
                        "to the K3 CT before K4 begins changes the K4 crib alignment. Do NOT "
                        "modify K2 unless a mechanism is proposed that explains why the existing "
                        "K2 decryption still works. Do NOT enumerate 4-position J-insertion "
                        "combinations — that is a noise-floor search.",
        "source": "IMG_1531-1532 (Colin Patrick first-hand photographs, AAA 2026-03-27); question-mark locations from Wikipedia canonical CT",
        "priority": 4,
        "status": "open",
    },
    {
        "anomaly_id": "aaa_stego_principle_handwritten",
        "title": "Sanborn's handwritten stego principle: 'encrypted message included within a set of modern day font characters'",
        "description": "PRIMARY EVIDENCE: photograph IMG_1236 taken first-hand at Archives of "
                        "American Art 2026-03-27 shows a design-period notebook page with a "
                        "building sketch (architectural facade with symbols above a doorway) "
                        "and handwritten caption in Sanborn's hand: 'encrypted message is "
                        "included within a set of modern day font characters. Could be done "
                        "to shade an area.' The handwriting is unambiguous. "
                        "WHAT IT ESTABLISHES: Sanborn explicitly articulated a steganographic "
                        "principle in which the carrier is a set of font characters and the "
                        "secondary effect is visual shading of an area. This is primary-source "
                        "evidence that a stego layer — where the cipher-bearing characters ALSO "
                        "serve a visual/spatial function — was in Sanborn's design vocabulary. "
                        "Prior stego hypotheses (null mask, character-density patterns) have "
                        "rested on community inference; this is the first primary anchor that "
                        "Sanborn himself thought in these terms. "
                        "IMPORTANT LIMITS: "
                        "  - The note is general, not K4-specific. It may describe a technique "
                        "    considered for any Kryptos-era project, not necessarily K4. "
                        "  - 'Shade an area' could mean literal visual density (dense vs "
                        "    sparse characters producing a shaded region) OR could be "
                        "    metaphorical. Do not assume a specific mechanism. "
                        "  - This does NOT resurrect the retired palette/null-mask construct. "
                        "    The retired palette failed because its selection rule was post-hoc, "
                        "    not because stego is impossible. This note is orthogonal. "
                        "SPECULATIVE RECIPES: "
                        "(1) test whether K4's character distribution produces a visual shading "
                        "pattern when rendered in a mono-spaced grid (heavy letters like M/W "
                        "clustering vs thin letters like I/J/L); "
                        "(2) check whether the 4 question marks, the L/YAR superscripts, and "
                        "the tableau extra-L collectively define a shaded region when projected "
                        "onto a uniform grid; "
                        "(3) search the archive image set for additional pages that elaborate "
                        "the 'shade an area' mechanism before committing compute.",
        "source": "IMG_1236 (Colin Patrick first-hand photograph, AAA 2026-03-27)",
        "priority": 2,
        "status": "open",
    },
    {
        "anomaly_id": "aaa_amber_transparency_overlay",
        "title": "Amber transparency with street grid positioned over KA tableau (IMG_1221)",
        "description": "PRIMARY EVIDENCE: photograph IMG_1221 taken first-hand at Archives of "
                        "American Art 2026-03-27 shows a physical working artifact: an amber/"
                        "orange transparent film bearing a street-grid map, laid directly over "
                        "what appears to be the Kryptos KA tableau (grid of letters visible "
                        "beneath and to the right of the transparency). The transparency is "
                        "not casually placed — it is registered over the tableau, and the "
                        "overall composition is a physical overlay test. "
                        "WHAT IT ESTABLISHES: Sanborn physically experimented with overlaying "
                        "a map onto the cipher tableau during the design period. This is "
                        "primary-source evidence for the 'physical overlay' hypothesis class "
                        "(family_id=physical_overlay, Tier 4) and a direct anchor that the "
                        "two-layer 'map + tableau' composition was an actual fabrication-era "
                        "activity, not a community retrofit. "
                        "MAP IDENTITY: the registry treats the map identity as unverified from "
                        "this image alone. Independent comparison against a known city grid would "
                        "be required before promoting this from 'grid-shaped transparency' to a "
                        "specific named map over the tableau. "
                        "IMPORTANT LIMITS: "
                        "  - One photograph of a physical object does not establish that the "
                        "    overlay is the K4 mechanism. It establishes that Sanborn tried it. "
                        "  - The transparency might have been part of a discarded or abandoned "
                        "    approach, a different project, or a visual study only. "
                        "  - Do NOT propose full coordinate systems from this single image "
                        "    without additional anchors. "
                        "SPECULATIVE RECIPES: "
                        "(1) identify the city/map depicted on the transparency from the raw image "
                        "or independent comparison; "
                        "(2) if identified, test whether registering that street grid on the "
                        "carved tableau selects a meaningful subset of letter positions; "
                        "(3) treat as one of several 'physical overlay' primary anchors "
                        "(alongside the compass-rose-lodestone and any photographic materials "
                        "Shaw may have produced) before committing significant compute.",
        "source": "IMG_1221 (Colin Patrick first-hand photograph, AAA 2026-03-27)",
        "priority": 3,
        "status": "open",
    },

    # ── Tier C: Weak or disputed ─────────────────────────────────────────
    {
        "anomaly_id": "pre_ene_high_ic",
        "title": "High IC in pre-ENE segment (statistically insignificant)",
        "description": "Positions 0-20 have IC ≈ 0.0667 (English-like), suggesting different treatment from post-ENE. "
                        "Bonferroni-corrected p=1.0 (E-FRAC-19), so statistically insignificant, "
                        "but the possibility of a separate sub-cipher at 0-20 is not formally dead.",
        "source": "kernel computation",
        "priority": 4,
        "status": "open",
    },
    # NOTE: w_delimiter_pattern REMOVED in 2026-04-13 hardening pass.
    # The entry had no specific positions, no mechanism, no citation
    # beyond "community analysis", and was already marked disputed.
    # Per the triage policy above, entries without a PRIMARY or DERIVED
    # anchor must not live in KNOWN_ANOMALIES. See RETIRED_ANOMALY_IDS.
]


# Controller reset policy (2026-04-15 hardening pass).
#
# Historical controller work remains visible in the ledger, but only this
# narrow anomaly subset is admissible as active theorist-prompting surface on
# next launch. The broader anomaly registry still exists for audit/history; it
# must not directly steer new generation after the null/stego contamination
# review.
ADMISSIBLE_PROMPT_ANOMALY_IDS: frozenset[str] = frozenset({
    "ct_perturbation",
    "aaa_coordinate_lie",
    "aaa_compass_cipher",
    "width21_vertical_bigrams",
    "w_delimiter_segments",
})


# Stale pending theories that should not survive the controller reset as active
# queue items. These are not eliminations; they are withdrawn from future
# launch state because their anomaly surface is retired or demoted from active
# prompting.
RETIRED_CONTROLLER_QUEUE_THEORIES: dict[str, str] = {
    "d09b21234352": (
        "withdrawn by controller reset: stehle_delta5_lag4 is no longer an "
        "active prompting surface"
    ),
    "62c962f23bfc": (
        "withdrawn by controller reset: retired null-palette anomaly"
    ),
    "ec869ce2c224": (
        "withdrawn by controller reset: retired null-palette anomaly"
    ),
    "98a63db676d4": (
        "withdrawn by controller reset: retired null-palette anomaly"
    ),
    "2e25d5885768": (
        "withdrawn by controller reset: null-mask/stego discriminator theory "
        "on a demoted anomaly surface"
    ),
}


# ---------------------------------------------------------------------------
# Bootstrap functions
# ---------------------------------------------------------------------------

def bootstrap_families(ledger: TheoryLedger) -> int:
    """Populate the family registry from known data. Returns count added/updated.

    For NEW families: insert with seed metadata.
    For EXISTING families: refresh metadata fields (name, status, elimination_tier,
    elimination_evidence) WITHOUT clobbering live stats (total_theories,
    eliminated_theories, best_score). This is the bridge that lets external
    campaign work update the controller's view of the family landscape on
    every controller launch — so stego_layer doesn't keep showing as
    "untested" after a campaign has tested it.
    """
    count = 0
    refreshed = 0
    for fam_data in KNOWN_FAMILIES:
        tier = fam_data["tier"]
        if tier <= 1:
            status = FamilyStatus.EXHAUSTED
        elif tier == 2:
            status = FamilyStatus.EXHAUSTED
        elif tier == 3:
            status = FamilyStatus.PARTIALLY_EXPLORED
        else:
            status = FamilyStatus.ACTIVE

        existing = ledger.get_family(fam_data["family_id"])
        if existing is None:
            # New family — insert with seed metadata only
            fam = FamilyRecord(
                family_id=fam_data["family_id"],
                name=fam_data["name"],
                status=status,
                elimination_tier=tier,
                elimination_evidence=fam_data.get("evidence", ""),
            )
            ledger.upsert_family(fam)
            count += 1
        else:
            # Existing family — refresh metadata, preserve live stats
            seed_evidence = fam_data.get("evidence", "")
            seed_name = fam_data["name"]
            metadata_changed = (
                existing.name != seed_name
                or existing.status != status
                or existing.elimination_tier != tier
                or existing.elimination_evidence != seed_evidence
            )
            if metadata_changed:
                existing.name = seed_name
                existing.status = status
                existing.elimination_tier = tier
                existing.elimination_evidence = seed_evidence
                # Preserve: total_theories, eliminated_theories, best_score, notes
                ledger.upsert_family(existing)
                refreshed += 1

    if refreshed:
        logger.info("bootstrap_families: refreshed %d existing family records", refreshed)
    return count


# Anomalies that must be retired if they exist in the DB from prior runs.
# These are on the do-not-revive list (MEMORY.md §5) or have been superseded.
RETIRED_ANOMALY_IDS: list[str] = [
    "bcl_beaufort_palette_enrichment",   # palette family retired 2026-04-01
    "null_palette_diversity",            # palette family retired 2026-04-01
    "ka_mod5_column_structure",          # palette family retired 2026-04-01
    # ── 2026-04-12 triage audit (Colin Patrick) ─────────────────────────
    # Removed because the entry chained three hearsay-dependent readings
    # ('T IS YOUR POSITION' Morse interpretation, compass deflection
    # direction, YAR-as-auth-trigraph) into a single speculative procedure
    # with no primary-evidence anchor.
    "comsec_composite",
    # Removed because the anchor was 'Sanborn reportedly refused to answer'
    # — testimonial hearsay about interview behavior, not a physical or
    # computational fact. The underlying misspelling is retained under the
    # new anomaly_id 'desparatly_misspelling' which anchors on the K3
    # plaintext only.
    "desparatly_skip_stride",
    # Removed because the anchor was an interpretive leap from one
    # notebook phrase ('A choice of 3 words most typified the way of life',
    # IMG_1567-1568) to a triple-keyword cipher construction. The phrase
    # reads more naturally as CIA/KGB tradecraft commentary than as a
    # cipher instruction, and the extrapolation has no second source.
    "aaa_three_keywords",
    # Removed because 'Normandy' appears once in a Sanborn notebook list
    # (IMG_1569-1570) and was extrapolated to Eisenhower-running-key,
    # OMAHA/UTAH/OVERLORD keyword sweeps, and thematic Cold War content.
    # Normandy is not a cipher and the entry had no grounded mechanism.
    "aaa_normandy_keyword",
    # Renamed to tableau_l_row_n_extra with a panel-separation correction:
    # the extra L is on the TABLEAU panel, the YAR superscript is on the
    # CIPHER panel. They are on physically different panels and do not
    # share a horizontal band. The prior entry claimed a co-location that
    # is not physically true.
    "tableau_overlay_misaligned",
    # ── 2026-04-13 hardening pass ───────────────────────────────────────
    # Removed because the entry had no specific W positions, no stated
    # mechanism, no citation beyond "community analysis", and was already
    # marked disputed. Per the triage policy in KNOWN_ANOMALIES, entries
    # without a PRIMARY or DERIVED anchor must not live in the registry.
    # The "W as delimiter" idea can be re-proposed if someone produces
    # a specific mechanism with falsifiable prediction.
    "w_delimiter_pattern",
]


def bootstrap_anomalies(ledger: TheoryLedger) -> int:
    """Populate the anomaly registry from known data.

    For NEW anomalies: insert with seed metadata.
    For EXISTING anomalies: refresh metadata fields (title, description,
    source) from KNOWN_ANOMALIES on every launch WITHOUT clobbering live
    state (theories_exploring, evidence_for, evidence_against, created_at,
    or a status that has been transitioned away from OPEN by the controller
    during normal operation). This is the analog of bootstrap_families'
    refresh pattern — it ensures that when the authoritative source of
    truth (KNOWN_ANOMALIES in this file) is updated with corrected titles
    or descriptions (e.g. after a triage audit), those corrections reach
    the theorist on the next launch instead of being stranded in the
    SQLite ledger.

    Returns count of NEWLY ADDED anomalies (refreshed ones are not counted).
    """
    count = 0
    refreshed = 0

    # Retire anomalies that should no longer be active
    for anom_id in RETIRED_ANOMALY_IDS:
        existing = ledger.get_anomaly(anom_id)
        if existing and existing.status != AnomalyStatus.IRRELEVANT:
            existing.status = AnomalyStatus.IRRELEVANT
            existing.description = (
                "[RETIRED 2026-04-11] " + existing.description
            )
            ledger.upsert_anomaly(existing)
            logger.info("Retired anomaly %s", anom_id)

    # Add or refresh known anomalies
    for anom_data in KNOWN_ANOMALIES:
        aid = anom_data["anomaly_id"]
        existing = ledger.get_anomaly(aid)

        if existing is None:
            # NEW anomaly — insert with seed metadata
            anom = AnomalyRecord(
                anomaly_id=aid,
                title=anom_data["title"],
                description=anom_data["description"],
                status=AnomalyStatus(anom_data.get("status", "open")),
                source=anom_data.get("source", ""),
            )
            ledger.upsert_anomaly(anom)
            count += 1
        else:
            # EXISTING anomaly — refresh text fields from KNOWN_ANOMALIES
            # but preserve live state (theories_exploring, evidence lists,
            # created_at). Refresh status ONLY if the registry now says
            # something other than 'open' AND the existing status is still
            # OPEN — this lets the registry mark entries as disputed/etc.
            # without clobbering an IRRELEVANT or closed status that was
            # set through normal controller operation.
            changed = False
            new_title = anom_data["title"]
            new_desc = anom_data["description"]
            new_source = anom_data.get("source", "")
            new_status = AnomalyStatus(anom_data.get("status", "open"))

            if existing.title != new_title:
                existing.title = new_title
                changed = True
            if existing.description != new_desc:
                existing.description = new_desc
                changed = True
            if existing.source != new_source:
                existing.source = new_source
                changed = True
            if (
                existing.status == AnomalyStatus.OPEN
                and new_status != AnomalyStatus.OPEN
            ):
                existing.status = new_status
                changed = True

            if changed:
                ledger.upsert_anomaly(existing)
                refreshed += 1

    if refreshed:
        logger.info(
            "bootstrap_anomalies: refreshed %d existing anomaly records",
            refreshed,
        )
    return count


def bootstrap_controller_queue_reset(ledger: TheoryLedger) -> int:
    """Withdraw stale pre-reset queue items that should not relaunch.

    This only touches nonterminal controller queue rows. Historical completed
    or eliminated work is preserved unchanged.
    """
    changed = 0
    for hypothesis_id, reason in RETIRED_CONTROLLER_QUEUE_THEORIES.items():
        theory = ledger.get_theory(hypothesis_id)
        if theory is None or theory.status in {
            TheoryStatus.WITHDRAWN,
            TheoryStatus.ELIMINATED,
            TheoryStatus.COMPLETED,
            TheoryStatus.PROMISING,
            TheoryStatus.SUPERSEDED,
        }:
            continue
        theory.status = TheoryStatus.WITHDRAWN
        marker = f"[controller-reset 2026-04-15] {reason}"
        if marker not in (theory.notes or ""):
            theory.notes = f"{theory.notes}\n{marker}".strip()
        ledger.upsert_theory(theory)
        changed += 1
    if changed:
        logger.info(
            "bootstrap_controller_queue_reset: withdrew %d stale queue items",
            changed,
        )
    return changed


def load_exhaustion_families(
    ledger: TheoryLedger,
    exhaustion_log_path: Path,
) -> int:
    """
    Enrich family registry from the repo's exhaustion_log.json.

    Groups scripts by family, counts exhausted vs active, and updates
    family records accordingly.
    """
    if not exhaustion_log_path.exists():
        logger.warning("Exhaustion log not found at %s", exhaustion_log_path)
        return 0

    log = json.loads(exhaustion_log_path.read_text())
    family_stats: dict[str, dict[str, int]] = {}

    for script_id, entry in log.items():
        fam = entry.get("family", "unknown")
        # Normalize family names to our family_id format
        fam_id = fam.replace("/", "_").replace(" ", "_").lower()
        if fam_id not in family_stats:
            family_stats[fam_id] = {"total": 0, "exhausted": 0}
        family_stats[fam_id]["total"] += 1
        if entry.get("status") == "exhausted":
            family_stats[fam_id]["exhausted"] += 1

    count = 0
    for fam_id, stats in family_stats.items():
        existing = ledger.get_family(fam_id)
        if existing:
            # Update stats on existing family
            existing.total_theories = max(existing.total_theories, stats["total"])
            existing.eliminated_theories = max(existing.eliminated_theories, stats["exhausted"])
            ledger.upsert_family(existing)
        else:
            # Create a new family record from exhaustion data
            ratio = stats["exhausted"] / stats["total"] if stats["total"] > 0 else 0
            if ratio >= 0.9:
                status = FamilyStatus.EXHAUSTED
            elif ratio >= 0.3:
                status = FamilyStatus.PARTIALLY_EXPLORED
            else:
                status = FamilyStatus.ACTIVE

            fam = FamilyRecord(
                family_id=fam_id,
                name=fam_id.replace("_", " ").title(),
                status=status,
                total_theories=stats["total"],
                eliminated_theories=stats["exhausted"],
            )
            ledger.upsert_family(fam)
            count += 1

    return count


def bootstrap_campaign_manifests(
    ledger: TheoryLedger,
    project_root: Path,
) -> int:
    """Read campaign manifests from results/campaign_manifests/ and update
    family records accordingly.

    This is the structural bridge between external campaign work and the
    controller's family registry. When a campaign in scripts/campaigns/
    or src/kryptos/campaigns/ produces a notable result, it writes a
    JSON manifest. The controller reads those manifests at every bootstrap
    and updates the family records' tier and evidence text — without
    clobbering live stats.

    Conservative: tier is only ever moved UPWARD (more eliminated). Evidence
    text is overwritten with the manifest's payload (the manifest is
    treated as the canonical statement of what the campaign found).

    Returns the count of family records updated.
    """
    # Try to import the campaign manifest reader. If kryptos.campaigns.manifest
    # is not available (e.g., the user is running an older repo), fall back
    # to plain JSON parsing so kryptosbot remains decoupled from the campaigns
    # package version.
    manifest_dir = project_root / "results" / "campaign_manifests"
    if not manifest_dir.exists():
        return 0

    # Build the scan list: HISTORICAL first, LIVE top-level manifests second.
    # Live entries must land last so they overlay older historical backfill
    # data when both touch the same family. The conservative tier-merging
    # logic below (only move tier upward) also protects against regressions.
    live_paths = sorted(manifest_dir.glob("*.json"))
    historical_dir = manifest_dir / "historical"
    historical_paths = (
        sorted(historical_dir.glob("*.json"))
        if historical_dir.exists()
        else []
    )
    all_paths = historical_paths + live_paths

    updated = 0
    for manifest_path in all_paths:
        try:
            data = json.loads(manifest_path.read_text())
        except Exception as exc:
            logger.warning("Failed to read manifest %s: %s", manifest_path.name, exc)
            continue

        family_updates = data.get("family_updates", {})
        if not family_updates:
            continue

        for fid, update in family_updates.items():
            existing = ledger.get_family(fid)
            if existing is None:
                # Create a new family record from the manifest update.
                # (FamilyRecord and FamilyStatus are imported at module level.)
                new_tier = int(update.get("tier", 4))
                if new_tier <= 2:
                    status = FamilyStatus.EXHAUSTED
                elif new_tier == 3:
                    status = FamilyStatus.PARTIALLY_EXPLORED
                else:
                    status = FamilyStatus.ACTIVE
                fam = FamilyRecord(
                    family_id=fid,
                    name=update.get("name", fid.replace("_", " ").title()),
                    status=status,
                    elimination_tier=new_tier,
                    elimination_evidence=update.get("evidence", ""),
                )
                ledger.upsert_family(fam)
                updated += 1
            else:
                # Update tier (only upward) and evidence text
                new_tier = int(update.get("tier", existing.elimination_tier))
                changed = False
                # Conservative: only move tier UP (toward more eliminated)
                # Tier numbering: 1=structural, 2=empirical, 3=partial, 4=untested
                # Lower number = more eliminated
                if new_tier < existing.elimination_tier or existing.elimination_tier == 0:
                    existing.elimination_tier = new_tier
                    changed = True
                    if new_tier <= 2:
                        existing.status = FamilyStatus.EXHAUSTED
                    elif new_tier == 3:
                        existing.status = FamilyStatus.PARTIALLY_EXPLORED
                    else:
                        existing.status = FamilyStatus.ACTIVE

                # Always refresh evidence text from manifest
                manifest_evidence = update.get("evidence", "")
                if manifest_evidence and existing.elimination_evidence != manifest_evidence:
                    existing.elimination_evidence = manifest_evidence
                    changed = True

                if changed:
                    ledger.upsert_family(existing)
                    updated += 1

    if updated:
        logger.info(
            "bootstrap_campaign_manifests: updated %d family record(s) "
            "from %s manifest file(s) (%s live + %s historical)",
            updated,
            len(all_paths),
            len(live_paths),
            len(historical_paths),
        )
    return updated


def bootstrap_local_reruns(
    ledger: TheoryLedger,
    project_root: Path,
) -> int:
    """Ingest structured local rerun manifests into the theory ledger."""
    rerun_root = project_root / "results" / "reruns"
    if not rerun_root.exists():
        return 0

    applied = 0
    for manifest in sorted(rerun_root.glob("*/rerun_manifest.jsonl")):
        for raw_line in manifest.read_text(encoding="utf-8").splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                entry = json.loads(raw_line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed rerun manifest line in %s", manifest)
                continue

            target = str(entry.get("target", "")).strip()
            theory_ids = [
                str(v).strip()
                for v in entry.get("theory_ids", [])
                if str(v).strip()
            ]
            if not target or not theory_ids:
                continue

            summary_lines = [
                str(v).strip()
                for v in entry.get("summary_lines", [])
                if str(v).strip()
            ]
            log_files = [
                str(v).strip()
                for v in entry.get("log_files", [])
                if str(v).strip()
            ]
            script_paths = [
                str(v).strip()
                for v in entry.get("script_paths", [])
                if str(v).strip()
            ]

            manifest_key = hashlib.sha256(
                f"{manifest}:{target}:{','.join(theory_ids)}".encode("utf-8")
            ).hexdigest()[:12]

            for hypothesis_id in theory_ids:
                theory = ledger.get_theory(hypothesis_id)
                if theory is None:
                    continue

                exp_id = f"rerun-{manifest_key}-{hypothesis_id[:8]}"
                contract = WorkerContract(
                    hypothesis_id=hypothesis_id,
                    worker_role="local_rerun",
                    status=WorkerStatus.DISPROVED,
                    score=0.0,
                    crib_score=0,
                    bean_passed=False,
                    best_plaintext="",
                    disproof_evidence=summary_lines[:8],
                    supporting_evidence=[
                        f"manifest={manifest}",
                        *[f"script={p}" for p in script_paths[:4]],
                    ],
                    next_action="Preserve as rerun-backed historical elimination evidence",
                    family_generalization="Bounded local rerun completed for this family",
                    raw_artifacts={
                        "manifest_path": str(manifest),
                        "log_files": log_files,
                        "script_paths": script_paths,
                        "result_class": entry.get("result_class", ""),
                    },
                    narrative_summary=(
                        f"Local rerun target '{target}' completed successfully; "
                        f"see logs {', '.join(log_files)}"
                    ),
                )
                ledger.record_experiment(
                    ExperimentRecord(
                        experiment_id=exp_id,
                        hypothesis_id=hypothesis_id,
                        worker_role="local_rerun",
                        config={
                            "source": "results/reruns manifest",
                            "target": target,
                            "manifest_path": str(manifest),
                            "script_paths": script_paths,
                        },
                        result=contract,
                        script_id=f"rerun:{target}",
                    )
                )

                if exp_id not in theory.experiment_ids:
                    theory.experiment_ids.append(exp_id)
                note_marker = f"[local-rerun:{target}]"
                if note_marker not in theory.notes:
                    summary = " | ".join(summary_lines[:3])[:1200]
                    theory.notes = f"{theory.notes}\n{note_marker} {summary}".strip()
                ledger.upsert_theory(theory)
                applied += 1

    if applied:
        logger.info("bootstrap_local_reruns: applied %d rerun experiment links", applied)
    return applied


def bootstrap_claims(ledger: TheoryLedger) -> int:
    """Populate the provenance claims registry. Returns count added/updated.

    Idempotent — existing claims are upserted with the canonical definition.
    """
    from .claims_registry import CANONICAL_CLAIMS

    count = 0
    for claim in CANONICAL_CLAIMS:
        ledger.upsert_claim(claim)
        count += 1
    return count


def bootstrap_all(
    ledger: TheoryLedger,
    project_root: Path | None = None,
) -> dict[str, int]:
    """Run all bootstrap operations. Returns counts.

    Order matters: families seed first, then exhaustion log enriches them,
    then campaign manifests overlay the canonical campaign-derived metadata
    on top. This way the most recent and most authoritative source wins.
    """
    result = {
        "families_added": bootstrap_families(ledger),
        "anomalies_added": bootstrap_anomalies(ledger),
        "claims_added": bootstrap_claims(ledger),
        "exhaustion_families": 0,
        "campaign_manifests_applied": 0,
        "local_reruns_applied": 0,
        "queue_reset_withdrawn": bootstrap_controller_queue_reset(ledger),
    }

    if project_root:
        exhaust_path = project_root / "exhaustion_log.json"
        if exhaust_path.exists():
            result["exhaustion_families"] = load_exhaustion_families(
                ledger, exhaust_path
            )

        # Campaign manifests are the canonical source for campaign-tested
        # families. They run AFTER exhaustion log loading so they overlay
        # the more authoritative campaign-level evidence.
        result["campaign_manifests_applied"] = bootstrap_campaign_manifests(
            ledger, project_root
        )
        result["local_reruns_applied"] = bootstrap_local_reruns(
            ledger, project_root
        )

    logger.info("Bootstrap complete: %s", result)
    return result
