"""
Canonical ProvenanceClaim registry for KryptosBot.

Single source of truth for epistemic status of every non-trivial claim the
controller uses. Each entry is tagged with an EpistemicClass, scope_conditions,
allowed_downstream_uses, and where relevant a dependency_chain.

Red-team invariants enforced here:
- All Bean-derived claims carry assumes_direct_positional_crib_alignment=True.
- Bean "624" claim explicitly scopes to the 24 crib positions.
- Bean-reported statistics remain BEAN_REPORTED_NOT_RERUN until an audit script
  independently reproduces the exact statistic and records its scope.
- Physical anomalies are split into EXISTENCE + INTERPRETATION claims.
- Retired palette is RETIRED_CLAIM, SUMMARY-only.
- Periodic-poly elimination is CONDITIONAL_ELIMINATION (direct positional
  alignment); pure transposition impossible is STRUCTURAL_ELIMINATION.
"""

from __future__ import annotations

from .provenance import (
    ProvenanceClaim,
    ScopeConditions,
    EpistemicClass as EC,
    VerificationStatus as VS,
    ReproducibilityStatus as RS,
    AllowedUse as AU,
)


def _pc(**kw) -> ProvenanceClaim:
    return ProvenanceClaim(**kw)


# ---------------------------------------------------------------------------
# Canonical claims
# ---------------------------------------------------------------------------

CANONICAL_CLAIMS: list[ProvenanceClaim] = [

    # === PUBLIC / PRIMARY-SOURCE FACTS ===========================================

    _pc(
        claim_id="k4_ct_97char",
        claim_text=(
            "K4 ciphertext is the 97-character string "
            "OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR"
        ),
        epistemic_class=EC.PUBLIC_FACT,
        scope_conditions=ScopeConditions(
            applies_to_entire_cipher=True,
            scope_notes="Canonical carved transcription. Verified in kryptos.kernel.constants.CT.",
        ),
        source_basis="Sanborn sculpture at CIA HQ; kryptos.kernel.constants.CT",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        allowed_downstream_uses=[
            AU.SUMMARY, AU.HARD_CONSTRAINT, AU.RANKING_FEATURE,
            AU.ELIMINATION_BASIS, AU.PROMPT_CONTEXT,
        ],
        tags=["ciphertext", "canonical"],
    ),

    _pc(
        claim_id="ene_disclosure",
        claim_text=(
            "Sanborn publicly disclosed that 'EASTNORTHEAST' is part of the K4 plaintext."
        ),
        epistemic_class=EC.PRIMARY_SOURCE_FACT,
        scope_conditions=ScopeConditions(
            scope_notes=(
                "Disclosure of the word itself. The binding of EASTNORTHEAST to a "
                "specific carved position range is a SEPARATE claim."
            ),
        ),
        source_basis="Sanborn 2010 disclosure (NYT)",
        verification_status=VS.PRIMARY_SOURCE_DOCUMENTED,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT, AU.RANKING_FEATURE],
        tags=["crib", "disclosure"],
    ),

    _pc(
        claim_id="berlin_disclosure",
        claim_text="Sanborn publicly disclosed that 'BERLIN' is part of the K4 plaintext.",
        epistemic_class=EC.PRIMARY_SOURCE_FACT,
        source_basis="Sanborn 2010 disclosure",
        verification_status=VS.PRIMARY_SOURCE_DOCUMENTED,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT, AU.RANKING_FEATURE],
        tags=["crib", "disclosure"],
    ),

    _pc(
        claim_id="clock_disclosure",
        claim_text=(
            "Sanborn publicly disclosed that 'CLOCK' is part of the K4 plaintext. "
            "CLOCK was disclosed independently; BERLINCLOCK adjacency is community consensus, "
            "not a creator statement."
        ),
        epistemic_class=EC.PRIMARY_SOURCE_FACT,
        source_basis="Sanborn 2014 disclosure",
        verification_status=VS.PRIMARY_SOURCE_DOCUMENTED,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT, AU.RANKING_FEATURE],
        tags=["crib", "disclosure"],
    ),

    _pc(
        claim_id="k1_solved",
        claim_text="K1 solved by Gillogly/Stein (1999): Vigenère with keyword PALIMPSEST and KRYPTOS tableau.",
        epistemic_class=EC.PRIMARY_SOURCE_FACT,
        source_basis="Gillogly/Stein 1999",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT, AU.RANKING_FEATURE],
        tags=["solved"],
    ),
    _pc(
        claim_id="k2_solved",
        claim_text="K2 solved by Gillogly/Stein (1999): Vigenère with keyword ABSCISSA and KRYPTOS tableau.",
        epistemic_class=EC.PRIMARY_SOURCE_FACT,
        source_basis="Gillogly/Stein 1999",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT, AU.RANKING_FEATURE],
        tags=["solved"],
    ),
    _pc(
        claim_id="k3_solved",
        claim_text="K3 solved by Gillogly/Stein (1999): keyed columnar transposition.",
        epistemic_class=EC.PRIMARY_SOURCE_FACT,
        source_basis="Gillogly/Stein 1999",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT, AU.RANKING_FEATURE],
        tags=["solved"],
    ),

    _pc(
        claim_id="k2_layer_two_sanborn_statement",
        claim_text=(
            "Sanborn stated in 2006 correspondence that K2 contains a reference "
            "reading 'X LAYER TWO'."
        ),
        epistemic_class=EC.PRIMARY_SOURCE_FACT,
        source_basis="Sanborn 2006 correspondence",
        verification_status=VS.PRIMARY_SOURCE_DOCUMENTED,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT],
        tags=["sanborn", "layer_two"],
    ),
    _pc(
        claim_id="k2_layer_two_operational_hypothesis",
        claim_text=(
            "The 'X LAYER TWO' Sanborn statement implies K4 requires a second, "
            "distinct operational layer beyond standard decryption."
        ),
        epistemic_class=EC.HYPOTHESIS,
        dependency_chain=["k2_layer_two_sanborn_statement"],
        source_basis="Interpretation of Sanborn 2006",
        verification_status=VS.PENDING_VERIFICATION,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT, AU.RANKING_FEATURE],
        tags=["hypothesis", "layer_two"],
    ),

    _pc(
        claim_id="kryptos_alphabet_ordering",
        claim_text=(
            "The KRYPTOS keyed alphabet used by K1-K3 is "
            "KRYPTOSABCDEFGHIJLMNQUVWXZ (all 26 letters, keyword first)."
        ),
        epistemic_class=EC.PUBLIC_FACT,
        source_basis="Physical sculpture tableau; kryptos.kernel.alphabet.KA",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        allowed_downstream_uses=[
            AU.SUMMARY, AU.HARD_CONSTRAINT, AU.PROMPT_CONTEXT, AU.RANKING_FEATURE,
        ],
        tags=["alphabet"],
    ),

    # === H1-CONDITIONAL DERIVATIONS ==============================================

    _pc(
        claim_id="fp32_modeled",
        claim_text=(
            "Under direct positional crib mapping, K[32]=0 (a fixed point) because "
            "CT[32]='S' and PT[32]='S' at the anchored EASTNORTHEAST position."
        ),
        epistemic_class=EC.H1_CONDITIONAL_DERIVATION,
        scope_conditions=ScopeConditions(
            assumes_direct_positional_crib_alignment=True,
            assumes_canonical_97_char_transcription=True,
            assumes_modeled_crib_positions=True,
            applies_only_to_crib_positions=True,
            valid_under_multilayer_composition=False,
            scope_notes=(
                "Only holds under H1. If any rearrangement, masking, or selector layer "
                "precedes the analyzed cipher step, the positional identity dissolves."
            ),
        ),
        dependency_chain=["k4_ct_97char", "ene_disclosure"],
        source_basis="Derivation from CT + anchored ENE crib",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "Does NOT hold if the carved CT is rearranged, masked, or filtered before "
            "the cipher step.",
        ],
        allowed_downstream_uses=[AU.SUMMARY, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT],
        tags=["fixed_point", "h1"],
    ),

    _pc(
        claim_id="fp73_modeled",
        claim_text=(
            "Under direct positional crib mapping, K[73]=0 (a fixed point) because "
            "CT[73]='K' and PT[73]='K' at the anchored BERLIN position."
        ),
        epistemic_class=EC.H1_CONDITIONAL_DERIVATION,
        scope_conditions=ScopeConditions(
            assumes_direct_positional_crib_alignment=True,
            assumes_canonical_97_char_transcription=True,
            assumes_modeled_crib_positions=True,
            applies_only_to_crib_positions=True,
            valid_under_multilayer_composition=False,
            scope_notes="Only holds under H1 (see fp32_modeled).",
        ),
        dependency_chain=["k4_ct_97char", "berlin_disclosure"],
        source_basis="Derivation from CT + anchored BERLIN crib",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "Does NOT hold if the carved CT is rearranged, masked, or filtered before "
            "the cipher step.",
        ],
        allowed_downstream_uses=[AU.SUMMARY, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT],
        tags=["fixed_point", "h1"],
    ),

    _pc(
        claim_id="bean_equality",
        claim_text=(
            "Under H1, k[27] = k[65] at the 24 crib positions because CT[27]=CT[65]='P' "
            "and PT[27]=PT[65]='R', independent of Vigenère/Beaufort/VarBeaufort variant."
        ),
        epistemic_class=EC.H1_CONDITIONAL_DERIVATION,
        scope_conditions=ScopeConditions(
            assumes_direct_positional_crib_alignment=True,
            assumes_canonical_97_char_transcription=True,
            assumes_additive_cipher_family=True,
            applies_only_to_crib_positions=True,
            valid_under_multilayer_composition=False,
        ),
        dependency_chain=["k4_ct_97char", "ene_disclosure", "berlin_disclosure", "fp32_modeled"],
        source_basis="Bean 2021, re-derived in kryptos.kernel.constants.BEAN_EQ",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "Invalidated by any non-additive cipher class or by any rearrangement of "
            "the carved CT before the analyzed step.",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.RANKING_FEATURE, AU.ELIMINATION_BASIS, AU.PROMPT_CONTEXT,
        ],
        tags=["bean", "h1"],
    ),

    _pc(
        claim_id="bean_inequalities_242",
        claim_text=(
            "Under H1, 242 of 276 crib-pair inequalities hold at the 24 crib positions "
            "with distinct key values under all three additive variants "
            "(Vigenère, Beaufort, Variant Beaufort)."
        ),
        epistemic_class=EC.H1_CONDITIONAL_DERIVATION,
        scope_conditions=ScopeConditions(
            assumes_direct_positional_crib_alignment=True,
            assumes_canonical_97_char_transcription=True,
            assumes_additive_cipher_family=True,
            applies_only_to_crib_positions=True,
            valid_under_multilayer_composition=False,
        ),
        dependency_chain=["bean_equality"],
        source_basis="Bean 2021; kryptos.kernel.constants.BEAN_INEQ",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "Count is variant-independent. Invalid outside additive-cipher / H1 context.",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.RANKING_FEATURE, AU.ELIMINATION_BASIS, AU.PROMPT_CONTEXT,
        ],
        tags=["bean", "h1"],
    ),

    _pc(
        claim_id="bean_linear_101",
        claim_text=(
            "Under H1, 101 Groebner-derived linear constraints further restrict "
            "the keystream value-vectors at the 24 crib positions."
        ),
        epistemic_class=EC.H1_CONDITIONAL_DERIVATION,
        scope_conditions=ScopeConditions(
            assumes_direct_positional_crib_alignment=True,
            assumes_canonical_97_char_transcription=True,
            assumes_additive_cipher_family=True,
            applies_only_to_crib_positions=True,
            valid_under_multilayer_composition=False,
        ),
        dependency_chain=["bean_equality", "bean_inequalities_242"],
        source_basis="Project-derived; kryptos.kernel.constants.BEAN_LINEAR",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "Not independent evidence — algebraic consequence of the same H1 system.",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.RANKING_FEATURE, AU.ELIMINATION_BASIS, AU.PROMPT_CONTEXT,
        ],
        tags=["bean", "h1"],
    ),

    _pc(
        claim_id="bean_624_keystream_vectors",
        claim_text=(
            "Under H1, exactly 624 keystream value-vectors at the 24 crib positions "
            "satisfy the combined Bean equality, 242 inequalities, and 101 linear constraints."
        ),
        epistemic_class=EC.H1_CONDITIONAL_DERIVATION,
        scope_conditions=ScopeConditions(
            assumes_direct_positional_crib_alignment=True,
            assumes_canonical_97_char_transcription=True,
            assumes_additive_cipher_family=True,
            applies_only_to_crib_positions=True,
            valid_under_multilayer_composition=False,
            scope_notes=(
                "The 73 non-crib keystream positions are UNCONSTRAINED by Bean. "
                "Cite as a crib-position constraint, not a global keystream constraint."
            ),
        ),
        dependency_chain=["bean_equality", "bean_inequalities_242", "bean_linear_101"],
        source_basis="Project enumeration under Bean constraints",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "The remaining 73 keystream positions are unconstrained by Bean. "
            "Cite as crib-position constraint, NOT as global keystream constraint.",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.RANKING_FEATURE, AU.ELIMINATION_BASIS, AU.PROMPT_CONTEXT,
        ],
        tags=["bean", "h1", "keystream"],
    ),

    _pc(
        claim_id="beaufort_a0_crib_keystream",
        claim_text=(
            "Under Beaufort A=0 and H1, one specific keystream vector at the 24 crib "
            "positions is selected from the 624 valid Bean vectors."
        ),
        epistemic_class=EC.H1_CONDITIONAL_DERIVATION,
        scope_conditions=ScopeConditions(
            assumes_direct_positional_crib_alignment=True,
            assumes_beaufort_a0=True,
            assumes_specific_variant="beaufort_a0",
            assumes_additive_cipher_family=True,
            applies_only_to_crib_positions=True,
            valid_under_multilayer_composition=False,
        ),
        dependency_chain=["bean_624_keystream_vectors"],
        source_basis="Project derivation",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "One specific instance from the 624 vectors; under different variants "
            "the values differ.",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT,
        ],
        tags=["bean", "h1", "beaufort"],
    ),

    # === PROJECT-REVERIFIED STATISTICAL ANOMALIES ================================

    _pc(
        claim_id="width21_bigrams",
        claim_text=(
            "Writing K4 at width 21 produces 11 repeated vertical bigrams out of 76; "
            "random-permutation null gives p≈0.0002 (z=4.47, 100K MC)."
        ),
        epistemic_class=EC.PROJECT_REVERIFIED_STATISTICAL_ANOMALY,
        scope_conditions=ScopeConditions(
            independently_project_rerun=True,
            multiplicity_corrected_in_project=False,
            uses_post_hoc_subset_selection=True,
            scope_notes=(
                "Project re-verification 2026-04-12: 100K MC, z=4.47, p≈0.0002 vs "
                "random-permutation null. Width 21 was selected post-hoc; not corrected "
                "for the number of widths historically tested. English-baseline "
                "expectation ~9.7 is close to observed 11."
            ),
        ),
        source_basis="Hannon (2010), LaTurner (2016), Bean 2021; reverified in project 2026-04-12",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_WITH_INSTRUCTIONS,
        caveats=[
            "Selected post-hoc; not corrected for the number of widths historically tested.",
            "Random-permutation null gives p≈0.0002 (z=4.47, 100K MC).",
            "English-baseline expectation ~9.7 is close to observed 11.",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.RANKING_FEATURE, AU.NULL_BASELINE, AU.PROMPT_CONTEXT,
        ],
        related_anomaly_id="width21_vertical_bigrams",
        tags=["anomaly", "width21", "statistical"],
    ),

    _pc(
        claim_id="ic_not_significant",
        claim_text=(
            "K4's overall IC (~0.0361) is below the random expectation (~0.0385). "
            "Bonferroni-corrected p=1.0; not statistically significant at length 97."
        ),
        epistemic_class=EC.PROJECT_REVERIFIED_STATISTICAL_ANOMALY,
        scope_conditions=ScopeConditions(
            independently_project_rerun=True,
            multiplicity_corrected_in_project=True,
            scope_notes="Negative result. E-FRAC-13.",
        ),
        source_basis="kernel computation; E-FRAC-13",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "Bonferroni p=1.0. Do not use IC alone as a discriminator.",
        ],
        allowed_downstream_uses=[AU.SUMMARY, AU.NULL_BASELINE, AU.PROMPT_CONTEXT],
        tags=["ic", "statistical"],
    ),

    # === BEAN / REPORTED STATISTICAL CLAIMS ======================================

    _pc(
        claim_id="stehle_delta5",
        claim_text=(
            "Every 4th character in carved positions 55-63 (DIAWINFBN) differs by "
            "exactly 5 mod 26 — a local [5,5,5,5,5] delta sequence."
        ),
        epistemic_class=EC.PROJECT_REVERIFIED_STATISTICAL_ANOMALY,
        scope_conditions=ScopeConditions(
            independently_project_rerun=True,
            depends_on_external_author_statistic=False,
            uses_post_hoc_subset_selection=True,
            multiplicity_corrected_in_project=False,
            scope_notes=(
                "EXISTENCE of the delta sequence and the 712-test Bonferroni "
                "p≈1/642 calculation are directly reproduced by Codex audit "
                "2026-05-01. This remains a post-hoc descriptive statistic, "
                "not a pre-registered cryptanalytic predicate."
            ),
        ),
        source_basis="Bean 2021 Section 2.3, citing Stehle (2000); scripts/audit/audit_stehle_significance.py",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "Existence of the [5,5,5,5,5] delta sequence is verified directly.",
            "The p≈1/642 value is reproduced only as a 712-test Bonferroni descriptive calculation.",
            "This is post-hoc and not a pre-registered cipher-family test.",
            "The pattern is local (9 chars at one position) and its cryptographic interpretation is open.",
        ],
        allowed_downstream_uses=[AU.SUMMARY, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT],
        related_anomaly_id="stehle_delta5_lag4",
        tags=["stehle", "bean_reported"],
    ),

    _pc(
        claim_id="bean_minor_diffs",
        claim_text=(
            "At the 24 known PT positions, the 10 where PT ∈ {K,R,Y,P,T,O,S} have CT "
            "letters very close in the standard alphabet (sum of distances=21, mean=2.1). "
            "Bean 2021 reports Monte Carlo p ≈ 1/5520; Codex audit 2026-05-01 "
            "reproduces the statistic under a K4-multiset permutation null at "
            "p≈0.000186."
        ),
        epistemic_class=EC.PROJECT_REVERIFIED_STATISTICAL_ANOMALY,
        scope_conditions=ScopeConditions(
            assumes_direct_positional_crib_alignment=True,
            applies_only_to_crib_positions=True,
            independently_project_rerun=True,
            depends_on_external_author_statistic=False,
            uses_post_hoc_subset_selection=True,
            multiplicity_corrected_in_project=False,
            scope_notes=(
                "The KRYPTOS-letter subset selection is post-hoc — the subset spells "
                "the project's name and the K1-K3 keyword. Codex audit also reports "
                "an exact IID p≈4.89e-5; K4-multiset permutation null is closer to "
                "Bean's reported value."
            ),
        ),
        source_basis="Bean 2021 Section 2.4 (Materna 2020); scripts/audit/audit_bean_reported_statistics.py",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "H1-conditional crib-position statistic.",
            "The KRYPTOS-letter subset selection is post-hoc (the subset spells the project's name and the K1-K3 keyword).",
            "Not a hard constraint or elimination basis; use as soft statistical context only.",
        ],
        allowed_downstream_uses=[AU.SUMMARY, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT],
        related_anomaly_id="bean_minor_diffs",
        last_verified_by="Codex audit 2026-05-01",
        evidence_links=[
            "results/audit/bean_reported_statistics.json",
            "docs/audits/bean_reported_statistics.md",
        ],
        tags=["bean_reported", "project_rerun", "statistical"],
    ),

    _pc(
        claim_id="bean_repeated_pt_distances",
        claim_text=(
            "Bean 2021 reports anomalous cipher distances for repeated plaintext letters "
            "at the 24 crib positions."
        ),
        epistemic_class=EC.BEAN_REPORTED_NOT_RERUN,
        scope_conditions=ScopeConditions(
            assumes_direct_positional_crib_alignment=True,
            applies_only_to_crib_positions=True,
            depends_on_external_author_statistic=True,
            uses_post_hoc_subset_selection=True,
            multiplicity_corrected_in_project=False,
        ),
        source_basis="Bean 2021",
        verification_status=VS.EXTERNAL_AUTHOR_REPORTED,
        reproducibility_status=RS.REPRODUCIBLE_WITH_INSTRUCTIONS,
        caveats=[
            "Reported by Bean 2021, NOT independently re-derived in project.",
            "Post-hoc subset selection; not multiplicity-corrected here.",
        ],
        allowed_downstream_uses=[AU.SUMMARY, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT],
        tags=["bean_reported"],
    ),

    # === PHYSICAL ANOMALIES: EXISTENCE vs INTERPRETATION =========================

    _pc(
        claim_id="yar_physical_existence",
        claim_text=(
            "Letters Y, A, R near line 15 (K3/K4 boundary) on the Kryptos sculpture "
            "are physically raised several centimeters above the baseline."
        ),
        epistemic_class=EC.PHYSICAL_FACT,
        source_basis="Elonka Dunin physical rubbings (Oct 2002)",
        verification_status=VS.PRIMARY_SOURCE_DOCUMENTED,
        reproducibility_status=RS.NON_REPRODUCIBLE,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT],
        related_anomaly_id="yar_superscript",
        tags=["physical", "yar"],
    ),
    _pc(
        claim_id="yar_cryptographic_interpretation",
        claim_text=(
            "The raised YAR letters are a cryptographically meaningful procedural marker."
        ),
        epistemic_class=EC.INTERPRETIVE_PHYSICAL_OBSERVATION,
        dependency_chain=["yar_physical_existence"],
        source_basis="Community interpretation",
        verification_status=VS.INTERPRETIVE,
        caveats=[
            "Physical existence is confirmed. Cryptographic role is unproven.",
            "50+ scripts tested YAR as algebra → noise.",
        ],
        allowed_downstream_uses=[AU.SUMMARY, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT],
        related_anomaly_id="yar_superscript",
        tags=["physical", "yar", "interpretive"],
    ),

    _pc(
        claim_id="extra_l_existence",
        claim_text=(
            "Row N of the engraved tableau has 27 characters (extra L) vs 26 for all other rows."
        ),
        epistemic_class=EC.PHYSICAL_FACT,
        source_basis="Sculpture; docs/anomaly_registry.md B1",
        verification_status=VS.PRIMARY_SOURCE_DOCUMENTED,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT],
        tags=["physical", "tableau"],
    ),
    _pc(
        claim_id="extra_l_alignment_interpretation",
        claim_text=(
            "The extra L shifts row N of any physical tableau overlay on the cipher panel, "
            "implying a misaligned-overlay procedure."
        ),
        epistemic_class=EC.INTERPRETIVE_PHYSICAL_OBSERVATION,
        dependency_chain=["extra_l_existence"],
        source_basis="docs/anomaly_registry.md B1+B2",
        verification_status=VS.INTERPRETIVE,
        caveats=["Cryptographic role unproven."],
        allowed_downstream_uses=[AU.SUMMARY, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT],
        tags=["physical", "interpretive"],
    ),

    _pc(
        claim_id="lodestone_existence",
        claim_text=(
            "A lodestone is embedded in the Kryptos installation; a nearby compass is "
            "physically deflected from geographic north."
        ),
        epistemic_class=EC.PHYSICAL_FACT,
        source_basis="Sculpture; docs/anomaly_registry.md D1",
        verification_status=VS.PRIMARY_SOURCE_DOCUMENTED,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT],
        tags=["physical", "compass"],
    ),
    _pc(
        claim_id="lodestone_ene_interpretation",
        claim_text=(
            "The compass deflection points east-northeast and implies a directional "
            "reading instruction aligned with the ENE crib."
        ),
        epistemic_class=EC.INTERPRETIVE_PHYSICAL_OBSERVATION,
        dependency_chain=["lodestone_existence", "ene_disclosure"],
        source_basis="Community interpretation",
        verification_status=VS.INTERPRETIVE,
        caveats=["Bearing interpretation unproven."],
        allowed_downstream_uses=[AU.SUMMARY, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT],
        tags=["physical", "interpretive"],
    ),

    _pc(
        claim_id="k2_coordinates_in_plaintext",
        claim_text=(
            "K2 plaintext contains coordinates 38°57'6.5\"N 77°8'44\"W."
        ),
        epistemic_class=EC.PHYSICAL_FACT,
        source_basis="K2 plaintext (Gillogly/Stein 1999)",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT, AU.RANKING_FEATURE],
        tags=["k2", "coordinates"],
    ),
    _pc(
        claim_id="k2_coordinates_manhole_observation",
        claim_text=(
            "The K2 coordinates point to a manhole near the Kryptos sculpture and this "
            "location is cryptographically meaningful for K4."
        ),
        epistemic_class=EC.INTERPRETIVE_PHYSICAL_OBSERVATION,
        dependency_chain=["k2_coordinates_in_plaintext"],
        source_basis="Community interpretation",
        verification_status=VS.INTERPRETIVE,
        caveats=["Cryptographic relevance unproven."],
        allowed_downstream_uses=[AU.SUMMARY, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT],
        tags=["physical", "interpretive"],
    ),

    _pc(
        claim_id="desparatly_misspelling_exists",
        claim_text=(
            "K2 plaintext contains the misspelling DESPARATLY (vs standard DESPERATELY): "
            "E→A at word position 5, E deleted at position 8."
        ),
        epistemic_class=EC.PHYSICAL_FACT,
        source_basis="K2 plaintext",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT, AU.RANKING_FEATURE],
        tags=["misspelling"],
    ),
    _pc(
        claim_id="desparatly_silence_as_signal_interpretation",
        claim_text=(
            "Sanborn's refusal to confirm or deny whether DESPARATLY is intentional "
            "is itself a cryptographic signal encoding parameters 5 and 8."
        ),
        epistemic_class=EC.INTERPRETIVE_PHYSICAL_OBSERVATION,
        dependency_chain=["desparatly_misspelling_exists"],
        source_basis="docs/anomaly_registry.md A4",
        verification_status=VS.INTERPRETIVE,
        caveats=["Behavioral signal interpretation is speculative."],
        allowed_downstream_uses=[AU.SUMMARY, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT],
        tags=["interpretive"],
    ),

    _pc(
        claim_id="morse_extra_e_count",
        claim_text=(
            "The Morse code on the Kryptos entrance slabs contains 26 extra E characters "
            "beyond the encoded message."
        ),
        epistemic_class=EC.PHYSICAL_FACT,
        source_basis="Sculpture; docs/anomaly_registry.md C1",
        verification_status=VS.PRIMARY_SOURCE_DOCUMENTED,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT, AU.RANKING_FEATURE],
        tags=["morse", "physical"],
    ),
    _pc(
        claim_id="morse_e_alphabet_interpretation",
        claim_text=(
            "The count of 26 extra Morse E's equals the alphabet size and therefore "
            "encodes a cipher alphabet mapping."
        ),
        epistemic_class=EC.INTERPRETIVE_PHYSICAL_OBSERVATION,
        dependency_chain=["morse_extra_e_count"],
        source_basis="Community interpretation",
        verification_status=VS.INTERPRETIVE,
        caveats=["Cryptographic role unproven; coincidence of count is suggestive but not evidence."],
        allowed_downstream_uses=[AU.SUMMARY, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT],
        tags=["interpretive"],
    ),

    _pc(
        claim_id="tableau_engraved_reverse",
        claim_text=(
            "The Kryptos tableau is engraved on the reverse of the cipher panel, "
            "facing the cipher text."
        ),
        epistemic_class=EC.PHYSICAL_FACT,
        source_basis="Sculpture",
        verification_status=VS.PRIMARY_SOURCE_DOCUMENTED,
        allowed_downstream_uses=[AU.SUMMARY, AU.PROMPT_CONTEXT, AU.RANKING_FEATURE],
        tags=["physical", "tableau"],
    ),

    # === STRUCTURAL ELIMINATIONS =================================================

    _pc(
        claim_id="pure_transposition_impossible",
        claim_text=(
            "Pure transposition (any permutation) of K4 cannot produce the known cribs: "
            "CT has 2 E's but the crib set requires 3 E's. Letter count is invariant "
            "under permutation."
        ),
        epistemic_class=EC.STRUCTURAL_ELIMINATION,
        scope_conditions=ScopeConditions(
            survives_transposition=True,
            applies_to_entire_cipher=True,
            scope_notes="Holds under any permutation of the carved 97-char CT.",
        ),
        dependency_chain=["k4_ct_97char", "ene_disclosure", "berlin_disclosure"],
        source_basis="Letter-count invariant argument",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "CT has 2 E's, cribs need 3. Letter count mismatch is structural under any permutation.",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.HARD_CONSTRAINT, AU.ELIMINATION_BASIS, AU.PROMPT_CONTEXT,
        ],
        tags=["elimination", "structural"],
    ),

    _pc(
        claim_id="fractionation_eliminated_structural",
        claim_text=(
            "Bifid, trifid, ADFGVX, and straddling-checkerboard ciphers are eliminated "
            "for K4 by parity, alphabet-count, or digit-output constraints."
        ),
        epistemic_class=EC.STRUCTURAL_ELIMINATION,
        scope_conditions=ScopeConditions(
            survives_transposition=True,
            applies_to_entire_cipher=True,
        ),
        source_basis="Structural arguments; K4 uses all 26 letters",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "Bifid/trifid/ADFGVX/checkerboard eliminated by parity, alphabet count, or digit-output constraints. Holds with or without transposition.",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.HARD_CONSTRAINT, AU.ELIMINATION_BASIS, AU.PROMPT_CONTEXT,
        ],
        tags=["elimination", "structural", "fractionation"],
    ),

    _pc(
        claim_id="autokey_eliminated",
        claim_text=(
            "Standard autokey variants (Vigenère / Beaufort / CT-autokey) are "
            "structurally eliminated: PT-autokey max 16/24, CT-autokey max 21/24."
        ),
        epistemic_class=EC.STRUCTURAL_ELIMINATION,
        scope_conditions=ScopeConditions(
            scope_notes=(
                "Under standard autokey primer/update rules (E-FRAC-37). "
                "Non-standard autokey variants are not covered."
            ),
        ),
        source_basis="E-FRAC-37",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "Under standard autokey primer/update rules.",
            "PT-autokey max 16/24, CT-autokey max 21/24.",
            "Non-standard autokey variants not covered.",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.HARD_CONSTRAINT, AU.ELIMINATION_BASIS, AU.PROMPT_CONTEXT,
        ],
        tags=["elimination", "autokey"],
    ),

    # === CONDITIONAL ELIMINATIONS (H1 / additive / direct positional) ============

    _pc(
        claim_id="periodic_poly_eliminated_h1",
        claim_text=(
            "Periodic Vigenère / Beaufort / Variant Beaufort is eliminated for K4 at "
            "all periods 1-26 under direct positional crib mapping."
        ),
        epistemic_class=EC.CONDITIONAL_ELIMINATION,
        scope_conditions=ScopeConditions(
            assumes_direct_positional_crib_alignment=True,
            assumes_additive_cipher_family=True,
            assumes_canonical_97_char_transcription=True,
            valid_under_multilayer_composition=False,
        ),
        dependency_chain=["bean_equality", "bean_inequalities_242"],
        source_basis="Bean 242-ineq applied to raw 97-char CT",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "Eliminates periodic Vig/Beau/VarBeau applied directly to the carved CT under direct positional crib mapping.",
            "Does NOT eliminate periodic substitution as one layer of a multi-layer cipher where an outer transposition or selector precedes the substitution step.",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.ELIMINATION_BASIS, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT,
        ],
        tags=["elimination", "conditional", "h1"],
    ),

    _pc(
        claim_id="hill_2x2_3x3_eliminated_h1",
        claim_text=(
            "Hill 2x2 and 3x3 are algebraically eliminated for K4 under direct "
            "positional crib mapping."
        ),
        epistemic_class=EC.CONDITIONAL_ELIMINATION,
        scope_conditions=ScopeConditions(
            assumes_direct_positional_crib_alignment=True,
            valid_under_multilayer_composition=False,
        ),
        source_basis="Project derivation",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "Algebraically eliminated under direct positional crib mapping.",
            "Does not eliminate Hill as inner layer of multi-layer construction.",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.ELIMINATION_BASIS, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT,
        ],
        tags=["elimination", "conditional", "hill"],
    ),

    _pc(
        claim_id="structured_additive_keys_bean_eliminated",
        claim_text=(
            "Structured additive key models (progressive, quadratic, Fibonacci) are "
            "eliminated for K4 under the additive-cipher-family assumption."
        ),
        epistemic_class=EC.CONDITIONAL_ELIMINATION,
        scope_conditions=ScopeConditions(
            assumes_additive_cipher_family=True,
            assumes_direct_positional_crib_alignment=True,
            valid_under_multilayer_composition=False,
        ),
        source_basis="E-FRAC-38",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=["Under additive-key model. E-FRAC-38."],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.ELIMINATION_BASIS, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT,
        ],
        tags=["elimination", "conditional"],
    ),

    _pc(
        claim_id="running_key_corpus_eliminated",
        claim_text=(
            "Running-key attacks using K1/K2/K3 PT, Carter Vol 1, Kahn, and 73 Gutenberg "
            "books crossed with structured transpositions are eliminated (17B+ checks)."
        ),
        epistemic_class=EC.CONDITIONAL_ELIMINATION,
        scope_conditions=ScopeConditions(
            valid_under_multilayer_composition=False,
            scope_notes="Does not cover unknown non-English texts.",
        ),
        source_basis="Project running-key sweep",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "K1/K2/K3 PT, Carter Vol 1, Kahn, 73 Gutenberg books × structured transpositions. 17B+ checks.",
            "Does not cover unknown non-English texts.",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.ELIMINATION_BASIS, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT,
        ],
        tags=["elimination", "running_key"],
    ),

    _pc(
        claim_id="running_key_unknown_english_columnar_eliminated",
        claim_text=(
            "Running-key with unknown English fragment + columnar transposition is "
            "eliminated for K4 under direct positional crib mapping and the project's "
            "English fragment scorer."
        ),
        epistemic_class=EC.CONDITIONAL_ELIMINATION,
        scope_conditions=ScopeConditions(
            assumes_direct_positional_crib_alignment=True,
            valid_under_multilayer_composition=False,
            scope_notes=(
                "Under project's English fragment scorer; not tight against "
                "ciphers with monoalphabetic preprocessing layer (cf. E-FRAC-54)."
            ),
        ),
        source_basis="E-FRAC-54",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "Under the project's English fragment scorer.",
            "Not tight against ciphers with monoalphabetic preprocessing layer (cf. E-FRAC-54).",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.ELIMINATION_BASIS, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT,
        ],
        tags=["elimination", "conditional", "running_key"],
    ),

    _pc(
        claim_id="columnar_4_6_8_9_additive_eliminated",
        claim_text=(
            "Columnar transposition at widths 4/6/8/9 composed with additive keystreams "
            "is eliminated for K4 under direct positional crib mapping."
        ),
        epistemic_class=EC.CONDITIONAL_ELIMINATION,
        scope_conditions=ScopeConditions(
            assumes_direct_positional_crib_alignment=True,
            assumes_additive_cipher_family=True,
            valid_under_multilayer_composition=False,
        ),
        source_basis="Project columnar + additive sweep",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "Does NOT cover non-additive keystreams, outer layers preceding the columnar step, or widths outside {4,6,8,9}.",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.ELIMINATION_BASIS, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT,
        ],
        tags=["elimination", "conditional", "columnar"],
    ),

    _pc(
        claim_id="two_layer_composition_null",
        claim_text=(
            "The project's two-layer composition framework returned a null result "
            "within its parameterized search space."
        ),
        epistemic_class=EC.CONDITIONAL_ELIMINATION,
        scope_conditions=ScopeConditions(
            valid_under_multilayer_composition=False,
            scope_notes=(
                "Only covers the space the composition framework expresses. "
                "Does not cover three-layer compositions, grilles, or procedural mechanisms."
            ),
        ),
        source_basis="Project two-layer composition sweep",
        verification_status=VS.PROJECT_VERIFIED,
        reproducibility_status=RS.REPRODUCIBLE_FROM_CODE,
        caveats=[
            "Within the two-layer parameterized search space the composition framework expresses.",
            "Does not cover three-layer compositions, grilles, or procedural mechanisms.",
        ],
        allowed_downstream_uses=[
            AU.SUMMARY, AU.ELIMINATION_BASIS, AU.RANKING_FEATURE, AU.PROMPT_CONTEXT,
        ],
        tags=["elimination", "conditional", "composition"],
    ),

    # === RETIRED CLAIMS ==========================================================

    _pc(
        claim_id="null_palette_retired",
        claim_text=(
            "The null palette {B,G,I,K,O,W,Z} was a retired K4 hypothesis. "
            "Do not revive without formal rehabilitation."
        ),
        epistemic_class=EC.RETIRED_CLAIM,
        scope_conditions=ScopeConditions(
            scope_notes="Retired 2026-04-01. See MEMORY.md §5.",
        ),
        source_basis="docs/a1_score_conditioned_null_report.md, MEMORY.md §5",
        verification_status=VS.RETIRED,
        caveats=[
            "Retired 2026-04-01. Do not revive. Any theory touching this palette is blocked.",
        ],
        allowed_downstream_uses=[AU.SUMMARY],
        tags=["retired", "palette"],
    ),
]


# Quick lookup by claim_id
CANONICAL_CLAIMS_BY_ID: dict[str, ProvenanceClaim] = {
    c.claim_id: c for c in CANONICAL_CLAIMS
}


def get_canonical_claim(claim_id: str) -> ProvenanceClaim | None:
    return CANONICAL_CLAIMS_BY_ID.get(claim_id)
