# Prior-work corrections and K1-K3 text integrity audit (2026-09-29)

Status: live audit record. Scope: repo documentation and embedded reference texts. No K4 claim is made here.

This dossier records errors found in earlier repo work during a clean-room session on 2026-09-29, the evidence for each, and what was changed. Each correction was checked directly against the repo before editing. Where a claim rests on session artifacts that are not yet in the repo, that is said explicitly.

## 1. Embedded K1-K3 texts that were not the real texts

**Defect.** Many experiment scripts embed their own copy of the K1, K2 or K3 plaintext or ciphertext instead of importing it. A large share of these copies match the real text only for the first 20-60 letters and then continue with invented text. Examples: K1 "...LIESTHENUABORDSECRETOFILLUSIONIMAGESWERETHEFORMOFFICTION", K3 "...REMAINSOFJPASSAGEDEBRIS...", K3 "...IMADETINYBREACH..." (missing A). The invented continuations were present when the scripts first entered git (commit 94637753, 2026-03-04), so they are original to the scripts, not later damage. They read like texts reconstructed from memory rather than transcribed.

**Consequence.** Any running-key, crib-drag, keystream or "sculpture text" result computed from one of these copies did not test the real K1-K3 text beyond the divergence point. Those results cannot be cited as evidence about the real texts.

**Reference used.** `kryptosbot/panel_cribs.py`, re-verified: K1 CT decrypts to K1 PT under Quagmire III (KA alphabet, key PALIMPSEST); K2 CT decrypts to K2 PT under Quagmire III (KA, ABSCISSA); K3 CT is the unkeyed double rotation of K3 PT (see section 2). Corrected forms of carved anomalies (ILLUSION for IQLUSION, UNDERGROUND for UNDERGRUUND, XLAYERTWO for IDBYROWS, DESPERATELY for DESPARATLY) are accepted as legitimate variants. UNDERGRUUND and IDBYROWS are errors, not intentional spellings.

**Guard.** `scripts/audit/audit_kryptos_text_integrity.py` (new). Repro:

```bash
PYTHONPATH=src python3 scripts/audit/audit_kryptos_text_integrity.py
```

Result at this commit: 850 embedded literals matched to a Kryptos text; 730 exact; 7 accepted variants; **113 divergent literals in 57 files** (`scripts/archive/` excluded). The guard exits 1 while any divergent literal remains.

**What this does and does not change.** The scripts were not edited: their recorded outputs were produced with the texts as they stand, and editing the texts would make those records unreproducible. The running-key-from-K1-K3 conclusion itself was re-derived on verified texts in the 2026-09-29 session (direct alignment, 24 primary and 832 extended tableau conventions, all offsets, forward and reversed: best 8/24, at matched-null level). That re-derivation's scripts live in the session scratchpad and are **not yet imported**; until they are, cite it as unarchived.

### Affected scripts

| Script | Exhaustion-log status | Divergent literals (reference @ offset, first wrong letter) |
|---|---|---|
| `scripts/_infra/k4_reverse_engine.py` | exhausted | K3PT@47 after 40 (line 70) |
| `scripts/_uncategorized/e_endyahr_mapping.py` | active | K3PT@0 after 43 (line 168); K3PT@140 after 36 (line 170); K3PT@212 after 40 (line 171) |
| `scripts/_uncategorized/e_opgold_02_progressive.py` | active | K2PT@122 after 40 (line 124); K2PT@181 after 42 (line 125) |
| `scripts/_uncategorized/e_s_124_palimpsest_method.py` | active | K3PT@99 after 35 (line 70) |
| `scripts/_uncategorized/e_s_145_dryad_matrix.py` | active | K1PT@0 after 47 (line 63); K3PT@0 after 44 (line 65) |
| `scripts/_uncategorized/e_s_152_nato_protocol.py` | active | K2PT@122 after 40 (line 259); K2PT@181 after 42 (line 260); K3PT@0 after 44 (line 264) |
| `scripts/_uncategorized/e_s_15_creative_keys.py` | active | K3PT@139 after 28 (line 327) |
| `scripts/_uncategorized/e_s_30_three_layer_mask.py` | active | K2CT@0 after 37 (line 55); K2PT@0 after 162 (line 58); K3PT@0 after 44 (line 59) |
| `scripts/_uncategorized/e_s_49_word_segmentation_sa.py` | active | K1PT@0 after 50 (line 346) |
| `scripts/analysis/e_corpus_keystream_search.py` | active | K1PT@0 after 50 (line 184); K3PT@0 after 163 (line 186) |
| `scripts/analysis/e_ct80_cipher_attack.py` | not logged | K1PT@0 after 47 (line 54); K2PT@0 after 115 (line 55); K3PT@0 after 44 (line 56) |
| `scripts/analysis/e_gko_running_key_search.py` | not logged | K2PT@138 after 20 (line 167); K2PT@0 after 327 (line 193); K2PT@0 after 327 (line 201) |
| `scripts/analysis/e_keystream_grid_coordinates.py` | active | K3PT@90 after 44 (line 78) |
| `scripts/analysis/e_top3_mask_cipher_attack.py` | active | K1PT@0 after 50 (line 56) |
| `scripts/antipodes/e_antipodes_08_stream_context.py` | active | K1PT@0 after 50 (line 105); K3PT@0 after 34 (line 107) |
| `scripts/blitz/blitz_concealment.py` | active | K2PT@0 after 147 (line 804); K3PT@0 after 43 (line 806) |
| `scripts/blitz/blitz_plaintext_archaeology.py` | active | K2PT@101 after 41 (line 87); K2PT@101 after 41 (line 94) |
| `scripts/blitz/blitz_wildcard.py` | exhausted | K3CT@62 after 62 (line 113); K3CT@188 after 56 (line 115) |
| `scripts/blitz/blitz_yar_selective.py` | active | K123CT@62 after 38 (line 776); K2CT@60 after 54 (line 777) |
| `scripts/campaigns/e_73_null_hypothesis_01.py` | active | K3PT@0 after 34 (line 517) |
| `scripts/campaigns/e_s_154_progressive_bridge.py` | active | K1PT@0 after 48 (line 119); K2PT@142 after 20 (line 124); K2PT@251 after 76 (line 457) |
| `scripts/campaigns/e_solve_03_remaining_gaps.py` | exhausted | K1PT@0 after 50 (line 326); K2PT@0 after 142 (line 331); K3PT@0 after 44 (line 336) |
| `scripts/campaigns/f_k1k3_running_key_q2_v1.py` | active | K2PT@107 after 38 (line 60); K2PT@149 after 29 (line 61); K3PT@106 after 23 (line 68) |
| `scripts/campaigns/f_running_key_null_v1.py` | active | K2PT@0 after 41 (line 37); K3PT@0 after 20 (line 42) |
| `scripts/campaigns/f_sculpture_path_search_v1.py` | active | K3PT@147 after 58 (line 131) |
| `scripts/campaigns/k4_two_layer.py` | active | K2CT@0 after 37 (line 259); K2PT@0 after 162 (line 262); K3PT@0 after 44 (line 263) |
| `scripts/campaigns/tableau_running_key.py` | active | K2PT@243 after 36 (line 166); K3PT@0 after 34 (line 177); K3PT@73 after 35 (line 178); K3PT@134 after 32 (line 179); K3PT@194 after 49 (line 180); K3PT@256 after 43 (line 181) |
| `scripts/encoding/e_misspelling_ct_letters.py` | exhausted | K2PT@310 after 51 (line 167); K2PT@310 after 51 (line 196) |
| `scripts/exploration/e_bespoke_12_dryad_lookup.py` | active | K1PT@0 after 50 (line 72); K3CT@0 after 45 (line 131) |
| `scripts/exploration/e_chart_04_morse_pattern.py` | active | K3PT@99 after 35 (line 114) |
| `scripts/exploration/e_explorer_04_nonstandard_structures.py` | exhausted | K1PT@0 after 50 (line 584); K2PT@0 after 140 (line 585); K3PT@0 after 42 (line 588) |
| `scripts/fractionation/e_bifid_5x6_ka.py` | active | K1PT@0 after 50 (line 478); K2PT@317 after 42 (line 486); K3PT@182 after 38 (line 491) |
| `scripts/fractionation/e_frac_17_beaufort_running_key.py` | active | K1PT@0 after 50 (line 156); K2PT@0 after 142 (line 158); K3PT@0 after 44 (line 160) |
| `scripts/fractionation/e_frac_39_running_key_bipartite.py` | active | K3PT@242 after 26 (line 313) |
| `scripts/fractionation/e_frac_41_word_discriminator.py` | active | K3PT@242 after 26 (line 136) |
| `scripts/fractionation/e_frac_42_refined_discriminator.py` | active | K3PT@242 after 26 (line 159) |
| `scripts/fractionation/e_frac_43_bigram_discriminator.py` | active | K3PT@242 after 26 (line 167) |
| `scripts/grille/blitz_grille_mask.py` | exhausted | K3PT@0 after 25 (line 92) |
| `scripts/grille/e_bean_keystream_construct.py` | active | K1PT@0 after 47 (line 865); K3PT@0 after 51 (line 867) |
| `scripts/grille/e_cipher_cylinder_03.py` | active | K1PT@0 after 50 (line 377) |
| `scripts/grille/e_grille_10_plaintext_source.py` | exhausted | K3PT@61 after 53 (line 117); K3PT@61 after 53 (line 135) |
| `scripts/grille/e_grille_13_field_ciphers.py` | active | K1PT@0 after 48 (line 49); K2PT@0 after 41 (line 50); K3PT@0 after 47 (line 51) |
| `scripts/grille/e_grille_14_fold_keyword.py` | active | K3PT@0 after 47 (line 113); K1PT@0 after 48 (line 116); K2PT@0 after 41 (line 117) |
| `scripts/grille/e_grille_18_equal_misspelling_params.py` | active | K1PT@0 after 50 (line 521); K2PT@0 after 142 (line 523); K3PT@0 after 133 (line 524) |
| `scripts/k3_continuity/e_antipodes_03_k3k4_continuity.py` | active | K3PT@0 after 34 (line 96) |
| `scripts/mirror_ka/e_mirror_ka_01_comprehensive.py` | active | K1PT@0 after 50 (line 172); K3PT@0 after 42 (line 179) |
| `scripts/polyalphabetic/e_polybius_coord_exploit.py` | active | K2PT@107 after 35 (line 295); K3PT@0 after 42 (line 297) |
| `scripts/running_key/e_s_11_running_key_transposition.py` | active | K3PT@139 after 28 (line 66) |
| `scripts/statistical/e_stat_01_missing_tests.py` | active | K2CT@0 after 31 (line 52) |
| `scripts/substitution/e_k2_coords_running_key.py` | active | K2PT@251 after 76 (line 37); K2PT@251 after 76 (line 39) |
| `scripts/tableau/blitz_tableau_structural.py` | exhausted | K3PT@0 after 25 (line 145) |
| `scripts/tableau/e_audit_07_k3_running_key.py` | exhausted | K3PT@0 after 34 (line 40); K3CT@62 after 62 (line 66) |
| `scripts/tableau/e_chart_03_misspelling_tableau.py` | active | K3PT@0 after 44 (line 86); K2PT@0 after 115 (line 89) |
| `scripts/tableau/e_chart_03b_reduced_misspelling.py` | active | K2PT@0 after 115 (line 110); K3PT@0 after 44 (line 111) |
| `scripts/transposition/columnar/e_grid31_columnar_phase3.py` | exhausted | K3CT@277 after 48 (line 281) |
| `scripts/two_system/e_two_sys_03_model_b_nonperiodic.py` | exhausted | K1PT@0 after 50 (line 226); K2PT@0 after 146 (line 227); K3PT@0 after 44 (line 228) |
| `scripts/yar/e_yar_nonperiodic.py` | active | K3PT@0 after 34 (line 84) |

Status of the 57 affected scripts in exhaustion_log.json: active 44, exhausted 11, not logged 2

## 2. K3's method was described wrongly

**Defect.** `scripts/tableau/e_tableau_20_k3method_keywords.py` described K3 as "Columnar(width=7, keyword=KRYPTOS) -> Vigenere(keyword=PALIMPSEST, period=10)". `docs/research_questions.md` (RQ-8) described it as "Double-length key Vigenere + columnar transposition". Both are wrong.

**Correct description [DERIVED FACT].** K3 is a pure transposition with no substitution: write the plaintext in 8 rows of 42, read the columns bottom to top, left to right; write that in 24 rows of 14 and read it the same way. Equivalently PT[i] = CT[(191 + 192*i) mod 337]. Check: K3 CT is an exact anagram of K3 PT, and the double rotation reproduces the CT 336/336 using `kryptosbot/panel_cribs.py`. The same check is built into `audit_kryptos_text_integrity.py`.

**Also in that script's header.** It cites E-FRAC-35's "Bean-surviving periods" as a proof. E-FRAC-35 was retracted on 2026-08-24 (Bean frame error). E-TABLEAU-20 still tested what it computed (width-8 and width-13 columnar with specific keywords at periods 8 and 13), but it is not a test of K3's method and its period restriction has no valid basis.

## 3. The "Gromark eliminated" claim had no valid support

**Defect.** `docs/elimination_tiers.md` marked Gromark/Vimark ELIMINATED because "Vimark is periodic/linear recurrence" and "E-FRAC-35 covers periods 2-7"; `docs/invariants.md` marked it "subsumed by recurrence elimination". A lagged-Fibonacci keystream is not periodic at K4's length; E-FRAC-35 was retracted; and the recurrence proofs assume fixed AZ/KA alphabets, while Gromark uses keyed alphabets. Every prior repo Gromark sweep used a fixed alphabet on both sides.

**What is established [DERIVED FACT, hand-checkable].** ACA-standard Gromark (straight plain alphabet, any keyed cipher alphabet) cannot produce the released cribs under direct alignment with any keystream whose values lie in 0..10. CT P encrypts PT R at position 27 and PT C at position 72, so C(P) = 17 + k27 = 2 + k72 (mod 26), which forces k72 - k27 = 15 or -11. No two values in 0..10 differ by that much. The same holds with the key subtracted.

**What is open in the repo record.** Gromark with keyed alphabets on both sides. The 2026-09-29 session tested this (feasibility over all alphabets, keyword-alphabet lookups, and alphabet annealing, all null) but those artifacts are not yet imported.

## 4. The Quagmire IV "consistent at every period" note is wrong

**Defect.** `scripts/crib_analysis/e_crib_71_quagmire_iv_exact.py` and `e_crib_72_quagmire_iv_exact.py` state that Quagmire IV is "underdetermined at EVERY period" and that "every cell would report consistent". The argument counts unknowns but ignores that both alphabets must be permutations.

**Counterexample [DERIVED FACT].** At period 1, Quagmire IV is a single monoalphabetic substitution. The cribs contradict that: CT Q at positions 25 and 26 would have to decrypt to both N and O. A 2026-09-29 CP-SAT run (not yet imported) found Quagmire IV contradicted over all alphabet pairs at periods 1-7, 9-12, 14, 15, 17, 18, 21, 22 and 25.

## 5. Swapped Beaufort labels in the columnar-periodic re-run

**Defect.** In `scripts/campaigns/f_columnar_periodic_rederived_v1.py`, the branch labelled `beaufort` computes k = PT - CT, which is Variant Beaufort under the CLAUDE.md convention, and the branch labelled `var_beaufort` computes k = CT + PT, which is Beaufort. The labels in `results/f_columnar_periodic_rederived_v1.json` carry the same swap. Also, `vigenere` (C - P) and the branch labelled `beaufort` (P - C) differ only in sign, so they always give identical survivor sets: the "3 variants" are 2 independent tests, and the 31.9M configuration count overstates independent configurations by 1.5x.

**Effect on the result.** None on the conclusion. Both arithmetic forms were run, and the clean null stands (re-derived independently in the 2026-09-29 session, which also covered the other three layer-order and read conventions, the KA alphabet and widths 10-13).

## 6. Already corrected earlier (listed for completeness)

`docs/archive_aaa_doctrine.md` (2026-06-05) already records that the word read as "Overlay" in Sanborn's list (IMG_1569/1571) is OVERLORD, a codename. Any argument that treats "overlay" as a method Sanborn listed should not be cited as archive-supported.

## Edits made with this dossier

- `scripts/tableau/e_tableau_20_k3method_keywords.py`: erratum block in the header.
- `docs/research_questions.md`: RQ-8 K3 method line corrected.
- `docs/elimination_tiers.md`: Gromark/Vimark rows and E-TABLEAU-20 citations annotated.
- `docs/invariants.md`: Gromark row corrected; K1-K3 running-key row annotated.
- `scripts/crib_analysis/e_crib_71_quagmire_iv_exact.py`, `e_crib_72_quagmire_iv_exact.py`: erratum blocks.
- `scripts/campaigns/f_columnar_periodic_rederived_v1.py`: erratum block on labels (code behaviour unchanged).
- `docs/methodological_audits.md`: AUDIT entry pointing here.
- `scripts/audit/audit_kryptos_text_integrity.py`: new guard.
