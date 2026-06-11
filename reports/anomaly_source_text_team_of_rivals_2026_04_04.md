# Anomaly-to-Source-Text Investigation — Team of Rivals Final Report

**Date:** 2026-04-04
**Investigator:** KryptosBot (Claude + Colin Patrick)
**Method:** Team of Rivals with 9 competing analysts, ablation controls, multiprocessing

---

## 1. INPUTS AUDITED

### Repo Assets Consumed
| Asset | Purpose |
|-------|---------|
| `docs/anomaly_registry.md` | Primary anomaly source (30+ anomalies, 452 lines) |
| `docs/two_ground_truths.md` | Physical vs intent divergences |
| `docs/kryptos_ground_truth.md` | Public facts, derived facts, cribs |
| `reference/ed_scheidt_dossier.md` | Scheidt statements on method |
| `reference/sanborn_body_of_work.md` | Sanborn's artistic practice |
| `reference/smithsonian_archive.md` | Unpublished book manuscript |
| `reference/kryptosfan_findings.md` | Yellow pad notes, auction material |
| `reference/sanborn_correspondence.md` | "kryptos is available to all" |
| `reference/sanborn_open_letter_aug2025.md` | "(CLUE) what's the point?" |
| `reference/archive_photo_evidence_inventory.md` | IMG_1211-1240 archive photos |
| `reference/elonka_pn26_kryptos.md` | Elonka PhreakNIC 26 talk |
| `reference/john_le_carre_dossier.md` | Le Carré investigation (resolved) |
| `reference/cia_fac_minutes_1988.md` | Original FAC commission proposal |
| `reference/museumvisit.md` | NCM material culture analysis |
| `reference/nova_sciencenow_kryptos.md` | NOVA segment transcript |
| `reference/william_h_webster.md` | WW dossier |
| `MEMORY.md` | Strategic state, AAA findings |
| `scripts/running_key/` | 27 existing running-key scripts |
| `reference/running_key_texts/` | 5 available source texts |
| `src/kryptos/kernel/constants.py` | CT, cribs, Bean constraints |

### Source-Text Corpora Available
- Howard Carter tomb text (2 versions)
- CIA Charter, JFK Berlin speech, Reagan Berlin speech, NSA Act 1947, UDHR
- Phillips Collection museum text (from archive photo)
- K1+K2+K3 plaintext
- Kryptos Morse code text
- FM 34-40.2 (Military Cryptanalytics, XML)
- Sanborn maintenance instructions

### What Was NOT Available
- David Kahn's "The Codebreakers" (not in repo)
- Weltzeituhr city list (German)
- COMSEC/DRYAD manuals
- KGB operational instructions
- Any text from the $962,500 auction lot

---

## 2. NORMALIZED ANOMALY MODEL

### Summary Statistics
- **Total anomalies cataloged:** 46
- **Unresolved (available for inference):** 34
- **Consumed (explained by known narrative):** 12
- **High confidence:** 37 / 46
- **Tier 1 (almost certainly operative):** 13
- **Tier 2 (probably operative):** 21

### Anomaly Families (counts)
| Family | Count | % of Total |
|--------|-------|------------|
| narrative_semantic | 8 | 17% |
| material_inscription | 7 | 15% |
| misspelling | 6 | 13% |
| statistical | 5 | 11% |
| morse_code | 4 | 9% |
| physical_placement | 4 | 9% |
| lineation_columnar | 3 | 7% |
| extra_letter | 2 | 4% |
| punctuation | 2 | 4% |
| mirrored_reversed | 2 | 4% |
| superscript, spacing, character_count | 3 | 7% |

### Clustering Results

**Cluster 1: PROCEDURAL / METHOD-CONSTRAINING** (strongest, 20+ anomalies)
Key members: IMG_1236 (stego concept sketch), IMG_1221 (physical overlay), STEGO (Scheidt confirmation), MASKED (frequency masking), TECHNIQUE_FIRST (two-step model), NOT_MATH, E0b (near-identity substitution), E0c (one-to-one encryption), E0e (width-21), C5 (T IS YOUR POSITION), A5/DYAHR (position markers), AAA_col (4,8,10,26=Col)

**Cluster 2: CONSUMED BY NARRATIVE** (12 anomalies)
Already explained: D1→EASTNORTHEAST, A1→LAYER TWO, K3_SOURCE→Carter, D2→coordinates, B2→reversal theme, C4→palindrome theme, D3/D4→art installation, C6→SOS

**Cluster 3: LINGUISTIC / ORTHOGRAPHIC** (weak for source-text)
A4 (DESPARATLY), A3 (UNDERGRUUND), C2 (DIGETAL), F1 (collected misspellings), ORIENTATION ("it's the positioning")
Verdict: These are POSITIONAL MARKERS, not linguistic indicators.

**Cluster 4: ARCHIVE / RUSSIAN MATERIAL** (isolated to other projects)
IMG_1211, IMG_1212, IMG_1218: Cyrillic grids and Russian text in Sanborn's working files.
Assessment: Related to Cyrillic Projector (1997), NOT to Kryptos directly.

### Signal Extraction

**Language (weighted scores):**
| Language | Score | Evidence Chain |
|----------|-------|---------------|
| English | 63 | MASKED, ENIGMATIC_PT, C5, C2, A4, A3, F1, ORIENTATION, POINT_CLUE |
| Russian | 27 | IMG_1211, IMG_1218, IMG_1212 (archive working files only) |
| Cyrillic | 21 | IMG_1211, IMG_1212 (same items) |
| English_plaintext_confirmed | 12 | MASKED (Scheidt statement) |
| German_possible | 9 | A3 (UNDERGRUUND ≈ Untergrund) |

**Document Types (top 5):**
| Document Type | Score | Key Evidence |
|---------------|-------|-------------|
| Cardan_grille | 24 | IMG_1221, IMG_1212, IMG_1236 |
| physical_overlay | 24 | IMG_1221, IMG_1236, IMG_1237 |
| steganographic_method | 24 | IMG_1236, STEGO |
| DRYAD_sheet | 12 | C5 (T IS YOUR POSITION) |
| coding_chart | 12 | NOT_MATH, AAA archive |

**Extraction Rules (top 5):**
| Rule | Score | Evidence |
|------|-------|---------|
| null_masking_confirmed | 12 | IMG_1236 |
| overlay_reveals_message | 12 | IMG_1236 |
| X_marks_null_positions | 12 | IMG_1212 |
| near_identity_substitution | 12 | E0b |
| one_to_one_substitution | 12 | E0c |

---

## 3. RIVAL ANALYSES

### Rival 1: Anomaly-Cartographer
**Key claim:** 34 of 46 anomalies are unresolved and available for inference.
**Strongest evidence:** The archive photo cluster (IMG_1211-1240) is the richest anomaly source, showing physical working materials.
**Strongest objection:** Many "anomalies" are actually confirmed artist statements or art-installation features, not cipher clues.
**Survived synthesis:** Yes — the 34/46 unresolved count and clustering structure were accepted.

### Rival 2: Orthographic-Forensics Analyst
**Key claim:** Misspellings are POSITIONAL MARKERS, not source-language indicators.
**Strongest evidence:** Sanborn's own statement: "it's not what it was... it's the orientation or the positioning."
**Strongest objection:** UNDERGRUUND resembling German "Untergrund" is suggestive.
**Survived synthesis:** Yes — the claim that misspellings are procedural, not linguistic, is strongly supported. The German connection is weak (EASTNORTHEAST is English, not "Ostnordost").

### Rival 3: Structural-Cryptanalyst
**Key claim:** Anomalies overwhelmingly favor grille/overlay over running key.
**Strongest evidence:** IMG_1236 (explicit stego sketch), IMG_1221 (physical overlay), Scheidt "a little bit of stego", "solve the technique first".
**Strongest objection:** Running-key model survives structurally (13 mono DOF). Procedural anomalies could describe the first step of a multi-step process that includes running key.
**Survived synthesis:** Yes — the procedural evidence for grille/overlay is the strongest single finding.

### Rival 4: Corpus-Hunter (English)
**Key claim:** Available English corpora have all produced noise in running-key tests.
**Strongest evidence:** 27+ scripts tested. Carter, Berlin texts, speeches, K123 PT, Gutenberg sweep — all noise.
**Strongest objection:** Many important texts aren't in the repo (Kahn's Codebreakers, COMSEC manuals).
**Survived synthesis:** Partially — the corpus gap is real, but the anomaly evidence doesn't point to any specific untested text.

### Rival 5: Corpus-Hunter (Multilingual)
**Key claim:** Cyrillic/Russian material in archive is from other Sanborn projects.
**Strongest evidence:** IMG_1211-1212 match the Cyrillic Projector (1997), not Kryptos. No Kryptos sculpture anomaly references Russian.
**Strongest objection:** Sanborn had multilingual interests; the Kryptos installation explicitly references Russian (KGB text in Code Room).
**Survived synthesis:** Yes — Russian/Cyrillic evidence is artifact of other projects, not K4 source-text signal.

### Rival 6: Statistical-Auditor
**Key claim:** The scoring system has fatal thematic circularity.
**Strongest evidence:** No hypothesis survives ablation at p<0.05. Shuffling anomaly labels produces comparable scores.
**Strongest objection:** The specific grille/overlay anomalies (IMG_1236) are so explicit that they survive any reasonable null model.
**Survived synthesis:** Yes — the thematic circularity finding is accepted. But the auditor acknowledges IMG_1236's specificity as non-circular.

### Rival 7: Archivist-Historian
**Key claim:** "kryptos is available to all" eliminates private/classified sources.
**Strongest evidence:** Sanborn's direct statement (Feb 2026 correspondence).
**Strongest objection:** "Available to all" might mean the sculpture + public clues, not necessarily the source text.
**Survived synthesis:** Yes — this is a hard constraint. Any source text must be publicly findable.

### Rival 8: Skeptical-Execution Reviewer
**Key claim:** The entire premise of anomaly→source-text inference is a category error.
**Strongest evidence:** Narrative anomaly allocation shows most anomalies are consumed. No anomaly says "use this book." Sanborn wrote PT himself.
**Strongest objection:** The investigation was commissioned to test this premise, and testing a premise to failure is still valuable.
**Survived synthesis:** Yes — the skeptic's core argument is upheld. The anomaly registry constrains METHOD, not SOURCE TEXT.

---

## 4. CANDIDATE SOURCE-TEXT CLASSES

### Class A: Physical Overlay / Cardan Grille (NOT a source text)
**Why anomalies support it:** IMG_1236 (explicit), IMG_1221/1237 (physical overlay), IMG_1212 (X-marks), STEGO, MASKED, TECHNIQUE_FIRST, NOT_MATH
**Which anomalies do the work:** The archive photo cluster is decisive.
**Which anomalies do not fit:** Statistical anomalies (E0a-E0e) describe substitution properties, not grille properties.
**Language/genre implications:** N/A — this is a PROCEDURE, not a text.
**Extraction-rule implications:** Null extraction via physical overlay, then keyword substitution cipher.
**Verdict:** This is NOT a source-text hypothesis. It is the ALTERNATIVE to source-text mechanisms. It is the strongest overall hypothesis.

### Class B: COMSEC / Signal Operating Procedures
**Why anomalies support it:** C5 (T IS YOUR POSITION → DRYAD/COMSEC), C3 (RQ → radio prosign), A6 (? → BT break)
**Which anomalies do the work:** The Morse code anomaly cluster.
**Which do not fit:** Archive photos show art/stego materials, not COMSEC documents.
**Language:** English
**Document type:** Signal Operating Instructions, DRYAD tables
**Verdict:** Moderately supported for the PROCEDURAL FRAMEWORK (how to interpret the cipher), not as a running-key source. The Morse code anomalies describe how a COMSEC officer would INTERPRET the cipher steps, not what text was used.

### Class C: Cryptography Reference Text (Kahn, Friedman, manuals)
**Why anomalies support it:** B1 (HILL reference), AAA_BEAUFORT (Beaufort in cipher list), Scheidt's professional domain
**Which anomalies do the work:** B1 and AAA_BEAUFORT are the only direct evidence.
**Which do not fit:** Hill cipher is eliminated. Beaufort is a method, not a source text.
**Verdict:** Thematic match only. No anomaly says "use page X of Codebreakers." Historical plausibility is high but anomaly alignment is low.

### Class D: Sculpture-Derived Self-Referential Key
**Why anomalies support it:** "kryptos is available to all" + physical installation is the only thing guaranteed to be available
**Which anomalies do the work:** D1 (compass), progressive complexity model, POINT_CLUE
**Verdict:** Conceptually attractive. Maximum discoverability (score 10). But no specific anomaly describes HOW sculpture text becomes a running key.

### Class E: German-Language Text (Weltzeituhr, Berlin material)
**Why anomalies support it:** BERLINCLOCK → Weltzeituhr (German monument), UNDERGRUUND ≈ Untergrund
**Which anomalies do not fit:** EASTNORTHEAST is English, not "Ostnordost." Sanborn's statement: "I wrote the Plain Text to be enigmatic" (English).
**Verdict:** German has weak thematic support but no procedural support. The BERLINCLOCK crib is a reference to a German monument, but the crib itself is written in English.

---

## 5. RANKED CANDIDATE SOURCES

| Rank | ID | Name | Score | Ablation p | Category |
|------|-----|------|-------|-----------|----------|
| 1 | H25 | Physical overlay / Cardan grille | 5.56 | 0.116 | NOT a source text — PROCEDURAL |
| 2 | H14 | Morse code manual / signal ops | 5.38 | 0.167 | Thematic (COMSEC framework) |
| 3 | H22 | Russian intelligence text | 4.08 | 0.082 | Archive artifact, not K4 |
| 4 | H03 | Le Carré novels | 4.06 | 0.219 | Thematic only |
| 5 | H01 | Carter Tomb text | 3.83 | 0.223 | Thematic only (TESTED: noise) |
| 6 | H06 | CIA Charter | 3.81 | 0.237 | Thematic only |
| 7 | H07 | JFK/Reagan Berlin speeches | 3.73 | 0.246 | Thematic only |
| 8 | H18 | Morse code as running key | 3.05 | 1.000 | Self-referential (untested as RK) |
| 9 | H24 | Bespoke chart system | 2.88 | 1.000 | Method hypothesis, not text |
| 10 | H09 | Cryptography manual | 2.75 | 1.000 | Untested, highest plausibility |

**Score breakdown notes:**
- H25 (grille) scores highest because it aligns with the archive photo anomalies AND has high discoverability
- H14 (COMSEC manual) scores high on historical plausibility (Scheidt's domain) but has no tested corpus
- H22 (Russian) has the lowest ablation p-value (0.082) but this is driven by the Cyrillic archive cluster, which is from another project
- H03-H07 all score 3.7-4.1 with ablation p>0.2 — thematic correlation, not genuine anomaly alignment
- NO hypothesis achieves both score>4.0 AND ablation p<0.05

---

## 6. ELIMINATIONS

### Source-Text Classes Ruled Out by Evidence

| Class | Reason |
|-------|--------|
| Latin texts | Zero anomaly evidence. No Latin on the sculpture except the concept name "Kryptos" (Greek). |
| French texts | Zero anomaly evidence. |
| Spanish texts | Zero anomaly evidence. |
| Post-1990 texts | Anachronistic. Kryptos completed Nov 1990. |
| Classified documents | Eliminated by "kryptos is available to all." |
| Le Carré as PT author | Resolved: collaboration never happened. Sanborn wrote PT himself. |
| Russian as source language | Cyrillic archive material is from Cyrillic Projector (1997), not K4. |
| EQUAL anagram hypothesis | Invalid: UNDERGRUUND is not a deliberate misspelling (corrected on Antipodes). |
| Hill cipher from extra L | Algebraically eliminated for n=2,3,4 (Tier 1). |
| Any single anomaly as decisive | No individual anomaly has sufficient specificity. |

### Source-Text Hypotheses Killed by Testing

| Hypothesis | Test Result |
|-----------|-------------|
| Carter Tomb as running key (direct) | 27+ scripts, max 4/24 = noise |
| K1+K2+K3 plaintext as running key | Tested, noise |
| Phillips Collection museum text | Tested 4/24 = noise |
| Berlin Wall historical texts | Multiple scripts, noise |
| Various Gutenberg texts | e_gutenberg_sweep_01.py, noise |

---

## 7. INFORMATIVE vs NOISY ANOMALIES

### Genuinely Informative (constrain the METHOD)
| Anomaly | What It Tells Us |
|---------|-----------------|
| IMG_1236 | NULL MASKING is the method ("encrypted message within set of characters") |
| IMG_1221/1237 | PHYSICAL OVERLAY exists in archive |
| IMG_1212 | Working 26x26 grid with X-marks (possible null positions) |
| STEGO | Scheidt confirmed steganography |
| MASKED | Frequency analysis will not help (masking layer) |
| TECHNIQUE_FIRST | Two-step: solve technique first, then puzzle |
| E0b | Near-identity substitution (keyword-based alphabet) |
| E0c | One-to-one encryption (no transposition at crib positions) |
| E0e | Width-21 is statistically significant |
| C5 | "T IS YOUR POSITION" → COMSEC position indicator |

### Likely Noisy (weak/no discriminating power for source text)
| Anomaly | Why It's Noise for Source-Text |
|---------|-------------------------------|
| D3 (pool) | Art installation feature |
| D4 (shadows) | Atmospheric/thematic |
| C4 (palindromes) | Property of Morse, not a clue |
| C6 (SOS) | Standard distress signal |
| B2 (flipped tableau) | K1-K3 feature, not K4 |
| A7 (4 question marks) | Section dividers |
| AP_SF (S.F. dots) | Antipodes-specific |

---

## 8. ACTIONABLE NEXT STEPS (Priority Order)

### Highest Value: Method Testing (anomaly-supported)

1. **Transcribe IMG_1212 X-mark pattern** — The 26x26 Cyrillic grid with X-marks is the most promising direct evidence of a null mask. Full transcription of the 676-cell grid could identify null positions. REQUIRES: high-resolution photo access or careful manual transcription.

2. **Test null-mask + keyword-Beaufort model** — Anomalies E0b and E0c strongly support near-identity substitution with keyword-based alphabet. Combine with null extraction at candidate positions. This is the model the anomalies ACTUALLY support.

3. **Test sculpture's own text as running key** — If a running key is involved, the sculpture itself is the most "available to all" source. Test the Vigenère tableau read in various orders (row, column, diagonal, spiral) as key material for K4.

4. **Test Morse code text as running key** — K0 Morse code → K1/K2 keywords established. K0 could similarly generate K4 key material. Self-referential and publicly discoverable.

### Medium Value: Corpus Additions (if running key pursued)

5. **Ingest David Kahn's "The Codebreakers"** — Highest plausibility untested text. Scheidt certainly knew it. Kahn visited the NCM (per museum analysis). Can obtain from public library.

6. **Ingest Weltzeituhr city list (German)** — The 24 city/timezone entries from the Berlin World Clock. Direct BERLINCLOCK connection. Short text (~500 chars), good for offset testing.

7. **Ingest FM 34-40.2 cryptanalysis manual plaintext** — Already in repo as XML. Extract clean plaintext for running-key testing.

### Low Value: Do NOT Invest

8. **Do NOT fish through random books** — The anomaly evidence does not support identifying a specific book. Every thematic-match test (Carter, Berlin, speeches) has produced noise.

9. **Do NOT prioritize multilingual corpora** — Russian/Cyrillic evidence is from other Sanborn projects. German evidence is thematic only. English is overwhelmingly supported.

10. **Do NOT treat misspellings as source-language indicators** — They are positional markers per Sanborn's own statement.

---

## 9. META-FINDING: THE ANOMALY REGISTRY AS METHOD ORACLE

The most important finding of this investigation is **negative for source-text inference but strongly positive for method inference.**

The anomaly registry, when properly analyzed with rival agents and ablation controls, reveals:

**What the anomalies DO constrain:**
- The cipher uses NULL MASKING / STEGANOGRAPHY (confirmed by 4 independent anomalies)
- Physical overlays are part of the method (archive evidence)
- The method has TWO STEPS: unmask then decrypt (Scheidt statement)
- The substitution layer uses a KEYWORD-BASED ALPHABET near AZ (Bean E0b)
- The substitution is ONE-TO-ONE, no transposition at crib positions (Bean E0c)
- Width 21 has structural significance (Bean E0e)
- COMSEC procedural framework applies (C5, C3, A6)

**What the anomalies DO NOT constrain:**
- Which specific book (if any) was used as a running key
- What language the source text is in (beyond English for PT)
- What genre or document type the source text belongs to
- What extraction rule was used on the source text

**The running-key hypothesis is not killed by this analysis** — it survives structurally. But the anomaly evidence cannot help locate the source text. If a running key IS involved, finding it requires cryptanalytic methods (crib-dragging, statistical correlation, source-text enumeration), not anomaly analysis.

The anomaly registry is a **method oracle**, not a **source-text oracle**.

---

*Generated by: `scripts/analysis/e_anomaly_source_text_inference.py`*
*Data: `results/anomaly_ledger.json` (46 anomalies), `results/source_text_hypothesis_scores.json` (26 hypotheses)*
*Runtime: 26 workers, 1000 ablation trials per hypothesis*
