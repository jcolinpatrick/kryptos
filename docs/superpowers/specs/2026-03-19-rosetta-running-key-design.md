# Rosetta — Multi-Source Running Key Search

**Date:** 2026-03-19
**Status:** Revised (post spec-review round 1)
**Motivation:** Running key is the ONLY surviving computational cipher class for K4. The corrected intermediate-space keystream IC=0.029 (below random 0.038) is the signature of a running key with a source of different frequency distribution than English. All prior running key tests used English-language sources exclusively (479 Gutenberg EN + 32 reference texts + K1-K3 PT transformations). Non-English sources are a genuine gap.

**Prior art:** `2026-03-17-k123-running-key-exhaustive-design.md` (K1-K3 PT transformations, max 7/24 = noise). TKAS v2 running key (38 texts, 336B comparisons, noise). Gutenberg Phase 4 (479 texts, 10 categories, max 10/24 = noise). All English. Also `e_antipodes_04_sculpture_running_key.py` tested K1/K2/K3 CT and concatenations as running keys — OVERLAP with Phase 1 original design. `e_cfm_01_running_key_foreign.py` tested ~9 hardcoded German/French passages — provides baseline but is not a large-scale corpus search.

---

## Architecture

```
Phase 1: Sculpture-Derived Running Keys (~100 configs, minutes)
  |
Phase 2: German Corpus Search (~500 texts, 2-4 hours)
  |
Phase 3: French + Russian Corpus Search (~300 texts, 1-3 hours)
  |
Phase 4: Extended Source Search (Egyptian, Latin, classified-era docs)
  |
Signal Classification + Bean Filtering
```

## Phase 1: Verification Baseline (sanity checks only)

### Rationale
Phase 1 is NOT novel exploration — it reproduces prior results as a sanity check for the scoring pipeline. Most sculpture-derived running keys have already been tested in `e_antipodes_04_sculpture_running_key.py` (K1/K2/K3 CT and concatenations) and periodic keywords are already conditionally eliminated in the direct-positional Bean model.

### What this phase does
1. **Reproduce** K3 PT as running key → confirm max 7/24 (matches prior result)
2. **Reproduce** K3 CT as running key → confirm noise (matches `e_antipodes_04` result)
3. **Include 50 English Gutenberg texts** as control → confirm max 10/24 (matches prior Phase 4)
4. **Synthetic positive test**: generate a fake K4 CT using a known German text + Beaufort → verify the pipeline finds it

### What this phase does NOT do
- Does NOT re-test cycling keywords (PALIMPSEST, ABSCISSA, KRYPTOS) — these are periodic substitution and are already conditionally eliminated in the direct-positional model
- Does NOT re-test tableau rows/columns as running keys — covered by `e_antipodes_04` and `e_chart_01`
- Does NOT re-test K2 coordinate texts — covered by elimination ledger entry 9

### Config count
~55 source texts × ~200 avg offsets × 6 variants × 2 models = ~132K evaluations

### Expected runtime: 1-2 minutes on 28 cores

---

## Phase 2: German Corpus Search

### Rationale
K4 plaintext contains BERLINCLOCK. K2 coordinates point to Berlin. Sanborn's Cold War espionage theme is inherently German. German letter frequencies differ significantly from English (more common: E, N, I, S, R; umlauts Ä/Ö/Ü stripped). A German running key would produce sub-random IC in the keystream — matching the observed 0.029.

### Corpus assembly
- Source: Project Gutenberg DE (gutenberg.org/browse/languages/de)
- Target: 500 texts minimum
- Priority categories:
  1. Berlin/Cold War/espionage themes
  2. Howard Carter tomb discovery accounts (German translations)
  3. Archaeological texts
  4. Compass/navigation/surveying
  5. Cryptography/codes/ciphers
  6. General literature (high-frequency classics: Goethe, Kafka, Mann)

### Text preparation
- Strip all non-alpha characters
- Convert umlauts: Ä→AE, Ö→OE, Ü→UE, ß→SS (standard)
- Also test: Ä→A, Ö→O, Ü→U (simplified)
- Convert to uppercase
- Minimum length: 200 chars after cleaning

### Method
Same scoring as Phase 1 but with larger corpus:
- Each text × sliding window (step=1, offsets 0 to len-97)
- 6 cipher variants: {Beaufort, Vigenère, Variant Beaufort} × {KA, AZ}
- **NOTE**: Existing `running_key.py` module supports AZ only. KA variants must be implemented inline using `KA.sequence` for index lookup. Pattern: `ka = KA.sequence; pi = (ka.index(key_c) - ka.index(ct_c)) % 26; pt_c = ka[pi]`
- Two models with explicit crib positions:
  - **Model B (raw 97)**: Decrypt all 97 chars. Cribs at positions 21-33 (ENE) and 63-73 (BCL).
  - **CT73 (consensus nulls extracted)**: Remove characters at consensus null positions {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85}. Remaining 80 chars (17 consensus nulls from 97). **Remapped crib positions**: ENE at raw 21-33 maps to CT73 positions 13-25 (subtract count of nulls before position 21: positions {0,1,2,5,8,12,14,20} = 8 nulls). BCL at raw 63-73 maps to CT73 positions 53-63 (subtract 10 nulls before position 63: add {36,52} = 10 total). **These remapped positions must be verified in the sanity check (Phase 1).**
- Crib-based scoring with n-gram followup for ≥ 8/24

### Config count
~500 texts × ~5000 avg offsets × 6 variants × 2 models = ~30M evaluations

### Expected runtime: 2-4 hours on 28 cores (parallelized by text)

---

## Phase 3: French + Russian Corpus Search

### Rationale
- **French:** Carter's original excavation reports published in French (Annales du Service des Antiquités de l'Égypte). Sanborn adapted Carter's journal for K3. The ORIGINAL French reports are thematically closer to K4 than English translations.
- **Russian (transliterated):** KGB/Cold War intelligence context. DEFECTOR keyword references Häyhänen (Soviet spy). Berlin was the epicenter of East-West intelligence. Russian texts transliterated to Latin alphabet have distinct frequency distributions.

### Corpus assembly
- French: Gutenberg FR, ~200 texts, same priority categories as German
- **Russian deferred to Phase 4.** Cyrillic-to-Latin transliteration is non-trivial (digraphs: Ш→SH, Щ→SHCH, Ч→CH, Ж→ZH, Ц→TS expand text length unpredictably). Deferring avoids implementation complexity in the critical path. If Phases 2-3 show systematic differences in foreign-language score distributions, Russian becomes worthwhile.

### Text preparation
- French: strip accents (É→E, À→A, Ç→C, Ê→E, etc.), uppercase, alpha-only
- Minimum length: 200 chars after cleaning

### Method
Same as Phase 2.

### Config count
~300 texts × ~5000 avg offsets × 6 variants × 2 models = ~18M evaluations

### Expected runtime: 1-3 hours on 28 cores

---

## Phase 4: Extended Source Search (if Phases 1-3 produce noise)

### Sources (same method/scoring as Phases 2-3)
- Russian transliterated texts (~100 texts, BGN/PCGN romanization with digraph handling)
- Egyptian hieroglyphic transliterations (Gardiner notation → Latin)
- Latin texts (classical cryptographic tradition)
- CIA declassified documents (available via FOIA reading room, plain text)

### Scope: Contingent on Phase 2-3 results. Only proceed if the foreign-language frequency effect shows promise (mean score distribution differs from English baseline).

---

## Scoring

### Primary: Crib consistency (0-24)
Count matching crib characters at stated positions:
- EASTNORTHEAST at positions 21-33 (13 chars)
- BERLINCLOCK at positions 63-73 (11 chars)

### Secondary: English n-gram quality
For any candidate scoring ≥ 8/24:
- Quadgram log-probability per character (English ~ -2.5 to -3.5, noise ~ -5 to -6)
- IC of decrypted text
- Word boundary detection (common English words present)

### Tertiary: Bean constraint filtering
For any candidate scoring ≥ 18/24:
- Check Bean equality: k[27] = k[65]
- Check all 242 Bean inequalities
- Full validation pipeline

### Thresholds
| Score | Action |
|-------|--------|
| 0-7 | Discard (noise) |
| 8-17 | Log with source text + offset + variant |
| 18-23 | SIGNAL — full Bean + n-gram analysis, manual review |
| 24 | BREAKTHROUGH — immediate stop and verify |

---

## Implementation

### Script: `scripts/running_key/e_rk_rosetta.py`

### Dependencies
- `kryptos.kernel.constants` (CT, cribs, Bean constraints)
- `kryptos.kernel.alphabet` (KA, AZ)
- `kryptos.kernel.scoring.aggregate` (score_candidate, score_candidate_free)
- `multiprocessing` (stdlib, 28-core parallelism)
- `urllib.request` (stdlib, Gutenberg downloads)

### Corpus storage
- `data/corpus/de/` — German texts (gitignored)
- `data/corpus/fr/` — French texts (gitignored)
- `data/corpus/ru/` — Russian transliterated texts (gitignored)
- `data/corpus/sculpture/` — Sculpture-derived texts (small, tracked)

### Output
- `results/rosetta/phase1_baseline.json` — Phase 1 verification results
- `results/rosetta/phase2_german.json` — Phase 2 results
- `results/rosetta/phase3_french.json` — Phase 3 results
- `results/rosetta/summary.json` — Overall summary + best candidates

### Registration
- Update `exhaustion_log.json` via `scripts/lib/exhaustion.update()` after completion
- Family: `running_key`
- Status: `completed` (regardless of outcome)

### Parallelization
- Phase 1: single-threaded (fast enough)
- Phases 2-3: `multiprocessing.Pool(28)`, one text per worker
- Each worker processes all offsets × variants × models for its text
- Workers write intermediate results to per-text JSONL files
- Main process aggregates at end

### Corpus download
- Gutenberg plain text URLs follow pattern: `gutenberg.org/cache/epub/{id}/pg{id}.txt`
- Curate a list of ~800 text IDs (500 DE + 200 FR + 100 RU) in `data/corpus/manifest.json`
- Download script: `scripts/running_key/download_corpus.py`
- Deduplication: skip texts shorter than 200 chars after cleaning

---

## Verification

1. **Sanity check:** Run Phase 1 with K3 PT as running key → should match prior result (max 7/24)
2. **English baseline:** Include 50 English Gutenberg texts as control group → should match prior Phase 4 (max 10/24 = noise)
3. **Synthetic positive:** Generate a synthetic K4 CT using a known German text as running key + Beaufort → verify the search finds it

---

## Risk Assessment

- **Probability of success:** Low (5-10%). Running key from a public text is unlikely given Sanborn's comments about the mechanism being "not reasonably guessable."
- **Value if successful:** Absolute breakthrough — K4 solved.
- **Value if unsuccessful:** Eliminates non-English public running keys as a class, narrowing the remaining attack surface to: classified/unpublished sources, bespoke mechanisms, or non-computational paths only.
- **Downside risk:** None (pure computation, no destructive operations).

---

## Success criteria

- Any candidate ≥ 18/24 with coherent plaintext fragments from a thematically relevant source = **investigate immediately**
- All phases ≤ 8/24 = non-English public running keys ELIMINATED, update elimination ledger
- Intermediate: identify whether German/French/Russian frequency distributions produce systematically different score distributions than English (informative even without a hit)
