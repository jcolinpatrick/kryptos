# YAR/NDYAHR Shifted-Letter Anomaly Audit

**Date**: 2026-04-03
**Method**: Team of Rivals adversarial investigation (7 parallel agents)
**Authors**: Colin Patrick (commissioning), Claude (computational partner)
**Status**: AUDIT COMPLETE — anomaly is REAL but UNDERDETERMINED

---

## 1. Executive Verdict

The shifted-letter phenomenon near the K3/K4 boundary on the Kryptos sculpture is **almost certainly real and intentional**, but its cryptographic function remains undetermined after extensive testing. The core evidence: Elonka Dunin confirmed physical displacement of Y, A, R via hands-on rubbings in October 2002 — this is first-hand tactile evidence, not photographic interpretation. Sanborn reportedly called the anomaly "important" but has never explained it. However, the exact letter set (3? 5? 6?), the displacement types, and the intended function are all contested. After 28+ scripts and thousands of configurations tested, no cipher mechanism using these letters has scored above noise (best: 4/24). The anomaly most likely functions as a structural signpost — possibly indicating that the KRYPTOS keyword and width-7 grid are relevant to K4 — rather than as direct key material.

---

## 2. Evidence Ledger

### 2.1 Primary Source Claims

| # | Source | Date | Claim | Letters | Displacement Type | Evidence Basis | Status |
|---|--------|------|-------|---------|------------------|----------------|--------|
| 1 | Elonka Dunin physical rubbings | Oct 2002 | Y, A, R raised above baseline | 3 (YAR) | Raised several cm | **First-hand physical contact** | SUPPORTED |
| 2 | solvingkryptos.com community | ~2003-2010 | DYARO (5 chars) all misaligned | 5 (DYARO) | General misalignment | Visual observation (photos?) | UNVERIFIED |
| 3 | Elonka at PhreakNIC 26 | Nov 2025 | DYAHR "out of alignment"; Sanborn says "important" | 5 (DYAHR) | Out of alignment | Second-hand (Elonka reporting Sanborn) | REPORTED |
| 4 | YouTube community video | ~2006+ | "odd spacing that makes them stand out" | 5 (DYAHR) | Odd spacing | Community observation | SECONDARY |
| 5 | ndyahr_displacement.md (project) | Mar 2026 | NDYAHR directional vectors (W,E,N,N,E,NW) | 6 (NDYAHR) | Directional (mixed) | Computational grid analysis | DERIVED — measurement basis unclear |
| 6 | anomaly_registry.md (project) | 2026 | YAR raised; DYARO alternative | 3 or 5 | Raised / misaligned | Synthesis of sources 1-4 | SYNTHESIS |

### 2.2 Contradiction Matrix

| Feature | Claim A | Claim B | Assessment |
|---------|---------|---------|------------|
| Letter count | 3 (YAR) — Elonka rubbings | 6 (NDYAHR) — project analysis | **UNRESOLVED**: only YAR has physical confirmation |
| Letter set | DYAHR (Elonka PN26) | DYARO (solvingkryptos.com) | **Different 5th letter**: H vs O |
| Displacement type | "Raised above baseline" | "Directional vectors (W,E,N,N,E,NW)" | **CONFLATED**: "raised" ≠ directional. Only Y,A,R confirmed raised |
| Sanborn statement | "Important" (via Elonka) | Never publicly addressed | **CONSISTENT**: evasion + second-hand confirmation |
| Antipodes comparison | YAR absent from Antipodes | No photographic verification in repo | **ASSUMED, NOT CONFIRMED** |

### 2.3 Internal Project Contradictions

The project's own scripts disagree with each other:
- `e_ndyahr_blind_cryptanalysis.py` line 362: claims "5 physically raised/displaced letters" but lists 7 (ENDYAHR)
- Same script line 769: "DYAHR (just the raised letters)" — only 4 if you spell it out
- Same script line 775: "YAR (the 3 traditionally raised letters)" — 3
- `anomaly_registry.md`: 3 (YAR) primary, 5 (DYARO) alternative
- `ndyahr_displacement.md`: 6 (NDYAHR) + 1 undisplaced (E) = 7 total

**This sequence instability is itself evidence that the boundary between "anomalous" and "normal variation" is subjective for letters beyond YAR.**

---

## 3. Measured Anomaly Table

### 3.1 What Has Been Measured

**CRITICAL GAP**: No pixel-level character position data exists in the repository. The 159+ photos in `reference/Pictures/` have never been processed for character bounding boxes or baseline measurements. The directional vectors in `ndyahr_displacement.md` are derived from grid analysis, not from image measurement.

### 3.2 Best Available Position Data (from ndyahr_displacement.md)

| CT Position | Letter | Row | Col | Visual Anomaly Type | Confidence | Measurement Source |
|-------------|--------|-----|-----|---------------------|------------|-------------------|
| ~434 | E | 14 | 0 | None (baseline reference) | HIGH | Elonka rubbings (undisplaced) |
| ~435 | N | 14 | 1 | Left-shifted? | LOW | Grid inference only |
| ~436 | D | 14 | 2 | Right-shifted? | LOW | Grid inference only |
| ~437 | Y | 14 | 3 | **Raised above baseline** | **HIGH** | **Elonka physical rubbings** |
| ~438 | A | 14 | 4 | **Raised above baseline** | **HIGH** | **Elonka physical rubbings** |
| ~439 | H | 14 | 5 | Right-shifted? | LOW | Grid inference only |
| ~440 | R | 14 | 6 | **Raised above baseline** | **HIGH** | **Elonka physical rubbings** |
| ~441 | O | 14 | 7 | Misaligned? | LOW | solvingkryptos.com only |

**Confidence assessment**: Only Y, A, R have HIGH confidence displacement (physically verified). N, D, H displacements are LOW confidence (inferred from grid position, not physically measured). The directional vectors (W, E, N, N, E, NW) in the project report are **computational claims without stated measurement methodology**.

---

## 4. Sequence Assessment

### 4.1 Best-Supported Sequence

**YAR (3 letters)** — the only sequence with first-hand physical verification (Elonka rubbings, 2002). Displacement type: raised above baseline by "several centimeters."

### 4.2 Alternatives Considered

| Sequence | Letters | Source | Why Retained or Rejected |
|----------|---------|--------|--------------------------|
| **YAR** | Y, A, R | Elonka rubbings | **RETAINED** — only physically verified set |
| **DYAHR** | D, Y, A, H, R | Elonka PN26 | RETAINED (tentative) — Elonka attributed to Sanborn but not physically verified beyond YAR |
| **DYARO** | D, Y, A, R, O | solvingkryptos.com | WEAK — conflicts with DYAHR (different 5th letter), no Sanborn attribution |
| **NDYAHR** | N, D, Y, A, H, R | Project analysis | SPECULATIVE — extends beyond any primary source; measurement basis unclear |
| **ENDYAHR** | E, N, D, Y, A, H, R | Project analysis | SPECULATIVE — includes undisplaced E as baseline anchor; convenient for col-7 mapping |

### 4.3 Assessment

The sequence is **unstable beyond YAR**. The progression YAR → DYAHR → NDYAHR → ENDYAHR looks like successive project sessions expanding the set without independent physical verification at each step. This is a contamination risk: each extension adds letters with decreasing confidence, and downstream analysis (column mappings, sum=64, directional vectors) depends on the extended set being correct.

**Recommendation**: Future work should treat YAR as the verified core and DYAHR/NDYAHR as unverified extensions requiring independent physical confirmation.

---

## 5. Rival Hypotheses Table

| # | Hypothesis | Mechanism | Supporting Evidence | Conflicting Evidence | Overfitting Risk | Tested? | Result | Next Falsification |
|---|-----------|-----------|--------------------|--------------------|-----------------|---------|--------|-------------------|
| H1 | Direct primer/key | Numeric values (Y=24, A=0, R=17) as Vimark/Gromark primer | Clean numeric values; matches p=3 primer length | All primer tests fail; Bean cycle feasibility eliminates Vimark with these values | MEDIUM | YES (extensively) | **NOISE** (best 4/24) | CLOSED — eliminated |
| H2 | Extraction order markers | Displaced letters mark CT positions to extract in order | Would explain physical salience | No mechanism for 3 positions → 97-char solve; order is ambiguous | HIGH | Partially | Inconclusive | Define extraction rule, test all orderings |
| H3 | Null/deletion markers | Displaced letters are nulls to remove before decryption | Removing Y,A,R from K4 gives 94 chars | 94 is not a useful length; removing from K1-K3 gives high IC but no plaintext | MEDIUM | YES | **NOISE** | CLOSED for simple removal |
| H4 | Grille registration marks | Mark corners/alignment for physical overlay | "I like spatial systems" (Sanborn); col-7 alignment | Only 3 points insufficient for unique registration; 5+ might work | MEDIUM | YES (extensive grille testing) | **NOISE** (0 crib hits across 511 subsets) | CLOSED for standard Cardan grille |
| H5 | Transposition anchors | Mark where to cut/rearrange text | KRYPTOS column correspondence (cols 0-6) | All col-7 transposition orderings tested; best 4/24 without null mask | LOW | YES | **NOISE** without null mask | Test WITH correct null mask (coupling hypothesis) |
| H6 | Route cipher turning points | Mark direction changes in route read | Directional vectors could encode turn sequence | 6 directions for 97-char route is underconstrained | HIGH | YES (H2 in displacement report) | **NOISE** (0/24) | CLOSED |
| H7 | Binary/ternary state encoding | Raised=1, normal=0 across full sculpture | Would give ~870-bit message | Only 3-6 letters identified as anomalous; no systematic survey of all 869 chars | HIGH | Partially (H4 in displacement report) | **NOISE** | Requires full-sculpture survey — infeasible without measurement |
| H8 | Section boundary marker | Simply marks K3→K4 transition; no cipher function | Located exactly at K3/K4 boundary; other sections have markers (? marks) | Why raise letters instead of using ? like other boundaries? | LOW | N/A | N/A (artistic interpretation) | Cannot be falsified — unfalsifiable |
| H9 | Structural signpost | Announces "KRYPTOS keyword + width-7 grid matter for K4" | ENDYAHR maps to KRYPTOS columns; sum=64=2^6; horizontal symmetry | Doesn't improve any attack score; post-hoc pattern matching | MEDIUM | Interpretive only | **Most favored by project** | Would be confirmed if width-7 solve succeeds |
| H10 | Fabrication artifact | Normal hand-cutting variation; not intentional | Copper is hand-cut with jigsaw; baseline variation expected | Elonka physical rubbings confirm "several centimeters" — too large for normal variation; Sanborn said "important" | LOW | N/A (skeptical null) | **Weakened** by Elonka evidence | Requires systematic survey showing comparable displacement elsewhere on sculpture |

---

## 6. Antipodes Comparison

### What is CONFIRMED:
- K4 ciphertext is byte-for-byte identical on both sculptures
- Antipodes has S.F. dots (2 periods) on Row 22 — the ONLY punctuation on either sculpture
- Antipodes corrects UNDERGRUUND → UNDERGROUND
- Antipodes uses full justification vs. Kryptos' ragged right
- Antipodes section order is K3→K4→K1→K2 (vs K1→K2→K3→K4)

### What is REPORTED but NOT VERIFIED:
- **YAR superscript absent from Antipodes** — stated in project scripts but no photographic evidence in repo; no primary Sanborn statement
- Extra L absent from Antipodes tableau — reported, not independently verified

### What is UNKNOWN:
- How Antipodes handles the K3/K4 boundary region physically
- Why any features differ between the sculptures (Sanborn has never commented)
- Whether Antipodes has its own typographic anomalies at different positions
- Identity of "S.F." on Antipodes (unexplained initials replacing W.W.)

### Assessment:
**The Antipodes comparison is weaker than the community assumes.** The absence of YAR on Antipodes is treated as near-certain in community discussion and in this project's scripts, but no one has produced photographic or physical evidence in the repo. The different justification (full vs ragged) means line breaks fall differently, which could affect apparent alignment even if the underlying letters are identically positioned. Using Antipodes as a "clean control" requires verification we don't have.

---

## 7. Strongest Pro-Anomaly Case

1. **Physical evidence**: Elonka Dunin physically rubbed the sculpture (Oct 2002) and confirmed Y, A, R are raised "several centimeters." This is not photography — it's tactile measurement on copper.
2. **Sanborn attribution**: Elonka reports Sanborn said the anomaly is "important." He has never contradicted this.
3. **Fabrication argument**: "You could not make any mistake with 1,800 letters" — Sanborn's own framing eliminates accidental explanation.
4. **Structural coherence**: ENDYAHR maps exactly to the KRYPTOS keyword columns (0-6) in a width-31 grid. This is a clean, non-arbitrary correspondence.
5. **Location significance**: The anomaly sits precisely at the K3/K4 boundary — the most cryptographically significant transition on the sculpture.

## 8. Strongest Anti-Anomaly Case (Red Team)

1. **Fabrication method kills the premise**: The Smithsonian archive (`reference/smithsonian_archive.md`, lines 323-347) reveals Kryptos was hand-cut with **jigsaws** by up to **20 assistants** over 8 months, consuming 900 blades. Each letter was drilled, jig-sawed, and filed individually at a rate of 6-10 letters per person per day. Baseline drift of "several centimeters" on a curved S-shape surface cut by 20 different people is **structurally expected, not anomalous**. The community assumption that Kryptos was precision-cut (waterjet) is factually wrong — waterjet was only used in later Sanborn works.

2. **No systematic survey**: Out of 869 characters on the cipher side, **nobody has measured displacement for all of them**. Elonka took rubbings of ONLY the YAR area (partial rubbings: `ndy.jpg` and `ahr.jpg`). This is textbook confirmation bias — one cluster selected from 869 characters on a hand-cut curved surface, noticed by one person, never compared to the sculpture's full displacement distribution.

3. **S-curve panel join coincidence**: The YAR location ("upper lefthand corner of the lower panel") is precisely where the S-curve copper plate has a curvature inflection point. At any inflection point, a straight scribe line departs from the surface normal, and letters cut along that line appear displaced when viewed from the convex side. Multiple adjacent letters shift together — exactly what's observed.

4. **Rubbings don't escape curvature**: Elonka's rubbings are pressed against a CURVED surface then flattened for scanning. A rubbing on a curve, when flattened, shows apparent displacement that maps to local curvature, not intentional offset. No straight-edge measurement was taken at the site.

5. **"Sanborn says it's important" provenance is weak**: The red-team traced this to auto-generated YouTube subtitles (`reference/youtube_sanborn_cipher.en-orig.srt`, lines 1727-1731): *"Sandborn has said that it's important, but you don't know much beyond that."* This is: (a) Elonka paraphrasing Sanborn, (b) machine-transcribed (note "Sandborn" misspelling), (c) no date/context for when Sanborn said it, (d) unclear whether "it" means the displacement specifically or the K3/K4 boundary generally.

6. **Sequence instability**: Observers cannot agree which letters are displaced (3, 5, or 6). Over 23 years, Elonka's own identification expanded from 3 (YAR, 2002) to 5 (DYAHR, 2025). This is scope creep on a continuous gradient, not binary intentional displacement.

7. **50 scripts, zero signal**: The exhaustion log contains 50 YAR-related entries spanning every conceivable interpretation. Zero have produced scores above noise. If YAR encoded meaningful cipher parameters, at least one of 50 diverse approaches should have found signal.

8. **Unfalsifiable signpost**: "Structural signpost" is the project's favored interpretation, but it's unfalsifiable — any correspondence can be called a signpost post-hoc.

### Red Team Probability Assessment

| Scenario | Estimated Probability |
|----------|----------------------|
| Displacement is physically present | ~85% |
| Displacement is intentional (Sanborn did it on purpose) | ~35% |
| Displacement is cryptographically meaningful | ~10% |
| Displacement will lead to K4 solution | ~5% |

The gap between "physically present" (~85%) and "cryptographically meaningful" (~10%) is where the community has made an unjustified leap.

---

## 9. Cryptanalyst's Hypothesis Ranking

The cryptanalytic agent ranked all hypotheses by residual plausibility after accounting for test results:

| Rank | Hypothesis | Status | Rationale |
|------|-----------|--------|-----------|
| 1 | **Section boundary marker** (no cipher function) | NULL HYPOTHESIS — favored | Most parsimonious; consistent with all data including 50 failed tests |
| 2 | **Fabrication artifact** | NULL HYPOTHESIS — strong | Hand-jigsaw + S-curve panel join explains displacement pattern |
| 3 | Direct primer/key | MOSTLY ELIMINATED | Survives only for untested cipher families |
| 4 | Grille registration marks | ELIMINATED | 12+ scripts, 511 subsets, zero crib hits |
| 5 | Null/deletion markers | ELIMINATED (simple) | Resulting lengths unhelpful; high IC trivial artifact |
| 6 | Extraction order | ELIMINATED | 512 subsets tested, all noise |
| 7 | Transposition anchors | ELIMINATED (standalone) | All col-7 orderings tested without null mask |
| 8 | Binary/ternary full-sculpture encoding | BLOCKED | Requires physical measurement of all 869 chars |
| 9 | Route cipher turning points | ELIMINATED | Pure transposition Tier 1 eliminated |
| 10 | K3 editing instructions | ELIMINATED | 50K configs, 6 phases, all noise |
| 11 | Authentication trigraph | UNFALSIFIABLE | No testable prediction |

**Key cryptanalyst observation**: The letter-count ambiguity (3/5/6) is itself evidence against cipher-functional hypotheses. If the displacement were a precise cipher instruction, boundaries would be sharp and all observers would agree. The gradient nature suggests either the medium doesn't support binary precision, or the displacement isn't a cipher instruction.

### Tier Reassessment Recommendation

**Current classification** (anomaly_registry.md): Tier 1 — "Almost certainly cryptographically operative"

**Recommended reclassification**: **Tier 2 — "Probably operative but function unknown"** or **Tier 3 — "Possibly operative"**

Rationale: "Almost certainly cryptographically operative" requires either (a) a Sanborn confirmation, or (b) a working mechanism. Neither exists. The physical displacement is probably real, Sanborn probably did it intentionally, but 50 failed tests and a thirdhand "important" quote do not support Tier 1 confidence in cryptographic operativeness.

---

## 10. Recommended Next Actions

### HIGH PRIORITY

1. **Pixel-level measurement from photographs** — Select the highest-resolution K3/K4 boundary photos from `reference/Pictures/` (cipherlowerleft.jpg, cipherlowermiddle.jpg, obkr.jpg) and extract character bounding boxes using computer vision. This is the single highest-value task: it would establish which letters are actually displaced and by how much, resolving the 3/5/6 letter ambiguity.

2. **Full-sculpture baseline survey** — Measure letter positions across the ENTIRE cipher panel (not just the K3/K4 boundary) to establish normal fabrication variation. Without this, we cannot distinguish signal from noise.

3. **Verify Antipodes YAR absence** — Obtain or locate photographs of the Antipodes K3/K4 boundary region. The Hirshhorn Museum (Washington DC) has the sculpture. Until this is verified, the Antipodes comparison is unreliable.

### MEDIUM PRIORITY

4. **Test NDYAHR directions WITH null mask** — The project's best lead (DEFECTOR:AZ_beau+col7+null-mask at 15/24) uses col-7 transposition. NDYAHR encodes col-7 directional information. These have been tested separately but never coupled with the correct null mask from the 15/24 model.

5. **Test YAR as verification mechanism** — Rather than testing YAR as INPUT to a cipher, test whether it serves as OUTPUT verification: "if you found the correct plaintext, do YAR positions have a special property?" This inverts the hypothesis direction.

### LOW PRIORITY

6. **Systematic archival search for Antipodes documentation** — The AAA archive has zero Antipodes documents. Check Hirshhorn Museum archives, Sanborn's studio records, or the private collector's records.

---

## 11. Do Not Repeat List

These specific approaches have been tested and should NOT be re-run without new evidence:

1. YAR values (24, 0, 17) as Vimark/Gromark primer — **ELIMINATED**
2. YAR selective substitution (tableau chars at YAR positions) — **ELIMINATED** (0 crib hits across 511 subsets)
3. NDYAHR removal from K1+K2+K3 as running key — **NOISE** (6/24)
4. NDYAHR directional vectors as transposition offsets — **NOISE** (2/24)
5. NDYAHR as null mask generator via mod-30 — **INCOMPATIBLE** with cribs
6. K3 with NDYAHR removed as hidden message — **DISPROVED** (high IC is trivial artifact)
7. All 10 cipher hypotheses in ndyahr_displacement.md — **ALL NOISE** (best 4/24)
8. Hill cipher with YART matrix parameters — **ELIMINATED** (E-S-151)

---

*Generated 2026-04-03 by Team of Rivals investigation (7 parallel agents)*
*Primary author: Claude (computational partner) for Colin Patrick*
