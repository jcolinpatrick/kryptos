# CT-Perturbation Stage B — Archive Review Checklist

**Purpose:** guide the operator through producing `ambiguous_positions.json` and the §13 decision-gate document, with discipline that survives a red-team review.

**Authors:** Colin Patrick + Claude
**Date:** 2026-05-11
**Status:** working checklist; do not treat as binding doctrine

---

## 1. The discipline before the evidence

The single biggest failure mode for this campaign is **researcher degrees of freedom**: picking positions because you've already imagined a correction at them. The prereg §3.1 says the set is "predeclared in a separate input file BEFORE the runner starts and MAY NOT be modified after the campaign launches" precisely because of this.

**Do this in order:**

1. Catalogue evidence first, candidates second, manifest third.
2. For each candidate position, the rationale exists BEFORE you look at the K4 character at that position.
3. Write the §13 decision-gate document BEFORE running `--execute-full`. The "what would change my mind" sentence is binding.

**Do NOT:**

- Look at which Hamming-2 corrections produce Bean-passing keystreams and reverse-engineer the manifest from that.
- Pick positions because they're crib-adjacent without a defensible per-position rationale.
- Cluster on repeated letters in K4 (e.g. all the K's) without a separate motivation — that's a different campaign.
- Pick numerologically pleasing patterns (every 7th, primes, Fibonacci) — those are number-theoretic skip-rules and belong in a separate campaign.

If you can't write the per-position rationale without referencing K4's content, you're reverse-engineering.

---

## 2. What "transcription-ambiguous" actually means

The motivating prior is: **the carved stone is what was photographed and transcribed; the encrypted output is what Sanborn intended**. If these differ at some positions due to a noisy transcription/carving process, then small-Hamming corrections to the carved CT might recover the intended CT.

Categories that qualify:

1. **Carved-letter visual ambiguity.** Letters with carved shapes that could plausibly be misread. The carved K4 is uppercase Roman serifs (likely; verify from photos). High-ambiguity pairs:
   - **E ↔ F** (missing bottom horizontal stroke)
   - **O ↔ Q ↔ G ↔ C** (tail, curl, opening)
   - **B ↔ P** (missing bottom loop)
   - **I ↔ J ↔ L** (vertical stem, hook, base)
   - **U ↔ V ↔ Y** (rounded base, angular base, extension)
   - **N ↔ H ↔ M** (cross-stroke, double stems)
   - **D ↔ O ↔ Q** (vertical stem)
   - **R ↔ B ↔ P** (loop with leg)
   - **S ↔ Z** (curvature)
   - **W ↔ M** (inversion)

2. **Patina occlusion.** Sanborn's care instructions MANDATE maintaining the copper patina (per `reference/Kryptos Care Instructions and other artifacts.pdf`). Positions where patina growth occludes the cut may have been misread. Identify per-photograph.

3. **Photographic distortion.** Perspective parallax (positions photographed at extreme angles), glare on the metal at oblique sun angles, shadow occlusion. Cross-reference multiple photographers.

4. **Stencil-fabrication anomalies.** Per AAA finding #16 (IMG_1219), Sanborn ordered custom letter stencils. If a stencil had a minor irregularity (worn edge, slight asymmetry), the resulting cut differs from the platonic letter shape.

5. **Chisel-error positions.** Cuts that show non-uniform depth, partial recuts, or burnishing artifacts from corrections.

6. **Chart-vs-stone divergence.** Positions where independent transcriptions disagree:
   - Elonka Dunin's canonical web transcription
   - The 1990 NYT chart (Sanborn's original publication — note: K4 chart is sealed until 2075 per `coding_chart_sealed.md`; what's available is the K4 transcription, not the encryption chart)
   - NSA-cited transcription
   - Carter book's representation
   - Sanborn's own working notes (AAA archive)

7. **Boundary positions** (0 and 96). First/last letter of K4 — stencil alignment has no neighboring letter to anchor against, so position is acceptable as a structural-ambiguity candidate.

8. **Adjacent-letter-blur positions.** Where two adjacent cuts are close enough that the dividing edge is ambiguous. Identify per-photograph.

---

## 3. Evidence quality tiers

Use this to rank candidate positions:

| Tier | Evidence type | Defensibility |
|------|---|---|
| **1** | Independent multi-photographer corroboration (same anomaly visible across multiple photographers, years, lighting conditions) | Strongest — survives Stage A's standard for cross-source persistence |
| **2** | AAA archive direct evidence (Sanborn's own notes show concern about a position) | Strong — primary-source authorial |
| **3** | Single high-resolution photograph showing a physical anomaly | Moderate — could be photographic artifact |
| **4** | Chart-vs-stone divergence with both sources reasonably authoritative | Moderate — requires both sources be vetted |
| **5** | Pattern-completion / "this looks ambiguous" | **Weak — flag and exclude unless backed by tier 1-4 evidence** |

The §13.1 "why is this A" paragraph must cite the tier per position.

---

## 4. Working procedure

### 4.1 Inventory pass (corpus-scale)

Use `kryptos-corpus-forensics` agent to sweep:

- AAA archive images (`reference/Pictures/Arichives of American Art/`, ~532 photos from 2026-03-27 visit)
- Direct sculpture photographs (cross-reference what's in `reference/Pictures/`)
- Chart scans (the 1990 NYT chart appearances)

Trigger phrase: "sweep the Kryptos photo corpus."

Goal: produce a corpus-level manifest of anomalies that persist across independent photographers. This is your tier-1 evidence base.

### 4.2 Per-photograph deep read (single-image forensic)

Use `forensic-photo-analyst` agent for any anomaly that survives corpus-scale persistence. This produces tier-2/tier-3 evidence with specific image hashes.

For each candidate position:
1. Identify the carved character
2. Identify the photograph(s) where the anomaly is visible
3. Get the SHA-256 hash of each photograph
4. Write a one-line rationale: "Position p: photograph IMG_NNNN shows X feature that is consistent with Y carving/patina/transcription anomaly"

### 4.3 AAA archive cross-reference

Read `archive_aaa_findings.md` (memory) for known AAA evidence. Items 1-16 from the 2026-03-27 visit are cataloged. Look specifically for:

- Sanborn's own marginalia or working notes about specific carved positions
- The "He lied" pattern (K2 coordinate manipulation) — methodological precedent, not K4 evidence directly
- Stencil-fabrication notes (IMG_1219)
- Any cipher-types-Sanborn-knew-about that suggest carving was deliberate (CIA Kubark glossary, IMG_1571)

Note that the AAA findings are NOT a direct K4-position list. They're authorial context. You'll need to interpret what's actionable.

### 4.4 Transcription cross-reference

Compare independent transcriptions character-by-character at all 97 positions:

- Elonka Dunin (`elonka.com/kryptos/`)
- Carter book representation
- NSA-cited K4 text
- Sanborn's working notes (AAA)

Any position where two independent transcriptions disagree is a candidate. Cite both transcriptions and the disagreement.

### 4.5 Filtering pass

You'll likely emerge with 15-40 candidate positions. Filter down to k ≤ 15 (prereg recommends k ≤ 20 default, but 15 keeps Bonferroni manageable: at k=15 the universe is 65,625 H2 variants × 4,314 configs ≈ 283M total configs).

Filter criteria:
- Drop tier-5 ("looks ambiguous") entries
- Keep tier-1 entries (multi-photographer corroboration)
- Keep tier-2 entries with explicit AAA citation
- For tier-3 (single-photograph): keep only if the anomaly is morphologically specific (not just "fuzzy in this picture")
- For tier-4 (chart-vs-stone): keep only if both sources are vetted authorities

### 4.6 Write the §13.2 "what was considered and excluded" list

For each candidate that almost made the cut, document why it didn't. Two-line entry per excluded position. This protects against retroactive set widening: if Stage B returns null, you have a record of what you considered, so you can't quietly add positions and re-run.

Recommend keeping this in a separate file (not in the JSON manifest): `decision_gate_excluded.md` alongside the run.

### 4.7 Write the §13 decision-gate document

Three required answers:

1. **Why this A?** (one paragraph; cite per-position evidence at the tier level)
2. **What was considered and excluded?** (list with rationales)
3. **What would change my mind?** (one sentence — be specific. "If I find that position p shows a chart-vs-stone divergence I missed, I'll add it" is acceptable. "If I find anything that looks ambiguous" is not.)

Commit this document to the run directory as `decision_gate.md` before launching.

---

## 5. The manifest schema

Final JSON must match this shape (prereg §3.2):

```json
{
  "schema_version": "ct_perturbation_stage_b.ambiguous_positions.v1",
  "archive_provenance": {
    "primary_source": "AAA, Sanborn, box X folder Y, image IMG_NNNN; cross-referenced against IMG_M, IMG_O",
    "image_hashes": [
      "sha256:abc123...",
      "sha256:def456..."
    ],
    "evaluator": "Colin Patrick",
    "evaluation_date": "YYYY-MM-DD",
    "method": "Manual visual review of [N] independent photographs against carved CT and chart transcriptions; cross-source persistence threshold [criterion]"
  },
  "positions": [3, 50, 95, ...],
  "rationale_per_position": {
    "3": "Tier-1: position visible in IMG_1234, IMG_5678, IMG_9012; consistent oblong distortion at carved 'O' is morphologically distinct from neighboring 'O' at position 12; suggests stencil irregularity or patina growth occluding upper-right curl.",
    "50": "Tier-2: AAA archive IMG_NNNN shows Sanborn's working notes ... [specific authorial citation]",
    "95": "Tier-3: IMG_QQQQ shows ..."
  },
  "checksum": {
    "sha256_of_positions_sorted": "<computed at write time>"
  }
}
```

Use `kryptosbot.ct_perturbation._sha256_of_positions(positions)` to compute the checksum.

The loader validates schema, position ranges, uniqueness, and checksum. Test with:

```bash
PYTHONPATH=src python3 -c "
from kryptosbot.ct_perturbation import load_ambiguous_positions
m = load_ambiguous_positions('path/to/your/manifest.json')
print(f'OK: k={m.k}, positions={sorted(m.positions)}')
"
```

---

## 6. Statistical implications of k

Bonferroni correction grows monotonically:

| k | Position pairs | H2 variants | Total configs | Bonferroni factor |
|---|---|---|---|---|
| 5 | 10 | 6,250 | 26,962,500 | ~2.7e7 |
| 10 | 45 | 28,125 | 121,331,250 | ~1.2e8 |
| 15 | 105 | 65,625 | 283,143,750 | ~2.8e8 |
| 20 | 190 | 118,750 | 512,381,250 | ~5.1e8 |

A finding with raw p = 10^-10 at k=5 reaches adjusted p ≈ 2.7e-3 (significant at α=0.01). The same finding at k=20 reaches adjusted p ≈ 5.1e-2 (NOT significant at α=0.01). Bigger A = harder to detect signal.

This is a direct argument for picking a tight A. The prereg's k ≤ 20 default is generous; **k=5-10 with strong tier-1/tier-2 evidence is the sweet spot.**

---

## 7. Anti-patterns from prior project work

Specifically banned by your feedback memory or this campaign's prereg:

- **No Sanborn-self-reference keywords** (`feedback_k4_keywords_must_fit_public_art_context.md`). This applies to the KEYWORD pool, not the ambiguous-positions set, but a parallel discipline applies: don't pick positions because they "feel meaningful" without external evidence.
- **No archive-OCR phantoms** (`feedback_archive_col_notation_is_ocr_phantom.md`). The "4, 8, 10, 26 = Col" notation was an OCR misread; don't theorize on archive OCR output without verifying the source.
- **No retroactive set widening** (prereg §3.1, §13). Once you launch, A is frozen. If null result, you may pursue Stage B' (different A), not re-run Stage B with an expanded A.
- **No adaptive selection based on Stage A scores** (prereg §2). Stage A was a different campaign; using its candidate scores to motivate Stage B positions is a multiplicity-correction violation.
- **No motivated subset elevation** (`feedback_two_tier_preregistration.md`). If you have a primary list (tier 1-2) and a secondary list (tier 3-4), preregister both as separate campaigns with appropriate alert bars — don't launder the secondary as primary.

---

## 8. Synthetic recovery test with your real manifest

Before launching `--execute-full`, run the synthetic-recovery test:

```bash
PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_b.py \
    --ambiguous-positions path/to/your/manifest.json \
    --synthetic-recovery-test
```

The recovery test injects synthetic corruption at known positions and verifies the harness finds it. It does NOT use your manifest's positions for the corruption (it uses fixed crib positions internally), but it does validate that your manifest LOADS and the runner can launch.

If this fails, fix the manifest before proceeding.

---

## 9. Smoke run before full launch

After the synthetic-recovery test passes, do a smoke run with small caps:

```bash
PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_b.py \
    --ambiguous-positions path/to/your/manifest.json \
    --execute-full \
    --max-h2-variants 5 \
    --keyword-count 3 \
    --keyword-limit 3 \
    --artifact-root /tmp/stage_b_pre_launch \
    --run-id smoke_pre_launch
```

Expected:
- Exit 0
- `summary.json` shows `status: "completed"` (or `"incomplete"` if caps truncated)
- 5 H2 variants × 3 families × 2 alphabets × 3 keywords = 90 configs evaluated
- `ambiguous_positions_manifest.json` and `universe_manifest.json` written
- No alerts (smoke caps unlikely to find signal)

If anything fails, debug before launching at scale.

---

## 10. Full launch checklist

Final pre-launch state:

- [ ] Manifest JSON loads cleanly via `load_ambiguous_positions`
- [ ] All cited images have computed SHA-256 hashes in `archive_provenance.image_hashes`
- [ ] Every position has a per-position rationale citing tier and source
- [ ] Decision-gate document written and committed to the run directory
- [ ] §13.2 "considered and excluded" list complete
- [ ] §13.3 "what would change my mind" sentence is specific
- [ ] Null cache is fresh (`null_baselines/manifest.json` `kernel_commit_at_latest_write` matches current HEAD)
- [ ] Synthetic-recovery test passes with your manifest
- [ ] Smoke run with `--max-h2-variants 5` produces all expected artifacts
- [ ] You have a `git log` checkpoint so the run is reproducible against a known kernel state

Then:

```bash
PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_b.py \
    --ambiguous-positions path/to/manifest.json \
    --execute-full \
    --workers 26 \
    --artifact-root results/ct_perturbation_stage_b \
    --run-id $(date -u +%Y%m%dT%H%M%SZ)_archive_anchored
```

(28 vCPUs; leave 2 for headroom.)

Expected wall time depends on k. At k=10, 121M configs at typical per-config speeds (~1e4/sec single-process, 28x speedup imperfect) is ~1-2 hours.

---

## 11. After the run

Per prereg §10, the negative-claim wording is binding. If no alert fires:

> "Under the operator-predeclared archive-anchored ambiguous-position set A = {…} (provenance: …), no candidate survived the preregistered Stage B alert bar across Hamming-2 substitutions within A × {Vigenère, Beaufort, Variant Beaufort} × {AZ, KA} × the curated keyword pool × the specified CT-parametric scoring and null model."

That's the ONLY claim a null result supports. Do NOT generalize to "Hamming≤2 correction does not unlock K4" — Stage B is constrained to A.

If an alert fires: pause before celebration. Run red-team-disprover on the alert. A 24/24 + bean_passed result in a 283M-config universe must survive multiplicity correction AND adversarial review before becoming canonical.

---

## 12. The one paragraph version

If you only remember one thing: **the manifest is a commitment, not an exploration**. Pick positions based on independent evidence that exists BEFORE you imagine what corrections at those positions would produce. Write down what evidence would change your mind. Stop when you have 5-10 strong positions, not when you've collected enough to feel comfortable.

The prereg's `decision_gate.md` is the discipline mechanism. Use it.
