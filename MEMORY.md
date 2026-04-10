# MEMORY.md — Live Control Document

**This file is volatile live state only.** For derived state (eliminations,
exhaustion, anomalies) run the session briefing:
```bash
PYTHONPATH=src python3 scripts/_infra/session_briefing.py
```
For structured claims see `docs/claims_registry.json`. For open epistemic
audits see `docs/methodological_audits.md`. For the canonical entry index
see `docs/README_current_state.md`. For historical strategy snapshots see
`docs/history/`. For retired research notes see `memory/retired/`.

---

## 1. Current Project State (2026-04-10)

- **No credible decrypt path.** All positive findings are descriptive
  anomalies, not solution candidates. (registry: `C-STATE-01`)
- **Bean linear constraints added (2026-04-10):** 101 Groebner-derived
  4-position linear constraints (`BEAN_LINEAR` in `constants.py`). Combined
  with pairwise eq+ineq, exactly **624 valid keystreams** at the 24 crib
  positions under any additive cipher variant. All prior eliminations
  strictly strengthened; no new signal opened. Bean's "mod-5 test" (13/24,
  p~1/1468 under reversed-KA) demoted to structural artifact of crib
  placement, not a cipher signature.
- Single-layer and two-layer classical cipher space systematically tested
  under the direct-positional crib mapping. Three-layer space partially
  explored. (registry: `C-STATE-02`)
- Composition framework v1+v2+v3: 105K+ branches across 37 campaigns,
  max 6/24 = noise. (registry: `C-COMP-01`)
- **TABP series exhausted 2026-04-09**: five campaigns completed
  testing the encryption model `CT = substitute(transpose(PT), key)`
  across (AZ/KA alphabet) × (single/two-layer outer) × (period 1-50).
  All clean null:
  - **v1** (AZ, single-layer, period 1-26): best non-crib ngram = **-5.953**
  - **v2a** (KA, single-layer, period 1-26): best = **-5.904** (best of 5)
  - **v2b** (AZ, two-layer, 252,840 composed Ts, period 1-26): best = **-6.012**
  - **v2c** (KA, two-layer, 252,840 composed Ts, period 1-26): best = **-6.046**
  - **v3** (AZ, extended period 27-50, determined-subset scoring):
    best = **-5.581** (35-char subset), NOT significant after Bonferroni
    correction across ~2000 tests (expected 0.08 false positives at this
    level, observed 1)

  Reference: English prose ≈ -4.96, random 97-char ≈ -6.39. No variant
  rose significantly above noise floor after multiplicity correction.
  Extends `C-BEAN-01` from widths {4,6,8,9} direct-positional to:
  6 new columnar widths, Myszkowski, rail fence, spiral/serpentine
  routes, two-layer compositions thereof, and both alphabets — all
  eliminated under the TABP encryption model. **Partial resolution of
  Hard Blocker #3** (crib-mapping assumption): the outer-transposition-
  at-encryption subcase is now exhausted. Grilles, multi-layer mixed
  families, non-additive inner ciphers, and other crib-mapping-break
  mechanisms remain untested. See
  `results/f_tabp_transposition_outer_v1.md` and
  `results/tabp_series_summary.md`.
- Project is in a **final honest search window** (see
  `docs/exhaustion_audit_2026_04_08.md`), not an active breakthrough hunt.
- Running-key has been **demoted** from a leading hypothesis to a residual
  admissible family for documentation closure only. (registry: `C-RUNKEY-01`)

---

## 2. Hard Blockers

1. **Short-text underdetermination.** 97 characters; surface statistics are
   weak and frequently deceptive.
2. **Multi-layer ambiguity.** Single-layer eliminations do not eliminate
   those families as one layer of a multi-layer construction.
3. **Crib-mapping assumption.** All Tier 1 / Tier 2 eliminations assume
   direct positional correspondence `CT[i] → PT[i]` on the carved CT.
   Anything that breaks that assumption — outer transposition before the
   analyzed layers, a position-dependent selector, a physical-overlay
   remap — is **partially** explored as of 2026-04-09. TABP v1 tested the
   **outer-transposition-at-encryption** variant (one specific mechanism)
   across 6,165 transpositions × periodic Vig/Beau/VarBeau at periods 1-26
   and found clean null. Still unexplored: multi-layer transpositions,
   grille/selector mechanisms, non-periodic inner ciphers under TABP,
   KA-alphabet inner substitution under TABP. See
   `results/f_tabp_transposition_outer_v1.md`. The full assumption is
   stated in `docs/elimination_tiers.md` Tier 1 (AUDIT-1 closed 2026-04-09).
4. **External-information ceiling.** Some avenues require physical,
   chart, or archive evidence (see Bin E below).
5. **Scoring ceiling at n=97.** Quadgram-class scorers provably cannot beat
   FM-1 (Markov-3 adversarial null) at 97 characters. (registry:
   `C-EFRAC54-01`)

---

## 3. Open Methodological Audits

See `docs/methodological_audits.md` for full text. Summary:

- **AUDIT-1** — CLOSED 2026-04-09. "SOURCE-INDEPENDENT" wording in
  Tier 1 columnar rows was scope-corrected to "running-key-source-
  independent within the analyzed cipher class". Registry: `C-BEAN-01`
  (now `live`, narrower scope).
- **AUDIT-2** — CLOSED 2026-04-09. Downstream palette citations banner-
  demoted or tagged retired; session briefing tightened.
- **AUDIT-3** — OPEN (`documentation only`). `BREAKTHROUGH` label
  semantics. Minimal fix pending.

---

## 4. Active Research Bins

### Bin C — Testable now (execute, then stop)

Red-team review (2026-04-08) downgraded C1/C2 from Opus compute to cheap
documentation closure. See `feedback_red_team_before_swings.md`.

1. **C7** — Admissibility backlog cleanup. Review 16 `ASSUMPTION_UNMET`
   running-key scripts; declare source, add license, or archive.
2. **C1/C2** — Carter Vol 1 and Kahn Codebreakers against columnar
   w6/8/9 × 3 variants. **Cheap background compute only**, not Opus budget.
3. **C6** — Non-columnar 3-layer enumeration (route / Myszkowski /
   rail-fence / block as middle layer). Scoring path audited clean
   (commit a72d2e3). Campaign script does **not yet exist** — extend
   `enumerate_stacks` in `composition/orchestrator.py:265` or write a
   custom 3-layer driver. Engineering, not compute.
4. **C3/C4/C5/C8** — Deferred; run only if C6 escalates. Any stateful
   proposal must clear `stateful_attack_requirements.md` first.

**Stop condition:** C7 complete AND C6 campaign written and run AND no
ESCALATED candidate AND C1/C2 closure docs published → publish
`exhaustion_certificate_2026_04_08.md` v2 and transition to waiting-list
phase.

### Bin D — Weakly testable (engineering, not compute)

- **D1 — Mono+Trans+Running-key search:** re-classified 2026-04-09 from
  "engineering blocked" to "structurally blocked on a scorer beating FM-1
  at n=97". See registry `C-EFRAC54-01`. The correct next move is scoring
  research, not search engineering. Do not re-propose the search build
  without (a) a scorer proven to beat FM-1 at n=97, (b) a recovery test
  from random sigma init, or (c) a gradient-above-noise-floor proof.
- Running-key from pre-declared non-English text (needs new
  `CorpusLicense`).
- Berlin Clock / Weltzeituhr time-dependent permutations (needs
  archive-derived clock-state argument).
- Pre-ENE (0–20) as separate sub-cipher (no crib/constraint available).
- Archive-term operationalization (ABSCISSA, ATBASH, "4, 8, 10, 26 = Col")
  — needs a parametric mapping from term to cipher family.

### Bin E — Untestable under current clues (waiting list)

- Bespoke chart-based cipher procedures (needs public chart reproduction
  or a `CipherProcedureLicense` schema).
- Model-free null mask search (no defined statistic; palette version
  retired — see `memory/retired/`).
- K5 ciphertext (not published).
- Circled letters IMG_1223-1235 (needs archive forensic extraction).
- Photogrammetric sculpture data (needs field measurement).
- Sanborn's private coding system (not public).

These are **prerequisites for being able to test anything new**, not
testable hypotheses.

---

## 5. Do-Not-Revive List

Do not re-propose, re-run, or re-cite these without a rehabilitation entry
in `docs/claims_registry.json` and a new audit close.

- The palette family {B,G,I,K,O,W,Z} and all derived null-mask constructs
  (mod-35, BCL enrichment, Polybius row-selection, palette null separator).
  Registry: `C-PALETTE-01` (retired).
- Autokey variants (PT / CT / Quagmire-II) on the carved CT under direct
  positional mapping. Registry: `C-AUTOKEY-01`.
- DEFECTOR / PALIMPSEST 15/24 framings (post-hoc artifacts).
- K2 numeric sequences as keystream.
- Tier C1 Chaocipher-class crib-chain attack (killed 2026-04-08 for
  failing `stateful_attack_requirements.md` conditions 4 and 8).
- E-FRAC-54 quadgram-based search engineering (killed 2026-04-09; see
  `C-EFRAC54-01`).

---

## 6. Discipline Rules

- Any Opus-compute swing estimated ≥$25 must be red-teamed before
  pitching. (registry: `C-RED-01`)
- Any stateful/Chaocipher-class attack must clear
  `stateful_attack_requirements.md` (8 conditions) before compute commit.
- Sanborn quotes are Tier-3 community hearsay, not [PUBLIC FACT].
  (registry: `C-SANBORN-01`)
- Positions are 0-indexed (cribs at 21–33 and 63–73). Import constants;
  never hardcode CT, cribs, or null positions.
- Null positions are model-dependent — always state the model.
- High scores at large periods are false positives. Bean-based
  "source-independent" eliminations in `docs/elimination_tiers.md` Tier 1
  are precisely scoped to running-key source choice within the analyzed
  cipher class (see AUDIT-1, closed) — they do **not** cover composed
  ciphers with an outer layer preceding the analyzed step.

---

## 7. Pointers

- **Canonical entry index:** `docs/README_current_state.md`
- **Structured claims:** `docs/claims_registry.json`
- **Open audits:** `docs/methodological_audits.md`
- **Historical snapshots:** `docs/history/`, `reports/final_synthesis.md`
- **Retired notes:** `memory/retired/`
- **Live research notes (repo `memory/`):** `keystream_forensics_v2.md`,
  `ticom_archive_research.md`, `width10_17_deep_investigation.md`,
  `width21_bigram_73char.md`, `bruteforce_7remaining.md`,
  `keystream_ap_investigation.md`

Last updated: 2026-04-09 (AUDIT-1 + AUDIT-2 closed: Bean-columnar
"source-independent" wording scope-corrected across load-bearing docs;
downstream palette citations banner-demoted or tagged retired; session
briefing now surfaces disputed/retired claim IDs from the registry).
