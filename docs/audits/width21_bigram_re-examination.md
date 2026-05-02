# Width-21 Bigram Anomaly: Re-examination Under Retired Palette

**Date:** 2026-05-02
**Predecessor:** `memory/width21_bigram_73char.md` (2026-03-15)
**Trigger:** Palette family RETIRED 2026-04-01; `CONSENSUS_NULL_POSITIONS`
moved to `kryptos.kernel.retired` (Phase 2, 2026-04-20).

---

## Verdict

**The 2026-03-15 conclusion is conditional on retired hypotheses and
must be retagged.** The width-21 anomaly on the raw 97-char carved CT
remains real (`p ≈ 1.6e-4` over 200K Monte Carlo trials, z=4.48). What
was claimed to be a "stego layer artifact" — that it disappears under
null extraction to CT73 — invoked the now-retired
`CONSENSUS_NULL_POSITIONS` mask, itself derived from the retired
palette `{B, G, I, K, O, W, Z}`.

With both retired, there is no project-defensible CT97→CT73 extraction.
The "stego artifact" framing therefore loses its supporting argument,
and the width-21 anomaly on CT97 is **back to unexplained** — neither
confirmed cipher signature nor confirmed stego artifact.

---

## What the 2026-03-15 analysis showed

| Stratum | Width 21 | MC mean | p(≥) | z |
|---|---:|---:|---:|---:|
| CT97 (raw) | 11 | 3.5 | **1.6e-4** | **4.48** |
| CT73 (palette-extracted) | 3 | 1.7 | 0.247 | 1.04 |
| CT73_COL7 | 2 | 1.7 | 0.540 | 0.22 |

The 2026-03-15 conclusion: width-21 is a stego artifact because
extracting the 17 palette-null positions destroys it.

That conclusion is logically valid **only if** the 17-position
extraction mask is the correct stego mask. It was retired 2026-04-01
because:

- the score-conditioned null test (`docs/a1_score_conditioned_null_report.md`)
  showed simulated annealing produces 11 distinct palettes on K4
  (`p = 0.30` vs shuffled), and
- the palette claim itself is post-hoc position selection (not a
  generative model).

`memory/project_consensus_nulls_epistemic_status_2026_04_14.md`
records the resolution: `CONSENSUS_NULL_POSITIONS` quarantined to
`kryptos.kernel.retired`. Any analysis whose conclusion depends on
that mask now requires an alternative non-palette mask or has its
conclusion downgraded.

---

## What survives, what doesn't

### Survives (independent of palette)

- **CT97 width-21 anomaly itself** (`p ≈ 1.6e-4`, z=4.48). The Monte
  Carlo null was over CT97-letter-multiset shufflings, not over any
  null-extraction step. The statistic stands.
- **CT97 width-7 marginal signal** (`p ≈ 0.036`, z=2.15). Marginal,
  but multiplicity-uncorrected.
- **CT97 width-10 marginal signal** (`p ≈ 0.024`, z=2.37). Same caveat.

### Does NOT survive (palette-dependent)

- "Width-21 is a stego artifact." Lost its supporting argument.
- CT73 width-10 and width-17 anomalies (`p = 0.006` and `p = 0.008`)
  are properties of the **palette-extracted** 73-char stratum. The
  stratum is no longer project-defensible without redefining the
  extraction.
- "Cipher layer has width-10 and width-17 structure" — same caveat.

---

## What this means for next moves

### If width-21 on CT97 is real

It is one of three remaining unexplained statistical anomalies on K4
(per session briefing "SURVIVING ANOMALIES"). The other two — width-10/17
on CT73, Stehle Δ5 — are also conditional or local-descriptive.

The width-21 effect on CT97 is large enough (z=4.48) that **multiplicity
correction across reasonable widths still leaves it real**. Bonferroni
across widths 2–32 (31 widths tested) gives corrected `p ≈ 5e-3` —
still notable.

### If width-21 is meaningful, what mechanism could produce it?

Three classes worth distinguishing:

1. **Cipher signature.** A periodic component at width 21 in the cipher
   itself (e.g., a transposition with column structure repeating at
   period 21, or a polyalphabetic family with period dividing 21).
   Direct test: re-run the existing periodic-poly elimination machinery
   with explicit attention to period-21 structure (Bean impossibility
   under direct positional crib mapping is already established for all
   periods 1–26, so this would have to break the crib mapping — see
   `docs/campaigns/crib_mapping_break_plan.md` §3.5).

2. **Real stego artifact (non-palette mask).** Some other null
   distribution at the carved level produces a width-21 vertical
   signature when written into a 21-column grid. Worth testing only
   against pre-declared non-palette masks; the test of
   "mask the 17 palette positions" cannot rerun under retirement.

3. **Coincidence under multi-anomaly search.** The CT97 statistic is
   one of many tested by Bean and others. The look-elsewhere burden
   has not been formally tracked across his paper's anomaly inventory.

### Recommended action

Three small probes, each ≤ 1 hour:

1. **Verify width-21 on CT97 against current scoring tooling.** Re-run
   `scripts/campaigns/f_width21_bigram_73char_v1.py` with the current
   kernel; confirm `p ≈ 1.6e-4` reproduces. If the legacy script
   imported anything from the retired palette path, replace with a
   palette-free reproduction.

2. **Cross-test width-21 against CT97 written into a 21-column grid
   with each of (3, 7, 11) row offsets** (i.e., non-trivial reading
   orders within a 21-column frame). This is a small, bounded probe
   for "the period-21 structure has a specific positional alignment."
   Two-tailed p-value with full 200K MC trials per offset.

3. **Pre-declare a non-palette null mask candidate set and test
   width-21 under each.** Specifically: random 17-position masks (MC
   over the 13M masks), regular masks (every 6th, every 7th), and
   masks defined by surface features (boundary positions, repeated
   letters) — pre-declared before computing any width-21 statistic on
   their extractions. This is the only way to ask "is width-21 a
   stego artifact" without invoking the retired palette.

If all three probes return clean null on the question they're asking,
write up width-21 as **"unexplained but real CT97-level anomaly,
mechanism unknown after exhaustive predeclared null search."** That is
a defensible parking position; it does not justify any further compute
on the basis of width-21 alone.

---

## Registry / claim implications

- `C-PALETTE-01` (retired). No change.
- New entry recommended: `C-WIDTH21-01 — width-21 bigram anomaly on
  CT97`, status `live` (existence verified), with caveat "stego-vs-cipher
  attribution unresolved after palette retirement."
- `memory/width21_bigram_73char.md` should gain an inline banner:
  *"Conclusion `width-21 is stego artifact` is conditional on the
  retired palette null mask. See
  `docs/audits/width21_bigram_re-examination.md` (2026-05-02) for the
  current attribution status."*

---

*Last updated 2026-05-02. Analysis only; no new compute. The three
recommended probes (§"Recommended action") are operator-launched and
each requires its own short prereg before running.*
