# Crib-Mapping Break — Campaign Plan

**Status:** PLAN — no implementation yet
**Author:** Colin Patrick + Claude (KryptosBot)
**Date authored:** 2026-05-02
**Predecessor:** TABP v1/v2/v3 (closed 2026-04-09, results in
`results/f_tabp_transposition_outer_v1.md` and
`results/tabp_series_summary.md`)

---

## 1. The hard blocker this addresses

`MEMORY.md` §2 Hard Blocker #3:

> **Crib-mapping assumption.** All Tier 1 / Tier 2 eliminations assume
> direct positional correspondence `CT[i] → PT[i]` on the carved CT.
> Anything that breaks that assumption — outer transposition before the
> analyzed layers, a position-dependent selector, a physical-overlay
> remap — is **partially** explored as of 2026-04-09.

This is the structurally weakest link in the elimination ledger. If the
crib-mapping assumption is wrong, much of Tier 1/Tier 2 is reopened.

---

## 2. What TABP v1/v2/v3 actually tested (closed)

The TABP encryption model `CT = substitute(transpose(PT), key)` was
exhaustively tested over:

| Variant | Alphabet | Trans layers | Periods | Configs | Best ngram |
|---|---|---|---|---|---|
| v1 | AZ | single (6,165 Ts) | 1–26 | ~2.4M | -5.953 |
| v2a | KA | single (6,165 Ts) | 1–26 | ~2.4M | -5.904 |
| v2b | AZ | double (252,840 Ts) | 1–26 | ~98M | -6.012 |
| v2c | KA | double (252,840 Ts) | 1–26 | ~98M | -6.046 |
| v3 | AZ | single | 27–50 (extended) | ~2K | -5.581 (NS Bonferroni) |

Reference: English prose ≈ -4.96, random 97-char ≈ -6.39. **All
variants clean null after multiplicity correction.**

Outer-transposition + periodic additive substitution + AZ/KA alphabet
× single + double layer transposition is **closed**. The TABP v3 result
(-5.581 over 35-char subset) was specifically tested for the Bonferroni
multiplicity question and came out non-significant (expected 0.08 false
positives at this level over ~2000 tests, observed 1).

---

## 3. What remains untested (the search frontier)

### 3.1 Three-layer outer transposition (extension of v2b/v2c)

Cardinality ~67B composed Ts (252,840²); too large for full sweep at
fixed alert bar, but a structured subset (predeclared classes of
composition, e.g., "two columnar then one route") is feasible.

**Estimated compute:** ~10-20 hours at 26 workers for a class-restricted
sweep at periods 1-26.

**Justification for testing:** TABP v2 saw 4-orders-of-magnitude
improvement in ngram from v1 to v2 (none — both ~-6.0). If the
encryption used three transposition layers, v2 would have failed. The
prior is weak; this is closing a documented gap, not chasing a hot lead.

### 3.2 Non-additive inner cipher under outer transposition (TABP-NA)

TABP tested only `additive(transpose(PT), key)`. Untested under the
TABP encryption model:

- **Porta inner.** 13 reciprocal pair-alphabets × period × outer T.
  Finite keyspace; tractable.
- **Quagmire III/IV inner.** Substantial keyspace but bounded by
  alphabet enumeration; tractable for keyword-pool inner key.
- **Beaufort variant inner with non-AZ/KA mixed alphabet.** Mixed
  alphabets generated from a curated keyword pool (k1-k3 vocabulary).

**Estimated compute:**
- Porta inner: ~5h at 26 workers (small inner keyspace × 6,165 outer Ts × period 1-26)
- Quagmire III/IV inner: ~10-20h at 26 workers (depends on keyword pool size)
- Mixed-alphabet Beaufort variant: ~5-10h at 26 workers

**Justification:** the TABP closure is binding for additive inner only.
A non-additive inner under outer T is structurally distinct — Bean
constraints don't apply the same way (the inner cipher is non-key-
recoverable from positional cribs in the same form), so the elimination
chain breaks earlier.

### 3.3 Grille/selector outer layer (not transposition)

A **grille** is a positional mask that selects a subset of positions
from a larger written-out form, possibly with rotation. Grilles are
not transpositions in the matrix sense — they are subset selections
followed by ordered readout.

Testable subclasses:

- **Cardano grille.** Fixed mask + rotation (4 orientations). Sweep
  over predeclared grille shapes and rotations. Cardinality bounded by
  `|grilles| × 4 × inner cipher`.
- **Turning grille.** k × k square with 1/4 of cells punched, applied
  in 4 rotations. Sweep over square sizes (4, 6, 8, 10, 12) and punch
  patterns from a generator.
- **Custom selector**: position-dependent inclusion rule (e.g., "include
  position iff `f(i) > threshold`"). Out of scope without a defensible
  prior — too large.

**Estimated compute:**
- Cardano: ~10h at 26 workers (depends on grille pool)
- Turning: ~20h at 26 workers (combinatorial grille generation)

**Justification:** grilles are the most plausible "physical overlay"
mechanism for K4 — they have direct historical precedent, small
keyspace, and are exactly the kind of mechanism Sanborn could have
specified procedurally. The escape-room-cryptanalyst persona surfaces
this regularly.

**Framework cost:** new generator code for Cardano + turning grille
masks. ~1 day of engineering. Existing dispatcher (per Codex's
audit, handles arbitrary-length challenges via `challenge_ciphertext` +
`challenge_crib_dict`) covers the eval primitive.

### 3.4 Position-dependent selector (mod-N)

A modular rule that selects position-class-dependent treatment, e.g.,
"positions where `i mod 7 ∈ {0, 1, 2}` are CT, others are PT/null."

The retired-palette family was a special case of this pattern. With
palette retired, the **mod-rule selector itself** has not been
systematically tested as a non-palette mechanism.

**Estimated compute:** ~5h at 26 workers for mod-N with N ≤ 24 and
inclusion-set sizes ≤ N/2.

**Justification:** weak prior. Worth testing only because the search is
small and would close a class of "obvious in retrospect" mechanisms.
Statistical-auditor red-team caveats: any positive must survive
correction across (a) modulus choice, (b) inclusion pattern choice,
(c) inner cipher class. Burden is high; the prior is low.

### 3.5 KA outer transposition single-layer (gap from v2a vs v2c)

v2a tested AZ outer single-layer; v2c tested KA outer double-layer.
**KA outer single-layer was not tested.** Cardinality ~2.4M configs at
26 workers ≈ 10 minutes. Discrete gap.

**Justification:** completeness; closes a documented hole.

---

## 4. Recommended attack order (priority)

| Priority | Section | Estimated time | Justification |
|---|---|---|---|
| 1 | §3.5 KA single-layer | ~10 min | Smallest, closes a documented gap, no new framework |
| 2 | §3.2 Porta inner under outer T | ~5h | Bounded keyspace, structurally distinct from TABP closure |
| 3 | §3.3 Cardano grille outer | ~10h + 1d eng | Most plausible physical-overlay mechanism, well-defined keyspace |
| 4 | §3.2 Quagmire III/IV inner | ~10-20h | Extends Porta result if positive; orthogonal closure if negative |
| 5 | §3.3 Turning grille outer | ~20h + eng | Grille generalization; only run if Cardano shows nothing |
| 6 | §3.1 Three-layer outer T | ~10-20h | Largest cardinality; only after smaller probes settle |
| 7 | §3.4 Mod-N selector | ~5h | Weak prior, narrow gain |

**Stop conditions:**

- A `crib_score == 24` AND `bean_passed` AND `ngram_score >= -3.5`
  AND `p_adjusted <= 0.01` candidate fires → halt + red-team-disprover
  pass before any further compute on this campaign.
- All seven priority items returned clean null → publish a "crib-
  mapping-break v2" exhaustion certificate that explicitly retains the
  "outer might still be procedural / chart-based / external-anchor" caveat.

---

## 5. What this plan deliberately excludes

- **Running-key under any of the above.** Stage A/B exclusion list
  applies; running-key requires CorpusLicense and is structurally
  disfavored per `C-RUNKEY-01`.
- **Non-English source text.** Same exclusion.
- **Procedural / chart-based mechanisms.** Stage C territory; needs
  `CipherProcedureLicense` schema + separate prereg.
- **Infinite-keyspace selectors.** "Position-dependent rule of arbitrary
  form" is undefendable under any multiplicity correction. Mod-N with
  bounded `N` (§3.4) is the only acceptable selector subclass.

---

## 6. Synthetic recovery test (mandatory before each priority item)

Each priority item runs a planted-correction recovery test before
`--execute-full`:

1. Build synthetic plaintext with K4 cribs at canonical positions.
2. Apply the candidate outer mechanism (selected from the priority
   item's class).
3. Apply a known inner cipher at known key.
4. Corrupt the result if needed to exercise CT-perturbation paths.
5. Verify the harness recovers the planted (outer + inner + key) tuple
   with full crib match and Bean pass.

This is the load-bearing assertion: if the harness can't recover a
planted answer in its own search class, no negative result on K4 is
defensible.

---

## 7. Adversarial review before launch

Per `feedback_red_team_before_swings.md` and `C-RED-01`: any priority
item with estimated compute ≥ $25 (≈ Priority 2 onwards) must be
red-teamed by `red-team-disprover` before launching. The red-team
question is: **"What's the strongest reason this priority item will
produce noise indistinguishable from real signal?"**

Specifically:

- Priority 2 (Porta inner): does the recovered keystream-at-cribs
  feasibility constraint apply the same way? If not, the elimination
  semantics differ from TABP and Bean's role is unclear.
- Priority 3 (Cardano grille outer): grille generation has multiplicity
  burden; how is the outer-grille-pool chosen and committed to before
  results land?
- Priority 4 (Quagmire III/IV inner): keyword pool selection is the
  multiplicity hazard — what's the predeclared pool?
- Priority 6 (three-layer outer T): which composition classes are
  predeclared as the search subset?

Each priority item must have its own short prereg before launch
(template: §3 "scope boundary" + §5 "null and p-value policy" +
§6 "alert vs watchlist policy" from Stage A's prereg).

---

## 8. Relationship to Stage A/B

Stages A and B operate on the **canonical 97-char carved CT** under the
direct positional crib mapping. The crib-mapping-break campaign is
**orthogonal**: it tests whether the carved CT might come from a
different encryption model that breaks the direct positional
correspondence.

Both can be pursued in parallel without contention. A negative on Stage
A/B does not weaken the crib-mapping-break prior; a negative on the
crib-mapping-break campaign does not weaken Stage A/B.

A positive on either is independently load-bearing.

---

## 9. Engineering scope estimate (one-time)

Before any priority item runs:

| Item | Time | Notes |
|---|---|---|
| Cardano grille generator + tests | 1d | Borrow from `cipher-discovery` corpus if present |
| Turning grille generator + tests | 1.5d | More careful combinatorics |
| Porta inner adapter for TABP harness | 0.5d | Plug into existing TABP scaffolding |
| Quagmire III/IV inner adapter | 0.5d | Plug into existing TABP scaffolding |
| Mod-N selector primitive + tests | 0.5d | Well-bounded, no new framework |

**Total framework cost before any compute:** 4 days engineering. Most
costs are amortized — once Cardano/turning grilles exist, they unlock
multiple priority items.

---

## 10. Decision before any priority item launches

The operator should answer in writing:

1. **Have I read the TABP closure docs?** (`results/f_tabp_transposition_outer_v1.md`, `results/tabp_series_summary.md`)
2. **Why this priority item, in this order?**
3. **What's the predeclared search subset for this priority item?**
   (e.g., for §3.3 Cardano: which grille pool? for §3.6 three-layer:
   which composition classes?)
4. **What's the alert bar and Bonferroni-adjusted threshold?**
5. **What would I do if it returns clean null?** (Move to next priority?
   Stop the campaign? Pivot to Stage A/B?)

The decision document lives at
`docs/campaigns/crib_mapping_break_decision_<priority>_<date>.md`
and is committed before launch.

---

*Last updated 2026-05-02. Plan only; no implementation. Priority 1
(KA single-layer) is the smallest gap and the natural first move
once an operator decision-gate is on file.*
