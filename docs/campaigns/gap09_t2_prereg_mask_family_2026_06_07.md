# Pre-registration — GAP-09 T2 candidate null-mask family (frozen before observable)

**Date:** 2026-06-07
**Author:** autonomous `/goal` session (Claude Code)
**Status:** PRE-REGISTERED + adversarially reviewed (4-agent red-team, NEEDS_FIX → fixed). Frozen + hashed BEFORE any GAP-09 observable is acquired.
**Spec:** `docs/REAL_K4_GAP09_ACQUISITION_SPEC_2026_05_29.md` (closure test T2)
**Protocol:** `docs/REAL_K4_O1_ACQUISITION_PROTOCOL_2026_05_29.md` (the O1 observable)
**Generator:** `scripts/campaigns/gap09_t2_prereg_mask_family_2026_06_07.py` (committed — this doc is the in-git freeze record)
**Frozen artifact:** `results/gap09_t2_prereg/gap09_t2_prereg_mask_family.json` (gitignored; reproducible from the committed generator)
**Regression guard:** `tests/test_gap09_t2_prereg.py` (committed)

This is the one in-repo prerequisite for the project's highest-residual acquisition
lead (GAP-09/O1). It locks the candidate masks, per-rule null model, test
parameters, threshold, multiplicity, observable definition, and the side-effect
predicate so that when an independent observable `O1` is acquired, the co-location
test is a single push-button call with **no post-hoc tuning of mask, δ, observable,
or null family**.

## 0. Freeze integrity (the in-git record)

The freeze is anchored in **git-tracked** objects (the generator + this doc + the
test), not in the gitignored `results/` artifact. The full 64-hex hashes below are
the immutable record; `--verify` (and the closure path) recompute a fresh re-freeze
and **refuse to run** unless the on-disk artifact reproduces `prereg_sha256`, so a
post-O1 edit of the generator cannot be laundered.

| Object | Full SHA-256 |
|---|---|
| `rule_set_sha256` (== pathway-2) | `931ed3db1b86093971a5ba7ce4dba00b71e877207fe2fb24f2c1f8bcfdd7a32b` |
| `mask_universe_hash` | `99664737b36c3ef905413b6e39f4af1b09d2f0b545c7f586c30b19362d7c43f9` |
| `prereg_sha256` (covers masks + null families + params + rules + locks) | `a353780bdd8e2b46d91f95e72117ae58c13acc9ea0dc26517283d672f6aa99bc` |

## 1. Frozen parameters

| | |
|---|---|
| Candidate masks | **15** admissible score-free masks (pathway-2 R1–R5, crib-filtered): **13 R3** grid-rows + **1 R2** Polybius band + **1 R5** vowels |
| **Live masks** | **2** (R2, R5). See §3 — the 13 R3 masks are co-location-INERT. |
| Tolerance δ | **0** (fixed; any δ>0 requires a NEW pre-registration) |
| Closure gate | **p ≤ 1e-6** (Bonferroni-corrected over the live count) |
| Multiplicity | **Bonferroni over n_live = 2** (inert R3 masks contribute 0 to the family-wise error rate); single observable O1, δ=0 |

The masks are deterministic functions of the **public** CT letters + public grid
geometry — **zero K4-decryption/score input** (score-free; verified by the red-team
to carry no crib-fit/plaintext/keystream/score signal). They do **not** revive the
retired `{B,G,I,K,O,W,Z}` palette / `CONSENSUS_NULL_POSITIONS` (R2's letter band
`{A,B,C,D,E}` shares only the trivial letter B, via an independent alphabet-rank
rule). The family is imported verbatim from pathway-2's `rule_masks()` and the build
**asserts** `rule_set_sha256 == 931ed3db…` (drift-protected).

## 2. Null-model assignment

| Rule | Count | Description | Null model | Why |
|---|---:|---|---|---|
| **R3** | 13 | grid row-take, W∈{7,14}, contiguous W-block | **matched** (`gap09_t2_colocation_p_matched`, family = all **whole crib-free rows** of the same W — the same rule that produced the candidates) | grid rows share quasi-periodic structure with carved line-breaks; the uniform null is **misspecified** here (period-W mask vs period-W breaks fires spuriously). Verified in `tests/test_gap09_colocation.py`. |
| **R2** | 1 | Polybius coordinate band (AZ, row r=0) | **uniform-hypergeometric** (`gap09_t2_colocation_p`) | letter-class mask; scatters w.r.t. line-break geometry → exact hypergeometric is the matched question |
| **R5** | 1 | vowel-class (AEIOU) | **uniform-hypergeometric** | same as R2 |

R1 (doubled-letter) and R4 (every-k-th) produced **no admissible masks** — every
such mask intersects a crib (cribs 21-33 / 63-73 cannot be nulls).

**Caveat (R2/R5):** the uniform-hypergeometric null assumes O1 line-breaks are
independent of CT letter content. If a future O1 is found correlated with letter
classes, the same matched-null discipline must be applied (a new pre-registration).

## 3. The 13 R3 masks are co-location-INERT (disclosed)

[INTERNAL RESULT] All 13 R3 grid-row masks are **mathematically incapable** of ever
clearing the gate, for ANY observable: their matched-null Phipson-Smyth floor is
`1/(1+|family|)` with `|family|` ∈ {≈5 (W=14), ≈10 (W=7)} → a p-floor of
**0.09–0.17**, Bonferroni-pinned to 1.0 — orders of magnitude above 1e-6. (This is
the matched null behaving correctly, not a bug: a grid mask aligning with grid
line-breaks is shared structure, not signal.) There is also a **region-vs-boundary
category mismatch**: R3 masks are contiguous row-CONTENT blocks while O1 is row-START
landmarks, so their co-location count is ~0–2 by construction.

Therefore the 13 R3 masks are pre-registered **only as a documented co-location-inert
negative**. The **effective live family is 2** (R2, R5), and the multiplicity is
Bonferroni over those 2. The R3 masks are retained (not deleted) so the negative is
explicit and the family stays hash-identical to pathway-2.

## 4. Side-effect predicate (mandatory 2nd gate) — frozen UNMET, config pinned

Beyond crib score: Bean reduction at non-null positions OR an n-gram floor pass on
the null-extracted CT73 plaintext. This is **mask-intrinsic** (independent of O) and
its computation is **pinned** (`side_effect_t3_config`): pathway-2's
`run_guarded_mask_search`, periods 1..12, `max_free_exhaustive=3`, AZ, default
variants, `calibrated_ngram_floor` via `select_solves`. **Frozen result: T3 = 0** —
no candidate yields a crib-consistent, Bean-valid forced key above the ngram floor on
CT73 (recompute: `scripts/campaigns/gap09_null_mask_pathway2_2026_05_27.py`).

**Consequence (honest):** this pre-registration's closure script can emit **at most
`COLOCATION_BUT_SIDE_EFFECT_UNMET`** — `GAP09_ANCHORED` is unreachable from it.
Anchoring GAP-09 requires a **separate** pre-registration that recomputes **and
hashes** a passing side-effect predicate (i.e., a new CT73 cipher hypothesis). The
pinned T3 config prevents the predicate from being silently loosened to flip the
status. The decision rule remains: anchor iff `(live mask AND Bonferroni p ≤ 1e-6)
AND side-effect met`.

## 5. Observable lock (one observable, one segmentation)

This pre-registration covers **O1 only**, under a single deterministic segmentation:
> O1 = the K4 character index (0–96) that BEGINS each carved physical row of the K4
> panel; row-start = leftmost glyph of each carved line, glyphs counted L→R, top→
> bottom; **ordinal only** (no metric flattening of the S-curved copper). δ=0.

Testing these masks against **O2–O5** or any **alternative segmentation** is a
SEPARATE pre-registration (new `prereg_sha256`) and is **not** covered by this
multiplicity budget — closing the cross-observable escape hatch.

**Acquisition admissibility (human step, GAP-09 spec §3):** before `run_closure`,
the observable must be certified **I1** score-blind, **I2** not a K4-internal CT
statistic, **I3** frozen before the test, **I4** cross-source persistent (≥2
independent primary sources). The code cannot verify provenance. None exists in-repo
(acquisition-gated; spec §5–6).

## 6. Honest expectation

This pre-registration makes the GAP-09 co-location test *executable and tamper-evident*,
not *closeable*. Three brakes are documented up front: (a) only **2** masks are live
(13 R3 are inert); (b) the **matched null** correctly refuses to call grid/line-break
shared structure signal; (c) the **side-effect predicate is unmet for all candidates**.
A documented NEGATIVE (`p>1e-6`, or co-location without a side-effect) is the modal
outcome and is itself a real, scoped result: the leading layout observable does not
anchor a score-free stego mask. This does not pretend a co-location alone solves K4.

## 7. Commands

```
# Freeze + write artifact (deterministic; asserts family == pathway-2):
PYTHONPATH=src python3 scripts/campaigns/gap09_t2_prereg_mask_family_2026_06_07.py
# Tamper-evidence check (on-disk artifact == fresh re-freeze):
PYTHONPATH=src python3 scripts/campaigns/gap09_t2_prereg_mask_family_2026_06_07.py --verify
# Self-test the locked closure (no real O1 needed):
PYTHONPATH=src python3 scripts/campaigns/gap09_t2_prereg_mask_family_2026_06_07.py --selftest
# Run the closure when a real O1 arrives (verifies the freeze first):
PYTHONPATH=src python3 scripts/campaigns/gap09_t2_prereg_mask_family_2026_06_07.py \
  --observable path/to/o1_row_start_indices.json
```
