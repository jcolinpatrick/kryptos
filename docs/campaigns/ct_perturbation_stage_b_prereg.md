# CT-Perturbation Stage B — Preregistration

**Campaign id:** `ct_perturbation_stage_b`
**Status:** DRAFT — framework binding; ambiguous-position set TBD by operator before launch
**Author:** Colin Patrick + Claude (KryptosBot)
**Date authored:** 2026-05-02
**Authoritative spec:** this document
**Code:** TBD — `kryptosbot/ct_perturbation.py` extension + `scripts/campaigns/ct_perturbation_stage_b.py`
**Tests:** TBD — `tests/test_ct_perturbation_stage_b.py`
**Predecessor:** `ct_perturbation_stage_a_prereg.md` (Stage A complete, clean negative across 10,465,764 H1 configs)

---

## 1. Motivation (the structural commitment)

Stage A established that **no Hamming-1 single-character substitution of
the 97-character carved K4 ciphertext** unlocks the canonical additive
cipher families × {AZ, KA} × the curated keyword pool under the
preregistered alert bar. Stage B extends the same hypothesis class to
**Hamming-2** *only* in the constrained form motivated by external
archive evidence.

The motivating archival object is the same as Stage A: the 2025–2026
Smithsonian / AAA coding-chart photographs that admit, without proving,
the hypothesis that the carved transcription differs from the encrypted
output in a small number of positions. Stage A swept the entire 97
positions (no archive prior). Stage B narrows the search to position
pairs where the archive evidence shows transcription ambiguity, on the
prior that two-character corruption from a noisy source process should
concentrate in positions the archive flags as visually ambiguous.

This stage is a controlled, defensible, predeclared search — not an
adaptive expansion of Stage A.

---

## 2. Hard scope boundary (binding)

Inherits Stage A §2 verbatim. Reproduced here for binding:

- **Running-key ciphers.** Not implemented, not parameterized, not
  invoked, not documented as a future Stage B path.
- **Non-English source text** of any kind.
- **CorpusLicense** schema work and any path that requires it.
- **Multi-layer compositions.** Single-layer keyed substitution only.
- **Position-dependent selectors, grilles, charts, autokey, Quagmire III,
  stateful families.**
- **Hamming distance > 2.** Stage B does not enumerate H3+.
- **Adaptive selection of ambiguous positions based on Stage A
  candidate scores.** This is a multiplicity-correction violation and
  is forbidden.

The runtime contract is enforced at the test level
(`tests/test_ct_perturbation_stage_b.py::TestScopeExclusion`) with the
same assertions as Stage A plus:

- `SUPPORTED_HAMMING_DISTANCES = {2}` (no H1, no H3).
- The campaign module reads its ambiguous-position set from a
  predeclared input file specified by `--ambiguous-positions PATH`.
  The file must carry an `archive_provenance` field with a date and a
  pointer to the AAA / Smithsonian source. The runner refuses to launch
  if the provenance field is empty or fails schema validation.

---

## 3. The predeclared ambiguous-position set (operator-supplied)

### 3.1 Definition

The ambiguous-position set `A ⊂ {0, 1, ..., 96}` is the set of carved-CT
positions that the operator has independently judged transcription-
ambiguous from primary archive evidence (visible chart marks, chisel
geometry, photograph parallax, redaction overlays, etc.). The set is
**predeclared in a separate input file** before the runner starts and
**MAY NOT be modified after the campaign launches**.

### 3.2 File schema

The operator provides `--ambiguous-positions PATH` pointing to a JSON
file with this schema:

```json
{
  "schema_version": "ct_perturbation_stage_b.ambiguous_positions.v1",
  "archive_provenance": {
    "primary_source": "AAA, Sanborn, box X folder Y, image IMG_NNNN",
    "image_hashes": ["sha256:..."],
    "evaluator": "Colin Patrick",
    "evaluation_date": "YYYY-MM-DD",
    "method": "manual visual review of chart photographs against carved CT"
  },
  "positions": [<int>, ...],
  "rationale_per_position": {
    "<position>": "<one-line explanation of why this position is flagged>"
  },
  "checksum": {
    "sha256_of_positions_sorted": "<hex>"
  }
}
```

The runner validates schema, ranges (0..96), uniqueness, and checksum.

### 3.3 Cardinality binding

Let `k = |A|`. The Stage B Hamming-2 universe per CT is:

| Quantity | Formula | Example k=5 | Example k=10 |
|---|---|---:|---:|
| Position pairs `(i,j)` with `i<j`, both in `A` | `C(k,2)` | 10 | 45 |
| Substitution pairs (other letter at each) | `25 × 25 = 625` | 6,250 | 28,125 |
| **Hamming-2 variants** | `C(k,2) × 625` | **6,250** | **28,125** |

Total configs: `H2_variants × 3 × 2 × |keywords|` where families and
alphabets are inherited from Stage A. For the 719-keyword curated pool:

| k | H2 variants | Total configs |
|---:|---:|---:|
| 5 | 6,250 | 26,962,500 |
| 10 | 28,125 | 121,331,250 |
| 15 | 65,625 | 283,143,750 |
| 20 | 118,750 | 512,381,250 |

The cardinality is **bounded above by the operator's chosen `k`** —
larger archive evidence sets monotonically increase the search universe.
**The runner refuses to launch when `k > k_max_default = 20`** unless
`--allow-large-ambiguous-set` is passed and a separate review is
documented in the run manifest.

### 3.4 Why both perturbations must be in `A` (not just one)

A "second perturbation in `A`, first perturbation free over 97
positions" reading of Stage A §11 was considered and rejected. Cardinality
under that reading is `2,425 × k × 25 = 60,625k`, which for k=10 is
606,250 H2 variants × 4,314 configs = 2.6B configs — too large to defend
under Bonferroni at the same alert bar as Stage A.

The "both in `A`" reading is defensible because the underlying prior is:
*two-character noise from the chart-to-carving transcription concentrates
in archive-flagged positions*. If only one position is archive-flagged
and the other is anywhere, the prior is incoherent — we are no longer
testing archive-anchored corruption, we are doing unconstrained H2
search with an arbitrary archive prior on a single position.

This is binding. Operators who wish to sweep `(any 97) × A` must author
a separate Stage B' preregistration with a defensible weaker prior and
a tighter alert bar.

---

## 4. CT-parametric scoring policy

Inherits Stage A §4 verbatim. Reproduced as a binding:

- **Crib score:** PT-only via `kryptos.kernel.scoring.crib_score`.
  CT-independent.
- **Bean (CT-parametric):** for each Hamming-2 CT variant, **re-derive**
  eq / ineq / linear constraint sets from the perturbed CT in the
  candidate's alphabet index space using
  `kryptosbot.ct_perturbation.derive_bean_constraints`. The frozen
  kernel sets are reference values for canonical CT only.
- **N-gram (PT-only):** `NgramScorer.score_per_char` over the AZ
  quadgram table. CT-independent.
- **IC:** not used.
- **Position-class effect (Stage B variant):** under H2/direct positional
  crib mapping, the keystream-affecting positions are still the 24 crib
  positions. A Hamming-2 variant changes Bean/crib feasibility iff at
  least one of its two perturbed positions overlaps the crib positions.
  The runner records, per H2 variant, the count `crib_overlapping ∈ {0, 1, 2}`.

---

## 5. Null and p-value policy

Inherits Stage A §5 verbatim with one cardinality update:

- `total_config_cardinality` in the Bonferroni adjustment uses the
  Stage B universe size from §3.3 (computed from operator-supplied `k`),
  **not** Stage A's 10,465,764.
- Reuse the same alphabet-keyed ngram null caches calibrated by
  `scripts/_infra/calibrate_null_baselines.py`. KA cache absence
  re-routes KA candidates to `watchlist_null_unavailable` exactly as
  in Stage A.
- The runner records the null cache `kernel_commit` field on launch.
  If this differs from the current kernel commit, the runner aborts
  with `stale_null_cache` (mirrors the alerts.py status added in the
  hardening pass).

---

## 6. Alert vs watchlist policy

Inherits Stage A §6 verbatim — same strict bar:

- **alert** iff `crib_score == 24` AND `bean_passed` AND
  `ngram_score >= -3.5` AND `p_adjusted <= 0.01`.
- **watchlist** iff `crib_score >= 18` AND not alert.
- `watchlist_null_unavailable` when nulls are missing for the candidate
  alphabet and `require_null_for_alert=True`.

The perturbation penalty is implicit in the larger
`total_config_cardinality` (bigger universe → larger Bonferroni factor).
Stage B does **not** apply a separate Hamming-distance penalty.

---

## 7. Synthetic recovery (mandatory pre-execution test)

Two recovery probes — both must pass before `--execute-full` accepts:

### 7.1 Selective recovery (load-bearing)

1. Pick two crib positions `p1, p2 ∈ {21..33, 63..73}` and two letters
   distinct from the canonical CT at those positions.
2. Build a synthetic CT that equals canonical CT everywhere except `p1, p2`.
3. Build a planted ambiguous-position set `A* = {p1, p2}` (k=2).
4. Construct synthetic plaintext with crib alignment and arbitrary
   filler.
5. Encrypt under one of (Vigenère + AZ + `PALIMPSEST`,
   Beaufort + KA + `KRYPTOS`) — both variants must be tested.
6. Corrupt the resulting CT at `p1, p2` to produce the synthetic carved CT.
7. Run Stage B on this synthetic carved CT with `A = A*`.
8. **Assert** the harness emits `alert` for the variant that recovers
   the original encryption: full crib match, Bean pass, correct
   `(p1, old, new), (p2, old, new)` triples.

### 7.2 Structural recovery (degenerate)

Plant a Hamming-2 perturbation outside crib positions. Verify the
harness reports: variant evaluated, Bean state unchanged from canonical
(non-crib positions can't change Bean state), no false alert fires.

Both probes are exposed via `--synthetic-recovery-test` and write
`recovery_test_report.json`. Either probe failing aborts the runner
with non-zero exit code.

---

## 8. Checkpointing and artifacts

Inherits Stage A §8 schema-v2 conventions. Differences:

- New artifact: `ambiguous_positions_manifest.json` — copy of the
  operator-supplied JSON file with checksum verified.
- `universe_manifest.json` carries `k`, `C(k,2)`, the explicit position
  pairs, and the resulting H2 variant count.
- JSONL row schema gains `pos_pair: [int, int]`,
  `chars_pair: [old, new, old, new]`, and `crib_overlapping: int`.

Default artifact root: `results/ct_perturbation_stage_b/<run_id>/`.

---

## 9. CLI

```
PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_b.py \
    --ambiguous-positions PATH \             # REQUIRED — predeclared, schema-validated
    [--keywords PATH] \
    [--keyword-cap N] \
    [--workers N] \
    [--artifact-root PATH] \
    [--run-id ID] \
    [--ct-path PATH] \
    [--max-h2-variants N] \                  # smoke cap, default 50
    [--keyword-limit N] \
    [--include-h0-baseline] \
    [--require-null | --allow-null-unavailable] \
    [--allow-large-ambiguous-set] \          # required if k > 20
    [--synthetic-recovery-test] \
    [--dry-run] \
    [--execute-full] \                       # required to disable smoke cap
    [--audit-run PATH] \
    [--verbose]
```

Default behaviour mirrors Stage A: no flag → smoke run with 1 H2
variant; `--dry-run` writes manifests without compute; `--execute-full`
required for the full Stage B universe at the operator's chosen `k`.

The runner refuses to launch when:

- `--ambiguous-positions` is missing or the file fails schema
  validation;
- `archive_provenance` is empty;
- `k > 20` without `--allow-large-ambiguous-set`;
- The synthetic recovery test fails or has not been requested with
  `--execute-full`;
- The null cache `kernel_commit` differs from the current commit.

---

## 10. Negative-claim wording (binding template)

If Stage B returns no `alert` rows under a specific
predeclared `A`, the **only** narrow negative claim this campaign
supports is:

> "Under the operator-predeclared archive-anchored ambiguous-position
> set `A = {…}` (provenance: …), no candidate survived the
> preregistered Stage B alert bar across Hamming-2 substitutions
> within `A` × {Vigenère, Beaufort, Variant Beaufort} × {AZ, KA} ×
> the curated keyword pool × the specified CT-parametric scoring and
> null model."

The campaign's evidence does **NOT** support, and operators must not
write, claims of the form:

- ❌ "Hamming≤2 correction does not unlock K4." (Stage B is
  constrained to `A`; H2 outside `A` is untested.)
- ❌ "The carved CT is correct." (Stage B does not test H≥3 or non-
  archive-anchored H2.)
- ❌ "All cipher families are now eliminated." (Single-layer additive
  only.)
- ❌ "The archive ambiguity hypothesis is falsified." (Negative under
  `A` does not falsify the broader archive hypothesis with a different `A`.)

A negative result motivates: (a) reviewing whether the predeclared `A`
matches actual archive evidence; (b) considering Stage C (procedural /
chart-derived); (c) treating the H2-archive-anchored prior as
disfavored relative to multi-layer or crib-mapping-break paths.

---

## 11. Stage C constraints (unchanged from Stage A §12)

Stage C, if pursued, will:

- Use the existing `kryptosbot.procedural_enumerator` /
  `ProceduralRecipe` / `HypothesisSpec` path. **No new framework.**
- Search (procedural overlay × algebraic) compositions for the subset
  of procedurals already vetted in `docs/procedural_recipes.json`.
- **Exclude running-key and non-English source text.** Period.
- Add a `CipherProcedureLicense` schema only if and when chart-derived
  procedures lack public reproducibility — and only after a separate
  preregistration document.

---

## 12. Reproducibility checklist

- [ ] `PYTHONPATH=src python3 -m kryptos doctor` returns all-PASS
      before launch.
- [ ] `PYTHONPATH=src python3 scripts/_infra/session_briefing.py`
      shows current state (Stage A clean negative, Stage B armed).
- [ ] `PYTHONPATH=src python3 scripts/_infra/calibrate_null_baselines.py`
      has run; `null_baselines/manifest.json` `kernel_commit` matches
      current kernel.
- [ ] `--ambiguous-positions PATH` file exists, schema-valid,
      provenance-cited, signed off by operator.
- [ ] `PYTHONPATH=src pytest tests/test_ct_perturbation_stage_b.py -q`
      green.
- [ ] `--synthetic-recovery-test --dry-run` reports `passed: true` for
      both selective and structural probes.
- [ ] Manifest `git_commit` matches the kernel commit recorded in the
      null-baseline cache.
- [ ] Operator has read Stage A's clean-negative result and Stage B's
      §10 binding negative-claim wording.

---

## 13. Decision gate before launch

Before launching `--execute-full`, the operator must answer in writing
(committed to the run directory as `decision_gate.md`):

1. **Why is this `A`?** (One paragraph citing specific archive evidence
   per position. Not "I think these look ambiguous" — the per-position
   rationale in the JSON file is binding evidence.)
2. **What was considered and excluded?** (List positions that *almost*
   made the cut and why they didn't. This protects against retroactive
   set widening.)
3. **What would change my mind?** (One sentence on what archive
   evidence, if found, would invalidate this `A` post-hoc. This protects
   against the "everything fits" failure mode.)

The decision-gate document is a discipline mechanism, not a research
artifact. It is the operator's commitment to treat Stage B's alert /
no-alert outcome as binding given the operator-chosen `A`.

---

*Last updated 2026-05-02. Framework binding; ambiguous-position set
TBD by operator. Implementation (`scripts/campaigns/ct_perturbation_stage_b.py`,
tests) follows after operator-supplied `A` and decision-gate document.*
