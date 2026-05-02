# CT-Perturbation Stage A — Preregistration

**Campaign id:** `ct_perturbation_stage_a`
**Status:** ARMED — awaiting `--execute-full` invocation
**Author:** Colin Patrick + Claude (KryptosBot)
**Date authored:** 2026-05-01
**Authoritative spec:** this document
**Code:** `kryptosbot/ct_perturbation.py` + `scripts/campaigns/ct_perturbation_stage_a.py`
**Tests:** `tests/test_ct_perturbation_stage_a.py`

---

## 1. Motivation (the structural commitment)

Every Tier-1 / Tier-2 elimination in this project is conditional on the
canonical 97-character carved K4 ciphertext being correct character-by-
character. The 2025–2026 Smithsonian / AAA archive evidence around
Sanborn's coding-chart photographs admits — without proving — the
hypothesis that the carved transcription differs from the encrypted
output by a small Hamming distance. If even one position is wrong,
every "exhausted" cipher family is reopened on the corrected CT.

Stage A treats the carved CT as **observation, not ground truth**, and
performs the smallest non-trivial systematic search of that hypothesis
space:

> for each of the 2,425 single-character substitutions of the carved
> CT, decrypt under the periodic additive families (Vigenère / Beaufort
> / Variant Beaufort) × {AZ, KA} alphabets × a curated keyword pool;
> re-derive Bean constraints on the perturbed CT; emit only candidates
> that pass the preregistered alert bar.

This is the highest-EV bounded swing the project can take this week
because (a) it has external archival motivation, (b) it directly
attacks the strongest belief shared across all eliminations, and (c)
it requires no new kernel work — only a CT-parametric scoring wrapper
that recomputes Bean from the perturbed CT instead of importing the
frozen canonical sets.

---

## 2. Hard scope boundary (binding)

The following are **explicitly out of scope** for Stage A and for this
preregistration:

- **Running-key ciphers.** Not implemented, not parameterized, not
  invoked, not documented as a future Stage A path.
- **Non-English source text** of any kind (German, Latin, Egyptian,
  hieratic, Gutenberg, Oranchak corpora, …).
- **CorpusLicense** schema work and any path that requires it.
- **Multi-layer compositions** (substitution + transposition,
  three-layer cascades). Stage A is single-layer keyed substitution
  over a perturbed CT.
- **Position-dependent selectors, grilles, charts, autokey, Quagmire III,
  stateful families.**

The runtime contract is enforced at the test level
(`tests/test_ct_perturbation_stage_a.py::TestScopeExclusion`):

- The campaign module imports nothing from `running_key`, `corpus`,
  or any non-English source-text branch.
- The CLI exposes no `--running-key`, `--corpus`, `--non-english`, or
  `--source-text` options.
- `SUPPORTED_FAMILIES` is exactly `{Vigenère, Beaufort, Variant Beaufort}`.

---

## 3. Universe arithmetic (honest cardinality)

### 3.1 Stated dimensions

| Dimension | Value | Source |
|---|---|---|
| Cipher families | 3 (Vigenère, Beaufort, Variant Beaufort) | `SUPPORTED_FAMILIES` |
| Alphabets | 2 (AZ, KA) | `SUPPORTED_ALPHABET_KINDS` |
| Keywords | up to 1000 (cap; actual = curated pool size) | `--keywords PATH` |
| Hamming-1 CT variants | exactly 2,425 = 97 × 25 | enumerator |
| Hamming-0 baseline | 1 (optional, `--include-h0-baseline`) | `canonical_variant` |

### 3.2 Period is not an independent dimension

The kernel's `decrypt_text(ct, key, variant, alphabet)` uses
`period = len(key)`. There is no independent period parameter for the
periodic additive families. **Distinct periods in the search universe
arise solely from the lengths of keywords in the curated pool.**

The runner records the actual set of periods present in the pool
(`period_values_observed_in_pool` in `preregistration.json`). It does
not multiply the universe by 26 to produce a 378M-config phantom.

### 3.3 Total cardinality

**Per CT variant:** `3 × 2 × |keywords|`.
**Full Hamming-1 sweep:** `(3 × 2 × |keywords|) × 2,425`.
**With H0 baseline included:** add `(3 × 2 × |keywords|)`.

For the canonical curated pool of `wordlists/thematic_keywords_v2.txt`
after normalization (719 unique A-Z keywords as of 2026-05-01):

| Configuration | Keywords | Per CT variant | Total |
|---|---|---|---|
| H1 only | 719 | 4,314 | **10,461,450** |
| H1 + H0 | 719 | 4,314 | **10,465,764** |

For a hypothetical 1,000-keyword pool:

| Configuration | Keywords | Per CT variant | Total |
|---|---|---|---|
| H1 only | 1,000 | 6,000 | **14,550,000** |
| H1 + H0 | 1,000 | 6,000 | **14,556,000** |

The naive-but-incorrect product `3 × 26 × 2 × 1000 × 2425 = 378,300,000`
appears nowhere in this campaign because it overcounts by claiming 26
independent periods that the kernel does not in fact provide.

The total cardinality used in Bonferroni adjustment is the actual
implemented universe (per the table above), not the phantom 378M.

---

## 4. CT-parametric scoring policy

### 4.1 Crib score (PT-only)

Wraps `kryptos.kernel.scoring.crib_score.score_cribs`. Inspects only
the candidate plaintext against the canonical `CRIB_DICT`. CT-independent.

### 4.2 Bean (CT-parametric — the core of the campaign)

For each CT variant, **re-derive** the eq / ineq / linear constraint
sets from the perturbed CT and the canonical crib dictionary using
`kryptosbot.ct_perturbation.derive_bean_constraints`. The kernel's
frozen `BEAN_EQ` / `BEAN_INEQ` / `BEAN_LINEAR` are reference values
for the canonical (Hamming-0) CT only and are used solely to verify
the local re-derivation reproduces them on canonical input
(`assert_canonical_bean_reproduction`).

Variant-independence test (per kernel, retained here): a pair `(a,b)`
is in the equality set iff the keystream values implied at `a` and `b`
are equal under all three additive variants (Vigenère, Beaufort,
Variant Beaufort) given `(CT[a], crib[a], CT[b], crib[b])`. The
inequality set is the dual condition.

For each candidate plaintext, the implied keystream is recovered at
the 24 crib positions using the chosen family's recovery rule
(`K = CT - PT mod 26` for Vigenère, `K = CT + PT mod 26` for Beaufort,
`K = PT - CT mod 26` for Variant Beaufort) and the chosen alphabet's
index table. The Bean constraint sets are derived in that same alphabet
index space. AZ canonical derivation reproduces the kernel's frozen
Bean sets; KA derivation is intentionally different and must not be
checked against AZ-derived constraints. The keystream is then checked
against the re-derived constraint sets — never the canonical sets.

### 4.3 N-gram (PT-only)

`kryptos.kernel.scoring.ngram.NgramScorer.score_per_char` over the
quadgram log-probability table at `data/english_quadgrams.json`.
CT-independent.

### 4.4 IC

Not used in Stage-A scoring. IC of K4 is below random and known
non-discriminative for n=97 (per `docs/elimination_tiers.md` and
[INTERNAL RESULT] E-FRAC-04).

### 4.5 Position-class effect

Under H1/direct positional crib mapping, the known crib positions are
fixed. A CT substitution at one of the 24 crib positions can change the
crib-derived keystream and Bean feasibility. A CT substitution outside
the 24 crib positions cannot change crib_score or Bean constraints; it
can only affect downstream plaintext/ngram scoring for candidates that
already survive crib/Bean gates.

| Class | Count |
|---|---:|
| Crib-position H1 substitutions | 600 |
| Non-crib-position H1 substitutions | 1,825 |
| H0 baseline | 1 |
| Total with H0 | 2,426 |

---

## 5. Null and p-value policy

### 5.1 `crib_p_raw`

Exact right-tail Binomial(n=24, p=1/26). Pure analytic; no cache
required. Computed by
`kryptosbot.ct_perturbation.crib_p_value_random`.

### 5.2 `ngram_p_raw`

Lookup of `kryptosbot.null_baselines.get_cached("ngram_score",
"random_text", n_chars=97, alphabet)`. Empirical normal-approx tail
when present (parametric_model="normal" in the cache). Set to None
when the cache is missing for the requested alphabet; the campaign
records this in `summary.json::null_status` and the
preregistration's `null_policy.status_at_launch`.

### 5.3 `p_combined_raw`

Fisher's combined probability test (chi-square upper tail with `2k`
degrees of freedom, where `k` is the count of available raw p-values).
Conservative: returns None whenever any input is missing. Implemented
in stdlib via the regularized upper-incomplete gamma.

### 5.4 `p_adjusted` (multiplicity correction)

Bonferroni over the **complete preregistered universe size** (not
merely over stored candidates):

```
p_adjusted = min(1.0, p_to_adjust * total_config_cardinality)
```

where `p_to_adjust` is `p_combined_raw` when available, else
`crib_p_raw`. The total cardinality is the value computed in §3.3 for
the actually-run universe (`UniverseDimensions.total`).

### 5.5 Null status

Run `scripts/_infra/calibrate_null_baselines.py` to build the standard
AZ random_text cache. At audit time the KA ngram random_text cache is
not present. When the ngram cache for the candidate alphabet is missing,
candidates with `crib_score >= h1_min_crib_score_watchlist` are emitted
as `watchlist_null_unavailable`, never as `alert`.

The CLI flag `--require-null` fails closed if any selected alphabet
lacks the required ngram null at launch. `--allow-null-unavailable`
proceeds with exploratory compute but does not permit solution-grade
alerts for missing-null candidates.

---

## 6. Alert vs watchlist policy

Defined in `kryptosbot.ct_perturbation.AlertPolicy`. Defaults:

### 6.1 Hamming-1 (strict bar)

A candidate fires `alert` iff **all** of:

- `crib_score == crib_total` (24/24)
- `bean_passed is True` (under re-derived constraints)
- `ngram_score >= -3.5` (per-char log-prob; English prose ≈ -3.0,
  random ≈ -6.4, calibrated alert bar from `kryptosbot/alerts.py`)
- `p_adjusted <= 0.01`

A candidate fires `watchlist` iff `crib_score >= 18` and one or more
of the above fails. Otherwise `none`.

When nulls are unavailable and `require_null_for_alert=True`, every
candidate with `crib_score >= 18` is emitted as
`watchlist_null_unavailable` and **no `alert` is ever fired**.

### 6.2 Hamming-0 (canonical baseline path)

A candidate fires `alert` iff `crib_score >= 18`, `bean_passed`, and
`p_adjusted <= 0.05`. The H0 universe is just the keyword pool, so the
adjusted-p threshold is permissive relative to H1.

### 6.3 Perturbation penalty

The strict H1 bar (full cribs + Bean + ngram floor + p_adjusted ≤ 0.01)
is the **perturbation penalty**: each H1 candidate carries the extra
search dimension (2,425 ways to perturb), and the alert bar reflects
that. Stage A does not apply a separate per-position penalty — the
extra cardinality is fully baked into the Bonferroni adjustment over
`total_config_cardinality`.

---

## 7. Synthetic recovery (mandatory pre-execution test)

Before any full execution, the campaign runs (and must pass) a planted-
correction recovery test:

1. Build a 97-char synthetic plaintext with the K4 cribs at canonical
   positions and arbitrary filler elsewhere.
2. Encrypt under Vigenère + AZ + keyword `PALIMPSEST`.
3. Corrupt exactly one CT position.
4. Run the CT-perturbation harness over a tiny keyword pool that
   includes `PALIMPSEST`.
5. Assert the harness emits an `alert` for the variant that recovers
   the original (uncorrupted) CT, with `crib_score == 24` and
   `bean_passed == True`, and identifies the correct
   `(pos, old_char, new_char)`.

This is implemented as `synthetic_recovery_test` in
`scripts/campaigns/ct_perturbation_stage_a.py` and exposed via
`--synthetic-recovery-test`. The test report lands at
`recovery_test_report.json`. The runner aborts with non-zero exit code
if the recovery test fails — this is the load-bearing assertion that
scoring is genuinely CT-parametric end-to-end.

---

## 8. Checkpointing and artifacts

### 8.1 Default artifact root

```
results/ct_perturbation_stage_a/<run_id>/
```

### 8.2 Artifacts written

| File | Purpose |
|---|---|
| `preregistration.json` | This document, rendered as machine-readable manifest at run start. |
| `keyword_source_manifest.json` | Source path, hash, normalized hash, count, normalization rules. |
| `universe_manifest.json` | Cardinality dimensions and total. |
| `progress.json` | Atomically written checkpoint after each variant chunk. |
| `checkpoints/` | Reserved for resume-from-mid-variant state in future revisions. |
| `top_candidates.jsonl` | Top-N by composite key (crib_score primary, ngram secondary). |
| `watchlist.jsonl` | Candidates not meeting alert bar but `crib_score >= 18`. |
| `alerts.jsonl` | Candidates that fired full alert. |
| `summary.json` | Schema-v2 end-of-run summary with H0/H1 counts, cardinality, Bean/alert totals, null status, benchmark fields, and position-class interpretation. |
| `coverage_report.json` | Structured coverage matrix and position-class interpretation. |
| `recovery_test_report.json` | (when `--synthetic-recovery-test`) recovery proof. |
| `audit_report.json` | Written by `--audit-run` when auditing a completed artifact directory. |

### 8.3 JSONL row schema

Every alert / watchlist / top row contains:

```
run_id, variant_id, distance, pos, old_char, new_char, ct_sha256,
family, alphabet, period, keyword,
score: { crib_score, crib_total, bean_passed, bean_variant,
         ngram_score, crib_p_raw, ngram_p_raw, p_combined_raw,
         p_adjusted, alert_class, rejection_reason },
plaintext
```

`plaintext` is recorded only on stored rows (alerts, watchlist, top-N).
Bulk negative results are not retained — the campaign keeps memory
bounded at the cost of not supporting per-cell post-hoc inspection.

### 8.4 Atomic writes

JSON checkpoint and summary files are written via temp-file + rename.
JSONL rows are appended one line at a time and survive process kill;
parse robustly by skipping blank lines.

---

## 9. CLI

```
PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_a.py \
    [--keywords PATH] \
    [--keyword-cap N] \
    [--workers N] \
    [--artifact-root PATH] \
    [--run-id ID] \
    [--ct-path PATH] \
    [--max-ct-variants N] \
    [--max-configs N] \
    [--keyword-limit N] \
    [--include-h0-baseline] \
    [--trace-first-configs N] \
    [--require-null | --allow-null-unavailable] \
    [--synthetic-recovery-test] \
    [--dry-run] \
    [--execute-full] \
    [--resume PATH] \
    [--audit-run PATH] \
    [--verbose]
```

### 9.1 Default behaviour is conservative

- **No flag:** smoke run with `--max-ct-variants=2`. Manifest written,
  tiny subset evaluated, artifacts produced. Cannot launch a 10M+
  config sweep accidentally.
- **`--dry-run`:** writes manifest + universe manifest + summary stub
  only. No candidate evaluation.
- **`--execute-full`:** required to disable the smoke cap and run all
  2,425 H1 variants × full keyword pool.
- **`--max-ct-variants N`:** caps H1 variants only. H0 is added
  separately when `--include-h0-baseline` is passed.
- **`--resume`:** disabled in schema v2; it fails before compute rather
  than pretending checkpoint resume is implemented.
- **`--audit-run PATH`:** validates expected artifacts, cardinality
  fields, JSON/JSONL parseability, null status, H0/H1 math, and
  position-class counts.

### 9.2 Recommended invocations

Dry run (verify manifest + universe arithmetic):
```
PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_a.py \
    --dry-run \
    --run-id $(date -u +%Y%m%dT%H%M%SZ)_dry
```

Smoke (1 H1 variant × small keyword set, fast end-to-end check):
```
PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_a.py \
    --keywords wordlists/thematic_keywords_v2.txt \
    --max-ct-variants 1 \
    --keyword-limit 10 \
    --run-id $(date -u +%Y%m%dT%H%M%SZ)_smoke
```

Synthetic recovery (mandatory before full):
```
PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_a.py \
    --synthetic-recovery-test \
    --dry-run \
    --run-id $(date -u +%Y%m%dT%H%M%SZ)_recovery
```

Full execution (all 2,425 H1 variants × full keyword pool, parallel):
```
PYTHONPATH=src python3 -u scripts/campaigns/ct_perturbation_stage_a.py \
    --keywords wordlists/thematic_keywords_v2.txt \
    --workers 26 \
    --execute-full \
    --include-h0-baseline \
    --synthetic-recovery-test \
    --run-id $(date -u +%Y%m%dT%H%M%SZ)_full
```

---

## 10. Negative-claim wording (binding template)

If Stage A returns no `alert` rows, the **only** narrow negative claim
this campaign supports is:

> "No candidate survived the preregistered thresholds under Hamming-1
> single-character substitutions of the 97-character carved CT ×
> {Vigenère, Beaufort, Variant Beaufort} × {AZ, KA} × the curated
> keyword pool × the specified CT-parametric scoring and null model."

The campaign's evidence does **NOT** support, and operators must not
write, claims of the form:

- ❌ "K4 cannot be solved by Hamming≤2 correction × any classical family."
- ❌ "Single-letter CT corrections do not unlock K4."
- ❌ "The carved CT is correct."
- ❌ "All cipher families are now eliminated."

Each of those claims would require Stage B (Hamming-2, archive-anchored
only) and / or a Stage C-like procedural framework — neither of which
is implemented or motivated by this run.

---

## 11. Stage B (NOT IMPLEMENTED — design constraints only)

Stage B will, when implemented:

- Operate on archive-anchored Hamming-2 only. The second perturbation
  position must come from a **predeclared** ambiguous-position set
  (positions where the 2025–2026 Smithsonian/AAA coding-chart photos
  show transcription ambiguity).
- **Not** select ambiguous positions adaptively after seeing Stage-A
  scores. Adaptive selection is a multiplicity-correction violation.
- **Not** generate unconstrained Hamming-2 (4.5M variants × 14M configs
  = 6 × 10¹³ — beyond the project's compute budget and beyond what a
  Bonferroni gate can defend at p<1).
- Reuse the same alert / watchlist / scoring policy as Stage A.
- Inherit Stage A's exclusion list verbatim (no running-key, no
  non-English source text, no CorpusLicense).

---

## 12. Stage C (NOT IMPLEMENTED — design constraints only)

Stage C, if pursued, will:

- Use the existing `kryptosbot.procedural_enumerator` /
  `ProceduralRecipe` / `HypothesisSpec` path. **No new framework.**
- Search (procedural overlay × algebraic) compositions for the subset
  of procedurals already vetted in `docs/procedural_recipes.json`.
- **Exclude running-key and non-English source text.** Period.
- Add a `CipherProcedureLicense` schema only if and when chart-derived
  procedures lack public reproducibility — and only after a separate
  preregistration document.

If you are reading this paragraph because you are about to start
Stage C, please confirm:

- [ ] Stage A has run and either produced no alert or has had its
      alerts independently red-teamed.
- [ ] Stage B has been authored or explicitly skipped (with reasoning).
- [ ] No CipherProcedureLicense entry has been added without operator
      review.

---

## 13. Reproducibility checklist

- [ ] `PYTHONPATH=src python3 -m kryptos doctor` returns all-PASS
      before launch.
- [ ] `PYTHONPATH=src python3 scripts/_infra/session_briefing.py`
      shows current state.
- [ ] `PYTHONPATH=src python3 scripts/_infra/calibrate_null_baselines.py`
      has run; `null_baselines/manifest.json` exists.
- [ ] `PYTHONPATH=src pytest tests/test_ct_perturbation_stage_a.py -q`
      green.
- [ ] `--synthetic-recovery-test --dry-run` reports
      `passed: true` in `recovery_test_report.json`.
- [ ] Manifest `git_commit` matches the kernel commit recorded in
      the null-baseline cache.

---

*Last updated 2026-05-01.*
