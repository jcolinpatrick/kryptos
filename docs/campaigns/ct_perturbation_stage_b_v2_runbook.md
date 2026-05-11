# CT-Perturbation Stage B v2 — Operator Runbook

**Audience:** the human operator running the Stage B archive-anchored
H2 CT-perturbation campaign on K4.
**Companion:** `docs/campaigns/ct_perturbation_stage_b_archive_review_checklist.md`
**Binding spec:** `docs/campaigns/ct_perturbation_stage_b_prereg.md`

---

## TL;DR

CT perturbation is not a license to mutate K4 freely. If you treat it
as a vague rescue mechanism — "the cipher fails, therefore some CT
character must be wrong, therefore we try them all" — you produce an
unfalsifiable campaign whose negative result means nothing and whose
positive result is overfit by construction.

The v2 workflow exists to convert CT perturbation into a disciplined,
preregistered, evidence-first campaign that survives red-team review.

The discipline is enforced at four layers:

1. **Schema** — v2 manifests require evidence per position, candidate
   substitutions, a "considered and excluded" list, and a frozen flag.
2. **Validator** — refuses 16 distinct invalid states at load time.
3. **Stage B runner** — refuses `--execute-full` on non-v2 manifests,
   unfrozen manifests, empty-excluded manifests, or stale-kernel
   manifests.
4. **Artifacts** — every run records `manifest_hash` and `universe_hash`
   so post-hoc tampering is detectable.

---

## What CT perturbation is, and is not

**It IS:** an investigation of the hypothesis that a small number of
positions on the carved CIA-courtyard panel differ from the encrypted
output Sanborn produced. The mechanism is archive-evidence-anchored:
the operator identifies candidate positions from photographs,
transcription disagreements, and physical anomalies BEFORE looking at
which corrections would produce attractive cipher results.

**It IS NOT:**

- A license to sweep all 97 positions × 25 alternates as the main
  campaign. That universe is unfalsifiable and is explicitly forbidden
  by the prereg.
- A score-driven selection process. If you pick positions because
  certain corrections happen to produce Bean-passing keystreams or
  high crib scores, you are reverse-engineering and the result is
  meaningless.
- A retroactive rescue. Once a v2 manifest is frozen and a Stage B run
  begins, the manifest may not be edited. If the run produces a null
  result, the operator may pursue a separate Stage B' preregistration
  with a different `A` — not silently rerun with an expanded `A`.

---

## The v2 manifest

Schema: `ct_perturbation_stage_b.ambiguous_positions.v2_evidence_anchored`

Required top-level fields:

| Field | Purpose |
|---|---|
| `schema_version` | Locks the schema; mismatch refuses load |
| `campaign_id` | `"ct_perturbation_stage_b"` |
| `created_at_utc` | ISO-8601 UTC string |
| `kernel_commit` | Git SHA at manifest authoring time |
| `ct_source` | `"carved_panel_v2026_canonical"` for real K4; synthetic fixtures use distinct labels |
| `ct_length` | Must equal canonical `CT_LEN` (97) |
| `frozen` | `true` required for `--execute-full` |
| `max_k` | Hard ceiling of allowed positions; respects `HARD_K_CEILING=20` |
| `selection_policy` | `{min_tier_for_main_campaign, max_k}` |
| `selected_positions` | List of evidence-anchored candidates |
| `excluded_positions` | List of considered-but-rejected positions |
| `evidence_sources` | List of source records |
| `manifest_hash` | sha256 over all other fields; detects tampering |

Each `selected_positions` record:

| Field | Purpose |
|---|---|
| `pos0` | Zero-based K4 position |
| `carved_char` | Letter at that position in canonical CT (validator cross-checks) |
| `candidate_substitutions` | Letters the operator believes the position could have carried. **Do not default to all 25; enumerate evidence-supported candidates only.** |
| `evidence_tier` | One of: `tier_1_direct_transcription_conflict`, `tier_2_visible_physical_ambiguity`, `tier_3_archive_or_photo_ambiguity`, `tier_4_weak_contextual_only` |
| `evidence_type` | Free-form descriptor (e.g. `transcription_disagreement`, `patina_occlusion`) |
| `rationale` | Per-position justification |
| `source_ids` | References to `evidence_sources[*].id` |
| `reviewer_notes` | Free-form |
| `allowed_in_main_campaign` | `true` gates inclusion in `--execute-full` universe |

Each `excluded_positions` record:

| Field | Purpose |
|---|---|
| `pos0` | Zero-based K4 position considered |
| `carved_char` | Letter at that position |
| `reason_excluded` | Why this position did NOT make the cut |
| `evidence_type_if_any` | Optional |
| `source_ids` | Optional |
| `reviewer_notes` | Optional |

---

## Discipline mechanism: tier policy

The `selection_policy.min_tier_for_main_campaign` floor is enforced by
the validator. Any `SelectedPosition` with `allowed_in_main_campaign=true`
whose tier is weaker than the floor causes a hard validation failure.

Default floor: `tier_2_visible_physical_ambiguity`. Operators may set
it higher (`tier_1_direct_transcription_conflict`) to require stronger
evidence; setting it lower is permitted but defeats the discipline.

Tier-4 entries are useful for documentation (showing what the operator
considered) but must carry `allowed_in_main_campaign=false`.

---

## Validator: 16 fail-closed conditions

Mounted at `kryptosbot.ambiguity_manifest.load_v2` /
`validate_dict`. Refuses:

1. Wrong `schema_version`
2. Missing `campaign_id`, `created_at_utc`, `kernel_commit`, `ct_source`
3. `ct_length` mismatch with canonical `CT_LEN`
4. Bad `selection_policy.min_tier_for_main_campaign` value
5. `max_k` exceeding `HARD_K_CEILING=20`
6. Duplicate selected positions
7. Positions outside `[0, CT_LEN)`
8. `carved_char` mismatch with canonical CT (for canonical ct_source)
9. Empty `candidate_substitutions` for selected positions
10. Candidate substitution equal to carved_char
11. Selected position without `evidence_tier`
12. Selected position without `rationale`
13. Selected position without `source_ids`
14. `source_ids` referencing an unknown `evidence_sources` id
15. `allowed_in_main_campaign=true` at tier weaker than policy floor
16. Allowed-position count exceeding `max_k`
17. Empty `excluded_positions` under `for_main_campaign=true`
   (override: `--allow-empty-excluded-for-test-only`, forbidden under
   `--execute-full`)
18. `frozen=false` under `for_main_campaign=true`
19. Stale `kernel_commit` (manifest vs current) when
   `require_fresh_kernel_commit=true`
20. `manifest_hash` mismatch with computed hash

(Counts higher than 16 because some original numbered rules expanded
into multiple discrete checks.)

---

## Stage B runner: refuse-to-launch conditions

`scripts/campaigns/ct_perturbation_stage_b.py --execute-full` refuses
launch when ANY of:

- `--ambiguous-positions-manifest` is missing
- v2 manifest fails any validator condition (see above)
- v2 manifest's `frozen=false`
- v2 manifest's `excluded_positions` empty (no override under `--execute-full`)
- v2 manifest's `kernel_commit` differs from current (require_fresh check)
- Null-baseline cache `kernel_commit` is stale relative to current kernel
  (override: `--allow-stale-null-cache`)
- Null-baseline cache is entirely absent
  (override: `--allow-null-unavailable`)
- `--per-task-timeout-sec <= 0`
- `--allow-empty-excluded-for-test-only` passed under `--execute-full`

Dry-run mode (no `--execute-full`) validates the manifest, prints a
summary including `manifest_hash`, and exits 0 without writing artifacts.

---

## Recommended campaign shape

- `k <= 10` strongly preferred; `k <= 5` ideal when evidence is strong
- 2-4 candidate substitutions per selected position (informed by what
  the evidence shows; not a brute enumeration)
- Tier 1 or Tier 2 for every `allowed_in_main_campaign=true` entry
- `excluded_positions` list with at least one entry, ideally 3-10
  showing the operator's deliberation

At `k=5` with 3 candidates per position, the universe is ~90 H2 variants
× ~4,300 configs = ~390K total configs. Bonferroni-manageable, fast to
execute, and the manifest discipline ensures any signal is real.

At `k=20` with 25 candidates per position (the legacy default), the
universe is ~118,750 H2 variants × ~4,300 configs = ~510M total configs.
This is the prereg's HARD_K_CEILING but is discouraged unless the
evidence base is exceptional.

---

## Command sequence

### 1. Validation only (dry-run, no compute)

```bash
PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_b.py \
    --ambiguous-positions-manifest path/to/manifest_v2.json
```

Exit 0 if the manifest validates; prints schema_version, manifest_hash,
allowed k, excluded count, and selection_policy. Does NOT require
frozen, does NOT require kernel match — those gates fire only under
`--execute-full`.

### 2. Synthetic recovery (harness sanity check)

```bash
PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_b.py \
    --synthetic-recovery-test
```

Runs prereg §7 in-memory. Independent of any manifest. Must PASS before
trusting any v2 launch.

### 3. Smoke run with v2 manifest

```bash
PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_b.py \
    --ambiguous-positions-manifest path/to/manifest_v2.json \
    --execute-full \
    --max-h2-variants 5 --keyword-count 3 --keyword-limit 3 \
    --artifact-root /tmp/stage_b_smoke \
    --run-id v2_smoke
```

Exercises the full launch path with a tiny universe. Verifies:
- Manifest validates under `--execute-full` rules
- Null cache fresh
- All 5 JSONL/JSON artifacts written
- `manifest_hash` and `universe_hash` in summary
- `ambiguous_positions_manifest.json` (copy of input) and
  `universe_manifest.json` (derived) both present

### 4. Full launch

```bash
PYTHONPATH=src python3 scripts/campaigns/ct_perturbation_stage_b.py \
    --ambiguous-positions-manifest path/to/manifest_v2.json \
    --execute-full \
    --workers 26 \
    --artifact-root results/ct_perturbation_stage_b \
    --run-id $(date -u +%Y%m%dT%H%M%SZ)_archive_anchored
```

Wall time depends on k. At k=5-10 with 2-4 candidates per position,
expect minutes-to-low-hours.

---

## Pre-launch checklist

Before invoking step 4:

- [ ] Manifest validates cleanly under `--ambiguous-positions-manifest` alone
- [ ] `decision_gate.md` written and committed alongside the manifest
- [ ] `§13.2 considered-and-excluded` list non-empty
- [ ] `§13.3 "what would change my mind"` sentence is specific
- [ ] Null cache fresh:
      `null_baselines/manifest.json` `kernel_commit_at_latest_write` matches
      `git rev-parse HEAD`. Rebuild with
      `PYTHONPATH=src python3 -u scripts/_infra/calibrate_null_baselines.py`
- [ ] Manifest `kernel_commit` matches `git rev-parse HEAD`
- [ ] Synthetic recovery test passes (step 2)
- [ ] Smoke run passes (step 3) with the real manifest
- [ ] `manifest_hash` recorded in operator log
- [ ] You have a `git log` checkpoint so the run is reproducible

---

## After the run

The negative-claim wording is binding (prereg §10). If no alert fires:

> "Under the operator-predeclared archive-anchored ambiguous-position
> set `A = {…}` (provenance: …; manifest_hash: …), no candidate
> survived the preregistered Stage B alert bar across Hamming-2
> substitutions within `A` with the operator-curated candidate
> substitutions × {Vigenère, Beaufort, Variant Beaufort} × {AZ, KA} ×
> the curated keyword pool × the specified CT-parametric scoring and
> null model."

That is the only claim a null result supports. Do not generalize.

If an alert fires:

1. Run `red-team-disprover` against the alert before celebration
2. Verify `manifest_hash` in the artifact matches the manifest you
   authored
3. Verify `universe_hash` matches a fresh recomputation
4. Run the same manifest a second time and confirm the result is
   identical (deterministic)
5. Cross-check with an independent reviewer

A `24/24 + bean_passed` result in a 100K+-config universe must survive
multiplicity correction AND adversarial review before becoming canonical.

---

## What this workflow prevents

| Failure mode | Mechanism that prevents it |
|---|---|
| Reverse-engineering positions from scores | v2 manifest must be `frozen=true` with a `created_at_utc` before any Stage B run; `manifest_hash` detects post-launch edits |
| Retroactive set widening after null result | `excluded_positions` list documents what was considered; manifest is immutable post-launch |
| Default-to-all-25 brute force | `candidate_substitutions` is operator-enumerated; no default fallback |
| Evidence-free position selection | `evidence_tier`, `rationale`, `source_ids` required; weaker than policy floor blocks `allowed_in_main_campaign=true` |
| Stale-kernel artifacts | `kernel_commit` required in manifest and validated against current under `--execute-full` |
| Stale null calibration | Null-cache `kernel_commit_at_latest_write` validated against current; override is explicit |
| Silent post-hoc tampering | `manifest_hash` over canonical serialization detects any field change |
| Test fixtures leaking into production | `--allow-empty-excluded-for-test-only` forbidden under `--execute-full` |

---

*Last updated 2026-05-11. v2 schema landed alongside Tasks 13-18 of the
v1 sweep-runner implementation pass.*
