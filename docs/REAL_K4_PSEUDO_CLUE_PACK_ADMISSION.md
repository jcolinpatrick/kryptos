# Real-K4 Pseudo-Clue Pack Admission Standard

**Status:** active. Created 2026-04-30 after the null closure of bridge
campaign 001 (`data/real_k4_pseudo_clue_packs/campaign_001_team_of_rivals/CLOSURE.md`).
Owner: this document. Authority: blocks new pack authoring and bridge
runs that fail the admission checks.

---

## Why this exists

Bridge campaign 001 ran 1,730 candidates across 31 packs and produced
a clean **null_level** result (max_crib=5/24, expected null max=5.35,
p=0.965, no Bean / ngram corroboration). The schema validator
([`kryptosbot/real_k4_pseudo_clue_pack.py`](../kryptosbot/real_k4_pseudo_clue_pack.py))
caught zero invalid packs because every pack was structurally valid —
they just had no real-K4 signal to find.

Schema validity is necessary but not sufficient. **Admission is the
filter that comes before the schema validator.** A pack must clear the
admission criteria below before it is authored, before it is added to a
campaign directory, and before any bridge audit is launched against it.
Adding more breadth without raising the admission bar is anti-productive:
the maximum-of-N null threshold grows with search size, and adding more
packs of campaign-001 shape only makes the bar harder to clear.

---

## Hard rules (every future pack)

A pack is **NOT admissible** unless every numbered item below is
satisfied. The admission validator
([`scripts/_infra/validate_pseudo_clue_pack_admission.py`](../scripts/_infra/validate_pseudo_clue_pack_admission.py))
checks the mechanical items; the human author is responsible for items
that require judgment.

### 1. Specific provenance item

- `provenance_items` must contain at least one entry whose
  `quote_or_summary` references a SPECIFIC artifact (a registry key, a
  document section, a memory note, a file path, or an anomaly id).
- A bare label like `"sculpture context"` or `"Sanborn statement"` is
  **not** specific; it must point at a checkable source.
- Source types `public_comment` and `human_note` require an explicit
  `url_or_registry_key` that resolves to a repo file or registry
  symbol.

### 2. Explicit mechanism mapping

- Every keyword and numeric role MUST have a `role_hint` that names how
  the value plays inside a hand-cipher. `unknown` is not admissible at
  authoring time (the schema allows it as a fallback; admission does
  not).
- Every numeric role MUST be tied to a specific anomaly, crib, or
  registry observation by `source_ids`. Numerology drawn from the open
  alphabet (e.g. "26 because there are 26 letters") is **not** a
  mechanism mapping.
- The author MUST state, in `caveats` or pack `hypothesis_summary`, the
  one-sentence claim of the form
  *"this pack tests whether `<provenance>` plays the `<role>` of `<value>`
  in `<composition>`"*.

### 3. Bounded parameter extraction

- `bounds.allow_project_safe_defaults` defaults to **false**. A pack that
  flips it to true MUST justify the deviation in `caveats` and explain
  why pack-supplied parameters are insufficient.
- `bounds.allow_default_widths` defaults to **false**. Same rule.
- `bounds.allowed_widths`, `bounds.allowed_depths`, and
  `bounds.allowed_shifts` MUST be small (≤8 entries) and individually
  cited via `numeric_roles` whose `source_ids` reach back to the pack's
  provenance items.

### 4. No arbitrary keys

- `bounds.allowed_keywords` MUST be set to an explicit pool drawn from
  evidence (cribs, K1/K2/K3 keywords, registered TIER_1 / TIER_2 entries
  in `kryptosbot.real_k4_clue_registry`, or anomalies with a documented
  letter signature).
- A pack that omits `allowed_keywords` AND uses keywords with role hints
  MUST justify reliance on `_pool_all_keywords` (i.e. why every keyword
  in the pack should be tried in every role) in `caveats`.
- "Common English words", "thematic keywords", and similar generic
  pools are **forbidden**. Each keyword needs a specific provenance
  link.

### 5. No arbitrary source texts

- Running-key and book-cipher hypotheses are NOT admissible through the
  bridge unless the pack identifies the candidate source text by a
  specific repo file or external citation, and constrains the offset
  and the source-tape segment by a citation. Open-ended literature
  searches are not admissible.

### 6. No default keyword pools unless justified

- Distinct from rule 4. The bridge compiler can fall back to
  `_DEFAULT_RAIL_DEPTHS`, `_DEFAULT_BOUSTROPHEDON_WIDTHS`, and
  `_DEFAULT_DIAGONAL_GRID_TUPLES` only when
  `bounds.allow_project_safe_defaults=true`. Every such use MUST carry
  a per-default justification in `caveats`.

### 7. Predicted side-effect beyond crib score (mandatory)

- A pack MUST predict, in `caveats` or `hypothesis_summary`, **at
  least one** observable side-effect that would corroborate a
  high-crib hit. The standard menu:
  1. **Bean constraint effect** — a candidate that scores high MUST
     also pass `bean_passed=True`. The pack states this as a
     prediction.
  2. **Anomaly alignment** — the pack predicts that a high-crib
     candidate's plaintext should align with one named anomaly in
     `docs/anomaly_registry.md` (e.g. preserves Stehle interval-4
     property, places YAR letters at expected positions, matches
     width-21 bigram structure).
  3. **N-gram floor improvement** — the pack predicts a minimum
     `ngram_score` floor for a winning candidate. If the campaign
     produces high crib but `ngram_score = 0`, the prediction
     falsified.
  4. **Crib position consistency** — the pack predicts that the
     winning plaintext respects a specific contextual constraint at
     the cribs (e.g. "BERLIN must be preceded by an English connector
     word").
  5. **Null-mask / route structure prediction** — the pack predicts a
     specific stego or route geometry that follows from its mechanism
     (a list of expected null positions, a specific 21x5 grid axis,
     etc.).
  6. **Independent observable in the anomaly registry** — the pack
     names another `docs/anomaly_registry.md` entry whose state should
     change under its hypothesis.
- Crib score alone is **not** a side-effect. The point of this rule is
  that any future "promising" hit carries independent corroboration on
  day one. Campaign 001's null result is the empirical justification.

### 8. Explicit campaign_001 coverage check

- Every new pack MUST state in `caveats` whether it is already covered
  by campaign 001's seven families. The four allowable values:
  - `"campaign_001_coverage: not_covered"` — pack tests a strictly new
    hypothesis class. The pack MUST point at the gap.
  - `"campaign_001_coverage: tightened"` — pack tightens a campaign-001
    family by removing degrees of freedom. The pack MUST explain which
    parameter was tightened and why the tightening would change the
    result.
  - `"campaign_001_coverage: new_provenance"` — pack uses a NEW
    provenance source not cited by any campaign-001 pack. The pack
    MUST cite the new source.
  - `"campaign_001_coverage: covered"` — pack overlaps a campaign-001
    pack. **Such packs are NOT admissible** (the family is already on
    the closed-null list); admission requires one of the first three
    states.

### 9. Maximum spec budget

- Per-pack `bounds.max_specs` MUST be ≤ 500 unless the pack carries an
  explicit cost justification in `caveats` AND the side-effect
  prediction (rule 7) is at least one of {Bean effect, anomaly
  alignment} (i.e. the strongest two corroboration types).
- Per-campaign global cap remains 20,000 (bridge audit hard ceiling).
- A campaign of more than 30 packs MUST justify the breadth in a
  campaign-level README and acknowledge the maximum-of-N null
  threshold growth explicitly.

### 10. Predeclared success criteria

- Every pack MUST predeclare, in `caveats`, the threshold(s) at which
  the pack would "win". The standard form:
  - "Pack passes if any candidate reaches `crib_score >= S` AND
    side-effect prediction `<rule 7 menu item>` is satisfied".
- Predeclared thresholds protect against post-hoc threshold shifting.
  A pack that does not predeclare its success criterion is **not**
  admissible.

---

## Worked example (admissible)

A future pack proposing that the K2 plaintext word `MAGNETIC` is the
substitution keyword:

- **(1)** Provenance: `kryptosbot.real_k4_clue_registry` MAGNETIC entry,
  TIER_KRYPTOS_PLAINTEXT_LEGACY.
- **(2)** Mechanism: keyword in substitution role, paired with BERLIN
  in columnar role.
- **(3)** Bounds: `allowed_widths=[8, 14]` (K3 widths) cited via
  `numeric_roles`.
- **(4)** Keywords: `allowed_keywords=["MAGNETIC", "BERLIN"]`.
- **(7)** Side-effect: predicts `bean_passed=True` AND
  `ngram_score >= -8` for any winning candidate.
- **(8)** Coverage: `"new_provenance"` — MAGNETIC was not cited by
  any campaign-001 pack.
- **(9)** `max_specs=200`.
- **(10)** Success: `"crib_score >= 18 AND bean_passed=True"`.

A pack of this shape is admissible. A pack that omits items 7, 8, or
10 is not.

## Worked example (not admissible)

A pack proposing that "thematic English words" should be tried as
columnar keys at default widths:

- Fails rule 4 (arbitrary keys).
- Fails rule 6 (default widths without justification).
- Fails rule 7 (no side-effect prediction).
- Fails rule 8 (overlaps F1/F7 from campaign 001).

Such a pack is rejected at admission. No schema validation, no
compile, no audit run.

---

## Validator

A small read-only validator lives at
[`scripts/_infra/validate_pseudo_clue_pack_admission.py`](../scripts/_infra/validate_pseudo_clue_pack_admission.py).
Usage:

```
PYTHONPATH=src python3 scripts/_infra/validate_pseudo_clue_pack_admission.py <pack.json | dir/>
```

The validator checks the mechanical items (default flags, keyword pool
explicitness, max_specs cap, role_hint = unknown, source_ids missing,
campaign_001 coverage statement present in caveats) and reports
HUMAN_REVIEW for items that require an author's judgment. It is
advisory — passing the validator does NOT exempt a pack from human
review against this document. Failing the validator DOES block authoring
until the failures are addressed.

---

## Update procedure

This document is the single source of truth for pack admission. When
campaign N closes, update this document with new lessons before
admitting campaign N+1 packs. Lower the bar **only** if a closed-null
campaign produced clear corroboration that the bar was too high; never
lower it to enable a new search.
