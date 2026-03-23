# Plain-English Language Layer for kryptosbot.com

**Date:** 2026-03-23
**Author:** Claude (with Colin Patrick)
**Status:** Approved

## Problem

kryptosbot.com serves two audiences: Kryptos enthusiasts who know basic cipher names but not scoring internals, and interested public with no cryptography background. The current site language is accurate but assumes familiarity with terms like "fractionation," "Bean constraint," "crib," "period underdetermination," and scoring thresholds. This creates a barrier for the broader Kryptos community.

## Approach

**Approach B: Plain-English Layer** — lead with accessible language, keep technical details visible but secondary. No structural overhaul; four templates and one Python file modified.

## Changes

### 1. Category Descriptions (`site_builder/build.py`)

Rewrite `CATEGORY_DESCRIPTIONS` dict to lead with what the method *does* before listing cipher names.

| Category | New Description |
|----------|----------------|
| substitution | "Methods that replace each letter with a different letter using a key or pattern — like a secret alphabet. Includes Vigenère, Beaufort, Quagmire, Hill, and more." |
| transposition | "Methods that scramble the order of letters without changing them — like writing a message into a grid and reading it back in a different order. Includes columnar, rail fence, route, and grille ciphers." |
| fractionation | "Methods that break each letter into smaller pieces (like grid coordinates), scramble those pieces, then reassemble them into new letters. Includes Bifid, Playfair, Four-Square, and ADFGVX." |
| multi-layer | "Combined approaches that stack multiple encryption steps — for example, replacing letters first, then scrambling their order. Includes null extraction, cascaded layers, and joint optimization." |
| key-models | "Different ways to generate the secret key — from a passage in a book, from a date, from a mathematical formula, or from the sculpture itself. Includes running keys, autokey, and keyword-derived approaches." |
| bespoke | "Non-standard methods inspired by the physical sculpture or military cipher systems — approaches that don't fit neatly into classical categories. Includes DRYAD charts, Morse code analysis, and coordinate-based approaches." |
| uncategorized | "Eliminations not yet assigned to a specific category." (unchanged) |

### 2. Elimination Page (`site_builder/templates/elimination.html`)

#### 2a. Auto-generated plain-English summary

Add a `<div class="plain-summary">` block between the description and the verdict row. Content is generated in the template from existing data fields:

```
We tested {configs_tested} configurations of {cipher_type}.
The best result matched {best_score} of 24 known letters —
{verdict_explanation}. This approach is ruled out.
```

Where `verdict_explanation` maps:
- best_score 0–9 (NOISE): "no better than random guessing"
- best_score 10–17 (INTERESTING): "slightly above random, but almost certainly coincidence"
- best_score 18–23 (SIGNAL): "worth investigating further, but not a solution"
- best_score 24 (FULL MATCH): "all known letters matched — under active investigation"

**Guard condition:** Only render the `.plain-summary` div when `e.configs_tested > 0`. A score of 0 is valid ("zero known letters matched") and should still produce a summary.

**Fallback for empty `cipher_type`:** Use `{{ e.cipher_type or "this approach" }}` so the sentence reads "We tested N configurations of this approach" when cipher_type is blank.

#### 2b. Humanized score display

Change the Best Score `<dd>` from:
```
3/24
```
To:
```
3 / 24 known letters matched · no better than random guessing
```

The italic classification text uses the same verdict_explanation mapping.

#### 2c. Bean Constraint renamed and explained

Change label from "Bean Constraint" to "Keystream Consistency (Bean)".

Add explanation line after PASS/FAIL:
```
Checks whether the key values at different positions are mathematically
consistent with each other.
```

### 3. Category Table (`site_builder/templates/category.html`)

Add subtitles to column headers:
- "Best Score" → "Best Score <small>(out of 24 known letters)</small>"
- "Verdict" → "Verdict <small>(noise = random, signal = worth investigating)</small>"

### 4. Methodology Page (`site_builder/templates/methodology.html`)

Add a "How to Read an Elimination Record" section at the top (after the intro paragraph, before "The K4 Ciphertext"). This is a brief annotated walkthrough of what each field means on an elimination page:

- **Title** — What was tested
- **Verdict** — NOISE (random), INTERESTING (above random, likely coincidence), SIGNAL (unusual, warrants investigation), FULL MATCH (all 24 letters correct)
- **Confidence Tier** — How certain we are: Tier 1 = mathematical proof, Tier 2 = every possibility tested, Tier 3 = partially tested, Tier 4 = untested
- **Configs Tested** — How many different key/parameter combinations were tried
- **Best Score** — How many of the 24 known plaintext letters the best attempt matched (24 = potential solution)
- **Keystream Consistency (Bean)** — Whether the key values at different positions are mathematically consistent with each other
- **Scope Limitations** — What this elimination does NOT rule out (important: eliminating one method doesn't eliminate combinations)

### 5. CSS Changes (`site_builder/static/style.css`)

Add styling for `.plain-summary`:
- Slightly larger font, muted color
- Margin below description, above verdict row
- "This approach is ruled out" in bold

## Files Modified

1. `site_builder/build.py` — Category descriptions
2. `site_builder/templates/elimination.html` — Summary, score, Bean rename
3. `site_builder/templates/category.html` — Column header subtitles
4. `site_builder/templates/methodology.html` — "How to read" section
5. `site_builder/static/style.css` — `.plain-summary` styling

## Files NOT Modified

- `site_builder/data_loader.py` — No data model changes needed
- `site_builder/categorizer.py` — No categorization logic changes
- `site_builder/overrides.toml` — Future: custom `plain_summary` per elimination, but not in this iteration
- `site_builder/templates/base.html` — No structural changes
- `site_builder/templates/home.html` — Categories will pick up new descriptions automatically

## Testing

1. Run `source venv/bin/activate && python3 site_builder/build.py` — should complete without errors
2. Spot-check 3-5 elimination pages for correct summary generation
3. Verify category browse pages show new descriptions
4. Verify methodology page has the new section
5. Visual check that `.plain-summary` styling looks correct in dark and light themes
