# Evidence Policy

**Purpose:** Define what counts as evidence in this project and how claims must be presented.

**Scope:** All public-facing content (kryptosbot.com, README, reports), all internal docs that
influence future analysis, and all script headers/comments.

---

## Claim Classification (Mandatory)

Every nontrivial claim must be one of:

| Tag | Definition | Requirements |
|-----|-----------|-------------|
| **[PUBLIC FACT]** | Verified by reputable public reporting or primary-source statements | Citation required |
| **[DERIVED FACT]** | Deterministic consequence of PUBLIC FACTS | Repro command required |
| **[INTERNAL RESULT]** | Empirical result produced by this repo | Repro command + artifact pointers + acceptance criteria |
| **[HYPOTHESIS]** | Plausible claim not yet proven | Test plan required |
| **[EXPLORATORY]** | Post-hoc observation with no independent validation | Must state this explicitly |
| **[RETRACTED]** | Previously stated claim now known to be wrong or unsupported | Correction note + date |

**Hard rule:** Nothing may appear as ground truth unless it is [PUBLIC FACT] or [DERIVED FACT].

---

## What Counts as Evidence

### Sufficient for public-facing factual language:
- Deterministic proofs (algebraic impossibility, Bean constraint violations)
- Exhaustive searches with stated assumptions and repro commands
- Pre-registered predictions that were subsequently confirmed

### Sufficient for internal results (labeled accordingly):
- Reproducible computational outputs with artifact pointers
- Statistical tests with proper null models and multiple-testing correction
- Cross-validation results

### NOT evidence (must be labeled exploratory or removed):
- Post-hoc pattern matches (discovered from data, not predicted)
- Descriptive fits with zero predictive power (e.g., the KRYPTOS × SEVEN table)
- Thematic associations (e.g., "these letters spell KGB")
- Numerological observations (e.g., "24 appears in four places")
- In-sample accuracy without cross-validation
- A script existing and running without errors
- A p-value from a test that was selected after seeing the data

---

## Language Discipline

### Allowed (use these):
- "tested," "observed," "computed," "measured"
- "under model X," "conditional on," "assuming"
- "exploratory," "post-hoc," "descriptive only"
- "does not independently validate"
- "suggestive but not proof"
- "failed adversarial review," "failed cross-validation"

### Requires full justification:
- "proves" — only for deterministic algebraic proofs
- "confirms" — only for pre-registered predictions
- "significant" — must include p-value, null model, correction method
- "evidence" — must specify what it is evidence FOR and AGAINST
- "shows" — must not be used for model-conditional results without stating the model

### Prohibited:
- "strong evidence" for model-conditional results
- "confirms" for post-hoc findings
- "consensus" when provenance is lost or sample is this project only
- "independently confirms" when the "independent" test uses the same data/model
- Any language that conflates hypothesis source, test execution, and evidentiary status

---

## Model-Conditional Results

Most findings in this project depend on a specific cipher model (typically KA-autokey Vigenère).
Model-conditional results MUST:

1. State the model at the point of claim (not buried in a footnote)
2. Report cross-model stability (e.g., Jaccard overlap across models)
3. Not be presented as intrinsic properties of K4 unless independently confirmed
4. Include the caveat that the model itself is unproven

---

## Post-Hoc Findings

A finding discovered from the data (not predicted in advance) has reduced evidentiary weight.
Post-hoc findings MUST:

1. Be labeled "post-hoc" or "exploratory" at the point of claim
2. Report cross-validation results if classification accuracy is claimed
3. Not appear in section headers that imply confirmation (e.g., "Confirmed Findings")
4. Be subject to adversarial review before any public presentation

---

## Retraction and Correction

When a previously stated claim is invalidated:

1. Remove it from findings/summary pages (do not merely soften the language)
2. Add a `[RETRACTED]` tag with date and reason
3. Trace downstream claims that depended on it and review each one
4. Update MEMORY.md if the retracted claim was influencing agent behavior

---

## Script Results ≠ Evidence

A script running to completion and producing output does not make its results evidence.
Results become evidence only when they pass:

1. Unit tests pass
2. Reference implementation reproduces the outcome
3. Invariant checks (bijection, reversibility, crib alignment)
4. Reproduction from a clean process
5. Adversarial review of the statistical methodology

---

*Adopted 2026-03-31 as part of the evidence-hardening pass.*
