# Claims Ladder — Evidence Classification for K4 Research

**Purpose:** A single, durable framework for classifying every claim in the project.
All public copy, internal docs, reports, and code comments must use language
consistent with these levels. Created as part of the 2026-04-01 audit remediation.

---

## The Four Levels

### Level A — Proven within stated assumptions

**What it means:** A deterministic, reproducible result that holds given explicitly
stated preconditions (e.g., correct cribs, correct CT, additive key model).
Mathematical proofs and exhaustive eliminations where 100% of the parameter space
was checked fall here.

**Required evidence:**
- Algebraic proof or complete enumeration
- Explicit list of assumptions/preconditions
- Reproduction command
- Peer-verifiable logic (not just "the code says so")

**Allowed language:**
- "proven impossible under [stated conditions]"
- "mathematically eliminated assuming [conditions]"
- "structurally incompatible with [constraint]"

**Forbidden language:**
- "eliminated" without conditions
- "impossible" without conditions
- "proven" without stating what is assumed

**Public pages:** May use "ruled out" or "eliminated" IF the scope condition is
visible in the same paragraph or in a linked scope-limitations section.

**Internal docs:** Must always state the assumptions inline or cite the tier.

---

### Level B — Exhaustively negative within tested scope

**What it means:** Every configuration within a defined parameter space was tested
and produced noise-level results. The elimination is solid for the specific model
tested but does NOT extend to untested variants, multi-layer combinations, or
different parameter ranges.

**Required evidence:**
- Defined parameter space (family, widths, periods, alphabets, key models)
- Configuration count
- Best score achieved
- Comparison to random baseline
- Reproduction command

**Allowed language:**
- "exhaustively tested within [scope] — no signal"
- "eliminated under direct positional correspondence at [parameter range]"
- "noise-level results across [N] configurations"

**Forbidden language:**
- "eliminated" without scope
- "impossible" (reserved for Level A)
- "proven" (reserved for Level A)
- Implying the result extends beyond the tested parameter space

**Public pages:** "We tested [N] configurations of [family] — no results above
random." Always include a scope-limitations note.

**Internal docs:** Must specify the exact parameter ranges tested.

---

### Level C — Descriptive anomaly / exploratory signal

**What it means:** A pattern or statistical observation that was discovered
post-hoc (from the data, not predicted in advance). Has not been corrected
for the full search breadth that produced it. May be model-conditional.
Does not prove anything about the cipher mechanism.

**Required evidence:**
- Description of the observation
- Null model and raw p-value
- Whether data-discovered or pre-specified
- Known dependence caveats
- What the observation does NOT prove
- Reproduction command

**Allowed language:**
- "descriptive anomaly"
- "post-hoc observation"
- "uncorrected p = [value] under [null model]"
- "model-conditional"
- "ciphertext-intrinsic under [convention]"

**Forbidden language:**
- "significant" without specifying "uncorrected" and null model
- "proof" or "evidence for [mechanism]"
- "model-independent" (unless truly invariant across all cipher models)
- "strongest anomaly" without search-breadth context
- Any language implying the observation explains how K4 was encrypted

**Public pages:** Must be labeled "observation" or "anomaly." Must include
a caveat about post-hoc discovery and model-conditionality where applicable.

**Internal docs:** Must include raw and (if available) corrected p-values,
the null model, and dependence structure.

---

### Level D — Hypothesis / lead / thematic inference

**What it means:** A plausible conjecture not yet supported by quantitative
evidence. Includes thematic connections (KRYPTOS×SEVEN keywords), physical-
installation hypotheses, and untested cipher models.

**Required evidence:**
- Falsifiable statement
- Test plan (what would confirm or refute)
- Why it is worth testing

**Allowed language:**
- "hypothesis"
- "working model"
- "open question"
- "untested"
- "thematic observation (not evidence)"

**Forbidden language:**
- "finding" or "result"
- "evidence" or "signal"
- Any language implying quantitative support

**Public pages:** Must be clearly separated from Levels A-C. Use "hypothesis"
or "open question" framing.

**Internal docs:** Must include a test plan.

---

## Quick Reference: Common Phrases

| Instead of... | Use... | Why |
|---|---|---|
| "ELIMINATED" (bare) | "eliminated within [scope] (Level B)" or "proven impossible under [conditions] (Level A)" | Distinguishes proof from search |
| "model-independent" | "ciphertext-intrinsic under Beaufort A=0 convention" or "deterministic given CT and cribs" | The interpretation as keystream IS model-dependent |
| "strongest anomaly" | "lowest uncorrected p-value among tested anomalies" | No search-breadth correction applied |
| "35/35 PERFECT" | "in-sample post-hoc fit (35/35)" | No holdout validation; LOO-CV = 47% |
| "only remaining model" | "only structured model surviving Bean constraints under additive-key assumptions" | Bean requires additive model |
| "significant" (bare) | "uncorrected p = X under [null model]" | Must specify null and correction status |
| "proof" | "proof under [stated assumptions]" | Always condition on assumptions |
| "zero positive findings" | "zero positive findings within tested cipher families and parameter ranges" | Does not cover untested methods |

---

## Applying This Framework

### When writing new docs or reports
1. Classify every factual claim at Level A, B, C, or D
2. Use only the allowed language for that level
3. If a claim spans levels (e.g., "eliminated" for a family that has both proofs and searches), use the weakest applicable level or separate the claims

### When reviewing existing docs
1. Find claims using the forbidden language for their actual evidence level
2. Rewrite using the allowed language
3. Add missing scope conditions

### When writing public copy
1. Lead with the strength of the elimination engine (Level A and B)
2. Treat Level C observations as interesting but inconclusive
3. Never present Level D hypotheses as findings
4. Include a "How to read claims" link on pages with mixed evidence levels

### Bean constraint conditionality
All Bean-based eliminations (Level A proofs at specific periods, Level B exhaustive searches)
must note that Bean constraints assume an additive key model: CT[i] = f(PT[i], K[i]) mod 26
for some fixed function f. If K4 uses a non-additive cipher (lookup table, physical overlay,
grid-based system), Bean constraints do not apply and those eliminations are invalidated.

This condition must appear:
- In the Tier 1 header of `docs/elimination_tiers.md`
- In the methodology page's Bean section
- In any document that uses Bean elimination as a premise

---

*Created 2026-04-01 as part of audit remediation. Authoritative for all future claim language.*
