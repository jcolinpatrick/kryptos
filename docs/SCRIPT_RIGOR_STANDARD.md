# Script Rigor Standard

**Purpose:** Define quality tiers for experiment scripts and establish a standard header format
so that scripts are honestly framed and their outputs are not confused with evidence.

---

## Script Tiers

Every script in `scripts/` falls into one of these tiers:

| Tier | Name | Criteria | Retention |
|------|------|----------|-----------|
| **A** | Production-grade evidentiary tool | Clear hypothesis, repro command, proper controls/nulls, result interpretable, connects to live RQ | Retain, reference in eliminations |
| **B** | Useful exploratory tool | Clear purpose, reproducible, but exploratory or lacking controls | Retain with honest header |
| **C** | Historical artifact | Superseded, one-off, or no longer connected to active research | Retain with deprecation warning |
| **D** | Low-value / misleading | Redundant, poorly justified, overclaims in comments, or creates false confidence | Rewrite header or archive |
| **E** | Delete | No defensible purpose, broken, or actively misleading | Delete |

### Evaluation criteria (in order of importance):
1. **Clear hypothesis or function** — What question does this answer?
2. **Reproducibility** — Can someone run it from a clean checkout?
3. **Controls** — Does it compare against a null model or baseline?
4. **Result interpretability** — Can the output be understood without reading the code?
5. **Provenance** — Are inputs imported from constants, not hardcoded?
6. **Uniqueness** — Is this the only script testing this hypothesis?
7. **Comment honesty** — Do comments describe what the code does, or smuggle in theory prestige?
8. **Connection to live research** — Is this answering an open question?

### Important distinctions:
- A script based on a "weird" idea is NOT automatically Tier D/E. If it tests a formally
  specifiable hypothesis with proper controls, it may be Tier A or B regardless of how
  unconventional the hypothesis source is.
- A script with beautiful code but overclaimed comments is worse than ugly code with
  honest comments.
- Passing pytest does not make a script scientifically valuable.

---

## Standard Header Format

All retained research scripts (Tier A-C) should include this header:

```python
"""
Script: e_<family>_<nn>_<description>.py
Tier: A|B|C
Purpose: <one sentence: what this tests>
Hypothesis source: <where the idea came from — literature, community, exploratory search, etc.>
Evidentiary status: <what the output proves, if anything>
Interpretation limits: <what the output does NOT prove>
Dependencies: <what constants/models this assumes>
Output: <what the script produces and where>
Repro: PYTHONPATH=src python3 -u <path>
"""
```

### Header rules:
- **Purpose** must be procedural ("tests whether X produces score > Y"), not narrative
  ("explores the deep connection between K4 and the Berlin Wall")
- **Hypothesis source** must be honest — if the idea came from numerology, say so
- **Evidentiary status** must distinguish between "eliminates family X" and "explores idea Y"
- **Interpretation limits** must state what the script CANNOT prove, especially:
  - Whether positive results require independent validation
  - Whether the test is model-conditional
  - Whether the search was post-hoc

---

## Comment Discipline

### Comments should:
- Explain what code does (mechanically)
- Note non-obvious algorithmic choices
- Flag known limitations or assumptions
- Reference the specific experiment ID and exhaustion log entry

### Comments should NOT:
- Assert that the motivating theory is credible
- Use words like "elegant," "remarkable," "striking," or "profound"
- Treat exploratory results as findings
- Narrate a story about why K4 works a certain way
- Claim that thematic resonance is evidence

### Example of BAD comment:
```python
# The seven palette letters {B,G,I,K,O,W,Z} contain KGB — a remarkable
# Cold War signature hidden by Sanborn in the null positions
```

### Example of GOOD comment:
```python
# Test whether palette letters correlate with Cold War acronyms.
# Post-hoc observation only — any 7-letter set can be pattern-matched
# to thematic words. Not evidence of intentional encoding.
```

---

## Deprecation Warnings

Scripts classified as Tier C should include:

```python
# DEPRECATED: This script is retained as a historical artifact.
# It has been superseded by <newer script or proof>.
# Do not cite its results as current findings.
```

Scripts classified as Tier D should include:

```python
# WARNING: This script's comments or methodology overclaim.
# Results should not be treated as evidence without independent validation.
# See docs/SCRIPT_RIGOR_STANDARD.md for evaluation criteria.
```

---

## Relationship to Exhaustion Log

The `exhaustion_log.json` tracks all scripts and their status. Script tier assignments
should be reflected in the log's `status` field:
- Tier A/B active scripts: `"status": "active"` or `"status": "promising"`
- Tier C archived scripts: `"status": "exhausted"` or `"status": "superseded"`
- Tier D/E scripts: should be either fixed or removed from the active corpus

---

*Adopted 2026-03-31 as part of the evidence-hardening pass.*
