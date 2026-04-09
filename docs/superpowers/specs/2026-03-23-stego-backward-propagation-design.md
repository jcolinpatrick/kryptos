---
status: HISTORICAL research plan — not authoritative
authored: 2026-03-23 (pre-dates palette retirement)
palette_dependency: yes — this plan materially depends on the retired {B,G,I,K,O,W,Z} palette construct and/or its derived null-mask rules
retired_on: 2026-04-01 (palette retirement); banner added 2026-04-09 (AUDIT-2 closure)
superseded_by: docs/a1_score_conditioned_null_report.md, memory/retired/README.md, MEMORY.md
---

> # HISTORICAL / PALETTE-DEPENDENT — NOT LIVE DOCTRINE
>
> This research plan was authored 2026-03-23 on top of the palette
> `{B,G,I,K,O,W,Z}` construct. That construct was **retired on 2026-04-01**
> as a post-hoc selection artifact (score-conditioned null; SA produces 11
> distinct letters on K4, indistinguishable from shuffled controls p=0.30).
> Any conclusion, predicted signal, or test plan in this file that depends
> on the palette, the mod-35 rule, BCL enrichment, or the Polybius
> row-selection model is **historical only** and must not be used to drive
> live research. See `memory/retired/README.md`, `docs/superpowers/README.md`,
> and `docs/a1_score_conditioned_null_report.md`.

# Stego Backward Propagation Pipeline — Design Spec

**Date:** 2026-03-23
**Author:** Colin Patrick + Claude (Opus 4.6)
**Status:** Draft

---

## 1. Problem Statement

After 950+ experiments and 884B+ configurations, every computational approach to K4 has been exhausted. The current scoring methodology (`score_candidate()`) evaluates candidates by checking whether cribs appear at fixed positions in the decrypted output. This assumes a direct, single-operation mapping CT[i] → PT[i].

**The limitation:** This scoring methodology cannot evaluate hypotheses about the key generation *mechanism* — only about the key *values*. We have rich, statistically validated properties of the stego layer that constrain the cipher layer, but no pipeline that propagates those constraints forward.

**The insight:** The stego layer (null palette, KRYPTOS×SEVEN Polybius, pos%7×pos%5 table) and cipher layer (Beaufort keystream with palette-enriched values) share the same keywords and grid structure. This coupling is not coincidence — it constrains the class of key generation mechanisms. By propagating stego properties into cipher constraints, we can produce a formal specification that any K4 solution must satisfy.

**The goal:** Even if we cannot decrypt K4, proving out the stego layer and deriving tight cipher constraints provides a foundation for future mathematicians to complete the solve.

---

## 2. Design Principles

- **Bean constraints are mathematical ground truth.** They derive from the ciphertext and known plaintext, not from Sanborn's statements.
- **Sanborn's statements are adversarial data.** They may contain errors, misdirection, or oversimplification. Do not treat them as axioms.
- **Coupling constraints are the primary novel contribution.** Bean found statistical anomalies; our stego work *explains* them. This explanatory power is the new scoring signal.
- **This is an analytical tool, not a search tool.** It constrains the mechanism space rather than brute-forcing it.
- **Stdlib only.** All new code lives in `src/kryptos/kernel/` with zero external dependencies.

---

## 3. Constraint Propagation Chain

Three layers, each constraining the next:

### Layer 1 — Stego Layer (Confirmed)

| ID | Property | Evidence | p-value | Source |
|----|----------|----------|---------|--------|
| S1 | Two systems confirmed | Sanborn dedication + Scheidt | [PRIMARY SOURCE] | `memory/confirmed_findings.md` |
| S2 | Null palette = {B,G,I,K,O,W,Z} | 17 consensus null positions use only 7 distinct letters | 6.3e-5 (MC, palette restriction) | `results/palette_deep_investigation.json` |
| S3 | 17 consensus null positions | {0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85} | derived from S2 | `memory/confirmed_findings.md` |
| S4 | (pos%7, pos%5) classifies 35/35 palette positions | KRYPTOS period × SEVEN period. **Note:** 35 positions = all CT97 positions containing a palette letter. 17 are consensus nulls, 18 are real characters (including 4 inside crib ranges: positions 30,31,70,73). The classification separates null from real WITHIN palette positions — the 4 crib-range positions are correctly classified as "real" by the cipher layer's palette enrichment (C×S-1). | post-hoc, 0 DOF | `results/palette_mod35_tiebreaker.json` |
| S5 | Palette = cols 0,3 of 5-wide KA Polybius | KRYPTOS×SEVEN dual-keyword generation | ≈1/1,672 (MC) | `memory/kryptos_seven_palette_generation.md` |
| S6 | Zero nulls in crib ranges | No consensus null in [21-33] or [63-73] | structural | derived |
| S7 | 35 palette positions = FIVE × SEVEN | Cylinder seam × palette generator | structural | `memory/cylinder_five_discovery.md` |

**S6 is the critical bridge:** Because no null positions fall within either crib range, Bean constraints derived from direct CT↔PT at crib positions remain valid regardless of the stego model. This validates Layer 2.

### Layer 2 — Cipher Layer (Derived from Bean + keystream work)

| ID | Property | Evidence | p-value | Source |
|----|----------|----------|---------|--------|
| C1 | Beaufort A=0 keystream at 24 cribs: `JLJODEGKUKKKLOCGGBGOKTRU` | Variant specificity (BCL enrichment selects Beaufort A=0) | 6.27e-4 | `results/bcl_palette_keystream.json` |
| C2 | Bean EQ: k[27]=k[65] (variant-independent). Under Beaufort A=0: both = G(6). Under Vigenere A=0: both = Y(24). | Mathematical identity (variant-independent) | exact | Bean 2021 |
| C3 | 242 Bean inequalities | Variant-independent (all 3 cipher variants) | exact | Bean 2021 |
| C4 | Non-periodic (all periods 1-∞) | Mathematical proof via Bean inequalities | exact | `memory/elimination_ledger.md` |
| C5 | AP {G(6),K(10),O(14)} at 12/24 positions | Step-4 arithmetic progression in A=0 | ~4e-6 specific, ~0.001 any | `results/keystream_ap_investigation.json` |
| C6 | Keystream IC = 0.0797 at crib positions | 2.07× random (0.0385) | 0.0047 | `results/model_b_deep_investigation.json` |
| C7 | Minor differences sum ≤ 21 | Bean permutation test | 1/5,520 | Bean 2021 |
| C8 | Same-PT clustering mean ≤ 3.6 | Bean permutation test | 1/240 | Bean 2021 |

### Layer 3 — Stego-Cipher Coupling (NEW — the core contribution)

These constraints are derived by intersecting Layers 1 and 2:

**C×S-1: Keystream values are palette-enriched**
- Observation: 13/24 keystream values ∈ {B,G,I,K,O,W,Z} (expected: 6.46)
- Joint null: p = 1.4e-7 (MC 50M, proper joint simulation)
- Derives from: S2 (palette) + C1 (keystream)
- **Constraint:** The key generator preferentially produces values in the palette set.
- Falsifiable: a mechanism that produces uniformly distributed keystream values at crib positions would violate this.

**C×S-2: Palette enrichment is a mod-5 KA structure (EXPLAINS Bean's mod-5 finding)**
- Observation: Every palette letter has KA_index mod 5 ∈ {0, 3}
  - B(KA=8, 8%5=3), G(KA=13, 13%5=3), I(KA=15, 15%5=0), K(KA=0, 0%5=0), O(KA=5, 5%5=0), W(KA=23, 23%5=3), Z(KA=25, 25%5=0)
- This IS Bean's reversed-KA mod-5 finding (13/24, p≈1/1,470) — our stego work explains WHY it exists.
- Derives from: S5 (5-wide KA Polybius) + C1 (keystream)
- **Constraint:** The key generator produces values whose KA indices are preferentially ≡ 0 or 3 (mod 5). The key generation process has a mod-5 component.
- **Relationship to C×S-1:** C×S-1 (palette membership) logically implies C×S-2 (mod-5 residue), since all palette letters satisfy the mod-5 condition. However, C×S-2 is STRICTLY WEAKER: 14/24 keystream values satisfy mod-5 ∈ {0,3} while only 13/24 are palette members. The extra position passes mod-5 without being in the palette. C×S-2 provides the EXPLANATORY mechanism (Polybius column structure) for the observation in C×S-1. For scoring, C×S-1 and C×S-2 are not independent — use C×S-1 as the primary metric and C×S-2 as the structural explanation.
- Falsifiable: a mechanism with no mod-5 structure would violate this.

**C×S-3: AP {G,K,O} lives entirely within the palette**
- Observation: All three AP members are palette letters
  - G → KA Polybius col 3, K → col 0, O → col 0
- AP has step-4 in standard A=0 alphabet but is NOT arithmetic in KA ordering (K→O gap=5, O→G gap=8)
- Derives from: S2 (palette) + C5 (AP)
- **Constraint:** The mechanism has arithmetic regularity in the STANDARD alphabet but structural regularity in the KA alphabet. Both alphabets participate in key generation.
- Falsifiable: a mechanism using only one alphabet (pure AZ or pure KA) would need to explain step-4 in AZ AND column-clustering in KA simultaneously.

**C×S-4: Dual-alphabet structure**
- The stego layer operates in KA space (5-wide KA Polybius grid)
- The cipher layer has step-4 AP in standard A=0 space
- Both layers couple through the palette
- Derives from: C×S-2 + C×S-3
- **Constraint:** The cipher mechanism involves BOTH alphabets — likely a tableau with a KA row and an AZ row, or a Quagmire-type structure mapping between them.

**C×S-5: Key source is a 5-wide grid [ABDUCTIVE — weaker than C×S-1 through C×S-4]**
- What class of key generators produce mod-5 constrained output?
  - Polybius lookup in a 5-wide grid (inherently mod-5)
  - Addition/subtraction of values that are multiples of 5
  - Table lookup with 5-periodic structure
  - Linear recurrence with coefficients divisible by 5
- Derives from: C×S-2 + Sanborn capability constraint (hand-executable with graph paper)
- **Constraint:** The key is likely read from or derived from the same 5-wide KA Polybius grid used for null generation. The encoding chart is the key source.
- **Inference type:** ABDUCTIVE (best explanation), not deductive. The mod-5 structure is statistically confirmed; the 5-wide grid is the most parsimonious explanation but not the only one. Scored as Tier 3 (structural) in the hierarchy, NOT Tier 1.
- This connects to the Antipodes proof: K4 is identical on both sculptures despite different geometric arrangements, so the key CANNOT come from the sculpture geometry — it must come from the chart.

### Propagation Chain (Visual)

```
S5 (palette = Polybius cols 0,3)  +  C1 (keystream at 24 positions)
            |                                    |
            +-------- C×S-1 (palette enrichment p=1.4e-7) --------+
                                |
            +-------- C×S-2 (mod-5 KA constraint) --------+
                                |
S2 (palette) + C5 (AP)  →  C×S-3 (AP ⊂ palette, step-4 in AZ)
                                |
            +-------- C×S-4 (dual alphabet: AZ + KA) --------+
                                |
            +-------- C×S-5 (key source = 5-wide grid = chart) --------+
```

**The punchline:** The stego layer doesn't just identify null positions. It reveals the key generation structure. Two systems, one grid.

---

## 4. Constraint Hierarchy

Constraints are tiered by evidential strength:

| Tier | Source | Role | Count |
|------|--------|------|-------|
| **Tier 0: Hard Gates** | Bean + keystream derivation | Pass/fail — violation eliminates | 4 (HC-1 to HC-4) |
| **Tier 1: Coupling (PRIMARY)** | Our stego-cipher coupling — NEW | Main scoring dimensions | 4 (C×S-1 to C×S-4) |
| **Tier 2: Bean Statistical** | Bean 2021 | Supporting evidence | 2 (SC-4, SC-5) |
| **Tier 3: Structural** | Qualitative/abductive | Soft filter | 4 (XC-1 to XC-4) |

### Tier 0 — Hard Constraints

| ID | Constraint | Test |
|----|-----------|------|
| HC-1 | Must produce keystream `JLJODEGKUKKKLOCGGBGOKTRU` at 24 crib positions | Exact match of 24 values |
| HC-2 | k[27] = k[65] (variant-independent Bean equality) | Equality check. Value depends on variant: G under Beaufort A=0, Y under Vigenere A=0 |
| HC-3 | 242 Bean inequalities satisfied | All-pairs check (variant-independent) |
| HC-4 | Mechanism is non-periodic | Declared property of the mechanism (proven mathematically for all periods 1-∞ on CT97; not testable from 24 values alone) |

### Tier 1 — Coupling Constraints (PRIMARY)

| ID | Constraint | Scoring | Notes |
|----|-----------|---------|-------|
| C×S-1 | ≥13/24 keystream values in palette {B,G,I,K,O,W,Z} | Count (threshold 13) | Primary metric; implies C×S-2 |
| C×S-2 | KA_index(key) mod 5 ∈ {0,3} at ≥14/24 positions | Count (threshold 14) | Structural explanation for C×S-1; strictly weaker (14 pass vs 13 palette). NOT scored independently — used to verify the explanatory mechanism |
| C×S-3 | AP {G,K,O} at ≥12/24 positions, all AP members ∈ palette | Count + membership check | Independent of C×S-1 (tests a specific subset pattern, not just palette membership) |
| C×S-4 | Mechanism involves both AZ and KA alphabets | Binary | From C×S-2 (KA structure) + C5 (AZ arithmetic) |

### Tier 2 — Bean Statistical Constraints

| ID | Constraint | Scoring | Computation |
|----|-----------|---------|-------------|
| SC-4 | Minor differences sum ≤ 21 | Numeric (lower = better) | For each repeated PT letter, find shortest distance between corresponding CT letters in standard alphabet. Sum all distances. (Bean Table 2: 10 values from {K,R,Y,P,T,O,S} set) |
| SC-5 | Same-PT clustering mean ≤ 3.6 | Numeric (lower = better) | For each repeated PT letter, compute shortest distances between ALL pairs of corresponding CT letters. Take the mean of all 13 values. (Bean Table 3) |

### Tier 3 — Structural Constraints

| ID | Constraint | Scoring | Inference type |
|----|-----------|---------|----------------|
| XC-1 | Dual-alphabet (AZ arithmetic + KA structure) | Binary | Deductive (from C×S-3 + C×S-4) |
| XC-2 | Mod-5 key generation component | Binary | Deductive (from C×S-2) |
| XC-3 | Hand-executable with graph paper | Binary | Historical (Sanborn capability) |
| XC-4 | Key derived from 5-wide grid structure | Binary | **Abductive** (best explanation for mod-5, not the only one) |

---

## 5. Implementation

### Module placement

```
src/kryptos/kernel/constraints/stego.py      — Stego layer formalization
src/kryptos/kernel/constraints/coupling.py   — Stego-cipher coupling derivation
src/kryptos/kernel/scoring/compliance.py     — Compliance scorer
scripts/analysis/stego_proof_pipeline.py     — Full pipeline script
docs/constraint_spec.md                      — Output: formal constraint specification
```

All modules use stdlib only. All import constants from `kryptos.kernel.constants`.

### 5.1 `stego.py` — Stego Layer Proof

Formalizes all Layer 1 properties as reproducible statistical tests.

**Data structures:**

```python
@dataclass
class StegoProperty:
    id: str              # "S1" through "S7"
    name: str            # human-readable name
    observed: Any        # measured value
    expected: Any        # expected under null hypothesis
    p_value: float       # MC or exact
    method: str          # "binomial", "permutation", "exact", "mc"
    status: str          # "CONFIRMED", "HYPOTHESIS", "POST_HOC"
    artifact: str        # file path for reproduction
```

**Functions:**

| Function | Returns | Computes |
|----------|---------|----------|
| `palette_restriction(ct, null_positions)` | StegoProperty (S2) | P(≤7 distinct letters in 17 draws from 26) |
| `null_position_classification(ct, null_positions)` | StegoProperty (S4) | (pos%7,pos%5) accuracy on palette positions |
| `polybius_generation(palette, keyword1, keyword2)` | StegoProperty (S5) | MC test: P(random keyword pair → this palette) |
| `crib_null_avoidance(null_positions, crib_ranges)` | StegoProperty (S6) | Boolean + combinatorial probability |
| `full_stego_proof(ct)` | list[StegoProperty] | All S1-S7 |

### 5.2 `coupling.py` — Constraint Propagation

Derives Layer 3 coupling constraints by intersecting stego and cipher properties.

**Data structures:**

```python
@dataclass
class DerivedConstraint:
    id: str              # "CxS-1" through "CxS-5"
    name: str            # human-readable
    description: str     # formal statement of the constraint
    evidence: list[str]  # S and C property IDs this derives from
    p_value: float       # statistical significance of the coupling
    constraint_type: str # "HARD", "STATISTICAL", "STRUCTURAL"
    falsifiable: str     # what would disprove this constraint
```

**Functions:**

| Function | Returns | Computes |
|----------|---------|----------|
| `keystream_palette_enrichment(keystream, palette)` | DerivedConstraint (C×S-1) | Count + binomial + joint MC |
| `mod5_ka_structure(keystream, ka_alphabet)` | DerivedConstraint (C×S-2) | KA mod-5 residue distribution |
| `ap_palette_containment(keystream, palette)` | DerivedConstraint (C×S-3) | AP detection + palette membership |
| `dual_alphabet_structure(keystream)` | DerivedConstraint (C×S-4) | AZ regularity vs KA regularity |
| `key_source_grid_constraint()` | DerivedConstraint (C×S-5) | Qualitative + Antipodes proof |
| `propagate_all(ct, keystream, palette)` | list[DerivedConstraint] | Full chain |

### 5.3 `compliance.py` — New Scoring Pipeline

Parallel scoring path alongside `score_candidate()` for mechanism evaluation (does not replace it).

**Data structures:**

```python
@dataclass
class MechanismDescription:
    """Metadata a proposed mechanism declares about itself."""
    name: str                    # e.g. "Beaufort with Polybius grid key"
    uses_ka: bool                # mechanism involves KA alphabet
    uses_az: bool                # mechanism involves standard AZ alphabet
    grid_width: int | None       # width of any grid used (e.g. 5)
    hand_executable: bool | None # can be done with graph paper, no computer
    periodic: bool | None        # does the mechanism produce periodic keystream
    key_source: str | None       # description of key source (e.g. "5-wide KA Polybius lookup")
    notes: str = ""              # free-form notes

@dataclass
class ComplianceScore:
    hard_pass: int       # count of Tier 0 constraints passed
    hard_fail: int       # count of Tier 0 constraints failed
    hard_unknown: int    # count of Tier 0 constraints not testable
    coupling_score: float  # Tier 1: weighted sum (0.0 to 4.0, C×S-1 through C×S-4)
    bean_score: float      # Tier 2: weighted sum
    structural_score: float # Tier 3: count of matches (0 to 4)
    total: float           # composite score
    details: dict          # per-constraint results
    verdict: str           # "ELIMINATED", "PARTIAL", "COMPLIANT"
```

**Functions:**

| Function | Returns | Purpose |
|----------|---------|---------|
| `check_hard_constraints(keystream_at_cribs, mechanism: MechanismDescription)` | dict[str, str] | HC-1 to HC-4: PASS/FAIL/UNKNOWN. HC-4 uses `mechanism.periodic` declaration |
| `check_coupling_constraints(keystream_at_cribs, mechanism: MechanismDescription)` | dict[str, float] | C×S-1 to C×S-4: 0.0 to 1.0 each |
| `check_bean_constraints(keystream_at_cribs)` | dict[str, float] | SC-4, SC-5: numeric |
| `check_structural_constraints(mechanism: MechanismDescription)` | dict[str, bool] | XC-1 to XC-4: True/False |
| `score_mechanism_compliance(keystream_at_cribs, mechanism_props)` | ComplianceScore | Full evaluation |

**Verdict logic:**
- Any HC failure → ELIMINATED
- All HC pass/unknown + Tier 1 ≥ 3.0/4.0 → COMPLIANT (at least 3 of 4 coupling constraints met)
- All HC pass/unknown + Tier 1 < 3.0 → PARTIAL
- Note: C×S-2 is NOT scored independently (subsumed by C×S-1). Effective Tier 1 scoring is on C×S-1, C×S-3, C×S-4 (quantitative) + C×S-4 (binary) = max 4.0

### 5.4 `stego_proof_pipeline.py` — Pipeline Script

Runs end-to-end:

```
1. Import CT, cribs, keystream from constants
2. Run full_stego_proof() → Layer 1 properties with p-values
3. Run propagate_all() → Layer 3 coupling constraints
4. Generate constraint_spec.md with all evidence
5. (Optional) Score a proposed mechanism via score_mechanism_compliance()
```

Output: `docs/constraint_spec.md` + console summary with all p-values.

### 5.5 `constraint_spec.md` — Formal Output Document

Three sections matching the constraint hierarchy:

1. **Hard Constraints** — HC-1 through HC-4 with exact values
2. **Coupling Constraints** — C×S-1 through C×S-5 with p-values and derivation chains
3. **Supporting Constraints** — SC-4, SC-5, XC-1 through XC-3

Plus a **Mechanism Compliance Checklist** that any researcher can use to evaluate a proposed solution.

---

## 6. Success Criteria

### Minimum success (achievable now)

- [ ] All stego properties formalized with reproducible statistical tests
- [ ] Constraint propagation chain implemented and verified
- [ ] Coupling constraints demonstrated to explain Bean's mod-5 finding
- [ ] Formal constraint specification produced
- [ ] Compliance scorer functional and tested against known mechanisms (Gromark, periodic, autokey) to verify they correctly score as ELIMINATED

### Stretch success

- [ ] Coupling constraints narrow surviving mechanism space to a single family
- [ ] Constraint spec tight enough for algebraic derivation of key generation rule
- [ ] 5-wide KA Polybius grid identified as the encoding chart structure

### Anti-goals

- This pipeline does NOT search for solutions
- This pipeline does NOT replace existing crib-score for brute-force work
- This pipeline does NOT require Sanborn's statements to be true

---

## 7. Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Coupling constraints are post-hoc | Flag clearly in spec; compute corrected p-values; the JOINT significance (p=1.4e-7) survives correction |
| Constraint spec may be too loose (many mechanisms satisfy it) | Prioritize Tier 1 coupling constraints which are highly specific |
| Constraint spec may be too tight (nothing satisfies it) | This would itself be a finding — implies the mechanism is genuinely novel |
| Bean's statistics assume direct CT→PT | S6 (zero nulls in crib ranges) validates this assumption for crib positions specifically |

---

## 8. Prerequisites

Before implementation, add the following constants to `kernel/constants.py` (with import-time `_verify()` checks):

```python
NULL_PALETTE = frozenset("BGIKOWZ")
CONSENSUS_NULL_POSITIONS = frozenset({0,1,2,5,8,12,14,20,36,52,58,59,74,75,78,84,85})
BEAUFORT_KEYSTREAM_AT_CRIBS = "JLJODEGKUKKKLOCGGBGOKTRU"  # 24 chars, Beaufort A=0
```

These are currently scattered across memory files and ad-hoc derivations. Centralizing them in `constants.py` ensures `_verify()` catches any drift.

---

## 9. Relationship to Existing Code

- `kernel/constraints/bean.py` — Bean EQ/INEQ checking. Used by `compliance.py` for HC-2, HC-3. **Note:** SC-4 (minor differences) and SC-5 (same-PT clustering) are NOT currently implemented in `bean.py` — they will be new computations in `compliance.py`.
- `kernel/scoring/aggregate.py` — Existing `score_candidate()` and `score_candidate_free()`. NOT replaced; `compliance.py` is a parallel scoring path for mechanism evaluation.
- `kernel/constants.py` — Source of truth for CT, cribs, keystream values, palette. All new modules import from here. New constants added per Section 8.
- `kernel/alphabet.py` — KA alphabet singleton used by `coupling.py` for mod-5 analysis.

No existing code is modified. This is purely additive.

---

## 10. Test Plan

| Test file | Coverage |
|-----------|----------|
| `tests/test_stego.py` | Unit tests for each `StegoProperty` computation against known values. Verify S2 p-value matches MC, S4 classifies 35/35, S6 confirms zero nulls in crib ranges. |
| `tests/test_coupling.py` | Unit tests for each `DerivedConstraint` derivation. Verify C×S-1 counts 13/24, C×S-2 counts 14/24, C×S-3 detects AP ⊂ palette. Verify C×S-1 → C×S-2 implication. |
| `tests/test_compliance.py` | Integration tests: (1) Known-eliminated mechanisms (periodic, autokey, Gromark) score as ELIMINATED. (2) The actual K4 Beaufort A=0 keystream scores as COMPLIANT. (3) Random keystreams score as PARTIAL or ELIMINATED. |

---

*Spec authored: 2026-03-23. Revised after code review: HC-2 split, MechanismDescription defined, C×S-1/C×S-2 redundancy clarified, HC-4 reframed as declaration, SC-4/SC-5 computation defined, C×S-5 demoted to Tier 3, test plan added.*
