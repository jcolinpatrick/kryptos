# Pre-Registered Thresholds — Bin-C Execution 2026-04-08

**Purpose.** Commitment device. Written BEFORE any C1/C2/C6 compute runs. Any post-hoc relaxation of these thresholds invalidates the exhaustion certificate.

**Background.** E-FRAC-36 proved that SA / hill-climbing at Bean-surviving periods trivially reaches 24/24 + Bean with quadgram < -5.0/char (gibberish). Therefore the crib score alone cannot serve as an escalation criterion. Every future campaign with a hill-climbing or large enumeration must use a **conjunctive** criterion that couples crib score, Bean constraint, AND an independent English fragment quality score. This document fixes that conjunction before results are seen.

---

## Definitions

- **Crib score (anchored):** `score_candidate(plaintext)` from `kryptos.kernel.scoring.aggregate`, returning the number of crib positions (0-24) where the decrypted letter matches the known crib letter under the direct-correspondence assumption.
- **Crib score (free):** `score_candidate_free(plaintext)` — search each crib anywhere in the plaintext. Used when any layer of the composition is a transposition.
- **Bean pass:** Simultaneous satisfaction of the Bean equality `k[27]=k[65]` AND all 242 variant-independent inequalities from the 24 crib positions. Computed via the scoring breakdown's `bean_passed` field or equivalent.
- **Quadgram score (per char):** Log-likelihood per character under `data/english_quadgrams.json` applied to the candidate plaintext. English baseline ≈ `-3.4/char`. Uniform random letters ≈ `-10.0/char`. E-FRAC-36 showed that the 175 false 24/24+Bean hits at Bean-surviving periods all scored worse than `-5.0/char`.
- **Word-hit count:** Number of dictionary words of length ≥6 found in the plaintext via substring scan against `wordlists/english.txt`.
- **"Coherent English fragment":** A contiguous substring of ≥10 characters that (a) contains at least 2 dictionary words of length ≥4 AND (b) has quadgram per-char ≥ -4.0 when scored in isolation.

---

## ESCALATION criterion (triggers investigation)

A candidate is **ESCALATED** iff ALL of the following hold:

1. Crib score (anchored OR free, whichever is appropriate for the stack) **≥ 20** out of 24.
2. Bean constraint **PASSED** (equality AND all 242 inequalities).
3. Quadgram per-char on the full plaintext **≥ -4.5** (i.e. plaintext is measurably more English-like than random; E-FRAC-36's false positives capped at -5.0).
4. Word-hit count **≥ 3** (at least three dictionary words of length ≥6).
5. At least one "coherent English fragment" as defined above.

All five conditions must hold. A candidate satisfying 4 of 5 is NOT escalated. It is logged with its shortfall reason and treated as noise.

**Rationale for 20/24 rather than 24/24:** 24/24 is the breakthrough threshold but is also trivially reachable by overdetermined searches (E-FRAC-36). 20/24 + Bean + the three quality criteria together gives a stronger conjunctive signal than 24/24 + Bean alone. A real solution will satisfy 24/24 automatically; this threshold catches near-solutions without admitting E-FRAC-36-style trivial saturations.

---

## STOP criterion (per campaign)

A campaign is **STOPPED** at its natural completion (full enumeration exhausted) OR at first ESCALATED candidate, whichever comes first.

No early stopping based on preliminary score distributions. No "the scores look promising so let me extend the search space." Either the enumeration completes or an escalation triggers, and nothing in between.

---

## DOWNGRADE criterion (for running-key as an open family)

Running-key (as an open family in MEMORY.md) is **downgraded to empirically saturated (bin B)** iff:

1. C1 (Carter + columnar w6/8/9 × 3 variants, admissibility-gated) completes with **zero ESCALATED candidates**.
2. C2 (Kahn + columnar w6/8/9 × 3 variants, admissibility-gated) completes with **zero ESCALATED candidates**.

If either campaign produces an ESCALATED candidate, running-key retains bin-C status pending investigation of that candidate. A candidate that fails secondary review (e.g., a false positive under stricter scrutiny) does NOT block downgrade.

---

## DOWNGRADE criterion (for composition 3-layer as an open family)

Three-layer non-columnar composition is **downgraded to empirically saturated (bin B)** iff:

1. C6 (bounded 3-layer enumeration with pre-registered family set) completes with **zero ESCALATED candidates**.
2. The enumeration covers at least: {additive, periodic_sub Vig, periodic_sub Beau} × {route, myszkowski, rail_fence, block_transposition} × {additive, periodic_sub Vig, periodic_sub Beau}, with inner-layer parameter space bounded to thematic keywords (≤50 per family) and middle-layer parameters bounded (widths 6-13, depths 2-12).

A partial enumeration does NOT downgrade the family; only completion or escalation does.

---

## RE-OPENING criterion

A family downgraded to bin B by the above can only be re-promoted to bin C if:

1. A new primary-source finding (archive, Sanborn/Scheidt statement, K5 release) materially changes the admissibility basis, OR
2. A new detection apparatus (not the current crib+Bean+quadgram+word-hit conjunction) resolves a previously underdetermined case (e.g., E-FRAC-54's mono-saturation), OR
3. A confirmed error in the current elimination — e.g., a proven bug in the Bean constraint implementation or the admissibility solver.

Aesthetic dissatisfaction, "it feels incomplete," or "what if the threshold was too strict" are not valid re-opening reasons.

---

## Record-keeping contract

Every campaign under this document must write its result JSON with:

- `preregistered_thresholds_doc`: path to this file
- `escalated_candidates`: list (possibly empty) of candidates meeting all 5 criteria
- `near_miss_candidates`: list of candidates meeting 4 of 5 criteria, WITH the specific criterion each fails
- `total_tested`: full enumeration count
- `bean_passes`: count of candidates that passed Bean (regardless of escalation)
- `max_crib_score`: maximum observed
- `max_quadgram`: maximum observed
- `verdict`: one of `{ESCALATED, EMPTY, PARTIAL, ERROR}`

`ESCALATED` means at least one escalated candidate. `EMPTY` means enumeration complete with zero escalated. `PARTIAL` means enumeration incomplete (e.g., stopped by operator). `ERROR` means a script crashed or produced malformed output.

`EMPTY` is the expected and desired verdict for all three campaigns under the current null hypothesis.

---

*Committed 2026-04-08 before any compute. Changes to this document after any compute run invalidate the exhaustion certificate.*
