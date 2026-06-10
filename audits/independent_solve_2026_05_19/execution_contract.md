---
status: live
type: execution_contract
session_started: 2026-05-19
operator: Claude Opus 4.7 (1M context)
authorizing_user: Colin Patrick (jcolinpatrick@gmail.com)
parent_doctrine: /home/cpatrick/kryptos/CLAUDE.md
parent_state: /home/cpatrick/kryptos/MEMORY.md
---

# Execution Contract: Independent K4 Solve Attempt (2026-05-19)

## 1. Mission

Attempt an independent cryptographic solve of Kryptos K4. The goal is **not**
a plausible plaintext. The goal is a reproducible decryption / encryption
method that maps the 97-letter K4 ciphertext to a coherent plaintext **and
back to the exact ciphertext**, derivable from public evidence and
independent computation alone.

If no method passes the gates below, the verdict is **NO VERIFIED SOLVE** and
all useful negative evidence is preserved for future work.

## 2. Honest accounting of prior state (mandatory framing)

This contract is **not** a fresh-build attempt. The repository this contract
sits inside has already run the program described in the originating prompt
across 1028 attack scripts, with the result recorded as
`C-STATE-01: no credible decrypt path; all positive findings are descriptive
anomalies, not solution candidates.` Tier 1 mathematical proofs in
`docs/elimination_tiers.md` cover:

- pure transposition (CT/PT letter-multiplicity mismatch);
- ALL periodic polyalphabetic, periods 1–26, all variants, direct
  positional;
- ALL autokey variants (PT / CT / Quagmire-II) on the carved CT;
- ALL fractionation families (bifid, trifid, ADFGVX, four-square);
- Hill 2x2 / 3x3 (algebraic);
- Gromark / Vimark orders 1–8 (8.74B configs);
- Progressive, quadratic, Fibonacci key schedules under Bean;
- Columnar widths 5–15 (w5, w7: zero Bean passes; others sampled
  exhaustively to max 13–14/24 noise);
- TABP outer-transposition-at-encryption series v1–v3 across 105K+
  branches and 252,840 composed transpositions.

Per `feedback_red_team_before_swings.md`, any Opus compute swing ≥ $25 must
be red-teamed before pitching. Per `MEMORY.md` Bin C/D/E, the live attack
surface is constrained to:

- **Hard Blocker #3** (crib-mapping assumption) — partially explored as
  of 2026-04-09; still untested: multi-layer transpositions,
  grille/selector mechanisms, non-periodic inner ciphers under TABP,
  KA-alphabet inner substitution under TABP;
- archive-derived running-key from a pre-declared public corpus (needs
  `CorpusLicense`);
- archive-derived clock/route procedures (needs `CipherProcedureLicense`).

This contract does NOT re-test items on the "DO NOT TEST" list in the
session briefing.

## 3. Solve criteria (binding gates)

A candidate is labelled **VERIFIED SOLVE** only if every one of these
deterministically passes against the candidate's own artifact:

1. **Method specification.** Full description: cipher family, alphabet,
   keying material, transformations, order of operations, padding /
   spacing / error treatment, route / table / matrix parameters.
2. **Forward consistency.** The method decrypts the 97-letter K4 CT into
   a full candidate plaintext.
3. **Inverse exactness.** The inverse encryption of that plaintext yields
   the exact 97-letter ciphertext, character-for-character.
4. **Crib alignment.** Plaintext positions 21–33 (0-indexed; prompt's
   1-indexed 22–34) = `EASTNORTHEAST`; positions 63–73 (prompt's 64–74)
   = `BERLINCLOCK`. Both must match exactly.
5. **Anti-overfit floor.** The method is not an arbitrary 97-character
   one-time pad, lookup table, unconstrained substitution, or manually
   fitted phrase list, unless the key material is independently derived
   from public Kryptos evidence and the derivation is reproducible.
6. **Explanatory economy.** The method plausibly relates to Kryptos
   materials, K1–K3 method, Sanborn / Scheidt practice, the Kryptos
   tableau, route/matrix clues, clocks, coordinates, or prior section
   themes — and the relationship is not just thematic colour.
7. **Skeptical-review survival.** Holdout test (cribs withheld from
   search) plus false-positive battery plus independent reproduction
   from a clean process all pass.

Any failure → **PARTIAL BREAKTHROUGH** or **NO VERIFIED SOLVE**.

## 4. Assumptions and explicit uncertainty

- K4 ciphertext is `OBKRUOXOGHULBSOLIFBBWFLRVQQPRNGKSSOTWTQSJQSSEKZZWATJKLUDIAWINFBNYPVTTMZFPKWGDKZXTJCDIGKUHUAUEKCAR`, 97 characters. *Verified.*
- The carved-CT crib alignment is real for the *direct-positional* branch.
  Under any transposition-aware branch the cribs are plaintext-position
  constraints after rearrangement and direct CT↔PT pairs may not all hold
  position-by-position.
- The plaintext **length is not confirmed at 97**; null insertion remains
  admissible (see `feedback_pt_length_open_question.md`).
- The Sanborn "two encryption systems" claim is Tier-3 hearsay (see
  `feedback_sanborn_epistemic_weight.md`), not [PUBLIC FACT]; it may not
  be true and must not drive structural assumptions.
- Surface statistics on n=97 are weak; IC 0.0361 is not significantly
  below random for this length.
- Bean constraints (1 equality, 242 inequality, 101 linear) admit exactly
  624 valid keystreams at the 24 crib positions under any additive
  variant; this is a *necessary* condition, not a *sufficient* one.

## 5. False-positive risks

Any candidate that exhibits one of these is downgraded or rejected:

- only anagrams or rearranges to meaningful words without a reversible
  rule;
- inserts spaces or nulls without a rule;
- matches BERLIN/CLOCK but fails EAST/NORTHEAST or vice versa;
- uses a 97-letter key that is essentially the PT/CT delta with a story
  attached;
- relies on an LLM-generated plaintext that code cannot re-encrypt;
- ignores length or crib positions;
- uses non-public recovered plaintext (e.g. sealed coding chart,
  auction-leaked, NDA-bound material);
- cannot be reproduced from a clean checkout;
- requires changing CT letters without independent evidence;
- has more free parameters than constraints (degrees-of-freedom audit
  fails);
- triggers `BREAKTHROUGH` (crib_score 24, Bean PASS) but fails ngram
  floor, p-value gate, or independent re-encryption.

## 6. Holdout strategy

For every search that reaches the candidate stage:

- Run search A with `EAST/NORTHEAST` (positions 21–33) withheld;
  candidate must independently predict those 13 characters.
- Run search B with `BERLIN/CLOCK` (positions 63–73) withheld;
  candidate must independently predict those 11 characters.
- A candidate that uses all 24 crib characters to constrain its key
  passes neither holdout and is automatically downgraded to PARTIAL at
  best.

## 7. Experiment order

This contract executes **audit-then-frontier**, not redo-all-five-phases.

- **Phase 0: Independent reference build.** Implement alphabets, Kryptos
  tableau, Vigenère, Beaufort, Variant Beaufort, autokey variants,
  columnar / route transposition, affine, Hill, scoring — pure stdlib,
  zero imports from `kryptos.kernel`. Reference comparator only.
- **Phase 1: Reference verification on K1, K2, K3.** Reproduce known
  plaintexts. If any K-section fails to reproduce, the reference is
  wrong; fix the reference, never the K-section data.
- **Phase 2: Cross-verification against the kernel.** Run 3–5 sampled
  Tier 1 eliminations through both the reference and the kernel; report
  any disagreement as an immediate audit finding.
- **Phase 3: Independent baseline statistics on K4.** Frequency, IC,
  Kasiski gaps, repeated n-grams, autocorrelation, deltas under
  AZ / KA / reversed-AZ / reversed-KA × Vig / Beaufort at the 24 crib
  positions; periodicity scan; alignment with KRYPTOS / PALIMPSEST /
  ABSCISSA / BERLIN / CLOCK / WORLD / LANGLEY / WEBSTER / CARTER /
  TUTANKHAMUN / EASTNORTHEAST.
- **Phase 4: Frontier experiment.** From Hard Blocker #3, identify the
  cheapest bounded experiment with non-zero new-evidence yield. Get
  user direction on which one. Pre-register thresholds. Run.
- **Phase 5: Final report.** Verdict (VERIFIED SOLVE / PARTIAL /
  NO VERIFIED SOLVE) with full provenance, the strongest remaining
  hypotheses, and one concrete next experiment worth human time.

## 8. File structure

```
audits/independent_solve_2026_05_19/
├── execution_contract.md                  (this file)
├── README.md
├── data/
│   ├── k4.json                            (CT, cribs, self-encrypting, Bean as data)
│   ├── sources.md                         (provenance for every public fact)
│   └── known_sections.md                  (K1-K3 plaintexts, methods, citations)
├── src/                                   (stdlib-only; never imports kryptos.kernel)
│   ├── alphabets.py
│   ├── kryptos_tableau.py
│   ├── stats.py
│   ├── scoring.py
│   ├── constraints.py
│   └── ciphers/
│       ├── vigenere.py
│       ├── beaufort.py
│       ├── autokey.py
│       ├── transposition.py
│       ├── affine.py
│       ├── hill.py
│       └── route.py
├── tests/
│   ├── test_data_integrity.py
│   ├── test_k1_k2_k3.py                   (reference must reproduce known sections)
│   ├── test_crib_constraints.py
│   ├── test_reversibility.py
│   └── test_cross_kernel.py               (reference vs kryptos.kernel parity)
├── experiments/
│   ├── e01_baseline_stats.py
│   ├── e02_vig_kryptos_keys_with_holdout.py
│   ├── e03_replicate_tier1_samples.py
│   └── e04_frontier_<TBD>.py
└── results/
    ├── experiment_log.md
    ├── candidates.jsonl
    ├── negative_results.md
    └── final_report.md
```

## 9. Logging rules

Every experiment appends to `results/experiment_log.md` with:

- `hypothesis` — one sentence;
- `command` — the exact invocation;
- `parameters` — full parameter sweep extent;
- `holdout_protocol` — which crib(s) withheld and how predictions checked;
- `result` — ACCEPT / REJECT / INCONCLUSIVE with score and provenance;
- `reason` — why accepted/rejected;
- `next_action` — what this run unlocks or closes.

Candidates with `crib_score ≥ 18` under the reference implementation are
appended to `results/candidates.jsonl` with full metadata for
reproduction; the kernel's `BREAKTHROUGH` label is treated as a
candidate-for-investigation, never an output.

## 10. Stop conditions

The contract terminates when **any** of the following becomes true:

1. A candidate clears every gate in §3 → final report = **VERIFIED SOLVE**.
2. The Phase 4 frontier experiment completes with clean null and no other
   Phase 4 candidate has non-zero red-team-survival → final report =
   **NO VERIFIED SOLVE** with explicit "strongest remaining hypotheses"
   and one bounded next experiment.
3. The reference build fails to reproduce K1, K2, or K3 and the fault is
   in the reference, not the kernel → halt; this contract cannot proceed
   without a sound comparator.
4. The cross-verification phase finds a disagreement between the
   reference and the kernel that material affects a cited Tier 1 row →
   halt; raise an `AUDIT-*` item in `docs/methodological_audits.md`,
   defer Phase 4.
5. A frontier experiment requires red-team review under
   `feedback_red_team_before_swings.md` and that review has not been
   commissioned → halt; surface to user.

## 11. What this contract will **not** do

- Will not re-run any item on the session-briefing "DO NOT TEST" list
  without a materially new assumption recorded in the registry.
- Will not consume the public-private boundary; sealed coding chart,
  RR Auction artifacts, NDA-bound material, and Sanborn's private
  coding system are excluded from inputs (see
  `feedback_auction_out_of_scope.md`).
- Will not commit any push to a public remote
  (`feedback_no_github_push.md`, `feedback_publish_workflow.md`).
- Will not claim VERIFIED SOLVE on a result that fails any gate in §3.
- Will not present a "plausible plaintext" without method + inverse +
  holdout pass.

— end of contract —
