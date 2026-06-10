# Pantheon Coverage Assessment — Is the agent roster appropriate to solve K4?

Date: 2026-05-30
Status: ASSESSMENT (no implementation). Classification: [POLICY] + [HYPOTHESIS].
Author: Colin Patrick (human lead) + Claude (computational partner).

> **STATUS UPDATE (2026-06-10 audit — three-lane verification against code at
> HEAD; full findings in the session record):** the roster/wiring facts (§2,
> §5.3, §5.4) re-verify EXACTLY (rotation still round-robin, frontier_map still
> advisory, script-auditor still wired nowhere, codebook/nomenclator still a
> total gap, scorer still English-only). However, the TOOLING half of the
> B-axis (alignment) gap has since CLOSED via a different route than §8.4's
> spec: Lever B1 wired `score_candidate_free` (2026-05-31, commit 5a878be);
> AUDIT-5 closed with route-undone-frame Bean re-derivation (2026-06-07,
> c0b1004); diagonal Quagmire tableau sweeps landed (`tableau_keyword`,
> cf9dee1). The `RealignmentSpec` vehicle in the §8.4 spec was never built and
> that spec's DRAFT status is itself stale. The GENERATIVE-PERSONA half of the
> gap remains OPEN: THEORIST_ROTATION is unchanged, no charter addendum landed,
> §8.2's zero-compute "theater test" was never run, and no theorist has emitted
> a genuine non-direct-alignment proposal (the post-Lever-B1 non-direct
> closures were operator/campaign dispatches). Capability-claim passages below
> that this supersedes carry inline [2026-06-10] notes; quoted agent text is
> left verbatim as historical record.

> Goal this answers: "determine if we have an appropriate pantheon of agents to
> solve K4 — each acts as a persona within the controller — and, since the cipher
> is truly bespoke, whether we are missing a perspective."

> Session caveat (honest): this file was written during a session whose Bash/Read
> tool-output delivery failed intermittently. Both agent passes nonetheless
> returned cleanly: the §3 triangulation (3 agents) AND the §5 deepening pass
> (3 agents). NO verification gates (doctor, pytest, self_test) were run as part
> of writing this — it is an org-design assessment, not a research result. The
> two unverified items are the historical timing of the tool failure (cosmetic)
> and that §5's findings have not themselves been independently re-audited.

---

## 0. TL;DR

- For its CURRENT job — **eliminating** hypotheses — the pantheon is well-designed
  and roughly complete. It is an excellent disproof engine.
- The intuitive fix for "the cipher is bespoke" (add a *bespoke-cipher designer*
  persona) is **wrong**: that surface is already triple-covered, and such a
  persona imports the project's #1 failure mode (narrative overfit).
- The genuine gap is not a cipher idea — it is an **assumption**. No GENERATIVE
  persona's prior is that the project's load-bearing framing is wrong. Concretely,
  the under-owned axes are: **alignment** (B), **construction-fidelity** (G) —
  together a "frame-faithfulness adversary" — and, distinct and under-recognized,
  the **plaintext-genre / semantic-target** axis (J).
- DECISIVE constraint (red-team, 0.82): adding a bare new generative persona is
  THEATER, because personas are the same model re-prompted (priors, not new
  capabilities), and the live frontier is blocked at the SCORER/DISPATCHER, not
  the idea generator. The fix is a capability, not (only) a seat.
- Verdict: **FIT-WITH-GAPS.** Fit for elimination; gapped for the one move that
  could actually solve a bespoke K4 — questioning the frame itself — and that gap
  is half roster, half tooling.

---

## 1. The right unit of analysis

"Do we have enough agents?" is the wrong question. Each persona is the SAME
underlying model (Opus) re-prompted with different priors; the reachable
idea-space does not grow by adding prompts. The correct unit is the
**solution-space axis**: an independent dimension along which a complete K4
solution must be specified. A correct pantheon has a GENERATIVE OWNER
(a persona whose default prior actively explores that axis) for every axis whose
value is unknown. An axis with no generative owner is a structural blind spot no
amount of compute fixes.

PANTHEON.md's own existence test (#8) is the same idea inverted: a persona should
exist only if it says something NO other persona would. So "missing a perspective"
== "an axis with no owner," and "redundant persona" == "two owners of one axis,
neither distinctive."

---

## 2. The roster (ground truth, read from disk this session)

GENERATIVE (controller rotates one per cycle — `kryptosbot/routing.py:53-60`
`THEORIST_ROTATION`):
1. **cryptanalyst** — algorithmic/algebraic attacks; classical/near-classical
   search space; elimination by compute.
2. **cipher-discovery-builder** — obscure documented hand ciphers from public
   sources; catalogs by structural fit. Bias: method is obscure/bespoke.
3. **stego-analyst** — null-mask / palette / placement rules (which carved
   positions are signal vs filler).
4. **keystream-forensics** — OTP/additive, finite key tapes, null-consumption,
   crib-derived keystream (Scheidt CKM lineage).
5. **escape-room-cryptanalyst** — physical installation, optical/spatial/material
   transforms of the sculpture.
6. **archivist-historian** — primary sources, designer intent, 1988-1990
   feasibility.

NON-GENERATIVE — JUDGES (audit only, fixed phases): statistical-auditor,
red-team-disprover, script-auditor, results-analyst.
MANAGER: research-chancellor (synthesizes; does not generate).
MANUAL-ONLY auditors (not in rotation): agent-roster-integration-auditor,
prompt-contract-auditor, known-answer-benchmark-auditor, forensic-photo-analyst,
kryptos-corpus-forensics.

Governing doctrine: `.claude/agents/PANTHEON.md` ("Team of Rivals": narrative
supplies priors, evidence decides; premature consensus is the enemy).

---

## 3. The triangulation (three mutually-blind agents — results returned cleanly)

To avoid my own confirmation bias, the core question was put to three independent
agents who did NOT see each other or my conclusion:

- **research-chancellor (field survey):** roster incomplete; the unowned axis is
  the ALIGNMENT MODEL itself (the project's self-identified load-bearing
  assumption). Recommended building the scorer capability FIRST; add a persona
  only if the existing cryptanalyst, given that capability, still fails to explore
  the axis. Confidence medium-high on the axis, medium on the vehicle.
- **red-team-disprover (tasked to DEFEND completeness):** "NOT JUSTIFIED" for a
  bare new generative persona, **confidence 0.82.** Strongest points: personas are
  re-prompts not capabilities; the bottleneck is the dispatcher/scorer
  (`crib_alignment='free'` recorded but scored anchored at
  `job_dispatcher.py:1807`); "bespoke" is triple-covered; a "designer-intent
  synthesist" is an unfalsifiability engine importing the dominant false-positive
  mode. The ONE surviving gap is an assumption/tooling role, not an idea fountain.
  *[2026-06-10: the anchored-at-:1807 claim was true at writing but is now
  resolved (Lever B1 + AUDIT-5); also note the same-day closure-integrity audit
  found anchored scoring was already CORRECT for dispatcher decrypt pipelines —
  the "bug" framing was stronger than the corrected record. Quote kept verbatim.]*
- **design-archaeologist (orthogonal frame — an ad-hoc prompted frame for that
  session, NOT a roster agent; no such agent exists in `.claude/agents/`):**
  the missing frame is
  CONSTRUCTIVE-RECONSTRUCTION — sit in the inventor's 1989 chair and forward-model
  how they would BUILD a custom system from their materials/skills/error-tolerance,
  predicting the construction ARTIFACTS it leaves. Shared blind spot of all six:
  **they assume the cipher was built correctly** — none is allowed to assume the
  carved copper is corrupt. (Notes the CT-perturbation harness exists, but only as
  a DEFENSIVE robustness check, not as a generative prior.)

Convergence (the signal): all three, from different starts, land on the same axis
— **the frame itself (alignment + construction fidelity) is doubted by no one.**
Divergence (the honest part): the REMEDY — new persona vs. charter the existing
six vs. finish the tooling.

---

## 4. Solution-space coverage matrix (my decomposition)

| Axis | What it specifies | Generative owner | Status |
|------|-------------------|------------------|--------|
| A. Input / transcription | which 97 chars; carved copper vs Antipodes authority | escape-room + archivist + (corpus-forensics, manual) | OWNED |
| B. **Alignment / indexing** | how carved pos i maps to the cipher's working/PT sequence (direct / post-trans / free / reordered / null-shifted) | — | **UNOWNED** |
| C. Stego / null layer | which positions are signal vs filler | stego-analyst | OWNED |
| D. Cipher transform | the algorithm family | cryptanalyst + cipher-discovery-builder | OWNED (slightly redundant) |
| E. Key / keystream | key material + consumption rule | keystream-forensics + cryptanalyst | OWNED |
| F. Composition / layering | how multiple systems combine ("two systems") | cryptanalyst tests multi_layer, but as fallback not prior | WEAKLY OWNED |
| G. **Construction fidelity** | is the carved text a CLEAN encryption or does it carry a hand-construction error | — | **UNOWNED** |
| H. Physical / material | sculpture geometry, optics, rest of installation | escape-room-cryptanalyst | OWNED |
| I. Provenance / intent | designer statements, historical feasibility | archivist-historian | OWNED |
| J. **Plaintext-target / genre** | WHAT KIND of message: English prose? coordinates? riddle? pointer? non-English? (scorer HARDCODES English n-grams) | — | **UNOWNED / under-recognized** |
| K. Verification | is a candidate real | judges (stat / red-team / script / results) | OWNED |
| L. Strategy / meta | what to attack next | research-chancellor | OWNED (see §6 caveat) |

### The unowned axes, ranked by how load-bearing they are

1. **B (Alignment) + G (Construction fidelity) — the "frame-faithfulness" axis.**
   Highest value: the project's own retrospectives name direct positional
   `CT[i]->PT[i]` on a fixed-97 message as the single load-bearing assumption
   under EVERY elimination. If it is wrong, a large fraction of the elimination
   ledger is conditional, not absolute. No generator's prior is "the frame is
   wrong." (B = the indexing is non-direct; G = the artifact is corrupt. Two faces
   of one doubt.)

2. **J (Plaintext-genre / semantic target) — distinct and under-recognized.**
   Every generator implicitly assumes the answer is English (the kernel scorer is
   built on English quadgrams; `score_candidate` rewards English n-grams). No
   persona's job is to reason about the NATURE of the target: K1-K3 are misspelled
   English riddle-prose with a deliberate error, but K4 could be a different genre
   entirely (coordinates, a second-stage pointer, a non-English layer, a
   number-string). A wrong genre prior makes the scorer itself a blind spot — a
   correct-method, non-English candidate would score as noise. This axis was
   under-weighted in the first triangulation and deserves its own analysis.

3. **F (Composition-as-prior) — weakest of the three.** Multi-layer IS tested by
   cryptanalyst, and a `multi-layer-composition` skill exists, but no generator
   wakes up believing "it's a composition of two systems" and designs the search
   around that. Given the (Tier-3) "two systems" claim, a composition-first prior
   is at least arguable. Lower priority because the capability mostly exists; it is
   a framing emphasis, not an absence.

> NOTE: the §5 deepening pass added more unowned axes (M search-strategy,
> N dispatchability, message-length) and a clean TOTAL gap — codebook/nomenclator
> (axis D2: word/number lookup, not letter-level) — plus judge-layer gaps. See §5
> for the corroborated, expanded ranking. The single highest-ranked STRUCTURAL
> weakness (per the manager audit) is not a missing generator at all but the
> evidence-blind, calendar-driven rotation (§5.4).

---

## 5. Deepening pass — RETURNED (3 mutually-blind agents)

Three agents independently attacked the §4 matrix (a general coverage-auditor, the
cryptanalyst on mechanism-class coverage, and the research-chancellor on
structure/judges/rotation). They CONFIRMED B/F/G/J as genuinely unowned and added
findings that change the picture. Convergence was high and several points are
corroborated by direct code reads.

### 5.1 New axes the A-L decomposition was MISSING

- **M. Search-strategy / optimization** (HIGH). "Which cipher" (D) is not "how do
  you search its keyspace" (SA vs exhaustive vs CP-SAT vs crib-derived inversion).
  A correct family with the wrong optimizer never converges. Split implicitly
  between cryptanalyst and manager; no generator's PRIOR is "the bottleneck is the
  search method, not the family." Given the project self-diagnoses as a "disproof
  engine, not a solver," this is arguably THE live gap. (auditor + cryptanalyst,
  high confidence it is a distinct axis.)
- **N. Tooling / dispatchability** (MEDIUM). A hypothesis is unsolvable-in-practice
  if the DSL/kernel cannot express it (`crib_alignment='free'` unimplemented;
  diagonal `ct==pt` Quagmire tableaus unsweepable). No generator owns "is this even
  expressible / scoreable." Silently prunes the space upstream of any idea.
  *[2026-06-10: both named examples have since been fixed — free scoring 2026-05-31,
  tableau_keyword 2026-06-09 — which proves the axis is real and actionable; the
  "no generator owns dispatchability" point itself still stands.]*
- **Message-boundary / length** (MEDIUM): "is PT 97, or are there nulls / a shorter
  true message" is structural, distinct from genre (J); owned by neither B nor C as
  a prior. MEMORY already flags "PT length is open question."

### 5.2 Confirmation + sharpening on B/F/G/J (all HIGH confidence)

- **G (construction fidelity) is the most insidious gap** (both auditor and
  cryptanalyst independently): every elimination assumes a CLEAN encryption, so a
  single hand transposition/copy error would invalidate the entire elimination
  ledger — and no agent is hunting for it. The CT-perturbation harness exists but
  as a DEFENSIVE side-harness, not a generative prior.
- **J (non-English genre) is doubly entrenched**: the blind spot is not just
  persona-level, it is BAKED INTO THE FITNESS FUNCTION (kernel ngram scorer reads
  `data/english_quadgrams.json`; an English wordlist segments candidates). A
  correct-method coordinate/German/second-cipher PT would be SYSTEMATICALLY
  INVISIBLE — scored as noise even if correctly decrypted. So J is also a hole in
  the verification layer (K), not only generation.
- **(a) Codebook / nomenclator / dictionary-lookup is a CLEAN TOTAL GAP**
  (cryptanalyst, high): every generator operates at letter/keystream/position
  level; there is no `codebook`/`nomenclator` family, no DSL `kind`, and the scorer
  scores letter-plaintext not token->codegroup. A 1989 nomenclator (entirely
  period-plausible) cannot be generated as a testable spec by anyone. This was
  absent from my A-L list entirely.
- **B (alignment) is owned only by a PASSIVE SKILL**: the `alignment-model` skill
  exists but "skills are pulled, personas push" — no generator's standing prior
  fires it, and the scorer collapses `free` to anchored anyway. Owner-less in
  practice. *[2026-06-10: the scorer clause is resolved (free and
  post_transposition are honored end-to-end); the no-generative-owner clause
  remains true — no theorist has emitted a genuine non-direct proposal since.]*

### 5.3 Judge-layer gaps (chancellor, HIGH on findings)

- **Semantic / linguistic-plausibility judge — MISSING.** No judge asks "is this a
  meaningful English sentence in K1-K3's declarative style"; only whether the
  quadgram score clears a floor. Given AUDIT-3 (BREAKTHROUGH dominated by post-hoc
  overfits), n-gram is necessary, not sufficient. This is the most defensible judge
  gap. Tied to axis J.
- **Cross-K1-K3 consistency judge — PARTIALLY COVERED but mis-scoped.**
  `known-answer-benchmark-auditor` verifies the KERNEL still rediscovers K1-K3 (a
  fitness gate), NOT whether a candidate K4 SOLVE is consistent with K1-K3
  conventions (KRYPTOS alphabet, Vigenère lineage, masking style). No agent owns
  "does this solve fit the established Kryptos system family."
- **Reproducibility — ADEQUATELY COVERED** (kernel overrule recomputes
  crib_score/Bean independently of worker self-reports). NOT a gap. Strongest part
  of the verification space.
- **WIRING BUG (verified):** `script-auditor` is documented in PANTHEON.md as a
  core judge but is **invoked nowhere in the controller** (grep count 0 in
  controller/siblings/dispatcher) — it is effectively manual-only. Either wire it
  in or reconcile the doctrine. (chancellor, verified.)

### 5.4 Structural / wiring findings (chancellor, HIGH)

- **Round-robin forbids the cross-product.** One generator per cycle means NO cycle
  ever combines two generative frames — so a proposal that is BOTH a cipher AND a
  non-direct-alignment hypothesis cannot be emitted in one cycle. This is the same
  root cause as the missing frame-faithfulness adversary, and the likeliest real
  solution shape ("non-standard alignment + ordinary cipher") is exactly that
  forbidden cross-product. Possibly the single most important structural fact here.
- **Rotation is calendar-driven, not evidence-driven.** Generator selection is
  `cycle_number % 6`; `frontier_map.py` builds a family x alignment grid but is
  "advisory only — nothing here gates dispatch." So the project CAN see where
  probability mass remains but has wired it as advisory; NO agent is accountable
  for steering toward the highest-EV axis. The chancellor ranks THIS — the
  manager-level strategic-allocation gap — as the single most important structural
  weakness, above the semantic-judge gap (a missing judge degrades verification of
  a found candidate; the allocation gap degrades whether the right candidate is
  ever generated).
- **Generative/judge separation adds repair latency:** when a judge finds a
  mechanical error, the corrected re-test must wait for a generator's turn. Right
  for confirmation, costly for repair.

### 5.5 Is "bottleneck = toolchain, not idea generator" right? (refined)

Partly. For **B (alignment)** and **F (composition)** the bottleneck IS the
scorer/dispatcher (wiring `score_candidate_free` + matched null would unblock
them). But for **(a) codebook/nomenclator** and **J (non-English PT)** the gap is
upstream and JOINT: no generator AND no DSL kind AND no non-English scorer — a
perfect free-alignment scorer would do nothing for them. So the precise statement:
*alignment/composition are toolchain-bottlenecked; codebook and non-English-genre
are bottlenecked in the roster AND the kernel scorer simultaneously.*
*[2026-06-10: the B/F toolchain unblock has since happened (Lever B1, AUDIT-5,
tableau_keyword, route_null matched-null harness) — and the prediction held:
with tooling closed, the remaining deficit is exactly the generative-prior half.
The codebook and non-English-genre joint gaps are unchanged.]*

---

## 6. Structural observations (independent of the missing axes)

- **Redundancy check:** cryptanalyst vs cipher-discovery-builder both own axis D,
  but they pass test #8 (attack-known vs find-obscure are distinct generative
  priors). Not a merge candidate. No other clear redundancy among generators.
- **Rotation blind spot (hypothesis):** because generators fire one-per-cycle, no
  single cycle combines a frame-faithfulness prior WITH a concrete cipher
  proposal. The most likely real solution shape ("non-standard alignment +
  ordinary cipher") is precisely the cross-product the rotation cannot emit in one
  cycle. This may matter more than any single missing persona.
- **Judge/scorer coupling to axis J:** the verification layer inherits the English
  assumption. If J is wrong, the judges cannot catch it — they would correctly
  reject a correct-method non-English candidate. A blind spot in J is therefore
  also a blind spot in K.
- **Strategy by rotation, not by probability:** the manager synthesizes but the
  controller's generator selection is round-robin, not driven by where the
  remaining probability mass is. This is a defensible anti-overfit choice
  (forces breadth) but means no agent is charged with "spend the next cycle on the
  highest-EV axis."

---

## 7. Verdict

**FIT-WITH-GAPS.**

- FIT as a disproof engine: the generative surface spans mechanism (D,E), stego
  (C), physical (H), provenance (I); the judge layer covers verification (K); the
  manager covers synthesis (L). For eliminating hypotheses WITHIN the standard
  frame, the roster is appropriate and the rivalry rules are sound.
- GAPPED on the one move most likely to crack a BESPOKE K4: no generator doubts
  the frame (B alignment, G fidelity), and no generator reasons about the
  plaintext's genre (J). These are exactly the axes a bespoke system is most
  likely to exploit, and they are exactly the axes the current roster cannot
  generate over.
- The gap is HALF ROSTER, HALF TOOLING. A new idea-generator alone is theater
  (red-team, 0.82): the alignment axis is unscoreable today because the dispatcher
  scores everything anchored. Closing the gap means a capability (scoreable
  non-direct alignment + matched null) AND a generative prior that uses it —
  whether that prior lives in a new persona, a charter addendum to the six, or a
  rotation change is the open implementation question (deferred, per the human
  lead). *[2026-06-10: the TOOLING half is now closed ("unscoreable today" no
  longer holds); the ROSTER half — a generative prior that actually uses the
  capability — is still open and is now the whole remaining gap on this axis.]*

---

## 8. What to decide next (implementation — DEFERRED to discussion)

Do NOT treat any of these as chosen. They are the menu the assessment produces:
1. Independently re-audit §5's returned findings in a clean session to confirm
   the axis list is complete and to resolve the judge/rotation/manager questions.
   *(Original wording "Finish §5" was stale — the deepening pass returned; what
   it never got was independent re-audit. The 2026-06-10 audit re-verified its
   code-level claims — script-auditor wiring, frontier_map advisory, codebook
   gap — but the quoted agent reasoning remains un-re-audited.)*
2. Decide the VEHICLE for the frame-faithfulness axis: new persona vs. charter the
   existing six vs. rotation change — gated behind a zero-compute "theater test"
   (replay a candidate prompt over past cycle inputs; does it produce dispatchable,
   non-direct-alignment, non-exhausted proposals the six don't?).
3. Decide whether axis J (plaintext-genre) warrants its own generative prior and/or
   a non-English-aware scoring path + a semantic-plausibility judge.
4. Only then: the scorer/dispatcher capability work (a separate, deliberate
   decision; a draft design/plan exists at
   `docs/specs/2026-05-30-frame-transform-dispatch-path-{design,plan}.md` but
   presumes a build decision not yet made).

---

## 9. Provenance & honesty notes

- Roster, PANTHEON.md, routing.py: read directly from disk this session.
- §3 triangulation: full agent results returned and are quoted faithfully.
- §4 matrix: my decomposition; axes B/G/J flagged UNOWNED are my analysis, partly
  corroborated by §3 (B/G) and grounded for J in the kernel's English-only scoring.
- §5: deepening pass returned and is quoted in full; its findings have not been
  independently re-audited (matching the header caveat). *(A prior version of
  this line said "dispatched but UNRETURNED" — written before §5 landed and
  never updated; corrected 2026-06-10 since it contradicted the doc's own §5
  body and header caveat.)*
- No K4 compute was run. No verification gates were run this session. K4 NOT
  solved. This is an org-design assessment, not a research result.
