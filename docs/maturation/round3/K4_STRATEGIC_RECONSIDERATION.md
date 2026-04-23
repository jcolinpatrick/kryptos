# K4 strategic reconsideration — scaffold

**Status:** Scaffold. Not a conclusion. The operator populates this; this document's purpose is to give that thinking a durable, structured place to live.
**Authored:** 2026-04-22, after the 3-layer serpentine sweep completed. The sweep's outcome is referenced below to anchor the reconsideration in current evidence rather than in session-over-session framing drift.
**Sweep outcome (referenced):** *populated post-sweep at §0 below*.
**Precedents:** this conversation has been deferred across the last three sessions. The prior strategic brief (unlanded) proposed a three-question framework that never got its durable place. This scaffold lands that place; it doesn't land answers.

---

## 0. Sweep outcome as context

The 3-layer serpentine-adjacent sweep completed 2026-04-22 at wall time 26.8 minutes across **1.573 billion parameter combinations** (certificate: `docs/maturation/round3/SERPENTINE_3LAYER_SWEEP_CERT.md`).

**Outcome: CLEAN NULL.** Max crib_score = **10**. Four points below the Gumbel-fit null threshold. Eight below SIGNAL. Eight results at exactly crib=10 (the minimum of the project's "interesting" band), no results at crib=11 or higher.

Combined with the 2-layer sweep's prior null (max crib = 9, 8.27M combinations), the serpentine-adjacent additive-inner hypothesis is **durably eliminated across both 2-layer and pruned-3-layer envelopes**. The theorist's three-persona convergence on serpentine-Vigenère during Campaign B was a legible hypothesis signal — but across 1.58 billion direct tests, no parameter in the tested envelope solves K4.

This is the fifth consecutive run concluding in "clean null, zero signal." The reconsideration scaffold below lands in that context.

---

## 1. What would genuine K4 progress look like from here?

### Framing

The project's past definition of "progress" has drifted. Early sessions equated progress with scripts run, families eliminated, hypotheses tested. More recent sessions have accumulated *methodological* progress (null calibration, matched-family gates, alert plumbing, dashboard telemetry, DSL expansion) at a high rate while cryptographic progress (max crib score, PROMISING theories, plaintext fragments) has stayed flat.

The reconsideration question is not whether methodological progress is valuable — it clearly is, because it makes future signal evaluation trustworthy. The question is whether continuing to *primarily* invest in methodology is the right allocation given:

- Five consecutive runs (v1, v2, v3, Campaign A, Campaign B + verification) have produced zero signal-level alerts.
- Most recent session discovered and surfaced a latent defect that would have silently degraded signal quality if signal had fired. That's a win for integrity, not for K4 proximity.
- The 2-layer and 3-layer sweeps bracketed a specific hypothesis family (serpentine-adjacent additive) cleanly; the bracketing is durable elimination evidence, but it is a specific narrow elimination, not a strategic pivot.

### Prompt

*What would constitute genuine K4 progress from the current state? Choose ONE of:*

- *A plaintext candidate that passes all current validation gates (crib, Bean, ngram, p-value, stat-audit review).*
- *A mechanism hypothesis with sufficient primary-source grounding that its truth/falsity is a finite testable question, even if the test has not been run.*
- *A structural elimination that rules out a broad family (not a specific variant within a narrow envelope), such that the search space shrinks meaningfully.*
- *Primary-source evidence (archive material, Sanborn communication, Scheidt material) that hadn't been considered, regardless of its immediate K4 implications.*
- *Something else — free response.*

*If none of these map well to what you'd call "progress", that is itself the answer: it may be that the project's current working definition of progress is too narrow or too broad. A sentence or two identifying what progress actually means to you now is the deliverable of this question.*

### Response (2026-04-23)

I want to solve K4, but my honest belief set is that either (A) the mechanism is so bespoke that it's effectively unsolvable from outside (chaocipher-analogy, not chaocipher-algorithm: a private construction of the author's, sealed until disclosure), or (B) Sanborn made an error he doesn't realize. In either case, search won't find it.

A lot of what Sanborn calls "clues" are anything but. They anchor (the known cribs at 21-33 and 63-73 are genuine plaintext fragments) but they don't carry mechanism content. A bespoke-private cipher whose author releases partial plaintext is behaviorally consistent with releasing "clues" that aren't cryptanalytic clues, and the observed pattern fits that profile.

Progress from here, if it exists at all, is **primary-source disclosure** (archive material, Sanborn / Scheidt statements that reveal mechanism rather than anchor position) or **internal-inconsistency evidence** (the puzzle is broken in a way its author doesn't realize). It is not more cryptanalytic search. The scaffold's menu assumed search-mediated progress and asked what shape it takes; my reaction is that the menu's premise may not hold for this puzzle.

**Implication for Q2 / Q3:** this answer makes Purpose A (solve K4) aspirational rather than operating, and sharpens Q3 into "when do I stop investing search effort against an object I believe is effectively sealed from outside?"

---

## 2. What is the project's actual purpose over the next six months?

### Framing

The project has two plausible purposes, and they aren't the same:

**Purpose A — solve K4.** The original stated goal. Every commit, every campaign, every analysis ties back to reducing the mechanism search space and producing a plaintext candidate.

**Purpose B — build a durable framework for solving hard puzzles under evidence scarcity.** The framework itself becomes the output. K4 is a test harness for the framework's integrity. Signal or no signal, the framework's behavior under realistic conditions is what this project documents.

The last three sessions have behaved as if Purpose B is the operating purpose (bugs caught by end-to-end exercise, architectural clarifications, methodological hardening), while Purpose A remains the nominal framing. This ambiguity is costly because decisions that look reasonable under B look wasteful under A, and vice versa.

Examples of decisions that differ between A and B:
- Running a 5-cycle verification after a prompt fix: high value under B (confirms architecture integrity), low value under A (doesn't find K4 signal).
- Calibrating matched-family nulls for deferred cipher kinds: valuable under B (preparation for future coverage), speculative under A (signal-dependent, signal hasn't fired).
- Writing a strategic reconsideration scaffold: meaningful under B (framework meta-work), irrelevant under A (doesn't touch the puzzle).

### Prompt

*What is the project's purpose over the next six months? Choose or compose:*

- *Purpose A (solve K4) — and all methodology work is subordinate instrumentation for that solve. Committing to A means declining methodology work that doesn't have a direct path to signal detection.*
- *Purpose B (framework-as-output) — with K4 as a load-bearing test case. Committing to B means accepting that signal may never fire, and that the project's value is the framework's durability under realistic conditions.*
- *A blend of A and B with an explicit time-share — e.g., "70% A, 30% B, revisit in 3 months." This is a defensible middle position IF the ratio is made explicit and enforced; it's a drift pattern if left implicit.*
- *Pivot — e.g., to K5, to Kryptos-adjacent puzzles (Cyrillic Projector, Antipodes), or to documenting the project's methodology as a primary artifact for others working on hard puzzles.*

*The honest answer may be "I don't know" — that is a valid answer, and its next step is to identify what information you'd need to decide.*

---

## 3. Under what conditions would you stop?

### Framing

"Stop" means something different from "pause." A pause is a rest between sessions; a stop is a decision that the current approach will not produce K4 progress and that the project's structure should change.

The project has never preregistered a stop condition. Every prior session has ended in "continue next session." That's not a failure — exploratory research doesn't need stopping rules at every step — but at session 50+ without K4 signal, the absence of a stopping rule is itself load-bearing. It means the project runs indefinitely on momentum.

Plausible stopping rules the operator might preregister:

- **Time-boxed:** "If no signal by session N + K, pause and reassess strategically."
- **Resource-boxed:** "If M more tokens/compute are consumed without signal, stop."
- **Evidence-boxed:** "If the next J campaigns produce max crib < X, the project has evidence that the current search framing is wrong and I stop to rethink."
- **Engagement-boxed:** "If I no longer want to work on this, I stop."

Stopping rules are not about abandoning K4. They are about committing, in advance, to the conditions under which the current approach will be judged insufficient and some alternative (pivot, document-and-close, new approach) will be pursued. Without stopping rules, sunk cost drives continuation.

### Prompt

*Under what conditions would you stop? Three possibilities:*

- *I would not stop. K4 is a lifetime project; the framework's maintenance continues indefinitely. — If this is the answer, record it. The framing concern then becomes "what does 'lifetime project' mean operationally?"*
- *I would stop when a specific event happens. Name the event. It might be concrete (no signal after N more campaigns, a competing solver announces K4) or abstract (I lose interest, my life circumstances change). Record whatever is true.*
- *I don't know when I would stop, but I want to think about it. Record that, and propose the information that would help you decide.*

*A stopping condition is not permission to stop. It's a commitment device that removes the need to decide whether to stop at every future session.*

---

## 4. How to use this document

This scaffold's value is not in its answers — it has no answers. It is a durable place for the three questions to live across sessions. When this conversation resumes (whether in this session or a future one), the document is where the accumulated thinking lands.

Suggested use pattern:

- **Today:** read the prompts. Don't force answers. Note which question you have a reaction to and which feel cold. The reactions are themselves data.
- **Next session:** if the reaction persists, write 2-3 sentences per question. Not decisions; observations. The act of writing them down is the commitment that prior sessions haven't made.
- **Session after that:** if the observations have stabilized, lift one of them into a decision. Update this document with the decision and its date.

The alternative to this scaffolded approach is what the last five sessions have done: defer the reconsideration each time and end the session with "continue next session." That isn't a path forward; it's a loop. The scaffold is infrastructure for breaking the loop.

---

*Scaffold complete 2026-04-22. Awaits operator population at next session's start, or whenever the three questions deserve durable thinking.*
